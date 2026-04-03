"""Tests for matrix.session_jumper — JumpSession, capture, restore, transfer state."""

import base64
import gzip
import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from matrix.session_jumper import (
    JumpSession, capture_session, restore_session,
    TransferState, TransferStateStore,
    MultiJumpStrategy, MultiJumpResult, TargetResult,
    JumpError,
)
from matrix.device_discovery import Device, Transport


class TestJumpSession(unittest.TestCase):
    """Test JumpSession serialize/deserialize and checksum."""

    def _make_session(self, **overrides):
        defaults = {
            "session_id": "test-session",
            "source_device": "device-1",
            "timestamp": 1000.0,
            "cwd": "/tmp/test",
            "env": {"HOME": "/home/user"},
            "clipboard": "hello",
            "files": {},
            "metadata": {"key": "val"},
        }
        defaults.update(overrides)
        return JumpSession(**defaults)

    def test_serialize_deserialize_roundtrip(self):
        session = self._make_session()
        data = session.serialize()
        restored = JumpSession.deserialize(data)
        self.assertEqual(restored.session_id, session.session_id)
        self.assertEqual(restored.source_device, session.source_device)
        self.assertEqual(restored.cwd, session.cwd)
        self.assertEqual(restored.env, session.env)
        self.assertEqual(restored.clipboard, session.clipboard)
        self.assertEqual(restored.metadata, session.metadata)

    def test_serialize_is_compressed(self):
        session = self._make_session()
        data = session.serialize()
        # gzip magic number
        self.assertTrue(data[:2] == b"\x1f\x8b")

    def test_compute_checksum_deterministic(self):
        session = self._make_session()
        c1 = session.compute_checksum()
        c2 = session.compute_checksum()
        self.assertEqual(c1, c2)
        self.assertEqual(len(c1), 64)  # SHA-256 hex

    def test_validate_no_checksum(self):
        session = self._make_session()
        session.checksum = ""
        self.assertTrue(session.validate())

    def test_validate_correct_checksum(self):
        session = self._make_session()
        session.checksum = session.compute_checksum()
        self.assertTrue(session.validate())

    def test_validate_wrong_checksum(self):
        session = self._make_session()
        session.checksum = "wrong" * 16
        self.assertFalse(session.validate())

    def test_serialize_excludes_checksum(self):
        session = self._make_session()
        session.checksum = "should_not_appear"
        data = session.serialize()
        raw = gzip.decompress(data).decode()
        self.assertNotIn("should_not_appear", raw)

    def test_with_files(self):
        content = b"file content here"
        b64 = base64.b64encode(content).decode()
        session = self._make_session(files={"test.txt": b64})
        data = session.serialize()
        restored = JumpSession.deserialize(data)
        self.assertIn("test.txt", restored.files)
        self.assertEqual(base64.b64decode(restored.files["test.txt"]), content)


class TestCaptureSession(unittest.TestCase):
    """Test capture_session function."""

    def test_capture_basic(self):
        session = capture_session("cap-1", "my-device")
        self.assertEqual(session.session_id, "cap-1")
        self.assertEqual(session.source_device, "my-device")
        self.assertIsInstance(session.timestamp, float)
        self.assertTrue(session.cwd)
        self.assertTrue(session.checksum)

    def test_capture_no_env(self):
        session = capture_session("cap-2", "dev", include_env=False)
        self.assertEqual(session.env, {})

    def test_capture_with_env(self):
        session = capture_session("cap-3", "dev", include_env=True)
        # Should only include safe env vars
        for key in session.env:
            safe_prefixes = ("HOME", "USER", "SHELL", "LANG", "TERM",
                             "PATH", "PWD", "EDITOR", "VISUAL", "DISPLAY")
            self.assertTrue(
                any(key.startswith(p) for p in safe_prefixes),
                f"Unexpected env var captured: {key}",
            )

    def test_capture_with_files(self):
        with tempfile.NamedTemporaryFile(dir=".", suffix=".txt", delete=False) as f:
            f.write(b"test content")
            fname = f.name
        try:
            session = capture_session("cap-4", "dev", include_files=[fname])
            rel = str(Path(fname).resolve().relative_to(Path.cwd().resolve()))
            self.assertIn(rel, session.files)
        finally:
            os.unlink(fname)

    def test_capture_skips_missing_file(self):
        session = capture_session("cap-5", "dev",
                                  include_files=["/nonexistent/file.txt"])
        self.assertEqual(session.files, {})

    def test_capture_metadata(self):
        session = capture_session("cap-6", "dev",
                                  extra_metadata={"custom": "data"})
        self.assertEqual(session.metadata["custom"], "data")


class TestRestoreSession(unittest.TestCase):
    """Test restore_session function."""

    def test_restore_rejects_bad_checksum(self):
        session = JumpSession(
            session_id="bad",
            source_device="dev",
            checksum="definitely_wrong_checksum_value_here",
        )
        with self.assertRaises(ValueError):
            restore_session(session)

    def test_restore_env_blocks_dangerous(self):
        session = JumpSession(
            session_id="env-test",
            source_device="dev",
            env={"LD_PRELOAD": "/evil.so", "HOME": "/safe"},
        )
        session.checksum = session.compute_checksum()
        restore_session(session, restore_env=True)
        self.assertNotEqual(os.environ.get("LD_PRELOAD"), "/evil.so")

    def test_restore_files(self):
        content = b"restored content"
        b64 = base64.b64encode(content).decode()
        session = JumpSession(
            session_id="file-test",
            source_device="dev",
            files={"subdir/restored.txt": b64},
        )
        session.checksum = session.compute_checksum()

        with tempfile.TemporaryDirectory() as tmpdir:
            restore_session(session, restore_files=True, target_dir=tmpdir)
            restored_path = Path(tmpdir) / "subdir" / "restored.txt"
            self.assertTrue(restored_path.exists())
            self.assertEqual(restored_path.read_bytes(), content)

    def test_restore_blocks_path_traversal(self):
        b64 = base64.b64encode(b"evil").decode()
        session = JumpSession(
            session_id="traversal",
            source_device="dev",
            files={"../../etc/passwd": b64},
        )
        session.checksum = session.compute_checksum()

        with tempfile.TemporaryDirectory() as tmpdir:
            restore_session(session, restore_files=True, target_dir=tmpdir)
            # File should NOT be created outside tmpdir
            self.assertFalse(Path("/etc/passwd_evil").exists())

    def test_restore_blocks_absolute_path(self):
        b64 = base64.b64encode(b"evil").decode()
        session = JumpSession(
            session_id="abs",
            source_device="dev",
            files={"/tmp/evil_file": b64},
        )
        session.checksum = session.compute_checksum()

        with tempfile.TemporaryDirectory() as tmpdir:
            restore_session(session, restore_files=True, target_dir=tmpdir)
            self.assertFalse(Path("/tmp/evil_file").exists())


class TestTransferState(unittest.TestCase):
    """Test TransferState tracking."""

    def test_initial_state(self):
        ts = TransferState(
            session_id="ts-1",
            total_size=1000,
            checksum="abc",
        )
        self.assertFalse(ts.is_complete)
        self.assertAlmostEqual(ts.progress, 0.0)

    def test_progress_tracking(self):
        ts = TransferState(session_id="ts-2", total_size=100, checksum="x")
        ts.buffer.extend(b"x" * 50)
        self.assertAlmostEqual(ts.progress, 0.5)

    def test_is_complete(self):
        ts = TransferState(session_id="ts-3", total_size=10, checksum="x")
        ts.buffer.extend(b"x" * 10)
        self.assertTrue(ts.is_complete)

    def test_zero_size(self):
        ts = TransferState(session_id="ts-4", total_size=0, checksum="x")
        self.assertAlmostEqual(ts.progress, 1.0)

    def test_to_resume_info(self):
        ts = TransferState(session_id="ts-5", total_size=1000, checksum="abc")
        ts.last_acked_offset = 500
        ts.last_acked_seq = 7
        ts.buffer.extend(b"x" * 500)
        info = ts.to_resume_info()
        self.assertEqual(info["session_id"], "ts-5")
        self.assertEqual(info["resume_offset"], 500)
        self.assertEqual(info["resume_seq"], 7)
        self.assertEqual(info["received_size"], 500)


class TestTransferStateStore(unittest.TestCase):
    """Test TransferStateStore with TTL eviction."""

    def test_get_or_create(self):
        store = TransferStateStore(ttl=300)
        state = store.get_or_create("s1", 1000, "checksum1")
        self.assertEqual(state.session_id, "s1")
        self.assertEqual(state.total_size, 1000)

    def test_get_or_create_returns_existing(self):
        store = TransferStateStore(ttl=300)
        s1 = store.get_or_create("s1", 1000, "c1")
        s1.buffer.extend(b"partial")
        s2 = store.get_or_create("s1", 1000, "c1")
        self.assertIs(s1, s2)
        self.assertEqual(len(s2.buffer), len(b"partial"))

    def test_get_nonexistent(self):
        store = TransferStateStore(ttl=300)
        self.assertIsNone(store.get("nonexistent"))

    def test_remove(self):
        store = TransferStateStore(ttl=300)
        store.get_or_create("s1", 100, "c1")
        store.remove("s1")
        self.assertIsNone(store.get("s1"))

    def test_ttl_eviction(self):
        store = TransferStateStore(ttl=0.0)  # Immediate expiry
        state = store.get_or_create("s1", 100, "c1")
        state.created_at = time.time() - 1  # Force expiry
        self.assertIsNone(store.get("s1"))


class TestMultiJumpResult(unittest.TestCase):
    """Test MultiJumpResult aggregation."""

    def _make_result(self, successes, failures):
        dev = Device("d", "dev", "1.2.3.4", Transport.WIFI)
        targets = []
        for _ in range(successes):
            targets.append(TargetResult(device=dev, success=True, elapsed=1.0))
        for _ in range(failures):
            targets.append(TargetResult(device=dev, success=False,
                                        elapsed=2.0, error="fail"))
        return MultiJumpResult(
            strategy=MultiJumpStrategy.BROADCAST,
            session_id="test",
            targets=targets,
            started=100.0,
            finished=105.0,
        )

    def test_succeeded_and_failed(self):
        r = self._make_result(3, 2)
        self.assertEqual(len(r.succeeded), 3)
        self.assertEqual(len(r.failed), 2)

    def test_all_ok(self):
        self.assertTrue(self._make_result(3, 0).all_ok)
        self.assertFalse(self._make_result(2, 1).all_ok)

    def test_any_ok(self):
        self.assertTrue(self._make_result(1, 2).any_ok)
        self.assertFalse(self._make_result(0, 2).any_ok)

    def test_total_elapsed(self):
        r = self._make_result(1, 0)
        self.assertAlmostEqual(r.total_elapsed, 5.0)

    def test_summary(self):
        r = self._make_result(2, 1)
        s = r.summary()
        self.assertIn("BROADCAST", s)
        self.assertIn("2/3", s)


if __name__ == "__main__":
    unittest.main()
