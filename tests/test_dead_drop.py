"""Tests for dead_drop.py — Cloud dead-drop transport backend."""

import os
import shutil
import tempfile
import threading
import time
import unittest
from unittest.mock import patch, MagicMock

from matrix.dead_drop import (
    CloudProvider,
    DeadDropConfig,
    FileSystemDeadDrop,
    S3DeadDrop,
    DeadDropBackend,
    DeadDropError,
)


# ── CloudProvider Enum ────────────────────────────────────────────────────────

class TestCloudProvider(unittest.TestCase):

    def test_s3_value(self):
        self.assertEqual(CloudProvider.S3.value, "s3")

    def test_gcs_value(self):
        self.assertEqual(CloudProvider.GCS.value, "gcs")

    def test_azure_value(self):
        self.assertEqual(CloudProvider.AZURE.value, "azure")

    def test_filesystem_value(self):
        self.assertEqual(CloudProvider.FILESYSTEM.value, "filesystem")

    def test_all_members(self):
        names = {m.name for m in CloudProvider}
        self.assertEqual(names, {"S3", "GCS", "AZURE", "FILESYSTEM"})


# ── DeadDropConfig ────────────────────────────────────────────────────────────

class TestDeadDropConfig(unittest.TestCase):

    def test_defaults(self):
        cfg = DeadDropConfig(provider=CloudProvider.FILESYSTEM)
        self.assertEqual(cfg.provider, CloudProvider.FILESYSTEM)
        self.assertEqual(cfg.bucket_name, "")
        self.assertEqual(cfg.prefix, "matrix-drops")
        self.assertEqual(cfg.base_path, "")
        self.assertEqual(cfg.poll_interval, 2.0)
        self.assertEqual(cfg.ttl, 300.0)
        self.assertEqual(cfg.credentials, {})

    def test_custom_values(self):
        cfg = DeadDropConfig(
            provider=CloudProvider.S3,
            bucket_name="my-bucket",
            prefix="custom-prefix",
            poll_interval=5.0,
            ttl=60.0,
            credentials={"access_key": "AKIA...", "secret_key": "secret"},
        )
        self.assertEqual(cfg.bucket_name, "my-bucket")
        self.assertEqual(cfg.prefix, "custom-prefix")
        self.assertEqual(cfg.poll_interval, 5.0)
        self.assertEqual(cfg.ttl, 60.0)
        self.assertIn("access_key", cfg.credentials)


# ── FileSystemDeadDrop ────────────────────────────────────────────────────────

class TestFileSystemDeadDrop(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="dead_drop_test_")
        self.adapter = FileSystemDeadDrop(self.tmpdir)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_write_and_read(self):
        self.adapter.write("msgs/hello.bin", b"hello world")
        data = self.adapter.read("msgs/hello.bin")
        self.assertEqual(data, b"hello world")

    def test_write_creates_subdirs(self):
        self.adapter.write("deep/nested/path/file.bin", b"data")
        data = self.adapter.read("deep/nested/path/file.bin")
        self.assertEqual(data, b"data")

    def test_read_nonexistent_raises(self):
        with self.assertRaises(DeadDropError) as ctx:
            self.adapter.read("nonexistent/file.bin")
        self.assertIn("not found", str(ctx.exception))

    def test_list_objects_empty(self):
        result = self.adapter.list_objects("no_such_prefix")
        self.assertEqual(result, [])

    def test_list_objects(self):
        self.adapter.write("inbox/msg_001.bin", b"a")
        self.adapter.write("inbox/msg_002.bin", b"b")
        self.adapter.write("inbox/msg_003.bin", b"c")
        keys = self.adapter.list_objects("inbox")
        self.assertEqual(len(keys), 3)
        # Should be sorted
        self.assertEqual(keys, sorted(keys))
        self.assertIn("inbox/msg_001.bin", keys)
        self.assertIn("inbox/msg_003.bin", keys)

    def test_delete(self):
        self.adapter.write("to_delete.bin", b"gone")
        self.adapter.delete("to_delete.bin")
        with self.assertRaises(DeadDropError):
            self.adapter.read("to_delete.bin")

    def test_delete_nonexistent_is_noop(self):
        # Should not raise
        self.adapter.delete("does_not_exist.bin")

    def test_write_overwrite(self):
        self.adapter.write("file.bin", b"version1")
        self.adapter.write("file.bin", b"version2")
        self.assertEqual(self.adapter.read("file.bin"), b"version2")

    def test_write_empty_data(self):
        self.adapter.write("empty.bin", b"")
        self.assertEqual(self.adapter.read("empty.bin"), b"")


# ── Mailbox Path Construction ─────────────────────────────────────────────────

class TestMailboxPaths(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="dead_drop_mbox_")
        cfg = DeadDropConfig(
            provider=CloudProvider.FILESYSTEM,
            base_path=self.tmpdir,
            prefix="matrix-drops",
            poll_interval=999,  # very long to avoid background polls during test
        )
        self.backend = DeadDropBackend(cfg, "alice", "bob")

    def tearDown(self):
        self.backend.close()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_inbox_path_local(self):
        path = self.backend._inbox_path("alice")
        self.assertEqual(path, "matrix-drops/alice/inbox")

    def test_inbox_path_remote(self):
        path = self.backend._inbox_path("bob")
        self.assertEqual(path, "matrix-drops/bob/inbox")


# ── S3DeadDrop Signing ────────────────────────────────────────────────────────

class TestS3Signing(unittest.TestCase):

    def test_sign_v4_produces_authorization_header(self):
        s3 = S3DeadDrop(
            bucket="test-bucket",
            region="us-west-2",
            access_key="AKIAIOSFODNN7EXAMPLE",
            secret_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        )
        headers = {"Host": "test-bucket.s3.us-west-2.amazonaws.com"}
        result = s3._sign_v4("GET", "/test-key", headers, b"")

        self.assertIn("Authorization", result)
        auth = result["Authorization"]
        self.assertTrue(auth.startswith("AWS4-HMAC-SHA256"))
        self.assertIn("Credential=AKIAIOSFODNN7EXAMPLE/", auth)
        self.assertIn("SignedHeaders=", auth)
        self.assertIn("Signature=", auth)
        self.assertIn("us-west-2", auth)
        self.assertIn("s3", auth)
        self.assertIn("aws4_request", auth)

    def test_sign_v4_sets_amz_date(self):
        s3 = S3DeadDrop(
            bucket="b",
            region="eu-west-1",
            access_key="AK",
            secret_key="SK",
        )
        headers = {"Host": "b.s3.eu-west-1.amazonaws.com"}
        result = s3._sign_v4("PUT", "/obj", headers, b"payload")
        self.assertIn("x-amz-date", result)
        # Format: YYYYMMDDTHHMMSSZ
        self.assertRegex(result["x-amz-date"], r"^\d{8}T\d{6}Z$")

    def test_sign_v4_sets_content_sha256(self):
        s3 = S3DeadDrop(
            bucket="b",
            region="us-east-1",
            access_key="AK",
            secret_key="SK",
        )
        headers = {"Host": "b.s3.us-east-1.amazonaws.com"}
        payload = b"test data"
        result = s3._sign_v4("PUT", "/key", headers, payload)
        self.assertIn("x-amz-content-sha256", result)
        import hashlib
        expected = hashlib.sha256(payload).hexdigest()
        self.assertEqual(result["x-amz-content-sha256"], expected)


# ── DeadDropBackend ───────────────────────────────────────────────────────────

class TestDeadDropBackend(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="dead_drop_backend_")
        cfg = DeadDropConfig(
            provider=CloudProvider.FILESYSTEM,
            base_path=self.tmpdir,
            prefix="drops",
            poll_interval=999,  # very long to suppress background polling
        )
        self.backend = DeadDropBackend(cfg, "node-A", "node-B")

    def tearDown(self):
        self.backend.close()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_peer_address(self):
        self.assertEqual(self.backend.peer_address, "dead-drop:node-B")

    def test_transport_name(self):
        self.assertEqual(self.backend.transport_name, "dead-drop")

    def test_is_connected_initially_true(self):
        self.assertTrue(self.backend.is_connected)

    def test_close_disconnects(self):
        self.backend.close()
        self.assertFalse(self.backend.is_connected)

    def test_close_stops_polling(self):
        self.backend.close()
        self.assertFalse(self.backend._poll_running)

    def test_send_bytes_writes_to_remote_inbox(self):
        self.backend.send_bytes(b"secret message")
        # Verify a file was written in node-B's inbox
        adapter = self.backend._adapter
        keys = adapter.list_objects("drops/node-B/inbox")
        self.assertEqual(len(keys), 1)
        data = adapter.read(keys[0])
        self.assertEqual(data, b"secret message")

    def test_recv_bytes_reads_from_local_inbox(self):
        # Simulate an incoming message by writing directly to node-A's inbox
        adapter = self.backend._adapter
        adapter.write("drops/node-A/inbox/test_msg.bin", b"incoming data")
        # Manually trigger a poll instead of waiting for the background thread
        self.backend._poll_inbox()
        result = self.backend.recv_bytes(13)
        self.assertEqual(result, b"incoming data")

    def test_send_after_close_raises(self):
        self.backend.close()
        with self.assertRaises(DeadDropError):
            self.backend.send_bytes(b"fail")

    def test_recv_after_close_raises(self):
        self.backend.close()
        with self.assertRaises(DeadDropError):
            self.backend.recv_bytes(1)

    def test_send_bytes_multiple_messages(self):
        self.backend.send_bytes(b"msg1")
        self.backend.send_bytes(b"msg2")
        adapter = self.backend._adapter
        keys = adapter.list_objects("drops/node-B/inbox")
        self.assertEqual(len(keys), 2)


# ── DeadDropBackend with unsupported provider ─────────────────────────────────

class TestDeadDropUnsupported(unittest.TestCase):

    def test_unsupported_provider_raises(self):
        cfg = DeadDropConfig(provider=CloudProvider.GCS)
        with self.assertRaises(DeadDropError) as ctx:
            DeadDropBackend(cfg, "a", "b")
        self.assertIn("unsupported provider", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
