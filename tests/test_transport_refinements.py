"""Regression tests for transport refinements (ws frame caps + fragmentation,
dead-drop TTL / dedup / path-safety)."""
import struct
import time
import unittest
from unittest.mock import MagicMock

from matrix.transport_ws import (
    WebSocketBackend, _ws_read_frame, WS_BINARY, WS_CONTINUATION, WS_MAX_FRAME,
)
from matrix.dead_drop import (
    DeadDropBackend, DeadDropConfig, CloudProvider, FileSystemDeadDrop, DeadDropError,
)


def _frame(opcode, payload, fin=True):
    b = bytearray()
    b.append((0x80 if fin else 0) | opcode)
    ln = len(payload)
    if ln < 126:
        b.append(ln)
    elif ln < 65536:
        b.append(126); b.extend(struct.pack("!H", ln))
    else:
        b.append(127); b.extend(struct.pack("!Q", ln))
    b.extend(payload)
    return bytes(b)


class TestWsFrameCaps(unittest.TestCase):
    def test_oversized_frame_rejected(self):
        # header claims a 64-bit length larger than the cap
        header = bytes([0x82, 127]) + struct.pack("!Q", WS_MAX_FRAME + 1)
        buf = bytearray(header)
        with self.assertRaises(ConnectionError):
            _ws_read_frame(MagicMock(), buf)

    def test_oversized_control_frame_rejected(self):
        # ping with >125 byte payload is illegal
        header = bytes([0x89, 126]) + struct.pack("!H", 200)
        buf = bytearray(header + b"x" * 200)
        with self.assertRaises(ConnectionError):
            _ws_read_frame(MagicMock(), buf)


class TestWsFragmentation(unittest.TestCase):
    def test_fragmented_message_reassembles(self):
        frames = _frame(WS_BINARY, b"hel", fin=False) + _frame(WS_CONTINUATION, b"lo", fin=True)
        be = WebSocketBackend(MagicMock(), is_client=False, initial_buf=bytearray(frames))
        self.assertEqual(be.recv_bytes(5), b"hello")

    def test_initial_buf_not_double_counted(self):
        frame = _frame(WS_BINARY, b"abcd", fin=True)
        be = WebSocketBackend(MagicMock(), is_client=False, initial_buf=bytearray(frame))
        self.assertEqual(be.recv_bytes(4), b"abcd")  # exactly the payload, no raw bytes


class TestDeadDropSafety(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.base = tempfile.mkdtemp()

    def test_sibling_path_traversal_blocked(self):
        fs = FileSystemDeadDrop(self.base)
        with self.assertRaises(DeadDropError):
            fs._safe_resolve("../" + self.base.rsplit("/", 1)[-1] + "-evil/x")

    def test_ttl_expires_stale_messages(self):
        cfg = DeadDropConfig(provider=CloudProvider.FILESYSTEM, base_path=self.base,
                             poll_interval=0.05, ttl=1.0)
        be = DeadDropBackend(cfg, "me", "peer")
        try:
            fs = be._adapter
            # write a message with an old timestamp embedded in the key
            old_key = f"matrix-drops/me/inbox/{time.time() - 9999:.6f}_dead.bin"
            fs.write(old_key, b"STALE")
            time.sleep(0.2)
            # stale message should be deleted, never delivered
            self.assertNotIn(b"STALE", bytes(be._recv_buffer))
            self.assertEqual(fs.list_objects("matrix-drops/me/inbox"), [])
        finally:
            be.close()

    def test_no_duplicate_on_failed_delete(self):
        cfg = DeadDropConfig(provider=CloudProvider.FILESYSTEM, base_path=self.base,
                             poll_interval=0.05, ttl=300.0)
        be = DeadDropBackend(cfg, "me", "peer")
        try:
            fs = be._adapter
            real_delete = fs.delete
            fs.delete = MagicMock(side_effect=DeadDropError("delete blip"))
            fs.write(f"matrix-drops/me/inbox/{time.time():.6f}_a.bin", b"HELLO")
            # Wait for at least one delivery (delete keeps failing throughout),
            # then a few more poll cycles to prove the bytes aren't re-delivered.
            deadline = time.time() + 5.0
            while not be._recv_buffer and time.time() < deadline:
                time.sleep(0.02)
            time.sleep(0.2)  # extra poll cycles with the delete still failing
            self.assertEqual(bytes(be._recv_buffer), b"HELLO")  # delivered exactly once
            fs.delete = real_delete
        finally:
            be.close()


if __name__ == "__main__":
    unittest.main()
