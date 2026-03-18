"""Tests for cross-device jumping system."""

import importlib.util
import gzip
import hashlib
import json
import os
import socket
import struct
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

CRYPTOGRAPHY_AVAILABLE = importlib.util.find_spec("cryptography") is not None

from device_discovery import (
    Device, Transport, DiscoveryManager, WiFiDiscovery, BluetoothDiscovery,
    _build_announce, _parse_announce, MAGIC,
)
if CRYPTOGRAPHY_AVAILABLE:
    from jump_protocol import (
    MsgType, encode_frame, decode_frame, ProtocolError,
    generate_keypair, derive_session_keys, SessionKeys,
    JumpConnection, JumpListener,
    client_handshake, server_handshake,
    HEADER_MAGIC, PROTOCOL_VERSION,
)
    from session_jumper import (
    JumpSession, capture_session, restore_session,
    send_session, receive_session, JumpNode,
)

else:
    MsgType = encode_frame = decode_frame = ProtocolError = None
    generate_keypair = derive_session_keys = SessionKeys = None
    JumpConnection = JumpListener = None
    client_handshake = server_handshake = None
    HEADER_MAGIC = PROTOCOL_VERSION = None
    JumpSession = capture_session = restore_session = None
    send_session = receive_session = JumpNode = None


# ── Device Discovery Tests ───────────────────────────────────────────────────

class TestDevice(unittest.TestCase):
    def test_device_creation(self):
        dev = Device(
            device_id="abc123",
            name="TestDevice",
            address="192.168.1.100",
            transport=Transport.WIFI,
            port=47701,
            last_seen=time.time(),
        )
        self.assertEqual(dev.device_id, "abc123")
        self.assertEqual(dev.transport, Transport.WIFI)
        self.assertFalse(dev.is_stale)

    def test_device_stale(self):
        dev = Device(
            device_id="old",
            name="OldDevice",
            address="10.0.0.1",
            transport=Transport.BLUETOOTH,
            last_seen=time.time() - 60,
        )
        self.assertTrue(dev.is_stale)

    def test_device_to_dict_bluetooth(self):
        dev = Device(
            device_id="bt1",
            name="Earbuds",
            address="AA:BB:CC:DD:EE:FF",
            transport=Transport.BLUETOOTH,
            last_seen=1234.5,
            capabilities=["jump"],
        )
        restored = Device.from_dict(dev.to_dict())
        self.assertEqual(restored.transport, Transport.BLUETOOTH)
        self.assertEqual(restored.address, dev.address)

    def test_device_to_dict_roundtrip(self):
        dev = Device(
            device_id="rt1",
            name="RoundTrip",
            address="192.168.1.5",
            transport=Transport.WIFI,
            port=8080,
            last_seen=1000.0,
            capabilities=["jump"],
        )
        d = dev.to_dict()
        self.assertEqual(d["transport"], "wifi")
        restored = Device.from_dict(d)
        self.assertEqual(restored.device_id, dev.device_id)
        self.assertEqual(restored.transport, Transport.WIFI)


class TestAnnounceProtocol(unittest.TestCase):
    def test_build_and_parse(self):
        msg = _build_announce("node1", "MyPC", 47701, ["jump"])
        result = _parse_announce(msg)
        self.assertIsNotNone(result)
        self.assertEqual(result["id"], "node1")
        self.assertEqual(result["name"], "MyPC")
        self.assertEqual(result["port"], 47701)
        self.assertEqual(result["caps"], ["jump"])

    def test_parse_invalid(self):
        self.assertIsNone(_parse_announce(b"garbage"))
        self.assertIsNone(_parse_announce(b"JUM"))
        self.assertIsNone(_parse_announce(MAGIC + b"\x00"))

    def test_parse_corrupted_json(self):
        bad = MAGIC + struct.pack("!H", 5) + b"xxxxx"
        self.assertIsNone(_parse_announce(bad))


class TestBluetoothDiscovery(unittest.TestCase):
    def test_no_bluetooth_returns_empty(self):
        bt = BluetoothDiscovery("node1")
        # Without PyBluez installed, should return empty
        devices = bt.get_devices()
        self.assertEqual(devices, [])


class TestWiFiDiscovery(unittest.TestCase):
    def test_init(self):
        wifi = WiFiDiscovery("n1", "test", 47701)
        self.assertEqual(wifi.node_id, "n1")
        self.assertEqual(wifi.node_name, "test")

    def test_get_devices_empty(self):
        wifi = WiFiDiscovery("n1", "test", 47701)
        self.assertEqual(wifi.get_devices(), [])


class TestDiscoveryManager(unittest.TestCase):
    def test_init(self):
        dm = DiscoveryManager(node_name="test", listen_port=47701)
        self.assertEqual(dm.node_name, "test")
        self.assertIsNotNone(dm.node_id)
        self.assertEqual(len(dm.node_id), 16)

    def test_discovery_manager_node_id_stable(self):
        dm = DiscoveryManager(node_name="stable", listen_port=47701)
        self.assertEqual(dm.node_id, dm.node_id)
        self.assertEqual(len(dm.node_id), 16)


# ── Protocol Tests ───────────────────────────────────────────────────────────

@unittest.skipUnless(CRYPTOGRAPHY_AVAILABLE, "cryptography not installed")
class TestFrameEncoding(unittest.TestCase):
    def test_encode_decode_roundtrip(self):
        payload = b"hello world"
        frame = encode_frame(MsgType.HELLO, payload, seq=42)
        msg_type, seq, data = decode_frame(frame)
        self.assertEqual(msg_type, MsgType.HELLO)
        self.assertEqual(seq, 42)
        self.assertEqual(data, payload)

    def test_empty_payload(self):
        frame = encode_frame(MsgType.PING, b"", seq=0)
        msg_type, seq, data = decode_frame(frame)
        self.assertEqual(msg_type, MsgType.PING)
        self.assertEqual(data, b"")

    def test_large_payload(self):
        payload = os.urandom(100_000)
        frame = encode_frame(MsgType.SESSION_DATA, payload, seq=1)
        msg_type, seq, data = decode_frame(frame)
        self.assertEqual(data, payload)

    def test_invalid_magic(self):
        with self.assertRaises(ProtocolError):
            decode_frame(b"XXXX" + b"\x00" * 10 + b"data")

    def test_truncated_frame(self):
        with self.assertRaises(ProtocolError):
            decode_frame(b"JMP\x01" + struct.pack("!BBIH", 1, 1, 0, 100) + b"short")

    def test_bad_version(self):
        frame = b"JMP\x01" + struct.pack("!BBIH", 99, 1, 0, 0)
        with self.assertRaises(ProtocolError):
            decode_frame(frame)


@unittest.skipUnless(CRYPTOGRAPHY_AVAILABLE, "cryptography not installed")
class TestKeyExchange(unittest.TestCase):
    def test_keypair_generation(self):
        priv, pub = generate_keypair()
        self.assertEqual(len(pub), 32)

    def test_key_agreement(self):
        priv_a, pub_a = generate_keypair()
        priv_b, pub_b = generate_keypair()

        keys_a = derive_session_keys(priv_a, pub_b)
        keys_b = derive_session_keys(priv_b, pub_a)

        # Both sides should derive the same shared secret
        self.assertEqual(keys_a.shared_key, keys_b.shared_key)

    def test_encrypt_decrypt(self):
        priv_a, pub_a = generate_keypair()
        priv_b, pub_b = generate_keypair()

        keys_a = derive_session_keys(priv_a, pub_b)
        keys_b = derive_session_keys(priv_b, pub_a)

        plaintext = b"secret session data"
        ciphertext = keys_a.encrypt(plaintext)
        decrypted = keys_b.decrypt(ciphertext)
        self.assertEqual(decrypted, plaintext)

    def test_wrong_key_fails(self):
        priv_a, pub_a = generate_keypair()
        priv_b, pub_b = generate_keypair()
        priv_c, pub_c = generate_keypair()

        keys_a = derive_session_keys(priv_a, pub_b)
        keys_c = derive_session_keys(priv_c, pub_a)  # wrong key pair

        ciphertext = keys_a.encrypt(b"test")
        with self.assertRaises(Exception):
            keys_c.decrypt(ciphertext)


# ── Handshake Integration Test (loopback) ────────────────────────────────────

@unittest.skipUnless(CRYPTOGRAPHY_AVAILABLE, "cryptography not installed")
class TestHandshake(unittest.TestCase):
    def test_full_handshake(self):
        """Test client ↔ server handshake over a real socket pair."""
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind(("127.0.0.1", 0))
        port = server_sock.getsockname()[1]
        server_sock.listen(1)

        server_conn = [None]
        server_err = [None]

        def server_side():
            try:
                client, _ = server_sock.accept()
                server_conn[0] = server_handshake(client)
            except Exception as e:
                server_err[0] = e

        t = threading.Thread(target=server_side)
        t.start()

        client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_sock.connect(("127.0.0.1", port))
        client_conn = client_handshake(client_sock, "test-node")

        t.join(timeout=5)
        self.assertIsNone(server_err[0], f"Server error: {server_err[0]}")
        self.assertIsNotNone(server_conn[0])

        # Test encrypted communication
        client_conn.send(MsgType.PING, b"hello from client")
        msg_type, data = server_conn[0].recv()
        self.assertEqual(msg_type, MsgType.PING)
        self.assertEqual(data, b"hello from client")

        server_conn[0].send(MsgType.PONG, b"hello from server")
        msg_type, data = client_conn.recv()
        self.assertEqual(msg_type, MsgType.PONG)
        self.assertEqual(data, b"hello from server")

        client_conn.close()
        server_conn[0].close()
        server_sock.close()

    def test_handshake_with_auth(self):
        """Test handshake with authentication."""
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind(("127.0.0.1", 0))
        port = server_sock.getsockname()[1]
        server_sock.listen(1)

        token = "secret-token-123"
        server_conn = [None]

        def server_side():
            client, _ = server_sock.accept()
            server_conn[0] = server_handshake(
                client, auth_validator=lambda t: t == token
            )

        t = threading.Thread(target=server_side)
        t.start()

        client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_sock.connect(("127.0.0.1", port))
        conn = client_handshake(client_sock, "test", auth_token=token)

        t.join(timeout=5)
        self.assertIsNotNone(server_conn[0])
        conn.close()
        server_conn[0].close()
        server_sock.close()


# ── Session Tests ────────────────────────────────────────────────────────────

@unittest.skipUnless(CRYPTOGRAPHY_AVAILABLE, "cryptography not installed")
class TestJumpSession(unittest.TestCase):
    def test_serialize_deserialize(self):
        session = JumpSession(
            session_id="test-1",
            source_device="dev-a",
            timestamp=time.time(),
            cwd="/home/user",
            env={"HOME": "/home/user"},
            metadata={"key": "value"},
        )
        data = session.serialize()
        restored = JumpSession.deserialize(data)
        self.assertEqual(restored.session_id, "test-1")
        self.assertEqual(restored.cwd, "/home/user")
        self.assertEqual(restored.metadata["key"], "value")

    def test_checksum(self):
        session = JumpSession(
            session_id="ck-1",
            source_device="dev-b",
        )
        cs = session.compute_checksum()
        self.assertEqual(len(cs), 64)  # SHA-256 hex
        # Checksum should be deterministic
        self.assertEqual(cs, session.compute_checksum())

    def test_validate_good(self):
        session = JumpSession(session_id="v1", source_device="d1")
        session.checksum = session.compute_checksum()
        self.assertTrue(session.validate())

    def test_validate_bad(self):
        session = JumpSession(session_id="v2", source_device="d2")
        session.checksum = "wrong"
        self.assertFalse(session.validate())

    def test_compression(self):
        big_env = {f"VAR_{i}": f"value_{i}" * 100 for i in range(50)}
        session = JumpSession(
            session_id="compress-test",
            source_device="d1",
            env=big_env,
        )
        data = session.serialize()
        raw = json.dumps({"session_id": "compress-test", "source_device": "d1",
                          "env": big_env}, sort_keys=True).encode()
        # Compressed should be smaller than raw
        self.assertLess(len(data), len(raw))


@unittest.skipUnless(CRYPTOGRAPHY_AVAILABLE, "cryptography not installed")
class TestCaptureRestore(unittest.TestCase):
    def test_capture_session(self):
        session = capture_session("cap-1", "dev-1")
        self.assertEqual(session.session_id, "cap-1")
        self.assertEqual(session.cwd, os.getcwd())
        self.assertIn("HOME", session.env)
        self.assertTrue(session.validate())

    def test_capture_nonexistent_file(self):
        session = capture_session("cap-missing", "dev-2", include_files=["/definitely/missing.txt"])
        self.assertEqual(session.files, {})

    def test_capture_with_files(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt",
                                         delete=False) as f:
            f.write("test content")
            fpath = f.name

        try:
            session = capture_session("cap-2", "dev-2",
                                      include_files=[fpath])
            self.assertIn(fpath, session.files)
        finally:
            os.unlink(fpath)

    def test_restore_files(self):
        import base64
        with tempfile.TemporaryDirectory() as tmpdir:
            session = JumpSession(
                session_id="restore-1",
                source_device="d1",
                files={"test.txt": base64.b64encode(b"restored!").decode()},
            )
            restore_session(session, restore_files=True, target_dir=tmpdir)
            restored = Path(tmpdir) / "test.txt"
            self.assertTrue(restored.exists())
            self.assertEqual(restored.read_text(), "restored!")

    def test_restore_checksum_error(self):
        session = JumpSession(
            session_id="bad-ck",
            source_device="d1",
            checksum="definitely_wrong",
        )
        with self.assertRaises(ValueError):
            restore_session(session)


# ── End-to-end Session Transfer Test ─────────────────────────────────────────

@unittest.skipUnless(CRYPTOGRAPHY_AVAILABLE, "cryptography not installed")
class TestReceiveSessionValidation(unittest.TestCase):
    def test_session_missing_separator(self):
        conn = MagicMock()
        meta = {"meta": {"size": 4, "checksum": None}}
        conn.recv_json.return_value = (MsgType.SESSION_DATA, meta)
        conn.recv.return_value = (MsgType.FILE_CHUNK, b"abcd")

        with self.assertRaisesRegex(ValueError, "missing separator"):
            receive_session(conn)


@unittest.skipUnless(CRYPTOGRAPHY_AVAILABLE, "cryptography not installed")
class TestSessionTransfer(unittest.TestCase):
    def test_send_receive_session(self):
        """Full end-to-end: handshake + send session + receive session."""
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind(("127.0.0.1", 0))
        port = server_sock.getsockname()[1]
        server_sock.listen(1)

        received = [None]
        errors = [None]

        def server_side():
            try:
                client, _ = server_sock.accept()
                conn = server_handshake(client)
                received[0] = receive_session(conn)
                conn.close()
            except Exception as e:
                errors[0] = e

        t = threading.Thread(target=server_side)
        t.start()

        # Client side
        session = JumpSession(
            session_id="e2e-test",
            source_device="sender",
            timestamp=time.time(),
            cwd="/tmp/test",
            env={"FOO": "bar"},
            metadata={"purpose": "testing"},
        )
        session.checksum = session.compute_checksum()

        client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_sock.connect(("127.0.0.1", port))
        conn = client_handshake(client_sock, "sender-node")
        ok = send_session(conn, session)
        conn.close()

        t.join(timeout=10)
        server_sock.close()

        self.assertIsNone(errors[0], f"Server error: {errors[0]}")
        self.assertTrue(ok)
        self.assertIsNotNone(received[0])
        self.assertEqual(received[0].session_id, "e2e-test")
        self.assertEqual(received[0].cwd, "/tmp/test")
        self.assertEqual(received[0].env["FOO"], "bar")
        self.assertEqual(received[0].metadata["purpose"], "testing")


if __name__ == "__main__":
    unittest.main()
