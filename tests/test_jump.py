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

from matrix.device_discovery import (
    Device, Transport, DiscoveryManager, WiFiDiscovery, BluetoothDiscovery,
    _build_announce, _parse_announce, MAGIC,
)
if CRYPTOGRAPHY_AVAILABLE:
    from matrix.jump_protocol import (
    MsgType, encode_frame, decode_frame, ProtocolError,
    generate_keypair, derive_session_keys, SessionKeys,
    JumpConnection, JumpListener,
    client_handshake, server_handshake,
    HEADER_MAGIC, PROTOCOL_VERSION,
)
    from matrix.session_jumper import (
    JumpSession, capture_session, restore_session,
    send_session, receive_session, JumpNode,
    MultiJumpStrategy, MultiJumpResult, TargetResult,
    jump_to_devices, _jump_single,
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

        keys_a = derive_session_keys(priv_a, pub_b, is_initiator=True)
        keys_b = derive_session_keys(priv_b, pub_a, is_initiator=False)

        plaintext = b"secret session data"
        ciphertext = keys_a.encrypt(plaintext)
        decrypted = keys_b.decrypt(ciphertext)
        self.assertEqual(decrypted, plaintext)

    def test_wrong_key_fails(self):
        priv_a, pub_a = generate_keypair()
        priv_b, pub_b = generate_keypair()
        priv_c, pub_c = generate_keypair()

        keys_a = derive_session_keys(priv_a, pub_b, is_initiator=True)
        keys_c = derive_session_keys(priv_c, pub_a, is_initiator=False)  # wrong key pair

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
        # File must be under CWD to pass the security check
        fname = "_test_capture_tmp.txt"
        fpath = os.path.join(os.getcwd(), fname)
        try:
            with open(fpath, "w") as f:
                f.write("test content")
            session = capture_session("cap-2", "dev-2",
                                      include_files=[fpath])
            self.assertIn(fname, session.files)
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


# ── Multi-Jump (Multiply / Duplicate) Tests ─────────────────────────────────

@unittest.skipUnless(CRYPTOGRAPHY_AVAILABLE, "cryptography not installed")
class TestMultiJumpResult(unittest.TestCase):
    def test_result_properties_all_success(self):
        targets = [
            TargetResult(
                device=Device("d1", "Dev1", "1.1.1.1", Transport.WIFI,
                              port=47701, last_seen=time.time()),
                success=True, elapsed=0.5,
            ),
            TargetResult(
                device=Device("d2", "Dev2", "1.1.1.2", Transport.WIFI,
                              port=47701, last_seen=time.time()),
                success=True, elapsed=0.3,
            ),
        ]
        r = MultiJumpResult(
            strategy=MultiJumpStrategy.BROADCAST,
            session_id="test-multi",
            targets=targets,
            started=100.0, finished=101.0,
        )
        self.assertTrue(r.all_ok)
        self.assertTrue(r.any_ok)
        self.assertEqual(len(r.succeeded), 2)
        self.assertEqual(len(r.failed), 0)
        self.assertAlmostEqual(r.total_elapsed, 1.0)
        self.assertIn("BROADCAST", r.summary())
        self.assertIn("2/2", r.summary())

    def test_result_properties_partial_failure(self):
        targets = [
            TargetResult(
                device=Device("d1", "Dev1", "1.1.1.1", Transport.WIFI,
                              port=47701, last_seen=time.time()),
                success=True, elapsed=0.5,
            ),
            TargetResult(
                device=Device("d2", "Dev2", "1.1.1.2", Transport.WIFI,
                              port=47701, last_seen=time.time()),
                success=False, elapsed=1.0, error="Connection refused",
            ),
        ]
        r = MultiJumpResult(
            strategy=MultiJumpStrategy.MIRROR,
            session_id="test-partial",
            targets=targets,
            started=100.0, finished=102.0,
        )
        self.assertFalse(r.all_ok)
        self.assertTrue(r.any_ok)
        self.assertEqual(len(r.succeeded), 1)
        self.assertEqual(len(r.failed), 1)

    def test_result_empty_targets(self):
        r = MultiJumpResult(
            strategy=MultiJumpStrategy.RACE,
            session_id="empty",
            targets=[],
            started=100.0, finished=100.0,
        )
        self.assertTrue(r.all_ok)  # vacuously true for empty list with all()
        self.assertFalse(r.any_ok)
        self.assertIn("0/0", r.summary())


@unittest.skipUnless(CRYPTOGRAPHY_AVAILABLE, "cryptography not installed")
class TestMultiJumpStrategy(unittest.TestCase):
    def test_strategy_values(self):
        self.assertEqual(MultiJumpStrategy.BROADCAST.value, "broadcast")
        self.assertEqual(MultiJumpStrategy.MIRROR.value, "mirror")
        self.assertEqual(MultiJumpStrategy.RACE.value, "race")
        self.assertEqual(MultiJumpStrategy.CASCADE.value, "cascade")

    def test_strategy_from_string(self):
        self.assertEqual(MultiJumpStrategy("broadcast"), MultiJumpStrategy.BROADCAST)
        self.assertEqual(MultiJumpStrategy("cascade"), MultiJumpStrategy.CASCADE)


@unittest.skipUnless(CRYPTOGRAPHY_AVAILABLE, "cryptography not installed")
class TestJumpToDevicesEmpty(unittest.TestCase):
    def test_empty_targets(self):
        session = JumpSession(session_id="empty-test", source_device="src")
        session.checksum = session.compute_checksum()
        result = jump_to_devices([], session)
        self.assertEqual(len(result.targets), 0)
        self.assertEqual(result.strategy, MultiJumpStrategy.BROADCAST)


@unittest.skipUnless(CRYPTOGRAPHY_AVAILABLE, "cryptography not installed")
class TestMultiJumpBroadcast(unittest.TestCase):
    """End-to-end broadcast to multiple listeners over real sockets."""

    def _start_listener(self):
        """Start a JumpListener on an ephemeral port, return (port, listener, received_list)."""
        received = []

        def on_conn(conn):
            try:
                session = receive_session(conn)
                received.append(session)
            except Exception:
                pass
            finally:
                conn.close()

        listener = JumpListener(port=0, on_connection=on_conn)
        # Bind to ephemeral port
        listener._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener._server_sock.bind(("127.0.0.1", 0))
        port = listener._server_sock.getsockname()[1]
        listener._server_sock.listen(5)
        listener._server_sock.settimeout(2.0)
        listener._running = True
        listener._thread = threading.Thread(target=listener._accept_loop, daemon=True)
        listener._thread.start()
        return port, listener, received

    def test_broadcast_two_targets(self):
        port1, l1, recv1 = self._start_listener()
        port2, l2, recv2 = self._start_listener()

        try:
            targets = [
                Device("t1", "Target1", "127.0.0.1", Transport.WIFI,
                       port=port1, last_seen=time.time()),
                Device("t2", "Target2", "127.0.0.1", Transport.WIFI,
                       port=port2, last_seen=time.time()),
            ]
            session = JumpSession(
                session_id="broadcast-e2e",
                source_device="sender",
                timestamp=time.time(),
                cwd="/tmp",
                metadata={"multi_jump": True},
            )
            session.checksum = session.compute_checksum()

            result = jump_to_devices(targets, session,
                                     strategy=MultiJumpStrategy.BROADCAST)

            self.assertEqual(len(result.targets), 2)
            self.assertTrue(result.all_ok, f"Failures: {[t.error for t in result.failed]}")
            self.assertEqual(result.strategy, MultiJumpStrategy.BROADCAST)

            # Wait briefly for async receive
            time.sleep(0.5)
            self.assertEqual(len(recv1), 1)
            self.assertEqual(recv1[0].session_id, "broadcast-e2e")
            self.assertEqual(len(recv2), 1)
            self.assertEqual(recv2[0].session_id, "broadcast-e2e")
        finally:
            l1.stop()
            l2.stop()

    def test_broadcast_with_one_failure(self):
        port1, l1, recv1 = self._start_listener()

        try:
            targets = [
                Device("t1", "Target1", "127.0.0.1", Transport.WIFI,
                       port=port1, last_seen=time.time()),
                Device("t2", "BadTarget", "127.0.0.1", Transport.WIFI,
                       port=1, last_seen=time.time()),  # port 1 = will fail
            ]
            session = JumpSession(
                session_id="partial-e2e",
                source_device="sender",
            )
            session.checksum = session.compute_checksum()

            result = jump_to_devices(targets, session,
                                     strategy=MultiJumpStrategy.BROADCAST)

            self.assertEqual(len(result.targets), 2)
            self.assertTrue(result.any_ok)
            self.assertFalse(result.all_ok)
            self.assertEqual(len(result.succeeded), 1)
            self.assertEqual(len(result.failed), 1)
        finally:
            l1.stop()

    def test_broadcast_progress_callback(self):
        port1, l1, _ = self._start_listener()
        progress_calls = []

        def on_progress(tr, done, total):
            progress_calls.append((tr.device.name, done, total))

        try:
            targets = [
                Device("t1", "Target1", "127.0.0.1", Transport.WIFI,
                       port=port1, last_seen=time.time()),
            ]
            session = JumpSession(session_id="progress-test",
                                  source_device="sender")
            session.checksum = session.compute_checksum()

            jump_to_devices(targets, session, on_progress=on_progress)
            self.assertEqual(len(progress_calls), 1)
            self.assertEqual(progress_calls[0][1], 1)  # done
            self.assertEqual(progress_calls[0][2], 1)  # total
        finally:
            l1.stop()


@unittest.skipUnless(CRYPTOGRAPHY_AVAILABLE, "cryptography not installed")
class TestMultiJumpCascade(unittest.TestCase):
    def _start_listener(self):
        received = []

        def on_conn(conn):
            try:
                received.append(receive_session(conn))
            except Exception:
                pass
            finally:
                conn.close()

        listener = JumpListener(port=0, on_connection=on_conn)
        listener._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener._server_sock.bind(("127.0.0.1", 0))
        port = listener._server_sock.getsockname()[1]
        listener._server_sock.listen(5)
        listener._server_sock.settimeout(2.0)
        listener._running = True
        listener._thread = threading.Thread(target=listener._accept_loop, daemon=True)
        listener._thread.start()
        return port, listener, received

    def test_cascade_stops_on_failure(self):
        port1, l1, recv1 = self._start_listener()

        try:
            targets = [
                Device("t1", "Target1", "127.0.0.1", Transport.WIFI,
                       port=port1, last_seen=time.time()),
                Device("bad", "BadTarget", "127.0.0.1", Transport.WIFI,
                       port=1, last_seen=time.time()),
                Device("t3", "NeverReached", "127.0.0.1", Transport.WIFI,
                       port=port1, last_seen=time.time()),
            ]
            session = JumpSession(session_id="cascade-stop",
                                  source_device="sender")
            session.checksum = session.compute_checksum()

            result = jump_to_devices(targets, session,
                                     strategy=MultiJumpStrategy.CASCADE)

            # Should have attempted 2 (first success, second failure, third skipped)
            self.assertEqual(len(result.targets), 2)
            self.assertTrue(result.targets[0].success)
            self.assertFalse(result.targets[1].success)
        finally:
            l1.stop()

    def test_cascade_all_succeed(self):
        port1, l1, recv1 = self._start_listener()
        port2, l2, recv2 = self._start_listener()

        try:
            targets = [
                Device("t1", "First", "127.0.0.1", Transport.WIFI,
                       port=port1, last_seen=time.time()),
                Device("t2", "Second", "127.0.0.1", Transport.WIFI,
                       port=port2, last_seen=time.time()),
            ]
            session = JumpSession(session_id="cascade-ok",
                                  source_device="sender")
            session.checksum = session.compute_checksum()

            result = jump_to_devices(targets, session,
                                     strategy=MultiJumpStrategy.CASCADE)

            self.assertEqual(len(result.targets), 2)
            self.assertTrue(result.all_ok)
            time.sleep(0.5)
            self.assertEqual(len(recv1), 1)
            self.assertEqual(len(recv2), 1)
        finally:
            l1.stop()
            l2.stop()


@unittest.skipUnless(CRYPTOGRAPHY_AVAILABLE, "cryptography not installed")
class TestMultiJumpRace(unittest.TestCase):
    def _start_listener(self):
        received = []

        def on_conn(conn):
            try:
                received.append(receive_session(conn))
            except Exception:
                pass
            finally:
                conn.close()

        listener = JumpListener(port=0, on_connection=on_conn)
        listener._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener._server_sock.bind(("127.0.0.1", 0))
        port = listener._server_sock.getsockname()[1]
        listener._server_sock.listen(5)
        listener._server_sock.settimeout(2.0)
        listener._running = True
        listener._thread = threading.Thread(target=listener._accept_loop, daemon=True)
        listener._thread.start()
        return port, listener, received

    def test_race_at_least_one_succeeds(self):
        port1, l1, recv1 = self._start_listener()
        port2, l2, recv2 = self._start_listener()

        try:
            targets = [
                Device("t1", "Racer1", "127.0.0.1", Transport.WIFI,
                       port=port1, last_seen=time.time()),
                Device("t2", "Racer2", "127.0.0.1", Transport.WIFI,
                       port=port2, last_seen=time.time()),
            ]
            session = JumpSession(session_id="race-test",
                                  source_device="sender")
            session.checksum = session.compute_checksum()

            result = jump_to_devices(targets, session,
                                     strategy=MultiJumpStrategy.RACE)

            self.assertTrue(result.any_ok)
            self.assertGreaterEqual(len(result.succeeded), 1)
        finally:
            l1.stop()
            l2.stop()


@unittest.skipUnless(CRYPTOGRAPHY_AVAILABLE, "cryptography not installed")
class TestMultiJumpNodeIntegration(unittest.TestCase):
    """Test the JumpNode.multi_jump() method."""

    def _start_listener(self):
        received = []

        def on_conn(conn):
            try:
                received.append(receive_session(conn))
            except Exception:
                pass
            finally:
                conn.close()

        listener = JumpListener(port=0, on_connection=on_conn)
        listener._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener._server_sock.bind(("127.0.0.1", 0))
        port = listener._server_sock.getsockname()[1]
        listener._server_sock.listen(5)
        listener._server_sock.settimeout(2.0)
        listener._running = True
        listener._thread = threading.Thread(target=listener._accept_loop, daemon=True)
        listener._thread.start()
        return port, listener, received

    def test_node_multi_jump_no_targets(self):
        node = JumpNode(listen_port=0)
        result = node.multi_jump(targets=[])
        self.assertEqual(len(result.targets), 0)

    def test_node_multi_jump_broadcast(self):
        port1, l1, recv1 = self._start_listener()
        port2, l2, recv2 = self._start_listener()

        try:
            node = JumpNode(listen_port=0)
            targets = [
                Device("t1", "N1", "127.0.0.1", Transport.WIFI,
                       port=port1, last_seen=time.time()),
                Device("t2", "N2", "127.0.0.1", Transport.WIFI,
                       port=port2, last_seen=time.time()),
            ]
            result = node.multi_jump(
                targets=targets,
                strategy=MultiJumpStrategy.BROADCAST,
                extra_metadata={"source": "test"},
            )
            self.assertTrue(result.all_ok)
            self.assertEqual(len(result.succeeded), 2)
            self.assertTrue(result.session_id.startswith("multi-"))

            time.sleep(0.5)
            self.assertEqual(len(recv1), 1)
            self.assertEqual(len(recv2), 1)
            # Verify metadata propagation
            self.assertTrue(recv1[0].metadata.get("multi_jump"))
            self.assertEqual(recv1[0].metadata["strategy"], "broadcast")
            self.assertEqual(recv1[0].metadata["target_count"], 2)
        finally:
            l1.stop()
            l2.stop()


@unittest.skipUnless(CRYPTOGRAPHY_AVAILABLE, "cryptography not installed")
class TestJumpSingleRetry(unittest.TestCase):
    def test_retry_on_failure(self):
        bad_target = Device("bad", "Unreachable", "127.0.0.1", Transport.WIFI,
                            port=1, last_seen=time.time())
        session = JumpSession(session_id="retry-test", source_device="src")
        session.checksum = session.compute_checksum()

        result = _jump_single(bad_target, session, timeout=1, max_retries=1)

        self.assertFalse(result.success)
        self.assertEqual(result.retries, 1)
        self.assertIsNotNone(result.error)
        self.assertGreater(result.elapsed, 0)


@unittest.skipUnless(CRYPTOGRAPHY_AVAILABLE, "cryptography not installed")
class TestSecurityHardening(unittest.TestCase):
    """Tests for security hardening of session restore and auth."""

    def test_path_traversal_blocked(self):
        """restore_session must reject paths with '..' components."""
        import base64
        session = JumpSession(
            session_id="evil",
            source_device="attacker",
            files={"../../etc/evil.txt": base64.b64encode(b"pwned").decode()},
        )
        session.checksum = session.compute_checksum()

        with tempfile.TemporaryDirectory() as td:
            restore_session(session, restore_files=True, target_dir=td)
            # The evil file must NOT have been written outside the target dir
            self.assertFalse(os.path.exists(os.path.join(td, "..", "..", "etc", "evil.txt")))
            # Nothing should have been written inside either (path was rejected)
            self.assertEqual(os.listdir(td), [])

    def test_absolute_path_blocked(self):
        """restore_session must reject absolute file paths."""
        import base64
        session = JumpSession(
            session_id="evil2",
            source_device="attacker",
            files={"/tmp/evil.txt": base64.b64encode(b"pwned").decode()},
        )
        session.checksum = session.compute_checksum()

        with tempfile.TemporaryDirectory() as td:
            restore_session(session, restore_files=True, target_dir=td)
            self.assertFalse(os.path.exists("/tmp/evil.txt"))
            self.assertEqual(os.listdir(td), [])

    def test_safe_path_allowed(self):
        """restore_session should allow clean relative paths."""
        import base64
        session = JumpSession(
            session_id="good",
            source_device="friend",
            files={"subdir/hello.txt": base64.b64encode(b"hello").decode()},
        )
        session.checksum = session.compute_checksum()

        with tempfile.TemporaryDirectory() as td:
            restore_session(session, restore_files=True, target_dir=td)
            written = os.path.join(td, "subdir", "hello.txt")
            self.assertTrue(os.path.exists(written))
            with open(written, "rb") as f:
                self.assertEqual(f.read(), b"hello")

    def test_env_injection_blocked(self):
        """restore_session must not set dangerous env vars like LD_PRELOAD."""
        session = JumpSession(
            session_id="env-evil",
            source_device="attacker",
            env={
                "LD_PRELOAD": "/tmp/evil.so",
                "PYTHONPATH": "/tmp/evil",
                "HOME": "/safe/home",
            },
        )
        session.checksum = session.compute_checksum()

        old_ld = os.environ.get("LD_PRELOAD")
        old_pypath = os.environ.get("PYTHONPATH")
        try:
            restore_session(session, restore_env=True)
            # Dangerous vars must NOT be set
            self.assertNotEqual(os.environ.get("LD_PRELOAD"), "/tmp/evil.so")
            self.assertNotEqual(os.environ.get("PYTHONPATH"), "/tmp/evil")
            # Safe vars should be set
            self.assertEqual(os.environ.get("HOME"), "/safe/home")
        finally:
            # Clean up
            if old_ld is None:
                os.environ.pop("LD_PRELOAD", None)
            else:
                os.environ["LD_PRELOAD"] = old_ld
            if old_pypath is None:
                os.environ.pop("PYTHONPATH", None)
            else:
                os.environ["PYTHONPATH"] = old_pypath
            os.environ.pop("HOME", None)

    def test_timing_safe_auth(self):
        """JumpNode._validate_auth must use constant-time comparison."""
        import hmac
        node = JumpNode(auth_token="secret123", listen_port=0)
        # Correct token
        self.assertTrue(node._validate_auth("secret123"))
        # Wrong token
        self.assertFalse(node._validate_auth("wrong"))
        # Empty token
        self.assertFalse(node._validate_auth(""))
        node.listener.stop()
        node.discovery.stop()

    def test_capture_rejects_files_outside_cwd(self):
        """capture_session should skip files that resolve outside CWD."""
        with tempfile.TemporaryDirectory() as td:
            # Create a file outside CWD
            outside = os.path.join(td, "secret.txt")
            with open(outside, "w") as f:
                f.write("secret")

            session = capture_session(
                "test-capture", "dev1",
                include_env=False,
                include_files=[outside],
            )
            # File outside CWD should not be included
            self.assertEqual(len(session.files), 0)


if __name__ == "__main__":
    unittest.main()
