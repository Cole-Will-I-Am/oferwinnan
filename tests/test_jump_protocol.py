"""Tests for matrix.jump_protocol — frame encoding, transport backends, key exchange, caching."""

import json
import socket
import struct
import threading
import time
import unittest
from unittest.mock import MagicMock, patch

from matrix.jump_protocol import (
    MsgType, ProtocolError, HEADER_MAGIC, HEADER_SIZE, PROTOCOL_VERSION,
    encode_frame, decode_frame,
    recv_frame_from, send_frame_to,
    DirectTCPBackend, _wrap_backend,
    generate_keypair, derive_session_keys,
    SessionKeys, SessionKeyCache,
    JumpConnection, JumpListener,
    client_handshake, server_handshake,
)


class TestFrameEncoding(unittest.TestCase):
    """Test encode_frame and decode_frame."""

    def test_roundtrip(self):
        payload = b"hello world"
        frame = encode_frame(MsgType.SESSION_DATA, payload, seq=42)
        msg_type, seq, decoded_payload = decode_frame(frame)
        self.assertEqual(msg_type, MsgType.SESSION_DATA)
        self.assertEqual(seq, 42)
        self.assertEqual(decoded_payload, payload)

    def test_empty_payload(self):
        frame = encode_frame(MsgType.PING, b"", seq=0)
        msg_type, seq, payload = decode_frame(frame)
        self.assertEqual(msg_type, MsgType.PING)
        self.assertEqual(payload, b"")

    def test_header_structure(self):
        frame = encode_frame(MsgType.HELLO, b"test", seq=1)
        self.assertTrue(frame.startswith(HEADER_MAGIC))
        self.assertEqual(len(frame), HEADER_SIZE + 4)

    def test_decode_invalid_magic(self):
        with self.assertRaises(ProtocolError):
            decode_frame(b"BAAD" + b"\x00" * 20)

    def test_decode_truncated(self):
        with self.assertRaises(ProtocolError):
            decode_frame(b"JMP\x01" + b"\x00" * 3)

    def test_decode_truncated_payload(self):
        # Build a frame header claiming 100 bytes but only provide 5
        header = HEADER_MAGIC + struct.pack("!BBII", PROTOCOL_VERSION,
                                             int(MsgType.PING), 0, 100)
        with self.assertRaises(ProtocolError):
            decode_frame(header + b"short")

    def test_all_msg_types_encodable(self):
        for mt in MsgType:
            frame = encode_frame(mt, b"x")
            msg_type, _, _ = decode_frame(frame)
            self.assertEqual(msg_type, mt)

    def test_large_payload(self):
        payload = b"x" * 65536
        frame = encode_frame(MsgType.FILE_CHUNK, payload)
        _, _, decoded = decode_frame(frame)
        self.assertEqual(decoded, payload)


class TestDirectTCPBackend(unittest.TestCase):
    """Test DirectTCPBackend wrapper."""

    def test_properties(self):
        sock = MagicMock(spec=socket.socket)
        sock.getpeername.return_value = ("10.0.0.1", 47701)
        backend = DirectTCPBackend(sock)
        self.assertEqual(backend.transport_name, "tcp")
        self.assertEqual(backend.peer_address, "10.0.0.1:47701")
        self.assertTrue(backend.is_connected)

    def test_send_bytes(self):
        sock = MagicMock(spec=socket.socket)
        sock.getpeername.return_value = ("10.0.0.1", 1234)
        backend = DirectTCPBackend(sock)
        backend.send_bytes(b"hello")
        sock.sendall.assert_called_once_with(b"hello")

    def test_send_bytes_failure(self):
        sock = MagicMock(spec=socket.socket)
        sock.getpeername.return_value = ("10.0.0.1", 1234)
        sock.sendall.side_effect = OSError("broken pipe")
        backend = DirectTCPBackend(sock)
        with self.assertRaises(ConnectionError):
            backend.send_bytes(b"data")
        self.assertFalse(backend.is_connected)

    def test_recv_bytes(self):
        sock = MagicMock(spec=socket.socket)
        sock.getpeername.return_value = ("10.0.0.1", 1234)
        sock.recv.side_effect = [b"hel", b"lo"]
        backend = DirectTCPBackend(sock)
        result = backend.recv_bytes(5)
        self.assertEqual(result, b"hello")

    def test_recv_bytes_closed(self):
        sock = MagicMock(spec=socket.socket)
        sock.getpeername.return_value = ("10.0.0.1", 1234)
        sock.recv.return_value = b""
        backend = DirectTCPBackend(sock)
        with self.assertRaises(ConnectionError):
            backend.recv_bytes(5)

    def test_close_idempotent(self):
        sock = MagicMock(spec=socket.socket)
        sock.getpeername.return_value = ("10.0.0.1", 1234)
        backend = DirectTCPBackend(sock)
        backend.close()
        backend.close()  # Should not raise
        self.assertFalse(backend.is_connected)

    def test_peer_address_unknown(self):
        sock = MagicMock(spec=socket.socket)
        sock.getpeername.side_effect = OSError()
        backend = DirectTCPBackend(sock)
        self.assertEqual(backend.peer_address, "unknown")


class TestWrapBackend(unittest.TestCase):
    """Test _wrap_backend helper."""

    def test_wraps_socket(self):
        sock = MagicMock(spec=socket.socket)
        sock.getpeername.return_value = ("1.2.3.4", 80)
        backend = _wrap_backend(sock)
        self.assertIsInstance(backend, DirectTCPBackend)

    def test_passes_through_backend(self):
        sock = MagicMock(spec=socket.socket)
        sock.getpeername.return_value = ("1.2.3.4", 80)
        original = DirectTCPBackend(sock)
        result = _wrap_backend(original)
        self.assertIs(result, original)

    def test_rejects_invalid_type(self):
        with self.assertRaises(TypeError):
            _wrap_backend("not a socket")


class TestBackendFrameIO(unittest.TestCase):
    """Test recv_frame_from and send_frame_to."""

    def test_send_and_recv_via_backend(self):
        # Use a real socketpair for integration
        s1, s2 = socket.socketpair()
        s1.settimeout(5)
        s2.settimeout(5)

        try:
            b1 = DirectTCPBackend(s1)
            b2 = DirectTCPBackend(s2)

            send_frame_to(b1, MsgType.PING, b"ping-data", seq=7)
            msg_type, seq, payload = recv_frame_from(b2)

            self.assertEqual(msg_type, MsgType.PING)
            self.assertEqual(seq, 7)
            self.assertEqual(payload, b"ping-data")
        finally:
            s1.close()
            s2.close()


class TestKeyExchange(unittest.TestCase):
    """Test X25519 key generation and derivation."""

    def test_generate_keypair(self):
        private, pub_bytes = generate_keypair()
        self.assertEqual(len(pub_bytes), 32)

    def test_derive_session_keys(self):
        priv_a, pub_a = generate_keypair()
        priv_b, pub_b = generate_keypair()

        keys_a = derive_session_keys(priv_a, pub_b, is_initiator=True)
        keys_b = derive_session_keys(priv_b, pub_a, is_initiator=False)

        self.assertEqual(keys_a.shared_key, keys_b.shared_key)
        self.assertIsNotNone(keys_a.ratchet)
        self.assertIsNotNone(keys_b.ratchet)

    def test_encrypt_decrypt_roundtrip(self):
        priv_a, pub_a = generate_keypair()
        priv_b, pub_b = generate_keypair()

        keys_a = derive_session_keys(priv_a, pub_b, is_initiator=True)
        keys_b = derive_session_keys(priv_b, pub_a, is_initiator=False)

        plaintext = b"secret message"
        ciphertext = keys_a.encrypt(plaintext)
        self.assertNotEqual(ciphertext, plaintext)

        decrypted = keys_b.decrypt(ciphertext)
        self.assertEqual(decrypted, plaintext)

    def test_encrypt_decrypt_multiple_messages(self):
        priv_a, pub_a = generate_keypair()
        priv_b, pub_b = generate_keypair()

        keys_a = derive_session_keys(priv_a, pub_b, is_initiator=True)
        keys_b = derive_session_keys(priv_b, pub_a, is_initiator=False)

        for i in range(5):
            msg = f"message {i}".encode()
            ct = keys_a.encrypt(msg)
            pt = keys_b.decrypt(ct)
            self.assertEqual(pt, msg)

    def test_clone_keys(self):
        priv, pub = generate_keypair()
        priv2, pub2 = generate_keypair()
        keys = derive_session_keys(priv, pub2, is_initiator=True)
        cloned = keys.clone()
        self.assertEqual(cloned.shared_key, keys.shared_key)
        self.assertEqual(cloned.connection_id, keys.connection_id)


class TestSessionKeyCache(unittest.TestCase):
    """Test SessionKeyCache TTL and operations."""

    def _make_keys(self, conn_id="test-conn"):
        priv, pub = generate_keypair()
        priv2, pub2 = generate_keypair()
        keys = derive_session_keys(priv, pub2, connection_id=conn_id,
                                   is_initiator=True)
        return keys

    def test_store_and_get(self):
        cache = SessionKeyCache(ttl=60)
        keys = self._make_keys("conn-1")
        cache.store(keys)
        retrieved = cache.get("conn-1")
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.connection_id, "conn-1")

    def test_get_nonexistent(self):
        cache = SessionKeyCache(ttl=60)
        self.assertIsNone(cache.get("nonexistent"))

    def test_remove(self):
        cache = SessionKeyCache(ttl=60)
        keys = self._make_keys("conn-2")
        cache.store(keys)
        cache.remove("conn-2")
        self.assertIsNone(cache.get("conn-2"))

    def test_ttl_eviction(self):
        cache = SessionKeyCache(ttl=0.0)
        keys = self._make_keys("conn-3")
        cache.store(keys)
        # Force eviction by accessing after TTL
        time.sleep(0.01)
        self.assertIsNone(cache.get("conn-3"))


class TestJumpConnection(unittest.TestCase):
    """Test JumpConnection send/recv over socketpair."""

    def _make_connected_pair(self):
        """Create a pair of JumpConnections sharing derived keys."""
        s1, s2 = socket.socketpair()
        s1.settimeout(5)
        s2.settimeout(5)

        priv_a, pub_a = generate_keypair()
        priv_b, pub_b = generate_keypair()
        keys_a = derive_session_keys(priv_a, pub_b, is_initiator=True)
        keys_b = derive_session_keys(priv_b, pub_a, is_initiator=False)

        conn_a = JumpConnection(s1, keys_a, is_initiator=True)
        conn_b = JumpConnection(s2, keys_b, is_initiator=False)
        return conn_a, conn_b

    def test_send_recv(self):
        a, b = self._make_connected_pair()
        try:
            a.send(MsgType.SESSION_DATA, b"test payload")
            msg_type, payload = b.recv()
            self.assertEqual(msg_type, MsgType.SESSION_DATA)
            self.assertEqual(payload, b"test payload")
        finally:
            a.close()
            b.close()

    def test_send_recv_json(self):
        a, b = self._make_connected_pair()
        try:
            a.send_json(MsgType.SESSION_ACK, {"status": "ok"})
            msg_type, obj = b.recv_json()
            self.assertEqual(msg_type, MsgType.SESSION_ACK)
            self.assertEqual(obj["status"], "ok")
        finally:
            a.close()
            b.close()

    def test_ping(self):
        a, b = self._make_connected_pair()

        def respond_to_ping():
            msg_type, payload = b.recv()
            if msg_type == MsgType.PING:
                b.send(MsgType.PONG, b"pong")

        t = threading.Thread(target=respond_to_ping)
        t.start()
        try:
            rtt = a.ping(timeout=5.0)
            self.assertGreater(rtt, 0)
        finally:
            t.join(timeout=5)
            a.close()
            b.close()

    def test_connection_properties(self):
        a, b = self._make_connected_pair()
        try:
            self.assertTrue(a.is_connected)
            self.assertEqual(a.transport_name, "tcp")
            self.assertTrue(a.connection_id)
        finally:
            a.close()
            b.close()


class TestHandshake(unittest.TestCase):
    """Test client/server handshake over socketpair."""

    def test_full_handshake(self):
        s1, s2 = socket.socketpair()
        s1.settimeout(5)
        s2.settimeout(5)

        result = {}

        def server_side():
            try:
                conn = server_handshake(s2)
                result["conn"] = conn
            except Exception as e:
                result["error"] = e

        t = threading.Thread(target=server_side)
        t.start()

        try:
            client_conn = client_handshake(s1, "test-client")
            t.join(timeout=5)

            self.assertIn("conn", result, f"Server error: {result.get('error')}")
            server_conn = result["conn"]

            # Test encrypted communication
            client_conn.send(MsgType.SESSION_DATA, b"from client")
            msg_type, payload = server_conn.recv()
            self.assertEqual(payload, b"from client")

            server_conn.send(MsgType.SESSION_ACK, b"from server")
            msg_type, payload = client_conn.recv()
            self.assertEqual(payload, b"from server")
        finally:
            s1.close()
            s2.close()

    def test_handshake_with_auth(self):
        s1, s2 = socket.socketpair()
        s1.settimeout(5)
        s2.settimeout(5)

        result = {}

        def server_side():
            try:
                def validator(token):
                    return token == "secret"
                conn = server_handshake(s2, auth_validator=validator)
                result["conn"] = conn
            except Exception as e:
                result["error"] = e

        t = threading.Thread(target=server_side)
        t.start()

        try:
            client_conn = client_handshake(s1, "test-client", auth_token="secret")
            t.join(timeout=5)
            self.assertIn("conn", result)
        finally:
            s1.close()
            s2.close()

    def test_handshake_auth_failure(self):
        s1, s2 = socket.socketpair()
        s1.settimeout(5)
        s2.settimeout(5)

        result = {}

        def server_side():
            try:
                def validator(token):
                    return token == "correct"
                conn = server_handshake(s2, auth_validator=validator)
                result["conn"] = conn
            except ProtocolError as e:
                result["error"] = e

        t = threading.Thread(target=server_side)
        t.start()

        try:
            with self.assertRaises(ProtocolError):
                client_handshake(s1, "test-client", auth_token="wrong")
            t.join(timeout=5)
            self.assertIn("error", result)
        finally:
            s1.close()
            s2.close()


if __name__ == "__main__":
    unittest.main()
