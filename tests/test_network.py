"""Tests for the network connectivity & resilience enhancements.

Covers:
  - TransportBackend abstraction (DirectTCPBackend)
  - WebSocket transport backend
  - Resumable transfers
  - Multi-path redundancy
  - Transport negotiation
  - Traffic normalization (padding, jitter, profiles)
"""

import importlib.util
import json
import os
import socket
import struct
import threading
import time
import unittest
from unittest.mock import MagicMock, patch

CRYPTOGRAPHY_AVAILABLE = importlib.util.find_spec("cryptography") is not None

if CRYPTOGRAPHY_AVAILABLE:
    from matrix.jump_protocol import (
        TransportBackend, DirectTCPBackend, SessionKeyCache,
        JumpConnection, JumpListener, MsgType, ProtocolError,
        encode_frame, decode_frame,
        generate_keypair, derive_session_keys, SessionKeys,
        client_handshake, server_handshake,
        recv_frame_from, send_frame_to,
        HEADER_MAGIC, PROTOCOL_VERSION, PROTOCOL_VERSION_LEGACY,
        _wrap_backend, _key_cache,
    )
    from matrix.session_jumper import (
        JumpSession, TransferState, TransferStateStore,
        send_session, receive_session,
    )
    from matrix.transport_ws import (
        WebSocketBackend, WebSocketListener,
        _ws_write_frame, _ws_read_frame,
        _ws_client_handshake, _ws_server_handshake,
        WS_BINARY, WS_CLOSE, WS_PING, WS_PONG,
    )
    from matrix.multipath import (
        PathState, PathHealth, MultiPathConnection,
    )
    from matrix.transport_negotiator import (
        TransportNegotiator, ProbeResult,
        pad_frame, strip_padding, PADDING_BUCKETS,
        TimingJitter, CoverTrafficGenerator,
        PlainProfile, CloudSyncProfile, WebAPIProfile,
        NormalizedConnection,
        _probe_tcp,
    )


# == TransportBackend Abstraction Tests ========================================

@unittest.skipUnless(CRYPTOGRAPHY_AVAILABLE, "cryptography not installed")
class TestDirectTCPBackend(unittest.TestCase):

    def test_implements_protocol(self):
        """DirectTCPBackend satisfies the TransportBackend protocol."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        backend = DirectTCPBackend(sock)
        self.assertIsInstance(backend, TransportBackend)
        self.assertEqual(backend.transport_name, "tcp")
        self.assertTrue(backend.is_connected)
        backend.close()
        self.assertFalse(backend.is_connected)
        sock.close()

    def test_send_recv_loopback(self):
        """Send and receive bytes through a TCP backend pair."""
        s1, s2 = socket.socketpair()
        b1 = DirectTCPBackend(s1)
        b2 = DirectTCPBackend(s2)

        b1.send_bytes(b"hello")
        data = b2.recv_bytes(5)
        self.assertEqual(data, b"hello")

        b2.send_bytes(b"world!")
        data = b1.recv_bytes(6)
        self.assertEqual(data, b"world!")

        b1.close()
        b2.close()

    def test_recv_exact(self):
        """recv_bytes returns exactly n bytes, even if fragmented."""
        s1, s2 = socket.socketpair()
        b1 = DirectTCPBackend(s1)
        b2 = DirectTCPBackend(s2)

        payload = os.urandom(10000)
        b1.send_bytes(payload)
        received = b2.recv_bytes(10000)
        self.assertEqual(received, payload)

        b1.close()
        b2.close()

    def test_close_idempotent(self):
        """Closing a backend multiple times doesn't raise."""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        b = DirectTCPBackend(s)
        b.close()
        b.close()
        b.close()

    def test_wrap_backend_socket(self):
        """_wrap_backend wraps a socket into DirectTCPBackend."""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        backend = _wrap_backend(s)
        self.assertIsInstance(backend, DirectTCPBackend)
        s.close()

    def test_wrap_backend_passthrough(self):
        """_wrap_backend returns a TransportBackend as-is."""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp = DirectTCPBackend(s)
        result = _wrap_backend(tcp)
        self.assertIs(result, tcp)
        s.close()

    def test_wrap_backend_invalid(self):
        """_wrap_backend raises on unsupported types."""
        with self.assertRaises(TypeError):
            _wrap_backend("not a socket")


@unittest.skipUnless(CRYPTOGRAPHY_AVAILABLE, "cryptography not installed")
class TestBackendFrameIO(unittest.TestCase):

    def test_send_recv_frame_via_backend(self):
        """Frames can be sent/received through backend-based I/O."""
        s1, s2 = socket.socketpair()
        b1 = DirectTCPBackend(s1)
        b2 = DirectTCPBackend(s2)

        send_frame_to(b1, MsgType.HELLO, b"test payload", seq=7)
        msg_type, seq, payload = recv_frame_from(b2)

        self.assertEqual(msg_type, MsgType.HELLO)
        self.assertEqual(seq, 7)
        self.assertEqual(payload, b"test payload")

        b1.close()
        b2.close()

    def test_backend_handshake(self):
        """Full handshake works with TransportBackend instead of raw socket."""
        s1, s2 = socket.socketpair()

        server_conn = [None]
        server_err = [None]

        def server_side():
            try:
                server_conn[0] = server_handshake(DirectTCPBackend(s2))
            except Exception as e:
                server_err[0] = e

        t = threading.Thread(target=server_side)
        t.start()

        client_conn = client_handshake(DirectTCPBackend(s1), "test-node")
        t.join(timeout=5)

        self.assertIsNone(server_err[0])
        self.assertIsNotNone(server_conn[0])
        self.assertIsNotNone(client_conn.connection_id)
        self.assertEqual(client_conn.transport_name, "tcp")

        # Test encrypted communication
        client_conn.send(MsgType.PING, b"hello")
        msg_type, data = server_conn[0].recv()
        self.assertEqual(data, b"hello")

        client_conn.close()
        server_conn[0].close()

    def test_resume_cache_miss_aborts_without_key_exchange(self):
        """If server claims resumed but cache is missing, client must fail fast."""

        class FakeBackend:
            def __init__(self, incoming: bytes):
                self._incoming = bytearray(incoming)
                self.sent: list[bytes] = []

            def send_bytes(self, data: bytes) -> None:
                self.sent.append(data)

            def recv_bytes(self, n: int) -> bytes:
                if len(self._incoming) < n:
                    raise ConnectionError("eof")
                out = bytes(self._incoming[:n])
                del self._incoming[:n]
                return out

            def close(self) -> None:
                pass

            @property
            def peer_address(self) -> str:
                return "fake"

            @property
            def transport_name(self) -> str:
                return "fake"

            @property
            def is_connected(self) -> bool:
                return True

        _key_cache.remove("missing-resume")
        ack = encode_frame(MsgType.HELLO_ACK, json.dumps({"resumed": True}).encode())
        backend = FakeBackend(ack)

        with self.assertRaises(ProtocolError):
            client_handshake(backend, "node-x", connection_id="missing-resume")

        sent_types = [decode_frame(frame)[0] for frame in backend.sent]
        self.assertEqual(sent_types, [MsgType.HELLO])

    def test_resume_authenticates_over_encrypted_channel(self):
        """0-RTT resume must authenticate over the encrypted channel, never in cleartext.

        Drives a real handshake to populate both key caches, then verifies that
        a resumed session is rejected with a bad token and accepted (and usable)
        with the correct one.
        """
        token = "good-token"

        def validator(t):
            return t == token

        cache = SessionKeyCache(ttl=60.0)

        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind(("127.0.0.1", 0))
        port = server_sock.getsockname()[1]
        server_sock.listen(2)

        out = {}

        def serve(key):
            try:
                client, _ = server_sock.accept()
                out[key] = server_handshake(
                    client, auth_validator=validator, key_cache=cache,
                )
            except Exception as e:  # noqa: BLE001
                out[key] = e

        try:
            # 1) Full handshake populates client (global) and server caches.
            t = threading.Thread(target=serve, args=("first",))
            t.start()
            c1 = socket.create_connection(("127.0.0.1", port))
            conn1 = client_handshake(c1, "node", auth_token=token)
            t.join(5)
            self.assertIsInstance(out["first"], JumpConnection)
            conn_id = conn1.connection_id
            self.assertTrue(conn_id)

            # 2) Resume with the WRONG token must be rejected on both ends.
            t = threading.Thread(target=serve, args=("bad",))
            t.start()
            c2 = socket.create_connection(("127.0.0.1", port))
            with self.assertRaises(ProtocolError):
                client_handshake(c2, "node", auth_token="wrong",
                                 connection_id=conn_id)
            t.join(5)
            self.assertIsInstance(out["bad"], ProtocolError)
            c2.close()

            # 3) Resume with the correct token succeeds and yields a usable conn.
            t = threading.Thread(target=serve, args=("good",))
            t.start()
            c3 = socket.create_connection(("127.0.0.1", port))
            conn3 = client_handshake(c3, "node", auth_token=token,
                                     connection_id=conn_id)
            t.join(5)
            self.assertIsInstance(out["good"], JumpConnection)

            conn3.send(MsgType.PING, b"resumed-hello")
            msg_type, data = out["good"].recv()
            self.assertEqual(msg_type, MsgType.PING)
            self.assertEqual(data, b"resumed-hello")

            conn3.close()
            out["good"].close()
            conn1.close()
            out["first"].close()
        finally:
            server_sock.close()


# == Protocol Version Compatibility ============================================

@unittest.skipUnless(CRYPTOGRAPHY_AVAILABLE, "cryptography not installed")
class TestProtocolVersionCompat(unittest.TestCase):

    def test_accepts_legacy_version(self):
        """decode_frame accepts PROTOCOL_VERSION_LEGACY (v1)."""
        payload = b"legacy data"
        header = HEADER_MAGIC + struct.pack("!BBII", PROTOCOL_VERSION_LEGACY,
                                            int(MsgType.HELLO), 0, len(payload))
        frame = header + payload
        msg_type, seq, data = decode_frame(frame)
        self.assertEqual(msg_type, MsgType.HELLO)
        self.assertEqual(data, payload)

    def test_rejects_unknown_version(self):
        """decode_frame rejects unknown protocol versions."""
        header = HEADER_MAGIC + struct.pack("!BBII", 99, int(MsgType.HELLO), 0, 0)
        with self.assertRaises(ProtocolError):
            decode_frame(header)


# == Session Key Cache =========================================================

@unittest.skipUnless(CRYPTOGRAPHY_AVAILABLE, "cryptography not installed")
class TestSessionKeyCache(unittest.TestCase):

    def test_store_and_retrieve(self):
        priv, pub = generate_keypair()
        keys = derive_session_keys(priv, pub, connection_id="test-123")
        cache = SessionKeyCache(ttl=10.0)
        cache.store(keys)

        retrieved = cache.get("test-123")
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.connection_id, "test-123")

    def test_miss(self):
        cache = SessionKeyCache(ttl=10.0)
        self.assertIsNone(cache.get("nonexistent"))

    def test_eviction(self):
        priv, pub = generate_keypair()
        keys = derive_session_keys(priv, pub, connection_id="expire-me")
        cache = SessionKeyCache(ttl=0.01)
        cache.store(keys)
        time.sleep(0.05)
        self.assertIsNone(cache.get("expire-me"))

    def test_remove(self):
        priv, pub = generate_keypair()
        keys = derive_session_keys(priv, pub, connection_id="rm-test")
        cache = SessionKeyCache(ttl=60.0)
        cache.store(keys)
        cache.remove("rm-test")
        self.assertIsNone(cache.get("rm-test"))

    def test_get_returns_independent_key_objects(self):
        priv, pub = generate_keypair()
        keys = derive_session_keys(priv, pub, connection_id="clone-test")
        cache = SessionKeyCache(ttl=60.0)
        cache.store(keys)

        first = cache.get("clone-test")
        second = cache.get("clone-test")

        self.assertIsNotNone(first)
        self.assertIsNotNone(second)
        self.assertIsNot(first, second)
        self.assertIsNot(first.ratchet, second.ratchet)

        # Advancing one retrieved keyset must not mutate the other.
        self.assertEqual(first.ratchet.send_ratchet.counter, 0)
        self.assertEqual(second.ratchet.send_ratchet.counter, 0)
        first.encrypt(b"independent-state")
        self.assertEqual(first.ratchet.send_ratchet.counter, 1)
        self.assertEqual(second.ratchet.send_ratchet.counter, 0)


# == WebSocket Transport Tests =================================================

@unittest.skipUnless(CRYPTOGRAPHY_AVAILABLE, "cryptography not installed")
class TestWebSocketFraming(unittest.TestCase):
    """Test low-level WebSocket frame encode/decode."""

    def test_binary_frame_roundtrip(self):
        """Write and read a binary frame over a socket pair."""
        s1, s2 = socket.socketpair()

        payload = b"hello websocket"
        _ws_write_frame(s1, WS_BINARY, payload, mask=False)
        opcode, data = _ws_read_frame(s2)

        self.assertEqual(opcode, WS_BINARY)
        self.assertEqual(data, payload)
        s1.close()
        s2.close()

    def test_masked_frame(self):
        """Masked frame (client-to-server) roundtrips correctly."""
        s1, s2 = socket.socketpair()

        payload = b"masked data"
        _ws_write_frame(s1, WS_BINARY, payload, mask=True)
        opcode, data = _ws_read_frame(s2)

        self.assertEqual(opcode, WS_BINARY)
        self.assertEqual(data, payload)
        s1.close()
        s2.close()

    def test_large_payload(self):
        """Frame with >125 byte payload uses extended length."""
        s1, s2 = socket.socketpair()

        payload = os.urandom(5000)
        _ws_write_frame(s1, WS_BINARY, payload, mask=False)
        opcode, data = _ws_read_frame(s2)

        self.assertEqual(data, payload)
        s1.close()
        s2.close()

    def test_very_large_payload(self):
        """Frame with >65535 byte payload uses 8-byte extended length."""
        s1, s2 = socket.socketpair()

        payload = os.urandom(70000)
        _ws_write_frame(s1, WS_BINARY, payload, mask=False)
        opcode, data = _ws_read_frame(s2)

        self.assertEqual(data, payload)
        s1.close()
        s2.close()

    def test_ping_pong(self):
        s1, s2 = socket.socketpair()

        _ws_write_frame(s1, WS_PING, b"ping!", mask=False)
        opcode, data = _ws_read_frame(s2)
        self.assertEqual(opcode, WS_PING)
        self.assertEqual(data, b"ping!")

        _ws_write_frame(s2, WS_PONG, b"ping!", mask=False)
        opcode, data = _ws_read_frame(s1)
        self.assertEqual(opcode, WS_PONG)

        s1.close()
        s2.close()


@unittest.skipUnless(CRYPTOGRAPHY_AVAILABLE, "cryptography not installed")
class TestWebSocketHandshake(unittest.TestCase):
    """Test the HTTP upgrade handshake for WebSocket."""

    def test_client_server_upgrade(self):
        """Full WebSocket upgrade handshake over a socket pair."""
        s_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s_server.bind(("127.0.0.1", 0))
        port = s_server.getsockname()[1]
        s_server.listen(1)

        path_result = [None]
        server_err = [None]
        server_sock = [None]
        client_read = threading.Event()

        def server_side():
            try:
                client, _ = s_server.accept()
                server_sock[0] = client
                path, excess = _ws_server_handshake(client)
                path_result[0] = path
                # Send a binary frame back
                _ws_write_frame(client, WS_BINARY, b"upgraded!", mask=False)
                # Wait for client to read before closing
                client_read.wait(timeout=5)
            except Exception as e:
                server_err[0] = e

        t = threading.Thread(target=server_side)
        t.start()

        # Client side
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("127.0.0.1", port))
        excess = _ws_client_handshake(sock, f"127.0.0.1:{port}", "/jump/ws")

        # Read the server's binary frame (pass excess buffer)
        ws_buf = bytearray(excess)
        opcode, data = _ws_read_frame(sock, ws_buf)
        client_read.set()
        self.assertEqual(opcode, WS_BINARY)
        self.assertEqual(data, b"upgraded!")

        t.join(timeout=5)
        self.assertIsNone(server_err[0])
        self.assertEqual(path_result[0], "/jump/ws")

        sock.close()
        if server_sock[0]:
            server_sock[0].close()
        s_server.close()


@unittest.skipUnless(CRYPTOGRAPHY_AVAILABLE, "cryptography not installed")
class TestWebSocketBackend(unittest.TestCase):
    """Test WebSocketBackend as a TransportBackend."""

    def _make_ws_pair(self):
        """Create a connected WebSocket backend pair via loopback."""
        s_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s_server.bind(("127.0.0.1", 0))
        port = s_server.getsockname()[1]
        s_server.listen(1)

        server_backend = [None]

        def server_side():
            client, _ = s_server.accept()
            _path, excess = _ws_server_handshake(client)
            server_backend[0] = WebSocketBackend(client, is_client=False,
                                                  initial_buf=excess)

        t = threading.Thread(target=server_side)
        t.start()

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("127.0.0.1", port))
        excess = _ws_client_handshake(sock, f"127.0.0.1:{port}", "/test")
        client_backend = WebSocketBackend(sock, is_client=True, initial_buf=excess)

        t.join(timeout=5)
        s_server.close()
        return client_backend, server_backend[0]

    def test_send_recv(self):
        """WebSocketBackend send_bytes/recv_bytes works."""
        client, server = self._make_ws_pair()

        client.send_bytes(b"hello ws")
        data = server.recv_bytes(8)
        self.assertEqual(data, b"hello ws")

        server.send_bytes(b"reply")
        data = client.recv_bytes(5)
        self.assertEqual(data, b"reply")

        client.close()
        server.close()

    def test_transport_name(self):
        client, server = self._make_ws_pair()
        self.assertEqual(client.transport_name, "websocket")
        self.assertEqual(server.transport_name, "websocket")
        client.close()
        server.close()

    def test_jump_handshake_over_websocket(self):
        """Full Jump protocol handshake over WebSocket transport."""
        client_ws, server_ws = self._make_ws_pair()

        server_conn = [None]
        server_err = [None]

        def server_side():
            try:
                server_conn[0] = server_handshake(server_ws)
            except Exception as e:
                server_err[0] = e

        t = threading.Thread(target=server_side)
        t.start()

        client_conn = client_handshake(client_ws, "ws-test-node")
        t.join(timeout=5)

        self.assertIsNone(server_err[0])
        self.assertIsNotNone(server_conn[0])

        # Test encrypted communication
        client_conn.send(MsgType.PING, b"ws-ping")
        msg_type, data = server_conn[0].recv()
        self.assertEqual(msg_type, MsgType.PING)
        self.assertEqual(data, b"ws-ping")

        client_conn.close()
        server_conn[0].close()

    def test_session_transfer_over_websocket(self):
        """Full session transfer over WebSocket transport."""
        client_ws, server_ws = self._make_ws_pair()

        received = [None]
        errors = [None]

        def server_side():
            try:
                conn = server_handshake(server_ws)
                received[0] = receive_session(conn)
                conn.close()
            except Exception as e:
                errors[0] = e

        t = threading.Thread(target=server_side)
        t.start()

        session = JumpSession(
            session_id="ws-e2e",
            source_device="ws-sender",
            timestamp=time.time(),
            cwd="/tmp",
            metadata={"transport": "websocket"},
        )
        session.checksum = session.compute_checksum()

        conn = client_handshake(client_ws, "ws-sender")
        ok = send_session(conn, session)
        conn.close()

        t.join(timeout=10)

        self.assertIsNone(errors[0], f"Server error: {errors[0]}")
        self.assertTrue(ok)
        self.assertIsNotNone(received[0])
        self.assertEqual(received[0].session_id, "ws-e2e")
        self.assertEqual(received[0].metadata["transport"], "websocket")


# == Resumable Transfer Tests ==================================================

@unittest.skipUnless(CRYPTOGRAPHY_AVAILABLE, "cryptography not installed")
class TestTransferState(unittest.TestCase):

    def test_basic_state(self):
        state = TransferState("sess-1", 1000, "abc123")
        self.assertEqual(state.session_id, "sess-1")
        self.assertEqual(state.total_size, 1000)
        self.assertFalse(state.is_complete)
        self.assertAlmostEqual(state.progress, 0.0)

    def test_progress(self):
        state = TransferState("sess-2", 100, "xyz")
        state.buffer.extend(b"x" * 50)
        self.assertAlmostEqual(state.progress, 0.5)

    def test_complete(self):
        state = TransferState("sess-3", 10, "abc")
        state.buffer.extend(b"0123456789")
        self.assertTrue(state.is_complete)

    def test_resume_info(self):
        state = TransferState("sess-4", 1000, "checksum")
        state.buffer.extend(b"x" * 500)
        state.last_acked_offset = 500
        state.last_acked_seq = 7
        info = state.to_resume_info()
        self.assertEqual(info["session_id"], "sess-4")
        self.assertEqual(info["resume_offset"], 500)
        self.assertEqual(info["resume_seq"], 7)
        self.assertEqual(info["received_size"], 500)


@unittest.skipUnless(CRYPTOGRAPHY_AVAILABLE, "cryptography not installed")
class TestTransferStateStore(unittest.TestCase):

    def test_get_or_create(self):
        store = TransferStateStore(ttl=60.0)
        state = store.get_or_create("s1", 1000, "ck")
        self.assertIsNotNone(state)
        self.assertEqual(state.session_id, "s1")

        # Same session returns same state
        state2 = store.get_or_create("s1", 1000, "ck")
        self.assertIs(state, state2)

    def test_eviction(self):
        store = TransferStateStore(ttl=0.01)
        store.get_or_create("exp", 100, "ck")
        time.sleep(0.05)
        self.assertIsNone(store.get("exp"))

    def test_remove(self):
        store = TransferStateStore(ttl=60.0)
        store.get_or_create("rm", 100, "ck")
        store.remove("rm")
        self.assertIsNone(store.get("rm"))


@unittest.skipUnless(CRYPTOGRAPHY_AVAILABLE, "cryptography not installed")
class TestReceiveSessionValidation(unittest.TestCase):

    def test_rejects_chunk_gap(self):
        class FakeConn:
            def __init__(self):
                self.sent_json = []

            def recv_json(self):
                return MsgType.SESSION_DATA, {
                    "meta": {
                        "session_id": "gap-test",
                        "size": 10,
                        "checksum": "",
                        "resumable": True,
                    }
                }

            def send_json(self, msg_type, obj):
                self.sent_json.append((msg_type, obj))

            def recv(self, timeout=None):
                meta = {"seq": 0, "offset": 5, "size": 2, "final": False}
                payload = json.dumps(meta).encode() + b"\x00" + b"ab"
                return MsgType.FILE_CHUNK, payload

        conn = FakeConn()
        store = TransferStateStore(ttl=60.0)
        with self.assertRaises(ProtocolError):
            receive_session(conn, transfer_store=store)

        sent_types = [msg_type for msg_type, _ in conn.sent_json]
        self.assertIn(MsgType.ERROR, sent_types)


# == Multi-Path Tests ==========================================================

@unittest.skipUnless(CRYPTOGRAPHY_AVAILABLE, "cryptography not installed")
class TestPathHealth(unittest.TestCase):

    def test_initial_state(self):
        h = PathHealth("tcp")
        self.assertEqual(h.state, PathState.HEALTHY)
        self.assertEqual(h.rtt_ewma, 0.0)

    def test_rtt_ewma(self):
        h = PathHealth("tcp")
        h.record_rtt(0.1)
        self.assertAlmostEqual(h.rtt_ewma, 0.1)
        h.record_rtt(0.05)
        # EWMA: 0.3 * 0.05 + 0.7 * 0.1 = 0.015 + 0.07 = 0.085
        self.assertAlmostEqual(h.rtt_ewma, 0.085)

    def test_degradation(self):
        h = PathHealth("tcp")
        h.record_miss()
        h.record_miss()
        self.assertEqual(h.state, PathState.HEALTHY)
        h.record_miss()
        self.assertEqual(h.state, PathState.DEGRADED)

    def test_death(self):
        h = PathHealth("tcp")
        for _ in range(6):
            h.record_miss()
        self.assertEqual(h.state, PathState.DEAD)

    def test_recovery(self):
        h = PathHealth("tcp")
        h.record_miss()
        h.record_miss()
        h.record_miss()
        self.assertEqual(h.state, PathState.DEGRADED)
        h.record_rtt(0.05)
        self.assertEqual(h.state, PathState.HEALTHY)

    def test_weight_dead(self):
        h = PathHealth("tcp")
        for _ in range(6):
            h.record_miss()
        self.assertEqual(h.weight, 0.0)

    def test_weight_healthy(self):
        h = PathHealth("tcp")
        h.record_rtt(0.1)
        self.assertGreater(h.weight, 0)


@unittest.skipUnless(CRYPTOGRAPHY_AVAILABLE, "cryptography not installed")
class TestMultiPathConnection(unittest.TestCase):

    def test_add_remove_path(self):
        mp = MultiPathConnection()
        priv, pub = generate_keypair()
        keys = derive_session_keys(priv, pub)

        s1, s2 = socket.socketpair()
        path_id = mp.add_path(DirectTCPBackend(s1), keys)
        self.assertEqual(mp.path_count, 1)

        mp.remove_path(path_id)
        self.assertEqual(mp.path_count, 0)
        s2.close()

    def test_health_report(self):
        mp = MultiPathConnection()
        priv, pub = generate_keypair()
        keys = derive_session_keys(priv, pub)

        s1, s2 = socket.socketpair()
        mp.add_path(DirectTCPBackend(s1), keys)

        health = mp.get_health()
        self.assertEqual(len(health), 1)
        for pid, info in health.items():
            self.assertEqual(info["state"], "healthy")
            self.assertEqual(info["transport"], "tcp")

        mp.close()
        s2.close()


# == Transport Negotiation Tests ===============================================

@unittest.skipUnless(CRYPTOGRAPHY_AVAILABLE, "cryptography not installed")
class TestProbe(unittest.TestCase):

    def test_probe_tcp_success(self):
        """TCP probe succeeds against a local listener."""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        port = server.getsockname()[1]
        server.listen(1)

        result = _probe_tcp("127.0.0.1", port, timeout=2.0)
        self.assertTrue(result.success)
        self.assertGreater(result.rtt_ms, 0)
        self.assertIsNotNone(result.backend)
        self.assertEqual(result.transport, "tcp")

        result.backend.close()
        server.close()

    def test_probe_tcp_failure(self):
        """TCP probe fails against a closed port."""
        result = _probe_tcp("127.0.0.1", 1, timeout=1.0)
        self.assertFalse(result.success)
        self.assertIsNotNone(result.error)

    def test_negotiator_tcp_only(self):
        """Negotiator works with TCP only."""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        port = server.getsockname()[1]
        server.listen(1)

        neg = TransportNegotiator("127.0.0.1", tcp_port=port)
        result = neg.negotiate(timeout=2.0)

        self.assertTrue(result.success)
        self.assertEqual(result.transport, "tcp")

        if result.backend:
            result.backend.close()
        server.close()

    def test_negotiator_all_fail(self):
        neg = TransportNegotiator("127.0.0.1", tcp_port=1)
        result = neg.negotiate(timeout=1.0)
        self.assertFalse(result.success)

    @patch("matrix.transport_negotiator._probe_tcp")
    @patch("matrix.transport_negotiator._probe_https")
    def test_negotiate_ignores_stateless_https_when_connectable_exists(
        self, mock_probe_https, mock_probe_tcp
    ):
        tcp_backend = MagicMock()
        mock_probe_tcp.return_value = ProbeResult(
            "tcp", True, rtt_ms=12.0, backend=tcp_backend
        )
        mock_probe_https.return_value = ProbeResult(
            "https", True, rtt_ms=2.0, backend=None
        )

        neg = TransportNegotiator("example.com", tcp_port=47701, https_url="https://example.com")
        result = neg.negotiate(timeout=1.0)

        self.assertTrue(result.success)
        self.assertEqual(result.transport, "tcp")
        self.assertIs(result.backend, tcp_backend)

    @patch("matrix.transport_negotiator._probe_tcp")
    @patch("matrix.transport_negotiator._probe_https")
    def test_negotiate_fails_when_only_stateless_probes_succeed(
        self, mock_probe_https, mock_probe_tcp
    ):
        mock_probe_tcp.return_value = ProbeResult("tcp", False, error="refused")
        mock_probe_https.return_value = ProbeResult(
            "https", True, rtt_ms=3.0, backend=None
        )

        neg = TransportNegotiator("example.com", tcp_port=47701, https_url="https://example.com")
        result = neg.negotiate(timeout=1.0)

        self.assertFalse(result.success)
        self.assertIn("No connectable transport", result.error)


# == Traffic Normalization Tests ===============================================

@unittest.skipUnless(CRYPTOGRAPHY_AVAILABLE, "cryptography not installed")
class TestFramePadding(unittest.TestCase):

    def test_small_payload_padded(self):
        data = b"x" * 50
        padded = pad_frame(data)
        self.assertEqual(len(padded), 128)  # First bucket >= 50

    def test_exact_bucket_no_change(self):
        data = b"x" * 128
        padded = pad_frame(data)
        self.assertEqual(len(padded), 128)

    def test_padding_is_random(self):
        data = b"x" * 50
        p1 = pad_frame(data)
        p2 = pad_frame(data)
        # First 50 bytes are identical, padding differs
        self.assertEqual(p1[:50], p2[:50])
        # Padding bytes are random — almost certainly different
        # (1 in 2^624 chance they're identical)
        if len(p1) > 50:
            self.assertNotEqual(p1[50:], p2[50:])

    def test_strip_padding(self):
        data = b"original data"
        padded = pad_frame(data)
        stripped = strip_padding(padded, len(data))
        self.assertEqual(stripped, data)

    def test_buckets_are_sorted(self):
        for i in range(len(PADDING_BUCKETS) - 1):
            self.assertLess(PADDING_BUCKETS[i], PADDING_BUCKETS[i + 1])


@unittest.skipUnless(CRYPTOGRAPHY_AVAILABLE, "cryptography not installed")
class TestTimingJitter(unittest.TestCase):

    def test_disabled(self):
        jitter = TimingJitter(enabled=False)
        t0 = time.monotonic()
        jitter.delay()
        elapsed = time.monotonic() - t0
        self.assertLess(elapsed, 0.01)

    def test_enabled(self):
        jitter = TimingJitter(mean_ms=50, stddev_ms=10, min_ms=20, max_ms=100,
                              enabled=True)
        t0 = time.monotonic()
        jitter.delay()
        elapsed = time.monotonic() - t0
        self.assertGreaterEqual(elapsed, 0.015)  # min_ms - tolerance
        self.assertLess(elapsed, 0.2)  # max_ms + tolerance


@unittest.skipUnless(CRYPTOGRAPHY_AVAILABLE, "cryptography not installed")
class TestTrafficProfiles(unittest.TestCase):

    def test_plain_profile(self):
        profile = PlainProfile()
        data = b"raw bytes"
        self.assertEqual(profile.wrap_outgoing(data), data)
        self.assertEqual(profile.unwrap_incoming(data), data)
        self.assertEqual(profile.name, "plain")

    def test_cloud_sync_profile_roundtrip(self):
        profile = CloudSyncProfile()
        data = b"secret session data"
        wrapped = profile.wrap_outgoing(data)
        self.assertNotEqual(wrapped, data)

        # Should be valid JSON
        parsed = json.loads(wrapped.decode())
        self.assertEqual(parsed["type"], "sync.chunk")

        unwrapped = profile.unwrap_incoming(wrapped)
        self.assertEqual(unwrapped, data)

    def test_web_api_profile_roundtrip(self):
        profile = WebAPIProfile(channel="jump-session")
        data = b"api payload"
        wrapped = profile.wrap_outgoing(data)

        parsed = json.loads(wrapped.decode())
        self.assertEqual(parsed["type"], "message")
        self.assertEqual(parsed["channel"], "jump-session")

        unwrapped = profile.unwrap_incoming(wrapped)
        self.assertEqual(unwrapped, data)

    def test_profile_handles_unwrap_garbage(self):
        """Profiles gracefully handle non-wrapped data."""
        for profile in [CloudSyncProfile(), WebAPIProfile()]:
            raw = b"not json at all"
            result = profile.unwrap_incoming(raw)
            self.assertEqual(result, raw)


@unittest.skipUnless(CRYPTOGRAPHY_AVAILABLE, "cryptography not installed")
class TestCoverTrafficGenerator(unittest.TestCase):

    def test_pause_blocks_chaff_until_resume(self):
        class DummyConn:
            def __init__(self):
                self.sent = 0
                self._lock = threading.Lock()

            def send(self, *_):
                with self._lock:
                    self.sent += 1

            def recv(self, timeout=None):
                return MsgType.PONG, b"pong"

        conn = DummyConn()
        gen = CoverTrafficGenerator(conn, min_interval=0.01, max_interval=0.02)
        gen.pause()
        gen.start()
        time.sleep(0.2)
        self.assertEqual(conn.sent, 0)

        gen.resume()
        time.sleep(0.2)
        self.assertGreater(conn.sent, 0)
        gen.stop()


@unittest.skipUnless(CRYPTOGRAPHY_AVAILABLE, "cryptography not installed")
class TestNormalizedConnection(unittest.TestCase):

    def test_padding_roundtrip_with_profile(self):
        class LoopbackConn:
            def __init__(self):
                self._last = None

            def send(self, msg_type, payload):
                self._last = (msg_type, payload)

            def recv(self, timeout=None):
                return self._last

            def close(self):
                pass

        base = LoopbackConn()
        norm = NormalizedConnection(
            base,
            profile=CloudSyncProfile(),
            enable_padding=True,
            enable_cover_traffic=False,
        )
        payload = b"classified-payload"
        norm.send(MsgType.SESSION_DATA, payload)
        msg_type, out = norm.recv()

        self.assertEqual(msg_type, MsgType.SESSION_DATA)
        self.assertEqual(out, payload)


# == WebSocket Listener Integration ============================================

@unittest.skipUnless(CRYPTOGRAPHY_AVAILABLE, "cryptography not installed")
class TestWebSocketListener(unittest.TestCase):

    def test_listener_accepts_websocket(self):
        """WebSocketListener upgrades connections and passes them to JumpListener."""
        received_sessions = []

        def on_conn(conn):
            try:
                session = receive_session(conn)
                received_sessions.append(session)
            except Exception:
                pass
            finally:
                conn.close()

        # Set up Jump listener that accepts from any backend
        jump_listener = JumpListener(port=0, on_connection=on_conn)
        # We won't start the TCP listener — just use accept_backend

        # Set up WebSocket listener
        ws_listener = WebSocketListener(
            host="127.0.0.1", port=0, path="/test/ws",
        )
        # Bind to get port
        ws_listener._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ws_listener._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        ws_listener._server_sock.bind(("127.0.0.1", 0))
        ws_port = ws_listener._server_sock.getsockname()[1]
        ws_listener._server_sock.listen(5)
        ws_listener._server_sock.settimeout(2.0)
        ws_listener._running = True
        ws_listener._on_backend = jump_listener.accept_backend
        ws_listener._thread = threading.Thread(
            target=ws_listener._accept_loop, daemon=True)
        ws_listener._thread.start()

        # Connect as WebSocket client
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("127.0.0.1", ws_port))
        excess = _ws_client_handshake(sock, f"127.0.0.1:{ws_port}", "/test/ws")
        client_backend = WebSocketBackend(sock, is_client=True, initial_buf=excess)

        # Full Jump handshake + session transfer
        conn = client_handshake(client_backend, "ws-client")
        session = JumpSession(
            session_id="ws-listener-test",
            source_device="ws-client",
        )
        session.checksum = session.compute_checksum()
        ok = send_session(conn, session)
        conn.close()

        time.sleep(1)

        self.assertTrue(ok)
        self.assertEqual(len(received_sessions), 1)
        self.assertEqual(received_sessions[0].session_id, "ws-listener-test")

        ws_listener.stop()


if __name__ == "__main__":
    unittest.main()
