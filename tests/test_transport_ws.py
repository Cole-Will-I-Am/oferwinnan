"""Tests for matrix.transport_ws — WebSocket framing, handshake, and backend."""

import os
import struct
import socket
import threading
import unittest
from unittest.mock import MagicMock, patch

from matrix.transport_ws import (
    _ws_read_frame, _ws_write_frame, _ws_recv_exact,
    _ws_client_handshake, _ws_server_handshake,
    WebSocketBackend, WebSocketListener,
    WS_BINARY, WS_TEXT, WS_CLOSE, WS_PING, WS_PONG,
)


class TestWsRecvExact(unittest.TestCase):
    """Test _ws_recv_exact helper."""

    def test_from_buffer_only(self):
        buf = bytearray(b"hello world")
        result = _ws_recv_exact(None, 5, buf)
        self.assertEqual(result, b"hello")
        self.assertEqual(buf, bytearray(b" world"))

    def test_from_socket(self):
        sock = MagicMock()
        sock.recv.return_value = b"data"
        result = _ws_recv_exact(sock, 4)
        self.assertEqual(result, b"data")

    def test_partial_buffer_then_socket(self):
        sock = MagicMock()
        sock.recv.return_value = b"ld"
        buf = bytearray(b"wor")
        result = _ws_recv_exact(sock, 5, buf)
        self.assertEqual(result, b"world")
        self.assertEqual(len(buf), 0)

    def test_connection_closed(self):
        sock = MagicMock()
        sock.recv.return_value = b""
        with self.assertRaises(ConnectionError):
            _ws_recv_exact(sock, 5)


class TestWsFraming(unittest.TestCase):
    """Test WebSocket frame read/write."""

    def _make_frame(self, opcode, payload, mask=False):
        """Build a raw WebSocket frame for testing."""
        frame = bytearray()
        frame.append(0x80 | opcode)
        length = len(payload)
        if mask:
            mask_key = b"\x01\x02\x03\x04"
            if length < 126:
                frame.append(0x80 | length)
            elif length < 65536:
                frame.append(0x80 | 126)
                frame.extend(struct.pack("!H", length))
            else:
                frame.append(0x80 | 127)
                frame.extend(struct.pack("!Q", length))
            frame.extend(mask_key)
            masked = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
            frame.extend(masked)
        else:
            if length < 126:
                frame.append(length)
            elif length < 65536:
                frame.append(126)
                frame.extend(struct.pack("!H", length))
            else:
                frame.append(127)
                frame.extend(struct.pack("!Q", length))
            frame.extend(payload)
        return bytes(frame)

    def test_read_unmasked_binary_frame(self):
        payload = b"hello"
        raw = self._make_frame(WS_BINARY, payload)
        sock = MagicMock()
        sock.recv.side_effect = [raw]
        buf = bytearray(raw)
        opcode, data = _ws_read_frame(sock, buf)
        self.assertEqual(opcode, WS_BINARY)
        self.assertEqual(data, payload)

    def test_read_masked_frame(self):
        payload = b"test data"
        raw = self._make_frame(WS_BINARY, payload, mask=True)
        buf = bytearray(raw)
        sock = MagicMock()
        opcode, data = _ws_read_frame(sock, buf)
        self.assertEqual(opcode, WS_BINARY)
        self.assertEqual(data, payload)

    def test_write_frame_unmasked(self):
        sock = MagicMock()
        payload = b"hello"
        _ws_write_frame(sock, WS_BINARY, payload, mask=False)
        sock.sendall.assert_called_once()
        sent = sock.sendall.call_args[0][0]
        self.assertEqual(sent[0] & 0x0F, WS_BINARY)
        self.assertEqual(sent[0] & 0x80, 0x80)  # FIN set

    def test_write_frame_masked(self):
        sock = MagicMock()
        payload = b"hello"
        _ws_write_frame(sock, WS_TEXT, payload, mask=True)
        sock.sendall.assert_called_once()
        sent = sock.sendall.call_args[0][0]
        self.assertTrue(sent[1] & 0x80)  # Mask bit set

    def test_read_medium_payload(self):
        """Test 126-byte extended payload length."""
        payload = b"x" * 200
        raw = self._make_frame(WS_BINARY, payload)
        buf = bytearray(raw)
        sock = MagicMock()
        opcode, data = _ws_read_frame(sock, buf)
        self.assertEqual(len(data), 200)
        self.assertEqual(data, payload)

    def test_write_medium_payload(self):
        sock = MagicMock()
        payload = b"y" * 200
        _ws_write_frame(sock, WS_BINARY, payload)
        sent = sock.sendall.call_args[0][0]
        # Length byte should be 126 (extended)
        self.assertEqual(sent[1] & 0x7F, 126)


class TestWebSocketBackend(unittest.TestCase):
    """Test WebSocketBackend send/recv/close."""

    def _make_backend(self, is_client=True):
        sock = MagicMock(spec=socket.socket)
        sock.getpeername.return_value = ("127.0.0.1", 8080)
        return WebSocketBackend(sock, is_client=is_client)

    def test_properties(self):
        backend = self._make_backend()
        self.assertEqual(backend.transport_name, "websocket")
        self.assertTrue(backend.is_connected)
        self.assertIn("ws://", backend.peer_address)

    def test_send_when_closed(self):
        backend = self._make_backend()
        backend._connected = False
        with self.assertRaises(ConnectionError):
            backend.send_bytes(b"data")

    def test_close_idempotent(self):
        backend = self._make_backend()
        backend.close()
        self.assertFalse(backend.is_connected)
        backend.close()  # Should not raise

    def test_connect_invalid_url(self):
        with self.assertRaises(ValueError):
            WebSocketBackend.connect("http://example.com")

    def test_connect_parses_wss(self):
        with patch("matrix.transport_ws.socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock_cls.return_value = mock_sock
            mock_sock.recv.return_value = b""
            with patch("matrix.transport_ws.ssl.create_default_context") as mock_ssl:
                mock_ctx = MagicMock()
                mock_ssl.return_value = mock_ctx
                mock_ctx.wrap_socket.return_value = mock_sock
                mock_sock.recv.side_effect = ConnectionError("test")
                with self.assertRaises(ConnectionError):
                    WebSocketBackend.connect("wss://example.com/ws", timeout=1)


class TestWebSocketHandshake(unittest.TestCase):
    """Test WebSocket upgrade handshake logic."""

    def test_server_handshake_missing_key(self):
        sock = MagicMock()
        # HTTP request without Sec-WebSocket-Key
        request = b"GET /ws HTTP/1.1\r\nHost: localhost\r\n\r\n"
        sock.recv.return_value = request
        with self.assertRaises(ConnectionError):
            _ws_server_handshake(sock)

    def test_server_handshake_malformed_request(self):
        sock = MagicMock()
        sock.recv.return_value = b"INVALID\r\n\r\n"
        with self.assertRaises(ConnectionError):
            _ws_server_handshake(sock)

    def test_client_handshake_rejected(self):
        sock = MagicMock()
        # Return a non-101 response
        sock.recv.return_value = b"HTTP/1.1 403 Forbidden\r\n\r\n"
        with self.assertRaises(ConnectionError):
            _ws_client_handshake(sock, "localhost", "/ws")

    def test_client_handshake_closed(self):
        sock = MagicMock()
        sock.recv.return_value = b""
        with self.assertRaises(ConnectionError):
            _ws_client_handshake(sock, "localhost", "/ws")

    def test_full_handshake_roundtrip(self):
        """Test client and server handshake against each other via socketpair."""
        s1, s2 = socket.socketpair()
        s1.settimeout(5)
        s2.settimeout(5)

        result = {}

        def server_side():
            try:
                path, excess = _ws_server_handshake(s2)
                result["path"] = path
                result["ok"] = True
            except Exception as e:
                result["error"] = str(e)

        t = threading.Thread(target=server_side)
        t.start()

        try:
            excess = _ws_client_handshake(s1, "localhost", "/jump/ws")
            t.join(timeout=5)
            self.assertTrue(result.get("ok"), f"Server failed: {result.get('error')}")
            self.assertEqual(result["path"], "/jump/ws")
        finally:
            s1.close()
            s2.close()
            t.join(timeout=2)


class TestWebSocketListener(unittest.TestCase):
    """Test WebSocketListener lifecycle."""

    def test_start_stop(self):
        listener = WebSocketListener(port=0, path="/test")
        callback = MagicMock()
        # Use port 0 to get an ephemeral port
        listener.port = 0
        try:
            listener.start(on_backend=callback)
            self.assertTrue(listener._running)
        finally:
            listener.stop()
            self.assertFalse(listener._running)


if __name__ == "__main__":
    unittest.main()
