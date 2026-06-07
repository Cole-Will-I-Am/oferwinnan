"""
WebSocket Transport Backend — Carry Jump frames over WebSocket (ws:// or wss://).

Enables firewall bypass by tunneling the Jump protocol inside standard
WebSocket binary frames on ports 80/443. From a network inspector's
perspective this looks like a normal real-time web application.

Usage:
    # Client side
    backend = WebSocketBackend.connect("wss://195518.online/jump/ws")
    conn = client_handshake(backend, "my-node")

    # Server side — standalone
    ws_listener = WebSocketListener(host="0.0.0.0", port=8443, path="/jump/ws")
    ws_listener.start(on_backend=jump_listener.accept_backend)

    # Server side — behind Caddy reverse proxy
    # Caddy config: reverse_proxy /jump/ws localhost:8443
"""

import json
import logging
import queue
import socket
import ssl
import struct
import threading
import time
from typing import Callable, Optional

logger = logging.getLogger(__name__)


# == WebSocket frame helpers (RFC 6455, minimal implementation) =================

# Opcodes
WS_CONTINUATION = 0x0
WS_TEXT = 0x1
WS_BINARY = 0x2
WS_CLOSE = 0x8
WS_PING = 0x9
WS_PONG = 0xA


def _ws_recv_exact(sock, n: int, buf: bytearray = None) -> bytes:
    """Read exactly n bytes, consuming from buf first, then from socket."""
    if buf is not None and len(buf) >= n:
        result = bytes(buf[:n])
        del buf[:n]
        return result

    result = bytearray()
    if buf is not None and len(buf) > 0:
        result.extend(buf)
        buf.clear()

    while len(result) < n:
        chunk = sock.recv(n - len(result))
        if not chunk:
            raise ConnectionError("WebSocket connection closed")
        result.extend(chunk)
    return bytes(result)


def _ws_read_frame(sock, buf: bytearray = None) -> tuple[int, bytes]:
    """Read a single WebSocket frame, return (opcode, payload).

    If buf is provided, consumes buffered data before reading from socket.
    """
    header = _ws_recv_exact(sock, 2, buf)
    opcode = header[0] & 0x0F
    masked = (header[1] & 0x80) != 0
    length = header[1] & 0x7F

    if length == 126:
        length = struct.unpack("!H", _ws_recv_exact(sock, 2, buf))[0]
    elif length == 127:
        length = struct.unpack("!Q", _ws_recv_exact(sock, 8, buf))[0]

    mask_key = _ws_recv_exact(sock, 4, buf) if masked else None

    payload = _ws_recv_exact(sock, length, buf) if length > 0 else b""

    if mask_key:
        payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))

    return opcode, payload


def _ws_write_frame(sock, opcode: int, payload: bytes, mask: bool = False):
    """Write a single WebSocket frame."""
    frame = bytearray()
    frame.append(0x80 | opcode)  # FIN + opcode

    length = len(payload)
    if mask:
        import os
        mask_key = os.urandom(4)
        if length < 126:
            frame.append(0x80 | length)
        elif length < 65536:
            frame.append(0x80 | 126)
            frame.extend(struct.pack("!H", length))
        else:
            frame.append(0x80 | 127)
            frame.extend(struct.pack("!Q", length))
        frame.extend(mask_key)
        masked_payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
        frame.extend(masked_payload)
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

    sock.sendall(bytes(frame))


def _ws_client_handshake(sock, host: str, path: str) -> bytearray:
    """Perform a WebSocket upgrade handshake (client side).

    Returns any excess bytes received after the HTTP headers (these may
    contain the start of the first WebSocket frame).
    """
    import base64
    import hashlib
    import os

    key = base64.b64encode(os.urandom(16)).decode()
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        f"Sec-WebSocket-Version: 13\r\n"
        f"\r\n"
    )
    sock.sendall(request.encode())

    # Read response headers
    response = bytearray()
    while b"\r\n\r\n" not in response:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("WebSocket handshake failed: connection closed")
        response.extend(chunk)
        if len(response) > 16384:
            raise ConnectionError("WebSocket handshake response too large")

    # Split headers from any trailing data
    sep_idx = response.index(b"\r\n\r\n") + 4
    header_bytes = bytes(response[:sep_idx])
    excess = bytearray(response[sep_idx:])

    header_text = header_bytes.decode("utf-8", errors="replace")
    status_line = header_text.split("\r\n")[0]

    if "101" not in status_line:
        raise ConnectionError(f"WebSocket upgrade rejected: {status_line}")

    # Validate accept key
    expected_accept = base64.b64encode(
        hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-5AB5DF11BE85").encode()).digest()
    ).decode()

    headers_lower = header_text.lower()
    if expected_accept.lower() not in headers_lower:
        raise ConnectionError("WebSocket accept key mismatch")

    return excess


def _ws_server_handshake(sock) -> tuple[str, bytearray]:
    """Perform a WebSocket upgrade handshake (server side).

    Returns (request_path, excess_bytes). Excess bytes may contain the
    start of the first WebSocket frame from the client.
    """
    import base64
    import hashlib

    # Read the HTTP upgrade request
    request = bytearray()
    while b"\r\n\r\n" not in request:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("WebSocket client disconnected during handshake")
        request.extend(chunk)
        if len(request) > 16384:
            raise ConnectionError("WebSocket handshake request too large")

    # Split headers from any trailing data
    sep_idx = request.index(b"\r\n\r\n") + 4
    header_bytes = bytes(request[:sep_idx])
    excess = bytearray(request[sep_idx:])

    header_text = header_bytes.decode("utf-8", errors="replace")
    lines = header_text.split("\r\n")

    # Parse request line
    parts = lines[0].split()
    if len(parts) < 2:
        raise ConnectionError("Malformed WebSocket request")
    path = parts[1]

    # Parse headers
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()

    ws_key = headers.get("sec-websocket-key", "")
    if not ws_key:
        raise ConnectionError("Missing Sec-WebSocket-Key")

    # Compute accept key
    accept = base64.b64encode(
        hashlib.sha1((ws_key + "258EAFA5-E914-47DA-95CA-5AB5DF11BE85").encode()).digest()
    ).decode()

    response = (
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Accept: {accept}\r\n"
        "\r\n"
    )
    sock.sendall(response.encode())

    return path, excess


# == WebSocketBackend ==========================================================

class WebSocketBackend:
    """TransportBackend that carries Jump frames inside WebSocket binary messages.

    Each call to send_bytes() becomes one WebSocket binary frame.
    Each call to recv_bytes(n) reads from a reassembly buffer filled by
    incoming WebSocket binary frames.
    """

    def __init__(self, sock: socket.socket, is_client: bool = True,
                 initial_buf: bytearray = None):
        self._sock = sock
        self._is_client = is_client  # clients must mask frames per RFC 6455
        self._connected = True
        self._recv_buf = bytearray(initial_buf) if initial_buf else bytearray()
        self._ws_buf = bytearray(initial_buf) if initial_buf else bytearray()
        self._lock = threading.Lock()
        self._recv_lock = threading.Lock()
        try:
            peer = sock.getpeername()
            if isinstance(peer, tuple) and len(peer) >= 2:
                self._peer_addr = f"ws://{peer[0]}:{peer[1]}"
            else:
                self._peer_addr = f"ws://{peer}"
        except (OSError, AttributeError):
            self._peer_addr = "ws://unknown"

    @classmethod
    def connect(cls, url: str, timeout: float = 30.0,
                verify_ssl: bool = True) -> "WebSocketBackend":
        """Connect to a WebSocket server.

        Args:
            url: WebSocket URL (ws:// or wss://)
            timeout: Connection timeout in seconds
            verify_ssl: Whether to verify SSL certificates

        Returns:
            A connected WebSocketBackend.
        """
        # Parse URL
        if url.startswith("wss://"):
            use_ssl = True
            rest = url[6:]
            default_port = 443
        elif url.startswith("ws://"):
            use_ssl = False
            rest = url[5:]
            default_port = 80
        else:
            raise ValueError(f"Invalid WebSocket URL: {url}")

        # Split host:port/path
        if "/" in rest:
            host_port, path = rest.split("/", 1)
            path = "/" + path
        else:
            host_port = rest
            path = "/"

        if ":" in host_port:
            host, port_str = host_port.rsplit(":", 1)
            port = int(port_str)
        else:
            host = host_port
            port = default_port

        # Create socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        try:
            if use_ssl:
                ctx = ssl.create_default_context()
                if not verify_ssl:
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)

            sock.connect((host, port))

            # WebSocket upgrade — capture any excess bytes
            excess = _ws_client_handshake(sock, host_port, path)
        except Exception:
            try:
                sock.close()
            except OSError:
                pass
            raise

        backend = cls(sock, is_client=True, initial_buf=excess)
        backend._peer_addr = f"{'wss' if use_ssl else 'ws'}://{host}:{port}{path}"
        return backend

    def send_bytes(self, data: bytes) -> None:
        with self._lock:
            if not self._connected:
                raise ConnectionError("WebSocket is closed")
            try:
                _ws_write_frame(self._sock, WS_BINARY, data, mask=self._is_client)
            except OSError as e:
                self._connected = False
                raise ConnectionError(f"WebSocket send failed: {e}") from e

    def recv_bytes(self, n: int) -> bytes:
        with self._recv_lock:
            while len(self._recv_buf) < n:
                if not self._connected:
                    raise ConnectionError("WebSocket is closed")
                try:
                    opcode, payload = _ws_read_frame(self._sock, self._ws_buf)
                except (ConnectionError, OSError) as e:
                    self._connected = False
                    raise ConnectionError(f"WebSocket recv failed: {e}") from e

                if opcode == WS_BINARY or opcode == WS_TEXT:
                    self._recv_buf.extend(payload)
                elif opcode == WS_PING:
                    # Reply with pong (auto-handle)
                    try:
                        _ws_write_frame(self._sock, WS_PONG, payload,
                                        mask=self._is_client)
                    except OSError:
                        pass
                elif opcode == WS_CLOSE:
                    self._connected = False
                    # Send close back
                    try:
                        _ws_write_frame(self._sock, WS_CLOSE, b"",
                                        mask=self._is_client)
                    except OSError:
                        pass
                    raise ConnectionError("WebSocket closed by peer")
                elif opcode == WS_PONG:
                    continue  # Ignore unsolicited pongs

            result = bytes(self._recv_buf[:n])
            del self._recv_buf[:n]
            return result

    def close(self) -> None:
        if not self._connected:
            return
        self._connected = False
        try:
            _ws_write_frame(self._sock, WS_CLOSE, b"", mask=self._is_client)
        except OSError:
            pass
        try:
            self._sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self._sock.close()
        except OSError:
            pass

    @property
    def peer_address(self) -> str:
        return self._peer_addr

    @property
    def transport_name(self) -> str:
        return "websocket"

    @property
    def is_connected(self) -> bool:
        return self._connected


# == WebSocket Listener ========================================================

class WebSocketListener:
    """TCP/TLS listener that upgrades connections to WebSocket, then hands them
    off as WebSocketBackend instances to a callback.

    Designed to sit behind Caddy (which handles TLS termination) or to run
    standalone with its own SSL context.

    Usage:
        def on_ws_backend(backend: WebSocketBackend):
            jump_listener.accept_backend(backend)

        ws = WebSocketListener(port=8443, path="/jump/ws")
        ws.start(on_backend=on_ws_backend)
    """

    def __init__(self, host: str = "0.0.0.0", port: int = 8443,
                 path: str = "/jump/ws",
                 ssl_context: Optional[ssl.SSLContext] = None,
                 max_connections: int = 64):
        self.host = host
        self.port = port
        self.path = path
        self.ssl_context = ssl_context
        self._server_sock: Optional[socket.socket] = None
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._on_backend: Optional[Callable[[WebSocketBackend], None]] = None
        self._conn_semaphore = threading.Semaphore(max_connections)

    def start(self, on_backend: Callable[[WebSocketBackend], None]):
        """Start accepting WebSocket connections.

        Args:
            on_backend: Called with each accepted WebSocketBackend.
                        Typically pass jump_listener.accept_backend.
        """
        self._on_backend = on_backend
        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.bind((self.host, self.port))
        self._server_sock.listen(5)
        self._server_sock.settimeout(2.0)

        if self.ssl_context:
            self._server_sock = self.ssl_context.wrap_socket(
                self._server_sock, server_side=True,
            )

        self._running = True
        self._thread = threading.Thread(target=self._accept_loop, daemon=True,
                                        name="ws-listener")
        self._thread.start()
        logger.info("WebSocketListener started on %s:%d%s", self.host, self.port, self.path)

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        if self._server_sock:
            try:
                self._server_sock.close()
            except OSError:
                pass
        logger.info("WebSocketListener stopped")

    def _accept_loop(self):
        while self._running:
            try:
                client_sock, addr = self._server_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            if not self._conn_semaphore.acquire(blocking=False):
                try:
                    client_sock.close()
                except OSError:
                    pass
                continue

            threading.Thread(
                target=self._handle_upgrade,
                args=(client_sock, addr),
                daemon=True,
            ).start()

    def _handle_upgrade(self, sock: socket.socket, addr):
        try:
            path, excess = _ws_server_handshake(sock)

            # Validate path if specified
            if self.path and path != self.path:
                logger.warning("WebSocket connection to wrong path: %s (expected %s)",
                               path, self.path)
                sock.close()
                self._conn_semaphore.release()
                return

            backend = WebSocketBackend(sock, is_client=False, initial_buf=excess)
            if self._on_backend:
                self._on_backend(backend)
            self._conn_semaphore.release()

        except (ConnectionError, OSError) as e:
            logger.debug("WebSocket upgrade failed from %s: %s", addr, e)
            self._conn_semaphore.release()
            try:
                sock.close()
            except OSError:
                pass
