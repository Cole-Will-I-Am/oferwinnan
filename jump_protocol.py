"""
Jump Protocol — Secure connection and data transfer for cross-device jumping.

Handles connections with TLS-like key exchange (using Fernet symmetric
encryption), chunked data transfer, and protocol framing so that session
state can be moved reliably between devices.

Transport-agnostic: any backend implementing the TransportBackend protocol
(TCP, WebSocket, QUIC, relay chain, etc.) can carry Jump frames.
"""

import hashlib
import hmac
import json
import os
import socket
import struct
import threading
import time
import uuid
from collections import deque
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Callable, Dict, Optional, Protocol, runtime_checkable

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization


# == Protocol Constants ========================================================

PROTOCOL_VERSION = 2  # Bumped: transport-agnostic framing
PROTOCOL_VERSION_LEGACY = 1
HEADER_MAGIC = b"JMP\x01"
HEADER_SIZE = 14
MAX_PAYLOAD = 16 * 1024 * 1024  # 16 MiB per frame
CHUNK_SIZE = 64 * 1024           # 64 KiB transfer chunks


class MsgType(IntEnum):
    HELLO = 0x01
    HELLO_ACK = 0x02
    KEY_EXCHANGE = 0x10
    KEY_EXCHANGE_ACK = 0x11
    SESSION_DATA = 0x20
    SESSION_ACK = 0x21
    RESUME = 0x22            # NEW: resume a transfer from a given offset
    RESUME_ACK = 0x23        # NEW: server confirms resume capability
    FILE_CHUNK = 0x30
    FILE_META = 0x31
    FILE_ACK = 0x32
    CHUNK_ACK = 0x33         # NEW: per-chunk acknowledgement
    PING = 0x40
    PONG = 0x41
    HEARTBEAT = 0x42         # NEW: health monitoring heartbeat
    HEARTBEAT_ACK = 0x43     # NEW: heartbeat response
    TRANSPORT_PROBE = 0x50   # NEW: transport negotiation probe
    TRANSPORT_SELECT = 0x51  # NEW: transport selection
    TERMINATE = 0x60         # Secure termination command
    TERMINATE_ACK = 0x61     # Termination acknowledgement
    RELAY = 0x70             # Peer-to-peer relay message
    RELAY_ACK = 0x71         # Relay acknowledgement
    ROUTE_UPDATE = 0x72      # Relay routing table update
    SYNC_MANIFEST = 0x80     # Data sync manifest exchange
    SYNC_REQUEST = 0x81      # Data sync request
    SYNC_CHUNK = 0x82        # Data sync chunk
    SYNC_ACK = 0x83          # Data sync acknowledgement
    ERROR = 0xFF


# == Transport Backend Abstraction =============================================

@runtime_checkable
class TransportBackend(Protocol):
    """Protocol that any transport layer must implement.

    Backends handle raw byte I/O. The Jump protocol framing, encryption,
    and handshake sit on top — completely transport-agnostic.
    """

    def send_bytes(self, data: bytes) -> None:
        """Send raw bytes. Must deliver the complete buffer or raise."""
        ...

    def recv_bytes(self, n: int) -> bytes:
        """Receive exactly `n` bytes. Blocks until complete or raises."""
        ...

    def close(self) -> None:
        """Close the transport. Idempotent."""
        ...

    @property
    def peer_address(self) -> str:
        """Human-readable address of the remote peer."""
        ...

    @property
    def transport_name(self) -> str:
        """Short identifier: 'tcp', 'websocket', 'quic', 'relay', etc."""
        ...

    @property
    def is_connected(self) -> bool:
        """Whether the transport believes it's still connected."""
        ...


class DirectTCPBackend:
    """TransportBackend wrapping a plain TCP socket — the original transport."""

    def __init__(self, sock: socket.socket):
        self._sock = sock
        self._connected = True
        try:
            peer = sock.getpeername()
            if isinstance(peer, tuple) and len(peer) >= 2:
                self._peer_addr = f"{peer[0]}:{peer[1]}"
            else:
                self._peer_addr = str(peer)
        except (OSError, AttributeError):
            self._peer_addr = "unknown"

    def send_bytes(self, data: bytes) -> None:
        try:
            self._sock.sendall(data)
        except OSError as e:
            self._connected = False
            raise ConnectionError(f"TCP send failed: {e}") from e

    def recv_bytes(self, n: int) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            try:
                chunk = self._sock.recv(n - len(buf))
            except OSError as e:
                self._connected = False
                raise ConnectionError(f"TCP recv failed: {e}") from e
            if not chunk:
                self._connected = False
                raise ConnectionError("Connection closed while reading")
            buf.extend(chunk)
        return bytes(buf)

    def close(self) -> None:
        self._connected = False
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
        return "tcp"

    @property
    def is_connected(self) -> bool:
        return self._connected

    @property
    def sock(self) -> socket.socket:
        """Access the underlying socket (for legacy code or setsockopt)."""
        return self._sock


def _wrap_backend(sock_or_backend) -> TransportBackend:
    """Accept a socket.socket or TransportBackend, return a TransportBackend."""
    if isinstance(sock_or_backend, TransportBackend):
        return sock_or_backend
    if isinstance(sock_or_backend, socket.socket):
        return DirectTCPBackend(sock_or_backend)
    raise TypeError(
        f"Expected socket.socket or TransportBackend, got {type(sock_or_backend).__name__}"
    )


# == Frame encoding / decoding ================================================

def encode_frame(msg_type: MsgType, payload: bytes, seq: int = 0) -> bytes:
    """Encode a protocol frame: magic(4) + version(1) + type(1) + seq(4) + length(4) + payload."""
    header = HEADER_MAGIC + struct.pack("!BBII", PROTOCOL_VERSION,
                                        int(msg_type), seq, len(payload))
    return header + payload


def decode_frame(data: bytes) -> tuple[MsgType, int, bytes]:
    """Decode a protocol frame, returning (msg_type, seq, payload)."""
    if len(data) < HEADER_SIZE or data[:4] != HEADER_MAGIC:
        raise ProtocolError("Invalid frame header")
    version, mtype, seq, length = struct.unpack("!BBII", data[4:HEADER_SIZE])
    if version not in (PROTOCOL_VERSION, PROTOCOL_VERSION_LEGACY):
        raise ProtocolError(f"Unsupported protocol version {version}")
    payload = data[HEADER_SIZE:HEADER_SIZE + length]
    if len(payload) != length:
        raise ProtocolError("Truncated payload")
    return MsgType(mtype), seq, payload


# -- Backend-based frame I/O --------------------------------------------------

def recv_frame_from(backend: TransportBackend) -> tuple[MsgType, int, bytes]:
    """Read exactly one frame from a TransportBackend."""
    header = backend.recv_bytes(HEADER_SIZE)
    if header[:4] != HEADER_MAGIC:
        raise ProtocolError("Invalid frame header")
    version, mtype, seq, length = struct.unpack("!BBII", header[4:HEADER_SIZE])
    if version not in (PROTOCOL_VERSION, PROTOCOL_VERSION_LEGACY):
        raise ProtocolError(f"Unsupported protocol version {version}")
    if length > MAX_PAYLOAD:
        raise ProtocolError(f"Payload too large: {length}")
    payload = backend.recv_bytes(length) if length > 0 else b""
    return MsgType(mtype), seq, payload


def send_frame_to(backend: TransportBackend, msg_type: MsgType,
                  payload: bytes, seq: int = 0):
    """Send one frame over a TransportBackend."""
    backend.send_bytes(encode_frame(msg_type, payload, seq))


# -- Legacy socket-based wrappers (backward compatibility) ---------------------

def recv_frame(sock: socket.socket) -> tuple[MsgType, int, bytes]:
    """Read exactly one frame from a socket. Legacy wrapper."""
    header = _recv_exact(sock, HEADER_SIZE)
    if header[:4] != HEADER_MAGIC:
        raise ProtocolError("Invalid frame header")
    version, mtype, seq, length = struct.unpack("!BBII", header[4:HEADER_SIZE])
    if version not in (PROTOCOL_VERSION, PROTOCOL_VERSION_LEGACY):
        raise ProtocolError(f"Unsupported protocol version {version}")
    if length > MAX_PAYLOAD:
        raise ProtocolError(f"Payload too large: {length}")
    payload = _recv_exact(sock, length) if length > 0 else b""
    return MsgType(mtype), seq, payload


def send_frame(sock: socket.socket, msg_type: MsgType, payload: bytes,
               seq: int = 0):
    """Send one frame over a socket. Legacy wrapper."""
    sock.sendall(encode_frame(msg_type, payload, seq))


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed while reading")
        buf.extend(chunk)
    return bytes(buf)


class ProtocolError(Exception):
    pass


# == Key Exchange (X25519 + Fernet) ============================================

@dataclass
class SessionKeys:
    shared_key: bytes       # raw 32-byte shared secret
    fernet: Fernet          # derived Fernet instance for encrypt/decrypt
    peer_public: bytes      # peer's X25519 public key bytes
    connection_id: str = ""  # unique ID for session resumption

    def encrypt(self, data: bytes) -> bytes:
        return self.fernet.encrypt(data)

    def decrypt(self, token: bytes) -> bytes:
        return self.fernet.decrypt(token)


def generate_keypair() -> tuple[x25519.X25519PrivateKey, bytes]:
    """Generate an X25519 keypair, returning (private_key, public_bytes)."""
    private = x25519.X25519PrivateKey.generate()
    public_bytes = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return private, public_bytes


def derive_session_keys(private_key: x25519.X25519PrivateKey,
                        peer_public_bytes: bytes,
                        connection_id: str = "") -> SessionKeys:
    """Perform X25519 key agreement and derive a Fernet key via HKDF."""
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    import base64

    peer_public = x25519.X25519PublicKey.from_public_bytes(peer_public_bytes)
    shared = private_key.exchange(peer_public)
    derived = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"matrix-jump-v2",
    ).derive(shared)
    fernet_key = base64.urlsafe_b64encode(derived)
    return SessionKeys(
        shared_key=shared,
        fernet=Fernet(fernet_key),
        peer_public=peer_public_bytes,
        connection_id=connection_id or uuid.uuid4().hex[:16],
    )


# == Connection (wraps a backend with encryption + framing) ====================

class JumpConnection:
    """An encrypted, framed connection between two devices.

    Transport-agnostic: works over any TransportBackend (TCP, WebSocket, etc.).
    Also accepts a raw socket.socket for backward compatibility.
    """

    def __init__(self, backend, keys: SessionKeys, is_initiator: bool,
                 peer_node_id: str = ""):
        self.backend: TransportBackend = _wrap_backend(backend)
        self.keys = keys
        self.is_initiator = is_initiator
        self.peer_node_id = peer_node_id
        self._seq = 0
        self._lock = threading.Lock()
        self._recv_lock = threading.Lock()
        self._pending_recv: deque[tuple[MsgType, bytes]] = deque()
        self._heartbeat_thread: Optional[threading.Thread] = None
        self._heartbeat_running = False
        self._rtt_samples: list[float] = []
        self._last_heartbeat_ack: float = time.monotonic()

        # Backward compat: expose .sock if the backend is TCP
        if isinstance(self.backend, DirectTCPBackend):
            self.sock = self.backend.sock
        else:
            self.sock = None

    def send(self, msg_type: MsgType, payload: bytes):
        encrypted = self.keys.encrypt(payload)
        with self._lock:
            self._seq += 1
            send_frame_to(self.backend, msg_type, encrypted, self._seq)

    def _infer_backend_socket(self) -> Optional[socket.socket]:
        if isinstance(self.backend, DirectTCPBackend):
            return self.backend.sock
        raw = getattr(self.backend, "_sock", None)
        if isinstance(raw, socket.socket):
            return raw
        return None

    def _recv_one_unlocked(self) -> tuple[MsgType, bytes]:
        msg_type, _, encrypted = recv_frame_from(self.backend)
        payload = self.keys.decrypt(encrypted)
        return msg_type, payload

    def _recv_with_timeout_unlocked(
        self, timeout: Optional[float]
    ) -> Optional[tuple[MsgType, bytes]]:
        if timeout is None:
            return self._recv_one_unlocked()
        if timeout <= 0:
            return None

        sock_ref = self._infer_backend_socket()
        if sock_ref is None:
            return self._recv_one_unlocked()

        prev_timeout = sock_ref.gettimeout()
        try:
            sock_ref.settimeout(timeout)
            return self._recv_one_unlocked()
        except socket.timeout:
            return None
        finally:
            try:
                sock_ref.settimeout(prev_timeout)
            except OSError:
                pass

    def _recv_expected(
        self, expected: set[MsgType], timeout: Optional[float] = None
    ) -> Optional[tuple[MsgType, bytes]]:
        deadline = None if timeout is None else time.monotonic() + timeout

        while True:
            with self._recv_lock:
                for idx, item in enumerate(self._pending_recv):
                    if item[0] in expected:
                        matched = self._pending_recv[idx]
                        del self._pending_recv[idx]
                        return matched

                remaining = None
                if deadline is not None:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        return None

                item = self._recv_with_timeout_unlocked(remaining)
                if item is None:
                    return None
                if item[0] in expected:
                    return item
                self._pending_recv.append(item)
            # A non-matching frame arrived; let callers consume it.
            return None

    def recv(self, timeout: Optional[float] = None) -> tuple[MsgType, bytes]:
        with self._recv_lock:
            if self._pending_recv:
                return self._pending_recv.popleft()

            item = self._recv_with_timeout_unlocked(timeout)
            if item is None:
                raise TimeoutError("Receive timed out")
            return item

    def send_json(self, msg_type: MsgType, obj: dict):
        self.send(msg_type, json.dumps(obj).encode())

    def recv_json(self) -> tuple[MsgType, dict]:
        msg_type, data = self.recv()
        return msg_type, json.loads(data.decode())

    def ping(self, timeout: float = 5.0) -> float:
        t0 = time.time()
        self.send(MsgType.PING, b"ping")
        matched = self._recv_expected({MsgType.PONG}, timeout=timeout)
        if not matched:
            raise ProtocolError("Timed out waiting for PONG")
        return time.time() - t0

    def close(self):
        self.stop_heartbeat()
        self.backend.close()

    @property
    def connection_id(self) -> str:
        return self.keys.connection_id

    @property
    def transport_name(self) -> str:
        return self.backend.transport_name

    @property
    def peer_address(self) -> str:
        return self.backend.peer_address

    @property
    def is_connected(self) -> bool:
        return self.backend.is_connected

    # -- Heartbeat system ------------------------------------------------------

    def start_heartbeat(self, interval: float = 2.0,
                        on_degraded: Optional[Callable[["JumpConnection"], None]] = None,
                        missed_threshold: int = 3,
                        ack_timeout: float = 2.0):
        """Start background heartbeat monitoring."""
        if self._heartbeat_running:
            return
        self._heartbeat_running = True
        self._heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop,
            args=(interval, on_degraded, missed_threshold, ack_timeout),
            daemon=True,
        )
        self._heartbeat_thread.start()

    def stop_heartbeat(self):
        self._heartbeat_running = False
        if self._heartbeat_thread:
            self._heartbeat_thread.join(timeout=5)
            self._heartbeat_thread = None

    @property
    def avg_rtt(self) -> float:
        """Exponentially weighted moving average RTT in seconds."""
        if not self._rtt_samples:
            return 0.0
        return self._rtt_samples[-1]

    def _heartbeat_loop(self, interval: float, on_degraded, missed_threshold: int,
                        ack_timeout: float):
        missed = 0
        ewma_rtt = 0.0
        alpha = 0.3  # EWMA smoothing factor

        while self._heartbeat_running and self.backend.is_connected:
            t0 = time.monotonic()
            try:
                self.send(MsgType.HEARTBEAT, struct.pack("!d", t0))
                matched = self._recv_expected({MsgType.HEARTBEAT_ACK},
                                              timeout=ack_timeout)
                if matched:
                    rtt = time.monotonic() - t0
                    ewma_rtt = alpha * rtt + (1 - alpha) * ewma_rtt if ewma_rtt else rtt
                    self._rtt_samples.append(ewma_rtt)
                    if len(self._rtt_samples) > 100:
                        self._rtt_samples = self._rtt_samples[-50:]
                    self._last_heartbeat_ack = time.monotonic()
                    missed = 0
                else:
                    missed += 1
            except (ConnectionError, ProtocolError, OSError, TimeoutError):
                missed += 1

            if missed >= missed_threshold and on_degraded:
                on_degraded(self)
                break

            elapsed = time.monotonic() - t0
            sleep_time = interval - elapsed
            if sleep_time > 0:
                time.sleep(sleep_time)


# == Session Key Cache (for 0-RTT resumption) ==================================

class SessionKeyCache:
    """Short-lived cache of SessionKeys for connection resumption.

    Keys are stored by connection_id and expire after ttl seconds.
    Thread-safe.
    """

    def __init__(self, ttl: float = 60.0):
        self._cache: Dict[str, tuple[SessionKeys, float]] = {}
        self._ttl = ttl
        self._lock = threading.Lock()

    def store(self, keys: SessionKeys) -> None:
        with self._lock:
            self._cache[keys.connection_id] = (keys, time.monotonic())
            self._evict()

    def get(self, connection_id: str) -> Optional[SessionKeys]:
        with self._lock:
            self._evict()
            entry = self._cache.get(connection_id)
            if entry:
                return entry[0]
            return None

    def remove(self, connection_id: str) -> None:
        with self._lock:
            self._cache.pop(connection_id, None)

    def _evict(self):
        now = time.monotonic()
        expired = [k for k, (_, ts) in self._cache.items()
                   if now - ts > self._ttl]
        for k in expired:
            del self._cache[k]


# Global key cache instance
_key_cache = SessionKeyCache(ttl=60.0)


# == Handshake helpers =========================================================

def client_handshake(backend, node_id: str,
                     auth_token: str = None,
                     connection_id: str = None) -> JumpConnection:
    """Perform a client-side handshake: HELLO -> KEY_EXCHANGE -> done.

    Accepts a socket.socket or TransportBackend.
    If connection_id is provided, attempts 0-RTT resumption.
    """
    backend = _wrap_backend(backend)
    conn_id = connection_id or ""

    # Send HELLO
    hello = json.dumps({
        "node_id": node_id,
        "version": PROTOCOL_VERSION,
        "connection_id": conn_id,
        "auth_token": auth_token or "",
    }).encode()
    send_frame_to(backend, MsgType.HELLO, hello)

    # Receive HELLO_ACK
    msg_type, _, payload = recv_frame_from(backend)
    if msg_type == MsgType.ERROR:
        raise ProtocolError(f"Server error: {payload.decode()}")
    if msg_type != MsgType.HELLO_ACK:
        raise ProtocolError(f"Expected HELLO_ACK, got {msg_type}")

    ack_info = json.loads(payload.decode())

    # Check for 0-RTT resumption
    if ack_info.get("resumed") and conn_id:
        cached = _key_cache.get(conn_id)
        if cached:
            return JumpConnection(backend, cached, is_initiator=True)
        raise ProtocolError(
            "Server accepted session resumption, but no local session keys are cached"
        )

    # Full key exchange
    private_key, pub_bytes = generate_keypair()
    kx_payload = json.dumps({
        "public_key": pub_bytes.hex(),
        "auth_token": auth_token or "",
    }).encode()
    send_frame_to(backend, MsgType.KEY_EXCHANGE, kx_payload)

    # Receive KEY_EXCHANGE_ACK
    msg_type, _, kx_resp = recv_frame_from(backend)
    if msg_type == MsgType.ERROR:
        raise ProtocolError(f"Key exchange failed: {kx_resp.decode()}")
    if msg_type != MsgType.KEY_EXCHANGE_ACK:
        raise ProtocolError(f"Expected KEY_EXCHANGE_ACK, got {msg_type}")
    peer_info = json.loads(kx_resp.decode())
    peer_pub = bytes.fromhex(peer_info["public_key"])

    new_conn_id = peer_info.get("connection_id", "")
    keys = derive_session_keys(private_key, peer_pub, connection_id=new_conn_id)
    _key_cache.store(keys)
    return JumpConnection(backend, keys, is_initiator=True)


def server_handshake(backend,
                     auth_validator: Callable[[str], bool] = None,
                     key_cache: Optional[SessionKeyCache] = None,
                     ) -> JumpConnection:
    """Perform a server-side handshake: receive HELLO -> KEY_EXCHANGE -> done.

    Accepts a socket.socket or TransportBackend.
    """
    backend = _wrap_backend(backend)
    cache = key_cache or _key_cache

    # Receive HELLO
    msg_type, _, payload = recv_frame_from(backend)
    if msg_type != MsgType.HELLO:
        raise ProtocolError(f"Expected HELLO, got {msg_type}")

    hello_info = json.loads(payload.decode())
    requested_conn_id = hello_info.get("connection_id", "")
    hello_auth_token = hello_info.get("auth_token", "")
    peer_node_id = hello_info.get("node_id", "")

    # Attempt 0-RTT resumption
    if requested_conn_id:
        cached = cache.get(requested_conn_id)
        if cached:
            if auth_validator:
                # Resume must be authenticated before skipping key exchange.
                if not hello_auth_token:
                    cached = None
                elif not auth_validator(hello_auth_token):
                    send_frame_to(backend, MsgType.ERROR, b"Authentication failed")
                    raise ProtocolError("Authentication failed")
        if cached:
            ack = json.dumps({
                "version": PROTOCOL_VERSION,
                "status": "ok",
                "resumed": True,
            }).encode()
            send_frame_to(backend, MsgType.HELLO_ACK, ack)
            return JumpConnection(backend, cached, is_initiator=False,
                                  peer_node_id=peer_node_id)

    # Normal handshake
    ack = json.dumps({
        "version": PROTOCOL_VERSION,
        "status": "ok",
        "resumed": False,
    }).encode()
    send_frame_to(backend, MsgType.HELLO_ACK, ack)

    # Receive KEY_EXCHANGE
    msg_type, _, kx_payload = recv_frame_from(backend)
    if msg_type != MsgType.KEY_EXCHANGE:
        raise ProtocolError(f"Expected KEY_EXCHANGE, got {msg_type}")
    kx_info = json.loads(kx_payload.decode())

    # Validate auth token
    if auth_validator and not auth_validator(kx_info.get("auth_token", "")):
        send_frame_to(backend, MsgType.ERROR, b"Authentication failed")
        raise ProtocolError("Authentication failed")

    peer_pub = bytes.fromhex(kx_info["public_key"])

    # Generate our keypair and respond
    private_key, pub_bytes = generate_keypair()
    conn_id = uuid.uuid4().hex[:16]
    kx_resp = json.dumps({
        "public_key": pub_bytes.hex(),
        "connection_id": conn_id,
    }).encode()
    send_frame_to(backend, MsgType.KEY_EXCHANGE_ACK, kx_resp)

    keys = derive_session_keys(private_key, peer_pub, connection_id=conn_id)
    cache.store(keys)
    return JumpConnection(backend, keys, is_initiator=False,
                          peer_node_id=peer_node_id)


# == Listener ==================================================================

class JumpListener:
    """Listener that accepts incoming jump connections.

    By default listens on TCP, but can accept connections from any
    TransportBackend via accept_backend().
    """

    def __init__(self, host: str = "0.0.0.0", port: int = 47701,
                 auth_validator: Callable[[str], bool] = None,
                 on_connection: Callable[[JumpConnection], None] = None,
                 max_connections: int = 64):
        self.host = host
        self.port = port
        self.auth_validator = auth_validator
        self.on_connection = on_connection
        self._server_sock: Optional[socket.socket] = None
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._conn_semaphore = threading.Semaphore(max_connections)
        self._key_cache = SessionKeyCache(ttl=60.0)

    def start(self):
        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.bind((self.host, self.port))
        self._server_sock.listen(5)
        self._server_sock.settimeout(2.0)
        self._running = True
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        if self._server_sock:
            self._server_sock.close()

    def accept_backend(self, backend: TransportBackend):
        """Accept a connection from any TransportBackend (WebSocket, relay, etc.)."""
        if not self._conn_semaphore.acquire(blocking=False):
            backend.close()
            return
        try:
            conn = server_handshake(
                backend,
                auth_validator=self.auth_validator,
                key_cache=self._key_cache,
            )
            if self.on_connection:
                threading.Thread(
                    target=self._guarded_handler,
                    args=(conn,), daemon=True,
                ).start()
            else:
                self._conn_semaphore.release()
        except (ProtocolError, ConnectionError, OSError):
            self._conn_semaphore.release()
            backend.close()

    def _accept_loop(self):
        while self._running:
            try:
                client_sock, addr = self._server_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            # Wrap in backend and delegate
            backend = DirectTCPBackend(client_sock)
            self.accept_backend(backend)

    def _guarded_handler(self, conn: JumpConnection):
        """Wrap on_connection to ensure the semaphore is always released."""
        try:
            self.on_connection(conn)
        finally:
            self._conn_semaphore.release()
