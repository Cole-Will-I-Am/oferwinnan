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
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from matrix.symmetric_ratchet import RatchetPair, RatchetError


# == Protocol Constants ========================================================

PROTOCOL_VERSION = 2  # Bumped: transport-agnostic framing
PROTOCOL_VERSION_LEGACY = 1
HEADER_MAGIC = b"JMP\x01"
HEADER_SIZE = 14
from matrix.config import config as _config

MAX_PAYLOAD = _config.max_payload     # 16 MiB per frame
CHUNK_SIZE = _config.chunk_size       # 64 KiB transfer chunks

# Seconds to wait for the encrypted AUTH exchange after key agreement.
AUTH_TIMEOUT = 30.0


class MsgType(IntEnum):
    HELLO = 0x01
    HELLO_ACK = 0x02
    KEY_EXCHANGE = 0x10
    KEY_EXCHANGE_ACK = 0x11
    AUTH = 0x12              # Encrypted post-handshake authentication
    AUTH_OK = 0x13           # Authentication accepted
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


# == Key Exchange (X25519 + Ratcheted AES-256-GCM) ============================

# Ratchet message header: 4-byte big-endian message index prepended to ciphertext
_RATCHET_INDEX_SIZE = 4


@dataclass
class SessionKeys:
    shared_key: bytes       # raw 32-byte shared secret
    fernet: Fernet          # Fernet instance (fallback / legacy)
    peer_public: bytes      # peer's X25519 public key bytes
    connection_id: str = ""  # unique ID for session resumption
    ratchet: Optional[RatchetPair] = None  # per-message forward secrecy

    def encrypt(self, data: bytes) -> bytes:
        """Encrypt data. Uses ratcheted AES-256-GCM if available, else Fernet."""
        if self.ratchet is None:
            return self.fernet.encrypt(data)

        key, idx = self.ratchet.next_send_key()
        if idx > 0xFFFFFFFF:
            raise ProtocolError("Ratchet message index overflow")
        nonce = os.urandom(12)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, data, None)
        # Wire format: [4-byte index][12-byte nonce][ciphertext+tag]
        return struct.pack("!I", idx) + nonce + ciphertext

    def decrypt(self, token: bytes) -> bytes:
        """Decrypt data. Uses ratcheted AES-256-GCM if available, else Fernet."""
        if self.ratchet is None:
            return self.fernet.decrypt(token)

        if len(token) < _RATCHET_INDEX_SIZE + 12:
            raise ProtocolError("Ratcheted ciphertext too short")

        idx = struct.unpack("!I", token[:_RATCHET_INDEX_SIZE])[0]
        nonce = token[_RATCHET_INDEX_SIZE:_RATCHET_INDEX_SIZE + 12]
        ciphertext = token[_RATCHET_INDEX_SIZE + 12:]

        key = b""
        try:
            key = self.ratchet.next_recv_key(idx)
        except RatchetError as e:
            raise ProtocolError(f"Ratchet key derivation failed: {e}") from e

        aesgcm = AESGCM(key)
        try:
            return aesgcm.decrypt(nonce, ciphertext, None)
        except Exception as e:
            # Preserve recoverability for the same message index after a failed
            # authentication attempt (e.g., corruption/tampering in transit).
            self.ratchet.restore_recv_key(idx, key)
            raise ProtocolError(f"AES-GCM decryption failed: {e}") from e

    def clone(self) -> "SessionKeys":
        """Create an independent copy suitable for resumption handoff."""
        return SessionKeys(
            shared_key=self.shared_key,
            fernet=self.fernet,
            peer_public=self.peer_public,
            connection_id=self.connection_id,
            ratchet=self.ratchet.clone() if self.ratchet else None,
        )


def generate_keypair() -> tuple[x25519.X25519PrivateKey, bytes]:
    """Generate an X25519 keypair, returning (private_key, public_bytes)."""
    private = x25519.X25519PrivateKey.generate()
    public_bytes = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return private, public_bytes


def derive_session_keys(private_key: x25519.X25519PrivateKey,
                        peer_public_bytes: bytes,
                        connection_id: str = "",
                        is_initiator: bool = True) -> SessionKeys:
    """Perform X25519 key agreement and derive ratcheted session keys.

    The shared secret feeds both a Fernet key (for legacy/resumption fallback)
    and a RatchetPair that provides per-message forward secrecy via
    AES-256-GCM with Signal-spec KDF_CK chain ratcheting.
    """
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
    ratchet = RatchetPair(derived, is_initiator=is_initiator)
    return SessionKeys(
        shared_key=shared,
        fernet=Fernet(fernet_key),
        peer_public=peer_public_bytes,
        connection_id=connection_id or uuid.uuid4().hex[:16],
        ratchet=ratchet,
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
            # Snapshot the keys so live session traffic cannot mutate the cached
            # ratchet state. Both peers must resume from an identical point for
            # the post-handshake encrypted AUTH exchange to stay in sync.
            self._cache[keys.connection_id] = (keys.clone(), time.monotonic())
            self._evict()

    def get(self, connection_id: str) -> Optional[SessionKeys]:
        with self._lock:
            self._evict()
            entry = self._cache.get(connection_id)
            if entry:
                return entry[0].clone()
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

    The auth token is never placed on the wire in cleartext: authentication
    happens over the encrypted channel after key agreement (AUTH/AUTH_OK).
    """
    backend = _wrap_backend(backend)
    conn_id = connection_id or ""

    # Send HELLO (no auth token — authentication is post-handshake & encrypted)
    hello = json.dumps({
        "node_id": node_id,
        "version": PROTOCOL_VERSION,
        "connection_id": conn_id,
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
        if not cached:
            raise ProtocolError(
                "Server accepted session resumption, but no local session keys are cached"
            )
        conn = JumpConnection(backend, cached, is_initiator=True)
        _client_authenticate(conn, auth_token, ack_info.get("auth_required"))
        return conn

    # Full key exchange (no auth token on the wire)
    private_key, pub_bytes = generate_keypair()
    kx_payload = json.dumps({
        "public_key": pub_bytes.hex(),
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
    keys = derive_session_keys(private_key, peer_pub, connection_id=new_conn_id,
                               is_initiator=True)
    _key_cache.store(keys)
    conn = JumpConnection(backend, keys, is_initiator=True)

    # Authenticate over the encrypted channel before any session traffic.
    _client_authenticate(conn, auth_token, peer_info.get("auth_required"))
    return conn


def _client_authenticate(conn: JumpConnection, auth_token: Optional[str],
                         auth_required) -> None:
    """Send the auth token over the encrypted channel and await AUTH_OK.

    No-op when the server did not request authentication.
    """
    if not auth_required:
        return
    conn.send(MsgType.AUTH, json.dumps({"auth_token": auth_token or ""}).encode())
    try:
        msg_type, payload = conn.recv(timeout=AUTH_TIMEOUT)
    except (TimeoutError, ConnectionError) as e:
        raise ProtocolError(f"No authentication response: {e}") from e
    if msg_type == MsgType.AUTH_OK:
        return
    if msg_type == MsgType.ERROR:
        raise ProtocolError(
            f"Authentication failed: {payload.decode(errors='replace')}"
        )
    raise ProtocolError(f"Expected AUTH_OK, got {msg_type}")


def server_handshake(backend,
                     auth_validator: Callable[[str], bool] = None,
                     key_cache: Optional[SessionKeyCache] = None,
                     ) -> JumpConnection:
    """Perform a server-side handshake: receive HELLO -> KEY_EXCHANGE -> done.

    Accepts a socket.socket or TransportBackend.

    When an auth_validator is supplied, the client must authenticate over the
    encrypted channel (AUTH/AUTH_OK) after key agreement; the token is never
    accepted in cleartext, including on the 0-RTT resumption path.
    """
    backend = _wrap_backend(backend)
    cache = key_cache or _key_cache
    auth_required = auth_validator is not None

    # Receive HELLO
    msg_type, _, payload = recv_frame_from(backend)
    if msg_type != MsgType.HELLO:
        raise ProtocolError(f"Expected HELLO, got {msg_type}")

    hello_info = json.loads(payload.decode())
    requested_conn_id = hello_info.get("connection_id", "")
    peer_node_id = hello_info.get("node_id", "")

    # Attempt 0-RTT resumption
    if requested_conn_id:
        cached = cache.get(requested_conn_id)
        if cached:
            ack = json.dumps({
                "version": PROTOCOL_VERSION,
                "status": "ok",
                "resumed": True,
                "auth_required": auth_required,
            }).encode()
            send_frame_to(backend, MsgType.HELLO_ACK, ack)
            conn = JumpConnection(backend, cached, is_initiator=False,
                                  peer_node_id=peer_node_id)
            # Resumption still authenticates over the encrypted channel.
            _server_authenticate(conn, auth_validator)
            return conn

    # Normal handshake
    ack = json.dumps({
        "version": PROTOCOL_VERSION,
        "status": "ok",
        "resumed": False,
    }).encode()
    send_frame_to(backend, MsgType.HELLO_ACK, ack)

    # Receive KEY_EXCHANGE (no auth token on the wire)
    msg_type, _, kx_payload = recv_frame_from(backend)
    if msg_type != MsgType.KEY_EXCHANGE:
        raise ProtocolError(f"Expected KEY_EXCHANGE, got {msg_type}")
    kx_info = json.loads(kx_payload.decode())
    peer_pub = bytes.fromhex(kx_info["public_key"])

    # Generate our keypair and respond
    private_key, pub_bytes = generate_keypair()
    conn_id = uuid.uuid4().hex[:16]
    kx_resp = json.dumps({
        "public_key": pub_bytes.hex(),
        "connection_id": conn_id,
        "auth_required": auth_required,
    }).encode()
    send_frame_to(backend, MsgType.KEY_EXCHANGE_ACK, kx_resp)

    keys = derive_session_keys(private_key, peer_pub, connection_id=conn_id,
                               is_initiator=False)
    cache.store(keys)
    conn = JumpConnection(backend, keys, is_initiator=False,
                          peer_node_id=peer_node_id)

    # Authenticate over the encrypted channel before any session traffic.
    _server_authenticate(conn, auth_validator)
    return conn


def _server_authenticate(conn: JumpConnection,
                         auth_validator: Optional[Callable[[str], bool]]) -> None:
    """Require an encrypted AUTH frame carrying a valid token, then AUTH_OK.

    No-op when authentication is not configured.
    """
    if auth_validator is None:
        return
    try:
        msg_type, payload = conn.recv(timeout=AUTH_TIMEOUT)
    except (TimeoutError, ConnectionError) as e:
        raise ProtocolError(f"Authentication not received: {e}") from e
    if msg_type != MsgType.AUTH:
        _try_send_error(conn, b"Authentication required")
        raise ProtocolError(f"Expected AUTH, got {msg_type}")
    try:
        token = json.loads(payload.decode()).get("auth_token", "")
    except (ValueError, UnicodeDecodeError) as e:
        _try_send_error(conn, b"Malformed authentication")
        raise ProtocolError(f"Malformed AUTH payload: {e}") from e
    if not auth_validator(token):
        _try_send_error(conn, b"Authentication failed")
        raise ProtocolError("Authentication failed")
    conn.send(MsgType.AUTH_OK, b"")


def _try_send_error(conn: JumpConnection, message: bytes) -> None:
    """Best-effort encrypted ERROR notification; never raises."""
    try:
        conn.send(MsgType.ERROR, message)
    except (ConnectionError, OSError, ProtocolError):
        pass


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

    @staticmethod
    def _is_public_host(host: str) -> bool:
        """True if binding `host` exposes the listener beyond loopback."""
        return host not in ("127.0.0.1", "::1", "localhost")

    def start(self):
        # Refuse to expose an unauthenticated listener on a public interface.
        if self._is_public_host(self.host) and self.auth_validator is None:
            raise PermissionError(
                f"Refusing to start an unauthenticated listener on public address "
                f"'{self.host}'. Set an auth token (MATRIX_AUTH_TOKEN or --token) "
                f"to listen on a public interface, or bind to 127.0.0.1 for "
                f"local-only use."
            )
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
