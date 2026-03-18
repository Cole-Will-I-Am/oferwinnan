"""
Jump Protocol — Secure connection and data transfer for cross-device jumping.

Handles TCP connections with TLS-like key exchange (using Fernet symmetric
encryption), chunked data transfer, and protocol framing so that session
state can be moved reliably between devices.
"""

import hashlib
import hmac
import json
import os
import socket
import struct
import threading
import time
from dataclasses import dataclass
from enum import IntEnum
from typing import Callable, Optional

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization


# ── Protocol Constants ───────────────────────────────────────────────────────

PROTOCOL_VERSION = 1
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
    FILE_CHUNK = 0x30
    FILE_META = 0x31
    FILE_ACK = 0x32
    PING = 0x40
    PONG = 0x41
    ERROR = 0xFF


# ── Frame encoding / decoding ───────────────────────────────────────────────

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
    if version != PROTOCOL_VERSION:
        raise ProtocolError(f"Unsupported protocol version {version}")
    payload = data[HEADER_SIZE:HEADER_SIZE + length]
    if len(payload) != length:
        raise ProtocolError("Truncated payload")
    return MsgType(mtype), seq, payload


def recv_frame(sock: socket.socket) -> tuple[MsgType, int, bytes]:
    """Read exactly one frame from a socket."""
    header = _recv_exact(sock, HEADER_SIZE)
    if header[:4] != HEADER_MAGIC:
        raise ProtocolError("Invalid frame header")
    version, mtype, seq, length = struct.unpack("!BBII", header[4:HEADER_SIZE])
    if version != PROTOCOL_VERSION:
        raise ProtocolError(f"Unsupported protocol version {version}")
    if length > MAX_PAYLOAD:
        raise ProtocolError(f"Payload too large: {length}")
    payload = _recv_exact(sock, length) if length > 0 else b""
    return MsgType(mtype), seq, payload


def send_frame(sock: socket.socket, msg_type: MsgType, payload: bytes,
               seq: int = 0):
    """Send one frame over a socket."""
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


# ── Key Exchange (X25519 + Fernet) ──────────────────────────────────────────

@dataclass
class SessionKeys:
    shared_key: bytes       # raw 32-byte shared secret
    fernet: Fernet          # derived Fernet instance for encrypt/decrypt
    peer_public: bytes      # peer's X25519 public key bytes

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
                        peer_public_bytes: bytes) -> SessionKeys:
    """Perform X25519 key agreement and derive a Fernet key."""
    peer_public = x25519.X25519PublicKey.from_public_bytes(peer_public_bytes)
    shared = private_key.exchange(peer_public)
    # Derive a Fernet-compatible key (URL-safe base64 of 32 bytes)
    import base64
    derived = hashlib.sha256(shared).digest()
    fernet_key = base64.urlsafe_b64encode(derived)
    return SessionKeys(
        shared_key=shared,
        fernet=Fernet(fernet_key),
        peer_public=peer_public_bytes,
    )


# ── Connection (wraps a socket with encryption + framing) ───────────────────

class JumpConnection:
    """An encrypted, framed connection between two devices."""

    def __init__(self, sock: socket.socket, keys: SessionKeys,
                 is_initiator: bool):
        self.sock = sock
        self.keys = keys
        self.is_initiator = is_initiator
        self._seq = 0
        self._lock = threading.Lock()

    def send(self, msg_type: MsgType, payload: bytes):
        encrypted = self.keys.encrypt(payload)
        with self._lock:
            self._seq += 1
            send_frame(self.sock, msg_type, encrypted, self._seq)

    def recv(self) -> tuple[MsgType, bytes]:
        msg_type, seq, encrypted = recv_frame(self.sock)
        payload = self.keys.decrypt(encrypted)
        return msg_type, payload

    def send_json(self, msg_type: MsgType, obj: dict):
        self.send(msg_type, json.dumps(obj).encode())

    def recv_json(self) -> tuple[MsgType, dict]:
        msg_type, data = self.recv()
        return msg_type, json.loads(data.decode())

    def ping(self) -> float:
        t0 = time.time()
        self.send(MsgType.PING, b"ping")
        msg_type, _ = self.recv()
        if msg_type != MsgType.PONG:
            raise ProtocolError(f"Expected PONG, got {msg_type}")
        return time.time() - t0

    def close(self):
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()


# ── Handshake helpers ────────────────────────────────────────────────────────

def client_handshake(sock: socket.socket, node_id: str,
                     auth_token: str = None) -> JumpConnection:
    """Perform a client-side handshake: HELLO → KEY_EXCHANGE → done."""
    # Send HELLO
    hello = json.dumps({"node_id": node_id, "version": PROTOCOL_VERSION}).encode()
    send_frame(sock, MsgType.HELLO, hello)

    # Receive HELLO_ACK
    msg_type, _, payload = recv_frame(sock)
    if msg_type == MsgType.ERROR:
        raise ProtocolError(f"Server error: {payload.decode()}")
    if msg_type != MsgType.HELLO_ACK:
        raise ProtocolError(f"Expected HELLO_ACK, got {msg_type}")

    # Key exchange
    private_key, pub_bytes = generate_keypair()
    kx_payload = json.dumps({
        "public_key": pub_bytes.hex(),
        "auth_token": auth_token or "",
    }).encode()
    send_frame(sock, MsgType.KEY_EXCHANGE, kx_payload)

    # Receive KEY_EXCHANGE_ACK
    msg_type, _, kx_resp = recv_frame(sock)
    if msg_type == MsgType.ERROR:
        raise ProtocolError(f"Key exchange failed: {kx_resp.decode()}")
    if msg_type != MsgType.KEY_EXCHANGE_ACK:
        raise ProtocolError(f"Expected KEY_EXCHANGE_ACK, got {msg_type}")
    peer_info = json.loads(kx_resp.decode())
    peer_pub = bytes.fromhex(peer_info["public_key"])

    keys = derive_session_keys(private_key, peer_pub)
    return JumpConnection(sock, keys, is_initiator=True)


def server_handshake(sock: socket.socket,
                     auth_validator: Callable[[str], bool] = None
                     ) -> JumpConnection:
    """Perform a server-side handshake: receive HELLO → KEY_EXCHANGE → done."""
    # Receive HELLO
    msg_type, _, payload = recv_frame(sock)
    if msg_type != MsgType.HELLO:
        raise ProtocolError(f"Expected HELLO, got {msg_type}")

    # Send HELLO_ACK
    ack = json.dumps({"version": PROTOCOL_VERSION, "status": "ok"}).encode()
    send_frame(sock, MsgType.HELLO_ACK, ack)

    # Receive KEY_EXCHANGE
    msg_type, _, kx_payload = recv_frame(sock)
    if msg_type != MsgType.KEY_EXCHANGE:
        raise ProtocolError(f"Expected KEY_EXCHANGE, got {msg_type}")
    kx_info = json.loads(kx_payload.decode())

    # Validate auth token if validator is provided
    if auth_validator and not auth_validator(kx_info.get("auth_token", "")):
        send_frame(sock, MsgType.ERROR, b"Authentication failed")
        raise ProtocolError("Authentication failed")

    peer_pub = bytes.fromhex(kx_info["public_key"])

    # Generate our keypair and respond
    private_key, pub_bytes = generate_keypair()
    kx_resp = json.dumps({"public_key": pub_bytes.hex()}).encode()
    send_frame(sock, MsgType.KEY_EXCHANGE_ACK, kx_resp)

    keys = derive_session_keys(private_key, peer_pub)
    return JumpConnection(sock, keys, is_initiator=False)


# ── Listener ─────────────────────────────────────────────────────────────────

class JumpListener:
    """TCP listener that accepts incoming jump connections."""

    def __init__(self, host: str = "0.0.0.0", port: int = 47701,
                 auth_validator: Callable[[str], bool] = None,
                 on_connection: Callable[[JumpConnection], None] = None):
        self.host = host
        self.port = port
        self.auth_validator = auth_validator
        self.on_connection = on_connection
        self._server_sock: Optional[socket.socket] = None
        self._running = False
        self._thread: Optional[threading.Thread] = None

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

    def _accept_loop(self):
        while self._running:
            try:
                client_sock, addr = self._server_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                conn = server_handshake(client_sock, self.auth_validator)
                if self.on_connection:
                    threading.Thread(target=self.on_connection, args=(conn,),
                                     daemon=True).start()
            except (ProtocolError, ConnectionError, OSError):
                try:
                    client_sock.close()
                except OSError:
                    pass
