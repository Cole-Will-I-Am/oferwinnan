"""
Session Jumper — Serialize, transfer, and resume sessions across devices.

A "session" is a bundle of state (environment variables, working directory,
open files, clipboard, arbitrary key-value data) that can be frozen on one
device and thawed on another.
"""

import gzip
import hashlib
import json
import logging
import os
import socket
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

from device_discovery import Device, Transport, DiscoveryManager
from jump_protocol import (
    JumpConnection, JumpListener, MsgType, ProtocolError,
    client_handshake, CHUNK_SIZE,
)


logger = logging.getLogger(__name__)

MAX_FILE_SIZE = 10 * 1024 * 1024


# ── Session Model ────────────────────────────────────────────────────────────

@dataclass
class JumpSession:
    """Serializable session state that travels between devices."""
    session_id: str
    source_device: str
    timestamp: float = 0.0
    cwd: str = ""
    env: dict = field(default_factory=dict)
    clipboard: str = ""
    files: dict = field(default_factory=dict)  # relative_path → bytes (base64)
    metadata: dict = field(default_factory=dict)
    checksum: str = ""

    def serialize(self) -> bytes:
        """Serialize to compressed JSON bytes."""
        d = asdict(self)
        d.pop("checksum", None)
        raw = json.dumps(d, sort_keys=True).encode()
        compressed = gzip.compress(raw, compresslevel=6)
        return compressed

    @classmethod
    def deserialize(cls, data: bytes) -> "JumpSession":
        """Deserialize from compressed JSON bytes."""
        raw = gzip.decompress(data)
        d = json.loads(raw.decode())
        return cls(**d)

    def compute_checksum(self) -> str:
        d = asdict(self)
        d.pop("checksum", None)
        raw = json.dumps(d, sort_keys=True).encode()
        return hashlib.sha256(raw).hexdigest()

    def validate(self) -> bool:
        if not self.checksum:
            return True
        return self.checksum == self.compute_checksum()


def capture_session(session_id: str, source_device: str,
                    include_env: bool = True,
                    include_files: list[str] = None,
                    extra_metadata: dict = None) -> JumpSession:
    """Capture the current environment as a JumpSession."""
    import base64

    env = {}
    if include_env:
        # Only capture safe, non-secret env vars
        safe_prefixes = ("HOME", "USER", "SHELL", "LANG", "TERM", "PATH",
                         "PWD", "EDITOR", "VISUAL", "DISPLAY")
        env = {k: v for k, v in os.environ.items()
               if any(k.startswith(p) for p in safe_prefixes)}

    files = {}
    if include_files:
        for fpath in include_files:
            p = Path(fpath)
            if not p.exists():
                logger.warning("Skipping missing file: %s", p)
                continue
            if p.is_file() and p.stat().st_size < MAX_FILE_SIZE:
                files[str(p)] = base64.b64encode(p.read_bytes()).decode()

    session = JumpSession(
        session_id=session_id,
        source_device=source_device,
        timestamp=time.time(),
        cwd=os.getcwd(),
        env=env,
        files=files,
        metadata=extra_metadata or {},
    )
    session.checksum = session.compute_checksum()
    return session


def restore_session(session: JumpSession, restore_env: bool = False,
                    restore_files: bool = False, target_dir: str = None):
    """Apply a received session on this device."""
    import base64

    if not session.validate():
        raise ValueError("Session checksum mismatch — data may be corrupted")

    if restore_env:
        for k, v in session.env.items():
            os.environ[k] = v

    if restore_files and session.files:
        base = Path(target_dir) if target_dir else Path.cwd()
        for rel_path, b64data in session.files.items():
            dest = base / rel_path
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(base64.b64decode(b64data))

    return session.metadata


# ── Jump Sender / Receiver ───────────────────────────────────────────────────

def send_session(conn: JumpConnection, session: JumpSession) -> bool:
    """Send a session over an established JumpConnection."""
    data = session.serialize()
    meta = {
        "session_id": session.session_id,
        "source": session.source_device,
        "size": len(data),
        "checksum": session.checksum,
        "timestamp": session.timestamp,
    }
    conn.send_json(MsgType.SESSION_DATA, {"meta": meta, "stage": "meta"})

    # Wait for ready signal
    msg_type, resp = conn.recv_json()
    if msg_type == MsgType.ERROR:
        raise ProtocolError(f"Receiver rejected session: {resp}")

    # Send data in chunks
    offset = 0
    seq = 0
    while offset < len(data):
        chunk = data[offset:offset + CHUNK_SIZE]
        chunk_meta = {"seq": seq, "offset": offset, "size": len(chunk),
                      "final": offset + len(chunk) >= len(data)}
        payload = json.dumps(chunk_meta).encode() + b"\x00" + chunk
        conn.send(MsgType.FILE_CHUNK, payload)
        offset += len(chunk)
        seq += 1

    # Wait for final ACK
    msg_type, ack = conn.recv_json()
    if msg_type != MsgType.SESSION_ACK:
        raise ProtocolError(f"Expected SESSION_ACK, got {msg_type}")
    return ack.get("status") == "ok"


def receive_session(conn: JumpConnection) -> JumpSession:
    """Receive a session over an established JumpConnection."""
    # Get metadata
    msg_type, info = conn.recv_json()
    if msg_type != MsgType.SESSION_DATA:
        raise ProtocolError(f"Expected SESSION_DATA, got {msg_type}")

    meta = info["meta"]
    expected_size = meta["size"]

    # Signal ready
    conn.send_json(MsgType.SESSION_ACK, {"status": "ready"})

    # Receive chunks
    buf = bytearray()
    while len(buf) < expected_size:
        msg_type, raw = conn.recv()
        if msg_type != MsgType.FILE_CHUNK:
            raise ProtocolError(f"Expected FILE_CHUNK, got {msg_type}")
        sep = raw.find(b"\x00")
        if sep == -1:
            raise ValueError("Invalid session data: missing separator")
        chunk_data = raw[sep + 1:]
        buf.extend(chunk_data)

    session = JumpSession.deserialize(bytes(buf))

    if meta.get("checksum") and session.compute_checksum() != meta["checksum"]:
        conn.send_json(MsgType.SESSION_ACK, {"status": "checksum_error"})
        raise ValueError("Session checksum mismatch")

    conn.send_json(MsgType.SESSION_ACK, {"status": "ok"})
    return session


# ── High-level jump operations ───────────────────────────────────────────────

def jump_to_device(target: Device, session: JumpSession,
                   auth_token: str = None, timeout: float = 30.0) -> bool:
    """Jump to a target device: connect, handshake, send session."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((target.address, target.port))
        conn = client_handshake(sock, session.source_device, auth_token)
        return send_session(conn, session)
    except (OSError, ProtocolError, ConnectionError) as e:
        raise JumpError(f"Failed to jump to {target.name}: {e}") from e
    finally:
        try:
            sock.close()
        except OSError:
            pass


class JumpError(Exception):
    pass


class JumpNode:
    """A node that can both send and receive jump sessions."""

    def __init__(self, node_name: str = None, listen_port: int = 47701,
                 auth_token: str = None,
                 on_session_received=None):
        self.node_name = node_name or socket.gethostname()
        self.listen_port = listen_port
        self.auth_token = auth_token
        self.on_session_received = on_session_received
        self.discovery = DiscoveryManager(
            node_name=self.node_name,
            listen_port=listen_port,
        )
        self.listener = JumpListener(
            port=listen_port,
            auth_validator=self._validate_auth if auth_token else None,
            on_connection=self._handle_connection,
        )
        self.received_sessions: list[JumpSession] = []

    def _validate_auth(self, token: str) -> bool:
        return token == self.auth_token

    def _handle_connection(self, conn: JumpConnection):
        try:
            session = receive_session(conn)
            self.received_sessions.append(session)
            if self.on_session_received:
                self.on_session_received(session)
        except (ProtocolError, ValueError, ConnectionError):
            pass
        finally:
            conn.close()

    def start(self):
        self.discovery.start()
        self.listener.start()

    def stop(self):
        self.discovery.stop()
        self.listener.stop()

    def discover_targets(self) -> list[Device]:
        return self.discovery.get_all_devices()

    def jump(self, target: Device, session_id: str = None,
             include_env: bool = True, include_files: list[str] = None,
             extra_metadata: dict = None) -> bool:
        sid = session_id or f"jump-{int(time.time())}"
        session = capture_session(
            session_id=sid,
            source_device=self.discovery.node_id,
            include_env=include_env,
            include_files=include_files,
            extra_metadata=extra_metadata,
        )
        return jump_to_device(target, session, auth_token=self.auth_token)
