"""
Session Jumper — Serialize, transfer, and resume sessions across devices.

A "session" is a bundle of state (environment variables, working directory,
open files, clipboard, arbitrary key-value data) that can be frozen on one
device and thawed on another.

Supports resumable transfers: if a connection drops mid-transfer, the
receiver can reconnect and continue from the last acknowledged chunk.
"""

import gzip
import hashlib
import hmac
import json
import logging
import os
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Callable, Dict, Optional

from matrix.device_discovery import Device, Transport, DiscoveryManager
from matrix.jump_protocol import (
    JumpConnection, JumpListener, MsgType, ProtocolError,
    TransportBackend, DirectTCPBackend, _wrap_backend,
    client_handshake, CHUNK_SIZE,
)


from matrix.config import config as _config

logger = logging.getLogger(__name__)

MAX_FILE_SIZE = _config.max_file_size


# == Session Model =============================================================

@dataclass
class JumpSession:
    """Serializable session state that travels between devices."""
    session_id: str
    source_device: str
    timestamp: float = 0.0
    cwd: str = ""
    env: dict = field(default_factory=dict)
    clipboard: str = ""
    files: dict = field(default_factory=dict)  # relative_path -> bytes (base64)
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
        cwd = Path.cwd().resolve()
        for fpath in include_files:
            p = Path(fpath).resolve()
            if not p.exists():
                logger.warning("Skipping missing file: %s", fpath)
                continue
            if not p.is_file():
                logger.warning("Skipping non-file: %s", fpath)
                continue
            if p.stat().st_size >= MAX_FILE_SIZE:
                logger.warning("Skipping oversized file: %s", fpath)
                continue
            # Store as a relative path; reject files that resolve outside cwd
            try:
                rel = p.relative_to(cwd)
            except ValueError:
                logger.warning("Skipping file outside working directory: %s", fpath)
                continue
            files[str(rel)] = base64.b64encode(p.read_bytes()).decode()

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


_SAFE_ENV_PREFIXES = ("HOME", "USER", "SHELL", "LANG", "TERM", "PATH",
                      "PWD", "EDITOR", "VISUAL", "DISPLAY")

_DANGEROUS_ENV_KEYS = frozenset({
    "LD_PRELOAD", "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES",
    "PYTHONPATH", "PYTHONSTARTUP", "PYTHONHOME",
    "NODE_OPTIONS", "PERL5LIB", "RUBYLIB",
    "CLASSPATH", "JAVA_TOOL_OPTIONS",
})


def restore_session(session: JumpSession, restore_env: bool = False,
                    restore_files: bool = False, target_dir: str = None):
    """Apply a received session on this device."""
    import base64

    if not session.validate():
        raise ValueError("Session checksum mismatch — data may be corrupted")

    if restore_env:
        for k, v in session.env.items():
            # Only restore env vars that match the safe capture allowlist
            if k in _DANGEROUS_ENV_KEYS:
                logger.warning("Blocked dangerous env var: %s", k)
                continue
            if not any(k.startswith(p) for p in _SAFE_ENV_PREFIXES):
                logger.warning("Skipping non-allowlisted env var: %s", k)
                continue
            os.environ[k] = v

    if restore_files and session.files:
        base = (Path(target_dir) if target_dir else Path.cwd()).resolve()
        for rel_path, b64data in session.files.items():
            # Reject absolute paths and traversal sequences
            if os.path.isabs(rel_path) or ".." in Path(rel_path).parts:
                logger.warning("Blocked path traversal attempt: %s", rel_path)
                continue
            dest = (base / rel_path).resolve()
            # Final containment check: dest must be within base
            if not str(dest).startswith(str(base) + os.sep) and dest != base:
                logger.warning("Blocked path escape: %s", rel_path)
                continue
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(base64.b64decode(b64data))

    return session.metadata


# == Transfer State (for resumption) ===========================================

@dataclass
class TransferState:
    """Tracks the progress of a session transfer for resumption."""
    session_id: str
    total_size: int
    checksum: str
    last_acked_offset: int = 0
    last_acked_seq: int = -1
    chunks_received: int = 0
    buffer: bytearray = field(default_factory=bytearray, repr=False)
    created_at: float = field(default_factory=time.time)

    @property
    def is_complete(self) -> bool:
        return len(self.buffer) >= self.total_size

    @property
    def progress(self) -> float:
        if self.total_size == 0:
            return 1.0
        return len(self.buffer) / self.total_size

    def to_resume_info(self) -> dict:
        """Info sent to the sender when resuming."""
        return {
            "session_id": self.session_id,
            "resume_offset": self.last_acked_offset,
            "resume_seq": self.last_acked_seq,
            "received_size": len(self.buffer),
            "partial_hash": hashlib.sha256(self.buffer).hexdigest(),
        }


class TransferStateStore:
    """Thread-safe store for in-progress transfer states.

    Enables resumption: if a connection drops, the receiver can look up the
    partial state and tell the sender where to continue from.
    """

    def __init__(self, ttl: float = 300.0):
        self._states: Dict[str, TransferState] = {}
        self._ttl = ttl
        self._lock = threading.Lock()

    def get_or_create(self, session_id: str, total_size: int,
                      checksum: str) -> TransferState:
        with self._lock:
            self._evict()
            state = self._states.get(session_id)
            if state and state.total_size == total_size:
                return state
            state = TransferState(
                session_id=session_id,
                total_size=total_size,
                checksum=checksum,
            )
            self._states[session_id] = state
            return state

    def get(self, session_id: str) -> Optional[TransferState]:
        with self._lock:
            self._evict()
            return self._states.get(session_id)

    def remove(self, session_id: str) -> None:
        with self._lock:
            self._states.pop(session_id, None)

    def _evict(self):
        now = time.time()
        expired = [k for k, v in self._states.items()
                   if now - v.created_at > self._ttl]
        for k in expired:
            del self._states[k]


# Global transfer state store
_transfer_store = TransferStateStore(ttl=300.0)


# == Jump Sender / Receiver ====================================================

def send_session(conn: JumpConnection, session: JumpSession,
                 on_chunk_ack: Optional[Callable[[int, int], None]] = None,
                 ) -> bool:
    """Send a session over an established JumpConnection.

    Supports resumable transfers: if the receiver sends a RESUME with an
    offset, the sender skips ahead to that point.

    Args:
        conn: Established encrypted connection.
        session: The session to transfer.
        on_chunk_ack: Optional callback(offset, total_size) after each chunk ACK.

    Returns:
        True if the session was fully received.
    """
    data = session.serialize()
    total_size = len(data)
    meta = {
        "session_id": session.session_id,
        "source": session.source_device,
        "size": total_size,
        "checksum": session.checksum,
        "timestamp": session.timestamp,
        "resumable": True,
    }
    conn.send_json(MsgType.SESSION_DATA, {"meta": meta, "stage": "meta"})

    # Wait for ready signal (or resume signal)
    msg_type, resp = conn.recv_json()
    if msg_type == MsgType.ERROR:
        raise ProtocolError(f"Receiver rejected session: {resp}")

    # Check for resume
    start_offset = 0
    start_seq = 0
    if msg_type == MsgType.RESUME_ACK:
        start_offset = resp.get("resume_offset", 0)
        start_seq = resp.get("resume_seq", 0) + 1
        logger.info("Resuming transfer from offset %d (seq %d)", start_offset, start_seq)
    elif msg_type == MsgType.SESSION_ACK:
        pass  # Fresh start
    else:
        # Legacy receiver — treat any other ACK-like response as ready
        pass

    # Send data in chunks
    offset = start_offset
    seq = start_seq
    while offset < total_size:
        chunk = data[offset:offset + CHUNK_SIZE]
        chunk_meta = {"seq": seq, "offset": offset, "size": len(chunk),
                      "final": offset + len(chunk) >= total_size}
        payload = json.dumps(chunk_meta).encode() + b"\x00" + chunk
        conn.send(MsgType.FILE_CHUNK, payload)
        offset += len(chunk)
        seq += 1

        if on_chunk_ack:
            on_chunk_ack(offset, total_size)

    # Wait for final ACK
    msg_type, ack = conn.recv_json()
    if msg_type != MsgType.SESSION_ACK:
        raise ProtocolError(f"Expected SESSION_ACK, got {msg_type}")
    return ack.get("status") == "ok"


def receive_session(conn: JumpConnection,
                    transfer_store: Optional[TransferStateStore] = None,
                    ) -> JumpSession:
    """Receive a session over an established JumpConnection.

    Supports resumable transfers: if we have partial state from a previous
    attempt, we tell the sender where to resume from.

    Args:
        conn: Established encrypted connection.
        transfer_store: Optional store for partial transfer state.

    Returns:
        The received JumpSession.
    """
    store = transfer_store or _transfer_store

    # Get metadata
    msg_type, info = conn.recv_json()
    if msg_type != MsgType.SESSION_DATA:
        raise ProtocolError(f"Expected SESSION_DATA, got {msg_type}")

    meta = info["meta"]
    expected_size = meta["size"]
    session_id = meta.get("session_id", "")
    checksum = meta.get("checksum", "")
    resumable = meta.get("resumable", False)

    # Check for existing partial transfer state
    state = store.get(session_id) if resumable and session_id else None

    if state and state.total_size == expected_size and len(state.buffer) > 0:
        # Resume from where we left off
        logger.info("Resuming session %s from offset %d/%d",
                     session_id, state.last_acked_offset, expected_size)
        conn.send_json(MsgType.RESUME_ACK, state.to_resume_info())
    else:
        # Fresh transfer
        state = store.get_or_create(session_id, expected_size, checksum)
        conn.send_json(MsgType.SESSION_ACK, {"status": "ready"})

    # Receive chunks
    while len(state.buffer) < expected_size:
        msg_type, raw = conn.recv()
        if msg_type != MsgType.FILE_CHUNK:
            raise ProtocolError(f"Expected FILE_CHUNK, got {msg_type}")
        sep = raw.find(b"\x00")
        if sep == -1:
            raise ValueError("Invalid session data: missing separator")

        chunk_meta_bytes = raw[:sep]
        chunk_data = raw[sep + 1:]
        chunk_meta = json.loads(chunk_meta_bytes.decode())

        chunk_offset = chunk_meta.get("offset", len(state.buffer))
        chunk_seq = chunk_meta.get("seq", state.chunks_received)
        chunk_size = chunk_meta.get("size", len(chunk_data))

        if chunk_size != len(chunk_data):
            conn.send_json(MsgType.ERROR, {
                "error": "invalid_chunk_size",
                "declared": chunk_size,
                "actual": len(chunk_data),
            })
            raise ProtocolError(
                f"Chunk size mismatch: declared {chunk_size}, got {len(chunk_data)} bytes"
            )

        # Handle out-of-order or duplicate chunks
        if chunk_offset < len(state.buffer):
            # Duplicate chunk — skip it
            continue
        elif chunk_offset > len(state.buffer):
            conn.send_json(MsgType.ERROR, {
                "error": "chunk_gap",
                "expected_offset": len(state.buffer),
                "got_offset": chunk_offset,
            })
            raise ProtocolError(
                f"Chunk gap: expected offset {len(state.buffer)}, got {chunk_offset}"
            )

        next_size = len(state.buffer) + len(chunk_data)
        if next_size > expected_size:
            conn.send_json(MsgType.ERROR, {
                "error": "chunk_overflow",
                "expected_size": expected_size,
                "would_be_size": next_size,
            })
            raise ProtocolError(
                f"Chunk overflow: expected total <= {expected_size}, got {next_size}"
            )

        state.buffer.extend(chunk_data)
        state.last_acked_offset = chunk_offset + len(chunk_data)
        state.last_acked_seq = chunk_seq
        state.chunks_received += 1

    session = JumpSession.deserialize(bytes(state.buffer))

    if checksum and session.compute_checksum() != checksum:
        conn.send_json(MsgType.SESSION_ACK, {"status": "checksum_error"})
        raise ValueError("Session checksum mismatch")

    conn.send_json(MsgType.SESSION_ACK, {"status": "ok"})

    # Clean up transfer state
    store.remove(session_id)

    return session


# == High-level jump operations ================================================

def jump_to_device(target: Device, session: JumpSession,
                   auth_token: str = None, timeout: float = 30.0,
                   backend: Optional[TransportBackend] = None,
                   *,
                   identity=None, trust_store=None,
                   require_peer_identity: bool = False,
                   expected_peer: Optional[str] = None) -> bool:
    """Jump to a target device: connect, handshake, send session.

    Args:
        target: Target device to jump to.
        session: Session to transfer.
        auth_token: Optional authentication token.
        timeout: Connection timeout.
        backend: Optional pre-connected TransportBackend. If None, creates
                 a DirectTCPBackend.
        identity: Optional Ed25519 IdentityKey presented to the target.
        trust_store: Optional PeerTrustStore for pinning the target identity.
        require_peer_identity: Abort unless the target proves its identity.
        expected_peer: Trust-store key for the target (defaults to its address).

    Returns:
        True if the session was accepted.
    """
    peer_name = expected_peer or f"{target.address}:{target.port}"
    hs_kwargs = dict(identity=identity, trust_store=trust_store,
                     expected_peer=peer_name,
                     require_peer_identity=require_peer_identity)

    if backend:
        # Use provided backend (WebSocket, relay, etc.)
        try:
            conn = client_handshake(backend, session.source_device, auth_token,
                                    **hs_kwargs)
            return send_session(conn, session)
        except (OSError, ProtocolError, ConnectionError) as e:
            raise JumpError(f"Failed to jump to {target.name}: {e}") from e
        finally:
            backend.close()

    # Default: direct TCP
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((target.address, target.port))
        conn = client_handshake(sock, session.source_device, auth_token,
                                **hs_kwargs)
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


# == Multi-target Jump (Multiply / Duplicate) ==================================

class MultiJumpStrategy(Enum):
    """Strategy for dispatching a session to multiple targets."""
    BROADCAST = "broadcast"   # Fire-and-forget to all; collect results
    MIRROR = "mirror"         # All must succeed or the whole operation fails
    RACE = "race"             # First successful delivery wins; cancel the rest
    CASCADE = "cascade"       # Sequential: each target only after the previous succeeds


@dataclass
class TargetResult:
    """Outcome of a jump attempt to a single target."""
    device: Device
    success: bool
    elapsed: float = 0.0
    error: Optional[str] = None
    retries: int = 0


@dataclass
class MultiJumpResult:
    """Aggregate outcome of a multi-target jump."""
    strategy: MultiJumpStrategy
    session_id: str
    targets: list  # list[TargetResult]
    started: float = 0.0
    finished: float = 0.0

    @property
    def succeeded(self) -> list:
        return [t for t in self.targets if t.success]

    @property
    def failed(self) -> list:
        return [t for t in self.targets if not t.success]

    @property
    def total_elapsed(self) -> float:
        return self.finished - self.started if self.finished else 0.0

    @property
    def all_ok(self) -> bool:
        return all(t.success for t in self.targets)

    @property
    def any_ok(self) -> bool:
        return any(t.success for t in self.targets)

    def summary(self) -> str:
        ok = len(self.succeeded)
        fail = len(self.failed)
        return (
            f"[{self.strategy.value.upper()}] {ok}/{ok + fail} targets reached "
            f"in {self.total_elapsed:.2f}s (session {self.session_id})"
        )


def _jump_single(
    target: Device,
    session: JumpSession,
    auth_token: str = None,
    timeout: float = 30.0,
    max_retries: int = 0,
    *,
    identity=None,
    trust_store=None,
    require_peer_identity: bool = False,
) -> TargetResult:
    """Jump to one target with optional retries. Returns a TargetResult."""
    t0 = time.time()
    last_err = None
    for attempt in range(1 + max_retries):
        try:
            ok = jump_to_device(target, session, auth_token=auth_token,
                                timeout=timeout, identity=identity,
                                trust_store=trust_store,
                                require_peer_identity=require_peer_identity)
            return TargetResult(
                device=target, success=ok,
                elapsed=time.time() - t0, retries=attempt,
            )
        except (JumpError, OSError, ConnectionError) as exc:
            last_err = exc
            if attempt < max_retries:
                time.sleep(min(2 ** attempt, 8))
    return TargetResult(
        device=target, success=False,
        elapsed=time.time() - t0,
        error=str(last_err), retries=max_retries,
    )


def jump_to_devices(
    targets: list,
    session: JumpSession,
    *,
    strategy: MultiJumpStrategy = MultiJumpStrategy.BROADCAST,
    auth_token: str = None,
    timeout: float = 30.0,
    max_retries: int = 0,
    max_workers: int = 0,
    on_progress: Callable[[TargetResult, int, int], None] = None,
    identity=None,
    trust_store=None,
    require_peer_identity: bool = False,
) -> MultiJumpResult:
    """Jump a session to multiple targets using the chosen strategy.

    Args:
        targets: Devices to send the session to.
        session: The session to transfer.
        strategy: Dispatch strategy (BROADCAST, MIRROR, RACE, CASCADE).
        auth_token: Shared auth token for all targets.
        timeout: Per-target TCP timeout.
        max_retries: Per-target retry count (with exponential backoff).
        max_workers: Thread pool size (0 = len(targets)).
        on_progress: Callback(result, completed_count, total) after each target.

    Returns:
        MultiJumpResult with per-target outcomes.
    """
    if not targets:
        return MultiJumpResult(
            strategy=strategy, session_id=session.session_id,
            targets=[], started=time.time(), finished=time.time(),
        )

    workers = max_workers or min(len(targets), 16)
    result = MultiJumpResult(
        strategy=strategy, session_id=session.session_id,
        targets=[], started=time.time(),
    )

    hs = dict(identity=identity, trust_store=trust_store,
              require_peer_identity=require_peer_identity)

    if strategy == MultiJumpStrategy.CASCADE:
        return _cascade_jump(targets, session, result,
                             auth_token, timeout, max_retries, on_progress, hs)

    if strategy == MultiJumpStrategy.RACE:
        return _race_jump(targets, session, result, workers,
                          auth_token, timeout, max_retries, on_progress, hs)

    # BROADCAST and MIRROR: dispatch all concurrently
    completed = 0
    cancel = threading.Event()

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(_jump_single, t, session, auth_token, timeout,
                        max_retries, **hs): t
            for t in targets
        }
        for future in as_completed(futures):
            tr = future.result()
            result.targets.append(tr)
            completed += 1
            if on_progress:
                on_progress(tr, completed, len(targets))
            # MIRROR: abort early on first failure
            if strategy == MultiJumpStrategy.MIRROR and not tr.success:
                cancel.set()
                for f in futures:
                    f.cancel()
                break

    result.finished = time.time()
    return result


def _cascade_jump(targets, session, result, auth_token, timeout,
                  max_retries, on_progress, hs=None):
    """Sequential jump — each target only attempted after the previous succeeds."""
    hs = hs or {}
    for i, target in enumerate(targets):
        tr = _jump_single(target, session, auth_token, timeout, max_retries, **hs)
        result.targets.append(tr)
        if on_progress:
            on_progress(tr, i + 1, len(targets))
        if not tr.success:
            break
    result.finished = time.time()
    return result


def _race_jump(targets, session, result, workers, auth_token, timeout,
               max_retries, on_progress, hs=None):
    """First successful delivery wins; remaining futures are cancelled."""
    hs = hs or {}
    winner_found = threading.Event()

    def _race_single(target):
        if winner_found.is_set():
            return TargetResult(device=target, success=False,
                                error="cancelled (race lost)")
        tr = _jump_single(target, session, auth_token, timeout, max_retries, **hs)
        if tr.success:
            winner_found.set()
        return tr

    completed = 0
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_race_single, t): t for t in targets}
        for future in as_completed(futures):
            tr = future.result()
            result.targets.append(tr)
            completed += 1
            if on_progress:
                on_progress(tr, completed, len(targets))

    result.finished = time.time()
    return result


class JumpNode:
    """A node that can both send and receive jump sessions."""

    def __init__(self, node_name: str = None, listen_port: int = 47701,
                 auth_token: str = None,
                 on_session_received=None,
                 rbac_manager=None,
                 task_relay=None,
                 identity=None,
                 trust_store=None,
                 require_peer_identity: bool = False):
        self.node_name = node_name or socket.gethostname()
        self.listen_port = listen_port
        self.auth_token = auth_token
        self.on_session_received = on_session_received
        self._rbac_manager = rbac_manager
        self._task_relay = task_relay
        self.identity = identity
        self.trust_store = trust_store
        self.require_peer_identity = require_peer_identity
        self.discovery = DiscoveryManager(
            node_name=self.node_name,
            listen_port=listen_port,
        )

        # Determine auth validator
        auth_validator = None
        if rbac_manager is not None:
            from matrix.rbac import Permission
            auth_validator = rbac_manager.make_auth_validator(Permission.JUMP)
        elif auth_token:
            auth_validator = self._validate_auth

        self.listener = JumpListener(
            port=listen_port,
            auth_validator=auth_validator,
            on_connection=self._handle_connection,
            identity=identity,
            trust_store=trust_store,
            require_peer_identity=require_peer_identity,
        )
        self.received_sessions: list[JumpSession] = []
        self._sessions_lock = threading.Lock()
        self._transfer_store = TransferStateStore(ttl=300.0)

    def _validate_auth(self, token: str) -> bool:
        # Constant-time comparison to prevent timing attacks
        return hmac.compare_digest(token, self.auth_token)

    def _handle_connection(self, conn: JumpConnection):
        try:
            # Peek at message type to dispatch relay/terminate messages
            msg_type, payload = conn.recv()
            if msg_type == MsgType.RELAY and self._task_relay is not None:
                import json as _json
                from matrix.task_relay import RelayMessage
                msg = RelayMessage.from_dict(_json.loads(payload.decode()))
                self._task_relay.handle_incoming(msg)
            elif msg_type == MsgType.ROUTE_UPDATE and self._task_relay is not None:
                peer_id = conn.peer_node_id or conn.peer_address
                self._task_relay.handle_route_update(peer_id, payload)
            elif msg_type == MsgType.TERMINATE:
                # Termination is handled by SecureTerminator if registered
                logger.info("received TERMINATE from %s", conn.peer_address)
            else:
                # Re-inject the already-read frame and receive session
                conn._pending_recv.appendleft((msg_type, payload))
                session = receive_session(conn, transfer_store=self._transfer_store)
                with self._sessions_lock:
                    self.received_sessions.append(session)
                if self.on_session_received:
                    self.on_session_received(session)
        except (ProtocolError, ValueError, ConnectionError):
            pass
        except Exception:
            logger.exception("unexpected error while handling inbound connection")
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
             extra_metadata: dict = None,
             backend: Optional[TransportBackend] = None) -> bool:
        sid = session_id or f"jump-{int(time.time())}"
        session = capture_session(
            session_id=sid,
            source_device=self.discovery.node_id,
            include_env=include_env,
            include_files=include_files,
            extra_metadata=extra_metadata,
        )
        return jump_to_device(target, session, auth_token=self.auth_token,
                              backend=backend, identity=self.identity,
                              trust_store=self.trust_store,
                              require_peer_identity=self.require_peer_identity)

    def multi_jump(
        self,
        targets: list = None,
        *,
        strategy: MultiJumpStrategy = MultiJumpStrategy.BROADCAST,
        session_id: str = None,
        include_env: bool = True,
        include_files: list[str] = None,
        extra_metadata: dict = None,
        max_retries: int = 0,
        max_workers: int = 0,
        on_progress: Callable[[TargetResult, int, int], None] = None,
    ) -> MultiJumpResult:
        """Multiply / duplicate this session to multiple targets.

        Args:
            targets: Devices to jump to. If None, discovers all available.
            strategy: BROADCAST, MIRROR, RACE, or CASCADE.
            session_id: Custom session ID.
            include_env: Include environment variables.
            include_files: Files to attach.
            extra_metadata: Arbitrary metadata dict.
            max_retries: Per-target retries with exponential backoff.
            max_workers: Thread pool size (0 = auto).
            on_progress: Callback after each target completes.

        Returns:
            MultiJumpResult with per-target outcomes.
        """
        if targets is None:
            targets = self.discover_targets()

        if not targets:
            logger.warning("multi_jump: no targets found")
            return MultiJumpResult(
                strategy=strategy,
                session_id=session_id or "empty",
                targets=[],
                started=time.time(),
                finished=time.time(),
            )

        sid = session_id or f"multi-{int(time.time())}"
        session = capture_session(
            session_id=sid,
            source_device=self.discovery.node_id,
            include_env=include_env,
            include_files=include_files,
            extra_metadata={
                **(extra_metadata or {}),
                "multi_jump": True,
                "strategy": strategy.value,
                "target_count": len(targets),
            },
        )

        return jump_to_devices(
            targets, session,
            strategy=strategy,
            auth_token=self.auth_token,
            max_retries=max_retries,
            max_workers=max_workers,
            on_progress=on_progress,
            identity=self.identity,
            trust_store=self.trust_store,
            require_peer_identity=self.require_peer_identity,
        )
