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
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Callable, Optional

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


# ── Multi-target Jump (Multiply / Duplicate) ────────────────────────────────

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
) -> TargetResult:
    """Jump to one target with optional retries. Returns a TargetResult."""
    t0 = time.time()
    last_err = None
    for attempt in range(1 + max_retries):
        try:
            ok = jump_to_device(target, session, auth_token=auth_token,
                                timeout=timeout)
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

    if strategy == MultiJumpStrategy.CASCADE:
        return _cascade_jump(targets, session, result,
                             auth_token, timeout, max_retries, on_progress)

    if strategy == MultiJumpStrategy.RACE:
        return _race_jump(targets, session, result, workers,
                          auth_token, timeout, max_retries, on_progress)

    # BROADCAST and MIRROR: dispatch all concurrently
    completed = 0
    cancel = threading.Event()

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(_jump_single, t, session, auth_token, timeout,
                        max_retries): t
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
                  max_retries, on_progress):
    """Sequential jump — each target only attempted after the previous succeeds."""
    for i, target in enumerate(targets):
        tr = _jump_single(target, session, auth_token, timeout, max_retries)
        result.targets.append(tr)
        if on_progress:
            on_progress(tr, i + 1, len(targets))
        if not tr.success:
            break
    result.finished = time.time()
    return result


def _race_jump(targets, session, result, workers, auth_token, timeout,
               max_retries, on_progress):
    """First successful delivery wins; remaining futures are cancelled."""
    winner_found = threading.Event()

    def _race_single(target):
        if winner_found.is_set():
            return TargetResult(device=target, success=False,
                                error="cancelled (race lost)")
        tr = _jump_single(target, session, auth_token, timeout, max_retries)
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
        )
