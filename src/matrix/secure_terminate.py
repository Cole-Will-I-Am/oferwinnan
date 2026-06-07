"""
Secure Termination — Cryptographically verified cleanup and shutdown.

Provides signed termination commands with replay protection, secure
state wiping, cascade propagation to connected peers, and an
append-only audit log of all termination events.
"""

from __future__ import annotations

import gc
import hashlib
import hmac
import json
import logging
import os
import struct
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set

logger = logging.getLogger(__name__)

__all__ = [
    "TerminationCommand",
    "TerminationAuditEntry",
    "SecureTerminator",
    "TerminationError",
]


# -- Errors --------------------------------------------------------------------

class TerminationError(Exception):
    """Raised on termination verification or execution failure."""


# -- Data Models ---------------------------------------------------------------

@dataclass(slots=True)
class TerminationCommand:
    """A signed command instructing a node to terminate."""

    command_id: str
    issuer_id: str
    target_node_id: str
    cascade: bool
    timestamp: float
    nonce: bytes
    signature: bytes = b""

    def signable_payload(self) -> bytes:
        """Canonical bytes over which the HMAC signature is computed."""
        parts = [
            self.command_id.encode(),
            self.issuer_id.encode(),
            self.target_node_id.encode(),
            b"\x01" if self.cascade else b"\x00",
            struct.pack("!d", self.timestamp),
            self.nonce,
        ]
        return b"|".join(parts)

    def to_dict(self) -> dict:
        return {
            "command_id": self.command_id,
            "issuer_id": self.issuer_id,
            "target_node_id": self.target_node_id,
            "cascade": self.cascade,
            "timestamp": self.timestamp,
            "nonce": self.nonce.hex(),
            "signature": self.signature.hex(),
        }

    @classmethod
    def from_dict(cls, d: dict) -> TerminationCommand:
        return cls(
            command_id=d["command_id"],
            issuer_id=d["issuer_id"],
            target_node_id=d["target_node_id"],
            cascade=d["cascade"],
            timestamp=d["timestamp"],
            nonce=bytes.fromhex(d["nonce"]),
            signature=bytes.fromhex(d["signature"]),
        )


@dataclass(slots=True)
class TerminationAuditEntry:
    """Immutable record of a termination-related event."""

    command_id: str
    issuer_id: str
    target_node_id: str
    action: str        # initiated, verified, executed, propagated, rejected, failed
    timestamp: float
    details: str = ""


# -- Nonce Tracker -------------------------------------------------------------

class _NonceTracker:
    """Prevents replay of termination commands via nonce tracking with TTL."""

    def __init__(self, ttl: float = 300.0) -> None:
        self._lock = threading.Lock()
        self._seen: Dict[bytes, float] = {}
        self._ttl = ttl

    def check_and_record(self, nonce: bytes) -> bool:
        """Return True if nonce is fresh (not seen before). Records it."""
        now = time.time()
        with self._lock:
            # Prune expired
            expired = [n for n, ts in self._seen.items() if now - ts > self._ttl]
            for n in expired:
                del self._seen[n]
            if nonce in self._seen:
                return False
            self._seen[nonce] = now
            return True

    def clear(self) -> None:
        with self._lock:
            self._seen.clear()


# -- Secure Terminator ---------------------------------------------------------

class SecureTerminator:
    """Creates, verifies, and executes cryptographically signed termination commands.

    Thread-safe.  Integrates with JumpNode for state wiping and optional
    RBACManager for permission enforcement.
    """

    def __init__(
        self,
        node,                          # JumpNode (avoid circular import)
        signing_key: bytes,
        *,
        rbac=None,                     # Optional[RBACManager]
        max_staleness: float = 120.0,
        nonce_ttl: float = 300.0,
    ) -> None:
        self._node = node
        self._signing_key = signing_key
        self._rbac = rbac
        self._max_staleness = max_staleness
        self._nonce_tracker = _NonceTracker(ttl=nonce_ttl)
        self._lock = threading.Lock()
        self._audit_log: List[TerminationAuditEntry] = []
        self._terminated = False

    # -- Audit -----------------------------------------------------------------

    def _audit(
        self,
        command_id: str,
        issuer_id: str,
        target_node_id: str,
        action: str,
        details: str = "",
    ) -> None:
        entry = TerminationAuditEntry(
            command_id=command_id,
            issuer_id=issuer_id,
            target_node_id=target_node_id,
            action=action,
            timestamp=time.time(),
            details=details,
        )
        with self._lock:
            self._audit_log.append(entry)
        logger.info("termination audit: %s %s → %s (%s)",
                     action, issuer_id, target_node_id, details)

    @property
    def audit_log(self) -> List[TerminationAuditEntry]:
        with self._lock:
            return list(self._audit_log)

    # -- Signing ---------------------------------------------------------------

    def _sign(self, payload: bytes) -> bytes:
        return hmac.new(self._signing_key, payload, hashlib.sha256).digest()

    def _verify_signature(self, payload: bytes, signature: bytes) -> bool:
        expected = self._sign(payload)
        return hmac.compare_digest(expected, signature)

    # -- Command Creation ------------------------------------------------------

    def create_command(
        self,
        target_node_id: str,
        cascade: bool = False,
        issuer_id: Optional[str] = None,
    ) -> TerminationCommand:
        """Create and sign a termination command."""
        cmd = TerminationCommand(
            command_id=str(uuid.uuid4()),
            issuer_id=issuer_id or getattr(self._node, "node_name", "unknown"),
            target_node_id=target_node_id,
            cascade=cascade,
            timestamp=time.time(),
            nonce=os.urandom(16),
        )
        cmd.signature = self._sign(cmd.signable_payload())
        self._audit(cmd.command_id, cmd.issuer_id, cmd.target_node_id,
                     "initiated")
        return cmd

    # -- Verification ----------------------------------------------------------

    def verify_command(self, command: TerminationCommand) -> bool:
        """Verify signature, nonce freshness, and timestamp staleness."""
        # Signature check
        if not self._verify_signature(command.signable_payload(), command.signature):
            self._audit(command.command_id, command.issuer_id,
                         command.target_node_id, "rejected",
                         "invalid signature")
            return False

        # Timestamp staleness
        age = abs(time.time() - command.timestamp)
        if age > self._max_staleness:
            self._audit(command.command_id, command.issuer_id,
                         command.target_node_id, "rejected",
                         f"stale command (age={age:.1f}s)")
            return False

        # Nonce replay
        if not self._nonce_tracker.check_and_record(command.nonce):
            self._audit(command.command_id, command.issuer_id,
                         command.target_node_id, "rejected",
                         "nonce replay detected")
            return False

        self._audit(command.command_id, command.issuer_id,
                     command.target_node_id, "verified")
        return True

    # -- Execution -------------------------------------------------------------

    def execute(
        self,
        command: TerminationCommand,
        auth_token: Optional[str] = None,
    ) -> None:
        """Verify and execute a termination command.

        Raises TerminationError on verification failure or permission denial.
        """
        if self._terminated:
            raise TerminationError("node already terminated")

        if not self.verify_command(command):
            raise TerminationError("command verification failed")

        # RBAC check — mandatory when RBAC is configured
        if self._rbac is not None:
            if auth_token is None:
                self._audit(command.command_id, command.issuer_id,
                             command.target_node_id, "rejected",
                             "RBAC configured but no auth token provided")
                raise TerminationError("auth token required when RBAC is configured")
            try:
                from matrix.rbac import Permission
                self._rbac.require_permission(
                    auth_token, Permission.TERMINATE,
                    target_node_id=command.target_node_id,
                )
            except TerminationError:
                raise
            except Exception as exc:
                self._audit(command.command_id, command.issuer_id,
                             command.target_node_id, "rejected",
                             f"RBAC denied: {exc}")
                raise TerminationError(f"permission denied: {exc}") from exc

        # Wipe state
        try:
            self._wipe_state()
        except Exception as exc:
            self._audit(command.command_id, command.issuer_id,
                         command.target_node_id, "failed",
                         f"wipe error: {exc}")
            raise TerminationError(f"state wipe failed: {exc}") from exc

        # Stop node
        try:
            self._node.stop()
        except Exception:
            pass  # best-effort

        self._terminated = True
        self._audit(command.command_id, command.issuer_id,
                     command.target_node_id, "executed")

        # Cascade
        if command.cascade:
            self._cascade(command)

    def _wipe_state(self) -> None:
        """Overwrite sensitive state in memory."""
        node = self._node

        # Overwrite auth token
        if hasattr(node, "auth_token") and node.auth_token:
            token_len = len(node.auth_token)
            node.auth_token = os.urandom(token_len).hex()

        # Clear received sessions
        if hasattr(node, "received_sessions"):
            lock = getattr(node, "_sessions_lock", None)
            if lock:
                with lock:
                    node.received_sessions.clear()
            else:
                node.received_sessions.clear()

        # Clear transfer state store
        if hasattr(node, "_transfer_store"):
            store = node._transfer_store
            if hasattr(store, "_states"):
                lock = getattr(store, "_lock", None)
                if lock:
                    with lock:
                        store._states.clear()
                else:
                    store._states.clear()

        # Force garbage collection
        gc.collect()
        logger.info("state wiped")

    def _cascade(self, command: TerminationCommand) -> None:
        """Propagate termination to connected peers (best-effort)."""
        from matrix.jump_protocol import MsgType
        cascade_cmd = TerminationCommand(
            command_id=str(uuid.uuid4()),
            issuer_id=command.issuer_id,
            target_node_id="*",  # broadcast
            cascade=False,       # prevent infinite cascade
            timestamp=time.time(),
            nonce=os.urandom(16),
        )
        cascade_cmd.signature = self._sign(cascade_cmd.signable_payload())
        payload = json.dumps(cascade_cmd.to_dict()).encode()

        # Discover known peers and send
        peers = []
        if hasattr(self._node, "discovery"):
            try:
                peers = self._node.discover_targets()
            except Exception:
                pass

        propagated = 0
        for peer in peers:
            try:
                from matrix.jump_protocol import client_handshake, DirectTCPBackend
                import socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5.0)
                sock.connect((peer.address, peer.port))
                backend = DirectTCPBackend(sock)
                conn = client_handshake(backend, command.issuer_id)
                conn.send(MsgType.TERMINATE, payload)
                conn.close()
                propagated += 1
            except Exception as exc:
                logger.debug("cascade to %s failed: %s", peer.address, exc)

        self._audit(command.command_id, command.issuer_id,
                     command.target_node_id, "propagated",
                     f"sent to {propagated}/{len(peers)} peers")

    # -- Status ----------------------------------------------------------------

    @property
    def is_terminated(self) -> bool:
        return self._terminated
