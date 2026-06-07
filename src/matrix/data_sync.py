"""
Data Synchronization — Chunked, encrypted, rate-limited sync with delivery confirmation.

Provides manifest-based delta synchronization between nodes.  Only changed
or missing data is transferred, using the same chunked transfer pattern
as session_jumper.py with added rate limiting and delivery tracking.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

__all__ = [
    "SyncManifest",
    "SyncEntry",
    "SyncManager",
    "RateLimiter",
    "DeliveryTracker",
    "SyncResult",
    "SyncError",
]


# -- Errors --------------------------------------------------------------------

class SyncError(Exception):
    """Raised on synchronization failure."""


# -- Constants -----------------------------------------------------------------

from matrix.config import config as _config

SYNC_CHUNK_SIZE = _config.chunk_size  # 64 KiB, matches jump_protocol.CHUNK_SIZE


# -- Data Models ---------------------------------------------------------------

@dataclass(slots=True)
class SyncEntry:
    """Metadata for a single synced data item."""

    key: str
    checksum: str           # SHA-256 hex digest
    size: int
    version: int
    last_modified: float
    source_node_id: str

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "checksum": self.checksum,
            "size": self.size,
            "version": self.version,
            "last_modified": self.last_modified,
            "source_node_id": self.source_node_id,
        }

    @classmethod
    def from_dict(cls, d: dict) -> SyncEntry:
        return cls(
            key=d["key"],
            checksum=d["checksum"],
            size=d["size"],
            version=d["version"],
            last_modified=d["last_modified"],
            source_node_id=d["source_node_id"],
        )


@dataclass(slots=True)
class SyncResult:
    """Result of a sync operation."""

    synced_keys: list = field(default_factory=list)
    failed_keys: list = field(default_factory=list)
    bytes_sent: int = 0
    bytes_received: int = 0
    elapsed: float = 0.0

    def to_dict(self) -> dict:
        return {
            "synced_keys": self.synced_keys,
            "failed_keys": self.failed_keys,
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received,
            "elapsed": self.elapsed,
        }


# -- Sync Manifest -------------------------------------------------------------

class SyncManifest:
    """Thread-safe manifest tracking what data exists on a node.

    Supports diff computation for delta synchronization — only missing
    or modified data needs to be transferred.
    """

    def __init__(self, node_id: str = "") -> None:
        self._node_id = node_id
        self._lock = threading.Lock()
        self._entries: Dict[str, SyncEntry] = {}

    def add(self, key: str, data: bytes, source_node_id: str = "") -> SyncEntry:
        """Register a data item in the manifest."""
        checksum = hashlib.sha256(data).hexdigest()
        with self._lock:
            existing = self._entries.get(key)
            version = (existing.version + 1) if existing else 1
            entry = SyncEntry(
                key=key,
                checksum=checksum,
                size=len(data),
                version=version,
                last_modified=time.time(),
                source_node_id=source_node_id or self._node_id,
            )
            self._entries[key] = entry
        return entry

    def remove(self, key: str) -> None:
        with self._lock:
            self._entries.pop(key, None)

    def get(self, key: str) -> Optional[SyncEntry]:
        with self._lock:
            return self._entries.get(key)

    def keys(self) -> List[str]:
        with self._lock:
            return list(self._entries.keys())

    def diff(
        self,
        remote_manifest: SyncManifest,
    ) -> Tuple[List[str], List[str], List[str]]:
        """Compare with a remote manifest.

        Returns:
            (missing_locally, missing_remotely, modified)
            - missing_locally: keys the remote has but we don't
            - missing_remotely: keys we have but the remote doesn't
            - modified: keys both have but with different checksums
        """
        with self._lock:
            local_keys = set(self._entries.keys())
            local_entries = dict(self._entries)

        with remote_manifest._lock:
            remote_keys = set(remote_manifest._entries.keys())
            remote_entries = dict(remote_manifest._entries)

        missing_locally = list(remote_keys - local_keys)
        missing_remotely = list(local_keys - remote_keys)
        modified = []
        for key in local_keys & remote_keys:
            if local_entries[key].checksum != remote_entries[key].checksum:
                # Checksum differs — need sync.  Pull from remote if its
                # version is newer OR versions are equal (diverged content
                # at same version — remote wins as tie-breaker).
                if local_entries[key].version <= remote_entries[key].version:
                    modified.append(key)

        return missing_locally, missing_remotely, modified

    def serialize(self) -> bytes:
        """Serialize manifest for exchange."""
        with self._lock:
            entries = [e.to_dict() for e in self._entries.values()]
        return json.dumps({
            "node_id": self._node_id,
            "entries": entries,
            "timestamp": time.time(),
        }).encode()

    @classmethod
    def deserialize(cls, data: bytes) -> SyncManifest:
        d = json.loads(data.decode())
        manifest = cls(node_id=d.get("node_id", ""))
        for entry_d in d.get("entries", []):
            entry = SyncEntry.from_dict(entry_d)
            with manifest._lock:
                manifest._entries[entry.key] = entry
        return manifest

    @property
    def entry_count(self) -> int:
        with self._lock:
            return len(self._entries)


# -- Rate Limiter --------------------------------------------------------------

class RateLimiter:
    """Token-bucket rate limiter for controlling transfer speed.

    Thread-safe.  Blocks callers until sufficient tokens are available.
    """

    def __init__(
        self,
        bytes_per_sec: float,
        burst_size: Optional[int] = None,
    ) -> None:
        self._rate = bytes_per_sec
        self._burst = burst_size or int(bytes_per_sec * 2)
        self._tokens = float(self._burst)
        self._last_refill = time.time()
        self._cond = threading.Condition()

    def acquire(self, nbytes: int) -> None:
        """Block until *nbytes* worth of tokens are available."""
        with self._cond:
            while True:
                self._refill()
                if self._tokens >= nbytes:
                    self._tokens -= nbytes
                    return
                # Wait for tokens to accumulate
                wait_time = (nbytes - self._tokens) / self._rate
                self._cond.wait(timeout=min(wait_time, 1.0))

    def _refill(self) -> None:
        now = time.time()
        elapsed = now - self._last_refill
        self._tokens = min(self._burst, self._tokens + elapsed * self._rate)
        self._last_refill = now

    def set_rate(self, bytes_per_sec: float) -> None:
        """Dynamically adjust the rate limit."""
        with self._cond:
            self._rate = bytes_per_sec
            self._burst = int(bytes_per_sec * 2)
            self._cond.notify_all()

    @property
    def rate(self) -> float:
        return self._rate


# -- Delivery Tracker ----------------------------------------------------------

@dataclass(slots=True)
class _DeliveryRecord:
    chunk_id: str
    data_hash: str
    sent_at: float
    confirmed: bool = False
    retries: int = 0


class DeliveryTracker:
    """Tracks delivery confirmations for sync chunks.

    Thread-safe.  Records sent chunks and matches them against
    peer acknowledgements to identify what needs retrying.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._pending: Dict[str, _DeliveryRecord] = {}

    def track(self, chunk_id: str, data_hash: str) -> None:
        """Record a sent chunk awaiting confirmation."""
        with self._lock:
            self._pending[chunk_id] = _DeliveryRecord(
                chunk_id=chunk_id,
                data_hash=data_hash,
                sent_at=time.time(),
            )

    def confirm(self, chunk_id: str, peer_hash: str) -> bool:
        """Confirm delivery. Returns True if hash matches."""
        with self._lock:
            record = self._pending.get(chunk_id)
            if record is None:
                return False
            if hmac.compare_digest(record.data_hash, peer_hash):
                record.confirmed = True
                return True
            return False

    def get_unconfirmed(self, max_age: float = 30.0) -> List[str]:
        """Return chunk IDs that haven't been confirmed within *max_age*."""
        now = time.time()
        with self._lock:
            return [
                cid for cid, rec in self._pending.items()
                if not rec.confirmed and now - rec.sent_at > max_age
            ]

    def retry_count(self, chunk_id: str) -> int:
        with self._lock:
            record = self._pending.get(chunk_id)
            return record.retries if record else 0

    def record_retry(self, chunk_id: str) -> None:
        with self._lock:
            record = self._pending.get(chunk_id)
            if record:
                record.retries += 1
                record.sent_at = time.time()

    def clear_confirmed(self) -> int:
        """Remove confirmed records. Returns count removed."""
        with self._lock:
            confirmed = [cid for cid, rec in self._pending.items() if rec.confirmed]
            for cid in confirmed:
                del self._pending[cid]
            return len(confirmed)

    @property
    def pending_count(self) -> int:
        with self._lock:
            return sum(1 for r in self._pending.values() if not r.confirmed)


# -- Sync Manager --------------------------------------------------------------

class SyncManager:
    """Orchestrates manifest-based delta synchronization between nodes.

    Thread-safe.  Uses chunked transfer with rate limiting and delivery
    confirmation.
    """

    def __init__(
        self,
        node=None,                      # JumpNode
        rate_limiter: Optional[RateLimiter] = None,
        rbac=None,                      # Optional[RBACManager]
        node_id: str = "",
    ) -> None:
        self._node = node
        self._rate_limiter = rate_limiter
        self._rbac = rbac

        self._lock = threading.Lock()
        self._manifest = SyncManifest(node_id=node_id)
        self._data_store: Dict[str, bytes] = {}
        self._tracker = DeliveryTracker()

    @property
    def manifest(self) -> SyncManifest:
        return self._manifest

    @property
    def tracker(self) -> DeliveryTracker:
        return self._tracker

    # -- Local Data Management -------------------------------------------------

    def add_data(self, key: str, data: bytes) -> SyncEntry:
        """Add data to the local store and manifest."""
        node_id = ""
        if self._node and hasattr(self._node, "node_name"):
            node_id = self._node.node_name
        with self._lock:
            self._data_store[key] = data
        return self._manifest.add(key, data, source_node_id=node_id)

    def get_data(self, key: str) -> Optional[bytes]:
        with self._lock:
            return self._data_store.get(key)

    def remove_data(self, key: str) -> None:
        with self._lock:
            self._data_store.pop(key, None)
        self._manifest.remove(key)

    def list_keys(self) -> List[str]:
        return self._manifest.keys()

    # -- Sync Protocol ---------------------------------------------------------

    def sync_with_peer(
        self,
        conn,                           # JumpConnection
        peer_manifest_data: Optional[bytes] = None,
        on_progress: Optional[Callable[[str, int, int], None]] = None,
    ) -> SyncResult:
        """Synchronize with a peer over an established connection.

        Steps:
        1. Exchange manifests
        2. Compute diff (delta)
        3. Send missing/modified data in rate-limited chunks
        4. Receive missing data from peer
        5. Confirm delivery

        Args:
            conn: An established JumpConnection.
            peer_manifest_data: Pre-exchanged manifest bytes (skip exchange step).
            on_progress: Callback(key, bytes_sent, total_bytes).
        """
        from matrix.jump_protocol import MsgType
        start = time.time()
        result = SyncResult()

        # Step 1: Exchange manifests
        if peer_manifest_data is None:
            local_manifest_bytes = self._manifest.serialize()
            conn.send(MsgType.SYNC_MANIFEST, local_manifest_bytes)
            msg_type, peer_manifest_data = conn.recv()
            result.bytes_sent += len(local_manifest_bytes)
            result.bytes_received += len(peer_manifest_data)

        peer_manifest = SyncManifest.deserialize(peer_manifest_data)

        # Step 2: Compute diff
        missing_locally, missing_remotely, modified = self._manifest.diff(
            peer_manifest
        )
        keys_to_send = missing_remotely
        keys_to_receive = missing_locally + modified

        # Step 3: Send data we have that peer needs
        for key in keys_to_send:
            data = self.get_data(key)
            if data is None:
                result.failed_keys.append(key)
                continue
            try:
                sent = self._send_data_chunked(conn, key, data, on_progress)
                result.bytes_sent += sent
                result.synced_keys.append(key)
            except Exception as exc:
                logger.warning("failed to sync key %s: %s", key, exc)
                result.failed_keys.append(key)

        # Step 4: Receive data peer is sending
        for key in keys_to_receive:
            try:
                data, received = self._receive_data_chunked(conn, key)
                if data is not None:
                    self.add_data(key, data)
                    result.bytes_received += received
                    result.synced_keys.append(key)
            except Exception as exc:
                logger.warning("failed to receive key %s: %s", key, exc)
                result.failed_keys.append(key)

        result.elapsed = time.time() - start
        return result

    def _send_data_chunked(
        self,
        conn,
        key: str,
        data: bytes,
        on_progress: Optional[Callable] = None,
    ) -> int:
        """Send data in rate-limited chunks with delivery tracking."""
        from matrix.jump_protocol import MsgType

        total = len(data)
        offset = 0
        seq = 0
        total_sent = 0

        # Send metadata
        meta = json.dumps({
            "key": key,
            "size": total,
            "checksum": hashlib.sha256(data).hexdigest(),
            "chunk_count": (total + SYNC_CHUNK_SIZE - 1) // SYNC_CHUNK_SIZE,
        }).encode()
        conn.send(MsgType.SYNC_REQUEST, meta)
        total_sent += len(meta)

        # Send chunks
        while offset < total:
            chunk = data[offset:offset + SYNC_CHUNK_SIZE]
            chunk_id = f"{key}:{seq}"
            chunk_hash = hashlib.sha256(chunk).hexdigest()

            # Rate limit
            if self._rate_limiter is not None:
                self._rate_limiter.acquire(len(chunk))

            # Build chunk header
            header = json.dumps({
                "key": key,
                "seq": seq,
                "offset": offset,
                "size": len(chunk),
                "checksum": chunk_hash,
                "final": offset + len(chunk) >= total,
            }).encode()
            payload = header + b"\x00" + chunk
            conn.send(MsgType.SYNC_CHUNK, payload)
            total_sent += len(payload)

            # Track delivery
            self._tracker.track(chunk_id, chunk_hash)

            offset += len(chunk)
            seq += 1

            if on_progress:
                on_progress(key, offset, total)

        # Wait for ACK
        try:
            msg_type, ack_data = conn.recv(timeout=10.0)
            if msg_type == MsgType.SYNC_ACK:
                ack = json.loads(ack_data.decode())
                # ACK contains per-chunk checksums for accurate confirmation
                chunk_checksums = ack.get("chunk_checksums", {})
                for confirmed_id in ack.get("confirmed", []):
                    chunk_hash = chunk_checksums.get(confirmed_id, "")
                    self._tracker.confirm(confirmed_id, chunk_hash)
        except Exception:
            pass

        return total_sent

    def _receive_data_chunked(
        self,
        conn,
        key: str,
    ) -> Tuple[Optional[bytes], int]:
        """Receive chunked data for a key."""
        from matrix.jump_protocol import MsgType

        total_received = 0

        # Receive metadata
        msg_type, meta_data = conn.recv(timeout=10.0)
        if msg_type != MsgType.SYNC_REQUEST:
            return None, 0
        meta = json.loads(meta_data.decode())
        expected_size = meta["size"]
        expected_checksum = meta["checksum"]
        chunk_count = meta["chunk_count"]
        total_received += len(meta_data)

        # Receive chunks
        buffer = bytearray()
        confirmed_ids = []
        chunk_checksums = {}  # chunk_id -> verified hash
        for _ in range(chunk_count):
            msg_type, payload = conn.recv(timeout=10.0)
            if msg_type != MsgType.SYNC_CHUNK:
                return None, total_received

            # Parse: header \x00 chunk_data
            sep = payload.index(b"\x00")
            header = json.loads(payload[:sep].decode())
            chunk_data = payload[sep + 1:]
            total_received += len(payload)

            # Verify chunk
            chunk_hash = hashlib.sha256(chunk_data).hexdigest()
            if chunk_hash != header["checksum"]:
                logger.warning("chunk checksum mismatch for %s seq %d",
                                key, header["seq"])
                continue

            buffer.extend(chunk_data)
            chunk_id = f"{key}:{header['seq']}"
            confirmed_ids.append(chunk_id)
            chunk_checksums[chunk_id] = chunk_hash

        # Verify complete data
        data = bytes(buffer)
        if hashlib.sha256(data).hexdigest() != expected_checksum:
            logger.warning("data checksum mismatch for key %s", key)
            return None, total_received

        # Send ACK with per-chunk checksums
        ack = json.dumps({
            "key": key,
            "confirmed": confirmed_ids,
            "chunk_checksums": chunk_checksums,
            "checksum": expected_checksum,
            "status": "ok",
        }).encode()
        try:
            conn.send(MsgType.SYNC_ACK, ack)
        except Exception:
            pass

        return data, total_received

    # -- Retry -----------------------------------------------------------------

    def retry_unconfirmed(
        self,
        conn,
        max_retries: int = 3,
    ) -> int:
        """Retry sending unconfirmed chunks. Returns count retried."""
        unconfirmed = self._tracker.get_unconfirmed()
        retried = 0
        for chunk_id in unconfirmed:
            if self._tracker.retry_count(chunk_id) >= max_retries:
                continue
            # Parse key:seq
            parts = chunk_id.rsplit(":", 1)
            if len(parts) != 2:
                continue
            key, seq_str = parts
            data = self.get_data(key)
            if data is None:
                continue

            seq = int(seq_str)
            offset = seq * SYNC_CHUNK_SIZE
            chunk = data[offset:offset + SYNC_CHUNK_SIZE]
            if not chunk:
                continue

            try:
                from matrix.jump_protocol import MsgType
                chunk_hash = hashlib.sha256(chunk).hexdigest()
                header = json.dumps({
                    "key": key,
                    "seq": seq,
                    "offset": offset,
                    "size": len(chunk),
                    "checksum": chunk_hash,
                    "final": offset + len(chunk) >= len(data),
                    "retry": True,
                }).encode()
                payload = header + b"\x00" + chunk
                conn.send(MsgType.SYNC_CHUNK, payload)
                self._tracker.record_retry(chunk_id)
                retried += 1
            except Exception as exc:
                logger.debug("retry failed for %s: %s", chunk_id, exc)

        return retried
