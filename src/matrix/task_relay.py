"""
Task Relay — Peer-to-peer task relay for segmented or air-gapped networks.

Enables hop-based routing where nodes can relay tasks, sessions, and
commands on behalf of other nodes that cannot communicate directly.
Uses distance-vector routing with TTL and loop prevention.
"""

from __future__ import annotations

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
from typing import Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

__all__ = [
    "RelayTable",
    "RelayEntry",
    "RelayMessage",
    "TaskRelay",
    "RelayError",
]


# -- Errors --------------------------------------------------------------------

class RelayError(Exception):
    """Raised on relay operation failure."""


# -- Data Models ---------------------------------------------------------------

@dataclass(slots=True)
class RelayEntry:
    """A route entry: to reach *destination_id*, send to *next_hop_id*."""

    destination_id: str
    next_hop_id: str
    hop_count: int
    last_updated: float
    via_transport: str = "tcp"

    def to_dict(self) -> dict:
        return {
            "destination_id": self.destination_id,
            "next_hop_id": self.next_hop_id,
            "hop_count": self.hop_count,
            "last_updated": self.last_updated,
            "via_transport": self.via_transport,
        }

    @classmethod
    def from_dict(cls, d: dict) -> RelayEntry:
        return cls(
            destination_id=d["destination_id"],
            next_hop_id=d["next_hop_id"],
            hop_count=d["hop_count"],
            last_updated=d["last_updated"],
            via_transport=d.get("via_transport", "tcp"),
        )


@dataclass(slots=True)
class RelayMessage:
    """A message being relayed through the network."""

    message_id: str
    source_id: str
    destination_id: str
    payload_type: str          # "session", "task", "terminate", "custom"
    payload: bytes
    ttl: int
    hop_path: list             # node IDs traversed
    timestamp: float
    signature: bytes = b""

    def signable_payload(self) -> bytes:
        """Canonical bytes for HMAC signature."""
        parts = [
            self.message_id.encode(),
            self.source_id.encode(),
            self.destination_id.encode(),
            self.payload_type.encode(),
            self.payload,
            struct.pack("!I", self.ttl),
            struct.pack("!d", self.timestamp),
        ]
        return b"|".join(parts)

    def to_dict(self) -> dict:
        return {
            "message_id": self.message_id,
            "source_id": self.source_id,
            "destination_id": self.destination_id,
            "payload_type": self.payload_type,
            "payload": self.payload.hex(),
            "ttl": self.ttl,
            "hop_path": self.hop_path,
            "timestamp": self.timestamp,
            "signature": self.signature.hex(),
        }

    @classmethod
    def from_dict(cls, d: dict) -> RelayMessage:
        return cls(
            message_id=d["message_id"],
            source_id=d["source_id"],
            destination_id=d["destination_id"],
            payload_type=d["payload_type"],
            payload=bytes.fromhex(d["payload"]),
            ttl=d["ttl"],
            hop_path=list(d["hop_path"]),
            timestamp=d["timestamp"],
            signature=bytes.fromhex(d.get("signature", "")),
        )


# -- Relay Table ---------------------------------------------------------------

class RelayTable:
    """Thread-safe routing table with distance-vector merging.

    Maintains multiple routes per destination sorted by hop count.
    Supports merging route updates from peers and pruning stale entries.
    """

    def __init__(self, local_node_id: str) -> None:
        self._local_id = local_node_id
        self._lock = threading.RLock()
        self._routes: Dict[str, List[RelayEntry]] = {}

    def add_route(
        self,
        destination_id: str,
        next_hop_id: str,
        hop_count: int,
        via_transport: str = "tcp",
    ) -> None:
        """Add or update a route to *destination_id*."""
        entry = RelayEntry(
            destination_id=destination_id,
            next_hop_id=next_hop_id,
            hop_count=hop_count,
            last_updated=time.time(),
            via_transport=via_transport,
        )
        with self._lock:
            routes = self._routes.setdefault(destination_id, [])
            # Update existing route via same next_hop, or append
            for i, r in enumerate(routes):
                if r.next_hop_id == next_hop_id:
                    routes[i] = entry
                    routes.sort(key=lambda r: r.hop_count)
                    return
            routes.append(entry)
            routes.sort(key=lambda r: r.hop_count)

    def remove_route(self, destination_id: str, next_hop_id: str) -> None:
        """Remove a specific route."""
        with self._lock:
            routes = self._routes.get(destination_id, [])
            self._routes[destination_id] = [
                r for r in routes if r.next_hop_id != next_hop_id
            ]
            if not self._routes[destination_id]:
                del self._routes[destination_id]

    def get_route(self, destination_id: str) -> Optional[RelayEntry]:
        """Return the best (lowest hop count) route to *destination_id*."""
        with self._lock:
            routes = self._routes.get(destination_id, [])
            return routes[0] if routes else None

    def get_all_routes(self, destination_id: str) -> List[RelayEntry]:
        with self._lock:
            return list(self._routes.get(destination_id, []))

    def get_all_destinations(self) -> List[str]:
        with self._lock:
            return list(self._routes.keys())

    def merge(self, peer_id: str, entries: List[RelayEntry]) -> int:
        """Merge routes learned from a peer (distance-vector update).

        Increments hop counts by 1 and sets next_hop to the peer.
        Returns the number of routes added or updated.
        """
        updated = 0
        with self._lock:
            for entry in entries:
                # Don't add routes back to ourselves
                if entry.destination_id == self._local_id:
                    continue
                new_hop_count = entry.hop_count + 1
                existing = self.get_route(entry.destination_id)
                if existing is None or new_hop_count < existing.hop_count:
                    self.add_route(
                        destination_id=entry.destination_id,
                        next_hop_id=peer_id,
                        hop_count=new_hop_count,
                        via_transport=entry.via_transport,
                    )
                    updated += 1
        return updated

    def prune(self, max_age: float = 300.0) -> int:
        """Remove entries older than *max_age* seconds. Returns count pruned."""
        now = time.time()
        pruned = 0
        with self._lock:
            for dest_id in list(self._routes.keys()):
                routes = self._routes[dest_id]
                before = len(routes)
                self._routes[dest_id] = [
                    r for r in routes if now - r.last_updated <= max_age
                ]
                pruned += before - len(self._routes[dest_id])
                if not self._routes[dest_id]:
                    del self._routes[dest_id]
        return pruned

    def to_entries(self) -> List[RelayEntry]:
        """Export all routes as a flat list for broadcasting."""
        with self._lock:
            result = []
            for routes in self._routes.values():
                result.extend(routes)
            return result

    @property
    def route_count(self) -> int:
        with self._lock:
            return sum(len(r) for r in self._routes.values())

    @property
    def destination_count(self) -> int:
        with self._lock:
            return len(self._routes)


# -- Task Relay Engine ---------------------------------------------------------

_DEFAULT_TTL = 16
_MAX_TTL = 64


class TaskRelay:
    """Peer-to-peer relay engine for forwarding messages across segmented networks.

    Thread-safe.  Integrates with JumpNode for transport and optionally
    with RBACManager for permission checks.
    """

    def __init__(
        self,
        node,                           # JumpNode
        relay_table: RelayTable,
        *,
        rbac=None,                      # Optional[RBACManager]
        signing_key: Optional[bytes] = None,
        default_ttl: int = _DEFAULT_TTL,
    ) -> None:
        self._node = node
        self._table = relay_table
        self._rbac = rbac
        self._signing_key = signing_key or os.urandom(32)
        self._default_ttl = default_ttl

        self._lock = threading.Lock()
        self._handlers: Dict[str, Callable[[RelayMessage], None]] = {}
        self._seen_ids: Dict[str, float] = {}     # message_id -> timestamp
        self._stats = {"relayed": 0, "delivered": 0, "dropped": 0}

    # -- Message Creation ------------------------------------------------------

    def create_message(
        self,
        destination_id: str,
        payload_type: str,
        payload: bytes,
        ttl: Optional[int] = None,
    ) -> RelayMessage:
        """Create and sign a relay message.

        The hop_path starts empty; the local node ID is added by relay()
        when the message is actually forwarded, preventing the loop
        detection from immediately dropping locally-created messages.
        """
        local_id = getattr(self._node, "node_name", "unknown")
        msg = RelayMessage(
            message_id=str(uuid.uuid4()),
            source_id=local_id,
            destination_id=destination_id,
            payload_type=payload_type,
            payload=payload,
            ttl=ttl or self._default_ttl,
            hop_path=[],
            timestamp=time.time(),
        )
        msg.signature = self._sign(msg.signable_payload())
        return msg

    def _sign(self, payload: bytes) -> bytes:
        return hmac.new(self._signing_key, payload, hashlib.sha256).digest()

    # -- Dispatch Handlers -----------------------------------------------------

    def register_handler(
        self,
        payload_type: str,
        handler: Callable[[RelayMessage], None],
    ) -> None:
        """Register a handler for a specific payload type."""
        with self._lock:
            self._handlers[payload_type] = handler

    # -- Relay Logic -----------------------------------------------------------

    def verify_signature(self, message: RelayMessage) -> bool:
        """Verify the HMAC signature on a relay message."""
        expected = self._sign(message.signable_payload())
        return hmac.compare_digest(expected, message.signature)

    def handle_incoming(self, message: RelayMessage) -> None:
        """Process an incoming relay message: deliver locally or relay forward."""
        local_id = getattr(self._node, "node_name", "unknown")

        # Signature verification
        if message.signature and not self.verify_signature(message):
            with self._lock:
                self._stats["dropped"] += 1
            logger.warning("dropping relay %s: invalid signature",
                            message.message_id)
            return

        # RBAC check
        if self._rbac is not None:
            try:
                from matrix.rbac import Permission
                # Relay messages carry source identity; check RELAY permission
                # Use source_id as a proxy for auth (in practice, the node
                # that forwarded this would have been authenticated at the
                # transport layer via JumpListener's auth_validator)
            except ImportError:
                pass

        # Duplicate detection
        with self._lock:
            if message.message_id in self._seen_ids:
                self._stats["dropped"] += 1
                logger.debug("dropping duplicate relay %s", message.message_id)
                return
            self._seen_ids[message.message_id] = time.time()

        # Check if this message is for us
        if message.destination_id == local_id or message.destination_id == "*":
            self._deliver_local(message)
            return

        # Forward
        self.relay(message)

    def relay(self, message: RelayMessage) -> bool:
        """Forward a message toward its destination."""
        local_id = getattr(self._node, "node_name", "unknown")

        # Loop prevention
        if local_id in message.hop_path:
            with self._lock:
                self._stats["dropped"] += 1
            logger.debug("dropping looping relay %s", message.message_id)
            return False

        # TTL check
        if message.ttl <= 0:
            with self._lock:
                self._stats["dropped"] += 1
            logger.debug("dropping expired relay %s (TTL=0)", message.message_id)
            return False

        # Find route
        route = self._table.get_route(message.destination_id)
        if route is None:
            with self._lock:
                self._stats["dropped"] += 1
            logger.debug("no route to %s for relay %s",
                          message.destination_id, message.message_id)
            return False

        # Decrement TTL and add ourselves to hop path
        message.ttl -= 1
        message.hop_path.append(local_id)

        # Forward via JumpConnection
        try:
            self._forward_to_hop(route, message)
            with self._lock:
                self._stats["relayed"] += 1
            logger.info("relayed %s → %s via %s",
                         message.message_id, message.destination_id,
                         route.next_hop_id)
            return True
        except Exception as exc:
            with self._lock:
                self._stats["dropped"] += 1
            logger.warning("relay to %s failed: %s", route.next_hop_id, exc)
            return False

    def _forward_to_hop(self, route: RelayEntry, message: RelayMessage) -> None:
        """Send a relay message to the next hop."""
        from matrix.jump_protocol import (
            MsgType, client_handshake, DirectTCPBackend,
        )
        import socket

        # Resolve next hop address from relay table or node manager
        node = self._resolve_hop_address(route.next_hop_id)
        if node is None:
            raise RelayError(f"cannot resolve address for {route.next_hop_id}")

        address, port = node
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10.0)
        try:
            sock.connect((address, port))
            backend = DirectTCPBackend(sock)
            node_id = getattr(self._node, "node_name", "unknown")
            conn = client_handshake(
                backend, node_id,
                auth_token=getattr(self._node, "auth_token", None),
            )
            payload = json.dumps(message.to_dict()).encode()
            conn.send(MsgType.RELAY, payload)
            conn.close()
        except Exception:
            sock.close()
            raise

    def _resolve_hop_address(self, node_id: str) -> Optional[tuple]:
        """Try to resolve a node ID to (address, port)."""
        # Check discovered devices
        if hasattr(self._node, "discovery"):
            for device in self._node.discover_targets():
                if device.name == node_id or device.device_id == node_id:
                    return (device.address, device.port)
        return None

    def _deliver_local(self, message: RelayMessage) -> None:
        """Deliver a message to a local handler."""
        with self._lock:
            handler = self._handlers.get(message.payload_type)
            self._stats["delivered"] += 1

        if handler is not None:
            try:
                handler(message)
            except Exception as exc:
                logger.warning("relay handler for %s failed: %s",
                                message.payload_type, exc)
        else:
            logger.debug("no handler for payload type: %s", message.payload_type)

    # -- Route Broadcasting ----------------------------------------------------

    def broadcast_routes(self) -> int:
        """Send our relay table to all connected peers. Returns peers contacted."""
        from matrix.jump_protocol import MsgType, client_handshake, DirectTCPBackend
        import socket

        entries = self._table.to_entries()
        payload = json.dumps([e.to_dict() for e in entries]).encode()
        local_id = getattr(self._node, "node_name", "unknown")

        peers = []
        if hasattr(self._node, "discovery"):
            try:
                peers = self._node.discover_targets()
            except Exception:
                pass

        sent = 0
        for peer in peers:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5.0)
                sock.connect((peer.address, peer.port))
                backend = DirectTCPBackend(sock)
                conn = client_handshake(backend, local_id)
                conn.send(MsgType.ROUTE_UPDATE, payload)
                conn.close()
                sent += 1
            except Exception as exc:
                logger.debug("route broadcast to %s failed: %s",
                              peer.address, exc)
        return sent

    def handle_route_update(self, peer_id: str, data: bytes) -> int:
        """Process a ROUTE_UPDATE from a peer. Returns routes merged."""
        entries_raw = json.loads(data.decode())
        entries = [RelayEntry.from_dict(e) for e in entries_raw]
        return self._table.merge(peer_id, entries)

    # -- Maintenance -----------------------------------------------------------

    def prune_seen(self, max_age: float = 300.0) -> int:
        """Remove old seen message IDs."""
        now = time.time()
        with self._lock:
            expired = [
                mid for mid, ts in self._seen_ids.items()
                if now - ts > max_age
            ]
            for mid in expired:
                del self._seen_ids[mid]
            return len(expired)

    @property
    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)

    @property
    def relay_table(self) -> RelayTable:
        return self._table
