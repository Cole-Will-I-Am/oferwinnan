"""
ICMP Tunnel Transport — Carry Jump frames inside ICMP echo request/response payloads.

ICMP is often permitted through firewalls even when TCP/UDP are blocked. This
transport embeds raw Jump frames in the data section of ICMP echo (ping)
packets. It requires a raw socket, so the process needs root or CAP_NET_RAW.

Usage:
    # Server side
    listener = ICMPListener(host="0.0.0.0")
    listener.start(on_backend=jump_listener.accept_backend)

    # Client side
    backend = ICMPBackend.connect("10.0.0.5", local_id="node-a")
    conn = client_handshake(backend, "node-a")
"""

from __future__ import annotations

import logging
import os
import socket
import struct
import threading
import time
from typing import Callable, Dict, Optional

logger = logging.getLogger(__name__)

__all__ = ["ICMPBackend", "ICMPListener", "ICMPError"]


class ICMPError(Exception):
    """Raised on ICMP transport failure."""


# ICMP constants
ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0
ICMP_CODE = 0
ICMP_HEADER_SIZE = 8

# Magic cookie so we ignore real ping traffic
_ICMP_MAGIC = b"MX"


def _icmp_checksum(data: bytes) -> int:
    """RFC 792 ICMP checksum."""
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s & 0xFFFF) + (s >> 16)
    s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def _build_icmp_echo(icmp_id: int, seq: int, payload: bytes) -> bytes:
    """Build an ICMP echo request/reply packet with magic + payload."""
    body = _ICMP_MAGIC + payload
    header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, ICMP_CODE, 0, icmp_id, seq)
    checksum = _icmp_checksum(header + body)
    header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, ICMP_CODE, checksum, icmp_id, seq)
    return header + body


def _parse_icmp_packet(data: bytes) -> Optional[dict]:
    """Parse an ICMP echo packet. Returns None if not our magic."""
    if len(data) < ICMP_HEADER_SIZE + len(_ICMP_MAGIC):
        return None
    typ, code, checksum, icmp_id, seq = struct.unpack("!BBHHH", data[:ICMP_HEADER_SIZE])
    body = data[ICMP_HEADER_SIZE:]
    if not body.startswith(_ICMP_MAGIC):
        return None
    return {
        "type": typ,
        "code": code,
        "id": icmp_id,
        "seq": seq,
        "payload": body[len(_ICMP_MAGIC):],
    }


# == ICMP Backend (client side) ===============================================

class ICMPBackend:
    """TransportBackend over ICMP echo request/reply."""

    def __init__(
        self,
        host: str,
        local_id: str,
        timeout: float = 10.0,
    ):
        self.host = host
        self.local_id = local_id
        self.timeout = timeout
        self._icmp_id = (os.getpid() & 0xFFFF) or 1
        self._seq = 0

        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        except PermissionError as exc:
            raise ICMPError("ICMP raw socket requires root or CAP_NET_RAW") from exc
        self._sock.settimeout(timeout)
        self._connected = True
        self._closed = False

        self._recv_buffer = bytearray()
        self._recv_lock = threading.Lock()
        self._pending: Dict[int, dict] = {}
        self._pending_lock = threading.Lock()

        self._receiver = threading.Thread(target=self._recv_loop, daemon=True, name="icmp-receiver")
        self._receiver.start()

    @classmethod
    def connect(cls, host: str, local_id: str, timeout: float = 10.0) -> "ICMPBackend":
        return cls(host, local_id, timeout)

    @property
    def transport_name(self) -> str:
        return "icmp"

    @property
    def peer_address(self) -> str:
        return f"icmp://{self.host}"

    @property
    def is_connected(self) -> bool:
        return self._connected and not self._closed

    def _next_seq(self) -> int:
        s = self._seq
        self._seq = (self._seq + 1) & 0xFFFF
        return s

    def _running(self) -> bool:
        return self._connected and not self._closed

    def _recv_loop(self) -> None:
        while self._running():
            try:
                raw, addr = self._sock.recvfrom(2048)
            except (OSError, ValueError):
                break
            # IP header length is in the first byte (low nibble * 4)
            if len(raw) < 20:
                continue
            ip_header_len = (raw[0] & 0x0F) * 4
            icmp_data = raw[ip_header_len:]
            parsed = _parse_icmp_packet(icmp_data)
            if parsed is None or parsed["type"] != ICMP_ECHO_REPLY:
                continue
            if parsed["id"] != self._icmp_id:
                continue
            with self._pending_lock:
                entry = self._pending.get(parsed["seq"])
            if entry is None:
                # Unsolicited reply data; buffer it for recv_bytes.
                with self._recv_lock:
                    self._recv_buffer.extend(parsed["payload"])
                continue
            entry["payload"] = parsed["payload"]
            entry["event"].set()

    def _ping(self, payload: bytes) -> bytes:
        """Send an ICMP echo request and return the reply payload."""
        seq = self._next_seq()
        packet = _build_icmp_echo(self._icmp_id, seq, payload)
        event = threading.Event()
        with self._pending_lock:
            self._pending[seq] = {"event": event, "payload": b""}
        try:
            self._sock.sendto(packet, (self.host, 0))
        except OSError as exc:
            self._connected = False
            raise ICMPError(f"ICMP send failed: {exc}") from exc

        if not event.wait(timeout=self.timeout):
            with self._pending_lock:
                self._pending.pop(seq, None)
            raise ICMPError(f"ICMP reply timeout from {self.host}")
        with self._pending_lock:
            entry = self._pending.pop(seq, None)
        return entry["payload"]

    def send_bytes(self, data: bytes) -> None:
        if not self.is_connected:
            raise ICMPError("ICMP transport closed")
        if not data:
            return
        # ICMP payload max ~1400 bytes to stay under common MTU
        chunk_size = 1200
        for i in range(0, len(data), chunk_size):
            reply_payload = self._ping(data[i:i + chunk_size])
            with self._recv_lock:
                self._recv_buffer.extend(reply_payload)

    def recv_bytes(self, n: int) -> bytes:
        if not self.is_connected:
            raise ICMPError("ICMP transport closed")
        deadline = time.time() + self.timeout
        while time.time() < deadline:
            with self._recv_lock:
                if len(self._recv_buffer) >= n:
                    result = bytes(self._recv_buffer[:n])
                    del self._recv_buffer[:n]
                    return result
            try:
                reply = self._ping(b"")
                with self._recv_lock:
                    self._recv_buffer.extend(reply)
            except ICMPError:
                pass
            time.sleep(0.02)
        raise ICMPError(f"recv timeout waiting for {n} bytes")

    def close(self) -> None:
        self._closed = True
        self._connected = False
        try:
            self._sock.close()
        except OSError:
            pass


# == ICMP Listener (server side) ==============================================

class ICMPListener:
    """Raw-socket ICMP echo server that hands off a backend per client."""

    def __init__(self, host: str = "0.0.0.0", max_connections: int = 256):
        self.host = host
        self.max_connections = max_connections
        self._sock: Optional[socket.socket] = None
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._on_backend: Optional[Callable[["_ServerICMPBackend"], None]] = None
        self._backends: Dict[str, "_ServerICMPBackend"] = {}
        self._backends_lock = threading.Lock()

    def start(self, on_backend: Callable[["_ServerICMPBackend"], None]) -> None:
        self._on_backend = on_backend
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        except PermissionError as exc:
            raise ICMPError("ICMP raw socket requires root or CAP_NET_RAW") from exc
        try:
            self._sock.bind((self.host, 0))
        except OSError as exc:
            raise ICMPError(f"cannot bind ICMP listener: {exc}") from exc
        self._running = True
        self._thread = threading.Thread(target=self._receive_loop, daemon=True, name="icmp-listener")
        self._thread.start()
        logger.info("ICMPListener started on %s", self.host)

    def stop(self) -> None:
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
        if self._thread:
            self._thread.join(timeout=5)
        with self._backends_lock:
            for backend in self._backends.values():
                backend.close()
            self._backends.clear()
        logger.info("ICMPListener stopped")

    def _receive_loop(self) -> None:
        while self._running:
            try:
                raw, addr = self._sock.recvfrom(2048)
            except OSError:
                break
            if len(raw) < 20:
                continue
            ip_header_len = (raw[0] & 0x0F) * 4
            icmp_data = raw[ip_header_len:]
            parsed = _parse_icmp_packet(icmp_data)
            if parsed is None or parsed["type"] != ICMP_ECHO_REQUEST:
                continue

            client_key = f"{addr[0]}:{parsed['id']}"
            with self._backends_lock:
                backend = self._backends.get(client_key)
                if backend is None:
                    if len(self._backends) >= self.max_connections:
                        continue
                    backend = _ServerICMPBackend(
                        remote_addr=addr,
                        icmp_id=parsed["id"],
                        send_reply=self._send_reply,
                    )
                    self._backends[client_key] = backend
                    if self._on_backend:
                        threading.Thread(
                            target=self._on_backend,
                            args=(backend,),
                            daemon=True,
                        ).start()

            if parsed["payload"]:
                backend._feed(parsed["payload"])

            reply_payload = backend._pop_outbound()
            self._send_reply(addr, parsed["id"], parsed["seq"], reply_payload)

    def _send_reply(self, addr, icmp_id: int, seq: int, payload: bytes) -> None:
        body = _ICMP_MAGIC + payload
        header = struct.pack("!BBHHH", ICMP_ECHO_REPLY, ICMP_CODE, 0, icmp_id, seq)
        checksum = _icmp_checksum(header + body)
        header = struct.pack("!BBHHH", ICMP_ECHO_REPLY, ICMP_CODE, checksum, icmp_id, seq)
        packet = header + body
        try:
            self._sock.sendto(packet, addr)
        except OSError:
            pass


class _ServerICMPBackend:
    """Server-side TransportBackend for one ICMP client."""

    def __init__(self, remote_addr, icmp_id: int, send_reply: Callable):
        self.remote_addr = remote_addr
        self.icmp_id = icmp_id
        self._send_reply = send_reply
        self._recv_buffer = bytearray()
        self._send_buffer = bytearray()
        self._lock = threading.Lock()
        self._connected = True
        self._closed = False

    @property
    def transport_name(self) -> str:
        return "icmp"

    @property
    def peer_address(self) -> str:
        return f"icmp://{self.remote_addr[0]}"

    @property
    def is_connected(self) -> bool:
        return self._connected and not self._closed

    def _feed(self, data: bytes) -> None:
        with self._lock:
            self._recv_buffer.extend(data)

    def _pop_outbound(self) -> bytes:
        with self._lock:
            chunk = bytes(self._send_buffer[:1200])
            del self._send_buffer[:1200]
        return chunk

    def send_bytes(self, data: bytes) -> None:
        if not self.is_connected:
            raise ICMPError("server ICMP backend closed")
        with self._lock:
            self._send_buffer.extend(data)

    def recv_bytes(self, n: int) -> bytes:
        if not self.is_connected:
            raise ICMPError("server ICMP backend closed")
        deadline = time.time() + 30.0
        while time.time() < deadline:
            with self._lock:
                if len(self._recv_buffer) >= n:
                    result = bytes(self._recv_buffer[:n])
                    del self._recv_buffer[:n]
                    return result
            time.sleep(0.02)
        raise ICMPError(f"recv timeout waiting for {n} bytes")

    def close(self) -> None:
        self._closed = True
        self._connected = False
