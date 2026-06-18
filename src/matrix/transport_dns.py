"""
DNS Tunnel Transport — Carry Jump frames inside DNS TXT queries and responses.

Uses UDP DNS on port 53 (or any configurable port). Data is encoded in DNS
labels as Base32 so the query names remain valid. The response carries
server-to-client data in TXT record strings.

This transport is intentionally simple and bypasses most firewalls because
DNS is almost always allowed, even on captive portals. It trades bandwidth
for reachability.

Usage:
    # Server side
    listener = DNSListener(domain="example.com", port=53)
    listener.start(on_backend=jump_listener.accept_backend)

    # Client side
    backend = DNSBackend.connect(
        resolver="8.8.8.8",
        domain="example.com",
        local_id="node-a",
        remote_id="node-b",
        port=53,
    )
    conn = client_handshake(backend, "node-a")
"""

from __future__ import annotations

import base64
import hashlib
import logging
import socket
import struct
import threading
import time
from typing import Callable, Dict, Optional

logger = logging.getLogger(__name__)

__all__ = ["DNSBackend", "DNSListener", "DNSError"]


# == Errors ===================================================================

class DNSError(Exception):
    """Raised on DNS transport failure."""


# == Constants ================================================================

MAX_LABEL = 63
MAX_NAME = 253

DNS_QR_QUERY = 0
DNS_QR_RESPONSE = 1
DNS_OPCODE_QUERY = 0
DNS_RCODE_NOERROR = 0
DNS_RCODE_NXDOMAIN = 3
DNS_TYPE_TXT = 16
DNS_CLASS_IN = 1
DNS_HEADER_SIZE = 12

# Keep server responses under the classic 512-byte UDP DNS limit.
MAX_RAW_PER_RESPONSE = 220
TXT_RECORD_MAX_RAW = 159  # 159 bytes encode to 255 base32 chars


def _b32encode(data: bytes) -> str:
    """Base32-encode and strip padding, return uppercase string."""
    return base64.b32encode(data).decode().rstrip("=")


def _b32decode(text: str) -> bytes:
    """Base32-decode, adding padding if needed."""
    pad = (8 - len(text) % 8) % 8
    return base64.b32decode(text + ("=" * pad))


def _split_labels(text: str, limit: int = MAX_LABEL) -> list[str]:
    return [text[i:i + limit] for i in range(0, len(text), limit)]


def _encode_name(labels: list[str], domain: str) -> bytes:
    """Encode a list of labels and a trailing domain into a DNS name."""
    parts = list(labels) + _split_labels(domain.strip("."), MAX_LABEL)
    out = bytearray()
    for part in parts:
        out.append(len(part))
        out.extend(part.encode())
    out.append(0)
    return bytes(out)


def _decode_name(data: bytes, offset: int = 0) -> tuple[list[str], int]:
    """Decode a DNS name at offset, returning labels and new offset."""
    labels = []
    jumped = False
    original_offset = offset
    while True:
        if offset >= len(data):
            raise DNSError("truncated DNS name")
        length = data[offset]
        offset += 1
        if length == 0:
            break
        if length & 0xC0 == 0xC0:
            if not jumped:
                original_offset = offset + 1
            pointer = ((length & 0x3F) << 8) | data[offset]
            offset += 1
            jumped = True
            offset = pointer
            continue
        if length > MAX_LABEL:
            raise DNSError(f"DNS label too long: {length}")
        labels.append(data[offset:offset + length].decode())
        offset += length
    if jumped:
        offset = original_offset
    return labels, offset


def _build_dns_query(transaction_id: int, name: bytes, qtype: int = DNS_TYPE_TXT) -> bytes:
    flags = (DNS_OPCODE_QUERY << 11) | 0x0100  # RD=1
    header = struct.pack(
        "!HHHHHH",
        transaction_id & 0xFFFF,
        flags,
        1, 0, 0, 0,
    )
    question = name + struct.pack("!HH", qtype, DNS_CLASS_IN)
    return header + question


def _build_dns_response(
    transaction_id: int,
    question_name: bytes,
    txt_records: list[bytes],
    rcode: int = DNS_RCODE_NOERROR,
) -> bytes:
    flags = (DNS_QR_RESPONSE << 15) | (DNS_OPCODE_QUERY << 11) | (rcode & 0xF) | 0x0100
    header = struct.pack(
        "!HHHHHH",
        transaction_id & 0xFFFF,
        flags,
        1,
        len(txt_records),
        0, 0,
    )
    question = question_name + struct.pack("!HH", DNS_TYPE_TXT, DNS_CLASS_IN)
    answer = bytearray()
    for txt in txt_records:
        answer.extend(b"\xC0\x0C")
        answer.extend(struct.pack("!HHIH", DNS_TYPE_TXT, DNS_CLASS_IN, 0, len(txt) + 1))
        answer.append(len(txt))
        answer.extend(txt)
    return header + question + bytes(answer)


def _parse_dns_packet(data: bytes) -> dict:
    if len(data) < DNS_HEADER_SIZE:
        raise DNSError("DNS packet too short")
    tid, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", data[:DNS_HEADER_SIZE])
    qr = (flags >> 15) & 1
    rcode = flags & 0xF
    offset = DNS_HEADER_SIZE

    questions = []
    for _ in range(qdcount):
        labels, offset = _decode_name(data, offset)
        qtype, qclass = struct.unpack("!HH", data[offset:offset + 4])
        offset += 4
        questions.append({"labels": labels, "qtype": qtype, "qclass": qclass})

    answers = []
    for _ in range(ancount):
        labels, offset = _decode_name(data, offset)
        atype, aclass, ttl, rdlen = struct.unpack("!HHIH", data[offset:offset + 10])
        offset += 10
        rdata = data[offset:offset + rdlen]
        offset += rdlen
        if atype == DNS_TYPE_TXT:
            strings = []
            roff = 0
            while roff < len(rdata):
                slen = rdata[roff]
                strings.append(rdata[roff + 1:roff + 1 + slen])
                roff += 1 + slen
            answers.append({"type": atype, "strings": strings})
        else:
            answers.append({"type": atype, "rdata": rdata})

    return {
        "id": tid,
        "qr": qr,
        "rcode": rcode,
        "questions": questions,
        "answers": answers,
    }


# == DNS Backend (client side) ================================================

class DNSBackend:
    """TransportBackend that sends data as DNS TXT queries and reads replies.

    Matches responses by transaction ID so out-of-order UDP replies do not
    corrupt the byte stream.
    """

    def __init__(
        self,
        resolver: str,
        domain: str,
        local_id: str,
        remote_id: str,
        port: int = 53,
        timeout: float = 30.0,
    ):
        self.resolver = resolver
        self.domain = domain.strip(".")
        self.local_id = local_id
        self.remote_id = remote_id
        self.port = port
        self.timeout = timeout

        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.settimeout(timeout)
        self._connected = True
        self._closed = False

        self._send_seq = 0
        self._recv_buffer = bytearray()
        self._recv_lock = threading.Lock()
        self._pending: Dict[int, dict] = {}
        self._pending_lock = threading.Lock()
        self._tid_lock = threading.Lock()
        self._next_tid = 1

        self._receiver = threading.Thread(target=self._recv_loop, daemon=True, name="dns-receiver")
        self._receiver.start()

    @classmethod
    def connect(
        cls,
        resolver: str,
        domain: str,
        local_id: str,
        remote_id: str,
        port: int = 53,
        timeout: float = 30.0,
    ) -> "DNSBackend":
        return cls(resolver, domain, local_id, remote_id, port, timeout)

    @property
    def transport_name(self) -> str:
        return "dns"

    @property
    def peer_address(self) -> str:
        return f"dns://{self.resolver}:{self.port}/{self.remote_id}.{self.domain}"

    @property
    def is_connected(self) -> bool:
        return self._connected and not self._closed

    def _alloc_tid(self) -> int:
        with self._tid_lock:
            tid = self._next_tid
            self._next_tid = (self._next_tid + 1) & 0xFFFF
            if self._next_tid == 0:
                self._next_tid = 1
            return tid

    def _recv_loop(self) -> None:
        while self._running():
            try:
                raw, _ = self._sock.recvfrom(4096)
            except OSError:
                break
            try:
                parsed = _parse_dns_packet(raw)
            except DNSError:
                continue
            if parsed.get("qr") != DNS_QR_RESPONSE:
                continue
            with self._pending_lock:
                entry = self._pending.get(parsed["id"])
            if entry is None:
                continue
            entry["parsed"] = parsed
            entry["event"].set()

    def _running(self) -> bool:
        return self._connected and not self._closed

    def _query(self, name: bytes, tid: int) -> dict:
        packet = _build_dns_query(tid, name)
        event = threading.Event()
        with self._pending_lock:
            self._pending[tid] = {"event": event, "parsed": None}
        try:
            self._sock.sendto(packet, (self.resolver, self.port))
        except OSError as exc:
            self._connected = False
            raise DNSError(f"DNS send failed: {exc}") from exc

        if not event.wait(timeout=self.timeout):
            with self._pending_lock:
                self._pending.pop(tid, None)
            raise DNSError(f"DNS query timeout to {self.resolver}:{self.port}")
        with self._pending_lock:
            entry = self._pending.pop(tid, None)
        return entry["parsed"]

    def send_bytes(self, data: bytes) -> None:
        if not self.is_connected:
            raise DNSError("DNS transport closed")
        if not data:
            return
        chunk_size = 120
        for i in range(0, len(data), chunk_size):
            chunk = data[i:i + chunk_size]
            self._send_chunk(chunk)

    def _send_chunk(self, chunk: bytes) -> None:
        encoded = _b32encode(chunk)
        seq_label = f"{self._send_seq:08X}"
        self._send_seq = (self._send_seq + 1) & 0xFFFFFFFF
        payload_labels = _split_labels(encoded, MAX_LABEL)
        labels = ["M", seq_label, self.local_id, self.remote_id] + payload_labels
        name = _encode_name(labels, self.domain)
        tid = self._alloc_tid()
        parsed = self._query(name, tid)
        self._drain_answers(parsed)

    def _drain_answers(self, parsed: dict) -> None:
        for ans in parsed.get("answers", []):
            if ans.get("type") != DNS_TYPE_TXT:
                continue
            for s in ans.get("strings", []):
                if not s:
                    continue
                try:
                    decoded = _b32decode(s.decode())
                except Exception:
                    continue
                with self._recv_lock:
                    self._recv_buffer.extend(decoded)

    def recv_bytes(self, n: int) -> bytes:
        if not self.is_connected:
            raise DNSError("DNS transport closed")
        deadline = time.time() + self.timeout
        while time.time() < deadline:
            with self._recv_lock:
                if len(self._recv_buffer) >= n:
                    result = bytes(self._recv_buffer[:n])
                    del self._recv_buffer[:n]
                    return result
            # Send an empty poll query to elicit any server data.
            try:
                self._send_chunk(b"")
            except DNSError:
                pass
            time.sleep(0.02)
        raise DNSError(f"recv timeout waiting for {n} bytes")

    def close(self) -> None:
        self._closed = True
        self._connected = False
        try:
            self._sock.close()
        except OSError:
            pass


# == DNS Listener (server side) ===============================================

class DNSListener:
    """UDP DNS server that hands off a backend per connected client."""

    def __init__(self, domain: str, host: str = "0.0.0.0", port: int = 53, max_connections: int = 256):
        self.domain = domain.strip(".")
        self.host = host
        self.port = port
        self.max_connections = max_connections
        self._sock: Optional[socket.socket] = None
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._on_backend: Optional[Callable[["_ServerDNSBackend"], None]] = None
        self._backends: Dict[str, "_ServerDNSBackend"] = {}
        self._backends_lock = threading.Lock()

    def start(self, on_backend: Callable[["_ServerDNSBackend"], None]) -> None:
        self._on_backend = on_backend
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.bind((self.host, self.port))
        except PermissionError as exc:
            raise DNSError(f"cannot bind DNS port {self.port}: {exc}") from exc
        self._running = True
        self._thread = threading.Thread(target=self._receive_loop, daemon=True, name="dns-listener")
        self._thread.start()
        logger.info("DNSListener started on %s:%d (domain=%s)", self.host, self.port, self.domain)

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
        logger.info("DNSListener stopped")

    def _receive_loop(self) -> None:
        while self._running:
            try:
                data, addr = self._sock.recvfrom(4096)
            except OSError:
                break
            threading.Thread(target=self._handle_query, args=(data, addr), daemon=True).start()

    def _handle_query(self, data: bytes, addr) -> None:
        try:
            parsed = _parse_dns_packet(data)
        except DNSError as exc:
            logger.debug("Malformed DNS packet from %s: %s", addr, exc)
            return

        if parsed.get("qr") != DNS_QR_QUERY or not parsed["questions"]:
            return

        q = parsed["questions"][0]
        labels = q["labels"]
        if len(labels) < 4 or labels[0] != "M":
            return

        seq_label = labels[1]
        local_id = labels[2]
        remote_id = labels[3]

        domain_labels = _split_labels(self.domain, MAX_LABEL)
        if len(labels) >= len(domain_labels) and labels[-len(domain_labels):] == domain_labels:
            labels = labels[:-len(domain_labels)]

        payload_labels = labels[4:]
        encoded = "".join(payload_labels)
        payload = b""
        if encoded:
            try:
                payload = _b32decode(encoded)
            except Exception:
                pass

        client_key = f"{local_id}@{addr[0]}"

        with self._backends_lock:
            backend = self._backends.get(client_key)
            if backend is None:
                if len(self._backends) >= self.max_connections:
                    return
                backend = _ServerDNSBackend(
                    local_id=local_id,
                    remote_addr=addr,
                    domain=self.domain,
                    send_response=self._send_response,
                )
                self._backends[client_key] = backend
                if self._on_backend:
                    threading.Thread(
                        target=self._on_backend,
                        args=(backend,),
                        daemon=True,
                    ).start()

        if payload:
            backend._feed(payload)

        txt_records = backend._pop_outbound()
        if not txt_records:
            txt_records = [b""]

        name_bytes = _encode_name(labels, self.domain)
        response = _build_dns_response(parsed["id"], name_bytes, txt_records)
        try:
            self._sock.sendto(response, addr)
        except OSError:
            pass

    def _send_response(self, addr, response: bytes) -> None:
        try:
            self._sock.sendto(response, addr)
        except OSError:
            pass


class _ServerDNSBackend:
    """Server-side TransportBackend for one DNS client."""

    def __init__(self, local_id: str, remote_addr, domain: str, send_response: Callable):
        self.local_id = local_id
        self.remote_addr = remote_addr
        self.domain = domain
        self._send_response = send_response
        self._recv_buffer = bytearray()
        self._send_buffer = bytearray()
        self._lock = threading.Lock()
        self._connected = True
        self._closed = False

    @property
    def transport_name(self) -> str:
        return "dns"

    @property
    def peer_address(self) -> str:
        return f"dns://{self.remote_addr[0]}:{self.remote_addr[1]}/{self.local_id}"

    @property
    def is_connected(self) -> bool:
        return self._connected and not self._closed

    def _feed(self, data: bytes) -> None:
        with self._lock:
            self._recv_buffer.extend(data)

    def _pop_outbound(self) -> list[bytes]:
        """Return up to MAX_RAW_PER_RESPONSE bytes as independently decodable TXT strings."""
        with self._lock:
            chunk = bytes(self._send_buffer[:MAX_RAW_PER_RESPONSE])
            del self._send_buffer[:MAX_RAW_PER_RESPONSE]
        if not chunk:
            return []
        return [_b32encode(chunk[i:i + TXT_RECORD_MAX_RAW]).encode()
                for i in range(0, len(chunk), TXT_RECORD_MAX_RAW)]

    def send_bytes(self, data: bytes) -> None:
        if not self.is_connected:
            raise DNSError("server DNS backend closed")
        with self._lock:
            self._send_buffer.extend(data)

    def recv_bytes(self, n: int) -> bytes:
        if not self.is_connected:
            raise DNSError("server DNS backend closed")
        deadline = time.time() + 30.0
        while time.time() < deadline:
            with self._lock:
                if len(self._recv_buffer) >= n:
                    result = bytes(self._recv_buffer[:n])
                    del self._recv_buffer[:n]
                    return result
            time.sleep(0.02)
        raise DNSError(f"recv timeout waiting for {n} bytes")

    def close(self) -> None:
        self._closed = True
        self._connected = False
