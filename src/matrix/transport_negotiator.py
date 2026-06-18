"""
Transport Negotiator — Probe, select, and normalize traffic across transports.

Phase 0 (Probe):   Parallel probes via TCP, WebSocket, HTTPS, DNS
Phase 1 (Select):  Choose the transport with lowest RTT that succeeded
Phase 2 (Connect): Full handshake over the selected transport

Also includes traffic normalization:
  - Frame padding to fixed size buckets (eliminates payload-size fingerprinting)
  - Per-session polymorphic frame magic and bucket sets (static signature evasion)
  - Timing jitter between frames (mimics interactive traffic)
  - Stateful cover traffic with idle typing/keepalive patterns
  - Pluggable TrafficProfile classes for application-layer mimicry
    (Slack, Teams, Discord, DNS-over-HTTPS, gRPC, cloud sync, generic Web API)
"""

import json
import logging
import os
import random
import secrets
import socket
import struct
import threading
import time
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from matrix.jump_protocol import (
    TransportBackend, DirectTCPBackend, JumpConnection,
    MsgType, ProtocolError, SessionKeys,
    client_handshake, server_handshake,
    encode_frame, HEADER_SIZE, HEADER_MAGIC, CHUNK_SIZE,
)

logger = logging.getLogger(__name__)


# == Transport Probe ===========================================================

@dataclass
class ProbeResult:
    """Result of probing a single transport."""
    transport: str          # "tcp", "websocket", "https", "dns"
    success: bool
    rtt_ms: float = 0.0     # Round-trip time in milliseconds
    backend: Optional[TransportBackend] = field(default=None, repr=False)
    error: Optional[str] = None


def _probe_tcp(host: str, port: int, timeout: float) -> ProbeResult:
    """Probe via direct TCP connection."""
    t0 = time.monotonic()
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        rtt = (time.monotonic() - t0) * 1000
        backend = DirectTCPBackend(sock)
        return ProbeResult("tcp", True, rtt, backend)
    except (OSError, ConnectionError) as e:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        return ProbeResult("tcp", False, error=str(e))


def _probe_websocket(url: str, timeout: float) -> ProbeResult:
    """Probe via WebSocket connection."""
    t0 = time.monotonic()
    try:
        from matrix.transport_ws import WebSocketBackend
        backend = WebSocketBackend.connect(url, timeout=timeout)
        rtt = (time.monotonic() - t0) * 1000
        return ProbeResult("websocket", True, rtt, backend)
    except (OSError, ConnectionError, ImportError) as e:
        return ProbeResult("websocket", False, error=str(e))


def _probe_https(url: str, timeout: float) -> ProbeResult:
    """Probe via HTTPS (check if endpoint is reachable)."""
    t0 = time.monotonic()
    try:
        import urllib.request
        req = urllib.request.Request(url, method="HEAD")
        with urllib.request.urlopen(req, timeout=timeout):
            pass
        rtt = (time.monotonic() - t0) * 1000
        # HTTPS probe only checks reachability — no persistent backend yet
        return ProbeResult("https", True, rtt, error=None)
    except Exception as e:
        return ProbeResult("https", False, error=str(e))


class _DeadDropPlaceholder:
    """Placeholder backend returned by dead-drop probes.

    Satisfies the ``backend is not None`` check in negotiate() so that
    dead-drop is considered connectable.  Must be replaced with a real
    DeadDropBackend (supplying node IDs) before actual use.
    """

    def __init__(self, config) -> None:
        self.config = config

    def send_bytes(self, data: bytes) -> None:
        raise NotImplementedError("replace placeholder with DeadDropBackend")

    def recv_bytes(self, n: int) -> bytes:
        raise NotImplementedError("replace placeholder with DeadDropBackend")

    def close(self) -> None:
        pass

    @property
    def peer_address(self) -> str:
        return "dead-drop:placeholder"

    @property
    def transport_name(self) -> str:
        return "dead-drop"

    @property
    def is_connected(self) -> bool:
        return False


class TransportNegotiator:
    """Probes multiple transports in parallel and selects the best one.

    Usage:
        neg = TransportNegotiator(
            host="195518.online",
            tcp_port=47701,
            ws_url="wss://195518.online/jump/ws",
        )
        result = neg.negotiate(timeout=5.0)
        if result.backend:
            conn = client_handshake(result.backend, "my-node")
    """

    def __init__(self, host: str,
                 tcp_port: int = 47701,
                 ws_url: Optional[str] = None,
                 https_url: Optional[str] = None,
                 dead_drop_config=None,
                 dns_config: Optional[dict] = None,
                 icmp_config: Optional[dict] = None):
        self.host = host
        self.tcp_port = tcp_port
        self.ws_url = ws_url
        self.https_url = https_url
        self.dead_drop_config = dead_drop_config  # Optional[DeadDropConfig]
        self.dns_config = dns_config  # {resolver, domain, local_id, remote_id}
        self.icmp_config = icmp_config  # {local_id}

    def negotiate(self, timeout: float = 5.0,
                  prefer: Optional[str] = None) -> ProbeResult:
        """Probe all configured transports in parallel, return the best.

        Args:
            timeout: Per-probe timeout in seconds.
            prefer: If set, prefer this transport even if slightly slower
                    (within 50ms of the fastest).

        Returns:
            ProbeResult with the best transport. If all fail, returns a
            failed ProbeResult.
        """
        # Build probe tasks
        tasks: List[Tuple[str, Callable]] = [
            ("tcp", lambda: _probe_tcp(self.host, self.tcp_port, timeout)),
        ]

        if self.ws_url:
            ws_url = self.ws_url
            tasks.append(
                ("websocket", lambda: _probe_websocket(ws_url, timeout)),
            )

        if self.https_url:
            https_url = self.https_url
            tasks.append(
                ("https", lambda: _probe_https(https_url, timeout)),
            )

        if self.dead_drop_config is not None:
            dd_config = self.dead_drop_config
            tasks.append(
                ("dead-drop", lambda: self._probe_dead_drop(dd_config, timeout)),
            )

        if self.dns_config:
            dns_cfg = self.dns_config
            tasks.append(
                ("dns", lambda: self._probe_dns(dns_cfg, timeout)),
            )

        if self.icmp_config:
            icmp_cfg = self.icmp_config
            tasks.append(
                ("icmp", lambda: self._probe_icmp(icmp_cfg, timeout)),
            )

        # Execute all probes in parallel
        results: List[ProbeResult] = []
        with ThreadPoolExecutor(max_workers=len(tasks)) as pool:
            futures = {pool.submit(fn): name for name, fn in tasks}
            for future in as_completed(futures):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    transport = futures[future]
                    results.append(ProbeResult(transport, False, error=str(e)))

        # Select best
        successful = [r for r in results if r.success]

        if not successful:
            logger.warning("TransportNegotiator: all probes failed")
            errors = "; ".join(f"{r.transport}: {r.error}" for r in results)
            return ProbeResult("none", False, error=f"All probes failed: {errors}")

        connectable = [r for r in successful if r.backend is not None]
        if not connectable:
            logger.warning(
                "TransportNegotiator: only stateless probes succeeded (no connectable backend)"
            )
            return ProbeResult(
                "none",
                False,
                error="No connectable transport succeeded (only reachability checks passed)",
            )

        # Sort by RTT
        connectable.sort(key=lambda r: r.rtt_ms)

        # Apply preference
        if prefer:
            preferred = [r for r in connectable if r.transport == prefer]
            if preferred:
                best = connectable[0]
                pref = preferred[0]
                # Use preferred if within 50ms of fastest
                if pref.rtt_ms - best.rtt_ms < 50:
                    logger.info("TransportNegotiator: using preferred %s (%.1fms) "
                                "over fastest %s (%.1fms)",
                                pref.transport, pref.rtt_ms,
                                best.transport, best.rtt_ms)
                    # Close non-selected backends
                    for r in connectable:
                        if r is not pref and r.backend:
                            r.backend.close()
                    return pref

        winner = connectable[0]
        logger.info("TransportNegotiator: selected %s (%.1fms RTT)",
                     winner.transport, winner.rtt_ms)

        # Close non-selected backends
        for r in connectable:
            if r is not winner and r.backend:
                r.backend.close()

        return winner

    @staticmethod
    def _probe_dns(config: dict, timeout: float) -> ProbeResult:
        """Probe DNS transport by sending an empty query."""
        try:
            backend = DNSBackend.connect(
                resolver=config["resolver"],
                domain=config["domain"],
                local_id=config["local_id"],
                remote_id=config["remote_id"],
                port=config.get("port", 53),
                timeout=timeout,
            )
            t0 = time.monotonic()
            backend.send_bytes(b"")
            rtt = (time.monotonic() - t0) * 1000
            return ProbeResult("dns", True, rtt, backend)
        except Exception as exc:
            return ProbeResult("dns", False, error=str(exc))

    @staticmethod
    def _probe_icmp(config: dict, timeout: float) -> ProbeResult:
        """Probe ICMP transport by sending an empty echo request."""
        try:
            backend = ICMPBackend.connect(
                host=config["host"],
                local_id=config["local_id"],
                timeout=timeout,
            )
            t0 = time.monotonic()
            backend.send_bytes(b"")
            rtt = (time.monotonic() - t0) * 1000
            return ProbeResult("icmp", True, rtt, backend)
        except Exception as exc:
            return ProbeResult("icmp", False, error=str(exc))

    @staticmethod
    def _probe_dead_drop(config, timeout: float) -> ProbeResult:
        """Probe dead-drop transport availability.

        Dead-drop always reports a high RTT penalty (10000ms) so it is only
        selected as a last-resort fallback when all other transports fail.
        Returns a _DeadDropPlaceholder as backend so the negotiator treats
        it as connectable.
        """
        t0 = time.monotonic()
        try:
            from matrix.dead_drop import DeadDropBackend, CloudProvider, FileSystemDeadDrop
            # For filesystem provider, verify the path exists
            if config.provider == CloudProvider.FILESYSTEM:
                import os
                if not os.path.isdir(config.base_path):
                    return ProbeResult("dead-drop", False,
                                       error=f"base_path not found: {config.base_path}")
            # Dead-drop is always "reachable" but slow — penalize RTT
            rtt = (time.monotonic() - t0) * 1000 + 10000.0
            # Return a placeholder backend so negotiate() treats this
            # as connectable.  Callers must replace with a real
            # DeadDropBackend (which requires node IDs) before use.
            placeholder = _DeadDropPlaceholder(config)
            return ProbeResult("dead-drop", True, rtt, placeholder)
        except Exception as e:
            return ProbeResult("dead-drop", False, error=str(e))

    def negotiate_multipath(self, timeout: float = 5.0
                            ) -> List[ProbeResult]:
        """Return ALL successful probe results for multi-path use.

        Unlike negotiate() which picks one, this returns all working
        transports so MultiPathConnection can use them simultaneously.
        """
        tasks: List[Tuple[str, Callable]] = [
            ("tcp", lambda: _probe_tcp(self.host, self.tcp_port, timeout)),
        ]
        if self.ws_url:
            ws_url = self.ws_url
            tasks.append(
                ("websocket", lambda: _probe_websocket(ws_url, timeout)),
            )

        results: List[ProbeResult] = []
        with ThreadPoolExecutor(max_workers=len(tasks)) as pool:
            futures = {pool.submit(fn): name for name, fn in tasks}
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result.success:
                        results.append(result)
                except Exception:
                    pass

        results.sort(key=lambda r: r.rtt_ms)
        return results


# == Traffic Normalization =====================================================

# -- Frame Padding -------------------------------------------------------------

# Default bucket sizes. Individual NormalizedConnection instances can use a
# polymorphic set derived from a session seed to avoid static signatures.
PADDING_BUCKETS = [128, 256, 512, 1024, 4096, 16384, 65536, 262144]


def _derive_buckets(seed: str) -> list[int]:
    """Generate a deterministic but unique set of padding buckets from seed.

    Keeps the same rough growth curve as the defaults so padding overhead
    remains bounded, but the exact values vary per session.
    """
    rng = random.Random(seed)
    base = [128, 256, 512, 1024, 4096, 16384, 65536, 262144]
    return [max(64, int(b * rng.uniform(0.85, 1.15))) for b in base]


def pad_frame(data: bytes, buckets: list[int] = None) -> bytes:
    """Pad frame data to the next bucket size.

    The original JMP frame header contains the real payload length,
    so the receiver can strip padding by reading only `length` bytes.
    Padding bytes are random to prevent pattern detection.
    """
    buckets = buckets or PADDING_BUCKETS
    size = len(data)
    target = size
    for bucket in buckets:
        if bucket >= size:
            target = bucket
            break
    else:
        target = size  # Larger than all buckets — don't pad

    if target > size:
        padding = os.urandom(target - size)
        return data + padding
    return data


def strip_padding(data: bytes, real_length: int) -> bytes:
    """Strip padding from received data."""
    return data[:real_length]


# -- Timing Jitter -------------------------------------------------------------

class TimingJitter:
    """Adds Gaussian-distributed delays between frame sends.

    Prevents traffic analysis from identifying burst patterns.
    """

    def __init__(self, mean_ms: float = 50.0, stddev_ms: float = 20.0,
                 min_ms: float = 5.0, max_ms: float = 200.0,
                 enabled: bool = True):
        self.mean = mean_ms / 1000.0
        self.stddev = stddev_ms / 1000.0
        self.min_delay = min_ms / 1000.0
        self.max_delay = max_ms / 1000.0
        self.enabled = enabled

    def delay(self) -> None:
        """Sleep for a jittered duration."""
        if not self.enabled:
            return
        d = random.gauss(self.mean, self.stddev)
        d = max(self.min_delay, min(self.max_delay, d))
        time.sleep(d)

    @property
    def avg_delay_ms(self) -> float:
        return self.mean * 1000


# -- Cover Traffic -------------------------------------------------------------

class CoverTrafficGenerator:
    """Sends realistic idle/cover traffic during quiet periods.

    Generates:
      - random-interval PING/PONG heartbeats
      - occasional typing indicators / presence events
      - realistic payload sizes drawn from common app patterns

    Prevents traffic analysis from identifying active vs idle connections.
    """

    def __init__(self, connection: JumpConnection,
                 min_interval: float = 2.0,
                 max_interval: float = 15.0,
                 send_lock: Optional[threading.Lock] = None,
                 seed: Optional[str] = None):
        self._conn = connection
        self._send_lock = send_lock or threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._paused = threading.Event()
        self._paused.set()  # Not paused by default

        rng = random.Random(seed)
        # Jittered idle interval: heavily skewed toward longer quiet periods
        self._min = min_interval
        self._max = max_interval
        # Common payload size bands for cover traffic (bytes)
        self._size_pool = [16, 32, 48, 64, 96, 128, 192, 256]
        self._rng = rng

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True,
                                        name="cover-traffic")
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        self._paused.set()  # Unblock if paused
        if self._thread:
            self._thread.join(timeout=5)

    def pause(self) -> None:
        """Pause cover traffic (e.g., during active transfer)."""
        self._paused.clear()

    def resume(self) -> None:
        """Resume cover traffic after a transfer."""
        self._paused.set()

    def _next_interval(self) -> float:
        """Return a jittered idle interval biased toward the long end."""
        # triangular distribution: more likely near max
        return self._rng.triangular(self._min, self._max, self._max)

    def _chaff_payload(self) -> bytes:
        """Return a random cover payload from realistic size bands."""
        size = self._rng.choice(self._size_pool)
        return os.urandom(size)

    def _loop(self) -> None:
        while self._running:
            if not self._paused.wait(timeout=1.0):
                continue
            if not self._running:
                break

            interval = self._next_interval()
            deadline = time.monotonic() + interval
            while self._running and self._paused.is_set():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                time.sleep(min(remaining, 0.1))

            if not self._running:
                break
            if not self._paused.is_set():
                continue

            try:
                event = self._rng.choice(["heartbeat", "heartbeat", "typing"])
                with self._send_lock:
                    if event == "typing":
                        # Typing indicator: tiny payload, looks like chat activity
                        self._conn.send(MsgType.HEARTBEAT, b"typing_v1")
                    else:
                        self._conn.send(MsgType.PING, self._chaff_payload())
                    try:
                        self._conn.recv(timeout=1.0)
                    except (ConnectionError, ProtocolError, TimeoutError):
                        pass
            except (ConnectionError, OSError):
                self._running = False
                break


# -- Traffic Profiles ----------------------------------------------------------

class TrafficProfile(ABC):
    """Base class for traffic normalization profiles.

    A profile wraps outgoing frame data to mimic a specific application's
    traffic pattern (message structure, timing, headers).
    """

    @abstractmethod
    def wrap_outgoing(self, data: bytes) -> bytes:
        """Wrap Jump frame data to look like this profile's traffic."""
        ...

    @abstractmethod
    def unwrap_incoming(self, data: bytes) -> bytes:
        """Unwrap incoming data, extracting the Jump frame."""
        ...

    @property
    @abstractmethod
    def name(self) -> str:
        ...


class PlainProfile(TrafficProfile):
    """No-op profile: frames pass through unchanged."""

    def wrap_outgoing(self, data: bytes) -> bytes:
        return data

    def unwrap_incoming(self, data: bytes) -> bytes:
        return data

    @property
    def name(self) -> str:
        return "plain"


class _StatefulProfileBase(TrafficProfile):
    """Shared helpers for stateful, realistic chat-style profiles."""

    def __init__(self):
        import base64
        self._b64 = base64
        self._user_id = self._fake_user_id()
        self._session_id = secrets.token_hex(8)
        self._msg_id = 0
        self._last_ts = int(time.time() * 1000)

    @staticmethod
    def _fake_user_id() -> str:
        return f"U{secrets.token_hex(4).upper()}"

    def _next_id(self) -> int:
        self._msg_id += 1
        return self._msg_id

    def _next_ts(self) -> int:
        now = int(time.time() * 1000)
        if now <= self._last_ts:
            now = self._last_ts + 1
        self._last_ts = now
        return now

    def _encode_payload(self, data: bytes) -> str:
        return self._b64.b64encode(data).decode()

    def _decode_payload(self, value: str) -> bytes:
        return self._b64.b64decode(value)


class SlackProfile(_StatefulProfileBase):
    """Mimics Slack WebSocket/Events API message envelopes."""

    def __init__(self, channel: str = "general"):
        super().__init__()
        self._channel = channel

    def wrap_outgoing(self, data: bytes) -> bytes:
        envelope = {
            "type": "message",
            "channel": self._channel,
            "user": self._user_id,
            "client_msg_id": secrets.token_urlsafe(12),
            "text": "",
            "blocks": [
                {
                    "type": "section",
                    "block_id": secrets.token_hex(4),
                    "elements": [
                        {
                            "type": "mrkdwn",
                            "text": f"data:{self._encode_payload(data)}",
                        }
                    ],
                }
            ],
            "ts": str(self._next_ts()),
        }
        return json.dumps(envelope).encode()

    def unwrap_incoming(self, data: bytes) -> bytes:
        try:
            envelope = json.loads(data.decode())
            for block in envelope.get("blocks", []):
                for element in block.get("elements", []):
                    text = element.get("text", "")
                    if isinstance(text, str) and text.startswith("data:"):
                        return self._decode_payload(text[5:])
            return data
        except (json.JSONDecodeError, KeyError, UnicodeDecodeError):
            return data

    @property
    def name(self) -> str:
        return "slack"


class TeamsProfile(_StatefulProfileBase):
    """Mimics Microsoft Teams chat activity events."""

    def __init__(self, channel: str = "General"):
        super().__init__()
        self._channel = channel

    def wrap_outgoing(self, data: bytes) -> bytes:
        envelope = {
            "eventType": "msTeamsMessage",
            "from": {
                "id": self._user_id,
                "name": "User",
                "aadObjectId": secrets.token_hex(16),
            },
            "conversation": {
                "id": self._session_id,
                "name": self._channel,
            },
            "timestamp": self._next_ts(),
            "entities": [
                {
                    "type": "data",
                    "payload": self._encode_payload(data),
                }
            ],
        }
        return json.dumps(envelope).encode()

    def unwrap_incoming(self, data: bytes) -> bytes:
        try:
            envelope = json.loads(data.decode())
            for entity in envelope.get("entities", []):
                if entity.get("type") == "data":
                    return self._decode_payload(entity["payload"])
            return data
        except (json.JSONDecodeError, KeyError, UnicodeDecodeError):
            return data

    @property
    def name(self) -> str:
        return "teams"


class DiscordProfile(_StatefulProfileBase):
    """Mimics Discord gateway message events."""

    def __init__(self, channel_id: str = None):
        super().__init__()
        self._channel_id = channel_id or secrets.token_hex(8)

    def wrap_outgoing(self, data: bytes) -> bytes:
        envelope = {
            "op": 0,
            "s": self._next_id(),
            "t": "MESSAGE_CREATE",
            "d": {
                "id": secrets.token_hex(9),
                "channel_id": self._channel_id,
                "author": {"id": self._user_id, "username": "user"},
                "content": f"||{self._encode_payload(data)}||",
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()),
                "attachments": [],
            },
        }
        return json.dumps(envelope).encode()

    def unwrap_incoming(self, data: bytes) -> bytes:
        try:
            envelope = json.loads(data.decode())
            payload = envelope.get("d", {}).get("content", "")
            if isinstance(payload, str) and payload.startswith("||") and payload.endswith("||"):
                return self._decode_payload(payload[2:-2])
            return data
        except (json.JSONDecodeError, KeyError, UnicodeDecodeError):
            return data

    @property
    def name(self) -> str:
        return "discord"


class DoHProfile(TrafficProfile):
    """Mimics DNS-over-HTTPS query/response JSON (Cloudflare/Google style)."""

    def __init__(self):
        import base64
        self._b64 = base64

    def wrap_outgoing(self, data: bytes) -> bytes:
        envelope = {
            "Status": 0,
            "TC": False,
            "RD": True,
            "RA": True,
            "AD": False,
            "CD": False,
            "Question": [{"name": secrets.token_hex(8) + ".example.com", "type": 16}],
            "Answer": [
                {
                    "name": secrets.token_hex(8) + ".example.com",
                    "type": 16,
                    "TTL": 300,
                    "data": self._b64.b64encode(data).decode(),
                }
            ],
        }
        return json.dumps(envelope).encode()

    def unwrap_incoming(self, data: bytes) -> bytes:
        try:
            envelope = json.loads(data.decode())
            for ans in envelope.get("Answer", []):
                if ans.get("type") == 16:
                    return self._b64.b64decode(ans["data"])
            return data
        except (json.JSONDecodeError, KeyError, UnicodeDecodeError):
            return data

    @property
    def name(self) -> str:
        return "doh"


class GrpcProfile(TrafficProfile):
    """Mimics gRPC unary messages with length-prefixed protobuf-like framing."""

    def __init__(self, service: str = "events.Stream"):
        self._service = service

    def wrap_outgoing(self, data: bytes) -> bytes:
        # gRPC length-prefixed messages: compressed flag (1 byte) + length (4 bytes BE) + payload
        meta = json.dumps({"service": self._service, "method": "Send"}).encode()
        body = meta + b"\x00" + data
        frame = bytes([0]) + struct.pack(">I", len(body)) + body
        return frame

    def unwrap_incoming(self, data: bytes) -> bytes:
        if len(data) < 5 or data[0] != 0:
            return data
        length = struct.unpack(">I", data[1:5])[0]
        body = data[5:5 + length]
        if b"\x00" in body:
            _, payload = body.split(b"\x00", 1)
            return payload
        return data

    @property
    def name(self) -> str:
        return "grpc"


class CloudSyncProfile(TrafficProfile):
    """Makes traffic look like cloud file sync (Dropbox/OneDrive-style).

    Wraps each frame in a JSON envelope with typical sync API fields.
    The actual encrypted frame data goes in a base64-encoded 'payload' field.
    """

    def __init__(self):
        import base64
        self._b64 = base64

    def wrap_outgoing(self, data: bytes) -> bytes:
        envelope = {
            "type": "sync.chunk",
            "version": "2.1",
            "namespace": "default",
            "cursor": os.urandom(8).hex(),
            "payload": self._b64.b64encode(data).decode(),
            "ts": int(time.time() * 1000),
        }
        return json.dumps(envelope).encode()

    def unwrap_incoming(self, data: bytes) -> bytes:
        try:
            envelope = json.loads(data.decode())
            return self._b64.b64decode(envelope["payload"])
        except (json.JSONDecodeError, KeyError, UnicodeDecodeError):
            # Not wrapped — pass through as-is
            return data

    @property
    def name(self) -> str:
        return "cloud_sync"


class WebAPIProfile(TrafficProfile):
    """Makes traffic look like a generic REST/WebSocket API.

    Wraps frames in JSON with fields typical of real-time web APIs.
    """

    def __init__(self, channel: str = "general"):
        import base64
        self._b64 = base64
        self._channel = channel
        self._msg_id = 0

    def wrap_outgoing(self, data: bytes) -> bytes:
        self._msg_id += 1
        envelope = {
            "type": "message",
            "channel": self._channel,
            "id": self._msg_id,
            "ts": f"{int(time.time())}.{random.randint(100000, 999999)}",
            "blocks": [{
                "type": "rich_text",
                "elements": [{
                    "type": "data",
                    "value": self._b64.b64encode(data).decode(),
                }],
            }],
        }
        return json.dumps(envelope).encode()

    def unwrap_incoming(self, data: bytes) -> bytes:
        try:
            envelope = json.loads(data.decode())
            blocks = envelope.get("blocks", [])
            if blocks:
                elements = blocks[0].get("elements", [])
                if elements:
                    return self._b64.b64decode(elements[0]["value"])
            return data
        except (json.JSONDecodeError, KeyError, UnicodeDecodeError, IndexError):
            return data

    @property
    def name(self) -> str:
        return "web_api"


# == Normalized Connection =====================================================

class NormalizedConnection:
    """Wraps a JumpConnection with traffic normalization.

    Applies padding, timing jitter, and optional traffic profiling
    to make Jump protocol traffic indistinguishable from normal
    application traffic.

    Per-session polymorphism: the pad magic and bucket sizes are derived
    from a seed so that static signatures cannot identify Matrix traffic.

    Usage:
        conn = client_handshake(backend, "node-1")
        norm = NormalizedConnection(
            conn,
            jitter=TimingJitter(mean_ms=30),
            profile=CloudSyncProfile(),
            enable_cover_traffic=True,
        )
        norm.send(MsgType.SESSION_DATA, data)
    """

    def __init__(self, connection: JumpConnection,
                 jitter: Optional[TimingJitter] = None,
                 profile: Optional[TrafficProfile] = None,
                 enable_padding: bool = True,
                 enable_cover_traffic: bool = False,
                 polymorphic_seed: Optional[str] = None):
        self._conn = connection
        self._jitter = jitter or TimingJitter(enabled=False)
        self._profile = profile or PlainProfile()
        self._padding = enable_padding
        self._cover: Optional[CoverTrafficGenerator] = None
        self._send_lock = threading.Lock()

        # Polymorphic per-session parameters. Both sides must share the same
        # seed, which is normally derived from the session key material.
        if polymorphic_seed:
            self._pad_magic = secrets.token_bytes(4)  # not shared - must agree
            # Actually we need both sides to agree, so use a deterministic magic from seed.
            rng = random.Random(polymorphic_seed)
            self._pad_magic = bytes([rng.randint(0, 255) for _ in range(4)])
            self._buckets = _derive_buckets(polymorphic_seed)
        else:
            self._pad_magic = b"NPAD"
            self._buckets = PADDING_BUCKETS

        if enable_cover_traffic:
            self._cover = CoverTrafficGenerator(
                connection,
                send_lock=self._send_lock,
                seed=polymorphic_seed,
            )
            self._cover.start()

    @property
    def pad_magic(self) -> bytes:
        return self._pad_magic

    def send(self, msg_type: MsgType, payload: bytes):
        """Send with normalization applied."""
        # Pause cover traffic during active send
        if self._cover:
            self._cover.pause()

        try:
            # Apply traffic profile
            wrapped = self._profile.wrap_outgoing(payload)

            # Apply padding
            if self._padding:
                wrapped = self._pad_magic + struct.pack("!I", len(wrapped)) + wrapped
                wrapped = pad_frame(wrapped, self._buckets)

            # Encrypt and send under the shared lock so an in-flight chaff PING
            # can't interleave and corrupt the ratchet.
            with self._send_lock:
                self._conn.send(msg_type, wrapped)

            # Apply timing jitter
            self._jitter.delay()
        finally:
            if self._cover:
                self._cover.resume()

    def recv(self) -> Tuple[MsgType, bytes]:
        """Receive with denormalization."""
        msg_type, data = self._conn.recv()

        if self._padding and data.startswith(self._pad_magic) and len(data) >= 8:
            real_len = struct.unpack("!I", data[4:8])[0]
            available = len(data) - 8
            if 0 <= real_len <= available:
                data = strip_padding(data[8:], real_len)

        # Strip profile wrapping
        data = self._profile.unwrap_incoming(data)

        return msg_type, data

    def send_json(self, msg_type: MsgType, obj: dict):
        self.send(msg_type, json.dumps(obj).encode())

    def recv_json(self) -> Tuple[MsgType, dict]:
        msg_type, data = self.recv()
        return msg_type, json.loads(data.decode())

    def close(self):
        if self._cover:
            self._cover.stop()
        self._conn.close()

    @property
    def connection(self) -> JumpConnection:
        return self._conn

    @property
    def profile_name(self) -> str:
        return self._profile.name
