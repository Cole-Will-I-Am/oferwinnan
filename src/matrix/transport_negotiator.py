"""
Transport Negotiator — Probe, select, and normalize traffic across transports.

Phase 0 (Probe):   Parallel probes via TCP, WebSocket, HTTPS, DNS
Phase 1 (Select):  Choose the transport with lowest RTT that succeeded
Phase 2 (Connect): Full handshake over the selected transport

Also includes traffic normalization:
  - Frame padding to fixed size buckets (eliminates payload-size fingerprinting)
  - Timing jitter between frames (mimics interactive traffic)
  - Cover traffic (chaff heartbeats during idle periods)
  - Pluggable TrafficProfile classes for application-layer mimicry
"""

import json
import logging
import os
import random
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
                 dead_drop_config=None):
        self.host = host
        self.tcp_port = tcp_port
        self.ws_url = ws_url
        self.https_url = https_url
        self.dead_drop_config = dead_drop_config  # Optional[DeadDropConfig]

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

# Pad all frames to one of these bucket sizes to eliminate payload-size
# fingerprinting. The receiver strips padding using the length field
# already in the JMP frame header.
PADDING_BUCKETS = [128, 256, 512, 1024, 4096, 16384, 65536, 262144]


def pad_frame(data: bytes) -> bytes:
    """Pad frame data to the next bucket size.

    The original JMP frame header contains the real payload length,
    so the receiver can strip padding by reading only `length` bytes.
    Padding bytes are random to prevent pattern detection.
    """
    size = len(data)
    target = size
    for bucket in PADDING_BUCKETS:
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
    """Sends chaff PING/PONG frames at random intervals during idle periods.

    Prevents traffic analysis from identifying active vs idle connections.
    """

    def __init__(self, connection: JumpConnection,
                 min_interval: float = 1.0,
                 max_interval: float = 5.0):
        self._conn = connection
        self._min = min_interval
        self._max = max_interval
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._paused = threading.Event()
        self._paused.set()  # Not paused by default

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

    def _loop(self) -> None:
        while self._running:
            # Wait for unpause
            if not self._paused.wait(timeout=1.0):
                continue
            if not self._running:
                break

            interval = random.uniform(self._min, self._max)
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
                # Send chaff ping with random payload
                chaff = os.urandom(random.randint(16, 128))
                self._conn.send(MsgType.PING, chaff)
                # Read pong (or discard)
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
                 enable_cover_traffic: bool = False):
        self._conn = connection
        self._jitter = jitter or TimingJitter(enabled=False)
        self._profile = profile or PlainProfile()
        self._padding = enable_padding
        self._cover: Optional[CoverTrafficGenerator] = None

        if enable_cover_traffic:
            self._cover = CoverTrafficGenerator(connection)
            self._cover.start()

    _PAD_MAGIC = b"NPAD"

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
                wrapped = self._PAD_MAGIC + struct.pack("!I", len(wrapped)) + wrapped
                wrapped = pad_frame(wrapped)

            # Encrypt and send via the underlying connection
            self._conn.send(msg_type, wrapped)

            # Apply timing jitter
            self._jitter.delay()
        finally:
            if self._cover:
                self._cover.resume()

    def recv(self) -> Tuple[MsgType, bytes]:
        """Receive with denormalization."""
        msg_type, data = self._conn.recv()

        if self._padding and data.startswith(self._PAD_MAGIC) and len(data) >= 8:
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
