"""
Device Discovery Module — Bluetooth and WiFi scanner for cross-device jumping.

Discovers nearby devices on the local network (WiFi) and via Bluetooth,
returning a unified list of reachable jump targets.
"""

import hashlib
import json
import socket
import struct
import threading
import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional

STALE_TIMEOUT_SECONDS = 30.0
ANNOUNCE_INTERVAL = 5
BT_SCAN_DURATION = 4


class Transport(Enum):
    WIFI = "wifi"
    BLUETOOTH = "bluetooth"


@dataclass
class Device:
    device_id: str
    name: str
    address: str
    transport: Transport
    port: int = 0
    last_seen: float = 0.0
    capabilities: list = field(default_factory=list)
    signal_strength: int = 0

    def to_dict(self):
        d = asdict(self)
        d["transport"] = self.transport.value
        return d

    @classmethod
    def from_dict(cls, d):
        d = dict(d)
        d["transport"] = Transport(d["transport"])
        return cls(**d)

    @property
    def is_stale(self):
        return (time.time() - self.last_seen) > STALE_TIMEOUT_SECONDS


# ── WiFi Discovery (UDP Broadcast) ──────────────────────────────────────────

MULTICAST_GROUP = "239.255.77.88"
DISCOVERY_PORT = 47700
MAGIC = b"JUMP"


def _build_announce(node_id: str, node_name: str, listen_port: int,
                    capabilities: list) -> bytes:
    payload = json.dumps({
        "id": node_id,
        "name": node_name,
        "port": listen_port,
        "caps": capabilities,
    }).encode()
    return MAGIC + struct.pack("!H", len(payload)) + payload


def _parse_announce(data: bytes) -> Optional[dict]:
    if not data.startswith(MAGIC):
        return None
    if len(data) < 6:
        return None
    length = struct.unpack("!H", data[4:6])[0]
    payload = data[6:6 + length]
    try:
        return json.loads(payload.decode())
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None


class WiFiDiscovery:
    """Discovers peers on the LAN using UDP multicast announcements."""

    def __init__(self, node_id: str, node_name: str, listen_port: int,
                 capabilities: list = None):
        self.node_id = node_id
        self.node_name = node_name
        self.listen_port = listen_port
        self.capabilities = capabilities or ["jump", "file_transfer"]
        self.devices: dict[str, Device] = {}
        self._lock = threading.Lock()
        self._running = False
        self._threads: list[threading.Thread] = []

    def start(self):
        self._running = True
        t_listen = threading.Thread(target=self._listen_loop, daemon=True)
        t_announce = threading.Thread(target=self._announce_loop, daemon=True)
        self._threads = [t_listen, t_announce]
        for t in self._threads:
            t.start()

    def stop(self):
        self._running = False
        for t in self._threads:
            t.join(timeout=2)

    def get_devices(self) -> list[Device]:
        with self._lock:
            return [d for d in self.devices.values() if not d.is_stale]

    def _announce_loop(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.settimeout(1.0)
        msg = _build_announce(self.node_id, self.node_name, self.listen_port,
                              self.capabilities)
        while self._running:
            try:
                sock.sendto(msg, (MULTICAST_GROUP, DISCOVERY_PORT))
            except OSError:
                pass
            time.sleep(ANNOUNCE_INTERVAL)
        sock.close()

    def _listen_loop(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("", DISCOVERY_PORT))
        except OSError:
            return
        group = socket.inet_aton(MULTICAST_GROUP)
        mreq = struct.pack("4sL", group, socket.INADDR_ANY)
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        except OSError:
            pass
        sock.settimeout(2.0)
        while self._running:
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            info = _parse_announce(data)
            if info is None or info.get("id") == self.node_id:
                continue
            device = Device(
                device_id=info["id"],
                name=info.get("name", "unknown"),
                address=addr[0],
                transport=Transport.WIFI,
                port=info.get("port", 0),
                last_seen=time.time(),
                capabilities=info.get("caps", []),
            )
            with self._lock:
                self.devices[device.device_id] = device
        sock.close()


# ── Bluetooth Discovery (simulated / real via PyBluez when available) ────────

class BluetoothDiscovery:
    """Discovers nearby Bluetooth devices.

    Uses PyBluez if available; otherwise falls back to a stub that returns
    an empty list (useful for testing or environments without Bluetooth).
    """

    def __init__(self, node_id: str):
        self.node_id = node_id
        self.devices: dict[str, Device] = {}
        self._lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._has_bluetooth = self._check_bluetooth()

    @staticmethod
    def _check_bluetooth() -> bool:
        try:
            import bluetooth  # noqa: F401
            return True
        except ImportError:
            return False

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._scan_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=10)

    def get_devices(self) -> list[Device]:
        with self._lock:
            return [d for d in self.devices.values() if not d.is_stale]

    def _scan_loop(self):
        while self._running:
            found = self._do_scan()
            with self._lock:
                for dev in found:
                    self.devices[dev.device_id] = dev
            # Bluetooth scans are slow; wait between scans
            for _ in range(100):
                if not self._running:
                    return
                time.sleep(0.1)

    def _do_scan(self) -> list[Device]:
        if not self._has_bluetooth:
            return []
        try:
            import bluetooth
            nearby = bluetooth.discover_devices(duration=BT_SCAN_DURATION, lookup_names=True,
                                                lookup_class=False, flush_cache=True)
            results = []
            for addr, name in nearby:
                dev_id = hashlib.sha256(addr.encode()).hexdigest()[:16]
                results.append(Device(
                    device_id=dev_id,
                    name=name or addr,
                    address=addr,
                    transport=Transport.BLUETOOTH,
                    last_seen=time.time(),
                    capabilities=["jump"],
                ))
            return results
        except Exception:
            return []


# ── Unified Discovery Manager ───────────────────────────────────────────────

class DiscoveryManager:
    """Runs WiFi and Bluetooth discovery together, providing a unified device list."""

    def __init__(self, node_name: str = None, listen_port: int = 47701,
                 capabilities: list = None):
        self.node_id = uuid.uuid4().hex[:16]
        self.node_name = node_name or socket.gethostname()
        self.listen_port = listen_port
        self.capabilities = capabilities or ["jump", "file_transfer"]
        self.wifi = WiFiDiscovery(self.node_id, self.node_name,
                                  self.listen_port, self.capabilities)
        self.bluetooth = BluetoothDiscovery(self.node_id)

    def start(self):
        self.wifi.start()
        self.bluetooth.start()

    def stop(self):
        self.wifi.stop()
        self.bluetooth.stop()

    def get_all_devices(self) -> list[Device]:
        seen = {}
        for dev in self.wifi.get_devices() + self.bluetooth.get_devices():
            if dev.device_id not in seen or dev.last_seen > seen[dev.device_id].last_seen:
                seen[dev.device_id] = dev
        return sorted(seen.values(), key=lambda d: d.last_seen, reverse=True)
