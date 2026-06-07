"""Tests for matrix.device_discovery — Device model, announce parsing, and discovery classes."""

import json
import struct
import time
import unittest
from unittest.mock import patch, MagicMock

from matrix.device_discovery import (
    Device, Transport, WiFiDiscovery, BluetoothDiscovery, DiscoveryManager,
    _build_announce, _parse_announce, MAGIC,
)


class TestDevice(unittest.TestCase):
    """Test Device dataclass."""

    def test_to_dict_and_from_dict_roundtrip(self):
        dev = Device(
            device_id="abc123",
            name="laptop",
            address="192.168.1.10",
            transport=Transport.WIFI,
            port=47701,
            last_seen=time.time(),
            capabilities=["jump", "file_transfer"],
            signal_strength=-50,
        )
        d = dev.to_dict()
        self.assertEqual(d["transport"], "wifi")
        self.assertIsInstance(d, dict)

        restored = Device.from_dict(d)
        self.assertEqual(restored.device_id, dev.device_id)
        self.assertEqual(restored.name, dev.name)
        self.assertEqual(restored.transport, Transport.WIFI)
        self.assertEqual(restored.port, dev.port)

    def test_is_stale(self):
        dev = Device(
            device_id="test",
            name="test",
            address="127.0.0.1",
            transport=Transport.WIFI,
            last_seen=time.time() - 9999,
        )
        self.assertTrue(dev.is_stale)

        dev2 = Device(
            device_id="test2",
            name="test2",
            address="127.0.0.1",
            transport=Transport.WIFI,
            last_seen=time.time(),
        )
        self.assertFalse(dev2.is_stale)

    def test_bluetooth_transport(self):
        dev = Device(
            device_id="bt1",
            name="phone",
            address="AA:BB:CC:DD:EE:FF",
            transport=Transport.BLUETOOTH,
        )
        d = dev.to_dict()
        self.assertEqual(d["transport"], "bluetooth")
        restored = Device.from_dict(d)
        self.assertEqual(restored.transport, Transport.BLUETOOTH)


class TestAnnounceProtocol(unittest.TestCase):
    """Test announce message building and parsing."""

    def test_build_and_parse_roundtrip(self):
        msg = _build_announce("node-1", "my-laptop", 47701, ["jump"])
        result = _parse_announce(msg)
        self.assertIsNotNone(result)
        self.assertEqual(result["id"], "node-1")
        self.assertEqual(result["name"], "my-laptop")
        self.assertEqual(result["port"], 47701)
        self.assertEqual(result["caps"], ["jump"])

    def test_parse_invalid_magic(self):
        self.assertIsNone(_parse_announce(b"BAAD" + b"\x00" * 20))

    def test_parse_truncated(self):
        self.assertIsNone(_parse_announce(MAGIC + b"\x00"))

    def test_parse_invalid_json(self):
        bad_payload = b"not json"
        data = MAGIC + struct.pack("!H", len(bad_payload)) + bad_payload
        self.assertIsNone(_parse_announce(data))

    def test_parse_empty_data(self):
        self.assertIsNone(_parse_announce(b""))

    def test_build_announce_structure(self):
        msg = _build_announce("id", "name", 1234, [])
        self.assertTrue(msg.startswith(MAGIC))
        length = struct.unpack("!H", msg[4:6])[0]
        payload = json.loads(msg[6:6 + length].decode())
        self.assertEqual(payload["id"], "id")


class TestWiFiDiscovery(unittest.TestCase):
    """Test WiFiDiscovery without actual network."""

    def test_get_devices_returns_empty_initially(self):
        wifi = WiFiDiscovery("node-1", "test", 47701)
        self.assertEqual(wifi.get_devices(), [])

    def test_get_devices_filters_stale(self):
        wifi = WiFiDiscovery("node-1", "test", 47701)
        # Manually inject a stale device
        wifi.devices["old"] = Device(
            device_id="old",
            name="old-device",
            address="10.0.0.1",
            transport=Transport.WIFI,
            last_seen=time.time() - 9999,
        )
        wifi.devices["fresh"] = Device(
            device_id="fresh",
            name="fresh-device",
            address="10.0.0.2",
            transport=Transport.WIFI,
            last_seen=time.time(),
        )
        devices = wifi.get_devices()
        self.assertEqual(len(devices), 1)
        self.assertEqual(devices[0].device_id, "fresh")

    def test_start_stop_no_crash(self):
        wifi = WiFiDiscovery("node-1", "test", 0)
        # start/stop should not raise even if binding fails
        wifi.start()
        wifi.stop()


class TestBluetoothDiscovery(unittest.TestCase):
    """Test BluetoothDiscovery stub behavior."""

    def test_no_bluetooth_returns_empty(self):
        bt = BluetoothDiscovery("node-1")
        # Without PyBluez, _has_bluetooth should be False
        if not bt._has_bluetooth:
            devices = bt._do_scan()
            self.assertEqual(devices, [])

    def test_get_devices_empty_initially(self):
        bt = BluetoothDiscovery("node-1")
        self.assertEqual(bt.get_devices(), [])


class TestDiscoveryManager(unittest.TestCase):
    """Test the unified DiscoveryManager."""

    def test_init_defaults(self):
        mgr = DiscoveryManager(node_name="test-node", listen_port=47701)
        self.assertEqual(mgr.node_name, "test-node")
        self.assertEqual(mgr.listen_port, 47701)
        self.assertIsNotNone(mgr.wifi)
        self.assertIsNotNone(mgr.bluetooth)

    def test_get_all_devices_deduplicates(self):
        mgr = DiscoveryManager(node_name="test", listen_port=0)
        now = time.time()
        dev1 = Device("dup", "d1", "10.0.0.1", Transport.WIFI, last_seen=now - 1)
        dev2 = Device("dup", "d2", "10.0.0.1", Transport.BLUETOOTH, last_seen=now)
        mgr.wifi.devices["dup"] = dev1
        mgr.bluetooth.devices["dup"] = dev2
        all_devs = mgr.get_all_devices()
        self.assertEqual(len(all_devs), 1)
        # Should keep the one with the latest last_seen
        self.assertEqual(all_devs[0].name, "d2")

    def test_get_all_devices_sorted_by_recency(self):
        mgr = DiscoveryManager(node_name="test", listen_port=0)
        now = time.time()
        mgr.wifi.devices["a"] = Device("a", "older", "10.0.0.1", Transport.WIFI, last_seen=now - 10)
        mgr.wifi.devices["b"] = Device("b", "newer", "10.0.0.2", Transport.WIFI, last_seen=now)
        devs = mgr.get_all_devices()
        self.assertEqual(devs[0].device_id, "b")


if __name__ == "__main__":
    unittest.main()
