"""Tests for new end-to-end Director tools: discovery, remote task, persistence, disguise, transport profile, probe."""

import time
import unittest
from unittest.mock import MagicMock

from matrix.director import ToolExecutor, LLMToolCall
from matrix.device_discovery import Device, Transport
from matrix.persistence import PersistResult


class MockNode:
    def __init__(self):
        self.discovery = MagicMock()
        self.discovery.node_id = "node-a"
        self.discovery.discover_targets.return_value = [
            Device(
                device_id="node-b",
                name="node-b",
                address="127.0.0.1",
                transport=Transport.WIFI,
                port=47701,
                last_seen=time.time(),
            )
        ]


class TestDiscoverDevices(unittest.TestCase):
    def test_returns_device_list(self):
        executor = ToolExecutor(node=MockNode())
        tc = LLMToolCall(tool_name="discover_devices", arguments={"timeout": 0})
        result = executor.execute(tc)
        self.assertTrue(result.success)
        self.assertEqual(result.result["count"], 1)
        self.assertEqual(result.result["devices"][0]["id"], "node-b")


class TestProbeTransport(unittest.TestCase):
    def test_returns_probe_result_shape(self):
        executor = ToolExecutor()
        tc = LLMToolCall(tool_name="probe_transport", arguments={"host": "127.0.0.1", "tcp_port": 22})
        result = executor.execute(tc)
        # probe will likely fail; check shape
        self.assertIn("transport", result.result or {})


class TestApplyDisguise(unittest.TestCase):
    def test_applies_title(self):
        executor = ToolExecutor()
        tc = LLMToolCall(tool_name="apply_disguise", arguments={"title": "/usr/lib/foo/bar"})
        result = executor.execute(tc)
        self.assertTrue(result.success)
        self.assertTrue(result.result["applied"])


class TestSetTransportProfile(unittest.TestCase):
    def test_sets_profile(self):
        node = MockNode()
        executor = ToolExecutor(node=node)
        tc = LLMToolCall(tool_name="set_transport_profile", arguments={"profile": "slack"})
        result = executor.execute(tc)
        self.assertTrue(result.success)
        self.assertEqual(node._director_profile, "slack")

    def test_rejects_unknown_profile(self):
        node = MockNode()
        executor = ToolExecutor(node=node)
        tc = LLMToolCall(tool_name="set_transport_profile", arguments={"profile": "unknown"})
        result = executor.execute(tc)
        self.assertFalse(result.success)


if __name__ == "__main__":
    unittest.main()
