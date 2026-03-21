"""Tests for task_relay.py — Peer-to-peer task relay and routing."""

import json
import struct
import time
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from task_relay import (
    RelayEntry,
    RelayMessage,
    RelayTable,
    TaskRelay,
    RelayError,
)


# ── Helper: Mock JumpNode ─────────────────────────────────────────────────────

def _mock_node(name="local-node", targets=None):
    """Create a mock JumpNode with node_name and discover_targets()."""
    node = SimpleNamespace()
    node.node_name = name
    node.auth_token = None
    node.discovery = True
    node.discover_targets = lambda: targets or []
    return node


# ── RelayEntry ────────────────────────────────────────────────────────────────

class TestRelayEntry(unittest.TestCase):

    def test_creation(self):
        ts = time.time()
        entry = RelayEntry(
            destination_id="dest-1",
            next_hop_id="hop-1",
            hop_count=2,
            last_updated=ts,
            via_transport="ws",
        )
        self.assertEqual(entry.destination_id, "dest-1")
        self.assertEqual(entry.next_hop_id, "hop-1")
        self.assertEqual(entry.hop_count, 2)
        self.assertEqual(entry.last_updated, ts)
        self.assertEqual(entry.via_transport, "ws")

    def test_to_dict_from_dict_roundtrip(self):
        ts = 1700000000.0
        entry = RelayEntry(
            destination_id="D",
            next_hop_id="H",
            hop_count=3,
            last_updated=ts,
            via_transport="dead-drop",
        )
        d = entry.to_dict()
        restored = RelayEntry.from_dict(d)
        self.assertEqual(restored.destination_id, entry.destination_id)
        self.assertEqual(restored.next_hop_id, entry.next_hop_id)
        self.assertEqual(restored.hop_count, entry.hop_count)
        self.assertEqual(restored.last_updated, entry.last_updated)
        self.assertEqual(restored.via_transport, entry.via_transport)

    def test_from_dict_default_transport(self):
        d = {
            "destination_id": "X",
            "next_hop_id": "Y",
            "hop_count": 1,
            "last_updated": 0.0,
        }
        entry = RelayEntry.from_dict(d)
        self.assertEqual(entry.via_transport, "tcp")


# ── RelayMessage ──────────────────────────────────────────────────────────────

class TestRelayMessage(unittest.TestCase):

    def _make_msg(self, **overrides):
        defaults = dict(
            message_id="msg-001",
            source_id="src",
            destination_id="dst",
            payload_type="task",
            payload=b"hello",
            ttl=16,
            hop_path=["src"],
            timestamp=1700000000.0,
            signature=b"\x00" * 32,
        )
        defaults.update(overrides)
        return RelayMessage(**defaults)

    def test_creation(self):
        msg = self._make_msg()
        self.assertEqual(msg.message_id, "msg-001")
        self.assertEqual(msg.payload, b"hello")
        self.assertEqual(msg.ttl, 16)

    def test_to_dict_from_dict_roundtrip(self):
        msg = self._make_msg(payload=b"\xde\xad\xbe\xef", signature=b"\xab\xcd")
        d = msg.to_dict()
        restored = RelayMessage.from_dict(d)
        self.assertEqual(restored.message_id, msg.message_id)
        self.assertEqual(restored.source_id, msg.source_id)
        self.assertEqual(restored.destination_id, msg.destination_id)
        self.assertEqual(restored.payload_type, msg.payload_type)
        self.assertEqual(restored.payload, msg.payload)
        self.assertEqual(restored.ttl, msg.ttl)
        self.assertEqual(restored.hop_path, msg.hop_path)
        self.assertEqual(restored.timestamp, msg.timestamp)
        self.assertEqual(restored.signature, msg.signature)

    def test_signable_payload_deterministic(self):
        msg = self._make_msg()
        p1 = msg.signable_payload()
        p2 = msg.signable_payload()
        self.assertEqual(p1, p2)

    def test_signable_payload_contains_fields(self):
        msg = self._make_msg()
        payload = msg.signable_payload()
        self.assertIn(b"msg-001", payload)
        self.assertIn(b"src", payload)
        self.assertIn(b"dst", payload)
        self.assertIn(b"task", payload)
        self.assertIn(b"hello", payload)
        # TTL packed as unsigned int
        self.assertIn(struct.pack("!I", 16), payload)

    def test_signable_payload_changes_with_ttl(self):
        msg1 = self._make_msg(ttl=10)
        msg2 = self._make_msg(ttl=20)
        self.assertNotEqual(msg1.signable_payload(), msg2.signable_payload())


# ── RelayTable ────────────────────────────────────────────────────────────────

class TestRelayTable(unittest.TestCase):

    def setUp(self):
        self.table = RelayTable("local")

    def test_add_and_get_route(self):
        self.table.add_route("dest-A", "hop-1", 1)
        route = self.table.get_route("dest-A")
        self.assertIsNotNone(route)
        self.assertEqual(route.destination_id, "dest-A")
        self.assertEqual(route.next_hop_id, "hop-1")
        self.assertEqual(route.hop_count, 1)

    def test_get_route_returns_lowest_hop_count(self):
        self.table.add_route("dest-X", "hop-far", 5)
        self.table.add_route("dest-X", "hop-near", 2)
        self.table.add_route("dest-X", "hop-mid", 3)
        best = self.table.get_route("dest-X")
        self.assertEqual(best.next_hop_id, "hop-near")
        self.assertEqual(best.hop_count, 2)

    def test_get_all_routes(self):
        self.table.add_route("D", "h1", 3)
        self.table.add_route("D", "h2", 1)
        routes = self.table.get_all_routes("D")
        self.assertEqual(len(routes), 2)
        # Sorted by hop count
        self.assertEqual(routes[0].hop_count, 1)
        self.assertEqual(routes[1].hop_count, 3)

    def test_get_route_nonexistent(self):
        self.assertIsNone(self.table.get_route("no-such"))

    def test_remove_route(self):
        self.table.add_route("D", "H", 1)
        self.table.remove_route("D", "H")
        self.assertIsNone(self.table.get_route("D"))

    def test_remove_one_of_multiple_routes(self):
        self.table.add_route("D", "H1", 1)
        self.table.add_route("D", "H2", 2)
        self.table.remove_route("D", "H1")
        route = self.table.get_route("D")
        self.assertIsNotNone(route)
        self.assertEqual(route.next_hop_id, "H2")

    def test_merge_increments_hop_count(self):
        peer_entries = [
            RelayEntry("far-node", "peer-1", 2, time.time()),
        ]
        updated = self.table.merge("peer-1", peer_entries)
        self.assertEqual(updated, 1)
        route = self.table.get_route("far-node")
        self.assertIsNotNone(route)
        self.assertEqual(route.hop_count, 3)  # 2 + 1
        self.assertEqual(route.next_hop_id, "peer-1")

    def test_merge_skips_self(self):
        peer_entries = [
            RelayEntry("local", "peer-1", 1, time.time()),
        ]
        updated = self.table.merge("peer-1", peer_entries)
        self.assertEqual(updated, 0)
        self.assertIsNone(self.table.get_route("local"))

    def test_merge_does_not_replace_shorter_route(self):
        self.table.add_route("far", "direct", 1)
        peer_entries = [
            RelayEntry("far", "relay", 3, time.time()),
        ]
        updated = self.table.merge("relay", peer_entries)
        self.assertEqual(updated, 0)
        route = self.table.get_route("far")
        self.assertEqual(route.next_hop_id, "direct")
        self.assertEqual(route.hop_count, 1)

    def test_prune_removes_stale_entries(self):
        # Manually add a stale entry
        old_time = time.time() - 500
        entry = RelayEntry("old-dest", "hop", 1, old_time)
        self.table._routes["old-dest"] = [entry]
        self.table.add_route("fresh-dest", "hop2", 1)

        pruned = self.table.prune(max_age=100.0)
        self.assertEqual(pruned, 1)
        self.assertIsNone(self.table.get_route("old-dest"))
        self.assertIsNotNone(self.table.get_route("fresh-dest"))

    def test_to_entries(self):
        self.table.add_route("A", "h1", 1)
        self.table.add_route("B", "h2", 2)
        entries = self.table.to_entries()
        self.assertEqual(len(entries), 2)
        dests = {e.destination_id for e in entries}
        self.assertEqual(dests, {"A", "B"})

    def test_route_count(self):
        self.table.add_route("A", "h1", 1)
        self.table.add_route("A", "h2", 2)
        self.table.add_route("B", "h3", 1)
        self.assertEqual(self.table.route_count, 3)

    def test_destination_count(self):
        self.table.add_route("A", "h1", 1)
        self.table.add_route("A", "h2", 2)
        self.table.add_route("B", "h3", 1)
        self.assertEqual(self.table.destination_count, 2)

    def test_update_existing_route_via_same_hop(self):
        self.table.add_route("D", "H", 5)
        self.table.add_route("D", "H", 2)
        routes = self.table.get_all_routes("D")
        self.assertEqual(len(routes), 1)
        self.assertEqual(routes[0].hop_count, 2)


# ── TaskRelay ─────────────────────────────────────────────────────────────────

class TestTaskRelay(unittest.TestCase):

    def setUp(self):
        self.node = _mock_node("local-node")
        self.table = RelayTable("local-node")
        self.relay = TaskRelay(
            self.node,
            self.table,
            signing_key=b"test-key-32bytes" * 2,
            default_ttl=16,
        )

    def test_create_message(self):
        msg = self.relay.create_message("remote", "task", b"do-stuff")
        self.assertEqual(msg.source_id, "local-node")
        self.assertEqual(msg.destination_id, "remote")
        self.assertEqual(msg.payload_type, "task")
        self.assertEqual(msg.payload, b"do-stuff")
        self.assertEqual(msg.ttl, 16)
        self.assertEqual(msg.hop_path, [])
        self.assertTrue(len(msg.signature) > 0)

    def test_create_message_custom_ttl(self):
        msg = self.relay.create_message("r", "task", b"x", ttl=5)
        self.assertEqual(msg.ttl, 5)

    def test_handle_incoming_delivers_locally(self):
        delivered = []
        self.relay.register_handler("task", lambda m: delivered.append(m))

        msg = RelayMessage(
            message_id="msg-local",
            source_id="remote",
            destination_id="local-node",
            payload_type="task",
            payload=b"for-me",
            ttl=10,
            hop_path=["remote"],
            timestamp=time.time(),
        )
        self.relay.handle_incoming(msg)
        self.assertEqual(len(delivered), 1)
        self.assertEqual(delivered[0].payload, b"for-me")
        self.assertEqual(self.relay.stats["delivered"], 1)

    def test_handle_incoming_relays_when_destination_differs(self):
        self.table.add_route("far-node", "hop-1", 1)

        msg = RelayMessage(
            message_id="msg-relay",
            source_id="origin",
            destination_id="far-node",
            payload_type="task",
            payload=b"relay-me",
            ttl=10,
            hop_path=["origin"],
            timestamp=time.time(),
        )
        with patch.object(self.relay, "_forward_to_hop") as mock_fwd:
            self.relay.handle_incoming(msg)
            mock_fwd.assert_called_once()
            self.assertEqual(self.relay.stats["relayed"], 1)

    def test_duplicate_message_detection(self):
        msg = RelayMessage(
            message_id="dup-msg",
            source_id="remote",
            destination_id="local-node",
            payload_type="task",
            payload=b"data",
            ttl=10,
            hop_path=["remote"],
            timestamp=time.time(),
        )
        self.relay.handle_incoming(msg)
        # Send it again — should be dropped
        self.relay.handle_incoming(msg)
        self.assertEqual(self.relay.stats["delivered"], 1)
        self.assertEqual(self.relay.stats["dropped"], 1)

    def test_ttl_enforcement_drops_at_zero(self):
        self.table.add_route("far", "hop", 1)

        msg = RelayMessage(
            message_id="ttl-zero",
            source_id="origin",
            destination_id="far",
            payload_type="task",
            payload=b"expired",
            ttl=0,
            hop_path=["origin"],
            timestamp=time.time(),
        )
        self.relay.handle_incoming(msg)
        self.assertEqual(self.relay.stats["dropped"], 1)

    def test_loop_prevention_drops_when_local_in_hop_path(self):
        self.table.add_route("far", "hop", 1)

        msg = RelayMessage(
            message_id="loop-msg",
            source_id="origin",
            destination_id="far",
            payload_type="task",
            payload=b"loop",
            ttl=10,
            hop_path=["origin", "local-node"],  # already visited local-node
            timestamp=time.time(),
        )
        self.relay.handle_incoming(msg)
        self.assertEqual(self.relay.stats["dropped"], 1)

    def test_register_handler_and_dispatch(self):
        results = []
        self.relay.register_handler("custom", lambda m: results.append(m.payload))

        msg = RelayMessage(
            message_id="dispatch-test",
            source_id="peer",
            destination_id="local-node",
            payload_type="custom",
            payload=b"custom-data",
            ttl=5,
            hop_path=["peer"],
            timestamp=time.time(),
        )
        self.relay.handle_incoming(msg)
        self.assertEqual(results, [b"custom-data"])

    def test_no_handler_still_delivers(self):
        """Message with no registered handler is still counted as delivered."""
        msg = RelayMessage(
            message_id="no-handler",
            source_id="peer",
            destination_id="local-node",
            payload_type="unknown-type",
            payload=b"data",
            ttl=5,
            hop_path=["peer"],
            timestamp=time.time(),
        )
        self.relay.handle_incoming(msg)
        self.assertEqual(self.relay.stats["delivered"], 1)

    def test_handle_route_update_merges_routes(self):
        entries = [
            RelayEntry("far-1", "peer-x", 1, time.time()).to_dict(),
            RelayEntry("far-2", "peer-x", 3, time.time()).to_dict(),
        ]
        data = json.dumps(entries).encode()
        merged = self.relay.handle_route_update("peer-x", data)
        self.assertEqual(merged, 2)
        route1 = self.table.get_route("far-1")
        self.assertIsNotNone(route1)
        self.assertEqual(route1.hop_count, 2)  # 1 + 1

    def test_stats_tracking(self):
        # Initial stats
        stats = self.relay.stats
        self.assertEqual(stats["relayed"], 0)
        self.assertEqual(stats["delivered"], 0)
        self.assertEqual(stats["dropped"], 0)

    def test_stats_returns_copy(self):
        s1 = self.relay.stats
        s1["delivered"] = 999
        self.assertEqual(self.relay.stats["delivered"], 0)

    def test_relay_table_property(self):
        self.assertIs(self.relay.relay_table, self.table)


# ── Mock JumpNode Behavior ────────────────────────────────────────────────────

class TestMockJumpNode(unittest.TestCase):

    def test_mock_node_has_node_name(self):
        node = _mock_node("test-node")
        self.assertEqual(node.node_name, "test-node")

    def test_mock_node_discover_targets(self):
        target = SimpleNamespace(
            name="peer", device_id="p1", address="10.0.0.1", port=47701,
        )
        node = _mock_node("n", targets=[target])
        targets = node.discover_targets()
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0].name, "peer")

    def test_mock_node_discover_empty(self):
        node = _mock_node("n")
        self.assertEqual(node.discover_targets(), [])


if __name__ == "__main__":
    unittest.main()
