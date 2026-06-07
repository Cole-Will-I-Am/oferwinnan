"""Tests for matrix.multipath — PathHealth, MultiPathConnection."""

import time
import unittest
from unittest.mock import MagicMock, patch

from matrix.multipath import PathHealth, PathState, MultiPathConnection, PathSlot
from matrix.jump_protocol import MsgType, SessionKeys, TransportBackend


class TestPathHealth(unittest.TestCase):
    """Test PathHealth EWMA tracking and state transitions."""

    def test_initial_state(self):
        h = PathHealth(transport_name="tcp")
        self.assertEqual(h.state, PathState.HEALTHY)
        self.assertEqual(h.rtt_ewma, 0.0)
        self.assertEqual(h.rtt_samples, 0)
        self.assertEqual(h.missed_heartbeats, 0)

    def test_record_rtt_first_sample(self):
        h = PathHealth(transport_name="tcp")
        h.record_rtt(0.05)
        self.assertAlmostEqual(h.rtt_ewma, 0.05)
        self.assertEqual(h.rtt_samples, 1)
        self.assertEqual(h.state, PathState.HEALTHY)

    def test_record_rtt_ewma(self):
        h = PathHealth(transport_name="tcp")
        h.record_rtt(0.1)
        h.record_rtt(0.2)
        # EWMA: 0.3 * 0.2 + 0.7 * 0.1 = 0.13
        self.assertAlmostEqual(h.rtt_ewma, 0.13, places=5)

    def test_record_rtt_resets_missed_heartbeats(self):
        h = PathHealth(transport_name="tcp")
        h.missed_heartbeats = 5
        h.state = PathState.DEAD
        h.record_rtt(0.01)
        self.assertEqual(h.missed_heartbeats, 0)
        self.assertEqual(h.state, PathState.HEALTHY)

    def test_record_miss_degrades(self):
        h = PathHealth(transport_name="tcp")
        for _ in range(3):
            h.record_miss()
        self.assertEqual(h.state, PathState.DEGRADED)

    def test_record_miss_kills(self):
        h = PathHealth(transport_name="tcp")
        for _ in range(6):
            h.record_miss()
        self.assertEqual(h.state, PathState.DEAD)

    def test_weight_healthy(self):
        h = PathHealth(transport_name="tcp")
        h.record_rtt(0.01)
        self.assertGreater(h.weight, 0)

    def test_weight_dead_is_zero(self):
        h = PathHealth(transport_name="tcp")
        h.state = PathState.DEAD
        self.assertEqual(h.weight, 0.0)

    def test_weight_degraded_is_minimal(self):
        h = PathHealth(transport_name="tcp")
        h.state = PathState.DEGRADED
        self.assertAlmostEqual(h.weight, 0.1)

    def test_weight_zero_rtt(self):
        h = PathHealth(transport_name="tcp")
        # No samples, rtt_ewma = 0
        self.assertEqual(h.weight, 1.0)

    def test_record_bytes(self):
        h = PathHealth(transport_name="tcp")
        h.record_bytes(sent=100, recv=200)
        self.assertEqual(h.total_bytes_sent, 100)
        self.assertEqual(h.total_bytes_recv, 200)
        h.record_bytes(sent=50)
        self.assertEqual(h.total_bytes_sent, 150)


def _make_mock_backend(name="tcp", addr="127.0.0.1:1234", connected=True):
    backend = MagicMock(spec=TransportBackend)
    backend.transport_name = name
    backend.peer_address = addr
    backend.is_connected = connected
    return backend


def _make_mock_keys():
    keys = MagicMock(spec=SessionKeys)
    keys.encrypt = MagicMock(side_effect=lambda d: d)
    keys.decrypt = MagicMock(side_effect=lambda d: d)
    return keys


class TestMultiPathConnection(unittest.TestCase):
    """Test MultiPathConnection path management."""

    def test_add_and_remove_path(self):
        mp = MultiPathConnection()
        backend = _make_mock_backend()
        keys = _make_mock_keys()

        with patch("matrix.multipath.JumpConnection"):
            path_id = mp.add_path(backend, keys)

        self.assertEqual(mp.path_count, 1)
        self.assertIn(path_id, mp.healthy_paths)

        mp.remove_path(path_id)
        self.assertEqual(mp.path_count, 0)

    def test_remove_nonexistent_path(self):
        mp = MultiPathConnection()
        mp.remove_path("nonexistent")  # Should not raise

    def test_all_degraded_empty(self):
        mp = MultiPathConnection()
        self.assertTrue(mp.all_degraded)

    def test_all_degraded_with_healthy(self):
        mp = MultiPathConnection()
        backend = _make_mock_backend()
        keys = _make_mock_keys()

        with patch("matrix.multipath.JumpConnection"):
            mp.add_path(backend, keys)

        self.assertFalse(mp.all_degraded)

    def test_get_health(self):
        mp = MultiPathConnection()
        backend = _make_mock_backend()
        keys = _make_mock_keys()

        with patch("matrix.multipath.JumpConnection"):
            path_id = mp.add_path(backend, keys)

        health = mp.get_health()
        self.assertIn(path_id, health)
        self.assertEqual(health[path_id]["state"], "healthy")

    def test_send_chunk_no_paths(self):
        mp = MultiPathConnection()
        result = mp.send_chunk(MsgType.SESSION_DATA, b"test")
        self.assertFalse(result)

    def test_recv_chunk_no_paths_raises(self):
        mp = MultiPathConnection()
        with self.assertRaises(ConnectionError):
            mp.recv_chunk()

    def test_close_clears_paths(self):
        mp = MultiPathConnection()
        backend = _make_mock_backend()
        keys = _make_mock_keys()

        with patch("matrix.multipath.JumpConnection"):
            mp.add_path(backend, keys)

        mp.close()
        self.assertEqual(mp.path_count, 0)

    def test_send_json_and_recv_json(self):
        mp = MultiPathConnection()
        backend = _make_mock_backend()
        keys = _make_mock_keys()

        mock_conn = MagicMock()
        with patch("matrix.multipath.JumpConnection", return_value=mock_conn):
            mp.add_path(backend, keys)

        # send_json should encode to JSON and call send_chunk
        result = mp.send_json(MsgType.SESSION_DATA, {"key": "value"})
        # The mock connection's send was called
        self.assertTrue(result)

    def test_start_stop_monitoring(self):
        mp = MultiPathConnection()
        # Should not raise even with no paths
        mp.start_monitoring()
        mp.stop_monitoring()


if __name__ == "__main__":
    unittest.main()
