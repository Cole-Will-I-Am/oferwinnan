"""Tests for data_sync.py — Manifest-based delta synchronization."""

import hashlib
import json
import time
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from matrix.data_sync import (
    SyncEntry,
    SyncResult,
    SyncManifest,
    RateLimiter,
    DeliveryTracker,
    SyncManager,
    SyncError,
    SYNC_CHUNK_SIZE,
)


# ── SyncEntry ─────────────────────────────────────────────────────────────────

class TestSyncEntry(unittest.TestCase):

    def test_creation(self):
        ts = time.time()
        entry = SyncEntry(
            key="config.json",
            checksum="abc123",
            size=1024,
            version=1,
            last_modified=ts,
            source_node_id="node-A",
        )
        self.assertEqual(entry.key, "config.json")
        self.assertEqual(entry.checksum, "abc123")
        self.assertEqual(entry.size, 1024)
        self.assertEqual(entry.version, 1)
        self.assertEqual(entry.last_modified, ts)
        self.assertEqual(entry.source_node_id, "node-A")

    def test_to_dict_from_dict_roundtrip(self):
        ts = 1700000000.0
        entry = SyncEntry(
            key="data.bin",
            checksum="deadbeef",
            size=512,
            version=3,
            last_modified=ts,
            source_node_id="node-B",
        )
        d = entry.to_dict()
        restored = SyncEntry.from_dict(d)
        self.assertEqual(restored.key, entry.key)
        self.assertEqual(restored.checksum, entry.checksum)
        self.assertEqual(restored.size, entry.size)
        self.assertEqual(restored.version, entry.version)
        self.assertEqual(restored.last_modified, entry.last_modified)
        self.assertEqual(restored.source_node_id, entry.source_node_id)

    def test_to_dict_contains_all_fields(self):
        entry = SyncEntry("k", "cs", 10, 1, 0.0, "n")
        d = entry.to_dict()
        expected_keys = {"key", "checksum", "size", "version", "last_modified", "source_node_id"}
        self.assertEqual(set(d.keys()), expected_keys)


# ── SyncResult ────────────────────────────────────────────────────────────────

class TestSyncResult(unittest.TestCase):

    def test_defaults(self):
        r = SyncResult()
        self.assertEqual(r.synced_keys, [])
        self.assertEqual(r.failed_keys, [])
        self.assertEqual(r.bytes_sent, 0)
        self.assertEqual(r.bytes_received, 0)
        self.assertEqual(r.elapsed, 0.0)

    def test_to_dict(self):
        r = SyncResult(
            synced_keys=["a", "b"],
            failed_keys=["c"],
            bytes_sent=100,
            bytes_received=200,
            elapsed=1.5,
        )
        d = r.to_dict()
        self.assertEqual(d["synced_keys"], ["a", "b"])
        self.assertEqual(d["failed_keys"], ["c"])
        self.assertEqual(d["bytes_sent"], 100)
        self.assertEqual(d["bytes_received"], 200)
        self.assertEqual(d["elapsed"], 1.5)


# ── SyncManifest ──────────────────────────────────────────────────────────────

class TestSyncManifest(unittest.TestCase):

    def setUp(self):
        self.manifest = SyncManifest(node_id="test-node")

    def test_add_and_get(self):
        entry = self.manifest.add("key1", b"hello")
        self.assertEqual(entry.key, "key1")
        self.assertEqual(entry.size, 5)
        self.assertEqual(entry.version, 1)
        self.assertEqual(entry.checksum, hashlib.sha256(b"hello").hexdigest())
        retrieved = self.manifest.get("key1")
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.key, "key1")

    def test_add_increments_version(self):
        self.manifest.add("k", b"v1")
        entry2 = self.manifest.add("k", b"v2")
        self.assertEqual(entry2.version, 2)

    def test_remove(self):
        self.manifest.add("k", b"data")
        self.manifest.remove("k")
        self.assertIsNone(self.manifest.get("k"))

    def test_remove_nonexistent_is_noop(self):
        self.manifest.remove("no-such-key")  # Should not raise

    def test_keys(self):
        self.manifest.add("alpha", b"a")
        self.manifest.add("beta", b"b")
        self.manifest.add("gamma", b"c")
        keys = self.manifest.keys()
        self.assertEqual(set(keys), {"alpha", "beta", "gamma"})

    def test_entry_count(self):
        self.assertEqual(self.manifest.entry_count, 0)
        self.manifest.add("a", b"1")
        self.manifest.add("b", b"2")
        self.assertEqual(self.manifest.entry_count, 2)

    def test_diff_missing_locally(self):
        local = SyncManifest("local")
        remote = SyncManifest("remote")
        remote.add("only-remote", b"data")

        missing_locally, missing_remotely, modified = local.diff(remote)
        self.assertIn("only-remote", missing_locally)
        self.assertEqual(missing_remotely, [])
        self.assertEqual(modified, [])

    def test_diff_missing_remotely(self):
        local = SyncManifest("local")
        remote = SyncManifest("remote")
        local.add("only-local", b"data")

        missing_locally, missing_remotely, modified = local.diff(remote)
        self.assertEqual(missing_locally, [])
        self.assertIn("only-local", missing_remotely)
        self.assertEqual(modified, [])

    def test_diff_modified(self):
        local = SyncManifest("local")
        remote = SyncManifest("remote")
        local.add("shared", b"version-1")
        # Remote has different data and higher version
        remote.add("shared", b"version-1")  # v1
        remote.add("shared", b"version-2")  # v2

        missing_locally, missing_remotely, modified = local.diff(remote)
        self.assertEqual(missing_locally, [])
        self.assertEqual(missing_remotely, [])
        self.assertIn("shared", modified)

    def test_diff_same_data_not_modified(self):
        local = SyncManifest("local")
        remote = SyncManifest("remote")
        local.add("same", b"identical")
        remote.add("same", b"identical")

        missing_locally, missing_remotely, modified = local.diff(remote)
        self.assertEqual(modified, [])

    def test_serialize_deserialize_roundtrip(self):
        self.manifest.add("file1", b"content-1")
        self.manifest.add("file2", b"content-2")

        data = self.manifest.serialize()
        restored = SyncManifest.deserialize(data)

        self.assertEqual(restored.entry_count, 2)
        self.assertEqual(set(restored.keys()), {"file1", "file2"})
        e1 = restored.get("file1")
        self.assertEqual(e1.checksum, hashlib.sha256(b"content-1").hexdigest())

    def test_serialize_produces_valid_json(self):
        self.manifest.add("k", b"v")
        data = self.manifest.serialize()
        parsed = json.loads(data.decode())
        self.assertIn("node_id", parsed)
        self.assertIn("entries", parsed)
        self.assertIn("timestamp", parsed)
        self.assertEqual(parsed["node_id"], "test-node")


# ── RateLimiter ───────────────────────────────────────────────────────────────

class TestRateLimiter(unittest.TestCase):

    def test_acquire_small_amount_immediate(self):
        # 10 KB/s with burst of 20 KB should allow immediate acquire of 1 byte
        limiter = RateLimiter(bytes_per_sec=10_000, burst_size=20_000)
        start = time.time()
        limiter.acquire(1)
        elapsed = time.time() - start
        self.assertLess(elapsed, 0.1)

    def test_acquire_blocks_when_tokens_exhausted(self):
        # Very small rate: 10 bytes/sec, burst 10
        limiter = RateLimiter(bytes_per_sec=10, burst_size=10)
        # Drain the bucket
        limiter.acquire(10)
        # Next acquire should block briefly
        start = time.time()
        limiter.acquire(1)
        elapsed = time.time() - start
        self.assertGreater(elapsed, 0.05)

    def test_set_rate_dynamically(self):
        limiter = RateLimiter(bytes_per_sec=100)
        self.assertEqual(limiter.rate, 100)
        limiter.set_rate(5000)
        self.assertEqual(limiter.rate, 5000)

    def test_rate_property(self):
        limiter = RateLimiter(bytes_per_sec=42)
        self.assertEqual(limiter.rate, 42)


# ── DeliveryTracker ───────────────────────────────────────────────────────────

class TestDeliveryTracker(unittest.TestCase):

    def setUp(self):
        self.tracker = DeliveryTracker()

    def test_track_and_confirm_matching_hash(self):
        self.tracker.track("chunk-1", "abc123")
        result = self.tracker.confirm("chunk-1", "abc123")
        self.assertTrue(result)

    def test_confirm_mismatched_hash_returns_false(self):
        self.tracker.track("chunk-2", "correct-hash")
        result = self.tracker.confirm("chunk-2", "wrong-hash")
        self.assertFalse(result)

    def test_confirm_unknown_chunk_returns_false(self):
        result = self.tracker.confirm("no-such-chunk", "hash")
        self.assertFalse(result)

    def test_get_unconfirmed(self):
        self.tracker.track("c1", "h1")
        self.tracker.track("c2", "h2")
        self.tracker.confirm("c1", "h1")
        # Manually set sent_at to the past to make c2 old enough
        self.tracker._pending["c2"].sent_at = time.time() - 60

        unconfirmed = self.tracker.get_unconfirmed(max_age=5.0)
        self.assertIn("c2", unconfirmed)
        self.assertNotIn("c1", unconfirmed)

    def test_get_unconfirmed_ignores_recent(self):
        self.tracker.track("recent", "h")
        unconfirmed = self.tracker.get_unconfirmed(max_age=30.0)
        self.assertEqual(unconfirmed, [])

    def test_record_retry_increments_count(self):
        self.tracker.track("c1", "h")
        self.assertEqual(self.tracker.retry_count("c1"), 0)
        self.tracker.record_retry("c1")
        self.assertEqual(self.tracker.retry_count("c1"), 1)
        self.tracker.record_retry("c1")
        self.assertEqual(self.tracker.retry_count("c1"), 2)

    def test_clear_confirmed_removes_confirmed_records(self):
        self.tracker.track("c1", "h1")
        self.tracker.track("c2", "h2")
        self.tracker.track("c3", "h3")
        self.tracker.confirm("c1", "h1")
        self.tracker.confirm("c3", "h3")

        removed = self.tracker.clear_confirmed()
        self.assertEqual(removed, 2)
        # c2 should still be pending
        self.assertEqual(self.tracker.pending_count, 1)

    def test_pending_count(self):
        self.tracker.track("a", "ha")
        self.tracker.track("b", "hb")
        self.assertEqual(self.tracker.pending_count, 2)
        self.tracker.confirm("a", "ha")
        self.assertEqual(self.tracker.pending_count, 1)

    def test_retry_count_unknown_returns_zero(self):
        self.assertEqual(self.tracker.retry_count("nonexistent"), 0)

    def test_record_retry_on_unknown_is_noop(self):
        self.tracker.record_retry("nonexistent")  # Should not raise


# ── SyncManager ───────────────────────────────────────────────────────────────

class TestSyncManager(unittest.TestCase):

    def setUp(self):
        self.node = SimpleNamespace(node_name="mgr-node")
        self.manager = SyncManager(node=self.node, node_id="mgr-node")

    def test_add_data(self):
        entry = self.manager.add_data("key1", b"value1")
        self.assertEqual(entry.key, "key1")
        self.assertEqual(entry.size, 6)

    def test_get_data(self):
        self.manager.add_data("k", b"hello")
        self.assertEqual(self.manager.get_data("k"), b"hello")

    def test_get_data_nonexistent(self):
        self.assertIsNone(self.manager.get_data("nonexistent"))

    def test_remove_data(self):
        self.manager.add_data("k", b"data")
        self.manager.remove_data("k")
        self.assertIsNone(self.manager.get_data("k"))
        self.assertIsNone(self.manager.manifest.get("k"))

    def test_remove_data_nonexistent(self):
        self.manager.remove_data("no-such")  # Should not raise

    def test_list_keys(self):
        self.manager.add_data("a", b"1")
        self.manager.add_data("b", b"2")
        self.manager.add_data("c", b"3")
        keys = self.manager.list_keys()
        self.assertEqual(set(keys), {"a", "b", "c"})

    def test_list_keys_empty(self):
        self.assertEqual(self.manager.list_keys(), [])

    def test_manifest_updated_when_data_added(self):
        self.assertEqual(self.manager.manifest.entry_count, 0)
        self.manager.add_data("file.txt", b"content")
        self.assertEqual(self.manager.manifest.entry_count, 1)
        entry = self.manager.manifest.get("file.txt")
        self.assertIsNotNone(entry)
        self.assertEqual(entry.checksum, hashlib.sha256(b"content").hexdigest())

    def test_manifest_updated_on_overwrite(self):
        self.manager.add_data("k", b"v1")
        self.manager.add_data("k", b"v2")
        entry = self.manager.manifest.get("k")
        self.assertEqual(entry.version, 2)
        self.assertEqual(entry.checksum, hashlib.sha256(b"v2").hexdigest())

    def test_manifest_property(self):
        self.assertIsInstance(self.manager.manifest, SyncManifest)

    def test_tracker_property(self):
        self.assertIsInstance(self.manager.tracker, DeliveryTracker)

    def test_manager_without_node(self):
        mgr = SyncManager(node_id="standalone")
        entry = mgr.add_data("k", b"data")
        self.assertEqual(entry.key, "k")
        self.assertEqual(mgr.get_data("k"), b"data")


# ── SYNC_CHUNK_SIZE Constant ─────────────────────────────────────────────────

class TestSyncChunkSize(unittest.TestCase):

    def test_matches_jump_protocol(self):
        self.assertEqual(SYNC_CHUNK_SIZE, 64 * 1024)

    def test_is_positive_integer(self):
        self.assertIsInstance(SYNC_CHUNK_SIZE, int)
        self.assertGreater(SYNC_CHUNK_SIZE, 0)


if __name__ == "__main__":
    unittest.main()
