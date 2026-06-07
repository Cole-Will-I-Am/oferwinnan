"""Packaging/runtime import regression tests."""

import unittest

from matrix.data_sync import SyncManager, SyncManifest
from matrix.rbac import RBACManager
from matrix.session_jumper import JumpNode
from matrix.transport_negotiator import _probe_websocket


class _NoopConn:
    """Connection stub for sync paths that do not perform I/O."""


class TestPackagingImports(unittest.TestCase):
    def test_jumpnode_rbac_import_path(self):
        node = JumpNode(listen_port=0, rbac_manager=RBACManager())
        self.assertIsNotNone(node.listener)

    def test_data_sync_import_path(self):
        sync = SyncManager()
        empty_peer = SyncManifest().serialize()
        result = sync.sync_with_peer(_NoopConn(), peer_manifest_data=empty_peer)
        self.assertEqual(result.failed_keys, [])

    def test_websocket_probe_import_path(self):
        result = _probe_websocket("ws://127.0.0.1:1", timeout=0.05)
        self.assertFalse(result.success)
        self.assertNotIn("No module named 'transport_ws'", str(result.error))


if __name__ == "__main__":
    unittest.main()
