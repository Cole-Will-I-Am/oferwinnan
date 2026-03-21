"""Tests for secure_terminate.py — Cryptographic termination and state wipe."""

import os
import struct
import threading
import time
import unittest

from secure_terminate import (
    TerminationCommand,
    TerminationAuditEntry,
    SecureTerminator,
    TerminationError,
    _NonceTracker,
)


# ── Mock JumpNode ─────────────────────────────────────────────────────────────

class _MockNode:
    """Minimal JumpNode stand-in with the attributes SecureTerminator touches."""

    def __init__(self, name="test-node"):
        self.node_name = name
        self.auth_token = "supersecrettoken"
        self.received_sessions = [{"id": "s1"}, {"id": "s2"}]
        self._sessions_lock = threading.Lock()
        self._transfer_store = _MockTransferStore()
        self._stopped = False

    def stop(self):
        self._stopped = True

    def discover_targets(self):
        return []  # no peers — avoid network


class _MockTransferStore:
    def __init__(self):
        self._lock = threading.Lock()
        self._states = {"tx-1": "data", "tx-2": "data"}


# ── TerminationCommand data model ────────────────────────────────────────────

class TestTerminationCommand(unittest.TestCase):
    def setUp(self):
        self.cmd = TerminationCommand(
            command_id="cmd-1",
            issuer_id="issuer-a",
            target_node_id="node-b",
            cascade=False,
            timestamp=1700000000.0,
            nonce=b"\x01\x02\x03\x04",
        )

    def test_creation(self):
        self.assertEqual(self.cmd.command_id, "cmd-1")
        self.assertEqual(self.cmd.issuer_id, "issuer-a")
        self.assertFalse(self.cmd.cascade)

    def test_signable_payload_deterministic(self):
        p1 = self.cmd.signable_payload()
        p2 = self.cmd.signable_payload()
        self.assertEqual(p1, p2)

    def test_signable_payload_contains_parts(self):
        payload = self.cmd.signable_payload()
        self.assertIn(b"cmd-1", payload)
        self.assertIn(b"issuer-a", payload)
        self.assertIn(b"node-b", payload)
        self.assertIn(b"\x00", payload)  # cascade=False

    def test_signable_payload_cascade_flag(self):
        self.cmd.cascade = True
        payload = self.cmd.signable_payload()
        self.assertIn(b"\x01", payload)

    def test_to_dict_from_dict_roundtrip(self):
        self.cmd.signature = b"\xaa\xbb\xcc"
        d = self.cmd.to_dict()
        restored = TerminationCommand.from_dict(d)
        self.assertEqual(restored.command_id, self.cmd.command_id)
        self.assertEqual(restored.issuer_id, self.cmd.issuer_id)
        self.assertEqual(restored.target_node_id, self.cmd.target_node_id)
        self.assertEqual(restored.cascade, self.cmd.cascade)
        self.assertAlmostEqual(restored.timestamp, self.cmd.timestamp, places=5)
        self.assertEqual(restored.nonce, self.cmd.nonce)
        self.assertEqual(restored.signature, self.cmd.signature)

    def test_to_dict_hex_encoding(self):
        self.cmd.nonce = b"\xde\xad"
        self.cmd.signature = b"\xbe\xef"
        d = self.cmd.to_dict()
        self.assertEqual(d["nonce"], "dead")
        self.assertEqual(d["signature"], "beef")


# ── _NonceTracker ─────────────────────────────────────────────────────────────

class TestNonceTracker(unittest.TestCase):
    def setUp(self):
        self.tracker = _NonceTracker(ttl=0.2)

    def test_fresh_nonce_accepted(self):
        self.assertTrue(self.tracker.check_and_record(b"nonce-1"))

    def test_replay_rejected(self):
        self.tracker.check_and_record(b"nonce-1")
        self.assertFalse(self.tracker.check_and_record(b"nonce-1"))

    def test_different_nonces_accepted(self):
        self.assertTrue(self.tracker.check_and_record(b"a"))
        self.assertTrue(self.tracker.check_and_record(b"b"))

    def test_ttl_expiry(self):
        """After TTL, the same nonce should be accepted again."""
        self.tracker.check_and_record(b"nonce-x")
        time.sleep(0.3)  # exceed TTL of 0.2s
        self.assertTrue(self.tracker.check_and_record(b"nonce-x"))

    def test_clear(self):
        self.tracker.check_and_record(b"n1")
        self.tracker.clear()
        self.assertTrue(self.tracker.check_and_record(b"n1"))


# ── SecureTerminator ──────────────────────────────────────────────────────────

class TestSecureTerminator(unittest.TestCase):
    def setUp(self):
        self.node = _MockNode()
        self.key = b"test-signing-key-32bytes!!" + b"\x00" * 6
        self.terminator = SecureTerminator(
            self.node, self.key, max_staleness=120.0, nonce_ttl=300.0,
        )

    def tearDown(self):
        pass

    # -- create_command --

    def test_create_command_signs_correctly(self):
        cmd = self.terminator.create_command("target-node")
        self.assertIsInstance(cmd, TerminationCommand)
        self.assertEqual(cmd.target_node_id, "target-node")
        self.assertNotEqual(cmd.signature, b"")
        self.assertEqual(cmd.issuer_id, "test-node")  # from node_name

    def test_create_command_custom_issuer(self):
        cmd = self.terminator.create_command("t", issuer_id="custom")
        self.assertEqual(cmd.issuer_id, "custom")

    def test_create_command_cascade_flag(self):
        cmd = self.terminator.create_command("t", cascade=True)
        self.assertTrue(cmd.cascade)

    # -- verify_command --

    def test_verify_valid_command(self):
        cmd = self.terminator.create_command("target")
        self.assertTrue(self.terminator.verify_command(cmd))

    def test_verify_tampered_signature_rejected(self):
        cmd = self.terminator.create_command("target")
        cmd.signature = b"\x00" * len(cmd.signature)
        self.assertFalse(self.terminator.verify_command(cmd))

    def test_verify_stale_timestamp_rejected(self):
        cmd = self.terminator.create_command("target")
        cmd.timestamp = time.time() - 300  # well beyond max_staleness
        # Re-sign with the tampered timestamp
        cmd.signature = self.terminator._sign(cmd.signable_payload())
        self.assertFalse(self.terminator.verify_command(cmd))

    def test_verify_nonce_replay_rejected(self):
        cmd = self.terminator.create_command("target")
        # First verification should pass
        self.assertTrue(self.terminator.verify_command(cmd))
        # Second with same nonce should fail
        self.assertFalse(self.terminator.verify_command(cmd))

    # -- execute --

    def test_execute_successful_wipes_state(self):
        cmd = self.terminator.create_command("target")
        self.terminator.execute(cmd)

        # Auth token should be overwritten (different from original)
        self.assertNotEqual(self.node.auth_token, "supersecrettoken")
        # Sessions should be cleared
        self.assertEqual(self.node.received_sessions, [])
        # Transfer store should be cleared
        self.assertEqual(self.node._transfer_store._states, {})
        # Node should be stopped
        self.assertTrue(self.node._stopped)
        # Terminator should be marked as terminated
        self.assertTrue(self.terminator.is_terminated)

    def test_execute_verification_failure_raises(self):
        cmd = self.terminator.create_command("target")
        cmd.signature = b"\x00" * 32  # corrupt
        with self.assertRaises(TerminationError):
            self.terminator.execute(cmd)

    def test_execute_double_termination_raises(self):
        cmd1 = self.terminator.create_command("target")
        self.terminator.execute(cmd1)
        cmd2 = self.terminator.create_command("target")
        with self.assertRaises(TerminationError) as ctx:
            self.terminator.execute(cmd2)
        self.assertIn("already terminated", str(ctx.exception))

    # -- audit_log --

    def test_audit_log_records_events(self):
        cmd = self.terminator.create_command("target")
        self.terminator.verify_command(cmd)
        log = self.terminator.audit_log
        self.assertGreater(len(log), 0)
        actions = [e.action for e in log]
        self.assertIn("initiated", actions)
        self.assertIn("verified", actions)

    def test_audit_log_records_rejection(self):
        cmd = self.terminator.create_command("target")
        cmd.signature = b"\x00" * 32
        self.terminator.verify_command(cmd)
        log = self.terminator.audit_log
        actions = [e.action for e in log]
        self.assertIn("rejected", actions)

    def test_audit_entry_fields(self):
        cmd = self.terminator.create_command("target-z")
        log = self.terminator.audit_log
        entry = log[-1]
        self.assertEqual(entry.command_id, cmd.command_id)
        self.assertEqual(entry.target_node_id, "target-z")
        self.assertEqual(entry.action, "initiated")
        self.assertIsInstance(entry.timestamp, float)


# ── Mock Node edge cases ─────────────────────────────────────────────────────

class TestWipeWithMinimalNode(unittest.TestCase):
    """Ensure wipe works with nodes missing optional attributes."""

    def test_wipe_node_without_transfer_store(self):
        class BareNode:
            node_name = "bare"
            auth_token = "tok"
            received_sessions = []

            def stop(self):
                pass

            def discover_targets(self):
                return []

        node = BareNode()
        term = SecureTerminator(node, b"key-key-key-key!")
        cmd = term.create_command("t")
        term.execute(cmd)
        self.assertTrue(term.is_terminated)

    def test_wipe_node_without_auth_token(self):
        class NoAuthNode:
            node_name = "noauth"
            received_sessions = []

            def stop(self):
                pass

            def discover_targets(self):
                return []

        node = NoAuthNode()
        term = SecureTerminator(node, b"key-key-key-key!")
        cmd = term.create_command("t")
        term.execute(cmd)
        self.assertTrue(term.is_terminated)


if __name__ == "__main__":
    unittest.main()
