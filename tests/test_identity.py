"""Tests for matrix.identity — Ed25519 identity keys and peer trust store."""

import os
import tempfile
import unittest
from pathlib import Path

from matrix.identity import (
    IdentityKey, IdentityError, PeerTrustStore,
    fingerprint, verify_signature,
)


class TestIdentityKey(unittest.TestCase):
    def test_generate_and_sign_verify(self):
        key = IdentityKey.generate()
        self.assertEqual(len(key.public_bytes), 32)
        sig = key.sign(b"hello")
        self.assertTrue(verify_signature(key.public_bytes, sig, b"hello"))
        self.assertFalse(verify_signature(key.public_bytes, sig, b"tampered"))

    def test_fingerprint_stable_and_hex(self):
        key = IdentityKey.generate()
        fp = key.fingerprint
        self.assertEqual(fp, fingerprint(key.public_bytes))
        self.assertEqual(len(fp), 64)
        int(fp, 16)  # valid hex

    def test_save_load_roundtrip_and_perms(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "id.ed25519"
            key = IdentityKey.generate()
            key.save(path)
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            loaded = IdentityKey.load(path)
            self.assertEqual(loaded.public_bytes, key.public_bytes)
            # Signatures from the reloaded key verify against the same pubkey.
            sig = loaded.sign(b"x")
            self.assertTrue(verify_signature(key.public_bytes, sig, b"x"))

    def test_load_or_create(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "sub" / "id.ed25519"
            k1 = IdentityKey.load_or_create(path)
            self.assertTrue(path.exists())
            k2 = IdentityKey.load_or_create(path)
            self.assertEqual(k1.public_bytes, k2.public_bytes)

    def test_load_rejects_bad_length(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "bad"
            path.write_bytes(b"too short")
            with self.assertRaises(IdentityError):
                IdentityKey.load(path)

    def test_verify_signature_handles_garbage(self):
        self.assertFalse(verify_signature(b"\x00" * 5, b"sig", b"data"))


class TestPeerTrustStore(unittest.TestCase):
    def test_tofu_pins_then_matches(self):
        key = IdentityKey.generate()
        store = PeerTrustStore(tofu=True)
        self.assertEqual(store.verify("peerA", key.public_bytes), "pinned")
        self.assertEqual(store.verify("peerA", key.public_bytes), "matched")

    def test_mismatch_raises(self):
        a, b = IdentityKey.generate(), IdentityKey.generate()
        store = PeerTrustStore(tofu=True)
        store.verify("peerA", a.public_bytes)
        with self.assertRaises(IdentityError):
            store.verify("peerA", b.public_bytes)

    def test_allowlist_mode_rejects_unknown(self):
        key = IdentityKey.generate()
        store = PeerTrustStore(tofu=False)
        with self.assertRaises(IdentityError):
            store.verify("peerA", key.public_bytes)
        # Pre-pinned peers are accepted under allowlist mode.
        store.pin("peerA", key.public_bytes)
        self.assertEqual(store.verify("peerA", key.public_bytes), "matched")

    def test_persistence_roundtrip(self):
        key = IdentityKey.generate()
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "known_peers"
            store = PeerTrustStore(path, tofu=True)
            store.verify("peerA", key.public_bytes)
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)

            # A fresh store loads the pinned key and enforces it.
            reloaded = PeerTrustStore(path, tofu=False)
            self.assertEqual(reloaded.get("peerA"), key.public_bytes)
            self.assertEqual(reloaded.verify("peerA", key.public_bytes), "matched")
            other = IdentityKey.generate()
            with self.assertRaises(IdentityError):
                reloaded.verify("peerA", other.public_bytes)


if __name__ == "__main__":
    unittest.main()
