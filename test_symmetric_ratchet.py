"""Tests for symmetric_ratchet.py — Signal KDF_CK integration."""

import hashlib
import hmac
import os
import threading
import unittest

from symmetric_ratchet import SymmetricRatchet, RatchetPair, RatchetError


class TestSymmetricRatchet(unittest.TestCase):
    """Core ratchet mechanics."""

    def test_step_returns_32_byte_key_and_index(self):
        r = SymmetricRatchet(os.urandom(32))
        key, idx = r.step()
        self.assertEqual(len(key), 32)
        self.assertEqual(idx, 0)

    def test_counter_increments(self):
        r = SymmetricRatchet(os.urandom(32))
        for i in range(5):
            _, idx = r.step()
            self.assertEqual(idx, i)
        self.assertEqual(r.counter, 5)

    def test_keys_are_unique(self):
        r = SymmetricRatchet(os.urandom(32))
        keys = [r.step()[0] for _ in range(100)]
        self.assertEqual(len(set(keys)), 100)

    def test_deterministic_from_same_seed(self):
        seed = os.urandom(32)
        r1 = SymmetricRatchet(seed)
        r2 = SymmetricRatchet(seed)
        for _ in range(10):
            k1, i1 = r1.step()
            k2, i2 = r2.step()
            self.assertEqual(k1, k2)
            self.assertEqual(i1, i2)

    def test_matches_signal_spec(self):
        """Verify derivation matches KDF_CK: HMAC(ck, 0x01) / HMAC(ck, 0x02)."""
        seed = os.urandom(32)
        r = SymmetricRatchet(seed)
        expected_mk = hmac.new(seed, b'\x01', hashlib.sha256).digest()
        expected_next_ck = hmac.new(seed, b'\x02', hashlib.sha256).digest()

        mk, _ = r.step()
        self.assertEqual(mk, expected_mk)
        self.assertEqual(r.chain_key, expected_next_ck)

    def test_invalid_key_length(self):
        with self.assertRaises(RatchetError):
            SymmetricRatchet(b"too-short")
        with self.assertRaises(RatchetError):
            SymmetricRatchet(os.urandom(64))

    def test_forward_secrecy(self):
        """Compromised chain key cannot recover past message keys."""
        seed = os.urandom(32)
        r = SymmetricRatchet(seed)
        past_keys = [r.step()[0] for _ in range(5)]

        compromised_ck = r.chain_key
        # Try to derive past keys from compromised state — impossible
        attacker = SymmetricRatchet(compromised_ck)
        for past_key in past_keys:
            attacker_key, _ = attacker.step()
            self.assertNotEqual(attacker_key, past_key)

    def test_thread_safety(self):
        r = SymmetricRatchet(os.urandom(32))
        results = {}
        errors = []

        def step_n(thread_id, n):
            try:
                for _ in range(n):
                    key, idx = r.step()
                    results[idx] = key
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=step_n, args=(i, 50)) for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(errors), 0)
        # 4 threads * 50 steps = 200 unique indices
        self.assertEqual(len(results), 200)
        self.assertEqual(set(results.keys()), set(range(200)))


class TestRatchetPair(unittest.TestCase):
    """Paired send/receive ratchets."""

    def test_basic_exchange(self):
        shared = os.urandom(32)
        client = RatchetPair(shared, is_initiator=True)
        server = RatchetPair(shared, is_initiator=False)

        for _ in range(10):
            key, idx = client.next_send_key()
            recv_key = server.next_recv_key(idx)
            self.assertEqual(key, recv_key)

    def test_bidirectional(self):
        shared = os.urandom(32)
        client = RatchetPair(shared, is_initiator=True)
        server = RatchetPair(shared, is_initiator=False)

        # Client -> Server
        k1, i1 = client.next_send_key()
        self.assertEqual(server.next_recv_key(i1), k1)

        # Server -> Client
        k2, i2 = server.next_send_key()
        self.assertEqual(client.next_recv_key(i2), k2)

        # Interleaved
        k3, i3 = client.next_send_key()
        k4, i4 = server.next_send_key()
        self.assertEqual(server.next_recv_key(i3), k3)
        self.assertEqual(client.next_recv_key(i4), k4)

    def test_out_of_order_delivery(self):
        shared = os.urandom(32)
        client = RatchetPair(shared, is_initiator=True)
        server = RatchetPair(shared, is_initiator=False)

        # Client sends 5 messages
        sent = [client.next_send_key() for _ in range(5)]

        # Server receives them in reverse order
        for key, idx in reversed(sent):
            recv_key = server.next_recv_key(idx)
            self.assertEqual(recv_key, key)

    def test_skipped_keys_cached(self):
        shared = os.urandom(32)
        client = RatchetPair(shared, is_initiator=True)
        server = RatchetPair(shared, is_initiator=False)

        sent = [client.next_send_key() for _ in range(5)]

        # Receive message 4 first — skips 0-3
        server.next_recv_key(sent[4][1])
        self.assertEqual(server.skipped_count, 4)

        # Now receive skipped messages
        for i in range(4):
            server.next_recv_key(sent[i][1])
        self.assertEqual(server.skipped_count, 0)

    def test_replay_rejected(self):
        shared = os.urandom(32)
        client = RatchetPair(shared, is_initiator=True)
        server = RatchetPair(shared, is_initiator=False)

        key, idx = client.next_send_key()
        server.next_recv_key(idx)

        # Replaying the same index must fail
        with self.assertRaises(RatchetError):
            server.next_recv_key(idx)

    def test_max_skip_exceeded(self):
        shared = os.urandom(32)
        client = RatchetPair(shared, is_initiator=True)
        server = RatchetPair(shared, is_initiator=False)

        # Skip way past the window
        for _ in range(RatchetPair.MAX_SKIP + 10):
            client.next_send_key()

        key, idx = client.next_send_key()
        with self.assertRaises(RatchetError):
            server.next_recv_key(idx)

    def test_invalid_shared_secret(self):
        with self.assertRaises(RatchetError):
            RatchetPair(b"short", is_initiator=True)

    def test_different_roles_different_keys(self):
        """Initiator send keys != responder send keys (different chains)."""
        shared = os.urandom(32)
        client = RatchetPair(shared, is_initiator=True)
        server = RatchetPair(shared, is_initiator=False)

        ck, _ = client.next_send_key()
        sk, _ = server.next_send_key()
        self.assertNotEqual(ck, sk)


class TestRatchetWithProtocol(unittest.TestCase):
    """Integration with jump_protocol SessionKeys."""

    def test_session_keys_ratcheted_encrypt_decrypt(self):
        from jump_protocol import derive_session_keys, generate_keypair

        priv_a, pub_a = generate_keypair()
        priv_b, pub_b = generate_keypair()

        keys_a = derive_session_keys(priv_a, pub_b, is_initiator=True)
        keys_b = derive_session_keys(priv_b, pub_a, is_initiator=False)

        # Verify ratchets are active
        self.assertIsNotNone(keys_a.ratchet)
        self.assertIsNotNone(keys_b.ratchet)

        # A encrypts, B decrypts
        plaintext = b"forward secrecy test"
        ct = keys_a.encrypt(plaintext)
        pt = keys_b.decrypt(ct)
        self.assertEqual(pt, plaintext)

    def test_multiple_messages(self):
        from jump_protocol import derive_session_keys, generate_keypair

        priv_a, pub_a = generate_keypair()
        priv_b, pub_b = generate_keypair()

        keys_a = derive_session_keys(priv_a, pub_b, is_initiator=True)
        keys_b = derive_session_keys(priv_b, pub_a, is_initiator=False)

        for i in range(20):
            msg = f"message {i}".encode()
            ct = keys_a.encrypt(msg)
            pt = keys_b.decrypt(ct)
            self.assertEqual(pt, msg)

    def test_bidirectional_protocol(self):
        from jump_protocol import derive_session_keys, generate_keypair

        priv_a, pub_a = generate_keypair()
        priv_b, pub_b = generate_keypair()

        keys_a = derive_session_keys(priv_a, pub_b, is_initiator=True)
        keys_b = derive_session_keys(priv_b, pub_a, is_initiator=False)

        # A -> B
        ct1 = keys_a.encrypt(b"hello from A")
        self.assertEqual(keys_b.decrypt(ct1), b"hello from A")

        # B -> A
        ct2 = keys_b.encrypt(b"hello from B")
        self.assertEqual(keys_a.decrypt(ct2), b"hello from B")

    def test_ciphertext_uniqueness(self):
        """Same plaintext produces different ciphertext each time (unique key + nonce)."""
        from jump_protocol import derive_session_keys, generate_keypair

        priv_a, pub_a = generate_keypair()
        priv_b, pub_b = generate_keypair()

        keys_a = derive_session_keys(priv_a, pub_b, is_initiator=True)

        ct1 = keys_a.encrypt(b"same data")
        ct2 = keys_a.encrypt(b"same data")
        self.assertNotEqual(ct1, ct2)

    def test_failed_decrypt_does_not_burn_key(self):
        from jump_protocol import derive_session_keys, generate_keypair, ProtocolError

        priv_a, pub_a = generate_keypair()
        priv_b, pub_b = generate_keypair()

        keys_a = derive_session_keys(priv_a, pub_b, is_initiator=True)
        keys_b = derive_session_keys(priv_b, pub_a, is_initiator=False)

        plaintext = b"tamper retry safety"
        ct = keys_a.encrypt(plaintext)
        tampered = bytearray(ct)
        tampered[-1] ^= 0x01

        with self.assertRaises(ProtocolError):
            keys_b.decrypt(bytes(tampered))

        # Valid packet for the same index should still decrypt.
        self.assertEqual(keys_b.decrypt(ct), plaintext)

    def test_encrypt_index_overflow_raises(self):
        from jump_protocol import derive_session_keys, generate_keypair, ProtocolError

        priv_a, pub_a = generate_keypair()
        priv_b, pub_b = generate_keypair()

        keys_a = derive_session_keys(priv_a, pub_b, is_initiator=True)
        keys_a.ratchet.send_ratchet._counter = 0x1_0000_0000

        with self.assertRaises(ProtocolError):
            keys_a.encrypt(b"overflow")


if __name__ == "__main__":
    unittest.main()
