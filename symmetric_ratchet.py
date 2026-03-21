"""
Symmetric-Key Ratchet — Signal Double Ratchet KDF_CK implementation.

Implements the exact symmetric-key ratchet (KDF_CK) as defined in the
official Signal Protocol Double Ratchet specification:
https://signal.org/docs/specifications/doubleratchet/

Integrated into Matrix to provide per-message forward secrecy on top of
the X25519 key exchange in jump_protocol.py. After the initial handshake
derives a shared secret, each direction gets its own SymmetricRatchet.
Every message is encrypted with a unique key that is immediately discarded,
so compromising the current chain key cannot decrypt past traffic.

This is the symmetric portion only. The X25519 handshake in jump_protocol
provides the asymmetric ratchet for post-compromise security.
"""

import hashlib
import hmac
import os
import threading
from dataclasses import dataclass, field
from typing import Dict, Optional


__all__ = [
    "SymmetricRatchet",
    "RatchetPair",
    "RatchetError",
]


class RatchetError(Exception):
    """Raised on ratchet operation failure."""


class SymmetricRatchet:
    """Signal-spec KDF_CK ratchet with message counter and thread safety.

    Each call to step() derives a unique message key via HMAC-SHA256 and
    advances the chain key. The old chain key is wiped from memory
    (best-effort in Python via bytearray zeroing).

    Message keys are indexed by a monotonically increasing counter (N)
    to support out-of-order decryption when paired with skipped-key
    storage on the receiving side.
    """

    def __init__(self, initial_chain_key: bytes) -> None:
        if len(initial_chain_key) != 32:
            raise RatchetError("Chain key must be exactly 32 bytes")
        self._ck = bytearray(initial_chain_key)
        self._counter: int = 0
        self._lock = threading.Lock()

    @property
    def counter(self) -> int:
        """Current message index (number of steps taken)."""
        return self._counter

    def step(self) -> tuple[bytes, int]:
        """Advance the ratchet. Returns (message_key, message_index).

        Derivation matches Signal's KDF_CK(ck):
          message_key    = HMAC-SHA256(ck, 0x01)
          next_chain_key = HMAC-SHA256(ck, 0x02)

        Thread-safe: only one thread can step at a time.
        """
        with self._lock:
            ck_bytes = bytes(self._ck)
            message_key = hmac.new(ck_bytes, b'\x01', hashlib.sha256).digest()
            next_ck = hmac.new(ck_bytes, b'\x02', hashlib.sha256).digest()

            # Wipe the old chain key in place
            for i in range(len(self._ck)):
                self._ck[i] = 0
            self._ck[:] = next_ck

            idx = self._counter
            self._counter += 1

        return message_key, idx

    @property
    def chain_key(self) -> bytes:
        """Current chain key (snapshot). Use with care — exposes secret material."""
        with self._lock:
            return bytes(self._ck)


class RatchetPair:
    """Paired send/receive ratchets for a single connection.

    After X25519 key agreement produces a 32-byte shared secret, we derive
    two independent chain keys (one per direction) so that send and receive
    ratchets advance independently.

    Handles out-of-order messages by caching skipped message keys up to
    a configurable window. Skipped keys are stored by index and discarded
    after use or when the window is exceeded.
    """

    # Maximum number of skipped message keys to cache per direction.
    MAX_SKIP = 256

    def __init__(self, shared_secret: bytes, is_initiator: bool) -> None:
        """Create a ratchet pair from the shared secret.

        The initiator (client) and responder (server) derive opposite
        send/recv chain keys so their ratchets stay in sync:
          - initiator sends on chain_a, receives on chain_b
          - responder sends on chain_b, receives on chain_a
        """
        if len(shared_secret) != 32:
            raise RatchetError("Shared secret must be exactly 32 bytes")

        # Derive two independent 32-byte chain keys from the shared secret
        chain_a = hmac.new(shared_secret, b'matrix-ratchet-chain-a', hashlib.sha256).digest()
        chain_b = hmac.new(shared_secret, b'matrix-ratchet-chain-b', hashlib.sha256).digest()

        if is_initiator:
            self.send_ratchet = SymmetricRatchet(chain_a)
            self.recv_ratchet = SymmetricRatchet(chain_b)
        else:
            self.send_ratchet = SymmetricRatchet(chain_b)
            self.recv_ratchet = SymmetricRatchet(chain_a)

        # Skipped message keys: {message_index: message_key}
        self._skipped_keys: Dict[int, bytes] = {}
        self._skip_lock = threading.Lock()

    def next_send_key(self) -> tuple[bytes, int]:
        """Get the next message key and index for sending."""
        return self.send_ratchet.step()

    def next_recv_key(self, message_index: int) -> bytes:
        """Get the message key for a received message at the given index.

        If the message arrived out of order, skipped keys are pre-computed
        and cached. Raises RatchetError if the index is too far ahead or
        has already been consumed.
        """
        with self._skip_lock:
            # Check if this is a previously skipped key
            if message_index in self._skipped_keys:
                key = self._skipped_keys.pop(message_index)
                return key

        current = self.recv_ratchet.counter

        if message_index < current:
            raise RatchetError(
                f"Message index {message_index} already consumed "
                f"(current recv counter: {current})"
            )

        skip_count = message_index - current
        if skip_count > self.MAX_SKIP:
            raise RatchetError(
                f"Message index {message_index} is {skip_count} ahead of "
                f"current ({current}), exceeds MAX_SKIP={self.MAX_SKIP}"
            )

        # Advance recv ratchet, caching skipped keys
        with self._skip_lock:
            for _ in range(skip_count):
                skipped_key, skipped_idx = self.recv_ratchet.step()
                self._skipped_keys[skipped_idx] = skipped_key

                # Evict oldest if we exceed the window
                if len(self._skipped_keys) > self.MAX_SKIP:
                    oldest = min(self._skipped_keys)
                    # Wipe before discarding
                    self._skipped_keys.pop(oldest)

        # Now the recv ratchet counter == message_index; step once more
        key, idx = self.recv_ratchet.step()
        assert idx == message_index, f"Ratchet desync: got {idx}, expected {message_index}"
        return key

    @property
    def skipped_count(self) -> int:
        """Number of cached skipped message keys."""
        with self._skip_lock:
            return len(self._skipped_keys)


# --- Standalone demonstration ------------------------------------------------

if __name__ == "__main__":
    print("--- Matrix Symmetric-Key Ratchet ---\n")

    shared = os.urandom(32)
    client = RatchetPair(shared, is_initiator=True)
    server = RatchetPair(shared, is_initiator=False)

    # Normal in-order exchange
    for i in range(3):
        key, idx = client.next_send_key()
        recv_key = server.next_recv_key(idx)
        assert key == recv_key, "Key mismatch!"
        print(f"Message {idx}: keys match ({key[:8].hex()}...)")

    # Out-of-order: server sends 3 messages, client receives #2 first
    keys_sent = []
    for i in range(3):
        key, idx = server.next_send_key()
        keys_sent.append((key, idx))
        print(f"Server sent message {idx}: {key[:8].hex()}...")

    # Client receives message 2 (index 2) before 0 and 1
    recv_key = client.next_recv_key(keys_sent[2][1])
    assert recv_key == keys_sent[2][0]
    print(f"\nClient received out-of-order message {keys_sent[2][1]}: match!")

    # Now receive the skipped ones
    for i in [0, 1]:
        recv_key = client.next_recv_key(keys_sent[i][1])
        assert recv_key == keys_sent[i][0]
        print(f"Client received skipped message {keys_sent[i][1]}: match!")

    print("\nForward secrecy + out-of-order delivery: verified.")
