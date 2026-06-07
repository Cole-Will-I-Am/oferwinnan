"""
Node identity and peer trust for authenticated handshakes.

Provides long-term Ed25519 identity keys and an SSH ``known_hosts``-style trust
store. These let the ephemeral X25519 key agreement in ``jump_protocol`` be
cryptographically bound to a *verified* peer identity, defeating active
man-in-the-middle attacks (an unauthenticated Diffie–Hellman exchange does not).

Design notes:
  - Identity keys are Ed25519 (small, fast, misuse-resistant).
  - A peer is identified by the SHA-256 fingerprint of its identity public key.
  - The trust store supports Trust-On-First-Use (TOFU, SSH-like) or a strict
    allowlist (``tofu=False``) for high-assurance deployments where every
    authorized peer key is provisioned ahead of time.
  - Private key material is written with ``0600`` permissions. Python cannot
    guarantee in-memory zeroization; for higher assurance back the identity key
    with a TPM/HSM/KMS (see docs/THREAT_MODEL.md).
"""

from __future__ import annotations

import hmac
import os
import threading
from pathlib import Path
from typing import Dict, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


__all__ = [
    "IdentityError",
    "IdentityKey",
    "PeerTrustStore",
    "fingerprint",
    "verify_signature",
]


class IdentityError(Exception):
    """Raised on identity load/verify failures or peer-trust violations."""


def fingerprint(public_bytes: bytes) -> str:
    """Return the hex SHA-256 fingerprint of an identity public key."""
    digest = hashes.Hash(hashes.SHA256())
    digest.update(public_bytes)
    return digest.finalize().hex()


def verify_signature(public_bytes: bytes, signature: bytes, data: bytes) -> bool:
    """Verify an Ed25519 signature. Returns False on any failure (never raises)."""
    try:
        Ed25519PublicKey.from_public_bytes(public_bytes).verify(signature, data)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


class IdentityKey:
    """A node's long-term Ed25519 signing identity."""

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._priv = private_key
        self._pub_bytes = private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    @classmethod
    def generate(cls) -> "IdentityKey":
        return cls(Ed25519PrivateKey.generate())

    @property
    def public_bytes(self) -> bytes:
        return self._pub_bytes

    @property
    def fingerprint(self) -> str:
        return fingerprint(self._pub_bytes)

    def sign(self, data: bytes) -> bytes:
        return self._priv.sign(data)

    def save(self, path) -> None:
        """Persist the raw private key with ``0600`` permissions (atomically)."""
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        raw = self._priv.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        tmp = p.with_name(p.name + ".tmp")
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, raw)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, p)
        try:
            os.chmod(p, 0o600)
        except OSError:
            pass

    @classmethod
    def load(cls, path) -> "IdentityKey":
        raw = Path(path).read_bytes()
        if len(raw) != 32:
            raise IdentityError(
                f"Invalid identity key length: expected 32 bytes, got {len(raw)}"
            )
        try:
            return cls(Ed25519PrivateKey.from_private_bytes(raw))
        except ValueError as e:
            raise IdentityError(f"Corrupt identity key: {e}") from e

    @classmethod
    def load_or_create(cls, path) -> "IdentityKey":
        """Load an identity key from ``path``, creating one if absent."""
        p = Path(path)
        if p.exists():
            return cls.load(p)
        key = cls.generate()
        key.save(p)
        return key


class PeerTrustStore:
    """An SSH ``known_hosts``-style store mapping a peer name to its identity key.

    File format (one entry per line)::

        <name> sha256:<fingerprint> <hex_public_key>

    With ``tofu=True`` (default) an unknown peer is pinned on first contact.
    With ``tofu=False`` the store acts as a strict allowlist: any peer whose
    key is not already pinned is rejected.
    """

    def __init__(self, path=None, tofu: bool = True) -> None:
        self._path = Path(path) if path else None
        self._tofu = tofu
        self._peers: Dict[str, bytes] = {}
        self._lock = threading.Lock()
        if self._path and self._path.exists():
            self._load()

    @property
    def tofu(self) -> bool:
        return self._tofu

    def _load(self) -> None:
        for line in self._path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            name, hex_pub = parts[0], parts[-1]
            try:
                self._peers[name] = bytes.fromhex(hex_pub)
            except ValueError:
                continue

    def _append(self, name: str, public_bytes: bytes) -> None:
        if not self._path:
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        line = f"{name} sha256:{fingerprint(public_bytes)} {public_bytes.hex()}\n"
        fd = os.open(str(self._path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, line.encode())
        finally:
            os.close(fd)
        try:
            os.chmod(self._path, 0o600)
        except OSError:
            pass

    def get(self, name: str) -> Optional[bytes]:
        with self._lock:
            return self._peers.get(name)

    def pin(self, name: str, public_bytes: bytes) -> None:
        """Explicitly pin (or re-pin) a peer's identity key."""
        with self._lock:
            self._peers[name] = public_bytes
            self._append(name, public_bytes)

    def verify(self, name: str, public_bytes: bytes) -> str:
        """Verify a presented identity key for ``name`` against the store.

        Returns ``"matched"`` if it equals the pinned key, or ``"pinned"`` if it
        was newly recorded under TOFU. Raises :class:`IdentityError` on mismatch
        or when an unknown peer is seen with TOFU disabled.
        """
        with self._lock:
            known = self._peers.get(name)
            if known is None:
                if not self._tofu:
                    raise IdentityError(
                        f"Unknown peer identity for {name!r} "
                        f"({fingerprint(public_bytes)}) and TOFU is disabled"
                    )
                self._peers[name] = public_bytes
                self._append(name, public_bytes)
                return "pinned"
            if not hmac.compare_digest(known, public_bytes):
                raise IdentityError(
                    f"Peer identity mismatch for {name!r}: pinned "
                    f"{fingerprint(known)}, presented {fingerprint(public_bytes)}"
                )
            return "matched"
