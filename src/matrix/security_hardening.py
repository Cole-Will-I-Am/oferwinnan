"""Runtime security hardening for Matrix jump protocol defaults.

This module patches the public jump protocol entry points without changing the
wire framing primitives. It addresses two high-risk defaults:

* bearer auth tokens are no longer sent in plaintext HELLO/KEY_EXCHANGE frames;
* TCP listeners no longer bind publicly without authentication.

The hardened handshake authenticates after X25519 key agreement by sending the
bearer token inside the newly encrypted