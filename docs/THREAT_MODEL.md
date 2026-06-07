# Matrix — Threat Model

Status: living document. Scope is the `matrix` session-jumping protocol and CLI.
This is a commercial-best-practice threat model intended to align the project
with NIST SP 800-53 / SSDF and NSA CNSA 2.0 direction. It does **not** constitute
a government accreditation (ATO) or an NSA Type 1 evaluation.

## 1. System overview

Matrix transfers a working session (environment, files, clipboard, metadata)
between devices over pluggable transports (TCP, WebSocket, cloud dead-drop).
Confidentiality and integrity are provided by an X25519 key exchange feeding a
Signal-style symmetric ratchet (AES-256-GCM per message). Peers are
authenticated by Ed25519 identity keys bound into the handshake transcript, with
optional token authentication and RBAC.

Trust boundaries:
- **Network** between two nodes (fully untrusted; active attacker assumed).
- **Process/host** running a node (trusted to the level of the OS user).
- **Persistent state**: identity key file, peer trust store, `.env`.

## 2. Assets

| Asset | Why it matters |
|---|---|
| Session payload (files, env, clipboard) | May contain sensitive working data |
| Node identity private key (Ed25519) | Impersonation if stolen |
| Session keys / ratchet state | Decrypt traffic if stolen |
| Auth token | Coarse authorization |
| Peer trust store | Integrity of who we trust |

## 3. Adversaries

- **Passive network observer** — records traffic, attempts later decryption.
- **Active network attacker (MITM)** — injects/modifies/relays, attempts to sit
  between peers, downgrade, or replay.
- **Malicious peer** — a node that completes the handshake but sends hostile
  payloads (path traversal, env injection, oversized data).
- **Local attacker** — another user on the host reading files/memory.
- **Supply-chain attacker** — tampered dependency or build.

## 4. STRIDE summary and mitigations

| Threat | Vector | Mitigation | Status |
|---|---|---|---|
| **Spoofing** | MITM substitutes keys on unauthenticated DH | Ed25519 identity signature over the handshake transcript (both ephemerals + version + suite); peer pinning (TOFU / allowlist) | **Implemented** (`identity.py`, `*_handshake`) |
| **Tampering** | Modify ciphertext in flight | AES-256-GCM AEAD per message; framing length checks | Implemented |
| **Repudiation** | Deny actions | Director audit log; RBAC | Partial |
| **Information disclosure** | Eavesdrop; cleartext token | Ratcheted AES-256-GCM; token only sent inside encrypted channel; initiator identity sent encrypted (SIGMA-I) | Implemented |
| **DoS** | Connection/resource exhaustion | Listener connection semaphore; payload caps; auth timeout | Partial |
| **Elevation of privilege** | Unauthorized jump | RBAC + token + (optional) required peer identity | Implemented |
| **Downgrade** | Force weaker suite/version | Suite + version bound into the signed transcript | Implemented |
| **Replay** | Re-send captured frames | Nonce/replay tracking; fresh ephemerals per session | Partial |

## 5. Handshake authentication (current design)

SIGMA-style mutual authentication layered on the existing flow:

1. `HELLO` (cleartext) — node id, version, `require_peer_identity`, capability.
2. `HELLO_ACK` (cleartext).
3. `KEY_EXCHANGE` (cleartext) — client ephemeral X25519 public key.
4. `KEY_EXCHANGE_ACK` (cleartext) — server ephemeral, and if the server has an
   identity, `identity_pub` + `identity_sig = Sign_server("server-id" || T)`
   where `T = "matrix-sigma-v1" || version || suite || client_eph || server_eph`.
5. Both derive the session keys; channel is now encrypted.
6. `AUTH` (**encrypted**) — client token and, if the server requires it,
   `identity_pub` + `Sign_client("client-id" || T)`.
7. `AUTH_OK` (**encrypted**).

Why this defeats MITM: the identity signatures cover both ephemeral public keys.
An attacker that injects its own ephemeral cannot produce a signature that
verifies against the transcript the victim computes, and cannot forge the
victim's identity key. Direction tags (`server-id` / `client-id`) prevent
reflection. The suite/version in `T` prevent downgrade. Verified by
`tests/test_jump_protocol.py::TestAuthenticatedHandshake` (success, pinning
mismatch, missing-identity, and substituted-ephemeral MITM).

0-RTT resume reuses cached session keys; possession of those keys is itself the
authentication, so the identity exchange (bound to fresh ephemerals) is not
repeated on resume.

## 6. Known gaps / residual risk (roadmap)

These are deliberately tracked, not yet closed:

1. **No post-quantum protection.** Move to hybrid X25519 + ML-KEM-1024 and
   ML-DSA identities (CNSA 2.0). *Harvest-now-decrypt-later applies today.*
2. **Fernet fallback.** `SessionKeys` retains an AES-128 Fernet path; remove it
   so the suite is AES-256 only with no downgrade.
3. **Key custody in interpreter memory.** Python cannot guarantee zeroization.
   Back identity (and ideally session) keys with TPM/HSM/KMS/enclave.
4. **Server-side client pinning keyed by client-claimed `node_id`.** Use
   allowlist mode (`tofu=False`, pre-provisioned keys) for high assurance.
5. **No formal verification / external audit.** Model the handshake in
   Tamarin/ProVerif; commission a third-party crypto review.
6. **AI Director attack surface.** Tool execution / code-upgrade proposals
   should be advisory-only or compiled out for hardened builds.
7. **Incomplete transports.** Dead-drop backend is a placeholder; HTTPS probe is
   reachability-only. Claims must match validated code.
8. **Supply chain.** Add SBOM, pinned hashes, reproducible builds, signed
   releases (SLSA/Sigstore).

## 7. Operational guidance

- Set `MATRIX_AUTH_TOKEN`; an unauthenticated public bind is refused.
- Provision identities (`--identity` / `MATRIX_IDENTITY_FILE`) and distribute
  fingerprints out of band; run with `--require-identity` once peers are pinned.
- For classified-adjacent use, run the trust store in allowlist mode
  (`MATRIX_TOFU=false`) with pre-provisioned peer keys, and keep identity keys in
  hardware.
