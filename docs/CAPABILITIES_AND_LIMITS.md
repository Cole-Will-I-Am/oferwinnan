# Matrix — Capabilities and Limits

This document maps what Matrix currently does versus what it explicitly does **not** do. It is intended for operators, reviewers, and defenders who need a clear boundary around the project's scope.

## What Matrix is

Matrix is a **Linux-only**, Python-based cross-device session-jumping and mesh-communication tool. It is deliberately built as ordinary Python source on disk, launched by the system Python interpreter, with no loaders, staged execution, or memory-resident payloads.

Current capabilities:

- Encrypted multi-transport mesh networking (TCP, WebSocket, DNS tunnel, ICMP tunnel, cloud dead drop).
- Cross-device session transfer (environment, files, clipboard metadata).
- Remote shell tasking over the encrypted Jump channel.
- Traffic mimicry (Slack, Teams, Discord, DoH, gRPC, cloud sync, generic Web API) and polymorphic per-session padding.
- Process-title disguise via `setproctitle` / Linux `prctl(PR_SET_NAME)`.
- Linux persistence (systemd system/user services, cron `@reboot`, `/etc/rc.local`, `.bashrc` alias, SSH authorized_keys backdoor) plus a watchdog re-spawner.
- LLM-augmented Tri-State Director with containment policies.
- Peer-to-peer task relay and distance-vector routing.

## What Matrix is not

The following techniques and features are **intentionally absent** and are outside the project's scope. They are listed here so reviewers do not have to hunt for them.

### Execution model

- **No implant or staged loader.** Matrix is installed as Python source and run directly by the system interpreter (`python -m matrix` or the `matrix` console entry point).
- **No shellcode, COFF/BOF runners, .NET in-memory execution, or PIC payloads.**
- **No cross-compilation or binary packers.** The agent is not compiled to a single-file native executable.
- **No indirect syscalls** (Hell's Gate, SysWhispers, etc.).

### Windows / macOS scope

- **No Windows agent.** Matrix is Linux-only and uses `/proc`, `getloadavg`, and other POSIX/Linux interfaces.
- **No macOS agent.** There is no LaunchAgent/LaunchDaemon implementation beyond an inert stub.
- **No Windows-specific telemetry evasion or EDR bypass.**

### EDR / AV / telemetry interaction

- **No AMSI, ETW, ETW-TI, or Windows Defender bypass.** Matrix does not patch, disable, or bypass security products.
- **No SmartScreen, WDAC, or AppLocker bypass.**
- **No API hooking or unhooking.**
- **No process injection, process hollowing, or cross-process memory manipulation.**
- **No token impersonation, DPAPI/Kerberos/LSA credential vaulting, or LSA secrets access.**

### Lateral movement and host interaction

- **No SMB / Named Pipe / WMI / WinRM / DCOM lateral movement primitives.**
- **No pivoting, SOCKS4a / SOCKS5 proxy, or port forwarding.**
- **No keystroke logging, credential harvesting, screenshot capture, clipboard theft, process/token enumeration, browser credential dumping, file browser, or VNC/RDP access.**

### C2 / redirector architecture

- **No staged loaders, domain fronting, CDN redirectors, or malleable C2 profiles.** The WebSocket domain-fronting helper is a thin split-SNI wrapper, not a full redirector framework.
- **No per-operator mTLS or per-implant PSK rotation.** Authentication is currently a single shared `MATRIX_AUTH_TOKEN` plus optional Ed25519 mutual auth.
- **No teamserver GUI, per-operator session sharing, or live log streaming.**
- **Dead-drop writes require operator-tier cloud credentials.** There is no automatic credential rotation or bucket-burn flow.

### Bluetooth and discovery

- **Bluetooth scanning depends on PyBluez, which is abandonware.** In environments without PyBluez the scanner silently returns an empty list; there is no real Bluetooth transport fallback.
- **UDP multicast discovery is limited to the local broadcast domain / VLAN.** It does not cross 802.1X boundaries or routed networks.
- **Bluetooth is treated as an optional discovery channel, not an initial-access vector.**

### Autonomy and sandboxing

- **The LLM Director has access to `propose_hot_upgrade` and other operational tools.** This makes the AI tier nondeterministic from an operator's perspective; containment policies (`restricted`, `advisory`, `disabled`) bound but do not eliminate this surface.
- **AST quarantine blocks `os` / `subprocess` / `exec` / `eval` / `open` at the top level, but interpreters such as `urllib`, `http.client`, `asyncio`, `ssl`, `struct`, and `mmap` are not comprehensively blacklisted.**

### Anti-forensics

- **No log scrubbing, timestomping, mtime/atime forgery, or secure file shredding.**
- **No self-delete on terminate.**
- **No secure cleanup of dead-drop artifacts on cloud storage after session close.**
- **Termination wipes in-memory session keys and the `auth_token` cache, but persistent logs and artifacts are the operator's responsibility.**

## Why these limits exist

Matrix is built as an auditable, single-stage Python tool that stays inside ordinary process boundaries and standard APIs. Keeping Windows, macOS, injection, hooking, EDR bypass, credential theft, and staged loaders out of scope:

- makes the codebase reviewable with standard static and dynamic analysis tools,
- reduces accidental misuse as commodity malware,
- and keeps the project aligned with defensive best practices and authorized red-team use.

If you need any of the capabilities listed as out-of-scope, Matrix is not the right tool.
