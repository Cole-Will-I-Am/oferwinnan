# Matrix

Cross-device session jumping via encrypted multi-transport mesh networking.

Transfer your working session (environment, files, clipboard) between machines over WiFi, Bluetooth, WebSocket, or cloud storage dead drops — with per-message forward secrecy via Signal-spec symmetric ratcheting.

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
      node_manager, transport_ws, data_sync, config
```

### Modules

| Module | Purpose |
|---|---|
| `cli.py` | CLI entry point — listen, discover, jump, multiply, status, rain, config, director |
| `jump_protocol.py` | Binary framing + X25519 key exchange + ratcheted AES-256-GCM |
| `symmetric_ratchet.py` | Signal-spec KDF_CK chain ratchet for per-message forward secrecy |
| `session_jumper.py` | Serialize, transfer, and resume sessions across devices |
| `device_discovery.py` | WiFi multicast + Bluetooth device scanning |
| `transport_ws.py` | WebSocket transport (tunnels through firewalls on 80/443) |
| `transport_negotiator.py` | Auto-selects fastest transport + traffic normalization |
| `multipath.py` | Split transfers across multiple transports simultaneously |
| `mirror_blend.py` | Runtime function instrumentation and hot-swap |
| `autonomous.py` | Self-healing orchestration: fallback chains, hot code upgrades, exhaustion hooks |
| `director.py` | Tri-State Director: FSM (AUTONOMOUS/AI_ACTIVE/HUMAN_OVERRIDE), EscalationDetector, ToolExecutor, SemanticDelta, audit trail |
| `llm_backend.py` | Unified LLM interface (Ollama + Anthropic) — zero external deps, single-turn tool-use only |
| `node_manager.py` | Node health tracking, task queues, campaigns |
| `task_relay.py` | Hop-based relay routing for segmented networks |
| `dead_drop.py` | Async transport via cloud storage mailboxes (S3/GCS/filesystem) |
| `rbac.py` | Role-based access control (ADMIN/OPERATOR/VIEWER) |
| `secure_terminate.py` | Signed shutdown commands with cascade propagation |
| `data_sync.py` | Delta sync with rate limiting and delivery tracking |
| `gut_check.py` | Matrix digital rain terminal visualization |
| `config.py` | Centralized configuration with env-var and .env support |

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

# Duplicate session to all discovered devices
matrix multiply --all --strategy broadcast

# Matrix rain
matrix rain

# Show loaded config
matrix config

# Start the Tri-State Director (LLM-augmented orchestration)
matrix director start

# Human override / release
matrix director override
matrix director release

# Manual AI escalation
matrix director escalate --reason "connectivity degraded"

# View director state and audit log
matrix director status
matrix director audit
```

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

## Running as a Service

```bash
sudo cp matrix.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now matrix
sudo journalctl -u matrix -f
```

The bundled unit runs with additional `systemd` hardening (`NoNewPrivileges`, `ProtectSystem`, capability drop, syscall/address-family restrictions) and starts listener mode with `--restore-files never` for non-interactive safety.

> **Set `MATRIX_AUTH_TOKEN` in `/root/Matrix/.env`.** The listener binds all interfaces and now refuses to start unauthenticated on a public address, so a token is required for the service to come up (it also gates the encrypted `AUTH` handshake).

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
| 2 | `AI_ACTIVE` | LLM evaluates and acts through 7 sandboxed tools |
| 1 | `HUMAN_OVERRIDE` | Human operator in direct control via CLI |

Escalation triggers: fallback exhaustion, all-paths-degraded (sustained), task failure rate, transport total failure, manual. All triggers use hysteresis (cooldown + sustain windows) to prevent flapping.

Safety constraints: action budget (default 5), dead-man's switch timeout, AST quarantine on all proposed code (blocks `os`/`subprocess`/`eval`/`exec`/`open`), rollback on any failure, full audit trail.

## Security

- **Forward secrecy**: Signal-spec symmetric ratchet (KDF_CK) with per-message AES-256-GCM keys
- **Key exchange**: X25519 ECDH with HKDF-SHA256 derivation
- **Authentication**: encrypted post-handshake `AUTH`/`AUTH_OK` exchange — the token is never sent in cleartext (including on 0-RTT resume); RBAC with constant-time token comparison
- **Safe binding**: an unauthenticated listener refuses to bind a public interface; set an auth token to listen beyond `127.0.0.1`
- **Replay protection**: Nonce tracking with TTL expiry
- **Traffic analysis resistance**: Frame padding, timing jitter, cover traffic, protocol mimicry
- **Secure cleanup**: Chain key zeroization, state wiping on termination

## License

All rights reserved.
