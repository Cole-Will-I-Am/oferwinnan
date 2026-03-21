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
          │session_jumper│ │gut_check │ │autonomous│
          └──────┬───────┘ └──────────┘ └────┬─────┘
                 │                           │
         ┌───────┼──────────┐          ┌─────┴──────┐
         ▼       ▼          ▼          ▼            │
    ┌──────────┐┌────────────┐┌──────────────────┐  │
    │device_   ││jump_       ││transport_        │  │
    │discovery ││protocol    ││negotiator        │  │
    └──────────┘└──────┬─────┘└──────────────────┘  │
                       │                             │
                ┌──────┴──────┐              ┌───────┴───────┐
                ▼             ▼              ▼               │
         ┌──────────────┐┌─────────┐  ┌────────────┐        │
         │symmetric_    ││multipath│  │mirror_blend │        │
         │ratchet       ││         │  └─────────────┘        │
         └──────────────┘└─────────┘                         │
                                                             │
      ── Layer 0 (no internal deps) ─────────────────────────┘
      rbac, dead_drop, secure_terminate, task_relay,
      node_manager, transport_ws, data_sync
```

### Modules

| Module | Purpose |
|---|---|
| `cli.py` | CLI entry point — listen, discover, jump, multiply, status, rain |
| `jump_protocol.py` | Binary framing + X25519 key exchange + ratcheted AES-256-GCM |
| `symmetric_ratchet.py` | Signal-spec KDF_CK chain ratchet for per-message forward secrecy |
| `session_jumper.py` | Serialize, transfer, and resume sessions across devices |
| `device_discovery.py` | WiFi multicast + Bluetooth device scanning |
| `transport_ws.py` | WebSocket transport (tunnels through firewalls on 80/443) |
| `transport_negotiator.py` | Auto-selects fastest transport + traffic normalization |
| `multipath.py` | Split transfers across multiple transports simultaneously |
| `mirror_blend.py` | Runtime function instrumentation and hot-swap |
| `autonomous.py` | Self-healing orchestration: fallback chains, hot code upgrades |
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

# Listen for incoming jumps
matrix listen --port 47701

# Jump to a target
matrix jump 192.168.1.50:47701

# Duplicate session to all discovered devices
matrix multiply --all --strategy broadcast

# Matrix rain
matrix rain

# Show loaded config
matrix config
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

## Running as a Service

```bash
sudo cp matrix.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now matrix
sudo journalctl -u matrix -f
```

## Development

```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
python -m pytest tests/ -v

# Run with unittest
python -m unittest discover -s tests -v
```

## Security

- **Forward secrecy**: Signal-spec symmetric ratchet (KDF_CK) with per-message AES-256-GCM keys
- **Key exchange**: X25519 ECDH with HKDF-SHA256 derivation
- **Authentication**: RBAC with constant-time token comparison
- **Replay protection**: Nonce tracking with TTL expiry
- **Traffic analysis resistance**: Frame padding, timing jitter, cover traffic, protocol mimicry
- **Secure cleanup**: Chain key zeroization, state wiping on termination

## License

MIT
