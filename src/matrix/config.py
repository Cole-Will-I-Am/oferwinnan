"""
matrix.config — Centralized configuration with env-var and .env support.

All values have hardcoded defaults matching the original behavior.
Override via environment variables or a .env file.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _load_dotenv() -> None:
    """Load .env file from CWD or project root if it exists. No external deps."""
    for candidate in [
        Path.cwd() / ".env",
        Path(__file__).resolve().parent.parent.parent / ".env",
    ]:
        if candidate.is_file():
            with open(candidate) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    key, _, value = line.partition("=")
                    key = key.strip()
                    value = value.strip().strip("'\"")
                    os.environ.setdefault(key, value)
            break


def _env(name: str, default, type_=str):
    """Read an env var, cast to type_, falling back to default."""
    raw = os.environ.get(name)
    if raw is None:
        return default
    if type_ is bool:
        return raw.lower() in ("1", "true", "yes")
    return type_(raw)


_load_dotenv()


@dataclass(frozen=True)
class MatrixConfig:
    """Immutable configuration snapshot."""

    # Network
    port: int = _env("MATRIX_PORT", 47701, int)
    discovery_port: int = _env("MATRIX_DISCOVERY_PORT", 47700, int)
    multicast_group: str = _env("MATRIX_MULTICAST_GROUP", "239.255.77.88")
    ws_path: str = _env("MATRIX_WS_PATH", "/jump/ws")
    ws_port: int = _env("MATRIX_WS_PORT", 8443, int)

    # Timing
    stale_timeout: float = _env("MATRIX_STALE_TIMEOUT", 30.0, float)
    announce_interval: int = _env("MATRIX_ANNOUNCE_INTERVAL", 5, int)
    bt_scan_duration: int = _env("MATRIX_BT_SCAN_DURATION", 4, int)

    # Transfer
    chunk_size: int = _env("MATRIX_CHUNK_SIZE", 65536, int)
    max_payload: int = _env("MATRIX_MAX_PAYLOAD", 16777216, int)
    max_file_size: int = _env("MATRIX_MAX_FILE_SIZE", 10485760, int)

    # Auth (optional)
    auth_token: str | None = _env("MATRIX_AUTH_TOKEN", None)
    node_name: str | None = _env("MATRIX_NODE_NAME", None)


config = MatrixConfig()
