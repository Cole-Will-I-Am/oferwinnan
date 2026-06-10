"""
autonomous.py — Self-healing, self-customizing, self-upgrading orchestration.

Ties together MirrorRegistry, Blender, AdaptiveWrapper, JumpSession, JumpNode,
and DiscoveryManager into an autonomous feedback loop.

Layer 1: ResilienceManager  — Exception-driven fallback chains
Layer 2: EnvironmentAdapter — Runtime self-tuning based on system signals
Layer 3: HotUpgrader        — Over-the-air code swap with automatic rollback
Layer 4: AutonomousLoop     — The feedback loop that ties it all together
"""

from __future__ import annotations

import ast
import base64
import importlib
import importlib.util
import logging
import os
import threading
import time
import types
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence

from matrix.mirror_blend import MirrorRegistry, Blender, AdaptiveWrapper, BlendError

logger = logging.getLogger(__name__)


# ── Layer 1: Self-Healing ────────────────────────────────────────────────────

@dataclass(slots=True)
class _FallbackSlot:
    """Tracks the fallback chain for a single resilient binding."""
    name: str
    namespace: Any              # module or globals dict
    namespace_kind: str         # "module" or "globals"
    fallbacks: list             # ordered list of fallback callables
    key: str = ""               # protection key (stable across re-installs)
    attempt: int = 0            # index into fallbacks currently active
    blend_key: str = ""         # current blend key (for revert)
    failure_count: int = 0      # total failures observed
    last_failure: float = 0.0   # timestamp of most recent failure


class ResilienceManager:
    """Wraps callables with automatic fallback chains.

    When a mirrored function raises, the manager reverts it and swaps in the
    next fallback in the chain. If all fallbacks are exhausted, it reverts to
    the original. Thread-safe — revert + blend is atomic under the Blender lock.

    Usage:
        rm = ResilienceManager(registry, blender)
        rm.protect(
            target_module, "parse_data",
            fallbacks=[fast_parse, safe_parse, minimal_parse],
        )
        # If fast_parse raises, safe_parse replaces it automatically.
        # If safe_parse raises, minimal_parse takes over.
        # If all fail, the original parse_data is restored.
    """

    def __init__(self, registry: MirrorRegistry, blender: Blender) -> None:
        self._registry = registry
        self._blender = blender
        self._slots: Dict[str, _FallbackSlot] = {}
        self._lock = threading.Lock()
        self._on_exhausted: Optional[Callable[[str, int], None]] = None

    def set_on_exhausted(
        self, callback: Optional[Callable[[str, int], None]]
    ) -> None:
        """Register callback(slot_name, failure_count) when all fallbacks exhaust."""
        self._on_exhausted = callback

    def protect(
        self,
        namespace: Any,
        name: str,
        fallbacks: Sequence[Callable],
        *,
        key: Optional[str] = None,
    ) -> str:
        """Install a fallback chain for `namespace.name`.

        The first callable in `fallbacks` replaces the current implementation.
        On failure, subsequent entries take over. If all exhaust, the original
        is restored.

        Returns:
            The protection key (for manual removal via `unprotect`).
        """
        if not fallbacks:
            raise ValueError("fallbacks must be non-empty")

        pkey = key or f"resilient:{_ns_label(namespace)}.{name}"

        with self._lock:
            slot = _FallbackSlot(
                name=name,
                namespace=namespace,
                namespace_kind="module" if isinstance(namespace, types.ModuleType) else "globals",
                fallbacks=list(fallbacks),
                key=pkey,
                attempt=0,
            )
            self._slots[pkey] = slot
            self._install(slot, index=0)

        return pkey

    def unprotect(self, key: str) -> None:
        """Remove a protection, reverting to the original."""
        with self._lock:
            slot = self._slots.pop(key, None)
            if slot and slot.blend_key:
                try:
                    self._blender.revert(slot.blend_key)
                except BlendError:
                    pass

    @property
    def protection_count(self) -> int:
        return len(self._slots)

    @property
    def total_failures(self) -> int:
        return sum(s.failure_count for s in self._slots.values())

    def _install(self, slot: _FallbackSlot, index: int) -> None:
        """Install fallback[index] into the namespace with exception handling."""
        fn = slot.fallbacks[index]
        slot.attempt = index

        def safe_wrapper(*args, **kwargs):
            try:
                return fn(*args, **kwargs)
            except Exception as exc:
                self._on_failure(slot, exc)
                raise

        mirror = self._registry.mirror(safe_wrapper, name=f"{slot.name}:fb{index}")

        # Revert previous blend if any
        if slot.blend_key:
            try:
                self._blender.revert(slot.blend_key)
            except BlendError:
                pass

        if slot.namespace_kind == "module":
            slot.blend_key = self._blender.blend_into_module(
                slot.namespace, slot.name, mirror, key=slot.key,
            )
        else:
            slot.blend_key = self._blender.blend_into_globals(
                slot.namespace, slot.name, mirror, key=slot.key,
            )

    def _on_failure(self, slot: _FallbackSlot, exc: BaseException) -> None:
        """Advance to the next fallback, or revert to original if exhausted."""
        with self._lock:
            slot.failure_count += 1
            slot.last_failure = time.monotonic()
            next_idx = slot.attempt + 1

            if next_idx < len(slot.fallbacks):
                logger.warning(
                    "ResilienceManager: %s fallback %d failed (%s), "
                    "advancing to fallback %d",
                    slot.name, slot.attempt, exc, next_idx,
                )
                self._install(slot, next_idx)
            else:
                logger.warning(
                    "ResilienceManager: %s all %d fallbacks exhausted, "
                    "reverting to original",
                    slot.name, len(slot.fallbacks),
                )
                if slot.blend_key:
                    try:
                        self._blender.revert(slot.blend_key)
                    except BlendError:
                        pass
                    slot.blend_key = ""
                if self._on_exhausted:
                    try:
                        self._on_exhausted(slot.name, slot.failure_count)
                    except Exception:
                        logger.debug("on_exhausted callback error", exc_info=True)


# ── Layer 2: Self-Customizing ────────────────────────────────────────────────

class EnvironmentAdapter:
    """Extends AdaptiveWrapper to tune behavior based on broader system signals.

    Checks CPU load, memory pressure, network latency, and application-level
    metrics (like frame timing from InstrumentedRain) to select the optimal
    operating mode.

    Modes:
        FULL        — All hooks, maximum fidelity
        LIGHTWEIGHT — Skip expensive post-processing
        PASSTHROUGH — Zero overhead
        ECO         — Reduced quality for resource-constrained environments
    """

    class Mode:
        FULL = "full"
        LIGHTWEIGHT = "light"
        PASSTHROUGH = "pass"
        ECO = "eco"

    def __init__(
        self,
        registry: MirrorRegistry,
        blender: Blender,
        *,
        cpu_threshold: float = 80.0,
        memory_threshold: float = 85.0,
        latency_threshold_ms: float = 200.0,
        frame_time_threshold_ms: float = 50.0,
    ) -> None:
        self._registry = registry
        self._blender = blender
        self._cpu_threshold = cpu_threshold
        self._memory_threshold = memory_threshold
        self._latency_threshold_ms = latency_threshold_ms
        self._frame_time_threshold_ms = frame_time_threshold_ms
        self._lock = threading.Lock()
        self._mode = self.Mode.FULL
        self._swap_registry: Dict[str, _AdaptiveSlot] = {}
        self._metrics: Dict[str, float] = {}

    def register_adaptive(
        self,
        namespace: Any,
        name: str,
        variants: Dict[str, Callable],
    ) -> str:
        """Register a callable with mode-specific variants.

        Args:
            namespace: Module or globals dict to patch.
            name: Attribute name.
            variants: Mapping of mode → callable. Must include at least "full".

        Returns:
            Registration key.
        """
        if "full" not in variants:
            raise ValueError("variants must include a 'full' entry")

        key = f"adaptive:{_ns_label(namespace)}.{name}"
        slot = _AdaptiveSlot(
            name=name,
            namespace=namespace,
            namespace_kind="module" if isinstance(namespace, types.ModuleType) else "globals",
            variants=dict(variants),
            active_mode="",
            blend_key="",
        )
        with self._lock:
            self._swap_registry[key] = slot
            self._apply_mode_to_slot(slot, self._mode)
        return key

    def update_metrics(self, **kwargs: float) -> None:
        """Feed in environment metrics. Keys can include:
        cpu_percent, memory_percent, network_latency_ms, frame_time_ms, etc.
        """
        with self._lock:
            self._metrics.update(kwargs)

    def adapt(self) -> str:
        """Re-evaluate the environment and switch modes if needed.

        Returns the newly selected mode.
        """
        with self._lock:
            mode = self._evaluate()
            if mode != self._mode:
                old = self._mode
                self._mode = mode
                logger.info("EnvironmentAdapter: mode %s → %s", old, mode)
                for slot in self._swap_registry.values():
                    self._apply_mode_to_slot(slot, mode)
        return mode

    @property
    def mode(self) -> str:
        return self._mode

    @property
    def metrics(self) -> Dict[str, float]:
        with self._lock:
            return dict(self._metrics)

    def _evaluate(self) -> str:
        """Determine mode from current metrics."""
        m = self._metrics
        cpu = m.get("cpu_percent", 0.0)
        mem = m.get("memory_percent", 0.0)
        latency = m.get("network_latency_ms", 0.0)
        frame_time = m.get("frame_time_ms", 0.0)

        # Under heavy load → eco mode
        if cpu > self._cpu_threshold or mem > self._memory_threshold:
            return self.Mode.ECO

        # High latency or slow frames → lightweight
        if latency > self._latency_threshold_ms or frame_time > self._frame_time_threshold_ms:
            return self.Mode.LIGHTWEIGHT

        return self.Mode.FULL

    def _apply_mode_to_slot(self, slot: "_AdaptiveSlot", mode: str) -> None:
        """Swap in the variant matching `mode`, falling back to 'full'."""
        if mode == slot.active_mode:
            return

        fn = slot.variants.get(mode) or slot.variants["full"]
        mirror = self._registry.mirror(fn, name=f"{slot.name}:{mode}")

        # Revert previous
        if slot.blend_key:
            try:
                self._blender.revert(slot.blend_key)
            except BlendError:
                pass

        if slot.namespace_kind == "module":
            slot.blend_key = self._blender.blend_into_module(
                slot.namespace, slot.name, mirror,
            )
        else:
            slot.blend_key = self._blender.blend_into_globals(
                slot.namespace, slot.name, mirror,
            )
        slot.active_mode = mode


@dataclass
class _AdaptiveSlot:
    name: str
    namespace: Any
    namespace_kind: str
    variants: Dict[str, Callable]
    active_mode: str
    blend_key: str


# ── Layer 3: Self-Upgrading ──────────────────────────────────────────────────

class HotUpgrader:
    """Hot-swap code into a running system with automatic rollback.

    Loads new Python code (from bytes or a file path), mirrors every callable
    with health-check hooks, and blends them into the target module. If anything
    goes wrong, `rollback()` restores the previous version instantly.

    Integrates with JumpSession: when a session arrives containing Python files,
    the upgrader can apply them as live patches.

    Usage:
        upgrader = HotUpgrader(registry, blender)
        upgrader.apply_upgrade(new_code_bytes, target_module)
        # If something breaks:
        upgrader.rollback()
    """

    # Modules and builtins that upgrade code must not use
    _BLOCKED_IMPORTS = frozenset({
        "os", "subprocess", "sys", "shutil", "socket", "ctypes",
        "signal", "pathlib", "io", "tempfile",
    })
    _BLOCKED_CALLS = frozenset({
        "exec", "eval", "__import__", "compile", "open",
        "getattr", "setattr", "delattr", "globals", "locals",
    })

    def __init__(self, registry: MirrorRegistry, blender: Blender) -> None:
        self._registry = registry
        self._blender = blender
        self._version_stack: List[_UpgradeRecord] = []
        self._lock = threading.Lock()

    @classmethod
    def _validate_code(cls, code_bytes: bytes, source_path: str = "<upgrade>") -> None:
        """Validate upgrade code via AST inspection. Raises ValueError on violations."""
        try:
            tree = ast.parse(code_bytes, filename=source_path)
        except SyntaxError as e:
            raise ValueError(f"Upgrade code has syntax error: {e}") from e

        for node in ast.walk(tree):
            # Block dangerous imports
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root_module = alias.name.split(".")[0]
                    if root_module in cls._BLOCKED_IMPORTS:
                        raise ValueError(
                            f"Upgrade code imports blocked module: {alias.name}"
                        )
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    root_module = node.module.split(".")[0]
                    if root_module in cls._BLOCKED_IMPORTS:
                        raise ValueError(
                            f"Upgrade code imports from blocked module: {node.module}"
                        )
            # Block dangerous function calls
            elif isinstance(node, ast.Call):
                func = node.func
                name = None
                if isinstance(func, ast.Name):
                    name = func.id
                elif isinstance(func, ast.Attribute):
                    name = func.attr
                if name in cls._BLOCKED_CALLS:
                    raise ValueError(
                        f"Upgrade code uses blocked call: {name}()"
                    )

    def apply_upgrade(
        self,
        source: bytes | str,
        target_module: types.ModuleType,
        *,
        health_check: Optional[Callable] = None,
        tag: str = "",
    ) -> int:
        """Load new code and hot-swap matching callables into target_module.

        Args:
            source: Python source as bytes, string, or a file path.
            target_module: The module whose functions will be replaced.
            health_check: Optional pre-hook applied to every swapped function.
                          Receives (fn, args, kwargs); raise to trigger rollback.
            tag: Human-readable label for this upgrade.

        Returns:
            Version index (for selective rollback).

        Raises:
            ValueError: If the code fails AST validation (blocked imports/calls).
        """
        if isinstance(source, (str, os.PathLike)):
            source_path = str(source)
            with open(source_path, "rb") as f:
                code_bytes = f.read()
        else:
            code_bytes = source
            source_path = "<upgrade>"

        # Validate code safety before execution
        self._validate_code(code_bytes, source_path)

        # Load into a sandboxed module
        spec = importlib.util.spec_from_loader("_upgrade_tmp", loader=None)
        new_mod = importlib.util.module_from_spec(spec)
        exec(compile(code_bytes, source_path, "exec"), new_mod.__dict__)

        keys: List[str] = []
        upgraded_names: List[str] = []

        with self._lock:
            for name in dir(new_mod):
                if name.startswith("_"):
                    continue
                new_obj = getattr(new_mod, name)
                if not callable(new_obj):
                    continue
                if not hasattr(target_module, name):
                    continue

                ver = len(self._version_stack)
                mirror = self._registry.mirror(
                    new_obj,
                    pre=health_check,
                    name=f"{target_module.__name__}.{name}:v{ver}",
                )
                blend_key = self._blender.blend_into_module(
                    target_module, name, mirror,
                    key=f"upgrade:v{ver}:{target_module.__name__}.{name}",
                )
                keys.append(blend_key)
                upgraded_names.append(name)

            record = _UpgradeRecord(
                version=len(self._version_stack),
                keys=keys,
                names=upgraded_names,
                tag=tag or f"v{len(self._version_stack)}",
                timestamp=time.monotonic(),
            )
            self._version_stack.append(record)

        logger.info(
            "HotUpgrader: applied %s — %d functions upgraded: %s",
            record.tag, len(keys), ", ".join(upgraded_names),
        )
        return record.version

    def apply_from_session(
        self,
        session: Any,
        target_module: types.ModuleType,
        *,
        file_filter: Optional[Callable[[str], bool]] = None,
        health_check: Optional[Callable] = None,
    ) -> List[int]:
        """Apply upgrades from a JumpSession's files dict.

        Looks for .py files in session.files, decodes them, and applies
        each as an upgrade to the target module.

        Args:
            session: A JumpSession with a `files` dict (path → base64 data).
            target_module: Module to patch.
            file_filter: Optional predicate on filename; defaults to *.py.
            health_check: Pre-hook for health checking.

        Returns:
            List of version indices for each applied upgrade.
        """
        versions = []
        for rel_path, b64data in session.files.items():
            if not rel_path.endswith(".py"):
                continue
            if file_filter and not file_filter(rel_path):
                continue

            code_bytes = base64.b64decode(b64data)
            ver = self.apply_upgrade(
                code_bytes, target_module,
                health_check=health_check,
                tag=f"session:{session.session_id}:{rel_path}",
            )
            versions.append(ver)

        return versions

    def rollback(self, version: Optional[int] = None) -> bool:
        """Roll back to a previous version.

        Args:
            version: Specific version to roll back. If None, rolls back the
                     most recent upgrade.

        Returns:
            True if rollback succeeded.
        """
        with self._lock:
            if not self._version_stack:
                return False

            if version is None:
                record = self._version_stack.pop()
            else:
                # Find and remove the specific version
                idx = None
                for i, rec in enumerate(self._version_stack):
                    if rec.version == version:
                        idx = i
                        break
                if idx is None:
                    return False
                record = self._version_stack.pop(idx)

            errors = []
            for key in record.keys:
                try:
                    self._blender.revert(key)
                except BlendError as e:
                    errors.append((key, e))

        if errors:
            logger.error("HotUpgrader: rollback %s had %d errors", record.tag, len(errors))
            return False

        logger.info("HotUpgrader: rolled back %s (%d functions)", record.tag, len(record.keys))
        return True

    def rollback_all(self) -> int:
        """Roll back all upgrades in reverse order. Returns count rolled back."""
        count = 0
        while self._version_stack:
            if self.rollback():
                count += 1
            else:
                break
        return count

    @property
    def version_count(self) -> int:
        return len(self._version_stack)

    @property
    def current_tag(self) -> str:
        if self._version_stack:
            return self._version_stack[-1].tag
        return "(original)"

    @property
    def history(self) -> List[str]:
        return [r.tag for r in self._version_stack]


@dataclass(slots=True)
class _UpgradeRecord:
    version: int
    keys: List[str]
    names: List[str]
    tag: str
    timestamp: float


# ── Layer 4: Autonomous Loop ─────────────────────────────────────────────────

class AutonomousLoop:
    """The feedback loop that ties self-healing, self-customizing, and
    self-upgrading into a single autonomous system.

    Runs as a background thread alongside the main application. Each tick:
      1. Collects health metrics (from InstrumentedRain, system stats, peers)
      2. Feeds them into EnvironmentAdapter for mode selection
      3. Checks for incoming upgrade sessions from peers
      4. Applies/reverts patches via HotUpgrader as needed
      5. Logs a summary

    Usage:
        loop = AutonomousLoop(registry, blender, node=jump_node)
        loop.start()
        # ... application runs ...
        loop.stop()
    """

    def __init__(
        self,
        registry: MirrorRegistry,
        blender: Blender,
        *,
        node: Optional[Any] = None,
        target_module: Optional[types.ModuleType] = None,
        tick_interval: float = 1.0,
    ) -> None:
        self.registry = registry
        self.blender = blender
        self.resilience = ResilienceManager(registry, blender)
        self.adapter = EnvironmentAdapter(registry, blender)
        self.upgrader = HotUpgrader(registry, blender)
        self.node = node
        self.target_module = target_module
        self._tick_interval = tick_interval
        self._running = False
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._tick_count = 0
        self._lock = threading.Lock()
        self._metrics_collectors: List[Callable[[], Dict[str, float]]] = []
        self._on_tick_callbacks: List[Callable[["AutonomousLoop"], None]] = []

    def add_metrics_collector(self, collector: Callable[[], Dict[str, float]]) -> None:
        """Register a function that returns metrics dict each tick."""
        self._metrics_collectors.append(collector)

    def add_on_tick(self, callback: Callable[["AutonomousLoop"], None]) -> None:
        """Register a callback invoked each tick after adaptation."""
        self._on_tick_callbacks.append(callback)

    def start(self) -> None:
        """Start the autonomous loop in a background thread."""
        if self._running:
            return
        self._running = True
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="autonomous")
        self._thread.start()
        logger.info("AutonomousLoop: started (interval=%.1fs)", self._tick_interval)

    def stop(self) -> None:
        """Stop the loop and clean up."""
        self._running = False
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=self._tick_interval * 3)
        logger.info("AutonomousLoop: stopped after %d ticks", self._tick_count)

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def tick_count(self) -> int:
        return self._tick_count

    @property
    def status(self) -> Dict[str, Any]:
        """Snapshot of the loop's current state."""
        return {
            "running": self._running,
            "tick_count": self._tick_count,
            "mode": self.adapter.mode,
            "metrics": self.adapter.metrics,
            "protections": self.resilience.protection_count,
            "total_failures": self.resilience.total_failures,
            "upgrade_version": self.upgrader.current_tag,
            "upgrade_history": self.upgrader.history,
            "mirrors": self.registry.mirror_count,
            "blends": self.blender.blend_count,
        }

    def _loop(self) -> None:
        while not self._stop_event.is_set():
            t0 = time.monotonic()
            try:
                self._tick()
            except Exception:
                logger.exception("AutonomousLoop: tick %d failed", self._tick_count)
            elapsed = time.monotonic() - t0
            sleep_time = self._tick_interval - elapsed
            if sleep_time > 0:
                # Interruptible wait — stop() wakes us immediately.
                self._stop_event.wait(sleep_time)

    def _tick(self) -> None:
        self._tick_count += 1

        # Phase 1: Collect metrics
        for collector in self._metrics_collectors:
            try:
                metrics = collector()
                self.adapter.update_metrics(**metrics)
            except Exception:
                logger.warning("AutonomousLoop: metrics collector failed", exc_info=True)

        # Phase 2: Adapt
        self.adapter.adapt()

        # Phase 3: Check for incoming upgrades from peers
        if self.node and self.target_module:
            self._check_for_upgrades()

        # Phase 4: Invoke tick callbacks
        for cb in self._on_tick_callbacks:
            try:
                cb(self)
            except Exception:
                logger.warning("AutonomousLoop: tick callback failed", exc_info=True)

    def _check_for_upgrades(self) -> None:
        """Process any sessions received by the JumpNode that contain code."""
        if not hasattr(self.node, "received_sessions"):
            return

        # Drain sessions thread-safely if the node has a lock
        lock = getattr(self.node, "_sessions_lock", None)
        if lock:
            with lock:
                pending = list(self.node.received_sessions)
                self.node.received_sessions.clear()
        else:
            pending = []
            while self.node.received_sessions:
                pending.append(self.node.received_sessions.pop(0))

        for session in pending:
            py_files = [f for f in session.files if f.endswith(".py")]
            if not py_files:
                continue

            logger.info(
                "AutonomousLoop: received upgrade session %s with %d Python files",
                session.session_id, len(py_files),
            )
            try:
                versions = self.upgrader.apply_from_session(
                    session, self.target_module,
                    health_check=self._upgrade_health_check,
                )
                logger.info(
                    "AutonomousLoop: applied %d upgrades from session %s",
                    len(versions), session.session_id,
                )
            except Exception:
                logger.exception(
                    "AutonomousLoop: failed to apply upgrade from session %s",
                    session.session_id,
                )

    @staticmethod
    def _upgrade_health_check(fn, args, kwargs):
        """Default health check for upgraded functions — just a pass-through.
        Override via subclass or by passing a custom health_check to the upgrader.
        """
        return None


# ── Utilities ────────────────────────────────────────────────────────────────

def _ns_label(namespace: Any) -> str:
    """Human-readable label for a namespace."""
    if isinstance(namespace, types.ModuleType):
        return namespace.__name__
    if isinstance(namespace, dict):
        return f"dict@{id(namespace):#x}"
    return repr(namespace)


def system_metrics() -> Dict[str, float]:
    """Collect basic system metrics. Works cross-platform without psutil."""
    metrics: Dict[str, float] = {}
    try:
        load = os.getloadavg()
        cpu_count = os.cpu_count() or 1
        metrics["cpu_percent"] = (load[0] / cpu_count) * 100.0
    except (OSError, AttributeError):
        pass

    try:
        with open("/proc/meminfo", "r") as f:
            lines = f.read()
        total = available = 0
        for line in lines.splitlines():
            if line.startswith("MemTotal:"):
                total = int(line.split()[1])
            elif line.startswith("MemAvailable:"):
                available = int(line.split()[1])
        if total > 0:
            metrics["memory_percent"] = ((total - available) / total) * 100.0
    except (OSError, ValueError):
        pass

    return metrics
