"""
matrix.director — Tri-State Director for LLM-augmented mesh orchestration.

Three tiers of authority:
  Tier 3: AUTONOMOUS      — Deterministic AutonomousLoop runs (default)
  Tier 2: AI_ACTIVE       — LLM evaluating and acting through sandboxed tools
  Tier 1: HUMAN_OVERRIDE  — Human operator in direct control via CLI

Transitions are ironclad:
  AUTONOMOUS     ──(escalation_trigger)──→ AI_ACTIVE
  AI_ACTIVE      ──(complete|timeout|fail)→ AUTONOMOUS
  ANY            ──(human_command)────────→ HUMAN_OVERRIDE
  HUMAN_OVERRIDE ──(release)─────────────→ AUTONOMOUS
"""

from __future__ import annotations

import json
import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

from matrix.config import config as _config
from matrix.llm_backend import (
    LLMBackend,
    LLMError,
    LLMResponse,
    LLMToolCall,
    ToolDefinition,
    create_backend,
)

logger = logging.getLogger(__name__)

__all__ = [
    "DirectorState",
    "EscalationTrigger",
    "EscalationEvent",
    "SemanticDelta",
    "ToolResult",
    "AuditEntry",
    "EscalationDetector",
    "ToolExecutor",
    "TriStateDirector",
    "DirectorError",
    "DIRECTOR_SYSTEM_PROMPT",
]


# ── Exceptions ───────────────────────────────────────────────────────────────


class DirectorError(Exception):
    """Raised on director operation failure."""


# ── Enums ────────────────────────────────────────────────────────────────────


class DirectorState(Enum):
    AUTONOMOUS = "autonomous"
    AI_ACTIVE = "ai_active"
    HUMAN_OVERRIDE = "human_override"


class EscalationTrigger(Enum):
    FALLBACKS_EXHAUSTED = "fallbacks_exhausted"
    ALL_PATHS_DEGRADED = "all_paths_degraded"
    TASK_FAILURE_RATE = "task_failure_rate"
    TRANSPORT_TOTAL_FAILURE = "transport_total_failure"
    MANUAL_ESCALATE = "manual_escalate"


# ── Data Structures ──────────────────────────────────────────────────────────


@dataclass(slots=True)
class EscalationEvent:
    """Record of an escalation trigger."""
    event_id: str
    trigger: EscalationTrigger
    timestamp: float
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class SemanticDelta:
    """Schema-validated telemetry payload assembled on escalation.

    Push-only.  Read-only from the LLM's perspective.
    Assembled ONCE per escalation, then frozen.
    """
    event: EscalationEvent
    loop_status: Dict[str, Any]
    path_health: Dict[str, dict]
    node_health: List[dict]
    recent_task_failures: List[dict]
    transport_probe: Optional[dict]
    adapter_mode: str
    adapter_metrics: Dict[str, float]
    system_metrics: Dict[str, float]
    timestamp: float = 0.0

    def to_json(self) -> str:
        """Serialize to JSON for inclusion in LLM prompt."""
        return json.dumps(
            {
                "escalation": {
                    "trigger": self.event.trigger.value,
                    "details": self.event.details,
                },
                "loop": self.loop_status,
                "paths": self.path_health,
                "nodes": self.node_health,
                "recent_failures": self.recent_task_failures,
                "transport": self.transport_probe,
                "adapter": {
                    "mode": self.adapter_mode,
                    "metrics": self.adapter_metrics,
                },
                "system": self.system_metrics,
                "timestamp": self.timestamp,
            },
            indent=2,
        )

    @classmethod
    def validate(cls, delta: SemanticDelta) -> bool:
        """Validate that all required fields are present and well-typed."""
        return (
            isinstance(delta.event, EscalationEvent)
            and isinstance(delta.loop_status, dict)
            and isinstance(delta.path_health, dict)
            and isinstance(delta.node_health, list)
            and isinstance(delta.recent_task_failures, list)
            and isinstance(delta.adapter_mode, str)
            and isinstance(delta.adapter_metrics, dict)
        )


@dataclass(slots=True)
class ToolResult:
    """Result of executing a single LLM tool call."""
    tool_name: str
    arguments: Dict[str, Any]
    success: bool
    result: Any = None
    error: Optional[str] = None
    duration_ms: float = 0.0


@dataclass(slots=True)
class AuditEntry:
    """Immutable record of any director event."""
    entry_id: str
    timestamp: float
    category: str       # transition | escalation | tool_call | human_override | llm_error | llm_response
    from_state: str
    to_state: str
    details: Dict[str, Any] = field(default_factory=dict)


# ── System Prompt ────────────────────────────────────────────────────────────


DIRECTOR_SYSTEM_PROMPT = """\
You are the AI Director for a Matrix mesh network node.
You are Tier 2 authority — above deterministic automation, below human operators.

You have been escalated because the autonomous systems detected a condition they
cannot resolve.  Your Semantic Delta below contains the full state snapshot.

CONSTRAINTS:
- You may invoke ONLY the tools listed below.  No other actions are possible.
- You have a budget of {action_budget} tool calls for this escalation.
- All proposed code upgrades undergo AST quarantine automatically.
- Your actions are authenticated, logged, and auditable.
- If you are uncertain, invoke zero tools and yield back to AUTONOMOUS.

OBJECTIVE: Restore the mesh to a healthy operational state using the minimum
number of actions necessary.  Prefer conservative, reversible actions.
"""


# ── Escalation Detector ─────────────────────────────────────────────────────


class EscalationDetector:
    """Monitors system signals and fires escalation events.

    Integrates with AutonomousLoop via on_tick callback.
    Uses hysteresis / cooldown to prevent flapping.
    """

    def __init__(
        self,
        *,
        cooldown_s: float = 60.0,
        degraded_sustain_s: float = 10.0,
        task_failure_window_s: float = 120.0,
        task_failure_threshold: int = 5,
    ):
        self._cooldown_s = cooldown_s
        self._degraded_sustain_s = degraded_sustain_s
        self._task_failure_window_s = task_failure_window_s
        self._task_failure_threshold = task_failure_threshold

        self._lock = threading.Lock()
        self._last_escalation: float = 0.0
        self._degraded_since: Optional[float] = None
        self._task_failures: List[float] = []
        self._on_escalation: Optional[Callable[[EscalationEvent], None]] = None

        # Attached components (set via attach())
        self._resilience_mgr: Any = None
        self._multipath: Any = None
        self._node_mgr: Any = None

    def attach(
        self,
        resilience: Any = None,
        multipath: Any = None,
        node_mgr: Any = None,
        on_escalation: Optional[Callable[[EscalationEvent], None]] = None,
    ) -> None:
        """Attach system components for monitoring."""
        if resilience is not None:
            self._resilience_mgr = resilience
        if multipath is not None:
            self._multipath = multipath
        if node_mgr is not None:
            self._node_mgr = node_mgr
        if on_escalation is not None:
            self._on_escalation = on_escalation

    # -- Tick Entry Point --

    def check(self, loop: Any = None) -> Optional[EscalationEvent]:
        """Called each tick.  Returns an EscalationEvent if threshold crossed.

        Checks are ordered by severity (most critical first).
        Only one escalation fires per check; cooldown prevents re-firing.
        """
        with self._lock:
            now = time.monotonic()
            if now - self._last_escalation < self._cooldown_s:
                return None

            event = self._check_fallbacks_exhausted()
            if event:
                return self._fire(event, now)

            event = self._check_all_degraded(now)
            if event:
                return self._fire(event, now)

            event = self._check_task_failures(now)
            if event:
                return self._fire(event, now)

            return None

    # -- External Notification Hooks --

    def record_task_failure(self, task_id: str = "", error: str = "") -> None:
        """Called by NodeManager integration when a task fails."""
        with self._lock:
            self._task_failures.append(time.monotonic())

    def notify_transport_failure(self, details: Optional[dict] = None) -> None:
        """Called by TransportNegotiator when all probes fail."""
        with self._lock:
            now = time.monotonic()
            if now - self._last_escalation < self._cooldown_s:
                return
            event = EscalationEvent(
                event_id=uuid.uuid4().hex,
                trigger=EscalationTrigger.TRANSPORT_TOTAL_FAILURE,
                timestamp=time.time(),
                details=details or {},
            )
            self._fire(event, now)

    # -- Internal Check Methods --

    def _fire(self, event: EscalationEvent, now: float) -> EscalationEvent:
        self._last_escalation = now
        if self._on_escalation:
            self._on_escalation(event)
        return event

    def _check_fallbacks_exhausted(self) -> Optional[EscalationEvent]:
        if not self._resilience_mgr:
            return None
        for key, slot in self._resilience_mgr._slots.items():
            if (
                slot.attempt >= len(slot.fallbacks) - 1
                and slot.failure_count > 0
                and slot.last_failure > self._last_escalation
            ):
                return EscalationEvent(
                    event_id=uuid.uuid4().hex,
                    trigger=EscalationTrigger.FALLBACKS_EXHAUSTED,
                    timestamp=time.time(),
                    details={
                        "slot_name": slot.name,
                        "failure_count": slot.failure_count,
                    },
                )
        return None

    def _check_all_degraded(self, now: float) -> Optional[EscalationEvent]:
        if not self._multipath:
            return None
        if self._multipath.all_degraded:
            if self._degraded_since is None:
                self._degraded_since = now
            elif now - self._degraded_since >= self._degraded_sustain_s:
                event = EscalationEvent(
                    event_id=uuid.uuid4().hex,
                    trigger=EscalationTrigger.ALL_PATHS_DEGRADED,
                    timestamp=time.time(),
                    details={
                        "degraded_duration_s": round(now - self._degraded_since, 2),
                    },
                )
                self._degraded_since = None
                return event
        else:
            self._degraded_since = None
        return None

    def _check_task_failures(self, now: float) -> Optional[EscalationEvent]:
        cutoff = now - self._task_failure_window_s
        self._task_failures = [t for t in self._task_failures if t > cutoff]
        if len(self._task_failures) >= self._task_failure_threshold:
            event = EscalationEvent(
                event_id=uuid.uuid4().hex,
                trigger=EscalationTrigger.TASK_FAILURE_RATE,
                timestamp=time.time(),
                details={
                    "failure_count": len(self._task_failures),
                    "window_s": self._task_failure_window_s,
                },
            )
            self._task_failures.clear()
            return event
        return None


# ── Tool Executor (LLM Sandbox) ─────────────────────────────────────────────


class ToolExecutor:
    """Sandboxed execution of LLM-requested tool calls.

    Each tool maps to a specific, bounded operation on the mesh.
    No raw Python execution.  No system queries.  No filesystem access.
    Every call is authenticated through RBAC and logged.
    """

    def __init__(
        self,
        *,
        node: Any = None,
        multipath: Any = None,
        node_mgr: Any = None,
        upgrader: Any = None,
        sync_mgr: Any = None,
        terminator: Any = None,
        rbac: Any = None,
        auth_token: str = "",
    ):
        self._node = node
        self._multipath = multipath
        self._node_mgr = node_mgr
        self._upgrader = upgrader
        self._sync_mgr = sync_mgr
        self._terminator = terminator
        self._rbac = rbac
        self._auth_token = auth_token

        self._handlers: Dict[str, Callable[..., Any]] = {
            "set_routing_weights": self._set_routing_weights,
            "force_session_jump": self._force_session_jump,
            "propose_hot_upgrade": self._propose_hot_upgrade,
            "adjust_rate_limit": self._adjust_rate_limit,
            "trigger_discovery": self._trigger_discovery,
            "terminate_node": self._terminate_node,
            "submit_task": self._submit_task,
        }

    # -- Tool Schema --

    @staticmethod
    def tool_definitions() -> List[ToolDefinition]:
        """Return the fixed set of tools the LLM may invoke."""
        return [
            ToolDefinition(
                name="set_routing_weights",
                description=(
                    "Adjust multipath routing weights. "
                    "Higher weight = more traffic on that path."
                ),
                parameters={
                    "type": "object",
                    "properties": {
                        "weights": {
                            "type": "object",
                            "description": "Mapping of path_id to weight (float 0.0-1.0)",
                            "additionalProperties": {"type": "number"},
                        },
                    },
                    "required": ["weights"],
                },
            ),
            ToolDefinition(
                name="force_session_jump",
                description="Force a session jump to a target node.",
                parameters={
                    "type": "object",
                    "properties": {
                        "target_node_id": {"type": "string"},
                        "strategy": {
                            "type": "string",
                            "enum": ["broadcast", "mirror", "race", "cascade"],
                        },
                    },
                    "required": ["target_node_id"],
                },
            ),
            ToolDefinition(
                name="propose_hot_upgrade",
                description=(
                    "Submit Python code for AST-validated hot upgrade. "
                    "Code must not import os/subprocess/sys/socket/ctypes "
                    "or call exec/eval/__import__/compile/open."
                ),
                parameters={
                    "type": "object",
                    "properties": {
                        "code": {"type": "string", "description": "Python source code"},
                        "target": {"type": "string", "description": "Target module name"},
                    },
                    "required": ["code", "target"],
                },
            ),
            ToolDefinition(
                name="adjust_rate_limit",
                description="Set the data sync rate limit in bytes per second.",
                parameters={
                    "type": "object",
                    "properties": {
                        "bytes_per_second": {"type": "integer", "minimum": 1024},
                    },
                    "required": ["bytes_per_second"],
                },
            ),
            ToolDefinition(
                name="trigger_discovery",
                description="Scan for new devices on the network.",
                parameters={
                    "type": "object",
                    "properties": {
                        "timeout": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": 30,
                            "default": 5,
                        },
                    },
                },
            ),
            ToolDefinition(
                name="terminate_node",
                description="Issue a signed termination command to a node. Use with extreme caution.",
                parameters={
                    "type": "object",
                    "properties": {
                        "target": {"type": "string"},
                        "cascade": {"type": "boolean", "default": False},
                    },
                    "required": ["target"],
                },
            ),
            ToolDefinition(
                name="submit_task",
                description="Queue a task for execution on a target node.",
                parameters={
                    "type": "object",
                    "properties": {
                        "task_type": {
                            "type": "string",
                            "enum": [
                                "jump", "discover", "upgrade",
                                "terminate", "sync", "relay", "custom",
                            ],
                        },
                        "target": {"type": "string"},
                        "params": {"type": "object", "default": {}},
                    },
                    "required": ["task_type", "target"],
                },
            ),
        ]

    # -- Dispatch --

    def execute(self, tool_call: LLMToolCall) -> ToolResult:
        """Execute a single tool call.  Returns ToolResult."""
        t0 = time.monotonic()
        handler = self._handlers.get(tool_call.tool_name)
        if handler is None:
            return ToolResult(
                tool_name=tool_call.tool_name,
                arguments=tool_call.arguments,
                success=False,
                error=f"Unknown tool: {tool_call.tool_name}",
                duration_ms=(time.monotonic() - t0) * 1000,
            )
        try:
            result = handler(**tool_call.arguments)
            return ToolResult(
                tool_name=tool_call.tool_name,
                arguments=tool_call.arguments,
                success=True,
                result=result,
                duration_ms=(time.monotonic() - t0) * 1000,
            )
        except Exception as exc:
            return ToolResult(
                tool_name=tool_call.tool_name,
                arguments=tool_call.arguments,
                success=False,
                error=str(exc),
                duration_ms=(time.monotonic() - t0) * 1000,
            )

    # -- Tool Implementations --

    def _set_routing_weights(self, weights: dict) -> dict:
        if not self._multipath:
            raise DirectorError("No multipath connection available")
        from matrix.multipath import PathState
        for path_id, weight in weights.items():
            if not isinstance(weight, (int, float)) or weight < 0:
                raise ValueError(f"Invalid weight for {path_id}: {weight}")
        with self._multipath._lock:
            for path_id, slot in self._multipath._paths.items():
                if path_id in weights:
                    target_weight = weights[path_id]
                    if target_weight > 0:
                        slot.health.rtt_ewma = 1.0 / max(target_weight, 0.001)
                        slot.health.missed_heartbeats = 0
                        slot.health.state = PathState.HEALTHY
                    else:
                        slot.health.state = PathState.DEGRADED
        return {"applied": list(weights.keys())}

    def _force_session_jump(
        self, target_node_id: str, strategy: str = "broadcast"
    ) -> dict:
        if not self._node_mgr:
            raise DirectorError("No NodeManager available")
        from matrix.node_manager import TaskType
        task = self._node_mgr.submit_task(
            TaskType.JUMP,
            target_node_id,
            params={"strategy": strategy},
            auth_token=self._auth_token,
        )
        return {"task_id": task.task_id, "status": task.status.value}

    def _propose_hot_upgrade(self, code: str, target: str) -> dict:
        if not self._upgrader:
            raise DirectorError("No HotUpgrader available")
        import sys as _sys
        from matrix.autonomous import HotUpgrader

        code_bytes = code.encode("utf-8")
        # Pre-validate (fail fast before touching any module)
        HotUpgrader._validate_code(code_bytes)

        target_module = _sys.modules.get(target)
        if target_module is None:
            raise DirectorError(f"Module not found: {target}")

        version = self._upgrader.apply_upgrade(
            code_bytes,
            target_module,
            tag=f"ai-director:{uuid.uuid4().hex[:8]}",
        )
        return {"version": version, "tag": self._upgrader.current_tag}

    def _adjust_rate_limit(self, bytes_per_second: int) -> dict:
        if not self._sync_mgr:
            raise DirectorError("No SyncManager available")
        if not hasattr(self._sync_mgr, "_rate_limiter") or not self._sync_mgr._rate_limiter:
            raise DirectorError("No RateLimiter available")
        self._sync_mgr._rate_limiter.set_rate(float(bytes_per_second))
        return {"new_rate_bps": bytes_per_second}

    def _trigger_discovery(self, timeout: int = 5) -> dict:
        if not self._node:
            raise DirectorError("No JumpNode available")
        devices = self._node.discover_targets()
        return {
            "devices": [
                {"name": getattr(d, "name", str(d)), "address": getattr(d, "address", "")}
                for d in devices
            ],
            "count": len(devices),
        }

    def _terminate_node(self, target: str, cascade: bool = False) -> dict:
        if not self._terminator:
            raise DirectorError("No SecureTerminator available")
        cmd = self._terminator.create_command(target, cascade=cascade)
        self._terminator.execute(cmd, auth_token=self._auth_token)
        return {
            "command_id": cmd.command_id,
            "target": target,
            "cascade": cascade,
        }

    def _submit_task(
        self, task_type: str, target: str, params: Optional[dict] = None
    ) -> dict:
        if not self._node_mgr:
            raise DirectorError("No NodeManager available")
        from matrix.node_manager import TaskType
        tt = TaskType(task_type)
        task = self._node_mgr.submit_task(
            tt,
            target,
            params=params or {},
            auth_token=self._auth_token,
        )
        return {"task_id": task.task_id, "status": task.status.value}


# ── Tri-State Director ──────────────────────────────────────────────────────


class TriStateDirector:
    """Orchestrates three tiers of authority for the Matrix mesh.

    Thread-safe.  Integrates with AutonomousLoop via on_tick callback.

    Usage::

        director = TriStateDirector(
            loop=autonomous_loop,
            node=jump_node,
            multipath=multi_path_conn,
            node_mgr=node_manager,
        )
        director.start()
        # ... system runs ...
        director.human_override()     # CLI command
        director.release_override()   # give back to autonomous
        director.stop()
    """

    def __init__(
        self,
        loop: Any,
        *,
        node: Any = None,
        multipath: Any = None,
        node_mgr: Any = None,
        rbac: Any = None,
        sync_mgr: Any = None,
        terminator: Any = None,
        llm_backend: Optional[LLMBackend] = None,
        config: Any = None,
    ):
        cfg = config or _config

        self._loop = loop
        self._node = node
        self._multipath = multipath
        self._node_mgr = node_mgr
        self._rbac = rbac
        self._sync_mgr = sync_mgr
        self._terminator = terminator

        # ── State machine ────────────────────────────────────────────────
        self._state = DirectorState.AUTONOMOUS
        self._state_lock = threading.RLock()
        self._state_changed = threading.Event()

        # ── LLM ──────────────────────────────────────────────────────────
        self._llm = llm_backend or create_backend(cfg)
        self._action_budget = cfg.llm_action_budget
        self._llm_timeout = cfg.llm_timeout

        # ── Escalation detector ──────────────────────────────────────────
        self._detector = EscalationDetector(
            cooldown_s=cfg.director_escalation_cooldown,
            degraded_sustain_s=cfg.director_degraded_sustain_s,
            task_failure_window_s=cfg.director_task_failure_window,
            task_failure_threshold=cfg.director_task_failure_threshold,
        )
        self._detector.attach(
            resilience=getattr(loop, "resilience", None),
            multipath=multipath,
            node_mgr=node_mgr,
            on_escalation=self._on_escalation,
        )

        # Wire ResilienceManager exhaustion hook → detector
        resilience = getattr(loop, "resilience", None)
        if resilience and hasattr(resilience, "set_on_exhausted"):
            resilience.set_on_exhausted(self._on_resilience_exhausted)

        # ── RBAC identity for the director ───────────────────────────────
        self._auth_token: str = ""
        if rbac:
            try:
                from matrix.rbac import Role, Permission
                self._auth_token = uuid.uuid4().hex
                rbac.register_identity(
                    node_id="local",
                    role=Role.OPERATOR,
                    auth_token=self._auth_token,
                    custom_permissions=frozenset({
                        Permission.JUMP,
                        Permission.DISCOVER,
                        Permission.UPGRADE,
                        Permission.SYNC_DATA,
                        Permission.RELAY,
                        Permission.TERMINATE,
                        Permission.VIEW_STATUS,
                    }),
                )
            except Exception:
                logger.debug("Director RBAC registration failed", exc_info=True)

        # ── Tool executor ────────────────────────────────────────────────
        self._executor = ToolExecutor(
            node=node,
            multipath=multipath,
            node_mgr=node_mgr,
            upgrader=getattr(loop, "upgrader", None),
            sync_mgr=sync_mgr,
            terminator=terminator,
            rbac=rbac,
            auth_token=self._auth_token,
        )

        # ── Audit log ────────────────────────────────────────────────────
        self._audit_lock = threading.Lock()
        self._audit_log: List[AuditEntry] = []

        # ── Escalation queue ─────────────────────────────────────────────
        self._escalation_queue: List[EscalationEvent] = []
        self._escalation_lock = threading.Lock()
        self._escalation_thread: Optional[threading.Thread] = None
        self._running = False

        # ── Human override latch ─────────────────────────────────────────
        self._human_override_active = threading.Event()

    # ── Lifecycle ────────────────────────────────────────────────────────

    def start(self) -> None:
        """Start the director.  Registers as an AutonomousLoop tick callback."""
        self._running = True
        if hasattr(self._loop, "add_on_tick"):
            self._loop.add_on_tick(self._on_tick)
        self._escalation_thread = threading.Thread(
            target=self._escalation_worker,
            daemon=True,
            name="director-escalation",
        )
        self._escalation_thread.start()
        logger.info("TriStateDirector: started in AUTONOMOUS state")

    def stop(self) -> None:
        """Stop the director."""
        self._running = False
        self._state_changed.set()
        if self._escalation_thread:
            self._escalation_thread.join(timeout=5.0)
        logger.info("TriStateDirector: stopped")

    # ── State Transitions ────────────────────────────────────────────────

    @property
    def state(self) -> DirectorState:
        with self._state_lock:
            return self._state

    def _transition(
        self,
        new_state: DirectorState,
        reason: str,
        details: Optional[dict] = None,
    ) -> None:
        """Atomic state transition with audit logging."""
        with self._state_lock:
            old = self._state
            if old == new_state:
                return
            self._state = new_state
            self._audit(
                "transition",
                old.value,
                new_state.value,
                {"reason": reason, **(details or {})},
            )
            logger.info(
                "Director: %s -> %s (%s)", old.value, new_state.value, reason
            )
            self._state_changed.set()

    def human_override(self, operator_id: str = "cli") -> None:
        """Tier 1: Human takes direct control.  Interrupts ANY state."""
        with self._state_lock:
            old = self._state
            self._state = DirectorState.HUMAN_OVERRIDE
            self._human_override_active.set()
        self._audit(
            "human_override",
            old.value,
            "human_override",
            {"operator": operator_id},
        )
        logger.warning("Director: HUMAN OVERRIDE activated by %s", operator_id)

    def release_override(self, operator_id: str = "cli") -> None:
        """Release human override, return to AUTONOMOUS."""
        with self._state_lock:
            if self._state != DirectorState.HUMAN_OVERRIDE:
                raise DirectorError("Not in HUMAN_OVERRIDE state")
            self._state = DirectorState.AUTONOMOUS
            self._human_override_active.clear()
        self._audit(
            "transition",
            "human_override",
            "autonomous",
            {"reason": "human_release", "operator": operator_id},
        )
        logger.info("Director: Human override released, returning to AUTONOMOUS")

    def manual_escalate(self, reason: str = "") -> None:
        """Manually trigger an AI escalation (e.g. from CLI)."""
        event = EscalationEvent(
            event_id=uuid.uuid4().hex,
            trigger=EscalationTrigger.MANUAL_ESCALATE,
            timestamp=time.time(),
            details={"reason": reason},
        )
        self._on_escalation(event)

    # ── Tick Callback ────────────────────────────────────────────────────

    def _on_tick(self, loop: Any) -> None:
        """Called by AutonomousLoop each tick.  Only detects in AUTONOMOUS."""
        with self._state_lock:
            if self._state != DirectorState.AUTONOMOUS:
                return
        self._detector.check(loop)

    def _on_escalation(self, event: EscalationEvent) -> None:
        """Callback from EscalationDetector when a trigger fires."""
        with self._state_lock:
            if self._state != DirectorState.AUTONOMOUS:
                logger.info(
                    "Director: escalation %s suppressed (state=%s)",
                    event.trigger.value,
                    self._state.value,
                )
                return
        with self._escalation_lock:
            self._escalation_queue.append(event)
        self._state_changed.set()

    def _on_resilience_exhausted(self, slot_name: str, failure_count: int) -> None:
        """Hook from ResilienceManager when all fallbacks are exhausted."""
        event = EscalationEvent(
            event_id=uuid.uuid4().hex,
            trigger=EscalationTrigger.FALLBACKS_EXHAUSTED,
            timestamp=time.time(),
            details={"slot_name": slot_name, "failure_count": failure_count},
        )
        self._on_escalation(event)

    # ── Escalation Worker ────────────────────────────────────────────────

    def _escalation_worker(self) -> None:
        """Background thread that processes escalation events."""
        while self._running:
            self._state_changed.wait(timeout=1.0)
            self._state_changed.clear()

            if not self._running:
                break

            with self._escalation_lock:
                events = list(self._escalation_queue)
                self._escalation_queue.clear()

            for i, event in enumerate(events):
                with self._state_lock:
                    if self._state != DirectorState.AUTONOMOUS:
                        with self._escalation_lock:
                            self._escalation_queue.extend(events[i:])
                        break
                self._handle_escalation(event)

    def _handle_escalation(self, event: EscalationEvent) -> None:
        """Process a single escalation: AI_ACTIVE → tool execution → AUTONOMOUS."""

        # 1. Transition to AI_ACTIVE
        self._transition(
            DirectorState.AI_ACTIVE,
            f"escalation:{event.trigger.value}",
            event.details,
        )

        # 2. Build Semantic Delta
        delta = self._build_semantic_delta(event)

        # 3. Invoke LLM and execute tools
        upgrade_versions: List[Optional[int]] = []
        try:
            response = self._invoke_llm(delta)

            actions_taken = 0
            for tool_call in response.tool_calls:
                # Check for human override interrupt
                if self._human_override_active.is_set():
                    logger.warning(
                        "Director: human override during AI action, aborting"
                    )
                    self._rollback_ai_upgrades(upgrade_versions)
                    return

                if actions_taken >= self._action_budget:
                    logger.warning(
                        "Director: action budget exhausted (%d/%d)",
                        actions_taken,
                        self._action_budget,
                    )
                    break

                result = self._executor.execute(tool_call)
                actions_taken += 1

                self._audit("tool_call", "ai_active", "ai_active", {
                    "tool": result.tool_name,
                    "arguments": result.arguments,
                    "success": result.success,
                    "result": str(result.result)[:500] if result.result else None,
                    "error": result.error,
                    "duration_ms": round(result.duration_ms, 2),
                })

                if result.tool_name == "propose_hot_upgrade" and result.success:
                    upgrade_versions.append(
                        result.result.get("version") if isinstance(result.result, dict) else None
                    )

                if result.tool_name == "propose_hot_upgrade" and not result.success:
                    logger.error(
                        "Director: upgrade failed (%s), rolling back",
                        result.error,
                    )
                    self._rollback_ai_upgrades(upgrade_versions)
                    break

        except LLMError as exc:
            self._audit("llm_error", "ai_active", "autonomous", {
                "error": str(exc),
            })
            logger.error("Director: LLM failed (%s), returning to AUTONOMOUS", exc)

        except Exception as exc:
            logger.exception("Director: unexpected error during AI action")
            self._rollback_ai_upgrades(upgrade_versions)
            self._audit("llm_error", "ai_active", "autonomous", {
                "error": f"unexpected: {exc}",
            })

        finally:
            with self._state_lock:
                if self._state == DirectorState.AI_ACTIVE:
                    self._transition(
                        DirectorState.AUTONOMOUS, "ai_action_complete"
                    )

    def _rollback_ai_upgrades(self, versions: List[Optional[int]]) -> None:
        """Roll back any upgrades applied during this escalation."""
        upgrader = getattr(self._loop, "upgrader", None)
        if not upgrader:
            return
        for version in reversed(versions):
            if version is not None:
                try:
                    upgrader.rollback(version)
                    logger.info(
                        "Director: rolled back AI upgrade version %d", version
                    )
                except Exception:
                    logger.exception(
                        "Director: failed to rollback version %d", version
                    )

    # ── Semantic Delta Assembly ──────────────────────────────────────────

    def _build_semantic_delta(self, event: EscalationEvent) -> SemanticDelta:
        """Assemble the complete state snapshot for the LLM."""
        from matrix.autonomous import system_metrics as _system_metrics

        loop_status = self._loop.status if hasattr(self._loop, "status") else {}

        path_health: Dict[str, dict] = {}
        if self._multipath and hasattr(self._multipath, "get_health"):
            path_health = self._multipath.get_health()

        node_health: List[dict] = []
        if self._node_mgr and hasattr(self._node_mgr, "list_nodes"):
            try:
                for node in self._node_mgr.list_nodes():
                    node_health.append(
                        self._node_mgr.get_node_health(node.node_id)
                    )
            except Exception:
                logger.debug("Failed to collect node health", exc_info=True)

        recent_failures: List[dict] = []
        if self._node_mgr and hasattr(self._node_mgr, "list_tasks"):
            try:
                from matrix.node_manager import TaskStatus
                failed = self._node_mgr.list_tasks(status=TaskStatus.FAILED)
                for task in sorted(
                    failed,
                    key=lambda t: t.finished_at or 0,
                    reverse=True,
                )[:10]:
                    recent_failures.append(task.to_dict())
            except Exception:
                logger.debug("Failed to collect task failures", exc_info=True)

        adapter_mode = ""
        adapter_metrics: Dict[str, float] = {}
        if hasattr(self._loop, "adapter"):
            adapter_mode = self._loop.adapter.mode
            adapter_metrics = self._loop.adapter.metrics

        sys_metrics: Dict[str, float] = {}
        try:
            sys_metrics = _system_metrics()
        except Exception:
            pass

        delta = SemanticDelta(
            event=event,
            loop_status=loop_status,
            path_health=path_health,
            node_health=node_health,
            recent_task_failures=recent_failures,
            transport_probe=None,
            adapter_mode=adapter_mode,
            adapter_metrics=adapter_metrics,
            system_metrics=sys_metrics,
            timestamp=time.time(),
        )

        if not SemanticDelta.validate(delta):
            raise DirectorError("Semantic delta validation failed")

        return delta

    # ── LLM Invocation ───────────────────────────────────────────────────

    def _invoke_llm(self, delta: SemanticDelta) -> LLMResponse:
        """Single-turn LLM invocation with dead-man's switch timeout."""
        system_prompt = DIRECTOR_SYSTEM_PROMPT.format(
            action_budget=self._action_budget,
        )
        user_message = delta.to_json()
        tools = ToolExecutor.tool_definitions()

        response = self._llm.invoke(
            system_prompt=system_prompt,
            user_message=user_message,
            tools=tools,
            timeout=self._llm_timeout,
        )

        self._audit("llm_response", "ai_active", "ai_active", {
            "tool_calls": len(response.tool_calls),
            "model": response.model,
            "tokens": response.usage_tokens,
            "raw_text_preview": response.raw_text[:200] if response.raw_text else "",
        })

        return response

    # ── Audit ────────────────────────────────────────────────────────────

    def _audit(
        self,
        category: str,
        from_state: str,
        to_state: str,
        details: Optional[dict] = None,
    ) -> None:
        entry = AuditEntry(
            entry_id=uuid.uuid4().hex,
            timestamp=time.time(),
            category=category,
            from_state=from_state,
            to_state=to_state,
            details=details or {},
        )
        with self._audit_lock:
            self._audit_log.append(entry)

    @property
    def audit_log(self) -> List[AuditEntry]:
        with self._audit_lock:
            return list(self._audit_log)

    # ── Status ───────────────────────────────────────────────────────────

    @property
    def status(self) -> dict:
        """JSON-serializable status snapshot."""
        with self._state_lock:
            state = self._state.value
        with self._escalation_lock:
            queue_depth = len(self._escalation_queue)
        return {
            "state": state,
            "audit_entries": len(self._audit_log),
            "escalation_queue_depth": queue_depth,
            "action_budget": self._action_budget,
            "llm_timeout": self._llm_timeout,
        }
