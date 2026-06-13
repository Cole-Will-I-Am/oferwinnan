"""
Node Manager — Real-time node health, task queuing, and campaign oversight.

Provides a central management interface for tracking registered nodes,
submitting and executing tasks against them, and grouping related
operations into named campaigns.
"""

from __future__ import annotations

import logging
import queue
import socket
import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

__all__ = [
    "NodeManager",
    "ManagedNode",
    "Task",
    "TaskStatus",
    "TaskType",
    "Campaign",
    "CampaignStatus",
    "ManagerError",
]


# -- Errors --------------------------------------------------------------------

class ManagerError(Exception):
    """Raised on management operation failure."""


class _StopSentinel:
    """Sentinel object for PriorityQueue that sorts before any Task."""

    def __lt__(self, other) -> bool:
        return True

    def __le__(self, other) -> bool:
        return True

    def __gt__(self, other) -> bool:
        return False

    def __ge__(self, other) -> bool:
        return isinstance(other, _StopSentinel)


_STOP = _StopSentinel()


# -- Enums ---------------------------------------------------------------------

class TaskStatus(Enum):
    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    CANCELLED = "cancelled"


class TaskType(Enum):
    JUMP = "jump"
    DISCOVER = "discover"
    UPGRADE = "upgrade"
    TERMINATE = "terminate"
    SYNC = "sync"
    RELAY = "relay"
    CUSTOM = "custom"


class CampaignStatus(Enum):
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"


# -- Data Models ---------------------------------------------------------------

@dataclass(slots=True)
class ManagedNode:
    """A registered node tracked by the manager."""

    node_id: str
    node_name: str
    address: str
    port: int
    status: str = "offline"               # online, offline, degraded
    last_heartbeat: float = 0.0
    path_health: dict = field(default_factory=dict)
    task_history: list = field(default_factory=list)  # task IDs
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "node_id": self.node_id,
            "node_name": self.node_name,
            "address": self.address,
            "port": self.port,
            "status": self.status,
            "last_heartbeat": self.last_heartbeat,
            "path_health": self.path_health,
            "task_count": len(self.task_history),
        }


@dataclass(slots=True)
class Task:
    """A queued or executed task."""

    task_id: str
    task_type: TaskType
    target_node_id: str
    status: TaskStatus = TaskStatus.QUEUED
    params: dict = field(default_factory=dict)
    result: Optional[dict] = None
    error: Optional[str] = None
    created_at: float = 0.0
    started_at: Optional[float] = None
    finished_at: Optional[float] = None
    retries: int = 0
    max_retries: int = 0
    priority: int = 5                     # lower = higher priority
    campaign_id: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "task_id": self.task_id,
            "task_type": self.task_type.value,
            "target_node_id": self.target_node_id,
            "status": self.status.value,
            "error": self.error,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "retries": self.retries,
            "campaign_id": self.campaign_id,
        }

    def __lt__(self, other: Task) -> bool:
        """Priority queue ordering (lower priority number = higher priority)."""
        return self.priority < other.priority


@dataclass(slots=True)
class Campaign:
    """A named group of related tasks and nodes."""

    campaign_id: str
    name: str
    status: CampaignStatus = CampaignStatus.ACTIVE
    node_ids: list = field(default_factory=list)
    task_ids: list = field(default_factory=list)
    created_at: float = 0.0
    metadata: dict = field(default_factory=dict)

    def summary(self) -> dict:
        return {
            "campaign_id": self.campaign_id,
            "name": self.name,
            "status": self.status.value,
            "node_count": len(self.node_ids),
            "task_count": len(self.task_ids),
            "created_at": self.created_at,
        }


# -- Node Manager --------------------------------------------------------------

class NodeManager:
    """Central management interface for nodes, tasks, and campaigns.

    Thread-safe.  Optionally integrates with RBACManager for permission
    checks and AutonomousLoop for periodic health polling, closed-loop
    healing (degraded nodes get auto-queued discovery tasks whose results
    refresh the registry), and hot code upgrades via the loop's HotUpgrader.
    """

    def __init__(
        self,
        local_node=None,               # JumpNode
        rbac=None,                      # Optional[RBACManager]
        autonomous=None,                # Optional[AutonomousLoop]
        *,
        auto_heal: bool = True,
        stale_threshold: float = 30.0,
        offline_threshold: float = 120.0,
        heal_cooldown: float = 30.0,
        probe_enabled: bool = False,
        probe_timeout: float = 2.0,
        probe_max_per_tick: int = 8,
        probe_fail_threshold: int = 2,
    ) -> None:
        self._local_node = local_node
        self._rbac = rbac
        self._autonomous = autonomous

        self._lock = threading.RLock()
        self._nodes: Dict[str, ManagedNode] = {}
        self._tasks: Dict[str, Task] = {}
        self._campaigns: Dict[str, Campaign] = {}

        # Closed-loop healing (driven by _health_tick)
        self._auto_heal = auto_heal
        self._stale_threshold = stale_threshold
        self._offline_threshold = offline_threshold
        self._heal_cooldown = heal_cooldown

        # Active probing (gives the health loop evidence, not just heartbeat age)
        self._probe_enabled = probe_enabled
        self._probe_timeout = probe_timeout
        self._probe_max_per_tick = probe_max_per_tick
        self._probe_fail_threshold = probe_fail_threshold
        self._probe_fails: Dict[str, int] = {}     # node_id → consecutive probe failures
        self._heal_campaign_id: Optional[str] = None
        self._heal_tasks: Dict[str, str] = {}      # node_id → last heal task_id
        self._heal_last: Dict[str, float] = {}     # node_id → last heal attempt ts

        # Tasks parked because their campaign is paused (campaign_id → tasks)
        self._deferred: Dict[str, List[Task]] = {}

        # Task execution
        self._task_queue: queue.PriorityQueue = queue.PriorityQueue()
        self._handlers: Dict[TaskType, Callable] = {
            TaskType.JUMP: self._execute_jump,
            TaskType.DISCOVER: self._execute_discover,
            TaskType.UPGRADE: self._execute_upgrade,
        }
        self._worker_running = False
        self._worker_thread: Optional[threading.Thread] = None

        # Register with AutonomousLoop if available
        if autonomous is not None and hasattr(autonomous, "add_on_tick"):
            autonomous.add_on_tick(self._health_tick)

    # -- Worker Thread ---------------------------------------------------------

    def start(self) -> None:
        """Start the background task worker."""
        if self._worker_running:
            return
        self._worker_running = True
        self._worker_thread = threading.Thread(
            target=self._worker_loop, daemon=True, name="node-manager-worker",
        )
        self._worker_thread.start()
        logger.info("node manager started")

    def stop(self) -> None:
        """Stop the background task worker."""
        self._worker_running = False
        # Unblock the queue with a sentinel that sorts before any Task
        try:
            self._task_queue.put_nowait(_STOP)
        except queue.Full:
            pass
        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=5.0)
        logger.info("node manager stopped")

    def _worker_loop(self) -> None:
        while self._worker_running:
            try:
                task = self._task_queue.get(timeout=1.0)
            except queue.Empty:
                continue
            if isinstance(task, _StopSentinel):
                break
            self._execute_task(task)

    def _execute_task(self, task: Task) -> None:
        # Tasks cancelled while still queued must not run.
        if task.status is TaskStatus.CANCELLED:
            return

        # Tasks in a paused campaign are parked until resume_campaign().
        if task.campaign_id is not None:
            with self._lock:
                campaign = self._campaigns.get(task.campaign_id)
                if campaign is not None and campaign.status is CampaignStatus.PAUSED:
                    self._deferred.setdefault(task.campaign_id, []).append(task)
                    return

        handler = self._handlers.get(task.task_type)
        if handler is None:
            task.status = TaskStatus.FAILED
            task.error = f"no handler for {task.task_type.value}"
            task.finished_at = time.time()
            return

        task.status = TaskStatus.RUNNING
        task.started_at = time.time()
        try:
            result = handler(task)
            task.status = TaskStatus.DONE
            task.result = result or {}
        except Exception as exc:
            task.retries += 1
            if task.retries <= task.max_retries:
                task.status = TaskStatus.QUEUED
                self._task_queue.put(task)
                logger.info("retrying task %s (%d/%d)",
                             task.task_id, task.retries, task.max_retries)
                return
            task.status = TaskStatus.FAILED
            task.error = str(exc)
        finally:
            task.finished_at = time.time()

        # Record in node history
        with self._lock:
            node = self._nodes.get(task.target_node_id)
            if node is not None:
                node.task_history.append(task.task_id)

    # -- Task Handlers ---------------------------------------------------------

    def _execute_jump(self, task: Task) -> dict:
        if self._local_node is None:
            raise ManagerError("no local node configured")
        target = self._resolve_target(task.target_node_id)
        if target is None:
            raise ManagerError(f"unknown target node: {task.target_node_id}")

        from matrix.device_discovery import Device, Transport
        device = Device(
            device_id=target.node_id,
            name=target.node_name,
            address=target.address,
            port=target.port,
            transport=Transport.WIFI,
        )
        success = self._local_node.jump(
            target=device,
            include_env=task.params.get("include_env", True),
            include_files=task.params.get("include_files"),
            extra_metadata=task.params.get("extra_metadata"),
        )
        return {"success": success}

    def _execute_discover(self, task: Task) -> dict:
        if self._local_node is None:
            raise ManagerError("no local node configured")
        devices = self._local_node.discover_targets()

        # Feed results back into the registry: a discovered device that matches
        # a registered node counts as a heartbeat. This is what closes the
        # auto-heal loop — a degraded node that answers discovery goes back
        # online.
        refreshed = []
        now = time.time()
        with self._lock:
            by_addr = {(n.address, n.port): n for n in self._nodes.values()}
            for d in devices:
                node = (self._nodes.get(getattr(d, "device_id", None))
                        or by_addr.get((d.address, d.port)))
                if node is not None:
                    node.status = "online"
                    node.last_heartbeat = now
                    refreshed.append(node.node_id)

        return {
            "devices": [
                {"name": d.name, "address": d.address, "port": d.port}
                for d in devices
            ],
            "count": len(devices),
            "refreshed_nodes": refreshed,
        }

    def _execute_upgrade(self, task: Task) -> dict:
        """Apply a hot code upgrade through the AutonomousLoop's HotUpgrader.

        Task params:
            code:          Python source as a string, or
            code_b64:      base64-encoded Python source, or
            code_path:     path to a .py file
            target_module: dotted module name (defaults to the loop's
                           ``target_module``)
            tag:           human-readable upgrade label

        The upgrader AST-validates the code (blocked imports/calls) before
        executing it; a validation failure fails the task.
        """
        upgrader = getattr(self._autonomous, "upgrader", None)
        if upgrader is None:
            raise ManagerError(
                "no upgrader available: NodeManager needs an AutonomousLoop"
            )

        params = task.params
        if "code" in params:
            source: Any = params["code"].encode("utf-8")
        elif "code_b64" in params:
            import base64
            source = base64.b64decode(params["code_b64"])
        elif "code_path" in params:
            source = params["code_path"]
        else:
            raise ManagerError(
                "upgrade task requires a 'code', 'code_b64', or 'code_path' param"
            )

        mod_name = params.get("target_module")
        if mod_name:
            import sys
            target_mod = sys.modules.get(mod_name)
            if target_mod is None:
                raise ManagerError(f"target module not loaded: {mod_name}")
        else:
            target_mod = getattr(self._autonomous, "target_module", None)
            if target_mod is None:
                raise ManagerError(
                    "no target module: pass params['target_module'] or set "
                    "AutonomousLoop.target_module"
                )

        tag = params.get("tag", f"task:{task.task_id[:8]}")
        version = upgrader.apply_upgrade(source, target_mod, tag=tag)
        return {
            "status": "upgraded",
            "version": version,
            "tag": tag,
            "module": target_mod.__name__,
        }

    def _resolve_target(self, node_id: str) -> Optional[ManagedNode]:
        with self._lock:
            return self._nodes.get(node_id)

    # -- Custom Handlers -------------------------------------------------------

    def register_handler(
        self,
        task_type: TaskType,
        handler: Callable[[Task], Optional[dict]],
    ) -> None:
        """Register a custom task handler."""
        self._handlers[task_type] = handler

    # -- Node Registry ---------------------------------------------------------

    def register_node(
        self,
        node_id: str,
        name: str,
        address: str,
        port: int = 47701,
        metadata: Optional[dict] = None,
    ) -> ManagedNode:
        """Register a node for management."""
        node = ManagedNode(
            node_id=node_id,
            node_name=name,
            address=address,
            port=port,
            status="online",
            last_heartbeat=time.time(),
            metadata=metadata or {},
        )
        with self._lock:
            self._nodes[node_id] = node
        logger.info("registered node %s (%s:%d)", name, address, port)
        return node

    def unregister_node(self, node_id: str) -> None:
        with self._lock:
            self._nodes.pop(node_id, None)

    def get_node(self, node_id: str) -> Optional[ManagedNode]:
        with self._lock:
            return self._nodes.get(node_id)

    def list_nodes(self, status: Optional[str] = None) -> List[ManagedNode]:
        with self._lock:
            nodes = list(self._nodes.values())
        if status is not None:
            nodes = [n for n in nodes if n.status == status]
        return nodes

    # -- Node Health -----------------------------------------------------------

    def update_node_health(
        self,
        node_id: str,
        status: str,
        path_health: Optional[dict] = None,
    ) -> None:
        with self._lock:
            node = self._nodes.get(node_id)
            if node is None:
                return
            node.status = status
            node.last_heartbeat = time.time()
            if status == "online":
                # Recovered via heartbeat — forget any prior probe-failure streak.
                self._probe_fails.pop(node_id, None)
            if path_health is not None:
                node.path_health = path_health

    def get_node_health(self, node_id: str) -> dict:
        with self._lock:
            node = self._nodes.get(node_id)
            if node is None:
                return {"error": "unknown node"}
            return {
                "node_id": node.node_id,
                "status": node.status,
                "last_heartbeat": node.last_heartbeat,
                "age": time.time() - node.last_heartbeat,
                "path_health": node.path_health,
            }

    def _tcp_probe(self, address: str, port: int) -> tuple[bool, Optional[float]]:
        """Measure TCP reachability and connect latency. Pure network I/O —
        MUST be called outside ``self._lock`` (a slow connect would otherwise
        stall every other manager operation)."""
        start = time.monotonic()
        try:
            with socket.create_connection((address, port), timeout=self._probe_timeout):
                return True, round((time.monotonic() - start) * 1000, 2)
        except OSError:
            return False, None

    def _recent_success_rate(self, node: ManagedNode, window: int = 20) -> dict:
        """Success rate over the node's most recent finished tasks. Resolves the
        task IDs in ``task_history`` against the task table. Hold ``self._lock``."""
        done = failed = 0
        for tid in node.task_history[-window:]:
            task = self._tasks.get(tid)
            if task is None:
                continue
            if task.status == TaskStatus.DONE:
                done += 1
            elif task.status == TaskStatus.FAILED:
                failed += 1
        total = done + failed
        return {
            "task_sample": total,
            "success_rate": round(done / total, 3) if total else None,
        }

    def _probe_node(self, node_id: str) -> Optional[dict]:
        """Probe a node's TCP reachability/latency and recent task success rate,
        recording the result under ``node.path_health['probe']``. The network
        probe runs outside the lock. Returns the probe dict, or None if the node
        is unknown."""
        with self._lock:
            node = self._nodes.get(node_id)
            if node is None:
                return None
            address, port = node.address, node.port
            rate = self._recent_success_rate(node)

        reachable, latency_ms = self._tcp_probe(address, port)
        probe = {
            "reachable": reachable,
            "latency_ms": latency_ms,
            "probed_at": time.time(),
            **rate,
        }

        with self._lock:
            node = self._nodes.get(node_id)
            if node is not None:
                # Merge under a sub-key so we don't clobber heartbeat-supplied
                # path_health that update_node_health() may have written.
                node.path_health = {**node.path_health, "probe": probe}
        return probe

    def _health_tick(self, loop) -> None:
        """Called by AutonomousLoop on each tick: age node health, probe degraded
        nodes for evidence, and queue auto-heal tasks (closed-loop healing)."""
        now = time.time()
        to_probe: List[str] = []
        with self._lock:
            for node in self._nodes.values():
                age = now - node.last_heartbeat
                if node.status == "online" and age > self._stale_threshold:
                    node.status = "degraded"
                    logger.warning("node %s degraded (no heartbeat)", node.node_id)
                elif node.status == "degraded" and age > self._offline_threshold:
                    node.status = "offline"
                    logger.warning("node %s offline (no heartbeat for %.0fs)",
                                   node.node_id, age)
                if node.status == "degraded":
                    to_probe.append(node.node_id)

        # Active probing runs OUTSIDE the lock (network I/O). Probe evidence lets
        # a degraded node that is also TCP-unreachable go offline before the blind
        # offline_threshold timer, and distinguishes a network flake (reachable
        # but heartbeat stale) from a dead node (unreachable).
        if self._probe_enabled:
            for node_id in to_probe[: self._probe_max_per_tick]:
                probe = self._probe_node(node_id)
                if not probe:
                    continue
                with self._lock:
                    if probe["reachable"]:
                        # A reachable probe clears the failure streak (flake, not death).
                        self._probe_fails.pop(node_id, None)
                        continue
                    fails = self._probe_fails.get(node_id, 0) + 1
                    self._probe_fails[node_id] = fails
                    node = self._nodes.get(node_id)
                    # Promote to offline only on sustained evidence: repeated probe
                    # failures AND a stale heartbeat. One dropped probe is a flake.
                    if (node is not None and node.status == "degraded"
                            and fails >= self._probe_fail_threshold
                            and time.time() - node.last_heartbeat > self._stale_threshold):
                        node.status = "offline"
                        self._probe_fails.pop(node_id, None)
                        logger.warning(
                            "node %s offline (%d consecutive failed probes, heartbeat stale)",
                            node_id, fails)

        # Re-collect degraded nodes for healing — statuses may have changed above.
        if self._auto_heal:
            with self._lock:
                to_heal = [n.node_id for n in self._nodes.values()
                           if n.status == "degraded"]
            for node_id in to_heal:
                self._maybe_submit_heal(node_id)

    def _maybe_submit_heal(self, node_id: str) -> None:
        """Queue a high-priority discovery task for a degraded node, at most
        once per heal_cooldown and never while a previous heal is in flight.

        Heal tasks are system-originated and bypass RBAC (there is no
        external principal); they live in a shared "auto-heal" campaign so
        they can be paused or stopped like any other work.
        """
        now = time.time()
        with self._lock:
            if now - self._heal_last.get(node_id, 0.0) < self._heal_cooldown:
                return
            prev = self._tasks.get(self._heal_tasks.get(node_id, ""))
            if prev is not None and prev.status in (TaskStatus.QUEUED, TaskStatus.RUNNING):
                return
            self._heal_last[node_id] = now

            campaign = self._campaigns.get(self._heal_campaign_id or "")
            if campaign is None:
                campaign = self.create_campaign("auto-heal", metadata={"system": True})
                self._heal_campaign_id = campaign.campaign_id

            task = Task(
                task_id=str(uuid.uuid4()),
                task_type=TaskType.DISCOVER,
                target_node_id=node_id,
                params={"heal": True},
                priority=1,
                created_at=now,
                campaign_id=campaign.campaign_id,
            )
            self._tasks[task.task_id] = task
            campaign.task_ids.append(task.task_id)
            if node_id not in campaign.node_ids:
                campaign.node_ids.append(node_id)
            self._heal_tasks[node_id] = task.task_id
        self._task_queue.put(task)
        logger.info("auto-heal: queued discovery for degraded node %s", node_id)

    # -- Task Queue ------------------------------------------------------------

    def submit_task(
        self,
        task_type: TaskType,
        target_node_id: str,
        params: Optional[dict] = None,
        max_retries: int = 0,
        priority: int = 5,
        auth_token: Optional[str] = None,
        campaign_id: Optional[str] = None,
    ) -> Task:
        """Submit a task to the execution queue.

        If `campaign_id` is given, the task joins that campaign and honours
        its pause/stop state.
        """
        # RBAC check — mandatory when RBAC is configured
        if self._rbac is not None:
            if auth_token is None:
                from matrix.rbac import AuthorizationError
                raise AuthorizationError(
                    "auth token required when RBAC is configured"
                )
            from matrix.rbac import Permission
            perm_map = {
                TaskType.JUMP: Permission.JUMP,
                TaskType.DISCOVER: Permission.DISCOVER,
                TaskType.UPGRADE: Permission.UPGRADE,
                TaskType.TERMINATE: Permission.TERMINATE,
                TaskType.SYNC: Permission.SYNC_DATA,
                TaskType.RELAY: Permission.RELAY,
            }
            perm = perm_map.get(task_type)
            if perm is not None:
                self._rbac.require_permission(auth_token, perm, target_node_id)

        task = Task(
            task_id=str(uuid.uuid4()),
            task_type=task_type,
            target_node_id=target_node_id,
            params=params or {},
            max_retries=max_retries,
            priority=priority,
            created_at=time.time(),
            campaign_id=campaign_id,
        )
        with self._lock:
            if campaign_id is not None:
                campaign = self._campaigns.get(campaign_id)
                if campaign is None:
                    raise ManagerError(f"unknown campaign: {campaign_id}")
                campaign.task_ids.append(task.task_id)
            self._tasks[task.task_id] = task
        self._task_queue.put(task)
        logger.info("queued task %s (%s → %s)",
                     task.task_id, task_type.value, target_node_id)
        return task

    def get_task(self, task_id: str) -> Optional[Task]:
        with self._lock:
            return self._tasks.get(task_id)

    def cancel_task(self, task_id: str) -> bool:
        with self._lock:
            task = self._tasks.get(task_id)
            if task is None:
                return False
            if task.status in (TaskStatus.QUEUED, TaskStatus.RUNNING):
                task.status = TaskStatus.CANCELLED
                task.finished_at = time.time()
                return True
            return False

    def list_tasks(
        self,
        status: Optional[TaskStatus] = None,
    ) -> List[Task]:
        with self._lock:
            tasks = list(self._tasks.values())
        if status is not None:
            tasks = [t for t in tasks if t.status == status]
        return tasks

    # -- Campaigns -------------------------------------------------------------

    def create_campaign(
        self,
        name: str,
        node_ids: Optional[List[str]] = None,
        metadata: Optional[dict] = None,
    ) -> Campaign:
        campaign = Campaign(
            campaign_id=str(uuid.uuid4()),
            name=name,
            node_ids=list(node_ids or []),
            created_at=time.time(),
            metadata=metadata or {},
        )
        with self._lock:
            self._campaigns[campaign.campaign_id] = campaign
        logger.info("created campaign %s (%s)", campaign.campaign_id, name)
        return campaign

    def add_task_to_campaign(
        self,
        campaign_id: str,
        task_id: str,
    ) -> None:
        with self._lock:
            campaign = self._campaigns.get(campaign_id)
            if campaign is None:
                raise ManagerError(f"unknown campaign: {campaign_id}")
            campaign.task_ids.append(task_id)
            task = self._tasks.get(task_id)
            if task is not None:
                task.campaign_id = campaign_id

    def pause_campaign(self, campaign_id: str) -> None:
        """Pause a campaign: its queued tasks are parked by the worker and
        held until resume_campaign()."""
        with self._lock:
            campaign = self._campaigns.get(campaign_id)
            if campaign is None:
                raise ManagerError(f"unknown campaign: {campaign_id}")
            campaign.status = CampaignStatus.PAUSED

    def resume_campaign(self, campaign_id: str) -> None:
        """Resume a paused campaign, re-enqueueing any parked tasks."""
        with self._lock:
            campaign = self._campaigns.get(campaign_id)
            if campaign is None:
                raise ManagerError(f"unknown campaign: {campaign_id}")
            campaign.status = CampaignStatus.ACTIVE
            parked = self._deferred.pop(campaign_id, [])
        for task in parked:
            self._task_queue.put(task)

    def stop_campaign(self, campaign_id: str) -> None:
        """Cancel all queued/parked tasks and mark campaign completed."""
        with self._lock:
            campaign = self._campaigns.get(campaign_id)
            if campaign is None:
                raise ManagerError(f"unknown campaign: {campaign_id}")
            for tid in campaign.task_ids:
                self.cancel_task(tid)
            self._deferred.pop(campaign_id, None)
            campaign.status = CampaignStatus.COMPLETED

    def campaign_status(self, campaign_id: str) -> dict:
        with self._lock:
            campaign = self._campaigns.get(campaign_id)
            if campaign is None:
                return {"error": "unknown campaign"}
            task_statuses = {}
            for tid in campaign.task_ids:
                task = self._tasks.get(tid)
                if task:
                    s = task.status.value
                    task_statuses[s] = task_statuses.get(s, 0) + 1
            return {
                **campaign.summary(),
                "task_breakdown": task_statuses,
            }

    def get_campaign(self, campaign_id: str) -> Optional[Campaign]:
        with self._lock:
            return self._campaigns.get(campaign_id)

    def list_campaigns(
        self,
        status: Optional[CampaignStatus] = None,
    ) -> List[Campaign]:
        with self._lock:
            campaigns = list(self._campaigns.values())
        if status is not None:
            campaigns = [c for c in campaigns if c.status == status]
        return campaigns

    # -- Aggregate Status ------------------------------------------------------

    def status(self) -> dict:
        """JSON-serializable aggregate overview."""
        with self._lock:
            nodes = [n.to_dict() for n in self._nodes.values()]
            tasks_by_status = {}
            for t in self._tasks.values():
                s = t.status.value
                tasks_by_status[s] = tasks_by_status.get(s, 0) + 1
            campaigns = [c.summary() for c in self._campaigns.values()]

        return {
            "nodes": nodes,
            "node_count": len(nodes),
            "tasks": tasks_by_status,
            "task_total": sum(tasks_by_status.values()),
            "campaigns": campaigns,
            "campaign_count": len(campaigns),
            "worker_running": self._worker_running,
        }
