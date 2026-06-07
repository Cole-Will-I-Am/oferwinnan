"""
Node Manager — Real-time node health, task queuing, and campaign oversight.

Provides a central management interface for tracking registered nodes,
submitting and executing tasks against them, and grouping related
operations into named campaigns.
"""

from __future__ import annotations

import logging
import queue
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
    checks and AutonomousLoop for periodic health polling.
    """

    def __init__(
        self,
        local_node=None,               # JumpNode
        rbac=None,                      # Optional[RBACManager]
        autonomous=None,                # Optional[AutonomousLoop]
    ) -> None:
        self._local_node = local_node
        self._rbac = rbac
        self._autonomous = autonomous

        self._lock = threading.RLock()
        self._nodes: Dict[str, ManagedNode] = {}
        self._tasks: Dict[str, Task] = {}
        self._campaigns: Dict[str, Campaign] = {}

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
        return {
            "devices": [
                {"name": d.name, "address": d.address, "port": d.port}
                for d in devices
            ],
            "count": len(devices),
        }

    def _execute_upgrade(self, task: Task) -> dict:
        # Placeholder: upgrade execution depends on AutonomousLoop
        return {"status": "upgrade_requested"}

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

    def _health_tick(self, loop) -> None:
        """Called by AutonomousLoop on each tick to check node health."""
        stale_threshold = 30.0
        now = time.time()
        with self._lock:
            for node in self._nodes.values():
                if node.status == "online" and now - node.last_heartbeat > stale_threshold:
                    node.status = "degraded"
                    logger.warning("node %s degraded (no heartbeat)", node.node_id)

    # -- Task Queue ------------------------------------------------------------

    def submit_task(
        self,
        task_type: TaskType,
        target_node_id: str,
        params: Optional[dict] = None,
        max_retries: int = 0,
        priority: int = 5,
        auth_token: Optional[str] = None,
    ) -> Task:
        """Submit a task to the execution queue."""
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
        )
        with self._lock:
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

    def pause_campaign(self, campaign_id: str) -> None:
        with self._lock:
            campaign = self._campaigns.get(campaign_id)
            if campaign is None:
                raise ManagerError(f"unknown campaign: {campaign_id}")
            campaign.status = CampaignStatus.PAUSED

    def resume_campaign(self, campaign_id: str) -> None:
        with self._lock:
            campaign = self._campaigns.get(campaign_id)
            if campaign is None:
                raise ManagerError(f"unknown campaign: {campaign_id}")
            campaign.status = CampaignStatus.ACTIVE

    def stop_campaign(self, campaign_id: str) -> None:
        """Cancel all queued tasks and mark campaign completed."""
        with self._lock:
            campaign = self._campaigns.get(campaign_id)
            if campaign is None:
                raise ManagerError(f"unknown campaign: {campaign_id}")
            for tid in campaign.task_ids:
                self.cancel_task(tid)
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
