"""Tests for node_manager.py — Node registry, task queue, and campaigns."""

import socket
import threading
import time
import unittest

from matrix.node_manager import (
    NodeManager,
    ManagedNode,
    Task,
    TaskStatus,
    TaskType,
    Campaign,
    CampaignStatus,
    ManagerError,
)


def _safe_stop(mgr):
    """Stop a NodeManager, draining the PriorityQueue first to avoid
    TypeError when None is compared against queued Task objects."""
    while not mgr._task_queue.empty():
        try:
            mgr._task_queue.get_nowait()
        except Exception:
            break
    mgr.stop()


# ── ManagedNode data model ───────────────────────────────────────────────────

class TestManagedNode(unittest.TestCase):
    def setUp(self):
        self.node = ManagedNode(
            node_id="n1",
            node_name="alpha",
            address="10.0.0.1",
            port=47701,
        )

    def test_creation(self):
        self.assertEqual(self.node.node_id, "n1")
        self.assertEqual(self.node.node_name, "alpha")
        self.assertEqual(self.node.address, "10.0.0.1")
        self.assertEqual(self.node.port, 47701)
        self.assertEqual(self.node.status, "offline")

    def test_to_dict(self):
        d = self.node.to_dict()
        self.assertEqual(d["node_id"], "n1")
        self.assertEqual(d["node_name"], "alpha")
        self.assertEqual(d["address"], "10.0.0.1")
        self.assertEqual(d["port"], 47701)
        self.assertIn("task_count", d)
        self.assertEqual(d["task_count"], 0)

    def test_to_dict_task_count(self):
        self.node.task_history = ["t1", "t2", "t3"]
        d = self.node.to_dict()
        self.assertEqual(d["task_count"], 3)


# ── Task data model ──────────────────────────────────────────────────────────

class TestTask(unittest.TestCase):
    def setUp(self):
        self.task = Task(
            task_id="task-1",
            task_type=TaskType.JUMP,
            target_node_id="n1",
            priority=3,
            created_at=time.time(),
        )

    def test_creation(self):
        self.assertEqual(self.task.task_id, "task-1")
        self.assertEqual(self.task.task_type, TaskType.JUMP)
        self.assertEqual(self.task.status, TaskStatus.QUEUED)

    def test_to_dict(self):
        d = self.task.to_dict()
        self.assertEqual(d["task_id"], "task-1")
        self.assertEqual(d["task_type"], "jump")
        self.assertEqual(d["status"], "queued")

    def test_ordering_by_priority(self):
        high = Task(task_id="h", task_type=TaskType.JUMP,
                    target_node_id="n", priority=1)
        low = Task(task_id="l", task_type=TaskType.JUMP,
                   target_node_id="n", priority=10)
        self.assertTrue(high < low)
        self.assertFalse(low < high)

    def test_equal_priority_not_lt(self):
        a = Task(task_id="a", task_type=TaskType.JUMP,
                 target_node_id="n", priority=5)
        b = Task(task_id="b", task_type=TaskType.JUMP,
                 target_node_id="n", priority=5)
        self.assertFalse(a < b)
        self.assertFalse(b < a)


# ── Campaign data model ─────────────────────────────────────────────────────

class TestCampaign(unittest.TestCase):
    def setUp(self):
        self.campaign = Campaign(
            campaign_id="c1",
            name="recon",
            node_ids=["n1", "n2"],
            task_ids=["t1"],
            created_at=1700000000.0,
        )

    def test_creation(self):
        self.assertEqual(self.campaign.campaign_id, "c1")
        self.assertEqual(self.campaign.name, "recon")
        self.assertEqual(self.campaign.status, CampaignStatus.ACTIVE)

    def test_summary(self):
        s = self.campaign.summary()
        self.assertEqual(s["campaign_id"], "c1")
        self.assertEqual(s["name"], "recon")
        self.assertEqual(s["status"], "active")
        self.assertEqual(s["node_count"], 2)
        self.assertEqual(s["task_count"], 1)


# ── NodeManager: node registry ──────────────────────────────────────────────

class TestNodeManagerRegistry(unittest.TestCase):
    def setUp(self):
        self.mgr = NodeManager()

    def tearDown(self):
        _safe_stop(self.mgr)

    def test_register_node(self):
        node = self.mgr.register_node("n1", "alpha", "10.0.0.1", 47701)
        self.assertEqual(node.node_id, "n1")
        self.assertEqual(node.status, "online")

    def test_get_node(self):
        self.mgr.register_node("n1", "alpha", "10.0.0.1")
        node = self.mgr.get_node("n1")
        self.assertIsNotNone(node)
        self.assertEqual(node.node_name, "alpha")

    def test_get_node_missing(self):
        self.assertIsNone(self.mgr.get_node("nope"))

    def test_unregister_node(self):
        self.mgr.register_node("n1", "alpha", "10.0.0.1")
        self.mgr.unregister_node("n1")
        self.assertIsNone(self.mgr.get_node("n1"))

    def test_unregister_nonexistent_safe(self):
        self.mgr.unregister_node("no-such")  # should not raise

    def test_list_nodes_all(self):
        self.mgr.register_node("n1", "a", "10.0.0.1")
        self.mgr.register_node("n2", "b", "10.0.0.2")
        nodes = self.mgr.list_nodes()
        self.assertEqual(len(nodes), 2)

    def test_list_nodes_by_status(self):
        self.mgr.register_node("n1", "a", "10.0.0.1")
        self.mgr.register_node("n2", "b", "10.0.0.2")
        self.mgr.update_node_health("n2", "degraded")
        online = self.mgr.list_nodes(status="online")
        self.assertEqual(len(online), 1)
        self.assertEqual(online[0].node_id, "n1")

    def test_register_with_metadata(self):
        node = self.mgr.register_node("n1", "a", "10.0.0.1",
                                       metadata={"version": "2.0"})
        self.assertEqual(node.metadata["version"], "2.0")


# ── NodeManager: node health ─────────────────────────────────────────────────

class TestNodeManagerHealth(unittest.TestCase):
    def setUp(self):
        self.mgr = NodeManager()
        self.mgr.register_node("n1", "alpha", "10.0.0.1")

    def tearDown(self):
        _safe_stop(self.mgr)

    def test_update_node_health(self):
        self.mgr.update_node_health("n1", "degraded",
                                     path_health={"latency": 50})
        node = self.mgr.get_node("n1")
        self.assertEqual(node.status, "degraded")
        self.assertEqual(node.path_health["latency"], 50)

    def test_get_node_health(self):
        h = self.mgr.get_node_health("n1")
        self.assertEqual(h["node_id"], "n1")
        self.assertEqual(h["status"], "online")
        self.assertIn("age", h)

    def test_get_node_health_unknown(self):
        h = self.mgr.get_node_health("nope")
        self.assertIn("error", h)

    def test_health_tick_marks_stale_as_degraded(self):
        """Nodes with old heartbeats should be marked degraded."""
        node = self.mgr.get_node("n1")
        # Force heartbeat to be old
        node.last_heartbeat = time.time() - 60
        self.mgr._health_tick(None)  # loop arg unused in our test
        self.assertEqual(node.status, "degraded")

    def test_health_tick_does_not_degrade_fresh(self):
        node = self.mgr.get_node("n1")
        node.last_heartbeat = time.time()
        self.mgr._health_tick(None)
        self.assertEqual(node.status, "online")


# ── NodeManager: task queue ──────────────────────────────────────────────────

class TestNodeManagerTasks(unittest.TestCase):
    def setUp(self):
        self.mgr = NodeManager()
        self.mgr.register_node("n1", "alpha", "10.0.0.1")

    def tearDown(self):
        _safe_stop(self.mgr)

    def test_submit_task(self):
        task = self.mgr.submit_task(TaskType.DISCOVER, "n1")
        self.assertIsNotNone(task.task_id)
        self.assertEqual(task.task_type, TaskType.DISCOVER)
        self.assertEqual(task.status, TaskStatus.QUEUED)

    def test_get_task(self):
        task = self.mgr.submit_task(TaskType.DISCOVER, "n1")
        found = self.mgr.get_task(task.task_id)
        self.assertIsNotNone(found)
        self.assertEqual(found.task_id, task.task_id)

    def test_get_task_missing(self):
        self.assertIsNone(self.mgr.get_task("no-such-task"))

    def test_cancel_task(self):
        task = self.mgr.submit_task(TaskType.DISCOVER, "n1")
        result = self.mgr.cancel_task(task.task_id)
        self.assertTrue(result)
        self.assertEqual(task.status, TaskStatus.CANCELLED)

    def test_cancel_nonexistent_returns_false(self):
        self.assertFalse(self.mgr.cancel_task("nope"))

    def test_list_tasks_all(self):
        self.mgr.submit_task(TaskType.DISCOVER, "n1")
        self.mgr.submit_task(TaskType.UPGRADE, "n1")
        tasks = self.mgr.list_tasks()
        self.assertEqual(len(tasks), 2)

    def test_list_tasks_by_status(self):
        t1 = self.mgr.submit_task(TaskType.DISCOVER, "n1")
        self.mgr.submit_task(TaskType.UPGRADE, "n1")
        self.mgr.cancel_task(t1.task_id)
        cancelled = self.mgr.list_tasks(status=TaskStatus.CANCELLED)
        self.assertEqual(len(cancelled), 1)
        self.assertEqual(cancelled[0].task_id, t1.task_id)

    def test_submit_task_with_params(self):
        task = self.mgr.submit_task(
            TaskType.JUMP, "n1",
            params={"include_env": False},
            priority=1,
            max_retries=2,
        )
        self.assertEqual(task.params["include_env"], False)
        self.assertEqual(task.priority, 1)
        self.assertEqual(task.max_retries, 2)


# ── NodeManager: worker thread execution ─────────────────────────────────────

class TestNodeManagerWorker(unittest.TestCase):
    def setUp(self):
        self.mgr = NodeManager()
        self.mgr.register_node("n1", "alpha", "10.0.0.1")

    def tearDown(self):
        _safe_stop(self.mgr)

    def test_worker_executes_task(self):
        """Register a custom handler, submit a task, start worker, wait for completion."""
        results = []

        def custom_handler(task):
            results.append(task.task_id)
            return {"handled": True}

        self.mgr.register_handler(TaskType.CUSTOM, custom_handler)
        task = self.mgr.submit_task(TaskType.CUSTOM, "n1")
        self.mgr.start()
        # Wait for worker to process
        deadline = time.time() + 5.0
        while task.status == TaskStatus.QUEUED and time.time() < deadline:
            time.sleep(0.05)
        self.mgr.stop()

        self.assertEqual(task.status, TaskStatus.DONE)
        self.assertIn(task.task_id, results)
        self.assertEqual(task.result, {"handled": True})

    def test_task_failure_no_retry(self):
        """Task with no retries should end up FAILED."""
        def failing_handler(task):
            raise RuntimeError("boom")

        self.mgr.register_handler(TaskType.CUSTOM, failing_handler)
        task = self.mgr.submit_task(TaskType.CUSTOM, "n1", max_retries=0)
        self.mgr.start()
        deadline = time.time() + 5.0
        while task.status in (TaskStatus.QUEUED, TaskStatus.RUNNING) and time.time() < deadline:
            time.sleep(0.05)
        self.mgr.stop()

        self.assertEqual(task.status, TaskStatus.FAILED)
        self.assertIn("boom", task.error)

    def test_task_failure_with_retry(self):
        """Task should retry up to max_retries, then succeed or fail."""
        call_count = [0]

        def flaky_handler(task):
            call_count[0] += 1
            if call_count[0] < 3:
                raise RuntimeError("not yet")
            return {"ok": True}

        self.mgr.register_handler(TaskType.CUSTOM, flaky_handler)
        task = self.mgr.submit_task(TaskType.CUSTOM, "n1", max_retries=5)
        self.mgr.start()
        deadline = time.time() + 5.0
        while task.status in (TaskStatus.QUEUED, TaskStatus.RUNNING) and time.time() < deadline:
            time.sleep(0.05)
        self.mgr.stop()

        self.assertEqual(task.status, TaskStatus.DONE)
        self.assertGreaterEqual(call_count[0], 3)

    def test_no_handler_marks_failed(self):
        """Task type with no handler should be marked FAILED."""
        task = self.mgr.submit_task(TaskType.TERMINATE, "n1")
        self.mgr.start()
        deadline = time.time() + 5.0
        while task.status == TaskStatus.QUEUED and time.time() < deadline:
            time.sleep(0.05)
        self.mgr.stop()

        self.assertEqual(task.status, TaskStatus.FAILED)
        self.assertIn("no handler", task.error)

    def test_start_stop_idempotent(self):
        self.mgr.start()
        self.mgr.start()  # double start should not crash
        self.mgr.stop()
        self.mgr.stop()  # double stop should not crash


# ── NodeManager: campaigns ──────────────────────────────────────────────────

class TestNodeManagerCampaigns(unittest.TestCase):
    def setUp(self):
        self.mgr = NodeManager()
        self.mgr.register_node("n1", "alpha", "10.0.0.1")

    def tearDown(self):
        _safe_stop(self.mgr)

    def test_create_campaign(self):
        c = self.mgr.create_campaign("recon", node_ids=["n1"])
        self.assertEqual(c.name, "recon")
        self.assertEqual(c.status, CampaignStatus.ACTIVE)
        self.assertIn("n1", c.node_ids)

    def test_add_task_to_campaign(self):
        c = self.mgr.create_campaign("ops")
        task = self.mgr.submit_task(TaskType.DISCOVER, "n1")
        self.mgr.add_task_to_campaign(c.campaign_id, task.task_id)
        self.assertIn(task.task_id, c.task_ids)

    def test_add_task_unknown_campaign_raises(self):
        with self.assertRaises(ManagerError):
            self.mgr.add_task_to_campaign("no-such", "t1")

    def test_pause_campaign(self):
        c = self.mgr.create_campaign("ops")
        self.mgr.pause_campaign(c.campaign_id)
        self.assertEqual(c.status, CampaignStatus.PAUSED)

    def test_resume_campaign(self):
        c = self.mgr.create_campaign("ops")
        self.mgr.pause_campaign(c.campaign_id)
        self.mgr.resume_campaign(c.campaign_id)
        self.assertEqual(c.status, CampaignStatus.ACTIVE)

    def test_stop_campaign(self):
        c = self.mgr.create_campaign("ops")
        task = self.mgr.submit_task(TaskType.DISCOVER, "n1")
        self.mgr.add_task_to_campaign(c.campaign_id, task.task_id)
        self.mgr.stop_campaign(c.campaign_id)
        self.assertEqual(c.status, CampaignStatus.COMPLETED)
        self.assertEqual(task.status, TaskStatus.CANCELLED)

    def test_campaign_status(self):
        c = self.mgr.create_campaign("ops")
        task = self.mgr.submit_task(TaskType.DISCOVER, "n1")
        self.mgr.add_task_to_campaign(c.campaign_id, task.task_id)
        status = self.mgr.campaign_status(c.campaign_id)
        self.assertEqual(status["name"], "ops")
        self.assertIn("task_breakdown", status)
        self.assertEqual(status["task_breakdown"].get("queued", 0), 1)

    def test_campaign_status_unknown(self):
        status = self.mgr.campaign_status("nope")
        self.assertIn("error", status)

    def test_pause_unknown_raises(self):
        with self.assertRaises(ManagerError):
            self.mgr.pause_campaign("nope")

    def test_resume_unknown_raises(self):
        with self.assertRaises(ManagerError):
            self.mgr.resume_campaign("nope")

    def test_stop_unknown_raises(self):
        with self.assertRaises(ManagerError):
            self.mgr.stop_campaign("nope")

    def test_get_campaign(self):
        c = self.mgr.create_campaign("ops")
        found = self.mgr.get_campaign(c.campaign_id)
        self.assertEqual(found.name, "ops")

    def test_list_campaigns(self):
        self.mgr.create_campaign("a")
        self.mgr.create_campaign("b")
        all_c = self.mgr.list_campaigns()
        self.assertEqual(len(all_c), 2)

    def test_list_campaigns_by_status(self):
        c1 = self.mgr.create_campaign("a")
        self.mgr.create_campaign("b")
        self.mgr.pause_campaign(c1.campaign_id)
        paused = self.mgr.list_campaigns(status=CampaignStatus.PAUSED)
        self.assertEqual(len(paused), 1)
        self.assertEqual(paused[0].name, "a")


# ── NodeManager: aggregate status ────────────────────────────────────────────

class TestNodeManagerStatus(unittest.TestCase):
    def setUp(self):
        self.mgr = NodeManager()

    def tearDown(self):
        _safe_stop(self.mgr)

    def test_status_empty(self):
        s = self.mgr.status()
        self.assertEqual(s["node_count"], 0)
        self.assertEqual(s["task_total"], 0)
        self.assertEqual(s["campaign_count"], 0)
        self.assertFalse(s["worker_running"])

    def test_status_with_data(self):
        self.mgr.register_node("n1", "a", "10.0.0.1")
        self.mgr.submit_task(TaskType.DISCOVER, "n1")
        self.mgr.create_campaign("ops")
        s = self.mgr.status()
        self.assertEqual(s["node_count"], 1)
        self.assertEqual(s["task_total"], 1)
        self.assertEqual(s["campaign_count"], 1)


# ── NodeManager: register_handler ────────────────────────────────────────────

class TestNodeManagerCustomHandler(unittest.TestCase):
    def setUp(self):
        self.mgr = NodeManager()
        self.mgr.register_node("n1", "alpha", "10.0.0.1")

    def tearDown(self):
        _safe_stop(self.mgr)

    def test_register_and_invoke_custom_handler(self):
        invocations = []

        def sync_handler(task):
            invocations.append(task.params)
            return {"synced": True}

        self.mgr.register_handler(TaskType.SYNC, sync_handler)
        task = self.mgr.submit_task(TaskType.SYNC, "n1",
                                     params={"source": "db"})
        self.mgr.start()
        deadline = time.time() + 5.0
        while task.status in (TaskStatus.QUEUED, TaskStatus.RUNNING) and time.time() < deadline:
            time.sleep(0.05)
        self.mgr.stop()

        self.assertEqual(task.status, TaskStatus.DONE)
        self.assertEqual(len(invocations), 1)
        self.assertEqual(invocations[0]["source"], "db")

    def test_register_handler_replaces_default(self):
        """Registering a handler for an existing type replaces it."""
        def new_discover(task):
            return {"custom": True}

        self.mgr.register_handler(TaskType.DISCOVER, new_discover)
        task = self.mgr.submit_task(TaskType.DISCOVER, "n1")
        self.mgr.start()
        deadline = time.time() + 5.0
        while task.status in (TaskStatus.QUEUED, TaskStatus.RUNNING) and time.time() < deadline:
            time.sleep(0.05)
        self.mgr.stop()

        self.assertEqual(task.status, TaskStatus.DONE)
        self.assertEqual(task.result, {"custom": True})


# ── Closed-loop orchestration (upgrade wiring, campaign enforcement, healing) ─

def _wait_task(task, timeout=5.0):
    deadline = time.time() + timeout
    while task.status in (TaskStatus.QUEUED, TaskStatus.RUNNING) and time.time() < deadline:
        time.sleep(0.02)


class _FakeDevice:
    def __init__(self, device_id, name, address, port):
        self.device_id = device_id
        self.name = name
        self.address = address
        self.port = port


class _FakeLocalNode:
    """Stand-in JumpNode whose discovery returns a fixed device list."""

    def __init__(self, devices=()):
        self.devices = list(devices)

    def discover_targets(self):
        return list(self.devices)


class TestNodeManagerUpgrade(unittest.TestCase):
    """The UPGRADE handler must drive the AutonomousLoop's HotUpgrader."""

    def setUp(self):
        import types
        from matrix.mirror_blend import MirrorRegistry, Blender
        from matrix.autonomous import AutonomousLoop

        registry = MirrorRegistry()
        blender = Blender(registry)
        self.loop = AutonomousLoop(registry, blender)  # not started: no ticking
        self.target = types.ModuleType("_upgrade_target_test")
        self.target.greet = lambda: "old"
        self.loop.target_module = self.target
        self.mgr = NodeManager(autonomous=self.loop)
        self.mgr.register_node("n1", "alpha", "10.0.0.1")

    def tearDown(self):
        _safe_stop(self.mgr)
        self.loop.upgrader.rollback_all()

    def _run(self, params, **kwargs):
        task = self.mgr.submit_task(TaskType.UPGRADE, "n1", params=params, **kwargs)
        self.mgr.start()
        _wait_task(task)
        self.mgr.stop()
        return task

    def test_upgrade_applies_code_to_loop_target_module(self):
        task = self._run({"code": "def greet():\n    return 'new'\n"})
        self.assertEqual(task.status, TaskStatus.DONE)
        self.assertEqual(task.result["status"], "upgraded")
        self.assertEqual(self.target.greet(), "new")
        # Rollback restores the original
        self.assertTrue(self.loop.upgrader.rollback(task.result["version"]))
        self.assertEqual(self.target.greet(), "old")

    def test_upgrade_explicit_target_module(self):
        import sys
        sys.modules["_upgrade_target_test"] = self.target
        try:
            task = self._run({
                "code": "def greet():\n    return 'explicit'\n",
                "target_module": "_upgrade_target_test",
            })
            self.assertEqual(task.status, TaskStatus.DONE)
            self.assertEqual(self.target.greet(), "explicit")
        finally:
            sys.modules.pop("_upgrade_target_test", None)

    def test_upgrade_requires_code_param(self):
        task = self._run({})
        self.assertEqual(task.status, TaskStatus.FAILED)
        self.assertIn("code", task.error)

    def test_upgrade_blocked_code_fails_task(self):
        task = self._run({"code": "import os\ndef greet():\n    return 'evil'\n"})
        self.assertEqual(task.status, TaskStatus.FAILED)
        self.assertIn("blocked", task.error)
        self.assertEqual(self.target.greet(), "old")

    def test_upgrade_without_autonomous_fails(self):
        mgr = NodeManager()
        mgr.register_node("n1", "alpha", "10.0.0.1")
        task = mgr.submit_task(TaskType.UPGRADE, "n1", params={"code": "x = 1\n"})
        mgr.start()
        _wait_task(task)
        _safe_stop(mgr)
        self.assertEqual(task.status, TaskStatus.FAILED)
        self.assertIn("upgrader", task.error)


class TestCampaignEnforcement(unittest.TestCase):
    """Pause/stop must actually gate task execution, not just flip a flag."""

    def setUp(self):
        self.mgr = NodeManager(auto_heal=False)
        self.mgr.register_node("n1", "alpha", "10.0.0.1")
        self.ran = []
        self.mgr.register_handler(
            TaskType.CUSTOM,
            lambda t: (self.ran.append(t.task_id), {"ok": True})[1],
        )

    def tearDown(self):
        _safe_stop(self.mgr)

    def test_paused_campaign_parks_tasks_until_resume(self):
        c = self.mgr.create_campaign("c1")
        self.mgr.pause_campaign(c.campaign_id)
        task = self.mgr.submit_task(TaskType.CUSTOM, "n1", campaign_id=c.campaign_id)
        self.mgr.start()
        time.sleep(0.3)
        self.assertEqual(self.ran, [])                      # parked, not run
        self.assertEqual(task.status, TaskStatus.QUEUED)

        self.mgr.resume_campaign(c.campaign_id)
        _wait_task(task)
        self.assertEqual(task.status, TaskStatus.DONE)
        self.assertEqual(self.ran, [task.task_id])

    def test_stopped_campaign_cancels_parked_tasks(self):
        c = self.mgr.create_campaign("c1")
        self.mgr.pause_campaign(c.campaign_id)
        task = self.mgr.submit_task(TaskType.CUSTOM, "n1", campaign_id=c.campaign_id)
        self.mgr.start()
        time.sleep(0.3)
        self.mgr.stop_campaign(c.campaign_id)
        self.assertEqual(task.status, TaskStatus.CANCELLED)
        # Resuming a completed campaign must not resurrect cancelled tasks
        self.mgr.resume_campaign(c.campaign_id)
        time.sleep(0.2)
        self.assertEqual(self.ran, [])

    def test_cancelled_queued_task_is_not_executed(self):
        task = self.mgr.submit_task(TaskType.CUSTOM, "n1")
        self.mgr.cancel_task(task.task_id)
        self.mgr.start()
        time.sleep(0.3)
        self.assertEqual(self.ran, [])
        self.assertEqual(task.status, TaskStatus.CANCELLED)

    def test_submit_task_unknown_campaign_raises(self):
        with self.assertRaises(ManagerError):
            self.mgr.submit_task(TaskType.CUSTOM, "n1", campaign_id="nope")


class TestAutoHeal(unittest.TestCase):
    """_health_tick must close the loop: degrade → heal task → discovery
    result refreshes the registry."""

    def test_health_tick_queues_heal_task_once(self):
        mgr = NodeManager()
        node = mgr.register_node("n1", "alpha", "10.0.0.1")
        node.last_heartbeat = time.time() - 60
        mgr._health_tick(None)
        self.assertEqual(node.status, "degraded")
        heals = [t for t in mgr.list_tasks() if t.params.get("heal")]
        self.assertEqual(len(heals), 1)
        self.assertEqual(heals[0].task_type, TaskType.DISCOVER)
        self.assertEqual(heals[0].target_node_id, "n1")
        # Within the cooldown and with the heal still queued: no duplicate
        mgr._health_tick(None)
        heals = [t for t in mgr.list_tasks() if t.params.get("heal")]
        self.assertEqual(len(heals), 1)
        _safe_stop(mgr)

    def test_heal_tasks_live_in_auto_heal_campaign(self):
        mgr = NodeManager()
        node = mgr.register_node("n1", "alpha", "10.0.0.1")
        node.last_heartbeat = time.time() - 60
        mgr._health_tick(None)
        campaigns = [c for c in mgr.list_campaigns() if c.name == "auto-heal"]
        self.assertEqual(len(campaigns), 1)
        self.assertEqual(len(campaigns[0].task_ids), 1)
        self.assertIn("n1", campaigns[0].node_ids)
        _safe_stop(mgr)

    def test_auto_heal_disabled(self):
        mgr = NodeManager(auto_heal=False)
        node = mgr.register_node("n1", "alpha", "10.0.0.1")
        node.last_heartbeat = time.time() - 60
        mgr._health_tick(None)
        self.assertEqual(node.status, "degraded")
        self.assertEqual(mgr.list_tasks(), [])
        _safe_stop(mgr)

    def test_degraded_node_goes_offline(self):
        mgr = NodeManager(auto_heal=False)
        node = mgr.register_node("n1", "alpha", "10.0.0.1")
        node.last_heartbeat = time.time() - 60
        mgr._health_tick(None)
        self.assertEqual(node.status, "degraded")
        node.last_heartbeat = time.time() - 200       # past offline_threshold
        mgr._health_tick(None)
        self.assertEqual(node.status, "offline")
        _safe_stop(mgr)

    def test_discovery_refreshes_known_node(self):
        """End-to-end heal: degraded node found by discovery goes back online."""
        local = _FakeLocalNode([_FakeDevice("n1", "alpha", "10.0.0.1", 47701)])
        mgr = NodeManager(local_node=local, heal_cooldown=0.0)
        node = mgr.register_node("n1", "alpha", "10.0.0.1", 47701)
        node.last_heartbeat = time.time() - 60
        mgr._health_tick(None)                         # degrade + queue heal
        self.assertEqual(node.status, "degraded")
        heal = [t for t in mgr.list_tasks() if t.params.get("heal")][0]
        mgr.start()
        _wait_task(heal)
        _safe_stop(mgr)
        self.assertEqual(heal.status, TaskStatus.DONE)
        self.assertIn("n1", heal.result["refreshed_nodes"])
        self.assertEqual(node.status, "online")
        self.assertLess(time.time() - node.last_heartbeat, 5.0)

    def test_discovery_matches_by_address_when_id_differs(self):
        local = _FakeLocalNode([_FakeDevice("ephemeral-x25519", "alpha", "10.0.0.1", 47701)])
        mgr = NodeManager(local_node=local)
        node = mgr.register_node("n1", "alpha", "10.0.0.1", 47701)
        node.status = "degraded"
        task = mgr.submit_task(TaskType.DISCOVER, "n1")
        mgr.start()
        _wait_task(task)
        _safe_stop(mgr)
        self.assertEqual(task.status, TaskStatus.DONE)
        self.assertIn("n1", task.result["refreshed_nodes"])
        self.assertEqual(node.status, "online")


# ── NodeManager: active probing (#2 — give the intelligence real eyes) ────────

class TestNodeManagerProbing(unittest.TestCase):
    def setUp(self):
        # A real listening socket on loopback = a reachable target.
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(1)
        self._open_port = self._listener.getsockname()[1]
        # A separately-allocated-then-closed port = a refused (unreachable) target.
        tmp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tmp.bind(("127.0.0.1", 0))
        self._closed_port = tmp.getsockname()[1]
        tmp.close()

    def tearDown(self):
        self._listener.close()

    def test_tcp_probe_reachable(self):
        mgr = NodeManager(probe_timeout=1.0)
        reachable, latency = mgr._tcp_probe("127.0.0.1", self._open_port)
        self.assertTrue(reachable)
        self.assertIsNotNone(latency)
        self.assertGreaterEqual(latency, 0.0)

    def test_tcp_probe_unreachable(self):
        mgr = NodeManager(probe_timeout=1.0)
        reachable, latency = mgr._tcp_probe("127.0.0.1", self._closed_port)
        self.assertFalse(reachable)
        self.assertIsNone(latency)

    def test_recent_success_rate(self):
        mgr = NodeManager()
        node = mgr.register_node("n1", "alpha", "127.0.0.1", self._open_port)
        for tid, status in [("t1", TaskStatus.DONE), ("t2", TaskStatus.DONE),
                            ("t3", TaskStatus.FAILED), ("t4", TaskStatus.QUEUED)]:
            mgr._tasks[tid] = Task(task_id=tid, task_type=TaskType.JUMP,
                                   target_node_id="n1", status=status)
            node.task_history.append(tid)
        rate = mgr._recent_success_rate(node)
        # 2 done, 1 failed (queued is ignored) → 2/3
        self.assertEqual(rate["task_sample"], 3)
        self.assertAlmostEqual(rate["success_rate"], 0.667, places=2)
        _safe_stop(mgr)

    def test_recent_success_rate_no_finished_tasks(self):
        mgr = NodeManager()
        node = mgr.register_node("n1", "alpha", "127.0.0.1")
        rate = mgr._recent_success_rate(node)
        self.assertEqual(rate["task_sample"], 0)
        self.assertIsNone(rate["success_rate"])
        _safe_stop(mgr)

    def test_probe_node_writes_health_without_clobbering(self):
        mgr = NodeManager(probe_timeout=1.0)
        mgr.register_node("n1", "alpha", "127.0.0.1", self._open_port)
        mgr.update_node_health("n1", "online", path_health={"latency": 5})
        probe = mgr._probe_node("n1")
        self.assertTrue(probe["reachable"])
        node = mgr.get_node("n1")
        self.assertEqual(node.path_health["latency"], 5)        # not clobbered
        self.assertTrue(node.path_health["probe"]["reachable"])  # merged in
        _safe_stop(mgr)

    def test_probe_node_unknown_returns_none(self):
        mgr = NodeManager()
        self.assertIsNone(mgr._probe_node("nope"))
        _safe_stop(mgr)

    def test_evidence_promotes_unreachable_degraded_to_offline(self):
        # stale + repeatedly unreachable → offline before the 120s age timer.
        mgr = NodeManager(auto_heal=False, probe_enabled=True,
                          probe_timeout=1.0, probe_fail_threshold=2)
        node = mgr.register_node("n1", "alpha", "127.0.0.1", self._closed_port)
        node.last_heartbeat = time.time() - 60        # stale, but < offline_threshold
        mgr._health_tick(None)                         # → degraded, 1st failed probe
        self.assertEqual(node.status, "degraded")
        node.last_heartbeat = time.time() - 60         # still stale, still < 120s
        mgr._health_tick(None)                         # 2nd failed probe → offline
        self.assertEqual(node.status, "offline")
        _safe_stop(mgr)

    def test_reachable_probe_keeps_degraded_node(self):
        # A degraded (stale heartbeat) but still-reachable node is a network
        # flake, not a dead node — it must NOT be promoted to offline.
        mgr = NodeManager(auto_heal=False, probe_enabled=True, probe_timeout=1.0,
                          probe_fail_threshold=2)
        node = mgr.register_node("n1", "alpha", "127.0.0.1", self._open_port)
        node.last_heartbeat = time.time() - 60
        mgr._health_tick(None)
        mgr._health_tick(None)
        self.assertEqual(node.status, "degraded")
        _safe_stop(mgr)


if __name__ == "__main__":
    unittest.main()
