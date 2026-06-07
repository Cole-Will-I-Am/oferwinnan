"""Tests for node_manager.py — Node registry, task queue, and campaigns."""

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


if __name__ == "__main__":
    unittest.main()
