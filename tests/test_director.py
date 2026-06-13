"""Tests for director.py — Tri-State Director, Escalation Detector, Tool Executor."""

import json
import threading
import time
import types
import unittest
from dataclasses import dataclass
from unittest.mock import MagicMock, patch

from matrix.mirror_blend import MirrorRegistry, Blender
from matrix.autonomous import (
    ResilienceManager,
    EnvironmentAdapter,
    HotUpgrader,
    AutonomousLoop,
)
from matrix.llm_backend import LLMResponse, LLMToolCall, LLMError, ToolDefinition
from matrix.director import (
    DirectorState,
    DirectorError,
    EscalationTrigger,
    EscalationEvent,
    SemanticDelta,
    ToolResult,
    AuditEntry,
    EscalationDetector,
    ToolExecutor,
    ContainmentPolicy,
    TriStateDirector,
    DIRECTOR_SYSTEM_PROMPT,
)


# ── Helpers ──────────────────────────────────────────────────────────────────


def _make_loop():
    """Create a minimal AutonomousLoop for testing."""
    registry = MirrorRegistry()
    blender = Blender(registry)
    loop = AutonomousLoop(registry, blender, tick_interval=60.0)
    return loop, registry, blender


def _make_event(trigger=EscalationTrigger.MANUAL_ESCALATE, details=None):
    return EscalationEvent(
        event_id="test-event-001",
        trigger=trigger,
        timestamp=time.time(),
        details=details or {},
    )


class _MockLLM:
    """Mock LLM backend that returns predetermined responses."""

    def __init__(self, tool_calls=None, raise_error=False):
        self.tool_calls = tool_calls or []
        self.raise_error = raise_error
        self.invoke_count = 0

    def invoke(self, system_prompt, user_message, tools, timeout=30.0):
        self.invoke_count += 1
        if self.raise_error:
            raise LLMError("mock LLM unreachable")
        return LLMResponse(
            tool_calls=self.tool_calls,
            raw_text="mock response",
            model="mock-model",
            usage_tokens=42,
        )


class _MockMultipath:
    """Mock MultiPathConnection."""

    def __init__(self, all_degraded=False):
        self._all_degraded = all_degraded
        self._lock = threading.RLock()
        self._paths = {}

    @property
    def all_degraded(self):
        return self._all_degraded

    def get_health(self):
        return {"mock_path": {"state": "degraded" if self._all_degraded else "healthy"}}


# ── DirectorState ────────────────────────────────────────────────────────────


class TestDirectorState(unittest.TestCase):
    def test_enum_values(self):
        self.assertEqual(DirectorState.AUTONOMOUS.value, "autonomous")
        self.assertEqual(DirectorState.AI_ACTIVE.value, "ai_active")
        self.assertEqual(DirectorState.HUMAN_OVERRIDE.value, "human_override")


class TestEscalationTrigger(unittest.TestCase):
    def test_enum_values(self):
        self.assertEqual(EscalationTrigger.FALLBACKS_EXHAUSTED.value, "fallbacks_exhausted")
        self.assertEqual(EscalationTrigger.ALL_PATHS_DEGRADED.value, "all_paths_degraded")
        self.assertEqual(EscalationTrigger.TASK_FAILURE_RATE.value, "task_failure_rate")
        self.assertEqual(EscalationTrigger.TRANSPORT_TOTAL_FAILURE.value, "transport_total_failure")
        self.assertEqual(EscalationTrigger.MANUAL_ESCALATE.value, "manual_escalate")


# ── SemanticDelta ────────────────────────────────────────────────────────────


class TestSemanticDelta(unittest.TestCase):
    def _make_delta(self):
        return SemanticDelta(
            event=_make_event(),
            loop_status={"running": True, "tick_count": 5},
            path_health={"tcp": {"state": "healthy"}},
            node_health=[{"node_id": "a", "status": "online"}],
            recent_task_failures=[],
            transport_probe=None,
            adapter_mode="full",
            adapter_metrics={"cpu_percent": 45.0},
            system_metrics={"cpu_percent": 45.0, "memory_percent": 60.0},
            timestamp=time.time(),
        )

    def test_to_json(self):
        delta = self._make_delta()
        j = delta.to_json()
        data = json.loads(j)
        self.assertEqual(data["escalation"]["trigger"], "manual_escalate")
        self.assertTrue(data["loop"]["running"])
        self.assertEqual(data["adapter"]["mode"], "full")

    def test_validate_good(self):
        delta = self._make_delta()
        self.assertTrue(SemanticDelta.validate(delta))

    def test_validate_bad_event(self):
        delta = self._make_delta()
        delta.event = "not an event"  # type: ignore
        self.assertFalse(SemanticDelta.validate(delta))

    def test_validate_bad_loop_status(self):
        delta = self._make_delta()
        delta.loop_status = "not a dict"  # type: ignore
        self.assertFalse(SemanticDelta.validate(delta))

    # ── trigger-aware evidence validation (#2) ──────────────────────────────

    def test_validate_for_trigger_manual_always_ok(self):
        delta = self._make_delta()  # MANUAL_ESCALATE, no special evidence needed
        ok, missing = SemanticDelta.validate_for_trigger(delta)
        self.assertTrue(ok)
        self.assertEqual(missing, [])

    def test_validate_for_trigger_transport_failure_needs_probe(self):
        delta = self._make_delta()
        delta.event = _make_event(EscalationTrigger.TRANSPORT_TOTAL_FAILURE)
        delta.transport_probe = None
        ok, missing = SemanticDelta.validate_for_trigger(delta)
        self.assertFalse(ok)
        self.assertIn("transport_probe", missing)
        # ...satisfied once a probe is present
        delta.transport_probe = {"all_degraded": True}
        ok, missing = SemanticDelta.validate_for_trigger(delta)
        self.assertTrue(ok)

    def test_validate_for_trigger_task_failure_needs_failures(self):
        delta = self._make_delta()
        delta.event = _make_event(EscalationTrigger.TASK_FAILURE_RATE)
        delta.recent_task_failures = []
        ok, missing = SemanticDelta.validate_for_trigger(delta)
        self.assertFalse(ok)
        self.assertIn("recent_task_failures", missing)

    def test_validate_for_trigger_all_paths_degraded_needs_path_health(self):
        delta = self._make_delta()
        delta.event = _make_event(EscalationTrigger.ALL_PATHS_DEGRADED)
        delta.path_health = {}
        ok, missing = SemanticDelta.validate_for_trigger(delta)
        self.assertFalse(ok)
        self.assertIn("path_health", missing)

    def test_validate_for_trigger_base_invalid(self):
        delta = self._make_delta()
        delta.event = "not an event"  # type: ignore
        ok, missing = SemanticDelta.validate_for_trigger(delta)
        self.assertFalse(ok)
        self.assertEqual(missing, ["base schema invalid"])


class TestTransportProbe(unittest.TestCase):
    """_build_transport_probe summarizes MultiPath health for the LLM."""

    class _FakeMP:
        all_degraded = False

        def get_health(self):
            return {
                "p1": {"transport": "tcp", "state": "healthy"},
                "p2": {"transport": "websocket", "state": "degraded"},
            }

    def _probe(self, multipath, event):
        # Method only touches self._multipath, so a stub self suffices.
        from matrix.director import TriStateDirector
        return TriStateDirector._build_transport_probe(
            types.SimpleNamespace(_multipath=multipath), event)

    def test_summarizes_multipath_health(self):
        probe = self._probe(self._FakeMP(), _make_event())
        self.assertEqual(probe["paths_total"], 2)
        self.assertEqual(probe["paths_healthy"], 1)
        self.assertFalse(probe["all_degraded"])
        self.assertEqual(probe["transports"], ["tcp", "websocket"])

    def test_folds_in_transport_failure_details(self):
        event = _make_event(EscalationTrigger.TRANSPORT_TOTAL_FAILURE,
                            details={"errors": "all probes failed"})
        probe = self._probe(self._FakeMP(), event)
        self.assertEqual(probe["failure"], {"errors": "all probes failed"})

    def test_none_when_no_multipath_and_no_details(self):
        probe = self._probe(None, _make_event())
        self.assertIsNone(probe)


# ── AuditEntry ───────────────────────────────────────────────────────────────


class TestAuditEntry(unittest.TestCase):
    def test_creation(self):
        entry = AuditEntry(
            entry_id="abc",
            timestamp=123.0,
            category="transition",
            from_state="autonomous",
            to_state="ai_active",
            details={"reason": "test"},
        )
        self.assertEqual(entry.category, "transition")
        self.assertEqual(entry.details["reason"], "test")


# ── EscalationDetector ──────────────────────────────────────────────────────


class TestEscalationDetector(unittest.TestCase):
    def test_no_components_returns_none(self):
        det = EscalationDetector(cooldown_s=0)
        result = det.check()
        self.assertIsNone(result)

    def test_cooldown_prevents_refire(self):
        fired = []
        det = EscalationDetector(cooldown_s=999, task_failure_threshold=1)
        det.attach(on_escalation=lambda e: fired.append(e))
        det.record_task_failure("t1", "err")
        det.check()
        self.assertEqual(len(fired), 1)
        # Second check within cooldown should not fire
        det.record_task_failure("t2", "err")
        result = det.check()
        self.assertIsNone(result)

    def test_task_failure_rate_trigger(self):
        fired = []
        det = EscalationDetector(
            cooldown_s=0,
            task_failure_threshold=3,
            task_failure_window_s=60.0,
        )
        det.attach(on_escalation=lambda e: fired.append(e))
        det.record_task_failure("t1", "err1")
        det.record_task_failure("t2", "err2")
        # Below threshold
        result = det.check()
        self.assertIsNone(result)
        # At threshold
        det.record_task_failure("t3", "err3")
        result = det.check()
        self.assertIsNotNone(result)
        self.assertEqual(result.trigger, EscalationTrigger.TASK_FAILURE_RATE)

    def test_all_paths_degraded_needs_sustain(self):
        mp = _MockMultipath(all_degraded=True)
        det = EscalationDetector(cooldown_s=0, degraded_sustain_s=0.1)
        det.attach(multipath=mp)
        # First check sets the timestamp
        result = det.check()
        self.assertIsNone(result)
        # Wait for sustain period
        time.sleep(0.15)
        result = det.check()
        self.assertIsNotNone(result)
        self.assertEqual(result.trigger, EscalationTrigger.ALL_PATHS_DEGRADED)

    def test_degraded_resets_on_recovery(self):
        mp = _MockMultipath(all_degraded=True)
        det = EscalationDetector(cooldown_s=0, degraded_sustain_s=10.0)
        det.attach(multipath=mp)
        det.check()  # Sets timestamp
        # Recover
        mp._all_degraded = False
        det.check()  # Should reset
        # Degrade again
        mp._all_degraded = True
        result = det.check()
        self.assertIsNone(result)  # Fresh start, not sustained yet

    def test_fallbacks_exhausted(self):
        loop, registry, blender = _make_loop()
        rm = loop.resilience

        @dataclass
        class _FakeSlot:
            name: str = "test_fn"
            fallbacks: list = None
            attempt: int = 0
            failure_count: int = 3
            last_failure: float = 0.0
            blend_key: str = ""

            def __post_init__(self):
                if self.fallbacks is None:
                    self.fallbacks = [lambda: None]

        slot = _FakeSlot(last_failure=time.monotonic() + 1)
        rm._slots["key1"] = slot

        det = EscalationDetector(cooldown_s=0)
        det.attach(resilience=rm)
        result = det.check()
        self.assertIsNotNone(result)
        self.assertEqual(result.trigger, EscalationTrigger.FALLBACKS_EXHAUSTED)

    def test_transport_failure_notification(self):
        fired = []
        det = EscalationDetector(cooldown_s=0)
        det.attach(on_escalation=lambda e: fired.append(e))
        det.notify_transport_failure({"reason": "all probes failed"})
        self.assertEqual(len(fired), 1)
        self.assertEqual(fired[0].trigger, EscalationTrigger.TRANSPORT_TOTAL_FAILURE)

    def test_transport_failure_respects_cooldown(self):
        fired = []
        det = EscalationDetector(cooldown_s=999)
        det.attach(on_escalation=lambda e: fired.append(e))
        det.notify_transport_failure()
        self.assertEqual(len(fired), 1)
        det.notify_transport_failure()
        self.assertEqual(len(fired), 1)  # Suppressed by cooldown


# ── ToolExecutor ─────────────────────────────────────────────────────────────


class TestToolExecutor(unittest.TestCase):
    def test_unknown_tool_rejected(self):
        executor = ToolExecutor()
        tc = LLMToolCall(tool_name="hack_mainframe", arguments={})
        result = executor.execute(tc)
        self.assertFalse(result.success)
        self.assertIn("Unknown tool", result.error)

    def test_tool_definitions_returns_seven(self):
        defs = ToolExecutor.tool_definitions()
        self.assertEqual(len(defs), 7)
        names = {d.name for d in defs}
        expected = {
            "set_routing_weights",
            "force_session_jump",
            "propose_hot_upgrade",
            "adjust_rate_limit",
            "trigger_discovery",
            "terminate_node",
            "submit_task",
        }
        self.assertEqual(names, expected)

    def test_trigger_discovery_no_node(self):
        executor = ToolExecutor()
        tc = LLMToolCall(tool_name="trigger_discovery", arguments={})
        result = executor.execute(tc)
        self.assertFalse(result.success)
        self.assertIn("No JumpNode", result.error)

    def test_adjust_rate_limit_no_sync_mgr(self):
        executor = ToolExecutor()
        tc = LLMToolCall(
            tool_name="adjust_rate_limit",
            arguments={"bytes_per_second": 4096},
        )
        result = executor.execute(tc)
        self.assertFalse(result.success)

    def test_set_routing_weights_no_multipath(self):
        executor = ToolExecutor()
        tc = LLMToolCall(
            tool_name="set_routing_weights",
            arguments={"weights": {"tcp": 0.5}},
        )
        result = executor.execute(tc)
        self.assertFalse(result.success)

    def test_propose_hot_upgrade_no_upgrader(self):
        executor = ToolExecutor()
        tc = LLMToolCall(
            tool_name="propose_hot_upgrade",
            arguments={"code": "def foo(): pass", "target": "matrix.config"},
        )
        result = executor.execute(tc)
        self.assertFalse(result.success)

    def test_propose_hot_upgrade_blocked_import(self):
        """AST quarantine should block dangerous imports."""
        loop, _, _ = _make_loop()
        executor = ToolExecutor(upgrader=loop.upgrader)
        tc = LLMToolCall(
            tool_name="propose_hot_upgrade",
            arguments={
                "code": "import os\ndef hack(): os.system('rm -rf /')",
                "target": "matrix.config",
            },
        )
        result = executor.execute(tc)
        self.assertFalse(result.success)
        self.assertIn("os", result.error)

    def test_propose_hot_upgrade_blocked_call(self):
        """AST quarantine should block dangerous calls."""
        loop, _, _ = _make_loop()
        executor = ToolExecutor(upgrader=loop.upgrader)
        tc = LLMToolCall(
            tool_name="propose_hot_upgrade",
            arguments={
                "code": "def hack(): eval('bad')",
                "target": "matrix.config",
            },
        )
        result = executor.execute(tc)
        self.assertFalse(result.success)
        self.assertIn("eval", result.error)

    def test_terminate_node_no_terminator(self):
        executor = ToolExecutor()
        tc = LLMToolCall(
            tool_name="terminate_node",
            arguments={"target": "node-1"},
        )
        result = executor.execute(tc)
        self.assertFalse(result.success)

    def test_submit_task_no_node_mgr(self):
        executor = ToolExecutor()
        tc = LLMToolCall(
            tool_name="submit_task",
            arguments={"task_type": "discover", "target": "node-1"},
        )
        result = executor.execute(tc)
        self.assertFalse(result.success)

    def test_force_session_jump_no_node_mgr(self):
        executor = ToolExecutor()
        tc = LLMToolCall(
            tool_name="force_session_jump",
            arguments={"target_node_id": "node-1"},
        )
        result = executor.execute(tc)
        self.assertFalse(result.success)

    def test_tool_result_tracks_duration(self):
        executor = ToolExecutor()
        tc = LLMToolCall(tool_name="trigger_discovery", arguments={})
        result = executor.execute(tc)
        self.assertGreaterEqual(result.duration_ms, 0)

    def test_trigger_discovery_with_mock_node(self):
        """Discovery works with a mock node that returns devices."""
        mock_node = MagicMock()
        mock_dev = MagicMock()
        mock_dev.name = "laptop"
        mock_dev.address = "192.168.1.2"
        mock_node.discover_targets.return_value = [mock_dev]

        executor = ToolExecutor(node=mock_node)
        tc = LLMToolCall(tool_name="trigger_discovery", arguments={"timeout": 5})
        result = executor.execute(tc)
        self.assertTrue(result.success)
        self.assertEqual(result.result["count"], 1)
        self.assertEqual(result.result["devices"][0]["name"], "laptop")

    def test_adjust_rate_limit_with_mock(self):
        mock_sync = MagicMock()
        mock_sync._rate_limiter = MagicMock()
        executor = ToolExecutor(sync_mgr=mock_sync)
        tc = LLMToolCall(
            tool_name="adjust_rate_limit",
            arguments={"bytes_per_second": 8192},
        )
        result = executor.execute(tc)
        self.assertTrue(result.success)
        mock_sync._rate_limiter.set_rate.assert_called_once_with(8192.0)


# ── Containment Policy ──────────────────────────────────────────────────────


class TestContainmentPolicy(unittest.TestCase):
    def test_presets(self):
        unr = ContainmentPolicy.unrestricted()
        self.assertTrue(unr.invoke_llm and unr.execute_tools)
        self.assertTrue(unr.allow_code_upgrade and unr.allow_termination)
        self.assertIn("propose_hot_upgrade", unr.allowed_tools)

        res = ContainmentPolicy.restricted()
        self.assertTrue(res.invoke_llm and res.execute_tools)
        self.assertFalse(res.allow_code_upgrade or res.allow_termination)
        self.assertNotIn("propose_hot_upgrade", res.allowed_tools)
        self.assertNotIn("terminate_node", res.allowed_tools)

        adv = ContainmentPolicy.advisory()
        self.assertTrue(adv.invoke_llm)
        self.assertFalse(adv.execute_tools)

        dis = ContainmentPolicy.disabled()
        self.assertFalse(dis.invoke_llm or dis.execute_tools)
        self.assertEqual(len(dis.allowed_tools), 0)

    def test_from_name_and_unknown(self):
        self.assertEqual(ContainmentPolicy.from_name("advisory").mode, "advisory")
        self.assertEqual(ContainmentPolicy.from_name(None).mode, "unrestricted")
        with self.assertRaises(DirectorError):
            ContainmentPolicy.from_name("nope")


class TestToolExecutorContainment(unittest.TestCase):
    def test_tool_definitions_filtered_by_policy(self):
        self.assertEqual(len(ToolExecutor.tool_definitions()), 7)
        self.assertEqual(
            len(ToolExecutor.tool_definitions(ContainmentPolicy.restricted())), 5)
        self.assertEqual(
            len(ToolExecutor.tool_definitions(ContainmentPolicy.disabled())), 0)

    def test_restricted_blocks_code_upgrade(self):
        ex = ToolExecutor(policy=ContainmentPolicy.restricted())
        r = ex.execute(LLMToolCall(tool_name="propose_hot_upgrade",
                                   arguments={"code": "x=1", "target": "m"}))
        self.assertFalse(r.success)
        self.assertIn("containment", r.error)

    def test_restricted_blocks_termination(self):
        ex = ToolExecutor(policy=ContainmentPolicy.restricted())
        r = ex.execute(LLMToolCall(tool_name="terminate_node",
                                   arguments={"target": "node-1"}))
        self.assertFalse(r.success)
        self.assertIn("containment", r.error)

    def test_restricted_blocks_submit_task_indirection(self):
        ex = ToolExecutor(policy=ContainmentPolicy.restricted())
        for dangerous in ("upgrade", "terminate"):
            r = ex.execute(LLMToolCall(
                tool_name="submit_task",
                arguments={"task_type": dangerous, "target": "n"}))
            self.assertFalse(r.success)
            self.assertIn("containment", r.error)

    def test_restricted_allows_safe_tool_through_to_handler(self):
        ex = ToolExecutor(policy=ContainmentPolicy.restricted())
        # Allowed by policy, then fails for lack of a NodeManager (not policy).
        r = ex.execute(LLMToolCall(
            tool_name="submit_task",
            arguments={"task_type": "discover", "target": "n"}))
        self.assertFalse(r.success)
        self.assertNotIn("containment", r.error)


class TestDirectorContainmentModes(unittest.TestCase):
    def test_advisory_records_but_does_not_execute(self):
        loop, _, _ = _make_loop()
        mock_llm = _MockLLM(tool_calls=[
            LLMToolCall(tool_name="terminate_node", arguments={"target": "n"}),
        ])
        director = TriStateDirector(loop, llm_backend=mock_llm,
                                    policy=ContainmentPolicy.advisory())
        director.start()
        try:
            director.manual_escalate(reason="advisory-test")
            time.sleep(0.5)
        finally:
            director.stop()

        self.assertGreaterEqual(mock_llm.invoke_count, 1)
        cats = [e.category for e in director.audit_log]
        self.assertIn("recommendation", cats)
        self.assertNotIn("tool_call", cats)  # nothing executed
        self.assertEqual(director.state, DirectorState.AUTONOMOUS)

    def test_disabled_never_invokes_llm(self):
        loop, _, _ = _make_loop()
        mock_llm = _MockLLM(tool_calls=[
            LLMToolCall(tool_name="trigger_discovery", arguments={}),
        ])
        director = TriStateDirector(loop, llm_backend=mock_llm,
                                    policy=ContainmentPolicy.disabled())
        director.start()
        try:
            director.manual_escalate(reason="disabled-test")
            time.sleep(0.5)
        finally:
            director.stop()

        self.assertEqual(mock_llm.invoke_count, 0)
        cats = [e.category for e in director.audit_log]
        self.assertIn("containment_blocked", cats)
        self.assertEqual(director.state, DirectorState.AUTONOMOUS)


# ── TriStateDirector — State Machine ────────────────────────────────────────


class TestTriStateDirectorFSM(unittest.TestCase):
    def setUp(self):
        self.loop, _, _ = _make_loop()
        self.mock_llm = _MockLLM()
        self.director = TriStateDirector(
            self.loop,
            llm_backend=self.mock_llm,
        )

    def tearDown(self):
        if self.director._running:
            self.director.stop()

    def test_initial_state_is_autonomous(self):
        self.assertEqual(self.director.state, DirectorState.AUTONOMOUS)

    def test_human_override(self):
        self.director.human_override("operator-1")
        self.assertEqual(self.director.state, DirectorState.HUMAN_OVERRIDE)

    def test_release_override(self):
        self.director.human_override()
        self.director.release_override()
        self.assertEqual(self.director.state, DirectorState.AUTONOMOUS)

    def test_release_without_override_raises(self):
        with self.assertRaises(DirectorError):
            self.director.release_override()

    def test_human_override_from_any_state(self):
        """Human override must work from AUTONOMOUS."""
        self.assertEqual(self.director.state, DirectorState.AUTONOMOUS)
        self.director.human_override()
        self.assertEqual(self.director.state, DirectorState.HUMAN_OVERRIDE)

    def test_status_snapshot(self):
        status = self.director.status
        self.assertEqual(status["state"], "autonomous")
        self.assertIn("audit_entries", status)
        self.assertIn("action_budget", status)
        self.assertIn("llm_timeout", status)
        self.assertIn("escalation_queue_depth", status)

    def test_audit_log_records_transitions(self):
        self.director.human_override("op1")
        self.director.release_override("op1")
        log = self.director.audit_log
        self.assertGreaterEqual(len(log), 2)
        categories = [e.category for e in log]
        self.assertIn("human_override", categories)
        self.assertIn("transition", categories)


# ── TriStateDirector — Escalation Flow ──────────────────────────────────────


class TestTriStateDirectorEscalation(unittest.TestCase):
    def setUp(self):
        self.loop, _, _ = _make_loop()
        self.mock_llm = _MockLLM(tool_calls=[
            LLMToolCall(tool_name="trigger_discovery", arguments={}),
        ])
        self.director = TriStateDirector(
            self.loop,
            llm_backend=self.mock_llm,
        )
        self.director.start()

    def tearDown(self):
        self.director.stop()

    def test_manual_escalate(self):
        """Manual escalation triggers LLM invocation."""
        self.director.manual_escalate(reason="test")
        # Wait for escalation worker to process
        time.sleep(0.5)
        self.assertGreaterEqual(self.mock_llm.invoke_count, 1)
        self.assertEqual(self.director.state, DirectorState.AUTONOMOUS)

    def test_escalation_returns_to_autonomous(self):
        self.director.manual_escalate()
        time.sleep(0.5)
        self.assertEqual(self.director.state, DirectorState.AUTONOMOUS)

    def test_escalation_suppressed_during_override(self):
        """Escalations should be suppressed when human override is active."""
        self.director.human_override()
        self.director.manual_escalate(reason="should be suppressed")
        time.sleep(0.3)
        self.assertEqual(self.mock_llm.invoke_count, 0)
        self.assertEqual(self.director.state, DirectorState.HUMAN_OVERRIDE)

    def test_audit_log_captures_escalation(self):
        self.director.manual_escalate(reason="audit-test")
        time.sleep(0.5)
        log = self.director.audit_log
        categories = [e.category for e in log]
        self.assertIn("transition", categories)
        self.assertIn("llm_response", categories)


class TestTriStateDirectorLLMFailure(unittest.TestCase):
    def setUp(self):
        self.loop, _, _ = _make_loop()
        self.mock_llm = _MockLLM(raise_error=True)
        self.director = TriStateDirector(
            self.loop,
            llm_backend=self.mock_llm,
        )
        self.director.start()

    def tearDown(self):
        self.director.stop()

    def test_llm_failure_returns_to_autonomous(self):
        """LLM failure should gracefully return to AUTONOMOUS."""
        self.director.manual_escalate(reason="llm-fail-test")
        time.sleep(0.5)
        self.assertEqual(self.director.state, DirectorState.AUTONOMOUS)
        # Verify error was audited
        log = self.director.audit_log
        categories = [e.category for e in log]
        self.assertIn("llm_error", categories)


class TestTriStateDirectorBudget(unittest.TestCase):
    def test_action_budget_enforced(self):
        """Director should stop executing after action budget is exhausted."""
        loop, _, _ = _make_loop()
        # Create 10 tool calls but budget is 5
        tool_calls = [
            LLMToolCall(tool_name="trigger_discovery", arguments={})
            for _ in range(10)
        ]
        mock_llm = _MockLLM(tool_calls=tool_calls)
        director = TriStateDirector(loop, llm_backend=mock_llm)
        director.start()
        director.manual_escalate(reason="budget-test")
        time.sleep(0.5)
        director.stop()

        # Count tool_call audit entries
        tool_call_entries = [
            e for e in director.audit_log if e.category == "tool_call"
        ]
        self.assertLessEqual(len(tool_call_entries), 5)


class TestTriStateDirectorHumanInterruptMidAI(unittest.TestCase):
    def test_human_override_interrupts_ai(self):
        """Human override during AI action should abort and roll back."""
        loop, _, _ = _make_loop()

        class _SlowLLM:
            def invoke(self, system_prompt, user_message, tools, timeout=30.0):
                return LLMResponse(
                    tool_calls=[
                        LLMToolCall(tool_name="trigger_discovery", arguments={})
                        for _ in range(5)
                    ],
                    raw_text="",
                    model="slow",
                )

        director = TriStateDirector(loop, llm_backend=_SlowLLM())
        director.start()

        # Trigger escalation
        director.manual_escalate(reason="interrupt-test")
        time.sleep(0.1)

        # Human override while AI might be processing
        director.human_override("operator")
        time.sleep(0.3)

        self.assertEqual(director.state, DirectorState.HUMAN_OVERRIDE)
        director.release_override()
        director.stop()


# ── TriStateDirector — Lifecycle ────────────────────────────────────────────


class TestTriStateDirectorLifecycle(unittest.TestCase):
    def test_start_stop(self):
        loop, _, _ = _make_loop()
        director = TriStateDirector(loop, llm_backend=_MockLLM())
        director.start()
        self.assertTrue(director._running)
        director.stop()
        self.assertFalse(director._running)

    def test_double_stop(self):
        loop, _, _ = _make_loop()
        director = TriStateDirector(loop, llm_backend=_MockLLM())
        director.start()
        director.stop()
        director.stop()  # Should not raise


# ── SemanticDelta Assembly ──────────────────────────────────────────────────


class TestSemanticDeltaAssembly(unittest.TestCase):
    def test_build_with_minimal_loop(self):
        """Delta assembly should work with just an AutonomousLoop."""
        loop, _, _ = _make_loop()
        director = TriStateDirector(loop, llm_backend=_MockLLM())
        event = _make_event()
        delta = director._build_semantic_delta(event)
        self.assertTrue(SemanticDelta.validate(delta))
        self.assertIsInstance(delta.loop_status, dict)
        self.assertIsInstance(delta.system_metrics, dict)

    def test_build_with_multipath(self):
        loop, _, _ = _make_loop()
        mp = _MockMultipath()
        director = TriStateDirector(loop, multipath=mp, llm_backend=_MockLLM())
        event = _make_event()
        delta = director._build_semantic_delta(event)
        self.assertIn("mock_path", delta.path_health)


# ── System Prompt ────────────────────────────────────────────────────────────


class TestSystemPrompt(unittest.TestCase):
    def test_prompt_format(self):
        prompt = DIRECTOR_SYSTEM_PROMPT.format(action_budget=5)
        self.assertIn("5", prompt)
        self.assertIn("Tier 2", prompt)
        self.assertIn("CONSTRAINTS", prompt)
        self.assertIn("AST quarantine", prompt)


# ── ToolResult ───────────────────────────────────────────────────────────────


class TestToolResult(unittest.TestCase):
    def test_success_result(self):
        tr = ToolResult(
            tool_name="test",
            arguments={},
            success=True,
            result={"ok": True},
        )
        self.assertTrue(tr.success)
        self.assertIsNone(tr.error)

    def test_failure_result(self):
        tr = ToolResult(
            tool_name="test",
            arguments={},
            success=False,
            error="boom",
        )
        self.assertFalse(tr.success)
        self.assertEqual(tr.error, "boom")


# ── Resilience Manager Exhaustion Hook ──────────────────────────────────────


class TestResilienceExhaustionHook(unittest.TestCase):
    def test_on_exhausted_callback(self):
        """ResilienceManager should fire on_exhausted when fallbacks exhaust."""
        registry = MirrorRegistry()
        blender = Blender(registry)
        rm = ResilienceManager(registry, blender)

        exhausted_calls = []
        rm.set_on_exhausted(lambda name, count: exhausted_calls.append((name, count)))

        def original():
            return "orig"

        def bad_fallback():
            raise ValueError("fail")

        mod = types.ModuleType("test_exhaust_mod")
        mod.func = original

        rm.protect(mod, "func", [bad_fallback])
        # Calling should trigger fallback → exhaust → callback
        try:
            mod.func()
        except ValueError:
            pass

        self.assertEqual(len(exhausted_calls), 1)
        self.assertEqual(exhausted_calls[0][0], "func")
        self.assertGreaterEqual(exhausted_calls[0][1], 1)
        blender.revert_all()


# ── Integration: Director + Detector + Loop ─────────────────────────────────


class TestDirectorDetectorIntegration(unittest.TestCase):
    def test_detector_wired_to_director(self):
        """Detector's on_escalation should be wired to director."""
        loop, _, _ = _make_loop()
        mock_llm = _MockLLM()
        director = TriStateDirector(loop, llm_backend=mock_llm)
        # Bound methods aren't identity-equal, so check the underlying function
        self.assertEqual(
            director._detector._on_escalation.__func__,
            TriStateDirector._on_escalation,
        )

    def test_detector_multipath_attached(self):
        loop, _, _ = _make_loop()
        mp = _MockMultipath()
        director = TriStateDirector(loop, multipath=mp, llm_backend=_MockLLM())
        self.assertIs(director._detector._multipath, mp)


if __name__ == "__main__":
    unittest.main()
