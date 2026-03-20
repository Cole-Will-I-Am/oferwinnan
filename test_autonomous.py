"""Tests for autonomous.py — self-healing, self-customizing, self-upgrading."""

import threading
import time
import types
import unittest

from mirror_blend import MirrorRegistry, Blender
from autonomous import (
    ResilienceManager,
    EnvironmentAdapter,
    HotUpgrader,
    AutonomousLoop,
    system_metrics,
)


def _make_module(name="test_mod", **attrs):
    """Create a throwaway module with given attributes."""
    mod = types.ModuleType(name)
    for k, v in attrs.items():
        setattr(mod, k, v)
    return mod


# ── Layer 1: ResilienceManager ───────────────────────────────────────────────

class TestResilienceManager(unittest.TestCase):
    def setUp(self):
        self.registry = MirrorRegistry()
        self.blender = Blender(self.registry)
        self.rm = ResilienceManager(self.registry, self.blender)

    def tearDown(self):
        self.blender.revert_all()

    def test_protect_installs_first_fallback(self):
        """First fallback in the chain should replace the original."""
        def original():
            return "original"

        def fallback_a():
            return "A"

        mod = _make_module(greet=original)
        self.rm.protect(mod, "greet", [fallback_a])
        self.assertEqual(mod.greet(), "A")

    def test_fallback_chain_advances_on_failure(self):
        """When a fallback raises, the next one should be installed."""
        call_log = []

        def bad():
            call_log.append("bad")
            raise ValueError("boom")

        def good():
            call_log.append("good")
            return "ok"

        mod = _make_module(work=lambda: "original")
        self.rm.protect(mod, "work", [bad, good])

        # First call triggers bad → raises, installs good
        with self.assertRaises(ValueError):
            mod.work()

        # Now good should be installed
        self.assertEqual(mod.work(), "ok")
        self.assertEqual(self.rm.total_failures, 1)

    def test_unprotect_reverts(self):
        """Unprotecting should restore the original."""
        def original():
            return "original"

        def replacement():
            return "replaced"

        mod = _make_module(fn=original)
        key = self.rm.protect(mod, "fn", [replacement])
        self.assertEqual(mod.fn(), "replaced")

        self.rm.unprotect(key)
        self.assertEqual(mod.fn(), "original")

    def test_protection_count(self):
        mod = _make_module(a=lambda: 1, b=lambda: 2)
        self.rm.protect(mod, "a", [lambda: 10])
        self.rm.protect(mod, "b", [lambda: 20])
        self.assertEqual(self.rm.protection_count, 2)


# ── Layer 2: EnvironmentAdapter ──────────────────────────────────────────────

class TestEnvironmentAdapter(unittest.TestCase):
    def setUp(self):
        self.registry = MirrorRegistry()
        self.blender = Blender(self.registry)
        self.adapter = EnvironmentAdapter(self.registry, self.blender)

    def tearDown(self):
        self.blender.revert_all()

    def test_default_mode_is_full(self):
        self.assertEqual(self.adapter.mode, "full")

    def test_high_cpu_triggers_eco(self):
        self.adapter.update_metrics(cpu_percent=95.0)
        mode = self.adapter.adapt()
        self.assertEqual(mode, "eco")

    def test_high_memory_triggers_eco(self):
        self.adapter.update_metrics(memory_percent=90.0)
        mode = self.adapter.adapt()
        self.assertEqual(mode, "eco")

    def test_high_latency_triggers_lightweight(self):
        self.adapter.update_metrics(network_latency_ms=300.0)
        mode = self.adapter.adapt()
        self.assertEqual(mode, "light")

    def test_slow_frames_trigger_lightweight(self):
        self.adapter.update_metrics(frame_time_ms=60.0)
        mode = self.adapter.adapt()
        self.assertEqual(mode, "light")

    def test_normal_stays_full(self):
        self.adapter.update_metrics(cpu_percent=30.0, memory_percent=40.0)
        mode = self.adapter.adapt()
        self.assertEqual(mode, "full")

    def test_register_adaptive_swaps_variants(self):
        """Registering variants and adapting should swap the active callable."""
        def full_fn():
            return "full"

        def eco_fn():
            return "eco"

        mod = _make_module(compute=full_fn)
        self.adapter.register_adaptive(mod, "compute", {
            "full": full_fn,
            "eco": eco_fn,
        })

        # Should start with full variant
        self.assertEqual(mod.compute(), "full")

        # Trigger eco mode
        self.adapter.update_metrics(cpu_percent=95.0)
        self.adapter.adapt()
        self.assertEqual(mod.compute(), "eco")

    def test_register_requires_full_variant(self):
        mod = _make_module(fn=lambda: 1)
        with self.assertRaises(ValueError):
            self.adapter.register_adaptive(mod, "fn", {"eco": lambda: 2})


# ── Layer 3: HotUpgrader ────────────────────────────────────────────────────

class TestHotUpgrader(unittest.TestCase):
    def setUp(self):
        self.registry = MirrorRegistry()
        self.blender = Blender(self.registry)
        self.upgrader = HotUpgrader(self.registry, self.blender)

    def tearDown(self):
        self.blender.revert_all()

    def test_apply_upgrade_replaces_functions(self):
        def original_add(a, b):
            return a + b

        mod = _make_module(add=original_add)

        upgrade_code = b"""
def add(a, b):
    return (a + b) * 10
"""
        self.upgrader.apply_upgrade(upgrade_code, mod)
        self.assertEqual(mod.add(2, 3), 50)

    def test_rollback_restores_original(self):
        def original():
            return "original"

        mod = _make_module(fn=original)

        self.upgrader.apply_upgrade(b"def fn(): return 'upgraded'", mod)
        self.assertEqual(mod.fn(), "upgraded")

        self.upgrader.rollback()
        self.assertEqual(mod.fn(), "original")

    def test_multiple_upgrades_rollback_in_order(self):
        mod = _make_module(fn=lambda: "v0")

        self.upgrader.apply_upgrade(b"def fn(): return 'v1'", mod, tag="v1")
        self.upgrader.apply_upgrade(b"def fn(): return 'v2'", mod, tag="v2")
        self.assertEqual(mod.fn(), "v2")

        self.upgrader.rollback()  # removes v2
        self.assertEqual(mod.fn(), "v1")

        self.upgrader.rollback()  # removes v1
        self.assertEqual(mod.fn(), "v0")

    def test_rollback_all(self):
        mod = _make_module(fn=lambda: "v0")
        self.upgrader.apply_upgrade(b"def fn(): return 'v1'", mod)
        self.upgrader.apply_upgrade(b"def fn(): return 'v2'", mod)
        count = self.upgrader.rollback_all()
        self.assertEqual(count, 2)
        self.assertEqual(mod.fn(), "v0")

    def test_version_count_and_history(self):
        mod = _make_module(fn=lambda: 1)
        self.upgrader.apply_upgrade(b"def fn(): return 2", mod, tag="alpha")
        self.upgrader.apply_upgrade(b"def fn(): return 3", mod, tag="beta")
        self.assertEqual(self.upgrader.version_count, 2)
        self.assertEqual(self.upgrader.history, ["alpha", "beta"])
        self.assertEqual(self.upgrader.current_tag, "beta")

    def test_skips_private_and_non_callable(self):
        mod = _make_module(public=lambda: 1)
        code = b"""
_private = lambda: 2
VALUE = 42
def public(): return 99
"""
        self.upgrader.apply_upgrade(code, mod)
        self.assertEqual(mod.public(), 99)
        self.assertFalse(hasattr(mod, "_private"))

    def test_apply_from_session(self):
        """Simulate a JumpSession with a .py file."""
        import base64

        class FakeSession:
            session_id = "test-session"
            files = {
                "patch.py": base64.b64encode(b"def fn(): return 'patched'").decode(),
                "readme.txt": base64.b64encode(b"not python").decode(),
            }

        mod = _make_module(fn=lambda: "original")
        versions = self.upgrader.apply_from_session(FakeSession(), mod)
        self.assertEqual(len(versions), 1)
        self.assertEqual(mod.fn(), "patched")


# ── Layer 4: AutonomousLoop ──────────────────────────────────────────────────

class TestAutonomousLoop(unittest.TestCase):
    def setUp(self):
        self.registry = MirrorRegistry()
        self.blender = Blender(self.registry)

    def tearDown(self):
        self.blender.revert_all()

    def test_start_stop(self):
        loop = AutonomousLoop(self.registry, self.blender, tick_interval=0.05)
        loop.start()
        self.assertTrue(loop.is_running)
        time.sleep(0.2)
        self.assertGreater(loop.tick_count, 0)
        loop.stop()
        self.assertFalse(loop.is_running)

    def test_metrics_collector_integration(self):
        """Metrics collectors should feed into the adapter."""
        loop = AutonomousLoop(self.registry, self.blender, tick_interval=0.05)
        loop.add_metrics_collector(lambda: {"cpu_percent": 95.0})
        loop.start()
        time.sleep(0.2)
        loop.stop()
        self.assertEqual(loop.adapter.mode, "eco")

    def test_on_tick_callback(self):
        ticks_seen = []
        loop = AutonomousLoop(self.registry, self.blender, tick_interval=0.05)
        loop.add_on_tick(lambda l: ticks_seen.append(l.tick_count))
        loop.start()
        time.sleep(0.2)
        loop.stop()
        self.assertGreater(len(ticks_seen), 0)

    def test_status_snapshot(self):
        loop = AutonomousLoop(self.registry, self.blender, tick_interval=0.05)
        status = loop.status
        self.assertIn("running", status)
        self.assertIn("mode", status)
        self.assertIn("mirrors", status)
        self.assertIn("blends", status)
        self.assertIn("upgrade_version", status)

    def test_upgrade_from_session(self):
        """Simulate a JumpNode receiving a session with code."""
        import base64

        class FakeNode:
            received_sessions = []

        class FakeSession:
            session_id = "ota-1"
            files = {
                "upgrade.py": base64.b64encode(b"def fn(): return 'ota'").decode(),
            }

        mod = _make_module(fn=lambda: "original")
        node = FakeNode()
        loop = AutonomousLoop(
            self.registry, self.blender,
            node=node, target_module=mod, tick_interval=0.05,
        )

        # Queue a session before starting
        node.received_sessions.append(FakeSession())
        loop.start()
        time.sleep(0.2)
        loop.stop()

        self.assertEqual(mod.fn(), "ota")


# ── system_metrics utility ───────────────────────────────────────────────────

class TestSystemMetrics(unittest.TestCase):
    def test_returns_dict(self):
        m = system_metrics()
        self.assertIsInstance(m, dict)
        # On Linux we should get at least cpu_percent
        # On other platforms it may be empty — that's fine


# ── Thread safety smoke test ─────────────────────────────────────────────────

class TestThreadSafety(unittest.TestCase):
    def test_concurrent_protect_and_adapt(self):
        """Hammer ResilienceManager and EnvironmentAdapter from multiple threads."""
        registry = MirrorRegistry()
        blender = Blender(registry)
        rm = ResilienceManager(registry, blender)
        adapter = EnvironmentAdapter(registry, blender)

        mod = _make_module(**{f"fn{i}": (lambda i=i: i) for i in range(10)})
        errors = []

        def protect_worker(idx):
            try:
                rm.protect(mod, f"fn{idx}", [lambda i=idx: i * 10],
                           key=f"test:{idx}")
            except Exception as e:
                errors.append(e)

        def adapt_worker():
            try:
                for _ in range(20):
                    adapter.update_metrics(cpu_percent=float(50 + _ * 3))
                    adapter.adapt()
            except Exception as e:
                errors.append(e)

        threads = []
        for i in range(10):
            threads.append(threading.Thread(target=protect_worker, args=(i,)))
        threads.append(threading.Thread(target=adapt_worker))

        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)

        self.assertEqual(errors, [])
        blender.revert_all()


class TestHotUpgraderValidation(unittest.TestCase):
    """Tests for AST-based code validation in HotUpgrader."""

    def setUp(self):
        self.registry = MirrorRegistry()
        self.blender = Blender(self.registry)
        self.upgrader = HotUpgrader(self.registry, self.blender)
        self.target = types.ModuleType("_test_target")
        self.target.greet = lambda: "hello"

    def tearDown(self):
        self.blender.revert_all()

    def test_clean_code_accepted(self):
        """Valid upgrade code should be accepted and applied."""
        code = b"def greet(): return 'upgraded'"
        version = self.upgrader.apply_upgrade(code, self.target, tag="clean")
        self.assertEqual(version, 0)
        self.assertEqual(self.target.greet(), "upgraded")

    def test_import_os_rejected(self):
        """Code importing os must be rejected."""
        code = b"import os\ndef greet(): return os.getcwd()"
        with self.assertRaises(ValueError) as ctx:
            self.upgrader.apply_upgrade(code, self.target)
        self.assertIn("blocked module", str(ctx.exception))

    def test_import_subprocess_rejected(self):
        """Code importing subprocess must be rejected."""
        code = b"import subprocess\ndef greet(): return 'hi'"
        with self.assertRaises(ValueError) as ctx:
            self.upgrader.apply_upgrade(code, self.target)
        self.assertIn("blocked module", str(ctx.exception))

    def test_from_os_import_rejected(self):
        """Code using 'from os import ...' must be rejected."""
        code = b"from os.path import join\ndef greet(): return join('a','b')"
        with self.assertRaises(ValueError) as ctx:
            self.upgrader.apply_upgrade(code, self.target)
        self.assertIn("blocked module", str(ctx.exception))

    def test_exec_call_rejected(self):
        """Code calling exec() must be rejected."""
        code = b"def greet(): exec('pass')"
        with self.assertRaises(ValueError) as ctx:
            self.upgrader.apply_upgrade(code, self.target)
        self.assertIn("blocked call", str(ctx.exception))

    def test_eval_call_rejected(self):
        """Code calling eval() must be rejected."""
        code = b"def greet(): return eval('1+1')"
        with self.assertRaises(ValueError) as ctx:
            self.upgrader.apply_upgrade(code, self.target)
        self.assertIn("blocked call", str(ctx.exception))

    def test_open_call_rejected(self):
        """Code calling open() must be rejected."""
        code = b"def greet(): return open('/etc/passwd').read()"
        with self.assertRaises(ValueError) as ctx:
            self.upgrader.apply_upgrade(code, self.target)
        self.assertIn("blocked call", str(ctx.exception))

    def test_dunder_import_rejected(self):
        """Code calling __import__() must be rejected."""
        code = b"def greet(): return __import__('os').getcwd()"
        with self.assertRaises(ValueError) as ctx:
            self.upgrader.apply_upgrade(code, self.target)
        self.assertIn("blocked call", str(ctx.exception))

    def test_syntax_error_rejected(self):
        """Code with syntax errors must be rejected."""
        code = b"def greet( return 'hi'"
        with self.assertRaises(ValueError) as ctx:
            self.upgrader.apply_upgrade(code, self.target)
        self.assertIn("syntax error", str(ctx.exception))

    def test_validate_code_classmethod(self):
        """_validate_code should be callable directly for testing."""
        # Clean code should not raise
        HotUpgrader._validate_code(b"def foo(): return 42")

        # Dangerous code should raise
        with self.assertRaises(ValueError):
            HotUpgrader._validate_code(b"import sys")


if __name__ == "__main__":
    unittest.main()
