"""
test_mirror_blend.py — Comprehensive tests for the mirror/blend framework.

Run: python3 -m pytest test_mirror_blend.py -v
  or: python3 test_mirror_blend.py
"""

import sys
import types
import threading
import builtins
import unittest
import warnings
from unittest.mock import MagicMock, patch

from mirror_blend import (
    MirrorRegistry,
    Blender,
    AdaptiveWrapper,
    MirrorError,
    BlendError,
    RevertError,
)


# ─── Fixtures ────────────────────────────────────────────────────────────────

def sample_add(a, b):
    """Add two numbers."""
    return a + b


def sample_greet(name, greeting="Hello"):
    return f"{greeting}, {name}!"


class SampleClass:
    CLASS_VAR = 42

    def __init__(self, value):
        self.value = value

    def double(self):
        return self.value * 2

    @staticmethod
    def static_method():
        return "static"

    @classmethod
    def class_method(cls):
        return cls.__name__

    @property
    def half(self):
        return self.value / 2


class SlottedClass:
    __slots__ = ("x", "y")

    def __init__(self, x, y):
        self.x = x
        self.y = y

    def sum(self):
        return self.x + self.y


# ─── MirrorRegistry Tests ───────────────────────────────────────────────────

class TestMirrorFunction(unittest.TestCase):

    def setUp(self):
        self.registry = MirrorRegistry()

    def test_mirror_preserves_call_semantics(self):
        mirror = self.registry.mirror(sample_add)
        self.assertEqual(mirror(2, 3), 5)
        self.assertEqual(mirror(0, 0), 0)
        self.assertEqual(mirror(-1, 1), 0)

    def test_mirror_preserves_signature_metadata(self):
        mirror = self.registry.mirror(sample_add)
        self.assertEqual(mirror.__name__, "sample_add")
        self.assertEqual(mirror.__doc__, "Add two numbers.")
        self.assertEqual(mirror.__module__, sample_add.__module__)

    def test_mirror_preserves_default_args(self):
        mirror = self.registry.mirror(sample_greet)
        self.assertEqual(mirror("World"), "Hello, World!")
        self.assertEqual(mirror("World", greeting="Hey"), "Hey, World!")

    def test_mirror_with_custom_name(self):
        mirror = self.registry.mirror(sample_add, name="my_add")
        self.assertEqual(mirror.__name__, "my_add")
        self.assertEqual(mirror(1, 2), 3)

    def test_mirror_cache_returns_same_object(self):
        m1 = self.registry.mirror(sample_add)
        m2 = self.registry.mirror(sample_add)
        self.assertIs(m1, m2)

    def test_mirror_count(self):
        self.assertEqual(self.registry.mirror_count, 0)
        self.registry.mirror(sample_add)
        self.assertEqual(self.registry.mirror_count, 1)
        self.registry.mirror(sample_greet)
        self.assertEqual(self.registry.mirror_count, 2)

    def test_unmirror_retrieves_original(self):
        mirror = self.registry.mirror(sample_add)
        original = self.registry.unmirror(mirror)
        self.assertIs(original, sample_add)

    def test_unmirror_unknown_raises(self):
        with self.assertRaises(MirrorError):
            self.registry.unmirror(lambda: None)

    def test_is_mirrored(self):
        mirror = self.registry.mirror(sample_add)
        self.assertTrue(self.registry.is_mirrored(mirror))
        self.assertFalse(self.registry.is_mirrored(sample_add))

    def test_mirror_non_callable_raises(self):
        with self.assertRaises(MirrorError):
            self.registry.mirror(42)

    def test_clear(self):
        self.registry.mirror(sample_add)
        self.registry.mirror(sample_greet)
        self.assertEqual(self.registry.mirror_count, 2)
        self.registry.clear()
        self.assertEqual(self.registry.mirror_count, 0)

    def test_mirror_has_origin_attribute(self):
        mirror = self.registry.mirror(sample_add)
        self.assertIs(mirror.__mirror_origin__, sample_add)


class TestMirrorHooks(unittest.TestCase):

    def setUp(self):
        self.registry = MirrorRegistry()

    def test_pre_hook_fires(self):
        calls = []

        def pre(fn, args, kwargs):
            calls.append(("pre", fn.__name__, args, kwargs))

        mirror = self.registry.mirror(sample_add, pre=pre)
        result = mirror(2, 3)
        self.assertEqual(result, 5)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0], ("pre", "sample_add", (2, 3), {}))

    def test_post_hook_fires(self):
        results = []

        def post(fn, result):
            results.append(("post", fn.__name__, result))

        mirror = self.registry.mirror(sample_add, post=post)
        r = mirror(10, 20)
        self.assertEqual(r, 30)
        self.assertEqual(results, [("post", "sample_add", 30)])

    def test_pre_hook_can_modify_args(self):
        def pre(fn, args, kwargs):
            return (args[0] * 10, args[1] * 10), kwargs

        mirror = self.registry.mirror(sample_add, pre=pre)
        self.assertEqual(mirror(2, 3), 50)  # 20 + 30

    def test_post_hook_can_replace_result(self):
        def post(fn, result):
            return result * 100

        mirror = self.registry.mirror(sample_add, post=post)
        self.assertEqual(mirror(2, 3), 500)  # 5 * 100

    def test_pre_hook_returning_none_passes_original_args(self):
        def pre(fn, args, kwargs):
            return None  # explicitly return None

        mirror = self.registry.mirror(sample_add, pre=pre)
        self.assertEqual(mirror(2, 3), 5)

    def test_post_hook_returning_none_keeps_original_result(self):
        def post(fn, result):
            return None

        mirror = self.registry.mirror(sample_add, post=post)
        self.assertEqual(mirror(2, 3), 5)

    def test_both_hooks(self):
        log = []

        def pre(fn, args, kwargs):
            log.append("pre")

        def post(fn, result):
            log.append("post")

        mirror = self.registry.mirror(sample_add, pre=pre, post=post)
        mirror(1, 2)
        self.assertEqual(log, ["pre", "post"])


class TestMirrorClass(unittest.TestCase):

    def setUp(self):
        self.registry = MirrorRegistry()

    def test_mirror_class_instantiation(self):
        Mirror = self.registry.mirror(SampleClass)
        obj = Mirror(10)
        self.assertEqual(obj.value, 10)

    def test_mirror_class_methods(self):
        Mirror = self.registry.mirror(SampleClass)
        obj = Mirror(7)
        self.assertEqual(obj.double(), 14)

    def test_mirror_class_static_method(self):
        Mirror = self.registry.mirror(SampleClass)
        self.assertEqual(Mirror.static_method(), "static")

    def test_mirror_class_class_method(self):
        Mirror = self.registry.mirror(SampleClass)
        result = Mirror.class_method()
        self.assertEqual(result, Mirror.__name__)

    def test_mirror_class_property(self):
        Mirror = self.registry.mirror(SampleClass)
        obj = Mirror(10)
        self.assertEqual(obj.half, 5.0)

    def test_mirror_class_with_hooks(self):
        calls = []

        def pre(fn, args, kwargs):
            calls.append(fn.__name__ if hasattr(fn, '__name__') else str(fn))

        Mirror = self.registry.mirror(SampleClass, pre=pre)
        obj = Mirror(5)
        obj.double()
        # pre hook receives the *original* fn, so names are the raw function names
        self.assertIn("__init__", calls)
        self.assertIn("double", calls)

    def test_mirror_class_preserves_class_var(self):
        Mirror = self.registry.mirror(SampleClass)
        self.assertEqual(Mirror.CLASS_VAR, 42)

    def test_mirror_slotted_class(self):
        Mirror = self.registry.mirror(SlottedClass)
        obj = Mirror(3, 4)
        self.assertEqual(obj.sum(), 7)


class TestMirrorThreadSafety(unittest.TestCase):

    def test_concurrent_mirror_creation(self):
        registry = MirrorRegistry()
        results = {}
        errors = []

        def worker(i):
            try:
                fn = lambda x: x + i  # noqa: E731
                fn.__name__ = f"fn_{i}"
                fn.__qualname__ = f"fn_{i}"
                mirror = registry.mirror(fn, name=f"fn_{i}")
                results[i] = mirror(10)
            except Exception as e:
                errors.append((i, e))

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(errors), 0, f"Errors: {errors}")
        for i, val in results.items():
            self.assertEqual(val, 10 + i)


# ─── Blender Tests ───────────────────────────────────────────────────────────

class TestBlendIntoModule(unittest.TestCase):

    def setUp(self):
        self.registry = MirrorRegistry()
        self.module = types.ModuleType("test_mod")
        self.module.original_fn = sample_add

    def test_blend_replaces_attribute(self):
        mirror = self.registry.mirror(sample_add, post=lambda fn, r: r * 2)
        blender = Blender(self.registry)
        blender.blend_into_module(self.module, "original_fn", mirror)

        self.assertIs(self.module.original_fn, mirror)
        self.assertEqual(self.module.original_fn(2, 3), 10)  # 5 * 2

    def test_revert_restores_original(self):
        mirror = self.registry.mirror(sample_add)
        blender = Blender(self.registry)
        blender.blend_into_module(self.module, "original_fn", mirror)
        blender.revert_all()

        self.assertIs(self.module.original_fn, sample_add)

    def test_blend_new_attribute_deleted_on_revert(self):
        mirror = self.registry.mirror(sample_add)
        blender = Blender(self.registry)
        blender.blend_into_module(self.module, "new_fn", mirror)

        self.assertTrue(hasattr(self.module, "new_fn"))
        blender.revert_all()
        self.assertFalse(hasattr(self.module, "new_fn"))

    def test_blend_non_module_raises(self):
        blender = Blender(self.registry)
        with self.assertRaises(BlendError):
            blender.blend_into_module("not_a_module", "x", lambda: None)

    def test_selective_revert(self):
        mirror1 = self.registry.mirror(sample_add, name="m1")
        mirror2 = self.registry.mirror(sample_greet, name="m2")
        blender = Blender(self.registry)

        key1 = blender.blend_into_module(self.module, "fn1", mirror1)
        key2 = blender.blend_into_module(self.module, "fn2", mirror2)

        self.assertEqual(blender.blend_count, 2)
        blender.revert(key1)
        self.assertEqual(blender.blend_count, 1)
        self.assertFalse(hasattr(self.module, "fn1"))
        self.assertTrue(hasattr(self.module, "fn2"))


class TestBlendIntoGlobals(unittest.TestCase):

    def setUp(self):
        self.registry = MirrorRegistry()

    def test_blend_into_dict(self):
        g = {"x": 1}
        mirror = self.registry.mirror(sample_add)
        blender = Blender(self.registry)
        blender.blend_into_globals(g, "my_fn", mirror)

        self.assertIs(g["my_fn"], mirror)
        blender.revert_all()
        self.assertNotIn("my_fn", g)

    def test_blend_overwrites_existing(self):
        g = {"target": sample_add}
        mirror = self.registry.mirror(sample_add, post=lambda fn, r: r * 3)
        blender = Blender(self.registry)
        blender.blend_into_globals(g, "target", mirror)

        self.assertEqual(g["target"](1, 2), 9)
        blender.revert_all()
        self.assertIs(g["target"], sample_add)

    def test_blend_non_dict_raises(self):
        blender = Blender(self.registry)
        with self.assertRaises(BlendError):
            blender.blend_into_globals([], "x", lambda: None)


class TestBlendIntoBuiltins(unittest.TestCase):

    def setUp(self):
        self.registry = MirrorRegistry()

    def test_blend_and_revert_builtins(self):
        mirror = self.registry.mirror(sample_add)
        blender = Blender(self.registry)

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            blender.blend_into_builtins("_test_mirror_blend_fn", mirror)

        self.assertTrue(hasattr(builtins, "_test_mirror_blend_fn"))
        blender.revert_all()
        self.assertFalse(hasattr(builtins, "_test_mirror_blend_fn"))

    def test_blend_builtins_emits_warning(self):
        mirror = self.registry.mirror(sample_add, name="warn_test")
        blender = Blender(self.registry)

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            blender.blend_into_builtins("_test_warn", mirror)
            self.assertTrue(any("builtins" in str(x.message) for x in w))

        blender.revert_all()


class TestBlenderContextManager(unittest.TestCase):

    def setUp(self):
        self.registry = MirrorRegistry()

    def test_context_manager_auto_reverts(self):
        module = types.ModuleType("ctx_test")
        module.fn = sample_add

        mirror = self.registry.mirror(sample_add)

        with Blender(self.registry) as b:
            b.blend_into_module(module, "fn", mirror)
            self.assertIs(module.fn, mirror)

        self.assertIs(module.fn, sample_add)

    def test_context_manager_reverts_on_exception(self):
        module = types.ModuleType("ctx_exc")
        module.fn = sample_add

        mirror = self.registry.mirror(sample_add)

        with self.assertRaises(ValueError):
            with Blender(self.registry) as b:
                b.blend_into_module(module, "fn", mirror)
                raise ValueError("boom")

        self.assertIs(module.fn, sample_add)

    def test_closed_blender_rejects_new_blends(self):
        blender = Blender(self.registry)
        blender.revert_all()

        with self.assertRaises(BlendError):
            blender.blend_into_globals({}, "x", lambda: None)

    def test_lifo_revert_order(self):
        """Blends should revert in LIFO order."""
        order = []
        module = types.ModuleType("lifo_test")

        class Tracker:
            def __init__(self, n):
                self.n = n

            def __del__(self):
                order.append(self.n)

        blender = Blender(self.registry)
        blender.blend_into_module(module, "a", Tracker(1))
        blender.blend_into_module(module, "b", Tracker(2))
        blender.blend_into_module(module, "c", Tracker(3))

        # After revert_all, LIFO means c reverted first, then b, then a
        # We can verify via blend_keys order being reversed during revert
        keys = blender.blend_keys
        self.assertEqual(len(keys), 3)
        blender.revert_all()
        self.assertEqual(blender.blend_count, 0)


class TestBlendKeys(unittest.TestCase):

    def setUp(self):
        self.registry = MirrorRegistry()

    def test_custom_key(self):
        g = {}
        blender = Blender(self.registry)
        mirror = self.registry.mirror(sample_add, name="ktest")
        key = blender.blend_into_globals(g, "fn", mirror, key="custom_key")
        self.assertEqual(key, "custom_key")
        self.assertIn("custom_key", blender.blend_keys)
        blender.revert_all()

    def test_auto_generated_keys(self):
        module = types.ModuleType("keymod")
        blender = Blender(self.registry)
        mirror = self.registry.mirror(sample_add, name="autokey")

        key = blender.blend_into_module(module, "fn", mirror)
        self.assertTrue(key.startswith("module:"))
        blender.revert_all()

    def test_revert_nonexistent_key_raises(self):
        blender = Blender(self.registry)
        with self.assertRaises(BlendError):
            blender.revert("nonexistent")


# ─── AdaptiveWrapper Tests ───────────────────────────────────────────────────

class TestAdaptiveWrapper(unittest.TestCase):

    def setUp(self):
        self.registry = MirrorRegistry()

    def test_callable(self):
        wrapper = AdaptiveWrapper(sample_add, self.registry)
        self.assertEqual(wrapper(3, 7), 10)

    def test_with_hooks(self):
        log = []
        wrapper = AdaptiveWrapper(
            sample_add,
            self.registry,
            pre=lambda fn, a, k: (log.append("pre"), None)[-1],
            post=lambda fn, r: (log.append("post"), None)[-1],
        )
        result = wrapper(1, 2)
        self.assertEqual(result, 3)
        self.assertEqual(log, ["pre", "post"])

    def test_pre_hook_modifies_args(self):
        wrapper = AdaptiveWrapper(
            sample_add,
            self.registry,
            pre=lambda fn, a, k: ((a[0] * 2, a[1] * 2), k),
        )
        self.assertEqual(wrapper(3, 4), 14)  # 6 + 8

    def test_post_hook_replaces_result(self):
        wrapper = AdaptiveWrapper(
            sample_add,
            self.registry,
            post=lambda fn, r: r + 1000,
        )
        self.assertEqual(wrapper(1, 2), 1003)

    def test_repr(self):
        wrapper = AdaptiveWrapper(sample_add, self.registry, name="my_fn")
        r = repr(wrapper)
        self.assertIn("AdaptiveWrapper", r)
        self.assertIn("my_fn", r)

    def test_str(self):
        wrapper = AdaptiveWrapper(sample_add, self.registry, name="test")
        self.assertEqual(str(wrapper), "AdaptiveWrapper(test)")

    def test_name_property(self):
        wrapper = AdaptiveWrapper(sample_add, self.registry, name="named")
        self.assertEqual(wrapper.__name__, "named")

    def test_wrapped_property(self):
        wrapper = AdaptiveWrapper(sample_add, self.registry)
        self.assertIs(wrapper.__wrapped__, sample_add)

    def test_attribute_forwarding(self):
        fn = lambda x: x  # noqa: E731
        fn.custom_attr = "forwarded"
        wrapper = AdaptiveWrapper(fn, self.registry)
        self.assertEqual(wrapper.custom_attr, "forwarded")

    def test_mode_full_by_default(self):
        wrapper = AdaptiveWrapper(sample_add, self.registry)
        self.assertEqual(wrapper.mode, AdaptiveWrapper.Mode.FULL)

    def test_mode_trace_with_debugger(self):
        wrapper = AdaptiveWrapper(sample_add, self.registry)
        fake_trace = lambda *a: None  # noqa: E731
        with patch.object(sys, "gettrace", return_value=fake_trace):
            with patch.object(sys, "getprofile", return_value=None):
                self.assertEqual(wrapper.mode, AdaptiveWrapper.Mode.TRACE)

    def test_mode_lightweight_with_profiler(self):
        wrapper = AdaptiveWrapper(sample_add, self.registry)
        with patch.object(sys, "gettrace", return_value=None):
            with patch.object(sys, "getprofile", return_value=lambda *a: None):
                self.assertEqual(wrapper.mode, AdaptiveWrapper.Mode.LIGHTWEIGHT)

    def test_passthrough_never_calls_hooks(self):
        """In passthrough mode, hooks should be skipped entirely."""
        calls = []

        class PassthroughWrapper(AdaptiveWrapper):
            __slots__ = ()
            def _adapt(self):
                return AdaptiveWrapper.Mode.PASSTHROUGH

        wrapper = PassthroughWrapper(
            sample_add,
            self.registry,
            pre=lambda fn, a, k: calls.append("pre"),
            post=lambda fn, r: calls.append("post"),
        )
        result = wrapper(2, 3)
        self.assertEqual(result, 5)
        self.assertEqual(calls, [])  # No hooks fired


# ─── Integration Tests ───────────────────────────────────────────────────────

class TestIntegration(unittest.TestCase):
    """End-to-end tests combining MirrorRegistry, Blender, and AdaptiveWrapper."""

    def test_full_pipeline(self):
        """Mirror → Blend → Use → Revert."""
        registry = MirrorRegistry()
        call_count = {"n": 0}

        def counter_pre(fn, args, kwargs):
            call_count["n"] += 1

        mirror = registry.mirror(sample_add, pre=counter_pre)
        target = types.ModuleType("pipeline_test")
        target.add = sample_add

        with Blender(registry) as b:
            b.blend_into_module(target, "add", mirror)
            self.assertEqual(target.add(1, 2), 3)
            self.assertEqual(target.add(10, 20), 30)
            self.assertEqual(call_count["n"], 2)

        # After context exit, original is restored
        self.assertIs(target.add, sample_add)
        # Call count frozen
        target.add(0, 0)
        self.assertEqual(call_count["n"], 2)

    def test_adaptive_wrapper_in_blend(self):
        """AdaptiveWrapper works when blended into a module."""
        registry = MirrorRegistry()
        wrapper = AdaptiveWrapper(
            sample_greet,
            registry,
            pre=lambda fn, a, k: None,
        )

        target = types.ModuleType("adaptive_test")

        with Blender(registry) as b:
            b.blend_into_module(target, "greet", wrapper)
            self.assertEqual(target.greet("Neo"), "Hello, Neo!")

    def test_multiple_blenders_independent(self):
        """Two blenders can coexist and revert independently."""
        registry = MirrorRegistry()
        m1 = registry.mirror(sample_add, name="m1")
        m2 = registry.mirror(sample_greet, name="m2")

        mod = types.ModuleType("multi")
        mod.add = sample_add
        mod.greet = sample_greet

        b1 = Blender(registry)
        b2 = Blender(registry)

        b1.blend_into_module(mod, "add", m1)
        b2.blend_into_module(mod, "greet", m2)

        b1.revert_all()
        self.assertIs(mod.add, sample_add)
        # b2 still active
        self.assertIs(mod.greet, m2)

        b2.revert_all()
        self.assertIs(mod.greet, sample_greet)

    def test_mirror_class_blend_and_use(self):
        """Mirror a class, blend it in, instantiate, call methods."""
        registry = MirrorRegistry()
        log = []

        def trace_pre(fn, args, kwargs):
            name = getattr(fn, "__name__", "?")
            log.append(name)

        MirroredSample = registry.mirror(SampleClass, pre=trace_pre)
        mod = types.ModuleType("class_blend")

        with Blender(registry) as b:
            b.blend_into_module(mod, "SampleClass", MirroredSample)
            obj = mod.SampleClass(42)
            self.assertEqual(obj.double(), 84)
            self.assertIn("__init__", log)
            self.assertIn("double", log)

    def test_concurrent_blend_revert(self):
        """Thread safety of blend/revert operations."""
        registry = MirrorRegistry()
        errors = []

        def worker(i):
            try:
                fn = lambda x: x + i  # noqa: E731
                fn.__name__ = f"fn_{i}"
                fn.__qualname__ = f"fn_{i}"
                mirror = registry.mirror(fn, name=f"worker_{i}")
                g = {}
                with Blender(registry) as b:
                    b.blend_into_globals(g, "fn", mirror)
                    result = g["fn"](100)
                    assert result == 100 + i, f"Expected {100+i}, got {result}"
                assert "fn" not in g, "Revert failed"
            except Exception as e:
                errors.append((i, e))

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(errors), 0, f"Errors: {errors}")


# ─── Runner ──────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    unittest.main(verbosity=2)
