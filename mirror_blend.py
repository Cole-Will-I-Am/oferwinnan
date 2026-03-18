"""
mirror_blend.py — Runtime object instrumentation framework.

Mirror any callable. Blend it into any namespace. Revert cleanly.
Thread-safe. No GC heap walks. No frame hacks. No broken abstractions.

    from mirror_blend import MirrorRegistry, Blender, AdaptiveWrapper

    registry = MirrorRegistry()
    mirror = registry.mirror(some_function, pre=log_call, post=log_return)

    with Blender(registry) as b:
        b.blend_into_module(some_module, "some_function", mirror)
        # ... instrumented code runs here ...
    # automatic revert on exit
"""

from __future__ import annotations

import sys
import weakref
import threading
import functools
import warnings
import builtins
import types
from dataclasses import dataclass, field
from typing import (
    Any,
    Callable,
    Dict,
    List,
    Optional,
    Set,
    Tuple,
    TypeVar,
    Union,
    Protocol,
    runtime_checkable,
)

__all__ = [
    "MirrorRegistry",
    "Blender",
    "AdaptiveWrapper",
    "MirrorError",
    "BlendError",
    "RevertError",
]

# ─── Exceptions ──────────────────────────────────────────────────────────────

class MirrorError(Exception):
    """Raised when mirroring fails."""


class BlendError(Exception):
    """Raised when blending fails."""


class RevertError(Exception):
    """Raised when revert encounters errors. Collects all failures."""

    def __init__(self, failures: List[Tuple[str, Exception]]):
        self.failures = failures
        details = "; ".join(f"{key}: {err}" for key, err in failures)
        super().__init__(f"Revert failed for {len(failures)} blend(s): {details}")


# ─── Hook Protocol ───────────────────────────────────────────────────────────

@runtime_checkable
class Hook(Protocol):
    def __call__(self, *args: Any, **kwargs: Any) -> Any: ...


HookFn = Optional[Callable[..., Any]]
F = TypeVar("F", bound=Callable[..., Any])


# ─── Cache Key ───────────────────────────────────────────────────────────────
# id(obj) is reusable after GC. We combine id + qualname + a generation
# counter, and use weak references to auto-evict dead entries.

@dataclass(frozen=True, slots=True)
class _CacheKey:
    obj_id: int
    qualname: str
    generation: int


# ─── MirrorRegistry ─────────────────────────────────────────────────────────

class MirrorRegistry:
    """Thread-safe registry that creates instrumented mirrors of callables.

    Mirrors preserve the original's signature, docstring, module, and
    qualname while injecting pre/post hooks around every call.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._mirrors: Dict[_CacheKey, Any] = {}
        self._origins: Dict[int, Any] = {}  # mirror_id -> original
        self._generation: int = 0
        self._weak_refs: Dict[int, weakref.ref] = {}  # obj_id -> weakref

    # ── Public API ────────────────────────────────────────────────────────

    def mirror(
        self,
        obj: Any,
        *,
        pre: HookFn = None,
        post: HookFn = None,
        name: Optional[str] = None,
    ) -> Any:
        """Create an instrumented mirror of `obj`.

        Args:
            obj: A function, method, class, or any callable.
            pre: Called before each invocation with (obj, args, kwargs).
                 May return a modified (args, kwargs) tuple or None.
            post: Called after each invocation with (obj, result).
                  May return a replacement result or None.
            name: Optional override for the mirror's display name.

        Returns:
            An instrumented mirror that is call-compatible with `obj`.
        """
        with self._lock:
            key = self._make_key(obj, name)

            if key in self._mirrors:
                return self._mirrors[key]

            if isinstance(obj, type):
                mirrored = self._mirror_class(obj, pre=pre, post=post, name=name)
            elif isinstance(obj, (staticmethod, classmethod)):
                mirrored = self._mirror_descriptor(obj, pre=pre, post=post, name=name)
            elif callable(obj):
                mirrored = self._mirror_function(obj, pre=pre, post=post, name=name)
            else:
                raise MirrorError(
                    f"Cannot mirror {type(obj).__name__!r} — object is not callable"
                )

            self._mirrors[key] = mirrored
            self._origins[id(mirrored)] = obj
            return mirrored

    def unmirror(self, mirrored: Any) -> Any:
        """Retrieve the original object from a mirror. Raises if not found."""
        with self._lock:
            mid = id(mirrored)
            if mid not in self._origins:
                raise MirrorError("Object is not a registered mirror")
            return self._origins[mid]

    def is_mirrored(self, obj: Any) -> bool:
        """Check whether `obj` is a mirror created by this registry."""
        with self._lock:
            return id(obj) in self._origins

    def clear(self) -> None:
        """Discard all mirrors and origins."""
        with self._lock:
            self._mirrors.clear()
            self._origins.clear()
            self._weak_refs.clear()
            self._generation += 1

    @property
    def mirror_count(self) -> int:
        with self._lock:
            return len(self._mirrors)

    # ── Cache Key Construction ────────────────────────────────────────────

    def _make_key(self, obj: Any, name: Optional[str]) -> _CacheKey:
        obj_id = id(obj)
        qualname = name or getattr(obj, "__qualname__", None) or repr(obj)

        # Install a weak-ref finalizer to bump generation on GC
        if obj_id not in self._weak_refs:
            try:
                ref = weakref.ref(obj, self._on_gc)
                self._weak_refs[obj_id] = ref
            except TypeError:
                pass  # Not weak-referenceable (e.g. built-in)

        return _CacheKey(obj_id, qualname, self._generation)

    def _on_gc(self, ref: weakref.ref) -> None:
        """Weak-ref callback: bump generation so stale ids aren't reused."""
        with self._lock:
            self._generation += 1
            # Evict dead entries — they'll never match again anyway
            dead = [k for k, v in self._mirrors.items()
                    if k.generation < self._generation]
            for k in dead:
                mirror = self._mirrors.pop(k, None)
                if mirror is not None:
                    self._origins.pop(id(mirror), None)

    # ── Function Mirroring ────────────────────────────────────────────────

    def _mirror_function(
        self,
        fn: Callable,
        *,
        pre: HookFn,
        post: HookFn,
        name: Optional[str],
    ) -> Callable:
        @functools.wraps(fn)
        def instrumented(*args: Any, **kwargs: Any) -> Any:
            call_args, call_kwargs = args, kwargs

            if pre is not None:
                override = pre(fn, call_args, call_kwargs)
                if override is not None:
                    call_args, call_kwargs = override

            result = fn(*call_args, **call_kwargs)

            if post is not None:
                replacement = post(fn, result)
                if replacement is not None:
                    result = replacement

            return result

        instrumented.__mirror_origin__ = fn
        instrumented.__mirror_registry__ = weakref.ref(self)
        if name:
            instrumented.__name__ = name
            instrumented.__qualname__ = name
        return instrumented

    # ── Descriptor Mirroring ──────────────────────────────────────────────

    def _mirror_descriptor(
        self,
        desc: Union[staticmethod, classmethod],
        *,
        pre: HookFn,
        post: HookFn,
        name: Optional[str],
    ) -> Union[staticmethod, classmethod]:
        inner = desc.__func__
        mirrored_inner = self._mirror_function(inner, pre=pre, post=post, name=name)
        if isinstance(desc, staticmethod):
            return staticmethod(mirrored_inner)
        return classmethod(mirrored_inner)

    # ── Class Mirroring ───────────────────────────────────────────────────

    def _mirror_class(
        self,
        cls: type,
        *,
        pre: HookFn,
        post: HookFn,
        name: Optional[str],
    ) -> type:
        # Respect the original metaclass
        metaclass = type(cls)
        cls_name = name or cls.__name__

        # Build new namespace from the original, mirroring callable members
        namespace: Dict[str, Any] = {}
        for attr_name, attr_value in cls.__dict__.items():
            if attr_name.startswith("__") and attr_name.endswith("__"):
                # Preserve dunders as-is (except __init__ and __call__)
                if attr_name in ("__init__", "__call__", "__new__"):
                    if callable(attr_value):
                        namespace[attr_name] = self._mirror_function(
                            attr_value, pre=pre, post=post, name=f"{cls_name}.{attr_name}"
                        )
                    else:
                        namespace[attr_name] = attr_value
                else:
                    namespace[attr_name] = attr_value
            elif isinstance(attr_value, staticmethod):
                namespace[attr_name] = self._mirror_descriptor(
                    attr_value, pre=pre, post=post, name=f"{cls_name}.{attr_name}"
                )
            elif isinstance(attr_value, classmethod):
                namespace[attr_name] = self._mirror_descriptor(
                    attr_value, pre=pre, post=post, name=f"{cls_name}.{attr_name}"
                )
            elif isinstance(attr_value, property):
                # Mirror the getter/setter/deleter if present
                fget = (self._mirror_function(attr_value.fget, pre=pre, post=post,
                        name=f"{cls_name}.{attr_name}.getter")
                        if attr_value.fget else None)
                fset = (self._mirror_function(attr_value.fset, pre=pre, post=post,
                        name=f"{cls_name}.{attr_name}.setter")
                        if attr_value.fset else None)
                fdel = (self._mirror_function(attr_value.fdel, pre=pre, post=post,
                        name=f"{cls_name}.{attr_name}.deleter")
                        if attr_value.fdel else None)
                namespace[attr_name] = property(fget, fset, fdel, attr_value.__doc__)
            elif callable(attr_value) and isinstance(attr_value, types.FunctionType):
                namespace[attr_name] = self._mirror_function(
                    attr_value, pre=pre, post=post, name=f"{cls_name}.{attr_name}"
                )
            elif isinstance(attr_value, types.MemberDescriptorType):
                # Slot descriptors — skip; they'll be re-created by __slots__
                continue
            else:
                namespace[attr_name] = attr_value

        # Handle __slots__: mirror the slot declarations but skip any that
        # would conflict with descriptors already created by mirrored methods.
        # We also can't re-declare slots inherited from bases.
        if "__slots__" in cls.__dict__:
            original_slots = cls.__dict__["__slots__"]
            if isinstance(original_slots, str):
                original_slots = (original_slots,)
            # Filter out slots that would conflict with namespace entries
            # (e.g., mirrored methods that replaced the slot descriptor)
            safe_slots = tuple(
                s for s in original_slots
                if s not in namespace or s in ("__dict__", "__weakref__")
            )
            if safe_slots:
                namespace["__slots__"] = safe_slots

        # Preserve the module
        namespace.setdefault("__module__", cls.__module__)
        namespace.setdefault("__qualname__", cls.__qualname__)

        # Build the mirrored class with the same bases
        mirrored_cls = metaclass(cls_name, cls.__bases__, namespace)
        mirrored_cls.__mirror_origin__ = cls
        mirrored_cls.__mirror_registry__ = weakref.ref(self)
        return mirrored_cls


# ─── Blend Slot ──────────────────────────────────────────────────────────────

@dataclass(slots=True)
class _BlendSlot:
    """Tracks one blended binding so we can revert it in O(1)."""
    kind: str                   # "module" | "globals" | "builtins"
    target: Any                 # the dict or module we patched
    attr_name: str              # the key/attribute name
    original: Any               # the value that was there before (sentinel if absent)
    had_original: bool          # whether the attr existed before blending


_SENTINEL = object()


# ─── Blender ─────────────────────────────────────────────────────────────────

class Blender:
    """Namespace injection engine with O(1) revert and context-manager support.

    Usage:
        registry = MirrorRegistry()
        mirror = registry.mirror(my_func, pre=hook)

        with Blender(registry) as b:
            b.blend_into_module(target_module, "my_func", mirror)
            # ... target_module.my_func is now instrumented ...
        # reverted automatically
    """

    def __init__(self, registry: MirrorRegistry) -> None:
        self._registry = registry
        self._lock = threading.RLock()
        self._blends: Dict[str, _BlendSlot] = {}
        self._closed = False

    # ── Context Manager ───────────────────────────────────────────────────

    def __enter__(self) -> Blender:
        return self

    def __exit__(self, *exc_info: Any) -> None:
        self.revert_all()

    # ── Blend Operations ──────────────────────────────────────────────────

    def blend_into_module(
        self,
        module: types.ModuleType,
        attr_name: str,
        mirror: Any,
        *,
        key: Optional[str] = None,
    ) -> str:
        """Replace `module.attr_name` with `mirror`. Returns the blend key."""
        if not isinstance(module, types.ModuleType):
            raise BlendError(f"Expected a module, got {type(module).__name__}")

        blend_key = key or f"module:{module.__name__}.{attr_name}"

        with self._lock:
            self._check_open()
            had = hasattr(module, attr_name)
            original = getattr(module, attr_name, _SENTINEL)
            setattr(module, attr_name, mirror)

            self._blends[blend_key] = _BlendSlot(
                kind="module",
                target=module,
                attr_name=attr_name,
                original=original,
                had_original=had,
            )
        return blend_key

    def blend_into_globals(
        self,
        target_globals: Dict[str, Any],
        name: str,
        mirror: Any,
        *,
        key: Optional[str] = None,
    ) -> str:
        """Inject `mirror` into a globals dict under `name`. Returns the blend key."""
        if not isinstance(target_globals, dict):
            raise BlendError(f"Expected a dict, got {type(target_globals).__name__}")

        blend_key = key or f"globals:{id(target_globals):#x}.{name}"

        with self._lock:
            self._check_open()
            had = name in target_globals
            original = target_globals.get(name, _SENTINEL)
            target_globals[name] = mirror

            self._blends[blend_key] = _BlendSlot(
                kind="globals",
                target=target_globals,
                attr_name=name,
                original=original,
                had_original=had,
            )
        return blend_key

    def blend_into_builtins(
        self,
        name: str,
        mirror: Any,
        *,
        key: Optional[str] = None,
    ) -> str:
        """Inject `mirror` into builtins. Use with extreme caution. Returns the blend key."""
        warnings.warn(
            f"Blending {name!r} into builtins — this affects the entire process",
            stacklevel=2,
        )
        blend_key = key or f"builtins:{name}"

        with self._lock:
            self._check_open()
            had = hasattr(builtins, name)
            original = getattr(builtins, name, _SENTINEL)
            setattr(builtins, name, mirror)

            self._blends[blend_key] = _BlendSlot(
                kind="builtins",
                target=builtins,
                attr_name=name,
                original=original,
                had_original=had,
            )
        return blend_key

    # ── Revert ────────────────────────────────────────────────────────────

    def revert(self, key: str) -> None:
        """Revert a single blend by key."""
        with self._lock:
            if key not in self._blends:
                raise BlendError(f"No blend registered under key {key!r}")
            slot = self._blends.pop(key)
            self._revert_slot(key, slot)

    def revert_all(self) -> None:
        """Revert all blends. Collects errors and raises RevertError if any fail."""
        with self._lock:
            self._closed = True
            failures: List[Tuple[str, Exception]] = []
            keys = list(self._blends.keys())

            for key in reversed(keys):  # LIFO order — last blended, first reverted
                slot = self._blends.pop(key)
                try:
                    self._revert_slot(key, slot)
                except Exception as e:
                    failures.append((key, e))

            if failures:
                raise RevertError(failures)

    @property
    def blend_count(self) -> int:
        with self._lock:
            return len(self._blends)

    @property
    def blend_keys(self) -> List[str]:
        with self._lock:
            return list(self._blends.keys())

    # ── Internal ──────────────────────────────────────────────────────────

    def _revert_slot(self, key: str, slot: _BlendSlot) -> None:
        if slot.kind == "module" or slot.kind == "builtins":
            if slot.had_original:
                setattr(slot.target, slot.attr_name, slot.original)
            else:
                try:
                    delattr(slot.target, slot.attr_name)
                except AttributeError:
                    pass  # Already gone
        elif slot.kind == "globals":
            if slot.had_original:
                slot.target[slot.attr_name] = slot.original
            else:
                slot.target.pop(slot.attr_name, None)

    def _check_open(self) -> None:
        if self._closed:
            raise BlendError("This Blender has been closed (revert_all was called)")


# ─── AdaptiveWrapper ─────────────────────────────────────────────────────────

class AdaptiveWrapper:
    """A smart callable proxy that adapts its behavior to the runtime environment.

    Detects debuggers, profilers, and tracing tools and adjusts instrumentation
    overhead accordingly. Forwards all attribute access to the wrapped target.

    Usage:
        wrapper = AdaptiveWrapper(my_callable, registry)
        result = wrapper(arg1, arg2)  # delegates to my_callable
    """

    __slots__ = (
        "_target",
        "_registry",
        "_pre",
        "_post",
        "_name",
        "_adapt_cache",
        "_adapt_lock",
    )

    class Mode:
        """Instrumentation intensity levels."""
        FULL = "full"           # All hooks active
        LIGHTWEIGHT = "light"   # Skip expensive post-processing
        PASSTHROUGH = "pass"    # Zero overhead — direct delegation
        TRACE = "trace"         # Enhanced output for debugger sessions

    def __init__(
        self,
        target: Callable,
        registry: MirrorRegistry,
        *,
        pre: HookFn = None,
        post: HookFn = None,
        name: Optional[str] = None,
    ) -> None:
        self._target = target
        self._registry = registry
        self._pre = pre
        self._post = post
        self._name = name or getattr(target, "__name__", repr(target))
        self._adapt_cache: Optional[str] = None
        self._adapt_lock = threading.Lock()

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        mode = self._adapt()

        if mode == self.Mode.PASSTHROUGH:
            return self._target(*args, **kwargs)

        call_args, call_kwargs = args, kwargs

        if self._pre is not None and mode != self.Mode.PASSTHROUGH:
            override = self._pre(self._target, call_args, call_kwargs)
            if override is not None:
                call_args, call_kwargs = override

        result = self._target(*call_args, **call_kwargs)

        if self._post is not None and mode == self.Mode.FULL:
            replacement = self._post(self._target, result)
            if replacement is not None:
                result = replacement

        if mode == self.Mode.TRACE:
            # Enhanced: emit trace info for debugger sessions
            frame = sys._getframe(1) if hasattr(sys, "_getframe") else None
            caller = f"{frame.f_code.co_filename}:{frame.f_lineno}" if frame else "?"
            sys.stderr.write(
                f"[TRACE] {self._name}("
                f"{', '.join(map(repr, call_args[:3]))}"
                f"{'...' if len(call_args) > 3 else ''}"
                f") -> {repr(result)[:80]} from {caller}\n"
            )

        return result

    def _adapt(self) -> str:
        """Detect the runtime environment and choose instrumentation mode.

        Cached per-call-site — re-evaluates when tracing state changes.
        """
        # Fast path: check cache
        with self._adapt_lock:
            current_trace = sys.gettrace()
            current_profile = sys.getprofile() if hasattr(sys, "getprofile") else None

            if current_trace is not None and current_profile is not None:
                # Both debugger AND profiler active — minimize overhead
                return self.Mode.LIGHTWEIGHT
            elif current_trace is not None:
                # Debugger active — provide trace output
                return self.Mode.TRACE
            elif current_profile is not None:
                # Profiler active — skip post-hooks to reduce noise
                return self.Mode.LIGHTWEIGHT
            else:
                # Normal execution — full instrumentation
                return self.Mode.FULL

    def __getattr__(self, name: str) -> Any:
        """Proxy attribute access to the wrapped target."""
        return getattr(self._target, name)

    def __repr__(self) -> str:
        mode = self._adapt()
        return (
            f"<AdaptiveWrapper [{mode}] "
            f"target={self._name} "
            f"pre={'yes' if self._pre else 'no'} "
            f"post={'yes' if self._post else 'no'}>"
        )

    def __str__(self) -> str:
        return f"AdaptiveWrapper({self._name})"

    @property
    def __name__(self) -> str:
        return self._name

    @property
    def __wrapped__(self) -> Callable:
        return self._target

    @property
    def mode(self) -> str:
        return self._adapt()
