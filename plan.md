# Plan: Rewrite MirrorRegistry / Blender / AdaptiveWrapper

## Problem Statement

The original code has significant issues:
1. **Missing imports**: `Dict`, `Optional`, `Tuple`, `wraps`, `sys` are used but never imported
2. **Bug in `_mirror_function`**: inner `**kwargs_` works but the outer `**kwargs` from the method signature is silently swallowed — callers passing `**kwargs` to `_mirror_function` think they're configuring behavior but those kwargs vanish
3. **`blend_into_frame` is unreliable**: writing to `frame.f_locals` is a no-op on CPython (it's a snapshot copy, not a live dict) — this is a fundamental design flaw, not just a caveat
4. **`revert_all` iterates `gc.get_objects()`**: O(n) over every Python object in the heap — catastrophically slow in real applications with millions of objects
5. **`AdaptiveWrapper` is incomplete**: `_adapt()` body is cut off, class isn't callable (`__call__` missing)
6. **`_mirror_class` is fragile**: copies `cls.__dict__` (a `mappingproxy`) into `type()` constructor, which can fail or produce broken classes; ignores `__slots__`, metaclasses, descriptors, `classmethod`/`staticmethod`
7. **No thread safety**: shared mutable `_mirrors`/`_origins`/`blended_objects` dicts with no locking
8. **Mirror cache uses `id(obj)`**: object IDs can be reused after GC — stale cache hits
9. **No `__call__` on `AdaptiveWrapper`**: registered as fallback for non-function/method/class callables but can't actually be called
10. **No context manager protocol**: `Blender` should support `with` for safe cleanup
11. **No integration with the existing project**: needs to fit the Matrix theme

## Implementation Plan

### Step 1: Create `mirror_blend.py` — the rewritten module

A clean, correct rewrite with the following structure:

```
mirror_blend.py
├── MirrorRegistry        — fixed cache key, thread-safe, proper mirroring
├── Blender               — context manager, no gc.get_objects(), no frame hacks
├── AdaptiveWrapper       — complete, callable, environment-aware
└── module-level helpers  — convenience functions
```

#### MirrorRegistry fixes:
- Add all missing imports (`sys`, `functools.wraps`, `typing.Dict/Optional/Tuple`, `threading.RLock`)
- Fix cache key: use `(id(obj), type(obj).__name__, name)` tuple + `weakref` callback to evict on GC
- Thread-safe with `threading.RLock` around `_mirrors`/`_origins`
- `_mirror_function`: properly separate config kwargs from call kwargs; use `functools.wraps` (imported correctly); add pre/post hooks as the instrumentation point
- `_mirror_method`: handle unbound correctly (Python 3 has no unbound methods — `MethodType.__self__` is always set)
- `_mirror_class`: use `type(cls)` as metaclass to respect custom metaclasses; handle `staticmethod`/`classmethod`/property/descriptors; preserve `__slots__` by detecting and handling them; use `__init_subclass__` properly
- Add `unmirror(obj)` to retrieve the original
- Add `is_mirrored(obj)` check

#### Blender fixes:
- Remove `blend_into_frame` entirely — it fundamentally cannot work on CPython and is a foot-gun
- `blend_into_globals`: store a direct reference to the dict itself (not rely on `gc.get_objects()` scan) for O(1) revert
- `blend_into_builtins`: store the name directly for O(1) revert
- `blend_into_module`: store `(module, name)` tuple for O(1) revert
- Add `__enter__`/`__exit__` for context manager protocol (`with Blender(registry) as b:`)
- `revert_all`: iterate stored references directly — no gc scan, no silent `except: pass`; collect errors and raise a single summary exception if any revert failed
- Add `revert(key)` for selective revert of a single blend
- Add logging via `warnings.warn` for dangerous operations (builtins injection)

#### AdaptiveWrapper completion:
- Add `__call__` method that delegates to `_target`
- Complete `_adapt()`: detect debugger (`sys.gettrace()`), profiler (`sys.getprofile()`), and user-supplied context hints
- Add `__repr__`, `__str__`, `__name__` property for debuggability
- Make it a proper proxy: forward `__getattr__` to `_target` so attribute access works

### Step 2: Add `test_mirror_blend.py` — comprehensive tests

Test cases:
- **MirrorRegistry**:
  - Mirror a plain function → verify call-through works, signature preserved
  - Mirror a method → verify binding preserved
  - Mirror a class → verify instantiation, method calls, isinstance checks
  - Mirror same object twice → verify cache returns same mirror
  - Mirror with pre/post hooks → verify hooks fire
  - Thread safety: concurrent mirror creation from multiple threads
- **Blender**:
  - `blend_into_module` → verify attribute replaced, revert restores original
  - `blend_into_globals` → verify dict updated, revert restores
  - `blend_into_builtins` → verify available globally, revert cleans up
  - Context manager → verify auto-revert on exit
  - Context manager with exception → verify revert still happens
  - `revert(key)` → selective revert
- **AdaptiveWrapper**:
  - Wraps a lambda → callable, returns correct result
  - `__repr__` shows useful info
  - Attribute forwarding to target
  - Adaptation detection (mock `sys.gettrace`)

### Step 3: Update `gut_check.py` integration

Add an optional `--instrumented` flag to `gut_check.py` that demonstrates the mirror/blend system by:
- Mirroring `random_glyph()` with a hook that counts calls per frame
- Blending a profiled version of `Stream.update` that tracks timing
- Printing a small stats line at the bottom of the terminal showing calls/frame and avg update time
- All done via context manager so cleanup is automatic on Ctrl+C

This serves as both a demo and integration test with the existing codebase.

### Step 4: Commit and push

Single commit with clear message describing the new module, tests, and integration.

## Files Changed

| File | Action | Description |
|---|---|---|
| `mirror_blend.py` | **Create** | Complete rewrite of the mirror/blend framework |
| `test_mirror_blend.py` | **Create** | Comprehensive test suite |
| `gut_check.py` | **Edit** | Add optional `--instrumented` demo mode |
