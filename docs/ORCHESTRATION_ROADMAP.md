# Orchestration & Intelligence — Roadmap

Follow-ups from the 2026-06-11 review of the orchestration/intelligence layer
(`node_manager`, `director`, `llm_backend`, `autonomous`, `mirror_blend`).

**#1 — Close the orchestration loop: DONE** (`9bca569`). NodeManager ↔
AutonomousLoop ↔ HotUpgrader are wired: real upgrade execution, closed-loop
healing (degrade → heal task → discovery → online), campaign pause/stop
enforcement, CLI wires a NodeManager into `matrix director start`.

---

## #2 — Give the intelligence real eyes: active probing + `transport_probe`

The Director's LLM makes decisions on incomplete data; node health is passive.

- [ ] **Active node probing** — `node_manager.py` `_health_tick()` only marks
      nodes degraded on stale heartbeat (>30s). Add a `_probe_node()` that
      measures TCP reachability/latency to `address:port` and computes a task
      success rate from recent `task_history`, feeding `node.path_health`.
      Distinguishes "network flake" from "node dead" and can drive the
      degraded→offline transition on evidence rather than just age.
      Builds on #1: the heal loop currently relies on discovery refresh only.
- [ ] **Populate `transport_probe`** — `director.py:1229`:
      `SemanticDelta.transport_probe` is always `None`. Query the
      TransportNegotiator during delta assembly so the LLM actually sees
      transport health — especially for `TRANSPORT_TOTAL_FAILURE` escalations.
- [ ] **Per-trigger delta validation** — `SemanticDelta.validate()`
      (director.py:132) is type-checks only. Add `validate_for_trigger()`:
      e.g. `TRANSPORT_TOTAL_FAILURE` requires non-null `transport_probe`,
      `ALL_PATHS_DEGRADED` requires non-empty `path_health`,
      `TASK_FAILURE_RATE` requires non-empty `recent_task_failures`.
- [ ] **Don't swallow per-node health errors** during delta assembly
      (director.py:1195) — log and continue instead of silently dropping.

**Unlocks:** better LLM decisions (the point of the Tri-State Director),
path-aware failover input for multipath routing.

## #3 — Production-grade LLM backend: retries, backoff, configurable limits

`llm_backend.py` is brittle exactly when it matters — escalations happen
*while things are already failing*.

- [ ] **Retry + backoff** — lines ~129-133 / ~198-202: single attempt, no
      retry; one transient hiccup → `LLMError` → escalation fails → human
      intervention. Add a shared retry wrapper (exponential backoff, e.g.
      base 2s / max 5 attempts), classify retryable (timeout, 5xx, 429,
      connection refused) vs fatal (400/401/404) errors.
- [ ] **Circuit breaker** — after N consecutive failures, reject attempts for
      a cool-off window instead of hammering a down provider.
- [ ] **Configurable `max_tokens`** — hardcoded to 1024 (line ~183); long
      escalation summaries get silently truncated. Add config knob
      (`llm_max_tokens`), plus `llm_max_retries` / `llm_backoff_base_ms`.
- [ ] **Update pinned API version** — `anthropic-version: 2023-06-01`
      (line ~194); review against current API before bumping.
- [ ] **Retry-aware logging** — include attempt count/backoff in error
      context so escalation audit logs show what happened.

**Unlocks:** the AI tier actually being available during the degraded
conditions it exists for. ~60 lines of code.

## Smaller items noted during review (fold in opportunistically)

- Director reaches into other components' privates: `_multipath._paths`
  (director.py:671), `_resilience_mgr._slots` (:382),
  `_sync_mgr._rate_limiter` (:721). Add public APIs
  (`MultiPathConnection.set_weights()`, `ResilienceManager.exhausted_slots()`,
  `SyncManager.set_rate()`) — natural to do alongside #2.
- `AutonomousLoop._upgrade_health_check()` (autonomous.py:797) is a no-op
  pass-through; give upgrades a real default health check.
- `TaskType.TERMINATE / SYNC / RELAY` have no built-in handlers — tasks fail
  with "no handler" unless one is registered.
- Line references are as of `9bca569`; expect drift.
