# Orchestration & Intelligence — Roadmap

Follow-ups from the 2026-06-11 review of the orchestration/intelligence layer
(`node_manager`, `director`, `llm_backend`, `autonomous`, `mirror_blend`).

**#1 — Close the orchestration loop: DONE** (`9bca569`). NodeManager ↔
AutonomousLoop ↔ HotUpgrader are wired: real upgrade execution, closed-loop
healing (degrade → heal task → discovery → online), campaign pause/stop
enforcement, CLI wires a NodeManager into `matrix director start`.

---

## #2 — Give the intelligence real eyes: active probing + `transport_probe`: DONE

The Director's LLM made decisions on incomplete data; node health was passive.

- [x] **Active node probing** — `node_manager.py` gained `_tcp_probe()`
      (reachability + connect latency), `_recent_success_rate()` (DONE vs FAILED
      over the last N `task_history` tasks), and `_probe_node()` which merges a
      `probe` snapshot into `node.path_health`. `_health_tick()` now probes
      degraded nodes **outside the lock** and promotes degraded→offline on
      *sustained* evidence (`probe_fail_threshold` consecutive failures + stale
      heartbeat), distinguishing a network flake (reachable but stale) from a
      dead node. Opt-in via `probe_enabled` (on in the CLI wiring; off by default
      so unit tests stay deterministic).
- [x] **Populate `transport_probe`** — `TriStateDirector._build_transport_probe()`
      summarizes MultiPath health (paths total/healthy, `all_degraded`, transport
      list) and folds in the negotiator's `event.details` for
      `TRANSPORT_TOTAL_FAILURE`. Derived from the existing health snapshot, **not**
      a live re-probe — a blocking `negotiate()` on the escalation path is unsafe
      when transports are already failing.
- [x] **Per-trigger delta validation** — `SemanticDelta.validate_for_trigger()`
      returns `(ok, missing)`: `TRANSPORT_TOTAL_FAILURE`→`transport_probe`,
      `ALL_PATHS_DEGRADED`→`path_health`, `TASK_FAILURE_RATE`→`recent_task_failures`.
      `_build_semantic_delta` logs a warning on missing evidence but still proceeds
      (a thin delta beats dropping a real escalation).
- [x] **Don't swallow per-node health errors** during delta assembly — node-health
      collection is now per-node try/except at warning level, so one bad node no
      longer drops the rest.

**Unlocked:** better LLM decisions (the point of the Tri-State Director),
path-aware failover input for multipath routing. Covered by 16 new tests
(`TestNodeManagerProbing`, `TestTransportProbe`, trigger-aware delta validation).

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
