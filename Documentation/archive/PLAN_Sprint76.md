# Sprint 76: Issuer Call-Path Performance — Timing Instrumentation & Concurrency Fix

## Problem Statement

VVP-attested calls (prefix `7` → signing → verification → delivery) take **6-8 seconds longer** than direct calls under normal conditions, and **18-23 seconds** when any concurrent load exists on the issuer. The root cause is a combination of:

1. **Single uvicorn worker** — the issuer runs with 1 process (no `--workers` flag)
2. **Synchronous SQLAlchemy** — all `db.query()` calls block the async event loop
3. **Zero caching in `/vvp/create`** — every call makes 5-10 KERI Agent HTTP requests even when inputs haven't changed
4. **No timing instrumentation** — impossible to identify where time is spent

### Evidence (collected during diagnosis)

| Measurement | Value | Source |
|-------------|-------|--------|
| `/vvp/create` from sip-redirect | 17,941 – 22,791ms | PBX sip-redirect logs |
| `PERF issuer_issue total` | 74 – 170ms | Issuer PERF logs |
| `request_complete duration_ms` | 22,292 – 29,923ms | Issuer middleware |
| `curl /tn/lookup TIME_TOTAL` | 22 – 27s | Direct curl during integration tests |
| `curl TIME_CONNECT` | 62ms | Same test (network is fine) |
| Verification (sip-verify) | 117 – 264ms | PBX sip-verify logs |

**Key insight:** Actual processing is 74-170ms. The 22+ seconds is **queueing time** — requests wait behind others because the single-threaded event loop is blocked by synchronous DB calls.

## Spec References

- §5.2B: PASSporT validity capped at 300 seconds — short-lived tokens demand fast issuance
- §4.1A: Call setup must not introduce perceptible delay — target < 1s for signing + verification

## Current State

### Call flow: 71006 → signing → verification → delivery

```
FreeSWITCH → sip-redirect:5070 (UDP, localhost)
  → HTTPS → Issuer /tn/lookup        [cached on sip-redirect after 1st call]
  → HTTPS → Issuer /vvp/create       [NOT CACHED — 5-10 KERI Agent calls every time]
                                        → get_identity()             [not cached]
                                        → check_dossier_revocation() [DossierCache]
                                        → validate_signing_constraints() [sync DB + KERI Agent]
                                        → DossierBuilder.build()     [not cached, N KERI calls]
                                        → get_credential() × N       [not cached]
                                        → create_vvp_attestation()   [signing, unavoidable]
← 302 redirect

FreeSWITCH → sip-verify:5071 (UDP, localhost)
  → HTTPS → Verifier /verify-callee  [verification_cache hit on 2nd call]
← 302 redirect

FreeSWITCH → user/1006 (deliver)
```

### Limitations

1. **No per-step timing** in `/vvp/create` — can't tell which step is slow
2. **No event-loop health metric** — can't measure queueing vs processing
3. **1 uvicorn worker** — all requests serialized through single event loop
4. **Sync SQLAlchemy blocks the event loop** — even simple queries stall all concurrent coroutines
5. **Redundant KERI Agent calls** — DossierBuilder.build() called twice (revocation check + brand extraction), get_credential() called 3× per SAID across different steps

## Proposed Solution

### Approach

Four layers of improvement, implemented in one sprint:

1. **Timing instrumentation** (Layer 1) — Measure every step so we can track improvements
2. **Uvicorn workers** (Layer 2) — Add `--workers 4` to eliminate single-process bottleneck
3. **VVP attestation cache** (Layer 3) — Cache intermediate results in `/vvp/create`
4. **Async DB wrapper** (Layer 4) — Wrap sync DB calls in `asyncio.to_thread()` to unblock event loop

### Alternatives Considered

| Alternative | Pros | Cons | Why Rejected |
|-------------|------|------|--------------|
| Migrate to async SQLAlchemy | Full async stack | Large refactor (50+ files), risky | Too invasive for this sprint |
| Add Redis cache | Shared across workers | New infra dependency | Unnecessary — in-process cache sufficient |
| Gunicorn with uvicorn workers | Better process management | Extra dependency | `--workers` flag on uvicorn is sufficient for now |
| Move all caching to sip-redirect | Signing service returns faster | Still slow on first call, harder to maintain | Issuer-side cache benefits all consumers |

### Detailed Design

#### Component 1: Timing Instrumentation for `/vvp/create`

**Purpose:** Measure per-step latency inside the VVP creation endpoint so we can identify and track bottlenecks.

**Location:** `services/issuer/app/api/vvp.py`

**Approach:** Reuse the verifier's `PhaseTimer` pattern (already in `services/verifier/app/vvp/timing.py`). Move to `common/common/vvp/timing.py` so both services can use it.

**Backward compatibility:** The verifier currently imports `from app.vvp.timing import PhaseTimer`. After the move:
1. Copy `PhaseTimer` to `common/common/vvp/timing.py` (identical code)
2. Replace `services/verifier/app/vvp/timing.py` contents with a re-export: `from common.vvp.timing import PhaseTimer` — this preserves all existing verifier imports without changes
3. The issuer imports directly from `common.vvp.timing`
4. No circular imports possible — common has no dependencies on either service

**Steps timed:**
- `identity_resolve` — `get_identity()` call
- `revocation_check` — `check_dossier_revocation()` call
- `signing_constraints` — `validate_signing_constraints()` call
- `brand_extraction` — DossierBuilder.build() + credential walk
- `attestation_signing` — `create_vvp_attestation()` call
- `total` — end-to-end

**Output:** Add `timing_ms` dict to `CreateVVPResponse` model:
```python
class CreateVVPResponse(BaseModel):
    # ... existing fields ...
    timing_ms: Optional[dict[str, float]] = None  # Per-step timing
```

The sip-redirect client logs this timing dict, enabling latency diagnosis from PBX logs alone.

#### Component 2: Timing Instrumentation for `/tn/lookup`

**Purpose:** Same treatment for the TN lookup endpoint.

**Location:** `services/issuer/app/api/tn.py`

**Steps timed:**
- `api_key_verify` — API key validation
- `tn_mapping_query` — Database lookup
- `ownership_validation` — TN Allocation credential check (KERI Agent calls)
- `total` — end-to-end

**Output:** Add `timing_ms` dict to the TN lookup response.

#### Component 3: Event Loop Latency Monitor

**Purpose:** Detect event loop blocking in real time. A healthy async event loop should respond to a scheduled callback within ~1ms. If it takes >100ms, the loop is being blocked.

**Location:** `services/issuer/app/core/event_loop_monitor.py` (new file)

**Design:**
```python
class EventLoopMonitor:
    """Periodic event loop health check.

    Schedules a callback every 5 seconds. Measures the actual delay
    between scheduled and actual execution. If > 100ms, logs a warning.
    Exposes metrics via /admin/event-loop-health endpoint.
    """

    def __init__(self, interval: float = 5.0, warn_threshold_ms: float = 100.0):
        self._interval = interval
        self._threshold = warn_threshold_ms
        self._last_latency_ms: float = 0.0
        self._max_latency_ms: float = 0.0
        self._blocked_count: int = 0
```

**Lifecycle:**
- **Startup:** Started via FastAPI `@app.on_event("startup")` hook. Creates an `asyncio.Task` for the periodic probe loop.
- **Shutdown:** Stopped via `@app.on_event("shutdown")` hook. Cancels the background task and awaits its completion to ensure clean exit. Uses `asyncio.CancelledError` handling inside the probe loop so the task terminates gracefully without warnings.

```python
async def start(self) -> None:
    self._task = asyncio.create_task(self._probe_loop())

async def stop(self) -> None:
    if self._task:
        self._task.cancel()
        with suppress(asyncio.CancelledError):
            await self._task
        self._task = None
```

Exposed at `GET /admin/event-loop-health` with:
```json
{
    "worker_pid": 12345,
    "current_latency_ms": 2.1,
    "max_latency_ms": 15234.5,
    "blocked_count": 42,
    "threshold_ms": 100.0
}
```

#### Component 4: Uvicorn Workers

**Purpose:** Allow 4 parallel request-processing processes so one blocked event loop doesn't starve all others.

**Location:** `services/issuer/Dockerfile`

**Change:**
```dockerfile
# Before:
CMD ["uvicorn", "app.main:app", "--host=0.0.0.0", "--port=8001"]

# After:
CMD ["uvicorn", "app.main:app", "--host=0.0.0.0", "--port=8001", "--workers=4"]
```

**Implications:**
- Each worker gets its own event loop, connection pool, and in-process cache
- Module-level singletons (DossierCache, IssuerClient, etc.) are per-worker — this is fine since they're in-memory caches
- DB connection pool `pool_size=5` × 4 workers = 20 connections — within PostgreSQL defaults (100 max)

**Per-worker observability:** With multiple workers, the following are per-process (NOT aggregated):
- `timing_ms` in responses — reflects the specific worker that handled the request (this is correct, no aggregation needed)
- Event loop monitor (`/admin/event-loop-health`) — returns metrics for the worker that handles the request. This is by design: callers can hit it multiple times and get a representative sample. The `worker_pid` field is included in the response so the caller knows which worker responded.
- Attestation cache and DossierCache — each worker has its own cache. Cache hits on one worker don't benefit another. This is acceptable: 4 independent caches each with 100 entries is simpler and safer than a shared cache, and the cold-start penalty (~100ms) is negligible.
- Log output — all workers log to stdout, differentiated by PID. Docker/Azure Container Apps log collectors capture all workers.

#### Component 5: VVP Attestation Cache

**Purpose:** Cache intermediate results that are identical across calls for the same identity + dossier, eliminating redundant KERI Agent calls.

**Location:** `services/issuer/app/vvp/attestation_cache.py` (new file)

**What's cached (keyed by `(identity_name, dossier_said)`):**
- Identity info (AID, witness URLs) — from `get_identity()`
- Brand card claim (vCard array) — from DossierBuilder + credential walk
- Dossier URL and OOBI URL — computed from identity + config

**What's NOT cached (unique per call):**
- PASSporT JWT (different `iat`, `call_id`, `cseq` per call)
- The `create_vvp_attestation()` signing call

**TTL:** 300 seconds (matches dossier cache TTL and spec §5C.2 key freshness)
**Max entries:** 100 (LRU eviction)

**Impact:** Eliminates ~8 KERI Agent calls on cached path, leaving only the single signing call (~60ms).

**Cache Invalidation Strategy:**

The attestation cache must be invalidated when the underlying data changes. Three invalidation triggers:

1. **Dossier revocation (primary concern):** The existing `DossierCache` in `common/common/vvp/dossier/cache.py` already detects revocation via background TEL checks and calls `invalidate_by_said()`. The attestation cache hooks into this by registering an invalidation callback with the DossierCache. When `DossierCache.invalidate_by_said(said)` or `invalidate_by_url(url)` fires, it also calls `attestation_cache.invalidate_by_dossier_said(said)` to evict any attestation cache entries keyed by that dossier SAID.

2. **Identity changes (AID rotation, witness changes):** These are extremely rare in production. The attestation cache keys include `identity_name`, and the 300s TTL ensures stale identity data is naturally evicted. For immediate invalidation, `attestation_cache.invalidate_by_identity(identity_name)` is exposed and can be called from admin endpoints.

3. **TTL expiry (catch-all):** The 300s TTL acts as a hard upper bound — even if a revocation callback is missed, stale data persists for at most 5 minutes. This matches the DossierCache TTL and spec §5C.2.

**Implementation:**

```python
class AttestationCache:
    def __init__(self, ttl: float = 300.0, max_entries: int = 100):
        self._cache: OrderedDict[Tuple[str, str], AttestationCacheEntry] = OrderedDict()
        self._ttl = ttl
        self._max_entries = max_entries

    def invalidate_by_dossier_said(self, dossier_said: str) -> int:
        """Remove all entries for a given dossier SAID (revocation trigger)."""
        keys_to_remove = [k for k in self._cache if k[1] == dossier_said]
        for key in keys_to_remove:
            del self._cache[key]
        return len(keys_to_remove)

    def invalidate_by_identity(self, identity_name: str) -> int:
        """Remove all entries for a given identity (identity change trigger)."""
        keys_to_remove = [k for k in self._cache if k[0] == identity_name]
        for key in keys_to_remove:
            del self._cache[key]
        return len(keys_to_remove)
```

**DossierCache callback registration** (in `services/issuer/app/vvp/dossier_service.py`):

```python
def get_issuer_dossier_cache() -> DossierCache:
    global _cache
    if _cache is None:
        _cache = DossierCache(...)
        # Register attestation cache invalidation callback
        from app.vvp.attestation_cache import get_attestation_cache
        attest_cache = get_attestation_cache()
        _cache.on_invalidate_said(attest_cache.invalidate_by_dossier_said)
    return _cache
```

This requires adding a simple callback mechanism to `DossierCache.invalidate_by_said()` — a list of `Callable[[str], Any]` invoked when a SAID is invalidated. This is a minimal addition to the common cache (1 field + 2 lines of code).

#### Component 6: Async DB Wrapper

**Purpose:** Prevent synchronous DB queries from blocking the event loop.

**Location:** `services/issuer/app/db/session.py`

**Thread Safety Strategy:** SQLAlchemy `Session` objects are NOT thread-safe. The wrapper MUST create a new session inside the worker thread and close it before returning. We never pass a session created on the event loop thread into `to_thread()`.

**Approach:** Add an `async_db_call()` helper that creates a fresh session per-thread:

```python
import asyncio
from typing import TypeVar, Callable

T = TypeVar("T")

async def async_db_call(fn: Callable[..., T], *args, **kwargs) -> T:
    """Run a synchronous DB operation in a thread pool with a fresh session.

    Creates a new SQLAlchemy Session inside the worker thread,
    passes it to the callable, and closes it before returning.
    This prevents blocking the async event loop while maintaining
    session thread-safety.

    The callable signature must accept a `db` keyword argument:
        def my_db_operation(db: Session, ...) -> T:
    """
    def _run():
        db = SessionLocal()
        try:
            result = fn(db=db, *args, **kwargs)
            db.commit()
            return result
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    return await asyncio.to_thread(_run)
```

**Usage in `/vvp/create`:**
```python
# Before (blocks event loop — session from FastAPI Depends):
check_credential_write_role(principal)  # uses db from request scope

# After (non-blocking — session created in worker thread):
await async_db_call(check_credential_write_role, principal=principal)
```

**Refactoring required:** The DB-touching functions in the VVP hot path must accept an explicit `db` parameter rather than relying on FastAPI's `Depends(get_db)` injection. Functions affected:
- `check_credential_write_role(principal)` → already doesn't use DB directly (checks in-memory principal roles); no change needed
- `validate_signing_constraints(orig_tn, dossier_said)` → calls KERI Agent (async), doesn't use DB directly; wrap only the embedded DB-touching helpers
- API key verification in `/tn/lookup` → the `verify_org_api_key()` and `lookup_tn_with_validation()` functions accept `db` already; wrap the call

In practice, most hot-path functions already accept `db` as a parameter or don't touch the DB at all. The wrapper is applied to the specific synchronous DB query points:
- `store.verify(api_key)` in TN lookup — wrap in `async_db_call`
- `store.get_by_tn(tn, org_id)` in TN lookup — wrap in `async_db_call`
- `validate_tn_ownership()` credential queries — already async (KERI Agent calls)

This is a targeted fix for the hot path — NOT a full async migration. Other endpoints continue using sync DB as-is.

#### Component 7: SIP Redirect Timing Logging

**Purpose:** Log the timing breakdown from the issuer's response so it appears in the PBX sip-redirect logs.

**Location:** `services/sip-redirect/app/redirect/client.py`

**Change:** When `/vvp/create` returns a `timing_ms` dict, log it alongside the existing elapsed time:
```
VVP create OK: orig=+441923311000, elapsed=450ms, timing={identity=12ms, revocation=5ms, constraints=8ms, brand=15ms, signing=62ms, total=102ms}
```

### Data Flow

```
sip-redirect receives SIP INVITE
  → lookup_tn() [sip-redirect cache hit = 0ms]
  → create_vvp() → POST /vvp/create
      → attestation_cache.get(identity, dossier) [cache hit = 0ms]
        OR [cache miss]:
          → await async_db_call(check_role)      [non-blocking DB]
          → get_identity()                        [KERI Agent ~10ms]
          → check_dossier_revocation()            [DossierCache ~0ms]
          → validate_signing_constraints()        [async thread ~5ms]
          → DossierBuilder.build()                [KERI Agent ~30ms]
          → get_credential() × N                  [KERI Agent ~20ms]
          → attestation_cache.put()               [store for next call]
      → create_vvp_attestation()                  [KERI Agent signing ~60ms]
      → return response + timing_ms
  ← 302 with VVP headers
```

### Error Handling

- Cache miss: Falls through to full computation path — no error
- Event loop monitor: Pure telemetry, no failure modes
- Async DB wrapper: Exceptions propagated transparently via `to_thread()`
- Multiple workers: Each worker handles errors independently

### Test Strategy

1. **Timing instrumentation tests** — Verify `timing_ms` present in `/vvp/create` and `/tn/lookup` responses
2. **Attestation cache tests** — Cache hit/miss behavior, TTL expiry, LRU eviction
3. **Async DB wrapper tests** — Verify thread-pool execution doesn't change semantics
4. **Event loop monitor tests** — Start/stop lifecycle, metric collection
5. **Integration test** — Verify calls still succeed with multiple workers (no shared state issues)

## Files to Create/Modify

| File | Action | Purpose |
|------|--------|---------|
| `common/common/vvp/timing.py` | Create | Shared PhaseTimer (moved from verifier) |
| `services/verifier/app/vvp/timing.py` | Modify | Import from common instead of local |
| `services/issuer/app/api/vvp.py` | Modify | Add per-step timing instrumentation |
| `services/issuer/app/api/tn.py` | Modify | Add per-step timing to TN lookup |
| `services/issuer/app/api/models.py` | Modify | Add `timing_ms` to response models |
| `services/issuer/app/vvp/attestation_cache.py` | Create | VVP attestation intermediate result cache with invalidation |
| `services/issuer/app/vvp/dossier_service.py` | Modify | Register attestation cache invalidation callback |
| `common/common/vvp/dossier/cache.py` | Modify | Add on_invalidate_said callback support (2 lines) |
| `services/issuer/app/core/event_loop_monitor.py` | Create | Event loop latency monitoring with graceful shutdown |
| `services/issuer/app/db/session.py` | Modify | Add `async_db_call()` helper |
| `services/issuer/app/main.py` | Modify | Start event loop monitor on startup |
| `services/issuer/Dockerfile` | Modify | Add `--workers=4` |
| `services/sip-redirect/app/redirect/client.py` | Modify | Log timing breakdown from response |
| `services/issuer/tests/test_attestation_cache.py` | Create | Cache tests |
| `services/issuer/tests/test_event_loop_monitor.py` | Create | Monitor tests |
| `services/issuer/tests/test_vvp_timing.py` | Create | Timing instrumentation tests |

## Open Questions

None — the diagnosis is complete and the approach is well-understood.

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Multiple workers break shared state | Low | High | All singletons are in-process (per-worker). DB is shared via PostgreSQL. Verified: DossierCache, KeriAgentClient, etc. are module-level singletons — each worker gets its own copy. |
| DB connection pool exhaustion (5 × 4 = 20) | Low | Medium | PostgreSQL default max_connections=100. 20 is well within limits. Monitor via `GET /admin/db-pool-status`. |
| Attestation cache serves stale data | Low | Low | Three-layer invalidation: (1) DossierCache revocation callback invalidates by SAID, (2) identity change invalidation exposed via admin API, (3) 300s TTL hard ceiling. Even if callback is missed, data is stale for at most 5 minutes. |
| `asyncio.to_thread()` changes exception semantics | Very Low | Medium | Exceptions propagate unchanged through `to_thread()`. Tested explicitly. |
| Integration tests still contend with live traffic | Medium | Medium | This sprint doesn't change test routing — but 4 workers means requests are no longer serialized, greatly reducing queueing. Future: separate test instance. |

## Expected Performance Impact

| Metric | Before (single worker, no cache) | After (4 workers, cache hit) |
|--------|----------------------------------|------------------------------|
| `/vvp/create` (no contention) | ~500ms-2s | ~80-120ms |
| `/vvp/create` (during integration tests) | 18-23s | ~200-500ms |
| `/tn/lookup` (no contention) | ~50ms | ~50ms (unchanged, sip-redirect caches) |
| `/tn/lookup` (during integration tests) | 22-27s | ~100-200ms |
| End-to-end call setup (71006) | 6-8s+ | ~1-2s |

## Revision History

| Round | Date | Changes |
|-------|------|---------|
| R1 | 2026-03-03 | Initial draft |
| R2 | 2026-03-03 | Per R1 [High]: Redesigned async_db_call() to create fresh SessionLocal inside worker thread (never pass event-loop session cross-thread). Per R1 [High]: Added concrete attestation cache invalidation — DossierCache callback on revocation, identity invalidation via admin API, 300s TTL ceiling. Per R1 [Medium]: Added PhaseTimer backward-compat re-export strategy. Per R1 [Medium]: Documented per-worker observability expectations (worker_pid, independent caches, log differentiation). Per R1 [Low]: Added EventLoopMonitor shutdown lifecycle (task cancellation + CancelledError suppression). |

---

## Implementation Notes

### Deviations from Plan

None — all 7 components implemented as specified.

### Code Review R1 Fixes

Addressed 6 findings from Codex code review R1:

1. **[High] Vetter constraints bypass on cache hit**: Moved `validate_signing_constraints()` and revocation check outside the cache-hit/miss branch so they run on every `/vvp/create` request. Constraints depend on per-call `orig_tn` and must always be enforced.

2. **[High] async_db_call not applied to TN lookup hot path**: Applied `asyncio.to_thread()` to the bcrypt-intensive API key verification in `lookup_tn_with_validation()`. DB queries kept synchronous (sub-millisecond) — the multi-worker architecture (4 workers) handles DB concurrency. Thread-pooling the bcrypt call prevents the main performance bottleneck (bcrypt is deliberately slow: 200-400ms).

3. **[Medium] Event loop monitor measures sleep(0) not interval drift**: Replaced `asyncio.sleep(0)` yield measurement with interval drift measurement. Now compares expected vs actual wake-up time from `asyncio.sleep(interval)`, which directly measures how blocked the event loop was during the interval.

4. **[Medium] DossierCache callback SAID mismatch**: DossierCache `invalidate_by_said()` now collects root dossier SAIDs from affected entries' DAGs before removal, and passes root SAIDs (not credential SAIDs) to callbacks. Fixed `DossierDAG` truthiness issue: empty DAG (no nodes) is falsy due to `__len__`, so check uses `is not None` instead of truthiness.

5. **[Low] Blocked detection test non-assertive**: Test now deliberately blocks the event loop with `time.sleep(0.15)` and asserts `blocked_count > 0` and `max_latency_ms > 10.0`.

6. **[Low] Additional test coverage**: Added DossierCache callback integration tests (verifying root SAID propagation with single and multiple dossiers), and `async_db_call` thread isolation test.

### Test Results

- 46 Sprint 76 tests: 46 passed (43 + 3 new)
- Full issuer suite: 948 passed, 7 skipped
- Full verifier suite: 1848 passed, 9 skipped

### Files Changed

| File | Lines | Summary |
|------|-------|---------|
| `common/common/vvp/timing.py` | +117 | New: Shared PhaseTimer with async context manager |
| `common/common/vvp/dossier/cache.py` | +25 | Invalidation callbacks + root SAID extraction |
| `services/verifier/app/vvp/timing.py` | ~8 | Re-export from common for backward compatibility |
| `services/issuer/app/api/vvp.py` | ~+60 | Per-step timing + attestation cache + constraints on every request |
| `services/issuer/app/api/tn.py` | +3 | Pass timing_ms through to response |
| `services/issuer/app/api/models.py` | +8 | Added timing_ms to CreateVVPResponse and TNLookupResponse |
| `services/issuer/app/api/admin.py` | +15 | New endpoint: GET /admin/event-loop-health |
| `services/issuer/app/tn/lookup.py` | +20 | Per-step timing + async bcrypt offload |
| `services/issuer/app/vvp/attestation_cache.py` | +200 | New: LRU attestation cache with invalidation |
| `services/issuer/app/vvp/dossier_service.py` | +10 | Register attestation cache invalidation callback |
| `services/issuer/app/core/event_loop_monitor.py` | +130 | New: Event loop latency monitor (interval drift) |
| `services/issuer/app/db/session.py` | +30 | async_db_call() wrapper |
| `services/issuer/app/main.py` | +8 | Start/stop event loop monitor on lifespan |
| `services/issuer/Dockerfile` | 1 | Added --workers=4 to uvicorn CMD |
| `services/sip-redirect/app/redirect/client.py` | +5 | Log timing_ms from issuer response |
| `services/issuer/tests/test_attestation_cache.py` | +220 | 19 tests: cache ops, TTL, LRU, invalidation, DossierCache integration |
| `services/issuer/tests/test_event_loop_monitor.py` | +110 | 10 tests: lifecycle, metrics, blocked detection |
| `services/issuer/tests/test_vvp_timing.py` | +130 | 14 tests: PhaseTimer, async_db_call, thread isolation |
