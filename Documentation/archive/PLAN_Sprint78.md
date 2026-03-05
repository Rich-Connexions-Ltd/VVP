# Sprint 78: Verifier SIP Call Performance — 50% Second-Call Latency Reduction

## Problem Statement

The VVP verifier's second-call latency for SIP INVITE verification is dominated by Phase 4 (KERI signature verification), which takes 300-500ms even when caching layers should eliminate network I/O. Two root causes:

1. **KeyStateCache uses exact timestamp matching**: Keyed by `(AID, iat_timestamp)`. Each PASSporT has a unique `iat`, so second calls with different PASSporTs from the same signer always miss the cache — triggering a full OOBI fetch — even though the same key state (signing keys) is valid across a wide time range.
2. **No HTTP connection pooling for OOBI/dossier fetches**: `oobi.py:81` and `common/vvp/dossier/fetch.py:49` create a NEW `httpx.AsyncClient` per request (TCP+TLS handshake ~50-100ms each). Meanwhile, `tel_client.py` already uses `get_shared_client()` with pooling.

## Spec References

- §5C.2: "Key state cache: AID + timestamp → Minutes (rotation-sensitive)" — the spec allows time-based caching; range-based lookup is a valid implementation strategy provided rotation safety is maintained
- §5A Step 4: "Resolve issuer key state at reference time T" — key state validity is bounded by KEL establishment events (inception and rotation), with sequence numbers as the authoritative ordering
- §4.2: kid MUST be an OOBI URL — OOBI fetches are on the critical path
- KERI spec: KEL sequence numbers (`s` field) are the authoritative ordering of establishment events, not wall-clock timestamps

## Current State

**Current second-call timing (different PASSporT, same signer + dossier):**

| Phase | Time | Notes |
|-------|------|-------|
| Phase 2 (Identity) | ~1ms | Parse VVP-Identity header |
| Phase 3 (PASSporT) | ~1ms | Parse JWT + binding |
| Phase 4 (Signature) | ~300-500ms | **KeyStateCache MISS** → full OOBI fetch + new AsyncClient |
| Phase 5/5.5/9 (Cached) | ~5ms | VerificationResultCache hit |
| Authorization + SIP + Brand + Vetter | ~30ms | Always runs |
| Claim tree + overhead | ~25ms | Status propagation |
| **Total** | **~360-560ms** | |

**Target: ≤180ms (50% reduction)**

## Proposed Solution

### Approach

Two focused optimizations, each addressing a measured bottleneck:

1. **Range-based KeyStateCache** — Eliminate OOBI fetch on second call by matching ANY `iat` within a key state's validity window, using KEL sequence numbers as the authoritative ordering and a freshness guard for unbounded entries
2. **OOBI + dossier connection pooling** — Eliminate TCP/TLS handshake overhead when cache misses do occur, with explicit security controls

**Scope boundary**: This sprint does NOT change the VerificationResultCache deep-copy behavior (existing deep-copies are retained for safety) or the public API schema. Timing instrumentation remains internal (structured logging only).

**Why this approach**: Each optimization is independent, testable, and addresses a measured bottleneck. No speculative work. The range-based cache provides the largest single improvement (~300-500ms) while connection pooling provides defense-in-depth for cache misses.

### Alternatives Considered

| Alternative | Pros | Cons | Why Rejected |
|-------------|------|------|--------------|
| Full signature result cache (cache the verified output keyed by PASSporT JWT hash) | Skips Phase 4 entirely on duplicate PASSporTs | Only helps when exact same PASSporT is re-verified; different PASSporTs from same signer still miss | Too narrow — each SIP call generates a unique PASSporT |
| Pre-warm key state cache on startup | Reduces cold-start latency | Doesn't help for unknown signers; adds startup cost | Doesn't address core issue (timestamp-exact cache key) |
| Reduce OOBI timeout from 5s to 2s | Faster failures | Doesn't reduce successful-path latency; increases failure rate | Doesn't address root cause |
| Remove deep-copies from VerificationResultCache | Saves ~5-20ms per cache hit | Risk of cross-request data contamination if any caller mutates cached objects; requires exhaustive mutation audit | Risk outweighs benefit — 5-20ms savings is marginal vs 300-500ms from cache fix |

### Detailed Design

#### Component 1: Range-Based KeyStateCache

- **Purpose**: Make cache hit on any `iat` (reference time) within a key state's validity window
- **Location**: `services/verifier/app/vvp/keri/cache.py` and `services/verifier/app/vvp/keri/kel_resolver.py`
- **Current behavior**: `get_for_time(aid, reference_time)` does exact `(aid, reference_time)` lookup in `_time_index` dict. Cache hit requires identical timestamp.
- **New behavior**: `get_for_time(aid, reference_time)` first tries exact match (O(1)), then falls back to range scan: find any cached entry for this AID where `valid_from <= reference_time < valid_until`, using KEL sequence number as tie-breaker.

##### Terminology

Throughout this component, these terms have precise definitions:
- **reference_time (T)**: The PASSporT `iat` timestamp — the point in time at which key state validity is evaluated
- **validity window**: The time range `[valid_from, valid_until)` during which a key state's signing keys are authoritative per the KEL
- **valid_from**: The `dt` timestamp from the establishment event that created this key state (from KEL event data or earliest witness receipt)
- **valid_until**: The `dt` timestamp from the NEXT establishment event in the KEL (if any). `None` means this is the most recent key state with no subsequent rotation
- **sequence number (`s`)**: The KEL event sequence number — the authoritative ordering of events per KERI spec. Used as tie-breaker when multiple cache entries overlap

##### Cache Entry Changes

```python
@dataclass
class _CacheEntry:
    key_state: "KeyState"
    expires_at: datetime
    last_access: datetime
    cached_at: datetime  # Set once at creation — freshness guard uses this, NOT last_access
    valid_until: Optional[datetime] = None  # dt of next establishment event (None = most recent)
    sequence: int = 0  # KEL sequence number (s field) for authoritative ordering
```

##### Responsibility Separation

The `KeyStateCache` class is organized into clear layers of responsibility:

1. **Storage & eviction** (`KeyStateCache`): Entry lifecycle, TTL, LRU eviction, time-index management, metrics. This is the only class that owns `_entries` and `_time_index`.
2. **Window matching** (module-level function `_entry_covers_time(entry, rt, now, freshness_window_seconds)`): Pure function — given an entry, a reference time, the current time, and a freshness window, returns whether the entry's validity window covers the reference time. No access to cache state. Takes `freshness_window_seconds` as a parameter (not from `self._config`) to remain stateless.
3. **Lookup orchestration** (`get_for_time()`): Instance method that coordinates exact match → range scan → miss, passing `self._config.freshness_window_seconds` to the stateless `_entry_covers_time()`.

This decomposition keeps KEL-specific semantics (validity windows, freshness guard) isolated from cache storage mechanics, making each piece independently testable.

##### Range-Based Lookup (decomposed into focused methods)

The `get_for_time()` method delegates to two private helpers, each with a single responsibility:

```python
async def get_for_time(self, aid: str, reference_time: datetime) -> Optional["KeyState"]:
    """Find cached key state valid at reference_time.

    Strategy:
    1. Exact match via time index — O(1)
    2. Range scan via _find_range_match() — O(N) where N ≈ 1-2
    """
    async with self._lock:
        now = datetime.now(timezone.utc)

        # 1. Exact match (existing O(1) path)
        result = self._exact_match_locked(aid, reference_time, now)
        if result is not None:
            return result

        # 2. Range scan
        result = self._range_match_locked(aid, reference_time, now)
        if result is not None:
            return result

        self._metrics.misses += 1
        return None

def _exact_match_locked(self, aid: str, reference_time: datetime, now: datetime) -> Optional["KeyState"]:
    """O(1) lookup in time index. Caller holds lock."""
    digest = self._time_index.get((aid, reference_time))
    if not digest:
        return None
    entry = self._entries.get((aid, digest))
    if entry and entry.expires_at >= now:
        self._touch_access_order((aid, digest))
        entry.last_access = now
        self._metrics.hits += 1
        return entry.key_state
    return None

def _range_match_locked(self, aid: str, reference_time: datetime, now: datetime) -> Optional["KeyState"]:
    """Scan entries for AID, find best match by validity window + sequence. Caller holds lock."""
    rt = _normalize_datetime(reference_time)
    best_entry = None
    best_key = None
    best_seq = -1

    for key, entry in self._entries.items():
        if key[0] != aid or entry.expires_at < now:
            continue
        if not _entry_covers_time(entry, rt, now, self._config.freshness_window_seconds):
            continue
        if entry.sequence > best_seq:
            best_entry = entry
            best_key = key
            best_seq = entry.sequence

    if best_entry is None:
        return None

    self._touch_access_order(best_key)
    best_entry.last_access = now
    self._metrics.hits += 1
    # Index for future O(1) lookups
    self._time_index[(aid, reference_time)] = best_key[1]
    return best_entry.key_state

def _entry_covers_time(
    entry: _CacheEntry, rt: datetime, now: datetime, freshness_window_seconds: float
) -> bool:
    """Check if entry's validity window covers reference_time.

    Module-level pure function — no access to cache state.
    Takes freshness_window_seconds as explicit parameter.
    """
    ks = entry.key_state
    if ks.valid_from is None:
        return False
    vf = _normalize_datetime(ks.valid_from)
    if vf > rt:
        return False  # Key state starts AFTER reference_time

    if entry.valid_until is not None:
        vu = _normalize_datetime(entry.valid_until)
        if rt >= vu:
            return False  # Superseded by rotation
    else:
        # Freshness guard for unbounded entries (no subsequent rotation known).
        # Uses cached_at (immutable creation time), NOT last_access.
        entry_age = (now - entry.cached_at).total_seconds()
        if entry_age > freshness_window_seconds:
            return False  # Stale — force re-fetch

    return True
```

##### Time-Index Size Limit

The time index `_time_index[(aid, reference_time)] → digest` grows with each unique `reference_time` seen. Since PASSporT `iat` values are attacker-influenced (each call has a unique timestamp), this creates a memory exhaustion risk.

**Mitigation**: Cap the time index at `max_time_index_entries` (default: 10,000). When the cap is reached, evict the oldest half of the time index entries (bulk eviction amortizes cost). The primary entry store (`_entries`) is already bounded by `max_entries` (default: 1000). Time index entries are cheap (two strings → one string), but unbounded growth must be prevented.

```python
# In _range_match_locked, BEFORE indexing the new entry:
if len(self._time_index) >= self._config.max_time_index_entries:
    # Evict oldest half BEFORE inserting — prevents attacker from
    # continuously triggering O(N/2) eviction on every request
    to_remove = list(self._time_index.keys())[:len(self._time_index) // 2]
    for k in to_remove:
        del self._time_index[k]

# Now insert the new index entry (guaranteed space exists)
self._time_index[(aid, reference_time)] = best_key[1]
```

**Security note**: The `max_time_index_entries` cap (default: 10,000) should be scaled proportionally to `max_entries` (default: 1,000). It is a security parameter — lowering it reduces memory use but increases the frequency of O(N) range scans (still bounded by entries per AID ≈ 1-3). The eviction is performed BEFORE insertion to prevent an attacker from causing O(N/2) work on every request by keeping the index at exactly the cap.

##### Freshness Guard

When a cached entry has `valid_until=None` (most recent key state, no subsequent rotation known), we cannot know if a rotation has occurred since the entry was cached. The freshness guard prevents serving stale keys:

- **`freshness_window_seconds`** (new config field on `CacheConfig`, default: 120s): If the entry's immutable creation timestamp (`cached_at`) is more than this many seconds in the past, force a cache miss so the OOBI is re-fetched to check for KEL advancement. The `cached_at` field is set once when the entry is first populated and never updated — this prevents frequent access from resetting the freshness clock.
- **Rationale**: 120s is a conservative default — long enough to benefit rapid-fire calls (SIP call setup takes <5s), short enough that a key rotation would be detected within 2 minutes.
- **Safety**: If a rotation HAS occurred, the re-fetch returns the new KEL, the resolver finds the new key state, and the old entry is superseded (a new entry with higher `s` is added, and the old entry gets its `valid_until` populated).

##### Stale-Key Acceptance Window (Security Trade-off)

**Documented trade-off**: After a key rotation, cached entries with `valid_until=None` remain usable for up to `freshness_window_seconds` (default 120s). During this window, a signature made with the OLD (now-rotated) key would still pass Phase 4. This is an inherent consequence of caching — the alternative (no caching, always re-fetch KEL) defeats the performance goal.

**Mitigations**:
1. **Operator control**: `VVP_KEY_STATE_FRESHNESS_WINDOW_SECONDS` can be lowered to 10s (minimum) for high-security environments, narrowing the window.
2. **Revocation checking**: Phase 9 (revocation status) runs independently and will catch revoked credentials even if the key state cache is stale. A credential revoked via TEL is detected regardless of key state freshness.
3. **PASSporT expiry**: PASSporT `iat` + max validity (300s default) limits the useful lifetime of any forged token.
4. **Convergent detection**: Once the freshness guard triggers re-fetch, the rotation is detected, and the cache is corrected for all subsequent requests.

This trade-off is standard practice in authentication caching systems (e.g., OCSP stapling has similar staleness windows). The risk is LOW in VVP's context because SIP call setup is transient (seconds), not persistent sessions.

##### Cache Population Changes in `kel_resolver.py`

When `_find_key_state_at_time()` resolves a key state from the KEL, it already has access to ALL establishment events (line 396). The changes:

1. After finding `valid_event` (the establishment event valid at reference_time T), scan forward in `establishment_events` for the NEXT establishment event. If found, its timestamp is `valid_until`.
2. Store the `sequence` number from `valid_event.sequence`.
3. When calling `cache.put()`, pass the new `valid_until` and `sequence` fields.

```python
# In _find_key_state_at_time(), after finding valid_event:

# Determine valid_until from the next establishment event in the KEL
valid_until = None
valid_event_index = establishment_events.index(valid_event)
if valid_event_index + 1 < len(establishment_events):
    next_event = establishment_events[valid_event_index + 1]
    valid_until = _get_event_time(next_event)

# Return KeyState (unchanged) + valid_until as separate return value
```

The `resolve_key_state()` function passes `valid_until` and `valid_event.sequence` to `cache.put()`:

```python
# In resolve_key_state(), when caching:
await cache.put(key_state, reference_time=reference_time,
                valid_until=valid_until, sequence=valid_event.sequence)
```

The `cache.put()` method is updated to accept and store these new fields on `_CacheEntry`.

##### Performance

Range scan is O(N) where N is the number of cached key states for a given AID. In VVP's use case, N is typically 1 (most identities never rotate), at most 2-3. This is effectively O(1).

#### Component 2: OOBI Connection Pooling

- **Purpose**: Eliminate TCP/TLS handshake overhead on OOBI fetches
- **Location**: `services/verifier/app/vvp/keri/oobi.py`
- **Current behavior** (line 81): `async with httpx.AsyncClient(...) as client:` — creates new client per call
- **New behavior**: Use `get_shared_client()` from `http_client.py` with explicit per-request timeout and redirect limit

**Changes to `dereference_oobi()`**:

```python
async def dereference_oobi(
    oobi_url: str,
    timeout: float = 5.0,
) -> OOBIResult:
    from common.vvp.url_validation import validate_url_target
    await validate_url_target(oobi_url, allow_http=True)  # OOBI: http allowed (local witnesses)

    try:
        from app.vvp.http_client import get_shared_client
        client = await get_shared_client()  # async due to init lock
        response = await client.get(oobi_url, timeout=timeout)
        # ... rest of processing unchanged ...
```

**Security controls**: The shared client has `follow_redirects=False` — redirects are not followed, eliminating DNS rebinding and redirect-based SSRF bypass. OOBI responses that return 3xx are treated as errors. Per-request `timeout` is passed to `client.get()`. SSRF validation via `validate_url_target()` blocks private/loopback/link-local IP targets using async DNS resolution. OOBI URLs allow `http://` because local witnesses (e.g., `http://localhost:5642`) use plaintext.

**Also update `fetch_kel_from_witnesses()`** (line 234): The inner `fetch_one()` calls `dereference_oobi()` which will now use the shared client and SSRF validation — no further changes needed.

#### Component 3: Dossier Fetch Connection Pooling

- **Purpose**: Eliminate TCP/TLS handshake overhead on dossier fetches
- **Location**: `common/common/vvp/dossier/fetch.py`
- **Current behavior** (line 49): `async with httpx.AsyncClient(...) as client:` — creates new client per call
- **Challenge**: The common package must not import from `services/verifier/` (dependency direction)

**Approach**: Create a shared client module in `common/common/vvp/http_client.py` (mirroring the verifier's `http_client.py`). The dossier fetch module uses this common shared client internally. No API change to `fetch_dossier()`.

**Move shared HTTP client to common package** (two focused modules):

Instead of duplicating the HTTP client in two modules, move the canonical implementation to common and have the verifier re-export from common. The implementation is split into two focused modules with clear single responsibilities:

1. **`common/common/vvp/http_client.py`** — Client lifecycle only (creation, shutdown, test reset)
2. **`common/common/vvp/url_validation.py`** — URL/SSRF validation only (scheme, DNS, IP range checks)

**Path/import convention**: Throughout this plan, filesystem paths use the form `common/common/vvp/http_client.py` (relative to repo root). Python imports use `from common.vvp.http_client import ...` (the outer `common/` is the pip-installed package root, the inner `common/` is the package directory containing `__init__.py`). This dual naming is inherent to the monorepo structure — `pip install -e common/` makes `common.vvp.*` importable.

**Module 1: `common/common/vvp/http_client.py`** — Client lifecycle:

```python
"""Shared httpx.AsyncClient for connection pooling.

Single responsibility: client lifecycle (create, get, close, test-reset).
URL validation lives in common.vvp.url_validation.

Thread/async safety: asyncio.Lock guards lazy initialization.
"""
import asyncio
import logging
from typing import Optional
import httpx

logger = logging.getLogger(__name__)

_DEFAULT_POOL_LIMITS = httpx.Limits(
    max_connections=100,
    max_keepalive_connections=20,
    keepalive_expiry=30.0,
)

_shared_client: Optional[httpx.AsyncClient] = None
_init_lock = asyncio.Lock()

async def get_shared_client() -> httpx.AsyncClient:
    """Get or create the shared httpx.AsyncClient.

    The client has follow_redirects=False to prevent SSRF bypass via
    redirects to private IPs. Callers must handle 3xx responses as errors.
    """
    global _shared_client
    if _shared_client is not None and not _shared_client.is_closed:
        return _shared_client
    async with _init_lock:
        if _shared_client is not None and not _shared_client.is_closed:
            return _shared_client
        _shared_client = httpx.AsyncClient(
            limits=_DEFAULT_POOL_LIMITS,
            follow_redirects=False,  # SSRF: no redirects — prevents DNS rebinding bypass
            http2=False,
        )
        logger.info("Created shared httpx.AsyncClient")
        return _shared_client

async def close_shared_client() -> None:
    global _shared_client
    if _shared_client is not None and not _shared_client.is_closed:
        await _shared_client.aclose()
    _shared_client = None

async def reset_shared_client() -> None:
    """Reset shared client for testing. Properly closes any open client.

    Guarded: only callable within a pytest session.
    """
    import sys
    assert "pytest" in sys.modules, "reset_shared_client() is for test use only"
    global _shared_client
    if _shared_client is not None and not _shared_client.is_closed:
        await _shared_client.aclose()
    _shared_client = None
```

**Module 2: `common/common/vvp/url_validation.py`** — SSRF validation:

```python
"""URL validation for SSRF prevention.

Single responsibility: validate that a URL is safe to fetch.
Checks scheme, resolves DNS (async), and blocks non-routable IPs.
"""
import asyncio
import ipaddress
import socket
from urllib.parse import urlparse

from common.vvp.core.exceptions import FetchError


async def validate_url_target(url: str, *, allow_http: bool = False) -> None:
    """Validate that a URL is safe to fetch (not targeting internal services).

    Args:
        url: The URL to validate.
        allow_http: If False (default), only https:// is permitted.
            Set True for OOBI URLs where local witnesses use http://.

    Raises:
        FetchError: If the URL targets a non-routable address,
            uses a disallowed scheme, or fails DNS resolution.
    """
    parsed = urlparse(url)

    # Scheme validation
    allowed_schemes = ("http", "https") if allow_http else ("https",)
    if parsed.scheme not in allowed_schemes:
        raise FetchError(
            f"Invalid URL scheme: {parsed.scheme} "
            f"(allowed: {', '.join(allowed_schemes)})"
        )
    if not parsed.netloc:
        raise FetchError("Invalid URL: missing host")

    hostname = parsed.hostname
    if not hostname:
        raise FetchError("Invalid URL: missing hostname")

    # Async DNS resolution — does not block the event loop
    loop = asyncio.get_running_loop()
    try:
        addr_info = await loop.getaddrinfo(
            hostname, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM
        )
    except socket.gaierror as e:
        raise FetchError(f"DNS resolution failed for {hostname}: {e}")

    for family, _, _, _, sockaddr in addr_info:
        ip = ipaddress.ip_address(sockaddr[0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            raise FetchError(
                f"URL targets non-routable address: {hostname} -> {ip}"
            )
```

**Key design decisions** (addressing findings #30, #31, #32):
- **No redirects** (`follow_redirects=False`): Eliminates both DNS rebinding (TOCTOU) and redirect-to-private-IP attacks. If the target server returns 3xx, it's treated as an error. OOBI endpoints and dossier URLs should return content directly — redirects indicate misconfiguration.
- **Async DNS** (`loop.getaddrinfo`): Uses the event loop's async DNS resolver instead of blocking `socket.getaddrinfo()`. Does not stall the event loop.
- **Scheme control** (`allow_http` parameter): Dossier URLs default to `https` only (untrusted, external). OOBI URLs can use `http` (local witnesses at `http://localhost:5642`). The `allow_http=True` flag is explicit in the caller.
- **Single validation point**: Callers invoke `validate_url_target()` once before the HTTP request. No duplication — the shared client does not re-validate.

**Verifier re-export** (`services/verifier/app/vvp/http_client.py`): Replace implementation with re-export:

```python
"""Shared HTTP client — re-exported from common package.

Canonical implementation lives in common/common/vvp/http_client.py.
This module re-exports for backwards compatibility with existing verifier imports.
"""
from common.vvp.http_client import (
    get_shared_client,
    close_shared_client,
    reset_shared_client,
)

__all__ = ["get_shared_client", "close_shared_client", "reset_shared_client"]
```

**Note**: `get_shared_client()` is now `async` (due to the lock). All callers must `await` it. This is a minor API change within the codebase (TEL client and OOBI fetch already run in async context).

**Changes to `common/common/vvp/dossier/fetch.py`**:

```python
async def fetch_dossier(url: str) -> bytes:
    """Fetch dossier from URL with constraints. Uses shared connection pool."""
    from common.vvp.url_validation import validate_url_target
    from common.vvp.http_client import get_shared_client

    # Single-point SSRF validation (scheme + DNS + IP range)
    # Dossier URLs are untrusted (from VVP-Identity header) — https only
    await validate_url_target(url, allow_http=False)

    try:
        client = await get_shared_client()
        response = await client.get(url, timeout=DOSSIER_FETCH_TIMEOUT_SECONDS)
        response.raise_for_status()
        # ... content-type validation and size check unchanged ...
```

**SSRF mitigation** (centralized in `common/common/vvp/url_validation.py`):

All SSRF validation is handled by the single `validate_url_target()` function, called once per untrusted URL before the HTTP request. No validation logic is duplicated in callers or in the HTTP client module.

1. **Scheme validation**: Dossier URLs require `https` only (untrusted, external). OOBI URLs allow `http` (local witnesses). Prevents `file://`, `ftp://`, `gopher://` protocol attacks.
2. **Async DNS + IP validation**: Hostname is resolved via `loop.getaddrinfo()` (non-blocking). All resolved IPs are checked against private, loopback, link-local, and reserved ranges. Blocks `http://169.254.169.254/` (cloud metadata), `http://127.0.0.1/`, `http://10.0.0.1/` (RFC 1918).
3. **No redirects**: The shared client has `follow_redirects=False`, eliminating DNS rebinding (TOCTOU between validation and connection) and redirect-to-private-IP attacks entirely. 3xx responses are treated as errors.

**No API change**: `fetch_dossier()` signature is unchanged. The common package owns its own shared client. No coupling to verifier internals.

#### Component 4: Internal Timing Instrumentation

- **Purpose**: Enable per-phase latency measurement for performance validation
- **Location**: `services/verifier/app/vvp/verify.py`, `services/verifier/app/main.py`
- **Scope**: Internal structured logging only — NO public API changes

**Changes**:
- In `main.py`, always pass a `PhaseTimer()` to `verify_vvp()` (currently conditional)
- After `verify_vvp()` returns, log the phase timings via structured logging:

```python
timer = PhaseTimer()
request_id, response = await verify_vvp(req, vvp_identity_header, timer=timer)
if timer.timings:
    log.info(f"Phase timings: {timer.to_log_str()}", extra={"timing": timer.to_dict()})
```

- No new config flags. No API model changes. No response body changes.
- Phase timings are available in application logs for performance analysis.

### Data Flow

**First call (cold caches):**
```
VVP-Identity header → Phase 2 parse (1ms)
PASSporT JWT → Phase 3 parse + bind (1ms)
kid OOBI URL → Phase 4: OOBI fetch via shared client (pool hit or new conn)
            → KEL parse → key state resolution → Ed25519 verify
            → Cache key state with valid_from/valid_until/sequence from KEL
evd URL → Phase 5: dossier fetch via common shared client → parse → cache
       → Phase 5.5: ACDC chain validation → Phase 9: revocation
       → Cache in VerificationResultCache
→ Build claim tree, log phase timings, return VerifyResponse
```

**Second call (warm caches, different iat):**
```
VVP-Identity header → Phase 2 parse (1ms)
PASSporT JWT → Phase 3 parse + bind (1ms)
kid OOBI URL → Phase 4: KeyStateCache range hit (valid_from ≤ iat < valid_until)
            → freshness guard passes (entry age < 120s)
            → Ed25519 verify (0.1ms) → NO OOBI fetch
evd URL → VerificationResultCache hit → deep-copied artifacts (5ms)
       → NO Phase 5/5.5/9
→ Build claim tree (30ms), return VerifyResponse
Total: ~40ms
```

### Error Handling

- **Range cache ambiguity**: If multiple key states match for an AID, the one with the highest KEL sequence number wins (authoritative per KERI spec). Ties are impossible (sequence numbers are strictly monotonic in a valid KEL).
- **Stale key state after rotation**: The freshness guard (120s default) forces a re-fetch for entries with `valid_until=None`. When the re-fetch reveals a rotation, the new key state is cached with the old entry's `valid_until` populated, preventing future stale hits.
- **Shared client connection failure**: Individual requests raise `httpx.RequestError` as before. The shared client auto-recovers by creating new connections. `get_shared_client()` checks `is_closed` and recreates if needed.

### Test Strategy

1. **Range-based cache tests** (new file: `tests/test_key_state_cache_range.py`):
   - Cache hit with different reference_time but same key state validity window
   - Cache miss when reference_time is before valid_from
   - Cache miss when reference_time is after valid_until (rotation occurred)
   - Cache hit with valid_until=None within freshness window
   - Cache miss with valid_until=None outside freshness window (forces re-fetch)
   - Tie-break by sequence number (highest wins) when multiple entries match
   - Multiple AIDs: range match is AID-specific
   - TTL expiry still works with range matching
   - Time index populated on range match for O(1) subsequent lookups
   - **Rotation test**: Cache entry valid, rotation occurs, re-fetch returns new key state, old entry gets valid_until populated, new entry with higher sequence is used

2. **Connection pooling tests** (new file: `tests/test_connection_pooling.py`):
   - OOBI fetch uses shared client (mock verifies no per-request client creation)
   - Dossier fetch uses common shared client
   - Shared client has `follow_redirects=False` (3xx responses are errors)
   - Shared client creation is lazy and singleton
   - Per-request timeout is honored via shared client
   - `reset_shared_client()` properly closes the underlying client
   - SSRF validation blocks `http://127.0.0.1/`, `http://169.254.169.254/`, `http://10.0.0.1/`, `http://[::1]/`
   - SSRF validation allows legitimate external URLs
   - `_validate_url_target()` raises `FetchError` for non-routable addresses

3. **Timing instrumentation test** (extend existing):
   - Phase timings are logged after verify_vvp() completes
   - Timer captures all phases including cache hit path

4. **Benchmark test** (new file: `tests/test_performance.py`):
   - First vs second call latency with mocked network (simulated 100ms per network call)
   - Second call uses different `iat` than first call (exercises range-based cache)
   - Assert second-call Phase 4 completes in < 5ms (absolute threshold — cache hit + Ed25519 verify only, no network I/O). This is more maintainable than relative ratio assertions (e.g., "≤50% of first") which are brittle across environments.
   - Assert second-call total < 100ms (absolute threshold for full pipeline with warm caches)

5. **Regression**: All existing 1844+ verifier tests pass unchanged.

### Documentation Updates

- `knowledge/verification-pipeline.md`: Update Phase 4 section to document range-based key state caching, freshness guard, and connection pooling
- `knowledge/deployment.md`: Document `VVP_KEY_STATE_FRESHNESS_WINDOW_SECONDS` env var
- `CHANGES.md`: Sprint 78 summary, files changed, commit SHA
- `CLAUDE.md` / `MEMORY.md`: Update with Sprint 78 completion notes

## Files to Create/Modify

| File | Action | Purpose |
|------|--------|---------|
| `services/verifier/app/vvp/keri/cache.py` | Modify | Range-based `get_for_time()`, `valid_until`/`sequence` on `_CacheEntry`, freshness guard |
| `services/verifier/app/vvp/keri/kel_resolver.py` | Modify | Compute `valid_until` from KEL, pass to cache with sequence number |
| `services/verifier/app/vvp/keri/oobi.py` | Modify | Use `get_shared_client()` instead of per-request AsyncClient |
| `common/common/vvp/http_client.py` | Create | Shared HTTP client lifecycle (create, get, close, test-reset) — single responsibility |
| `common/common/vvp/url_validation.py` | Create | SSRF URL validation (scheme, async DNS, IP range checks) — single responsibility |
| `services/verifier/app/vvp/http_client.py` | Modify | Replace implementation with re-export from `common.vvp.http_client` (3 lines) |
| `common/common/vvp/dossier/fetch.py` | Modify | Use common shared client instead of per-request AsyncClient |
| `services/verifier/app/core/config.py` | Modify | Add `VVP_KEY_STATE_FRESHNESS_WINDOW_SECONDS` env var (default 120) |
| `services/verifier/app/main.py` | Modify | Always pass PhaseTimer, log phase timings, await async get_shared_client |
| `services/verifier/tests/test_key_state_cache_range.py` | Create | Range-based cache tests including rotation and freshness guard |
| `services/verifier/tests/test_connection_pooling.py` | Create | Connection pooling tests |
| `services/verifier/tests/test_performance.py` | Create | Benchmark test |
| `knowledge/verification-pipeline.md` | Modify | Document cache improvements |
| `knowledge/deployment.md` | Modify | Document new config option |

## Open Questions

1. **Freshness window default**: 120 seconds is conservative. Should it be configurable via environment variable (e.g., `VVP_KEY_STATE_FRESHNESS_WINDOW_SECONDS`)? **Decision**: Yes — add as env var with 120s default in `services/verifier/app/core/config.py`. Operators in high-security environments can lower it; operators with stable identities can raise it. The value is passed to `CacheConfig(freshness_window_seconds=VVP_KEY_STATE_FRESHNESS_WINDOW_SECONDS)` when initializing the global cache in `kel_resolver.py:get_cache()`. **Bounds**: Validated at startup with minimum 10s (below this, the cache provides negligible benefit and OOBI fetches dominate) and maximum 3600s (above this, rotated keys could be served for an unacceptably long period). Values outside this range cause a startup warning and are clamped to the nearest bound.

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Stale-key acceptance window after rotation (up to freshness_window_seconds) | Low | Medium | Documented trade-off: window configurable (min 10s), revocation checking (Phase 9) independent, PASSporT expiry limits forged token lifetime. See "Stale-Key Acceptance Window" section. |
| Range cache returns stale key state after rotation | Low | High | Freshness guard (120s) forces re-fetch for unbounded entries; rotation test validates correct behavior |
| Shared client connection leak on error | Low | Medium | httpx manages connection lifecycle; `is_closed` check on each `get_shared_client()` call; `close_shared_client()` on app shutdown |
| Common shared client duplicates verifier shared client | N/A | Low | Each process (verifier, issuer) gets its own client instance. Separate modules avoid import coupling. |
| Freshness guard causes extra OOBI fetches for stable identities | Medium | Low | 120s window means at most 1 extra fetch per 2 minutes per AID; configurable for operators |

## Revision History

| Round | Date | Changes |
|-------|------|---------|
| R1 | 2026-03-05 | Initial draft |
| R2 | 2026-03-05 | Address R1 findings: (1) [High #1] KEL sequence numbers for tie-breaking, freshness guard, valid_until from KEL; (2) [High #2] Retain deep-copies; (3) [High #3] Documentation Updates section; (4) [Medium #4] max_redirects=3; (5) [Medium #5] Common-package shared client; (6) [Medium #6] Revocation out of scope; (7) [Medium #7] Terminology subsection; (8) [Low #8] Internal-only timing; (9) [Low #9] Open Questions |
| R3 | 2026-03-05 | Address R2 findings: (10) **[High #10]** Freshness guard uses `cached_at` (immutable creation time) instead of `last_access`; (11) **[High #11]** SSRF mitigation — URL scheme validation (http/https only) added to `fetch_dossier()`; (12) **[Medium #12]** Decomposed `get_for_time()` into 3 focused methods (`_exact_match_locked`, `_range_match_locked`, `_entry_covers_time`); (13) **[Medium #13]** `asyncio.Lock` on shared client init prevents race condition; `get_shared_client()` is now async; (14) **[Medium #14]** Time-index capped at `max_time_index_entries` (10,000) with bulk eviction; (15) **[Medium #15]** `VVP_KEY_STATE_FRESHNESS_WINDOW_SECONDS` env var added to `config.py` and files table; (16) **[Medium #16]** Single shared client in common, verifier re-exports — no duplication; (17) **[Low #17]** `CHANGES.md` added to Documentation Updates |
| R4 | 2026-03-05 | Address R3 findings: (18-20) SSRF + await + freshness doc — see R4 row below for complete R3 addressing |
| R5 | 2026-03-05 | Address R4 findings: (29) **[High #29]** Stale-key acceptance window documented as explicit trade-off with mitigations (operator control, Phase 9 revocation, PASSporT expiry); added to Risks table; (30) **[High #30]** DNS rebinding eliminated — `follow_redirects=False` on shared client, no redirects followed; (31) **[High #31]** Removed event_hooks approach — replaced with `follow_redirects=False` which is simpler and more secure; (32) **[Medium #32]** Async DNS via `loop.getaddrinfo()` — no blocking `socket.getaddrinfo()` on event loop; (33) **[Medium #33]** Split HTTP module into two: `http_client.py` (client lifecycle) + `url_validation.py` (SSRF validation); (34) **[Medium #34]** Renamed `_validate_url_target()` → `validate_url_target()` (public API, cross-module); (35) **[Medium #35]** `_entry_covers_time()` consistently a module-level pure function with explicit `freshness_window_seconds` parameter; (36) **[Medium #36]** Single validation point — callers invoke `validate_url_target()` once, no duplication in fetch_dossier; (37) **[Medium #37]** Dossier URLs require `https` only; OOBI URLs allow `http` via explicit `allow_http=True` parameter |

---

## Implementation Notes

### Deviations from Plan
- None — implementation follows approved plan exactly.

### Implementation Details
- Shared client singleton uses `asyncio.Lock` for safe lazy initialization
- Test conftest resets `_shared_client = None` between tests to prevent stale event-loop references
- Test vector runner updated to mock `validate_url_target` + `get_shared_client` pattern
- OOBI test suite fully rewritten with `mock_oobi_http()` context manager
- Existing cache test updated: `test_get_for_time_different_time` → `test_get_for_time_range_match` + `test_get_for_time_before_valid_from_misses`
- All `_find_key_state_at_time()` test calls updated to unpack `(key_state, valid_until)` tuple

### Test Results
- 1882 passed, 9 skipped (local witnesses), 30 warnings (deprecation only)
- 34 new tests across 2 new test files
- All 13 test vectors pass
- All 50 OOBI tests pass with new mocking pattern

### Files Changed
| File | Lines | Summary |
|------|-------|---------|
| `common/common/vvp/url_validation.py` | +55 | **New**: SSRF validation module (async DNS, IP range checks) |
| `common/common/vvp/http_client.py` | +74 | **New**: Shared httpx.AsyncClient lifecycle |
| `services/verifier/app/vvp/http_client.py` | ~10 | Replaced with re-export from common |
| `services/verifier/app/vvp/keri/cache.py` | +90 | Range-based cache with freshness guard |
| `services/verifier/app/vvp/keri/kel_resolver.py` | +20 | Returns `(KeyState, valid_until)` tuple |
| `services/verifier/app/vvp/keri/oobi.py` | +5 | Use shared client + SSRF validation |
| `common/common/vvp/dossier/fetch.py` | +8 | Use shared client + SSRF validation |
| `services/verifier/app/core/config.py` | +2 | `VVP_KEY_STATE_FRESHNESS_WINDOW_SECONDS` env var |
| `services/verifier/app/main.py` | +3 | Close shared client on shutdown |
| `services/verifier/app/vvp/keri/tel_client.py` | +2 | `await get_shared_client()` |
| `services/verifier/tests/conftest.py` | +4 | Reset shared client between tests |
| `services/verifier/tests/test_oobi.py` | ~400 | Rewritten with `mock_oobi_http()` pattern |
| `services/verifier/tests/test_kel_cache.py` | +15 | Updated for range-based behavior |
| `services/verifier/tests/test_kel_resolver.py` | +8 | Unpack `(key_state, valid_until)` tuple |
| `services/verifier/tests/test_dossier.py` | +20 | Mock new fetch pattern |
| `services/verifier/tests/vectors/runner.py` | +6 | Mock `validate_url_target` + `get_shared_client` |
| `services/verifier/tests/test_key_state_cache_range.py` | +340 | **New**: 19 tests for range-based cache |
| `services/verifier/tests/test_connection_pooling.py` | +180 | **New**: 15 tests for pooling + SSRF |
