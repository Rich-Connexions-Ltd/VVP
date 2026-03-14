# Sprint 83: Root of Trust Admin Configuration

## Problem Statement

`TRUSTED_ROOT_AIDS` is currently a `frozenset` populated once at service startup from the `VVP_TRUSTED_ROOT_AIDS` environment variable. Changing the trusted root set requires an environment variable update and a service restart. This is operationally inconvenient during:

- Onboarding of new trust anchors (GSMA governance AID, GLEIF staging)
- Emergency revocation of a compromised root (including clearing all roots to fail-closed)
- Testing with different trust configurations without deploying new pods

Operators need a UI page and HTTP API to inspect and mutate trusted roots at runtime. The same capability is needed in the OVC-VVP-Verifier, which currently has no admin page at all.

## Spec References

- §5.1-7: Verifier MUST accept a configured root of trust; ACDC credentials must chain back to one of these AIDs.

## Current State

### Monorepo VVP Verifier
- `TRUSTED_ROOT_AIDS: frozenset[str]` is a module-level constant in `app/core/config.py` (line 175).
- Set once at import time; cannot be changed without restart.
- `GET /admin` endpoint does not expose trusted roots.
- `/ui/admin` admin page has no Trusted Roots section.
- `compute_config_fingerprint()` caches result in `_cached_config_fingerprint`; must be invalidated when roots change.
- Import audit: `TRUSTED_ROOT_AIDS` imported directly in `app/main.py` (2 call sites); all lower-level functions already accept `trusted_roots: Set[str]` as a parameter — no further changes downstream.

### OVC-VVP-Verifier
- `TRUSTED_ROOT_AIDS: frozenset[str]` in `app/config.py` (line 59).
- `config_fingerprint()` recomputes fresh each call.
- No admin endpoints beyond `/healthz` and `/verify`.
- No HTML admin page.

## Proposed Solution

### Approach

Replace the module-level `frozenset` constant with a mutable, asyncio-protected runtime state store. Expose read/write API endpoints and a simple HTML admin page in both services. Verification requests take a single immutable snapshot of the trusted roots set at request start and carry that snapshot — including its fingerprint — through all verification phases and into cache storage.

The trusted-root set is allowed to become **empty**. An empty set is a valid fail-closed state: the existing ACDC chain validation fails for any credential when no issuer matches a trusted root. No global pre-check is added to `verify.py` — chain validation already handles this correctly.

**This feature is scoped to single-instance deployments only** for runtime mutation. Multi-replica HA deployments must use env var + rolling restart. The admin UI and deployment docs explicitly communicate this constraint.

**Admin authentication is fail-closed by default:** mutation endpoints are disabled unless `VVP_ADMIN_TOKEN` is configured. Read endpoints are always accessible.

### Alternatives Considered

| Alternative | Pros | Cons | Why Rejected |
|-------------|------|------|--------------|
| Database persistence | Survives restarts, multi-instance safe | Adds SQLite/DB dep to stateless OVC; schema migrations | Overkill for rare mutations |
| Write to env file on disk | Survives restarts | Non-atomic, platform-specific, still not multi-instance | Complex and fragile |
| In-memory only (this plan) | Simple, no new deps | Lost on restart, single-instance only | Acceptable: env var is authoritative; feature explicitly scoped |
| Shared state (Redis/etcd) | Multi-instance safe | Large new dependency | Out of scope |
| Full OIDC/OAuth for admin | Industry standard auth | Heavy new dependency; admin is local/operator-facing | Deferred to future sprint |

### Scope Constraint

> **Runtime trusted-root mutation supports single-instance deployments only.**
> In multi-replica deployments, mutations are per-process. The admin UI shows a permanent banner: "Changes apply to this instance only. For HA/multi-replica deployments, update `VVP_TRUSTED_ROOT_AIDS` and restart all instances."
> `knowledge/deployment.md` will explicitly state: do not use runtime trusted-root mutation in HA deployments.

### Detailed Design

#### Component 1: Runtime Trusted Roots State (both services)

Replace `TRUSTED_ROOT_AIDS: frozenset[str]` with `_TrustedRootsStore`. The module-level constant is **removed**; no proxy shim.

```python
import asyncio

class _TrustedRootsStore:
    """Asyncio-safe mutable store for trusted root AIDs.

    Mutations are lock-protected. Reads use a snapshot method that
    returns an immutable copy — callers hold the frozenset for the
    duration of one request; concurrent mutations cannot affect it.
    An empty set is a valid state (fail-closed emergency mode).
    """
    def __init__(self, initial: frozenset[str]) -> None:
        self._roots: set[str] = set(initial)
        self._lock: asyncio.Lock = asyncio.Lock()

    async def snapshot(self) -> frozenset[str]:
        async with self._lock:
            return frozenset(self._roots)

    async def add(self, aid: str) -> frozenset[str]:
        async with self._lock:
            self._roots.add(aid)
            return frozenset(self._roots)

    async def remove(self, aid: str) -> frozenset[str]:
        """Remove an AID. Raises KeyError if not present. Empty set allowed."""
        async with self._lock:
            if aid not in self._roots:
                raise KeyError(aid)
            self._roots.discard(aid)
            return frozenset(self._roots)

    async def replace(self, new_roots: set[str]) -> frozenset[str]:
        """Atomically replace all roots. Empty set is permitted (fail-closed)."""
        async with self._lock:
            self._roots = set(new_roots)
            return frozenset(self._roots)

_trusted_roots_store = _TrustedRootsStore(_parse_trusted_roots())


async def get_trusted_roots_snapshot() -> frozenset[str]:
    """Take an atomic immutable snapshot of trusted roots for one request.

    Called once per request at the boundary in main.py; the returned
    frozenset is threaded through all verification phases.
    """
    return await _trusted_roots_store.snapshot()
```

**Import site migration (complete audit):**

| File | Line | Current use | Migration |
|------|------|-------------|-----------|
| `app/main.py` | ~627, ~1002 | `trusted_roots=set(TRUSTED_ROOT_AIDS)` (2 call sites) | Replace with `trusted_roots=await get_trusted_roots_snapshot()` |
| `app/vvp/verify_callee.py` | 779 | `from app.core.config import TRUSTED_ROOT_AIDS` then `trusted_roots=TRUSTED_ROOT_AIDS` at line 802 | Change to accept `trusted_roots` parameter passed from `main.py` caller; remove local import |
| `app/vvp/ui/credential_viewmodel.py` | 21, 1580 | `issuer_aid in TRUSTED_ROOT_AIDS` (UI display only) | Change `build_credential_card_vm()` to accept `trusted_roots: frozenset[str]` parameter; caller in `main.py` passes the request-scoped snapshot |
| All deeper functions | — | Already accept `trusted_roots: Set[str]` as parameter | No changes |

The two entry points in `main.py` call `verify()` and `verify_callee()`. Both paths must pass the same snapshot obtained at the top of the request handler. The `build_credential_card_vm()` function used in UI paths also receives the snapshot from the same request handler.

#### Component 1b: Empty-Set Behavior — Chain Validation Handles It

**No global pre-check is added.** When `trusted_roots == ∅`, `validate_credential_chain()` already fails with a chain error because no issuer matches a trusted root. This is fail-closed behavior without requiring a special pre-check in `verify.py`.

**Trust domain awareness and known limitation:**

The existing `TRUSTED_ROOT_AIDS` single flat set spans two governance domains:
- **vLEI domain**: GLEIF Root AID — anchors the main vLEI chain (required for `overall_status`)
- **Vetter domain**: GSMA Governance AID — **NOTE:** the `verify_vetter_constraints()` path does NOT validate the VetterCertification credential's issuer chain back to trusted roots; it finds the credential by schema type in the dossier. This means removing the GSMA root from `TRUSTED_ROOT_AIDS` will NOT disable vetter constraint evaluation. This is existing behavior, unchanged by this sprint.

The admin UI will **label known AIDs** and include a warning for the GSMA root: "Note: removing this root does not disable vetter constraint evaluation (Phase 11b). Full vetter chain trust validation is a future enhancement." The `GET /admin/trusted-roots` response includes a `known_roots` advisory:
```json
{
  "trusted_roots": ["EDP1vHcw_..."],
  "known_roots": {
    "EDP1vHcw_wc4M__Fj53-cJaBnZZASd-aMTaSyWEQ-PC2": {
      "domain": "vLEI", "label": "GLEIF Root",
      "required_for": "vLEI chain validation (affects overall_status)"
    }
  }
}
```

Domain-aware split configuration (separate `VVP_TRUSTED_VLEI_AIDS` / `VVP_TRUSTED_VETTER_AIDS`) and full vetter chain trust validation are deferred to a future sprint.

#### Component 2: Request-Scoped Trusted-Root Fingerprint

Cache correctness requires that a verification result is stored under the trusted-root set that was **actually used** during that request — not the global state at cache-write time. This ensures a mutation cannot cause stale results to be served from cache.

**Design:**
1. Each request computes a `trusted_roots_fp` from its snapshot: `hashlib.sha256(",".join(sorted(snapshot)).encode()).hexdigest()[:8]`
2. This fingerprint is included in the `VerifyRequest` context and passed to `verify()`.
3. The verification cache key and fingerprint-check both use this per-request value, not the global `compute_config_fingerprint()`.
4. `compute_config_fingerprint()` in `verification_cache.py` is updated to accept an explicit `trusted_roots: frozenset[str]` parameter rather than reading from mutable global state:

```python
def compute_config_fingerprint(trusted_roots: frozenset[str]) -> str:
    """Compute config fingerprint for the given request's trusted roots.

    All existing inputs are preserved (clock_skew, max_token_age, max_validity,
    schema strictness); trusted_roots is now passed explicitly rather than read
    from mutable global state. This ensures the fingerprint is consistent with
    the request-scoped snapshot.
    """
    data = json.dumps({
        "clock_skew": CLOCK_SKEW_SECONDS,
        "max_token_age": MAX_TOKEN_AGE_SECONDS,
        "max_validity": MAX_PASSPORT_VALIDITY_SECONDS,
        "schema_strict": SCHEMA_VALIDATION_STRICT,  # preserved existing input
        "trusted_roots": sorted(trusted_roots),      # explicit arg, not global
    }, sort_keys=True)
    return hashlib.sha256(data.encode()).hexdigest()[:16]
```

5. The module-level `_cached_config_fingerprint` cache is removed (no longer needed since the value depends on the per-request snapshot, not a stable global).
6. `invalidate_trusted_roots_cache()` in `verification_cache.py` becomes just: `get_verification_cache().clear()`.

This cleanly removes the mutable global from the cache path. Cache entries are bound to the fingerprint of the exact root set used for that request.

#### Component 3: AID Validation Using KERI Identifier Prefix

New trusted roots are validated using `keripy.core.coring.Prefixer`, which validates:
- Valid qb64 derivation code
- Correct qb64 encoding
- Correct total length for the derivation code

```python
def validate_aid_as_keri_prefix(aid: str) -> bool:
    """Validate aid is a syntactically valid KERI identifier prefix."""
    try:
        from keripy.core.coring import Prefixer
        Prefixer(qb64=aid)
        return True
    except Exception:
        return False
```

**Documented semantic limitation:** keripy `Prefixer` validates that a value is a valid KERI identifier prefix. It cannot distinguish a controller AID (key-derived) from a content-addressed SAID (both may use the same derivation codes). Operators are responsible for adding only controller AIDs. The admin UI prominently warns: "Only add controller AIDs from KERI key events — not schema SAIDs."

#### Component 4: Admin Authentication — Fail-Closed By Default

**New env var:** `VVP_ADMIN_TOKEN: str | None = os.getenv("VVP_ADMIN_TOKEN")`

**Authorization policy:**
- `VVP_ADMIN_TOKEN` **not set**: all mutation endpoints return **503 with `{"detail": "Admin mutations require VVP_ADMIN_TOKEN to be configured"}`**. **All read-only admin endpoints** (`GET /admin`, `GET /admin/trusted-roots`) also require the token when it is configured — they return 401 without a valid token. When no token is configured, read-only endpoints remain accessible (informational, no state change possible).
- `VVP_ADMIN_TOKEN` **set**: **all `/admin/*` endpoints** require `Authorization: Bearer <token>`; absent or wrong token → 401.
- `ADMIN_ENDPOINT_ENABLED=false`: all admin endpoints (read and write) return 404 as before.

This makes the entire admin surface uniformly require authentication when a token is configured.

**CORS policy for `/admin/*`:**

All admin routes enforce same-origin only: if an `Origin` header is present, it must match the request host exactly. Cross-origin requests → 403. No exceptions.

FastAPI dependency:
```python
def require_admin_write(request: Request):
    """Dependency for all trusted-root mutation endpoints."""
    if not ADMIN_ENDPOINT_ENABLED:
        raise HTTPException(status_code=404, detail="Admin endpoint disabled")
    if ADMIN_TOKEN is None:
        raise HTTPException(
            status_code=503,
            detail="Admin mutations require VVP_ADMIN_TOKEN to be configured",
        )
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer ") or auth[7:] != ADMIN_TOKEN:
        raise HTTPException(status_code=401, detail="Unauthorized")
```

Deployment docs will advise setting `VVP_ADMIN_TOKEN` for any admin-accessible deployment, and restricting admin ports to trusted networks.

**CORS for admin paths:**

A FastAPI middleware/dependency enforces same-origin: if an `Origin` header is present on a mutation request, it must match the request host. Cross-origin mutations are rejected with 403. Read endpoints allow cross-origin (needed for UI).

#### Component 5: Browser Admin UI — Safe Token Handling

The admin UI browser flow must not store the bearer token in `localStorage`, `sessionStorage`, URL params, DOM attributes, or inline HTML.

**Design: in-memory session token prompt**

When the user first attempts a mutation action in the admin UI:
1. A modal dialog appears: "Enter admin token to authorize changes"
2. The input uses `type="password"` (masked)
3. The token is held **only** in a module-scoped JS variable (`let _adminToken = null`)
4. The variable is cleared on page close/refresh (standard JS lifecycle)
5. The token is sent only as an `Authorization: Bearer` header in `fetch()` calls — never appended to URLs, stored in DOM, or logged

```javascript
// admin.js
let _adminToken = null;

async function requireToken() {
    if (_adminToken) return _adminToken;
    _adminToken = window.prompt("Enter admin token:");  // simplest safe approach
    return _adminToken;
}

async function mutateRoots(action, body) {
    const token = await requireToken();
    const resp = await fetch(`/admin/trusted-roots/${action}`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify(body),
    });
    if (resp.status === 401) {
        _adminToken = null;  // clear bad token, will re-prompt
        throw new Error("Invalid admin token");
    }
    return resp.json();
}
```

Using `window.prompt()` avoids custom modal HTML while keeping the implementation simple and the token out of the DOM. The prompt is browser-native and not stored anywhere.

**Security properties:**
- Token not in DOM, not in localStorage, not in URL
- Token cleared on page close/refresh
- HTTPS-only recommendation in deployment docs prevents network interception

#### Component 6: Security Headers

All admin responses (read and write) include:
```
Cache-Control: no-store, no-cache
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Content-Security-Policy: default-src 'self'; script-src 'self'; connect-src 'self'; style-src 'self'
```

The admin UI templates use no inline scripts or styles; all JS is in `admin.js` (external file). CSP is compatible with `script-src 'self'`.

#### Component 7: Normalized API Contract

**Canonical trusted-roots response shape** (used in both endpoints):
```json
{
  "trusted_roots": ["EDP1vHcw_..."],
  "count": 1,
  "env_source": "VVP_TRUSTED_ROOT_AIDS",
  "empty_set_active": false,
  "_scope": "single-instance only — changes are not propagated to other replicas"
}
```

When `trusted_roots` is empty:
```json
{
  "trusted_roots": [],
  "count": 0,
  "env_source": "VVP_TRUSTED_ROOT_AIDS",
  "empty_set_active": true,
  "_scope": "...",
  "_warning": "No trusted roots configured. Verifier is in fail-closed mode — all verification requests return INVALID."
}
```

**`GET /admin/trusted-roots`** — returns the canonical shape above.

**`GET /admin`** — `trusted_roots` field is the same canonical shape (not a different structure). The `GET /admin` response embeds the full trusted-roots object:
```json
{
  "normative": { ... },
  "configurable": { ... },
  "trusted_roots": {  ← same canonical TrustedRootsResponse shape
    "trusted_roots": ["E..."],
    "count": 1,
    "env_source": "VVP_TRUSTED_ROOT_AIDS",
    "empty_set_active": false,
    "_scope": "..."
  },
  "witnesses": { ... },
  ...
}
```

Mutation responses include the same canonical shape plus a `_mutation_warning`:
```json
{
  "trusted_roots": ["E..."],
  "count": 1,
  "env_source": "VVP_TRUSTED_ROOT_AIDS",
  "empty_set_active": false,
  "_scope": "...",
  "_mutation_warning": "Changes are in-memory and apply to this instance only. Update VVP_TRUSTED_ROOT_AIDS and restart all instances to persist."
}
```

#### Component 8: Cache Invalidation

On every mutation: call `invalidate_trusted_roots_cache()` which calls `get_verification_cache().clear()`.

With the fingerprint now request-scoped (Component 2), there is no global `_cached_config_fingerprint` to reset. Cache invalidation is just a cache clear.

**Operational impact (quantified):**
- Cache max size: 200 entries; TTL: 3600s
- Each re-verification: ~1–3 witness queries at ~200ms each = ~200–600ms per entry
- Worst case: 200 entries parallelized async = cold-start completes within ~1–2 minutes
- At VVP SIP scale (10–50 calls/minute), cache refills within the re-verification window
- Operator guardrail: admin UI warns "This will clear the verification cache"
- Rate limiting: `require_admin_write` dependency rejects a second mutation within 30 seconds (503 "rate limited") to prevent rapid repeated flushes

Acceptable for mutations that occur at most a few times per day. Versioned/fingerprint-based cache aging is deferred to a future sprint.

#### Component 9: Admin HTML Pages

**Route naming (normalized):**
- Both services: admin HTML at `/admin/ui`
- Monorepo also: `/ui/admin` redirects 302 → `/admin/ui` for backwards compatibility

**Monorepo** — update `services/verifier/app/templates/admin.html`:
- New "Trusted Roots" section at top
- Orange banner: "⚠️ In-memory only — applies to this instance only."
- Red banner (when count = 0): "🚨 Fail-closed mode — no trusted roots configured."
- Table: current AIDs + Remove button per row
- Add form: text input with placeholder `E...`, warning label, submit
- Token prompt via `window.prompt()` on first mutation
- External JS only (`/static/admin.js`); no inline scripts

**OVC** — new `app/templates/admin.html`:
Self-contained page. Sections:
- Service Configuration (read-only)
- Trusted Roots (editable, same structure)
- Cache Status (read-only)
- External JS via `/static/admin.js`

#### Component 10: Documentation Updates

| Document | Required Update |
|----------|----------------|
| `knowledge/api-reference.md` | All new/changed admin routes: endpoint contracts, request/response shapes, auth model (token-required vs informational), error codes, redirect behavior (`/ui/admin` → `/admin/ui`) |
| `knowledge/verification-pipeline.md` | Trusted-root snapshot model (request-scoped); empty trusted-roots behavior (chain validation fails naturally, no global pre-check); domain labels for GLEIF/GSMA roots |
| `knowledge/deployment.md` | "Trusted Roots Admin" section: `VVP_ADMIN_TOKEN` setup, HTTPS + same-origin requirements, single-instance constraint, rate limiting, HA/multi-replica guidance |
| `CHANGES.md` | Sprint 83 entry |
| OVC `README.md` | "Admin Page" section: `/admin/ui`, env vars (`VVP_ADMIN_TOKEN`, `VVP_TRUSTED_ROOT_AIDS`), known-roots domain labels, single-instance note, fail-closed behavior |
| OVC `CHANGES.md` | v0.3.0 entry |

### Data Flow

```
Admin mutation:
1. POST /admin/trusted-roots/add {"aid": "E..."}
   Authorization: Bearer <token>
2. require_admin_write() → validates ADMIN_ENDPOINT_ENABLED + token
3. validate_aid_as_keri_prefix(aid)
4. _trusted_roots_store.add(aid)     (asyncio-locked)
5. get_verification_cache().clear()  (evict all cached entries)
6. return canonical TrustedRootsResponse with _mutation_warning

Concurrent verification request:
1. Request arrives
2. trusted_roots = await get_trusted_roots_snapshot()   (atomic lock + copy)
   → if empty: snapshot is empty frozenset; chain validation will fail for all credentials
3. fp = compute_config_fingerprint(trusted_roots)        (explicit arg, not global)
4. Cache lookup uses fp
5. All verification phases receive trusted_roots frozenset
6. Cache write stores entry with fp from step 3
   → Admin mutation at step 4 above cannot affect this fp or these phases
```

### Error Handling

| Condition | HTTP Status | Response |
|-----------|-------------|---------- |
| Invalid AID (keripy Prefixer fails) | 422 | `{"detail": "Invalid AID: not a valid KERI identifier prefix"}` |
| Remove: AID not in set | 404 | `{"detail": "AID not found in trusted roots"}` |
| Replace: invalid AID in list | 422 | `{"detail": "Invalid AID at index N"}` |
| No `VVP_ADMIN_TOKEN` configured | 503 | `{"detail": "Admin mutations require VVP_ADMIN_TOKEN to be configured"}` |
| Missing/wrong bearer token | 401 | `{"detail": "Unauthorized"}` |
| Cross-origin mutation | 403 | `{"detail": "Cross-origin admin access not allowed"}` |
| Admin disabled | 404 | `{"detail": "Admin endpoint disabled"}` |
| Verify with empty roots | 200 INVALID | Existing chain validation returns INVALID — error: "chain terminated without trusted root" |

### Test Strategy

**Monorepo** — `tests/test_admin_trusted_roots.py`:
- `GET /admin/trusted-roots` returns initial set, canonical shape
- `GET /admin` embeds same canonical trusted-roots shape
- With no `VVP_ADMIN_TOKEN`: mutation endpoints return 503
- With `VVP_ADMIN_TOKEN` set but wrong bearer: 401
- With correct bearer: mutations succeed
- `POST add` adds valid AID, idempotent for existing AID
- `POST remove` removes existing AID; 404 for unknown
- `POST remove` last root: succeeds, returns empty set with `empty_set_active: true`
- `POST replace` with empty list: succeeds (fail-closed state)
- `POST replace` with invalid AID: 422
- Invalid AID format: 422
- Verification cache cleared after mutation
- Config fingerprint is per-request (not global): test that snapshot fp == cache entry fp
- `GET /verify` with empty roots returns `INVALID` (chain validation fails naturally — no pre-check needed)
- Snapshot isolation: snapshot before mutation unchanged by concurrent mutation
- Cross-origin mutation rejected with 403

**OVC** — `tests/test_admin.py`:
- All equivalent tests
- `GET /admin` returns full config including canonical trusted-roots shape
- `GET /admin/ui` returns 200 HTML with `Content-Security-Policy` header
- `Cache-Control: no-store` on admin responses

## Files to Create/Modify

| Repo | File | Action | Purpose |
|------|------|--------|---------|
| Monorepo | `services/verifier/app/core/config.py` | Modify | Add `_TrustedRootsStore`, `get_trusted_roots_snapshot()`, `ADMIN_TOKEN`; remove `TRUSTED_ROOT_AIDS` |
| Monorepo | `services/verifier/app/vvp/verification_cache.py` | Modify | Parameterize `compute_config_fingerprint(trusted_roots)`, remove global cache, add `invalidate_trusted_roots_cache()` |
| Monorepo | `services/verifier/app/vvp/verify.py` | Modify | Pass snapshot-derived `trusted_roots` and `fp` to cache operations |
| Monorepo | `services/verifier/app/vvp/verify_callee.py` | Modify | Remove local `TRUSTED_ROOT_AIDS` import; accept `trusted_roots` parameter from caller |
| Monorepo | `services/verifier/app/vvp/ui/credential_viewmodel.py` | Modify | Remove module-level import; accept `trusted_roots` param in `build_credential_card_vm()` |
| Monorepo | `services/verifier/app/main.py` | Modify | Snapshot call sites (all 3+); add trusted-roots endpoints + auth dependency; `/admin/ui` + redirect from `/ui/admin`; security headers middleware |
| Monorepo | `services/verifier/app/templates/admin.html` | Modify | Add Trusted Roots section; link to `/admin/ui` |
| Monorepo | `services/verifier/web/admin.js` | Create | Admin UI JS (token prompt, fetch wrappers) |
| Monorepo | `services/verifier/tests/test_admin_trusted_roots.py` | Create | New tests |
| Monorepo | `knowledge/api-reference.md` | Modify | Document new endpoints |
| Monorepo | `knowledge/deployment.md` | Modify | Trusted-roots admin section |
| OVC | `app/config.py` | Modify | Add `_TrustedRootsStore`, `get_trusted_roots_snapshot()`, `ADMIN_TOKEN` |
| OVC | `app/vvp/verify.py` | Modify | Pass snapshot-derived `trusted_roots` to chain validation |
| OVC | `app/admin.py` | Create | Admin APIRouter |
| OVC | `app/main.py` | Modify | Mount admin router; snapshot call site; static mount |
| OVC | `app/static/admin.js` | Create | Admin UI JS |
| OVC | `app/templates/admin.html` | Create | Admin HTML page |
| OVC | `tests/test_admin.py` | Create | New tests |
| OVC | `README.md` | Modify | Admin page documentation |
| OVC | `CHANGES.md` | Modify | v0.3.0 entry |

## Open Questions

None — scope fully defined.

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Developer forgets cache clear after mutation | Low | Medium | `invalidate_trusted_roots_cache()` is the single exit point for all mutations; tested |
| Operator clears all roots accidentally | Low | Medium | UI shows red fail-closed banner; `empty_set_active: true` in API response; confirm button required |
| Schema SAID added as trusted root | Low | High | keripy Prefixer validates; UI warning; error message explains distinction |
| Multi-instance deployment uses runtime mutation | Medium | High | 503 response when `ADMIN_TOKEN` not set (fail-closed); permanent UI banner; deployment docs |
| `window.prompt()` blocked in some browser environments | Low | Low | The mutation endpoint still works via curl/API; only UI flow affected. Can upgrade to custom modal in future sprint |
| `keripy` import fails in OVC edge case | Low | Low | OVC already uses keripy in `canonical.py`; fallback to regex with warning |

## Revision History

| Round | Date | Changes |
|-------|------|---------|
| R1 | 2026-03-12 | Initial draft |
| R2 | 2026-03-12 | Address R1: snapshot semantics, CSRF/CORS, AID validation, last-root invariant, single-instance scope, docs |
| R3 | 2026-03-12 | Address R2: keripy Prefixer validation, fail-closed auth (token required), allow empty set, route normalization, idempotent add, import audit, cache impact bounded |
| R4 | 2026-03-12 | Address R3: (1) request-scoped fingerprint — `compute_config_fingerprint(trusted_roots)` explicit arg, remove global cache; (2) fail-closed by default — mutations return 503 when `VVP_ADMIN_TOKEN` unset; (3) browser token in JS memory only via `window.prompt()`, never in DOM/storage; (4) canonical `TrustedRootsResponse` shape used in both GET endpoints |
| R5 | 2026-03-12 | Address R4: (1) complete import audit — adds `verify_callee.py` (line 802) and `credential_viewmodel.py` (line 1580) as call sites requiring snapshot propagation; (2) trust-domain classification deferred — current sprint maintains single undifferentiated `TRUSTED_ROOT_AIDS` set; admin UI shows `known_roots` advisory labels (GLEIF/GSMA) for operator clarity; domain-aware split is a future concern; (3) live witness resolution for AID validation explicitly out of scope; documented; (4) admin read-endpoint authentication consistent with all existing admin endpoints |
| R6 | 2026-03-12 | Address R5: (1) trust domain — remove global empty-set pre-check; rely on existing chain validation fail-closed behavior; add `known_roots` advisory labels in API response; (2) admin security — all `/admin/*` routes require bearer token when `VVP_ADMIN_TOKEN` set (reads AND writes); same-origin CORS enforced; (3) cache impact quantified; mutation rate limiting (30s cooldown); (4) documentation expanded to include `knowledge/verification-pipeline.md` and full route/auth/error coverage |
| R7 | 2026-03-12 | Address R6: (1) vetter constraint known limitation documented — `verify_vetter_constraints()` does not chain-validate back to trusted roots (existing behavior, unchanged by sprint); admin UI warns operators about GSMA root limitation; full vetter chain trust deferred; (2) internal consistency — all `NO_TRUSTED_ROOTS` references removed; no `verify.py` pre-check; chain validation handles empty-set naturally; (3) `compute_config_fingerprint()` retains all existing inputs including `SCHEMA_VALIDATION_STRICT`; `trusted_roots` made explicit arg |
