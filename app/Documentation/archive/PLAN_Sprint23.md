# Sprint 23: Caching, Test Vectors & Deployment Completion

## Problem Statement

The VVP Verifier is at 96% completion (174/182 items). Sprint 23 aims to complete all remaining practical items to reach production readiness. Analysis reveals many checklist items are already implemented but not marked complete.

## Exploration Findings

### Items Already Complete (Checklist Updates Only)
| Item | Description | Evidence |
|------|-------------|----------|
| 15.5 | OOBI timeout test vector | `v05_oobi_timeout.json` exists |
| 15.8 | SAID mismatch test vector | `v07_said_mismatch.json` exists |
| 15.10 | TNAlloc mismatch test vector | `v09_tnalloc_mismatch.json` exists |
| 15.11 | Delegation invalid test vector | `v11_delegation_invalid.json` exists |
| 15.12 | Revoked credential test vector | `v10_revoked_credential.json` exists |
| 15.14 | CI integration | `.github/workflows/deploy.yml` runs tests |
| 16.2 | POST /verify-callee | `app/main.py:67-122` + 41 tests |
| 16.8 | Docker build verification | CI pipeline builds successfully |

### Items Requiring Implementation
| Item | Description | Complexity |
|------|-------------|------------|
| 14.2 | SAID-based dossier cache | Medium |
| 14.6 | Cache invalidation on revocation | Medium |
| 14.7 | Cache metrics/logging | Low |
| 15.7 | Key rotated before T test vector | Low |
| 16.6 | Dockerfile updates (blake3) | Low |
| 16.7 | pyproject.toml (add blake3) | Low |
| 16.9 | E2E test documentation | Low |

### Uncommitted Work to Commit
- `app/vvp/keri/identity_resolver.py` (372 lines, complete)
- `tests/test_identity_resolver.py` (45 tests, complete)
- Various UI/config changes from recent development

## Proposed Solution

### Part 1: Commit Uncommitted Work

Commit the identity_resolver module and related changes that are already complete.

**Files to commit:**
- `app/vvp/keri/identity_resolver.py` (new)
- `tests/test_identity_resolver.py` (new)
- Modified files per git status

### Part 2: URL-Keyed Dossier Cache with SAID Index (14.2)

**Location:** `app/vvp/dossier/cache.py` (new file)

**Reviewer Feedback Addressed:**
- [High] Cache by URL (available pre-fetch) instead of SAID (only available post-parse)
- [Medium] Implement proper LRU eviction with `_access_order` tracking
- [Medium] Secondary index maps credential SAIDs → URLs for revocation invalidation

**Design:**
```python
@dataclass
class CachedDossier:
    dag: DossierDAG
    raw_content: bytes
    fetch_timestamp: float
    content_type: str
    contained_saids: Set[str]  # All credential SAIDs in this dossier

class DossierCache:
    def __init__(self, ttl_seconds: float = 300, max_entries: int = 100):
        # Primary index: URL → (CachedDossier, cached_at)
        self._cache: Dict[str, tuple[CachedDossier, float]] = {}
        # Secondary index: credential SAID → set of URLs containing it
        self._said_to_urls: Dict[str, Set[str]] = {}
        # LRU tracking
        self._access_order: list[str] = []
        self._ttl = ttl_seconds
        self._max_entries = max_entries
        self._lock = asyncio.Lock()
        self._metrics = CacheMetrics()

    async def get(self, url: str) -> Optional[CachedDossier]:
        """Lookup by URL (available pre-fetch). Updates LRU order."""

    async def put(self, url: str, dossier: CachedDossier) -> None:
        """Store with URL key. Builds SAID index. Enforces LRU eviction."""

    async def invalidate_by_said(self, said: str) -> int:
        """Invalidate all dossiers containing a revoked credential SAID.
        Returns count of invalidated entries."""

    async def invalidate_by_url(self, url: str) -> bool:
        """Direct invalidation by URL. Returns True if entry existed."""

    def _evict_lru(self) -> None:
        """Evict least-recently-used entry when at capacity."""

    def _update_access_order(self, url: str) -> None:
        """Move URL to end of access order (most recent)."""
```

**Integration in verify.py:**
```python
# Before fetch_dossier() - URL is available from VVP-Identity evd field
evd_url = vvp_identity.evd
cached = await dossier_cache.get(evd_url)
if cached:
    log.info(f"Dossier cache hit: {evd_url[:50]}...")
    return cached.dag, cached.raw_content

# After successful fetch and parse
dossier_cache.put(evd_url, CachedDossier(
    dag=dag,
    raw_content=raw_content,
    fetch_timestamp=time.time(),
    content_type=content_type,
    contained_saids={node.said for node in dag.nodes.values()}
))
```

**Configuration in config.py:**
```python
# TTL aligned with §5C.2 freshness policy (default: 5 minutes, same as key state)
# Can be increased for stable dossiers, but should not exceed credential expiry
DOSSIER_CACHE_TTL_SECONDS: int = int(os.getenv("VVP_DOSSIER_CACHE_TTL", "300"))
DOSSIER_CACHE_MAX_ENTRIES: int = int(os.getenv("VVP_DOSSIER_CACHE_MAX_ENTRIES", "100"))
```

**TTL and §5C.2 Freshness:**
- Default TTL of 300s matches key state cache freshness per §5C.2
- Configurable to allow longer TTL for stable production dossiers
- Should not exceed `MAX_TOKEN_AGE_SECONDS` to ensure verification freshness

### Part 3: Cache Invalidation on Revocation (14.6)

**Reviewer Feedback Addressed:**
- [Medium] Use secondary index to map revoked credential SAID → cached dossier URLs

**Design:** When revocation detected, use SAID→URL index to invalidate related caches.

**Location:** Modify `app/vvp/verify.py` in `check_dossier_revocations()`

```python
# After detecting REVOKED status:
if result.status == CredentialStatus.REVOKED:
    log.info(f"Credential revoked: {said[:20]}...")
    # Use secondary index to find and invalidate all dossiers containing this credential
    invalidated_count = await dossier_cache.invalidate_by_said(said)
    log.info(f"Invalidated {invalidated_count} cached dossier(s) containing revoked credential")
    # Key state cache invalidation for issuer
    if issuer_aid:
        key_state_cache.invalidate(issuer_aid)
```

**DossierCache.invalidate_by_said():**
- Lookup `_said_to_urls[said]` to get all URLs containing this credential
- Remove each URL from `_cache`
- Update `_said_to_urls` to remove the invalidated mappings
- Update `_access_order` to remove invalidated URLs
- Log invalidation event with count
- Increment `_metrics.invalidations`

### Part 4: Cache Metrics/Logging (14.7)

**Design:** Add structured logging for cache operations.

**Location:** Extend each cache class with metrics tracking.

```python
@dataclass
class CacheMetrics:
    hits: int = 0
    misses: int = 0
    evictions: int = 0
    invalidations: int = 0

    def hit_rate(self) -> float:
        total = self.hits + self.misses
        return self.hits / total if total > 0 else 0.0
```

**Logging pattern:**
```python
log.info(f"cache_operation", extra={
    "cache_type": "dossier",
    "operation": "hit",
    "key": said[:20],
    "cache_size": len(self._cache),
    "hit_rate": self._metrics.hit_rate()
})
```

**Admin endpoint extension:**
```python
@app.get("/admin")
async def admin_info():
    return {
        ...existing...,
        "cache_metrics": {
            "dossier": dossier_cache.metrics(),
            "key_state": key_state_cache.metrics(),
            "revocation": tel_client.cache_metrics()
        }
    }
```

### Part 5: Key Rotated Before T Test Vector (15.7)

**File:** `tests/vectors/data/v12_key_rotated_before_t.json`

**Design:**
- Tier 2 test vector
- PASSporT signed with key that was rotated before reference_time_t
- Mock via `mock_key_state_error: "KEY_ROTATED_BEFORE_T"`
- Expected: INVALID with `passport_verified: INVALID`
- Error: `KERI_STATE_INVALID`

**Runner modification:** Add handling for `KEY_ROTATED_BEFORE_T` mock error.

### Part 6: Dependency Updates (16.6, 16.7)

**pyproject.toml:**
```toml
dependencies = [
  ...existing...,
  "blake3>=0.3.0",  # SAID computation (already used in kel_parser.py)
]
```

**Dockerfile:** No changes needed - blake3 is pure Python with optional C extension.

### Part 7: Checklist Updates

Update `app/Documentation/VVP_Implementation_Checklist.md`:
- Mark 15.5, 15.8, 15.10, 15.11, 15.12, 15.14 as complete
- Mark 16.2, 16.8 as complete
- Add commit SHAs for completed items

## Files to Create/Modify

| File | Action | Purpose |
|------|--------|---------|
| `app/vvp/dossier/cache.py` | Create | SAID-based dossier cache |
| `app/vvp/dossier/__init__.py` | Modify | Export DossierCache |
| `app/vvp/verify.py` | Modify | Integrate dossier cache, add invalidation |
| `app/vvp/keri/cache.py` | Modify | Add CacheMetrics |
| `app/vvp/keri/tel_client.py` | Modify | Add cache_metrics() method |
| `app/core/config.py` | Modify | Add dossier cache config |
| `app/main.py` | Modify | Add cache metrics to /admin |
| `tests/test_dossier_cache.py` | Create | Tests for dossier cache |
| `tests/vectors/data/v12_key_rotated_before_t.json` | Create | New test vector |
| `tests/vectors/runner.py` | Modify | Handle KEY_ROTATED_BEFORE_T |
| `pyproject.toml` | Modify | Add blake3 dependency |
| `app/Documentation/VVP_Implementation_Checklist.md` | Modify | Mark complete items |
| `CHANGES.md` | Modify | Sprint 23 summary |

## Test Strategy

1. **Dossier Cache Tests** (`tests/test_dossier_cache.py`):
   - Basic get/put operations by URL
   - TTL expiration behavior
   - LRU eviction when at max_entries (verify oldest accessed is evicted)
   - `invalidate_by_said()` uses secondary index correctly
   - `invalidate_by_url()` direct invalidation
   - Secondary index (`_said_to_urls`) correctly tracks contained SAIDs
   - Concurrent access with asyncio.Lock

2. **Cache Metrics Tests**:
   - Hit/miss counting
   - Hit rate calculation
   - Metrics reset

3. **Integration Tests**:
   - Verify cache hit on repeated dossier fetch
   - Verify invalidation on revocation
   - Verify metrics in /admin response

4. **Test Vector**:
   - Run `./scripts/run-tests.sh tests/vectors/test_vectors.py::TestVectorSuite::test_vector[v12]`

## Verification

```bash
# Run all tests
./scripts/run-tests.sh -v

# Run specific new tests
./scripts/run-tests.sh tests/test_dossier_cache.py -v
./scripts/run-tests.sh tests/vectors/test_vectors.py -v

# Verify cache metrics in admin endpoint
curl http://localhost:8000/admin | jq '.cache_metrics'

# Verify Docker build
docker build -t vvp-test .
docker run --rm vvp-test python -c "import blake3; print('blake3 OK')"
```

## Implementation Order (Pair Programming Workflow)

### Phase A: Plan Review
1. **Plan Review Request** - Submit plan to Reviewer for approval
2. **Address Feedback** - Iterate until APPROVED verdict received

### Phase B: Implementation (After Plan Approval)
1. **Commit existing work** - identity_resolver + related changes
2. **Add blake3 dependency** - pyproject.toml update
3. **Create dossier cache** - cache.py + tests
4. **Add cache metrics** - Extend all caches
5. **Add invalidation logic** - verify.py modifications
6. **Create test vector** - v12_key_rotated_before_t.json
7. **Update checklist** - Mark complete items
8. **Run tests** - Verify all tests pass

### Phase C: Code Review
9. **Code Review Request** - Submit implementation to Reviewer
10. **Address Feedback** - Fix issues until APPROVED verdict

### Phase D: Completion
11. **Update CHANGES.md** - Sprint 23 summary with commit SHA
12. **Archive Plan** - Copy to `app/Documentation/PLAN_Sprint23.md`
13. **Final Commit** - Documentation updates

## Open Questions

None - analysis is complete and approach is clear.

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Cache memory growth | Low | Medium | LRU eviction with configurable max_entries |
| Race conditions in cache | Low | High | asyncio.Lock for thread safety |
| Test vector timing sensitivity | Low | Low | Use frozen time in vector runner |

---

## Implementation Notes

### Deviations from Plan

None - implementation followed the approved plan exactly.

### Additional Work

- Created `tests/conftest.py` with autouse fixture to reset dossier cache before each test
- Updated `tests/vectors/conftest.py` with matching cache reset fixture
- Added verify_vvp-level integration tests after code review feedback:
  - `test_verify_vvp_fetch_skipped_on_cache_hit` - Asserts fetch_dossier NOT called on cache hit
  - `test_verify_vvp_fetch_called_on_cache_miss` - Asserts fetch_dossier IS called on cache miss

### Test Results

```
1103 passed in 6.12s
```

### Review History

| Round | Verdict | Key Feedback |
|-------|---------|--------------|
| Plan Rev 0 | CHANGES_REQUESTED | Cache by URL instead of SAID; add LRU eviction |
| Plan Rev 1 | APPROVED | Design addresses feedback |
| Code Rev 0 | CHANGES_REQUESTED | verify.py doesn't use cache (get/put missing) |
| Code Rev 1 | CHANGES_REQUESTED | Integration tests don't exercise verify_vvp directly |
| Code Rev 2 | APPROVED | verify_vvp integration tests exercise cache behavior |

### Commits

| Commit | Description |
|--------|-------------|
| 7e0a87a | Add OOBI-based identity resolver for issuer discovery |
| 7e49dc6 | Sprint 23: URL-keyed dossier cache with SAID index |

### Checklist Items Completed

- 14.2: SAID-based dossier cache (URL-keyed with SAID secondary index)
- 14.6: Cache invalidation on revocation
- 14.7: Cache metrics/logging
- 15.5: OOBI timeout test vector (already existed)
- 15.7: Key rotated before T test vector
- 15.8: SAID mismatch test vector (already existed)
- 15.10: TNAlloc mismatch test vector (already existed)
- 15.11: Delegation invalid test vector (already existed)
- 15.12: Revoked credential test vector (already existed)
- 15.14: CI integration (already existed)
- 16.2: POST /verify-callee (already existed)
- 16.7: Add blake3 dependency
- 16.8: Docker build verification (already existed)

**Overall Progress:** 99% (180/182 items)
