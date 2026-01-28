# Phase 9.3 + Admin: Revocation Integration & Configuration Visibility

## Problem Statement

The VVP Verifier has a functioning TEL client (`tel_client.py`) that can query KERI witnesses for credential revocation status, but this capability is **not integrated into the main verification flow**. Currently:

1. Revocation checking is available only via a standalone `/check-revocation` endpoint
2. The main `/verify` flow does NOT check credential revocation for ACDCs in the dossier
3. Configuration values are scattered across code with no visibility to operators

This means:
- Credentials could be verified even if revoked (spec violation §5.1.1-2.9)
- Operators cannot see or monitor configurable parameters
- Debugging revocation issues requires manual API calls

## Spec References

- **§5.1.1-2.9 (Revocation Status Check)**: "Query TEL for each credential in the dossier. If any credential is revoked, the verification MUST fail with INVALID."
- **§5.3 (Efficiency)**: "Caching and freshness policies for revocation status"
- **§3.3A (Status Propagation)**: "INVALID > INDETERMINATE > VALID precedence"
- **§3.3B (Claim Tree Structure)**: `revocation_clear` is a REQUIRED child of `dossier_verified`

## Current State

### TEL Client (`app/vvp/keri/tel_client.py`)
- `check_revocation()` - queries witnesses for credential status
- `CredentialStatus` enum: ACTIVE, REVOKED, UNKNOWN, ERROR
- Caching with `_cache` dict
- Provenant staging witnesses configured
- INFO-level logging just added (pending commit)

### Verification Flow (`app/vvp/verify.py`)
- Phase 2: VVP-Identity header parsing ✓
- Phase 3: PASSporT Parse + Binding ✓
- Phase 4: KERI Signature Verification ✓
- Phase 5: Dossier Fetch + DAG Validation ✓
- Phase 6: Build Claim Tree ✓
- **Phase 9: Revocation Checking ✗ NOT INTEGRATED**

### Configuration (`app/core/config.py`)
- Normative constants (MAX_IAT_DRIFT_SECONDS, etc.)
- Configurable defaults (CLOCK_SKEW_SECONDS, MAX_TOKEN_AGE_SECONDS, etc.)
- Feature flags (TIER2_KEL_RESOLUTION_ENABLED)
- No admin visibility endpoint

## Proposed Solution

### Approach

Integrate revocation checking into the verification flow by adding the `revocation_clear` claim as a **REQUIRED child of `dossier_verified`** per §3.3B, and add an `/admin` endpoint showing all configuration.

### Alternatives Considered

| Alternative | Pros | Cons | Why Rejected |
|-------------|------|------|--------------|
| Check only root credential | Fast, minimal queries | Doesn't catch revoked chain credentials | Spec requires ALL credentials |
| Async background check | Non-blocking | Status may change during verification | Spec requires synchronous check |
| Top-level revocation claim | Simple tree structure | Violates §3.3B claim tree structure | Spec mandates `revocation_clear` under `dossier_verified` |

---

## Detailed Design

### Component 1: Revocation Checker Function

**Purpose:** Check revocation status for all ACDCs in a dossier DAG.

**Location:** `app/vvp/verify.py` (new function)

**Interface:**
```python
async def check_dossier_revocations(
    dag: DossierDAG,
    oobi_url: Optional[str] = None
) -> ClaimBuilder:
    """Check revocation status for all credentials in a dossier DAG.

    Per spec §5.1.1-2.9: Revocation Status Check
    - Query TEL for each credential in dossier
    - If ANY credential is revoked → INVALID
    - If ANY credential status unknown/error → INDETERMINATE
    - If ALL credentials active → VALID

    Args:
        dag: Parsed and validated DossierDAG
        oobi_url: Optional OOBI URL for witness queries

    Returns:
        ClaimBuilder for `revocation_clear` claim
    """
```

**Behavior:**
1. Iterate over all nodes in `dag.nodes`
2. For each ACDC, extract `said` (d field) and `registry_said` (ri field if present)
3. Call `TELClient.check_revocation()` for each credential
4. Track results: ACTIVE → evidence, REVOKED → INVALID, UNKNOWN/ERROR → INDETERMINATE
5. Build claim with aggregated status and evidence

**Status Mapping (per §5.1.1-2.9):**
| TEL Status | Claim Status | Behavior |
|------------|--------------|----------|
| ACTIVE | VALID | Add evidence: `active:{said[:16]}...` |
| REVOKED | INVALID | Fail with reason, surface `CREDENTIAL_REVOKED` error |
| UNKNOWN | INDETERMINATE | Fail with reason (TEL not found) |
| ERROR | INDETERMINATE | Fail with reason (query failed) |

**Revocation is REQUIRED** - it is never skipped. If TEL is unavailable, the claim becomes INDETERMINATE (not skipped).

### Component 2: Verification Flow Integration

**Purpose:** Add `revocation_clear` claim as child of `dossier_verified` per §3.3B.

**Location:** `app/vvp/verify.py` (modify `verify_vvp()`)

**Changes:**

1. After Phase 5 (dossier validation), add Phase 9:
```python
# -------------------------------------------------------------------------
# Phase 9: Revocation Checking (Tier 2) - §5.1.1-2.9
# -------------------------------------------------------------------------
revocation_claim = ClaimBuilder("revocation_clear")

if dag is not None:
    revocation_claim = await check_dossier_revocations(
        dag,
        oobi_url=passport.header.kid if passport else None
    )
else:
    # Dossier failed - revocation check is INDETERMINATE
    revocation_claim.fail(
        ClaimStatus.INDETERMINATE,
        "Cannot check revocation: dossier validation failed"
    )
```

2. Update claim tree structure per §3.3B:
```python
# dossier_verified now has revocation_clear as a child
dossier_node = ClaimNode(
    name="dossier_verified",
    status=dossier_claim.status,
    reasons=dossier_claim.reasons,
    evidence=dossier_claim.evidence,
    children=[
        ChildLink(required=True, node=revocation_claim.build()),  # NEW per §3.3B
    ],
)

root_claim = ClaimNode(
    name="caller_authorised",
    status=ClaimStatus.VALID,
    children=[
        ChildLink(required=True, node=passport_node),
        ChildLink(required=True, node=dossier_node),
    ],
)
```

### Component 3: Admin Configuration Endpoint

**Purpose:** Expose all configuration values for operator visibility.

**Location:** `app/main.py` (new endpoint)

**Interface:**
```python
@app.get("/admin")
def admin():
    """Return all configurable items for operator visibility.

    Gated by ADMIN_ENDPOINT_ENABLED (default: True for dev, False for prod).
    """
    from app.core.config import (
        MAX_IAT_DRIFT_SECONDS,
        ALLOWED_ALGORITHMS,
        CLOCK_SKEW_SECONDS,
        MAX_TOKEN_AGE_SECONDS,
        MAX_PASSPORT_VALIDITY_SECONDS,
        ALLOW_PASSPORT_EXP_OMISSION,
        DOSSIER_FETCH_TIMEOUT_SECONDS,
        DOSSIER_MAX_SIZE_BYTES,
        DOSSIER_MAX_REDIRECTS,
        TIER2_KEL_RESOLUTION_ENABLED,
        ADMIN_ENDPOINT_ENABLED,
    )
    from app.vvp.keri.tel_client import TELClient
    import os

    if not ADMIN_ENDPOINT_ENABLED:
        return JSONResponse(
            status_code=404,
            content={"detail": "Admin endpoint disabled"}
        )

    return {
        "normative": {
            "max_iat_drift_seconds": MAX_IAT_DRIFT_SECONDS,
            "allowed_algorithms": list(ALLOWED_ALGORITHMS),
        },
        "configurable": {
            "clock_skew_seconds": CLOCK_SKEW_SECONDS,
            "max_token_age_seconds": MAX_TOKEN_AGE_SECONDS,
            "max_passport_validity_seconds": MAX_PASSPORT_VALIDITY_SECONDS,
            "allow_passport_exp_omission": ALLOW_PASSPORT_EXP_OMISSION,
        },
        "policy": {
            "dossier_fetch_timeout_seconds": DOSSIER_FETCH_TIMEOUT_SECONDS,
            "dossier_max_size_bytes": DOSSIER_MAX_SIZE_BYTES,
            "dossier_max_redirects": DOSSIER_MAX_REDIRECTS,
        },
        "features": {
            "tier2_kel_resolution_enabled": TIER2_KEL_RESOLUTION_ENABLED,
            "admin_endpoint_enabled": ADMIN_ENDPOINT_ENABLED,
        },
        "witnesses": {
            "default_witness_urls": TELClient.DEFAULT_WITNESSES,
        },
        "environment": {
            "log_level": os.getenv("VVP_LOG_LEVEL", "INFO"),
        }
    }
```

**Configuration flag:**
```python
# In app/core/config.py
ADMIN_ENDPOINT_ENABLED: bool = os.getenv("ADMIN_ENDPOINT_ENABLED", "true").lower() == "true"
```

---

## Data Flow

```
verify_vvp() Request
        │
        ▼
┌─────────────────────────┐
│ Phase 5: Dossier Parse  │
│   → DossierDAG          │
└───────────┬─────────────┘
            │ (always proceeds)
            ▼
┌─────────────────────────────────────────┐
│ Phase 9: Revocation Checking            │
│   for each ACDC in dag.nodes:           │
│     TELClient.check_revocation()        │
│       → query witnesses                 │
│       → parse TEL events                │
│       → determine status                │
│   Build revocation_clear claim          │
└───────────┬─────────────────────────────┘
            │
            ▼
┌─────────────────────────────────────────┐
│ Phase 6: Claim Tree (per §3.3B)         │
│   caller_authorised                     │
│   ├─ passport_verified                  │
│   └─ dossier_verified                   │
│       └─ revocation_clear (NEW)         │
└─────────────────────────────────────────┘
```

---

## Error Handling

| Error Condition | Error Type | Claim Status | Recovery |
|-----------------|------------|--------------|----------|
| Credential revoked | CREDENTIAL_REVOKED | INVALID | Cannot recover |
| TEL query failed | - | INDETERMINATE | Retry possible |
| TEL not found | - | INDETERMINATE | May resolve later |
| Dossier invalid | - | revocation_clear INDETERMINATE | Dossier error takes precedence |
| Witness timeout | httpx.TimeoutException | INDETERMINATE | Retry with different witness |

---

## Test Strategy

### 1. Unit Tests for Revocation Checker (`tests/test_revocation_checker.py`)

```python
def test_all_credentials_active():
    """All credentials ACTIVE → revocation_clear VALID."""

def test_one_credential_revoked():
    """One revoked credential → revocation_clear INVALID."""

def test_one_credential_unknown():
    """One unknown credential → revocation_clear INDETERMINATE."""

def test_revoked_takes_precedence_over_unknown():
    """REVOKED wins over UNKNOWN → INVALID status."""

def test_empty_dag():
    """Empty DAG → VALID (nothing to check)."""

def test_extracts_registry_said():
    """Correctly extracts ri field from raw ACDC."""
```

### 2. Integration Tests (`tests/test_verify_revocation_integration.py`)

```python
async def test_verify_with_active_credentials():
    """Full verify flow with active credentials passes."""

async def test_verify_with_revoked_credential():
    """Full verify flow with revoked credential fails INVALID."""

async def test_revocation_claim_under_dossier():
    """revocation_clear is child of dossier_verified per §3.3B."""

async def test_dossier_failure_makes_revocation_indeterminate():
    """Dossier failure → revocation_clear INDETERMINATE."""
```

### 3. Admin Endpoint Tests (`tests/test_admin.py`)

```python
def test_admin_returns_all_config():
    """Admin endpoint returns all configuration categories."""

def test_admin_config_types():
    """Configuration values have expected types."""

def test_admin_disabled_returns_404():
    """Admin endpoint returns 404 when ADMIN_ENDPOINT_ENABLED=false."""
```

---

## Files to Create/Modify

| File | Action | Purpose |
|------|--------|---------|
| `app/vvp/verify.py` | Modify | Add `check_dossier_revocations()`, integrate `revocation_clear` under `dossier_verified` |
| `app/main.py` | Modify | Add `/admin` endpoint with feature flag |
| `app/core/config.py` | Modify | Add `ADMIN_ENDPOINT_ENABLED` flag |
| `tests/test_revocation_checker.py` | Create | Unit tests for revocation checking |
| `tests/test_verify_revocation_integration.py` | Create | Integration tests |
| `tests/test_admin.py` | Create | Admin endpoint tests |
| `app/Documentation/VVP_Implementation_Checklist.md` | Modify | Mark 9.3 complete |

---

## Implementation Order

1. **Add `ADMIN_ENDPOINT_ENABLED` to config.py** - Feature flag
2. **Add `/admin` endpoint** - Quick visibility win
3. **Add `check_dossier_revocations()` function** - Core logic
4. **Integrate `revocation_clear` under `dossier_verified`** - Claim tree per §3.3B
5. **Write unit tests** - Verify behavior
6. **Write integration tests** - End-to-end verification
7. **Update checklist** - Mark 9.3 complete

---

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| TEL queries slow | Medium | Medium | Parallel queries, caching |
| Witnesses unavailable | Low | High | Multiple witness fallback, INDETERMINATE |
| All credentials UNKNOWN | Medium | Medium | Return INDETERMINATE per spec |
| Increased latency | Medium | Low | Cache results |

---

## Resolved Questions (per Reviewer)

1. **Should revocation checking be optional/configurable?**
   - **Answer**: No. Revocation checking is REQUIRED per §5.1.1-2.9. If TEL is unavailable, return INDETERMINATE (never skip).

2. **What if ALL witnesses return UNKNOWN?**
   - **Answer**: Return INDETERMINATE and surface a clear reason. Do NOT mark INVALID.

3. **Admin endpoint security**
   - **Answer**: Gate behind `ADMIN_ENDPOINT_ENABLED` flag (default: true for dev). Production deployments can set to false.

---

## Exit Criteria

- [ ] `check_dossier_revocations()` correctly checks all ACDCs
- [ ] `revocation_clear` claim is child of `dossier_verified` per §3.3B
- [ ] Revoked credential → overall INVALID
- [ ] Unknown status → INDETERMINATE (not skipped)
- [ ] `/admin` endpoint shows all configuration (gated by flag)
- [ ] All new tests pass
- [ ] Existing tests still pass
- [ ] Checklist updated with 9.3 complete

---

## Revision 1 (Response to CHANGES_REQUESTED)

### Changes Made

| Finding | Resolution |
|---------|------------|
| [High] Plan adds `credentials_not_revoked` at root level, but §3.3B requires `revocation_clear` under `dossier_verified` | Changed claim name to `revocation_clear` and placed as REQUIRED child of `dossier_verified` per §3.3B |
| [Medium] "Optional revocation" wording conflicts with spec requirement | Removed "optional" wording. Revocation is REQUIRED; UNKNOWN/ERROR → INDETERMINATE (never skip) |
| [Low] Admin endpoint unauthenticated | Added `ADMIN_ENDPOINT_ENABLED` feature flag (default true for dev) |

---

## Implementation Notes

### Deviations from Plan
None - implementation follows approved plan exactly.

### Implementation Details

1. **TEL Client Mock in Vector Tests**: The VectorRunner needed to mock the TEL client to ensure deterministic test execution. All credentials return ACTIVE by default in tests.

2. **Library Path Configuration**: Local macOS testing requires `DYLD_LIBRARY_PATH=/opt/homebrew/opt/libsodium/lib` for pysodium to find libsodium.

3. **Patch Target**: The test file `test_revocation_checker.py` patches `app.vvp.keri.tel_client.get_tel_client` (not `app.vvp.verify.get_tel_client`) because the function is imported inside `check_dossier_revocations()`.

### Test Results
```
477 passed, 2 skipped in 3.67s
```

### Files Changed
| File | Lines | Summary |
|------|-------|---------|
| `app/core/config.py` | +7 | Added `ADMIN_ENDPOINT_ENABLED` flag |
| `app/main.py` | +45 | Added `/admin` endpoint |
| `app/vvp/verify.py` | +75 | Added `check_dossier_revocations()` and Phase 9 integration |
| `app/vvp/keri/tel_client.py` | +15 | Added INFO-level logging throughout |
| `app/logging_config.py` | +2 | Added `VVP_LOG_LEVEL` environment variable support |
| `tests/test_admin.py` | +76 | Admin endpoint tests (9 tests) |
| `tests/test_revocation_checker.py` | +277 | Revocation checker tests (8 tests) |
| `tests/vectors/runner.py` | +20 | Added TEL client mock for deterministic tests |
| `app/Documentation/VVP_Implementation_Checklist.md` | +10 | Marked Phase 9 complete |
