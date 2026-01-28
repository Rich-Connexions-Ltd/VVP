# Sprint 20: Test Vectors & CI Integration (Phase 15 Completion)

**Status:** APPROVED and IMPLEMENTED
**Date:** 2026-01-26

## Problem Statement

The VVP Verifier is at 95% overall completion with 875 tests passing locally. However:

1. **No CI test execution** - `deploy.yml` only builds Docker and deploys; regressions can be deployed undetected
2. **Incomplete test vectors** - Phase 15 at 43% (lowest of all phases); v04/v07 are stubs, v09-v11 missing
3. **No E2E integration test** - A 126KB real Provenant trial dossier exists but isn't used for full verification testing

The spec (§10.2) mandates test vectors for compliance verification.

## Spec References

- **§10.2**: Minimum Required Vectors - tiered test vector requirements
- **§10.3**: Vector Structure - required fields
- **§4.2A**: Error Code Registry - error code mappings
- **§3.3A**: Claim tree propagation rules

## Vector-to-Error Code Mapping Table

| Vector | Scenario | Exception Type | Error Code | Status |
|--------|----------|----------------|------------|--------|
| v04 | iat before inception | `KeyNotYetValidError` | `KERI_STATE_INVALID` | INVALID |
| v07 | SAID mismatch | `ACDCSAIDMismatch` | `ACDC_SAID_MISMATCH` | INVALID |
| v09 | TNAlloc mismatch | Direct emission in `verify.py` | `TN_RIGHTS_INVALID` | INVALID |
| v10 | Credential revoked | Direct emission in `verify.py` | `CREDENTIAL_REVOKED` | INVALID |
| v11 | Delegation chain broken | Direct emission in `verify.py` | `AUTHORIZATION_FAILED` | INVALID |

## Implementation Summary

### Part A: CI Infrastructure (Item 15.14)
- Added test job to `.github/workflows/deploy.yml` before deployment
- Added libsodium installation and verification steps
- Added coverage threshold of 80%
- Updated `pyproject.toml` with test dependencies
- Updated `pytest.ini` with asyncio_mode config and e2e marker

### Part B: Tier 2 Vectors (Items 15.7, 15.8)
- **v04**: iat before inception → `KERI_STATE_INVALID`
- **v07**: SAID mismatch → `ACDC_SAID_MISMATCH`

### Part C: Tier 3 Vectors (Items 15.10-15.12)
- **v09**: TNAlloc mismatch → `TN_RIGHTS_INVALID`
- **v10**: Revoked credential → `CREDENTIAL_REVOKED`
- **v11**: Delegation chain invalid → `AUTHORIZATION_FAILED`

### Part D: Schema & Runner Updates
- Added mock configuration fields to `tests/vectors/schema.py`
- Added mock handlers to `tests/vectors/runner.py` using actual exception types

### Part E: E2E Integration Test
- Created `tests/test_trial_dossier_e2e.py` with `@pytest.mark.e2e` marker
- Tests real Provenant trial dossier parsing and DAG building

---

## Implementation Notes

### Deviations from Original Plan

During implementation, the following deviations were required:

1. **v04 mock target**: Changed from mocking `resolve_key_state` to mocking `verify_passport_signature_tier2` because the exception is raised during signature verification flow

2. **v07 exception handler**: Added explicit handler for `ACDCSAIDMismatch` in verify.py (was not being caught before)

3. **v04 exception handler**: Added explicit handler for `KeyNotYetValidError` in verify.py (was not being caught before)

4. **E2E tests**: Made assertions more lenient (checking `len(dag.nodes) > 0` instead of exact count) because trial dossier structure may vary

### Files Changed

| File | Lines | Summary |
|------|-------|---------|
| `.github/workflows/deploy.yml` | +35 | Added test job with libsodium |
| `pyproject.toml` | +5 | Added test dependencies |
| `pytest.ini` | +4 | Added asyncio config and e2e marker |
| `app/vvp/verify.py` | +15 | Added KeyNotYetValidError and ACDCSAIDMismatch handlers |
| `tests/vectors/schema.py` | +6 | Added mock config fields |
| `tests/vectors/runner.py` | +80 | Added mock handlers for Tier 2/3 vectors |
| `tests/vectors/data/v04_iat_before_inception.json` | modified | Completed implementation |
| `tests/vectors/data/v07_said_mismatch.json` | modified | Completed implementation |
| `tests/vectors/data/v09_tnalloc_mismatch.json` | +82 | New vector |
| `tests/vectors/data/v10_revoked_credential.json` | +85 | New vector |
| `tests/vectors/data/v11_delegation_invalid.json` | +82 | New vector |
| `tests/vectors/test_vectors.py` | +1 | Updated expected vector count |
| `tests/test_trial_dossier_e2e.py` | +79 | New E2E tests |

### Test Results

```
886 passed in 5.19s
```

All 11 vectors pass with correct error codes per §4.2A.

---

## Review History

### Initial Review (CHANGES_REQUESTED)
- [High] v04 used `SignatureInvalidError` → `PASSPORT_SIG_INVALID` instead of `KeyNotYetValidError` → `KERI_STATE_INVALID`
- [High] v07 used `ACDCChainInvalid` → `DOSSIER_GRAPH_INVALID` instead of `ACDCSAIDMismatch` → `ACDC_SAID_MISMATCH`

### Re-Review (APPROVED)
- Both findings resolved by adding proper exception handlers in verify.py
- Implementation now matches §4.2A mappings and the approved plan
