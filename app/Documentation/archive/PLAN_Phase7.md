# Phase 7: KERI Key State Resolution (Tier 2)

## Problem Statement

The current Tier 1 implementation extracts Ed25519 public keys directly from KERI AIDs and verifies PASSporT signatures against them. This approach has a critical limitation: it assumes the key embedded in the AID is currently valid and ignores key rotation or revocation events that may have occurred.

VVP verification requires determining key state at a specific reference time T (the `iat` timestamp). Without this capability:

1. A rotated key could still verify signatures created after the rotation
2. A revoked key could still pass verification
3. Historical verification (per §5D) is impossible
4. The verifier cannot distinguish between "key was valid at time T" and "key is valid now"

## Spec References

From `VVP_Verifier_Specification_v1.5.md`:

- **§5A Step 4** (Key State Retrieval): "Resolve issuer key state at reference time T (§5.1.1-2.4)"
- **§5C.2** (Caching): "Key state cache: AID + timestamp → Minutes (rotation-sensitive)"
- **§5D** (Historical Verification): "VVP passports can verify at arbitrary past moments using historical data"

From VVP draft §5.1.1-2.4:
- "The verifier MUST resolve the key state of the AID at reference time T"
- "Key state resolution involves fetching the Key Event Log (KEL) from witnesses"
- "The verifier MUST validate witness receipts to achieve confidence in key state"

## Solution Implemented

Implemented a **lightweight KEL resolver** that fetches, parses, and **cryptographically validates** Key Event Logs without requiring the full keripy installation.

### Components

| Component | File | Purpose |
|-----------|------|---------|
| OOBI Dereferencer | `app/vvp/keri/oobi.py` | Fetch KEL data from OOBI URLs |
| KEL Parser | `app/vvp/keri/kel_parser.py` | Parse and validate KERI events |
| Key State Resolver | `app/vvp/keri/kel_resolver.py` | Determine key state at time T |
| Key State Cache | `app/vvp/keri/cache.py` | LRU cache with TTL for resolved states |
| Tier 2 Signature | `app/vvp/keri/signature.py` | Verify using historical key state |

### Feature Gating

**IMPORTANT**: Tier 2 is gated behind `TIER2_KEL_RESOLUTION_ENABLED` feature flag (default: `False`).

Current limitations that prevent production use:
- JSON-only: CESR binary format NOT supported
- Signature canonicalization uses JSON sorted-keys, NOT KERI-compliant Blake3
- SAID validation disabled by default

Enable only for testing with synthetic fixtures. Production requires CESR support.

## Files Changed

| File | Lines | Summary |
|------|-------|---------|
| `app/core/config.py` | +20 | Added `TIER2_KEL_RESOLUTION_ENABLED` feature flag |
| `app/vvp/keri/exceptions.py` | +48 | Added KELChainInvalidError, KeyNotYetValidError, DelegationNotSupportedError, OOBIContentInvalidError |
| `app/vvp/keri/cache.py` | +210 | New key state cache with LRU eviction and TTL |
| `app/vvp/keri/kel_parser.py` | +380 | KEL event parser with chain validation |
| `app/vvp/keri/oobi.py` | +180 | OOBI dereferencer for fetching KEL data |
| `app/vvp/keri/kel_resolver.py` | +330 | Key state resolver at reference time T |
| `app/vvp/keri/signature.py` | +50 | Added verify_passport_signature_tier2 |
| `app/vvp/keri/__init__.py` | +30 | Updated exports for Tier 2 |
| `tests/test_kel_parser.py` | +190 | KEL parser unit tests |
| `tests/test_kel_chain.py` | +280 | Chain validation tests |
| `tests/test_kel_cache.py` | +280 | Cache behavior tests |
| `tests/test_kel_resolver.py` | +290 | Resolver tests |
| `tests/test_kel_integration.py` | +280 | End-to-end integration tests |

## Test Results

```
97 passed (Phase 7 tests)
368 passed, 2 skipped (full test suite)
```

## Review History

- **Revision 0**: CHANGES_REQUESTED - Missing chain validation, incorrect rotation handling, cache rounding
- **Revision 1**: CHANGES_REQUESTED - CESR not supported, signature canonicalization test-only
- **Revision 2**: APPROVED - Feature flag gating makes limitations explicit

## Reviewer Recommendations (for future phases)

1. Add note about when to flip `TIER2_KEL_RESOLUTION_ENABLED` once CESR support lands
2. Document intended production default for SAID validation once CESR/canonicalization implemented
