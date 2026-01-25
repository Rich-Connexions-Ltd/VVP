# VVP Verifier Change Log

## CESR Parsing & Provenant Witness Integration

**Date:** 2026-01-25
**Commit:** `565c8bf`

### Files Changed

| File | Action | Description |
|------|--------|-------------|
| `app/vvp/keri/cesr.py` | Created | CESR stream parser for `application/json+cesr` |
| `app/vvp/keri/keri_canonical.py` | Created | KERI canonical field ordering per spec |
| `app/vvp/keri/tel_client.py` | Created | TEL client with Provenant staging witnesses |
| `app/vvp/keri/kel_parser.py` | Modified | Enhanced with CESR attachment parsing |
| `app/vvp/keri/kel_resolver.py` | Modified | Pass content-type to parser |
| `app/vvp/keri/oobi.py` | Modified | Improved OOBI URL handling |
| `ROADMAP.md` | Created | Strategic roadmap with tier architecture |
| `app/Documentation/VVP_Implementation_Checklist.md` | Modified | Updated to v3.2 (60% complete) |
| `scripts/test_witness_resolution.py` | Created | Standalone witness test script |
| `tests/test_cesr_parser.py` | Created | CESR parser unit tests |
| `tests/test_canonicalization.py` | Created | Canonical ordering tests |
| `tests/fixtures/keri/*.json` | Created | Test fixtures from keripy |

### Summary

Integrated with Provenant staging witnesses for live KERI ecosystem testing.

**Key Changes:**
- CESR stream parsing for witness OOBI responses
- KERI-compliant field ordering for serialization
- TEL client infrastructure for revocation checking
- Provenant witness endpoints: witness4/5/6.stage.provenant.net:5631
- Verified live resolution with test AID `EGay5ufBqAanbhFa_qe-KMFUPJHn8J0MFba96yyWRrLF`

**Documentation:**
- Created ROADMAP.md with tier architecture overview
- Updated checklist to reflect implementation progress (60%)
- Archived old spec versions (v1.1, v1.2, v1.3)

### Normative Note: `kid` Field Semantics

Per VVP draft and KERI specifications:

> **`kid` is an OOBI reference to a KERI autonomous identifier whose historical key state, witness receipts, and delegations MUST be resolved and validated to determine which signing key was authorised at the PASSporT reference time.**

This means `kid` is NOT a generic JWT key ID - resolution requires OOBI dereferencing and KEL validation at reference time T.

---

## Phase 7: KERI Key State Resolution (Tier 2)

**Date:** 2026-01-24
**Commit:** `850df11`

### Files Changed

| File | Action | Description |
|------|--------|-------------|
| `app/core/config.py` | Modified | Added `TIER2_KEL_RESOLUTION_ENABLED` feature flag |
| `app/vvp/keri/exceptions.py` | Modified | Added KELChainInvalidError, KeyNotYetValidError, DelegationNotSupportedError, OOBIContentInvalidError |
| `app/vvp/keri/cache.py` | Created | Key state cache with LRU eviction and TTL |
| `app/vvp/keri/kel_parser.py` | Created | KEL event parser with chain validation |
| `app/vvp/keri/oobi.py` | Created | OOBI dereferencer for fetching KEL data |
| `app/vvp/keri/kel_resolver.py` | Created | Key state resolver at reference time T |
| `app/vvp/keri/signature.py` | Modified | Added verify_passport_signature_tier2 |
| `app/vvp/keri/__init__.py` | Modified | Updated exports for Tier 2 |
| `tests/test_kel_parser.py` | Created | KEL parser unit tests |
| `tests/test_kel_chain.py` | Created | Chain validation tests |
| `tests/test_kel_cache.py` | Created | Cache behavior tests |
| `tests/test_kel_resolver.py` | Created | Resolver tests |
| `tests/test_kel_integration.py` | Created | End-to-end integration tests |
| `app/Documentation/PLAN_Phase7.md` | Created | Archived phase plan |

### Summary

Implemented Tier 2 KERI key state resolution for historical key verification per VVP §5A Step 4 and §5D.

**Components:**
- OOBI dereferencer for fetching KEL data from witness endpoints
- KEL event parser with chain continuity and signature validation
- Key state resolver that determines signing keys valid at reference time T
- LRU cache keyed by (AID, establishment_digest) with time-based secondary index

**Feature Gating:**
- `TIER2_KEL_RESOLUTION_ENABLED = False` by default
- Tier 2 is TEST-ONLY due to limitations:
  - JSON-only (CESR binary format not supported)
  - Signature canonicalization uses JSON sorted-keys (not KERI-compliant Blake3)
  - SAID validation disabled by default
- Tests use `_allow_test_mode=True` to bypass feature gate

### Spec Sections Implemented

- §5A Step 4: Resolve issuer key state at reference time T
- §5C.2: Key state cache (AID + timestamp → rotation-sensitive)
- §5D: Historical verification capabilities

### Test Results

```
97 passed (Phase 7 tests)
368 passed, 2 skipped (full test suite)
```

---

## Phase 9: VVP Verifier Specification v1.5

**Date:** 2026-01-24
**Commit:** `953e694`

### Files Changed

| File | Action | Description |
|------|--------|-------------|
| `app/Documentation/VVP_Verifier_Specification_v1.5.md` | Created | Complete verification algorithm specification |
| `app/Documentation/PLAN_Phase9.md` | Created | Archived plan for Phase 9 |

### Summary

Extended VVP_Verifier_Specification_v1.4_FINAL with complete verification algorithms per authoritative VVP draft §5.

**New Sections:**
- §3.3B: Complete claim tree structure for caller and callee verification
- §4.2A: 8 new error codes (CREDENTIAL_REVOKED, CONTEXT_MISMATCH, AUTHORIZATION_FAILED, TN_RIGHTS_INVALID, BRAND_CREDENTIAL_INVALID, GOAL_REJECTED, DIALOG_MISMATCH, ISSUER_MISMATCH)
- §4.4: SIP Context Fields normative section
- §5A: 13-step Caller Verification Algorithm per VVP §5.1
- §5B: 14-step Callee Verification Algorithm per VVP §5.2
- §5C: Efficiency and Caching guidance per VVP §5.3
- §5D: Historical Verification capabilities per VVP §5.4
- §9: Full pseudocode for caller and callee verification with explicit claim node initialization
- §10.2: Test vectors tiered by implementation phase (Tier 1/2/3)
- §12: Implementation Tiers (Tier 1/2/3)
- Appendix A: Spec §5 Traceability Matrix

**Key Design Decisions:**
- SIP context absence produces INDETERMINATE, not rejection (policy-driven)
- Replay tolerance (30s) distinguished from iat binding tolerance (5s)
- `issuer_matched` placed under `dossier_verified` in callee claim tree
- Step-to-claim mapping tables added to prevent drift

### Spec Sections Implemented

- VVP §5.1.1-2.1 through §5.1.1-2.13: Caller verification algorithm
- VVP §5.2-2.1 through §5.2-2.14: Callee verification algorithm
- VVP §5.3: Efficiency and caching
- VVP §5.4: Historical verification

---

## Phase 3: PASSporT JWT Verification

**Date:** 2026-01-23
**Commit:** `38197e6`

### Files Changed

| File | Action | Description |
|------|--------|-------------|
| `app/vvp/exceptions.py` | Modified | Added PassportError exception class |
| `app/vvp/passport.py` | Created | PASSporT JWT parser and validator per §5.0-§5.4 |
| `tests/test_passport.py` | Created | 68 unit tests for PASSporT parsing |

### Summary

- Created `PassportError` exception class with factory methods:
  - `missing()` → `PASSPORT_MISSING`
  - `parse_failed(reason)` → `PASSPORT_PARSE_FAILED` (binding violations, structure errors)
  - `forbidden_alg(alg)` → `PASSPORT_FORBIDDEN_ALG`
  - `expired(reason)` → `PASSPORT_EXPIRED` (actual expiry policy failures only)
- Created frozen dataclasses: `PassportHeader`, `PassportPayload`, `Passport`
- Implemented `parse_passport(jwt)` function:
  - JWT structure parsing (header.payload.signature)
  - Algorithm enforcement: accept EdDSA only, reject none/ES256/HMAC/RSA (§5.0, §5.1)
  - Header validation: require `alg`, `ppt`, `kid`; ignore `typ` (§5.2)
  - Payload validation: require `iat`, `orig`, `dest`, `evd` (local policy)
  - Support optional fields: `iss`, `exp`, `card`, `goal`, `call-reason`→`call_reason`, `origid`
  - Validate `ppt` = "vvp" per §5.2
- Implemented `validate_passport_binding(passport, vvp_identity, now)` function:
  - `ppt` binding: PASSporT ppt must match VVP-Identity ppt (§5.2)
  - `kid` binding: strict equality in Phase 3 (§5.2)
  - `iat` drift: ≤5 seconds between PASSporT and VVP-Identity (§5.2A)
  - `exp > iat` validation (§5.2A)
  - `exp` drift: ≤5 seconds when both present (§5.2A)
  - Expiry policy: max validity 300s, clock skew ±300s (§5.2B)
- Preserved raw header/payload and signature bytes for Phase 4 signature verification

### Error Code Usage

| Error Code | Used For |
|------------|----------|
| `PASSPORT_MISSING` | JWT is None or empty |
| `PASSPORT_PARSE_FAILED` | Malformed JWT, invalid base64/JSON, missing fields, binding violations (ppt/kid mismatch, iat drift, exp mismatch) |
| `PASSPORT_FORBIDDEN_ALG` | Algorithm not in allowed list (only EdDSA accepted) |
| `PASSPORT_EXPIRED` | Token expired, validity window exceeded, max-age exceeded |

### Spec Sections Implemented

- §5.0 PASSporT Non-compliance Note
- §5.1 Allowed Algorithms (EdDSA only)
- §5.2 Header Binding Rules (ppt, kid)
- §5.2A Temporal Binding Rules (iat drift ≤5s, exp consistency)
- §5.2B PASSporT Expiry Policy (max validity 300s, clock skew ±300s)
- §5.4 Failure Mapping

### Checklist Tasks Completed

- [x] 3.1 - Create `app/vvp/passport.py` module
- [x] 3.2 - Parse JWT structure (header.payload.signature)
- [x] 3.3 - Reject `alg=none`
- [x] 3.4 - Reject ES256, HMAC, RSA algorithms
- [x] 3.5 - Accept only EdDSA (Ed25519)
- [x] 3.6 - Return PASSPORT_FORBIDDEN_ALG for algorithm violations
- [x] 3.7 - Extract header claims: `alg`, `typ` (ignored), `ppt`, `kid`
- [x] 3.8 - Extract VVP payload claims: `iat` (required), `orig`, `dest`, `evd` (local policy)
- [x] 3.9 - Extract optional VVP claims: `iss`, `card`, `goal`, `call-reason`, `origid`, `exp`
- [x] 3.10 - Validate `ppt` = "vvp" and matches VVP-Identity ppt (§5.2)
- [x] 3.11 - Validate `kid` binding (strict equality in Phase 3) (§5.2)
- [x] 3.12 - Defer signature verification (placeholder for Phase 4)
- [x] 3.13 - Unit tests for PASSporT parsing

### Test Results

```
139 passed in 0.22s (68 new + 71 from Phase 1+2)
```

---

## Phase 2: VVP-Identity Header Parser

**Date:** 2026-01-23
**Commit:** `70fd80f`

### Files Changed

| File | Action | Description |
|------|--------|-------------|
| `app/vvp/exceptions.py` | Created | Typed exceptions with error codes |
| `app/vvp/header.py` | Created | VVP-Identity header parser per §4.1A/B |
| `tests/test_header.py` | Created | 38 unit tests for header parsing |

### Summary

- Created `VVPIdentityError` exception class with factory methods for `VVP_IDENTITY_MISSING` and `VVP_IDENTITY_INVALID`
- Created `VVPIdentity` frozen dataclass with fields: `ppt`, `kid`, `evd`, `iat`, `exp`
- Implemented `parse_vvp_identity()` function:
  - Base64url decoding with padding fix
  - JSON parsing with UTF-8 validation
  - Required field validation: `ppt`, `kid`, `evd`, `iat`
  - Type validation: strings must be non-empty, integers must be actual integers (not booleans)
  - Clock skew validation for `iat` (±300s configurable)
  - Optional `exp` handling (defaults to `iat + MAX_TOKEN_AGE_SECONDS`)
- Treats `kid`/`evd` as opaque OOBI references (no URL validation)
- Does NOT validate `ppt` value (deferred to Phase 3/5 per §5.2)
- Distinguishes `VVP_IDENTITY_MISSING` (absent header) from `VVP_IDENTITY_INVALID` (parse/validation errors)

### Spec Sections Implemented

- §4.1A VVP-Identity Header (Decoded)
- §4.1B OOBI Semantics for kid/evd
- §4.2A Error Codes: VVP_IDENTITY_MISSING, VVP_IDENTITY_INVALID

### Checklist Tasks Completed

- [x] 2.1 - Create `app/vvp/header.py` module
- [x] 2.2 - Implement base64url decoding of VVP-Identity header
- [x] 2.3 - Parse JSON with fields: `ppt`, `kid`, `evd`, `iat`, `exp`
- [x] 2.4 - Validate `ppt` field exists (value validation deferred to Phase 3)
- [x] 2.5 - Validate `kid` and `evd` are present as opaque strings
- [x] 2.6 - Implement clock skew validation (±300s) on `iat`
- [x] 2.7 - Handle optional `exp`; if absent, use `iat` + 300s max age
- [x] 2.8 - Reject future `iat` beyond clock skew
- [x] 2.9 - Return structured errors: `VVP_IDENTITY_MISSING` vs `VVP_IDENTITY_INVALID`
- [x] 2.10 - Unit tests for header parsing

### Test Results

```
71 passed in 0.26s (38 new + 33 from Phase 1)
```

---

## Phase 1: Core Infrastructure

**Date:** 2026-01-23
**Commit:** `9546f37`

### Files Changed

| File | Action | Description |
|------|--------|-------------|
| `.gitignore` | Created | Python/IDE/OS ignores |
| `app/core/__init__.py` | Created | Empty package init |
| `app/core/config.py` | Created | Configuration constants per §4.1A, §5.2A/B |
| `app/vvp/api_models.py` | Replaced | Models per §3.2, §4.1-4.3, §4.2A |
| `app/vvp/verify.py` | Updated | Use new models (placeholder returns INDETERMINATE) |
| `tests/__init__.py` | Created | Test package init |
| `tests/test_models.py` | Created | 33 unit tests for Phase 1 models |
| `CLAUDE.md` | Created | Project instructions for Claude Code |
| `CHANGES.md` | Created | This change log |

### Summary

- Defined `ClaimStatus` enum (VALID, INVALID, INDETERMINATE) per §3.2
- Defined `ClaimNode` with `{required, node}` children structure per §4.3B
- Defined `ChildLink` model for explicit required/optional child relationships
- Defined `CallContext` model per §4.1
- Defined `VerifyRequest` model with required `passport_jwt` and `context` per §4.1
- Defined `VerifyResponse` model with `overall_status`, `claims`, `errors` per §4.2/§4.3
- Defined `ErrorDetail` model per §4.2
- Created 18 error codes per §4.2A with `ERROR_RECOVERABILITY` mapping
- Implemented `derive_overall_status()` function per §4.3A precedence rules
- Created configuration constants: clock skew (±300s), max token age (300s), max iat drift (5s), allowed algorithms (EdDSA)
- Updated `verify.py` to use new models (placeholder implementation)
- Created 33 unit tests covering all Phase 1 models

### Spec Sections Implemented

- §3.2 Claim Status
- §4.1 Request Models
- §4.2 Error Envelope
- §4.2A Error Code Registry
- §4.3 Response Models
- §4.3A overall_status Derivation
- §4.3B Claim Node Schema
- §4.1A, §5.2A/B Configuration Constants

### Checklist Tasks Completed

- [x] 1.1 - Create `app/core/config.py`
- [x] 1.2 - Define `ClaimStatus` enum
- [x] 1.3 - Define `ClaimNode` model
- [x] 1.4 - Define `VerifyRequest` model
- [x] 1.5 - Define `VerifyResponse` model
- [x] 1.6 - Define `ErrorDetail` model
- [x] 1.7 - Create error code constants
- [x] 1.8 - Implement `overall_status` derivation

### Test Results

```
33 passed in 0.14s
```
