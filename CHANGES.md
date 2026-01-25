# VVP Verifier Change Log

## Phase 10: Tier 2 Completion - ACDC & Crypto Finalization

**Date:** 2026-01-25
**Commit:** `a8d0833`

### Files Changed

| File | Action | Description |
|------|--------|-------------|
| `app/core/config.py` | Modified | Added `TRUSTED_ROOT_AIDS` with multi-root support via env var |
| `app/vvp/keri/cesr.py` | Modified | Added `decode_pss_signature()` for CESR PSS signatures |
| `app/vvp/keri/kel_parser.py` | Modified | Enhanced `validate_witness_receipts()` |
| `app/vvp/keri/kel_resolver.py` | Modified | Added `_fetch_and_validate_oobi()` for §4.2 OOBI KEL validation |
| `app/vvp/keri/oobi.py` | Modified | Added `validate_oobi_is_kel()` |
| `app/vvp/keri/signature.py` | Modified | Moved pysodium to lazy import inside functions |
| `app/vvp/passport.py` | Modified | Integrated CESR PSS signature auto-detection in `_decode_signature()` |
| `app/vvp/acdc/__init__.py` | Created | Package exports for ACDC verification |
| `app/vvp/acdc/exceptions.py` | Created | ACDCError hierarchy (Parse, SAID, Signature, Chain) |
| `app/vvp/acdc/models.py` | Created | ACDC and ACDCChainResult dataclasses |
| `app/vvp/acdc/parser.py` | Created | ACDC parsing and SAID validation with Blake3 |
| `app/vvp/acdc/verifier.py` | Created | Chain validation, schema validation, credential type validation |
| `tests/test_cesr_pss.py` | Created | 8 tests for PSS signature decoding |
| `tests/test_witness_receipts.py` | Created | 8 tests for witness validation |
| `tests/test_acdc.py` | Created | 38 tests for ACDC verification |
| `tests/test_trusted_roots.py` | Created | 7 tests for root configuration |
| `tests/test_passport.py` | Modified | 6 new tests for CESR signature integration |
| `app/Documentation/PLAN_Phase10.md` | Created | Archived implementation plan |

### Summary

Completed Tier 2 verification components: ACDC chain validation, CESR PSS signature decoding, OOBI KEL validation, and trusted root configuration.

**Key Changes:**

1. **Root of Trust Configuration (§5.1-7):**
   - `TRUSTED_ROOT_AIDS` frozenset from `VVP_TRUSTED_ROOT_AIDS` env var
   - Default: GLEIF External AID for production vLEI ecosystem
   - Supports multiple comma-separated roots

2. **PSS CESR Signature Decoding (§6.3.1):**
   - `decode_pss_signature()` handles 0A/0B/0C/0D/AA prefixed CESR signatures
   - Auto-detection in `_decode_signature()` with fallback to base64url

3. **OOBI KEL Validation (§4.2):**
   - `_fetch_and_validate_oobi()` validates KEL structure during resolution
   - Checks: KEL data present, inception event first, chain integrity

4. **ACDC Chain Validation (§6.3.x):**
   - `validate_credential_chain()` walks edges to trusted root
   - Credential type-specific validation: APE, DE, TNAlloc
   - `pss_signer_aid` parameter for DE signer binding per §6.3.4
   - Schema SAID validation against known vLEI governance schemas

5. **Lazy pysodium Import:**
   - Moved import inside functions to avoid load-time errors

**Spec Compliance:**
- §4.2: OOBI must resolve to valid KEL
- §5.1-7: Root of trust configuration
- §6.3.1: PSS CESR signature format
- §6.3.3: APE credential validation (vetting edge required)
- §6.3.4: DE credential validation (PSS signer must match delegate)
- §6.3.6: TNAlloc credential validation (TN subset of parent)

---

## Phase 9.4: TEL Resolution Architecture Fix

**Date:** 2026-01-25
**Commit:** `4de5855`

### Files Changed

| File | Action | Description |
|------|--------|-------------|
| `app/vvp/verify.py` | Modified | Added `_query_registry_tel()` helper, inline TEL parsing with latin-1 decoding, registry OOBI discovery |
| `app/vvp/keri/tel_client.py` | Modified | Added detailed logging to `parse_dossier_tel()` |
| `tests/test_revocation_checker.py` | Modified | Added 7 new tests for inline TEL, registry OOBI, binary-safe parsing |
| `app/main.py` | Modified | Added `POST /admin/log-level` endpoint for runtime log level changes |
| `tests/test_admin.py` | Modified | Added 6 tests for log level endpoint |
| `app/Documentation/PLAN_Phase9.4.md` | Created | Archived implementation plan |

### Summary

Fixed TEL resolution architecture so revocation checking works correctly instead of always returning INDETERMINATE.

**Problem:** The previous implementation queried the wrong endpoints (PASSporT signer's KERIA agent instead of registry witnesses), causing all TEL queries to return 404.

**Solution:**
1. **Inline TEL Parsing**: Check if TEL events are embedded in the raw dossier using binary-safe latin-1 decoding
2. **Registry OOBI Discovery**: Derive registry OOBI URL from base OOBI pattern (`{scheme}://{netloc}/oobi/{registry_said}`)
3. **Fallback Chain**: Inline TEL → Registry OOBI witnesses → Default witnesses

**Key Changes:**
- `check_dossier_revocations()` now accepts `raw_dossier` parameter for inline TEL parsing
- Latin-1 decoding preserves all byte values (byte-transparent) for CESR streams
- Evidence format standardized: `revocation_source:{dossier|witness}` with summary counts
- Runtime log level endpoint: `POST /admin/log-level` with `{"level": "DEBUG"}` body
- 440 tests passing (20 revocation tests)

**Spec Compliance:**
- §5.1.1-2.9: Revocation status checking via correct TEL sources
- §6.1B: Inline TEL events in CESR dossier format supported

---

## Phase 9.3: Revocation Integration & Admin Endpoint

**Date:** 2026-01-25
**Commit:** `c08c0bb`

### Files Changed

| File | Action | Description |
|------|--------|-------------|
| `app/vvp/verify.py` | Modified | Added `check_dossier_revocations()`, integrated `revocation_clear` under `dossier_verified` per §3.3B |
| `app/vvp/api_models.py` | Modified | Added `CREDENTIAL_REVOKED` error code |
| `app/main.py` | Modified | Added `/admin` endpoint for configuration visibility |
| `app/core/config.py` | Modified | Added `ADMIN_ENDPOINT_ENABLED` flag |
| `app/vvp/keri/tel_client.py` | Modified | Added INFO-level logging throughout |
| `app/logging_config.py` | Modified | Added `VVP_LOG_LEVEL` env var support |
| `tests/test_revocation_checker.py` | Created | Revocation checking tests (11 tests) |
| `tests/test_admin.py` | Created | Admin endpoint tests (9 tests) |
| `tests/test_models.py` | Modified | Updated error code count for CREDENTIAL_REVOKED |
| `tests/vectors/runner.py` | Modified | Added TEL client mock for deterministic tests |
| `app/Documentation/VVP_Implementation_Checklist.md` | Modified | Updated to v3.3, Phase 9 100% complete |

### Summary

Integrated revocation checking into the main verification flow per spec §5.1.1-2.9.

**Key Changes:**
- `revocation_clear` claim is now a REQUIRED child of `dossier_verified` per §3.3B
- `dossier_verified` status propagates from `revocation_clear` per §3.3A
- `CREDENTIAL_REVOKED` errors emitted for each revoked credential
- `/admin` endpoint exposes all configuration values (gated by `ADMIN_ENDPOINT_ENABLED`)
- INFO-level logging added to TEL client for debugging
- 480 tests passing (11 new revocation tests, 9 new admin tests)

**Spec Compliance:**
- §5.1.1-2.9: Revocation status checking for all ACDCs in dossier
- §3.3B: `revocation_clear` placed under `dossier_verified`
- §3.3A: Status propagation (INVALID > INDETERMINATE > VALID)

---

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
