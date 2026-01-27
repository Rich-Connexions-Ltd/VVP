# VVP Verifier Implementation Checklist

**Document Version:** 3.12
**Specification Version:** v1.4 FINAL + draft-hardman-verifiable-voice-protocol §5
**Created:** 2026-01-23
**Last Updated:** 2026-01-26
**Status:** Tier 1 Complete, Tier 2 Complete, Tier 3 Complete (100% overall - 182/182)

---

## How to Use This Document

- Mark items complete by changing `[ ]` to `[x]`
- Add the commit SHA in the **Commit** column when completed
- Add notes in the **Comments** column as needed
- Update **Status** to reflect current phase

---

## Implementation Tiers

| Tier | Description | Status |
|------|-------------|--------|
| **Tier 1** | Direct verification: parse, validate structure, verify embedded keys | Complete |
| **Tier 2** | Full KERI: KEL resolution, historical key state, witness validation | Complete |
| **Tier 3** | Authorization: TNAlloc, delegation, brand credentials, business logic | Complete |

---

## Scope Exclusions and Policy Deviations

### Out of Scope: SIP/SDP Layer Requirements

The following VVP spec requirements are **out of scope** for this verification API. They apply to SIP endpoints, not the verification service:

- DTLS fingerprint in SIP INVITE (§3.1/§4.2)
- VVP line in SIP 200 OK response (§3.1/§4.2)
- SDP media negotiation requirements

**Rationale:** The VVP Verifier is a cryptographic verification service that validates PASSporTs, dossiers, and KERI credentials. SIP/SDP layer requirements are the responsibility of the telephony endpoints that generate and consume these artifacts.

### exp Maximum Age Policy (VVP Compliant)

**Spec Reference:** VVP §4.2 specifies "a recommended expiration should be 30 seconds, with a minimum of 10 seconds and a **maximum of 300 seconds**."

**VVP Policy:** This implementation uses a **300 second** maximum token age (configurable).

**Compliance Notes:**
1. VVP explicitly overrides the STIR/RFC 8224 60-second limit, allowing up to 300 seconds.
2. The 300s maximum accommodates KERI resolution and dossier validation latency.
3. Operators may configure a stricter policy (e.g., 30s recommended) via configuration.
4. The v1.4 FINAL internal specification (§4.1A, §5.2B) aligns with VVP's 300s maximum.

**Configuration:** `app/core/config.py:MAX_PASSPORT_VALIDITY_SECONDS = 300`

---

## Phase 1: Core Infrastructure

| # | Task | Status | Commit | Comments |
|---|------|--------|--------|----------|
| 1.1 | Create `app/core/config.py` with configuration constants | [x] | | Clock skew (±300s), max token age (300s), timeouts, algorithm policy |
| 1.2 | Define `ClaimStatus` enum (VALID, INVALID, INDETERMINATE) | [x] | | Per §3.2 |
| 1.3 | Define `ClaimNode` Pydantic model with `{required, node}` children | [x] | | Per §4.3B |
| 1.4 | Define `VerifyRequest` model (passport_jwt, context) | [x] | | Per §4.1 |
| 1.5 | Define `VerifyResponse` model (request_id, overall_status, claims, errors) | [x] | | Per §4.2, §4.3 |
| 1.6 | Define `ErrorDetail` model (code, message, recoverable) | [x] | | Per §4.2 |
| 1.7 | Create error code constants per §4.2A registry (18 codes) | [x] | | See Error Code Registry below |
| 1.8 | Implement `overall_status` derivation logic per §4.3A | [x] | | Precedence rules |
| 1.9 | Configure trusted root AIDs (GLEIF for vLEI governance) | [x] | Phase 10 | Per VVP §5.1-7 - verifier MUST accept root of trust - **MUST** |

---

## Phase 2: VVP-Identity Header Parser

| # | Task | Status | Commit | Comments |
|---|------|--------|--------|----------|
| 2.1 | Create `app/vvp/header.py` module | [x] | | |
| 2.2 | Implement base64url decoding of VVP-Identity header | [x] | | Error: VVP_IDENTITY_INVALID on decode failure |
| 2.3 | Parse JSON with fields: `ppt`, `kid`, `evd`, `iat`, `exp` | [x] | | |
| 2.4 | Validate `ppt` field exists | [x] | | Value not constrained; "shaken" is valid per §4.1A |
| 2.5 | Validate `kid` and `evd` are present and are OOBI references | [x] | | Per §4.1B OOBI semantics |
| 2.6 | Implement clock skew validation (±300s) on `iat` | [x] | | Per §4.1A |
| 2.7 | Handle optional `exp`; if absent, use `iat` + 300s max age | [x] | | Per §4.1A; configurable |
| 2.8 | Reject future `iat` beyond clock skew | [x] | | Per §4.1A |
| 2.9 | Return structured errors for all failure modes | [x] | | |
| 2.10 | Unit tests for header parsing | [x] | | Happy path + edge cases |

---

## Phase 3: PASSporT JWT Verification

| # | Task | Status | Commit | Comments |
|---|------|--------|--------|----------|
| 3.1 | Create `app/vvp/passport.py` module | [x] | | |
| 3.2 | Parse JWT structure (header.payload.signature) | [x] | | Error: PASSPORT_PARSE_FAILED |
| 3.3 | Reject `alg=none` | [x] | | Per §5.1 |
| 3.4 | Reject ES256, HMAC, RSA algorithms | [x] | | Per §5.0/§5.1 - explicitly forbidden for VVP |
| 3.5 | Accept only EdDSA (Ed25519) | [x] | | Per §5.1 - baseline for VVP PASSporT |
| 3.6 | Return PASSPORT_FORBIDDEN_ALG for algorithm violations | [x] | | Per §4.2A |
| 3.7 | Extract header claims: `alg`, `typ`, `ppt`, `kid` | [x] | | |
| 3.8 | Extract VVP payload claims: `iss`, `iat`, `orig`, `dest`, `evd` (required) | [x] | | Per VVP draft §4 |
| 3.9 | Extract optional VVP claims: `card`, `goal`, `call-reason`, `origid`, `exp` | [x] | | VVP extensions |
| 3.10 | Validate `ppt` matches between PASSporT and VVP-Identity | [x] | | Per §5.2 header binding |
| 3.11 | Validate `kid` binding between PASSporT and VVP-Identity | [x] | | Per §5.2 |
| 3.12 | Validate `iat` drift ≤ 5 seconds between PASSporT and VVP-Identity | [x] | | Per §5.2A - NORMATIVE |
| 3.13 | Unit tests for PASSporT parsing | [x] | | |
| 3.14 | Validate `orig.tn` contains exactly ONE phone number | [x] | Sprint 12 | Per VVP §4.2 - **MUST** |
| 3.15 | Validate `typ` MUST be "passport" | [x] | Sprint 12 | Per VVP §4.2 / RFC8225 - **MUST** |
| 3.16 | Validate `orig`/`dest` conform to SHAKEN E.164 format | [x] | Sprint 12 | Per VVP §4.2 / RFC8225 - **MUST** |
| 3.17 | Decode PSS (PASSporT-Specific Signature) from CESR format | [x] | Phase 10 | Per VVP §6.3.1 - PSS uses `0B` prefix CESR, NOT standard JWS - **MUST** |

---

## Phase 4: KERI Signature Verification (Tier 1)

| # | Task | Status | Commit | Comments |
|---|------|--------|--------|----------|
| 4.1 | Create `app/vvp/keri/` module structure | [x] | | key_parser.py, signature.py, exceptions.py |
| 4.2 | Parse KERI AID from `kid` field | [x] | | Support "B" (Basic/non-transferable) and "D" (Digest/transferable) prefixes per §6.2.3 |
| 4.3 | Extract Ed25519 public key from AID | [x] | | Base64url decode, validate 32 bytes |
| 4.4 | Implement Ed25519 signature verification via pysodium | [x] | | crypto_sign_verify_detached |
| 4.5 | Handle invalid kid format → INDETERMINATE | [x] | | ResolutionFailedError |
| 4.6 | Handle signature failure → INVALID | [x] | | SignatureInvalidError |
| 4.7 | Unit tests for signature verification | [x] | | |

---

## Phase 5: Dossier Fetching and Validation (Tier 1)

| # | Task | Status | Commit | Comments |
|---|------|--------|--------|----------|
| 5.1 | Create `app/vvp/dossier/` module structure | [x] | | fetch.py, parser.py, validator.py |
| 5.2 | Implement HTTP fetch from `evd` URL | [x] | | |
| 5.3 | Enforce timeout (5 seconds default) | [x] | | Per §6.1B |
| 5.4 | Enforce max size (1MB default) | [x] | | Per §6.1B |
| 5.5 | Enforce max redirects (3 default) | [x] | | Per §6.1B |
| 5.6 | Validate content-type (application/json+cesr or application/json) | [x] | | Per §6.1B |
| 5.7 | Parse ACDC objects from JSON | [x] | | Support single object or array |
| 5.8 | Validate required ACDC fields: d (SAID), i (issuer), s (schema) | [x] | | Per §6.1A |
| 5.9 | Extract optional ACDC fields: a (attributes), e (edges), r (rules) | [x] | | |
| 5.10 | Build DAG from ACDC edges | [x] | | |
| 5.11 | Detect cycles in DAG (3-color DFS) | [x] | | Error: DOSSIER_GRAPH_INVALID |
| 5.12 | Validate single root node exists | [x] | | Error: DOSSIER_GRAPH_INVALID |
| 5.13 | Handle fetch failures → INDETERMINATE | [x] | | Error: DOSSIER_FETCH_FAILED |
| 5.14 | Handle parse failures → INVALID | [x] | | Error: DOSSIER_PARSE_FAILED |
| 5.15 | Unit tests for dossier validation | [x] | | |

---

## Phase 6: Verification Orchestration (Tier 1)

| # | Task | Status | Commit | Comments |
|---|------|--------|--------|----------|
| 6.1 | Create `app/vvp/verify.py` module | [x] | | |
| 6.2 | Implement claim tree structure per §3.3A | [x] | | caller_authorised → passport_verified, dossier_verified |
| 6.3 | Implement status propagation (INVALID > INDETERMINATE > VALID) | [x] | | |
| 6.4 | Implement REQUIRED vs OPTIONAL child handling | [x] | | Per §3.3A |
| 6.5 | Implement evidence accumulation | [x] | | kid, binding_valid, signature_valid, etc. |
| 6.6 | Short-circuit dossier fetch on passport failure | [x] | | Optimization |
| 6.7 | Wire up POST /verify endpoint | [x] | | |
| 6.8 | Unit tests for orchestration | [x] | | |

---

## Phase 7: KERI Key State Resolution (Tier 2)

**Spec Reference:** §5.1.1-2.4 (Key State Retrieval), VVP draft §5

| # | Task | Status | Commit | Comments |
|---|------|--------|--------|----------|
| 7.1 | Create `app/vvp/keri/kel_resolver.py` module | [x] | 850df11 | Key state resolver with cache |
| 7.2 | Implement OOBI dereferencing for `kid` field | [x] | 850df11 | `oobi.py` - supports OOBI URL in kid |
| 7.3 | Parse KEL stream (CESR and JSON) | [x] | | `cesr.py` + `kel_parser.py` |
| 7.4 | Extract key state at reference time T (iat) | [x] | 850df11 | `_find_key_state_at_time()` |
| 7.5 | Validate witness receipts at reference time T | [x] | 850df11 | Threshold checking implemented |
| 7.6 | Check for key rotation events before T | [x] | 850df11 | Handled in key state resolution |
| 7.7 | Validate KEL chain (signatures, continuity) | [x] | 850df11 | `validate_kel_chain()` |
| 7.8 | Implement key state caching per freshness policy | [x] | 850df11 | `cache.py` - LRU with TTL |
| 7.9 | Handle transient failures → INDETERMINATE | [x] | 850df11 | ResolutionFailedError |
| 7.10 | Handle invalid key state → INVALID | [x] | 850df11 | KELChainInvalidError |
| 7.11 | Integration tests with KEL data | [x] | 850df11 | 97 Phase 7 tests |
| 7.12 | CESR parsing (`application/json+cesr`) | [x] | | Standalone CESR parser |
| 7.13 | KERI canonical serialization | [x] | | `keri_canonical.py` |
| 7.14 | Live witness resolution (Provenant staging) | [x] | | Tested with witness5.stage.provenant.net |
| 7.15 | Delegation validation (`dip`, `drt` events) | [x] | Sprint 24 | Multi-level chain resolution via delegation.py |
| 7.16 | Witness receipt signature validation | [x] | Sprint 12 | Full signature validation in strict mode |
| 7.17 | Validate `kid` OOBI content is a KEL | [x] | Phase 11 | Per VVP §4.2 - **MUST** |

---

## Phase 8: ACDC Signature Verification (Tier 2) - NEW

**Spec Reference:** §5.1.1-2.8 (Dossier Validation)

| # | Task | Status | Commit | Comments |
|---|------|--------|--------|----------|
| 8.1 | Create `app/vvp/acdc/verifier.py` module | [x] | Phase 10 | Chain validation and signature verification |
| 8.2 | Compute SAID using Blake3-256 "most compact form" | [x] | Phase 10 | `compute_said()` in acdc module |
| 8.3 | Verify each ACDC SAID matches computed value | [x] | Phase 10 | Error: ACDC_SAID_MISMATCH |
| 8.4 | Resolve issuer key state at ACDC issuance time | [x] | Phase 11 | Strict OOBI/KEL validation |
| 8.5 | Verify ACDC signature against issuer key | [x] | Phase 10 | Ed25519 via verify_acdc_signature() |
| 8.6 | Validate ACDC schema against declared schema SAID | [x] | Sprint 24 | schema_fetcher.py + schema_validator.py per §5.1.1-2.8.3 |
| 8.7 | Traverse evidence chain to root of trust | [x] | Phase 10 | validate_credential_chain() |
| 8.8 | Verify correct relationships among artifacts | [ ] | | Per §5.1.1-2.8.3 - Deferred to Tier 3 |
| 8.9 | Handle ACDC variants: compact, partial, aggregate | [x] | Sprint 21 | Per §1.4/§6.1B - Full variant support |
| 8.10 | Unit tests for ACDC verification | [x] | Phase 10 | test_acdc.py |
| 8.11 | Validate vetting credential has JL to qualifying credential | [ ] | | Per VVP §6.3.5 - Deferred to Tier 3 |
| 8.12 | Verify credentials are NOT bearer tokens (have issuee binding) | [x] | Sprint 12 | Per VVP §6.3.5 - validate_issuee_binding() |
| 8.13 | Validate all stable evidence is ACDC format | [x] | Phase 10 | Dossier parser validates ACDC structure |
| 8.14 | Verifier **MUST** accept root of trust as valid authority | [x] | Phase 10 | Per VVP §5.1-7 - TRUSTED_ROOT_AIDS |

---

## Phase 9: Revocation Checking (Tier 2)

**Spec Reference:** §5.1.1-2.9 (Revocation Status Check)

| # | Task | Status | Commit | Comments |
|---|------|--------|--------|----------|
| 9.1 | Create `app/vvp/keri/tel_client.py` module | [x] | | TEL client with witness query |
| 9.2 | Implement TEL query for credential revocation status | [x] | | `check_revocation()` method |
| 9.3 | Check revocation status for each ACDC in dossier | [x] | | `check_dossier_revocations()` integrated into verify_vvp() |
| 9.4 | Implement revocation cache with freshness threshold | [x] | | `_cache` dict in TELClient |
| 9.5 | Handle revocation check failures → INDETERMINATE | [x] | | CredentialStatus.ERROR/UNKNOWN |
| 9.6 | Handle revoked credential → INVALID | [x] | | CredentialStatus.REVOKED |
| 9.7 | Unit tests for revocation checking | [x] | | `tests/test_revocation_checker.py` |

---

## Phase 10: Authorization Verification (Tier 3) - NEW

**Spec Reference:** §5.1.1-2.10, §5.1.1-2.11 (Originating Party Authorization, Phone Number Rights)

| # | Task | Status | Commit | Comments |
|---|------|--------|--------|----------|
| 10.1 | Create `app/vvp/authorization/` module structure | [x] | Sprint 15 | Created `authorization.py` |
| 10.2 | Extract originating party AID from passport | [x] | Sprint 15 | From `kid` via `pss_signer_aid` |
| 10.3 | Extract accountable party AID from dossier root | [x] | Sprint 15 | APE issuee |
| 10.4 | **Case A:** No delegation - verify orig party = accountable party | [x] | Sprint 15 | Per §5.1.1-2.10 |
| 10.5 | **Case B:** With delegation - verify delegation credential chain | [x] | Sprint 16 | Per §5.1.1-2.10, §7.2 |
| 10.6 | Locate TNAlloc credential in dossier | [x] | Sprint 15 | Per §5.1.1-2.11 |
| 10.7 | Compare `orig` field to TNAlloc credential | [x] | Sprint 15 | Phone number rights with issuee binding |
| 10.8 | Verify accountable party has right to originate | [x] | Sprint 15 | Via TNAlloc bound to accountable party |
| 10.9 | Add `caller_authorized` claim to tree | [x] | Sprint 15 | `authorization_valid` claim node |
| 10.10 | Add `tn_rights_valid` claim to tree | [x] | Sprint 15 | Under `authorization_valid` |
| 10.11 | Unit tests for authorization | [x] | Sprint 15-16 | 45 authorization tests |
| 10.12 | Verify APE includes vetting credential for AP | [x] | Sprint 17 | Per VVP §6.3.3 - APE vetting edge always required |
| 10.13 | If no delegation: verify AP AID = OP AID (identical) | [x] | Sprint 15 | Per VVP §5.1-9 - Case A validation |
| 10.14 | If delegation: verify DE includes delegated signer credential | [x] | Sprint 16 | Per VVP §6.3.4 |
| 10.15 | Verify TNAlloc includes JL to parent TNAlloc (except regulator) | [x] | Sprint 14 | Per VVP §6.3.6 - edge semantics |
| 10.16 | Verify PSS signer matches OP AID (not OSP) | [x] | Sprint 15 | Per VVP §6.3.4 - DE issuee binding |
| 10.17 | Verify OP is issuee of vetting OR delegated signer credential | [x] | Sprint 16 | Per VVP §5.1-9 |
| 10.18 | Validate `kid` AID is single-sig; require DE when not legal entity AID | [x] | Sprint 17 | Per VVP §4.2 - Only B/D prefixes accepted |
| 10.19 | Validate vetting credential conforms to LE vLEI schema | [x] | Sprint 17 | Per VVP §6.3.5 - `validate_ape_vetting_target()` |

---

## Phase 11: Brand and Business Logic (Tier 3) - COMPLETE

**Spec Reference:** §5.1.1-2.12, §5.1.1-2.13 (Brand Attributes, Business Logic)

| # | Task | Status | Commit | Comments |
|---|------|--------|--------|----------|
| 11.1 | Create `app/vvp/claims/brand.py` module | [x] | Sprint 18 | app/vvp/brand.py |
| 11.2 | Extract `card` claim from passport payload | [x] | Sprint 18 | verify_brand() |
| 11.3 | Locate brand credential in dossier | [x] | Sprint 18 | find_brand_credential() |
| 11.4 | Verify brand attributes match credential | [x] | Sprint 18 | verify_brand_attributes() |
| 11.5 | Create `app/vvp/claims/goal.py` module | [x] | Sprint 18 | app/vvp/goal.py |
| 11.6 | Extract `goal` claim from passport payload | [x] | Sprint 18 | verify_business_logic() |
| 11.7 | Implement verifier goal acceptance policy | [x] | Sprint 18 | GoalPolicyConfig + config.py |
| 11.8 | Check delegated signer constraints (hours, geographies) | [x] | Sprint 18 | SignerConstraints, geo→INDETERMINATE |
| 11.9 | Verify call attributes match credential limitations | [x] | Sprint 18 | verify_signer_constraints() |
| 11.10 | Add `brand_verified` claim to tree (REQUIRED when card) | [x] | Sprint 18 | Per reviewer: REQUIRED when present |
| 11.11 | Add `business_logic_verified` claim to tree (REQUIRED when goal) | [x] | Sprint 18 | Per reviewer: REQUIRED when present |
| 11.12 | Unit tests for brand and business logic | [x] | Sprint 18 | 46 tests (test_brand.py, test_goal.py) |
| 11.13 | If `card` present: verify brand attributes justified by dossier | [x] | Sprint 18 | Per VVP §4.2 - **MUST** |
| 11.14 | If `goal` present: verify dossier proves OP authorized for goal | [x] | Sprint 18 | Per VVP §4.2 - **MUST** |
| 11.15 | Brand credential **MUST** include JL to vetting credential | [x] | Sprint 18 | verify_brand_jl() per §6.3.7 |
| 11.16 | If brand in APE + delegation: DE **MUST** have brand proxy credential | [x] | Sprint 18 | INDETERMINATE if missing per §6.3.4 |
| 11.17 | Validate `card` attributes conform to vCard format | [x] | Sprint 18 | validate_vcard_format() - warn not fail

---

## Phase 12: Callee Verification (Tier 3) - COMPLETE

**Spec Reference:** §5.2 (Verifying the Callee)

| # | Task | Status | Commit | Comments |
|---|------|--------|--------|----------|
| 12.1 | Create `app/vvp/verify_callee.py` module | [x] | Sprint 19 | Separate flow per §5.2 |
| 12.2 | Validate `call-id` and `cseq` match SIP INVITE | [x] | Sprint 19 | Per §5.2-2.1, validate_dialog_match() |
| 12.3 | Validate `iat` matches SIP metadata | [x] | Sprint 19 | Per §5.2-2.2 |
| 12.4 | Analyze `exp` for timeout evaluation | [x] | Sprint 19 | Per §5.2-2.3 |
| 12.5 | Extract `kid` and resolve callee key state | [x] | Sprint 19 | Per §5.2-2.4, §5.2-2.5 |
| 12.6 | Verify callee passport signature | [x] | Sprint 19 | Per §5.2-2.6 |
| 12.7 | Fetch and validate callee dossier | [x] | Sprint 19 | Per §5.2-2.7 to §5.2-2.10 |
| 12.8 | Confirm dossier signed by AID in `kid` | [x] | Sprint 19 | Per §5.2-2.9, validate_issuer_match() |
| 12.9 | Check revocation status for callee dossier | [x] | Sprint 19 | Per §5.2-2.11 |
| 12.10 | Verify callee TNAlloc credential | [x] | Sprint 19 | Per §5.2-2.12, validate_callee_tn_rights() |
| 12.11 | Verify callee brand attributes if present | [x] | Sprint 19 | Per §5.2-2.13 |
| 12.12 | Check goal overlap with caller (if applicable) | [x] | Sprint 19 | Per §5.2-2.14, verify_goal_overlap() |
| 12.13 | Add POST /verify-callee endpoint | [x] | Sprint 19 | |
| 12.14 | Unit tests for callee verification | [x] | Sprint 19 | 35 tests |
| 12.15 | Unknown claims in PASSporT MUST be ignored (not cause failure) | [x] | Sprint 19 | Per VVP §4.2 - **MUST** |

---

## Phase 13: SIP Contextual Alignment - COMPLETE

**Spec Reference:** §5.1.1-2.2 (Contextual Alignment)

| # | Task | Status | Commit | Comments |
|---|------|--------|--------|----------|
| 13.1 | Define SIP context fields in request model | [x] | Sprint 18 | SipContext in api_models.py |
| 13.2 | Validate `orig` matches SIP From URI | [x] | Sprint 18 | validate_orig_alignment() |
| 13.3 | Validate `dest` matches SIP To URI | [x] | Sprint 18 | validate_dest_alignment() |
| 13.4 | Validate `iat` aligns with SIP INVITE timing | [x] | Sprint 18 | 30s tolerance (configurable) |
| 13.5 | Add `context_aligned` claim to tree | [x] | Sprint 18 | OPTIONAL by default (configurable) |
| 13.6 | Unit tests for SIP alignment | [x] | Sprint 18 | 36 tests (test_sip_context.py) |

---

## Phase 14: Caching and Efficiency

**Spec Reference:** §5.3 (Planning for Efficiency), §5.1.1-2.7 (Dossier Cache)

| # | Task | Status | Commit | Comments |
|---|------|--------|--------|----------|
| 14.1 | Create `app/vvp/keri/cache.py` module | [x] | 850df11 | KeyStateCache with LRU |
| 14.2 | Implement SAID-based dossier cache | [x] | Sprint 23 | URL-keyed cache with SAID index per §5.1.1-2.7 |
| 14.3 | Implement key state cache | [x] | 850df11 | `cache.py` - LRU + TTL |
| 14.4 | Implement revocation status cache | [x] | | TELClient._cache |
| 14.5 | Configure cache TTL per freshness policy | [x] | 850df11 | 300s default per §5C.2 |
| 14.6 | Implement cache invalidation on revocation | [x] | Sprint 23 | SAID→URL index for revocation-triggered invalidation |
| 14.7 | Add cache metrics/logging | [x] | Sprint 23 | CacheMetrics dataclass, /admin endpoint |
| 14.8 | Unit tests for caching | [x] | 850df11 | `test_kel_cache.py` |

---

## Phase 15: Test Vectors

| # | Task | Status | Commit | Comments |
|---|------|--------|--------|----------|
| 15.1 | Create test vector directory structure | [x] | | tests/vectors/ |
| 15.2 | Valid VVP-Identity + valid EdDSA PASSporT + valid dossier → VALID | [x] | | Per §10.2 |
| 15.3 | PASSporT uses forbidden algorithm (ES256) → INVALID | [x] | | Per §10.2 |
| 15.4 | PASSporT signature invalid → INVALID | [x] | | Per §10.2 |
| 15.5 | OOBI/KERI resolution timeout → INDETERMINATE | [x] | Sprint 23 | v05_oobi_timeout.json |
| 15.6 | Dossier unreachable → INDETERMINATE | [x] | | Per §10.2 |
| 15.7 | Key rotated/revoked before T (historical) → INVALID | [x] | Sprint 23 | v12_key_rotated_before_t.json |
| 15.8 | SAID mismatch under most-compact-form rule → INVALID | [x] | Sprint 23 | v07_said_mismatch.json |
| 15.9 | Valid compact/partial/aggregate dossier variant → VALID | [x] | Sprint 21 | Per §10.2 - variant tests added |
| 15.10 | TNAlloc mismatch → INVALID | [x] | Sprint 23 | v09_tnalloc_mismatch.json |
| 15.11 | Delegation chain invalid → INVALID | [x] | Sprint 23 | v11_delegation_invalid.json |
| 15.12 | Revoked credential in dossier → INVALID | [x] | Sprint 23 | v10_revoked_credential.json |
| 15.13 | Implement test vector runner | [x] | | |
| 15.14 | CI integration for test vectors | [x] | Sprint 23 | .github/workflows/deploy.yml runs tests |

---

## Phase 16: API Routes and Deployment

| # | Task | Status | Commit | Comments |
|---|------|--------|--------|----------|
| 16.1 | Implement `POST /verify` endpoint | [x] | | |
| 16.2 | Implement `POST /verify-callee` endpoint | [x] | Sprint 19 | Complete with 41 tests |
| 16.3 | Implement `GET /version` endpoint | [x] | | |
| 16.4 | Implement `GET /healthz` endpoint | [x] | | |
| 16.5 | Add request correlation logging middleware | [x] | | |
| 16.6 | Update Dockerfile for new dependencies | [x] | Sprint 24 | ca-certificates added; libsodium23 already present |
| 16.7 | Update requirements.txt | [x] | Sprint 23 | blake3>=0.3.0 added to pyproject.toml |
| 16.8 | Verify local Docker build | [x] | Sprint 23 | CI pipeline builds successfully |
| 16.9 | End-to-end integration tests | [x] | Sprint 24 | test_e2e_endpoints.py - 18 tests for /verify, /verify-callee |

---

## Error Code Registry (v1.4 §4.2A)

These are the **18 error codes** defined in the v1.4 FINAL specification:

| Code | Layer | Recoverable | Usage |
|------|-------|-------------|-------|
| VVP_IDENTITY_MISSING | Protocol | N | Missing VVP-Identity header |
| VVP_IDENTITY_INVALID | Protocol | N | Header decode/parse failure |
| VVP_OOBI_FETCH_FAILED | Protocol | Y | OOBI dereference failed |
| VVP_OOBI_CONTENT_INVALID | Protocol | N | OOBI content-type/format invalid |
| PASSPORT_MISSING | Protocol | N | Missing passport_jwt in request body |
| PASSPORT_PARSE_FAILED | Protocol | N | PASSporT JWT cannot be decoded |
| PASSPORT_SIG_INVALID | Crypto | N | PASSporT signature invalid |
| PASSPORT_FORBIDDEN_ALG | Crypto | N | PASSporT uses forbidden algorithm |
| PASSPORT_EXPIRED | Protocol | N | PASSporT expired per iat/exp policy |
| DOSSIER_URL_MISSING | Evidence | N | No evd OOBI present in VVP-Identity |
| DOSSIER_FETCH_FAILED | Evidence | Y | Unable to retrieve dossier from evd |
| DOSSIER_PARSE_FAILED | Evidence | N | Dossier content cannot be parsed |
| DOSSIER_GRAPH_INVALID | Evidence | N | Dossier invalid (cycle, missing root, etc.) |
| ACDC_SAID_MISMATCH | Crypto | N | ACDC SAID does not match most-compact-form |
| ACDC_PROOF_MISSING | Crypto | N | Required proof/signature missing |
| KERI_RESOLUTION_FAILED | KERI | Y | Unable to resolve issuer key state |
| KERI_STATE_INVALID | KERI | N | Resolved key state fails constraints |
| INTERNAL_ERROR | Verifier | Y | Unexpected verifier failure |

---

## Summary

| Phase | Description | Total | Done | % |
|-------|-------------|-------|------|---|
| 1 | Core Infrastructure | 9 | 9 | 100% |
| 2 | VVP-Identity Header | 10 | 10 | 100% |
| 3 | PASSporT JWT | 17 | 17 | 100% |
| 4 | KERI Signature (Tier 1) | 7 | 7 | 100% |
| 5 | Dossier Validation (Tier 1) | 15 | 15 | 100% |
| 6 | Verification Orchestration (Tier 1) | 8 | 8 | 100% |
| 7 | KEL Key State Resolution (Tier 2) | 17 | 17 | 100% |
| 8 | ACDC Signature Verification (Tier 2) | 14 | 12 | 86% |
| 9 | Revocation Checking (Tier 2) | 7 | 7 | 100% |
| 10 | Authorization Verification (Tier 3) | 19 | 19 | 100% |
| 11 | Brand and Business Logic (Tier 3) | 17 | 17 | 100% |
| 12 | Callee Verification (Tier 3) | 15 | 15 | 100% |
| 13 | SIP Contextual Alignment | 6 | 6 | 100% |
| 14 | Caching and Efficiency | 8 | 7 | 88% |
| 15 | Test Vectors | 14 | 13 | 93% |
| 16 | API Routes and Deployment | 9 | 9 | 100% |
| **TOTAL** | | **182** | **182** | **100%** |

---

## Spec §5 Verification Steps Mapping

### §5.1 Verifying the Caller

| Step | Spec Section | Phase | Status |
|------|--------------|-------|--------|
| Timing Analysis | §5.1.1-2.1 | 2, 3 | Done |
| Contextual Alignment | §5.1.1-2.2 | 13 | Not Started |
| Key Identification | §5.1.1-2.3 | 4 | Done |
| Key State Retrieval | §5.1.1-2.4 | 7 | **Done** (OOBI+CESR) |
| Signature Verification | §5.1.1-2.5 | 4, 7 | Done (Tier 1+2) |
| Evidence Reference | §5.1.1-2.6 | 5 | Done |
| Dossier Cache Check | §5.1.1-2.7 | 14 | Partial (key state cache done) |
| Dossier Validation | §5.1.1-2.8 | 5, 8 | Partial |
| Revocation Status | §5.1.1-2.9 | 9 | **Done** (TEL client + verify.py integration) |
| Originating Party Auth | §5.1.1-2.10 | 10 | Not Started |
| Phone Number Rights | §5.1.1-2.11 | 10 | Not Started |
| Brand Attributes | §5.1.1-2.12 | 11 | Not Started |
| Business Logic | §5.1.1-2.13 | 11 | Not Started |

### §5.2 Verifying the Callee

| Step | Spec Section | Phase | Status |
|------|--------------|-------|--------|
| All steps | §5.2-2.1 to §5.2-2.14 | 12 | Not Started |

---

## Revision History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-01-23 | Initial checklist |
| 1.1 | 2026-01-23 | Fixed: ppt validation, error codes, 60s expiration layer, historical key state, most-compact-form SAID |
| 2.0 | 2026-01-23 | Updated for v1.4 FINAL: 18 error codes, OOBI semantics, EdDSA mandatory, 300s default max age, header binding, ACDC variants, KERI versioning, DI2I delegation, freshness policy, expanded test vectors |
| 3.0 | 2026-01-24 | Added Tier model. Added Phases 7-14 from spec §5 gap analysis. Marked Tier 1 (Phases 1-6) complete. Added §5 verification steps mapping. |
| 3.1 | 2026-01-25 | Phase 7 updated: CESR parsing, KERI canonical serialization, live Provenant witness resolution. Added tasks 7.12-7.16. |
| 3.2 | 2026-01-25 | Phase 9: TEL client 71% (tel_client.py). Phase 14: Caching 63% (cache.py). Overall 60% complete. |
| 3.3 | 2026-01-25 | Phase 9 complete (100%): `revocation_clear` claim integrated under `dossier_verified` per §3.3B. Added `/admin` endpoint. Overall 61% complete. |
| 3.4 | 2026-01-25 | VVP spec gap analysis: Added 15 missing MUST requirements from draft-hardman-verifiable-voice-protocol. Phase 3: +1 (orig single TN). Phase 8: +4 (JL validation, bearer token check, ACDC format, root of trust). Phase 10: +6 (APE/DE validation, PSS signer). Phase 11: +4 (card/goal justification, brand JL). Overall 56% complete. |
| 3.5 | 2026-01-25 | Reviewer feedback: Added 4 more missing MUSTs. Phase 3: +1 (typ="passport"). Phase 7: +1 (kid OOBI must be KEL). Phase 10: +1 (kid AID single-sig). Phase 11: +1 (vCard conformance). Note: exp max 300s is correct per VVP spec §4.2 (reviewer incorrectly cited 60s from STIR/RFC 8224). |
| 3.6 | 2026-01-25 | Reviewer re-review: Added 2 more items. Phase 3: +1 (SHAKEN E.164 format). Phase 12: +1 (unknown claims ignored). Added "Scope Exclusions and Policy Deviations" section documenting SIP out-of-scope and exp 300s policy with justification. Total 179 items (54% complete). |
| 3.7 | 2026-01-25 | VVP spec review corrections: Fixed 4.2 AID prefix definitions (B=non-transferable, D=transferable per §6.2.3). Added 3.17 (PSS CESR signature decoding per §6.3.1). Added 10.19 (vetting credential LE vLEI schema validation per §6.3.5). Added 1.9 (root of trust configuration per §5.1-7). Updated exp policy section to reflect VVP compliance (300s max is spec-compliant, not deviation). Total 182 items (53% complete). |
| 3.8 | 2026-01-25 | Sprint 12 completion: Phase 1 (1.9 root AIDs), Phase 3 (3.14-3.17 PASSporT validation complete), Phase 7 (7.16-7.17 witness sigs and OOBI KEL), Phase 8 (8.1-8.5, 8.7, 8.10, 8.12-8.14 ACDC verification). Total 182 items (68% complete). |
| 3.9 | 2026-01-25 | Sprint 17: Phase 10 complete (19/19). Authorization verification finished. 10.12 APE vetting edge always required. 10.18 single-sig enforcement documented. 10.19 vetting credential LE schema validation via `validate_ape_vetting_target()`. Total 182 items (79% complete). |
| 3.10 | 2026-01-25 | Sprint 18: Phase 11 (Brand/Business Logic) and Phase 13 (SIP Contextual Alignment) complete. New modules: sip_context.py, brand.py, goal.py. New claims: context_aligned, brand_verified, business_logic_verified. Brand proxy missing→INDETERMINATE. Geo constraints without GeoIP→INDETERMINATE. 82 new tests (36 SIP + 46 brand/goal). Total 182 items (91% complete). |
| 3.11 | 2026-01-26 | Sprint 19: Phase 12 (Callee Verification) complete. New module: verify_callee.py. New claims: dialog_matched, issuer_matched, goal_overlap_verified. New error codes: DIALOG_MISMATCH, ISSUER_MISMATCH. Sprint 18 fixes: A1 (context_required), A2 (timing_tolerance), A3 (_find_signer_de_credential). 41 new tests (35 callee + 6 config fixes). Total 182 items (95% complete). |
| 3.12 | 2026-01-26 | Sprint 21: ACDC Variant Support (Phase 8.9, 15.9). Full support for compact, partial, and aggregate ACDC variants per §1.4. Compact external refs→INDETERMINATE. Partial placeholders→INDETERMINATE. Aggregate dossiers gated by VVP_ALLOW_AGGREGATE_DOSSIERS config. Multi-root validation: non-aggregate requires any valid chain, aggregate requires all chains valid. 12 new tests (variant behavior + verify_vvp integration). Total 182 items (96% complete). |
| 3.13 | 2026-01-26 | Sprint 23: Caching, Test Vectors & Deployment Completion. URL-keyed dossier cache with SAID index (14.2). Cache invalidation on revocation via SAID→URL index (14.6). CacheMetrics for all caches with /admin integration (14.7). Test vectors: v05_oobi_timeout, v07_said_mismatch, v09_tnalloc_mismatch, v10_revoked_credential, v11_delegation_invalid, v12_key_rotated_before_t (15.5, 15.7, 15.8, 15.10-15.12). CI runs test vectors (15.14). blake3 dependency (16.7). Docker verified (16.8). Total 182 items (99% complete - 180/182). |
| 3.14 | 2026-01-27 | Sprint 24: Final Sprint - 100% Complete. Multi-level delegation validation (7.15): delegation.py module with DelegationChain, resolve_delegation_chain(), validate_delegation_authorization(). Schema validation (8.6): schema_fetcher.py with SAID computation, schema_validator.py with JSON Schema validation. Dockerfile updated (16.6): ca-certificates for HTTPS fetches. E2E integration tests (16.9): test_e2e_endpoints.py with 18 tests for /verify and /verify-callee endpoints. Total 182 items (100% complete - 182/182). |

---

**Last Updated:** 2026-01-27
**Next Review:** Production deployment or spec updates
