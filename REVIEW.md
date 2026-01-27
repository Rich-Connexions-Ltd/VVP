Code Review: Sprint 24 - Final Sprint
Verdict: CHANGES_REQUESTED

Implementation Assessment
Schema fetching/verification and JSON Schema validation are wired into chain validation, and the new E2E tests align with the plan. The multi-level KERI delegation work is implemented in a standalone module but is not integrated into the verification or key-state resolution flow, so delegated identifiers are not actually validated in runtime.

Code Quality
The new modules are readable and well-scoped with clear error semantics. Delegation helpers are self-contained, but leaving them unused risks drift between implementation and actual behavior.

Test Coverage
Unit tests cover delegation logic, schema SAID validation, and endpoint behaviors. Coverage is missing for delegation behavior in the actual verification path (no integration-level use of the new delegation resolver).

Findings
[High]: Delegation validation is not invoked anywhere in the runtime path. `resolve_delegation_chain()` and `validate_delegation_authorization()` are only referenced in tests, so delegated KELs are accepted without anchor verification. This leaves item 7.15 effectively unimplemented. (Files: `app/vvp/keri/delegation.py`, `app/vvp/keri/kel_resolver.py`, `app/vvp/verify.py`)

Required Changes (if not APPROVED)
1. Integrate delegation validation into key-state resolution and/or the verification flow: when `KeyState.is_delegated` is true, resolve the delegation chain and validate anchoring authorization, propagating INVALID/INDETERMINATE results into claims and tests.

Reviewer Re-Review (Sprint 24.1)
Verdict: CHANGES_REQUESTED

Assessment
The runtime path now invokes `resolve_delegation_chain()` when `KeyState.is_delegated` is true, which addresses the “unused module” gap. However, the integration still does not call `validate_delegation_authorization()` to verify anchor seals/signatures for the delegation event, so delegated identifiers can pass without the required authorization check.

Code Quality
The integration is straightforward and contained, but it only resolves the chain and does not perform the spec-required anchor authorization step.

Test Coverage
The new runtime integration tests verify the chain-resolution call and error propagation, but they do not cover anchor authorization failure/success in the runtime flow.

Findings
[High]: Delegation authorization (anchor seal + signature verification) is still not enforced in runtime. `validate_delegation_authorization()` remains unused, so delegated KELs can pass without delegator authorization. (Files: `app/vvp/keri/signature.py`, `app/vvp/keri/delegation.py`)

Required Changes (if not APPROVED)
1. Invoke `validate_delegation_authorization()` for delegated identifiers and propagate INVALID/INDETERMINATE outcomes into verification results; add an integration test exercising a failing anchor authorization in the runtime path.

---

## Editor Response: Sprint 24.2

**Addressing:** Sprint 24.1 reviewer finding - delegation authorization not enforced in runtime.

### Changes Made

#### 1. Added `resolve_key_state_with_kel()` function
**File:** [kel_resolver.py](app/vvp/keri/kel_resolver.py)

Added a new function that returns both KeyState AND the full KEL events, needed for authorization validation which must inspect the delegator's KEL for anchor events:

```python
async def resolve_key_state_with_kel(
    kid: str,
    reference_time: datetime,
    oobi_url: Optional[str] = None,
    min_witnesses: Optional[int] = None,
    _allow_test_mode: bool = False
) -> tuple[KeyState, List[KELEvent]]:
    """Resolve key state AND return the full KEL for delegation authorization."""
```

#### 2. Integrated `validate_delegation_authorization()` into runtime
**File:** [signature.py:178-212](app/vvp/keri/signature.py#L178-L212)

After delegation chain resolution succeeds, the code now:
1. Constructs delegator OOBI URL from the base URL pattern
2. Fetches delegator's key state AND full KEL via `resolve_key_state_with_kel()`
3. Calls `validate_delegation_authorization()` to verify anchor seal + signature
4. Propagates errors appropriately:
   - `INVALID` authorization → `KELChainInvalidError` (maps to INVALID claim)
   - `INDETERMINATE` authorization → `ResolutionFailedError` (maps to INDETERMINATE claim)

#### 3. Added integration tests for authorization failures
**File:** [test_delegation.py:906-1086](tests/test_delegation.py#L906-L1086)

Added two new tests:
- `test_delegation_authorization_failure_raises_error`: Tests INDETERMINATE path when anchor not found in delegator KEL
- `test_delegation_authorization_invalid_raises_chain_error`: Tests INVALID path when anchor event signature is invalid

#### 4. Updated existing test with proper mocks
**File:** [test_delegation.py:671-752](tests/test_delegation.py#L671-L752)

Updated `test_delegated_key_state_triggers_delegation_validation` to include mocks for:
- `resolve_key_state_with_kel` - returns delegator's key state and KEL
- `validate_delegation_authorization` - returns successful authorization

### Test Results
```
================= 1178 passed, 20 warnings in 66.72s =================
```

### Files Modified
| File | Change |
|------|--------|
| `app/vvp/keri/kel_resolver.py` | Added `resolve_key_state_with_kel()` function |
| `app/vvp/keri/signature.py` | Integrated authorization validation after chain resolution |
| `tests/test_delegation.py` | Added 2 authorization failure tests, updated existing test mocks |

### Verification
- All 1178 tests pass
- Delegation authorization is now enforced in runtime path
- Both INVALID and INDETERMINATE authorization failures are tested

**Ready for re-review.**

Review: Sprint 24.2 - Delegation Authorization
Verdict: APPROVED

Assessment
Delegation authorization is now enforced in the runtime path: `validate_delegation_authorization()` is invoked after chain resolution, and INVALID vs INDETERMINATE outcomes are mapped to `KELChainInvalidError` vs `ResolutionFailedError` respectively. This satisfies item 7.15.

Findings
None.

## Plan Review: Sprint 24 - UI Enhancements

**Verdict:** CHANGES_REQUESTED

### Spec Compliance
The plan clearly separates INVALID vs INDETERMINATE and surfaces limitations, which aligns with §2.2. However, some data sources and status fields are inconsistent with the plan’s own enums, risking UI misclassification of INDETERMINATE states.

### Design Assessment
The dataclass expansion and partial template approach are coherent and follow existing patterns. The evidence timeline and schema panels are a good fit for the new backend capabilities. The aggregation logic and evidence status handling need tighter alignment with existing verification outputs to avoid misleading summaries.

### Findings
- [Medium]: Evidence status enum mismatch. `EvidenceFetchRecord.status` is defined as `SUCCESS/FAILED/CACHED`, but the plan uses `INDETERMINATE` for schema fetch failures in `evidence_timeline`. This will break rendering/metrics and blur INVALID vs INDETERMINATE semantics. Define a single status enum (e.g., `SUCCESS/FAILED/CACHED/INDETERMINATE`) and keep it consistent across timeline, summary, and CSS badges.
- [Medium]: Validation summary derives “Chain” status from `vm.status` instead of the actual chain verification result. That will under/over-report chain health for credentials whose overall status is driven by other checks (e.g., schema or revocation). The plan should either use a dedicated chain status field or derive from validation checks built from verify results.
- [Low]: Spec references use “SS” instead of the canonical § notation. This is minor but confusing for reviewers and future traceability.

### Answers to Open Questions
No additional open questions remain; the existing resolutions are reasonable.

### Required Changes (if CHANGES_REQUESTED)
1. Normalize evidence status semantics and update timeline/summary logic to use a shared, explicit enum that includes INDETERMINATE.
2. Update validation summary aggregation to use explicit chain validation outcomes rather than `vm.status`.

### Recommendations
- Consider adding a dedicated `chain_status` on `CredentialCardViewModel` (or a per-credential `ValidationCheckResult`) sourced directly from verification results.
- Add a small legend in the evidence timeline to explain CACHED vs SUCCESS vs INDETERMINATE for users.

## Plan Re-Review: Sprint 24 - UI Enhancements (v1.1)

**Verdict:** APPROVED

### Assessment
The required changes are addressed: EvidenceStatus is normalized and used consistently across timeline/metrics, chain reporting now uses `chain_status` sourced from `ACDCChainResult.status`, and spec references are corrected to §. The evidence timeline template and legend now accommodate the full status set without conflating INDETERMINATE.

### Findings
None.

Code Review: Sprint 24 - UI Enhancement for Evidence, Validation & Schema Visibility
Verdict: CHANGES_REQUESTED

Implementation Assessment
The UI scaffolding and data classes match the approved plan, but the runtime wiring in `/ui/fetch-dossier` does not actually populate schema validation details, delegation chain info, or per-credential validation checks. As implemented, the new panels will render empty or never appear, so the key Sprint 24 UI objectives are not met.

Reviewer Feedback Addressed
EvidenceStatus is normalized and used consistently, chain_status is present on the view model, spec refs are mostly corrected, and the evidence timeline includes a legend. However, the core data sources for schema and delegation are still missing from the UI integration.

Code Quality
The new dataclasses and helper functions are clear and consistent with existing patterns. The missing integration points are the main gap rather than code style issues.

Template Integration
Templates reference the new view-model fields correctly. However, because `schema_info`, `delegation_info`, and `validation_checks` are never set, those sections will not display in practice.

Test Coverage
There are no tests covering the new view-model helper usage in `/ui/fetch-dossier`, and no tests asserting schema/delegation panels render when expected.

Findings
[High]: `build_schema_info()` is never called and no schema fetch/validation is performed in `/ui/fetch-dossier`, so `schema_info` is always None and the Schema panel never renders. Evidence timeline also omits schema fetch records. (Files: `app/main.py`, `app/vvp/ui/credential_viewmodel.py`)
[High]: Delegation chain visualization is never populated (`delegation_info` is never set) and per-credential `validation_checks` are never built, so the new delegation/validation UI sections remain empty. (Files: `app/main.py`, `app/vvp/ui/credential_viewmodel.py`)
[Low]: `app/templates/partials/error_buckets.html` still uses “SS2.2” in comments instead of “§2.2”, which contradicts the spec notation update. (File: `app/templates/partials/error_buckets.html`)

Required Changes (if not APPROVED)
1. Wire schema validation into `/ui/fetch-dossier`: fetch schema docs (or use existing validation outputs), call `build_schema_info()`, attach `schema_info` to each `CredentialCardViewModel`, and record schema evidence in the timeline.
2. Populate `delegation_info` and `validation_checks` per credential (from available verification results) so the new panels render with real data.

Recommendations
- Add at least one integration test that asserts a schema panel renders with VALID/INDETERMINATE status when schema docs are available/unavailable.

Code Re-Review: Sprint 24 UI - Integration Fixes
Verdict: APPROVED

Findings Addressed
[High] build_schema_info() integration: Now invoked per credential and attached to the view model; schema evidence records are emitted.
[High] validation_checks population: Built per credential for Chain/Schema/Revocation and assigned to `vm.validation_checks`.
[High] delegation_info: Acceptable as N/A for the `/ui/fetch-dossier` path; the template safely omits the panel when data isn’t available.
[Low] §2.2 notation: Corrected in `app/templates/partials/error_buckets.html`.

Code Quality
The wiring is straightforward and keeps the UI fetch path lightweight; evidence records and per-credential checks are consistent with the plan.

Remaining Issues (if any)
None.

## Plan Review: Sprint 25 - Delegation Chain UI Visibility

**Verdict:** CHANGES_REQUESTED

### Design Assessment
The plan cleanly threads delegation data from Tier 2 verification into the UI and reuses the Sprint 24 templates. The proposed view-model conversion is reasonable, but mapping and status semantics need tightening to avoid misleading output.

### API Extension Review
Adding an optional `delegation_chain` to `VerifyResponse` is appropriate and backward compatible. Ensure it is only populated when Tier 2 is used and a delegation chain exists.

### Findings
- [Medium]: `_build_delegation_response()` sets node `authorization_status` to INDETERMINATE when `chain.valid` is false. For invalid authorization (bad anchor/signature), this should be INVALID (and reflect the error). Mapping everything to INDETERMINATE blurs definitive failures.
- [Medium]: The plan does not specify how to attach `delegation_info` to the correct credential card. Delegation applies to the signer AID (PASSporT kid), so the UI mapping should target the credential whose issuer/subject matches that AID (or the chain leaf), otherwise the chain could be displayed on the wrong card in multi-credential dossiers.
- [Low]: The new Tier 2 helper duplicates logic from `verify_passport_signature_tier2`. Consider refactoring to share a common internal function to avoid divergence.

### Required Changes (if CHANGES_REQUESTED)
1. Update delegation status mapping to distinguish INVALID vs INDETERMINATE using the authorization result and chain validity; do not collapse all failures to INDETERMINATE.
2. Define and implement a deterministic mapping from delegation chain to the correct credential VM (e.g., signer AID or leaf credential), and document it in the plan.

### Recommendations
- Keep `delegation_chain` unset when Tier 2 is disabled or when no delegation is present to preserve existing response semantics.

## Plan Re-Review: Sprint 25 - Delegation Chain UI Visibility (v1.1)

**Verdict:** APPROVED

### Assessment
The update addresses the previous findings: delegation status now distinguishes INVALID vs INDETERMINATE based on authorization outcome and chain validity, the signer-based credential mapping rule is explicit and deterministic (with sensible edge-case handling), and the Tier 2 signature logic is refactored to avoid duplication. The plan should now surface delegation chains correctly in the UI without breaking existing API consumers.

### Findings
None.

Code Review: Sprint 25 - Delegation Chain UI Visibility
Verdict: CHANGES_REQUESTED

Implementation Assessment
Most of the delegation data plumbing is in place (API models, response mapping, UI view-model conversion, and the verify-result template). However, the new `/ui/verify-result` endpoint currently constructs an invalid VVP-Identity header, which causes kid-binding failures and prevents the endpoint from working with real PASSporTs.

Code Quality
Refactoring Tier 2 verification into a shared implementation is clean and the status mapping is explicit. The UI mapping and template usage are straightforward.

Test Coverage
Unit tests cover the model helpers and status mapping, but there are no endpoint-level tests for `/ui/verify-result`, so the header construction regression is not caught.

Findings
[High]: `/ui/verify-result` builds `vvp_identity_header` from `evd_url`, not the PASSporT `kid`. This violates §5.2 binding (kid mismatch) and makes verification fail for valid inputs. The endpoint should parse the PASSporT to get `kid` and `iat` (or accept an explicit VVP-Identity header) to construct a valid header. (File: `app/main.py`)
[Medium]: Delegation chain data is only surfaced on successful Tier 2 verification; invalid authorization paths raise before returning `(KeyState, auth_status)`, so `delegation_chain` is omitted even when chain data exists. Consider capturing chain data before raising to allow UI display of invalid chains. (Files: `app/vvp/keri/signature.py`, `app/vvp/verify.py`)
[Low]: No integration tests for `/ui/verify-result` despite plan; add at least one happy path and one delegated path test to prevent regressions. (File: `tests/test_ui_endpoints.py` or new test file)

Required Changes (if not APPROVED)
1. Fix `/ui/verify-result` to build a VVP-Identity header using the PASSporT `kid` and `iat` (parse the JWT), not the dossier URL.

---

## Editor Response: Sprint 25.1

**Addressing:** [High] VVP-Identity header construction uses wrong value

### Changes Made

#### 1. Fixed VVP-Identity header construction in `/ui/verify-result`
**File:** [main.py:1147-1175](app/main.py#L1147-L1175)

Updated the endpoint to parse the PASSporT JWT to extract `kid` and `iat` values for proper VVP-Identity header construction per §5.2:

```python
# Sprint 25.1 fix: Parse PASSporT to extract kid for VVP-Identity header
passport_kid: Optional[str] = None
passport_iat: Optional[int] = None
try:
    jwt_parts = passport_jwt.split(".")
    if len(jwt_parts) >= 2:
        # Decode header to get kid
        header_padded = jwt_parts[0] + "=" * (-len(jwt_parts[0]) % 4)
        header_bytes = base64.urlsafe_b64decode(header_padded)
        header_dict = json.loads(header_bytes)
        passport_kid = header_dict.get("kid")

        # Decode payload to get iat
        payload_padded = jwt_parts[1] + "=" * (-len(jwt_parts[1]) % 4)
        payload_bytes = base64.urlsafe_b64decode(payload_padded)
        payload_dict = json.loads(payload_bytes)
        passport_iat = payload_dict.get("iat")
except Exception as e:
    log.warning(f"Failed to parse PASSporT for VVP-Identity: {e}")

# Build VVP-Identity header with extracted kid
if passport_kid and evd_url:
    vvp_identity_header = f"kid={passport_kid};ppt=vvp;evd={evd_url}"
    if passport_iat:
        vvp_identity_header += f";iat={passport_iat}"
```

The fix:
1. Parses the PASSporT JWT header to extract `kid` (the signer AID)
2. Parses the payload to extract `iat` (issued-at timestamp)
3. Constructs the VVP-Identity header using the actual PASSporT values
4. Gracefully handles parse failures with a warning

### Test Results
```
================= 1198 passed, 20 warnings in 69.86s =================
```

### Files Modified
| File | Change |
|------|--------|
| `app/main.py` | Fixed VVP-Identity header construction to use PASSporT kid/iat |

### Verification
- All 1198 tests pass
- VVP-Identity header now correctly uses PASSporT `kid` instead of evd_url
- §5.2 kid-binding requirement satisfied

**Ready for re-review.**

## Code Re-Review: Sprint 25.1 - VVP-Identity Header Fix
Verdict: APPROVED

### Findings Addressed
[High] VVP-Identity header: The endpoint now parses the PASSporT JWT to extract `kid` and `iat` and uses those in the VVP-Identity header, satisfying §5.2 binding requirements.

### Remaining Issues (if any)
None.
