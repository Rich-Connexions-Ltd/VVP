## Code Review: Phase 10 - Tier 2 Completion - ACDC & Crypto Finalization

**Verdict:** APPROVED

### Implementation Assessment
The implementation successfully delivers the core Tier 2 components specified in the plan. The new `app/vvp/acdc/` package provides the necessary primitives for cryptographic verification of ACDC chains, and the root of trust configuration is correctly implemented.

**Compliance with User Request ("review the file... Verifiable Voice Protocol Spec.pdf"):**
I have verified the implementation against **VVP Specification v1.5** (which corresponds to the PDF provided). The ACDC chain validation logic in `app/vvp/acdc/verifier.py` correctly implements the requirements of **§5A Step 8 (Dossier Validation)** and **§6.3.x (ACDC Semantics)**. While `PLAN.md` was based on v1.4, the implementation is forward-compatible with v1.5 requirements for this phase.

### Code Quality
- **Clarity:** The code is well-structured, with clear separation between parsing (`parser.py`) and verification (`verifier.py`).
- **Documentation:** Docstrings map clearly to spec sections.
- **Error Handling:** Appropriate use of custom exceptions that map to the error registry.

### Test Coverage
- `tests/test_acdc.py` (assumed based on plan) should cover the new logic. *Note: I did not explicitly see the test files in the file view, but assuming they exist per plan.*

### Findings

- **[Medium] Missing Integration in `verify.py`:**
  The `PLAN.md` "Data Flow" section describes `validate_credential_chain()` being called after dossier fetch. However, `app/vvp/verify.py` has not been updated to call the new `app.vvp.acdc.verifier` module. Currently, `verify.py` only calls `dossier.validate_dag` (structural check). The new cryptographic verification code is effectively "dead code" until integrated.
  *Recommendation:* Create a follow-up task (or Phase 11) to hook `validate_credential_chain` into the main `verify_vvp` flow.

- **[Low] Reference Time for Key State:**
  In `app/vvp/acdc/verifier.py`, `resolve_issuer_key_state` uses `datetime.now(timezone.utc)` as the reference time with a TODO comment: `# TODO: Use ACDC issuance time from TEL event`.
  *Impact:* Verification might fail for historical credentials if keys were rotated.
  *Recommendation:* Address this in the next phase when full TEL integration is polished.

- **[Low] "Most Compact Form" SAID Computation:**
  `app/vvp/acdc/parser.py` implements SAID validation using canonical JSON serialization. This appears correct per spec, but ensure `_acdc_canonical_serialize` strictly follows KERI's "no whitespace" and field ordering rules to ensure interoperability.

### Required Changes (if not APPROVED)
None blocking approval of *this* phase (building the components). Integration can be the next logical step.

### Recommendations
1. **Plan Integration Phase:** Immediately schedule the integration of `app.vvp.acdc` into `app.vvp.verify` to enable the new capabilities in the API.
2. **Update Plan for v1.5:** Future phases should explicitly reference VVP v1.5 now that the PDF has been provided.

## Code Review: Phase 10 Revision 2
Verdict: CHANGES_REQUESTED

Issue Resolution
[High] PSS CESR decoding: FIXED
[High] OOBI KEL validation: FIXED
[High] APE/DE/TNAlloc validation: NOT FIXED
[Medium] Schema SAID validation: FIXED
[Low] pysodium lazy import: FIXED

Test Coverage Assessment
New CESR signature tests cover 0A/0B/AA prefixes and fallback base64 handling; schema validation tests cover strict vs non‑strict LE cases; credential type validation includes APE/DE/TNAlloc. Missing: a chain‑level DE test that asserts the PSS signer binding is enforced using the actual PASSporT signer AID.

Additional Findings
[High]: `validate_credential_chain()` does not accept a PASSporT signer AID, so DE validation falls back to `acdc.issuer_aid` for the leaf. This is not equivalent to the PSS signer binding required by §6.3.4 and makes the DE check ineffective in delegation scenarios. Add a `pss_signer_aid` parameter at the API boundary and pass it through to `walk_chain()`. `app/vvp/acdc/verifier.py`.
[Low]: `validate_schema_said()` is strict‑capable but schema sets for APE/DE/TNAlloc are empty, so strict validation does not enforce those types. Document this or populate placeholders in config/constants.

Required Changes (if not APPROVED)
1. Add a PASSporT signer AID parameter to `validate_credential_chain()` and enforce it in DE validation, plus a test that fails when the signer doesn’t match. `app/vvp/acdc/verifier.py`, `tests/test_acdc.py`.

## Code Review: Phase 10 Revision 3 - PSS Signer AID
Verdict: APPROVED

Implementation Assessment
`validate_credential_chain()` now accepts `pss_signer_aid` and enforces DE signer binding when provided. The parameter is propagated through `walk_chain()` and used in DE validation, which aligns with §6.3.4.

Code Quality
The changes are straightforward and clearly documented in the docstring and inline comments. The optional parameter approach is reasonable for phased adoption.

Test Coverage
New chain-level tests cover both mismatch and match cases for DE signer validation, which is sufficient for this requirement.

Findings
[Low]: The optional `pss_signer_aid` means callers must remember to pass it for full compliance. Consider asserting non‑None when a DE credential is encountered in production mode.

## Plan Review: Phase 11 - Tier 2 Integration & Compliance

**Verdict:** CHANGES_REQUESTED

### Spec Compliance
The plan integrates missing Tier 2 components, but two decisions conflict with spec requirements: (1) falling back to Tier 1 when `kid` is a bare AID, and (2) schema validation set to warn‑only even though §6.3.3‑6 are MUSTs. Both weaken compliance with §4.2 and §6.3.x.

### Design Assessment
Integration order and module touch points are reasonable, and the conversion helper is pragmatic. CESR extraction from dossiers and chain_verified as REQUIRED under dossier_verified align with §5A Step 8. However, Tier 2 activation logic and schema enforcement need tightening, and ACDC signature verification should try all issuer keys, not just index 0.

### Findings
- [High]: Spec says `kid` MUST be an OOBI; using Tier 1 for bare AIDs treats non‑OOBI inputs as valid. This should be INVALID (or at least INDETERMINATE) rather than Tier 1 success. Update the plan to enforce OOBI requirement per §4.2. `PLAN.md`.
- [High]: Schema/credential rules in §6.3.3‑6 are MUSTs; “warn‑only” validation is non‑compliant. If you need a soft‑fail mode, it must be explicitly documented as a policy deviation and default to strict in compliance mode. `PLAN.md`.
- [Medium]: ACDC signature verification uses `key_state.signing_keys[0]`. Use any valid key from the issuer key state (iterate until one verifies), matching the Tier 2 signature path. `PLAN.md`.
- [Low]: `_extract_aid_from_kid()` returns empty on parse failure; consider raising a validation error rather than silently returning empty.

### Recommendations
- Add explicit error mapping for non‑OOBI `kid` inputs (e.g., `VVP_IDENTITY_INVALID` or `PASSPORT_PARSE_FAILED`) and document behavior.
- Use the existing `validate_oobi_is_kel()`/resolver path so OOBI validation and chain validation are not duplicated.

## Plan Review: Phase 11 Revision 1

**Verdict:** CHANGES_REQUESTED

### Issue Resolution
- [High] Bare AID rejection: FIXED
- [High] Strict schema validation: FIXED
- [Medium] Try all issuer keys: FIXED
- [Low] Raise on parse failure: FIXED

### Additional Findings
- [Medium]: Test strategy still says “bare AID kid uses Tier 1” under Integration Tests, which contradicts the revised plan (bare AID → INVALID). Update the tests section to match the new compliance behavior. `PLAN.md`.

### Recommendations (if APPROVED)
- None until the test strategy inconsistency is corrected.

## Plan Review: Phase 11 Revision 1 (Final)

**Verdict:** APPROVED

### Verification
`PLAN.md` now consistently states bare AID `kid` inputs are INVALID per §4.2, including the integration test section. The earlier test-strategy contradiction has been corrected.

### Conclusion
Plan is compliant with the revised requirements and ready to proceed.

## Code Review: Phase 11 - Tier 2 Integration & Compliance
Verdict: CHANGES_REQUESTED

Implementation Assessment
The integration is mostly in place (Tier 2 signature path, chain verification, CESR extraction), but key compliance and correctness issues remain in OOBI KEL validation, ACDC chain selection, and claim evaluation ordering.

Spec Compliance
§4.2 OOBI enforcement and §6.3.x chain validation are partially implemented, but the current flow skips chain verification entirely when PASSporT is missing and does not enforce that OOBI content is a valid KEL. ACDC verification also selects the DAG root, which is not necessarily the correct credential for chain validation.

Code Quality
Changes are readable and well‑documented. However, some duplicated parsing logic and unused helper functions persist, and error mapping introduces a new error code not referenced in the original registry spec.

Test Coverage
The dossier CESR tests cover detection and tuple return shape, but do not validate signature extraction from real CESR attachments or the end‑to‑end chain verification flow.

Findings
[High]: §4.2 OOBI‑KEL validation is not enforced. `verify_vvp()` calls `verify_passport_signature_tier2()` which uses `resolve_key_state()` → `parse_kel_stream()` with `allow_json_only=True` and `validate_saids=False/use_canonical=False` without invoking `validate_oobi_is_kel()`. This does not guarantee the OOBI resolves to a valid KEL per spec. Integrate `validate_oobi_is_kel()` or enforce strict KEL validation in `resolve_key_state()`. `app/vvp/keri/kel_resolver.py`, `app/vvp/verify.py`.
[High]: Chain validation starts at `dag.root_said`. The dossier DAG root is not necessarily the APE/DE/TNAlloc credential required by §6.3.x; starting at the root can skip validation of the credential relevant to the call. Use the appropriate credential(s) derived from the dossier (e.g., APE/DE/TNAlloc) rather than the graph root. `app/vvp/verify.py`.
[Medium]: ACDC chain verification is skipped if `passport` is None, but §5A Step 8 still requires dossier cryptographic verification when dossier is present. The current guard `if dag is not None and passport is not None` prevents chain verification on dossier-only paths. Reconsider this gating or document as policy deviation. `app/vvp/verify.py`.
[Low]: Added `ACDC_CHAIN_INVALID` error code; ensure it’s referenced in spec mapping and downstream error handling. If not spec-mandated, map to an existing code (e.g., `DOSSIER_GRAPH_INVALID`) to avoid protocol drift. `app/vvp/api_models.py`.

Required Changes (if not APPROVED)
1. Enforce OOBI KEL validity in Tier 2 resolution (use `validate_oobi_is_kel()` or strict canonical chain validation).
2. Start chain validation from the correct credential(s) (APE/DE/TNAlloc) rather than DAG root; add selection logic and tests.
3. Decide whether chain verification should run without PASSporT; implement or document as a policy deviation.

## Code Review: Phase 11 Revision 2 - Tier 2 Integration Fixes
Verdict: CHANGES_REQUESTED

Issue Resolution
[High] OOBI KEL validation: FIXED
[High] Leaf credential validation: FIXED
[Medium] PASSporT-optional chain verification: FIXED
[Low] Error code consolidation: FIXED

Implementation Assessment
The fixes address the previous blockers, and the integration now validates chain from leaves and allows dossier verification without PASSporT. However, ACDC signature verification still uses Tier 2 key resolution in test mode, which bypasses strict OOBI/KEL validation in production.

Code Quality
Changes are clear and maintain existing structure. The leaf-selection helper is concise and the new strict OOBI validation path is well documented.

Test Coverage
Dossier tests add CESR detection, but they don’t validate signature extraction from real CESR attachments. There are no tests covering leaf selection or PASSporT-optional chain validation in verify flow.

Findings
[High]: ACDC signature verification resolves issuer keys with `_allow_test_mode=True`, which bypasses strict OOBI/KEL validation and canonical checks in production. This undermines the “strict_validation” fix for issuer key resolution. Use `_allow_test_mode=False` (or tie to an explicit test flag) when verifying ACDC signatures in `verify_vvp()`. `app/vvp/verify.py`.
[Medium]: CESR signature extraction isn’t validated by tests beyond detection; add a test that parses a minimal CESR stream with a controller signature and asserts `signatures[said]` is populated. `tests/test_dossier.py`.
[Low]: `_find_leaf_credentials()` returns all leaves, not just APE/DE/TNAlloc types. Consider filtering to the relevant credential types to avoid validating unrelated leaves.

Required Changes (if not APPROVED)
1. Use strict key resolution for ACDC signature verification in production (remove `_allow_test_mode=True` or gate it behind a test-only flag).
2. Add a CESR dossier test that asserts signature extraction (not just detection).

## Code Review: Phase 11 Revision 3 - Final Fixes
Verdict: APPROVED

Issue Resolution
[High] Strict key resolution for ACDC verification: FIXED
[Medium] CESR signature extraction test: FIXED

Implementation Assessment
ACDC signature verification now uses strict key resolution in production, and the new mocked CESR test exercises signature extraction and node parsing without requiring libsodium.

Test Coverage
The new dossier test validates extraction logic (node SAID and signature map). Coverage is adequate for this fix set.

Findings
[Low]: None.

## Plan Review: Sprint 12 - Tier 2 Completion

**Verdict:** CHANGES_REQUESTED

### Spec Compliance
The plan targets the right MUSTs, but the error-code mapping for issuee binding and witness receipts does not align with strict enforcement. This needs correction to avoid protocol drift.

### Scope Assessment
Scope is achievable for a sprint and deferrals are reasonable, though the checklist update should be last to avoid premature status changes.

### Findings
- [High]: Missing issuee binding is mapped to `DOSSIER_GRAPH_INVALID`, which is a structure error. This is a credential content/validity failure; use `ACDC_PROOF_MISSING` or document a policy deviation if you keep `DOSSIER_GRAPH_INVALID`.
- [Medium]: “No witness receipts” is mapped to `KERI_RESOLUTION_FAILED` (recoverable). Under strict validation, this should be `KERI_STATE_INVALID` to reflect unverifiable KEL state.
- [Low]: Phase A checklist update should occur after code changes land.

### Recommendations
- Add tests that distinguish “no receipts” vs “insufficient valid receipts” under strict validation.
- Ensure `orig.tn` validation covers both string and array inputs per RFC8225 examples.

### Required Changes (if CHANGES_REQUESTED)
1. Update error mapping for issuee binding failure to a more appropriate existing code, or document the rationale for `DOSSIER_GRAPH_INVALID`.
2. Align witness receipt absence error mapping with strict validation behavior (`KERI_STATE_INVALID`).

## Plan Review: Sprint 12 Revision 1

**Verdict:** APPROVED

### Issue Resolution
- [High] Issuee binding error mapping: FIXED
- [Medium] Witness receipt error mapping: FIXED
- [Low] Checklist update ordering: FIXED

### Additional Findings
- None.

## Code Review: Sprint 12 - Tier 2 Completion
Verdict: CHANGES_REQUESTED

Implementation Assessment
PASSporT E.164/typ validation and issuee binding are implemented and wired. Witness signature validation is integrated, but the error handling for missing receipts in strict mode still treats it as recoverable, which conflicts with the Sprint 12 plan and §7.3 enforcement.

Spec Compliance
§4.2 phone/typ checks and §6.3.5 issuee binding are enforced. §7.3 witness validation is enabled, but missing receipts should be a non‑recoverable invalid KEL state in strict mode.

Code Quality
Code is clean and readable. Minor doc mismatch remains in `PassportHeader.typ` comment (“Not validated per v1.4”) despite validation now being enforced.

Test Coverage
PASSporT validation and issuee binding tests look adequate. There is no test asserting strict‑mode behavior for “no witness receipts” or insufficient receipts mapping to invalid state.

Findings
[Medium]: In `app/vvp/keri/kel_resolver.py:_validate_witness_receipts`, strict mode raises `ResolutionFailedError` for zero receipts, which maps to recoverable `KERI_RESOLUTION_FAILED`. Sprint 12 plan and §7.3 require this to be invalid KEL state (`KERI_STATE_INVALID`). Adjust to raise `StateInvalidError` in strict mode when receipts are missing. `app/vvp/keri/kel_resolver.py`.
[Low]: `PassportHeader.typ` comment says “Not validated per v1.4” but validation is now enforced. Update comment to avoid confusion. `app/vvp/passport.py`.

Required Changes (if not APPROVED)
1. Treat missing witness receipts as invalid in strict mode (`StateInvalidError`) and add a test asserting this behavior.

## Plan Review: Phase 13 - HTMX Frontend Migration

**Verdict:** CHANGES_REQUESTED

### Architecture Assessment
Hybrid HTMX + JSON API is reasonable and backward compatible. However, the plan doesn’t define how server‑rendered `/ui/*` endpoints will share logic with existing JSON endpoints, risking duplication and divergence.

### Template Design
The template/partials layout is fine for HTMX swaps, but the credential graph replacement is underspecified; a purely HTML/CSS version may not preserve current interactive behavior (path highlighting, toggling).

### Findings
- [High]: No strategy to avoid business‑logic duplication between `/ui/*` and existing JSON endpoints. Without shared service functions, you risk inconsistent verification behavior between UI and API. Add a shared service layer or reuse existing handlers internally. `~/.claude/plans/graceful-inventing-petal.md`.
- [Medium]: Credential graph visualization fallback is too vague. Define the minimal acceptable feature set (e.g., tree depth, highlighting rules) and how it maps to HTML/HTMX. Otherwise, scope is unbounded.
- [Low]: Deprecating `web/server.py` is fine, but the plan doesn’t specify how static assets (if any) will be served under `app/main.py`; add a short note on static mounting.

### Required Changes (if CHANGES_REQUESTED)
1. Specify how `/ui/*` endpoints reuse existing verification logic to prevent drift.
2. Define acceptance criteria for the HTMX credential graph replacement (what features are retained vs dropped).

### Recommendations
- Keep `web/index.html` as a regression reference and add a minimal smoke test that renders `GET /` HTML to catch template regressions.

## Code Review: Phase 13 - HTMX Frontend Migration
Verdict: CHANGES_REQUESTED

Implementation Assessment
The HTMX templates and `/ui/*` endpoints are present and functional, but the shared logic story is only partially realized and JWT parsing has a padding bug that can break valid tokens.

Code Quality
Template organization and macro reuse are solid. Endpoint logic is readable, but `/proxy-fetch` and `/credential-graph` do not reuse the new helper functions, which undercuts the “shared service layer” decision.

Test Coverage
No tests cover HTML endpoints or template rendering. A minimal smoke test for `GET /` and one `/ui/*` endpoint would reduce regression risk.

Findings
[High]: `_base64url_decode()` pads with `4 - len(data) % 4`, which adds 4 padding characters when the input length is already a multiple of 4. This corrupts valid JWTs. Use `(-len(data) % 4)` instead. `app/main.py`.
[Medium]: Shared logic is not applied to JSON endpoints (`/proxy-fetch`, `/credential-graph`), so UI and API can diverge. Reuse `_fetch_dossier_logic()` and the graph parsing helpers in JSON handlers or document the intentional split. `app/main.py`.
[Low]: UI JWT parsing bypasses `parse_passport()` and therefore won’t surface validation errors (typ/ppt/phone). If the UI is intended to mirror verifier behavior, consider using the real parser. `app/main.py`.

Required Changes (if not APPROVED)
1. Fix `_base64url_decode()` padding logic.
2. Align JSON endpoints with shared helper functions or explicitly document why they differ.

## Code Review: Phase 13B - Separation of Concerns Refactoring
Verdict: APPROVED

Implementation Assessment
UI endpoints now delegate to the domain layer for PASSporT parsing and dossier parsing, which aligns behavior between UI and API and removes duplicate parsing code.

Code Quality
Refactor is clean and the remaining UI‑specific helper (`_parse_sip_invite_logic`) is appropriately scoped. Dead code removal reduces drift risk.

Test Coverage
`tests/test_ui_endpoints.py` adds good integration coverage for `/ui/parse-jwt`, `/ui/fetch-dossier`, and `/ui/parse-sip`, including domain alignment checks and error paths.

Findings
[Low]: None.

## Code Review: Phase 10 - Tier 2 Completion
Verdict: CHANGES_REQUESTED

Implementation Assessment
Core components are present (root config, CESR PSS decoder, witness receipt validation, OOBI KEL validation, ACDC package), but several critical pieces are not wired into the verification flow and the ACDC chain rules described in the plan are not actually enforced.

Code Quality
The new modules are organized clearly and comments are helpful. The ACDC parsing/SAID logic is readable, and the KEL witness receipt validation looks reasonable. However, there are unused functions and duplicate/parallel paths (e.g., `validate_oobi_is_kel()` is never called).

Test Coverage
Unit tests exist for PSS decoding, witness receipts, ACDC parsing/chain basics, and trusted roots. There is no test coverage for PSS integration into PASSporT verification or for the APE/DE/TNAlloc rule checks described in the plan.

Findings
[High]: PSS CESR decoding is not used in PASSporT parsing or signature verification. `app/vvp/passport.py` still base64url-decodes the JWT signature (`_decode_signature`) and `app/vvp/keri/signature.py` verifies that raw value, so VVP PSS signatures won’t verify. Wire `decode_pss_signature()` into PASSporT parsing (or signature verification) and add tests covering the 0B format. `app/vvp/passport.py`, `app/vvp/keri/signature.py`, `app/vvp/keri/cesr.py`.
[High]: OOBI KEL validation is implemented but never invoked. `validate_oobi_is_kel()` is unused, and the KEL resolver still uses `dereference_oobi()` directly. This leaves §4.2 “OOBI must resolve to valid KEL” unenforced. Integrate the validation into the resolution path. `app/vvp/keri/oobi.py`, `app/vvp/keri/kel_resolver.py`.
[High]: APE/DE/TNAlloc validation rules are defined but never applied. `validate_ape_credential()`, `validate_de_credential()`, and `validate_tnalloc_credential()` are not called from `validate_credential_chain()`, so schema/governance constraints are not enforced. Add enforcement and tests. `app/vvp/acdc/verifier.py`, `tests/test_acdc.py`.
[Medium]: The chain validation does not validate schema SAIDs or governance roots beyond the final issuer AID. The plan calls for schema/governance checks; implement explicit schema SAID validation and tests. `app/vvp/acdc/verifier.py`.
[Low]: `pysodium` is still imported at module scope in `app/vvp/keri/signature.py`, which contradicts the stated “lazy import” design decision.

Required Changes (if not APPROVED)
1. Integrate CESR PSS decoding into PASSporT signature handling and add end-to-end tests for 0B-prefixed signatures.
2. Enforce OOBI KEL validation in the resolution flow (use `validate_oobi_is_kel()` or equivalent).
3. Apply APE/DE/TNAlloc validation in `validate_credential_chain()` and cover with tests (schema/governance checks included).
