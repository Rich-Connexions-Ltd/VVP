# Phase 1: Scope & Baseline - Findings

## Review Boundaries

### In-Scope

| Area | Files | LOC |
|------|-------|-----|
| **Verifier service** | 118 .py files | 21,692 app / 28,696 tests |
| **Issuer service** | 51 .py files | 10,024 app / 5,815 tests |
| **Common module** | 14 .py files | 1,091 |
| **Integration tests** | 19 .py files | (included in test counts) |
| **Documentation** | 61 .md files | N/A |

**Total Python files:** 203
**Total application LOC:** ~32,807
**Total test LOC:** ~34,511

### Out-of-Scope

- `keripy/` - Vendored KERI library (external code)
- `venv/`, `.venv/` - Virtual environments
- `__pycache__/` - Compiled Python

---

## Tooling Inventory

| Tool | Status | Notes |
|------|--------|-------|
| **Type checking (pyright/mypy)** | ❌ Not configured | No pyrightconfig.json, mypy.ini, or pyproject.toml sections |
| **Linting (ruff/flake8)** | ❌ Not configured | No ruff.toml or pyproject.toml sections |
| **Formatting (black/ruff)** | ❌ Not configured | No configuration found |
| **Pre-commit hooks** | ❌ Not configured | No .pre-commit-config.yaml |

---

## Architecture References

The following documents define the system architecture:

1. **[SYSTEM_OVERVIEW.md](SYSTEM_OVERVIEW.md)** - High-level architecture, component mapping, data flows
2. **[VVP_Verifier_Specification_v1.5.md](Documentation/VVP_Verifier_Specification_v1.5.md)** - Authoritative specification (47KB)
3. **[PLAN_VVP_Issuer_Infrastructure.md](Documentation/PLAN_VVP_Issuer_Infrastructure.md)** - Issuer architecture (22KB)
4. **[CLAUDE.md](CLAUDE.md)** - Development workflow and permissions

---

## Baseline Metrics Summary

```
┌────────────────────────────────────────────────────────────┐
│                    VVP Codebase Baseline                   │
├────────────────┬───────────┬──────────────┬───────────────┤
│ Service        │ Py Files  │ App LOC      │ Test LOC      │
├────────────────┼───────────┼──────────────┼───────────────┤
│ Verifier       │ 118       │ 21,692       │ 28,696        │
│ Issuer         │ 51        │ 10,024       │ 5,815         │
│ Common         │ 14        │ 1,091        │ -             │
│ Integration    │ 19        │ -            │ (shared)      │
├────────────────┼───────────┼──────────────┼───────────────┤
│ TOTAL          │ 203       │ 32,807       │ 34,511        │
└────────────────┴───────────┴──────────────┴───────────────┘

Documentation: 61 markdown files
Tooling: None configured (type checking, linting, formatting, pre-commit)
```

---

## Findings Registry

This section is populated as phases complete. Each phase adds findings here to enable de-duplication in Phase 11.

| Phase | Blocking | High | Medium | Low | Status |
|-------|----------|------|--------|-----|--------|
| 1. Baseline | 0 | 0 | 0 | 0 | Completed |
| 2. Type Safety | 0 | 2 | 3 | 2 | Completed |
| 3. Architecture | 0 | 2 | 3 | 1 | Completed |
| 4. Redundancy | 0 | 3 | 4 | 3 | Completed |
| 5. Code Quality | 0 | 2 | 5 | 2 | Completed |
| 6. Security | 1 | 0 | 5 | 2 | Completed |
| 7. Internal Docs | 0 | 2 | 3 | 2 | Completed |
| 8. Developer Docs | 0 | 4 | 4 | 2 | Completed |
| 9. Doc Consistency | 0 | 2 | 2 | 14 | Completed |
| 10. Test Coverage | 1 | 5 | 4 | 3 | Completed |
| **TOTAL** | **2** | **22** | **33** | **31** | |

*Note: Severity reclassified per Reviewer guidance - "Blocking" reserved for security/data loss/outage risks only.*

---

## Phase 9: Documentation Consistency Review - Findings (Revised)

### 1. Docs vs Code Alignment - With Evidence

#### BLOCKING: README.md Path References

**Evidence - Broken Links:**

| Line | Current (Broken) | Correct Path | File Exists |
|------|------------------|--------------|-------------|
| 19 | `app/Documentation/VVP_Verifier_Documentation.md` | `Documentation/VVP_Verifier_Documentation.md` | ✓ Verified |
| 106 | `app/Documentation/VVP_Verifier_Documentation.md` | `Documentation/VVP_Verifier_Documentation.md` | ✓ Verified |
| 107 | `app/Documentation/VVP_Verifier_Specification_v1.5.md` | `Documentation/VVP_Verifier_Specification_v1.5.md` | ✓ Verified |
| 108 | `app/Documentation/VVP_Implementation_Checklist.md` | `Documentation/VVP_Implementation_Checklist.md` | ✓ Verified |
| 109 | `app/Documentation/CREATING_DOSSIERS.md` | `Documentation/CREATING_DOSSIERS.md` | ✓ Verified |

**Root Cause:** Monorepo refactoring moved `app/Documentation/` to root `Documentation/` but README.md links not updated.

#### HIGH: Python Version Mismatch

**Evidence:**

| File | Line | States | Authoritative? |
|------|------|--------|----------------|
| `services/verifier/pyproject.toml` | 4 | `requires-python = ">=3.12"` | ✓ **AUTHORITATIVE** |
| `services/issuer/pyproject.toml` | 5 | `requires-python = ">=3.12"` | ✓ **AUTHORITATIVE** |
| `README.md` | 25 | "Python 3.12 or higher" | ✓ Correct |
| `Documentation/DEVELOPMENT.md` | 8 | "Python 3.10+" | ✗ **INCORRECT** |

**Authoritative Source:** Both `pyproject.toml` files (verifier line 4, issuer line 5) require Python 3.12+.

### 2. Terminology Inconsistencies

**Reference Document:** `Documentation/GLOSSARY.md` (exists, 50+ lines defining canonical terms)

| Term | GLOSSARY Definition | Variations in Docs | Standard to Use |
|------|--------------------|--------------------|-----------------|
| ACDC | Line 14: "Authentic Chained Data Container" | "credential", "cred", "ACDC" | "ACDC" (technical), "credential" (user-facing) |
| AID | Line 21: "Autonomic Identifier" | "identifier", "identity", "AID" | "AID" in technical context |
| Dossier | Line 49: "DAG of ACDCs" | "credential bundle", "dossier" | "dossier" per GLOSSARY |

**Note:** GLOSSARY.md at `Documentation/GLOSSARY.md` defines canonical terms and should be the authoritative reference.

### 3. Contradictions - With Evidence

#### Spec Version Reference

| File | Line | States | Authoritative? |
|------|------|--------|----------------|
| `Documentation/VVP_Implementation_Checklist.md` | 4 | `Specification Version: v1.4 FINAL` | ✗ Outdated |
| `Documentation/VVP_Verifier_Specification_v1.5.md` | (filename) | v1.5 | ✓ **AUTHORITATIVE** |
| `CLAUDE.md` | 490 | "Authoritative spec: Documentation/VVP_Verifier_Specification_v1.5.md" | ✓ Confirms v1.5 |

**Authoritative Source:** `CLAUDE.md` line 490 explicitly states v1.5 is authoritative.

### 4. Summary (Revised)

| Category | Count | Severity | Evidence Provided |
|----------|-------|----------|-------------------|
| Path alignment issues | 5 links | 1 Blocking | Line-by-line table above |
| Python version mismatch | 1 file | 1 High | pyproject.toml authoritative source |
| Spec version mismatch | 1 file | 1 Medium | CLAUDE.md authoritative source |
| Terminology inconsistencies | 3 terms | Medium | GLOSSARY.md reference |
| Language/style issues | ~8 instances | Low | Scattered, non-blocking |
| **TOTAL** | **~18 issues** | 1 Blocking, 1 High, 2 Medium, ~14 Low |

### Files Requiring Updates (Revised)

| Priority | File | Line(s) | Change Required | Authoritative Source |
|----------|------|---------|-----------------|---------------------|
| BLOCKING | `README.md` | 19, 106-109 | Change `app/Documentation/` → `Documentation/` | File system structure |
| HIGH | `Documentation/DEVELOPMENT.md` | 8 | Change "Python 3.10+" → "Python 3.12+" | `services/*/pyproject.toml` |
| MEDIUM | `Documentation/VVP_Implementation_Checklist.md` | 4 | Update "v1.4 FINAL" → "v1.5" | `CLAUDE.md:490` |

---

## Acceptance Criteria

- [x] Scope boundaries documented (in-scope/out-of-scope)
- [x] Baseline metrics captured (file counts, LOC)
- [x] Tooling inventory complete
- [x] Architecture references listed
- [x] Findings registry initialized

---

# Phase 1 Review Verdict

**Verdict:** APPROVED

## Review Notes

### Scope Boundaries
The in-scope/out-of-scope boundaries are appropriate and match the stated plan. Excluding `keripy/` and virtualenv artifacts is reasonable.

### Metrics Reasonableness
The file counts and LOC totals are internally consistent across the summary and table. The test LOC exceeds app LOC, which is plausible for an integration-heavy repo.

### Architecture References
References cover the main system overview, verifier spec, and issuer plan. Consider adding `SYSTEM.md` if it contains architectural or operational details, but this is not blocking.

### Findings Registry Format
The registry format is clear and ready for parallel phase aggregation. Phase 1 status could be marked **Completed** now that acceptance criteria are met, but this is optional.

## Phase 9 Review Verdict

**Verdict:** CHANGES_REQUESTED

### Assessment
The findings are plausible and align with known doc drift patterns, but they are not yet reviewable as written because they lack verifiable evidence (file paths and exact locations). To validate accuracy and completeness, each item needs a precise reference and (for version requirements) a source of truth from code/config.

### Findings
- [High]: Evidence missing for the reported blocking/high items (broken README link target, Python version requirement). Provide file paths and line references so the reviewer can confirm.
- [Medium]: Terminology inconsistencies and spec version references likely valid but need concrete examples with exact doc locations and the authoritative source for the correct term/version.
- [Low]: Style/language issues are acceptable but should be grouped with examples to avoid subjective drift.

### Required Changes (if CHANGES_REQUESTED)
1. Add file/line references for each of the 22 issues (at least for all blocking/high/medium) and include the authoritative source for the “correct” value (e.g., pyproject/tooling docs for Python version, spec file for v1.5).
2. Confirm the README link issue by listing the exact broken link(s) and intended target(s).
3. For terminology inconsistencies, provide a short glossary or reference doc that defines the standard terms used for comparison.

## Phase 9 Re-Review Verdict

**Verdict:** APPROVED

### Evidence Assessment
The added line references and authoritative sources are sufficient to verify the key issues. The README link breakage is now traceable to specific lines, the Python version mismatch is backed by `pyproject.toml`, terminology standards are anchored to `Documentation/GLOSSARY.md`, and the spec version authority is clearly cited.

### Severity Validation
The severity classifications are reasonable: the broken README links can block onboarding, the Python version mismatch is a high‑impact setup risk, the terminology/spec reference issues are medium, and the remaining language/style items are low.

---

# Phase 11: Remediation Planning

## Consolidated Findings Summary

All 10 review phases are complete. This section consolidates findings into an actionable remediation backlog.

**Total Issues by Severity (Revised):**

| Severity | Count | Action |
|----------|-------|--------|
| **Blocking** | 2 | Must fix before release (security/data loss/outage) |
| **High** | 22 | Fix in current sprint |
| **Medium** | 32 | Plan for next sprint |
| **Low** | 31 | Backlog |
| **TOTAL** | **87** | |

---

## Blocking Issues (Security/Data Loss/Outage Risk Only)

| ID | Phase | Issue | File(s) | Effort | Risk |
|----|-------|-------|---------|--------|------|
| B1 | 6 | Open redirect in OAuth | `api/auth.py` line 444 | S | Security |
| B2 | 10 | Issuer persistence not tested | `app/keri/persistence.py` | M | Data loss |

**Note:** Per Reviewer guidance, "Blocking" is reserved for security, data loss, or outage risks. Documentation issues reclassified to High/Medium.

---

## High Priority Issues (Fix in Current Sprint)

### Reclassified from Blocking (Documentation/Quality)
| ID | Issue | File(s) | Effort | Rationale |
|----|-------|---------|--------|-----------|
| H1 | Broken README.md links | `README.md` lines 19, 106-109 | S | Onboarding impact |
| H2 | Missing service READMEs | `services/verifier/`, `services/issuer/`, `common/` | M | Onboarding impact |
| H3 | No coverage thresholds | `pyproject.toml` | S | Quality gate |

### Type Safety (Phase 2)
| ID | Issue | File | Effort |
|----|-------|------|--------|
| H4 | `_query_registry_tel()` missing return type | `verify.py` | S |
| H5 | Module functions missing return types | `identity.py` | S |

### Architecture (Phase 3)
| ID | Issue | File | Effort |
|----|-------|------|--------|
| H6 | Verifier main.py "god module" (2,132 LOC) | `services/verifier/app/main.py` | L |
| H7 | Issuer admin.py "god module" (1,234 LOC) | `services/issuer/app/api/admin.py` | L |

### Redundancy (Phase 4)
| ID | Issue | File(s) | Effort |
|----|-------|---------|--------|
| H8 | TELClient timeout hardcoded 5x | `verify.py` lines 906, 1171, 1336, 1552, 1927 | S |
| H9 | 4 duplicate cache implementations | `keri/cache.py`, `dossier/cache.py`, etc. | L |
| H10 | SAID function proliferation (5+ functions) | `keri/kel_parser.py`, `acdc/parser.py` | M |

### Code Quality (Phase 5)
| ID | Issue | File(s) | Effort |
|----|-------|---------|--------|
| H11 | 46+ broad `except Exception` blocks | Issuer API modules | M |
| H12 | Witness publishing error swallowing | `credential.py:80-82` | S |

### Internal Docs (Phase 7)
| ID | Issue | File | Effort |
|----|-------|------|--------|
| H13 | Witness consensus TODO undocumented | `keri/oobi.py` | S |
| H14 | TEL timing workaround undocumented | `acdc/verifier.py` | S |

### Developer Docs (Phase 8)
| ID | Issue | File(s) | Effort |
|----|-------|---------|--------|
| H15 | Missing API reference documentation | New `API_REFERENCE.md` | M |
| H16 | Missing RBAC/auth policy docs | New `AUTH_AND_ROLES.md` | M |

### Documentation Consistency (Phase 9)
| ID | Issue | File | Effort |
|----|-------|------|--------|
| H17 | Python version mismatch | `Documentation/DEVELOPMENT.md` line 8 | S |

### Test Coverage (Phase 10)
| ID | Issue | File(s) | Effort |
|----|-------|---------|--------|
| H18 | Issuer auth roles not tested | `app/auth/roles.py` | M |
| H19 | Audit logging not tested | `app/audit/logger.py` | M |
| H20 | Timing-dependent tests (flaky) | `test_kel_cache.py`, `test_session.py` | S |
| H21 | Skipped non-transferable identity test | `test_identity.py:37` | M |

---

## Medium Priority Issues (Plan for Next Sprint)

### Reclassified from Blocking (Low Impact)
- M0: Outdated ROADMAP.md (causes confusion but not release-blocking)

### Type Safety
- M1: Untyped generic `dict` parameters → `dict[str, Any]`
- M2: Heavy `Any` usage in passport/ACDC parsing (156 instances, justified but could tighten)
- M3: Property methods without explicit return types

### Architecture
- M4: Auth.py combines session + OAuth concerns
- M5: Credential_viewmodel.py size (2,025 LOC)
- M6: Document verifier subsystem responsibilities

### Redundancy
- M7: HTTPException handling duplication (65 occurrences)
- M8: Cache TTL values scattered (300s appears 6+ times)
- M9: BCRYPT_COST_FACTOR duplicated
- M10: Complex conditionals need comments

### Code Quality
- M11: Hard-coded `/data/vvp-issuer` path
- M12: Sparse debug logging
- M13: HTTPException detail messages too generic
- M14: 34 `except Exception` in verifier main.py
- M15: Consider circuit breaker for external services

### Security
- M16: Missing HTTP security headers (X-Frame-Options, etc.)
- M17: Plaintext dev keys in repository (`dev-keys.txt`)
- M18: Session store not distributed (single-instance)
- M19: Loose version pinning for security libraries
- M20: Admin endpoint enabled by default

### Internal Docs
- M21: Schema resolution flow needs diagram
- M22: Verification orchestration flow needs diagram
- M23: Config dependency table needed

### Developer Docs
- M24: Missing troubleshooting guide
- M25: Missing database/LMDB documentation
- M26: Missing contributing guide

### Documentation Consistency
- M27: Spec version reference update (`v1.4` → `v1.5`)
- M28: Terminology standardization across docs

### Test Coverage
- M29: Schema store tests
- M30: API admin module coverage
- M31: Dossier format coverage
- M32: Coverage report generation in CI

---

## Effort Key

| Size | Description | Time Estimate |
|------|-------------|---------------|
| **S** | Small | < 2 hours |
| **M** | Medium | 2-4 hours |
| **L** | Large | 4-8 hours |
| **XL** | Extra Large | 1-2 days |

---

## Recommended Sprint Allocation (Revised)

### Sprint 38 (Current - Blocking + Critical High)

**Must Complete (True Blockers):**
1. B1: Fix OAuth open redirect (S) - **Security risk**
2. B2: Create issuer persistence tests (M) - **Data loss risk**

**Should Complete (Top High Priority):**
3. H1: Fix README.md broken links (S)
4. H3: Add coverage thresholds (S)
5. H8: Extract TELClient timeout to config (S)
6. H17: Fix Python version in DEVELOPMENT.md (S)

**Stretch Goals:**
7. H13-H14: Document TODOs (S each)

**Estimated Sprint Capacity:** 1-2 days focused remediation

### Sprint 39 (High Priority Remainder)

**Focus Areas:**
1. H2: Create service READMEs (M each × 3)
2. H6-H7: Plan god module refactoring (design only)
3. H15-H16: Create API reference and auth docs
4. H18-H21: Test coverage gaps

### Sprint 40+ (Medium Priority)

**Focus Areas:**
1. Security hardening (M16-M20)
2. Error handling improvements (H11, M7)
3. Documentation diagrams (M21-M23)
4. Developer documentation (M24-M26)

---

## Verification Approach

After remediation, verify each fix:

| Fix Category | Verification Method |
|--------------|---------------------|
| Documentation | Manual review + link checker |
| Type safety | `pyright --outputjson` |
| Security | Manual + `pip audit` |
| Tests | `pytest --cov --cov-fail-under=70` |
| Architecture | Code review |

---

## Phase 11 Acceptance Criteria

- [x] All findings consolidated from Phases 2-10
- [x] De-duplication applied (overlapping issues merged)
- [x] Severity tiers assigned (Blocking/High/Medium/Low)
- [x] Effort estimates provided (S/M/L/XL)
- [x] Sprint allocation recommended
- [x] Verification approach defined

## Phase 11 Review Verdict

**Verdict:** CHANGES_REQUESTED

### Consolidation Assessment
The consolidation appears complete and organized, with counts matching the stated totals and a clear de‑duplication pass. The backlog structure and verification approach are usable. However, several severity assignments look inconsistent with the blocking criteria and should be corrected before approval.

### Sprint Allocation
Sprint 38 scope is reasonable for 2–3 days if limited to truly blocking/high items. As written, it mixes blocking, high, and documentation tasks that likely exceed the stated capacity unless work is tightly scoped.

### Recommendations
- Reclassify B1 (missing service READMEs) and B2 (outdated ROADMAP) from **Blocking** to **High/Medium** unless there is a release gate requiring them. Blocking should be limited to security, data loss, or outage risks per the plan.
- Consider moving B5 (coverage thresholds) to **High** unless release policy explicitly mandates thresholds.
- Keep B3 (broken README links) as **High**; it impacts onboarding but is not typically release‑blocking.
- Ensure Sprint 38 includes only blocking + top highs to match the 2–3 day estimate.

## Phase 11 Re-Review Verdict

**Verdict:** APPROVED

### Severity Assessment
The revised severity scheme aligns with the stated blocking criteria. Limiting blocking to the OAuth open redirect and issuer persistence testing is appropriate; documentation and coverage policy items are now correctly classified as high/medium.

### Sprint Allocation
The revised Sprint 38 scope is reasonable for a 1–2 day window, focusing on the two blockers plus a small set of top‑priority highs. The scope now matches the stated capacity.

## Plan Review: Sprint 40 - Vetter Certification Constraints

**Verdict:** CHANGES_REQUESTED

### Spec Compliance
The plan captures the three core checks from the spec (ECC targets for TN, jurisdiction targets for identity/brand) and the idea that outcomes are status bits for client interpretation. However, two spec‑critical points need tightening: (1) the spec explicitly says each credential (Identity, Brand, TN) contains a backlink edge to the Vetter Certification; this should be treated as required, not optional; and (2) the plan’s default `VVP_ENFORCE_VETTER_CONSTRAINTS=true` makes violations hard failures by default, which conflicts with the spec guidance that these are status bits the client decides how to treat.

### Schema Assessment
The proposed Vetter Certification schema aligns with the spec’s two fields (ECC Targets, Jurisdiction Targets). The credential backlink edge on TN/Identity/Brand is consistent with the spec’s “each credential contains an edge” requirement, so Option A should be the definitive path. The proposed `country` field for Legal Entity is reasonable if that is the source of incorporation country used by the Identity credential; otherwise, the plan should clarify where incorporation country is read from and ensure it is ISO 3166‑1 as required by the spec (the plan currently assumes alpha‑3 without confirming the spec’s code format).

### Design Assessment
The module structure and claim‑tree integration are reasonable, and the status‑bit approach is aligned with the spec’s enforcement model. The configurable enforcement is acceptable if default behavior remains non‑blocking and only the client decides hard failure. Brand assertion country derived from TN country code is consistent with the example in the spec, but should be explicitly justified as the intended interpretation.

### Findings
- [High]: Option A (credential backlink edges) is spec‑mandated; keeping Option B as an alternative risks violating the spec. The plan should require backlink edges on Identity/Brand/TN credentials.
- [High]: Default enforcement as hard failure (`VVP_ENFORCE_VETTER_CONSTRAINTS=true`) conflicts with spec guidance that these are status bits for client interpretation. Default should be non‑blocking with explicit client enforcement.
- [Medium]: Jurisdiction code format is assumed to be ISO 3166‑1 alpha‑3; the spec only states ISO 3166‑1. Clarify whether alpha‑2 vs alpha‑3 is required and align schemas/tests accordingly.
- [Low]: Brand assertion country derivation should be justified in the plan text to avoid ambiguity (e.g., “derived from destination TN country code per spec example”).

### Required Changes (if CHANGES_REQUESTED)
1. Make Option A (credential backlink edges) the required approach and remove Option B as a fallback, or explicitly mark Option B as non‑compliant with the spec.
2. Change default enforcement so violations are surfaced as status bits without hard failure unless explicitly enabled by clients/config; update claim tree semantics accordingly.
3. Clarify the ISO 3166‑1 code format (alpha‑2 vs alpha‑3) and align `jurisdiction_targets`/`country` field patterns and tests to the chosen format.

### Recommendations
- Add a short rationale for deriving brand assertion country from TN country code (cite the spec example) to reduce interpretation risk.
- Consider a small glossary/enum for credential types (Identity/Brand/TN) in the API model to avoid ambiguity in responses.

## Plan Re-Review: Sprint 40 - Vetter Certification Constraints

**Verdict:** APPROVED

### Changes Assessment
All required changes are addressed: credential backlink edges are now required per spec, enforcement defaults to non‑blocking with status bits, ISO 3166‑1 alpha‑3 is explicitly specified with examples, and the brand assertion country derivation is justified using the spec’s UK call example.

### Remaining Findings (if any)
- None.

## Code Review: Sprint 40 - Vetter Certification Constraints

**Verdict:** CHANGES_REQUESTED

### Spec Compliance
Partially compliant. The core ECC and jurisdiction checks are implemented and status bits are returned, but the verifier still resolves certifications without a required `certification` edge and accepts alternate edge names. This undermines the spec requirement that each Identity/Brand/TN credential contains a backlink edge to the vetter certification. Also, the brand constraint cannot be issued in a spec‑compliant way because the extended Brand schema with required certification edge is missing.

### Implementation Assessment
The vetter constraint module is structured and integrated into verification with non‑blocking default enforcement, which matches the approved plan. However, there are plan gaps: external certification resolution is configured but not implemented, and the brand schema extension deliverable is missing. Credential type detection in `verify.py` is heuristic and may skip brand or identity constraints for schemas that don’t match the expected attribute keys.

### Code Quality
Code is readable and well‑documented, with clear dataclasses and helper functions. Error handling is reasonable, but the traversal fallback logic contradicts the spec requirement and could produce false positives. Also, unused config (`VVP_VETTER_CERT_EXTERNAL_RESOLUTION`) adds dead‑path complexity.

### Test Coverage
Unit tests cover ECC/jurisdiction logic and parsing. Coverage is thin for verifier integration: no tests assert the required backlink edge behavior, no tests for ENFORCE=false vs ENFORCE=true claim propagation, and no tests for brand assertion country derivation using destination TN.

### UI Assessment
The vetter certification UI is usable and includes target selectors. The credential edge picker supports `certification` edges but doesn’t enforce required edges when issuing extended schemas. The jurisdiction selector renders with a “+” prefix (same as E.164) which is misleading for ISO alpha‑3 values.

### Findings
- [High]: Spec‑required certification edge can be bypassed. `find_vetter_certification` accepts alternate edge names and falls back to issuer‑AID matching even when no certification edge exists, allowing non‑compliant credentials to pass constraint checks. `services/verifier/app/vvp/vetter/traversal.py`.
- [High]: Missing extended Brand schema with required `certification` edge. Only TN and Legal Entity have extended schemas; brand credentials cannot be issued in a spec‑compliant way. `services/issuer/app/schema/schemas/`.
- [Medium]: `VVP_VETTER_CERT_EXTERNAL_RESOLUTION` is configured but never used; plan calls for external resolution when enabled. `services/verifier/app/core/config.py`.
- [Medium]: Credential type detection is heuristic and may skip or misclassify identity/brand credentials, causing constraints not to run for some schemas. `services/verifier/app/vvp/verify.py`.
- [Low]: UI edge picker doesn’t enforce required `certification` edges for extended schemas, and jurisdiction selectors display a “+” prefix. `services/issuer/web/credentials.html`, `services/issuer/web/vetter.html`.

### Required Changes (if not APPROVED)
1. Enforce spec‑required `certification` edges: remove fallback issuer‑AID matching and restrict edge lookup to the `certification` edge (or explicitly flag non‑compliant edge names as missing certification). Update tests to cover missing‑edge behavior.
2. Add the extended Brand schema with required `certification` edge (and update any schema registries/UI lists) so brand credentials can be issued in a spec‑compliant way.
3. Either implement `VVP_VETTER_CERT_EXTERNAL_RESOLUTION` or remove the config flag to avoid dead‑path behavior; add tests if implemented.

## Code Re-Review: Sprint 40 - Vetter Certification Constraints

**Verdict:** APPROVED

### Changes Assessment
All required changes are addressed. The issuer‑AID fallback has been removed in `traversal.py`, the extended Brand schema now exists with a required `certification` edge, and the unused `VVP_VETTER_CERT_EXTERNAL_RESOLUTION` flag has been removed from configuration. The additional improvements noted (assertionCountry extraction, improved credential classification, UI fix, and new tests) align with the approved plan.

### Findings (if any)
- None.

## Plan Review: Fix Issuer vs Issuee Identity Confusion

**Verdict:** CHANGES_REQUESTED

### Spec Compliance
The plan correctly distinguishes ACDC issuer (`i`) from issuee/subject (`a.i`/`a.issuee`) and treats attributes like `legalName`/`LEI` as describing the issuee. This aligns with ACDC/KERI semantics and the VVP verifier spec guidance about issuee binding.

### Design Assessment
Adding a role field and introducing explicit subject display on credential cards is the right direction. However, the plan defines a role value of "issuer" but never assigns it, leaving issuer provenance ambiguous. The subject lookup uses `issuer_identities`, which remains a misleading name and can still cause confusion unless a clearer alias or documentation is added.

### Findings
- [Medium]: The plan defines `role="issuer"` but never sets it; issuer identities will remain unlabeled or only show as `wellknown`. This undermines the goal of clarifying provenance.
- [Low]: `issuer_identities` remains a confusing name once it stores both subject and well‑known identities; consider adding an alias or docstring to clarify usage.

### Answers to Open Questions
1. Should `issuer_identities` be renamed to `resolved_identities`?
   - Yes, long‑term. For backward compatibility, keep `issuer_identities` but add an alias (e.g., `resolved_identities`) and update internal usage/documentation.
2. Should role values use different terminology?
   - Prefer `issuee` (spec term) over `subject`. Suggested set: `issuee`, `issuer`, `wellknown`. If you keep `subject`, document it explicitly as synonym of `issuee`.

### Required Changes (if CHANGES_REQUESTED)
1. Define and implement how `role="issuer"` is populated (e.g., when identity is derived from a credential whose `i` matches the identity AID, or when a well‑known registry record is used specifically to label the issuer).
2. Add at least one test that asserts issuer role labeling in the API response or UI view model.

### Recommendations
- Add a short docstring or type alias clarifying that the identity map is a "resolved identities" cache keyed by AID, not strictly issuer identities.
- Consider including both `issuer_identity` and `subject_identity` objects in the API to avoid client confusion.

## Plan Review: Enhanced Chain Resolution with Multiple Roots

**Verdict:** CHANGES_REQUESTED

### Architecture Assessment
Supporting multiple roots via `root_aids: Set[str]` and per‑root `trust_paths_valid` is the right direction for dossiers with independent trust hierarchies. The graph changes preserve existing node/edge modeling and keep the multi‑root data localized to the graph structure.

### Backwards Compatibility
The compatibility properties (`root_aid`, `trust_path_valid`) are reasonable, but `root_aid` derived from a set is non‑deterministic. UI consumers and tests will see unstable values across runs. A deterministic selection strategy (sorted list or priority order) is needed.

### API Surface Changes
Adding `rootAids` and `trustPathsValid` is appropriate. However, serializing a set directly into a list without ordering will produce unstable output, which is problematic for UI diffing and caching. The response should use a stable ordering.

### Findings
- [Medium]: `root_aid` and `rootAids` are derived from a `Set`; ordering is non‑deterministic. This can lead to flaky UI/JSON comparisons and inconsistent legacy behavior.
- [Low]: `trust_paths_valid` only tracks trusted roots. Consider clarifying in API docs that untrusted issuer “roots” are not included, or include a separate list for terminal issuers to avoid confusion.

### Required Changes (if CHANGES_REQUESTED)
1. Make `root_aid` deterministic (e.g., `sorted(self.root_aids)[0]` or priority order) and ensure `rootAids` is emitted in a stable order.
2. Add a test that asserts deterministic `root_aid`/`rootAids` ordering and covers the no‑trusted‑roots case.

### Recommendations
- Consider including `terminalIssuers` (untrusted roots) in the API response so UIs can show all chain termini.
- Document that `trustPathsValid` is keyed only by trusted roots and how it should be interpreted by UI consumers.

## Plan Re-Review: Enhanced Chain Resolution with Multiple Roots

**Verdict:** APPROVED

### Changes Assessment
The deterministic ordering change (sorted `root_aids` with helper insertion), the addition of `terminal_issuers`, and the new tests directly address the prior concerns. API output is now stable, backward compatibility remains intact, and the docstrings clarify how `trustPathsValid` should be interpreted.

### Findings (if any)
- None.

## Plan Review: Deep vLEI Chain Resolution

**Verdict:** CHANGES_REQUESTED

### Design Assessment
The plan’s async, eager resolution approach is directionally sound given the need to fetch credentials from witnesses and to complete multi‑hop vLEI chains. Using existing resolver infrastructure is appropriate, and adding resolution metadata to the graph is a good fit. However, several spec‑alignment and implementation details are underspecified, which risks resolving or validating the wrong chain.

### Findings
- [High]: Chain validation is keyed to `credential_type == "QVI"`, but vLEI verification should be driven by schema SAIDs (QVI, LE, OOR/ECR auth, etc.) rather than inferred type strings. The vLEI spec defines concrete schemas for QVI/LE/OOR/ECR credentials, and the plan should bind validation to those normative schema identifiers. citeturn7view0
- [Medium]: The vLEI chain structure is richer than “QVI→LE”; OOR/ECR credentials have authorization credentials (OOR/ECR Auth) in their sources/edges per the vLEI credential set. The plan’s edge list (`qvi`, `le`, `auth`) needs to be explicitly mapped to the actual vLEI schema edge names and source references. citeturn7view0
- [Medium]: Eager resolution can become a latency spike without concurrency limits, caching policy, and a per‑request budget. The plan references TTL caching but doesn’t specify how it’s applied to this new resolution path.
- [Low]: `chain_complete` semantics aren’t defined for partial success (some edges resolved, others missing). That makes UI/consumer interpretation ambiguous.

### Required Changes (if CHANGES_REQUESTED)
1. Replace `credential_type == "QVI"` checks with schema‑SAID‑based validation using the normative vLEI schema IDs (QVI, LE, OOR/ECR Auth, OOR/ECR). Add explicit mapping of edge names/sources expected per schema. citeturn7view0
2. Define and implement resolution policy: concurrency limit, timeout, cache usage, and maximum total fetch budget per verification. Include how failures map to `INDETERMINATE` vs `INVALID` consistently.
3. Specify `chain_complete` semantics and how it should behave when only some edges resolve or when untrusted roots are present.

### Recommendations
- Provide a small decision table documenting how each vLEI credential type contributes to chain completion (e.g., LE requires QVI; OOR/ECR require OOR/ECR Auth; each must chain back to GLEIF QVI root). citeturn7view0
- Consider a lazy‑resolution fallback (resolve only when UI expands a node) if eager resolution causes unacceptable latency in practice.

## Plan Re-Review: Deep vLEI Chain Resolution (v2)

**Verdict:** CHANGES_REQUESTED

### Changes Assessment
The updated plan addresses the prior feedback substantially: schema‑SAID validation replaces credential_type heuristics, explicit edge mappings are documented, concurrency/budget limits are added, and chain semantics are clarified with `chain_complete` + `root_reached`. Overall direction is sound. One remaining spec‑alignment issue: the plan uses the GLEIF root AID as the QVI schema SAID in the mapping table, which appears incorrect (issuer AID ≠ schema SAID). This can misclassify QVI credentials during validation and must be corrected.

### Findings (if any)
- [High]: `VLEI_SCHEMA_SAIDS["QVI"]` is set to the GLEIF root AID (`EBfdlu8R...`), but schema SAIDs and issuer AIDs are different identifiers. The mapping should use the normative QVI schema SAID, not the root AID. This breaks schema‑SAID validation and edge resolution. citeturn7view0

### Required Changes (if CHANGES_REQUESTED)
1. Replace the QVI schema SAID in `VLEI_SCHEMA_SAIDS` with the actual normative QVI schema SAID from the vLEI registry, and update any dependent constants/tests accordingly. citeturn7view0
