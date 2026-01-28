# Sprint 19: Callee Verification (Phase 12) + Sprint 18 Fixes

## Problem Statement

The VVP Verifier currently supports only caller verification (§5A). The spec defines a parallel callee verification algorithm (§5B) with 14 steps that validates the called party's identity and rights. Without this, the verifier cannot support bidirectional verification in VVP call flows.

Additionally, Sprint 18 code review identified three configuration/logic issues that need fixing.

## Spec References

- §5B: Callee Verification Algorithm (14 steps)
- §5.2-2.1: Dialog Matching (call-id, cseq)
- §5.2-2.9: Issuer Verification (dossier issuer matches kid)
- §5.2-2.12: Phone Number Rights (callee TN rights)
- §4.2A: Error codes DIALOG_MISMATCH, ISSUER_MISMATCH

## Current State

- Caller verification (§5A) is 100% complete
- Phase 12 (Callee Verification) is 0% complete (15 items)
- Overall project is at 91% completion
- Existing infrastructure (passport parsing, KERI resolution, dossier validation, revocation checking, TN rights) can be reused
- **Sprint 18 code review identified 3 issues requiring fixes**

---

## Part A: Sprint 18 Code Review Fixes

### Issues from Code Review (CHANGES_REQUESTED)

#### A1. [High] CONTEXT_ALIGNMENT_REQUIRED not applied

**Problem:** `verify_sip_context_alignment()` always returns INDETERMINATE when SIP context is absent, even when `CONTEXT_ALIGNMENT_REQUIRED=True` in config.

**Fix:** Add `context_required` parameter to `verify_sip_context_alignment()`, maintaining the existing `ClaimBuilder` return type.

**Files:** `app/vvp/sip_context.py`, `app/vvp/verify.py`

#### A2. [Medium] SIP_TIMING_TOLERANCE_SECONDS not used

**Problem:** `verify_sip_context_alignment()` always uses default 30s instead of configured `SIP_TIMING_TOLERANCE_SECONDS`.

**Fix:** Pass config value through call chain (maintains ClaimBuilder pattern).

**Files:** `app/vvp/sip_context.py`, `app/vvp/verify.py`

#### A3. [Medium] DE selection uses first DE instead of signer's DE

**Problem:** `_find_de_credential()` returns first DE in dossier, not the DE from signer's delegation chain. This causes false positives/negatives for brand proxy and business constraints.

**Fix:** Pass signer AID and filter DEs by delegation chain.

**Files:** `app/vvp/verify.py`

---

## Part B: Phase 12 Callee Verification

### Approach

Create a new `verify_callee.py` module that implements §5B, reusing existing components where possible. The callee flow differs from caller in:

1. **Dialog matching** (new): call-id/cseq validation against SIP INVITE
2. **Issuer verification** (new): dossier issuer must match PASSporT kid
3. **TN rights context** (modified): validates callee can receive at the number
4. **Goal overlap** (new, optional): checks goal compatibility between caller and callee

### Claim Tree (per §3.3B)

```
callee_verified (root)
├── passport_verified (REQUIRED)
│   ├── dialog_matched (REQUIRED)
│   ├── timing_valid (REQUIRED)
│   └── signature_valid (REQUIRED)
├── dossier_verified (REQUIRED)
│   ├── structure_valid (REQUIRED)
│   ├── acdc_signatures_valid (REQUIRED)
│   ├── revocation_clear (REQUIRED)
│   └── issuer_matched (REQUIRED)
├── tn_rights_valid (REQUIRED)
├── brand_verified (REQUIRED when card present, else omitted)
└── goal_overlap_verified (REQUIRED when both goals present, else omitted)
```

### New Error Codes

| Code | When | Status | Recoverable |
|------|------|--------|-------------|
| `DIALOG_MISMATCH` | call-id/cseq don't match SIP INVITE | INVALID | N |
| `ISSUER_MISMATCH` | dossier issuer != passport kid | INVALID | N |

## Files Created/Modified

### Part A: Sprint 18 Fixes

| File | Action | Purpose |
|------|--------|---------|
| `app/vvp/sip_context.py` | Modify | Add `context_required` and `timing_tolerance` parameters |
| `app/vvp/verify.py` | Modify | Pass config values to SIP alignment, fix DE selection for signer chain |
| `tests/test_verify.py` | Modify | Add tests for config-driven behavior |

### Part B: Phase 12 Callee Verification

| File | Action | Purpose |
|------|--------|---------|
| `app/vvp/verify_callee.py` | Create | Callee verification module (~850 lines) |
| `app/vvp/api_models.py` | Modify | Add VerifyCalleeRequest, DIALOG_MISMATCH/ISSUER_MISMATCH error codes |
| `app/vvp/goal.py` | Modify | Add goal overlap validation function (subset check) |
| `app/main.py` | Modify | Add POST /verify-callee endpoint |
| `tests/test_verify_callee.py` | Create | Unit tests for callee verification (70+ tests) |
| `tests/test_models.py` | Modify | Update error code count to include new codes |
| `app/Documentation/VVP_Implementation_Checklist.md` | Modify | Mark Phase 12 complete |

## Sprint Scope

### Part A: Sprint 18 Fixes (3 items)
- A1: [High] Plumb `CONTEXT_ALIGNMENT_REQUIRED` into `verify_sip_context_alignment()`
- A2: [Medium] Plumb `SIP_TIMING_TOLERANCE_SECONDS` into `verify_sip_context_alignment()`
- A3: [Medium] Fix DE selection to use signer's delegation chain DE

### Part B: Phase 12 Callee Verification (all 15 items)
- 12.1: Create verify_callee.py module
- 12.2: Dialog matching (call-id, cseq)
- 12.3: Timing alignment (iat validation)
- 12.4: Expiration analysis (exp policy)
- 12.5: Key identifier extraction (kid)
- 12.6: Signature verification
- 12.7: Dossier fetch and validation
- 12.8: Issuer verification (dossier issuer == kid)
- 12.9: Revocation status check
- 12.10: Phone number rights (callee receiving)
- 12.11: Brand attributes verification (REQUIRED when card present)
- 12.12: Goal overlap verification (REQUIRED when both goals present)
- 12.13: Add POST /verify-callee endpoint
- 12.14: Unit tests
- 12.15: Unknown claims in passport ignored (per VVP §4.2)

---

## Implementation Notes

### Revision 1 Fixes (Post-Review)

The initial implementation received CHANGES_REQUESTED with three findings:

1. **[High] Callee TN rights validation not bound to accountable party**
   - Fixed: Rewrote `validate_callee_tn_rights()` to use `tn_utils` for proper E.164 validation and bind to accountable party (APE issuee)

2. **[High] Callee claim tree omits required timing_valid and signature_valid children**
   - Fixed: Added `timing_valid` and `signature_valid` claims under `passport_verified`
   - Fixed: Added `structure_valid` and `acdc_signatures_valid` claims under `dossier_verified`

3. **[Medium] validate_callee_tn_rights() doesn't validate E.164 formats**
   - Fixed: Now uses `tn_utils.parse_tn_allocation()` for proper validation

### Test Results

```
875 passed in 5.00s
```

## Review History

- **Initial Review**: CHANGES_REQUESTED (3 findings)
- **Revision 1 Review**: APPROVED

**Source**: [draft-hardman-verifiable-voice-protocol-04](https://datatracker.ietf.org/doc/html/draft-hardman-verifiable-voice-protocol-04)
