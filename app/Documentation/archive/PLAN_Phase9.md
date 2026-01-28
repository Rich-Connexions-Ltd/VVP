# Phase 9: VVP Verifier Specification v1.5

## Problem Statement

The VVP Verifier Specification v1.4 FINAL defines core verification infrastructure but lacks the complete verification algorithm as specified in the authoritative VVP draft specification §5. Without updating the specification:

1. Implementers cannot understand the complete 13-step caller verification algorithm
2. Implementers cannot understand the 14-step callee verification algorithm
3. The claim tree structure is incomplete (missing authorization, TNAlloc, brand, and business logic claims)
4. There is no guidance on caching strategies or historical verification
5. The Implementation Checklist v3.0 references phases (7-14) that have no normative backing

## Spec References

From `https://dhh1128.github.io/vvp/draft-hardman-verifiable-voice-protocol.html`:

- **§5.1.1-2.1 through §5.1.1-2.13**: Complete caller verification algorithm (13 steps)
- **§5.2-2.1 through §5.2-2.14**: Complete callee verification algorithm (14 steps)
- **§5.3**: Planning for Efficiency (caching, SAID-based validation sharing)
- **§5.4**: Historical Analysis (temporal verification capabilities)

## Current State

**VVP_Verifier_Specification_v1.4_FINAL.md** provides:
- Claim model and propagation rules (§3)
- API contracts (§4)
- PASSporT verification basics (§5)
- Dossier model (§6)
- KERI integration notes (§7)
- Basic verification pseudocode (§9)
- Test vectors structure (§10)

**Limitations:**
- No complete verification algorithm (only high-level pseudocode)
- No SIP contextual alignment requirements
- No authorization verification (TNAlloc, delegation)
- No brand/business logic verification
- No callee verification flow
- No caching/efficiency guidance
- Claim tree structure incomplete

## Proposed Solution

Create **VVP_Verifier_Specification_v1.5.md** that extends v1.4 with complete verification algorithms.

### Summary of Changes

| Section | Change Type | Description |
|---------|-------------|-------------|
| Status | Updated | Lists all changes from v1.4 |
| §2.1 | Updated | Architecture diagram includes SIP context and authorization |
| §3.3B | NEW | Complete claim tree structure for caller and callee |
| §4.1 | Updated | Request body includes `context.sip` object |
| §4.2A | Extended | 7 new error codes for authorization and context |
| §4.4 | NEW | SIP Context Fields normative section |
| §5A | NEW | 13-step Caller Verification Algorithm |
| §5B | NEW | 14-step Callee Verification Algorithm |
| §5C | NEW | Efficiency and Caching guidance |
| §5D | NEW | Historical Verification capabilities |
| §9 | Expanded | Full pseudocode for caller and callee verification |
| §10.2 | Expanded | 8 additional test vectors |
| §12 | NEW | Implementation Tiers (Tier 1/2/3) |
| Appendix A | NEW | Spec §5 Traceability Matrix |

### Detailed Changes

#### §3.3B: Complete Claim Tree Structure

Added normative claim tree structures for both caller and callee verification:

**Caller:**
```
caller_verified (root)
├── passport_verified (REQUIRED)
├── dossier_verified (REQUIRED)
├── authorization_valid (REQUIRED)
│   ├── party_authorized (REQUIRED)
│   └── tn_rights_valid (REQUIRED)
├── context_aligned (REQUIRED or OPTIONAL per policy)
├── brand_verified (OPTIONAL)
└── business_logic_verified (OPTIONAL)
```

**Why:** The v1.4 claim tree only showed a simple example. Implementers need the complete structure to build correct claim propagation.

#### §4.2A: Extended Error Code Registry

Added 7 new error codes:

| Code | Purpose |
|------|---------|
| CREDENTIAL_REVOKED | Credential in dossier has been revoked |
| CONTEXT_MISMATCH | SIP context does not match PASSporT claims |
| AUTHORIZATION_FAILED | Originating party not authorized |
| TN_RIGHTS_INVALID | TNAlloc credential does not match orig |
| BRAND_CREDENTIAL_INVALID | Brand credential does not support card claims |
| GOAL_REJECTED | Goal claim rejected by verifier policy |
| DIALOG_MISMATCH | call-id/cseq do not match SIP INVITE |

**Why:** The new verification steps require error codes to report failures. Mapping to existing codes would lose semantic precision.

#### §4.4: SIP Context Fields

New normative section defining the `context.sip` request object:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| from_uri | string | Yes | SIP From URI |
| to_uri | string | Yes | SIP To URI |
| invite_time | RFC3339 | Yes | Timestamp of SIP INVITE |
| cseq | integer | No | CSeq number (for callee) |

**Why:** §5.1.1-2.2 requires contextual alignment with SIP metadata. The API must accept this data.

#### §5A: Caller Verification Algorithm

Complete 13-step algorithm per VVP §5.1, including:
- Each step with spec reference
- MUST/MAY requirements
- Failure mapping to error codes
- Claim node affected by each step

**Why:** This is the core normative content from the VVP draft that was missing from v1.4.

#### §5B: Callee Verification Algorithm

Complete 14-step algorithm per VVP §5.2, including:
- Dialog matching (call-id, cseq)
- Issuer verification
- Goal overlap checking

**Why:** Callee verification is a distinct flow with different requirements than caller verification.

#### §5C: Efficiency and Caching

Guidance per VVP §5.3:
- Cache types (dossier, key state, revocation)
- Recommended TTLs
- Data sovereignty considerations

**Why:** Production deployments need caching to achieve acceptable performance.

#### §5D: Historical Verification

Capabilities per VVP §5.4:
- Verification at past reference times
- Fuzzy range handling
- Use cases (forensics, disputes, compliance)

**Why:** Historical verification is a key VVP capability that enables post-incident analysis.

#### §12: Implementation Tiers

Formalized the tier model from the Implementation Checklist:

| Tier | Description |
|------|-------------|
| Tier 1 | Direct verification (complete) |
| Tier 2 | Full KERI (KEL, ACDC signatures, revocation) |
| Tier 3 | Authorization and rich call data |

**Why:** Provides clear implementation roadmap aligned with checklist phases.

#### Appendix A: Traceability Matrix

Maps each VVP §5 section to:
- This spec section
- Implementation phase number

**Why:** Ensures nothing from the authoritative spec was missed and enables verification of completeness.

## Files Created/Modified

| File | Action | Purpose |
|------|--------|---------|
| `app/Documentation/VVP_Verifier_Specification_v1.5.md` | Created | New specification version |

## Open Questions

1. **SIP Context Requirement:** Should `context_aligned` be REQUIRED or OPTIONAL by default? The spec says "MUST confirm" but practical deployments may not have SIP context at the verifier. Current decision: configurable via policy (`policy.context_required`).

2. **Replay Tolerance:** VVP §5.1.1-2.1 recommends 30 seconds for replay tolerance. We currently use 5 seconds for iat drift (§5.2A). Should replay tolerance be separate from iat binding tolerance?

3. **Error Code Consolidation:** Should AUTHORIZATION_FAILED and TN_RIGHTS_INVALID be separate codes, or consolidated under a single AUTHORIZATION error?

4. **Callee API Endpoint:** Should callee verification be a separate `/verify-callee` endpoint or a mode flag on `/verify`?

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Spec divergence from VVP draft | Low | High | Explicit § references, traceability matrix |
| Error code proliferation | Medium | Low | Consolidate if semantically equivalent |
| Over-specification | Low | Medium | Mark unimplemented as "Tier 2/3" |

---

---

## Revision 1 (Response to CHANGES_REQUESTED)

### Changes Made

| Finding | Resolution |
|---------|------------|
| [High] §9 pseudocode doesn't build REQUIRED claim nodes from §3.3B | Rewrote §9.1 and §9.2 to explicitly initialize and populate all REQUIRED claim nodes with exact names from §3.3B |
| [Medium] `issuer_matched` under wrong parent in callee tree | Moved from `passport_verified` to `dossier_verified` in §3.3B and §9.2 |
| [Medium] §10.2 vectors conflict with Tier 1 scope | Split into §10.2.1 (Tier 1), §10.2.2 (Tier 2), §10.2.3 (Tier 3) with 8/5/7 vectors respectively |
| [Low] Missing error code for issuer mismatch | Added `ISSUER_MISMATCH` to §4.2A and referenced in §5B Step 9 |

### Additional Improvements (per recommendations)

1. Added step-to-claim mapping tables after §5A and §5B to prevent future drift
2. Clarified SIP context absent behavior in §4.4: MUST produce INDETERMINATE (not INVALID), MUST NOT reject
3. Added note in §5A Step 1 distinguishing replay tolerance (30s) from iat binding tolerance (5s)

### Answers to Open Questions (incorporated)

1. **SIP Context Requirement**: Now policy-driven, default OPTIONAL; absence produces INDETERMINATE
2. **Replay Tolerance**: Documented as separate from iat binding (30s vs 5s)
3. **Error Code Consolidation**: Kept separate as recommended
4. **Callee API Endpoint**: Noted in recommendations for future consideration

---

## Reviewer Prompt (Revision 1)

```
## Plan Review Request: Phase 9 - VVP Verifier Specification v1.5 (Revision 1)

You are the Reviewer in a pair programming workflow. This is a re-review after addressing your previous CHANGES_REQUESTED feedback.

### Documents to Review

1. `app/Documentation/VVP_Verifier_Specification_v1.5.md` - The revised specification
2. `PLAN.md` - Summary of changes including "Revision 1" section documenting fixes

### Changes Made Since Last Review

| Finding | Resolution |
|---------|------------|
| [High] §9 pseudocode doesn't build REQUIRED claim nodes | Rewrote §9.1 and §9.2 with explicit claim node initialization |
| [Medium] `issuer_matched` wrong parent | Moved to `dossier_verified` in §3.3B and §9.2 |
| [Medium] §10.2 vectors conflict with Tier 1 scope | Split into §10.2.1/2/3 by tier |
| [Low] Missing ISSUER_MISMATCH error code | Added to §4.2A and §5B Step 9 |

Additional improvements:
- Added step-to-claim mapping tables after §5A and §5B
- Clarified SIP context absent behavior (INDETERMINATE, not reject)
- Documented replay tolerance vs iat binding tolerance distinction

### Your Task

1. Verify the required changes have been correctly implemented
2. Confirm §9 pseudocode now builds all REQUIRED claim nodes from §3.3B
3. Confirm `issuer_matched` is now under `dossier_verified` in callee tree
4. Confirm §10.2 test vectors are properly tiered
5. Provide verdict and feedback in `REVIEW.md`

### Response Format

Write your response to `REVIEW.md` using this structure:

## Plan Review: Phase 9 - VVP Verifier Specification v1.5 (Revision 1)

**Verdict:** APPROVED | CHANGES_REQUESTED

### Required Changes Verification
[Confirm each required change was properly addressed]

### Additional Improvements Assessment
[Evaluation of step-to-claim tables and clarifications]

### Findings
- [High]: Critical issue that blocks approval
- [Medium]: Important issue that should be addressed
- [Low]: Suggestion for improvement (optional)

### Required Changes (if CHANGES_REQUESTED)
1. [Specific change required]

### Final Recommendations
- [Optional improvements or future considerations]
```
