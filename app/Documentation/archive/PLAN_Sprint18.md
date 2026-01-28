# Sprint 18: Brand/Business Logic & SIP Contextual Alignment (Revision 1)

**Phases:** 11 (Brand/Business Logic) + 13 (SIP Contextual Alignment)
**Checklist Items:** 23 items (17 + 6)
**Target Completion:** 88% overall (161/182 items)

---

## Revision 1 Changes (Addressing Reviewer Feedback)

| Issue | Resolution |
|-------|------------|
| [High] Brand proxy warnings only | Brand proxy → INDETERMINATE when delegation present but proxy credential missing |
| [High] Geographic constraints warnings only | Geo constraints → INDETERMINATE when constraints exist but GeoIP unavailable |
| [Medium] OPTIONAL claim nodes | brand_verified/business_logic_verified are REQUIRED when card/goal present |

---

## Overview

Sprint 18 completes the caller verification algorithm (§5A Steps 2, 12-13) by adding:
1. **SIP Contextual Alignment** - Validate PASSporT claims match SIP INVITE metadata
2. **Brand Verification** - Validate `card` claims against dossier credentials
3. **Business Logic** - Validate `goal` claims against verifier policy

**Claim Status Semantics (Revised):**
- `context_aligned`: REQUIRED or OPTIONAL per policy (default: OPTIONAL)
- `brand_verified`: REQUIRED when `card` is present (failures propagate)
- `business_logic_verified`: REQUIRED when `goal` is present (failures propagate)

---

## Files to Create

| File | Purpose |
|------|---------|
| `app/vvp/sip_context.py` | SIP URI parsing, contextual alignment validation |
| `app/vvp/brand.py` | Brand credential location, vCard validation |
| `app/vvp/goal.py` | Goal policy, signer constraint checking |
| `tests/test_sip_context.py` | Phase 13 unit tests |
| `tests/test_brand.py` | Brand verification tests |
| `tests/test_goal.py` | Goal/business logic tests |

## Files to Modify

| File | Changes |
|------|---------|
| `app/vvp/api_models.py` | Add `SipContext` model, add error codes to recoverability map |
| `app/core/config.py` | Add goal policy, SIP timing tolerance, context required flag |
| `app/vvp/verify.py` | Integrate 3 new claim nodes into orchestration |

---

## Phase 13: SIP Contextual Alignment (6 items)

### 13.1 Model Changes (`api_models.py`)

```python
class SipContext(BaseModel):
    """SIP context fields per spec §4.4."""
    from_uri: str       # SIP From URI
    to_uri: str         # SIP To URI
    invite_time: str    # RFC3339 timestamp of SIP INVITE
    cseq: Optional[int] = None  # For callee verification

class CallContext(BaseModel):
    call_id: str
    received_at: str
    sip: Optional[SipContext] = None  # NEW - optional per §4.4
```

Add to `ERROR_RECOVERABILITY`:
```python
ErrorCode.CONTEXT_MISMATCH: False,  # Non-recoverable
```

### 13.2 New Module: `sip_context.py`

**Functions:**
- `extract_tn_from_sip_uri(uri: str) -> Optional[str]` - Parse phone from SIP/TEL URI
- `validate_orig_alignment(orig_tn: str, from_uri: str) -> Tuple[bool, str]` - §5A Step 2
- `validate_dest_alignment(dest_tns: List[str], to_uri: str) -> Tuple[bool, str]` - §5A Step 2
- `validate_timing_alignment(iat: int, invite_time: datetime, tolerance: int) -> Tuple[bool, str]`
- `verify_sip_context_alignment(passport: Passport, sip: Optional[SipContext]) -> ClaimBuilder`

**URI Formats to Support:**
- `sip:+15551234567@domain.com`
- `sip:15551234567@domain.com;user=phone`
- `tel:+15551234567`
- `tel:+1-555-123-4567` (visual separators)

**Behavior:**
- If `sip` is None → INDETERMINATE with reason "SIP context not provided"
- If `sip` provided but mismatch → INVALID with CONTEXT_MISMATCH error
- Timing tolerance: 30 seconds (configurable via `VVP_SIP_TIMING_TOLERANCE`)

### 13.3 Config Changes (`config.py`)

```python
# SIP contextual alignment timing tolerance (§5A Step 2)
SIP_TIMING_TOLERANCE_SECONDS: int = int(os.getenv("VVP_SIP_TIMING_TOLERANCE", "30"))

# Whether context alignment is required (§4.4 - default False)
CONTEXT_ALIGNMENT_REQUIRED: bool = os.getenv("VVP_CONTEXT_REQUIRED", "false").lower() == "true"
```

---

## Phase 11: Brand & Business Logic (17 items)

### 11.1 Brand Module (`brand.py`)

**Functions:**
- `validate_vcard_format(card: Dict) -> List[str]` - Validate vCard field names/types (warn on unknown)
- `find_brand_credential(dossier_acdcs: Dict[str, ACDC]) -> Optional[ACDC]` - Locate by attributes
- `verify_brand_attributes(card: Dict, credential: ACDC) -> Tuple[bool, List[str]]` - Match card to credential
- `verify_brand_jl(credential: ACDC, dossier: Dict) -> Tuple[bool, str]` - Check JL to vetting (§6.3.7)
- `verify_brand_proxy(de: ACDC, dossier: Dict) -> Tuple[bool, str]` - Check brand proxy in delegation (§6.3.4)
- `verify_brand(passport: Passport, dossier_acdcs: Dict, de_credential: Optional[ACDC]) -> ClaimBuilder`

**vCard Fields (subset):**
```python
VCARD_FIELDS = {"fn", "org", "tel", "email", "url", "logo", "photo", "adr"}
# Unknown fields: log warning but do NOT mark INVALID (per Reviewer answer)
```

**Behavior (Revised):**
- If `card` is None → No claim created (nothing to verify)
- If `card` present:
  - No brand credential found → INVALID with BRAND_CREDENTIAL_INVALID
  - Brand credential missing JL to vetting → INVALID (§6.3.7 MUST)
  - **NEW:** Delegation present but brand proxy missing → INDETERMINATE (§6.3.4 MUST, but can't verify without proxy)
  - Attributes don't match → INVALID
  - All checks pass → VALID

### 11.2 Goal Module (`goal.py`)

**Functions:**
- `verify_goal_policy(goal: str, accepted: FrozenSet[str], reject_unknown: bool) -> Tuple[bool, str]`
- `extract_signer_constraints(de: Optional[ACDC]) -> SignerConstraints`
- `verify_signer_constraints(constraints: SignerConstraints, call_time: datetime, caller_geo: Optional[str]) -> Tuple[ClaimStatus, List[str]]`
- `verify_business_logic(passport: Passport, dossier: Dict, de: Optional[ACDC], policy: GoalPolicyConfig, call_time: datetime) -> ClaimBuilder`

**SignerConstraints dataclass:**
```python
@dataclass
class SignerConstraints:
    hours_of_operation: Optional[Tuple[int, int]] = None  # (start_hour, end_hour) UTC
    geographies: Optional[List[str]] = None  # ISO 3166-1 codes
```

**Behavior (Revised):**
- If `goal` is None → No claim created
- If `goal` present:
  - Goal rejected by policy → INVALID with GOAL_REJECTED
  - Hours constraint violated → INVALID
  - **NEW:** Geo constraints present but GeoIP unavailable → INDETERMINATE (can't verify)
  - All checks pass → VALID

### 11.3 Config Changes (`config.py`)

```python
# Goal acceptance policy (§5.1.1-2.13)
# Empty = accept all goals
def _parse_accepted_goals() -> frozenset[str]:
    env_value = os.getenv("VVP_ACCEPTED_GOALS", "")
    if env_value:
        return frozenset(g.strip() for g in env_value.split(",") if g.strip())
    return frozenset()  # Empty = accept all

ACCEPTED_GOALS: frozenset[str] = _parse_accepted_goals()
REJECT_UNKNOWN_GOALS: bool = os.getenv("VVP_REJECT_UNKNOWN_GOALS", "false").lower() == "true"

# Geographic constraint enforcement (§5.1.1-2.13)
# When True: geo constraints trigger INDETERMINATE if GeoIP unavailable
# When False: geo constraints are skipped (policy deviation, logged)
GEO_CONSTRAINTS_ENFORCED: bool = os.getenv("VVP_GEO_CONSTRAINTS_ENFORCED", "true").lower() == "true"
```

---

## Integration into verify.py

### Claim Tree (Updated - Revision 1)

```
caller_authorised (root)
├── passport_verified (REQUIRED)
├── dossier_verified (REQUIRED)
│   ├── chain_verified (REQUIRED)
│   └── revocation_clear (REQUIRED)
├── authorization_valid (REQUIRED)
│   ├── party_authorized (REQUIRED)
│   └── tn_rights_valid (REQUIRED)
├── context_aligned (REQUIRED or OPTIONAL per policy)     ← NEW
├── brand_verified (REQUIRED when card present)           ← REVISED
└── business_logic_verified (REQUIRED when goal present)  ← REVISED
```

**Status Propagation:**
- When `card` is present, `brand_verified` is a REQUIRED child → failures propagate
- When `goal` is present, `business_logic_verified` is a REQUIRED child → failures propagate
- When neither is present, these nodes are not added to the tree

### Integration Points

After authorization validation (~line 853), add:

```python
# Phase 13: SIP Contextual Alignment (§5A Step 2)
from app.vvp.sip_context import verify_sip_context_alignment
context_claim = verify_sip_context_alignment(passport, req.context.sip)

# Phase 11: Brand Verification (§5A Step 12)
brand_claim = None
if passport and passport.payload.card:
    from app.vvp.brand import verify_brand
    brand_claim = verify_brand(passport, dossier_acdcs, de_credential=matching_de)

# Phase 11: Business Logic (§5A Step 13)
business_claim = None
if passport and passport.payload.goal:
    from app.vvp.goal import verify_business_logic, GoalPolicyConfig
    from app.core.config import ACCEPTED_GOALS, REJECT_UNKNOWN_GOALS, GEO_CONSTRAINTS_ENFORCED
    policy = GoalPolicyConfig(
        accepted_goals=ACCEPTED_GOALS,
        reject_unknown=REJECT_UNKNOWN_GOALS,
        geo_enforced=GEO_CONSTRAINTS_ENFORCED
    )
    business_claim = verify_business_logic(
        passport, dossier_acdcs, matching_de, policy, call_time=datetime.now(timezone.utc)
    )
```

### Claim Tree Assembly (Revised)

```python
children = [
    ChildLink(required=True, node=passport_node),
    ChildLink(required=True, node=dossier_node),
    ChildLink(required=True, node=authorization_node),
    ChildLink(required=CONTEXT_ALIGNMENT_REQUIRED, node=context_claim.build()),
]

# Brand and business claims are REQUIRED when present (per Reviewer feedback)
if brand_claim:
    children.append(ChildLink(required=True, node=brand_claim.build()))
if business_claim:
    children.append(ChildLink(required=True, node=business_claim.build()))
```

---

## Test Strategy

### Phase 13 Tests (`test_sip_context.py`)

| Test | Description |
|------|-------------|
| `test_extract_tn_sip_uri_with_plus` | Parse `sip:+15551234567@domain.com` |
| `test_extract_tn_tel_uri` | Parse `tel:+15551234567` |
| `test_extract_tn_with_separators` | Parse `tel:+1-555-123-4567` |
| `test_orig_alignment_exact_match` | orig.tn matches From URI |
| `test_orig_alignment_mismatch` | Different numbers → INVALID |
| `test_dest_alignment_in_array` | To URI in dest.tn array |
| `test_dest_alignment_not_in_array` | To URI not in array → INVALID |
| `test_timing_within_tolerance` | iat within 30s of invite |
| `test_timing_exceeds_tolerance` | iat outside 30s → INVALID |
| `test_sip_context_absent` | No SIP context → INDETERMINATE |
| `test_sip_context_provided_mismatch` | Context provided but mismatch → INVALID |

### Phase 11 Tests (`test_brand.py`, `test_goal.py`)

| Test | Description |
|------|-------------|
| `test_vcard_valid_fields` | Known vCard fields accepted |
| `test_vcard_unknown_fields_warn` | Unknown fields log warning, not INVALID |
| `test_find_brand_credential` | Locate by org/name attributes |
| `test_brand_attributes_match` | card values match credential |
| `test_brand_missing_jl` | No JL to vetting → INVALID |
| `test_brand_proxy_missing_delegation` | Delegation but no proxy → INDETERMINATE |
| `test_goal_in_whitelist` | Accepted goal → VALID |
| `test_goal_rejected_policy` | Unknown goal + reject_unknown → INVALID |
| `test_hours_constraint_valid` | Call within permitted hours |
| `test_hours_constraint_violated` | Call outside hours → INVALID |
| `test_geo_constraint_no_geoip` | Geo constraint but no GeoIP → INDETERMINATE |
| `test_no_card_no_claim` | card=None → no brand_verified node |
| `test_no_goal_no_claim` | goal=None → no business_logic node |
| `test_brand_failure_propagates` | brand INVALID → caller_authorised INVALID |
| `test_business_failure_propagates` | business INVALID → caller_authorised INVALID |

---

## Implementation Order

1. **Phase 13 foundation** - Add SipContext model to api_models.py
2. **Phase 13 core** - Create sip_context.py with URI parsing and validators
3. **Phase 13 tests** - Unit tests for SIP context alignment
4. **Phase 13 integration** - Wire into verify.py
5. **Phase 11 brand** - Create brand.py module (with brand proxy check)
6. **Phase 11 goal** - Create goal.py module (with geo INDETERMINATE)
7. **Phase 11 config** - Add goal policy and geo enforcement to config.py
8. **Phase 11 tests** - Unit tests for brand and goal
9. **Phase 11 integration** - Wire into verify.py with REQUIRED semantics
10. **Integration tests** - Full flow tests with status propagation
11. **Update checklist** - Mark items complete

---

## Policy Deviations (Documented)

Per Reviewer recommendation, explicit policy deviations with documented behavior:

| Deviation | Behavior | Status | Config Flag |
|-----------|----------|--------|-------------|
| Geographic constraints | GeoIP lookup not available | INDETERMINATE | `GEO_CONSTRAINTS_ENFORCED=true` |
| Geographic constraints (disabled) | Skip geo checks | VALID (logged) | `GEO_CONSTRAINTS_ENFORCED=false` |

When `GEO_CONSTRAINTS_ENFORCED=false`, geographic constraint violations are logged but do not affect claim status. This is a documented policy deviation from §5.1.1-2.13.

---

## Verification

```bash
# Run all tests
DYLD_LIBRARY_PATH="/opt/homebrew/lib" python3 -m pytest tests/ -v

# Run new tests specifically
DYLD_LIBRARY_PATH="/opt/homebrew/lib" python3 -m pytest tests/test_sip_context.py tests/test_brand.py tests/test_goal.py -v

# Verify integration and propagation
DYLD_LIBRARY_PATH="/opt/homebrew/lib" python3 -m pytest tests/test_verify.py -v -k "sip_context or brand or goal or propagat"
```

---

## Checklist Items Addressed

**Phase 11 (17 items):** 11.1-11.17
**Phase 13 (6 items):** 13.1-13.6

After Sprint 18: **161/182 items complete (88%)**

---

## Plan Review Request (Revision 1)

Copy the following prompt to the Reviewer agent:

~~~
## Plan Review Request: Sprint 18 Revision 1 - Brand/Business Logic & SIP Contextual Alignment

You are the Reviewer in a pair programming workflow. Please review the revised plan and provide your assessment in `REVIEW.md`.

### Changes from Original Plan
1. [High] Brand proxy: Now INDETERMINATE when delegation present but proxy missing (was: warning only)
2. [High] Geographic constraints: Now INDETERMINATE when geo constraints exist but GeoIP unavailable (was: warning only)
3. [Medium] brand_verified/business_logic_verified: Now REQUIRED when card/goal present (was: OPTIONAL)
4. Added policy deviation documentation for geo constraint enforcement flag
5. Added tests for status propagation from brand/business failures

### Spec References
- §4.4: SIP Context Fields
- §5.1.1-2.2: Contextual Alignment step
- §5.1.1-2.12: Brand Attributes Verification
- §5.1.1-2.13: Business Logic Verification
- §6.3.4: Delegation with brand proxy requirement
- §6.3.7: Brand credential MUST include JL to vetting

### Evaluation Criteria
- Are the high-priority issues from original review resolved?
- Is the INDETERMINATE status appropriate for "can't verify" scenarios?
- Is the policy deviation documentation adequate?

### Response Format
Write your response to `REVIEW.md`:

## Plan Review: Sprint 18 Revision 1

**Verdict:** APPROVED | CHANGES_REQUESTED

### Issue Resolution
- [High] Brand proxy: FIXED | NOT FIXED
- [High] Geographic constraints: FIXED | NOT FIXED
- [Medium] Claim node semantics: FIXED | NOT FIXED

### Additional Findings
- [severity]: description

### Required Changes (if CHANGES_REQUESTED)
1. [change]
~~~
