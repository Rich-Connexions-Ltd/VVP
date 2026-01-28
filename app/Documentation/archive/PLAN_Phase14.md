# Sprint 14: Tier 2 Completion

## Problem Statement

The VVP Verifier has Tier 2 at 88% completion with 5 remaining items:
- **Phase 7.15**: Delegation validation (dip/drt events)
- **Phase 8.6**: ACDC schema SAID validation
- **Phase 8.8**: Edge/relationship semantic validation
- **Phase 8.9**: ACDC variants (compact/partial/aggregate)
- **Phase 8.11**: TNAlloc JL validation with phone number range subset

Completing these items enables full KERI-based verification before moving to Tier 3 authorization.

## Spec References

- **§7.2**: "If the selected verification library does not support DI2I: the verifier MUST treat delegation verification as INDETERMINATE"
- **§6.3.x**: "Credentials must use recognized schema SAIDs from the vLEI governance framework"
- **§6.3.6**: "TNAlloc MUST contain JL to parent TNAlloc; phone number ranges must be subset"
- **§1.4**: "Verifiers MUST support valid ACDC variants (compact/partial/aggregate)"

## Sprint Scope

Given complexity, this sprint focuses on the **highest-value items**:

| Item | Priority | Effort | Rationale |
|------|----------|--------|-----------|
| 8.6 Schema SAID | HIGH | Medium | Adds governance validation |
| 8.8 Edge semantics | HIGH | Medium | Validates credential relationships |
| 8.11 JL/TNAlloc | HIGH | Medium | Critical for phone number rights |
| 7.15 Delegation | DEFER | High | Requires new module, complex |
| 8.9 ACDC variants | DEFER | High | Complex CESR handling |

**Target**: Phase 8 to 100%, Phase 7 remains at 94%

---

## Detailed Design

### Component 1: Schema SAID Validation (8.6)

**Location**: `app/vvp/acdc/verifier.py`

**Changes**:
1. Populate known schema SAIDs from vLEI governance registry file
2. Schema validation defaults to **strict=True** per §6.3.x MUSTs
3. Add config option `SCHEMA_VALIDATION_STRICT` (default: True) for policy deviation
4. Create `app/vvp/acdc/schema_registry.py` for versioned schema management
5. Add unit tests for schema validation

### Component 2: Edge Relationship Validation (8.8)

**Location**: `app/vvp/acdc/verifier.py`

**Changes**:
1. Add `validate_edge_semantics()` function
2. Define edge rules per credential type:
   - APE: MUST have `vetting`/`le` edge → LE credential
   - DE: MUST have `delegation`/`d` edge → delegating credential
   - TNAlloc: MUST have `jl` edge → parent TNAlloc (unless root)
3. Validate edge target has correct credential type
4. Integrate into `walk_chain()` for automatic enforcement

### Component 3: TNAlloc Phone Number Validation (8.11)

**Location**: `app/vvp/tn_utils.py` (new)

**Changes**:
1. Create `app/vvp/tn_utils.py` for phone number utilities
2. Implement E.164 parsing with wildcard support
3. Implement range subset algorithm
4. Integrate into `validate_tnalloc_credential()`

### Component 4: ACDC Variant Detection (8.9 explicit handling)

**Location**: `app/vvp/acdc/parser.py`

**Changes**:
1. Add `detect_acdc_variant()` function
2. Detect full, compact, and partial variants
3. Reject non-full variants with ParseError (documented non-compliance)

---

## Files Created/Modified

| File | Action | Purpose |
|------|--------|---------|
| `app/vvp/acdc/schema_registry.py` | Create | Versioned schema SAID registry |
| `app/vvp/acdc/verifier.py` | Modify | Schema validation (strict default), edge semantics, chain integration |
| `app/vvp/acdc/parser.py` | Modify | ACDC variant detection and rejection |
| `app/vvp/tn_utils.py` | Create | Phone number parsing, E.164 validation, range subset |
| `tests/test_acdc.py` | Modify | Add schema/edge/variant validation tests (19 new tests) |
| `tests/test_tn_utils.py` | Create | Phone number utility tests (15 tests) |

---

## Implementation Notes

### Deviations from Plan

1. **ParseError vs DossierParseError**: The plan referenced `DossierParseError` but the actual exception in `app/vvp/dossier/exceptions.py` is named `ParseError`. Updated imports accordingly.

2. **Edge semantics enforcement**: Added call to `validate_edge_semantics()` in `walk_chain()` at line 264-266 to ensure edge validation is performed during chain traversal, not just as a standalone function.

3. **Missing target handling**: Changed behavior for required edges with missing targets from warning to error (`ACDCChainInvalid`) per reviewer feedback.

### Test Results

```
701 passed, 2 skipped, 20 warnings in 4.81s
```

### Review History

- **Initial Review**: CHANGES_REQUESTED
  - [High] Edge semantics not enforced in chain validation
  - [Medium] Missing targets treated as warning instead of error
- **Revision 1**: APPROVED

---

## Deferred Items (with Explicit Non-Compliance Handling)

### 7.15 Delegation (dip/drt events)
**Explicit Behavior per §7.2**:
- When `dip`/`drt` events encountered → raise `DelegationNotSupportedError`
- Maps to `KERI_RESOLUTION_FAILED` (recoverable)
- Claim status: `INDETERMINATE` (not INVALID)

### 8.9 ACDC Variants (compact/partial/aggregate)
**Explicit Behavior per §1.4**:
- Compact ACDCs: Detected by missing expanded fields → `DOSSIER_PARSE_FAILED`
- Partial ACDCs: Detected by `"_"` placeholder values → `DOSSIER_PARSE_FAILED`
- Aggregate ACDCs: Detected by multiple roots → `DOSSIER_GRAPH_INVALID`

---

## Expected Outcome

After Sprint 14:
- **Phase 8**: 86% (12/14 items) - up from 71%
- **Phase 7**: 94% (16/17 items) - unchanged
- **Tier 2 Overall**: ~93% (up from 88%)
- **Project Overall**: ~70% (up from 68%)
