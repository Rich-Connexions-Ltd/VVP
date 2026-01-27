# Phase: ToIP Dossier Specification Warnings

## Problem Statement

The new ToIP Verifiable Dossiers Specification v0.6 defines stricter requirements than VVP currently enforces. We need to warn (but not fail) when dossiers don't meet these stricter standards, providing transparency without breaking compatibility.

## Spec References

- ToIP Verifiable Dossiers Specification v0.6 (Section 3: Edge structure, Section 4: Verification)
- VVP Spec §6.1C (Edge Structure - newly added)
- VVP Spec §6.1D (Dossier Versioning - newly added)

## Proposed Solution

Add a warning infrastructure to the dossier validation layer that captures ToIP spec violations as non-blocking warnings. Warnings are propagated to the API response for transparency.

### Warning Codes

| Code | Condition | Field Path |
|------|-----------|------------|
| `EDGE_MISSING_SCHEMA` | Edge has `n` but no `s` (schema SAID) | `e.<edge_name>` |
| `EDGE_NON_OBJECT_FORMAT` | Edge is direct SAID string, not `{n,s}` object | `e.<edge_name>` |
| `DOSSIER_HAS_ISSUEE` | Root ACDC has `issuee`/`ri` field | `a.i` or `ri` |
| `DOSSIER_HAS_PREV_EDGE` | Dossier has `prev` edge (versioning) | `e.prev` |
| `EVIDENCE_IN_ATTRIBUTES` | Evidence-like data in `a` not `e` | `a.<field>` |
| `JOINT_ISSUANCE_OPERATOR` | `thr`/`fin`/`rev` operators detected | `r.<op>` |

### Data Model

```python
# app/vvp/dossier/models.py

class ToIPWarningCode(str, Enum):
    EDGE_MISSING_SCHEMA = "EDGE_MISSING_SCHEMA"
    EDGE_NON_OBJECT_FORMAT = "EDGE_NON_OBJECT_FORMAT"
    DOSSIER_HAS_ISSUEE = "DOSSIER_HAS_ISSUEE"
    DOSSIER_HAS_PREV_EDGE = "DOSSIER_HAS_PREV_EDGE"
    EVIDENCE_IN_ATTRIBUTES = "EVIDENCE_IN_ATTRIBUTES"
    JOINT_ISSUANCE_OPERATOR = "JOINT_ISSUANCE_OPERATOR"

@dataclass(frozen=True)
class DossierWarning:
    code: ToIPWarningCode
    message: str
    said: Optional[str] = None
    field_path: Optional[str] = None

@dataclass
class DossierDAG:
    # ... existing fields ...
    warnings: List[DossierWarning] = field(default_factory=list)  # NEW
```

### Implementation Approach

1. **Validator layer** (`validator.py`): Add `_collect_toip_warnings()` called at end of `validate_dag()`, populates `dag.warnings`
2. **API model** (`api_models.py`): Add `toip_warnings: Optional[List[dict]]` to `VerifyResponse`
3. **Verify flow** (`verify.py`): Propagate `dag.warnings` to response after validation

This approach:
- Minimizes function signature changes (follows existing `validate_dag()` mutation pattern)
- Follows existing patterns (`has_variant_limitations`, `Passport.warnings`)
- Keeps warnings non-blocking (no effect on validation result)

## Files Modified

| File | Changes |
|------|---------|
| [models.py](app/vvp/dossier/models.py) | Add `ToIPWarningCode`, `DossierWarning`, `warnings` field to `DossierDAG` |
| [validator.py](app/vvp/dossier/validator.py) | Add `_collect_toip_warnings()` and 6 helper functions |
| [__init__.py](app/vvp/dossier/__init__.py) | Export new types |
| [api_models.py](app/vvp/api_models.py) | Add `ToIPWarningDetail` model and `toip_warnings` to `VerifyResponse` |
| [verify.py](app/vvp/verify.py) | Capture warnings from DAG, propagate to response |
| [test_dossier.py](tests/test_dossier.py) | Add `TestToIPWarnings` class with 15 test cases |

## Test Strategy

Unit tests for each warning type:
- `test_edge_missing_schema_warning` - Edge without `s` field
- `test_edge_with_schema_no_warning` - Edge with both `n` and `s`
- `test_edge_direct_said_string_warning` - Direct SAID string edge
- `test_edge_object_format_no_string_warning` - Proper object format
- `test_root_issuee_warning` - Root ACDC with `a.i` field
- `test_root_registry_id_warning` - Root ACDC with `ri` field
- `test_evidence_in_attributes_warning` - `proof_digest` in attributes
- `test_joint_issuance_operator_warning` - `thr` operator in rules
- `test_prev_edge_warning` - Dossier with `prev` edge
- `test_no_prev_edge_no_warning` - Dossier without `prev` edge
- `test_warnings_do_not_fail_validation` - Multiple warnings, validation succeeds
- `test_non_root_issuee_no_warning` - Child ACDC with issuee is OK
- `test_no_warnings_for_clean_dossier` - Clean dossier has no warnings
- `test_api_model_serialization` - ToIPWarningDetail serialization
- `test_multiple_warning_types` - Multiple warnings across different ACDCs

## Verification

```bash
# Run dossier tests
./scripts/run-tests.sh tests/test_dossier.py -v

# Run full test suite
./scripts/run-tests.sh
```

Check API response includes `toip_warnings` array when warnings present.

---

## Implementation Notes

### Review History

- **v1.0**: Initial implementation with 11 tests
  - CHANGES_REQUESTED: Missing `prev` edge warning per §6.1D, no warning for direct SAID string edges

- **v1.1**: Added `DOSSIER_HAS_PREV_EDGE` and `EDGE_NON_OBJECT_FORMAT` warnings
  - Added 4 new tests (15 total)
  - APPROVED

### Test Results

```
1214 passed, 19 warnings in 66.90s
```

All 15 ToIP warning tests pass.
