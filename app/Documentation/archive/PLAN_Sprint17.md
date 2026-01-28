# Sprint 17: APE Vetting Edge & Schema Validation

## Problem Statement

Sprint 17 addresses three remaining MUST requirements in Phase 10 (Authorization Verification):
- **10.12**: APE must include vetting edge → LE credential (§6.3.3)
- **10.18**: kid AID single-sig validation (§4.2)
- **10.19**: Vetting credential must conform to LE vLEI schema (§6.3.5)

## Spec References

- **§6.3.3**: "APE credentials MUST reference a vetting credential (LE) that establishes the legal entity's identity"
- **§4.2**: "kid identifies the originating party's AID... must be single-signature Ed25519"
- **§6.3.5**: "Vetting credentials MUST conform to the vLEI Legal Entity schema"

## Current State & Gaps

### 10.12 - APE Vetting Edge
- `validate_edge_semantics()` in `verifier.py` defines APE vetting edge as `required=True`
- **Gap**: Lines 170-175 skip required edge checks when `is_root=True`
- **Gap**: No validation that vetting target has valid LE schema SAID

### 10.18 - Single-Sig AID
- **Already enforced**: `key_parser.py` only accepts B/D prefixes (both single-sig Ed25519)
- All other prefixes raise `ResolutionFailedError`
- **Action**: Add documentation comment only

### 10.19 - Vetting LE Schema
- Schema registry has LE SAID: `EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao`
- `is_known_schema()` helper exists but not used for vetting credential validation
- **Gap**: Need explicit validation call when APE vetting edge is found

---

## Implementation Plan

### Change 1: Fix APE Vetting Edge Always Required

**File**: `app/vvp/acdc/verifier.py` (lines 170-186)

Modify `validate_edge_semantics()` to not skip required checks for APE credentials:

```python
# Current (line 170-175):
if found_edge is None:
    if required and not is_root:
        raise ACDCChainInvalid(...)

# New:
if found_edge is None:
    # APE vetting edge is ALWAYS required per §6.3.3, even for root issuers
    skip_for_root = is_root and cred_type != "APE"
    if required and not skip_for_root:
        raise ACDCChainInvalid(...)
```

Same pattern for lines 180-186 (edge target not found case).

### Change 2: Add APE Vetting Target Validation Function

**File**: `app/vvp/acdc/verifier.py` (new function after `validate_edge_semantics`)

```python
def validate_ape_vetting_target(
    vetting_target: ACDC,
    strict_schema: bool = True
) -> None:
    """Validate APE vetting credential per §6.3.3 and §6.3.5.

    Args:
        vetting_target: The credential referenced by APE vetting edge.
        strict_schema: If True, require known vLEI LE schema SAID.

    Raises:
        ACDCChainInvalid: If vetting credential is invalid.
    """
    # Validate credential type is LE
    if vetting_target.credential_type != "LE":
        raise ACDCChainInvalid(
            f"APE vetting credential must be LE type, got {vetting_target.credential_type}"
        )

    # Validate schema SAID against known vLEI LE schemas (§6.3.5)
    if strict_schema and has_governance_schemas("LE"):
        if not is_known_schema("LE", vetting_target.schema_said):
            raise ACDCChainInvalid(
                f"APE vetting credential schema {vetting_target.schema_said[:20]}... "
                f"not in known vLEI LE schemas per §6.3.5"
            )
```

### Change 3: Call Vetting Target Validation

**File**: `app/vvp/acdc/verifier.py` (in `validate_edge_semantics`, after line 194)

When APE vetting edge is found and validated, call the new function:

```python
# After validating target credential type (line 194):
# Add APE-specific vetting target validation
if cred_type == "APE" and found_target is not None:
    from app.core.config import SCHEMA_VALIDATION_STRICT
    validate_ape_vetting_target(found_target, strict_schema=SCHEMA_VALIDATION_STRICT)
```

### Change 4: Document Single-Sig Enforcement

**File**: `app/vvp/keri/key_parser.py` (add comment near line 15)

```python
# Per VVP §4.2, kid MUST be a single-sig AID. The B and D prefixes
# are the only single-sig Ed25519 KERI codes per §6.2.3:
#   B = Ed25519 non-transferable (single-sig, cannot rotate)
#   D = Ed25519 transferable (single-sig, can rotate)
# Multi-sig AIDs (prefixes E, F, M, etc.) are rejected, satisfying
# checklist item 10.18 requirements.
ED25519_CODES = frozenset({"B", "D"})
```

---

## Files to Modify

| File | Action | Changes |
|------|--------|---------|
| `app/vvp/acdc/verifier.py` | Modify | Fix is_root bypass for APE; add `validate_ape_vetting_target()` |
| `app/vvp/keri/key_parser.py` | Modify | Add documentation comment for §4.2 |
| `tests/test_acdc.py` | Modify | Add 4 new tests |
| `app/Documentation/VVP_Implementation_Checklist.md` | Modify | Mark 10.12, 10.18, 10.19 complete |

---

## Test Strategy

### New Tests (in `tests/test_acdc.py`)

1. **test_ape_vetting_edge_required_even_for_root_issuer**
   - APE credential from trusted root issuer
   - No vetting edge → should raise `ACDCChainInvalid`

2. **test_ape_vetting_edge_target_must_be_le_type**
   - APE with vetting edge pointing to TNAlloc instead of LE
   - Should raise `ACDCChainInvalid`

3. **test_ape_vetting_credential_requires_known_le_schema**
   - APE with vetting edge to LE credential
   - LE has unknown schema SAID
   - Strict mode → should raise `ACDCChainInvalid`

4. **test_ape_vetting_credential_known_schema_passes**
   - APE with vetting edge to LE credential
   - LE has known vLEI schema SAID (`EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao`)
   - Should pass validation

---

## Verification

```bash
# Run all tests
DYLD_LIBRARY_PATH="/opt/homebrew/lib" python3 -m pytest tests/ -v

# Run specific ACDC tests
DYLD_LIBRARY_PATH="/opt/homebrew/lib" python3 -m pytest tests/test_acdc.py -v -k "vetting"

# Run authorization tests (regression)
DYLD_LIBRARY_PATH="/opt/homebrew/lib" python3 -m pytest tests/test_authorization.py -v
```

---

## Checklist Items Completed

- **10.12**: APE vetting edge to LE always required (fixed is_root bypass)
- **10.18**: Single-sig AID enforcement (already done, documented)
- **10.19**: Vetting credential LE schema validation (new function)

---

## Risks & Mitigations

| Risk | Mitigation |
|------|------------|
| Breaking valid dossiers | Schema validation uses existing SCHEMA_VALIDATION_STRICT flag |
| Unknown LE schemas rejected | Registry has known SAID; flag allows relaxed mode |
| Root APE edge requirement | Spec is clear per §6.3.3; all APEs need vetting |

---

## Implementation Notes

### Deviations from Plan
- Test `test_ape_vetting_edge_required_even_for_root_issuer` changed from "APE without edges" to "APE with vetting edge pointing to missing target" due to credential type detection depending on edges
- Changed `from app.core.config import SCHEMA_VALIDATION_STRICT` to `from app.core import config` then `config.SCHEMA_VALIDATION_STRICT` to allow monkeypatching in tests

### Test Results

```
752 passed, 2 skipped in 4.89s
```

### Files Changed

| File | Lines | Summary |
|------|-------|---------|
| `app/vvp/acdc/verifier.py` | +46 | Fixed is_root bypass; added `validate_ape_vetting_target()` |
| `app/vvp/keri/key_parser.py` | +8 | Added §4.2 single-sig documentation |
| `tests/test_acdc.py` | +143 | 4 new tests + `KNOWN_LE_SCHEMA` constant + updated 4 existing tests |
| `app/Documentation/VVP_Implementation_Checklist.md` | +53/-34 | Phase 10 100%, overall 79% |
