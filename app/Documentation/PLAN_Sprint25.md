# Sprint 25: Delegation Chain UI Visibility

## Summary

Surface delegation chain information in the UI when verification results are available. The backend already computes delegation chain data during Tier 2 signature verification, but this data is not exposed to the UI.

**Problem**: Delegation chain validation happens in `verify_passport_signature_tier2()` and populates `KeyState.delegation_chain`, but this information is lost - only the pass/fail status propagates to the claim tree.

**Solution**:
1. Extend `VerifyResponse` to include delegation chain details
2. Add a UI endpoint that performs full verification and renders results with delegation visualization
3. Wire the existing `delegation_chain.html` template (already implemented in Sprint 24)

---

## Revision History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-01-27 | Initial plan |
| 1.1 | 2026-01-27 | Addressed reviewer feedback: proper INVALID/INDETERMINATE status mapping, credential-to-delegation mapping rule, refactored shared internal function |

---

## Implementation Phases

### Phase 1: Extend API Response Models

**File:** `app/vvp/api_models.py`

Added new Pydantic models for delegation chain in API response:

```python
class DelegationNodeResponse(BaseModel):
    """Single node in delegation chain for API response."""
    aid: str
    aid_short: str
    display_name: Optional[str] = None
    is_root: bool = False
    authorization_status: str = "INDETERMINATE"


class DelegationChainResponse(BaseModel):
    """Complete delegation chain for API response."""
    chain: List[DelegationNodeResponse] = Field(default_factory=list)
    depth: int = 0
    root_aid: Optional[str] = None
    is_valid: bool = False
    errors: List[str] = Field(default_factory=list)
```

Extended `VerifyResponse`:
```python
class VerifyResponse(BaseModel):
    # ... existing fields ...
    delegation_chain: Optional[DelegationChainResponse] = None
    signer_aid: Optional[str] = None  # For credential-to-delegation mapping
```

---

### Phase 2: Capture Delegation Chain in Verification Flow

**File:** `app/vvp/keri/signature.py`

Refactored to share common implementation:

```python
async def _verify_passport_signature_tier2_impl(...) -> tuple["KeyState", str]:
    """Internal implementation returning (KeyState, authorization_status)."""
    # Returns tuple of (resolved KeyState, authorization_status string)
    # authorization_status is "VALID", "INVALID", or "INDETERMINATE"


async def verify_passport_signature_tier2(...) -> None:
    """Existing function - calls _impl."""


async def verify_passport_signature_tier2_with_key_state(...) -> tuple["KeyState", str]:
    """Returns (KeyState, authorization_status) for UI display."""
```

**File:** `app/vvp/verify.py`

Added `_build_delegation_response()` helper with proper status mapping:
- `chain.valid=True, auth_status="VALID"` → nodes get VALID
- `chain.valid=True, auth_status="INVALID"` → nodes get INVALID
- `chain.valid=True, auth_status="INDETERMINATE"` → nodes get INDETERMINATE
- `chain.valid=False` → nodes get INVALID (definitive failure)

---

### Phase 3: View Model Mapping Function

**File:** `app/vvp/ui/credential_viewmodel.py`

Added `build_delegation_chain_info()` to convert API response to UI view model with identity resolution from LE credentials.

---

### Phase 4: UI Verify Result Endpoint

**File:** `app/main.py`

Added `/ui/verify-result` endpoint that:
1. Parses PASSporT JWT to extract `kid` and `iat` for VVP-Identity header (§5.2 binding)
2. Calls `verify_vvp()` for full verification
3. Fetches and parses dossier for credential display
4. Builds delegation_info from verify_response.delegation_chain
5. Attaches delegation_info to credentials where issuer AID matches signer AID
6. Returns verify_result.html template

#### Credential-to-Delegation Mapping Rule

Delegation applies to the PASSporT signer (the `kid` AID). The delegation chain shows how the signer was authorized to sign on behalf of the root delegator.

**Mapping rule**: Attach `delegation_info` to credentials where **issuer AID matches the signer AID**.

---

### Phase 5: Verification Result Template

**File:** `app/templates/partials/verify_result.html`

Created template with:
- Overall status banner with VALID/INVALID/INDETERMINATE styling
- Delegation banner showing chain depth and validity
- Inline delegation chain visualization (leaf → root)
- Credential cards with delegation panel integration
- Claim tree (collapsible)
- Verification errors display

---

## Files Modified

| File | Action | Changes |
|------|--------|---------|
| `app/vvp/api_models.py` | Modified | Added DelegationNodeResponse, DelegationChainResponse; extended VerifyResponse |
| `app/vvp/keri/signature.py` | Modified | Refactored with shared _impl, added verify_passport_signature_tier2_with_key_state |
| `app/vvp/keri/__init__.py` | Modified | Exported new function |
| `app/vvp/verify.py` | Modified | Capture delegation chain, add _build_delegation_response helper |
| `app/vvp/ui/credential_viewmodel.py` | Modified | Add build_delegation_chain_info function |
| `app/main.py` | Modified | Add /ui/verify-result endpoint |
| `app/templates/partials/verify_result.html` | Created | New template for verification results |
| `tests/test_delegation_ui.py` | Created | Unit tests for new functions |
| `tests/test_verify.py` | Modified | Updated mocks for new function signature |
| `tests/test_dossier_cache.py` | Modified | Updated mocks for new function signature |
| `tests/vectors/runner.py` | Modified | Updated mocks for new function signature |

---

## Test Results

```
================= 1198 passed, 20 warnings in 69.86s =================
```

---

## Review History

- Plan Rev 0: CHANGES_REQUESTED - Status mapping and credential mapping issues
- Plan Rev 1: APPROVED - Addressed reviewer feedback
- Code Rev 0: CHANGES_REQUESTED - VVP-Identity header construction bug
- Code Rev 1 (Sprint 25.1): APPROVED - Fixed to parse PASSporT JWT for kid/iat

---

## Backwards Compatibility

- `VerifyResponse.delegation_chain` is Optional with default None
- Existing `/verify` consumers see no change unless they read the new field
- `/ui/fetch-dossier` unchanged (no full verification)
