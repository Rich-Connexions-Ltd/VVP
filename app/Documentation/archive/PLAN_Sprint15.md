# Sprint 15: Authorization Verification

## Problem Statement

Per VVP Specification §5A Steps 10-11, the verifier must validate:
1. **Step 10 - Party Authorization**: Confirm the originating party (OP) is authorized to sign the PASSporT
2. **Step 11 - TN Rights**: Confirm the accountable party has rights to originate calls from `orig.tn`

Currently, verification completes chain validation and revocation checking but does **not** validate authorization or TN rights.

## Spec References

- **§5A Step 10**: OP must be issuee of identity credential (APE) in dossier
- **§5A Step 11**: `orig.tn` must be covered by TNAlloc credential in dossier
- **§3.3B**: `authorization_valid` claim with `party_authorized` and `tn_rights_valid` children

## Scope

**In Scope (Case A - No Delegation):**
- Party authorization: PASSporT signer AID == APE credential issuee
- TN rights: `orig.tn` covered by TNAlloc credential ranges (bound to accountable party)
- New claims: `authorization_valid`, `party_authorized`, `tn_rights_valid`

**Out of Scope (Deferred):**
- Case B delegation chains (DE credentials) - returns INDETERMINATE

## Solution Design

### Target Claim Tree

```
caller_authorised
├── passport_verified (REQUIRED)
├── dossier_verified (REQUIRED)
│   ├── chain_verified (REQUIRED)
│   └── revocation_clear (REQUIRED)
└── authorization_valid (REQUIRED)      ← NEW
    ├── party_authorized (REQUIRED)     ← NEW
    └── tn_rights_valid (REQUIRED)      ← NEW
```

### Module Structure

Created `app/vvp/authorization.py`:

```python
@dataclass
class AuthorizationContext:
    pss_signer_aid: str              # From PASSporT kid
    orig_tn: str                     # From passport.payload.orig["tn"]
    dossier_acdcs: Dict[str, ACDC]   # All credentials from dossier

def validate_authorization(ctx: AuthorizationContext) -> Tuple[ClaimBuilder, ClaimBuilder]:
    """Main entry: validates party_authorized and tn_rights_valid."""

def verify_party_authorization(ctx: AuthorizationContext) -> Tuple[ClaimBuilder, Optional[ACDC]]:
    """Step 10: Find APE where issuee == pss_signer_aid."""

def verify_tn_rights(ctx: AuthorizationContext, authorized_aid: str) -> ClaimBuilder:
    """Step 11: Find TNAlloc covering orig_tn, bound to authorized party."""
```

### Files Changed

| File | Action | Changes |
|------|--------|---------|
| `app/vvp/authorization.py` | Create | Authorization module (~265 lines) |
| `app/vvp/api_models.py` | Modify | Add `AUTHORIZATION_FAILED`, `TN_RIGHTS_INVALID` error codes |
| `app/vvp/verify.py` | Modify | Wire authorization_valid claim (~98 lines) |
| `tests/test_authorization.py` | Create | Unit + integration tests (36 tests) |
| `tests/vectors/data/v*.json` | Modify | Updated expected claim tree structure |

### Key Implementation Details

**Party Authorization (verify_party_authorization):**
1. Find all APE credentials: `[a for a in dossier_acdcs.values() if a.credential_type == "APE"]`
2. For each APE, extract issuee: `acdc.attributes.get("i") or acdc.attributes.get("issuee")`
3. If any APE issuee == `pss_signer_aid`: VALID, return matching APE
4. If DE credential found: INDETERMINATE (Case B deferred)
5. Otherwise: INVALID with `AUTHORIZATION_FAILED`

**TN Rights (verify_tn_rights):**
1. Requires `authorized_aid` parameter (from matching APE issuee)
2. If no `authorized_aid`: INDETERMINATE (can't bind without accountable party)
3. Find all TNAlloc credentials bound to `authorized_aid` (issuee match)
4. Parse orig_tn to integer range: `parse_tn_allocation(orig_tn)`
5. If any bound TNAlloc covers orig_tn via `is_subset()`: VALID
6. Otherwise: INVALID with `TN_RIGHTS_INVALID`

### Error Codes

| Code | Condition | Recoverable |
|------|-----------|-------------|
| `AUTHORIZATION_FAILED` | No APE with matching issuee | No |
| `TN_RIGHTS_INVALID` | No TNAlloc covering orig.tn for accountable party | No |

## Review History

### Initial Review (Rev 0)
**Verdict:** CHANGES_REQUESTED
- [High]: TN rights validation did not bind to accountable party

### Revision 1
**Verdict:** APPROVED
- Added `authorized_aid` parameter to `verify_tn_rights()`
- TNAlloc credentials filtered by issuee matching authorized party
- Added 5 new tests for binding validation

## Test Coverage

36 tests covering:
- Issuee extraction from ACDC attributes
- Credential type filtering
- Party authorization (valid, no APE, issuee mismatch, DE found)
- TN rights (valid, not covered, no TNAlloc, invalid format, issuee mismatch)
- Integration tests for combined validation flow

## Checklist Items Addressed

- [x] 10.2 Extract originating party AID from PASSporT
- [x] 10.4 Case A: verify orig = accountable (via APE issuee)
- [x] 10.6 Locate TNAlloc in dossier
- [x] 10.7 Compare orig field to TNAlloc credential (bound to accountable party)
- [x] 10.9 Add caller_authorized claim to tree
- [x] 10.10 Add tn_rights_valid claim to tree
- [x] 10.11 Unit tests for authorization

## Commit

SHA: 82c88a0
