# Phase 11: Tier 2 Integration & Compliance

**Archived:** 2026-01-25
**Status:** APPROVED (Revision 3)

## Problem Statement

While the core components for Tier 2 (ACDC verification, KEL validation, PSS signatures) have been implemented, they are not fully integrated into the main verification flow. Key gaps identified:

1. **ACDC chain validation is NOT called** - `validate_credential_chain()` exists in `acdc/verifier.py` but is never invoked from `verify.py`
2. **ACDC signature verification is NOT performed** - `verify_acdc_signature()` exists but isn't called
3. **Credential type rules exist but aren't enforced** - APE/DE/TNAlloc validators exist but aren't integrated
4. **PASSporT Tier 2 verification unused** - `verify_passport_signature_tier2()` exists but verify.py only uses Tier 1

**Important Discovery**: PSS signature decoding IS already integrated in `passport.py:_decode_signature` (lines 249-255). The proposal's Component 1 is already complete.

## User Decisions

1. **ACDC Signatures**: Include verification in Phase 11
2. **Tier 2 PASSporT**: Enable when OOBI is in kid
3. **Schema Validation**: Configurable via `SCHEMA_VALIDATION_STRICT` (default strict per spec)

## Spec References

- §5.1-7: Root of trust application
- §6.3.1: PSS CESR signature format (ALREADY IMPLEMENTED)
- §4.2: OOBI MUST resolve to valid KEL
- §6.3.3-6: ACDC schema rules (APE/DE/TNAlloc) MUST be enforced
- §5A Step 8: Dossier validation MUST perform cryptographic verification

## Implementation Summary

### Component 1: PSS Verification Wiring
**Status:** Already complete. `passport.py:_decode_signature` already handles CESR-encoded PSS signatures.

### Component 2: Tier 2 PASSporT Signature Verification
**Location:** `app/vvp/verify.py`

- Uses Tier 2 when `kid` contains an OOBI URL
- Bare AID kid returns INVALID per §4.2

### Component 3: ACDC Signature Extraction & Verification
**Locations:** `app/vvp/dossier/parser.py`, `app/vvp/verify.py`

- Dossier parser detects CESR format and extracts signatures
- Returns `Tuple[List[ACDCNode], Dict[str, bytes]]`
- Signatures verified against issuer key state with strict OOBI/KEL validation

### Component 4: ACDC Chain Validation Integration
**Location:** `app/vvp/verify.py`

- Phase 5.5 added after dossier validation, before revocation
- `chain_verified` claim is REQUIRED child of `dossier_verified`
- Validates from leaf credentials (APE/DE/TNAlloc), not just DAG root
- Runs even when PASSporT is None per §5A Step 8

### Component 5: Strict OOBI KEL Validation
**Location:** `app/vvp/keri/kel_resolver.py`

- `_fetch_and_validate_oobi()` accepts `strict_validation` parameter
- Strict mode (production): canonical KERI validation, SAID checks
- Lenient mode (test): allows placeholder SAIDs and non-canonical serialization

### Component 6: Leaf Credential Selection
**Location:** `app/vvp/verify.py`

- `_find_leaf_credentials()` identifies credentials not referenced by edges
- Chain validation starts from leaves (APE/DE/TNAlloc) per §6.3.x
- At least one leaf must validate to trusted root

## Files Modified

| File | Action | Purpose |
|------|--------|---------|
| `app/vvp/verify.py` | Modified | Added chain_verified claim, Tier 2 PASSporT, ACDC integration, leaf selection |
| `app/vvp/keri/kel_resolver.py` | Modified | Added strict_validation parameter to _fetch_and_validate_oobi() |
| `app/vvp/dossier/parser.py` | Modified | Extract CESR signatures when parsing dossier |
| `app/vvp/dossier/__init__.py` | Modified | Export signature dict from parse_dossier |
| `app/core/config.py` | Modified | Added SCHEMA_VALIDATION_STRICT flag |
| `tests/test_dossier.py` | Modified | Added CESR signature extraction tests |

## Review History

### Revision 1 (CHANGES_REQUESTED)
- [High] OOBI KEL validation not enforced
- [High] Chain validation starts at DAG root instead of leaves
- [Medium] Chain verification skipped when PASSporT is None
- [Low] ACDC_CHAIN_INVALID should use existing error code

### Revision 2 (CHANGES_REQUESTED)
- [High] ACDC signature verification uses `_allow_test_mode=True`
- [Medium] No test for CESR signature extraction

### Revision 3 (APPROVED)
- [High] Fixed: Strict key resolution for ACDC verification
- [Medium] Fixed: Added CESR signature extraction test with mocking
