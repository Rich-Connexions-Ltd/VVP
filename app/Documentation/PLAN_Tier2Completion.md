# Phase: Completing Tier 2 KERI Verification

**Status:** COMPLETED
**Date:** 2026-01-28

## Problem Statement

The verifier currently treats KERI resolution as an experimental feature and lacks support for binary CESR format and strict KERI canonicalization. This prevents true "Tier 2" checks against standard KERI witnesses in a production environment.

## Spec References

- **VVP Spec v1.5 Section 7.3**: Witness receipt validation and threshold requirements
- **KERI Spec (IETF draft-ssmith-keri)**: CESR encoding, canonical serialization, SAID computation
- **ACDC Spec**: Schema SAID computation (uses sorted keys, different from KEL events)

## Implementation Summary

### Phase 1: Canonicalization Foundation
- Flipped defaults in `validate_kel_chain()` to `use_canonical=True`, `validate_saids=True`
- Added `compute_kel_event_said()` routing function to separate KEL from ACDC SAID computation
- Updated ACDC SAID documentation in `parser.py` and `schema_fetcher.py`
- Updated all test fixtures to use canonical serialization

### Phase 2: CESR Binary Support
- Added CESR exception types: `CESRFramingError`, `CESRMalformedError`, `UnsupportedSerializationKind`
- Implemented version string parser with MGPK/CBOR rejection
- Completed -D transferable receipt parsing
- Completed -V attachment group parsing with framing validation
- Added negative tests for all CESR error conditions

### Phase 3: Production Enablement
- Removed TEST-ONLY warnings from `kel_resolver.py` and `signature.py`
- Added environment variable support for `TIER2_KEL_RESOLUTION_ENABLED`
- Production defaults now use strict validation

### Phase 4: Golden Fixtures
- Created fixture generation script using vendored keripy (`scripts/generate_keripy_fixtures.py`)
- Generated binary CESR fixtures with real Ed25519 signatures
- Added golden tests comparing parser output to keripy reference
- Fixed CESR signature decoding to strip 2 lead bytes from indexed signatures
- Fixed KERI key decoding to handle CESR qb64 lead bytes (0x04 for B-prefix, 0x0c for D-prefix)
- Added `generate_witness_receipts_fixture()` for properly signed witness receipts
- Fixed test helpers to use proper CESR B-prefix encoding

## Files Changed

| File | Action | Purpose |
|------|--------|---------|
| `app/vvp/keri/kel_parser.py` | Modified | Flip defaults, add `compute_kel_event_said()`, fix key decoding |
| `app/vvp/keri/cesr.py` | Modified | Binary CESR, -D/-V parsing, counter table, framing validation, signature lead byte fix |
| `app/vvp/keri/keri_canonical.py` | Modified | Version string validation |
| `app/vvp/keri/kel_resolver.py` | Modified | Remove TEST-ONLY, update docstrings |
| `app/vvp/keri/signature.py` | Modified | Remove TEST-ONLY warnings |
| `app/vvp/keri/exceptions.py` | Modified | Add `CESRFramingError`, `CESRMalformedError`, `UnsupportedSerializationKind` |
| `app/core/config.py` | Modified | Add env var support |
| `app/vvp/acdc/parser.py` | Modified | Document ACDC SAID computation |
| `app/vvp/acdc/schema_fetcher.py` | Modified | Document schema SAID (sorted keys) |
| `tests/test_cesr_parser.py` | Modified | Binary CESR tests |
| `tests/test_cesr_negative.py` | Created | Negative tests for framing/counter errors |
| `tests/test_keripy_integration.py` | Created | Golden fixture tests |
| `tests/test_witness_receipts.py` | Modified | Fix CESR B-prefix encoding |
| `tests/test_kel_integration.py` | Modified | Fix CESR B-prefix encoding |
| `tests/fixtures/keri/binary_kel.json` | Created | Binary CESR fixture |
| `tests/fixtures/keri/witness_receipts_keripy.json` | Created | Witness receipts fixture |
| `scripts/generate_keripy_fixtures.py` | Created | Fixture generation from keripy |

## Key Technical Details

### CESR Signature Lead Bytes
Indexed CESR signatures (codes 0A, 0B, 0C, 0D, AA) include 2 lead bytes:
- 88-char qb64 decodes to 66 bytes
- First 2 bytes are code/index prefix
- Remaining 64 bytes are the Ed25519 signature

### CESR Key Lead Bytes
CESR qb64 keys (44 chars) decode to 33 bytes with 1 lead byte:
- B-prefix (Ed25519N non-transferable): lead byte 0x04
- D-prefix (Ed25519 transferable): lead byte 0x0c
- Legacy format detection via lead byte check with fallback

### Witness Fixture Generation
Proper CESR B-prefix encoding for witnesses:
```python
cesr_lead_byte = bytes([0x04])  # Ed25519N
full_bytes = cesr_lead_byte + public_key
aid = base64.urlsafe_b64encode(full_bytes).decode().rstrip("=")
```

## Test Results

```
1408 passed, 19 warnings in 97.81s
```

## Review History

- **Phase 1**: APPROVED
- **Phase 2**: APPROVED
- **Phase 3**: APPROVED
- **Phase 4 Rev 0**: CHANGES_REQUESTED - Rotation signed with wrong key, missing validate_kel_chain test
- **Phase 4 Rev 1**: CHANGES_REQUESTED - CESR signature/key lead byte handling incorrect
- **Phase 4 Rev 2**: APPROVED - All fixes applied, witness fixture regenerated
