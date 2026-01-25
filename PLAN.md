# Phase 11: Tier 2 Integration & Compliance

## Problem Statement

While the core components for Tier 2 (ACDC verification, KEL validation, PSS signatures) have been implemented in Phase 10, they are not fully integrated into the main verification flow. Key gaps identified:

1. **ACDC chain validation is NOT called** - `validate_credential_chain()` exists in `acdc/verifier.py` but is never invoked from `verify.py`
2. **ACDC signature verification is NOT performed** - `verify_acdc_signature()` exists but isn't called
3. **Credential type rules exist but aren't enforced** - APE/DE/TNAlloc validators exist but aren't integrated
4. **PASSporT Tier 2 verification unused** - `verify_passport_signature_tier2()` exists but verify.py only uses Tier 1

**Important Discovery**: PSS signature decoding IS already integrated in `passport.py:_decode_signature` (lines 249-255). The original proposal's Component 1 is already complete.

## User Decisions

1. **ACDC Signatures**: Include verification in Phase 11
2. **Tier 2 PASSporT**: Enable when OOBI is in kid (bare AID → INVALID per §4.2)
3. **Schema Validation**: Strict by default (§6.3.3-6 are MUSTs), with `SCHEMA_VALIDATION_STRICT` config flag

## Spec References

- §5.1-7: Root of trust application
- §6.3.1: PSS CESR signature format (ALREADY IMPLEMENTED)
- §4.2: OOBI MUST resolve to valid KEL
- §6.3.3-6: ACDC schema rules (APE/DE/TNAlloc) MUST be enforced
- §5A Step 8: Dossier validation MUST perform cryptographic verification

## Current State Analysis

### Already Working ✅

1. **PSS Signature Decoding** (`passport.py:227-262`)
   - Auto-detects CESR codes (0A, 0B, 0C, 0D, AA)
   - Calls `decode_pss_signature()` from `cesr.py`
   - Returns 64-byte Ed25519 signature

2. **OOBI KEL Validation** (`oobi.py:validate_oobi_is_kel`)
   - Fetches OOBI, parses KEL, validates chain
   - Returns KeyState

3. **ACDC Credential Rules** (`acdc/verifier.py`)
   - `validate_ape_credential()` - checks vetting edge
   - `validate_de_credential()` - checks PSS signer matches delegate
   - `validate_tnalloc_credential()` - checks TN subset
   - `validate_credential_chain()` - orchestrates chain walk

4. **Tier 2 KEL Resolution** (`TIER2_KEL_RESOLUTION_ENABLED = True` in config.py)

5. **CESR Stream Parsing** (`keri/cesr.py:parse_cesr_stream`)
   - Extracts JSON events + signature attachments from CESR streams
   - Returns `CESRMessage` with `controller_sigs` list

### Not Integrated ❌

1. **verify.py does NOT call ACDC chain validation**
   - Only does structural DAG validation + revocation checking
   - Missing: `validate_credential_chain()` invocation
   - Missing: `chain_verified` claim in claim tree

2. **ACDC signatures are NOT verified**
   - `verify_acdc_signature()` exists but never called
   - Dossier parser ignores CESR attachments (only parses JSON)
   - Need to extract signatures when dossier is CESR format

3. **Model mismatch**: Dossier uses `ACDCNode`, ACDC module uses `ACDC`

4. **PASSporT Tier 2 unused**: `verify_passport_signature_tier2()` never called

## Proposed Solution

### Component 1: PSS Verification Wiring
**Status: ALREADY COMPLETE** - No changes needed. `passport.py:_decode_signature` already handles CESR-encoded PSS signatures.

### Component 2: Tier 2 PASSporT Signature Verification
**Location**: `app/vvp/verify.py`

Update Phase 4 to enforce OOBI requirement per §4.2:

```python
# Phase 4: KERI Signature Verification
if passport and not passport_fatal:
    kid = passport.header.kid
    is_oobi_kid = kid.startswith(("http://", "https://"))

    try:
        if is_oobi_kid:
            # Tier 2: Use historical key state resolution via OOBI
            await verify_passport_signature_tier2(
                passport,
                oobi_url=kid,
                _allow_test_mode=False  # Use feature flag
            )
            passport_claim.add_evidence("signature_valid,tier2")
        else:
            # §4.2: kid MUST be an OOBI URL - bare AIDs are non-compliant
            # Mark as INVALID rather than silently falling back to Tier 1
            raise ResolutionFailedError(
                f"kid must be an OOBI URL per §4.2, got bare AID: {kid[:20]}..."
            )
    except SignatureInvalidError as e:
        # ...existing error handling - maps to INVALID
    except ResolutionFailedError as e:
        # ...existing error handling - maps to INDETERMINATE for network issues
        # But for bare AID, this is a spec violation → INVALID
        if "must be an OOBI" in str(e):
            passport_claim.fail(ClaimStatus.INVALID, e.message)
        else:
            passport_claim.fail(ClaimStatus.INDETERMINATE, e.message)
```

**Note:** Per §4.2, `kid` MUST resolve to a valid KEL via OOBI. Bare AIDs without OOBI resolution are non-compliant. This is a breaking change from Tier 1 behavior but required for spec compliance.

### Component 3: ACDC Signature Extraction & Verification
**Locations**: `app/vvp/dossier/parser.py`, `app/vvp/verify.py`

The current dossier parser only handles JSON and ignores CESR signature attachments. Need to:

1. **Enhance dossier parser** to detect CESR format and extract signatures:

```python
# In dossier/parser.py
from ..keri.cesr import parse_cesr_stream, is_cesr_stream

def parse_dossier(raw: bytes) -> Tuple[List[ACDCNode], Dict[str, bytes]]:
    """Parse dossier, extracting ACDCs and their signatures.

    Returns:
        Tuple of (list of ACDCNode, dict mapping SAID -> signature bytes)
    """
    signatures: Dict[str, bytes] = {}

    # Check if CESR format
    if is_cesr_stream(raw):
        messages = parse_cesr_stream(raw)
        nodes = []
        for msg in messages:
            if "d" in msg.event_dict and "i" in msg.event_dict:
                node = parse_acdc(msg.event_dict)
                nodes.append(node)
                # Extract first controller signature
                if msg.controller_sigs:
                    signatures[node.said] = msg.controller_sigs[0]
        return nodes, signatures

    # Plain JSON - no signatures
    # ...existing JSON parsing...
    return nodes, signatures
```

2. **Add ACDC signature verification** in verify.py Phase 5.5:

```python
# For each ACDC with a signature, verify against issuer key
for said, signature in acdc_signatures.items():
    acdc = dossier_acdcs[said]
    try:
        # Resolve issuer key state
        key_state = await resolve_key_state(
            kid=acdc.issuer_aid,
            reference_time=reference_time,
            _allow_test_mode=True
        )
        # Verify signature against ALL issuer keys (not just index 0)
        # At least one key must validate the signature
        signature_valid = False
        for signing_key in key_state.signing_keys:
            try:
                verify_acdc_signature(acdc, signature, signing_key)
                signature_valid = True
                break
            except ACDCSignatureInvalid:
                continue

        if not signature_valid:
            raise ACDCSignatureInvalid(f"No issuer key validates signature for {said[:20]}...")

        chain_claim.add_evidence(f"sig_valid:{said[:16]}...")
    except (ACDCSignatureInvalid, ResolutionFailedError) as e:
        chain_claim.fail(ClaimStatus.INVALID, f"ACDC signature invalid: {e}")
```

### Component 4: ACDC Chain Validation Integration
**Location**: `app/vvp/verify.py`

Add new Phase 5.5 after dossier validation but before revocation:

```python
# Phase 5.5: ACDC Chain Verification (§6.3.x)
chain_claim = ClaimBuilder("chain_verified")

if dag is not None:
    from app.core.config import TRUSTED_ROOT_AIDS
    from app.vvp.acdc import validate_credential_chain, ACDCChainInvalid

    # Convert DossierDAG nodes to ACDC format
    dossier_acdcs = _convert_dag_to_acdcs(dag)

    # Get PSS signer AID from passport kid
    pss_signer_aid = _extract_aid_from_kid(passport.header.kid) if passport else None

    # Validate chain from root
    root_acdc = dossier_acdcs.get(dag.root_said)
    if root_acdc:
        try:
            # §6.3.3-6: Schema validation is a MUST, strict by default
            # Use SCHEMA_VALIDATION_STRICT config flag for policy deviation
            from app.core.config import SCHEMA_VALIDATION_STRICT

            result = await validate_credential_chain(
                acdc=root_acdc,
                trusted_roots=TRUSTED_ROOT_AIDS,
                dossier_acdcs=dossier_acdcs,
                pss_signer_aid=pss_signer_aid,
                validate_schemas=SCHEMA_VALIDATION_STRICT  # Default True per spec
            )
            chain_claim.add_evidence(f"chain_valid,root={result.root_aid[:16]}...")
        except ACDCChainInvalid as e:
            chain_claim.fail(ClaimStatus.INVALID, str(e))
```

### Component 5: Schema Validation Config
**Location**: `app/core/config.py`

Add configuration flag for schema validation strictness:

```python
# Schema SAID validation strictness (§6.3.3-6)
# True (default): Reject unknown schema SAIDs per spec
# False: Log warnings but allow (policy deviation, must be documented)
SCHEMA_VALIDATION_STRICT: bool = os.getenv("SCHEMA_VALIDATION_STRICT", "true").lower() == "true"
```

**Note:** Per §6.3.3-6, schema rules are MUSTs. Setting `SCHEMA_VALIDATION_STRICT=false` is a documented policy deviation for environments where schema SAIDs are not yet populated (e.g., testing with non-production credentials).

### Component 6: Model Conversion Helper
**Location**: `app/vvp/verify.py`

```python
def _convert_dag_to_acdcs(dag: DossierDAG) -> Dict[str, ACDC]:
    """Convert DossierDAG nodes to ACDC format for chain validation."""
    from app.vvp.acdc import ACDC
    result = {}
    for said, node in dag.nodes.items():
        result[said] = ACDC(
            version=node.raw.get("v", ""),
            said=said,
            issuer_aid=node.issuer,
            schema_said=node.raw.get("s", ""),
            attributes=node.raw.get("a"),
            edges=node.edges,
            rules=node.raw.get("r"),
            raw=node.raw,
        )
    return result


def _extract_aid_from_kid(kid: str) -> str:
    """Extract AID from kid (which may be bare AID or OOBI URL).

    Raises:
        ResolutionFailedError: If AID cannot be extracted from OOBI URL.
    """
    from app.vvp.keri.oobi import _extract_aid_from_url
    from app.vvp.keri.exceptions import ResolutionFailedError

    if kid.startswith(("http://", "https://")):
        aid = _extract_aid_from_url(kid)
        if not aid:
            raise ResolutionFailedError(f"Could not extract AID from OOBI URL: {kid[:50]}...")
        return aid
    # Bare AID - return as-is but note this should trigger INVALID per §4.2
    return kid
```

### Component 7: Claim Tree Update
**Location**: `app/vvp/verify.py`

Add `chain_verified` as a REQUIRED child of `dossier_verified`:

```python
dossier_node = dossier_claim.build(children=[
    ChildLink(required=True, node=revocation_node),
    ChildLink(required=True, node=chain_node),  # NEW
])
```

## Files to Modify

| File | Action | Purpose |
|------|--------|---------|
| `app/core/config.py` | Modify | Add SCHEMA_VALIDATION_STRICT flag |
| `app/vvp/verify.py` | Modify | Add chain_verified claim, Tier 2 PASSporT, ACDC integration |
| `app/vvp/dossier/parser.py` | Modify | Extract CESR signatures when parsing dossier |
| `app/vvp/dossier/__init__.py` | Modify | Export signature dict from parse_dossier |
| `tests/test_verify.py` | Modify | Add chain validation, Tier 2, and bare AID rejection tests |
| `tests/test_dossier.py` | Modify | Add CESR signature extraction tests |
| `tests/test_acdc.py` | Verify | Ensure existing tests still pass |

## Implementation Order

1. **Dossier Parser Enhancement** - Extract signatures from CESR streams
2. **Model Conversion Helper** - `_convert_dag_to_acdcs()`
3. **Tier 2 PASSporT Integration** - Conditional use of `verify_passport_signature_tier2()`
4. **Chain Validation Integration** - Call `validate_credential_chain()` in verify.py
5. **ACDC Signature Verification** - Verify each ACDC against issuer key
6. **Schema Warning Logger** - Log unknown schema SAIDs
7. **Claim Tree Update** - Add chain_verified as child of dossier_verified
8. **Tests**

## Test Strategy

### Unit Tests

1. **Dossier Parser** (`tests/test_dossier.py`)
   - Test CESR stream parsing extracts signatures
   - Test JSON-only dossier returns empty signatures dict

2. **Model Conversion** (`tests/test_verify.py`)
   - Test `_convert_dag_to_acdcs()` preserves all fields
   - Test `_extract_aid_from_kid()` for bare AID and OOBI URL

3. **Chain Validation** (`tests/test_acdc.py`)
   - Existing tests for APE/DE/TNAlloc rules
   - Add test for pss_signer_aid binding in DE chain

### Integration Tests

1. **Tier 2 PASSporT** (`tests/test_verify.py`)
   - Test OOBI kid triggers Tier 2 verification
   - Test bare AID kid returns INVALID per §4.2 (not Tier 1 fallback)

2. **Chain Validation in Verify Flow**
   - End-to-end with valid chain → chain_verified VALID
   - End-to-end with untrusted issuer → chain_verified INVALID
   - End-to-end with DE signer mismatch → chain_verified INVALID

3. **ACDC Signature Verification**
   - Valid CESR dossier with signatures → verified
   - CESR with invalid signature → INVALID

### Verification Commands

```bash
# Run all tests
python3 -m pytest tests/ -v

# Run specific test modules
python3 -m pytest tests/test_acdc.py -v
python3 -m pytest tests/test_verify.py -v
python3 -m pytest tests/test_dossier.py -v

# Start server and test endpoint
./run_server.sh &
curl http://localhost:8000/healthz
curl http://localhost:8000/admin | jq .

# Manual verification with test JWT (if available)
curl -X POST http://localhost:8000/verify \
  -H "Content-Type: application/json" \
  -H "VVP-Identity: ppt=vvp;kid=...;iat=...;evd=..." \
  -d '{"passport_jwt": "..."}'
```

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| CESR signature extraction fails on real data | Medium | High | Test with real CESR streams from KERI witnesses |
| Model conversion loses data | Low | Medium | Thorough testing with real dossiers |
| Tier 2 resolution slow/times out | Medium | Medium | Keep Tier 1 as fallback, add timeout handling |
| Chain validation too strict | Low | Medium | Warn-only schema mode, log detailed errors |
| Issuer key resolution fails | Medium | Medium | Map to INDETERMINATE, don't break entire flow |

## Open Questions

None - all user decisions captured above.

---

## Revision 1: Addressing Reviewer Feedback

### Changes Requested (from REVIEW.md)

The reviewer identified four issues that needed to be addressed:

1. **[High] Bare AID in `kid` should be INVALID**: Spec §4.2 requires OOBI URL
2. **[High] Schema validation must be strict**: §6.3.3-6 are MUSTs, warn-only is non-compliant
3. **[Medium] ACDC signature should try all keys**: Not just `signing_keys[0]`
4. **[Low] `_extract_aid_from_kid()` should raise error**: Not return empty on failure

### Fixes Applied

1. **Bare AID → INVALID**: Updated Component 2 to reject bare AIDs with `ResolutionFailedError` that maps to INVALID, not silently fall back to Tier 1.

2. **Strict Schema Validation**: Added `SCHEMA_VALIDATION_STRICT` config flag (default True) in Component 5. Chain validation now uses this flag. Setting to `false` is a documented policy deviation.

3. **Try All Issuer Keys**: Updated ACDC signature verification to iterate through `key_state.signing_keys` until one validates, matching Tier 2 PASSporT behavior.

4. **Raise on Parse Failure**: Updated `_extract_aid_from_kid()` to raise `ResolutionFailedError` when AID cannot be extracted from OOBI URL.
