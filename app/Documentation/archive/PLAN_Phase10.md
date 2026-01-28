# Phase 10: Tier 2 Completion - ACDC & Crypto Finalization

## Problem Statement

The VVP verifier currently validates PASSporT signatures against KERI key state but cannot verify the complete credential chain in a dossier. To achieve full Tier 2 compliance, we must:

1. Fix critical crypto gaps (PSS CESR signature decoding, witness receipt validation)
2. Implement ACDC verification to validate credentials in the dossier
3. Establish root of trust configuration for the vLEI governance framework

Without these capabilities, the verifier cannot validate that a caller's credentials (Legal Entity, vLEI, TNAlloc) are authentic, properly chained, and issued by trusted authorities.

## Spec References

- §5.1-7: Root of trust configuration - verifier MUST accept configurable trusted root AIDs
- §6.2.3: KERI AID prefixes - "B" (Basic/non-transferable), "D" (Digest/transferable)
- §6.3.1: PSS CESR format - "This passport-specific signature (PSS) MUST be an Ed25519 signature serialized as CESR... The AA at the front is cut and replaced with 0B"
- §6.3.4: ACDC structure - attributes, edges, rules for credential chaining
- §6.3.5: Credential types - APE (Auth Phone Entity), DE (Delegate Entity), TNAlloc
- §7.3: Witness receipt validation - signatures from witness AIDs in KEL

## Current State

### What Exists
- Phase 4: PASSporT signature verification using Ed25519 (`app/vvp/keri/signature.py`)
- Phase 7: KEL parsing with CESR support (`app/vvp/keri/kel_parser.py`)
- Phase 7a: SAID validation using Blake3-256 (`app/vvp/keri/said.py`)
- Phase 7b: CESR binary format support (`app/vvp/keri/cesr.py`)
- Phase 9: TEL client for revocation checking (`app/vvp/keri/tel_client.py`)

### Limitations
1. **PSS CESR decoding missing**: PASSporT signatures use custom `0B` prefix CESR encoding, not standard JWS
2. **Witness receipt validation incomplete**: KEL parser extracts receipts but doesn't validate signatures
3. **No ACDC verification**: Dossier credentials cannot be verified
4. **No root of trust**: Verifier doesn't know which AIDs to trust as issuance roots

## Proposed Solution

### Approach

Implement the remaining Tier 2 components in dependency order:

1. **Foundation fixes** (1.9, 3.17): Root of trust config and PSS CESR decoding
2. **KERI completion** (7.16, 7.17): Witness receipts and OOBI content validation
3. **ACDC verification** (8.1-8.14): Full credential chain validation

This order ensures each component can be tested independently before integration.

### Alternatives Considered

| Alternative | Pros | Cons | Why Rejected |
|-------------|------|------|--------------|
| Implement ACDC first | Gets to core value faster | Would need stubs for crypto dependencies | Leads to incomplete testing |
| Skip witness receipts | Simpler KEL validation | Violates spec §7.3 | Spec compliance required |
| Hardcode GLEIF root | Simpler config | Not deployment-flexible | Different roots for test/prod |

### Detailed Design

#### Component 1: Root of Trust Configuration (1.9)

- **Purpose**: Configure which AIDs are trusted as credential issuance roots
- **Location**: `app/core/config.py`
- **Interface**:
  ```python
  def _parse_trusted_roots() -> frozenset[str]:
      """Parse comma-separated trusted root AIDs from environment.

      Supports multiple roots for different governance frameworks:
      - GLEIF External (production vLEI)
      - QVI roots (Qualified vLEI Issuers)
      - Test roots (development/staging)
      """
      env_value = os.getenv("VVP_TRUSTED_ROOT_AIDS", "")
      if env_value:
          # Parse comma-separated AIDs, strip whitespace
          return frozenset(aid.strip() for aid in env_value.split(",") if aid.strip())
      # Default: GLEIF External AID for production vLEI ecosystem
      return frozenset({"EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao"})

  TRUSTED_ROOT_AIDS: frozenset[str] = _parse_trusted_roots()
  ```
- **Behavior**:
  - Supports multiple roots via comma-separated `VVP_TRUSTED_ROOT_AIDS` env var
  - Default to GLEIF External AID for production vLEI ecosystem
  - Example: `VVP_TRUSTED_ROOT_AIDS=EBfdlu8...,EQq7xL2...,ETest123...`
  - Used by ACDC verifier to anchor trust chain
  - Empty/invalid AIDs are filtered out

#### Component 2: PSS CESR Signature Decoding (3.17)

- **Purpose**: Decode PASSporT-Specific Signatures from VVP's CESR format
- **Location**: `app/vvp/keri/cesr.py` (extend existing module)
- **Interface**:
  ```python
  def decode_pss_signature(cesr_sig: str) -> bytes:
      """Decode a PSS signature from CESR format to raw Ed25519 bytes.

      Args:
          cesr_sig: CESR-encoded signature with 0B prefix

      Returns:
          64-byte Ed25519 signature

      Raises:
          CesrError: If prefix is not 0B or length is invalid
      """
  ```
- **Behavior**:
  - Validate `0B` prefix (Ed25519 signature in CESR)
  - Decode remaining Base64url to 64 raw bytes
  - Reject non-0B prefixes with clear error

#### Component 3: Witness Receipt Signature Validation (7.16)

- **Purpose**: Validate witness signatures on KEL events per §7.3
- **Location**: `app/vvp/keri/kel_parser.py` (extend)
- **Interface**:
  ```python
  def validate_witness_receipts(
      event: dict,
      receipts: list[WitnessReceipt],  # From cesr.py
      witness_aids: list[str]
  ) -> list[str]:
      """Validate witness signatures on an event.

      Threshold Determination:
      - Use event's 'kt' (key threshold) field if present
      - Otherwise, default to majority: ceil(len(witness_aids) / 2)
      - Do NOT hardcode 2-of-3

      Args:
          event: The KEL event that was witnessed
          receipts: WitnessReceipt objects from CESR parser
          witness_aids: Expected witness AIDs from event 'b' field

      Returns:
          List of AIDs whose signatures validated

      Raises:
          KeriError: If validated count < threshold (KERI_STATE_INVALID)
      """
  ```
- **Behavior**:
  - Extract witness AID from each receipt
  - Verify Ed25519 signature against event SAID bytes
  - Compute threshold from event `kt` field or use majority default
  - Return list of validated witness AIDs
  - Raise if `len(validated) < threshold`

#### Component 4: OOBI Content Validation (7.17)

- **Purpose**: Validate that kid OOBI resolves to a valid KEL
- **Location**: `app/vvp/keri/oobi.py` (extend existing module)
- **Integration**: Extends existing `dereference_oobi()` with KEL validation
- **Interface**:
  ```python
  async def validate_oobi_is_kel(oobi_url: str) -> KeyState:
      """Fetch OOBI and validate it contains a valid KEL.

      This extends the existing dereference_oobi() by adding:
      1. KEL structure validation (must contain icp event)
      2. SAID chain validation (each event references previous)
      3. Key state extraction from terminal event

      Integration with existing code:
      - Uses existing dereference_oobi() for fetch
      - Uses existing kel_parser.parse_kel() for parsing
      - Uses existing kel_resolver.resolve_key_state() for state

      Args:
          oobi_url: OOBI URL from kid field

      Returns:
          Resolved KeyState from the KEL

      Raises:
          OOBIContentInvalidError: If content is not a valid KEL
            - No inception (icp) event found
            - SAID chain broken
            - Invalid event structure
      """
  ```
- **Behavior**:
  - Call existing `dereference_oobi(oobi_url)` to fetch
  - Validate response contains KEL events (not just OOBI metadata)
  - Check for required `icp` (inception) event
  - Validate SAID chain integrity using existing `said.py`
  - Extract key state using existing `kel_resolver.py`

#### Component 5: ACDC Verifier Module (8.1-8.14)

- **Purpose**: Verify ACDC credentials in dossier
- **Location**: `app/vvp/acdc/` (new package)
- **Files**:
  - `__init__.py`
  - `models.py` - ACDC dataclasses
  - `parser.py` - Parse ACDC structure
  - `verifier.py` - Verification logic
  - `exceptions.py` - ACDCError hierarchy

##### 8.1-8.4: ACDC Parsing

```python
@dataclass(frozen=True)
class ACDC:
    """Authentic Chained Data Container."""
    version: str           # v field
    schema_said: str       # s field (SAID of schema)
    issuer_aid: str        # i field
    subject_aid: str       # a.i field (if present)
    attributes: dict       # a field
    edges: Optional[dict]  # e field (credential chain)
    rules: Optional[dict]  # r field
    said: str              # d field (self-addressing identifier)

def parse_acdc(data: dict) -> ACDC:
    """Parse and validate ACDC structure."""
```

##### 8.5-8.6: SAID Validation with Canonicalization

```python
def validate_acdc_said(acdc: ACDC, raw_data: dict) -> None:
    """Validate ACDC's self-addressing identifier.

    Canonicalization Process (per KERI/CESR spec):
    1. Replace 'd' field with placeholder of same length (##############...)
    2. Serialize to KERI canonical JSON:
       - Deterministic key ordering: v, d, i, s, a, e, r
       - No whitespace between elements
       - UTF-8 encoded
    3. Compute Blake3-256 hash of canonical bytes
    4. CESR-encode hash with 'E' prefix (44 chars total)
    5. Compare computed SAID to 'd' field value

    Reuses:
    - app/vvp/keri/keri_canonical.py for serialization
    - app/vvp/keri/said.py for Blake3 + CESR encoding

    Raises:
        ACDCError: If computed SAID != d field (ACDC_SAID_MISMATCH)
    """
```

##### 8.7-8.8: Issuer Key State

```python
async def resolve_issuer_key_state(issuer_aid: str) -> KeyState:
    """Resolve issuer's current key state from OOBI/witness.

    Reuses existing Tier 2 key state resolution.
    """
```

##### 8.9-8.10: Signature Verification with Signing Input Derivation

```python
def verify_acdc_signature(
    acdc: ACDC,
    signature: bytes,
    issuer_key_state: KeyState
) -> None:
    """Verify ACDC signature against issuer's current keys.

    Signing Input Derivation (per CESR/ACDC spec):
    1. Get canonical ACDC bytes using keri_canonical serialization
    2. The signature covers: KERI canonical JSON bytes of full ACDC
    3. Signature format: Ed25519 (64 bytes) from CESR attachment
    4. Extract public key from issuer_key_state.current_keys[0]
    5. Verify: crypto_sign_verify_detached(signature, acdc_bytes, pubkey)

    Key State Considerations:
    - Use key state at ACDC issuance time (from TEL event `dt` field)
    - For rotated keys, must resolve historical key state

    Reuses:
    - app/vvp/keri/signature.py for Ed25519 verification
    - app/vvp/keri/keri_canonical.py for signing input

    Raises:
        SignatureInvalidError: If signature doesn't verify (ACDC_PROOF_MISSING)
    """
```

##### 8.13-8.14: Edge/Chain Validation with Schema/Governance

```python
async def validate_credential_chain(
    acdc: ACDC,
    trusted_roots: set[str],
    dossier_acdcs: dict[str, ACDC]  # SAID -> ACDC lookup
) -> list[ACDC]:
    """Walk the credential chain back to a trusted root.

    Chain Validation Rules (per VVP §6.3.x):

    1. **APE (Auth Phone Entity) - §6.3.3**
       - MUST contain vetting credential reference in edges
       - Vetting credential issuer MUST be in trusted_roots (QVI/GLEIF)
       - Schema: APE schema SAID must match known APE schema

    2. **DE (Delegate Entity) - §6.3.4**
       - MUST contain delegated signer credential reference
       - Edge 'd' points to delegating credential
       - PSS signer MUST match OP AID in delegation chain

    3. **TNAlloc (TN Allocation) - §6.3.6**
       - MUST contain JL (jurisdiction link) to parent TNAlloc
       - Exception: Regulator credentials have no parent
       - Phone number ranges must be subset of parent allocation

    Governance Checks:
    - Each edge 's' field references schema SAID
    - Schema SAIDs must match known vLEI governance schemas
    - Root issuer AID must be in trusted_roots

    Args:
        acdc: The credential to validate
        trusted_roots: Set of trusted root AIDs (GLEIF, QVIs)
        dossier_acdcs: All ACDCs in dossier for edge resolution

    Returns:
        List of credentials in chain (leaf to root)

    Raises:
        ACDCError: If chain invalid (DOSSIER_GRAPH_INVALID):
          - Edge target not found in dossier
          - Schema mismatch for credential type
          - Chain doesn't terminate at trusted root
          - Circular reference detected
    """

    # Implementation sketch:
    visited: set[str] = set()
    chain: list[ACDC] = []

    def walk_chain(current: ACDC) -> None:
        if current.said in visited:
            raise ACDCError("Circular reference in credential chain")
        visited.add(current.said)
        chain.append(current)

        # Check if issuer is trusted root
        if current.issuer_aid in trusted_roots:
            return  # Chain complete

        # Resolve edges to parent credentials
        if current.edges:
            for edge_name, edge_ref in current.edges.items():
                if edge_name in ('d', 'n'):  # Skip digest/nonce
                    continue
                parent_said = edge_ref.get('n') or edge_ref  # SAID reference
                if parent_said not in dossier_acdcs:
                    raise ACDCError(f"Edge target {parent_said} not in dossier")
                walk_chain(dossier_acdcs[parent_said])
        else:
            # No edges and not trusted root = invalid chain
            raise ACDCError(f"Chain ends at untrusted AID: {current.issuer_aid}")

    walk_chain(acdc)
    return chain
```

### Data Flow

```
PASSporT (with PSS signature)
    │
    ▼
decode_pss_signature() ──────► Raw Ed25519 bytes
    │
    ▼
verify_passport_signature() ──► Caller key state validated
    │
    ▼
Dossier (evd URL)
    │
    ▼
fetch_dossier() ──────────────► ACDC credentials retrieved
    │
    ▼
For each ACDC:
    │
    ├─► parse_acdc() ─────────► ACDC structure validated
    │
    ├─► validate_acdc_said() ─► SAID integrity confirmed
    │
    ├─► resolve_issuer_key_state() ─► Issuer keys resolved
    │
    ├─► verify_acdc_signature() ──► Signature validated
    │
    └─► validate_credential_chain() ─► Chain to trusted root
```

### Error Handling

Errors map to existing `ErrorCode` registry in `app/vvp/api_models.py`:

| Error Type | Condition | HTTP Status | Existing ErrorCode |
|------------|-----------|-------------|------------|
| CesrError | Invalid PSS `0B` prefix | 400 | `PASSPORT_PARSE_FAILED` |
| KeriError | Witness threshold not met | 400 | `KERI_STATE_INVALID` |
| OobiError | OOBI content not KEL | 400 | `VVP_OOBI_CONTENT_INVALID` |
| ACDCError | SAID validation failed | 400 | `ACDC_SAID_MISMATCH` |
| ACDCError | Signature invalid | 400 | `ACDC_PROOF_MISSING` |
| ACDCError | Chain not trusted | 400 | `DOSSIER_GRAPH_INVALID` |

**Note:** No new error codes required. Chain trust failures use `DOSSIER_GRAPH_INVALID` as this represents an invalid credential graph structure (untrusted root = broken graph).

### Test Strategy

1. **Unit tests for PSS decoding**: Valid 0B prefix, invalid prefixes, wrong length
2. **Unit tests for witness receipts**: Single witness, threshold scenarios, invalid sigs
3. **Unit tests for ACDC parsing**: Valid structure, missing fields, invalid types
4. **Unit tests for SAID validation**: Correct hash, tampered data, edge cases
5. **Unit tests for chain validation**: Direct issuance, delegation chain, untrusted root
6. **Integration tests**: Full dossier verification with test credentials

**Fixture Generation** (per reviewer recommendation):
- Use vendored keripy for generating real PSS CESR signatures and ACDC test vectors
- Avoid home-grown vectors that may not match production CESR/KERI formats
- Generate fixtures for: PSS signatures, witness receipts, ACDC chains (APE→vLEI→GLEIF)

## Files to Create/Modify

| File | Action | Purpose |
|------|--------|---------|
| `app/core/config.py` | Modify | Add TRUSTED_ROOT_AIDS with multi-root support |
| `app/vvp/keri/cesr.py` | Modify | Add decode_pss_signature for 0B prefix |
| `app/vvp/keri/kel_parser.py` | Modify | Add validate_witness_receipts with threshold |
| `app/vvp/keri/oobi.py` | Modify | Add validate_oobi_is_kel (extends existing module) |
| `app/vvp/acdc/__init__.py` | Create | Package init |
| `app/vvp/acdc/models.py` | Create | ACDC dataclasses |
| `app/vvp/acdc/parser.py` | Create | ACDC parsing with canonicalization |
| `app/vvp/acdc/verifier.py` | Create | ACDC verification with chain validation |
| `app/vvp/acdc/exceptions.py` | Create | ACDCError hierarchy (maps to existing ErrorCodes) |
| `tests/test_cesr_pss.py` | Create | PSS decoding tests |
| `tests/test_witness_receipts.py` | Create | Witness validation tests |
| `tests/test_acdc.py` | Create | ACDC verification tests with keripy fixtures |

## Implementation Order

1. **1.9**: Root of trust configuration (foundation)
2. **3.17**: PSS CESR signature decoding (unblocks PASSporT verification)
3. **7.16**: Witness receipt validation (completes KEL verification)
4. **7.17**: OOBI content validation (completes key resolution)
5. **8.1-8.4**: ACDC parsing (structure validation)
6. **8.5-8.6**: ACDC SAID validation (integrity)
7. **8.7-8.8**: Issuer key state resolution (uses existing)
8. **8.9-8.10**: ACDC signature verification (authenticity)
9. **8.13-8.14**: Credential chain validation (trust)

## Resolved Questions (per Reviewer)

1. **Should TRUSTED_ROOT_AIDS support multiple roots?**
   - **Answer**: Yes. Use comma-separated `VVP_TRUSTED_ROOT_AIDS` env var, normalized to a frozenset.

2. **What's the default witness threshold for receipt validation?**
   - **Answer**: Follow KEL witness thresholds from the event itself (`kt` field). If absent, default to majority of witnesses. Do not hardcode 2-of-3.

3. **Should we cache resolved ACDC chains?**
   - **Answer**: Yes, keyed by `(credential_said, hash(trusted_roots))` with short TTL. Reuse existing cache patterns from `app/vvp/keri/cache.py`.

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| CESR format complexity | Medium | High | Extensive unit tests with real CESR samples |
| Chain validation loops | Low | High | Add visited set to detect cycles |
| Performance on deep chains | Low | Medium | Add depth limit (e.g., 10 levels) |
| Missing test credentials | Medium | High | Create synthetic test ACDCs with known SAIDs |

---

## Implementation Notes

### Deviations from Plan

1. **validate_witness_receipts return type**: Changed from `int` to `List[str]` to return the list of validated witness AIDs, not just the count. This provides more useful information for debugging and logging.

2. **pysodium import in verifier.py**: Moved the `import pysodium` inside the `verify_acdc_signature()` function to avoid import errors when the module is loaded in environments without libsodium installed (test environments may not have it configured).

### Implementation Details

1. **Root of Trust Configuration**: Added `_parse_trusted_roots()` helper and `TRUSTED_ROOT_AIDS` frozenset to `config.py`. Supports comma-separated environment variable with whitespace trimming and empty entry filtering.

2. **PSS CESR Decoding**: Added `decode_pss_signature()` to `cesr.py`. Handles 0A, 0B, 0C, 0D, and AA derivation codes. Validates 88-character length and returns 64-byte Ed25519 signature.

3. **Witness Receipt Validation**: Enhanced `validate_witness_receipts()` in `kel_parser.py` with proper threshold computation (event.toad → majority default) and returns list of validated AIDs.

4. **OOBI Content Validation**: Added `validate_oobi_is_kel()` to `oobi.py`. Validates KEL structure, checks for inception event, validates chain integrity, and extracts KeyState.

5. **ACDC Package**: Created complete `app/vvp/acdc/` package with:
   - `exceptions.py`: ACDCError hierarchy mapping to existing ErrorCodes
   - `models.py`: ACDC and ACDCChainResult dataclasses
   - `parser.py`: ACDC parsing and SAID validation with canonicalization
   - `verifier.py`: Signature verification and chain validation

### Test Results

```
560 passed, 2 skipped in 3.81s
```

New tests added:
- `tests/test_cesr_pss.py`: 8 tests for PSS signature decoding
- `tests/test_witness_receipts.py`: 8 tests for witness validation
- `tests/test_acdc.py`: 36 tests for ACDC verification (including credential type and schema validation)
- `tests/test_trusted_roots.py`: 7 tests for root configuration
- `tests/test_passport.py`: 6 new tests for CESR signature integration

### Files Changed

| File | Lines | Summary |
|------|-------|---------|
| `app/core/config.py` | +31 | Added TRUSTED_ROOT_AIDS with multi-root support |
| `app/vvp/keri/cesr.py` | +65 | Added decode_pss_signature() |
| `app/vvp/keri/kel_parser.py` | +40 | Enhanced validate_witness_receipts() |
| `app/vvp/keri/kel_resolver.py` | +58 | Added _fetch_and_validate_oobi() for §4.2 compliance |
| `app/vvp/keri/oobi.py` | +98 | Added validate_oobi_is_kel() |
| `app/vvp/keri/signature.py` | +6 | Moved pysodium to lazy import |
| `app/vvp/passport.py` | +35 | Integrated CESR PSS signature decoding |
| `app/vvp/acdc/__init__.py` | +55 | Package exports (added validate_schema_said, KNOWN_SCHEMA_SAIDS) |
| `app/vvp/acdc/exceptions.py` | +50 | ACDCError hierarchy |
| `app/vvp/acdc/models.py` | +98 | ACDC and ACDCChainResult |
| `app/vvp/acdc/parser.py` | +137 | ACDC parsing and SAID validation |
| `app/vvp/acdc/verifier.py` | +318 | Signature, chain, schema, and credential type validation |
| `tests/test_cesr_pss.py` | +91 | PSS decoding tests |
| `tests/test_witness_receipts.py` | +249 | Witness validation tests |
| `tests/test_acdc.py` | +370 | ACDC verification tests (including type and schema) |
| `tests/test_trusted_roots.py` | +98 | Root configuration tests |
| `tests/test_passport.py` | +83 | CESR signature integration tests |
| `tests/test_witness_validation.py` | +10 | Updated for new return type |
| `tests/test_kel_cesr_integration.py` | +4 | Updated for new return type |

---

## Revision 2: Addressing Reviewer Feedback

### Changes Requested (from REVIEW.md)

The reviewer identified five issues that needed to be addressed:

1. **[High] PSS CESR decoding not used in PASSporT parsing**
2. **[High] OOBI KEL validation never invoked**
3. **[High] APE/DE/TNAlloc validation rules defined but not applied**
4. **[Medium] Chain validation doesn't validate schema SAIDs**
5. **[Low] pysodium still imported at module scope in signature.py**

### Fixes Applied

#### 1. PSS CESR Decoding Integration
- Updated `_decode_signature()` in `passport.py` to auto-detect CESR format
- CESR signatures (88 chars with 0A/0B/0C/0D/AA prefix) are decoded via `decode_pss_signature()`
- Standard JWS base64url signatures still work for backward compatibility
- Added 6 tests in `TestCESRSignature` class

#### 2. OOBI KEL Validation Enforcement
- Added `_fetch_and_validate_oobi()` helper in `kel_resolver.py`
- Validates: KEL data present, inception event at start, chain integrity
- Called from `resolve_key_state()` at line 151
- Uses `validate_kel_chain()` with appropriate settings for test fixtures

#### 3. APE/DE/TNAlloc Validation in Chain Walk
- Updated `walk_chain()` in `verifier.py` to call type-specific validators
- APE: `validate_ape_credential()` checks for vetting edge
- DE: `validate_de_credential()` checks PSS signer matches delegate
- TNAlloc: `validate_tnalloc_credential()` checks TN subset of parent
- Added 9 tests for credential type validation

#### 4. Schema SAID Validation
- Added `KNOWN_SCHEMA_SAIDS` dict with vLEI governance schemas
- Added `validate_schema_said()` function (strict/non-strict modes)
- Added `validate_schemas` parameter to `validate_credential_chain()`
- Added 7 tests for schema validation

#### 5. pysodium Lazy Import
- Removed module-level `import pysodium` from `signature.py`
- Added import inside `verify_passport_signature()` and `verify_passport_signature_tier2()`
- Added docstring explaining lazy import rationale

---

## Revision 3: PSS Signer AID Parameter for DE Validation

### Issue from REVIEW.md

> **[High]**: `validate_credential_chain()` does not accept a PASSporT signer AID, so DE validation
> falls back to `acdc.issuer_aid` for the leaf. This is not equivalent to the PSS signer binding
> required by §6.3.4 and makes the DE check ineffective in delegation scenarios.

### Fix Applied

#### 1. Added `pss_signer_aid` Parameter to `validate_credential_chain()`

**File:** `app/vvp/acdc/verifier.py`

- Added `pss_signer_aid: Optional[str] = None` parameter to function signature (line 159)
- Updated docstring to document the parameter and its purpose
- Updated `walk_chain()` inner function to accept and use `pss_signer_aid` directly
- Fixed initial call to `walk_chain()` to pass `pss_signer_aid` through (line 312)
- DE validation now uses the caller-provided `pss_signer_aid` (from PASSporT kid field)
  rather than falling back to `acdc.issuer_aid`

#### 2. Added Chain-Level DE Tests

**File:** `tests/test_acdc.py`

Added two new tests in `TestCredentialTypeValidation`:

1. `test_de_chain_pss_signer_mismatch_raises` - Verifies that DE chain validation
   fails when `pss_signer_aid` doesn't match the delegate AID in the DE credential

2. `test_de_chain_pss_signer_match_passes` - Verifies that DE chain validation
   passes when `pss_signer_aid` matches the delegate AID

### Usage

The caller who has access to the PASSporT (and thus the `kid` field containing the
signer's AID) should pass this as `pss_signer_aid`:

```python
# In verify.py or wherever chain validation is called
result = await validate_credential_chain(
    acdc=credential,
    trusted_roots=TRUSTED_ROOT_AIDS,
    dossier_acdcs=dossier_map,
    pss_signer_aid=passport.header.kid  # The PASSporT signer's AID
)
```

### Test Results

```
tests/test_acdc.py::TestCredentialTypeValidation::test_de_chain_pss_signer_mismatch_raises PASSED
tests/test_acdc.py::TestCredentialTypeValidation::test_de_chain_pss_signer_match_passes PASSED
```

Overall: 175 passed, 2 skipped (skipped tests are environmental - libsodium not installed)
