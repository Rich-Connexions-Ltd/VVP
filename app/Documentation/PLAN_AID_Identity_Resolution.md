# Phase: AID to Identity Resolution Enhancement

## Problem Statement

The VVP verifier resolves AID key state and validates credential chains, but does not expose the semantic identity of issuers (legal name, LEI) in the API response. Identity information is only available in the UI layer, preventing downstream systems from programmatically accessing issuer identity.

## Spec References

- §6.3: Credentials contain identity attributes (legalName, LEI, vCard)
- §6.3.x: Schema validation for credential types
- KERI: AID alone represents cryptographic control, not semantic identity

## Current State

1. `VerifyResponse` returns claim tree, signer_aid, delegation_chain - but no identity
2. Identity extraction exists in `credential_viewmodel.py` (UI layer only)
3. vCard parsing handles LOGO, ORG, NOTE;LEI, CATEGORIES
4. Well-known AIDs provide fallback identity for root issuers

## Proposed Solution

### Priority 1: Expose Issuer Identities in API Response

Add new optional field `issuer_identities` to `VerifyResponse` containing resolved identities for all AIDs encountered during verification.

### Priority 2: Expand vCard Field Extraction

Extend `VCardInfo` to extract additional RFC 6350 fields: ADR, TEL, EMAIL, URL, FN.

---

## Reviewer Decisions (from REVIEW.md)

1. **Include delegation chain AIDs**: Yes, optionally when dossier-sourced identity exists
2. **Add organization_type field**: Not now, defer until normative source identified
3. **Well-known AIDs configurable**: Yes, make configurable with default built-in list

---

## Detailed Design

### Component 1: API Models (api_models.py)

**New Models:**

```python
class IssuerIdentityInfo(BaseModel):
    """Resolved identity for an AID.

    Note: This is INFORMATIONAL only and may be incomplete when
    dossiers are partial/compact. The identity_source indicates
    provenance: "dossier" includes direct attributes AND vCard-derived
    values; "wellknown" is from the built-in registry fallback.
    """
    aid: str
    legal_name: Optional[str] = None
    lei: Optional[str] = None
    source_said: Optional[str] = None  # SAID of LE credential
    identity_source: Literal["dossier", "wellknown"] = "dossier"

class VerifyResponse(BaseModel):
    # ... existing fields ...
    issuer_identities: Optional[Dict[str, IssuerIdentityInfo]] = None
```

### Component 2: Identity Extraction Module (vvp/identity.py)

Move/refactor identity extraction from UI layer to core verification layer.

**New file: `app/vvp/identity.py`**

```python
# Configurable well-known AIDs registry
# Default built-in list, overridable via WELLKNOWN_AIDS_FILE env var
WELLKNOWN_AIDS: Dict[str, tuple[str, Optional[str]]] = _load_wellknown_aids()

def build_issuer_identity_map(acdcs: List[ACDC]) -> Dict[str, IssuerIdentity]:
    """Extract identity information from LE credentials in dossier."""

def get_wellknown_identity(aid: str) -> Optional[IssuerIdentity]:
    """Get identity from well-known AIDs registry."""

def _load_wellknown_aids() -> Dict[str, tuple[str, Optional[str]]]:
    """Load well-known AIDs from file or use defaults."""
```

This extracts the identity logic from `credential_viewmodel.py` so it can be called from `verify.py` without pulling in UI dependencies.

### Component 3: Verification Flow (verify.py)

**Integration Point:** `verify_vvp()` function at line 687, after Phase 5.5 (ACDC chain verification, ~line 1120) and before the return statement at line 1436.

```python
# After Phase 5.5 chain verification, before building final response
# ~line 1420 in verify_vvp()

# Build issuer identity map from dossier credentials
issuer_identities = None
if dag is not None and dag.nodes:
    from .identity import build_issuer_identity_map, IssuerIdentity
    from .acdc import ACDC

    # Convert DAG nodes to ACDC list for identity extraction
    acdcs = [_dag_node_to_acdc(said, node) for said, node in dag.nodes.items()]
    identity_map = build_issuer_identity_map(acdcs)

    # Include delegation chain AIDs if available
    if delegation_chain_data and delegation_chain_data.chain:
        for node in delegation_chain_data.chain:
            if node.aid not in identity_map:
                # Check well-known registry for delegation chain AIDs
                from .identity import get_wellknown_identity
                wk = get_wellknown_identity(node.aid)
                if wk:
                    identity_map[node.aid] = wk

    if identity_map:
        issuer_identities = {
            aid: IssuerIdentityInfo(
                aid=aid,
                legal_name=ident.legal_name,
                lei=ident.lei,
                source_said=ident.source_said,
                identity_source="dossier" if ident.source_said else "wellknown",
            )
            for aid, ident in identity_map.items()
        }

# Line 1436
return request_id, VerifyResponse(
    request_id=request_id,
    overall_status=overall_status,
    claims=claims,
    errors=errors if errors else None,
    has_variant_limitations=has_variant_limitations,
    delegation_chain=delegation_chain_data,
    signer_aid=signer_aid,
    toip_warnings=toip_warnings,
    issuer_identities=issuer_identities,  # NEW
)
```

### Component 4: Expanded vCard Parsing

**Update VCardInfo dataclass:**

```python
@dataclass
class VCardInfo:
    logo_url: Optional[str] = None
    logo_hash: Optional[str] = None
    org: Optional[str] = None
    lei: Optional[str] = None
    categories: Optional[str] = None
    # New fields
    fn: Optional[str] = None          # Full name
    adr: Optional[str] = None         # Address
    tel: Optional[str] = None         # Telephone
    email: Optional[str] = None       # Email
    url: Optional[str] = None         # Website URL
    raw_lines: List[str] = field(default_factory=list)
```

**Update _parse_vcard_lines():**

Add parsing for: FN, ADR, TEL, EMAIL, URL

---

## Files to Create/Modify

| File | Action | Purpose |
|------|--------|---------|
| `app/vvp/api_models.py` | Modify | Add IssuerIdentityInfo, update VerifyResponse |
| `app/vvp/identity.py` | Create | Core identity extraction module with configurable well-known AIDs |
| `app/vvp/verify.py` | Modify | Call identity extraction in `verify_vvp()` after Phase 5.5, add to response |
| `app/vvp/ui/credential_viewmodel.py` | Modify | Expand VCardInfo, update vCard parsing, import from identity.py |
| `tests/test_identity.py` | Create | Tests for identity extraction |
| `tests/test_credential_viewmodel.py` | Modify | Tests for expanded vCard parsing |
| `tests/test_verify.py` | Modify | Test issuer_identities in VerifyResponse

---

## Implementation Steps

### Step 1: Add API Models
1. Add `IssuerIdentityInfo` model to api_models.py
2. Add `issuer_identities` field to `VerifyResponse`

### Step 2: Create Identity Module
1. Create `app/vvp/identity.py`
2. Add `IssuerIdentity` dataclass (core version without UI concerns)
3. Add `_load_wellknown_aids()` to support env/file config via `WELLKNOWN_AIDS_FILE`
4. Add `WELLKNOWN_AIDS` dictionary with default built-in values
5. Add `build_issuer_identity_map()` function
6. Add `get_wellknown_identity()` function
7. Update credential_viewmodel.py to import from identity.py (avoid duplication)

### Step 3: Integrate into Verification Flow
1. Import identity module in verify.py
2. In `verify_vvp()` after Phase 5.5 (~line 1420), call `build_issuer_identity_map()` on DAG nodes
3. Include delegation chain AIDs via well-known lookup when dossier-sourced identity exists
4. Convert to API model and add `issuer_identities` to VerifyResponse at line 1436

### Step 4: Expand vCard Parsing
1. Add new fields to VCardInfo dataclass
2. Add parsing logic for FN, ADR, TEL, EMAIL, URL
3. Update tests

### Step 5: Write Tests
1. Test identity extraction from various LE credential formats
2. Test well-known AID fallback
3. Test API response includes issuer_identities
4. Test expanded vCard field parsing

---

## Test Strategy

1. **Unit tests for identity.py:**
   - Extract identity from LE credential with legalName/LEI
   - Extract identity from lids field (string, dict, list variants)
   - Extract identity from vCard ORG fallback (counts as "dossier" source)
   - Well-known AID resolution returns "wellknown" source
   - Handle missing/malformed credentials
   - Configurable well-known AIDs via `WELLKNOWN_AIDS_FILE` env var

2. **Integration tests for verify.py:**
   - VerifyResponse includes issuer_identities when dossier present
   - **issuer_identities is None (not empty dict) when no dossier present**
   - Multiple issuers correctly mapped
   - Delegation chain AIDs included when dossier identity exists for them

3. **Unit tests for vCard parsing:**
   - Parse FN, ADR, TEL, EMAIL, URL fields
   - Handle case-insensitive field names
   - Handle malformed lines gracefully

---

## Verification

```bash
# Run identity tests
./scripts/run-tests.sh tests/test_identity.py -v

# Run vCard parsing tests
./scripts/run-tests.sh tests/test_credential_viewmodel.py -v -k vcard

# Run full verification tests
./scripts/run-tests.sh tests/test_verify.py -v

# Verify API response manually
curl -X POST http://localhost:8000/verify \
  -H "Content-Type: application/json" \
  -d '{"passport": "...", "dossier_url": "..."}' | jq '.issuer_identities'

# Test issuer_identities is None when no dossier
./scripts/run-tests.sh tests/test_verify.py -v -k "no_dossier"
```

---

## Resolved Questions (per Reviewer)

1. **Include delegation chain AIDs?** → Yes, optionally when dossier-sourced identity exists
2. **Add organization_type?** → Not now, defer until normative source identified
3. **Well-known AIDs configurable?** → Yes, via `WELLKNOWN_AIDS_FILE` env var with built-in defaults

---

## Notes

- `issuer_identities` is **INFORMATIONAL** and may be incomplete when dossiers are partial/compact
- `identity_source: "dossier"` includes both direct attributes AND vCard-derived values
- `identity_source: "wellknown"` is used for built-in registry fallback only
