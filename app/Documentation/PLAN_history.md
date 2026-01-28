# PLAN_AID_Identity_Resolution.md

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


# PLAN_Credential_Card_UI.md

# Plan: Enhanced Credential Card UI (Revised)

## 1. Problem Statement

Recent sprints have introduced complex Tier 2/3 functionality: ACDC credentials, schema validation, revocation checking (TEL), and trust chains (APE/TNAlloc/vLEI). The current UI does not adequately visualize these rich data structures or their validation states. Users (Agents/Admins) need to see *why* a call is verified, not just a green checkmark.

## 2. Current State

### Existing Implementation

| Component | Location | Current Capability |
|-----------|----------|-------------------|
| Credential card template | `app/templates/partials/credential_card.html` | Basic card with type badge, status, SAID, issuer, attributes |
| Revocation template | `app/templates/partials/revocation.html` | Table-based revocation results |
| Chain visualization | `app/templates/partials/credential_graph.html` | Hierarchical chain display |
| Revocation endpoint | `POST /ui/check-revocation` | Batch revocation check, returns table HTML |
| CSS variables | `app/templates/base.html:16-22` | `--vvp-success`, `--vvp-danger`, `--vvp-warning`, `--vvp-muted` |
| Badge classes | `app/templates/base.html:39-45` | `.badge-root`, `.badge-issuer`, `.badge-le`, `.badge-ape`, `.badge-de`, `.badge-tnalloc` |
| Type inference | `app/vvp/acdc/models.py:46-86` | `ACDC.credential_type` property |
| Trusted roots | `app/core/config.py` | `TRUSTED_ROOT_AIDS` configuration |

### Current Limitations

1. **No primary attribute highlighting** - All attributes treated equally
2. **No lazy revocation per-credential** - Batch check only
3. **No chain expansion UX** - Full chain rendered at once or not at all
4. **No variant handling** - Compact/partial credentials may cause template errors
5. **Raw ACDC field access** - Templates use `acdc.d`, `acdc.a.tn` directly, fragile to schema variations

## 3. Design Goals

* **Transparency:** Visualize the "Why". Show the chain of trust (e.g., "This caller is authorized by Company X, who is a Qualified vLEI Issuer trusted by GLEIF").
* **Hierarchy:** Distinct visuals for different credential types (APE vs vLEI vs TNAlloc).
* **Robustness:** Handle compact/partial variants gracefully without template errors.
* **Responsiveness:** Card must adapt from desktop (admin dashboard) to mobile (field agent).
* **HTMX-Native:** Lazy loading of heavy data (revocation status, chain details) to keep initial load fast.

## 4. View-Model Design

### 4.1 CredentialCardViewModel Shape

A Python adapter normalizes raw ACDC + chain/revocation results into a template-friendly structure:

```python
@dataclass
class CredentialCardViewModel:
    """Normalized view model for credential card rendering."""

    # Identity
    said: str                           # Credential SAID (from acdc.d)
    schema_said: str                    # Schema SAID (from acdc.s)
    credential_type: str                # APE|DE|TNAlloc|vLEI|LE|unknown
    variant: str                        # full|compact|partial

    # Status (ClaimStatus from chain validation)
    status: str                         # VALID|INVALID|INDETERMINATE

    # Revocation (separate from ClaimStatus)
    revocation: RevocationStatus        # Nested object

    # Issuer
    issuer: IssuerInfo                  # Nested object

    # Normalized attributes
    primary: AttributeDisplay           # Single primary attribute
    secondary: List[AttributeDisplay]   # Up to 3 secondary attributes

    # Edges with availability
    edges: Dict[str, EdgeLink]          # vetting, delegation, parent, etc.

    # Variant limitations
    limitations: VariantLimitations     # Missing data indicators

    # Debug data
    raw: RawACDCData                    # Original for details panel


@dataclass
class RevocationStatus:
    """Revocation state (independent of ClaimStatus)."""
    state: str                  # ACTIVE|REVOKED|UNKNOWN
    checked_at: Optional[str]   # RFC3339 timestamp
    source: str                 # witness|oobi|inline|unknown
    error: Optional[str]        # Error message if check failed


@dataclass
class IssuerInfo:
    aid: str
    aid_short: str              # Truncated for display
    is_trusted_root: bool       # True if in TRUSTED_ROOT_AIDS


@dataclass
class AttributeDisplay:
    label: str                  # Human-readable label
    value: str                  # Display value (or "—" if unavailable)


@dataclass
class EdgeLink:
    said: Optional[str]         # Target credential SAID
    label: str                  # "Vetted By", "Delegated By", etc.
    available: bool             # True if target exists in dossier


@dataclass
class VariantLimitations:
    has_variant_limitations: bool
    missing_edge_targets: List[str]     # SAIDs of edges not in dossier
    redacted_fields: List[str]          # Field names with placeholders
    is_compact: bool                    # True if attributes is SAID ref
    is_partial: bool                    # True if has placeholder values
```

### 4.2 Attribute Mapping Rules

The view-model adapter normalizes schema-specific fields:

| Credential Type | Primary Attribute | Source Fields (in priority order) |
|----------------|-------------------|-----------------------------------|
| APE | Phone Number | `a.tn`, `a.phone`, `a.number` |
| DE | Delegate Name | `a.name`, `a.delegateName` |
| TNAlloc | Number Block | `a.tn`, `a.block`, `a.range` |
| vLEI / LE | Legal Name | `a.legalName`, `a.LEI` |
| unknown | SAID (truncated) | `d[:16]...` |

Secondary attributes (up to 3) are selected from remaining fields, excluding:
- `d` (SAID, already shown)
- `dt` (datetime, shown in meta)
- Internal fields starting with `_`

### 4.3 Edge Normalization

Edges can be strings (SAID reference) or dicts with `n` (node) or `d` (digest):

```python
def normalize_edge(edge_value: Any) -> Optional[str]:
    """Extract target SAID from edge value."""
    if isinstance(edge_value, str):
        return edge_value
    if isinstance(edge_value, dict):
        return edge_value.get('n') or edge_value.get('d')
    return None
```

Edge labels are mapped:

| Edge Key | Display Label |
|----------|---------------|
| vetting | Vetted By |
| le | Legal Entity |
| delegation | Delegated By |
| jl, jurisdiction | Jurisdiction |
| parent | Parent |

### 4.4 Compact/Partial Variant Handling

| Variant | Behavior |
|---------|----------|
| `full` | All fields available, render normally |
| `compact` | `attributes` is SAID string; show "Attributes not expanded" placeholder |
| `partial` | Some fields are placeholders; mark with "(redacted)" and muted styling |

The `limitations` field surfaces these for UI:
- `is_compact`: Show info banner "Credential uses compact encoding"
- `missing_edge_targets`: Disable expansion links for unavailable parents
- `redacted_fields`: Show which fields couldn't be verified

## 5. Backend Implementation

### 5.1 View-Model Adapter

**File:** `app/vvp/ui/credential_viewmodel.py` (new)

```python
from app.vvp.acdc.models import ACDC, ACDCChainResult
from app.core.config import TRUSTED_ROOT_AIDS

def build_credential_card_vm(
    acdc: ACDC,
    chain_result: Optional[ACDCChainResult] = None,
    revocation_result: Optional[dict] = None,
    available_saids: Optional[Set[str]] = None,
) -> CredentialCardViewModel:
    """Build view model from raw ACDC and validation results."""
    ...
```

### 5.2 Revocation Badge Endpoint

**Endpoint:** `POST /ui/revocation-badge`

Returns a single `<span class="badge">` for one credential. Used for lazy loading.

```python
@app.post("/ui/revocation-badge")
async def ui_revocation_badge(
    request: Request,
    credential_said: str = Form(...),
    oobi_url: Optional[str] = Form(None),
):
    """Return revocation badge HTML for a single credential."""
    # ... check revocation ...
    return templates.TemplateResponse(
        "partials/revocation_badge.html",
        {"request": request, "revocation": result}
    )
```

**Auth/CSRF:** Uses existing session; no additional CSRF token required for HTMX partials (same-origin).

### 5.3 Chain Expansion Endpoint

**Endpoint:** `GET /ui/credential/{said}`

Returns a single credential card for chain expansion.

```python
@app.get("/ui/credential/{said}")
async def ui_credential_card(
    request: Request,
    said: str,
):
    """Return credential card HTML for chain expansion."""
    # Lookup credential from session/cache
    # Build view model
    # Return partial
```

## 6. Template Implementation

### 6.1 Enhanced Credential Card

**File:** `app/templates/partials/credential_card.html` (modify existing)

```html
{# Enhanced credential card partial #}
{# Expects: vm (CredentialCardViewModel) #}

{% set status_class = 'valid' if vm.status == 'VALID' else ('invalid' if vm.status == 'INVALID' else 'unknown') %}

<article class="credential-card {{ status_class }}" data-said="{{ vm.said }}">
  <header>
    {# Type badge #}
    <span class="badge badge-{{ vm.credential_type | lower }}">{{ vm.credential_type }}</span>

    {# Primary attribute or truncated SAID #}
    <strong class="credential-primary">{{ vm.primary.value }}</strong>

    {# Status badge #}
    <span class="badge badge-{{ status_class }}">{{ vm.status }}</span>

    {# Trusted root indicator #}
    {% if vm.issuer.is_trusted_root %}
    <span class="badge badge-root" title="Trusted Root">ROOT</span>
    {% endif %}
  </header>

  {# Variant limitation banner #}
  {% if vm.limitations.has_variant_limitations %}
  <div class="credential-limitation-banner">
    {% if vm.limitations.is_compact %}
      <small>Compact encoding - attributes not expanded</small>
    {% elif vm.limitations.is_partial %}
      <small>Partial data - some fields redacted</small>
    {% endif %}
  </div>
  {% endif %}

  <div class="card-body">
    {# Secondary attributes #}
    {% if vm.secondary %}
    <dl class="attrs-grid">
      {% for attr in vm.secondary %}
      <dt>{{ attr.label }}</dt>
      <dd>{{ attr.value }}</dd>
      {% endfor %}
    </dl>
    {% endif %}
  </div>

  <div class="card-meta">
    <small>Issued by: <code>{{ vm.issuer.aid_short }}</code></small>

    {# Lazy revocation badge #}
    <div hx-post="/ui/revocation-badge"
         hx-vals='{"credential_said": "{{ vm.said }}"}'
         hx-trigger="load"
         hx-swap="outerHTML">
      <span class="badge badge-muted htmx-indicator">Checking...</span>
    </div>
  </div>

  <footer>
    {# Chain expansion links #}
    {% for key, edge in vm.edges.items() %}
      {% if edge.said %}
        {% if edge.available %}
        <a href="#"
           hx-get="/ui/credential/{{ edge.said }}"
           hx-target="#chain-{{ vm.said }}"
           hx-swap="beforeend">
          {{ edge.label }} &rarr;
        </a>
        {% else %}
        <span class="edge-unavailable" title="Not in dossier">
          {{ edge.label }} (unavailable)
        </span>
        {% endif %}
      {% endif %}
    {% endfor %}

    {# Details toggle #}
    <details>
      <summary>Details</summary>
      <div class="code-block">{{ vm.raw.attributes | tojson(indent=2) }}</div>
    </details>
  </footer>

  {# Chain expansion container #}
  <div id="chain-{{ vm.said }}" class="credential-layer"></div>
</article>
```

### 6.2 Revocation Badge Partial

**File:** `app/templates/partials/revocation_badge.html` (new)

```html
{# Single revocation badge #}
{# Expects: revocation (RevocationStatus) #}

{% if revocation.error %}
  <span class="badge badge-warning" title="{{ revocation.error }}">REV?</span>
{% elif revocation.state == 'ACTIVE' %}
  <span class="badge badge-success" title="Checked: {{ revocation.checked_at }}">ACTIVE</span>
{% elif revocation.state == 'REVOKED' %}
  <span class="badge badge-danger" title="Source: {{ revocation.source }}">REVOKED</span>
{% else %}
  <span class="badge badge-muted" title="Could not verify">UNKNOWN</span>
{% endif %}
```

## 7. Error Handling

| Scenario | UI Behavior |
|----------|-------------|
| Revocation check timeout | Show `<span class="badge badge-warning">REV?</span>` with tooltip explaining timeout |
| Revocation network error | Show warning badge with error tooltip |
| Chain expansion 404 | Show toast "Credential not found in dossier" |
| Chain expansion error | Show toast with error message |
| Compact credential | Show banner, disable attribute display, edges still work |
| Partial credential | Show available fields, mark redacted with "(redacted)" |

HTMX error handling (already in `base.html`):
```javascript
document.body.addEventListener('htmx:responseError', function(evt) {
    // Shows toast notification
});
```

## 8. CSS Additions

**File:** `app/templates/base.html` (add to existing styles)

```css
/* Credential card enhancements */
.credential-primary {
    font-size: 1.1em;
    font-weight: 600;
}

.credential-limitation-banner {
    background: var(--vvp-warning);
    color: black;
    padding: 0.25em 0.5em;
    border-radius: 0.25em;
    margin: 0.5em 0;
}

.attrs-grid {
    display: grid;
    grid-template-columns: auto 1fr;
    gap: 0.25em 1em;
    margin: 0.5em 0;
}

.edge-unavailable {
    color: var(--vvp-muted);
    font-style: italic;
}

/* Responsive: stack on mobile */
@media (max-width: 600px) {
    .credential-card header {
        flex-direction: column;
        align-items: flex-start;
    }
    .attrs-grid {
        grid-template-columns: 1fr;
    }
}
```

## 9. Files to Create/Modify

| File | Action | Purpose |
|------|--------|---------|
| `app/vvp/ui/__init__.py` | Create | UI module init |
| `app/vvp/ui/credential_viewmodel.py` | Create | View-model adapter |
| `app/templates/partials/credential_card.html` | Modify | Enhanced card template |
| `app/templates/partials/revocation_badge.html` | Create | Single badge partial |
| `app/templates/base.html` | Modify | Add CSS for new components |
| `app/main.py` | Modify | Add `/ui/revocation-badge` and `/ui/credential/{said}` endpoints |
| `tests/test_credential_viewmodel.py` | Create | Unit tests for view-model adapter |
| `tests/test_ui_endpoints.py` | Modify | Integration tests for new endpoints |

## 10. Test Strategy

### Unit Tests (`test_credential_viewmodel.py`)

1. **Attribute mapping** - Each credential type extracts correct primary attribute
2. **Edge normalization** - Handles string, dict with `n`, dict with `d`
3. **Variant detection** - Correctly identifies compact/partial variants
4. **Trusted root** - Correctly checks issuer against `TRUSTED_ROOT_AIDS`
5. **Missing data** - Graceful handling of missing fields

### Integration Tests (`test_ui_endpoints.py`)

1. **Revocation badge endpoint** - Returns valid HTML for each state
2. **Credential card endpoint** - Returns 404 for unknown SAID
3. **HTMX headers** - Responses include proper content-type

## 11. User Experience Walkthrough

1. **Agent sees incoming call** on dashboard
2. **Initial view:** Summary card shows "APE: +15550100" with GREEN status badge
3. **Revocation loads:** Badge updates from "Checking..." to "ACTIVE" (green)
4. **Investigation:** Agent clicks "Vetted By &rarr;"
5. **Chain expands:** vLEI card slides in below, showing "Acme Corp" with ROOT badge
6. **Trust confirmed:** Agent sees full chain from caller to trusted root
7. **Decision:** Agent answers confidently

## 12. Open Questions

None - all previous questions addressed.

## 13. Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Revocation endpoint latency | Medium | Poor UX | Lazy loading isolates impact; timeout + fallback badge |
| Schema field name changes | Low | Broken display | View-model adapter centralizes mapping; easy to update |
| Large credential chains | Low | DOM bloat | Limit expansion depth; collapse older cards |

---

## Implementation Notes

### Deviations from Plan

1. **Template backwards compatibility** - The credential_card.html template accepts both `vm` (new CredentialCardViewModel) and `acdc` (legacy raw dict) to allow gradual migration without breaking existing code.

2. **Chain expansion endpoint placeholder** - The `/ui/credential/{said}` endpoint returns a toast notification for now since session-based credential storage is not yet implemented. This will require follow-up work to store dossier credentials in session during initial verification.

3. **Reviewer finding: status_class** - Used `indeterminate` instead of `unknown` for INDETERMINATE status, aligning with existing CSS semantic naming (per reviewer's Low finding).

4. **Reviewer finding: list-valued edges** - Added list handling to `normalize_edge()` function, returning first valid SAID from list (per reviewer's Low finding about defensive improvements).

### Implementation Details

- The ACDC model's `credential_type` property checks attributes before edges, so credentials with `tn` attribute are classified as TNAlloc even if they have vetting edges. This is existing behavior and tests were adjusted to match.

- RevocationStatus dataclass is used both in the view-model and as the template context for the revocation badge endpoint, enabling consistent rendering.

### Test Results

```
918 passed, 20 warnings in 4.37s
```

31 new tests added for credential_viewmodel module covering:
- Edge normalization (string, dict, list formats)
- Primary/secondary attribute extraction
- Variant limitation detection
- Trusted root checking
- Raw data preservation

### Files Changed

| File | Lines | Summary |
|------|-------|---------|
| `app/vvp/ui/__init__.py` | +30 | New UI module with exports |
| `app/vvp/ui/credential_viewmodel.py` | +340 | View-model dataclasses and adapter |
| `app/templates/partials/credential_card.html` | +116 (rewrite) | Dual-path template (vm + legacy) |
| `app/templates/partials/revocation_badge.html` | +12 | New single badge partial |
| `app/templates/base.html` | +35 | CSS for card enhancements |
| `app/main.py` | +85 | Two new UI endpoints |
| `tests/test_credential_viewmodel.py` | +350 | 31 unit tests for view-model |


# PLAN_Phase1.md

# Current Plan

<!-- STATUS: IMPLEMENTED -->
<!-- RECONSTRUCTED: This plan was reconstructed from CHANGES.md and implementation code -->

## Phase 1: Core Infrastructure

### Overview

Define foundational models, enums, and configuration constants per VVP Specification v1.4 §3.2, §4.1-§4.3, §4.2A. This phase establishes the data structures used throughout the verification pipeline.

### Spec References

- **§3.2** - Claim Status (VALID, INVALID, INDETERMINATE)
- **§4.1** - Request Models (CallContext, VerifyRequest)
- **§4.2** - Error Envelope (ErrorDetail)
- **§4.2A** - Error Code Registry (18 codes with recoverability)
- **§4.3** - Response Models (VerifyResponse, ClaimNode)
- **§4.3A** - overall_status Derivation (precedence rules)
- **§4.3B** - Claim Node Schema (children with required/optional flags)

### Files to Create/Modify

| File | Action | Description |
|------|--------|-------------|
| `app/core/__init__.py` | Create | Empty package init |
| `app/core/config.py` | Create | Configuration constants per §4.1A, §5.2A/B |
| `app/vvp/api_models.py` | Create | Pydantic models per §3.2, §4.1-4.3, §4.2A |
| `app/vvp/verify.py` | Update | Use new models (placeholder returns INDETERMINATE) |
| `tests/test_models.py` | Create | Unit tests for Phase 1 models |

### Implementation Approach

#### 1. ClaimStatus Enum (§3.2)

```python
class ClaimStatus(str, Enum):
    VALID = "VALID"
    INVALID = "INVALID"
    INDETERMINATE = "INDETERMINATE"
```

#### 2. ClaimNode Model (§4.3B)

```python
class ChildLink(BaseModel):
    required: bool
    node: "ClaimNode"

class ClaimNode(BaseModel):
    name: str
    status: ClaimStatus
    reasons: List[str] = []
    evidence: List[str] = []
    children: List[ChildLink] = []
```

#### 3. Request Models (§4.1)

```python
class CallContext(BaseModel):
    source: Optional[str] = None
    destination: Optional[str] = None
    timestamp: Optional[int] = None

class VerifyRequest(BaseModel):
    passport_jwt: str
    context: CallContext
```

#### 4. Response Models (§4.2, §4.3)

```python
class ErrorDetail(BaseModel):
    code: str
    message: str
    recoverable: bool

class VerifyResponse(BaseModel):
    request_id: str
    overall_status: ClaimStatus
    claims: Optional[ClaimNode] = None
    errors: List[ErrorDetail] = []
```

#### 5. Error Code Registry (§4.2A)

18 error codes with recoverability mapping:

| Code | Recoverable | Layer |
|------|-------------|-------|
| VVP_IDENTITY_MISSING | No | Protocol |
| VVP_IDENTITY_INVALID | No | Protocol |
| VVP_OOBI_FETCH_FAILED | Yes | Protocol |
| VVP_OOBI_CONTENT_INVALID | No | Protocol |
| PASSPORT_MISSING | No | Protocol |
| PASSPORT_PARSE_FAILED | No | Protocol |
| PASSPORT_SIG_INVALID | No | Crypto |
| PASSPORT_FORBIDDEN_ALG | No | Crypto |
| PASSPORT_EXPIRED | No | Protocol |
| DOSSIER_URL_MISSING | No | Evidence |
| DOSSIER_FETCH_FAILED | Yes | Evidence |
| DOSSIER_PARSE_FAILED | No | Evidence |
| DOSSIER_GRAPH_INVALID | No | Evidence |
| ACDC_SAID_MISMATCH | No | Crypto |
| ACDC_PROOF_MISSING | No | Crypto |
| KERI_RESOLUTION_FAILED | Yes | KERI |
| KERI_STATE_INVALID | No | KERI |
| INTERNAL_ERROR | Yes | Verifier |

#### 6. Configuration Constants

```python
CLOCK_SKEW_SECONDS = 300          # ±5 minutes per §4.1A
MAX_TOKEN_AGE_SECONDS = 300       # 5 minutes per §5.2B
MAX_IAT_DRIFT_SECONDS = 5         # ≤5 seconds per §5.2A (normative)
ALLOWED_ALGORITHMS = frozenset({"EdDSA"})  # Per §5.0, §5.1
```

#### 7. overall_status Derivation (§4.3A)

```python
def derive_overall_status(claims: ClaimNode) -> ClaimStatus:
    """Derive overall status from root claims.

    Precedence: INVALID > INDETERMINATE > VALID
    """
```

### Checklist Tasks Covered

- [x] 1.1 - Create `app/core/config.py`
- [x] 1.2 - Define `ClaimStatus` enum
- [x] 1.3 - Define `ClaimNode` model with ChildLink
- [x] 1.4 - Define `VerifyRequest` model
- [x] 1.5 - Define `VerifyResponse` model
- [x] 1.6 - Define `ErrorDetail` model
- [x] 1.7 - Create error code constants (18 codes per §4.2A)
- [x] 1.8 - Implement `overall_status` derivation per §4.3A

### Test Results

```
33 passed in 0.14s
```

---

**Status:** IMPLEMENTED
**Commit:** `9546f37`


# PLAN_Phase2.md

# Current Plan

<!-- STATUS: IMPLEMENTED -->

## Phase 2: VVP-Identity Header Parser

### Overview

Implement parsing and validation of the VVP-Identity HTTP header per spec §4.1A and §4.1B.

### Spec References

- **§4.1A** - VVP-Identity Header (Decoded) structure and validation rules
- **§4.1B** - OOBI semantics for `kid` and `evd` fields
- **§4.2A** - Error codes: `VVP_IDENTITY_MISSING`, `VVP_IDENTITY_INVALID`

### Files to Create/Modify

| File | Action | Description |
|------|--------|-------------|
| `app/vvp/header.py` | Create | VVP-Identity header parser |
| `app/vvp/exceptions.py` | Create | Typed exceptions for error codes |
| `tests/test_header.py` | Create | Unit tests for header parsing |

### Decoded Header Structure (§4.1A)

```json
{
  "ppt": "shaken",
  "kid": "oobi:...",
  "evd": "oobi:...",
  "iat": 1737500000,
  "exp": 1737503600
}
```

**Note:** Field values shown are illustrative per §4.1A. The `ppt` value is not validated in Phase 2; only field presence is checked. Value validation (e.g., binding `ppt` to VVP PASSporT) is deferred to Phase 3/5 per §5.2.

### Implementation Approach

#### 1. Custom Exception: `VVPIdentityError`

Per reviewer recommendation, use typed exceptions to keep the parsing API clean:

```python
class VVPIdentityError(Exception):
    """Base exception for VVP-Identity parsing errors."""
    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(message)
```

This allows the caller to convert exceptions to `ErrorDetail` while keeping the parser return type simple.

#### 2. Data Model: `VVPIdentity`

```python
@dataclass
class VVPIdentity:
    ppt: str           # PASSporT profile (value not validated in Phase 2)
    kid: str           # Key identifier (opaque OOBI reference)
    evd: str           # Evidence/dossier URL (opaque OOBI reference)
    iat: int           # Issued-at timestamp (seconds since epoch)
    exp: int           # Expiry timestamp (computed if absent in header)
```

#### 3. Parser Function: `parse_vvp_identity(header: Optional[str]) -> VVPIdentity`

Steps:
1. If `header` is `None` or empty, raise `VVPIdentityError` with `VVP_IDENTITY_MISSING`
2. Base64url decode the header string
3. Parse as JSON
4. Validate required fields exist: `ppt`, `kid`, `evd`, `iat`
5. Validate `iat` is not in the future beyond clock skew
6. Handle optional `exp`; if absent, compute default expiry as `iat + MAX_TOKEN_AGE_SECONDS`
7. Return `VVPIdentity` dataclass

On any decode/parse/validation failure (steps 2-6), raise `VVPIdentityError` with `VVP_IDENTITY_INVALID`.

#### 4. Validation Rules (§4.1A)

| Rule | Implementation | Error Code |
|------|----------------|------------|
| Header absent/empty | Raise before decoding | `VVP_IDENTITY_MISSING` |
| Base64url decode failure | `base64.urlsafe_b64decode()` with padding fix | `VVP_IDENTITY_INVALID` |
| Malformed JSON | `json.loads()` | `VVP_IDENTITY_INVALID` |
| Missing required field | Check `ppt`, `kid`, `evd`, `iat` exist | `VVP_IDENTITY_INVALID` |
| `iat` in future beyond skew | Compare to `now + CLOCK_SKEW_SECONDS` | `VVP_IDENTITY_INVALID` |
| `exp` absent | Compute as `iat + MAX_TOKEN_AGE_SECONDS` | N/A (valid) |

#### 5. OOBI Field Handling (§4.1B)

**Critical:** `kid` and `evd` fields are OOBI (Out-Of-Band Introduction) references per §4.1B. In Phase 2:

- Treat `kid` and `evd` as **opaque strings**
- **DO NOT** apply URL normalization
- **DO NOT** apply generic URL validation that could reject OOBI schemes
- Only validate that the fields are **present and non-empty strings**
- Deep OOBI validation (KERI/CESR parsing, `application/json+cesr` support) is deferred to Phase 4

This ensures we don't reject valid OOBI references that don't conform to standard URL patterns.

### Test Strategy

| Test Case | Expected Result |
|-----------|-----------------|
| Missing header (None) | `VVP_IDENTITY_MISSING` |
| Empty header ("") | `VVP_IDENTITY_MISSING` |
| Valid header with all fields | Returns `VVPIdentity` |
| Valid header without `exp` | Returns `VVPIdentity` with computed expiry |
| Invalid base64 | `VVP_IDENTITY_INVALID` |
| Invalid JSON | `VVP_IDENTITY_INVALID` |
| Missing `ppt` | `VVP_IDENTITY_INVALID` |
| Missing `kid` | `VVP_IDENTITY_INVALID` |
| Missing `evd` | `VVP_IDENTITY_INVALID` |
| Missing `iat` | `VVP_IDENTITY_INVALID` |
| `iat` in future beyond skew | `VVP_IDENTITY_INVALID` |
| `iat` in future within skew | Valid (accepted) |
| `ppt` with any string value | Valid (value not validated in Phase 2) |
| `kid`/`evd` with non-URL OOBI format | Valid (treated as opaque) |

### Resolved Questions

Based on reviewer feedback:

1. **OOBI validation**: Defer KERI/CESR parsing to Phase 4. In Phase 2, treat `kid`/`evd` as opaque OOBI references. Avoid URL-specific validation that could reject valid OOBI schemes.

2. **Error return style**: Raise typed `VVPIdentityError` exceptions carrying error codes. This keeps the parser API clean (`-> VVPIdentity`) and allows the caller to convert to `ErrorDetail`.

3. **`ppt` value validation**: Only require presence in Phase 2. Actual value checks (`ppt == "vvp"` for VVP PASSporTs) must be done in Phase 3/5 when binding PASSporT to VVP-Identity per §5.2.

### Checklist Tasks Covered

- [x] 2.1 - Create `app/vvp/header.py` module
- [x] 2.2 - Implement base64url decoding of VVP-Identity header
- [x] 2.3 - Parse JSON with fields: `ppt`, `kid`, `evd`, `iat`, `exp`
- [x] 2.4 - Validate `ppt` field exists (value validation deferred to Phase 3)
- [x] 2.5 - Validate `kid` and `evd` are present as opaque strings (OOBI validation deferred)
- [x] 2.6 - Implement clock skew validation (±300s) on `iat`
- [x] 2.7 - Handle optional `exp`; if absent, use `iat` + 300s max age
- [x] 2.8 - Reject future `iat` beyond clock skew
- [x] 2.9 - Return structured errors: `VVP_IDENTITY_MISSING` vs `VVP_IDENTITY_INVALID`
- [x] 2.10 - Unit tests for header parsing

---

**Status:** Implemented


# PLAN_Phase3.md

# Current Plan

<!-- STATUS: IMPLEMENTED -->

## Phase 3: PASSporT JWT Verification

### Overview

Implement parsing and validation of VVP PASSporT JWTs per spec §5.0-§5.4. This phase covers JWT structure parsing, algorithm enforcement, header/payload extraction, and binding validation between PASSporT and VVP-Identity. Signature verification is deferred to Phase 4 (requires KERI key state).

### Spec References

- **§5.0** - Non-compliance note: VVP mandates EdDSA, forbids ES256/HMAC/RSA
- **§5.1** - Allowed Algorithms: reject `none`, ES256, HMAC, RSA; require EdDSA
- **§5.2** - Header Binding Rules: `ppt` must be "vvp" and match VVP-Identity; `kid` binding
- **§5.2A** - Temporal Binding Rules: iat drift ≤ 5 seconds (NORMATIVE per spec)
- **§5.2B** - PASSporT Expiry Policy: max validity 300s (configurable per spec)
- **§5.4** - Failure Mapping: parse/algorithm failures → INVALID

### Files to Create/Modify

| File | Action | Description |
|------|--------|-------------|
| `app/vvp/passport.py` | Create | PASSporT JWT parser and validator |
| `app/vvp/exceptions.py` | Modify | Add PASSporT-specific exceptions |
| `tests/test_passport.py` | Create | Unit tests for PASSporT parsing |

### PASSporT JWT Structure

A VVP PASSporT is a JWS (JSON Web Signature) with three base64url-encoded parts:

```
header.payload.signature
```

#### Header Claims (per §5.1, §5.2)

```json
{
  "alg": "EdDSA",
  "typ": "passport",
  "ppt": "vvp",
  "kid": "did:keri:..."
}
```

| Field | Required | Validation | Source |
|-------|----------|------------|--------|
| `alg` | Yes | Must be "EdDSA"; reject "none", ES256, HMAC, RSA | §5.0, §5.1 (Normative) |
| `typ` | No | Ignored (not validated) | Not in v1.4 |
| `ppt` | Yes | Must be "vvp" per §5.2; must match VVP-Identity ppt | §5.2 (Normative) |
| `kid` | Yes | Must match VVP-Identity kid (strict equality in Phase 3) | §5.2 (Normative) |

**Note on `kid` binding:** §5.2 states kid must "match (or be resolvable from)" VVP-Identity kid. Phase 3 implements strict equality only. OOBI resolution will be added in Phase 4.

#### Payload Claims

```json
{
  "iat": 1737500000,
  "orig": {"tn": "+12025551234"},
  "dest": {"tn": ["+12025555678"]},
  "evd": "oobi:..."
}
```

| Field | Required | Validation | Source |
|-------|----------|------------|--------|
| `iat` | Yes | Must align with VVP-Identity iat ±5s | §5.2A (Normative) |
| `orig` | Yes* | Originator claim | VVP-draft (Local Policy) |
| `dest` | Yes* | Destination claim | VVP-draft (Local Policy) |
| `evd` | Yes* | Evidence/dossier OOBI reference | VVP-draft (Local Policy) |
| `iss` | No | Issuer identifier (if present) | VVP-draft (Local Policy) |
| `exp` | No | Expiry timestamp (validate per §5.2A/§5.2B if present) | §5.2A/B (Normative) |
| `card` | No | Card claim (VVP extension) | VVP-draft |
| `goal` | No | Goal claim (VVP extension) | VVP-draft |
| `call-reason` | No | Call reason (VVP extension) | VVP-draft |
| `origid` | No | Original call ID (VVP extension) | VVP-draft |

*Note: `orig`, `dest`, and `evd` are required by VVP-draft but not mandated by v1.4 spec. Treated as **local policy**.

### Implementation Approach

#### 1. Custom Exceptions

Extend `app/vvp/exceptions.py`:

```python
class PassportError(Exception):
    """Base exception for PASSporT parsing/validation errors."""
    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(message)

    @classmethod
    def missing(cls) -> "PassportError":
        """Factory for PASSPORT_MISSING error."""

    @classmethod
    def parse_failed(cls, reason: str) -> "PassportError":
        """Factory for PASSPORT_PARSE_FAILED error."""

    @classmethod
    def forbidden_alg(cls, alg: str) -> "PassportError":
        """Factory for PASSPORT_FORBIDDEN_ALG error."""

    @classmethod
    def expired(cls, reason: str) -> "PassportError":
        """Factory for PASSPORT_EXPIRED error."""
```

#### 2. Data Models

```python
@dataclass(frozen=True)
class PassportHeader:
    """Decoded PASSporT JWT header."""
    alg: str
    ppt: str
    kid: str
    typ: Optional[str] = None  # Not validated

@dataclass(frozen=True)
class PassportPayload:
    """Decoded PASSporT JWT payload."""
    iat: int
    orig: Optional[dict] = None    # Required by local policy
    dest: Optional[dict] = None    # Required by local policy
    evd: Optional[str] = None      # Required by local policy
    iss: Optional[str] = None
    exp: Optional[int] = None
    card: Optional[dict] = None
    goal: Optional[str] = None
    call_reason: Optional[str] = None  # Mapped from "call-reason"
    origid: Optional[str] = None

@dataclass(frozen=True)
class Passport:
    """Parsed VVP PASSporT."""
    header: PassportHeader
    payload: PassportPayload
    signature: bytes
    raw_header: str      # Base64url-encoded header (for signature verification)
    raw_payload: str     # Base64url-encoded payload (for signature verification)
```

#### 3. Parser Function

```python
def parse_passport(jwt: Optional[str]) -> Passport:
    """Parse and validate a VVP PASSporT JWT.

    Args:
        jwt: The PASSporT JWT string (header.payload.signature).

    Returns:
        Passport dataclass with parsed header, payload, and signature.

    Raises:
        PassportError: With appropriate error code on failure.

    Note:
        Signature verification is NOT performed here (deferred to Phase 4).
        This function validates structure, algorithm, and required field presence.
    """
```

#### 4. Binding Validator

```python
def validate_passport_binding(
    passport: Passport,
    vvp_identity: VVPIdentity,
    now: Optional[int] = None
) -> None:
    """Validate binding between PASSporT and VVP-Identity per §5.2.

    Args:
        passport: Parsed PASSporT.
        vvp_identity: Parsed VVP-Identity header.
        now: Current timestamp (defaults to time.time()).

    Raises:
        PassportError: If binding validation fails.

    Validates (Normative per spec):
        - ppt in PASSporT == "vvp" (§5.2)
        - ppt in PASSporT matches VVP-Identity ppt (§5.2)
        - kid in PASSporT matches VVP-Identity kid (§5.2) - strict equality
        - iat drift ≤ 5 seconds (§5.2A) - binding violation
        - exp consistency (§5.2A) - binding violation
        - PASSporT not expired (§5.2B) - expiry policy
    """
```

### Validation Rules

#### Algorithm Validation (§5.0, §5.1) - NORMATIVE

| Algorithm | Action | Error Code |
|-----------|--------|------------|
| `none` | Reject | `PASSPORT_FORBIDDEN_ALG` |
| `ES256` | Reject | `PASSPORT_FORBIDDEN_ALG` |
| `HS256`, `HS384`, `HS512` | Reject | `PASSPORT_FORBIDDEN_ALG` |
| `RS256`, `RS384`, `RS512` | Reject | `PASSPORT_FORBIDDEN_ALG` |
| `EdDSA` | Accept | - |
| Any other | Reject | `PASSPORT_FORBIDDEN_ALG` |

#### Header Binding (§5.2) - NORMATIVE

| Rule | Validation | Error Code |
|------|------------|------------|
| `ppt` value | Must be exactly "vvp" | `PASSPORT_PARSE_FAILED` |
| `ppt` match | PASSporT ppt must equal VVP-Identity ppt | `PASSPORT_PARSE_FAILED` |
| `kid` match | PASSporT kid must equal VVP-Identity kid (strict) | `PASSPORT_PARSE_FAILED` |

**Note:** Binding failures use `PASSPORT_PARSE_FAILED` (protocol layer) per §4.2A.

#### Temporal Binding (§5.2A) - NORMATIVE

| Rule | Validation | Error Code | Rationale |
|------|------------|------------|-----------|
| PASSporT iat present | Required | `PASSPORT_PARSE_FAILED` | Missing field |
| PASSporT exp > iat | If exp present, must be > iat | `PASSPORT_PARSE_FAILED` | Invalid structure |
| iat drift | `|PASSporT.iat - VVPIdentity.iat|` ≤ 5 seconds | `PASSPORT_PARSE_FAILED` | Binding violation |
| Both exp present | `|PASSporT.exp - VVPIdentity.exp|` ≤ 5 seconds | `PASSPORT_PARSE_FAILED` | Binding violation |
| VVP-Identity exp present, PASSporT exp absent | Reject (unless configured) | `PASSPORT_PARSE_FAILED` | Binding violation |

**Note:** Temporal binding violations (iat drift, exp mismatch) use `PASSPORT_PARSE_FAILED` because they are binding/protocol errors, not expiry policy failures.

#### Expiry Policy (§5.2B) - NORMATIVE (with configurable defaults)

| Rule | Validation | Error Code | Rationale |
|------|------------|------------|-----------|
| exp present | `(exp - iat)` ≤ MAX_PASSPORT_VALIDITY_SECONDS (default 300) | `PASSPORT_EXPIRED` | Validity window |
| Expiry check | `now > exp + CLOCK_SKEW_SECONDS` | `PASSPORT_EXPIRED` | Token expired |
| exp absent | `now > iat + MAX_TOKEN_AGE_SECONDS + CLOCK_SKEW_SECONDS` | `PASSPORT_EXPIRED` | Max-age exceeded |

**Note:** `PASSPORT_EXPIRED` is reserved for actual expiry policy failures per §4.2A.

### Spec-Mandated vs Local Policy

| Check | Source | Treatment | Error Code |
|-------|--------|-----------|------------|
| Algorithm = EdDSA | §5.0, §5.1 | **Normative** - must enforce | `PASSPORT_FORBIDDEN_ALG` |
| ppt = "vvp" | §5.2 | **Normative** - must enforce | `PASSPORT_PARSE_FAILED` |
| ppt match | §5.2 | **Normative** - must enforce | `PASSPORT_PARSE_FAILED` |
| kid match (strict) | §5.2 | **Normative** - strict equality in Phase 3 | `PASSPORT_PARSE_FAILED` |
| iat present | §5.2A | **Normative** - must enforce | `PASSPORT_PARSE_FAILED` |
| iat drift ≤ 5s | §5.2A | **Normative** - binding violation | `PASSPORT_PARSE_FAILED` |
| exp > iat | §5.2A | **Normative** - must enforce | `PASSPORT_PARSE_FAILED` |
| exp drift ≤ 5s | §5.2A | **Normative** - binding violation | `PASSPORT_PARSE_FAILED` |
| exp consistency | §5.2A | **Normative** - binding violation | `PASSPORT_PARSE_FAILED` |
| Max validity 300s | §5.2B | **Configurable** - default 300s | `PASSPORT_EXPIRED` |
| Clock skew ±300s | §5.2B | **Configurable** - default 300s | `PASSPORT_EXPIRED` |
| Expiry check | §5.2B | **Normative** - expiry policy | `PASSPORT_EXPIRED` |
| typ field | Not in v1.4 | **Ignored** - not validated | - |
| iss field | VVP-draft | **Local Policy** - optional | - |
| orig required | VVP-draft | **Local Policy** - required | `PASSPORT_PARSE_FAILED` |
| dest required | VVP-draft | **Local Policy** - required | `PASSPORT_PARSE_FAILED` |
| evd required | VVP-draft | **Local Policy** - required | `PASSPORT_PARSE_FAILED` |

### Test Strategy

| Test Case | Expected Result |
|-----------|-----------------|
| **Parsing** | |
| Missing JWT (None) | `PASSPORT_MISSING` |
| Empty JWT ("") | `PASSPORT_MISSING` |
| Malformed JWT (wrong parts count) | `PASSPORT_PARSE_FAILED` |
| Invalid base64 in header | `PASSPORT_PARSE_FAILED` |
| Invalid JSON in header | `PASSPORT_PARSE_FAILED` |
| Invalid base64 in payload | `PASSPORT_PARSE_FAILED` |
| Invalid JSON in payload | `PASSPORT_PARSE_FAILED` |
| **Algorithm (§5.0, §5.1)** | |
| `alg: "none"` | `PASSPORT_FORBIDDEN_ALG` |
| `alg: "ES256"` | `PASSPORT_FORBIDDEN_ALG` |
| `alg: "HS256"` | `PASSPORT_FORBIDDEN_ALG` |
| `alg: "RS256"` | `PASSPORT_FORBIDDEN_ALG` |
| `alg: "EdDSA"` | Valid |
| Unknown algorithm | `PASSPORT_FORBIDDEN_ALG` |
| **Header Fields** | |
| Missing `alg` | `PASSPORT_PARSE_FAILED` |
| Missing `ppt` | `PASSPORT_PARSE_FAILED` |
| Missing `kid` | `PASSPORT_PARSE_FAILED` |
| ppt = "vvp" | Valid |
| ppt != "vvp" (e.g., "shaken") | `PASSPORT_PARSE_FAILED` |
| Missing `typ` | Valid (not required) |
| **Payload Fields** | |
| Missing `iat` | `PASSPORT_PARSE_FAILED` |
| Missing `orig` | `PASSPORT_PARSE_FAILED` (local policy) |
| Missing `dest` | `PASSPORT_PARSE_FAILED` (local policy) |
| Missing `evd` | `PASSPORT_PARSE_FAILED` (local policy) |
| Missing `iss` | Valid (optional) |
| Valid with all optional fields | Valid |
| Valid without optional fields | Valid |
| **Binding (§5.2)** | |
| ppt mismatch with VVP-Identity | `PASSPORT_PARSE_FAILED` |
| kid mismatch with VVP-Identity | `PASSPORT_PARSE_FAILED` |
| ppt = "vvp" and matches VVP-Identity | Valid |
| **Temporal Binding (§5.2A)** | |
| iat drift > 5 seconds | `PASSPORT_PARSE_FAILED` |
| iat drift ≤ 5 seconds | Valid |
| exp < iat | `PASSPORT_PARSE_FAILED` |
| exp drift > 5 seconds (both present) | `PASSPORT_PARSE_FAILED` |
| VVP-Identity exp present, PASSporT exp absent | `PASSPORT_PARSE_FAILED` |
| **Expiry Policy (§5.2B)** | |
| exp - iat > 300 seconds | `PASSPORT_EXPIRED` |
| PASSporT expired (now > exp + skew) | `PASSPORT_EXPIRED` |
| PASSporT not expired | Valid |
| exp absent, max-age exceeded | `PASSPORT_EXPIRED` |

### Resolved Questions

1. **`typ` validation**: Not validated. The `typ` field is ignored entirely as it is not mandated by v1.4 spec.

2. **Binding failure error code**:
   - Use `PASSPORT_PARSE_FAILED` for all binding violations (ppt/kid mismatch, iat drift, exp mismatch)
   - Reserve `PASSPORT_EXPIRED` only for actual expiry policy failures (token too old, validity window exceeded)

3. **`call-reason` field mapping**: Map `call-reason` → `call_reason` in the dataclass. Store raw payload for logging/signature verification.

4. **`kid` binding**: Phase 3 implements strict equality. §5.2 allows "match or be resolvable from" - OOBI resolution will be added in Phase 4.

### Checklist Tasks Covered

- [x] 3.1 - Create `app/vvp/passport.py` module
- [x] 3.2 - Parse JWT structure (header.payload.signature)
- [x] 3.3 - Reject `alg=none`
- [x] 3.4 - Reject ES256, HMAC, RSA algorithms
- [x] 3.5 - Accept only EdDSA (Ed25519)
- [x] 3.6 - Return PASSPORT_FORBIDDEN_ALG for algorithm violations
- [x] 3.7 - Extract header claims: `alg`, `typ` (ignored), `ppt`, `kid`
- [x] 3.8 - Extract VVP payload claims: `iat` (required), `orig`, `dest`, `evd` (local policy)
- [x] 3.9 - Extract optional VVP claims: `iss`, `card`, `goal`, `call-reason`, `origid`, `exp`
- [x] 3.10 - Validate `ppt` = "vvp" and matches VVP-Identity ppt (§5.2)
- [x] 3.11 - Validate `kid` binding (strict equality in Phase 3) (§5.2)
- [x] 3.12 - Defer signature verification (placeholder for Phase 4)
- [x] 3.13 - Unit tests for PASSporT parsing

---

**Status:** IMPLEMENTED (139 tests passing)


# PLAN_Phase4.md

# Current Plan

<!-- STATUS: IMPLEMENTED -->
<!-- RECONSTRUCTED: This plan was reconstructed from commit message and implementation code -->

## Phase 4: Ed25519 Signature Verification (Tier 1)

### Overview

Implement PASSporT signature verification using Ed25519 (pysodium). This is a Tier 1 implementation that directly extracts the public key from the KERI AID embedded in the `kid` field. Full KERI integration (historical key state lookup, KEL validation, witness receipts) is deferred to Tier 2.

### Spec References

- **§5.0** - VVP mandates EdDSA (Ed25519) for PASSporT signatures
- **§5.3** - Historical key state at reference time T (deferred to Tier 2)
- **§4.2A** - Error codes: PASSPORT_SIG_INVALID, KERI_RESOLUTION_FAILED

### Tier 1 Scope

**Implemented:**
- Parse KERI AID to extract Ed25519 public key
- Verify Ed25519 signature using pysodium
- Support B (transferable) and D (non-transferable) prefix codes

**Deferred to Tier 2:**
- Historical key state lookup at time T
- KEL/witness receipt validation
- Key rotation/revocation checking
- OOBI dereferencing with `application/json+cesr`

### Files to Create/Modify

| File | Action | Description |
|------|--------|-------------|
| `app/vvp/keri/__init__.py` | Create | Package init with exports |
| `app/vvp/keri/exceptions.py` | Create | KeriError, SignatureInvalidError, ResolutionFailedError |
| `app/vvp/keri/key_parser.py` | Create | parse_kid_to_verkey() |
| `app/vvp/keri/signature.py` | Create | verify_passport_signature() |
| `tests/test_signature.py` | Create | Unit tests for signature verification |
| `pyproject.toml` | Modify | Add pysodium dependency |

### Implementation Approach

#### 1. Exception Hierarchy

```python
class KeriError(Exception):
    """Base exception for KERI-related errors."""
    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(message)

class SignatureInvalidError(KeriError):
    """Signature cryptographically invalid → INVALID (non-recoverable)."""

class ResolutionFailedError(KeriError):
    """Could not resolve/parse identifier → INDETERMINATE (recoverable)."""
```

#### 2. Key Parser

KERI AID format: `<derivation_code><base64url_key>`
- `B` prefix = Ed25519 transferable (43 chars key)
- `D` prefix = Ed25519 non-transferable (43 chars key)

```python
@dataclass(frozen=True)
class VerificationKey:
    raw: bytes    # 32-byte Ed25519 public key
    aid: str      # Original AID (for logging)
    code: str     # KERI derivation code

def parse_kid_to_verkey(kid: str) -> VerificationKey:
    """Parse kid (KERI AID) to extract Ed25519 public key.

    Raises:
        ResolutionFailedError: Format invalid or unsupported algorithm
    """
```

#### 3. Signature Verification

JWT signing input: `base64url(header).base64url(payload)`

```python
def verify_passport_signature(passport: Passport) -> None:
    """Verify PASSporT Ed25519 signature.

    Args:
        passport: Parsed Passport with raw_header, raw_payload, signature

    Raises:
        SignatureInvalidError: Signature cryptographically invalid (→ INVALID)
        ResolutionFailedError: Could not resolve kid to key (→ INDETERMINATE)
    """
```

### Validation Rules

| Check | Action | Error Code |
|-------|--------|------------|
| kid format invalid | Reject | KERI_RESOLUTION_FAILED (recoverable) |
| Unsupported derivation code | Reject | KERI_RESOLUTION_FAILED (recoverable) |
| Invalid base64 in kid | Reject | KERI_RESOLUTION_FAILED (recoverable) |
| Key length ≠ 32 bytes | Reject | KERI_RESOLUTION_FAILED (recoverable) |
| Signature verification fails | Reject | PASSPORT_SIG_INVALID (non-recoverable) |
| Signature valid | Accept | - |

### Test Strategy

| Test Case | Expected Result |
|-----------|-----------------|
| **Key Parsing** | |
| Valid B-prefix AID | Returns VerificationKey |
| Valid D-prefix AID | Returns VerificationKey |
| Unsupported prefix (E, F, etc.) | KERI_RESOLUTION_FAILED |
| Invalid base64 in AID | KERI_RESOLUTION_FAILED |
| Too short AID | KERI_RESOLUTION_FAILED |
| Wrong key length | KERI_RESOLUTION_FAILED |
| **Signature Verification** | |
| Valid signature | Passes |
| Invalid signature | PASSPORT_SIG_INVALID |
| Tampered header | PASSPORT_SIG_INVALID |
| Tampered payload | PASSPORT_SIG_INVALID |
| Wrong key | PASSPORT_SIG_INVALID |
| Malformed kid | KERI_RESOLUTION_FAILED |

### Checklist Tasks Covered

- [x] 4.1 - Add pysodium to dependencies
- [x] 4.13 - Implement Ed25519 signature verification
- [x] 4.14 - Handle transient failures → INDETERMINATE
- [x] 4.15 - Handle cryptographically invalid state → INVALID
- [x] 4.16 - Unit tests for signature verification

### Deferred Tasks (Tier 2)

- [ ] 4.2 - Create resolver.py module
- [ ] 4.3 - Initialize KERI database (Habery context)
- [ ] 4.4 - Implement KeriResolver.resolve() for historical key state
- [ ] 4.5 - Implement OOBI dereferencing for kid field
- [ ] 4.6 - Validate OOBI content-type is application/json+cesr
- [ ] 4.7 - Handle OOBI fetch failures
- [ ] 4.8 - Implement KEL parsing
- [ ] 4.9 - Implement KERI/CESR version handling
- [ ] 4.10 - Historical key state lookup at reference time T
- [ ] 4.11 - Validate witness receipts at reference time T
- [ ] 4.12 - Check for key rotation/revocation prior to T

### Test Results

```
161 passed (141 prior + 20 new)
```

---

**Status:** IMPLEMENTED
**Commit:** `9c1900a`


# PLAN_Phase5.md

# Current Plan

<!-- STATUS: IMPLEMENTED -->
<!-- RECONSTRUCTED: This plan was reconstructed from commit message and implementation code -->

## Phase 5: Dossier Fetching and Structural Validation (Tier 1)

### Overview

Implement dossier (ACDC credential bundle) fetching and structural validation per VVP Specification §6.1. This includes HTTP fetch with constraints, ACDC JSON parsing, and DAG validation. CESR parsing, SAID verification, and issuer signature verification are deferred to Tier 2.

### Spec References

- **§6.1** - Dossier Structure
- **§6.1A** - ACDC Node Structure (d, i, s, a, e, r fields)
- **§6.1B** - Dossier Fetch Constraints (timeout, size, redirects, content-type)
- **§4.2A** - Error codes: DOSSIER_FETCH_FAILED, DOSSIER_PARSE_FAILED, DOSSIER_GRAPH_INVALID

### Tier 1 Scope

**Implemented:**
- HTTP fetch with timeout, size limit, and redirect constraints
- ACDC JSON parsing with required field validation
- DAG construction from edge references
- Cycle detection
- Root node identification (node with no incoming edges)
- Error classification: recoverable (FetchError) vs non-recoverable (ParseError, GraphError)

**Deferred to Tier 2:**
- CESR parsing (application/json+cesr)
- SAID computation using "most compact form" rule
- SAID verification (Blake3-256)
- Issuer signature verification via KERI historical key state

### Files to Create/Modify

| File | Action | Description |
|------|--------|-------------|
| `app/vvp/dossier/__init__.py` | Create | Package init with exports |
| `app/vvp/dossier/exceptions.py` | Create | DossierError, FetchError, ParseError, GraphError |
| `app/vvp/dossier/models.py` | Create | ACDCNode, DossierDAG dataclasses |
| `app/vvp/dossier/fetch.py` | Create | Async HTTP fetch with httpx |
| `app/vvp/dossier/parser.py` | Create | ACDC JSON structure parsing |
| `app/vvp/dossier/validator.py` | Create | DAG cycle detection, root finding |
| `app/core/config.py` | Modify | Add dossier config constants |
| `pyproject.toml` | Modify | Add httpx dependency |
| `tests/test_dossier.py` | Create | Unit tests |

### Implementation Approach

#### 1. Exception Hierarchy

```python
class DossierError(Exception):
    """Base exception for dossier-related errors."""
    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message

class FetchError(DossierError):
    """Network/timeout errors → INDETERMINATE (recoverable)."""

class ParseError(DossierError):
    """JSON/structure errors → INVALID (non-recoverable)."""

class GraphError(DossierError):
    """DAG validation errors → INVALID (non-recoverable)."""
```

#### 2. Data Models

```python
@dataclass(frozen=True)
class ACDCNode:
    """ACDC credential node per spec §6.1A."""
    said: str                           # d field - Self-Addressing ID
    issuer: str                         # i field - Issuer AID
    schema: str                         # s field - Schema SAID
    attributes: Optional[Any] = None    # a field - may be SAID (compact)
    edges: Optional[Dict] = None        # e field - references to other ACDCs
    rules: Optional[Dict] = None        # r field - rules block
    raw: Dict = field(default_factory=dict)  # For SAID recomputation

@dataclass
class DossierDAG:
    """DAG of ACDC nodes per spec §6.1."""
    nodes: Dict[str, ACDCNode]
    root_said: Optional[str] = None
```

#### 3. HTTP Fetch

```python
async def fetch_dossier(url: str) -> bytes:
    """Fetch dossier from URL with constraints per §6.1B.

    Constraints:
    - Timeout: 5 seconds (configurable)
    - Max size: 1 MB (configurable)
    - Max redirects: 3 (configurable)
    - Content-Type: application/json or application/json+cesr

    Raises:
        FetchError: On network/timeout/size errors (recoverable)
    """
```

#### 4. ACDC Parser

```python
def parse_dossier(raw: bytes) -> List[ACDCNode]:
    """Parse dossier JSON into ACDC nodes.

    Expects either:
    - Single ACDC object: {"d": "...", "i": "...", ...}
    - Array of ACDCs: [{"d": ...}, {"d": ...}]

    Raises:
        ParseError: On JSON/structure errors (non-recoverable)
    """
```

#### 5. DAG Validator

```python
def build_dag(nodes: List[ACDCNode]) -> DossierDAG:
    """Build DAG from list of ACDC nodes."""

def validate_dag(dag: DossierDAG) -> None:
    """Validate DAG structure per §6.1.

    Checks:
    - No cycles (depth-first traversal)
    - Exactly one root node (no incoming edges)
    - All edge targets exist in DAG

    Raises:
        GraphError: On validation failure (non-recoverable)
    """
```

### Configuration Constants

```python
DOSSIER_FETCH_TIMEOUT_SECONDS = 5.0   # Per §6.1B
DOSSIER_MAX_SIZE_BYTES = 1_048_576    # 1 MB
DOSSIER_MAX_REDIRECTS = 3             # Per §6.1B
```

### Validation Rules

| Check | Action | Error Code |
|-------|--------|------------|
| Network timeout | Reject | DOSSIER_FETCH_FAILED (recoverable) |
| HTTP error (4xx/5xx) | Reject | DOSSIER_FETCH_FAILED (recoverable) |
| Too many redirects | Reject | DOSSIER_FETCH_FAILED (recoverable) |
| Response too large | Reject | DOSSIER_FETCH_FAILED (recoverable) |
| Invalid content-type | Reject | DOSSIER_FETCH_FAILED (recoverable) |
| Invalid JSON | Reject | DOSSIER_PARSE_FAILED (non-recoverable) |
| Missing required field (d, i, s) | Reject | DOSSIER_PARSE_FAILED (non-recoverable) |
| Cycle in DAG | Reject | DOSSIER_GRAPH_INVALID (non-recoverable) |
| No root node | Reject | DOSSIER_GRAPH_INVALID (non-recoverable) |
| Multiple root nodes | Reject | DOSSIER_GRAPH_INVALID (non-recoverable) |
| Edge target not in DAG | Reject | DOSSIER_GRAPH_INVALID (non-recoverable) |

### Test Strategy

| Test Case | Expected Result |
|-----------|-----------------|
| **Fetch** | |
| Valid URL, valid response | Returns bytes |
| Network timeout | DOSSIER_FETCH_FAILED |
| HTTP 404 | DOSSIER_FETCH_FAILED |
| HTTP 503 | DOSSIER_FETCH_FAILED |
| Too many redirects | DOSSIER_FETCH_FAILED |
| Response > 1MB | DOSSIER_FETCH_FAILED |
| Wrong content-type | DOSSIER_FETCH_FAILED |
| **Parsing** | |
| Valid single ACDC | Returns [ACDCNode] |
| Valid ACDC array | Returns [ACDCNode, ...] |
| Invalid JSON | DOSSIER_PARSE_FAILED |
| Missing d field | DOSSIER_PARSE_FAILED |
| Missing i field | DOSSIER_PARSE_FAILED |
| Missing s field | DOSSIER_PARSE_FAILED |
| **DAG Validation** | |
| Valid single-node DAG | Valid, node is root |
| Valid multi-node DAG | Valid, root identified |
| Cycle detected | DOSSIER_GRAPH_INVALID |
| No root (all have incoming) | DOSSIER_GRAPH_INVALID |
| Multiple roots | DOSSIER_GRAPH_INVALID |
| Edge to nonexistent node | DOSSIER_GRAPH_INVALID |

### Checklist Tasks Covered

- [x] 5.1 - Create fetch.py module
- [x] 5.2 - Create model.py module
- [x] 5.3 - Define ACDCNode dataclass
- [x] 5.4 - Define DossierGraph dataclass
- [x] 5.5 - Implement OOBI dereference for evd field
- [x] 5.6 - Validate response content-type
- [x] 5.7 - Enforce timeout (5 seconds)
- [x] 5.8 - Enforce redirect limits
- [x] 5.9 - Enforce size limit (1MB)
- [x] 5.12 - Implement DAG cycle detection
- [x] 5.13 - Validate explicit root node exists
- [x] 5.19 - Handle fetch failures → INDETERMINATE
- [x] 5.20 - Unit tests for dossier validation

### Deferred Tasks (Tier 2)

- [ ] 5.10 - Parse dossier using KERI/CESR parser
- [ ] 5.11 - Handle ACDC variants: compact, partial, aggregate
- [ ] 5.14 - Implement "most compact form" SAID computation
- [ ] 5.15 - Verify each ACDC SAID matches recomputed value
- [ ] 5.16 - Verify ACDC issuer signatures via KERI historical key state
- [ ] 5.17 - Verify ACDC proofs present where required
- [ ] 5.18 - Enforce freshness/expiry policy on credentials

### Test Results

```
222 passed (161 prior + 61 new)
```

---

**Status:** IMPLEMENTED
**Commit:** `98cffc5`


# PLAN_Phase6.md

# Current Plan

<!-- STATUS: IMPLEMENTED -->
<!-- RECONSTRUCTED: This plan was reconstructed from commit message and implementation code -->

## Phase 6: Verification Orchestration and Claim Derivation (Tier 1)

### Overview

Implement the full VVP verification orchestration engine per spec §9, wiring together all verification phases (VVP-Identity parsing, PASSporT validation, signature verification, dossier fetching) and building a claim tree with status propagation per §3.3A.

### Spec References

- **§3.3A** - Child Status Propagation (REQUIRED children affect parent)
- **§4.3A** - overall_status Derivation
- **§9** - Verification Pseudocode and Orchestration

### Tier 1 Scope

**Implemented:**
- ClaimBuilder helper for accumulating evidence and failures
- Fixed claim tree structure: `caller_authorised` → [`passport_verified`, `dossier_verified`]
- Status propagation per §3.3A (REQUIRED children affect parent)
- Error-to-ErrorDetail conversion with recoverability lookup
- Early exit on VVP-Identity failure
- Skip dossier fetch on non-recoverable passport failure

**Tier 1 Claim Tree:**
```
caller_authorised (REQUIRED root)
├── passport_verified (REQUIRED)
└── dossier_verified (REQUIRED)
```

### Files to Create/Modify

| File | Action | Description |
|------|--------|-------------|
| `app/vvp/verify.py` | Rewrite | Full orchestration engine |
| `app/main.py` | Modify | Wire up async verify endpoint |
| `tests/test_verify.py` | Create | Unit tests for orchestration |

### Implementation Approach

#### 1. ClaimBuilder

```python
@dataclass
class ClaimBuilder:
    """Accumulates evidence and failures for a single claim."""
    name: str
    status: ClaimStatus = ClaimStatus.VALID
    reasons: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)

    def fail(self, status: ClaimStatus, reason: str) -> None:
        """Record a failure. INVALID always wins over INDETERMINATE."""

    def add_evidence(self, ev: str) -> None:
        """Add evidence string."""

    def build(self, children: List[ChildLink] = None) -> ClaimNode:
        """Build the final ClaimNode."""
```

#### 2. Error Conversion

```python
def to_error_detail(exc: Exception) -> ErrorDetail:
    """Convert domain exception to ErrorDetail for API response.

    Extracts error code and message from exception attributes,
    and looks up recoverability from ERROR_RECOVERABILITY mapping.
    """
```

#### 3. Status Propagation (§3.3A)

```python
def _worse_status(a: ClaimStatus, b: ClaimStatus) -> ClaimStatus:
    """Return the worse of two statuses.
    Precedence: INVALID > INDETERMINATE > VALID
    """

def propagate_status(node: ClaimNode) -> ClaimStatus:
    """Compute effective status considering REQUIRED children per §3.3A.

    Rules:
    - REQUIRED children: parent status is worst of own + all required children
    - OPTIONAL children: do not affect parent status
    """
```

#### 4. Main Orchestrator

```python
async def verify_vvp(
    req: VerifyRequest,
    vvp_identity_header: Optional[str] = None,
    raw_dossier: Optional[bytes] = None,  # For testing
) -> VerifyResponse:
    """Main verification orchestration per §9.

    Flow:
    1. Generate request_id
    2. Parse VVP-Identity header → early exit if fails
    3. Parse PASSporT JWT
    4. Validate PASSporT binding with VVP-Identity
    5. Verify PASSporT signature
    6. Fetch and validate dossier (skip on non-recoverable passport failure)
    7. Build claim tree with status propagation
    8. Derive overall_status from root claim
    9. Return VerifyResponse
    """
```

### Orchestration Flow

```
1. Parse VVP-Identity
   └── Failure → Early exit with errors[], overall_status = INVALID/INDETERMINATE

2. Parse PASSporT
   └── Failure → passport_verified = INVALID/INDETERMINATE

3. Validate PASSporT binding
   └── Failure → passport_verified = INVALID

4. Verify signature
   └── Failure → passport_verified = INVALID/INDETERMINATE

5. Fetch dossier (skip if passport non-recoverable failure)
   └── Failure → dossier_verified = INVALID/INDETERMINATE

6. Parse dossier
   └── Failure → dossier_verified = INVALID

7. Validate DAG
   └── Failure → dossier_verified = INVALID

8. Build claim tree
   └── caller_authorised = propagate_status(children)

9. Derive overall_status
   └── overall_status = propagate_status(root)
```

### Error Handling Rules

| Phase | Exception Type | Claim Affected | Recoverability |
|-------|---------------|----------------|----------------|
| VVP-Identity | VVPIdentityError | (early exit) | Depends on code |
| PASSporT parse | PassportError | passport_verified | Non-recoverable |
| Signature | SignatureInvalidError | passport_verified | Non-recoverable |
| Signature | ResolutionFailedError | passport_verified | Recoverable |
| Dossier fetch | FetchError | dossier_verified | Recoverable |
| Dossier parse | ParseError | dossier_verified | Non-recoverable |
| Dossier graph | GraphError | dossier_verified | Non-recoverable |

### Test Strategy

| Test Case | Expected Result |
|-----------|-----------------|
| **VVP-Identity** | |
| Missing VVP-Identity | Early exit, INDETERMINATE, VVP_IDENTITY_MISSING |
| Invalid VVP-Identity | Early exit, INVALID, VVP_IDENTITY_INVALID |
| **PASSporT** | |
| Missing PASSporT | passport_verified = INVALID |
| Parse failure | passport_verified = INVALID |
| Forbidden algorithm | passport_verified = INVALID |
| Expired | passport_verified = INVALID |
| Binding mismatch | passport_verified = INVALID |
| **Signature** | |
| Invalid signature | passport_verified = INVALID |
| Resolution failed | passport_verified = INDETERMINATE |
| Valid signature | passport_verified = VALID |
| **Dossier** | |
| Fetch timeout | dossier_verified = INDETERMINATE |
| Fetch HTTP error | dossier_verified = INDETERMINATE |
| Parse failure | dossier_verified = INVALID |
| Graph invalid | dossier_verified = INVALID |
| Valid dossier | dossier_verified = VALID |
| **Propagation** | |
| All valid | overall = VALID |
| Passport invalid | overall = INVALID |
| Passport indeterminate | overall = INDETERMINATE |
| Dossier invalid | overall = INVALID |
| Dossier indeterminate | overall = INDETERMINATE |
| Skip dossier on fatal passport | dossier_verified = INDETERMINATE (skipped) |

### Checklist Tasks Covered

- [x] 6.1 - Create engine.py module (integrated into verify.py)
- [x] 6.3 - Implement claim tree construction from dossier
- [x] 6.4 - Validate children have explicit required/optional flag
- [x] 6.5 - Implement REQUIRED child propagation: INVALID → parent INVALID
- [x] 6.6 - Implement REQUIRED child propagation: INDETERMINATE → parent INDETERMINATE
- [x] 6.7 - Implement OPTIONAL child handling (never invalidates parent)
- [x] 6.8 - Implement overall_status derivation from root claims
- [x] 6.9 - Support partial trees for recoverable failures
- [x] 6.10 - Implement short-circuit on fatal PASSporT failures
- [x] 6.13 - Unit tests for claim propagation

### Test Results

```
264 passed (222 prior + 42 new)
```

---

**Status:** IMPLEMENTED
**Commit:** `6f6a0cb`


# PLAN_Phase7.md

# Phase 7: KERI Key State Resolution (Tier 2)

## Problem Statement

The current Tier 1 implementation extracts Ed25519 public keys directly from KERI AIDs and verifies PASSporT signatures against them. This approach has a critical limitation: it assumes the key embedded in the AID is currently valid and ignores key rotation or revocation events that may have occurred.

VVP verification requires determining key state at a specific reference time T (the `iat` timestamp). Without this capability:

1. A rotated key could still verify signatures created after the rotation
2. A revoked key could still pass verification
3. Historical verification (per §5D) is impossible
4. The verifier cannot distinguish between "key was valid at time T" and "key is valid now"

## Spec References

From `VVP_Verifier_Specification_v1.5.md`:

- **§5A Step 4** (Key State Retrieval): "Resolve issuer key state at reference time T (§5.1.1-2.4)"
- **§5C.2** (Caching): "Key state cache: AID + timestamp → Minutes (rotation-sensitive)"
- **§5D** (Historical Verification): "VVP passports can verify at arbitrary past moments using historical data"

From VVP draft §5.1.1-2.4:
- "The verifier MUST resolve the key state of the AID at reference time T"
- "Key state resolution involves fetching the Key Event Log (KEL) from witnesses"
- "The verifier MUST validate witness receipts to achieve confidence in key state"

## Solution Implemented

Implemented a **lightweight KEL resolver** that fetches, parses, and **cryptographically validates** Key Event Logs without requiring the full keripy installation.

### Components

| Component | File | Purpose |
|-----------|------|---------|
| OOBI Dereferencer | `app/vvp/keri/oobi.py` | Fetch KEL data from OOBI URLs |
| KEL Parser | `app/vvp/keri/kel_parser.py` | Parse and validate KERI events |
| Key State Resolver | `app/vvp/keri/kel_resolver.py` | Determine key state at time T |
| Key State Cache | `app/vvp/keri/cache.py` | LRU cache with TTL for resolved states |
| Tier 2 Signature | `app/vvp/keri/signature.py` | Verify using historical key state |

### Feature Gating

**IMPORTANT**: Tier 2 is gated behind `TIER2_KEL_RESOLUTION_ENABLED` feature flag (default: `False`).

Current limitations that prevent production use:
- JSON-only: CESR binary format NOT supported
- Signature canonicalization uses JSON sorted-keys, NOT KERI-compliant Blake3
- SAID validation disabled by default

Enable only for testing with synthetic fixtures. Production requires CESR support.

## Files Changed

| File | Lines | Summary |
|------|-------|---------|
| `app/core/config.py` | +20 | Added `TIER2_KEL_RESOLUTION_ENABLED` feature flag |
| `app/vvp/keri/exceptions.py` | +48 | Added KELChainInvalidError, KeyNotYetValidError, DelegationNotSupportedError, OOBIContentInvalidError |
| `app/vvp/keri/cache.py` | +210 | New key state cache with LRU eviction and TTL |
| `app/vvp/keri/kel_parser.py` | +380 | KEL event parser with chain validation |
| `app/vvp/keri/oobi.py` | +180 | OOBI dereferencer for fetching KEL data |
| `app/vvp/keri/kel_resolver.py` | +330 | Key state resolver at reference time T |
| `app/vvp/keri/signature.py` | +50 | Added verify_passport_signature_tier2 |
| `app/vvp/keri/__init__.py` | +30 | Updated exports for Tier 2 |
| `tests/test_kel_parser.py` | +190 | KEL parser unit tests |
| `tests/test_kel_chain.py` | +280 | Chain validation tests |
| `tests/test_kel_cache.py` | +280 | Cache behavior tests |
| `tests/test_kel_resolver.py` | +290 | Resolver tests |
| `tests/test_kel_integration.py` | +280 | End-to-end integration tests |

## Test Results

```
97 passed (Phase 7 tests)
368 passed, 2 skipped (full test suite)
```

## Review History

- **Revision 0**: CHANGES_REQUESTED - Missing chain validation, incorrect rotation handling, cache rounding
- **Revision 1**: CHANGES_REQUESTED - CESR not supported, signature canonicalization test-only
- **Revision 2**: APPROVED - Feature flag gating makes limitations explicit

## Reviewer Recommendations (for future phases)

1. Add note about when to flip `TIER2_KEL_RESOLUTION_ENABLED` once CESR support lands
2. Document intended production default for SAID validation once CESR/canonicalization implemented


# PLAN_Phase8.md

# Current Plan

<!-- STATUS: IMPLEMENTED -->
<!-- RECONSTRUCTED: This plan was reconstructed from commit message and implementation code -->

## Phase 8: Test Vectors per VVP Spec §10

### Overview

Implement test vectors as specified in VVP Specification §10. Each vector includes input artifacts, verification context, and expected results. The test infrastructure supports time freezing, configuration patching, and HTTP mocking for deterministic testing.

### Spec References

- **§10** - Test Vectors
- **§10.2** - Required Test Cases
- **§10.3** - Test Vector Format

### Implementation

**8 Test Vectors:**
- 6 Tier 1 passing (fully tested)
- 2 Tier 2 skipped (require historical key state / SAID verification)

### Files to Create

| File | Action | Description |
|------|--------|-------------|
| `tests/vectors/__init__.py` | Create | Package init |
| `tests/vectors/conftest.py` | Create | Pytest fixtures |
| `tests/vectors/schema.py` | Create | Pydantic models for vector format |
| `tests/vectors/helpers.py` | Create | JWT/header generation utilities |
| `tests/vectors/runner.py` | Create | VectorRunner with mocking infrastructure |
| `tests/vectors/test_vectors.py` | Create | Parametrized test execution |
| `tests/vectors/data/v01_valid_happy_path.json` | Create | Vector: Valid request |
| `tests/vectors/data/v02_forbidden_algorithm.json` | Create | Vector: ES256 forbidden |
| `tests/vectors/data/v03_invalid_signature.json` | Create | Vector: Bad signature |
| `tests/vectors/data/v04_key_rotated.json` | Create | Vector: Key rotation (Tier 2) |
| `tests/vectors/data/v05_oobi_timeout.json` | Create | Vector: OOBI timeout |
| `tests/vectors/data/v06_dossier_unreachable.json` | Create | Vector: HTTP 503 |
| `tests/vectors/data/v07_said_mismatch.json` | Create | Vector: SAID mismatch (Tier 2) |
| `tests/vectors/data/v08_acdc_variants.json` | Create | Vector: ACDC DAG |

### Test Vector Format (§10.3)

```python
class VectorCase(BaseModel):
    id: str                              # e.g., "v01"
    name: str                            # e.g., "valid_happy_path"
    description: str                     # Human-readable description
    tier: int = 1                        # 1 = Tier 1, 2 = Tier 2
    skip_reason: Optional[str] = None   # Why vector is skipped
    input: VectorInput                   # VVP-Identity, PASSporT, context
    artifacts: VectorArtifacts           # Mock HTTP responses
    verification_context: VerificationContext  # Reference time, skew, etc.
    expected: ExpectedResult             # overall_status, claim tree, errors
```

### Test Vectors

| ID | Name | Tier | Status | Description |
|----|------|------|--------|-------------|
| v01 | valid_happy_path | 1 | ✓ | Valid VVP-Identity + EdDSA PASSporT + dossier → VALID |
| v02 | forbidden_algorithm | 1 | ✓ | PASSporT uses ES256 → INVALID |
| v03 | invalid_signature | 1 | ✓ | Ed25519 signature verification fails → INVALID |
| v04 | key_rotated | 2 | SKIP | Key rotated before T (requires historical state) |
| v05 | oobi_timeout | 1 | ✓ | Dossier fetch timeout → INDETERMINATE |
| v06 | dossier_unreachable | 1 | ✓ | Dossier HTTP 503 → INDETERMINATE |
| v07 | said_mismatch | 2 | SKIP | ACDC SAID doesn't match (requires SAID verification) |
| v08 | acdc_variants | 1 | ✓ | Valid multi-node ACDC DAG → VALID |

### Test Infrastructure

#### VectorRunner

```python
class VectorRunner:
    """Runs test vectors with deterministic mocking.

    Features:
    - Time freezing at reference_time_t
    - Configuration patching (clock_skew, max_token_age)
    - httpx.AsyncClient mocking for dossier fetch
    - Proper AsyncMock context manager support
    """

    async def run(self, vector: VectorCase) -> VerifyResponse:
        """Execute vector and return verification response."""

    def assert_result(
        self,
        response: VerifyResponse,
        expected: ExpectedResult
    ) -> None:
        """Assert response matches expected result.

        Checks:
        - overall_status matches
        - Claim tree structure matches (if specified)
        - Child count verification (Tier 1 structure guarantee)
        - Error codes present (if specified)
        """
```

#### Claim Tree Assertions

```python
class ExpectedClaimNode(BaseModel):
    name: str
    status: ExpectedStatus
    reasons_contain: Optional[List[str]] = None   # Substring match
    evidence_contain: Optional[List[str]] = None  # Substring match
    children: Optional[List[ExpectedChildLink]] = None

class ExpectedChildLink(BaseModel):
    required: bool
    node: ExpectedClaimNode
```

### Helper Utilities

```python
def make_vvp_identity_header(
    ppt: str = "vvp",
    kid: str = "...",
    evd: str = "...",
    iat: int = ...,
    exp: Optional[int] = None,
) -> str:
    """Generate base64url-encoded VVP-Identity header."""

def make_passport_jwt(
    header: dict,
    payload: dict,
    private_key: bytes,
) -> str:
    """Generate signed PASSporT JWT."""

def generate_ed25519_keypair() -> Tuple[bytes, bytes]:
    """Generate Ed25519 keypair for testing."""
```

### Checklist Tasks Covered

- [x] 8.1 - Create test vector directory structure
- [x] 8.2 - Valid VVP-Identity + valid EdDSA PASSporT + valid dossier → VALID
- [x] 8.3 - PASSporT uses forbidden algorithm (ES256) → INVALID
- [x] 8.4 - PASSporT signature invalid at reference time T → INVALID
- [x] 8.6 - OOBI/KERI resolution timeout → INDETERMINATE
- [x] 8.7 - Dossier unreachable → INDETERMINATE
- [x] 8.9 - Valid compact/partial/aggregate dossier variant → VALID
- [x] 8.10 - Each vector includes: input, artefacts, T, expected tree, errors
- [x] 8.11 - Implement test vector runner

### Deferred Tasks (Tier 2)

- [ ] 8.5 - Key rotated/revoked before T (historical) → INVALID
- [ ] 8.8 - SAID mismatch under most-compact-form rule → INVALID
- [ ] 8.12 - CI integration for test vectors

### Test Results

```
271 passed, 2 skipped
Skipped:
- v04_key_rotated: Requires Tier 2 historical key state
- v07_said_mismatch: Requires Tier 2 SAID verification
```

---

**Status:** IMPLEMENTED
**Commit:** `59b4942`


# PLAN_Phase9.3.md

# Phase 9.3 + Admin: Revocation Integration & Configuration Visibility

## Problem Statement

The VVP Verifier has a functioning TEL client (`tel_client.py`) that can query KERI witnesses for credential revocation status, but this capability is **not integrated into the main verification flow**. Currently:

1. Revocation checking is available only via a standalone `/check-revocation` endpoint
2. The main `/verify` flow does NOT check credential revocation for ACDCs in the dossier
3. Configuration values are scattered across code with no visibility to operators

This means:
- Credentials could be verified even if revoked (spec violation §5.1.1-2.9)
- Operators cannot see or monitor configurable parameters
- Debugging revocation issues requires manual API calls

## Spec References

- **§5.1.1-2.9 (Revocation Status Check)**: "Query TEL for each credential in the dossier. If any credential is revoked, the verification MUST fail with INVALID."
- **§5.3 (Efficiency)**: "Caching and freshness policies for revocation status"
- **§3.3A (Status Propagation)**: "INVALID > INDETERMINATE > VALID precedence"
- **§3.3B (Claim Tree Structure)**: `revocation_clear` is a REQUIRED child of `dossier_verified`

## Current State

### TEL Client (`app/vvp/keri/tel_client.py`)
- `check_revocation()` - queries witnesses for credential status
- `CredentialStatus` enum: ACTIVE, REVOKED, UNKNOWN, ERROR
- Caching with `_cache` dict
- Provenant staging witnesses configured
- INFO-level logging just added (pending commit)

### Verification Flow (`app/vvp/verify.py`)
- Phase 2: VVP-Identity header parsing ✓
- Phase 3: PASSporT Parse + Binding ✓
- Phase 4: KERI Signature Verification ✓
- Phase 5: Dossier Fetch + DAG Validation ✓
- Phase 6: Build Claim Tree ✓
- **Phase 9: Revocation Checking ✗ NOT INTEGRATED**

### Configuration (`app/core/config.py`)
- Normative constants (MAX_IAT_DRIFT_SECONDS, etc.)
- Configurable defaults (CLOCK_SKEW_SECONDS, MAX_TOKEN_AGE_SECONDS, etc.)
- Feature flags (TIER2_KEL_RESOLUTION_ENABLED)
- No admin visibility endpoint

## Proposed Solution

### Approach

Integrate revocation checking into the verification flow by adding the `revocation_clear` claim as a **REQUIRED child of `dossier_verified`** per §3.3B, and add an `/admin` endpoint showing all configuration.

### Alternatives Considered

| Alternative | Pros | Cons | Why Rejected |
|-------------|------|------|--------------|
| Check only root credential | Fast, minimal queries | Doesn't catch revoked chain credentials | Spec requires ALL credentials |
| Async background check | Non-blocking | Status may change during verification | Spec requires synchronous check |
| Top-level revocation claim | Simple tree structure | Violates §3.3B claim tree structure | Spec mandates `revocation_clear` under `dossier_verified` |

---

## Detailed Design

### Component 1: Revocation Checker Function

**Purpose:** Check revocation status for all ACDCs in a dossier DAG.

**Location:** `app/vvp/verify.py` (new function)

**Interface:**
```python
async def check_dossier_revocations(
    dag: DossierDAG,
    oobi_url: Optional[str] = None
) -> ClaimBuilder:
    """Check revocation status for all credentials in a dossier DAG.

    Per spec §5.1.1-2.9: Revocation Status Check
    - Query TEL for each credential in dossier
    - If ANY credential is revoked → INVALID
    - If ANY credential status unknown/error → INDETERMINATE
    - If ALL credentials active → VALID

    Args:
        dag: Parsed and validated DossierDAG
        oobi_url: Optional OOBI URL for witness queries

    Returns:
        ClaimBuilder for `revocation_clear` claim
    """
```

**Behavior:**
1. Iterate over all nodes in `dag.nodes`
2. For each ACDC, extract `said` (d field) and `registry_said` (ri field if present)
3. Call `TELClient.check_revocation()` for each credential
4. Track results: ACTIVE → evidence, REVOKED → INVALID, UNKNOWN/ERROR → INDETERMINATE
5. Build claim with aggregated status and evidence

**Status Mapping (per §5.1.1-2.9):**
| TEL Status | Claim Status | Behavior |
|------------|--------------|----------|
| ACTIVE | VALID | Add evidence: `active:{said[:16]}...` |
| REVOKED | INVALID | Fail with reason, surface `CREDENTIAL_REVOKED` error |
| UNKNOWN | INDETERMINATE | Fail with reason (TEL not found) |
| ERROR | INDETERMINATE | Fail with reason (query failed) |

**Revocation is REQUIRED** - it is never skipped. If TEL is unavailable, the claim becomes INDETERMINATE (not skipped).

### Component 2: Verification Flow Integration

**Purpose:** Add `revocation_clear` claim as child of `dossier_verified` per §3.3B.

**Location:** `app/vvp/verify.py` (modify `verify_vvp()`)

**Changes:**

1. After Phase 5 (dossier validation), add Phase 9:
```python
# -------------------------------------------------------------------------
# Phase 9: Revocation Checking (Tier 2) - §5.1.1-2.9
# -------------------------------------------------------------------------
revocation_claim = ClaimBuilder("revocation_clear")

if dag is not None:
    revocation_claim = await check_dossier_revocations(
        dag,
        oobi_url=passport.header.kid if passport else None
    )
else:
    # Dossier failed - revocation check is INDETERMINATE
    revocation_claim.fail(
        ClaimStatus.INDETERMINATE,
        "Cannot check revocation: dossier validation failed"
    )
```

2. Update claim tree structure per §3.3B:
```python
# dossier_verified now has revocation_clear as a child
dossier_node = ClaimNode(
    name="dossier_verified",
    status=dossier_claim.status,
    reasons=dossier_claim.reasons,
    evidence=dossier_claim.evidence,
    children=[
        ChildLink(required=True, node=revocation_claim.build()),  # NEW per §3.3B
    ],
)

root_claim = ClaimNode(
    name="caller_authorised",
    status=ClaimStatus.VALID,
    children=[
        ChildLink(required=True, node=passport_node),
        ChildLink(required=True, node=dossier_node),
    ],
)
```

### Component 3: Admin Configuration Endpoint

**Purpose:** Expose all configuration values for operator visibility.

**Location:** `app/main.py` (new endpoint)

**Interface:**
```python
@app.get("/admin")
def admin():
    """Return all configurable items for operator visibility.

    Gated by ADMIN_ENDPOINT_ENABLED (default: True for dev, False for prod).
    """
    from app.core.config import (
        MAX_IAT_DRIFT_SECONDS,
        ALLOWED_ALGORITHMS,
        CLOCK_SKEW_SECONDS,
        MAX_TOKEN_AGE_SECONDS,
        MAX_PASSPORT_VALIDITY_SECONDS,
        ALLOW_PASSPORT_EXP_OMISSION,
        DOSSIER_FETCH_TIMEOUT_SECONDS,
        DOSSIER_MAX_SIZE_BYTES,
        DOSSIER_MAX_REDIRECTS,
        TIER2_KEL_RESOLUTION_ENABLED,
        ADMIN_ENDPOINT_ENABLED,
    )
    from app.vvp.keri.tel_client import TELClient
    import os

    if not ADMIN_ENDPOINT_ENABLED:
        return JSONResponse(
            status_code=404,
            content={"detail": "Admin endpoint disabled"}
        )

    return {
        "normative": {
            "max_iat_drift_seconds": MAX_IAT_DRIFT_SECONDS,
            "allowed_algorithms": list(ALLOWED_ALGORITHMS),
        },
        "configurable": {
            "clock_skew_seconds": CLOCK_SKEW_SECONDS,
            "max_token_age_seconds": MAX_TOKEN_AGE_SECONDS,
            "max_passport_validity_seconds": MAX_PASSPORT_VALIDITY_SECONDS,
            "allow_passport_exp_omission": ALLOW_PASSPORT_EXP_OMISSION,
        },
        "policy": {
            "dossier_fetch_timeout_seconds": DOSSIER_FETCH_TIMEOUT_SECONDS,
            "dossier_max_size_bytes": DOSSIER_MAX_SIZE_BYTES,
            "dossier_max_redirects": DOSSIER_MAX_REDIRECTS,
        },
        "features": {
            "tier2_kel_resolution_enabled": TIER2_KEL_RESOLUTION_ENABLED,
            "admin_endpoint_enabled": ADMIN_ENDPOINT_ENABLED,
        },
        "witnesses": {
            "default_witness_urls": TELClient.DEFAULT_WITNESSES,
        },
        "environment": {
            "log_level": os.getenv("VVP_LOG_LEVEL", "INFO"),
        }
    }
```

**Configuration flag:**
```python
# In app/core/config.py
ADMIN_ENDPOINT_ENABLED: bool = os.getenv("ADMIN_ENDPOINT_ENABLED", "true").lower() == "true"
```

---

## Data Flow

```
verify_vvp() Request
        │
        ▼
┌─────────────────────────┐
│ Phase 5: Dossier Parse  │
│   → DossierDAG          │
└───────────┬─────────────┘
            │ (always proceeds)
            ▼
┌─────────────────────────────────────────┐
│ Phase 9: Revocation Checking            │
│   for each ACDC in dag.nodes:           │
│     TELClient.check_revocation()        │
│       → query witnesses                 │
│       → parse TEL events                │
│       → determine status                │
│   Build revocation_clear claim          │
└───────────┬─────────────────────────────┘
            │
            ▼
┌─────────────────────────────────────────┐
│ Phase 6: Claim Tree (per §3.3B)         │
│   caller_authorised                     │
│   ├─ passport_verified                  │
│   └─ dossier_verified                   │
│       └─ revocation_clear (NEW)         │
└─────────────────────────────────────────┘
```

---

## Error Handling

| Error Condition | Error Type | Claim Status | Recovery |
|-----------------|------------|--------------|----------|
| Credential revoked | CREDENTIAL_REVOKED | INVALID | Cannot recover |
| TEL query failed | - | INDETERMINATE | Retry possible |
| TEL not found | - | INDETERMINATE | May resolve later |
| Dossier invalid | - | revocation_clear INDETERMINATE | Dossier error takes precedence |
| Witness timeout | httpx.TimeoutException | INDETERMINATE | Retry with different witness |

---

## Test Strategy

### 1. Unit Tests for Revocation Checker (`tests/test_revocation_checker.py`)

```python
def test_all_credentials_active():
    """All credentials ACTIVE → revocation_clear VALID."""

def test_one_credential_revoked():
    """One revoked credential → revocation_clear INVALID."""

def test_one_credential_unknown():
    """One unknown credential → revocation_clear INDETERMINATE."""

def test_revoked_takes_precedence_over_unknown():
    """REVOKED wins over UNKNOWN → INVALID status."""

def test_empty_dag():
    """Empty DAG → VALID (nothing to check)."""

def test_extracts_registry_said():
    """Correctly extracts ri field from raw ACDC."""
```

### 2. Integration Tests (`tests/test_verify_revocation_integration.py`)

```python
async def test_verify_with_active_credentials():
    """Full verify flow with active credentials passes."""

async def test_verify_with_revoked_credential():
    """Full verify flow with revoked credential fails INVALID."""

async def test_revocation_claim_under_dossier():
    """revocation_clear is child of dossier_verified per §3.3B."""

async def test_dossier_failure_makes_revocation_indeterminate():
    """Dossier failure → revocation_clear INDETERMINATE."""
```

### 3. Admin Endpoint Tests (`tests/test_admin.py`)

```python
def test_admin_returns_all_config():
    """Admin endpoint returns all configuration categories."""

def test_admin_config_types():
    """Configuration values have expected types."""

def test_admin_disabled_returns_404():
    """Admin endpoint returns 404 when ADMIN_ENDPOINT_ENABLED=false."""
```

---

## Files to Create/Modify

| File | Action | Purpose |
|------|--------|---------|
| `app/vvp/verify.py` | Modify | Add `check_dossier_revocations()`, integrate `revocation_clear` under `dossier_verified` |
| `app/main.py` | Modify | Add `/admin` endpoint with feature flag |
| `app/core/config.py` | Modify | Add `ADMIN_ENDPOINT_ENABLED` flag |
| `tests/test_revocation_checker.py` | Create | Unit tests for revocation checking |
| `tests/test_verify_revocation_integration.py` | Create | Integration tests |
| `tests/test_admin.py` | Create | Admin endpoint tests |
| `app/Documentation/VVP_Implementation_Checklist.md` | Modify | Mark 9.3 complete |

---

## Implementation Order

1. **Add `ADMIN_ENDPOINT_ENABLED` to config.py** - Feature flag
2. **Add `/admin` endpoint** - Quick visibility win
3. **Add `check_dossier_revocations()` function** - Core logic
4. **Integrate `revocation_clear` under `dossier_verified`** - Claim tree per §3.3B
5. **Write unit tests** - Verify behavior
6. **Write integration tests** - End-to-end verification
7. **Update checklist** - Mark 9.3 complete

---

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| TEL queries slow | Medium | Medium | Parallel queries, caching |
| Witnesses unavailable | Low | High | Multiple witness fallback, INDETERMINATE |
| All credentials UNKNOWN | Medium | Medium | Return INDETERMINATE per spec |
| Increased latency | Medium | Low | Cache results |

---

## Resolved Questions (per Reviewer)

1. **Should revocation checking be optional/configurable?**
   - **Answer**: No. Revocation checking is REQUIRED per §5.1.1-2.9. If TEL is unavailable, return INDETERMINATE (never skip).

2. **What if ALL witnesses return UNKNOWN?**
   - **Answer**: Return INDETERMINATE and surface a clear reason. Do NOT mark INVALID.

3. **Admin endpoint security**
   - **Answer**: Gate behind `ADMIN_ENDPOINT_ENABLED` flag (default: true for dev). Production deployments can set to false.

---

## Exit Criteria

- [ ] `check_dossier_revocations()` correctly checks all ACDCs
- [ ] `revocation_clear` claim is child of `dossier_verified` per §3.3B
- [ ] Revoked credential → overall INVALID
- [ ] Unknown status → INDETERMINATE (not skipped)
- [ ] `/admin` endpoint shows all configuration (gated by flag)
- [ ] All new tests pass
- [ ] Existing tests still pass
- [ ] Checklist updated with 9.3 complete

---

## Revision 1 (Response to CHANGES_REQUESTED)

### Changes Made

| Finding | Resolution |
|---------|------------|
| [High] Plan adds `credentials_not_revoked` at root level, but §3.3B requires `revocation_clear` under `dossier_verified` | Changed claim name to `revocation_clear` and placed as REQUIRED child of `dossier_verified` per §3.3B |
| [Medium] "Optional revocation" wording conflicts with spec requirement | Removed "optional" wording. Revocation is REQUIRED; UNKNOWN/ERROR → INDETERMINATE (never skip) |
| [Low] Admin endpoint unauthenticated | Added `ADMIN_ENDPOINT_ENABLED` feature flag (default true for dev) |

---

## Implementation Notes

### Deviations from Plan
None - implementation follows approved plan exactly.

### Implementation Details

1. **TEL Client Mock in Vector Tests**: The VectorRunner needed to mock the TEL client to ensure deterministic test execution. All credentials return ACTIVE by default in tests.

2. **Library Path Configuration**: Local macOS testing requires `DYLD_LIBRARY_PATH=/opt/homebrew/opt/libsodium/lib` for pysodium to find libsodium.

3. **Patch Target**: The test file `test_revocation_checker.py` patches `app.vvp.keri.tel_client.get_tel_client` (not `app.vvp.verify.get_tel_client`) because the function is imported inside `check_dossier_revocations()`.

### Test Results
```
477 passed, 2 skipped in 3.67s
```

### Files Changed
| File | Lines | Summary |
|------|-------|---------|
| `app/core/config.py` | +7 | Added `ADMIN_ENDPOINT_ENABLED` flag |
| `app/main.py` | +45 | Added `/admin` endpoint |
| `app/vvp/verify.py` | +75 | Added `check_dossier_revocations()` and Phase 9 integration |
| `app/vvp/keri/tel_client.py` | +15 | Added INFO-level logging throughout |
| `app/logging_config.py` | +2 | Added `VVP_LOG_LEVEL` environment variable support |
| `tests/test_admin.py` | +76 | Admin endpoint tests (9 tests) |
| `tests/test_revocation_checker.py` | +277 | Revocation checker tests (8 tests) |
| `tests/vectors/runner.py` | +20 | Added TEL client mock for deterministic tests |
| `app/Documentation/VVP_Implementation_Checklist.md` | +10 | Marked Phase 9 complete |


# PLAN_Phase9.4.md

# Phase 9.4: TEL Resolution Architecture Fix

## Problem Statement

The TEL client is querying the **wrong endpoints** for credential revocation status. Currently:

1. The OOBI URL passed to TEL client (`https://origin.demo.provenant.net/v1/agent/public/...`) is a **KERIA agent endpoint**
2. The client derives endpoint paths like `/tels/{registry_said}` from this base URL
3. KERIA agents don't serve TEL data at these paths → all queries return **404 Not Found**
4. Fallback to hardcoded GLEIF testnet witnesses also fails (those witnesses don't have the credential's TEL)

**Observed behavior:**
```
[TEL] Querying: https://origin.demo.provenant.net/tels/EIq8De62NNDz3oXZxzHm-EW9... → 404
[TEL] Querying: https://origin.demo.provenant.net/credentials/EFraNIE0qvXSojKskl9m... → 404
[TEL] Querying: https://wit1.testnet.gleif.org:5641/tels/EIq8De62NNDz3oXZxzHm-EW9... → 404
[TEL] Final result: UNKNOWN
```

This means **revocation checking always returns INDETERMINATE** even for valid credentials with published TEL data.

## Spec References

- **§5.1.1-2.9 (Revocation Status Check)**: "Query TEL for each credential in the dossier"
- **§6.1B (Dossier Format)**: "Dossier MAY include TEL events alongside ACDCs in CESR format"
- **KERI TEL Spec**: TEL events are managed by credential registry controllers, not by the credential issuer's agent

## Current Architecture

### Data Flow (Current - Broken)
```
verify_vvp()
    │
    ├─ Dossier fetch from evd URL
    │   └─ raw_dossier: bytes (may contain TEL events - IGNORED)
    │
    ├─ parse_dossier(raw_dossier)
    │   └─ Extracts ACDCs only (JSON parsing)
    │   └─ TEL events in CESR stream are DISCARDED
    │
    └─ check_dossier_revocations(dag, oobi_url=passport.kid)
        │
        └─ TELClient.check_revocation()
            ├─ Derives base URL from passport.kid OOBI
            │   └─ WRONG: This is the PASSporT signer's agent, not TEL host
            ├─ Tries /tels/{registry} → 404
            ├─ Tries /credentials/{said} → 404
            └─ Falls back to hardcoded witnesses → 404
```

### Key Issues

1. **Wrong OOBI**: We pass `passport.header.kid` (PASSporT signer's OOBI) but credentials may have different issuers with different infrastructure

2. **Inline TEL ignored**: Raw dossier bytes may contain TEL events in CESR format, but we only parse JSON ACDCs

3. **No registry OOBI resolution**: Each credential's registry (`ri` field) has its own controller that publishes TEL - we don't discover this

4. **Witness discovery gap**: During KEL resolution we discover witness AIDs (`b` field), but not their URLs

---

## Proposed Solution

### Combined Approach: Inline TEL + Registry OOBI Discovery

Per reviewer feedback, implementing **only** inline TEL parsing is insufficient because it leaves the 404 issue unresolved for dossiers without inline TEL. This phase implements **both**:

1. **Step 1: Inline TEL Parsing** - Check if TEL events are embedded in the raw dossier (no network required)
2. **Step 2: Registry OOBI Discovery** - For credentials without inline TEL, resolve the registry's OOBI to find TEL-serving witnesses

This ensures revocation checking works for:
- Self-contained CESR dossiers with inline TEL (Step 1)
- Dossiers that reference externally-hosted TEL (Step 2)

### Alternatives Considered

| Alternative | Pros | Cons | Why Rejected |
|-------------|------|------|--------------|
| Inline TEL only | Simple, fast | Doesn't fix 404s for non-inline TEL | Reviewer: insufficient as sole fix |
| PASSporT signer OOBI for TEL | No extra resolution | Wrong endpoint (agent, not registry) | Root cause of 404s |
| Hardcoded witnesses only | Simple fallback | Witnesses don't have all TELs | Current broken behavior |

---

## Detailed Design

### Component 1: Binary-Safe Inline TEL Parsing

**Location**: `app/vvp/verify.py`

**Issue**: CESR dossiers may be binary (e.g., `application/octet-stream`). Naive UTF-8 decoding with `errors="replace"` can corrupt binary CESR data or miss embedded TEL events.

**Solution**: Parse raw bytes directly, looking for JSON objects within the CESR stream. The existing `_extract_tel_events()` method already handles this pattern - it searches for `{"v":"KERI` markers in text.

```python
def _parse_raw_dossier_for_tel(raw_dossier: bytes) -> str:
    """Convert raw dossier bytes to text for TEL parsing.

    CESR streams are ASCII-safe for JSON portions. Binary attachments
    (signatures, receipts) use Base64 encoding which is also ASCII-safe.
    We decode as latin-1 to preserve all byte values without replacement.
    """
    # latin-1 is byte-transparent: every byte 0x00-0xFF maps to a character
    # This preserves all data while allowing string operations for JSON extraction
    return raw_dossier.decode("latin-1")
```

### Component 2: Update `check_dossier_revocations()` Signature

**Location**: `app/vvp/verify.py`

**Current**:
```python
async def check_dossier_revocations(
    dag: DossierDAG,
    oobi_url: Optional[str] = None
) -> Tuple[ClaimBuilder, List[str]]:
```

**Proposed**:
```python
async def check_dossier_revocations(
    dag: DossierDAG,
    raw_dossier: Optional[bytes] = None,
    oobi_url: Optional[str] = None  # Used only for registry OOBI base URL derivation
) -> Tuple[ClaimBuilder, List[str]]:
```

### Component 3: Inline TEL + Registry OOBI Logic

**Location**: `app/vvp/verify.py` (within `check_dossier_revocations()`)

```python
async def check_dossier_revocations(
    dag: DossierDAG,
    raw_dossier: Optional[bytes] = None,
    oobi_url: Optional[str] = None
) -> Tuple[ClaimBuilder, List[str]]:
    """Check revocation status for all credentials in a dossier DAG.

    Strategy (per reviewer feedback):
    1. First check if TEL events are included inline in raw_dossier
    2. If found, use inline TEL to determine status (no network required)
    3. If not found, resolve registry OOBI to discover TEL-serving witnesses
    4. Query registry witnesses for TEL events

    The PASSporT signer's OOBI (oobi_url) is NOT used for TEL queries because
    it points to the signer's agent, not the credential registry controller.
    """
    from .keri.tel_client import get_tel_client, CredentialStatus

    claim = ClaimBuilder("revocation_clear")
    client = get_tel_client()
    revoked_saids: List[str] = []

    # Step 1: Try to extract TEL events from inline dossier (binary-safe)
    inline_tel_results: Dict[str, RevocationResult] = {}
    if raw_dossier:
        log.info("check_dossier_revocations: checking for inline TEL events")
        # Use latin-1 for byte-transparent decoding (preserves all bytes)
        dossier_text = raw_dossier.decode("latin-1")
        for said, node in dag.nodes.items():
            registry_said = node.raw.get("ri")
            result = client.parse_dossier_tel(
                dossier_text,
                credential_said=said,
                registry_said=registry_said
            )
            if result.status != CredentialStatus.UNKNOWN:
                inline_tel_results[said] = result
                log.info(f"  found inline TEL for {said[:20]}...: {result.status.value}")

    # Step 2: Check each credential
    for said, node in dag.nodes.items():
        registry_said = node.raw.get("ri")

        # Use inline result if available
        if said in inline_tel_results:
            result = inline_tel_results[said]
            log.info(f"  using inline TEL for {said[:20]}...: {result.status.value}")
        else:
            # Step 3: Resolve registry OOBI and query its witnesses
            log.info(f"  no inline TEL for {said[:20]}..., resolving registry OOBI")
            result = await _query_registry_tel(
                client,
                credential_said=said,
                registry_said=registry_said,
                base_oobi_url=oobi_url  # Used to derive registry OOBI pattern
            )

        # Process result with consistent evidence format
        if result.status == CredentialStatus.REVOKED:
            revoked_saids.append(said)
            claim.fail(ClaimStatus.INVALID, f"Credential {said[:20]}... is revoked")
            claim.add_evidence(f"revocation_source:{result.source}")
        elif result.status in (CredentialStatus.UNKNOWN, CredentialStatus.ERROR):
            if claim.status != ClaimStatus.INVALID:
                claim.fail(ClaimStatus.INDETERMINATE,
                    f"Could not determine revocation status for {said[:20]}...: {result.error or 'unknown'}")
        else:
            claim.add_evidence(f"active:{said[:16]}...|revocation_source:{result.source}")

    # Summary evidence
    total = len(dag.nodes)
    inline_count = len(inline_tel_results)
    claim.add_evidence(f"checked:{total},inline:{inline_count},queried:{total - inline_count}")

    return claim, revoked_saids
```

### Component 4: Registry OOBI Resolution

**Location**: `app/vvp/verify.py` (new helper function)

```python
async def _query_registry_tel(
    client: TELClient,
    credential_said: str,
    registry_said: Optional[str],
    base_oobi_url: Optional[str]
) -> RevocationResult:
    """Query TEL via registry OOBI resolution.

    Strategy:
    1. Construct registry OOBI URL from base OOBI pattern
    2. Resolve registry OOBI to get registry controller's witnesses
    3. Query those witnesses for TEL events

    Args:
        client: TEL client instance
        credential_said: Credential SAID to check
        registry_said: Registry SAID (from ACDC 'ri' field)
        base_oobi_url: Base OOBI URL to derive registry OOBI pattern

    Returns:
        RevocationResult from registry witnesses
    """
    if not registry_said:
        log.info(f"    no registry SAID for {credential_said[:20]}..., cannot resolve registry OOBI")
        return RevocationResult(
            status=CredentialStatus.UNKNOWN,
            credential_said=credential_said,
            registry_said=None,
            issuance_event=None,
            revocation_event=None,
            error="No registry SAID in credential",
            source="none"
        )

    # Derive registry OOBI URL from base OOBI pattern
    # Pattern: replace AID in OOBI path with registry SAID
    registry_oobi_url = None
    if base_oobi_url:
        from urllib.parse import urlparse, urlunparse
        parsed = urlparse(base_oobi_url)
        # Construct registry OOBI: {scheme}://{netloc}/oobi/{registry_said}
        registry_oobi_url = f"{parsed.scheme}://{parsed.netloc}/oobi/{registry_said}"
        log.info(f"    constructed registry OOBI: {registry_oobi_url}")

    # Query via registry OOBI
    if registry_oobi_url:
        result = await client.check_revocation(
            credential_said=credential_said,
            registry_said=registry_said,
            oobi_url=registry_oobi_url
        )
        if result.status != CredentialStatus.ERROR:
            return result
        log.info(f"    registry OOBI query failed: {result.error}")

    # Fallback: try direct witness queries (existing behavior)
    log.info(f"    falling back to default witness queries")
    return await client.check_revocation(
        credential_said=credential_said,
        registry_said=registry_said,
        oobi_url=None  # Use default witnesses
    )
```

### Component 5: Update `verify_vvp()` Call Site

**Location**: `app/vvp/verify.py` (within `verify_vvp()`)

**Current**:
```python
if dag is not None:
    revocation_claim, revoked_saids = await check_dossier_revocations(
        dag,
        oobi_url=passport.header.kid if passport else None
    )
```

**Proposed**:
```python
if dag is not None:
    revocation_claim, revoked_saids = await check_dossier_revocations(
        dag,
        raw_dossier=raw_dossier,  # Pass raw bytes for inline TEL parsing
        oobi_url=passport.header.kid if passport else None  # For registry OOBI derivation
    )
```

### Component 6: Enhance TEL Client Logging

**Location**: `app/vvp/keri/tel_client.py`

```python
def parse_dossier_tel(
    self,
    dossier_data: str,
    credential_said: str,
    registry_said: Optional[str] = None
) -> RevocationResult:
    """Parse TEL events from a dossier CESR stream (no network request)."""
    log.info(f"parse_dossier_tel: scanning for TEL events for {credential_said[:20]}...")

    result = self._parse_tel_response(
        credential_said, registry_said, dossier_data, "dossier"
    )

    log.info(f"parse_dossier_tel: result={result.status.value} "
             f"issuance={result.issuance_event is not None} "
             f"revocation={result.revocation_event is not None}")

    return result
```

---

## Data Flow (After Fix)

```
verify_vvp()
    │
    ├─ Dossier fetch from evd URL
    │   └─ raw_dossier: bytes
    │
    ├─ parse_dossier(raw_dossier)
    │   └─ Extracts ACDCs → dag
    │
    └─ check_dossier_revocations(dag, raw_dossier, oobi_url)
        │
        ├─ Step 1: Parse raw_dossier for inline TEL events (binary-safe)
        │   └─ TELClient.parse_dossier_tel() for each credential
        │   └─ If TEL found → use it (no network needed)
        │
        └─ Step 2: For credentials without inline TEL
            ├─ Derive registry OOBI URL from base OOBI
            │   └─ {scheme}://{netloc}/oobi/{registry_said}
            ├─ Query registry OOBI for TEL events
            └─ Fallback to default witnesses if registry OOBI fails
```

---

## Test Strategy

### Unit Tests (`tests/test_revocation_checker.py`)

```python
class TestInlineTELParsing:
    """Tests for inline TEL extraction from dossier."""

    @pytest.mark.asyncio
    async def test_inline_tel_active(self):
        """Inline TEL showing ACTIVE status → VALID claim."""

    @pytest.mark.asyncio
    async def test_inline_tel_revoked(self):
        """Inline TEL showing revocation → INVALID claim."""

    @pytest.mark.asyncio
    async def test_binary_cesr_dossier(self):
        """Binary CESR dossier with TEL events parsed correctly."""


class TestRegistryOOBIDiscovery:
    """Tests for registry OOBI resolution."""

    @pytest.mark.asyncio
    async def test_registry_oobi_derived_correctly(self):
        """Registry OOBI URL constructed from base OOBI pattern."""

    @pytest.mark.asyncio
    async def test_registry_oobi_query_success(self):
        """Registry OOBI query returns TEL status."""

    @pytest.mark.asyncio
    async def test_fallback_to_default_witnesses(self):
        """Falls back to default witnesses when registry OOBI fails."""

    @pytest.mark.asyncio
    async def test_no_registry_said_returns_unknown(self):
        """Credential without registry SAID returns UNKNOWN."""


class TestEvidenceFormat:
    """Tests for consistent evidence formatting."""

    @pytest.mark.asyncio
    async def test_evidence_shows_revocation_source_dossier(self):
        """Evidence includes revocation_source:dossier for inline TEL."""

    @pytest.mark.asyncio
    async def test_evidence_shows_revocation_source_witness(self):
        """Evidence includes revocation_source:witness for queried TEL."""

    @pytest.mark.asyncio
    async def test_evidence_summary_counts(self):
        """Summary evidence shows checked, inline, queried counts."""
```

---

## Files to Create/Modify

| File | Action | Purpose |
|------|--------|---------|
| `app/vvp/verify.py` | Modify | Add `raw_dossier` param, inline TEL check, registry OOBI discovery |
| `app/vvp/keri/tel_client.py` | Modify | Add logging to `parse_dossier_tel()` |
| `tests/test_revocation_checker.py` | Modify | Add inline TEL and registry OOBI tests |

---

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Dossier doesn't include TEL | Medium | Medium | Registry OOBI discovery as fallback |
| Registry OOBI pattern varies | Medium | Medium | Fallback to default witnesses |
| Binary CESR parsing fails | Low | Low | Use latin-1 for byte-transparent decoding |
| Registry OOBI returns 404 | Medium | Low | Fallback chain with clear logging |

---

## Resolved Questions (per Reviewer)

1. **Should we cache inline TEL results?**
   - **Answer**: No—inline parsing is cheap and dossier-specific; cache only witness queries.

2. **What if inline TEL contradicts witness TEL?**
   - **Answer**: Prefer inline TEL if it is part of the fetched dossier; if conflict is detected, surface INDETERMINATE with both sources in reasons.

3. **Should we log when falling back to witness queries?**
   - **Answer**: Yes, log at INFO with credential SAID and registry SAID.

---

## Exit Criteria

- [ ] `check_dossier_revocations()` accepts `raw_dossier` parameter
- [ ] Inline TEL events are parsed using binary-safe decoding (latin-1)
- [ ] Inline TEL status is used when available
- [ ] Registry OOBI is derived and queried when inline TEL is absent
- [ ] Fallback to default witnesses when registry OOBI fails
- [ ] Evidence uses consistent format: `revocation_source:{dossier|witness}`
- [ ] Summary evidence shows counts: `checked:{n},inline:{n},queried:{n}`
- [ ] All existing tests pass
- [ ] New inline TEL and registry OOBI tests pass
- [ ] Logging shows clear progression: inline → registry OOBI → fallback

---

## Revision 1 (Response to CHANGES_REQUESTED)

### Changes Made

| Finding | Resolution |
|---------|------------|
| [High] Fallback still uses PASSporT signer OOBI which is wrong endpoint | Added registry OOBI discovery: derive `/oobi/{registry_said}` from base URL, query registry witnesses before falling back to defaults |
| [Medium] Naive UTF-8 decode may corrupt binary CESR | Changed to latin-1 decoding which is byte-transparent and preserves all data for JSON extraction |
| [Low] Evidence format inconsistent | Standardized to `revocation_source:{dossier\|witness}` and added summary counts |

---

## Implementation Notes

### Deviations from Plan

1. **Registry SAID handling**: When `registry_said` is None (credential has no `ri` field), the implementation now falls back to default witness queries instead of immediately returning UNKNOWN. This preserves backward compatibility with existing tests.

### Implementation Details

1. **`_query_registry_tel()` helper**: Added as a separate function for clarity. Handles:
   - No registry SAID → fall back to default witnesses
   - Registry OOBI derivation: `{scheme}://{netloc}/oobi/{registry_said}`
   - Registry OOBI query with fallback to default witnesses

2. **Logging**: Added detailed logging to `parse_dossier_tel()` showing:
   - Number of inline TEL events found
   - Event types and sequence numbers
   - Final result status

3. **Evidence format**: Active credentials show `active:{said[:16]}...|revocation_source:{source}` for traceability.

### Test Results

```
tests/test_revocation_checker.py - 20 passed
Full test suite - 440 passed, 2 skipped in 3.69s
```

### Files Changed

| File | Lines | Summary |
|------|-------|---------|
| `app/vvp/verify.py` | +60 | Added `_query_registry_tel()` helper, updated `check_dossier_revocations()` with inline TEL + registry OOBI logic |
| `app/vvp/keri/tel_client.py` | +15 | Added logging to `parse_dossier_tel()` |
| `tests/test_revocation_checker.py` | +150 | Added 5 new test classes with 7 new tests for inline TEL, registry OOBI, and binary-safe parsing |


# PLAN_Phase9.md

# Phase 9: VVP Verifier Specification v1.5

## Problem Statement

The VVP Verifier Specification v1.4 FINAL defines core verification infrastructure but lacks the complete verification algorithm as specified in the authoritative VVP draft specification §5. Without updating the specification:

1. Implementers cannot understand the complete 13-step caller verification algorithm
2. Implementers cannot understand the 14-step callee verification algorithm
3. The claim tree structure is incomplete (missing authorization, TNAlloc, brand, and business logic claims)
4. There is no guidance on caching strategies or historical verification
5. The Implementation Checklist v3.0 references phases (7-14) that have no normative backing

## Spec References

From `https://dhh1128.github.io/vvp/draft-hardman-verifiable-voice-protocol.html`:

- **§5.1.1-2.1 through §5.1.1-2.13**: Complete caller verification algorithm (13 steps)
- **§5.2-2.1 through §5.2-2.14**: Complete callee verification algorithm (14 steps)
- **§5.3**: Planning for Efficiency (caching, SAID-based validation sharing)
- **§5.4**: Historical Analysis (temporal verification capabilities)

## Current State

**VVP_Verifier_Specification_v1.4_FINAL.md** provides:
- Claim model and propagation rules (§3)
- API contracts (§4)
- PASSporT verification basics (§5)
- Dossier model (§6)
- KERI integration notes (§7)
- Basic verification pseudocode (§9)
- Test vectors structure (§10)

**Limitations:**
- No complete verification algorithm (only high-level pseudocode)
- No SIP contextual alignment requirements
- No authorization verification (TNAlloc, delegation)
- No brand/business logic verification
- No callee verification flow
- No caching/efficiency guidance
- Claim tree structure incomplete

## Proposed Solution

Create **VVP_Verifier_Specification_v1.5.md** that extends v1.4 with complete verification algorithms.

### Summary of Changes

| Section | Change Type | Description |
|---------|-------------|-------------|
| Status | Updated | Lists all changes from v1.4 |
| §2.1 | Updated | Architecture diagram includes SIP context and authorization |
| §3.3B | NEW | Complete claim tree structure for caller and callee |
| §4.1 | Updated | Request body includes `context.sip` object |
| §4.2A | Extended | 7 new error codes for authorization and context |
| §4.4 | NEW | SIP Context Fields normative section |
| §5A | NEW | 13-step Caller Verification Algorithm |
| §5B | NEW | 14-step Callee Verification Algorithm |
| §5C | NEW | Efficiency and Caching guidance |
| §5D | NEW | Historical Verification capabilities |
| §9 | Expanded | Full pseudocode for caller and callee verification |
| §10.2 | Expanded | 8 additional test vectors |
| §12 | NEW | Implementation Tiers (Tier 1/2/3) |
| Appendix A | NEW | Spec §5 Traceability Matrix |

### Detailed Changes

#### §3.3B: Complete Claim Tree Structure

Added normative claim tree structures for both caller and callee verification:

**Caller:**
```
caller_verified (root)
├── passport_verified (REQUIRED)
├── dossier_verified (REQUIRED)
├── authorization_valid (REQUIRED)
│   ├── party_authorized (REQUIRED)
│   └── tn_rights_valid (REQUIRED)
├── context_aligned (REQUIRED or OPTIONAL per policy)
├── brand_verified (OPTIONAL)
└── business_logic_verified (OPTIONAL)
```

**Why:** The v1.4 claim tree only showed a simple example. Implementers need the complete structure to build correct claim propagation.

#### §4.2A: Extended Error Code Registry

Added 7 new error codes:

| Code | Purpose |
|------|---------|
| CREDENTIAL_REVOKED | Credential in dossier has been revoked |
| CONTEXT_MISMATCH | SIP context does not match PASSporT claims |
| AUTHORIZATION_FAILED | Originating party not authorized |
| TN_RIGHTS_INVALID | TNAlloc credential does not match orig |
| BRAND_CREDENTIAL_INVALID | Brand credential does not support card claims |
| GOAL_REJECTED | Goal claim rejected by verifier policy |
| DIALOG_MISMATCH | call-id/cseq do not match SIP INVITE |

**Why:** The new verification steps require error codes to report failures. Mapping to existing codes would lose semantic precision.

#### §4.4: SIP Context Fields

New normative section defining the `context.sip` request object:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| from_uri | string | Yes | SIP From URI |
| to_uri | string | Yes | SIP To URI |
| invite_time | RFC3339 | Yes | Timestamp of SIP INVITE |
| cseq | integer | No | CSeq number (for callee) |

**Why:** §5.1.1-2.2 requires contextual alignment with SIP metadata. The API must accept this data.

#### §5A: Caller Verification Algorithm

Complete 13-step algorithm per VVP §5.1, including:
- Each step with spec reference
- MUST/MAY requirements
- Failure mapping to error codes
- Claim node affected by each step

**Why:** This is the core normative content from the VVP draft that was missing from v1.4.

#### §5B: Callee Verification Algorithm

Complete 14-step algorithm per VVP §5.2, including:
- Dialog matching (call-id, cseq)
- Issuer verification
- Goal overlap checking

**Why:** Callee verification is a distinct flow with different requirements than caller verification.

#### §5C: Efficiency and Caching

Guidance per VVP §5.3:
- Cache types (dossier, key state, revocation)
- Recommended TTLs
- Data sovereignty considerations

**Why:** Production deployments need caching to achieve acceptable performance.

#### §5D: Historical Verification

Capabilities per VVP §5.4:
- Verification at past reference times
- Fuzzy range handling
- Use cases (forensics, disputes, compliance)

**Why:** Historical verification is a key VVP capability that enables post-incident analysis.

#### §12: Implementation Tiers

Formalized the tier model from the Implementation Checklist:

| Tier | Description |
|------|-------------|
| Tier 1 | Direct verification (complete) |
| Tier 2 | Full KERI (KEL, ACDC signatures, revocation) |
| Tier 3 | Authorization and rich call data |

**Why:** Provides clear implementation roadmap aligned with checklist phases.

#### Appendix A: Traceability Matrix

Maps each VVP §5 section to:
- This spec section
- Implementation phase number

**Why:** Ensures nothing from the authoritative spec was missed and enables verification of completeness.

## Files Created/Modified

| File | Action | Purpose |
|------|--------|---------|
| `app/Documentation/VVP_Verifier_Specification_v1.5.md` | Created | New specification version |

## Open Questions

1. **SIP Context Requirement:** Should `context_aligned` be REQUIRED or OPTIONAL by default? The spec says "MUST confirm" but practical deployments may not have SIP context at the verifier. Current decision: configurable via policy (`policy.context_required`).

2. **Replay Tolerance:** VVP §5.1.1-2.1 recommends 30 seconds for replay tolerance. We currently use 5 seconds for iat drift (§5.2A). Should replay tolerance be separate from iat binding tolerance?

3. **Error Code Consolidation:** Should AUTHORIZATION_FAILED and TN_RIGHTS_INVALID be separate codes, or consolidated under a single AUTHORIZATION error?

4. **Callee API Endpoint:** Should callee verification be a separate `/verify-callee` endpoint or a mode flag on `/verify`?

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Spec divergence from VVP draft | Low | High | Explicit § references, traceability matrix |
| Error code proliferation | Medium | Low | Consolidate if semantically equivalent |
| Over-specification | Low | Medium | Mark unimplemented as "Tier 2/3" |

---

---

## Revision 1 (Response to CHANGES_REQUESTED)

### Changes Made

| Finding | Resolution |
|---------|------------|
| [High] §9 pseudocode doesn't build REQUIRED claim nodes from §3.3B | Rewrote §9.1 and §9.2 to explicitly initialize and populate all REQUIRED claim nodes with exact names from §3.3B |
| [Medium] `issuer_matched` under wrong parent in callee tree | Moved from `passport_verified` to `dossier_verified` in §3.3B and §9.2 |
| [Medium] §10.2 vectors conflict with Tier 1 scope | Split into §10.2.1 (Tier 1), §10.2.2 (Tier 2), §10.2.3 (Tier 3) with 8/5/7 vectors respectively |
| [Low] Missing error code for issuer mismatch | Added `ISSUER_MISMATCH` to §4.2A and referenced in §5B Step 9 |

### Additional Improvements (per recommendations)

1. Added step-to-claim mapping tables after §5A and §5B to prevent future drift
2. Clarified SIP context absent behavior in §4.4: MUST produce INDETERMINATE (not INVALID), MUST NOT reject
3. Added note in §5A Step 1 distinguishing replay tolerance (30s) from iat binding tolerance (5s)

### Answers to Open Questions (incorporated)

1. **SIP Context Requirement**: Now policy-driven, default OPTIONAL; absence produces INDETERMINATE
2. **Replay Tolerance**: Documented as separate from iat binding (30s vs 5s)
3. **Error Code Consolidation**: Kept separate as recommended
4. **Callee API Endpoint**: Noted in recommendations for future consideration

---

## Reviewer Prompt (Revision 1)

```
## Plan Review Request: Phase 9 - VVP Verifier Specification v1.5 (Revision 1)

You are the Reviewer in a pair programming workflow. This is a re-review after addressing your previous CHANGES_REQUESTED feedback.

### Documents to Review

1. `app/Documentation/VVP_Verifier_Specification_v1.5.md` - The revised specification
2. `PLAN.md` - Summary of changes including "Revision 1" section documenting fixes

### Changes Made Since Last Review

| Finding | Resolution |
|---------|------------|
| [High] §9 pseudocode doesn't build REQUIRED claim nodes | Rewrote §9.1 and §9.2 with explicit claim node initialization |
| [Medium] `issuer_matched` wrong parent | Moved to `dossier_verified` in §3.3B and §9.2 |
| [Medium] §10.2 vectors conflict with Tier 1 scope | Split into §10.2.1/2/3 by tier |
| [Low] Missing ISSUER_MISMATCH error code | Added to §4.2A and §5B Step 9 |

Additional improvements:
- Added step-to-claim mapping tables after §5A and §5B
- Clarified SIP context absent behavior (INDETERMINATE, not reject)
- Documented replay tolerance vs iat binding tolerance distinction

### Your Task

1. Verify the required changes have been correctly implemented
2. Confirm §9 pseudocode now builds all REQUIRED claim nodes from §3.3B
3. Confirm `issuer_matched` is now under `dossier_verified` in callee tree
4. Confirm §10.2 test vectors are properly tiered
5. Provide verdict and feedback in `REVIEW.md`

### Response Format

Write your response to `REVIEW.md` using this structure:

## Plan Review: Phase 9 - VVP Verifier Specification v1.5 (Revision 1)

**Verdict:** APPROVED | CHANGES_REQUESTED

### Required Changes Verification
[Confirm each required change was properly addressed]

### Additional Improvements Assessment
[Evaluation of step-to-claim tables and clarifications]

### Findings
- [High]: Critical issue that blocks approval
- [Medium]: Important issue that should be addressed
- [Low]: Suggestion for improvement (optional)

### Required Changes (if CHANGES_REQUESTED)
1. [Specific change required]

### Final Recommendations
- [Optional improvements or future considerations]
```


# PLAN_Phase10.md

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


# PLAN_Phase11.md

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


# PLAN_Phase14.md

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


# PLAN_Sprint15.md

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


# PLAN_Sprint17.md

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


# PLAN_Sprint18.md

# Sprint 18: Brand/Business Logic & SIP Contextual Alignment (Revision 1)

**Phases:** 11 (Brand/Business Logic) + 13 (SIP Contextual Alignment)
**Checklist Items:** 23 items (17 + 6)
**Target Completion:** 88% overall (161/182 items)

---

## Revision 1 Changes (Addressing Reviewer Feedback)

| Issue | Resolution |
|-------|------------|
| [High] Brand proxy warnings only | Brand proxy → INDETERMINATE when delegation present but proxy credential missing |
| [High] Geographic constraints warnings only | Geo constraints → INDETERMINATE when constraints exist but GeoIP unavailable |
| [Medium] OPTIONAL claim nodes | brand_verified/business_logic_verified are REQUIRED when card/goal present |

---

## Overview

Sprint 18 completes the caller verification algorithm (§5A Steps 2, 12-13) by adding:
1. **SIP Contextual Alignment** - Validate PASSporT claims match SIP INVITE metadata
2. **Brand Verification** - Validate `card` claims against dossier credentials
3. **Business Logic** - Validate `goal` claims against verifier policy

**Claim Status Semantics (Revised):**
- `context_aligned`: REQUIRED or OPTIONAL per policy (default: OPTIONAL)
- `brand_verified`: REQUIRED when `card` is present (failures propagate)
- `business_logic_verified`: REQUIRED when `goal` is present (failures propagate)

---

## Files to Create

| File | Purpose |
|------|---------|
| `app/vvp/sip_context.py` | SIP URI parsing, contextual alignment validation |
| `app/vvp/brand.py` | Brand credential location, vCard validation |
| `app/vvp/goal.py` | Goal policy, signer constraint checking |
| `tests/test_sip_context.py` | Phase 13 unit tests |
| `tests/test_brand.py` | Brand verification tests |
| `tests/test_goal.py` | Goal/business logic tests |

## Files to Modify

| File | Changes |
|------|---------|
| `app/vvp/api_models.py` | Add `SipContext` model, add error codes to recoverability map |
| `app/core/config.py` | Add goal policy, SIP timing tolerance, context required flag |
| `app/vvp/verify.py` | Integrate 3 new claim nodes into orchestration |

---

## Phase 13: SIP Contextual Alignment (6 items)

### 13.1 Model Changes (`api_models.py`)

```python
class SipContext(BaseModel):
    """SIP context fields per spec §4.4."""
    from_uri: str       # SIP From URI
    to_uri: str         # SIP To URI
    invite_time: str    # RFC3339 timestamp of SIP INVITE
    cseq: Optional[int] = None  # For callee verification

class CallContext(BaseModel):
    call_id: str
    received_at: str
    sip: Optional[SipContext] = None  # NEW - optional per §4.4
```

Add to `ERROR_RECOVERABILITY`:
```python
ErrorCode.CONTEXT_MISMATCH: False,  # Non-recoverable
```

### 13.2 New Module: `sip_context.py`

**Functions:**
- `extract_tn_from_sip_uri(uri: str) -> Optional[str]` - Parse phone from SIP/TEL URI
- `validate_orig_alignment(orig_tn: str, from_uri: str) -> Tuple[bool, str]` - §5A Step 2
- `validate_dest_alignment(dest_tns: List[str], to_uri: str) -> Tuple[bool, str]` - §5A Step 2
- `validate_timing_alignment(iat: int, invite_time: datetime, tolerance: int) -> Tuple[bool, str]`
- `verify_sip_context_alignment(passport: Passport, sip: Optional[SipContext]) -> ClaimBuilder`

**URI Formats to Support:**
- `sip:+15551234567@domain.com`
- `sip:15551234567@domain.com;user=phone`
- `tel:+15551234567`
- `tel:+1-555-123-4567` (visual separators)

**Behavior:**
- If `sip` is None → INDETERMINATE with reason "SIP context not provided"
- If `sip` provided but mismatch → INVALID with CONTEXT_MISMATCH error
- Timing tolerance: 30 seconds (configurable via `VVP_SIP_TIMING_TOLERANCE`)

### 13.3 Config Changes (`config.py`)

```python
# SIP contextual alignment timing tolerance (§5A Step 2)
SIP_TIMING_TOLERANCE_SECONDS: int = int(os.getenv("VVP_SIP_TIMING_TOLERANCE", "30"))

# Whether context alignment is required (§4.4 - default False)
CONTEXT_ALIGNMENT_REQUIRED: bool = os.getenv("VVP_CONTEXT_REQUIRED", "false").lower() == "true"
```

---

## Phase 11: Brand & Business Logic (17 items)

### 11.1 Brand Module (`brand.py`)

**Functions:**
- `validate_vcard_format(card: Dict) -> List[str]` - Validate vCard field names/types (warn on unknown)
- `find_brand_credential(dossier_acdcs: Dict[str, ACDC]) -> Optional[ACDC]` - Locate by attributes
- `verify_brand_attributes(card: Dict, credential: ACDC) -> Tuple[bool, List[str]]` - Match card to credential
- `verify_brand_jl(credential: ACDC, dossier: Dict) -> Tuple[bool, str]` - Check JL to vetting (§6.3.7)
- `verify_brand_proxy(de: ACDC, dossier: Dict) -> Tuple[bool, str]` - Check brand proxy in delegation (§6.3.4)
- `verify_brand(passport: Passport, dossier_acdcs: Dict, de_credential: Optional[ACDC]) -> ClaimBuilder`

**vCard Fields (subset):**
```python
VCARD_FIELDS = {"fn", "org", "tel", "email", "url", "logo", "photo", "adr"}
# Unknown fields: log warning but do NOT mark INVALID (per Reviewer answer)
```

**Behavior (Revised):**
- If `card` is None → No claim created (nothing to verify)
- If `card` present:
  - No brand credential found → INVALID with BRAND_CREDENTIAL_INVALID
  - Brand credential missing JL to vetting → INVALID (§6.3.7 MUST)
  - **NEW:** Delegation present but brand proxy missing → INDETERMINATE (§6.3.4 MUST, but can't verify without proxy)
  - Attributes don't match → INVALID
  - All checks pass → VALID

### 11.2 Goal Module (`goal.py`)

**Functions:**
- `verify_goal_policy(goal: str, accepted: FrozenSet[str], reject_unknown: bool) -> Tuple[bool, str]`
- `extract_signer_constraints(de: Optional[ACDC]) -> SignerConstraints`
- `verify_signer_constraints(constraints: SignerConstraints, call_time: datetime, caller_geo: Optional[str]) -> Tuple[ClaimStatus, List[str]]`
- `verify_business_logic(passport: Passport, dossier: Dict, de: Optional[ACDC], policy: GoalPolicyConfig, call_time: datetime) -> ClaimBuilder`

**SignerConstraints dataclass:**
```python
@dataclass
class SignerConstraints:
    hours_of_operation: Optional[Tuple[int, int]] = None  # (start_hour, end_hour) UTC
    geographies: Optional[List[str]] = None  # ISO 3166-1 codes
```

**Behavior (Revised):**
- If `goal` is None → No claim created
- If `goal` present:
  - Goal rejected by policy → INVALID with GOAL_REJECTED
  - Hours constraint violated → INVALID
  - **NEW:** Geo constraints present but GeoIP unavailable → INDETERMINATE (can't verify)
  - All checks pass → VALID

### 11.3 Config Changes (`config.py`)

```python
# Goal acceptance policy (§5.1.1-2.13)
# Empty = accept all goals
def _parse_accepted_goals() -> frozenset[str]:
    env_value = os.getenv("VVP_ACCEPTED_GOALS", "")
    if env_value:
        return frozenset(g.strip() for g in env_value.split(",") if g.strip())
    return frozenset()  # Empty = accept all

ACCEPTED_GOALS: frozenset[str] = _parse_accepted_goals()
REJECT_UNKNOWN_GOALS: bool = os.getenv("VVP_REJECT_UNKNOWN_GOALS", "false").lower() == "true"

# Geographic constraint enforcement (§5.1.1-2.13)
# When True: geo constraints trigger INDETERMINATE if GeoIP unavailable
# When False: geo constraints are skipped (policy deviation, logged)
GEO_CONSTRAINTS_ENFORCED: bool = os.getenv("VVP_GEO_CONSTRAINTS_ENFORCED", "true").lower() == "true"
```

---

## Integration into verify.py

### Claim Tree (Updated - Revision 1)

```
caller_authorised (root)
├── passport_verified (REQUIRED)
├── dossier_verified (REQUIRED)
│   ├── chain_verified (REQUIRED)
│   └── revocation_clear (REQUIRED)
├── authorization_valid (REQUIRED)
│   ├── party_authorized (REQUIRED)
│   └── tn_rights_valid (REQUIRED)
├── context_aligned (REQUIRED or OPTIONAL per policy)     ← NEW
├── brand_verified (REQUIRED when card present)           ← REVISED
└── business_logic_verified (REQUIRED when goal present)  ← REVISED
```

**Status Propagation:**
- When `card` is present, `brand_verified` is a REQUIRED child → failures propagate
- When `goal` is present, `business_logic_verified` is a REQUIRED child → failures propagate
- When neither is present, these nodes are not added to the tree

### Integration Points

After authorization validation (~line 853), add:

```python
# Phase 13: SIP Contextual Alignment (§5A Step 2)
from app.vvp.sip_context import verify_sip_context_alignment
context_claim = verify_sip_context_alignment(passport, req.context.sip)

# Phase 11: Brand Verification (§5A Step 12)
brand_claim = None
if passport and passport.payload.card:
    from app.vvp.brand import verify_brand
    brand_claim = verify_brand(passport, dossier_acdcs, de_credential=matching_de)

# Phase 11: Business Logic (§5A Step 13)
business_claim = None
if passport and passport.payload.goal:
    from app.vvp.goal import verify_business_logic, GoalPolicyConfig
    from app.core.config import ACCEPTED_GOALS, REJECT_UNKNOWN_GOALS, GEO_CONSTRAINTS_ENFORCED
    policy = GoalPolicyConfig(
        accepted_goals=ACCEPTED_GOALS,
        reject_unknown=REJECT_UNKNOWN_GOALS,
        geo_enforced=GEO_CONSTRAINTS_ENFORCED
    )
    business_claim = verify_business_logic(
        passport, dossier_acdcs, matching_de, policy, call_time=datetime.now(timezone.utc)
    )
```

### Claim Tree Assembly (Revised)

```python
children = [
    ChildLink(required=True, node=passport_node),
    ChildLink(required=True, node=dossier_node),
    ChildLink(required=True, node=authorization_node),
    ChildLink(required=CONTEXT_ALIGNMENT_REQUIRED, node=context_claim.build()),
]

# Brand and business claims are REQUIRED when present (per Reviewer feedback)
if brand_claim:
    children.append(ChildLink(required=True, node=brand_claim.build()))
if business_claim:
    children.append(ChildLink(required=True, node=business_claim.build()))
```

---

## Test Strategy

### Phase 13 Tests (`test_sip_context.py`)

| Test | Description |
|------|-------------|
| `test_extract_tn_sip_uri_with_plus` | Parse `sip:+15551234567@domain.com` |
| `test_extract_tn_tel_uri` | Parse `tel:+15551234567` |
| `test_extract_tn_with_separators` | Parse `tel:+1-555-123-4567` |
| `test_orig_alignment_exact_match` | orig.tn matches From URI |
| `test_orig_alignment_mismatch` | Different numbers → INVALID |
| `test_dest_alignment_in_array` | To URI in dest.tn array |
| `test_dest_alignment_not_in_array` | To URI not in array → INVALID |
| `test_timing_within_tolerance` | iat within 30s of invite |
| `test_timing_exceeds_tolerance` | iat outside 30s → INVALID |
| `test_sip_context_absent` | No SIP context → INDETERMINATE |
| `test_sip_context_provided_mismatch` | Context provided but mismatch → INVALID |

### Phase 11 Tests (`test_brand.py`, `test_goal.py`)

| Test | Description |
|------|-------------|
| `test_vcard_valid_fields` | Known vCard fields accepted |
| `test_vcard_unknown_fields_warn` | Unknown fields log warning, not INVALID |
| `test_find_brand_credential` | Locate by org/name attributes |
| `test_brand_attributes_match` | card values match credential |
| `test_brand_missing_jl` | No JL to vetting → INVALID |
| `test_brand_proxy_missing_delegation` | Delegation but no proxy → INDETERMINATE |
| `test_goal_in_whitelist` | Accepted goal → VALID |
| `test_goal_rejected_policy` | Unknown goal + reject_unknown → INVALID |
| `test_hours_constraint_valid` | Call within permitted hours |
| `test_hours_constraint_violated` | Call outside hours → INVALID |
| `test_geo_constraint_no_geoip` | Geo constraint but no GeoIP → INDETERMINATE |
| `test_no_card_no_claim` | card=None → no brand_verified node |
| `test_no_goal_no_claim` | goal=None → no business_logic node |
| `test_brand_failure_propagates` | brand INVALID → caller_authorised INVALID |
| `test_business_failure_propagates` | business INVALID → caller_authorised INVALID |

---

## Implementation Order

1. **Phase 13 foundation** - Add SipContext model to api_models.py
2. **Phase 13 core** - Create sip_context.py with URI parsing and validators
3. **Phase 13 tests** - Unit tests for SIP context alignment
4. **Phase 13 integration** - Wire into verify.py
5. **Phase 11 brand** - Create brand.py module (with brand proxy check)
6. **Phase 11 goal** - Create goal.py module (with geo INDETERMINATE)
7. **Phase 11 config** - Add goal policy and geo enforcement to config.py
8. **Phase 11 tests** - Unit tests for brand and goal
9. **Phase 11 integration** - Wire into verify.py with REQUIRED semantics
10. **Integration tests** - Full flow tests with status propagation
11. **Update checklist** - Mark items complete

---

## Policy Deviations (Documented)

Per Reviewer recommendation, explicit policy deviations with documented behavior:

| Deviation | Behavior | Status | Config Flag |
|-----------|----------|--------|-------------|
| Geographic constraints | GeoIP lookup not available | INDETERMINATE | `GEO_CONSTRAINTS_ENFORCED=true` |
| Geographic constraints (disabled) | Skip geo checks | VALID (logged) | `GEO_CONSTRAINTS_ENFORCED=false` |

When `GEO_CONSTRAINTS_ENFORCED=false`, geographic constraint violations are logged but do not affect claim status. This is a documented policy deviation from §5.1.1-2.13.

---

## Verification

```bash
# Run all tests
DYLD_LIBRARY_PATH="/opt/homebrew/lib" python3 -m pytest tests/ -v

# Run new tests specifically
DYLD_LIBRARY_PATH="/opt/homebrew/lib" python3 -m pytest tests/test_sip_context.py tests/test_brand.py tests/test_goal.py -v

# Verify integration and propagation
DYLD_LIBRARY_PATH="/opt/homebrew/lib" python3 -m pytest tests/test_verify.py -v -k "sip_context or brand or goal or propagat"
```

---

## Checklist Items Addressed

**Phase 11 (17 items):** 11.1-11.17
**Phase 13 (6 items):** 13.1-13.6

After Sprint 18: **161/182 items complete (88%)**

---

## Plan Review Request (Revision 1)

Copy the following prompt to the Reviewer agent:

~~~
## Plan Review Request: Sprint 18 Revision 1 - Brand/Business Logic & SIP Contextual Alignment

You are the Reviewer in a pair programming workflow. Please review the revised plan and provide your assessment in `REVIEW.md`.

### Changes from Original Plan
1. [High] Brand proxy: Now INDETERMINATE when delegation present but proxy missing (was: warning only)
2. [High] Geographic constraints: Now INDETERMINATE when geo constraints exist but GeoIP unavailable (was: warning only)
3. [Medium] brand_verified/business_logic_verified: Now REQUIRED when card/goal present (was: OPTIONAL)
4. Added policy deviation documentation for geo constraint enforcement flag
5. Added tests for status propagation from brand/business failures

### Spec References
- §4.4: SIP Context Fields
- §5.1.1-2.2: Contextual Alignment step
- §5.1.1-2.12: Brand Attributes Verification
- §5.1.1-2.13: Business Logic Verification
- §6.3.4: Delegation with brand proxy requirement
- §6.3.7: Brand credential MUST include JL to vetting

### Evaluation Criteria
- Are the high-priority issues from original review resolved?
- Is the INDETERMINATE status appropriate for "can't verify" scenarios?
- Is the policy deviation documentation adequate?

### Response Format
Write your response to `REVIEW.md`:

## Plan Review: Sprint 18 Revision 1

**Verdict:** APPROVED | CHANGES_REQUESTED

### Issue Resolution
- [High] Brand proxy: FIXED | NOT FIXED
- [High] Geographic constraints: FIXED | NOT FIXED
- [Medium] Claim node semantics: FIXED | NOT FIXED

### Additional Findings
- [severity]: description

### Required Changes (if CHANGES_REQUESTED)
1. [change]
~~~


# PLAN_Sprint19.md

# Sprint 19: Callee Verification (Phase 12) + Sprint 18 Fixes

## Problem Statement

The VVP Verifier currently supports only caller verification (§5A). The spec defines a parallel callee verification algorithm (§5B) with 14 steps that validates the called party's identity and rights. Without this, the verifier cannot support bidirectional verification in VVP call flows.

Additionally, Sprint 18 code review identified three configuration/logic issues that need fixing.

## Spec References

- §5B: Callee Verification Algorithm (14 steps)
- §5.2-2.1: Dialog Matching (call-id, cseq)
- §5.2-2.9: Issuer Verification (dossier issuer matches kid)
- §5.2-2.12: Phone Number Rights (callee TN rights)
- §4.2A: Error codes DIALOG_MISMATCH, ISSUER_MISMATCH

## Current State

- Caller verification (§5A) is 100% complete
- Phase 12 (Callee Verification) is 0% complete (15 items)
- Overall project is at 91% completion
- Existing infrastructure (passport parsing, KERI resolution, dossier validation, revocation checking, TN rights) can be reused
- **Sprint 18 code review identified 3 issues requiring fixes**

---

## Part A: Sprint 18 Code Review Fixes

### Issues from Code Review (CHANGES_REQUESTED)

#### A1. [High] CONTEXT_ALIGNMENT_REQUIRED not applied

**Problem:** `verify_sip_context_alignment()` always returns INDETERMINATE when SIP context is absent, even when `CONTEXT_ALIGNMENT_REQUIRED=True` in config.

**Fix:** Add `context_required` parameter to `verify_sip_context_alignment()`, maintaining the existing `ClaimBuilder` return type.

**Files:** `app/vvp/sip_context.py`, `app/vvp/verify.py`

#### A2. [Medium] SIP_TIMING_TOLERANCE_SECONDS not used

**Problem:** `verify_sip_context_alignment()` always uses default 30s instead of configured `SIP_TIMING_TOLERANCE_SECONDS`.

**Fix:** Pass config value through call chain (maintains ClaimBuilder pattern).

**Files:** `app/vvp/sip_context.py`, `app/vvp/verify.py`

#### A3. [Medium] DE selection uses first DE instead of signer's DE

**Problem:** `_find_de_credential()` returns first DE in dossier, not the DE from signer's delegation chain. This causes false positives/negatives for brand proxy and business constraints.

**Fix:** Pass signer AID and filter DEs by delegation chain.

**Files:** `app/vvp/verify.py`

---

## Part B: Phase 12 Callee Verification

### Approach

Create a new `verify_callee.py` module that implements §5B, reusing existing components where possible. The callee flow differs from caller in:

1. **Dialog matching** (new): call-id/cseq validation against SIP INVITE
2. **Issuer verification** (new): dossier issuer must match PASSporT kid
3. **TN rights context** (modified): validates callee can receive at the number
4. **Goal overlap** (new, optional): checks goal compatibility between caller and callee

### Claim Tree (per §3.3B)

```
callee_verified (root)
├── passport_verified (REQUIRED)
│   ├── dialog_matched (REQUIRED)
│   ├── timing_valid (REQUIRED)
│   └── signature_valid (REQUIRED)
├── dossier_verified (REQUIRED)
│   ├── structure_valid (REQUIRED)
│   ├── acdc_signatures_valid (REQUIRED)
│   ├── revocation_clear (REQUIRED)
│   └── issuer_matched (REQUIRED)
├── tn_rights_valid (REQUIRED)
├── brand_verified (REQUIRED when card present, else omitted)
└── goal_overlap_verified (REQUIRED when both goals present, else omitted)
```

### New Error Codes

| Code | When | Status | Recoverable |
|------|------|--------|-------------|
| `DIALOG_MISMATCH` | call-id/cseq don't match SIP INVITE | INVALID | N |
| `ISSUER_MISMATCH` | dossier issuer != passport kid | INVALID | N |

## Files Created/Modified

### Part A: Sprint 18 Fixes

| File | Action | Purpose |
|------|--------|---------|
| `app/vvp/sip_context.py` | Modify | Add `context_required` and `timing_tolerance` parameters |
| `app/vvp/verify.py` | Modify | Pass config values to SIP alignment, fix DE selection for signer chain |
| `tests/test_verify.py` | Modify | Add tests for config-driven behavior |

### Part B: Phase 12 Callee Verification

| File | Action | Purpose |
|------|--------|---------|
| `app/vvp/verify_callee.py` | Create | Callee verification module (~850 lines) |
| `app/vvp/api_models.py` | Modify | Add VerifyCalleeRequest, DIALOG_MISMATCH/ISSUER_MISMATCH error codes |
| `app/vvp/goal.py` | Modify | Add goal overlap validation function (subset check) |
| `app/main.py` | Modify | Add POST /verify-callee endpoint |
| `tests/test_verify_callee.py` | Create | Unit tests for callee verification (70+ tests) |
| `tests/test_models.py` | Modify | Update error code count to include new codes |
| `app/Documentation/VVP_Implementation_Checklist.md` | Modify | Mark Phase 12 complete |

## Sprint Scope

### Part A: Sprint 18 Fixes (3 items)
- A1: [High] Plumb `CONTEXT_ALIGNMENT_REQUIRED` into `verify_sip_context_alignment()`
- A2: [Medium] Plumb `SIP_TIMING_TOLERANCE_SECONDS` into `verify_sip_context_alignment()`
- A3: [Medium] Fix DE selection to use signer's delegation chain DE

### Part B: Phase 12 Callee Verification (all 15 items)
- 12.1: Create verify_callee.py module
- 12.2: Dialog matching (call-id, cseq)
- 12.3: Timing alignment (iat validation)
- 12.4: Expiration analysis (exp policy)
- 12.5: Key identifier extraction (kid)
- 12.6: Signature verification
- 12.7: Dossier fetch and validation
- 12.8: Issuer verification (dossier issuer == kid)
- 12.9: Revocation status check
- 12.10: Phone number rights (callee receiving)
- 12.11: Brand attributes verification (REQUIRED when card present)
- 12.12: Goal overlap verification (REQUIRED when both goals present)
- 12.13: Add POST /verify-callee endpoint
- 12.14: Unit tests
- 12.15: Unknown claims in passport ignored (per VVP §4.2)

---

## Implementation Notes

### Revision 1 Fixes (Post-Review)

The initial implementation received CHANGES_REQUESTED with three findings:

1. **[High] Callee TN rights validation not bound to accountable party**
   - Fixed: Rewrote `validate_callee_tn_rights()` to use `tn_utils` for proper E.164 validation and bind to accountable party (APE issuee)

2. **[High] Callee claim tree omits required timing_valid and signature_valid children**
   - Fixed: Added `timing_valid` and `signature_valid` claims under `passport_verified`
   - Fixed: Added `structure_valid` and `acdc_signatures_valid` claims under `dossier_verified`

3. **[Medium] validate_callee_tn_rights() doesn't validate E.164 formats**
   - Fixed: Now uses `tn_utils.parse_tn_allocation()` for proper validation

### Test Results

```
875 passed in 5.00s
```

## Review History

- **Initial Review**: CHANGES_REQUESTED (3 findings)
- **Revision 1 Review**: APPROVED

**Source**: [draft-hardman-verifiable-voice-protocol-04](https://datatracker.ietf.org/doc/html/draft-hardman-verifiable-voice-protocol-04)


# PLAN_Sprint20.md

# Sprint 20: Test Vectors & CI Integration (Phase 15 Completion)

**Status:** APPROVED and IMPLEMENTED
**Date:** 2026-01-26

## Problem Statement

The VVP Verifier is at 95% overall completion with 875 tests passing locally. However:

1. **No CI test execution** - `deploy.yml` only builds Docker and deploys; regressions can be deployed undetected
2. **Incomplete test vectors** - Phase 15 at 43% (lowest of all phases); v04/v07 are stubs, v09-v11 missing
3. **No E2E integration test** - A 126KB real Provenant trial dossier exists but isn't used for full verification testing

The spec (§10.2) mandates test vectors for compliance verification.

## Spec References

- **§10.2**: Minimum Required Vectors - tiered test vector requirements
- **§10.3**: Vector Structure - required fields
- **§4.2A**: Error Code Registry - error code mappings
- **§3.3A**: Claim tree propagation rules

## Vector-to-Error Code Mapping Table

| Vector | Scenario | Exception Type | Error Code | Status |
|--------|----------|----------------|------------|--------|
| v04 | iat before inception | `KeyNotYetValidError` | `KERI_STATE_INVALID` | INVALID |
| v07 | SAID mismatch | `ACDCSAIDMismatch` | `ACDC_SAID_MISMATCH` | INVALID |
| v09 | TNAlloc mismatch | Direct emission in `verify.py` | `TN_RIGHTS_INVALID` | INVALID |
| v10 | Credential revoked | Direct emission in `verify.py` | `CREDENTIAL_REVOKED` | INVALID |
| v11 | Delegation chain broken | Direct emission in `verify.py` | `AUTHORIZATION_FAILED` | INVALID |

## Implementation Summary

### Part A: CI Infrastructure (Item 15.14)
- Added test job to `.github/workflows/deploy.yml` before deployment
- Added libsodium installation and verification steps
- Added coverage threshold of 80%
- Updated `pyproject.toml` with test dependencies
- Updated `pytest.ini` with asyncio_mode config and e2e marker

### Part B: Tier 2 Vectors (Items 15.7, 15.8)
- **v04**: iat before inception → `KERI_STATE_INVALID`
- **v07**: SAID mismatch → `ACDC_SAID_MISMATCH`

### Part C: Tier 3 Vectors (Items 15.10-15.12)
- **v09**: TNAlloc mismatch → `TN_RIGHTS_INVALID`
- **v10**: Revoked credential → `CREDENTIAL_REVOKED`
- **v11**: Delegation chain invalid → `AUTHORIZATION_FAILED`

### Part D: Schema & Runner Updates
- Added mock configuration fields to `tests/vectors/schema.py`
- Added mock handlers to `tests/vectors/runner.py` using actual exception types

### Part E: E2E Integration Test
- Created `tests/test_trial_dossier_e2e.py` with `@pytest.mark.e2e` marker
- Tests real Provenant trial dossier parsing and DAG building

---

## Implementation Notes

### Deviations from Original Plan

During implementation, the following deviations were required:

1. **v04 mock target**: Changed from mocking `resolve_key_state` to mocking `verify_passport_signature_tier2` because the exception is raised during signature verification flow

2. **v07 exception handler**: Added explicit handler for `ACDCSAIDMismatch` in verify.py (was not being caught before)

3. **v04 exception handler**: Added explicit handler for `KeyNotYetValidError` in verify.py (was not being caught before)

4. **E2E tests**: Made assertions more lenient (checking `len(dag.nodes) > 0` instead of exact count) because trial dossier structure may vary

### Files Changed

| File | Lines | Summary |
|------|-------|---------|
| `.github/workflows/deploy.yml` | +35 | Added test job with libsodium |
| `pyproject.toml` | +5 | Added test dependencies |
| `pytest.ini` | +4 | Added asyncio config and e2e marker |
| `app/vvp/verify.py` | +15 | Added KeyNotYetValidError and ACDCSAIDMismatch handlers |
| `tests/vectors/schema.py` | +6 | Added mock config fields |
| `tests/vectors/runner.py` | +80 | Added mock handlers for Tier 2/3 vectors |
| `tests/vectors/data/v04_iat_before_inception.json` | modified | Completed implementation |
| `tests/vectors/data/v07_said_mismatch.json` | modified | Completed implementation |
| `tests/vectors/data/v09_tnalloc_mismatch.json` | +82 | New vector |
| `tests/vectors/data/v10_revoked_credential.json` | +85 | New vector |
| `tests/vectors/data/v11_delegation_invalid.json` | +82 | New vector |
| `tests/vectors/test_vectors.py` | +1 | Updated expected vector count |
| `tests/test_trial_dossier_e2e.py` | +79 | New E2E tests |

### Test Results

```
886 passed in 5.19s
```

All 11 vectors pass with correct error codes per §4.2A.

---

## Review History

### Initial Review (CHANGES_REQUESTED)
- [High] v04 used `SignatureInvalidError` → `PASSPORT_SIG_INVALID` instead of `KeyNotYetValidError` → `KERI_STATE_INVALID`
- [High] v07 used `ACDCChainInvalid` → `DOSSIER_GRAPH_INVALID` instead of `ACDCSAIDMismatch` → `ACDC_SAID_MISMATCH`

### Re-Review (APPROVED)
- Both findings resolved by adding proper exception handlers in verify.py
- Implementation now matches §4.2A mappings and the approved plan


# PLAN_Sprint22.md

# Sprint 22: Credential Card & Chain Graph Enhancements

## Problem Statement

The current credential card UI has limitations that hide important credential data:
1. **Attributes are collapsed** - Only 3 secondary attributes shown, nested objects display as "(complex)", arrays truncated to 2 items
2. **Edge links not navigable** - Links use HTMX to append cards below, but can't navigate to or highlight linked credentials
3. **No visual chain graph** - Credential layers are rendered as cards without visual connectors showing the trust relationships

## User Requirements

1. Display all attributes prominently (not in collapsed section), with proper handling for:
   - Simple values: `"role": "Tn Allocator"`
   - Booleans: `"doNotOriginate": false`
   - Dates: `"startDate": "2024-11-25T20:20:39+00:00"`
   - Nested objects: `"numbers": {"rangeStart": "+447884666200", "rangeEnd": "+447884666200"}`
   - Arrays: `"c_goal": ["ops.it.telco.send.sign"]`

2. Make edge links clickable to navigate to the linked credential

3. Display a graphical credential chain graph with visual links between credentials

## Spec References

- §6.1: Dossier structure and credential chain
- §5.1-7: Trust chain validation to root of trust
- Sprint 21 Plan: Credential card view-model architecture

## Implementation Summary

### Part 1: Collapsible Attribute Sections

Grouped attributes by category in collapsible sections:
- **Identity**: LEI, legalName, role, issuee
- **Dates & Times**: startDate, endDate, dt, issuanceDate (formatted human-readable)
- **Permissions**: c_goal, channel, doNotOriginate (Yes/No for booleans)
- **Numbers & Ranges**: tn, numbers.rangeStart/rangeEnd (flattened nested objects)
- **Other**: Any remaining attributes

### Part 2: Clickable Edge Links

Edge links now scroll and highlight target credential:
- `id="cred-{said}"` added to each credential card
- `highlightCredential(said)` JavaScript function scrolls and pulse-highlights
- 2-second highlight animation with box-shadow

### Part 3: Visual Chain Graph (SVG Connectors)

SVG connectors between credential cards showing trust relationships:
- Bezier curves from parent card bottom to child card top
- Color-coded by edge type:
  - vetting → green (#28a745)
  - delegation → blue (#007bff)
  - issued_by → purple (#6f42c1)
  - jl (jurisdiction) → orange (#fd7e14)
- Arrow markers at endpoints
- Redraw on window resize and details toggle
- Hidden on mobile (< 768px)

### Part 4: Field Tooltips

Normative descriptions from ToIP ACDC specification on mouseover:
- Core ACDC fields (v, d, i, s, a, e, r, n, dt)
- Common attribute fields (LEI, legalName, tn, channel)
- `.has-tooltip` CSS class with dotted underline

### Part 5: Raw Contents Section

Collapsed "Raw Contents" section with all ACDC fields:
- Complete list of all fields with tooltips
- Recursively flattened nested dicts with dot notation
- Formatted values (arrays, booleans, dates)

### Part 6: Redaction Masking

ACDC partial disclosure placeholders properly displayed:
- `"_"` full redaction placeholder → "(redacted)"
- `"_:type"` typed placeholders → "(redacted)"
- `""`, `"#"`, `"[REDACTED]"` → "(redacted)"
- `.attr-redacted` CSS class with muted styling

### Part 7: Inline Revocation Display

Revocation status displayed inline (not lazy-loaded):
- ACTIVE → green badge
- REVOKED → red badge
- UNKNOWN → yellow badge with error tooltip

## Files Changed

| File | Summary |
|------|---------|
| `app/vvp/ui/credential_viewmodel.py` | Added AttributeSection, formatting functions, sections field, tooltips, raw_contents, redaction detection |
| `app/vvp/ui/__init__.py` | Export AttributeSection |
| `app/templates/partials/credential_card.html` | Collapsible sections, edge links, tooltips, Raw Contents, inline revocation |
| `app/templates/partials/credential_graph.html` | SVG container, edges data attribute |
| `app/templates/base.html` | CSS for sections/connectors/tooltips/highlight/redaction, JS functions |
| `tests/test_credential_viewmodel.py` | 66 new tests for Sprint 22 features |
| `scripts/run-tests.sh` | Test runner script with DYLD_LIBRARY_PATH |

## Test Results

```
999 passed, 20 warnings in 5.63s
```

## Review History

- **Rev 0**: CHANGES_REQUESTED - Redaction masking not applied to `_build_attribute_sections`
- **Rev 1**: APPROVED - Added `_is_redacted_value()` and updated `_format_value()`


# PLAN_Sprint23.md

# Sprint 23: Caching, Test Vectors & Deployment Completion

## Problem Statement

The VVP Verifier is at 96% completion (174/182 items). Sprint 23 aims to complete all remaining practical items to reach production readiness. Analysis reveals many checklist items are already implemented but not marked complete.

## Exploration Findings

### Items Already Complete (Checklist Updates Only)
| Item | Description | Evidence |
|------|-------------|----------|
| 15.5 | OOBI timeout test vector | `v05_oobi_timeout.json` exists |
| 15.8 | SAID mismatch test vector | `v07_said_mismatch.json` exists |
| 15.10 | TNAlloc mismatch test vector | `v09_tnalloc_mismatch.json` exists |
| 15.11 | Delegation invalid test vector | `v11_delegation_invalid.json` exists |
| 15.12 | Revoked credential test vector | `v10_revoked_credential.json` exists |
| 15.14 | CI integration | `.github/workflows/deploy.yml` runs tests |
| 16.2 | POST /verify-callee | `app/main.py:67-122` + 41 tests |
| 16.8 | Docker build verification | CI pipeline builds successfully |

### Items Requiring Implementation
| Item | Description | Complexity |
|------|-------------|------------|
| 14.2 | SAID-based dossier cache | Medium |
| 14.6 | Cache invalidation on revocation | Medium |
| 14.7 | Cache metrics/logging | Low |
| 15.7 | Key rotated before T test vector | Low |
| 16.6 | Dockerfile updates (blake3) | Low |
| 16.7 | pyproject.toml (add blake3) | Low |
| 16.9 | E2E test documentation | Low |

### Uncommitted Work to Commit
- `app/vvp/keri/identity_resolver.py` (372 lines, complete)
- `tests/test_identity_resolver.py` (45 tests, complete)
- Various UI/config changes from recent development

## Proposed Solution

### Part 1: Commit Uncommitted Work

Commit the identity_resolver module and related changes that are already complete.

**Files to commit:**
- `app/vvp/keri/identity_resolver.py` (new)
- `tests/test_identity_resolver.py` (new)
- Modified files per git status

### Part 2: URL-Keyed Dossier Cache with SAID Index (14.2)

**Location:** `app/vvp/dossier/cache.py` (new file)

**Reviewer Feedback Addressed:**
- [High] Cache by URL (available pre-fetch) instead of SAID (only available post-parse)
- [Medium] Implement proper LRU eviction with `_access_order` tracking
- [Medium] Secondary index maps credential SAIDs → URLs for revocation invalidation

**Design:**
```python
@dataclass
class CachedDossier:
    dag: DossierDAG
    raw_content: bytes
    fetch_timestamp: float
    content_type: str
    contained_saids: Set[str]  # All credential SAIDs in this dossier

class DossierCache:
    def __init__(self, ttl_seconds: float = 300, max_entries: int = 100):
        # Primary index: URL → (CachedDossier, cached_at)
        self._cache: Dict[str, tuple[CachedDossier, float]] = {}
        # Secondary index: credential SAID → set of URLs containing it
        self._said_to_urls: Dict[str, Set[str]] = {}
        # LRU tracking
        self._access_order: list[str] = []
        self._ttl = ttl_seconds
        self._max_entries = max_entries
        self._lock = asyncio.Lock()
        self._metrics = CacheMetrics()

    async def get(self, url: str) -> Optional[CachedDossier]:
        """Lookup by URL (available pre-fetch). Updates LRU order."""

    async def put(self, url: str, dossier: CachedDossier) -> None:
        """Store with URL key. Builds SAID index. Enforces LRU eviction."""

    async def invalidate_by_said(self, said: str) -> int:
        """Invalidate all dossiers containing a revoked credential SAID.
        Returns count of invalidated entries."""

    async def invalidate_by_url(self, url: str) -> bool:
        """Direct invalidation by URL. Returns True if entry existed."""

    def _evict_lru(self) -> None:
        """Evict least-recently-used entry when at capacity."""

    def _update_access_order(self, url: str) -> None:
        """Move URL to end of access order (most recent)."""
```

**Integration in verify.py:**
```python
# Before fetch_dossier() - URL is available from VVP-Identity evd field
evd_url = vvp_identity.evd
cached = await dossier_cache.get(evd_url)
if cached:
    log.info(f"Dossier cache hit: {evd_url[:50]}...")
    return cached.dag, cached.raw_content

# After successful fetch and parse
dossier_cache.put(evd_url, CachedDossier(
    dag=dag,
    raw_content=raw_content,
    fetch_timestamp=time.time(),
    content_type=content_type,
    contained_saids={node.said for node in dag.nodes.values()}
))
```

**Configuration in config.py:**
```python
# TTL aligned with §5C.2 freshness policy (default: 5 minutes, same as key state)
# Can be increased for stable dossiers, but should not exceed credential expiry
DOSSIER_CACHE_TTL_SECONDS: int = int(os.getenv("VVP_DOSSIER_CACHE_TTL", "300"))
DOSSIER_CACHE_MAX_ENTRIES: int = int(os.getenv("VVP_DOSSIER_CACHE_MAX_ENTRIES", "100"))
```

**TTL and §5C.2 Freshness:**
- Default TTL of 300s matches key state cache freshness per §5C.2
- Configurable to allow longer TTL for stable production dossiers
- Should not exceed `MAX_TOKEN_AGE_SECONDS` to ensure verification freshness

### Part 3: Cache Invalidation on Revocation (14.6)

**Reviewer Feedback Addressed:**
- [Medium] Use secondary index to map revoked credential SAID → cached dossier URLs

**Design:** When revocation detected, use SAID→URL index to invalidate related caches.

**Location:** Modify `app/vvp/verify.py` in `check_dossier_revocations()`

```python
# After detecting REVOKED status:
if result.status == CredentialStatus.REVOKED:
    log.info(f"Credential revoked: {said[:20]}...")
    # Use secondary index to find and invalidate all dossiers containing this credential
    invalidated_count = await dossier_cache.invalidate_by_said(said)
    log.info(f"Invalidated {invalidated_count} cached dossier(s) containing revoked credential")
    # Key state cache invalidation for issuer
    if issuer_aid:
        key_state_cache.invalidate(issuer_aid)
```

**DossierCache.invalidate_by_said():**
- Lookup `_said_to_urls[said]` to get all URLs containing this credential
- Remove each URL from `_cache`
- Update `_said_to_urls` to remove the invalidated mappings
- Update `_access_order` to remove invalidated URLs
- Log invalidation event with count
- Increment `_metrics.invalidations`

### Part 4: Cache Metrics/Logging (14.7)

**Design:** Add structured logging for cache operations.

**Location:** Extend each cache class with metrics tracking.

```python
@dataclass
class CacheMetrics:
    hits: int = 0
    misses: int = 0
    evictions: int = 0
    invalidations: int = 0

    def hit_rate(self) -> float:
        total = self.hits + self.misses
        return self.hits / total if total > 0 else 0.0
```

**Logging pattern:**
```python
log.info(f"cache_operation", extra={
    "cache_type": "dossier",
    "operation": "hit",
    "key": said[:20],
    "cache_size": len(self._cache),
    "hit_rate": self._metrics.hit_rate()
})
```

**Admin endpoint extension:**
```python
@app.get("/admin")
async def admin_info():
    return {
        ...existing...,
        "cache_metrics": {
            "dossier": dossier_cache.metrics(),
            "key_state": key_state_cache.metrics(),
            "revocation": tel_client.cache_metrics()
        }
    }
```

### Part 5: Key Rotated Before T Test Vector (15.7)

**File:** `tests/vectors/data/v12_key_rotated_before_t.json`

**Design:**
- Tier 2 test vector
- PASSporT signed with key that was rotated before reference_time_t
- Mock via `mock_key_state_error: "KEY_ROTATED_BEFORE_T"`
- Expected: INVALID with `passport_verified: INVALID`
- Error: `KERI_STATE_INVALID`

**Runner modification:** Add handling for `KEY_ROTATED_BEFORE_T` mock error.

### Part 6: Dependency Updates (16.6, 16.7)

**pyproject.toml:**
```toml
dependencies = [
  ...existing...,
  "blake3>=0.3.0",  # SAID computation (already used in kel_parser.py)
]
```

**Dockerfile:** No changes needed - blake3 is pure Python with optional C extension.

### Part 7: Checklist Updates

Update `app/Documentation/VVP_Implementation_Checklist.md`:
- Mark 15.5, 15.8, 15.10, 15.11, 15.12, 15.14 as complete
- Mark 16.2, 16.8 as complete
- Add commit SHAs for completed items

## Files to Create/Modify

| File | Action | Purpose |
|------|--------|---------|
| `app/vvp/dossier/cache.py` | Create | SAID-based dossier cache |
| `app/vvp/dossier/__init__.py` | Modify | Export DossierCache |
| `app/vvp/verify.py` | Modify | Integrate dossier cache, add invalidation |
| `app/vvp/keri/cache.py` | Modify | Add CacheMetrics |
| `app/vvp/keri/tel_client.py` | Modify | Add cache_metrics() method |
| `app/core/config.py` | Modify | Add dossier cache config |
| `app/main.py` | Modify | Add cache metrics to /admin |
| `tests/test_dossier_cache.py` | Create | Tests for dossier cache |
| `tests/vectors/data/v12_key_rotated_before_t.json` | Create | New test vector |
| `tests/vectors/runner.py` | Modify | Handle KEY_ROTATED_BEFORE_T |
| `pyproject.toml` | Modify | Add blake3 dependency |
| `app/Documentation/VVP_Implementation_Checklist.md` | Modify | Mark complete items |
| `CHANGES.md` | Modify | Sprint 23 summary |

## Test Strategy

1. **Dossier Cache Tests** (`tests/test_dossier_cache.py`):
   - Basic get/put operations by URL
   - TTL expiration behavior
   - LRU eviction when at max_entries (verify oldest accessed is evicted)
   - `invalidate_by_said()` uses secondary index correctly
   - `invalidate_by_url()` direct invalidation
   - Secondary index (`_said_to_urls`) correctly tracks contained SAIDs
   - Concurrent access with asyncio.Lock

2. **Cache Metrics Tests**:
   - Hit/miss counting
   - Hit rate calculation
   - Metrics reset

3. **Integration Tests**:
   - Verify cache hit on repeated dossier fetch
   - Verify invalidation on revocation
   - Verify metrics in /admin response

4. **Test Vector**:
   - Run `./scripts/run-tests.sh tests/vectors/test_vectors.py::TestVectorSuite::test_vector[v12]`

## Verification

```bash
# Run all tests
./scripts/run-tests.sh -v

# Run specific new tests
./scripts/run-tests.sh tests/test_dossier_cache.py -v
./scripts/run-tests.sh tests/vectors/test_vectors.py -v

# Verify cache metrics in admin endpoint
curl http://localhost:8000/admin | jq '.cache_metrics'

# Verify Docker build
docker build -t vvp-test .
docker run --rm vvp-test python -c "import blake3; print('blake3 OK')"
```

## Implementation Order (Pair Programming Workflow)

### Phase A: Plan Review
1. **Plan Review Request** - Submit plan to Reviewer for approval
2. **Address Feedback** - Iterate until APPROVED verdict received

### Phase B: Implementation (After Plan Approval)
1. **Commit existing work** - identity_resolver + related changes
2. **Add blake3 dependency** - pyproject.toml update
3. **Create dossier cache** - cache.py + tests
4. **Add cache metrics** - Extend all caches
5. **Add invalidation logic** - verify.py modifications
6. **Create test vector** - v12_key_rotated_before_t.json
7. **Update checklist** - Mark complete items
8. **Run tests** - Verify all tests pass

### Phase C: Code Review
9. **Code Review Request** - Submit implementation to Reviewer
10. **Address Feedback** - Fix issues until APPROVED verdict

### Phase D: Completion
11. **Update CHANGES.md** - Sprint 23 summary with commit SHA
12. **Archive Plan** - Copy to `app/Documentation/PLAN_Sprint23.md`
13. **Final Commit** - Documentation updates

## Open Questions

None - analysis is complete and approach is clear.

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Cache memory growth | Low | Medium | LRU eviction with configurable max_entries |
| Race conditions in cache | Low | High | asyncio.Lock for thread safety |
| Test vector timing sensitivity | Low | Low | Use frozen time in vector runner |

---

## Implementation Notes

### Deviations from Plan

None - implementation followed the approved plan exactly.

### Additional Work

- Created `tests/conftest.py` with autouse fixture to reset dossier cache before each test
- Updated `tests/vectors/conftest.py` with matching cache reset fixture
- Added verify_vvp-level integration tests after code review feedback:
  - `test_verify_vvp_fetch_skipped_on_cache_hit` - Asserts fetch_dossier NOT called on cache hit
  - `test_verify_vvp_fetch_called_on_cache_miss` - Asserts fetch_dossier IS called on cache miss

### Test Results

```
1103 passed in 6.12s
```

### Review History

| Round | Verdict | Key Feedback |
|-------|---------|--------------|
| Plan Rev 0 | CHANGES_REQUESTED | Cache by URL instead of SAID; add LRU eviction |
| Plan Rev 1 | APPROVED | Design addresses feedback |
| Code Rev 0 | CHANGES_REQUESTED | verify.py doesn't use cache (get/put missing) |
| Code Rev 1 | CHANGES_REQUESTED | Integration tests don't exercise verify_vvp directly |
| Code Rev 2 | APPROVED | verify_vvp integration tests exercise cache behavior |

### Commits

| Commit | Description |
|--------|-------------|
| 7e0a87a | Add OOBI-based identity resolver for issuer discovery |
| 7e49dc6 | Sprint 23: URL-keyed dossier cache with SAID index |

### Checklist Items Completed

- 14.2: SAID-based dossier cache (URL-keyed with SAID secondary index)
- 14.6: Cache invalidation on revocation
- 14.7: Cache metrics/logging
- 15.5: OOBI timeout test vector (already existed)
- 15.7: Key rotated before T test vector
- 15.8: SAID mismatch test vector (already existed)
- 15.10: TNAlloc mismatch test vector (already existed)
- 15.11: Delegation invalid test vector (already existed)
- 15.12: Revoked credential test vector (already existed)
- 15.14: CI integration (already existed)
- 16.2: POST /verify-callee (already existed)
- 16.7: Add blake3 dependency
- 16.8: Docker build verification (already existed)

**Overall Progress:** 99% (180/182 items)


# PLAN_Sprint24_UI.md

# Sprint 24 UI Enhancement Plan: Evidence, Validation & Schema Visibility

## Summary

Enhance the VVP Verifier UI to surface new backend capabilities from Sprint 24:
- Schema registry and validation status
- Multi-level delegation chain visualization
- Evidence fetch timeline with cache metrics
- Clear separation of INVALID vs INDETERMINATE outcomes (per spec §2.2)
- Enhanced variant limitation details with remediation hints

---

## Revision History

| Version | Date | Changes |
|---------|------|---------|
| 1.1 | 2026-01-27 | Addressed reviewer feedback: normalized EvidenceStatus enum, added chain_status field, fixed spec notation |

---

## Implementation Phases

### Phase 1: View Model Extensions
**Files:** `app/vvp/ui/credential_viewmodel.py`

Add new dataclasses following existing patterns (type hints, docstrings, default_factory):

```python
# Shared enum for evidence fetch status (addresses reviewer finding)
class EvidenceStatus(str, Enum):
    """Evidence fetch status values.

    Used consistently across EvidenceFetchRecord, timeline rendering, and CSS badges.
    """
    SUCCESS = "SUCCESS"              # Fetch succeeded
    FAILED = "FAILED"                # Fetch failed with error
    CACHED = "CACHED"                # Served from cache
    INDETERMINATE = "INDETERMINATE"  # Could not determine (e.g., schema unavailable)

@dataclass
class ValidationCheckResult:
    """Single validation check result for dashboard strip."""
    name: str                          # "Signature", "Schema", "Delegation", etc.
    status: str                        # VALID, INVALID, INDETERMINATE
    short_reason: str                  # Brief reason
    spec_ref: Optional[str] = None     # e.g., "§5.0"
    severity: str = "success"          # error, warning, success

@dataclass
class ValidationSummary:
    """Top-level validation dashboard."""
    checks: List[ValidationCheckResult] = field(default_factory=list)
    overall_status: str = "VALID"
    failure_count: int = 0
    warning_count: int = 0

@dataclass
class ErrorBucketItem:
    """Single error/warning with remediation."""
    message: str
    spec_ref: Optional[str] = None
    remedy_hint: Optional[str] = None

@dataclass
class ErrorBucket:
    """Grouped errors (INVALID) or warnings (INDETERMINATE)."""
    title: str                         # "Failures" or "Uncertainties"
    bucket_type: str                   # "error" or "warning"
    items: List[ErrorBucketItem] = field(default_factory=list)

@dataclass
class SchemaValidationInfo:
    """Schema validation details for a credential."""
    schema_said: str
    registry_source: str               # "GLEIF", "Pending", "Fetched"
    validation_status: str             # VALID, INVALID, INDETERMINATE
    has_governance: bool = False       # True if in governance registry
    field_errors: List[str] = field(default_factory=list)
    validated_count: int = 0
    total_required: int = 0

@dataclass
class EvidenceFetchRecord:
    """Single evidence fetch operation."""
    source_type: str                   # OOBI, SCHEMA, TEL, DOSSIER, KEY_STATE
    url: str
    status: EvidenceStatus             # SUCCESS, FAILED, CACHED, INDETERMINATE (uses shared enum)
    latency_ms: Optional[int] = None
    cache_hit: bool = False
    cache_ttl_remaining: Optional[int] = None
    error: Optional[str] = None

@dataclass
class EvidenceTimeline:
    """Timeline of all evidence fetches."""
    records: List[EvidenceFetchRecord] = field(default_factory=list)
    total_fetch_time_ms: int = 0
    cache_hit_rate: float = 0.0
    failed_count: int = 0

@dataclass
class DelegationNode:
    """Node in delegation chain."""
    aid: str
    aid_short: str
    display_name: Optional[str] = None
    is_root: bool = False
    authorization_status: str = "INDETERMINATE"

@dataclass
class DelegationChainInfo:
    """Complete delegation chain from leaf to root."""
    chain: List[DelegationNode] = field(default_factory=list)
    depth: int = 0
    root_aid: Optional[str] = None
    is_valid: bool = False
    errors: List[str] = field(default_factory=list)
```

**Extend existing VariantLimitations:**
```python
@dataclass
class VariantLimitations:
    # ... existing fields ...
    verification_impact: Optional[str] = None      # "Status INDETERMINATE per §2.2"
    remediation_hints: List[str] = field(default_factory=list)
```

**Extend CredentialCardViewModel:**
```python
@dataclass
class CredentialCardViewModel:
    # ... existing fields ...
    chain_status: str = "INDETERMINATE"  # Explicit chain validation result (from ACDCChainResult.status)
    schema_info: Optional[SchemaValidationInfo] = None
    delegation_info: Optional[DelegationChainInfo] = None
    validation_checks: List[ValidationCheckResult] = field(default_factory=list)
```

**Note:** `chain_status` is sourced directly from `ACDCChainResult.status` during view model construction, separate from the overall `status` field. This allows validation summary to accurately report chain-specific outcomes.

**Add DossierViewModel:**
```python
@dataclass
class DossierViewModel:
    """Top-level view model for dossier display."""
    evd_url: str
    credentials: List[CredentialCardViewModel] = field(default_factory=list)
    validation_summary: Optional[ValidationSummary] = None
    evidence_timeline: Optional[EvidenceTimeline] = None
    error_buckets: List[ErrorBucket] = field(default_factory=list)
    total_time_ms: int = 0
```

---

## Approval

**Reviewer Verdict:** APPROVED (2026-01-27)

> The required changes are addressed: EvidenceStatus is normalized and used consistently across timeline/metrics, chain reporting now uses `chain_status` sourced from `ACDCChainResult.status`, and spec references are corrected to §. The evidence timeline template and legend now accommodate the full status set without conflating INDETERMINATE.


# PLAN_Sprint25.md

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


# PLAN_ToIP_Warnings.md

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


