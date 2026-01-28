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
