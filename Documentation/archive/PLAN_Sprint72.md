# Sprint 72: Issuer UI Simplification — Dossier Creation UX

## Problem Statement

Creating a complete VVP dossier requires 10 steps across 5 pages, deep KERI knowledge, and navigating 949+ credentials with no pagination. The UI exposes every schema field, KERI-internal options (publish to witnesses, transferable), and jargon labels (AID, SAID, I2I, GCD). A user who understands VVP but not KERI internals cannot create a dossier without confusion.

Full audit: `DOSSIER_SIMPLIFICATION_AUDIT.md`

## Spec References

- VVP Multichannel Vetters: Vetter certification, extended schemas, jurisdictional constraints
- ACDC spec: Cooperative delegation (GCD), edge operators (I2I, NI2I)
- ITU-T E.164: Country codes for ECC targets
- ISO 3166-1: Alpha-3 country codes for jurisdictions and brand assertion

## Current State

- 21 HTML pages, all using vanilla JS + `shared.js` utilities
- Schema-driven form generator (`SchemaFormGenerator` class in credentials.html)
- 4-step dossier wizard with edge slot picker
- Vetter cert page with 70+ checkbox grids
- No pagination on any credential list
- Every form has "Publish to witnesses" checkbox
- GCD form shows 14 optional constraint fields

## Proposed Solution

### Approach

Iterative UI refinement in 4 phases (A→B→C→D), each independently deployable. Phases A, B are client-side only (HTML/JS/CSS). Phase C requires a minor API change to add server-side pagination to `GET /credential`. Phase D is a manual walkthrough to validate the end-to-end experience.

### Alternatives Considered

| Alternative | Pros | Cons | Why Rejected |
|-------------|------|------|--------------|
| Full React rewrite | Modern tooling, component reuse | Massive effort, new build system, blocks all other work | Disproportionate to the problem |
| Guided wizard spanning all pages | Best UX, single flow | Would require session state across pages, complex routing | Could be a future sprint once individual pages are clean |
| API-side simplification (fewer fields) | Cleaner data model | Schema fields are spec-driven, can't remove | Would break compliance |

### Detailed Design

---

#### Phase A: Quick Wins

All changes are surgical edits to existing HTML files. No new files, no API changes.

##### A1: Remove "Publish to witnesses" checkbox

**Files**: `create.html`, `credentials.html`, `vetter.html`

Remove the checkbox HTML and always send `publish_to_witnesses: true` (or `publish: true`) in the POST body. Delete the associated `const publishCheck` references.

**create.html** — Remove lines 49-52 (checkbox row), hardcode `publish_to_witnesses: true` in the fetch body.

**credentials.html** — Remove checkbox at line 389-392, remove `publishCheck` const, hardcode in submit handler.

**vetter.html** — Remove checkbox at lines 198-201, hardcode in submit handler.

##### A2: Replace `assertionCountry` with country dropdown

**File**: `credentials.html` → `SchemaFormGenerator.renderSimpleField()`

When the field key is `assertionCountry` (or schema description mentions "ISO 3166-1 alpha-3"), render a `<select>` with country options instead of a text input. Use the same `ISO_CODES` array already defined in `vetter.html` — extract it to `shared.js` as a shared constant.

```javascript
// In SchemaFormGenerator.renderSimpleField():
if (key === 'assertionCountry') {
  input = document.createElement('select');
  input.innerHTML = '<option value="">Select country...</option>' +
    ISO_3166_CODES.map(c => `<option value="${c.code}">${c.name} (${c.code})</option>`).join('');
}
```

##### A3: Replace `channel` with dropdown

**File**: `credentials.html` → `SchemaFormGenerator.renderSimpleField()`

When the field key is `channel`, render a dropdown with known values:

```javascript
if (key === 'channel') {
  input = document.createElement('select');
  input.innerHTML = '<option value="">Select channel...</option>' +
    ['voice', 'sms', 'video'].map(c => `<option value="${c}">${c}</option>`).join('');
}
```

##### A4: Hide GCD constraint fields under collapsible section

**File**: `credentials.html` → `SchemaFormGenerator.renderFields()`

Detect fields starting with `c_` or named `gfw` and group them into a collapsible "Advanced Constraints" `<details>` element:

```javascript
static renderFields(schema, container, pathPrefix) {
  const required = schema.required || [];
  const advancedKeys = [];
  const normalKeys = [];

  for (const [key, prop] of Object.entries(schema.properties || {})) {
    if (SYSTEM_FIELDS.includes(key)) continue;
    if (key.startsWith('c_') || key === 'gfw') {
      advancedKeys.push([key, prop]);
    } else {
      normalKeys.push([key, prop]);
    }
  }

  // Render normal fields
  for (const [key, prop] of normalKeys) { ... }

  // Render advanced fields in collapsible section
  if (advancedKeys.length > 0) {
    const details = document.createElement('details');
    details.className = 'advanced-section';
    const summary = document.createElement('summary');
    summary.textContent = `Advanced Constraints (${advancedKeys.length} fields)`;
    details.appendChild(summary);
    for (const [key, prop] of advancedKeys) { ... render into details ... }
    container.appendChild(details);
  }
}
```

##### A5: Hide auto-injected `certification` edge

**File**: `credentials.html` → `renderSchemaEdgeSlots()`

Skip edge slots named `certification` when rendering (the backend auto-injects it):

```javascript
function renderSchemaEdgeSlots(edgeSlots) {
  // Filter out auto-injected edges
  const visibleSlots = edgeSlots.filter(s => s.name !== 'certification');
  ...
}
```

##### A6: Hide "Additional Edges (manual)" under Advanced toggle

**File**: `credentials.html`

Wrap the manual edges section (`#manualEdgesGroup`) in a `<details>` element:

```html
<details class="advanced-section">
  <summary>Additional Edges (Advanced)</summary>
  <div id="manualEdgesGroup">...</div>
</details>
```

##### A7: Rename "Transferable" and update placeholder

**File**: `create.html`

- Change label from "Transferable (keys can rotate)" to "Allow key rotation"
- Add hint text: "Recommended. Allows rotating keys without changing the identity."
- Change placeholder from "e.g., my-issuer" to "e.g., acme-signing-key"

##### A8: Add CSS for collapsible advanced sections

**File**: `styles.css` (shared)

```css
.advanced-section {
  margin-top: 1rem;
  border: 1px solid var(--vvp-border);
  border-radius: 4px;
}
.advanced-section summary {
  padding: 0.6rem 0.75rem;
  cursor: pointer;
  font-size: 0.9rem;
  color: var(--vvp-text-muted);
  background: #fafafa;
}
.advanced-section[open] summary {
  border-bottom: 1px solid var(--vvp-border);
}
.advanced-section > :not(summary) {
  padding: 0 0.75rem 0.75rem;
}
```

---

#### Phase B: Smart Defaults & Pickers

##### B1: Identity picker for GCD delegate and recipient

**File**: `credentials.html`

When the selected schema is GCD (`EL7irIKYJL9Io0hhKSGWI4OznhwC7qgJG5Qf4aEs6j0o`), replace the generic "Recipient AID" text input with an identity picker dropdown populated from `GET /identity`:

```javascript
async function loadIdentityPicker() {
  const res = await authFetch('/identity');
  if (!res.ok) return;
  const data = await res.json();
  // Build dropdown options from identities
  // Filter out system identities (mock-gleif, mock-qvi, mock-gsma)
}
```

Also rename the `i` field label from "I" to "Delegate Identity" in the dynamic form when schema is GCD.

**Scalability note**: The system currently has 69 identities — well within dropdown limits. Filter out system identities (mock-gleif, mock-qvi, mock-gsma) by name prefix to keep the list manageable. If identity count exceeds ~200 in future, convert to a type-ahead search component (same pattern as `SearchableMultiSelect`).

##### B2: Auto-populate issuer edge with org's LE credential

**File**: `credentials.html`

After schema selection, if the schema has an `issuer` edge with I2I operator, auto-fetch the current org's LE credential SAID from `GET /organizations/{org_id}` and pre-select it:

```javascript
async function autoPopulateIssuerEdge() {
  const orgId = currentSession.organizationId || currentSession.activeOrgId;
  if (!orgId) return;
  const res = await authFetch(`/organizations/${orgId}`);
  if (!res.ok) return;
  const org = await res.json();
  if (org.le_credential_said) {
    schemaEdgeSelections.set('issuer', org.le_credential_said);
    // Update UI to show auto-selected
  }
}
```

##### B3: Context-aware field labels

**File**: `credentials.html` → `SchemaFormGenerator`

Map schema SAID to context-aware labels for the `i` field and recipient:

```javascript
const SCHEMA_FIELD_LABELS = {
  'EL7irIKYJL9Io0hhKSGWI4OznhwC7qgJG5Qf4aEs6j0o': { // GCD
    'i': 'Delegate Identity',
    'recipient': 'Delegate Identity',
  },
  'EK7kPhs5YkPsq9mZgUfPYfU-zq5iSlU8XVYJWqrVPk6g': { // Extended Brand
    'i': 'Brand Owner',
    'recipient': 'Brand Owner Organization',
  },
  'EFvnoHDY7I-kaBBeKlbDbkjG4BaI0nKLGadxBdjMGgSQ': { // TNAlloc
    'i': 'Allocated Organization',
    'recipient': 'Allocated Organization',
  },
};
```

##### B4: Searchable country multi-select for VetterCert

**File**: `vetter.html`

Replace the 70-checkbox grid with a searchable type-ahead input:

```javascript
class SearchableMultiSelect {
  constructor(container, options, { onChange, prefix = '' }) {
    this.selected = new Set();
    // Render: search input + scrollable filtered list + selected chips
  }
  filter(query) { /* filter options by name or code */ }
  toggle(code) { /* add/remove from selected set */ }
  getSelected() { return [...this.selected]; }
}
```

Render common countries first (US, UK, DE, FR, AU, CA) then alphabetical.

Also remove the "Vetter Organization Name" field — auto-derive from selected org.

##### B5: Org creation LEI hint

**File**: `organizations.html`

Add hint text below the Pseudo LEI field:

```html
<p class="hint">20-character Legal Entity Identifier. Leave blank to auto-generate a pseudo-LEI for testing.</p>
```

Backend already generates pseudo-LEIs, so this is just a label clarification.

---

#### Phase C: Credential List & Dossier Wizard UX

##### C1: Server-side credential list pagination and type filter

**Files**: `credentials.html`, `services/issuer/app/api/credential.py`

The existing `GET /credential` endpoint returns ALL credentials (949+), which is unsustainable. Add server-side pagination and filtering.

**API change** — `services/issuer/app/api/credential.py`:

Add `limit` (default 50, max 200) and `offset` (default 0) query parameters to `GET /credential`. The endpoint already supports `schema_said` and `org_id` filters. Return a `total` count in the response alongside the paginated `credentials` array:

```python
@router.get("/credential")
async def list_credentials(
    schema_said: str | None = None,
    org_id: str | None = None,
    status: str | None = None,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    ...
):
    # Existing filtering logic...
    total = len(all_credentials)
    paginated = all_credentials[offset:offset + limit]
    return {"credentials": paginated, "total": total, "limit": limit, "offset": offset}
```

**Client change** — `credentials.html`:

Replace the single `loadCredentials()` call with paginated fetching:

```javascript
const CREDS_PER_PAGE = 50;
let credPage = 1;
let credFilter = ''; // schema SAID filter
let credTotal = 0;

async function loadCredentials(page = 1, schemaFilter = '') {
  const params = new URLSearchParams({
    limit: CREDS_PER_PAGE,
    offset: (page - 1) * CREDS_PER_PAGE,
  });
  if (schemaFilter) params.set('schema_said', schemaFilter);
  // ... fetch and render with pagination controls
}
```

**Dossier wizard** — `dossier.html`:

Apply the same server-side pagination when loading edge candidates. The dossier wizard's `loadEdgeCredentials()` already passes `schema_said` filter — add `limit=50` to prevent loading hundreds of candidates per slot.
```

##### C2: Dossier wizard edge label rename

**File**: `dossier.html`

Update `EDGE_SLOTS` labels:

```javascript
const EDGE_SLOTS = [
  { name: 'vetting',  label: 'Organisation Verification',      desc: 'Legal Entity credential verifying the AP', ... },
  { name: 'alloc',    label: 'Service Provider Authorisation',  desc: 'Delegation credential authorising the AP to allocate telephone numbers', ... },
  { name: 'tnalloc',  label: 'Phone Number Allocation',         desc: 'Telephone number allocation credential', ... },
  { name: 'delsig',   label: 'Signing Authorisation',           desc: 'Delegation from AP to signing identity', ... },
  { name: 'bownr',    label: 'Brand Ownership',                 desc: 'Brand ownership credential (optional)', ... },
  { name: 'bproxy',   label: 'Brand Proxy',                     desc: 'Brand proxy delegation (optional)', ... },
];
```

##### C3: Auto-select single-candidate edges

**File**: `dossier.html` → `renderEdgeCredentialPicker()`

When a slot has exactly one valid credential candidate, auto-select it:

```javascript
if (filteredCreds.length === 1 && !edgeSelections[slot.name]) {
  selectEdgeCredential(slot.name, filteredCreds[0].said);
}
```

##### C4: Credential attribute preview in dossier edge picker

**File**: `dossier.html` → `renderEdgeCredentialPicker()`

Extend the table to show a brief attribute summary column (brand name, phone numbers, LEI, etc.) — reuse the `getCredPreview()` pattern from `credentials.html`.

##### C5: TN mapping auto-fill from dossier context

**File**: `tn-mappings.html`

Accept query params `?dossier=<SAID>` and pre-select the dossier dropdown. Fetch the dossier's brand credential to auto-fill brand name and logo URL.

---

#### Phase D: Walkthrough Validation

After all UI changes are deployed, perform a full end-to-end dossier creation walkthrough:

1. **As mock-gsma**: Issue VetterCert for Brand Assure (UK + US ECC, GBR + USA jurisdiction)
2. **As mock-gsma**: Issue VetterCert for Deutsche Vetters (DE + UK ECC, DEU + GBR jurisdiction)
3. **As Brand Assure**: Issue Extended Brand credential for ACME Inc
4. **As Deutsche Vetters**: Issue Extended TNAlloc credential for ACME Inc
5. **As ACME Inc**: Create signing identity
6. **As ACME Inc**: Issue GCD (delsig) delegating to signing identity
7. **As ACME Inc**: Issue GCD (alloc) for service provider authorisation
8. **As ACME Inc**: Create dossier via wizard (select all edges)
9. **As ACME Inc**: Create TN mapping
10. **Verify**: Download dossier, confirm it contains all credentials

Document any remaining friction points for future sprints.

## Files to Create/Modify

| File | Action | Purpose |
|------|--------|---------|
| `services/issuer/web/styles.css` | Modify | Add `.advanced-section`, `.searchable-select` styles |
| `services/issuer/web/create.html` | Modify | Remove publish checkbox, rename transferable, update placeholder |
| `services/issuer/web/credentials.html` | Modify | Country/channel dropdowns, hide advanced, identity picker, auto-edges, pagination |
| `services/issuer/web/vetter.html` | Modify | Searchable country selectors, remove publish checkbox + vetter name |
| `services/issuer/web/dossier.html` | Modify | Rename edge labels, auto-select, attribute preview |
| `services/issuer/web/tn-mappings.html` | Modify | Pre-select dossier, auto-fill brand |
| `services/issuer/web/organizations.html` | Modify | LEI hint text |
| `services/issuer/static/shared.js` | Modify | Add shared constants (ISO_3166_CODES, E164_CODES) and reusable SearchableMultiSelect component |
| `services/issuer/app/api/credential.py` | Modify | Add `limit`/`offset` query params for server-side pagination |
| `services/issuer/tests/test_credential_pagination.py` | Create | Tests for pagination params, edge cases, filter+pagination |

## Test Strategy

This sprint is primarily UI changes (HTML/JS/CSS) with one API modification (server-side pagination in Phase C1).

**Backend tests:**
- Add tests for `GET /credential` pagination params (`limit`, `offset`) and response shape (`total`, `limit`, `offset` fields)
- Add tests for edge cases: `offset` beyond total, `limit=0`, `schema_said` filter combined with pagination
- Run full issuer test suite to confirm no regressions (859+ tests)

**UI validation:**
- Manual walkthrough of all 10 dossier creation steps (Phase D)
- The project does not have a Playwright/Cypress setup. Adding a full E2E browser test framework is out of scope for this sprint. The risk is mitigated by: (a) changes are isolated to individual HTML files with no shared state, (b) the Phase D walkthrough exercises every changed page, (c) the backend API tests cover the pagination contract. A future sprint could add browser automation if regression risk increases.

## Open Questions

None — the audit document covers all findings and the recommendations are concrete.

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Breaking existing credential issuance | Low | High | Only change to API is additive (new optional query params). All existing tests pass. |
| Shared constant extraction breaks vetter.html | Low | Medium | Extract to shared.js first, verify vetter page still works before changing credentials page |
| Identity picker shows too many identities | Medium | Low | Filter out system identities by name prefix. Current count (69) is fine for dropdown. Convert to type-ahead if >200 in future. |
| Pagination breaks edge selection state | Low | Medium | Maintain selection state independently of page rendering |
| Auto-populate edge silently fails | Low | Low | Log `console.warn` on API failure; user can still manually select edge |

## Revision History

| Round | Date | Changes |
|-------|------|---------|
| R1 | 2026-02-18 | Initial draft based on DOSSIER_SIMPLIFICATION_AUDIT.md |
| R2 | 2026-02-18 | Per Gemini R2 review: C1 changed from client-side to server-side pagination (API change to GET /credential with limit/offset params). Test strategy updated with backend pagination tests and justification for manual-only UI testing. SearchableMultiSelect explicitly noted as reusable shared component. |
| R3 | 2026-02-18 | Per Gemini R3 review: Added identity picker scalability note (69 identities OK for dropdown, type-ahead threshold at 200). Added console.warn for auto-populate edge failures. |
