# Sprint 63: Dossier Creation Wizard UI

## Problem Statement

The current dossier page (`/ui/dossier`) is a flat "select root credential → build → download" tool. It has no organization awareness, no schema-driven edge slot selection, and no ACDC issuance — it only serializes an existing credential chain. Users cannot create new dossier ACDCs through the UI, nor can they associate dossiers with OSP organizations for TN mapping authorization.

## Spec References

- **§6.3.2 — Dossier**: CVD asserted to the world (not issued to a specific party). No issuee field.
- **§3.1.4 — Accountable Party**: AP prepares and signs the dossier. The dossier's `i` field = AP's AID.
- **§3.1.3 — Originating Party**: OP signs PASSporTs, authorized via `delsig` edge.
- **§6.3.4 — Delegation Evidence**: `delsig` credential required; `bproxy` required if brand + OP ≠ AP.
- **§5.1 step 9**: `delsig` issuee = OP's AID, issuer = AP.

## Current State

**What exists:**
- `GET /credential` — lists credentials, org-scoped for non-admins (with `relationship` tagging: `issued`/`subject`)
- `GET /api/organizations` — admin-only, returns full org details
- `POST /api/credentials/issue` — issues ACDC with schema, attributes, edges, optional recipient
- `POST /api/dossier/build` / `/build/info` — builds serialized dossier from root SAID
- `GET /api/dossier/{said}` — public dossier retrieval
- Organization, ManagedCredential, TNMapping DB models
- `dossier.html` — flat credential list with radio-select → build → download
- `shared.js` — `authFetch()`, session management, schema utilities
- `scoping.py` — `can_access_credential()`, `get_org_credentials()`, `register_credential()`

**What's missing:**
1. No organization selector on the dossier page
2. No credential filtering by schema type per edge slot
3. No dossier ACDC creation — page only downloads existing dossier chains
4. No OSP association — no way to record which OSP organization is associated with a dossier. **Scope for this sprint:** OSP association is VISIBILITY ONLY — it allows OSP orgs to discover dossiers associated with them via a new API endpoint. TN mapping authorization is OUT OF SCOPE for this sprint and continues to use the existing `can_access_credential()` ownership/subject checks. A future sprint can wire OSP association into TN mapping authorization if needed, but the current TN mapping flow (`validate_tn_ownership()` in `app/tn/lookup.py`) validates ownership via TN Allocation credentials, not dossier associations.
5. No dossier name input
6. Credential lists show raw SAIDs without human-readable context

## Proposed Solution

### Approach

Build the sprint in 5 phases matching the sprint deliverables: API enhancements → OSP association model → UI wizard → credential display enrichment → tests. The API work comes first so the UI has endpoints to call.

### Alternatives Considered

| Alternative | Pros | Cons | Why Rejected |
|-------------|------|------|--------------|
| Single monolithic endpoint | Simpler API surface | Complex request validation, hard to test | Composability: separate list/filter/create endpoints are cleaner |
| Separate dossier wizard page (new file) | Clean separation | Duplicated nav/styles, two pages for dossiers | Rewriting in-place preserves existing download functionality |
| Client-side edge validation only | Faster iteration | Bypasses server validation, security risk | Server MUST validate edge schema constraints |

---

## Detailed Design

### Phase 1: API Enhancements

#### 1A. `GET /api/organizations/names` (new endpoint)

**File:** `services/issuer/app/api/organization.py`

**Purpose:** Lightweight org list for any authenticated user (needed for AP and OSP dropdowns).

```python
class OrganizationNameResponse(BaseModel):
    id: str
    name: str

class OrganizationNameListResponse(BaseModel):
    count: int
    organizations: list[OrganizationNameResponse]

@router.get("/names", response_model=OrganizationNameListResponse)
async def list_organization_names(
    principal: Principal = require_auth,
    db: Session = Depends(get_db),
) -> OrganizationNameListResponse:
    """List organization names. Available to any authenticated user."""
    orgs = db.query(Organization.id, Organization.name).filter(
        Organization.enabled == True
    ).order_by(Organization.name).all()

    return OrganizationNameListResponse(
        count=len(orgs),
        organizations=[
            OrganizationNameResponse(id=o.id, name=o.name) for o in orgs
        ],
    )
```

**Why:** The existing `GET /api/organizations` requires `issuer:admin` and exposes sensitive fields (AID, registry key, LE credential SAID). The wizard needs a lightweight list for two purposes: AP selection (Step 1) and OSP selection (Step 3). Only `id` and `name` are exposed.

**Auth & Scoping:** `require_auth` (any authenticated user). Accepts optional `?purpose=ap|osp` query parameter (default: `ap`):

```python
# Scoping logic:
if purpose == "osp":
    # OSP selection: all authenticated users see all enabled orgs.
    # Org names are not sensitive data, and the association is validated
    # server-side (delsig issuee AID must match OSP org AID).
    # This enables non-admin AP users to select OSP targets.
    orgs = db.query(Organization.id, Organization.name).filter(
        Organization.enabled == True
    ).order_by(Organization.name).all()
elif principal.is_system_admin:
    # AP selection for admins: see all enabled orgs (cross-org workflows)
    orgs = db.query(Organization.id, Organization.name).filter(
        Organization.enabled == True
    ).order_by(Organization.name).all()
else:
    # AP selection for non-admins: only their own org
    orgs = db.query(Organization.id, Organization.name).filter(
        Organization.id == principal.organization_id,
        Organization.enabled == True,
    ).all()
```

**Cross-org policy (architecture decision):** Only `issuer:admin` has cross-org access for AP selection (choosing which org to create a dossier FOR). Non-admin users can only create dossiers for their own org. However, ALL authenticated users can see org names for OSP selection (Step 3), because:
- Org names are not sensitive — they're public-facing identifiers
- The actual authorization for OSP association is enforced server-side in `POST /api/dossier/create` (delsig issuee AID must match OSP org AID)
- Without OSP org visibility, non-admin AP users would be unable to create dossier-OSP associations, defeating the sprint's stated goal
- This does NOT expand cross-org create/write/access capabilities — it only exposes names for selection

#### 1B. Credential list filtering by schema (modify existing)

**File:** `services/issuer/app/api/credential.py`

**Purpose:** Add `schema_said` and `org_id` query parameters to `GET /credential`.

```python
@router.get("", response_model=CredentialListResponse)
async def list_credentials(
    registry_key: Optional[str] = None,
    status: Optional[str] = None,
    schema_said: Optional[str] = None,       # NEW
    org_id: Optional[str] = None,            # NEW (admin only)
    principal: Principal = require_auth,
    db: Session = Depends(get_db),
) -> CredentialListResponse:
```

**Changes:**
- `schema_said`: Filter results to only credentials matching this schema SAID. Applied after org scoping (works for both admin and non-admin).
- `org_id`: Admin-only filter to scope credentials to a specific org (useful when creating a dossier for another org). Validation:
  - **Non-admin principals** (including `issuer:operator`) providing `org_id` receive a **403 error** ("org_id filter requires admin role") — explicit rejection maintains tenant isolation.
  - **Malformed `org_id`** (not a valid UUID format): return **400** ("invalid org_id format").
  - **Unknown `org_id`** (valid UUID but org does not exist in DB): return **404** ("organization not found").

**Implementation:**
- After the existing org-scoped credential fetch, apply schema_said filter: `credentials = [c for c in credentials if c.schema_said == schema_said]`
- For `org_id` filter (admin-only, return 403 for non-admins): apply the same dual-visibility logic used for non-admin users — include credentials where the specified org ISSUED them (`ManagedCredential.organization_id == org_id`) OR where the org is the SUBJECT/recipient (`credential.recipient_aid == org.aid`). This ensures the admin sees the same credential universe as an org user would, which is essential for correct edge selection when creating dossiers for another org.
- **Relationship tagging with `org_id`:** When `org_id` is provided, the `relationship` field on each credential is computed FROM THE PERSPECTIVE OF THE SPECIFIED ORG (not the requesting admin's org). Credentials issued by that org get `relationship: "issued"`; credentials where that org is the recipient get `relationship: "subject"`. This allows the wizard to correctly present I2I-filtered results (e.g., `alloc` edge needs credentials where the AP org is the SUBJECT/issuee).

#### 1C. `POST /api/dossier/create` (new endpoint)

**File:** `services/issuer/app/api/dossier.py`

**Purpose:** Issue a dossier ACDC with schema-validated edges.

**Request model** (added to `app/api/models.py`):

```python
class CreateDossierRequest(BaseModel):
    """Request to create (issue) a dossier ACDC."""
    owner_org_id: str = Field(..., description="Accountable Party organization ID")
    name: Optional[str] = Field(None, max_length=255, description="Optional dossier name")
    edges: dict[str, str] = Field(
        ...,
        description="Edge selections: {edge_name: credential_SAID}",
    )
    osp_org_id: Optional[str] = Field(
        None, description="OSP organization to associate (administrative)"
    )

class CreateDossierResponse(BaseModel):
    """Response from dossier creation."""
    dossier_said: str
    issuer_aid: str
    schema_said: str
    edge_count: int
    name: Optional[str] = None
    osp_org_id: Optional[str] = None
    dossier_url: str
    publish_results: Optional[list[WitnessPublishResult]] = None  # reuse existing model
```

**Endpoint logic:**

```python
@router.post("/create", response_model=CreateDossierResponse)
async def create_dossier(
    body: CreateDossierRequest,
    http_request: Request,
    principal: Principal = require_auth,
    db: Session = Depends(get_db),
) -> CreateDossierResponse:
```

**Verifier Compatibility:**

The reviewer raised a concern about whether newly created dossier CVDs (no issuee) are compatible with the current verifier authorization flow. This is already handled:

1. **Existing dossiers already have no issuee.** The dossier is CVD — our schema `EH1jN4U4...` has no `a.i` field. All dossiers created via the bootstrap script or existing issuance have `recipient_aid=None`. The verifier already processes these successfully.
2. **Verifier authorization flow** uses the `delsig` edge within the dossier to determine the OP. It checks that the PASSporT signer's AID matches the `delsig` issuee's AID (§5.1 step 9). It does NOT depend on a dossier issuee field.
3. **Party authorization** in `verify.py` extracts AP from the dossier's `i` field (issuer) and OP from the `delsig` edge. No APE issuee matching is involved for dossier-level authorization.
4. **Integration test** (Phase 5): We will add a test that creates a dossier via `POST /api/dossier/create`, then verifies it passes `POST /api/dossier/build` (ensuring the chain is walkable). Full E2E verification through the verifier is an E2E test concern, not a unit test concern, but we will verify the dossier structure is valid.

**Transaction Semantics:**

The create flow has three write operations: (a) KERI ACDC issuance, (b) `ManagedCredential` registration, (c) optional `DossierOspAssociation` creation. Operations (b) and (c) are SQL and share the same DB session — they are committed atomically. Operation (a) is KERI/LMDB and is not transactional with SQL.

**Failure handling:**
- If edge validation fails (steps 1-4): no writes occur, return 400/403/404.
- If `issue_credential()` fails (step 7): no SQL writes have occurred, return 500.
- If witness publish fails (step 9): **non-fatal**. The KERI credential already exists in LMDB. Publish failure is caught, logged, and publish results are included in the response (as `null` or partial). SQL commit (step 10) proceeds normally. This matches the established pattern in `POST /credential/issue`.
- If SQL registration/association fails after successful ACDC issuance (steps 8-11): the KERI credential exists but has no `ManagedCredential` record. This is a partial state. We handle this by wrapping SQL writes in a single `db.commit()` with rollback on exception, logging the orphaned credential SAID for admin recovery. The KERI credential can be cleaned up manually or re-registered later.
- **Important:** We do NOT call `register_credential()` (which commits internally). Instead, the create endpoint performs both SQL writes (ManagedCredential + DossierOspAssociation) inline using `db.add()` / `db.flush()` / `db.commit()` in a single transaction block. This avoids the existing helper's internal commit and ensures atomicity.

**Steps:**
1. `check_credential_write_role(principal)` — require `issuer:operator+` or `org:dossier_manager+`
2. Resolve `owner_org_id` → Organization record. Verify org exists, is enabled, has AID and registry.
3. **Cross-org access policy (admin-only):**
   - **System admins** (`issuer:admin`): Can create dossiers for any org.
   - **All other principals** (`issuer:operator`, `org:dossier_manager`, `org:administrator`): Must belong to `owner_org_id`. Return 403 if attempting to create for another org. This maintains the Sprint 41 tenant isolation boundary — only admins have cross-org access, consistent with `can_access_credential()` and all downstream access checks.
4. **Validate edges:**
   - Required edges: `vetting`, `alloc`, `tnalloc`, `delsig` — all must be present
   - Optional edges: `bownr`, `bproxy` — may be omitted
   - For each provided edge:
     - **Access enforcement (per-edge policy):** Edge credentials are checked against an access policy that varies by edge type:
       - **AP-org scoped edges** (`vetting`, `alloc`, `tnalloc`, `delsig`, `bownr`): The credential must be ISSUED BY the owner org (`ManagedCredential.organization_id == owner_org.id`) OR the owner org must be the SUBJECT/recipient (`credential.recipient_aid == owner_org.aid`). This prevents unauthorized credential linking.
       - **Cross-entity edges** (`bproxy`): The credential must be accessible to the **requesting principal** via the existing `can_access_credential()` check (admin sees all; org-scoped principals see their own org's issued/subject credentials). `bproxy` is inherently cross-entity — it authorizes one entity to use another's brand — so the AP-org universe restriction would block legitimate spec-valid dossiers. The server-side `bproxy` enforcement (§6.3.4 check below) ensures the credential is only accepted when semantically required.
       - Return 403 ("access denied to credential {SAID}") if not accessible under the applicable policy.
     - Credential SAID must exist and be in `issued` status (not revoked)
     - Schema-constrained edges must match: `alloc`/`delsig` → `EL7irIKYJL9Io0hhKSGWI4OznhwC7qgJG5Qf4aEs6j0o`, `tnalloc` → `EFvnoHDY7I-kaBBeKlbDbkjG4BaI0nKLGadxBdjMGgSQ`
     - I2I edges (`alloc`, `tnalloc`): credential's recipient AID must match the owner org's AID
     - **`delsig` delegation validation (§5.1 step 9):** The `delsig` credential's **issuer** AID MUST equal the AP's AID (the owner org's AID). The `delsig` credential's **issuee** (`a.i` / `recipient_aid`) identifies the OP's AID — this is the entity authorized to sign PASSporTs. The endpoint validates this by fetching the `delsig` credential details and confirming `issuer_aid == owner_org.aid`. If not, return 400 ("delsig credential issuer must be the Accountable Party"). The issuee AID is recorded and used for the `bproxy` check.
   - **`bproxy` enforcement (§6.3.4):** If `bownr` is present, determine whether OP ≠ AP by inspecting the `delsig` credential's issuee AID. If the `delsig` issuee (OP) differs from the AP org's AID and `bproxy` is absent, return a **400 hard error** — not a warning. Per §6.3.4, `bproxy` is REQUIRED when brand + OP ≠ AP. If OP == AP (self-signing), `bproxy` is optional even with `bownr`.
5. **Build ACDC edges dict** for `issue_credential()`:
   ```python
   edges = {
       "d": "",  # placeholder for SAID computation
       "vetting": {"n": vetting_said, "s": vetting_schema, "o": "NI2I"},
       "alloc": {"n": alloc_said, "s": "EL7ir...", "o": "I2I"},
       "tnalloc": {"n": tnalloc_said, "s": "EFvno...", "o": "I2I"},
       "delsig": {"n": delsig_said, "s": "EL7ir...", "o": "NI2I"},
       # optional:
       "bownr": {"n": bownr_said, "s": bownr_schema, "o": "NI2I"},
       "bproxy": {"n": bproxy_said, "s": bproxy_schema},
   }
   ```
6. **Build attributes dict:**
   ```python
   attributes = {"d": "", "dt": nowIso8601()}
   if body.name:
       attributes["name"] = body.name
   ```
7. **Issue the dossier ACDC** via `CredentialIssuer.issue_credential()`:
   - `registry_name`: Resolved from the org's stored `registry_key`. We look up the registry by its key (`regery.registryByKey(org.registry_key)`) to get the registry name, avoiding brittle name derivation.
   - `schema_said`: `EH1jN4U4LMYHmPVI4FYdZ10bIPR7YWKp8TDdZ9Y9Al-P` (dossier schema)
   - `attributes`: as built above
   - `recipient_aid`: `None` (CVD, no issuee)
   - `edges`: as built above
   - `private`: False
8. **Stage SQL writes (no commit yet):**
   a. Create `ManagedCredential` record inline (NOT via `register_credential()` which commits internally) — `db.add(ManagedCredential(...))`.
   b. If `osp_org_id` is provided, create `DossierOspAssociation` record — `db.add(DossierOspAssociation(...))`.
   Both are added to the session but NOT committed yet.
9. **Publish** anchor IXN to witnesses (**best-effort, non-fatal**). Following the established pattern in `credential.py` (lines 99-123), witness publish is attempted but failure does NOT fail the create request:
   - If `WITNESS_IURLS` is configured, retrieve the anchor IXN bytes via `issuer.get_anchor_ixn_bytes(cred_said)` and call `publisher.publish_event()`.
   - On success: include `publish_results` (per-witness success/error) in the response.
   - On threshold failure (not enough witnesses acknowledged): log a warning, still include partial `publish_results` in the response.
   - On exception: catch, log error (`"Failed to publish dossier anchor ixn to witnesses: {e}"`), set `publish_results = None` in the response.
   - **Rationale:** The KERI credential already exists in LMDB after step 7. Witness publish distributes the anchoring event but is not required for the credential to be valid. Witnesses will eventually receive the event via other mechanisms (e.g., when the verifier resolves the OOBI). This matches the existing `POST /credential/issue` behavior exactly.
10. **Commit SQL** — `db.commit()` atomically commits all staged writes (ManagedCredential + optional DossierOspAssociation) in a single transaction. On failure: rollback, log orphaned credential SAID, return 500.
11. **Audit log** the dossier creation (following the existing pattern in `credential.py`):
    ```python
    audit.log_access(
        action="dossier.create",
        principal_id=principal.key_id,
        resource=dossier_said,
        details={
            "owner_org_id": owner_org_id,
            "osp_org_id": body.osp_org_id,
            "edge_count": len(edges),
            "name": body.name,
        },
    )
    ```
    If `osp_org_id` was provided, a separate audit entry is logged:
    ```python
    audit.log_access(
        action="dossier.osp_associate",
        principal_id=principal.key_id,
        resource=dossier_said,
        details={"osp_org_id": body.osp_org_id},
    )
    ```
12. Return response with dossier SAID, dossier URL, publish results, etc.

**Edge schema/operator constants** (defined at module level):

```python
DOSSIER_SCHEMA_SAID = "EH1jN4U4LMYHmPVI4FYdZ10bIPR7YWKp8TDdZ9Y9Al-P"
GCD_SCHEMA_SAID = "EL7irIKYJL9Io0hhKSGWI4OznhwC7qgJG5Qf4aEs6j0o"
TNALLOC_SCHEMA_SAID = "EFvnoHDY7I-kaBBeKlbDbkjG4BaI0nKLGadxBdjMGgSQ"

DOSSIER_EDGE_DEFS = {
    "vetting":  {"required": True,  "schema": None,              "operator": "NI2I", "i2i": False, "access": "ap_org"},
    # vetting is intentionally schema-unconstrained: the dossier schema uses "flexible"
    # for the vetting edge because it can be an LE credential (ENPXp1vQ...), an OOR
    # credential, or any identity vetting credential from a trusted vetter. The actual
    # trust chain validation happens at verification time, not issuance time.
    "alloc":    {"required": True,  "schema": GCD_SCHEMA_SAID,   "operator": "I2I",  "i2i": True,  "access": "ap_org"},
    "tnalloc":  {"required": True,  "schema": TNALLOC_SCHEMA_SAID, "operator": "I2I", "i2i": True, "access": "ap_org"},
    "delsig":   {"required": True,  "schema": GCD_SCHEMA_SAID,   "operator": "NI2I", "i2i": False, "access": "ap_org"},
    "bownr":    {"required": False, "schema": None,              "operator": "NI2I", "i2i": False, "access": "ap_org"},
    "bproxy":   {"required": False, "schema": None,              "operator": None,   "i2i": False, "access": "principal"},
    # bproxy uses "principal" access: checked via can_access_credential() instead of
    # AP-org scoping, because bproxy is inherently cross-entity (brand owner → AP/OP).
}

# Access policy key:
# - "ap_org": credential must be issued by or targeted to the AP org
# - "principal": credential must be accessible to the requesting principal
#   (via can_access_credential() — admin sees all, org-scoped sees own org)
```

**Edge Access Policy Matrix:**

| Edge | Access Policy | Rationale |
|------|--------------|-----------|
| `vetting` | `ap_org` | Identity vetting credential belongs to the AP org (issued to them or by them) |
| `alloc` | `ap_org` | Service allocation granted TO the AP org (I2I, AP is issuee) |
| `tnalloc` | `ap_org` | TN allocation granted TO the AP org (I2I, AP is issuee) |
| `delsig` | `ap_org` | Delegation evidence issued BY the AP org (AP is issuer, OP is issuee) |
| `bownr` | `ap_org` | Brand ownership belongs to the AP org's credential universe |
| `bproxy` | `principal` | Brand proxy is inherently cross-entity: issued BY the brand owner TO the AP/OP. When OP ≠ AP (cross-org), the bproxy credential may not be in the AP org's universe but must still be accessible to the requesting principal |

This per-edge policy ensures that 5 of 6 edges are strictly confined to the AP org's issued/subject credential universe, while `bproxy` uses the existing `can_access_credential()` check to support legitimate cross-entity brand delegation patterns required by §6.3.4.

#### 1D. Edge Credential Validation (helper function)

**File:** `services/issuer/app/api/dossier.py` (private function)

```python
async def _validate_dossier_edges(
    db: Session,
    principal: Principal,
    owner_org: Organization,
    edge_selections: dict[str, dict],
) -> tuple[dict, list[str]]:
    """Validate and build edges dict for dossier ACDC issuance.

    Returns:
        (edges_dict, warnings) — edges_dict ready for issue_credential(), warnings list

    Raises:
        HTTPException: If validation fails (missing required edges, schema mismatch, etc.)
    """
```

This function encapsulates all edge validation logic: required check, schema match, I2I operator check, `delsig` issuer validation (§5.1 step 9), and `bproxy` enforcement (§6.3.4 — hard 400 error when `bownr` + OP ≠ AP without `bproxy`).

---

### Phase 2: OSP Association Model

#### 2A. Database Model

**File:** `services/issuer/app/db/models.py`

```python
class DossierOspAssociation(Base):
    """Administrative record: which OSP org can reference which dossier.

    This is NOT a protocol-level concept and does NOT gate TN mapping authorization.
    The actual cryptographic authorization comes from the delsig edge within the
    dossier (§6.3.9). TN mapping creation continues to use existing
    can_access_credential() ownership/subject checks. This association is for
    VISIBILITY ONLY — it allows OSP orgs to discover dossiers associated with them
    via GET /api/dossier/associated.
    """
    __tablename__ = "dossier_osp_associations"

    id = Column(Integer, primary_key=True, autoincrement=True)
    dossier_said = Column(String(44), nullable=False, index=True)
    owner_org_id = Column(
        String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    osp_org_id = Column(
        String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False,
        index=True  # indexed for GET /api/dossier/associated queries
    )
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    __table_args__ = (
        UniqueConstraint("dossier_said", "osp_org_id", name="uq_dossier_osp"),
    )
```

**Why no FK to `managed_credentials.said`:** The `managed_credentials` table uses SAID as PK, but the dossier SAID comes from KERI issuance. We store the SAID as a string with an index for efficient queries. The integrity is maintained by the creation flow (dossier must be created before association).

**Lifecycle & cleanup strategy:**
- **Org deletion:** Both `owner_org_id` and `osp_org_id` have `ondelete="CASCADE"`, so associations are automatically deleted when either org is deleted.
- **Dossier revocation:** KERI credentials cannot be "deleted" — they can only be revoked via TEL. A revoked dossier's association remains in the table but is harmless: the `GET /api/dossier/associated` endpoint returns the association, and the client can check credential status separately. No automatic cleanup is needed because the association metadata (owner/OSP relationship) remains historically meaningful.
- **ManagedCredential deletion:** If a `ManagedCredential` record is deleted (e.g., via `DELETE /credential/{said}`), the `DossierOspAssociation` is NOT automatically cleaned up (no FK relationship). However, this is a benign orphan — the association references a SAID that still exists in KERI/LMDB. As a defensive measure, `GET /api/dossier/associated` can optionally filter out associations whose `dossier_said` has no corresponding `ManagedCredential` record. For this sprint, we accept benign orphans; a future sprint can add a cleanup endpoint or background task if needed.

#### 2B. OSP Association in Create Endpoint

When `POST /api/dossier/create` receives `osp_org_id`:
1. Verify the OSP org exists and is enabled. Return 404 if not found, 400 if disabled.
2. **Mandatory consistency check:** Validate that the `delsig` edge's issuee AID (the OP) matches the OSP org's AID. This ensures the administrative association is consistent with the cryptographic delegation — the OP that the dossier authorizes to sign PASSporTs should belong to the OSP org that will reference the dossier. Return 400 ("delsig issuee AID does not match OSP organization AID") if mismatched.
3. Create `DossierOspAssociation(dossier_said=..., owner_org_id=..., osp_org_id=...)`.
4. **Note on idempotency:** `POST /api/dossier/create` is NOT idempotent at the request level — each call issues a new dossier ACDC with a unique SAID. Retried requests create additional dossiers. The `(dossier_said, osp_org_id)` unique constraint only prevents duplicate OSP associations for the SAME dossier SAID, not duplicate dossier creation. Clients should not retry on success.

#### 2C. OSP Visibility (future enhancement)

The sprint specifies that "the OSP org should be able to see dossiers associated with them." For this sprint, we'll add a `GET /api/dossier/associated` endpoint:

```python
@router.get("/associated", response_model=AssociatedDossierListResponse)
async def list_associated_dossiers(
    principal: Principal = require_auth,
    db: Session = Depends(get_db),
) -> AssociatedDossierListResponse:
    """List dossiers associated with the principal's organization as OSP."""
```

**Route ordering:** FastAPI resolves routes by declaration order. The `/associated` route MUST be declared **before** the `/{said}` route in `dossier.py` to prevent `"associated"` from being captured as a `{said}` path parameter. Similarly, `/create` must precede `/{said}`. The route declaration order will be: `/build` → `/build/info` → `/create` → `/associated` → `/{said}`.

This returns dossier SAIDs, owner org names, and creation dates.

**Auth & Scoping:**
- `check_credential_access_role(principal)` — requires `issuer:readonly+` or `org:dossier_manager+`
- **System admins:** See all associations across all orgs (no org filter applied). Optionally accept `?org_id=...` query parameter to filter by a specific OSP org.
- **Org-scoped principals:** See only associations where `osp_org_id == principal.organization_id` (their org is the OSP).
- **Principals without `organization_id`:** Return empty list (no org context = no associations to show). Not an error — just zero results.

---

### Phase 3: UI Redesign (`dossier.html`)

**File:** `services/issuer/web/dossier.html`

Complete rewrite of the page content into a multi-step wizard. The nav header and shared.js imports remain identical.

#### Wizard Steps

**Step 1: Select Accountable Party Organization**
- Dropdown populated from `GET /api/organizations/names`
- **System admins** (`issuer:admin`): See all enabled orgs in dropdown (cross-org workflows)
- **All other principals** (`issuer:operator`, `org:dossier_manager`, `org:administrator`): See their own org pre-selected, dropdown disabled
- On selection, triggers credential loading for subsequent steps

**Step 2: Select Edge Credentials**
- For each of the 6 edge slots, render a collapsible section:
  - Heading: edge name + description + required/optional badge
  - Credential picker table filtered by:
    - Schema SAID (for constrained edges like `alloc`, `tnalloc`, `delsig`)
    - Organization ownership (I2I edges show only credentials issued TO the org)
    - Status = `issued` only
  - Each row: truncated SAID, schema type label, issuance date, status badge, key attributes
  - Radio-select for required edges, checkbox toggle for optional edges
  - Empty state: "No matching credentials" with link to credentials page
- Uses `GET /credential?schema_said=...&org_id=...` for filtered fetches

**Step 3: Dossier Metadata**
- Dossier name (optional text input)
- OSP Organization dropdown (optional, from `GET /api/organizations/names?purpose=osp` — shows all enabled orgs for any authenticated user)
- Summary panel showing all selected edges

**Step 4: Review & Create**
- Confirmation panel with all selections
- "Create Dossier" button → `POST /api/dossier/create`
- **Double-submit prevention:** Button is disabled and shows a spinner while the request is in-flight. Re-enabled on error response. On success, button is replaced with result panel (no second click possible).
- Success: show dossier SAID, download link, option to create TN mapping
- Error: show validation errors with links back to relevant step

#### Wizard Navigation

- Step indicators at top (1-2-3-4 with active highlighting)
- "Next" / "Back" buttons
- "Next" disabled until step requirements met (e.g., AP selected, required edges filled)
- Validation feedback inline (not modal)

#### Preserving Existing Functionality

The existing "Build & Download" functionality is preserved as a separate section below the wizard (or accessible after dossier creation). The wizard adds the *creation* step; build/download remains for *existing* dossiers.

#### Schema Type Labels

The UI maps schema SAIDs to human-readable labels using a local mapping:

```javascript
const SCHEMA_LABELS = {
    "EH1jN4U4LMYHmPVI4FYdZ10bIPR7YWKp8TDdZ9Y9Al-P": "VVP Dossier",
    "EL7irIKYJL9Io0hhKSGWI4OznhwC7qgJG5Qf4aEs6j0o": "Cooperative Delegation (GCD)",
    "EFvnoHDY7I-kaBBeKlbDbkjG4BaI0nKLGadxBdjMGgSQ": "TN Allocation (RTU)",
    "ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY": "Legal Entity (LE)",
    // ... additional schemas from registry
};
```

---

### Phase 4: Credential Display Enrichment

#### 4A. Schema Type Labels

Both in the wizard credential pickers (Phase 3) and the existing credential management section, schema SAIDs are mapped to human-readable labels. The `SCHEMA_LABELS` map is defined once in the JS and used for all credential table renderings.

If a schema SAID is not in the local map, the UI falls back to `schema_said.substring(0, 16) + "..."`.

#### 4B. Credential Attribute Preview

When a user hovers over or selects a credential in an edge picker, show key attributes:
- **LE (vetting):** entity name, country
- **TNAlloc:** phone numbers/ranges
- **Brand (bownr):** brand name, logo URL
- **GCD (alloc/delsig):** delegation target info

This requires fetching credential details (`GET /credential/{said}`) on hover/selection. To avoid excessive API calls, cache details per session.

#### 4C. Organization Name Display

Already implemented in the credentials page via `issuer_name`/`recipient_name` in `CredentialResponse`. The wizard reuses this pattern.

---

### Phase 5: Tests

#### 5A. `test_dossier_create.py` (new file)

**File:** `services/issuer/tests/test_dossier_create.py`

Tests for `POST /api/dossier/create`:
- **Happy path:** Create dossier with all 4 required edges, verify SAID returned, verify ManagedCredential created
- **With optional edges:** Include `bownr` and `bproxy`, verify 6-edge dossier
- **With dossier name:** Verify `a.name` attribute in issued ACDC
- **With OSP association:** Verify `DossierOspAssociation` record created
- **Missing required edge:** Omit `vetting`, expect 400
- **Schema mismatch:** Provide TNAlloc credential for `alloc` slot (wrong schema), expect 400
- **Revoked credential:** Provide revoked credential for an edge, expect 400
- **I2I validation:** Provide credential not issued to the org for I2I edge, expect 400
- **Non-admin cross-org:** Non-admin tries to create dossier for another org, expect 403
- **bownr without bproxy (OP ≠ AP):** Create with `bownr` but no `bproxy` when `delsig` issuee ≠ AP, expect 400
- **bownr without bproxy (OP == AP):** Create with `bownr` but no `bproxy` when `delsig` issuee == AP (self-signing), expect success
- **delsig issuer validation:** Provide `delsig` credential whose issuer AID ≠ AP org AID, expect 400
- **bproxy cross-entity access:** Provide a `bproxy` credential that is accessible to the principal but NOT in the AP org's issued/subject universe — expect success (bproxy uses `can_access_credential()` policy, not AP-org scoping)
- **bproxy inaccessible credential:** Provide a `bproxy` credential SAID that the principal cannot access (e.g., from another org, non-admin principal) — expect 403

#### 5B. `test_credential_filters.py` (new file)

**File:** `services/issuer/tests/test_credential_filters.py`

Tests for credential list filtering:
- **Schema filter:** `GET /credential?schema_said=X` returns only matching credentials
- **Org filter (admin):** `GET /credential?org_id=Y` returns only that org's credentials
- **Org filter (non-admin):** `org_id` parameter returns 403 for `issuer:operator` and org-scoped principals
- **Combined filters:** `schema_said` + `org_id` together

#### 5C. Tests for `GET /api/organizations/names`

Added to existing org tests or in a new file:
- Auth required (401 without key)
- Returns only `id` and `name` (no sensitive fields)
- Accessible by non-admin users
- Only enabled orgs returned
- **AP purpose (default):** Non-admin sees only their own org; admin sees all enabled orgs
- **OSP purpose:** `?purpose=osp` — ALL authenticated users see all enabled orgs (used for OSP selection in wizard Step 3)
- **Invalid purpose:** `?purpose=invalid` returns 400

#### 5C2. Non-Admin Cross-Org Rejection Tests

Tests verifying tenant isolation is maintained for non-admin principals:
- **AP org listing:** `GET /api/organizations/names` (default purpose=ap) returns only operator's own org (not all orgs)
- **OSP org listing:** `GET /api/organizations/names?purpose=osp` returns ALL enabled orgs for operator (valid — OSP selection is not a privilege escalation)
- **Credential filtering:** `GET /credential?org_id=X` returns 403 for `issuer:operator`
- **Cross-org dossier creation:** `POST /api/dossier/create` with `owner_org_id` of another org returns 403 for `issuer:operator`
- **Org-scoped cross-org rejection:** `org:dossier_manager` attempting `org_id` filter gets 403; attempting cross-org `owner_org_id` gets 403

#### 5D. OSP Association Tests

- Create association via dossier create endpoint
- **OSP consistency check:** Provide `osp_org_id` whose AID doesn't match `delsig` issuee, expect 400
- **OSP consistency check (happy):** Provide `osp_org_id` whose AID matches `delsig` issuee, expect success
- Uniqueness: `POST /create` is not request-idempotent (each call issues new ACDC); duplicate OSP association for same SAID is prevented by unique constraint

#### 5E. `GET /api/dossier/associated` Tests

- **Auth required:** 401 without API key
- **Org-scoped principal:** Returns only associations where OSP = principal's org
- **Admin principal:** Returns all associations (unfiltered)
- **Admin with `org_id` filter:** Returns only associations for specified OSP org
- **Principal without org:** Returns empty list (not an error)
- **Empty results:** Returns empty list when no associations exist
- **Org deletion cascade:** Delete an org that has associations (as owner or OSP); verify associations are removed (CASCADE FK)

#### 5E2. Audit Logging Tests

- **Dossier create audit:** After successful `POST /api/dossier/create`, verify `audit.log_access()` was called with `action="dossier.create"`, correct `principal_id`, `resource=dossier_said`, and `owner_org_id` in details
- **OSP association audit:** When `osp_org_id` is provided, verify additional `audit.log_access()` call with `action="dossier.osp_associate"`
- **No audit on failure:** When create fails (e.g., missing required edge), verify no audit entry is logged

#### 5F. Transaction / Partial Failure / Integration Tests

- **SQL failure after ACDC issuance:** Mock DB commit failure after `issue_credential()` succeeds; verify error response and log of orphaned credential SAID
- **Witness publish failure during create:** Mock `publisher.publish_event()` to raise an exception; verify dossier creation still succeeds (200), `publish_results` is `null` in response, and SQL records (ManagedCredential, DossierOspAssociation) are committed
- **Non-admin `org_id` filter on credential list:** Returns 403 (not silently ignored)
- **Route ordering:** `GET /api/dossier/associated` does not get captured by `GET /api/dossier/{said}` — verify 200 (not 404/wrong handler)
- **Created dossier is buildable:** After `POST /api/dossier/create`, call `POST /api/dossier/build` with the returned SAID — verify the dossier chain is walkable and serializable
- **Relationship tagging with `org_id`:** `GET /credential?org_id=X` returns `relationship` from perspective of org X (not requesting admin)
- **Invalid `org_id` on credential list:** Malformed UUID returns 400; unknown UUID returns 404
- **CVD verifier compatibility:** Create a dossier with `recipient_aid=None`, then verify the dossier's issuer AID matches the AP and the `delsig` issuee AID is the OP — confirming the verifier authorization model (AP from `dossier.i`, OP from `delsig.issuee`) is satisfied

#### 5G. UI / Integration Tests

The issuer does not have an existing browser test framework (no Selenium/Playwright). Manual verification of wizard flows is acceptable for this sprint, with the following deterministic integration tests using the API:
- **Wizard step 1 data:** `GET /api/organizations/names` returns expected scoping (admin vs org user)
- **Wizard step 2 data:** `GET /credential?schema_said=X&org_id=Y` returns correctly filtered and relationship-tagged credentials for each edge slot
- **Legacy build/download preserved:** `POST /api/dossier/build` with a pre-existing root SAID works before AND after the wizard code changes (regression test)
- **Full wizard flow (API-level):** Simulate the wizard steps via sequential API calls: list orgs → filter credentials per edge → create dossier → build & download — verify end-to-end success

---

## Data Flow

```
User (Admin) → Wizard UI
  Step 1: Select AP org → GET /api/organizations/names (purpose=ap, default)
  Step 2: Select edges → GET /credential?schema_said=X&org_id=Y (per edge slot)
  Step 3: Enter name, select OSP → GET /api/organizations/names?purpose=osp
  Step 4: Review → POST /api/dossier/create
    → Validate edges (schema, status, I2I, access enforcement)
    → issue_credential() with dossier schema
    → db.add(ManagedCredential) + optional db.add(DossierOspAssociation)
    → Publish anchor IXN to witnesses (best-effort, non-fatal)
    → db.commit() (single atomic SQL transaction)
    → Return dossier SAID + URL + publish_results
  Optional: Download → POST /api/dossier/build (existing)
```

## Error Handling

| Error | HTTP Status | Detail |
|-------|-------------|--------|
| Missing required edge | 400 | "Required edge 'vetting' not provided" |
| Schema mismatch | 400 | "Edge 'alloc' requires schema EL7ir..., got EFvno..." |
| Revoked credential | 400 | "Credential XYZ for edge 'alloc' is revoked" |
| I2I violation | 400 | "I2I edge 'alloc': credential issuee does not match org AID" |
| Credential not found | 404 | "Credential XYZ not found" |
| Org not found | 404 | "Organization not found" |
| Edge access denied | 403 | "Access denied to credential {SAID} for organization {org_name}" |
| Cross-org access | 403 | "Access denied: can only create dossiers for your own organization" |
| Witness publish failure | 200 (non-fatal) | Response includes `publish_results: null`; dossier created successfully |
| Auth failure | 401/403 | Standard auth errors |

## Files to Create/Modify

| File | Action | Purpose |
|------|--------|---------|
| `services/issuer/app/api/dossier.py` | Modify | Add `POST /create`, `GET /associated`, edge validation |
| `services/issuer/app/api/credential.py` | Modify | Add `schema_said` and `org_id` query filters |
| `services/issuer/app/api/organization.py` | Modify | Add `GET /names` endpoint |
| `services/issuer/app/api/models.py` | Modify | Add `CreateDossierRequest`, `CreateDossierResponse`, `AssociatedDossierListResponse` |
| `services/issuer/app/db/models.py` | Modify | Add `DossierOspAssociation` model |
| `services/issuer/web/dossier.html` | Rewrite | Multi-step wizard UI |
| `services/issuer/tests/test_dossier_create.py` | Create | Dossier creation + OSP tests |
| `services/issuer/tests/test_credential_filters.py` | Create | Schema/org filter tests |
| `knowledge/api-reference.md` | Update | Document new endpoints |
| `knowledge/data-models.md` | Update | Document `DossierOspAssociation` model |

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| `issue_credential()` doesn't handle no-recipient CVD | Low | High | Test with `recipient_aid=None` first; keripy `proving.credential()` already supports this |
| Schema SAID constants change | Low | Medium | Constants defined once, used everywhere; easy to update |
| Edge validation too strict (blocks valid dossiers) | Medium | Medium | Hard errors for spec-mandated constraints only; `bproxy` enforced per §6.3.4 (only when brand + OP ≠ AP) |
| Large number of credentials slows UI | Low | Low | Schema filter reduces payload; pagination can be added later if needed |
| DB migration for `DossierOspAssociation` | Low | Low | `Base.metadata.create_all()` handles auto-creation (no Alembic) |

---

## Implementation Notes

### Deviations from Plan

1. **`get_registry_by_key()` → `get_registry()`**: The plan referenced `get_registry_by_key()` but the actual method in `app/keri/registry.py` is `get_registry(registry_key)` returning `Optional[RegistryInfo]`. Fixed during implementation.

2. **Test database initialization**: ASGITransport doesn't invoke FastAPI lifespan, so `init_database()` is never called during tests. Added `_init_app_db()` helper to ensure tables exist in API-level tests.

3. **SQLite foreign key enforcement**: In-memory SQLite test fixture needed explicit `PRAGMA foreign_keys=ON` event listener for CASCADE delete tests.

4. **Flat edges contract**: Plan initially defined `edges: dict[str, dict]` (nested `{edge_name: {said: ...}}`). Implemented as `edges: dict[str, str]` (flat `{edge_name: credential_SAID}`) since the backend builds the full ACDC edge structure internally during `_validate_dossier_edges()`. The flat format is simpler for both the UI and API consumers. Plan updated in round 6 to match.

### Implementation Details

- Edge validation order: required-edge check → per-edge loop (existence → status → access → schema → I2I → delsig-specific) → post-loop bproxy enforcement
- Mock credential helper `_make_edge_mock()` returns correct schema per edge definition (EDGE_SCHEMAS map), preventing test-setup schema mismatches
- API tests use uuid-based pseudo_lei values to avoid unique constraint violations in shared SQLite databases

### Review Fixes (Rounds 1-2)

**Round 1 fixes:**
- Added delsig recipient_aid validation (`§5.1 step 9`)
- Added OSP org AID existence check
- Implemented I2I filtering in UI edge picker (filter to `subject` relationship)
- Added credential attribute preview on selection via credDetailCache
- 4 new tests: delsig-no-recipient, OSP-no-AID, audit, unknown-edge API

**Round 2 fixes:**
- Moved OSP validation to step 4 (before ACDC issuance at step 7) — all 4xx errors now side-effect free
- Reordered `_validate_dossier_edges()` to fast-fail required/unknown edge checks before KERI init
- Fixed invalid `<div>` inside `<tbody>` — changed to `<p>` before table
- Tightened assertions from `in (400, 404)` to exact status codes with detail checks
- Added 5 happy-path tests: required-edges-only, all-6-edges, OSP association + DB persistence, witness failure non-fatal, OSP AID mismatch

### Review Fixes (Rounds 3-5)

**Round 3 fixes:**
- Strict I2I filtering in edge picker — empty-state message instead of fallback-to-all
- Fixed `<p>` inside `<tbody>` — moved info text before table element
- Removed unused `org_managed` variable in credential.py line 217
- Added 3 tests: cross-org 403, readonly 403, create-then-build integration

**Round 4 fixes:**
- Sanitized 500 error message: generic `"Failed to issue dossier credential"` instead of leaking `{e}`
- Added contextual step navigation links in wizard error display

**Round 5 fixes:**
- Removed AP org exclusion from OSP dropdown — an org can be both AP and OSP (self-signing)
- Added concrete audit logging assertions: mock `get_audit_logger` with call count/argument verification for create (1 call), create+OSP (2 calls), and failure (0 calls)
- Added admin `org_id` filter test for `/dossier/associated`

### Test Results

```
46 tests in test_sprint63_wizard.py — all pass
497 tests total in issuer test suite — all pass (5 skipped, 3 deselected)
```

### Files Changed

| File | Lines | Summary |
|------|-------|---------|
| `services/issuer/app/api/dossier.py` | +413 | Sprint 63 edge validation, POST /create, GET /associated |
| `services/issuer/app/api/credential.py` | +63 | schema_said and org_id query parameters |
| `services/issuer/app/api/models.py` | +66 | CreateDossierRequest/Response, AssociatedDossier, OrgName models |
| `services/issuer/app/api/organization.py` | +48 | GET /organizations/names with purpose=ap/osp |
| `services/issuer/app/db/models.py` | +40 | DossierOspAssociation model |
| `services/issuer/web/dossier.html` | +1124/-280 | 4-step wizard UI rewrite |
| `services/issuer/tests/test_sprint63_wizard.py` | +1684 | 46 tests across 15 test classes |
