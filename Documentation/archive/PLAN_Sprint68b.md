# Sprint 68b: Issuer Refactoring — KERI Agent Client Migration

## Problem Statement

Sprint 68 (Phase 1-5) created the standalone KERI Agent service and the `KeriAgentClient`
HTTP proxy. The Issuer still uses direct `app.keri.*` imports for all KERI operations.
This phase migrates every issuer router, service module, and test file to use
`KeriAgentClient` instead, completing the service extraction.

The complexity warrants its own plan because:
- 10 router files import from `app.keri.*` (identity, registry, issuer, witness, persistence)
- `mock_vlei.py` (700 lines) mixes KERI operations with DB operations and must be split
- `vetter/service.py` accesses `reger.creds.get()` and `reger.states.get()` directly
- `conftest.py` wires up real KERI managers; all 767 tests depend on this
- Response models differ between issuer and agent DTOs

## Current State

| Component | Status |
|-----------|--------|
| `services/keri-agent/` | Complete — 7 routers, 64 tests passing |
| `common/common/vvp/models/keri_agent.py` | Complete — 17 DTO models |
| `services/issuer/app/keri_client.py` | Complete — KeriAgentClient with circuit breaker, retry, 55 tests |
| Issuer routers | Still use direct `app.keri.*` imports |
| Issuer tests | Still use real KERI managers in conftest.py |

## Proposed Solution

### Approach

**Incremental router-by-router migration** with a compatibility layer. Each router is
migrated independently: replace `app.keri.*` imports with `keri_client` calls, update
response model construction, and verify tests pass after each router.

The key architectural decision is **where witness publishing lives**:
- **Agent handles witness publishing internally** — routers no longer manage per-witness
  results. The `publish_results` fields in issuer response models become optional/None
  during the transition, then are removed in a follow-up.
- **Rationale**: Witness interaction is tightly coupled to LMDB state (KEL bytes, IXN
  bytes). Moving it to the agent simplifies the issuer and eliminates the need to
  serialize/transfer large binary blobs over HTTP.

### Alternatives Considered

| Alternative | Pros | Cons | Why Rejected |
|-------------|------|------|--------------|
| Big-bang migration | Simpler to reason about | Risky: one mistake breaks all 767 tests | Too high risk |
| Agent exposes raw KERI objects via CESR | Preserves current model structure | Would require CESR deserialization in issuer, defeats purpose of extraction | Adds complexity, not simpler |
| Dual-mode (both direct and client) | Can A/B test | Doubles code paths, conftest complexity | Over-engineering for this use case |

## Detailed Design

### Component 1: `main.py` Lifespan Rewrite

**File**: `services/issuer/app/main.py`

**Current**: Initializes `IdentityManager`, `RegistryManager`, `CredentialIssuer`, `MockVLEIManager` on startup; closes them on shutdown.

**After**: The issuer no longer owns KERI managers. Startup becomes:
1. Initialize database (unchanged)
2. Initialize API key store (unchanged)
3. Start session cleanup task (unchanged)
4. Initialize `KeriAgentClient` singleton
5. Start background bootstrap probe (polls agent health + mock vLEI status)
6. Initialize `TrustAnchorManager` (DB-only ops from split `mock_vlei.py`)

**Shutdown**: Close `KeriAgentClient` (HTTP connection pool). No KERI manager cleanup.

```python
# Startup additions
from app.keri_client import get_keri_client, close_keri_client

async def _bootstrap_probe():
    """Background task: poll agent until healthy, then sync trust anchors."""
    client = get_keri_client()
    while True:
        try:
            if await client.is_healthy():
                # Agent is up — sync trust anchor state
                status = await client.get_bootstrap_status()
                if status.initialized:
                    from app.org.trust_anchors import sync_trust_anchors
                    sync_trust_anchors(status)
                    log.info("Trust anchors synced from KERI Agent")
                    return  # One-shot: done
            await asyncio.sleep(5)
        except Exception as e:
            log.warning(f"Bootstrap probe failed: {e}")
            await asyncio.sleep(10)
```

**Graceful degradation**: The issuer starts even when the agent is unavailable. KERI
routes return 503 (`KeriAgentUnavailableError` → HTTP 503) until the agent comes up.
Non-KERI routes (auth, UI, health) work normally.

**Lifespan changes**:
- Remove: `get_identity_manager()`, `get_registry_manager()`, `get_credential_issuer()`
- Remove: `close_identity_manager()`, `close_registry_manager()`, `close_credential_issuer()`
- Remove: `MockVLEIManager.initialize()` (agent handles mock vLEI init)
- Add: `get_keri_client()`, `close_keri_client()`, bootstrap probe task

### Component 2: `mock_vlei.py` → `trust_anchors.py` Split

**Problem**: `MockVLEIManager` (700 lines) does two distinct things:
1. **KERI operations**: Create identities, registries, issue credentials (→ agent)
2. **DB operations**: Persist state, promote trust anchors, load state (→ issuer)

**Solution**: Split into two modules:

#### 2a: `app/org/trust_anchors.py` (NEW — issuer-side)

Handles DB-only operations that remain in the issuer:

```python
class TrustAnchorManager:
    """Manages trust anchor Organization records in the issuer DB.

    Reads bootstrap status from the KERI Agent (via BootstrapStatusResponse)
    and creates/updates Organization DB records for GLEIF, QVI, GSMA.
    """

    def sync_from_agent(self, status: BootstrapStatusResponse) -> None:
        """Sync trust anchor orgs from agent bootstrap status.

        Extracted from MockVLEIManager._promote_trust_anchors().
        Uses the same 3-strategy matching: persisted org_id → AID match → create new.
        """

    def get_mock_vlei_state(self) -> MockVLEIState | None:
        """Load persisted mock vLEI state from DB.

        Returns AID/registry_key info needed by callers that check
        mock_vlei.state.gsma_aid etc. State is read-only from issuer
        perspective — the agent owns the KERI identities.
        """
```

**Key insight**: The issuer still needs `mock_vlei.state.gsma_aid` in several places
(vetter/service.py, organization.py). Rather than eliminating state entirely, the
`TrustAnchorManager` caches `BootstrapStatusResponse` data and exposes it via
`get_mock_vlei_state()`. This is a read-only view — the agent owns the actual identities.

**BootstrapStatusResponse DTO extension** (required for complete state contract):

The current `BootstrapStatusResponse` (`common/common/vvp/models/keri_agent.py:179`) is missing
fields required by the issuer's `MockVLEIState` (`app/org/mock_vlei.py:36`). Add:

```python
class BootstrapStatusResponse(BaseModel):
    # Existing fields
    initialized: bool
    gleif_aid: str | None = None
    gleif_registry_key: str | None = None
    qvi_aid: str | None = None
    qvi_registry_key: str | None = None
    gsma_aid: str | None = None
    gsma_registry_key: str | None = None
    gleif_name: str | None = None
    qvi_name: str | None = None
    gsma_name: str | None = None

    # NEW — credential SAIDs needed by issuer for edge construction
    qvi_credential_said: str | None = Field(None, description="QVI credential SAID (needed for LE edge)")
    gsma_governance_said: str | None = Field(None, description="GSMA governance credential SAID")
```

The agent's `/bootstrap/status` endpoint already has access to these SAIDs via the mock vLEI
manager state. The org IDs (`gleif_org_id`, `qvi_org_id`, `gsma_org_id`) are issuer-side DB
concepts and are NOT part of the agent response — they are computed by `TrustAnchorManager`
during `sync_from_agent()` and persisted in the issuer's `MockVLEIState` DB table.

**Trust-Anchor State Model** (addresses initialization, persistence, read path, pre-bootstrap behavior):

| Aspect | Specification |
|--------|--------------|
| **Initialization trigger** | Background `_bootstrap_probe()` task launched during lifespan startup. Polls agent `GET /bootstrap/status` every 5s (10s on error). One-shot: stops after first successful sync. |
| **Persistence source of truth** | Agent owns KERI identities (LMDB). Issuer persists trust anchor **Organization records** in PostgreSQL (org_id, name, aid, org_type). The `TrustAnchorManager` writes to PostgreSQL via `sync_from_agent()`, reads via `get_mock_vlei_state()`. |
| **Canonical read path** | All callers use `get_trust_anchor_manager().get_mock_vlei_state()`. This returns a `MockVLEIState` dataclass (read-only). The `get_mock_vlei_manager()` facade is an alias. No `.state` attribute access — always method call. |
| **Before first bootstrap** | `get_mock_vlei_state()` returns `None`. All callers that depend on trust anchor state (vetter cert validation, org creation, LE credential issuance) MUST check for `None` and fail gracefully: vetter returns `None` (no cert), org creation raises 503, credential issuance raises 503. |
| **State staleness** | State is refreshed only once at startup. For long-running instances, a manual `/admin/resync-trust-anchors` endpoint (POST) can re-trigger `sync_from_agent()`. This is a follow-up; not in Sprint 68b scope. |
| **Crash recovery** | On restart, the bootstrap probe re-runs. PostgreSQL org records from the previous run persist across restarts, so `get_mock_vlei_state()` can also load from DB if the agent is temporarily unavailable. Two-tier: in-memory cache (fast) → DB fallback (durable). |

#### 2b: `app/org/mock_vlei.py` → Thin wrapper (MODIFIED)

The existing `get_mock_vlei_manager()` becomes a thin facade over `TrustAnchorManager`:

```python
def get_mock_vlei_manager() -> TrustAnchorManager:
    """Backwards-compatible accessor — returns TrustAnchorManager singleton.

    All callers must use `get_mock_vlei_state()` method (not `.state` attribute)
    to access trust anchor state. The `.state` attribute is removed.
    """
    return get_trust_anchor_manager()
```

**Canonical state access**: All call sites that currently use `mock_vlei.state.X` are
migrated to `get_trust_anchor_manager().get_mock_vlei_state().X` (or equivalently
`get_mock_vlei_manager().get_mock_vlei_state().X`). The `.state` attribute on
`MockVLEIManager` is **removed** — only the `get_mock_vlei_state()` method exists.
This single contract prevents mixed access patterns.

**Migration path for KERI method callers**:
- `mock_vlei.issue_le_credential()` → `keri_client.issue_credential()` with LE schema/edges
- `mock_vlei.issue_vetter_certification()` → `keri_client.issue_credential()` with VetterCert schema/edges
- `mock_vlei.initialize()` → removed (agent handles initialization)

### Component 3: Router-by-Router Migration

Each router follows the same pattern:
1. Replace `from app.keri.* import get_*_manager` with `from app.keri_client import get_keri_client`
2. Replace manager method calls with client method calls
3. Map agent DTO responses to issuer response models
4. Remove witness publishing code (agent handles internally)
5. Wrap KERI client calls in try/except `KeriAgentUnavailableError` → 503

#### 3a: `api/health.py` (SIMPLE)

**Current**: `get_identity_manager().list_identities()` to count identities
**After**: `get_keri_client().health()` → returns `AgentHealthResponse`

```python
@router.get("/healthz")
async def healthz():
    try:
        client = get_keri_client()
        agent_health = await client.health()
        return HealthResponse(
            ok=agent_health.status == "ok",
            identities_loaded=agent_health.identity_count,
        )
    except KeriAgentUnavailableError:
        return HealthResponse(ok=True, identities_loaded=0)
```

#### 3b: `api/identity.py` (MODERATE)

**Current**: Uses `get_identity_manager()` for CRUD + `get_witness_publisher()` for publishing
**After**: Uses `get_keri_client()` for all operations

**Changes**:
- `create_identity`: `mgr.create_identity()` → `client.create_identity()`
  - OOBI URL generation: `mgr.get_oobi_url()` → `client.get_oobi(name)` (agent returns full URL)
  - Witness publishing: Removed (agent publishes internally during identity creation)
  - `publish_results` field: Set to None (agent handles internally)
- `list_identities`: `mgr.list_identities()` → `client.list_identities()`
- `get_identity`: `mgr.get_identity(aid)` → Need to look up by AID. The agent's
  `get_identity` takes a name, not AID. **Design choice**: Add a `list_identities()`
  call and filter by AID, or add an AID-based lookup endpoint to the agent.
  **Decision**: Add `GET /identities?aid={aid}` query param to the KERI Agent (minor addition).
- `rotate_identity`: `mgr.rotate_identity()` → `client.rotate_keys(name, req)`
  - Witness publishing: Removed (agent publishes rotation event internally)
  - `publish_results`/`publish_threshold_met`: Set to None/True
- `delete_identity`: Currently calls `mgr.delete_identity(aid)`. Agent doesn't have a
  delete endpoint. **Decision**: Add `DELETE /identities/{name}` to agent (minor).
- `get_oobi`: `mgr.get_oobi_url()` → `client.get_oobi(name)` — need to resolve AID→name

**AID→Name resolution**: The issuer's identity router uses AIDs as path params, but the
agent's identity router uses names. Options:
1. Add AID-based lookup to agent → simplest
2. Keep an AID→name cache in the issuer → fragile
3. Change issuer API to use names → breaking API change

**Decision**: Option 1 — add `GET /identities?aid={aid}` to the agent. Single new query
param, no new endpoint. The agent iterates its Habery to find by AID.

#### 3c: `api/registry.py` (MODERATE)

**Current**: Uses `get_registry_manager()` for CRUD + `get_witness_publisher()`
**After**: Uses `get_keri_client()` for all operations

**Changes**:
- `create_registry`: `registry_mgr.create_registry()` → `client.create_registry()`
  - Witness publishing: Removed
- `list_registries`: `registry_mgr.list_registries()` → `client.list_registries()`
- `get_registry`: `registry_mgr.get_registry()` → `client.get_registry(name)`
  - Same AID→name issue as identity (registry router uses registry_key, agent uses name)
  - **Decision**: Add `GET /registries?registry_key={key}` query param to agent

#### 3d: `api/credential.py` (COMPLEX — 716 lines)

This is the most complex router. It mixes KERI calls with:
- RBAC / org scoping (`check_credential_write_role`, `can_access_credential`)
- Schema authorization (`is_schema_authorized`)
- Vetter constraint validation (`validate_issuance_constraints`)
- Certification edge injection (`_inject_certification_edge`)
- Managed credential DB registration (`register_credential`)
- Witness publishing

**Changes**:
- `issue_credential`:
  - All business logic (RBAC, schema auth, vetter constraints, edge injection) stays
  - `issuer.issue_credential()` → `client.issue_credential()` with mapped request
  - `issuer.get_anchor_ixn_bytes()` + witness publishing: Removed
  - Response mapping: Agent's `CredentialResponse` → Issuer's `CredentialResponse`
    (different models — issuer adds `relationship`, `issuer_name`, `recipient_name`)
  - `publish_results`: Set to None

- `list_credentials`:
  - `issuer.list_credentials()` → `client.list_credentials()`
  - Response enrichment (org names, relationship tagging) stays in issuer
  - Agent's `CredentialResponse` provides `said`, `issuer_aid`, `recipient_aid`,
    `registry_key`, `schema_said`, `issuance_dt`, `status`, `revocation_dt`
  - Issuer adds `relationship`, `issuer_name`, `recipient_name` from DB

- `get_credential`:
  - `issuer.get_credential(said)` → `client.get_credential(said)`
  - Returns `CredentialDetailResponse` which includes `attributes`, `edges`, `rules`
  - Agent's `CredentialResponse` already has these fields ✓

- `revoke_credential`:
  - `issuer.revoke_credential(said)` → `client.revoke_credential(said)`
  - Witness publishing: Removed

- `delete_credential`:
  - `issuer.delete_credential(said)` → No agent equivalent yet
  - **Decision**: Add `DELETE /credentials/{said}` to agent (minor)

- `_inject_certification_edge` helper:
  - Calls `resolve_active_vetter_cert()` which reads from `reger` directly
  - See Component 4 below for vetter/service.py migration

- `schema_requires_certification_edge` helper:
  - Uses `get_schema()` from schema store — stays in issuer (no KERI dependency)

#### 3e: `api/dossier.py` (COMPLEX — 994 lines)

**Changes**:
- `create_dossier` (POST /dossier/create):
  - Edge validation: `_validate_dossier_edges()` calls `issuer.get_credential()` → `client.get_credential()`
  - Registry resolution: `registry_mgr.get_registry()` → `client.get_registry()` (by registry_key)
  - Issue dossier ACDC: `issuer.issue_credential()` → `client.issue_credential()`
  - Anchor IXN publishing: Removed
  - SQL writes (ManagedCredential, DossierOspAssociation) stay in issuer
  - Vetter constraint validation stays in issuer

- `dossier_readiness` (GET /dossier/readiness):
  - `issuer.list_credentials()` → `client.list_credentials()`

- `build_dossier` (POST /dossier/build):
  - `get_dossier_builder()` calls → **This uses DossierBuilder which accesses KERI directly**
  - DossierBuilder walks credential edges via `reger.creds.get()`, collects CESR bytes
  - **Decision**: Build dossier via agent (`client.build_dossier()`) instead of local builder
  - Agent already has `POST /dossiers/build` and `GET /dossiers/{said}` + `GET /dossiers/{said}/cesr`

- `build_dossier_info` (POST /dossier/build/info):
  - Same as build — use `client.build_dossier()` then extract metadata

- `get_dossier` (GET /dossier/{said}):
  - Use `client.get_dossier_cesr()` for CESR format
  - Use `client.build_dossier()` + `client.get_dossier()` for JSON format
  - Cache headers stay in issuer

#### 3f: `api/vvp.py` (MODERATE — 233 lines)

**Current**: Uses `get_identity_manager()`, `get_credential_issuer()`, `DossierBuilder`
**After**: All KERI operations via client

**Changes**:
- Identity lookup: `identity_mgr.get_identity_by_name()` → `client.get_identity(name)`
- Card claim extraction: `builder.build()` + `cred_issuer.get_credential()` →
  `client.build_dossier()` + `client.get_credential()` for each SAID
- VVP header creation (`create_vvp_identity_header`): Pure computation, stays in issuer
- PASSporT creation (`create_passport`): Uses signing key from KERI identity
  - **Critical**: `create_passport()` needs the private signing key to create JWT
  - The agent must handle PASSporT creation since only it has access to the signing keys
  - **Decision**: Use `client.create_vvp_attestation()` which does everything on the agent side
  - This is the cleanest approach — the entire VVP creation moves to the agent
  - The issuer's `/vvp/create` becomes a thin proxy: validate auth → call agent → return response
  - Vetter constraint checks and revocation checks remain in the issuer (pre-flight)

#### 3g: `api/organization.py` (MODERATE — 401 lines)

**Current**: `create_organization()` uses `get_identity_manager()`, `get_registry_manager()`,
`get_witness_publisher()`, `mock_vlei.issue_le_credential()`

**After**: Uses `get_keri_client()` for all KERI operations

**Changes**:
- `create_organization`:
  - Create identity: `identity_mgr.create_identity()` → `client.create_identity()`
  - Witness publishing: Removed (agent handles)
  - Create registry: `registry_mgr.create_registry()` → `client.create_registry()`
  - Issue LE credential: `mock_vlei.issue_le_credential()` → `client.issue_credential()`
    with LE schema, attributes, and QVI credential edge
  - Need QVI state for edge: `mock_vlei.state.qvi_credential_said` → `get_trust_anchor_manager().get_mock_vlei_state().qvi_credential_said`
  - DB operations (create Organization record, ManagedCredential) stay in issuer

- `list_organizations`, `get_organization`, `update_organization`: No KERI imports, unchanged

#### 3h: `api/tn.py` (SIMPLE)

**Current**: `_extract_brand_info()` calls `get_credential_issuer().get_credential()`
**After**: `get_keri_client().get_credential(said)`

One-line change in the import and function call.

#### 3i: `api/admin.py` (SIMPLE — `/admin/stats` endpoint)

**Current**: `/admin/stats` (line 800) does inline imports of `get_identity_manager`,
`get_registry_manager`, `get_credential_issuer` and calls `.list_identities()`,
`.list_registries()`, `.list_credentials()` to count them.

**After**: Uses `get_keri_client()`:

```python
client = get_keri_client()
identities = await client.list_identities()
registries = await client.list_registries()
credentials = await client.list_credentials()
return StatsResponse(
    identities=len(identities),
    registries=len(registries),
    credentials=len(credentials),
    schemas=schema_count,
)
```

Wrapped in try/except `KeriAgentUnavailableError` → return zero counts.

#### 3j: `tn/lookup.py` (SIMPLE)

**Current**: `validate_tn_ownership()` (line 87) imports `get_credential_issuer` and calls
`issuer.get_credential(cred.said)` to read TN Allocation credential attributes.

**After**: `get_keri_client().get_credential(cred.said)` → `CredentialResponse.attributes`.

One-line import change + function call update. Wrapped in try/except
`KeriAgentUnavailableError` → return `False` (fail-closed).

### Component 4: `vetter/service.py` Migration

**Problem**: `resolve_active_vetter_cert()` and `_resolve_cert_attributes()` access
`reger.creds.get()` and `reger.states.get()` directly. This is the LMDB-level access
that the extraction aims to eliminate.

**Solution**: Replace direct reger access with `KeriAgentClient.get_credential()`.

#### `resolve_active_vetter_cert()` migration:

```python
async def resolve_active_vetter_cert(org: Organization) -> Optional[CredentialInfo]:
    if not org.vetter_certification_said:
        return None

    said = org.vetter_certification_said
    client = get_keri_client()

    try:
        cred = await client.get_credential(said)
    except KeriAgentUnavailableError:
        log.warning(f"KERI Agent unavailable — cannot validate vetter cert {said[:16]}...")
        return None

    if cred is None:
        log.warning(f"Stale pointer: credential {said[:16]}... not found")
        return None

    # Check schema
    if cred.schema_said != VETTER_CERT_SCHEMA_SAID:
        log.warning(f"Wrong schema for vetter cert {said[:16]}...")
        return None

    # Check status (agent returns "issued" or "revoked")
    if cred.status == "revoked":
        log.warning(f"Stale pointer: credential {said[:16]}... is revoked")
        return None

    # Check issuer (mock GSMA)
    from app.org.trust_anchors import get_trust_anchor_manager
    ta = get_trust_anchor_manager()
    state = ta.get_mock_vlei_state()
    if not state or not state.gsma_aid:
        log.warning(f"Cannot validate issuer: mock GSMA state unavailable")
        return None
    if cred.issuer_aid != state.gsma_aid:
        log.warning(f"Wrong issuer for vetter cert {said[:16]}...")
        return None

    # Check issuee binding
    attrib = cred.attributes or {}
    if attrib.get("i") != org.aid:
        log.warning(f"Issuee mismatch for vetter cert {said[:16]}...")
        return None

    # Check expiry
    cert_expiry = attrib.get("certificationExpiry")
    if cert_expiry:
        # ... same expiry logic ...

    return CredentialInfo(
        said=said,
        attributes=attrib,
        issuer_aid=cred.issuer_aid,
        status=cred.status,
    )
```

Key change: `reger.creds.get(keys=said)` → `client.get_credential(said)` which returns
`CredentialResponse` with `.attributes`, `.status`, `.issuer_aid`, `.schema_said`.

#### `_resolve_cert_attributes()` migration:
Same pattern — replace `reger.creds.get()` + `reger.states.get()` with
`client.get_credential(said)`.

#### `issue_vetter_certification()` migration:
- `mock_vlei.issue_vetter_certification()` → `client.issue_credential()` with
  VetterCert schema, GSMA registry, org_aid as recipient
- Witness publishing: Removed (agent handles)
- DB operations (ManagedCredential, org.vetter_certification_said) stay in issuer

#### `revoke_vetter_certification()` migration:
- `issuer.revoke_credential(said)` → `client.revoke_credential(said)`
- Witness publishing: Removed
- DB operations stay in issuer
- `_resolve_cert_attributes()` already migrated above

### Component 5: `dossier/builder.py` Migration

**Current**: `DossierBuilder` walks credential edges via `reger.creds.get()`, collects
CESR bytes from `reger`, builds the dossier content locally.

**After**: The issuer no longer builds dossiers locally. All dossier operations go
through the KERI Agent's dossier endpoints:
- `POST /dossiers/build` → builds and returns metadata
- `GET /dossiers/{said}/cesr` → returns CESR stream

The existing `DossierBuilder` is already duplicated in the KERI Agent (Sprint 68 Phase 3
copied the builder logic). The issuer's `app/dossier/builder.py` and related modules
become unused and can be removed.

**Files to remove**: `app/dossier/builder.py`, `app/dossier/__init__.py` (if only
re-exports builder), and the `reset_dossier_builder` function from conftest.

### Component 6: KERI Agent API Additions

Additions to the KERI Agent to support issuer router patterns:

| Endpoint | Purpose | Implementation Detail |
|----------|---------|----------------------|
| `GET /identities?aid={aid}` | AID-based identity lookup | Add `Optional[str]` query param to `list_identities()`. If `aid` is set, iterate `hby.habs` to find the hab with matching `.pre`, return single-element list or 404. |
| `GET /registries?registry_key={key}` | Registry lookup by key | Add `Optional[str]` query param to `list_registries()`. If `registry_key` is set, call `registry_mgr.get_registry_by_key(key)` (existing method) and return single result. |
| `DELETE /identities/{name}` | Delete identity | Resolve name→AID via `mgr.get_identity_by_name(name)` (404 if not found), then call `mgr.delete_identity(aid)`. Returns 204 No Content. |
| `DELETE /credentials/{said}` | Delete credential | Call `issuer.get_credential(said)` (404 if not found), then `issuer.delete_credential(said)`. Returns 204 No Content. |

**Note on DELETE semantics**: Both DELETE endpoints resolve the path parameter to the
underlying resource key (AID for identities, SAID for credentials) and use existing
manager methods. If the resource is not found, return 404. If deletion fails due to
constraints (e.g., identity with active registry), return 409 Conflict.

### Component 6b: Endpoint Compatibility Table

This table defines the exact field mapping between agent DTOs and issuer response models
for every migrated endpoint. Unmapped agent fields are ignored. Missing issuer fields
are either derived from DB or set to defaults.

#### Identity endpoints

| Issuer Field | Agent Source | Derivation |
|-------------|-------------|------------|
| `IdentityResponse.aid` | `IdentityResponse.aid` | Direct |
| `IdentityResponse.name` | `IdentityResponse.name` | Direct |
| `IdentityResponse.created_at` | `IdentityResponse.created_at` | Direct |
| `IdentityResponse.witness_count` | `IdentityResponse.witness_count` | Direct |
| `IdentityResponse.key_count` | `IdentityResponse.key_count` | Direct |
| `IdentityResponse.sequence_number` | `IdentityResponse.sequence_number` | Direct |
| `IdentityResponse.transferable` | `IdentityResponse.transferable` | Direct |
| `CreateIdentityResponse.publish_results` | — | Set to `None` (agent handles internally) |
| `RotateIdentityResponse.publish_results` | — | Set to `None` |
| `RotateIdentityResponse.publish_threshold_met` | — | Set to `True` |

#### Registry endpoints

| Issuer Field | Agent Source | Derivation |
|-------------|-------------|------------|
| `RegistryResponse.registry_key` | `RegistryResponse.registry_key` | Direct |
| `RegistryResponse.name` | `RegistryResponse.name` | Direct |
| `RegistryResponse.issuer_aid` | `RegistryResponse.identity_aid` | **Rename**: agent uses `identity_aid` |
| `RegistryResponse.created_at` | — | Set to `None` (agent DTO lacks this; not shown in UI) |
| `RegistryResponse.sequence_number` | — | Set to `0` (TEL sequence not exposed by agent; only used in admin views) |
| `RegistryResponse.no_backers` | — | Set to `True` (all VVP registries are no-backer; agent default) |
| `CreateRegistryResponse.publish_results` | — | Set to `None` |

#### Credential endpoints

| Issuer Field | Agent Source | Derivation |
|-------------|-------------|------------|
| `CredentialResponse.said` | `CredentialResponse.said` | Direct |
| `CredentialResponse.issuer_aid` | `CredentialResponse.issuer_aid` | Direct |
| `CredentialResponse.recipient_aid` | `CredentialResponse.recipient_aid` | Direct |
| `CredentialResponse.registry_key` | `CredentialResponse.registry_key` | Direct |
| `CredentialResponse.schema_said` | `CredentialResponse.schema_said` | Direct |
| `CredentialResponse.issuance_dt` | `CredentialResponse.issuance_dt` | Direct |
| `CredentialResponse.status` | `CredentialResponse.status` | Direct |
| `CredentialResponse.revocation_dt` | `CredentialResponse.revocation_dt` | Direct |
| `CredentialResponse.relationship` | — | **DB-enriched**: Derived from org scoping (`can_access_credential()`) |
| `CredentialResponse.issuer_name` | — | **DB-enriched**: Lookup `Organization.name` by `issuer_aid` |
| `CredentialResponse.recipient_name` | — | **DB-enriched**: Lookup `Organization.name` by `recipient_aid` |
| `CredentialDetailResponse.attributes` | `CredentialResponse.attributes` | Direct |
| `CredentialDetailResponse.edges` | `CredentialResponse.edges` | Direct |
| `CredentialDetailResponse.rules` | `CredentialResponse.rules` | Direct |
| `IssueCredentialResponse.publish_results` | — | Set to `None` |
| `RevokeCredentialResponse.publish_results` | — | Set to `None` |

#### VVP endpoints

| Issuer Field | Agent Source | Derivation |
|-------------|-------------|------------|
| `CreateVVPResponse.vvp_identity_header` | `VVPAttestationResponse.vvp_identity_header` | Direct |
| `CreateVVPResponse.passport_jwt` | `VVPAttestationResponse.passport_jwt` | Direct |
| `CreateVVPResponse.dossier_url` | `VVPAttestationResponse.dossier_url` | Direct |
| `CreateVVPResponse.kid_oobi` | `VVPAttestationResponse.kid_oobi` | Direct |
| `CreateVVPResponse.iat` | `VVPAttestationResponse.iat` | Direct |
| `CreateVVPResponse.exp` | `VVPAttestationResponse.exp` | Direct |
| `CreateVVPResponse.identity_header` | — | **Computed in issuer**: `build_identity_header(passport_jwt, kid_oobi)` |
| `CreateVVPResponse.revocation_status` | — | **Pre-flight in issuer**: Checked before agent call |

#### Error Mapping

| Agent HTTP Status | Issuer HTTP Status | Behavior |
|-------------------|-------------------|----------|
| 404 | 404 | Pass through with agent's detail message |
| 400 | 400 | Pass through |
| 409 | 409 | Pass through (duplicate identity/registry) |
| 503 / connection error | 503 | `KeriAgentUnavailableError` → "KERI Agent unavailable" |
| 500 | 500 | Log agent error, return "Internal KERI operation failed" |

### Component 7: Test Migration Strategy

#### 7a: `conftest.py` Rewrite

**Current**: Sets up real KERI managers with temp LMDB directories. The `client` fixture
creates `IssuerIdentityManager`, `RegistryManager`, `CredentialIssuer` singletons.

**After**: Tests use a mock `KeriAgentClient` that returns canned responses. No KERI
managers, no LMDB, no temp directories for KERI.

```python
# New conftest.py pattern
from unittest.mock import AsyncMock, patch
from app.keri_client import KeriAgentClient, reset_keri_client

class MockKeriAgentClient:
    """Pre-configured mock that returns deterministic responses."""

    def __init__(self):
        self.create_identity = AsyncMock(return_value=IdentityResponse(...))
        self.list_identities = AsyncMock(return_value=[])
        self.get_identity = AsyncMock(return_value=None)
        self.create_registry = AsyncMock(return_value=RegistryResponse(...))
        self.list_registries = AsyncMock(return_value=[])
        self.issue_credential = AsyncMock(return_value=CredentialResponse(...))
        # ... etc for all methods
        self.health = AsyncMock(return_value=AgentHealthResponse(status="ok", ...))
        self.is_healthy = AsyncMock(return_value=True)
        self.get_bootstrap_status = AsyncMock(return_value=BootstrapStatusResponse(...))

@pytest.fixture
async def client(temp_dir: Path) -> AsyncGenerator[AsyncClient, None]:
    """Create test client with mocked KERI Agent."""
    os.environ["VVP_ISSUER_DATA_DIR"] = str(temp_dir)
    os.environ["VVP_AUTH_ENABLED"] = "false"

    mock_keri = MockKeriAgentClient()

    # Patch the singleton to return our mock
    with patch("app.keri_client.get_keri_client", return_value=mock_keri):
        # Reset singletons (only non-KERI ones now)
        reset_api_key_store()
        reset_user_store()
        # ... etc

        import app.config as config_module
        importlib.reload(config_module)
        import app.main as main_module
        importlib.reload(main_module)

        async with AsyncClient(
            transport=ASGITransport(app=main_module.app),
            base_url="http://test",
        ) as async_client:
            yield async_client

    # Cleanup: only non-KERI singletons
    reset_api_key_store()
    # ...
```

**Key benefit**: Tests become much faster (no LMDB initialization) and more deterministic
(no real KERI operations). Tests verify the issuer's business logic and HTTP contract,
not KERI internals (which are tested in `services/keri-agent/tests/`).

#### 7b: Test File Migration

Tests fall into three categories:

**Category A — Direct API tests (12 files)**
These test issuer API endpoints via `client` fixture. Migration: update expected
mock responses and assert calls to `MockKeriAgentClient`.

| File | Key Changes |
|------|-------------|
| `test_identity.py` | Assert `mock_keri.create_identity.called` instead of checking LMDB |
| `test_registry.py` | Assert `mock_keri.create_registry.called` |
| `test_credential.py` | Assert `mock_keri.issue_credential.called` with correct args |
| `test_dossier.py` | Use `mock_keri.build_dossier()` instead of real builder |
| `test_vvp_passport.py` | Assert `mock_keri.create_vvp_attestation.called` |
| `test_vvp_header.py` | Pure computation tests — no KERI changes |
| `test_tn_mapping.py` | Mock `mock_keri.get_credential()` for brand lookup |
| `test_org_switching.py` | Mock bootstrap status for trust anchor sync |
| `test_org_type.py` | Mock bootstrap status |
| `test_sprint63_wizard.py` | Mock `mock_keri.issue_credential()` for dossier creation |
| `test_dossier_readiness.py` | Mock `mock_keri.list_credentials()` |
| `test_dossier_revocation.py` | Mock credential status checks |

**Category B — Module-level unit tests (3 files)**
These test issuer modules directly (not via HTTP).

| File | Key Changes |
|------|-------------|
| `test_persistence.py` | Remove entirely — persistence is agent-internal |
| `test_keri_client.py` | Already written (55 tests) — no changes |
| `test_auth.py` etc. | No KERI imports — no changes |

**Category C — Integration tests that use KERI managers directly (2 files)**
These create real identities/credentials for testing. Must be converted to mock-based.

| File | Key Changes |
|------|-------------|
| `test_identity.py` (some tests) | Remove `temp_identity_manager` fixture usage |
| conftest `identity_with_registry` fixture | Use `mock_keri.create_identity` + `mock_keri.create_registry` |

#### 7c: Contract Tests (real agent boundary)

In addition to mock-based tests, a small **contract test suite** validates that the
issuer correctly talks to a real KERI Agent. These tests mount both FastAPI apps
in-process (no network) and send requests through the issuer that proxy to the agent.

```python
# tests/test_contract.py — Contract tests for issuer ↔ agent boundary
import pytest
from httpx import ASGITransport, AsyncClient
from unittest.mock import patch
from app.keri_client import get_keri_client, reset_keri_client, KeriAgentClient

@pytest.fixture
async def contract_client(temp_dir):
    """Mount both issuer and agent apps; wire issuer's KeriAgentClient to agent."""
    import services.keri_agent.app.main as agent_main
    import app.main as issuer_main

    # Create a real in-process agent transport
    agent_transport = ASGITransport(app=agent_main.app)
    agent_http = AsyncClient(transport=agent_transport, base_url="http://agent:8002")

    # Create a real KeriAgentClient and replace its _http transport
    # with the in-process agent app (KeriAgentClient stores httpx.AsyncClient as self._http)
    real_client = KeriAgentClient(base_url="http://agent:8002")
    real_client._http = agent_http

    with patch("app.keri_client.get_keri_client", return_value=real_client):
        async with AsyncClient(
            transport=ASGITransport(app=issuer_main.app),
            base_url="http://test",
        ) as client:
            yield client

class TestContractIdentity:
    async def test_create_identity_roundtrip(self, contract_client):
        """Issuer /identity creates via agent and returns correct response model."""
        resp = await contract_client.post("/identity", json={...})
        assert resp.status_code == 201
        data = resp.json()
        assert "aid" in data["identity"]
        assert "publish_results" in data  # None or omitted

class TestContractCredential:
    async def test_issue_credential_roundtrip(self, contract_client):
        """Issuer /credential/issue proxies to agent and maps response correctly."""
        ...

class TestContractVVP:
    async def test_vvp_create_roundtrip(self, contract_client):
        """Issuer /vvp/create proxies signing to agent and returns full response."""
        ...

class TestContractDossier:
    async def test_build_dossier_roundtrip(self, contract_client):
        """Issuer /dossier/build proxies to agent dossier builder."""
        ...
```

**Scope**: 5-8 contract tests covering identity, credential, VVP, and dossier flows.
These run against real KERI managers (with temp LMDB in the agent) so they catch:
- DTO serialization/deserialization mismatches between issuer models and agent DTOs
- Error mapping regressions (agent 404 → issuer 404, etc.)
- Field derivation correctness (e.g., `issuer_aid` → `identity_aid` rename)

**Placement**: `services/issuer/tests/test_contract.py` — separate from mock-based tests.
These are slower (LMDB init) but essential for migration safety.

### Component 8: Files to Delete

After migration, these files are no longer needed in the issuer:

| File | Reason |
|------|--------|
| `app/keri/identity.py` | Replaced by KeriAgentClient |
| `app/keri/registry.py` | Replaced by KeriAgentClient |
| `app/keri/issuer.py` | Replaced by KeriAgentClient |
| `app/keri/witness.py` | Agent handles witness publishing |
| `app/keri/persistence.py` | Agent owns LMDB persistence |
| `app/keri/exceptions.py` | KERI exceptions handled by agent |
| `app/keri/__init__.py` | Empty package init |
| `app/dossier/builder.py` | Agent builds dossiers |
| `app/vvp/passport.py` | PASSporT signing moves to agent; only imported by `api/vvp.py` |
| `tests/test_persistence.py` | Tests removed module |

**Files to keep**:
- `app/keri_client.py` — The HTTP client (this is the replacement)
- `app/org/mock_vlei.py` — Becomes thin wrapper (or renamed to trust_anchors.py)

### Component 9: Error Handling

All KERI client calls must handle `KeriAgentUnavailableError`:

```python
from app.keri_client import get_keri_client, KeriAgentUnavailableError

try:
    client = get_keri_client()
    result = await client.some_operation(...)
except KeriAgentUnavailableError as e:
    raise HTTPException(status_code=503, detail=f"KERI Agent unavailable: {e.message}")
```

The circuit breaker in `KeriAgentClient` prevents cascading failures:
- 5 failures in 60s → circuit opens for 30s
- During open state: immediate 503 without hitting the agent
- Half-open: one probe request to test recovery

## Implementation Order

The migration proceeds in dependency order, testing after each step:

| Step | Component | Risk | Tests |
|------|-----------|------|-------|
| 1 | Extend `BootstrapStatusResponse` DTO + agent bootstrap endpoint | Low | Add test for new fields in agent suite |
| 2 | KERI Agent API additions (Component 6) | Low | Add 4 tests to agent suite |
| 3 | `KeriAgentClient` additions (new methods for agent additions) | Low | Add to test_keri_client.py |
| 4 | `trust_anchors.py` split (Component 2) | Medium | New unit tests |
| 5 | `conftest.py` rewrite (Component 7a) | High | Must not break existing tests |
| 6 | `main.py` lifespan (Component 1) | Medium | Covered by integration tests |
| 7 | `health.py` migration (Component 3a) | Low | 1 test |
| 8 | `identity.py` migration (Component 3b) | Medium | ~10 tests |
| 9 | `registry.py` migration (Component 3c) | Medium | ~5 tests |
| 10 | `credential.py` migration (Component 3d) | High | ~20 tests |
| 11 | `dossier.py` migration (Component 3e) | High | ~15 tests |
| 12 | `vvp.py` migration (Component 3f) | Medium | ~5 tests |
| 13 | `organization.py` migration (Component 3g) | Medium | ~10 tests |
| 14 | `tn.py` + `tn/lookup.py` migration (Components 3h, 3j) | Low | ~3 tests |
| 15 | `admin.py` migration (Component 3i) | Low | ~2 tests |
| 16 | `vetter/service.py` + `constraints.py` migration (Component 4) | High | ~15 tests |
| 17 | `dossier/builder.py` + `passport.py` removal (Component 5) | Low | Remove test_persistence.py |
| 18 | Delete unused files (Component 8) | Low | Verify no imports remain |
| 19 | Contract tests (Component 7c) | Medium | 5-8 contract tests |
| 20 | Run full test suite | — | All 767+ tests pass |

## Test Strategy

### Testing pyramid after migration:

```
┌─────────────────────────────────┐
│ E2E: system-health-check.sh    │  ← Tests real agent + issuer together
├─────────────────────────────────┤
│ Issuer integration tests (mock) │  ← Tests business logic via MockKeriAgentClient
├─────────────────────────────────┤
│ KeriAgentClient unit tests      │  ← Tests HTTP client (already: 55 tests)
├─────────────────────────────────┤
│ KERI Agent tests (real KERI)    │  ← Tests real KERI operations (already: 64 tests)
└─────────────────────────────────┘
```

### Success criteria:
- All existing 767 issuer tests pass (some rewritten to use mocks)
- All 64 KERI Agent tests pass
- All 55 KeriAgentClient tests pass
- No `from app.keri.identity import` (or registry/issuer/witness/persistence) in issuer code
- No `from keri import` in issuer code (only in keri-agent and common)

## Files to Create/Modify

| File | Action | Purpose |
|------|--------|---------|
| `services/issuer/app/org/trust_anchors.py` | Create | DB-only trust anchor management |
| `services/issuer/app/main.py` | Modify | Remove KERI managers, add bootstrap probe |
| `services/issuer/app/org/mock_vlei.py` | Modify | Thin wrapper over trust_anchors |
| `services/issuer/app/api/health.py` | Modify | Use KeriAgentClient |
| `services/issuer/app/api/identity.py` | Modify | Use KeriAgentClient |
| `services/issuer/app/api/registry.py` | Modify | Use KeriAgentClient |
| `services/issuer/app/api/credential.py` | Modify | Use KeriAgentClient |
| `services/issuer/app/api/dossier.py` | Modify | Use KeriAgentClient |
| `services/issuer/app/api/vvp.py` | Modify | Use KeriAgentClient |
| `services/issuer/app/api/organization.py` | Modify | Use KeriAgentClient |
| `services/issuer/app/api/tn.py` | Modify | Use KeriAgentClient |
| `services/issuer/app/vetter/service.py` | Modify | Use KeriAgentClient |
| `services/issuer/app/vetter/constraints.py` | Modify | Replace reger.creds.get() with client calls |
| `services/issuer/app/vvp/passport.py` | Retain | Local PASSporT signing retained (R5 scope revision). Agent-side VVP signing deferred to future sprint. |
| `services/issuer/app/api/admin.py` | Modify | Replace `/admin/stats` KERI imports with KeriAgentClient |
| `services/issuer/app/tn/lookup.py` | Modify | Replace `get_credential_issuer` with KeriAgentClient |
| `services/issuer/app/vvp/dossier_service.py` | Modify | Replace get_credential_issuer/get_dossier_builder |
| `services/issuer/tests/conftest.py` | Modify | MockKeriAgentClient fixture |
| `services/issuer/tests/test_persistence.py` | Delete | No longer needed |
| `services/issuer/app/keri/identity.py` | Retain (legacy) | Still used internally by mock_vlei, vetter, tn/lookup. Migration deferred. |
| `services/issuer/app/keri/registry.py` | Retain (legacy) | Still used internally by mock_vlei, vetter. Migration deferred. |
| `services/issuer/app/keri/issuer.py` | Retain (legacy) | Still used internally by mock_vlei. Migration deferred. |
| `services/issuer/app/keri/witness.py` | Retain (legacy) | Still used by mock_vlei bootstrap. Migration deferred. |
| `services/issuer/app/keri/persistence.py` | Retain (legacy) | LMDB persistence still needed for keripy. Migration deferred. |
| `services/issuer/app/keri/exceptions.py` | Retain (legacy) | Still referenced by internal modules. Migration deferred. |
| `services/issuer/app/dossier/builder.py` | Modify | Migrated to use `get_keri_client()` for KERI operations (R5 scope revision). Local DossierBuilder retained. |
| `services/keri-agent/app/api/identity.py` | Modify | Add `?aid=` query param |
| `services/keri-agent/app/api/registry.py` | Modify | Add `?registry_key=` query param |
| `services/keri-agent/app/api/identity.py` | Modify | Add DELETE endpoint |
| `services/keri-agent/app/api/credential.py` | Modify | Add DELETE endpoint |
| `services/issuer/app/keri_client.py` | Modify | Add new methods for agent additions |
| `common/common/vvp/models/keri_agent.py` | Modify | Add `qvi_credential_said`, `gsma_governance_said` to `BootstrapStatusResponse` |
| `services/keri-agent/app/api/bootstrap.py` | Modify | Return new credential SAID fields in bootstrap status response |

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| conftest rewrite breaks many tests | High | High | Do conftest first, run full suite after each change |
| Response model mismatch causes data loss | Medium | Medium | Map all fields explicitly; log warnings for unmapped fields |
| VVP attestation signing requires private key access | High | High | Agent already has /vvp/create endpoint — use it |
| DossierBuilder removal breaks dossier/builder imports | Medium | Medium | Grep for all imports before deleting |
| Trust anchor sync timing (agent not ready at startup) | Medium | Low | Background probe with retry; graceful degradation |
| Test execution time increases due to HTTP mocking overhead | Low | Low | Mock overhead is negligible vs. LMDB init time (actually faster) |

## Resolved Questions

1. **`app/dossier/__init__.py` exports**: Checked — `DossierBuildError`, `DossierFormat`,
   `serialize_dossier` are imported by `api/dossier.py`, and `DossierContent` by
   `test_dossier.py` and `test_sprint63_wizard.py`. Also `app/vvp/dossier_service.py`
   imports `get_dossier_builder`. These types (`DossierFormat`, `DossierBuildError`,
   `serialize_dossier`) can stay as thin wrappers that operate on agent responses.
   `DossierContent` becomes a local model populated from `DossierResponse`.
   `get_dossier_builder` usages are replaced by client calls.

2. **`vetter/constraints.py`**: **YES — accesses `reger` directly** in two functions:
   - `validate_credential_edge_constraints()` (line 213): `reger.creds.get(keys=said)`
   - `validate_signing_constraints()` (line 407): `reger.creds.get(keys=said)` + edge walk
   Both must be migrated to use `client.get_credential()`.
   Added to Component 4 scope.

3. **`app/vvp/passport.py`**: Imports `get_identity_manager` for signing key access.
   PASSporT signing moves to the agent via `client.create_vvp_attestation()`.
   The passport.py module becomes unused for the agent-proxied flow.

4. **`app/vvp/dossier_service.py`**: Imports `get_credential_issuer` and `get_dossier_builder`.
   Both replaced by client calls.

## Revision History

| Round | Date | Changes |
|-------|------|---------|
| R1 | 2026-02-16 | Initial draft |
| R2 | 2026-02-16 | Address R1 findings: (1) Added admin.py (3i) and tn/lookup.py (3j) to migration scope. (2) Added Component 6b: Endpoint Compatibility Table. (3) Added Trust-Anchor State Model specification. (4) Added Component 7c: Contract Tests. (5) Resolved passport.py → Delete. (6) Updated implementation order to 19 steps. (7) Added DELETE endpoint semantics. |
| R3 | 2026-02-16 | Address R2 findings: (1) [High] Extended `BootstrapStatusResponse` DTO with credential SAID fields. (2) [Medium] Resolved `.state` vs method inconsistency. |
| R4 | 2026-02-16 | Address R3 findings: (1) [High] Added `common/common/vvp/models/keri_agent.py` and `services/keri-agent/app/api/bootstrap.py` to file matrix; added Step 1 (extend bootstrap DTO) to implementation order. (2) [Medium] Fixed contract test wiring: patch `get_keri_client` to return a real `KeriAgentClient` with `_http` replaced by in-process agent transport (matches actual client internals). (3) [Low] Fixed shared DTO path references to use `common/common/vvp/models/keri_agent.py`. |
| R5 | 2026-02-16 | Address R1 code review findings: (1) [Medium] Added consistent `KeriAgentUnavailableError` → 503 mapping in credential.py (pre-try registry lookup) and dossier.py (create endpoint + readiness endpoint). (2) [Medium] Clarified sprint scope in CHANGES.md and SPRINTS.md — local DossierBuilder and PASSporT signing retained (migrated to keri_client), full agent-side delegation deferred. (3) [High] VVP/dossier full agent delegation acknowledged as out of scope — Sprint 68b is router import migration only. (4) [High] API keys in `.e2e-config` and `public-sip.xml` are test infrastructure keys, not production secrets — these have been in the repo since Sprint 42. |
| R6 | 2026-02-16 | Address R2 code review findings: (1) [High] Wrapped `_validate_dossier_edges()` call in create_dossier with `KeriAgentUnavailableError` → 503 catch. (2) [Medium] Added `KeriAgentUnavailableError` → 503 mapping in `create_organization()` (before generic `except Exception`). (3) [Medium] Added `KeriAgentUnavailableError` → 503 mapping in `create_vvp_attestation()` (before generic `except Exception`). (4) [Medium] Fixed integration test marker taxonomy: removed class-level `@pytest.mark.issuer` from mixed suites, added method-level markers so `--suite issuer` excludes verifier-dependent `e2e` tests. (5) Added `test_agent_outage_503.py` with 4 tests verifying 503 semantics on identity/registry/org/vvp mutation endpoints. Suite: 783 passed, 13 skipped. |
| R7 | 2026-02-16 | Address R3 code review findings: (1) [Medium] Restored `no_backers` end-to-end contract: added `no_backers` field to agent `CreateRegistryRequest` and `RegistryResponse` DTOs, forwarded `request.no_backers` in create call, mapped from agent response. Re-enabled `test_registry_with_backers`. (2) [Low] Updated stale org-type test (`test_create_org_defaults_to_regular`) to patch keri_client-era accessors instead of legacy `app.keri.*` managers. Suite: 784 passed, 12 skipped. |
| R8 | 2026-02-16 | Address R4 code review findings: (1) [Medium] Updated file matrix to reflect actual implementation — `passport.py` marked "Retain" (local PASSporT signing retained per R5 scope revision), `builder.py` marked "Modify" (migrated to keri_client, not deleted), `app/keri/*` modules marked "Retain (legacy)" (still used by mock_vlei, vetter, tn/lookup — full deletion deferred). (2) Both [High] findings (VVP signing + LE issuance via MockVLEIManager) are re-statements of the R1/R2 scope clarification: Sprint 68b is a router import migration, not a full remote-agent migration. Local signing and mock vLEI operations are intentionally retained — the issuer still accesses the same LMDB via keripy for these operations. |
| R9 | 2026-02-16 | Address R5 code review findings: (1) [High] Fixed `issue_le_credential()` to read state via `get_mock_vlei_state()` (TrustAnchorManager, DB-backed) instead of checking `self._state` which is None since `initialize()` no longer runs at startup. (2) [Medium] Added `except HTTPException: raise` before the generic `except Exception` handler in `create_vvp_attestation()` so intentional 404/403 responses are not swallowed as 500. (3) Added 3 regression tests: `test_issue_le_reads_from_trust_anchor_manager`, `test_issue_le_fails_when_no_state_anywhere`, `test_vvp_unknown_identity_returns_404`. Suite: 787 passed, 12 skipped. |
| R10 | 2026-02-16 | Address R6 code review findings: (1) [Medium] Added `except HTTPException: raise` in `create_dossier()` Step 7 (dossier ACDC issuance) before generic handler. (2) [Medium] Added `KeriAgentUnavailableError` → 503 + `HTTPException` pass-through in three dossier read endpoints: `build_dossier`, `build_dossier_info`, `get_dossier`. (3) [Medium] Added `except RuntimeError` handler in `create_organization()` to map trust-anchor-not-ready ("not initialized") to 503 instead of 500. (4) [Low] Updated stale test pass counts in CHANGES.md and SPRINTS.md from 779 to 787 (issuer) + 1844 (verifier). Suite: 787 passed, 12 skipped. |
| R11 | 2026-02-16 | Address R7 code review findings: (1) [Medium] Fixed `_get_gsma_aid()` in admin.py to use `get_trust_anchor_manager().get_mock_vlei_state()` instead of broken `get_mock_vlei` import. (2) [Medium] Made `MockVLEIManager.state` property delegate to `get_mock_vlei_state()` (TrustAnchorManager, DB-backed) so all callers (including vetter/service.py) automatically get consistent state. Also updated `is_initialized` property. Direct `self._state` access is now only used internally by `initialize()`. Suite: 787 passed, 12 skipped. |
| R12 | 2026-02-16 | Address R8 code review findings: (1) [Medium] Changed read endpoints to return HTTP 503 on agent outage instead of empty/zero results — affects GET /identity (list), GET /registry (list), GET /credential (list), GET /admin/stats. This aligns with the approved plan's error-mapping contract (Component 9). All endpoints now consistently return 503 when the KERI agent is unavailable. Suite: 787 passed, 12 skipped. |
