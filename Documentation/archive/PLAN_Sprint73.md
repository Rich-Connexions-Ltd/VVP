# Sprint 73: Credential & Identity Cleanup — Cascade Delete and Bulk Purge

## Problem Statement

The current DELETE endpoints for credentials and identities only remove items from KERI Agent LMDB. This creates three problems:

1. **Zombie resurrection**: PostgreSQL seed tables (`keri_credential_seeds`, `keri_identity_seeds`) retain records for deleted items, so StateBuilder rebuilds them on every container restart. Deletion is effectively temporary.
2. **Orphan metadata**: The issuer's `managed_credentials` table retains ownership records for deleted credentials, causing phantom entries in org-scoped queries.
3. **No bulk cleanup**: The only way to remove test data en masse is `POST /admin/mock-vlei/reinitialize`, which is nuclear — it wipes ALL orgs, users, API keys, and TN mappings.

## Current State

### Delete Flow (credential)
```
Issuer DELETE /credential/{said}
  → KeriAgentClient.delete_credential(said)
    → KERI Agent DELETE /credentials/{said}
      → reger.creds.rem(said)      ✅ LMDB cleared
      → reger.cancs.rem(said)      ✅ LMDB cleared
      → keri_credential_seeds      ❌ NOT cleared (zombie on restart)
  → managed_credentials            ❌ NOT cleared (orphan metadata)
```

### Delete Flow (identity)
```
Issuer DELETE /identity/{aid}
  → KeriAgentClient.delete_identity(name)
    → KERI Agent DELETE /identities/{name}
      → hby.habs[pre] deleted      ✅ LMDB cleared
      → hby.prefixes.remove(pre)   ✅ LMDB cleared
      → keri_identity_seeds         ❌ NOT cleared (zombie on restart)
      → keri_rotation_seeds         ❌ NOT cleared (orphan rotations)
```

### Storage Layers

| Layer | Credentials | Identities | Cleared on DELETE? |
|-------|-------------|------------|-------------------|
| KERI Agent LMDB | `reger.creds`, `reger.cancs` | `hby.habs`, `hby.prefixes` | ✅ Yes |
| KERI Agent PostgreSQL | `keri_credential_seeds` | `keri_identity_seeds`, `keri_rotation_seeds` | ❌ No |
| Issuer PostgreSQL | `managed_credentials` | — | ❌ No |

## Proposed Solution

### Approach

Add delete methods to the existing `SeedStore` class, wire them into the KERI Agent delete operations, and have the Issuer API clean up its own `managed_credentials` table. For bulk cleanup, add admin endpoints that accept filters (org, schema, date range, name pattern) and cascade through all layers.

This approach was chosen because:
- It follows the existing architecture (SeedStore already handles all seed CRUD)
- It's minimally invasive — each existing delete method gains 1-2 extra calls
- The KERI Agent is the right place to own seed deletion (seeds are its concern)
- The Issuer is the right place to own managed_credentials deletion (multi-tenancy is its concern)

### Alternatives Considered

| Alternative | Pros | Cons | Why Rejected |
|-------------|------|------|--------------|
| Database triggers (ON DELETE CASCADE) | Automatic, no code changes | Seeds aren't FK-linked to LMDB state; can't cascade cross-DB | Architecture mismatch |
| Scheduled cleanup job | Non-blocking, background | Stale data persists between runs; adds operational complexity | Overkill for the problem |
| Mark-as-deleted flag | Non-destructive, auditable | Adds column to every table; StateBuilder must filter; UI must filter | More complexity than actual deletion |

### Detailed Design

#### Component 1: SeedStore Delete Methods

**Purpose**: Enable deletion of individual seeds from PostgreSQL.
**Location**: `services/keri-agent/app/keri/seed_store.py`

New methods on `SeedStore`:

```python
def delete_credential_seed(self, expected_said: str) -> bool:
    """Delete a credential seed by SAID. Returns True if deleted, False if not found."""

def delete_identity_seed(self, name: str) -> bool:
    """Delete an identity seed and its rotation seeds. Returns True if deleted."""

def delete_identity_seed_by_aid(self, aid: str) -> bool:
    """Delete an identity seed by AID (expected_aid) and its rotation seeds. Returns True if deleted."""

def delete_rotation_seeds_by_aid(self, aid: str) -> int:
    """Delete all rotation seeds for an identity by AID. Joins on keri_identity_seeds.expected_aid to find the identity_name, then deletes matching keri_rotation_seeds rows. Returns count deleted."""

def get_credential_seeds_by_issuer(self, identity_name: str) -> list[KeriCredentialSeed]:
    """Get all credential seeds issued by a specific identity."""

def get_credential_seeds_by_schema(self, schema_said: str) -> list[KeriCredentialSeed]:
    """Get all credential seeds for a specific schema."""
```

#### Component 2: KERI Agent Cascade Delete

**Purpose**: Wire seed deletion into existing KERI Agent delete operations.
**Locations**:
- `services/keri-agent/app/keri/issuer.py` — `CredentialIssuer.delete_credential()`
- `services/keri-agent/app/keri/identity.py` — `IssuerIdentityManager.delete_identity()`

Changes to `delete_credential()`:
```python
async def delete_credential(self, credential_said: str) -> bool:
    # ... existing LMDB deletion ...
    # NEW: Also delete seed so it won't rebuild on restart
    seed_store = get_seed_store()
    seed_store.delete_credential_seed(credential_said)
    return True
```

Changes to `delete_identity()`:
```python
async def delete_identity(self, aid: str) -> bool:
    # ... existing LMDB deletion (hby.habs, hby.prefixes) ...
    # NEW: Also delete seed and rotation seeds using the AID directly
    seed_store = get_seed_store()
    seed_store.delete_identity_seed_by_aid(aid)
    return True
```

#### Component 3: Issuer Cascade Delete

**Purpose**: Clean up `managed_credentials` when a credential is deleted.
**Location**: `services/issuer/app/api/credential.py` — `delete_credential()`

After successful KERI Agent deletion, delete the `ManagedCredential` row:
```python
# After: await client.delete_credential(said)
# NEW: Clean up issuer metadata
from app.db.models import ManagedCredential
db.query(ManagedCredential).filter(ManagedCredential.said == said).delete()
db.commit()
```

#### Component 4: KERI Agent Bulk Cleanup API

**Purpose**: Delete multiple credentials/identities by filter criteria.
**Location**: `services/keri-agent/app/api/admin.py` (new endpoints on existing admin router, or new router)

Endpoints:

```
POST /admin/cleanup/credentials
Body: {
    "saids": ["EAbc...", "EBcd..."],          // optional: explicit SAID list
    "issuer_identity_name": "acme-signing",   // optional: by issuer
    "schema_said": "EBfdc...",                 // optional: by schema
    "before": "2026-02-01T00:00:00Z",         // optional: by date
    "force": false,                            // if true, delete even if other creds depend on these (edge_saids)
    "dry_run": true                            // preview only
}
Response: {
    "deleted_count": 12,
    "deleted_saids": ["EAbc...", "EBcd...", ...],
    "failed": [],                              // items that failed to delete (with error reason)
    "blocked_saids": [],                       // credentials blocked due to dependents (when force=false)
    "dry_run": true
}

POST /admin/cleanup/identities
Body: {
    "names": ["test-id-1", "test-id-2"],      // optional: explicit name list
    "name_pattern": "test-*",                 // optional: glob pattern
    "metadata_type": "regular",               // optional: by metadata.type
    "before": "2026-02-01T00:00:00Z",         // optional: by date
    "cascade_credentials": false,             // if true, also delete credentials issued by these identities
    "force": false,                            // if true, delete trust-anchor identities too
    "dry_run": true
}
Response: {
    "deleted_count": 5,
    "deleted_names": ["test-id-1", ...],
    "failed": [],                              // items that failed to delete (with error reason)
    "blocked_names": [],                       // identities with credentials (if cascade_credentials=false)
    "cascaded_credential_count": 0,           // credentials also deleted (if cascade_credentials=true)
    "dry_run": true
}
```

The agent-side bulk endpoints accept either an explicit list of identifiers (for batch calls from the Issuer) or filter criteria (for direct use). They iterate over matching items, delete LMDB state + seed for each, and return a summary. The Issuer's bulk cleanup queries `managed_credentials` for matching SAIDs, then makes a **single** call to the KERI Agent bulk endpoint with the collected SAIDs, avoiding N+1 network calls.

#### Component 5: Issuer Bulk Cleanup API

**Purpose**: Admin-facing bulk cleanup that cascades through KERI Agent and Issuer metadata.
**Location**: `services/issuer/app/api/admin.py` (new endpoints)

```
POST /admin/cleanup/credentials
Body: {
    "organization_id": "uuid-...",            // optional: by org
    "schema_said": "EBfdc...",                // optional: by schema
    "before": "2026-02-01T00:00:00Z",        // optional: by date
    "dry_run": true
}

POST /admin/cleanup/identities
Body: {
    "organization_id": "uuid-...",            // optional: by org (matches identities used by this org)
    "name_pattern": "test-*",                 // optional: by name glob
    "cascade_credentials": false,             // cascade to credentials issued by these identities
    "force": false,                            // delete trust-anchor identities too
    "dry_run": true
}
```

These call the KERI Agent bulk endpoints, then clean up `managed_credentials` rows.

### Data Flow

**Single credential delete (fixed):**
```
Issuer DELETE /credential/{said}
  → KERI Agent: reger.creds.rem(said)        ✅
  → KERI Agent: seed_store.delete_credential_seed(said)  ✅ NEW
  → Issuer: managed_credentials.delete(said)  ✅ NEW
```

**Bulk credential cleanup:**
```
Issuer POST /admin/cleanup/credentials {org_id, schema, ...}
  → Query managed_credentials for matching SAIDs
  → Single call to KERI Agent POST /admin/cleanup/credentials {saids: [...]}
    → KERI Agent deletes LMDB + seeds for all SAIDs in batch
  → Delete managed_credentials rows in batch
  → Return summary
```

### Error Handling

- **Single deletes**: Seed deletion failures are logged but don't fail the overall delete (best-effort cleanup — the LMDB item is already gone)
- **Bulk cleanup partial failure**: The KERI Agent processes items one-by-one in a synchronous loop. If an individual item fails, the error is captured in the `failed` array with the item identifier and reason. Processing continues for remaining items. The HTTP response is always 200 with the summary — the `failed` array tells the caller which items need attention. This avoids ambiguity about what was deleted vs. not.
- **Issuer bulk cleanup**: Uses a DB transaction for the issuer-side `managed_credentials` deletes. If the KERI Agent call succeeds but the Issuer DB commit fails, the response includes a warning (credentials removed from KERI Agent but metadata orphaned — operator should retry).
- If KERI Agent is unavailable during bulk cleanup, return 503
- **Performance note**: The synchronous loop in the KERI Agent bulk handler is acceptable for test-data cleanup (hundreds of items). For production-scale bulk operations (thousands+), a background task/queue model would be needed — out of scope for this sprint.

### Test Strategy

1. **Unit tests for SeedStore delete methods** — verify rows actually removed from DB
2. **Integration tests for cascade** — delete credential, verify seed gone, simulate restart scenario
3. **Integration tests for identity cascade** — delete identity, verify identity + rotation seeds gone
4. **Issuer cascade test** — delete credential, verify managed_credential row gone
5. **Bulk cleanup tests** — filter by org, schema, date, dry-run mode
6. **Regression** — existing delete tests still pass

## Files to Create/Modify

| File | Action | Purpose |
|------|--------|---------|
| `services/keri-agent/app/keri/seed_store.py` | Modify | Add delete_credential_seed, delete_identity_seed, query helpers |
| `services/keri-agent/app/keri/issuer.py` | Modify | Cascade credential delete to seed store |
| `services/keri-agent/app/keri/identity.py` | Modify | Cascade identity delete to seed store |
| `services/keri-agent/app/api/admin.py` | Create | Bulk cleanup endpoints (credentials + identities) |
| `services/issuer/app/api/credential.py` | Modify | Cascade to managed_credentials on delete |
| `services/issuer/app/api/admin.py` | Modify | Add bulk cleanup admin endpoints |
| `services/keri-agent/tests/test_seed_store_delete.py` | Create | SeedStore delete method tests |
| `services/keri-agent/tests/test_cascade_delete.py` | Create | Cascade delete integration tests |
| `services/issuer/tests/test_cleanup.py` | Create | Bulk cleanup endpoint tests |

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Deleting a credential that other credentials depend on (edge references) | Medium | High | Bulk cleanup checks edge_saids for dependencies; refuses to delete if dependents exist (unless `force: true`) |
| Deleting trust-anchor identities (GLEIF, QVI, GSMA) | Low | Critical | Bulk cleanup refuses to delete identities with metadata_type in {mock_gleif, mock_qvi, mock_gsma} unless `force: true` |
| Deleting an identity that has issued credentials | Medium | High | By default, bulk identity cleanup blocks deletion if the identity has issued credentials (returns them in `blocked_names` with reason). `cascade_credentials: true` opt-in deletes the identity AND all its issued credentials. Uses `get_credential_seeds_by_issuer()` to discover dependents. |
| Seed deletion fails but LMDB deletion succeeds | Low | Low | Log warning; item won't be in LMDB but seed remains (harmless — rebuilds a credential that exists nowhere) |

## Revision History

| Round | Date | Changes |
|-------|------|---------|
| R1 | 2026-02-18 | Initial draft |
| R2 | 2026-02-18 | Per Gemini R1: (1) Bulk data flow uses single KERI Agent call with SAIDs list instead of N+1 pattern; (2) Identity delete uses `delete_identity_seed_by_aid(aid)` directly instead of name-based lookup; (3) Corrected file table — bulk endpoints in `admin.py` not credential/identity routers |
| R3 | 2026-02-18 | Per Gemini R2: (1) Identity deletion blocks if identity has issued credentials; `cascade_credentials: true` opt-in deletes identity + its credentials; (2) `delete_rotation_seeds` now uses AID (`delete_rotation_seeds_by_aid`) for consistent identifier usage |
| R4 | 2026-02-18 | Per Gemini R3: (1) Added `force` flag to both bulk endpoint request bodies; (2) Defined partial failure contract — `failed` array in response, always 200; (3) Added `organization_id` filter to Issuer identity cleanup endpoint; (4) Clarified rotation seed method uses join, not lookup; (5) Added performance note for large-scale operations |
