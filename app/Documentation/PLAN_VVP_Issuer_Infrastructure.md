# Implementation Plan: VVP Dossier/ACDC Creation Infrastructure

## Summary

Add credential issuance capabilities to VVP via a new VVP-Issuer service in a monorepo structure with shared code.

### Architectural Decisions (User-Approved)

| Decision | Choice |
|----------|--------|
| Infrastructure | **Hybrid** - Local dev + Azure staging/production |
| Key Storage | **Deferred** - Start with keripy Keeper, decide production storage later |
| Separation | **Separate Services** - VVP-Issuer as new service |
| Codebase | **Monorepo, Strict Separation** - `/common`, `/services/verifier`, `/services/issuer` |

---

## Phase 0: Monorepo Refactoring (Foundation)

**Goal:** Restructure codebase without breaking existing verifier.

**Exit Criteria:** All 1400+ tests pass, verifier deploys to Azure unchanged.

### New Directory Structure

```
VVP/
├── common/
│   └── vvp/
│       ├── core/           # config.py, exceptions.py, logging.py
│       ├── models/         # acdc.py, dossier.py
│       ├── canonical/      # keri_canonical.py, cesr.py, parser.py, said.py
│       ├── schema/         # registry.py, store.py, validator.py
│       └── utils/          # tn_utils.py
├── services/
│   ├── verifier/           # Existing service (relocated)
│   │   ├── app/
│   │   ├── tests/
│   │   ├── pyproject.toml
│   │   └── Dockerfile
│   └── issuer/             # NEW service
│       ├── app/
│       ├── tests/
│       ├── pyproject.toml
│       └── Dockerfile
├── keripy/                 # Vendored (unchanged)
├── scripts/
├── pyproject.toml          # Workspace configuration
└── docker-compose.yml
```

### Files to Extract to `/common`

| Current Location | Target | Reason |
|------------------|--------|--------|
| `app/vvp/acdc/models.py` | `common/vvp/models/acdc.py` | ACDC dataclass for both parsing and creation |
| `app/vvp/dossier/models.py` | `common/vvp/models/dossier.py` | DossierDAG, ACDCNode |
| `app/vvp/keri/keri_canonical.py` | `common/vvp/canonical/keri_canonical.py` | SAID computation |
| `app/vvp/keri/cesr.py` (primitives) | `common/vvp/canonical/cesr.py` | CESR encoding/decoding |
| `app/vvp/acdc/parser.py` | `common/vvp/canonical/parser.py` | ACDC parsing + SAID validation |
| `app/vvp/acdc/schema_registry.py` | `common/vvp/schema/registry.py` | Schema SAIDs |
| `app/vvp/acdc/schema_validator.py` | `common/vvp/schema/validator.py` | Schema validation utilities |
| `app/vvp/tn_utils.py` | `common/vvp/utils/tn_utils.py` | Phone number utilities |
| `app/logging_config.py` | `common/vvp/core/logging.py` | Shared logging configuration |
| `app/vvp/exceptions.py` (base classes) | `common/vvp/core/exceptions.py` | VVPError, PassportError bases |

**NOT extracted** (verifier-specific):
- `app/vvp/api_models.py` - Request/response models specific to verification API
- `app/vvp/verify.py`, `verify_callee.py` - Verification logic
- `app/vvp/keri/signature.py` - Signature verification (issuer uses keripy signing)

### Migration Strategy

1. Create `common/` package with `__init__.py` files
2. Copy files to new locations (keep originals)
3. Create compatibility shims that re-export from common
4. Run all tests to verify nothing breaks
5. Gradually migrate verifier imports to common
6. Move verifier to `services/verifier/`
7. Remove compatibility shims

### Verification

- All 1400+ existing tests must pass
- Dockerfile builds correctly
- CI/CD deploys verifier to Azure
- No import errors in either service

---

## Phase 1: Local Witness Infrastructure

**Goal:** Set up local KERI witnesses using keripy.

### Deliverables

1. **`scripts/local-witnesses.sh`** - Start 3 local witnesses
   ```bash
   kli witness demo  # Starts wan, wil, wes on ports 5632, 5642, 5652
   ```

2. **`docker-compose.yml`** - Multi-service orchestration
   - witness-wan, witness-wil, witness-wes containers
   - verifier service
   - issuer service (placeholder)

3. **`services/issuer/config/witnesses.json`** - Witness configuration

### Verification

- Witnesses respond to OOBI requests at `http://127.0.0.1:5642/oobi/{aid}`
- Verifier can resolve AIDs via local witnesses
- Witness receipts are returned for test events

---

## Phase 2: Issuer Service Skeleton

**Goal:** Create VVP-Issuer with identity management using keripy Habery.

### Service Structure

```
services/issuer/
├── app/
│   ├── __init__.py
│   ├── main.py              # FastAPI application
│   ├── config.py            # Issuer configuration
│   ├── keri/
│   │   ├── identity.py      # IssuerIdentityManager (wraps Habery)
│   │   ├── witness.py       # Witness interaction + OOBI publishing
│   │   └── persistence.py   # Storage path management
│   └── api/
│       ├── identity.py      # POST /identity, GET /identity/{aid}
│       └── health.py        # GET /healthz
├── tests/
├── pyproject.toml
└── Dockerfile
```

### Key Classes

**`IssuerIdentityManager`** - Wraps keripy's Habery:
- `create_identity(config)` - Create new AID with witnesses
- Key rotation support
- OOBI publishing to witnesses

### Persistence Strategy (Keeper State)

**Local Development:**
```
~/.vvp-issuer/
├── keystores/          # Keeper LMDB databases (private keys)
│   └── {name}/
├── databases/          # Habery LMDB databases (KEL, credentials)
│   └── {name}/
└── config/             # Runtime configuration
```

**Azure Production:**
- **Keeper databases**: Azure Files persistent volume mounted at `/data/vvp-issuer/`
- **Backup**: Nightly backup to Azure Blob Storage
- **Recovery**: Documented restore procedure from backup

**Docker Volume Configuration:**
```yaml
services:
  issuer:
    volumes:
      - issuer-data:/data/vvp-issuer
volumes:
  issuer-data:
    driver: local  # Azure: azure_file
```

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/identity` | POST | Create new issuer identity |
| `/identity/{aid}` | GET | Get identity info |
| `/identity/{aid}/oobi` | GET | Get OOBI URL for identity |
| `/healthz` | GET | Health check |

### Verification

- Create identity via API
- Verify AID can be resolved by verifier via OOBI
- Restart container, verify identity persists
- OOBI published to witnesses and resolvable

---

## Phase 3: Credential Registry & Schema Strategy

**Goal:** Implement TEL registry using keripy Regery + define schema management.

### Key Classes

**`CredentialRegistryManager`** - Wraps keripy's Regery:
- `create_registry(issuer_alias, name)` - Create TEL
- Registry lookup by name
- Witness receipt anchoring for registry events

### Schema Registry Strategy

**Source of Truth:** vLEI schema repository (GLEIF-published)

**Schema SAIDs (from `common/vvp/schema/registry.py`):**
| Type | Schema SAID | Version |
|------|-------------|---------|
| Legal Entity (LE) | `EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao` | 1.0.0 |
| Authorized Public Entity (APE) | `ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY` | 1.0.0 |
| Designated Entity (DE) | ... | 1.0.0 |
| TN Allocation | ... | 1.0.0 |

**Schema Resolution:**
1. Issuer validates credential data against schema before issuance
2. Schema SAIDs embedded in credentials reference `common/vvp/schema/`
3. New schema versions require coordinated update to both services

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/registry` | POST | Create credential registry |
| `/registry/{id}` | GET | Get registry info |
| `/schema` | GET | List available schemas |
| `/schema/{said}` | GET | Get schema definition |

### Verification

- Create registry via API
- TEL events published to witnesses with receipts
- Registry state persists across restart

---

## Phase 3.5: Issuer Security Model

**Goal:** Implement authentication and authorization before credential issuance endpoints.

### Security Architecture

```
                    ┌─────────────────┐
   Public Internet  │                 │
        ───────────►│  Azure Gateway  │
                    │  (HTTPS only)   │
                    └────────┬────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
              ▼              ▼              ▼
        ┌──────────┐  ┌──────────┐  ┌──────────┐
        │ Verifier │  │  Issuer  │  │ Witness  │
        │ (public) │  │(internal)│  │(internal)│
        └──────────┘  └──────────┘  └──────────┘
```

### Network Isolation

**Local Development:**
- All services on Docker network `vvp-internal`
- Issuer only accessible from localhost

**Azure Production:**
- Verifier: Public endpoint (existing)
- Issuer: **Internal only** - Azure Container Apps internal ingress
- Issuer accessible only from:
  - VNet-connected admin tools
  - Authorized service principals

### Authentication

**API Key Authentication (Phase 3.5):**
```python
# services/issuer/app/auth/api_key.py
from fastapi import Security, HTTPException
from fastapi.security import APIKeyHeader

api_key_header = APIKeyHeader(name="X-API-Key")

async def verify_api_key(api_key: str = Security(api_key_header)):
    if api_key != settings.ISSUER_API_KEY:
        raise HTTPException(status_code=403, detail="Invalid API key")
```

**Environment Configuration:**
```yaml
# Azure Container App environment
- name: ISSUER_API_KEY
  secretRef: issuer-api-key  # From Azure Key Vault
```

### Authorization

**Role-Based Access:**
| Role | Permissions |
|------|-------------|
| `issuer:admin` | Create identities, registries, issue any credential |
| `issuer:operator` | Issue credentials with existing identity/registry |
| `issuer:readonly` | View identities, registries, credentials |

**Endpoint Protection:**
| Endpoint | Required Role |
|----------|---------------|
| `POST /identity` | `issuer:admin` |
| `POST /registry` | `issuer:admin` |
| `POST /credential/issue` | `issuer:operator` |
| `POST /credential/{said}/revoke` | `issuer:admin` |
| `GET /*` | `issuer:readonly` |

### Audit Logging

All issuance operations logged with:
- Timestamp
- Authenticated principal
- Operation type
- Credential SAID (for issuance/revocation)
- Source IP

### Verification

- Unauthenticated requests to issuer return 401
- Invalid API key returns 403
- Audit logs capture all issuance operations
- Issuer not accessible from public internet (Azure)

---

## Phase 4: ACDC Credential Issuance

**Goal:** Core credential issuance using keripy's `credential()` function.

**Prerequisite:** Phase 3.5 security model implemented.

### Key Classes

**`CredentialIssuer`** - Issues ACDC credentials:
- `issue_credential(req)` - Create and sign ACDC
- Uses `keri.vc.proving.credential()`
- Anchors to registry (TEL iss event)
- Collects witness receipts

### Issuance Flow

```
1. Validate request (schema, attributes, recipient)
2. Create ACDC via keri.vc.proving.credential()
3. Sign with issuer Hab
4. Create TEL issuance event (iss)
5. Publish to witnesses, collect receipts
6. Store credential + receipts
7. Return credential SAID
```

### API Endpoints

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/credential/issue` | POST | `issuer:operator` | Issue new ACDC |
| `/credential/{said}` | GET | `issuer:readonly` | Get credential by SAID |
| `/credential/{said}/revoke` | POST | `issuer:admin` | Revoke credential |

### Supported Credential Types

| Type | Schema SAID | Required Attributes |
|------|-------------|---------------------|
| Legal Entity (LE) | `EBfdlu8R27...` | LEI, legal name |
| Authorized Public Entity (APE) | `ENPXp1vQ...` | LEI, role |
| Designated Entity (DE) | ... | LEI, delegation chain |
| TN Allocation | ... | TN ranges, allocation date |

### Verification

- Issue credential via API
- Verify with existing verifier service
- Test revocation flow
- Verify TEL events have witness receipts

---

## Phase 5: Dossier Assembly

**Goal:** Assemble credentials into complete dossiers compatible with verifier.

### Dossier Format Requirements (per VVP Spec)

**Supported Formats:**
| Format | Content-Type | Description |
|--------|--------------|-------------|
| CESR Stream | `application/cesr` | Full CESR-encoded credentials + signatures + TEL |
| JSON + CESR | `application/json+cesr` | JSON wrapper with embedded CESR attachments |
| Compact | - | Minimal representation (SAID references only) |

**SAID Computation Rules:**
- All SAIDs computed using Blake3-256 per KERI spec
- Use `common/vvp/canonical/said.py` for consistent computation
- SAID placeholder: `"d": ""` before computation
- Canonical field ordering per `common/vvp/canonical/keri_canonical.py`

### Key Classes

**`DossierBuilder`** - Builds dossiers from credential chains:
```python
class DossierBuilder:
    def build_dossier(
        self,
        root_said: str,
        format: DossierFormat = DossierFormat.CESR,
        include_chain: bool = True,
        include_tel: bool = True,
    ) -> Dossier:
        """Build a dossier for the given root credential.

        Args:
            root_said: SAID of the primary credential
            format: Output format (CESR, JSON_CESR, COMPACT)
            include_chain: Include full credential chain via edges
            include_tel: Include TEL issuance/revocation events
        """
```

### Dossier Structure

**Full CESR Dossier:**
```
┌─────────────────────────────────────┐
│ Version String: "KERI10JSON..."     │
├─────────────────────────────────────┤
│ ACDC 1 (root credential)            │
│   + Controller signature            │
│   + Witness receipts                │
├─────────────────────────────────────┤
│ ACDC 2 (edge credential)            │
│   + Controller signature            │
│   + Witness receipts                │
├─────────────────────────────────────┤
│ ...                                 │
├─────────────────────────────────────┤
│ TEL Events                          │
│   + Registry inception              │
│   + Issuance events (iss)           │
│   + Revocation events (rev) if any  │
└─────────────────────────────────────┘
```

**Compact/Partial Dossier:**
- Only SAIDs of credentials (verifier fetches full credentials)
- Used when bandwidth is constrained
- Requires verifier to have OOBI access to credential store

**Aggregate Dossier:**
- Multiple credential chains bundled together
- For complex authorization scenarios (e.g., LE + APE + TNAlloc)

### Edge Resolution

Walk credential edges to build complete chain:
```python
def _walk_chain(self, cred: ACDC) -> List[ACDC]:
    """Recursively resolve edge references."""
    chain = []
    if cred.edges:
        for edge_said in cred.edges.values():
            edge_cred = self.credential_store.get(edge_said)
            chain.append(edge_cred)
            chain.extend(self._walk_chain(edge_cred))
    return chain
```

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/dossier/build` | POST | Build dossier for credential |
| `/dossier/{said}` | GET | Get dossier (format via Accept header) |
| `/dossier/{said}/cesr` | GET | Get CESR stream directly |

### Verification

- Build dossier from issued credentials
- Fetch dossier, pass to verifier `/verify` endpoint
- Verify all formats (CESR, JSON+CESR, compact)
- Verify SAID computation matches verifier expectations
- Test multi-credential chain (LE → APE → TNAlloc)

---

## Phase 6: Azure Deployment

**Goal:** Deploy issuer to Azure alongside verifier.

### Infrastructure

| Component | Azure Service | Configuration |
|-----------|---------------|---------------|
| Issuer Service | Container App | Internal ingress only |
| Keeper Storage | Azure Files | Premium, encrypted at rest |
| Secrets | Key Vault | API keys, future HSM keys |
| Logging | Log Analytics | Audit trail retention |
| Backup | Blob Storage | Nightly Keeper backup |

### Network Configuration

```
Azure VNet
├── Public Subnet
│   └── Verifier Container App (external ingress)
└── Private Subnet
    ├── Issuer Container App (internal ingress)
    └── Witness Container Apps (internal)
```

### CI/CD Updates

```yaml
# .github/workflows/deploy.yml
jobs:
  test:
    # Run all tests

  deploy-verifier:
    needs: test
    # Existing verifier deployment

  deploy-issuer:
    needs: test
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build issuer image
        run: docker build -t vvp-issuer services/issuer/
      - name: Push to ACR
        # ...
      - name: Deploy to Azure Container Apps
        # Internal ingress configuration
```

### Verification

- End-to-end: issue credential in Azure, verify in Azure
- Security: confirm issuer not accessible from public internet
- Persistence: restart issuer, verify identities/registries intact
- Backup/restore: test recovery from backup

---

## Phase Dependencies

```
Phase 0 ─── Phase 1 ─── Phase 2 ───┬─── Phase 3 ─── Phase 3.5 ─── Phase 4 ─── Phase 5 ─── Phase 6
                                   │
                                   └─── (parallel: schema strategy)
```

**Critical Path:** 0 → 1 → 2 → 3 → 3.5 → 4 → 5 → 6

**Gate:** Phase 3.5 (Security) MUST complete before Phase 4 (Issuance)

---

## Critical Files Reference

| File | Purpose |
|------|---------|
| [app/vvp/acdc/models.py](app/vvp/acdc/models.py) | ACDC dataclass to extract |
| [app/vvp/keri/keri_canonical.py](app/vvp/keri/keri_canonical.py) | KERI serialization to extract |
| [app/vvp/acdc/parser.py](app/vvp/acdc/parser.py) | SAID computation to extract |
| [keripy/src/keri/vc/proving.py](keripy/src/keri/vc/proving.py) | `credential()` function |
| [keripy/src/keri/vdr/credentialing.py](keripy/src/keri/vdr/credentialing.py) | Regery, Credentialer |
| [keripy/src/keri/app/habbing.py](keripy/src/keri/app/habbing.py) | Habery for identity |

---

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Import breakage in Phase 0 | High | Medium | Compatibility shims, gradual migration |
| keripy API changes | Medium | High | Pin keripy version, integration tests |
| Witness availability | Medium | Medium | Local fallback, multiple witness pools |
| Key management complexity | Medium | High | Defer to Keeper, plan Key Vault later |
| **Unauthorized credential minting** | Medium | **Critical** | Phase 3.5 security gate, network isolation |
| **Keeper state loss** | Medium | **High** | Persistent volumes, nightly backups |
| **Dossier format incompatibility** | Medium | High | Shared SAID computation, format tests |
| Schema version mismatch | Low | Medium | Coordinated schema updates, version checks |

---

## Documentation Updates

Update `app/Documentation/CREATING_DOSSIERS.md` after each phase with:
- Architecture diagrams
- Setup guides (local + Azure)
- API reference with examples
- Security configuration
- Troubleshooting
- Backup/restore procedures

---

## Implementation Status

### Phase 0: Monorepo Refactoring - COMPLETE

**Completed Date:** 2026-01-31

**Summary:** Created shared `common/` package with compatibility shims for gradual migration.

#### Files Created

| File | Purpose |
|------|---------|
| `common/__init__.py` | Package root |
| `common/vvp/__init__.py` | VVP namespace |
| `common/vvp/core/__init__.py` | Core exports (exceptions, logging) |
| `common/vvp/core/exceptions.py` | VVPError, ACDCError, KeriError, etc. |
| `common/vvp/core/logging.py` | JsonFormatter, configure_logging() |
| `common/vvp/models/__init__.py` | Model exports (ACDC, DossierDAG) |
| `common/vvp/models/acdc.py` | ACDC, ACDCChainResult dataclasses |
| `common/vvp/models/dossier.py` | DossierDAG, ACDCNode, ToIPWarningCode |
| `common/vvp/models/api.py` | ClaimStatus, ErrorCode, ERROR_RECOVERABILITY |
| `common/vvp/canonical/__init__.py` | Canonical serialization exports |
| `common/vvp/canonical/keri_canonical.py` | FIELD_ORDER, canonical_serialize() |
| `common/vvp/schema/__init__.py` | Schema registry exports |
| `common/vvp/schema/registry.py` | KNOWN_SCHEMA_SAIDS, is_known_schema() |
| `common/vvp/utils/__init__.py` | Utility exports |
| `common/vvp/utils/tn_utils.py` | TNRange, parse_tn_allocation(), is_subset() |
| `common/pyproject.toml` | Package configuration |

#### Compatibility Shims Updated

| File | Status |
|------|--------|
| `app/vvp/acdc/models.py` | Re-exports from `common.vvp.models.acdc` |
| `app/vvp/dossier/models.py` | Re-exports from `common.vvp.models.dossier` |
| `app/vvp/acdc/schema_registry.py` | Re-exports from `common.vvp.schema.registry` |
| `app/vvp/acdc/exceptions.py` | Re-exports from `common.vvp.core.exceptions` |
| `app/vvp/keri/keri_canonical.py` | Re-exports from `common.vvp.canonical.keri_canonical` |
| `app/logging_config.py` | Re-exports from `common.vvp.core.logging` |
| `app/vvp/tn_utils.py` | Re-exports from `common.vvp.utils.tn_utils` |

#### Production Code Migrated

| File | Import Changes |
|------|----------------|
| `app/main.py` | Uses `common.vvp.core.logging` |
| `app/vvp/authorization.py` | Uses `common.vvp.models`, `common.vvp.utils.tn_utils` |
| `app/vvp/ui/credential_viewmodel.py` | Uses `common.vvp.models`, `common.vvp.schema.registry` |

#### Test Results

- **All 1564 tests pass** (17.45s)
- No import errors
- Compatibility shims working correctly

#### Remaining Phase 0 Work (Deferred)

- Move verifier to `services/verifier/` directory
- Update Dockerfile and CI/CD for new structure
- Remove compatibility shims after full migration

These items are deferred as the current structure meets the exit criteria (all tests pass, verifier works unchanged) and can be completed incrementally.
