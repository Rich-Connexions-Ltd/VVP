# VVP Issuer Implementation Sprints

Reference this document by saying "Sprint N" to begin pair programming on that sprint.

## Previous Sprints (Verifier)

Sprints 1-25 implemented the VVP Verifier. See `Documentation/archive/PLAN_Sprint*.md` for history.

## Status Overview (Issuer)

| Sprint | Name | Status | Dependencies |
|--------|------|--------|--------------|
| 26 | Monorepo Foundation | COMPLETE | - |
| 27 | Local Witness Infrastructure | COMPLETE | Sprint 26 |
| 28 | Issuer Service Skeleton | COMPLETE | Sprint 27 |
| 29 | Credential Registry | COMPLETE | Sprint 28 |
| 30 | Security Model | COMPLETE | Sprint 29 |
| 31 | ACDC Issuance | Ready | Sprint 30 |
| 32 | Dossier Assembly | Blocked | Sprint 31 |
| 33 | Azure Deployment | Blocked | Sprint 32 |

---

## Sprint 26: Monorepo Foundation (COMPLETE)

**Goal:** Restructure codebase for multi-service architecture.

**Deliverables:**
- [x] Create `common/` package with shared code
- [x] Move verifier to `services/verifier/`
- [x] Update CI/CD for monorepo paths
- [x] Add root convenience scripts
- [x] Restructure UI routes (`/`, `/verify`, `/create`)
- [x] Consider UI functionality needed to expose this sprint's capabilities

**Commits:** `0b7d5fa`, `60df06e`, `b7ba9a3`

---

## Sprint 27: Local Witness Infrastructure (COMPLETE)

**Goal:** Set up local KERI witnesses for development and testing.

**Deliverables:**
- [x] `docker-compose.yml` with witness containers (wan, wil, wes)
- [x] `scripts/local-witnesses.sh` to start witness network
- [x] Witness configuration in `services/issuer/config/witnesses.json`
- [x] Verify witnesses respond to OOBI requests
- [x] Verify verifier can resolve AIDs via local witnesses
- [x] Consider UI functionality needed to expose this sprint's capabilities

**Commits:** `7f18a94`

**Key Files:**
```
docker-compose.yml
scripts/local-witnesses.sh
services/issuer/config/witnesses.json
```

**Technical Notes:**
- Use keripy's `kli witness demo` for local witnesses
- Witness ports (from kli witness demo):
  - wan: TCP 5632, HTTP 5642
  - wil: TCP 5633, HTTP 5643
  - wes: TCP 5634, HTTP 5644
- OOBI format: `http://127.0.0.1:{http_port}/oobi/{aid}/controller`

**Exit Criteria:**
- `docker-compose up` starts all witnesses
- `curl http://127.0.0.1:5642/oobi/{wan_aid}/controller` returns valid OOBI
- Verifier tests pass with local witness resolution

---

## Sprint 28: Issuer Service Skeleton (COMPLETE)

**Goal:** Create VVP-Issuer FastAPI service with identity management.

**Deliverables:**
- [x] `services/issuer/` directory structure
- [x] FastAPI application with health endpoint
- [x] `IssuerIdentityManager` wrapping keripy Habery
- [x] Identity creation API (`POST /identity`)
- [x] OOBI publishing to witnesses (events accepted by all 3 witnesses)
- [x] Dockerfile for issuer service
- [x] Integration tests for witness publishing
- [x] Consider UI functionality needed to expose this sprint's capabilities

**Commits:** `ee47606`, `65f3033`

**Notes:**
- Witness publishing uses CESR HTTP format (application/cesr+json + CESR-ATTACHMENT header)
- Full OOBI resolution requires complete witness receipt protocol (planned for future sprint)
- Current implementation successfully sends events to all witnesses (HTTP 200)

**Key Files:**
```
services/issuer/
├── app/
│   ├── main.py
│   ├── config.py
│   ├── keri/
│   │   ├── identity.py      # IssuerIdentityManager
│   │   ├── witness.py       # Witness interaction
│   │   └── persistence.py   # Storage paths
│   └── api/
│       ├── identity.py      # POST /identity, GET /identity/{aid}
│       └── health.py
├── tests/
├── pyproject.toml
└── Dockerfile
```

**API Endpoints:**
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/identity` | POST | Create new issuer identity |
| `/identity/{aid}` | GET | Get identity info |
| `/identity/{aid}/oobi` | GET | Get OOBI URL |
| `/healthz` | GET | Health check |

**Persistence Strategy:**
- Local: `~/.vvp-issuer/keystores/`, `~/.vvp-issuer/databases/`
- Docker: `/data/vvp-issuer/` volume mount

**Exit Criteria:**
- Create identity via API
- Identity persists across restart
- OOBI resolvable by verifier

---

## Sprint 29: Credential Registry (COMPLETE)

**Goal:** Implement TEL registry for credential issuance tracking.

**Deliverables:**
- [x] `CredentialRegistryManager` wrapping keripy Regery
- [x] Registry creation API (`POST /registry`)
- [x] Schema registry integration from `common/vvp/schema/`
- [x] Witness receipt anchoring for registry events
- [x] UI for registry management and schema browsing

**Commits:** `8c28f2f`

**Key Files:**
```
services/issuer/app/
├── keri/
│   └── registry.py          # CredentialRegistryManager
├── schema/
│   └── store.py             # Embedded schema store
└── api/
    ├── registry.py          # POST /registry, GET /registry/{id}
    └── schema.py            # GET /schema, GET /schema/{said}, POST /schema/validate
services/issuer/web/
├── registry.html            # Registry management UI
└── schemas.html             # Schema browser UI
services/issuer/tests/
├── test_registry.py         # Registry tests (13 tests)
└── test_schema.py           # Schema tests (10 tests)
```

**API Endpoints:**
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/registry` | POST | Create credential registry |
| `/registry` | GET | List all registries |
| `/registry/{key}` | GET | Get registry by key |
| `/schema` | GET | List available schemas |
| `/schema/{said}` | GET | Get schema definition |
| `/schema/validate` | POST | Validate schema SAID |
| `/registry/ui` | GET | Registry management UI |
| `/schemas/ui` | GET | Schema browser UI |

**Schema SAIDs (embedded):**
| Type | SAID |
|------|------|
| Legal Entity | `ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY` |
| QVI | `EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao` |
| OOR Auth | `EKA57bKBKxr_kN7iN5i7lMUxpMG-s19dRcmov1iDxz-E` |
| ECR Auth | `EH6ekLjSr8V32WyFbGe1zXjTzFs9PkTYmupJ9H65O14g` |
| Dossier | `EH1jN4U4LMYHmPVI4FYdZ10bIPR7YWKp8TDdZ9Y9Al-P` |
| TN Allocation | `EFvnoHDY7I-kaBBeKlbDbkjG4BaI0nKLGadxBdjMGgSQ` |

**Technical Notes:**
- Regery uses same `headDirPath` as Habery for consistent storage
- TEL properties (regi, noBackers) wrapped in try/except for lazy tever loading
- Registry manager shares Habery singleton with identity manager

**Exit Criteria:**
- [x] Create registry via API
- [x] TEL events published to witnesses
- [x] Schema validation working
- [x] UI for registry and schema management
- [x] All 33 tests passing

---

## Sprint 30: Security Model (COMPLETE)

**Goal:** Implement authentication and authorization before credential issuance.

**CRITICAL:** This sprint MUST complete before Sprint 31 (issuance).

**Deliverables:**
- [x] API key authentication middleware (bcrypt hashing, constant-time verification)
- [x] Role-based authorization (admin, operator, readonly with hierarchy)
- [x] Audit logging for all security operations
- [x] Key rotation support (file mtime polling + admin reload endpoint)
- [x] Key revocation support (revoked flag)
- [x] Consider UI functionality needed (UI auth exempt by default for local dev)

**Commits:** `a61a4e1`

**Key Files:**
```
services/issuer/app/
├── auth/
│   ├── __init__.py
│   ├── api_key.py           # APIKeyBackend, APIKeyStore, Principal
│   └── roles.py             # Role enum, hierarchy, require_role()
├── audit/
│   ├── __init__.py
│   └── logger.py            # AuditLogger for security events
├── api/
│   └── admin.py             # POST /admin/auth/reload, GET /admin/auth/status
├── config.py                # AUTH_ENABLED, API_KEYS_FILE, etc.
└── main.py                  # AuthenticationMiddleware integration
services/issuer/config/
└── api_keys.json            # Default dev API keys (bcrypt hashed)
services/issuer/scripts/
└── generate-api-key.py      # Key generation with bcrypt
services/issuer/tests/
└── test_auth.py             # Auth unit tests (17 tests)
```

**Roles:**
| Role | Permissions |
|------|-------------|
| `issuer:admin` | Create identities, registries, issue/revoke any credential |
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
| `/healthz`, `/version` | None (exempt) |
| `/create`, `/registry/ui`, `/schemas/ui` | None (exempt by default) |
| `POST /admin/auth/reload` | `issuer:admin` |

**Configuration:**
| Variable | Default | Description |
|----------|---------|-------------|
| `VVP_AUTH_ENABLED` | `true` | Enable/disable authentication |
| `VVP_API_KEYS_FILE` | `config/api_keys.json` | Path to API keys config |
| `VVP_API_KEYS` | - | Inline JSON (for Docker secrets) |
| `VVP_DOCS_AUTH_EXEMPT` | `false` | Exempt /docs and /openapi.json |
| `VVP_UI_AUTH_ENABLED` | `false` | Require auth for UI pages |
| `VVP_AUTH_RELOAD_INTERVAL` | `60` | Key reload interval (seconds) |

**Exit Criteria:**
- [x] Unauthenticated requests return 401
- [x] Invalid API key returns 401
- [x] Revoked API key returns 401
- [x] Insufficient role returns 403
- [x] All operations logged with principal, timestamp, action
- [x] All 50 tests passing (17 auth + 33 existing)

---

## Sprint 31: ACDC Credential Issuance

**Goal:** Core credential issuance using keripy.

**Prerequisites:** Sprint 30 (Security) MUST be complete.

**Deliverables:**
- [ ] `CredentialIssuer` class using `keri.vc.proving.credential()`
- [ ] Issuance API with schema validation
- [ ] TEL issuance event (iss) anchoring
- [ ] Witness receipt collection
- [ ] Revocation API
- [ ] Consider UI functionality needed to expose this sprint's capabilities

**Key Files:**
```
services/issuer/app/
├── keri/
│   └── issuer.py            # CredentialIssuer
└── api/
    └── credential.py        # POST /credential/issue, POST /credential/{said}/revoke
```

**API Endpoints:**
| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/credential/issue` | POST | operator | Issue new ACDC |
| `/credential/{said}` | GET | readonly | Get credential by SAID |
| `/credential/{said}/revoke` | POST | admin | Revoke credential |

**Issuance Flow:**
1. Validate request (schema, attributes, recipient)
2. Create ACDC via `keri.vc.proving.credential()`
3. Sign with issuer Hab
4. Create TEL issuance event (iss)
5. Publish to witnesses, collect receipts
6. Store credential + receipts
7. Return credential SAID

**Supported Credential Types:**
- Legal Entity (LE)
- Qualified vLEI Issuer (QVI)
- OOR Authorization
- TN Allocation

**Exit Criteria:**
- Issue credential via API
- Verify with verifier service
- Revocation updates TEL

---

## Sprint 32: Dossier Assembly

**Goal:** Assemble credentials into complete dossiers for VVP.

**Deliverables:**
- [ ] `DossierBuilder` class for chain assembly
- [ ] CESR stream output format
- [ ] JSON+CESR hybrid format
- [ ] Edge resolution (walk credential chain)
- [ ] TEL event inclusion
- [ ] Consider UI functionality needed to expose this sprint's capabilities

**Key Files:**
```
services/issuer/app/
├── dossier/
│   ├── builder.py           # DossierBuilder
│   └── formats.py           # CESR, JSON+CESR serialization
└── api/
    └── dossier.py           # POST /dossier/build, GET /dossier/{said}
```

**Dossier Formats:**
| Format | Content-Type | Description |
|--------|--------------|-------------|
| CESR | `application/cesr` | Full CESR stream |
| JSON+CESR | `application/json+cesr` | JSON wrapper with CESR attachments |
| Compact | - | SAID references only |

**Exit Criteria:**
- Build dossier from credential chain
- Dossier verifiable by verifier service
- All formats work with verifier `/verify` endpoint

---

## Sprint 33: Azure Deployment

**Goal:** Deploy issuer to Azure alongside verifier.

**Deliverables:**
- [ ] Azure Container App configuration (internal ingress)
- [ ] Azure Files for Keeper persistence
- [ ] Key Vault integration for API keys
- [ ] CI/CD pipeline updates
- [ ] Backup/restore procedures
- [ ] Consider UI functionality needed to expose this sprint's capabilities

**Infrastructure:**
| Component | Azure Service |
|-----------|---------------|
| Issuer Service | Container App (internal) |
| Keeper Storage | Azure Files (Premium) |
| Secrets | Key Vault |
| Logging | Log Analytics |
| Backup | Blob Storage |

**Network Configuration:**
```
Azure VNet
├── Public Subnet
│   └── Verifier Container App (external)
└── Private Subnet
    ├── Issuer Container App (internal)
    └── Witness Container Apps (internal)
```

**CI/CD Updates:**
```yaml
jobs:
  deploy-issuer:
    needs: [test, deploy-verifier]
    steps:
      - Build issuer image
      - Push to ACR
      - Deploy with internal ingress
```

**Exit Criteria:**
- End-to-end: issue in Azure, verify in Azure
- Issuer not accessible from public internet
- Keeper persists across restarts
- Backup/restore tested

---

## Quick Reference

To start a sprint, say:
- "Sprint 27" - Local witness infrastructure
- "Sprint 28" - Issuer service skeleton
- "Sprint 29" - Credential registry
- "Sprint 30" - Security model (required before issuance)
- "Sprint 31" - ACDC credential issuance
- "Sprint 32" - Dossier assembly
- "Sprint 33" - Azure deployment

Each sprint follows the pair programming workflow:
1. Plan phase (design, review, approval)
2. Implementation phase (code, test, review)
3. Completion phase (commit, deploy, document)
