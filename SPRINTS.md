# VVP Issuer Implementation Sprints

Reference this document by saying "Sprint N" to begin pair programming on that sprint.

## Status Overview

| Sprint | Name | Status | Dependencies |
|--------|------|--------|--------------|
| 0 | Monorepo Foundation | COMPLETE | - |
| 1 | Local Witness Infrastructure | Ready | Sprint 0 |
| 2 | Issuer Service Skeleton | Ready | Sprint 1 |
| 3 | Credential Registry | Ready | Sprint 2 |
| 4 | Security Model | Ready | Sprint 3 |
| 5 | ACDC Issuance | Blocked | Sprint 4 |
| 6 | Dossier Assembly | Blocked | Sprint 5 |
| 7 | Azure Deployment | Blocked | Sprint 6 |

---

## Sprint 0: Monorepo Foundation (COMPLETE)

**Goal:** Restructure codebase for multi-service architecture.

**Deliverables:**
- [x] Create `common/` package with shared code
- [x] Move verifier to `services/verifier/`
- [x] Update CI/CD for monorepo paths
- [x] Add root convenience scripts
- [x] Restructure UI routes (`/`, `/verify`, `/create`)

**Commits:** `0b7d5fa`, `60df06e`, `b7ba9a3`

---

## Sprint 1: Local Witness Infrastructure

**Goal:** Set up local KERI witnesses for development and testing.

**Deliverables:**
- [ ] `docker-compose.yml` with witness containers (wan, wil, wes)
- [ ] `scripts/local-witnesses.sh` to start witness network
- [ ] Witness configuration in `services/issuer/config/witnesses.json`
- [ ] Verify witnesses respond to OOBI requests
- [ ] Verify verifier can resolve AIDs via local witnesses

**Key Files:**
```
docker-compose.yml
scripts/local-witnesses.sh
services/issuer/config/witnesses.json
```

**Technical Notes:**
- Use keripy's `kli witness demo` for local witnesses
- Witnesses run on ports 5632, 5642, 5652
- OOBI format: `http://127.0.0.1:5642/oobi/{aid}`

**Exit Criteria:**
- `docker-compose up` starts all witnesses
- `curl http://127.0.0.1:5642/.well-known/keri/oobi` returns valid OOBI
- Verifier tests pass with local witness resolution

---

## Sprint 2: Issuer Service Skeleton

**Goal:** Create VVP-Issuer FastAPI service with identity management.

**Deliverables:**
- [ ] `services/issuer/` directory structure
- [ ] FastAPI application with health endpoint
- [ ] `IssuerIdentityManager` wrapping keripy Habery
- [ ] Identity creation API (`POST /identity`)
- [ ] OOBI publishing to witnesses
- [ ] Dockerfile for issuer service

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

## Sprint 3: Credential Registry

**Goal:** Implement TEL registry for credential issuance tracking.

**Deliverables:**
- [ ] `CredentialRegistryManager` wrapping keripy Regery
- [ ] Registry creation API (`POST /registry`)
- [ ] Schema registry integration from `common/vvp/schema/`
- [ ] Witness receipt anchoring for registry events

**Key Files:**
```
services/issuer/app/
├── keri/
│   └── registry.py          # CredentialRegistryManager
└── api/
    ├── registry.py          # POST /registry, GET /registry/{id}
    └── schema.py            # GET /schema, GET /schema/{said}
```

**API Endpoints:**
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/registry` | POST | Create credential registry |
| `/registry/{id}` | GET | Get registry info |
| `/schema` | GET | List available schemas |
| `/schema/{said}` | GET | Get schema definition |

**Schema SAIDs (from vLEI):**
| Type | SAID |
|------|------|
| Legal Entity | `EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao` |
| QVI | `EFgnk_c08WmZGgv9_mpldibRuqFMTQN-rAgtD-TCOwbs` |
| OOR Auth | `EH1jN4U4LMYHmPVI4FYdZ10bIPR7YWKp8TDdZ9Y9Al-P` |

**Exit Criteria:**
- Create registry via API
- TEL events published to witnesses
- Schema validation working

---

## Sprint 4: Security Model

**Goal:** Implement authentication and authorization before credential issuance.

**CRITICAL:** This sprint MUST complete before Sprint 5 (issuance).

**Deliverables:**
- [ ] API key authentication middleware
- [ ] Role-based authorization (admin, operator, readonly)
- [ ] Audit logging for all issuance operations
- [ ] Network isolation configuration (issuer internal-only)

**Key Files:**
```
services/issuer/app/
├── auth/
│   ├── api_key.py           # API key verification
│   └── roles.py             # Role-based access
└── middleware/
    └── audit.py             # Audit logging
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

**Exit Criteria:**
- Unauthenticated requests return 401
- Invalid API key returns 403
- All operations logged with principal, timestamp, SAID

---

## Sprint 5: ACDC Credential Issuance

**Goal:** Core credential issuance using keripy.

**Prerequisites:** Sprint 4 (Security) MUST be complete.

**Deliverables:**
- [ ] `CredentialIssuer` class using `keri.vc.proving.credential()`
- [ ] Issuance API with schema validation
- [ ] TEL issuance event (iss) anchoring
- [ ] Witness receipt collection
- [ ] Revocation API

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

## Sprint 6: Dossier Assembly

**Goal:** Assemble credentials into complete dossiers for VVP.

**Deliverables:**
- [ ] `DossierBuilder` class for chain assembly
- [ ] CESR stream output format
- [ ] JSON+CESR hybrid format
- [ ] Edge resolution (walk credential chain)
- [ ] TEL event inclusion

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

## Sprint 7: Azure Deployment

**Goal:** Deploy issuer to Azure alongside verifier.

**Deliverables:**
- [ ] Azure Container App configuration (internal ingress)
- [ ] Azure Files for Keeper persistence
- [ ] Key Vault integration for API keys
- [ ] CI/CD pipeline updates
- [ ] Backup/restore procedures

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
- "Sprint 1" - Local witness infrastructure
- "Sprint 2" - Issuer service skeleton
- "Sprint 3" - Credential registry
- "Sprint 4" - Security model (required before issuance)
- "Sprint 5" - ACDC credential issuance
- "Sprint 6" - Dossier assembly
- "Sprint 7" - Azure deployment

Each sprint follows the pair programming workflow:
1. Plan phase (design, review, approval)
2. Implementation phase (code, test, review)
3. Completion phase (commit, deploy, document)
