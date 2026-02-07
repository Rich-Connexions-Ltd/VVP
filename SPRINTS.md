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
| 31 | ACDC Issuance | COMPLETE | Sprint 30 |
| 32 | Dossier Assembly | COMPLETE | Sprint 31 |
| 33 | Azure Deployment | COMPLETE | Sprint 32 |
| 34 | Schema Management | COMPLETE | Sprint 29 |
| 35 | E2E Integration Testing | COMPLETE | Sprint 33 |
| 36 | Key Management & Rotation | COMPLETE | Sprint 30 |
| 37 | Session-Based Authentication | COMPLETE | Sprint 30 |
| 38 | OAuth (Microsoft M365) | COMPLETE | Sprint 30 |
| 39 | Code Review Remediation | COMPLETE | Sprint 38 |
| 40 | Vetter Certification Constraints | COMPLETE | Sprint 31 |
| - | VVP CLI Toolkit | COMPLETE | Sprint 26 |
| - | Chain Revocation Fixes | COMPLETE | Sprint 35 |
| 41 | User Management & Mock vLEI | COMPLETE | Sprint 37 |
| 42 | SIP Redirect Signing Service | COMPLETE | Sprint 41 |
| 43 | PBX Test Infrastructure | COMPLETE | Sprint 42 |
| 44 | SIP Redirect Verification Service | COMPLETE | Sprint 43 |
| 45 | CI/CD SQLite Persistence Fixes | COMPLETE | Sprint 41 |
| 46 | PostgreSQL Migration | COMPLETE | Sprint 45 |
| 47 | SIP Monitor - Core Infrastructure | COMPLETE | Sprint 43 |
| 48 | SIP Monitor - Real-Time & VVP Viz | COMPLETE | Sprint 47 |
| 49 | Shared Dossier Cache & Revocation | COMPLETE | Sprint 32 |

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

## Sprint 31: ACDC Credential Issuance (COMPLETE)

**Goal:** Core credential issuance using keripy.

**Prerequisites:** Sprint 30 (Security) MUST be complete.

**Deliverables:**
- [x] `CredentialIssuer` class using `keri.vc.proving.credential()`
- [x] Issuance API with schema validation
- [x] TEL issuance event (iss) anchoring to KEL
- [x] Witness receipt collection (anchor IXN publishing)
- [x] Revocation API with TEL rev event
- [x] Credential management UI at `/credentials/ui`

**Key Files:**
```
services/issuer/app/
├── keri/
│   ├── issuer.py            # CredentialIssuer class
│   └── registry.py          # Updated with TEL anchoring
├── api/
│   ├── credential.py        # POST /credential/issue, GET /credential, etc.
│   └── models.py            # Credential request/response models
└── main.py                  # Lifecycle integration
services/issuer/web/
└── credentials.html         # Credential management UI
services/issuer/tests/
└── test_credential.py       # 18 unit tests + 1 integration test
```

**API Endpoints:**
| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/credential/issue` | POST | operator | Issue new ACDC |
| `/credential` | GET | readonly | List all credentials |
| `/credential/{said}` | GET | readonly | Get credential by SAID |
| `/credential/{said}/revoke` | POST | admin | Revoke credential |
| `/credentials/ui` | GET | exempt | Credential management UI |

**Technical Notes:**
- TEL events (iss/rev) are anchored to issuer's KEL via interaction events
- Witnesses receipt the KEL anchor IXN, not TEL events directly
- `registry.anchorMsg()` stores KEL anchor, then `tvy.processEvent()` populates tevers
- `reger.getAnc(dgKey(cred_said, tel_event_said))` retrieves KEL anchor for publishing
- `reger.cancs` stores SealSourceTriples for ACDC wire format (different purpose)

**Exit Criteria:**
- [x] Issue credential via API returns credential SAID
- [x] Get credential by SAID returns full details
- [x] List credentials shows all issued credentials
- [x] Revoke credential updates status to "revoked"
- [x] TEL events published to witnesses
- [x] All 68 tests passing (18 credential + 50 existing)
- [x] UI allows credential issuance and listing

**UI Enhancement (post-sprint):**
- Schema-driven dynamic forms in `/credentials/ui`
- Form Mode tab generates input fields from schema properties
- Supports arrays, nested objects, dropdowns, date pickers
- JSON Mode tab for advanced/manual entry

---

## Sprint 32: Dossier Assembly (COMPLETE)

**Goal:** Assemble credentials into complete dossiers for VVP.

**Deliverables:**
- [x] `DossierBuilder` class for chain assembly
- [x] CESR stream output format
- [x] JSON+CESR hybrid format
- [x] Edge resolution (walk credential chain)
- [x] TEL event inclusion
- [x] Dossier management UI at `/dossier/ui`

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
- [x] Build dossier from credential chain
- [x] Dossier verifiable by verifier service
- [x] All formats work with verifier `/verify` endpoint
- [x] UI for dossier assembly

---

## Sprint 33: Azure Deployment (COMPLETE)

**Goal:** Deploy issuer and VVP-owned witnesses to Azure with custom domains.

**Commits:** `bfc61eb`, `e858a58`, `f2a4b2a`

**Deliverables:**
- [x] VVP-owned KERI witnesses deployed (3x Container Apps with deterministic AIDs)
- [x] Custom witness Docker image (`services/witness/Dockerfile`)
- [x] Issuer Container App with external ingress
- [x] Custom domains on rcnx.io (verifier, issuer, 3 witnesses)
- [x] HTTPS certificates (Azure managed) for all services
- [x] CI/CD pipeline with witness build and deployment
- [x] keripy submodule fixed for Python 3.12 compatibility

**Infrastructure:**
| Component | Azure Service | URL |
|-----------|---------------|-----|
| Verifier | Container App | https://vvp-verifier.rcnx.io |
| Issuer | Container App | https://vvp-issuer.rcnx.io |
| Witness 1 (wan) | Container App | https://vvp-witness1.rcnx.io |
| Witness 2 (wil) | Container App | https://vvp-witness2.rcnx.io |
| Witness 3 (wes) | Container App | https://vvp-witness3.rcnx.io |

**Witness AIDs (deterministic):**
- wan: `BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha`
- wil: `BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM`
- wes: `BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX`

**Key Files:**
```
services/witness/
├── Dockerfile           # Custom witness image based on gleif/keri:1.2.10
└── start-witness.py     # Deterministic salt startup script
.github/workflows/deploy.yml  # CI/CD with witness build/deploy jobs
.gitmodules              # keripy submodule configuration
```

**Exit Criteria:** ✅ All met
- [x] All 5 services deployed and healthy on rcnx.io custom domains
- [x] CI/CD pipeline successfully builds and deploys all services
- [x] Witness AIDs match expected deterministic values
- [x] HTTPS certificates working for all custom domains
- [x] Health endpoints responding (`/healthz` for services, `/oobi` for witnesses)

---

## Sprint 34: Schema Management (COMPLETE)

**Goal:** Import schemas from WebOfTrust repository, add SAID generation, enhanced schema UI.

**Prerequisites:** Sprint 29 (Credential Registry) complete.

**Commits:** `e0338f0`

**Deliverables:**
- [x] SAID computation module using keripy's `Saider.saidify()`
- [x] Schema import from WebOfTrust/schema repository
- [x] Schema creation API with auto-SAID generation
- [x] Enhanced schema management UI (import, create, delete)
- [x] Tests for SAID computation and import

**Key Files:**
```
services/issuer/app/schema/
├── said.py              # SAID computation using keripy Saider
├── importer.py          # WebOfTrust import with version pinning
└── store.py             # Enhanced with write capability
```

**API Endpoints:**
| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/schema/import` | POST | admin | Import schema from WebOfTrust registry |
| `/schema/create` | POST | admin | Create new schema with SAID computation |
| `/schema/{said}` | DELETE | admin | Remove user-added schema |
| `/schema/{said}/verify` | GET | readonly | Verify schema SAID is correct |

**Technical Notes:**
- SAID computation uses `keri.core.coring.Saider.saidify(sad=schema, label="$id")`
- Embedded schemas: `services/issuer/app/schema/schemas/` (read-only)
- User schemas: `~/.vvp-issuer/schemas/` or `/data/vvp-issuer/schemas/` (writable)
- Version pinning via `VVP_SCHEMA_REPO_REF` environment variable

**Exit Criteria:**
- SAID computation matches WebOfTrust kaslcred tool output
- Import all vLEI schemas from WebOfTrust repository
- Create custom schemas with valid SAIDs
- UI supports full schema lifecycle (view, import, create, delete)

---

## Sprint 35: End-to-End Integration Testing (COMPLETE)

**Goal:** Comprehensive integration test suite running against deployed Azure infrastructure.

**Prerequisites:** Sprint 33 (Azure Deployment) complete.

**Deliverables:**
- [x] Cross-service integration test framework
- [x] Full credential lifecycle test (issue → build dossier → verify)
- [x] Tests run against Azure-deployed issuer and verifier
- [x] Credential chain tests (root → intermediate → leaf)
- [x] All dossier formats tested against verifier `/verify` endpoint
- [x] Performance benchmarks for end-to-end flows
- [x] CI/CD integration for nightly integration test runs
- [x] Edge resolution tests (all edge types including direct SAID, dangling edges)
- [x] Benchmark results dashboard at `/admin/benchmarks/ui`
- [x] Azure Blob Storage helper for dossier hosting in Azure mode (SAS URLs)
- [x] Post-deployment integration tests in CI/CD (runs after deploy)
- [x] Deployment test results dashboard at `/admin` (shows pass/fail, history)

**Test Scenarios:**
| Scenario | Description |
|----------|-------------|
| Single credential | Issue one TN Allocation, build dossier, verify |
| Chained credentials | Issue chain (LE → TN Alloc), verify full chain |
| Aggregate dossier | Multiple root credentials in one dossier |
| CESR format | Build CESR dossier, verify via `/verify` |
| JSON format | Build JSON array dossier, verify via `/verify` |
| Revocation | Issue, revoke, verify rejection |
| Edge resolution | Verify all edge types parsed correctly |

**Key Files:**
```
tests/
└── integration/
    ├── conftest.py                  # Environment fixtures, unified dossier_server
    ├── pytest.ini                   # Test configuration
    ├── helpers/
    │   ├── issuer_client.py         # Issuer API wrapper
    │   ├── verifier_client.py       # Verifier API wrapper
    │   ├── passport_generator.py    # PASSporT generation
    │   ├── mock_dossier_server.py   # Mock HTTP server for local EVD URL
    │   └── azure_blob_helper.py     # Azure Blob Storage for Azure mode EVD URL
    ├── test_credential_lifecycle.py # Includes Azure full lifecycle tests
    ├── test_credential_chains.py
    ├── test_dossier_formats.py
    ├── test_revocation_flow.py
    ├── test_aggregate_dossiers.py
    ├── test_edge_resolution.py
    └── benchmarks/
        ├── conftest.py              # Benchmark fixtures
        └── test_performance.py      # Performance tests
scripts/
└── run-integration-tests.sh         # Run integration tests
.github/workflows/
├── integration-tests.yml            # Nightly CI/CD
└── deploy.yml                       # Post-deployment integration tests
services/issuer/app/api/
└── admin.py                         # /admin/benchmarks + /admin/deployment-tests
services/issuer/web/
├── benchmarks.html                  # Benchmark dashboard UI
└── admin.html                       # Admin dashboard with deployment test results
```

**Configuration:**
| Variable | Description |
|----------|-------------|
| `VVP_TEST_MODE` | Test mode (local, docker, azure) |
| `VVP_ISSUER_URL` | Issuer endpoint |
| `VVP_VERIFIER_URL` | Verifier endpoint |
| `VVP_TEST_API_KEY` | API key for test operations |
| `VVP_AZURE_STORAGE_CONNECTION_STRING` | Azure Storage for EVD URL serving |
| `VVP_ADMIN_API_KEY` | Admin API key for submitting test results (CI/CD secret) |

**Benchmark Thresholds:**
| Metric | p95 Target | p99 Max |
|--------|-----------|---------|
| Single credential | < 5s | < 10s |
| Chained (3 deep) | < 10s | < 20s |
| Concurrent (10x) | < 15s | < 30s |

**Exit Criteria:**
- [x] Integration tests pass locally with docker-compose
- [x] Tests cover full issuer → verifier flow
- [x] CI/CD runs integration tests nightly
- [x] Performance benchmarks with configurable thresholds
- [x] Benchmark dashboard at /admin/benchmarks/ui
- [x] Post-deployment integration tests run after Azure deploy
- [x] Deployment test results visible at /admin with history

---

## Sprint 36: Key Management & Rotation (COMPLETE)

**Goal:** Add key management and rotation capabilities for issuer identities.

**Prerequisites:** Sprint 30 (Security Model) complete.

**Deliverables:**
- [x] Identity rotation API (`POST /identity/{aid}/rotate`)
- [x] Rotation publishing to witnesses (KEL rotation events)
- [x] Key state persistence validated after rotation
- [x] Rotation audit logging and authorization (admin-only)
- [x] Rotation error handling (non-transferable AIDs, invalid thresholds)
- [x] Tests for rotation flows (pre/post-rotation verification)
- [x] UI "Rotate Keys" button with confirmation dialog and per-witness status

**Key Files:**
```
services/issuer/app/
├── keri/exceptions.py        # IdentityNotFoundError, NonTransferableIdentityError, InvalidRotationThresholdError
├── keri/identity.py          # RotationResult dataclass, rotate_identity() method
├── api/identity.py           # POST /identity/{aid}/rotate endpoint
├── api/models.py             # RotateIdentityRequest/Response, WitnessPublishDetail
└── web/create.html           # Rotate Keys UI button
services/issuer/tests/
├── test_identity.py          # 9 rotation unit tests + 3 API tests
tests/integration/
├── helpers/issuer_client.py  # rotate_identity() method
└── test_rotation.py          # 7 integration tests
```

**API Endpoints:**
| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/identity/{aid}/rotate` | POST | admin | Rotate keys for identity |

**Exit Criteria:**
- [x] Rotate an identity and publish rotation to witnesses
- [x] Key state persists correctly (sequence number incremented)
- [x] Rotation tests pass (18 unit + 3 API + 7 integration)

---

## Sprint 37: Session-Based Authentication (COMPLETE)

**Goal:** Implement session-based authentication for UI write operations, enabling users to log in once and perform authenticated operations without entering API keys for each request.

**Prerequisites:** Sprint 30 (Security Model) complete.

**Background:**
Currently, API endpoints require API keys via the `X-API-Key` header. GET endpoints are public for UI access, but write operations (POST/DELETE) require authentication. This sprint adds session-based auth so UI users can:
1. Log in once with their API key OR email/password
2. Have a session cookie that persists across requests
3. Perform write operations from the UI without manual API key entry

**Deliverables:**
- [x] Session management with secure cookies (HttpOnly, SameSite, Secure in production)
- [x] Login/logout API endpoints (`POST /auth/login`, `POST /auth/logout`, `GET /auth/status`)
- [x] Session store (in-memory with async locks; Redis stub for future)
- [x] Login UI modal with tabbed interface for email/password and API key authentication
- [x] Authenticated fetch wrapper (`authFetch()`) for UI JavaScript
- [x] Dual-mode auth: checks both session cookie and `X-API-Key` header
- [x] Session expiry and automatic cleanup via background task
- [x] Logout functionality in UI header
- [x] Login rate limiting (5 attempts per 15 minutes per IP)
- [x] CSRF protection via `X-Requested-With` header for cookie-authenticated requests
- [x] Tests for session lifecycle (login, auth, expiry, logout)
- [x] **Bonus:** Username/password authentication with bcrypt password hashing
- [x] **Bonus:** User management CRUD endpoints under `/admin/users`
- [x] **Bonus:** User management UI in admin panel
- [x] Session invalidation when user disabled or API key revoked (with `reload_if_stale()` checks)

**Commits:** `0e3795f`

**Key Files:**
```
services/issuer/app/
├── auth/
│   ├── session.py           # SessionStore, SessionMiddleware
│   └── api_key.py           # Updated to support session auth
├── api/
│   └── auth.py              # POST /auth/login, POST /auth/logout, GET /auth/status
├── config.py                # SESSION_SECRET, SESSION_EXPIRY, etc.
└── main.py                  # Session middleware integration
services/issuer/web/
├── shared.js                # authFetch() wrapper, session state management
├── login.html               # Standalone login page (optional)
└── *.html                   # Add login modal to existing UI pages
services/issuer/tests/
└── test_session.py          # Session management tests
```

**API Endpoints:**
| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/auth/login` | POST | None | Exchange API key for session cookie |
| `/auth/logout` | POST | Session | Invalidate current session |
| `/auth/status` | GET | Session | Get current session status and user info |

**Login Flow:**
1. User visits UI page (e.g., `/ui/credentials`)
2. UI checks session status via `GET /auth/status`
3. If no session, show login modal prompting for API key
4. User enters API key, UI calls `POST /auth/login` with key
5. Server validates key, creates session, sets `vvp_session` cookie
6. UI stores session state, enables write operations
7. Subsequent requests use `authFetch()` which includes credentials

**Session Cookie:**
| Attribute | Value | Description |
|-----------|-------|-------------|
| Name | `vvp_session` | Session identifier |
| HttpOnly | `true` | Prevent JavaScript access |
| SameSite | `Lax` | CSRF protection |
| Secure | `true` (prod) | HTTPS only in production |
| Max-Age | `3600` (1 hour) | Session duration |

**Configuration:**
| Variable | Default | Description |
|----------|---------|-------------|
| `VVP_SESSION_SECRET` | (required) | Secret key for session signing |
| `VVP_SESSION_EXPIRY` | `3600` | Session expiry in seconds |
| `VVP_SESSION_STORE` | `memory` | Session backend (memory, redis) |

**Technical Notes:**
- Sessions stored server-side; cookie contains signed session ID only
- Dual-mode auth: Accept either session cookie OR `X-API-Key` header
- Session inherits roles from the API key used at login
- In-memory store suitable for single-instance; Redis for multi-instance
- CSRF protection via SameSite cookie + optional token for state-changing ops

**Exit Criteria:**
- [x] Login via UI sets session cookie
- [x] Write operations work with session auth (no manual API key needed)
- [x] Session expires after configured duration
- [x] Logout clears session
- [x] Both session and API key auth work concurrently
- [x] UI shows logged-in state and user info
- [x] All session tests pass

---

## Sprint 38: OAuth (Microsoft M365) (COMPLETE)

**Goal:** Add Microsoft M365 OAuth login for the Issuer UI, enabling SSO alongside existing API key and username/password flows.

**Prerequisites:** Sprint 30 (Security Model) complete, Sprint 37 (Session-Based Authentication) complete.

**Background:**
Current UI authentication uses sessions created from API keys or username/password. This sprint adds Microsoft Entra ID (Azure AD) OAuth login to exchange a validated Microsoft identity for a VVP session. The existing API key and user auth remain supported for backward compatibility.

**Deliverables:**
- [x] OAuth login endpoints (`GET /auth/oauth/m365/start`, `GET /auth/oauth/m365/callback`)
- [x] Microsoft Entra application registration configuration (tenant ID, client ID, client secret)
- [x] Token validation and user identity mapping (email -> VVP user record)
- [x] Optional auto-provisioning for first-time users (configurable)
- [x] Session creation on successful OAuth callback
- [x] UI login modal button: "Sign in with Microsoft"
- [x] Admin configuration visibility for OAuth settings (read-only)
- [x] Tests for OAuth flow (mocked token exchange and callback)
- [x] Open redirect vulnerability protection for redirect_after parameter
- [x] Token validation tests with mocked JWKS (12 test cases)

**Key Files:**
```
services/issuer/app/
├── api/
│   └── auth.py              # OAuth start/callback endpoints + open redirect protection
├── auth/
│   ├── oauth.py             # OAuthStateStore, PKCE, token validation
│   └── users.py             # Updated with is_oauth_user flag
├── config.py                # OAUTH_* settings
└── main.py                  # Auth router + callback integration
services/issuer/web/
├── shared.js                # Microsoft login button + OAuth error handling
└── styles.css               # OAuth button styles
services/issuer/tests/
└── test_oauth.py            # 56 OAuth flow tests (mocked)
```

**OAuth Flow:**
1. UI clicks "Sign in with Microsoft"
2. `GET /auth/oauth/m365/start` redirects to Microsoft authorization URL
3. User authenticates with Microsoft, returns to callback URL
4. `GET /auth/oauth/m365/callback` exchanges code for tokens
5. Validate ID token (issuer, audience, nonce, tid, expiry)
6. Map email to VVP user; optionally auto-provision
7. Create VVP session and redirect back to UI

**Security Measures:**
- Server-side OAuthStateStore (mirrors SessionStore pattern)
- PKCE (code_verifier/code_challenge) prevents authorization code interception
- State parameter prevents CSRF attacks
- Nonce prevents ID token replay attacks
- Tenant (tid) claim validation ensures token from expected Azure tenant
- Full JWT validation (alg=RS256, kid, exp, iat, nbf, iss, aud, tid, nonce)
- Open redirect protection (validates redirect URLs are relative paths)
- HttpOnly cookies with SameSite=Lax for state_id cookie
- OAuth users flagged separately (cannot use password auth)

**Configuration:**
| Variable | Default | Description |
|----------|---------|-------------|
| `VVP_OAUTH_M365_ENABLED` | `false` | Enable Microsoft OAuth login |
| `VVP_OAUTH_M365_TENANT_ID` | - | Azure tenant ID |
| `VVP_OAUTH_M365_CLIENT_ID` | - | App registration client ID |
| `VVP_OAUTH_M365_CLIENT_SECRET` | - | App registration client secret |
| `VVP_OAUTH_M365_REDIRECT_URI` | - | OAuth callback URL |
| `VVP_OAUTH_M365_AUTO_PROVISION` | `false` | Auto-create user on first login |
| `VVP_OAUTH_M365_ALLOWED_DOMAINS` | - | Optional allowed email domains |
| `VVP_OAUTH_STATE_TTL_SECONDS` | `600` | OAuth state cookie/store TTL |
| `VVP_OAUTH_M365_DEFAULT_ROLES` | `issuer:readonly` | Roles for auto-provisioned users |

**Exit Criteria:**
- [x] OAuth login works end-to-end with Microsoft Entra
- [x] Session created and UI authenticated after OAuth callback
- [x] API key and username/password auth still function
- [x] Token validation and domain restrictions enforced
- [x] OAuth tests pass (56 tests, all mocked)

---

## Sprint 39: Code Review Remediation (COMPLETE)

**Goal:** Address blocking and high-priority issues identified during comprehensive code review (Phases 1-11).

**Prerequisites:** Sprint 38 (OAuth) complete, Code Review complete.

**Deliverables:**
- [x] B1: Verified OAuth redirect URL validation (already correctly implemented)
- [x] B2: Created issuer persistence tests (19 new tests)
- [x] H1: Fixed broken README.md documentation links (5 links corrected)
- [x] H3: Added coverage thresholds to pyproject.toml (70% fail_under for both services)
- [x] H8: Extracted TELClient timeout to configurable VVP_TEL_CLIENT_TIMEOUT
- [x] H17: Fixed Python version mismatch in DEVELOPMENT.md (3.10+ → 3.12+)

**Key Files:**
```
services/issuer/tests/test_persistence.py     # NEW: 19 persistence tests
services/issuer/pyproject.toml                # Added coverage config
services/verifier/pyproject.toml              # Added coverage config
services/verifier/app/core/config.py          # Added TEL_CLIENT_TIMEOUT_SECONDS
services/verifier/app/vvp/keri/tel_client.py  # Uses config for timeout
README.md                                      # Fixed documentation links
Documentation/DEVELOPMENT.md                  # Fixed Python version
```

**Test Results:**
- Issuer: 276 passed, 2 skipped
- Persistence tests: 19 passed

**Exit Criteria:**
- [x] All blocking issues addressed
- [x] Top high-priority items fixed
- [x] All tests pass
- [x] Code review remediation backlog documented in REVIEW.md

---

## Sprint 40: Vetter Certification Constraints (COMPLETE)

**Goal:** Implement verification of Vetter Certification credentials to enforce geographic and jurisdictional constraints on credential issuers.

**Prerequisites:** Sprint 31 (ACDC Issuance) complete.

**Spec Reference:** [How To Constrain Multichannel Vetters](Documentation/Specs/How%20To%20Constrain%20Multichannel%20Vetters.pdf)

**Background:**

Vetters (credential issuers) receive a "Vetter Certification" credential that constrains their authority:
- **ECC Targets**: List of E.164 country codes for which the vetter can attest TN (telephone number) right-to-use
- **Jurisdiction Targets**: List of ISO 3166-1 country codes for which the vetter can attest legal entity incorporation and brand licensure

When verifying a dossier, the verifier must check that:
1. The TN credential's country code appears in the issuing vetter's ECC Targets
2. The identity credential's incorporation country appears in the issuing vetter's Jurisdiction Targets
3. The brand credential's assertion country appears in the issuing vetter's Jurisdiction Targets

**Example Scenario:**

Vetter B has:
- ECC Targets: `["33", "91", "81", "66", "27", "971"]` (France, India, Japan, Thailand, South Africa, UAE)
- Jurisdiction Targets: `["FRA", "ZAF", "THA", "IND", "PAK", "USA", "CAN"]`

If Vetter B issues a TN credential for a UK number (+44), the verifier should flag this as invalid because "44" is not in Vetter B's ECC Targets.

**Deliverables:**

- [x] **Vetter Certification schema** - Define ACDC schema for Vetter Certification with `ecc_targets` and `jurisdiction_targets` fields
- [x] **Extended schemas** - TN Allocation, Legal Entity, and Brand schemas with required certification edges
- [x] **Credential edge traversal** - Follow backlinks from Identity/Brand/TN credentials to their issuing vetter's certification
- [x] **ECC Target validation** - Extract country code from TN and validate against vetter's ECC Targets
- [x] **Jurisdiction Target validation** - Validate incorporation country and brand assertion country against vetter's Jurisdiction Targets
- [x] **New claim types** - Add `vetter_constraints_valid` claim with `ecc_authorized` and `jurisdiction_authorized` child claims
- [x] **Error codes** - Add `VETTER_ECC_UNAUTHORIZED`, `VETTER_JURISDICTION_UNAUTHORIZED`, `VETTER_CERTIFICATION_MISSING`, `VETTER_CERTIFICATION_INVALID` error codes
- [x] **Configuration** - Add `VVP_ENFORCE_VETTER_CONSTRAINTS` flag (default: false) to enable/disable enforcement
- [x] **UI display** - Show vetter constraint validation status in verification UI
- [x] **Issuer UI** - Vetter Certification creation UI with ECC/jurisdiction target selection and edge picker for credentials
- [x] **Tests** - Comprehensive test coverage (61 unit tests for vetter constraints)

**Key Files:**

```
services/verifier/app/
├── vvp/
│   ├── vetter/                      # Vetter constraint validation
│   │   ├── __init__.py
│   │   ├── constraints.py           # ECC/Jurisdiction validation logic
│   │   ├── certification.py         # VetterCertification dataclass and parsing
│   │   ├── traversal.py             # Edge traversal to find vetter certifications
│   │   └── country_codes.py         # E.164 and ISO 3166-1 utilities
│   ├── verify.py                    # Integration with main verification flow
│   └── api_models.py                # VetterConstraintInfo, error codes
├── core/
│   └── config.py                    # VVP_ENFORCE_VETTER_CONSTRAINTS
services/verifier/tests/
├── test_vetter_constraints.py       # 61 unit tests
services/issuer/app/schema/schemas/
├── vetter-certification-credential.json   # Vetter Certification schema
├── extended-tn-allocation-credential.json # Extended TN with certification edge
├── extended-legal-entity-credential.json  # Extended LE with country + certification edge
├── extended-brand-credential.json         # Extended Brand with certification edge
services/issuer/web/
├── vetter.html                      # Vetter Certification creation UI
├── credentials.html                 # Updated with edge picker
├── help.html                        # Updated help recipes
```

**Schema SAIDs:**

| Type | SAID |
|------|------|
| Vetter Certification | `EJN4UJ_LIW5lrzmEAPv-fMhE2U64aJqp2aY38p1X-i8A` |
| Extended TN Allocation | `EGUh_fVLbjfkYFb5zAsY2Rqq0NqwnD3r5jsdKWLTpU8_` |
| Extended Legal Entity | `EPknTwPpSZi379molapnuN4V5AyhCxz_6TLYdiVNWvbV` |
| Extended Brand | `EK7kPhs5YkPsq9mZgUfPYfU-zq5iSlU8XVYJWqrVPk6g` |

**Configuration:**

| Variable | Default | Description |
|----------|---------|-------------|
| `VVP_ENFORCE_VETTER_CONSTRAINTS` | `false` | When true, violations propagate to parent claim status |

**Exit Criteria:**

- [x] Vetter Certification schema registered and validated
- [x] Extended schemas with certification edges created
- [x] ECC Target validation working for TN credentials
- [x] Jurisdiction Target validation working for Identity and Brand credentials
- [x] New claims appear in VerifyResponse
- [x] UI shows vetter constraint status
- [x] Issuer UI for vetter certification creation
- [x] All tests passing (1617 total tests)
- [x] Code review approved

---

## VVP CLI Toolkit (COMPLETE)

**Goal:** Create chainable command-line tools for parsing and analyzing JWTs, ACDCs, CESR streams, dossiers, and KERI structures.

**Deliverables:**
- [x] Unified `vvp` command with 8 subcommand groups (16 total commands)
- [x] JWT/PASSporT parsing and validation (`vvp jwt parse/validate`)
- [x] VVP-Identity header parsing (`vvp identity parse`)
- [x] CESR stream parsing and detection (`vvp cesr parse/detect`)
- [x] SAID computation, validation, injection (`vvp said compute/validate/inject`)
- [x] ACDC credential parsing and type detection (`vvp acdc parse/type`)
- [x] Dossier parsing, validation, and fetching (`vvp dossier parse/validate/fetch`)
- [x] Credential graph building (`vvp graph build`)
- [x] KEL parsing and validation (`vvp kel parse/validate`)
- [x] Adapter module for centralized imports with clear error messages
- [x] Comprehensive documentation (`Documentation/CLI_USAGE.md`)

**Key Files:**
```
common/common/vvp/cli/
├── __init__.py           # Package exports
├── main.py               # Main typer app, subcommand registration
├── adapters.py           # Centralized imports from verifier
├── utils.py              # Stdin/file reading, run_async(), exit codes
├── output.py             # JSON/pretty/table formatting
├── jwt.py                # vvp jwt parse/validate
├── identity.py           # vvp identity parse
├── cesr.py               # vvp cesr parse/detect
├── said.py               # vvp said compute/validate/inject
├── acdc.py               # vvp acdc parse/type
├── dossier.py            # vvp dossier parse/validate/fetch
├── graph.py              # vvp graph build
└── kel.py                # vvp kel parse/validate
common/pyproject.toml      # CLI deps + entry point
Documentation/CLI_USAGE.md # User guide with examples
```

**Installation:**
```bash
pip install -e services/verifier && pip install -e 'common[cli]'
vvp --help
```

**Exit Criteria:**
- [x] All 16 commands functional
- [x] Chainable via Unix pipes (stdin/stdout)
- [x] JSON output format for machine parsing
- [x] Adapter module for clean imports
- [x] Code review approved
- [x] Documentation complete

---

## Chain Revocation Fixes (COMPLETE)

**Goal:** Address code review issues in chain-aware revocation checking.

**Commits:** `a779952`

**Deliverables:**
- [x] Fix chain completeness enforcement in `build_all_credential_chains()` to detect missing links
- [x] Fix registry SAID extraction to use top-level ACDC `ri` field (not attributes)
- [x] Guard against empty `chain_saids` returning ACTIVE in `check_chain_revocation()`
- [x] Add 4 new tests for missing link detection, synthetic edges, ri extraction, empty chains

**Key Files:**
```
services/verifier/app/vvp/acdc/graph.py      # Chain completeness + ri extraction
services/verifier/app/vvp/keri/tel_client.py # Empty chain guard
services/verifier/tests/test_chain_revocation.py  # New tests
```

**Technical Notes:**
- `build_all_credential_chains()` now checks if `node.edges_to` targets exist in graph
- Missing links (excluding synthetic `root:`, `issuer:`, `qvi:` nodes) set `complete=False`
- `_build_node_from_acdc()` extracts `ri` from `acdc.raw` (top-level) not `acdc.attributes` (the `a` field)
- `check_chain_revocation()` returns UNKNOWN for empty chains instead of ACTIVE (empty `all()` bug)

**Exit Criteria:**
- [x] All 3 code review issues addressed
- [x] All 1661 tests pass (4 new tests added)
- [x] Code review approved

---

## Edge Operator Validation + DAG Visualization (COMPLETE)

**Goal:** Implement ACDC edge operator validation (I2I/DI2I/NI2I) and fix DAG visualization to properly represent credential chains.

**Deliverables:**
- [x] EdgeOperator enum (I2I, DI2I, NI2I) and EdgeValidationWarning dataclass
- [x] I2I validation: child.issuer == parent.issuee constraint
- [x] DI2I validation: delegation chain via DE credentials in dossier
- [x] NI2I validation: permissive, no constraint (reference-only edges)
- [x] Bearer credential recognition (`is_bearer`, `is_subject_bound` properties)
- [x] Schema constraint validation (warning-only, not blocking)
- [x] Operator validation integrated into vLEI chain resolution
- [x] `VVP_OPERATOR_VIOLATION_SEVERITY` config flag (INDETERMINATE/INVALID)
- [x] DAG visualization: arrows flow top→bottom (root→leaf)
- [x] DAG visualization: layer labels, separator lines, back-reference highlighting
- [x] Unit tests for operator validation (25 tests)

**Key Files:**
```
common/common/vvp/models/dossier.py          # EdgeOperator, EdgeValidationWarning
common/common/vvp/models/acdc.py             # is_bearer, issuee_aid properties
services/verifier/app/vvp/dossier/validator.py  # validate_i2i_edge, validate_di2i_edge, etc.
services/verifier/app/vvp/acdc/vlei_chain.py    # operator validation in chain resolution
services/verifier/app/core/config.py            # VVP_OPERATOR_VIOLATION_SEVERITY
services/verifier/app/templates/partials/credential_graph.html  # DAG visualization
services/verifier/tests/test_edge_operator.py   # 25 unit tests
```

**Technical Notes:**
- I2I is default operator when `o` field absent in edge
- Bearer credentials (no issuee) skip I2I constraint validation
- DI2I uses dossier-based delegation (DE credential chains)
- KEL-based delegated AID verification deferred to future phase
- DAG edges in data model: from=child, to=parent (reversed for display)
- Back-references highlighted in red with dashed lines

**Exit Criteria:**
- [x] All edge operators validated per ACDC spec
- [x] Operator warnings visible in chain resolution result
- [x] DAG visualization flows top-to-bottom (root to leaf)
- [x] All 1711 tests pass (25 new tests added)

---

## Sprint 41: User Management & Mock vLEI Infrastructure (COMPLETE)

**Goal:** Add multi-tenant user and organization management with mock vLEI credential chain and complete UI.

**Prerequisites:** Sprint 37 (Session-Based Authentication) complete.

**Deliverables:**
- [x] Database schema (SQLite + SQLAlchemy) for orgs, users, roles
- [x] Mock GLEIF + QVI infrastructure (pseudo root-of-trust)
- [x] Organization CRUD API (`POST/GET/PATCH /organizations`)
- [x] User management API (`POST/GET/PATCH/DELETE /users`)
- [x] Org roles: `org:administrator`, `org:dossier_manager`
- [x] Dossier scoping by credential ownership (full chain validation)
- [x] Organization API key management
- [x] Enhanced login page (`/login`) with email/password + API key + OAuth
- [x] User management UI (`/users/ui`) for org administrators
- [x] Organization management UI (`/organizations/ui`) for system admins
- [x] User profile page (`/profile`) for self-service password change
- [x] Navigation updates with role-based links and user/company context
- [x] Tests for multi-tenant access control (33 tests)
- [x] Combined system/org role access for credential/dossier endpoints

**Key Files:**
```
services/issuer/app/
├── db/
│   ├── models.py           # SQLAlchemy ORM (Organization, User)
│   └── session.py          # Database session management
├── org/
│   ├── service.py          # Organization CRUD
│   ├── mock_vlei.py        # Mock GLEIF/QVI manager
│   └── lei_generator.py    # Pseudo-LEI generation
├── auth/
│   ├── db_users.py         # Database-backed user store
│   └── org_roles.py        # Org role authorization
└── api/
    ├── organization.py     # Org management API
    └── user.py             # User management API
services/issuer/web/
├── login.html              # Enhanced login page
├── users.html              # User management UI
├── organizations.html      # Organization management UI
├── profile.html            # User profile page
└── shared.js               # Updated with org context
```

**Configuration:**
| Variable | Default | Description |
|----------|---------|-------------|
| `VVP_DATABASE_URL` | `sqlite:///.../vvp_issuer.db` | Database connection |
| `VVP_MOCK_VLEI_ENABLED` | `true` | Enable mock GLEIF/QVI |
| `VVP_MOCK_GLEIF_NAME` | `mock-gleif` | Mock GLEIF identity name |
| `VVP_MOCK_QVI_NAME` | `mock-qvi` | Mock QVI identity name |

**Exit Criteria:**
- [x] Mock GLEIF + QVI created on startup with valid credential chain
- [x] Organizations get pseudo-LEI + AID + Legal Entity credential
- [x] Organization API keys can be created and used for auth
- [x] Org admins can create/manage users in their org only
- [x] Dossier managers can build dossiers from org's credentials only
- [x] Cross-org access returns 403 Forbidden
- [x] Login page works with all auth methods (email/password, API key, OAuth)
- [x] User management UI allows CRUD operations for org users
- [x] Profile page allows password change
- [x] Navigation shows user/company context
- [x] All tests pass (367 tests)

---

## Sprint 42: SIP Redirect Signing Service

**Goal:** Implement a native SIP redirect signing service that receives SIP INVITEs, authenticates enterprises, looks up dossiers by originating TN, and returns SIP 302 responses with VVP-Identity headers and PASSporTs.

**Prerequisites:** Sprint 41 (User Management & Mock vLEI) MUST be COMPLETE.

**Background:**

SIP redirect is a standard B2BUA pattern where a redirect server receives a SIP INVITE, processes it, and returns a SIP 302 Moved Temporarily response with additional headers. This allows enterprises to sign outbound calls with VVP attestation without modifying their SBC infrastructure significantly.

**Architecture:**

```
Enterprise SBC ──SIP INVITE──> Azure VM (SIP Redirect) ──HTTPS──> Issuer API
     ↑                              │
     └───SIP 302 + VVP headers──────┘
```

- **SIP Redirect Service:** Runs on Azure VM (Container Apps don't support UDP)
- **Listens:** UDP/TCP port 5060
- **Auth:** `X-VVP-API-Key` custom SIP header
- **Response Headers:** `P-VVP-Identity`, `P-VVP-Passport`

**Deliverables:**

- [x] **SIP Service** (`services/sip-redirect/`)
  - [x] Minimal SIP parser (INVITE only, RFC 3261 subset)
  - [x] SIP 302/4xx response builder
  - [x] AsyncIO UDP/TCP transport server
  - [x] INVITE handler (parse → auth → lookup → VVP create → respond)
  - [x] Issuer API client for `/vvp/create` and `/tn/lookup`
  - [x] Unit tests for parser, builder, handler
  - [x] Comprehensive test fixtures (credentials, SIP messages, dossier)

- [x] **TN Mapping Module** (Issuer service)
  - [x] `TNMapping` model (org_id, tn, dossier_said, identity_name)
  - [x] `TNMappingStore` using Sprint 41 database
  - [x] TN lookup API (`POST /tn/lookup`)
  - [x] TN mapping CRUD API (`/tn/mappings`)
  - [x] TN mapping management UI (`/tn-mappings/ui`)

- [x] **Azure VM Deployment**
  - [x] VM provisioning on vvp-pbx (pbx.rcnx.io)
  - [x] Mock SIP services deployed (UDP 5070 signing, UDP 5071 verification)
  - [x] Systemd service configuration (vvp-mock-sip.service)
  - [x] Monitoring and logging

- [x] **Documentation**
  - [x] Enterprise SBC integration guide (`Documentation/SIP_SIGNER.md`)
  - [x] API key role requirements documented (org:dossier_manager or issuer:operator)
  - [x] Test fixtures documentation

**Key Files:**

```
services/sip-redirect/                 # NEW SERVICE
├── app/
│   ├── main.py                        # AsyncIO entrypoint
│   ├── config.py                      # Configuration
│   ├── audit.py                       # Audit logging
│   ├── status.py                      # HTTP status endpoint
│   ├── sip/
│   │   ├── parser.py                  # SIP message parser
│   │   ├── builder.py                 # SIP response builder
│   │   ├── models.py                  # SIPRequest, SIPResponse
│   │   └── transport.py               # UDP/TCP server
│   ├── redirect/
│   │   ├── handler.py                 # INVITE handler
│   │   └── client.py                  # Issuer API client
│   └── auth/
│       ├── api_key.py                 # X-VVP-API-Key validation
│       └── rate_limiter.py            # Per-API-key rate limiting
├── tests/
│   ├── fixtures/
│   │   ├── credentials.py             # Test AIDs, keys, credentials
│   │   ├── sip_messages.py            # Pre-built SIP messages
│   │   └── acme_dossier.json          # Test dossier JSON
│   ├── test_parser.py
│   ├── test_builder.py
│   ├── test_auth.py
│   └── test_fixtures.py
├── pyproject.toml
└── Dockerfile

services/issuer/app/
├── tn/                                # TN Mapping Module
│   ├── store.py                       # TNMappingStore CRUD
│   └── lookup.py                      # TN lookup with validation
├── api/
│   ├── tn.py                          # TN mapping API endpoints
│   └── vvp.py                         # Updated: accepts org:dossier_manager
└── web/
    └── tn-mappings.html               # TN mapping management UI

Documentation/
└── SIP_SIGNER.md                      # Enterprise integration guide
```

**API Endpoints:**

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/tn/mappings` | POST | operator | Create TN mapping |
| `/tn/mappings` | GET | readonly | List org's TN mappings |
| `/tn/mappings/{id}` | GET | readonly | Get specific mapping |
| `/tn/mappings/{id}` | PATCH | operator | Update mapping |
| `/tn/mappings/{id}` | DELETE | admin | Delete mapping |
| `/tn/lookup` | POST | internal | Lookup TN → dossier |

**SIP Protocol:**

Request (INVITE):
```
INVITE sip:+14445678@carrier.com SIP/2.0
From: <sip:+15551234567@enterprise.com>;tag=abc123
To: <sip:+14445678901@carrier.com>
Call-ID: xyz789@enterprise.com
X-VVP-API-Key: vvp_prod_abc123
...
```

Response (302):
```
SIP/2.0 302 Moved Temporarily
Contact: <sip:+14445678901@carrier.com>
Identity: <base64url>;info=<oobi>;alg=EdDSA;ppt=vvp
P-VVP-Identity: eyJwcHQiOiJ2dnAi...
P-VVP-Passport: eyJhbGciOiJFZERTQSI...
X-VVP-Brand-Name: Acme Corporation
X-VVP-Brand-Logo: https://cdn.acme.com/logo.png
X-VVP-Status: VALID
...
```

**X-Header Response Format (302 Response):**

The SIP Redirect service returns these headers on 302 Moved Temporarily responses:

| Header | Required | Description |
|--------|----------|-------------|
| `Identity` | Yes | RFC 8224 STIR PASSporT (standard STIR header) |
| `P-VVP-Identity` | Yes | Base64url VVP-Identity JSON |
| `P-VVP-Passport` | Yes | Complete PASSporT JWT |
| `X-VVP-Brand-Name` | Yes | Organization name from dossier |
| `X-VVP-Brand-Logo` | No | Logo URL from dossier vCard (may be absent) |
| `X-VVP-Status` | Yes | VALID, INVALID, or INDETERMINATE |

Note: `X-VVP-LEI` and `X-VVP-Error` are optional future enhancements, not required for MVP.

**Configuration:**

| Variable | Default | Description |
|----------|---------|-------------|
| `VVP_SIP_LISTEN_HOST` | `0.0.0.0` | Listen address |
| `VVP_SIP_LISTEN_PORT` | `5060` | SIP port |
| `VVP_SIP_TRANSPORT` | `udp` | Transport (udp, tcp, both) |
| `VVP_ISSUER_URL` | `https://vvp-issuer.rcnx.io` | Issuer API URL |
| `VVP_TN_MAPPING_ENABLED` | `true` | Enable TN mapping API |

**Security:**

1. `X-VVP-API-Key` header authentication
2. Organization-scoped TN mappings (uses Sprint 41 org model)
3. TN ownership validation against org's TN Allocation credentials
4. SIPS (TLS) support on port 5061
5. Audit logging for all INVITE requests
6. Per-API-key rate limiting

**Exit Criteria:**

- [x] SIP service listens on UDP port 5070 (mock signing service)
- [x] Parses INVITE, extracts From TN and X-VVP-API-Key
- [x] Authenticates API key via Issuer API
- [x] Looks up TN → dossier (org-scoped)
- [x] Returns SIP 302 with P-VVP-Identity and P-VVP-Passport
- [x] TN mapping CRUD API working
- [x] TN mapping management UI
- [x] Azure VM deployed with public IP (pbx.rcnx.io)
- [x] All tests passing (23 fixture tests + parser/builder tests)
- [x] Enterprise integration documentation (SIP_SIGNER.md)
- [x] `/vvp/create` updated to accept org:dossier_manager role

**Commits:** `e949bfe`, `9a060c2`, `4f7284a`, `a5faeaf`

**Test Fixtures:**
```
services/sip-redirect/tests/fixtures/
├── credentials.py      # AIDs, keys, credential builders, VVP-Identity header
├── sip_messages.py     # Pre-built SIP INVITE messages
├── acme_dossier.json   # Test dossier (JSON array of ACDCs)
├── test_data.json      # All test data in JSON format
└── acme_logo.svg       # Test organization logo
```

---

## Sprint 43: PBX Test Infrastructure

**Goal:** Deploy a PBX with SBC capabilities to test the VVP SIP redirect signer end-to-end, including a WebRTC client that displays verified brand name and logo.

**Prerequisites:** Sprint 42 (SIP Redirect Signing Service) should be COMPLETE or in progress.

**Background:**

To test the VVP SIP redirect signer, we need a PBX that can send SIP INVITEs to the redirect server, follow 3xx redirects, and pass X-VVP-* headers through to the receiving endpoint. A WebRTC client will display the verified caller's brand name and logo from these headers.

**Architecture:**

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Azure UK South                               │
│                                                                      │
│  ┌──────────────────┐     ┌──────────────────┐    ┌──────────────┐ │
│  │ FusionPBX VM     │     │ SIP Redirect VM  │    │ VVP Verifier │ │
│  │ (FreeSWITCH)     │     │ (Sprint 42)      │    │ Container App│ │
│  │                  │     │                  │    │              │ │
│  │ - SBC functions  │ SIP │ - Receives INVITE│HTTP│ - /verify    │ │
│  │ - mod_verto      │────>│ - Calls issuer   │───>│ - /verify-   │ │
│  │ - WebRTC gateway │<────│ - Returns 302    │    │   callee     │ │
│  │                  │ 302 │   + X-VVP-*      │    │              │ │
│  └────────┬─────────┘     └──────────────────┘    └──────────────┘ │
│           │                                                         │
│           │ WSS (WebSocket Secure)                                  │
└───────────┼─────────────────────────────────────────────────────────┘
            │
            ▼
    ┌──────────────────┐
    │ WebRTC Client    │
    │ (Browser)        │
    │ - SaraPhone fork │
    │ - Display name   │
    │ - Display logo   │
    │ - Show VVP status│
    └──────────────────┘
```

**Deliverables:**

**Phase 1: Azure Infrastructure Setup** (COMPLETE)
- [x] Deploy FusionPBX from Azure Marketplace (UK South)
- [x] Configure SSL certificate (Let's Encrypt)
- [x] Configure basic SIP trunk (Twilio Elastic SIP)
- [x] Verify WebRTC works (SIP.js client, not built-in Verto)
- [x] Document access URLs and credentials (pbx.rcnx.io)

**Phase 2: SIP Header Propagation & WebRTC Bridging** (COMPLETE)
- [x] Configure FreeSWITCH dialplan for VVP header injection
- [x] Add VVP header extraction dialplan (`/etc/freeswitch/dialplan/public.xml`)
- [x] **CRITICAL FINDING**: Verto.js `verto.rtc` endpoint cannot receive incoming calls
- [x] **SOLUTION**: Implemented SIP.js WebRTC client using port 7443 WSS (standard SIP over WebSocket)
- [x] Configured Let's Encrypt certificate for WSS endpoint
- [x] Fixed extension dial_string to use `sofia_contact()` instead of `verto_contact()`
- [x] **VALIDATED**: X-VVP-* headers propagate from dialplan → SIP INVITE → SIP.js browser client
- [x] Document validation results (SIP headers captured in browser console)

**Phase 3: WebRTC Client Development** (COMPLETE)
- [x] Created VVP Phone SIP.js client at `services/pbx/webrtc/vvp-phone/sip-phone.html`
- [x] Add VVP header extraction from SIP INVITE (`X-VVP-Brand-Name`, `X-VVP-Status`, `X-VVP-Brand-Logo`)
- [x] Add VVP display module for brand name, logo, status badge
- [x] Add bidirectional calling (inbound PSTN + outbound dial pad)
- [x] Style to match VVP branding
- [x] Test in Chrome, Safari (Firefox pending)

**Phase 4: End-to-End Integration** (PENDING - requires Sprint 42)
- [ ] Connect FusionPBX to VVP SIP Redirect service (Sprint 42)
- [ ] Configure test TN mappings in issuer
- [ ] Verify brand name and logo appear on WebRTC client
- [ ] Test all VVP status outcomes (VALID/INVALID/INDETERMINATE)

**Key Files:**

```
services/pbx/                           # NEW DIRECTORY
├── config/
│   ├── dialplan.xml                   # VVP header extraction
│   └── verto.conf.xml                 # Verto configuration
├── webrtc/
│   └── saraphone-vvp/                 # Forked SaraPhone
│       └── (modified for VVP display)
├── test/
│   └── mock_redirect.py               # Test 302 server
└── README.md                          # Setup documentation

Documentation/
└── PLAN_PBX.md                        # Approved plan (detailed)
```

**Configuration:**

| Setting | Value | Notes |
|---------|-------|-------|
| Domain | pbx.rcnx.io | DNS A record required |
| Azure Region | UK South | Same as other VVP services |
| VM Size | Standard_B2s | 2 vCPU, 4 GB RAM |
| Platform | FusionPBX (FreeSWITCH) | Azure Marketplace image |
| WebRTC Client | SaraPhone fork | Verto.js-based |

**Exit Criteria:**

- [x] FusionPBX accessible at https://pbx.rcnx.io
- [x] SIP registration working (port 5080 for Twilio, port 7443 WSS for WebRTC)
- [x] Dialplan injects X-VVP-* headers into SIP INVITE to WebRTC client
- [x] VVP headers propagate to WebRTC client via SIP.js (port 7443 WSS)
- [x] WebRTC client extracts brand name, logo, and status from SIP headers
- [x] Inbound PSTN call rings WebRTC client with VVP data displayed
- [ ] End-to-end test with real VVP SIP Redirect (requires Sprint 42)
- [ ] All three VVP statuses (VALID/INVALID/INDETERMINATE) render with correct colors

**Detailed Plan:** See `Documentation/PLAN_PBX.md` for full technical details, fallback approaches, and risk mitigations.

---

## Sprint 44: SIP Redirect Verification Service

**Goal:** Implement a SIP redirect-based verification service that receives inbound SIP INVITEs containing VVP headers (Identity/PASSporT), validates the dossier via the VVP Verifier, and returns the verified brand information as X-VVP-* headers for the receiving endpoint.

**Prerequisites:** Sprint 43 (PBX Test Infrastructure) MUST be COMPLETE.

**Background:**

Sprint 42 implements a **signing** service for outbound calls (enterprise → carrier). Sprint 44 implements the complementary **verification** service for inbound calls (carrier → enterprise). The PBX (Sprint 43) has already defined the expected header format and demonstrated header propagation to WebRTC clients.

**Architecture:**

```
Carrier SBC ──SIP INVITE + Identity/PASSporT──> SIP Redirect Verifier
                                                       │
                                                       ▼ HTTPS
                                                 VVP Verifier API
                                                 (/verify-callee)
                                                       │
                                                       ▼
                                                 Verification Result
                                                 (status, brand, logo)
                                                       │
PBX/WebRTC <──SIP 302 + X-VVP-* headers──────────────────┘
```

**Flow:**
1. Carrier sends SIP INVITE with RFC 8224 `Identity` header containing VVP PASSporT
2. SIP Redirect Verifier extracts headers: `Identity`, `P-VVP-Identity`, `P-VVP-Passport`
3. Service calls VVP Verifier `/verify-callee` endpoint with parsed data
4. Verifier validates: signature, dossier chain, revocation, TN authorization, brand
5. Service extracts verification result (status, brand name, logo URL)
6. Returns SIP 302 with X-VVP-* headers for PBX to pass to receiving endpoint

**Deliverables:**

**Phase 1: SIP Verification Service** (`services/sip-verify/`)
- [x] **SIP Parser** - Extract `Identity`, `P-VVP-Identity`, `P-VVP-Passport` headers from INVITE
- [x] **Identity Header Parser** - Parse RFC 8224 Identity header format:
  - `Identity: <base64url PASSporT>;info=<oobi>;alg=EdDSA;ppt=vvp`
- [x] **VVP-Identity Decoder** - Base64url decode JSON payload
- [x] **Verifier API Client** - Call VVP Verifier `/verify-callee` endpoint
- [x] **SIP 302 Response Builder** - Include X-VVP-* headers based on verification result
- [x] **SIP 4xx Response Builder** - Return appropriate errors for failed verification
- [x] **AsyncIO UDP/TCP Transport** - Extracted to `common/common/vvp/sip/` for reuse

**Phase 2: VVP Verifier Enhancements** (`services/verifier/`)
- [x] **Brand Info Extraction** - Add `brand_name` and `brand_logo_url` to VerifyResponse
- [x] **Caller ID from PASSporT** - Extract orig.tn for X-VVP-Caller-ID header
- [ ] **SIP Context Endpoint** - Optional: `/verify-sip` endpoint that accepts raw SIP headers

**Phase 3: PBX Integration** (`services/pbx/`)
- [ ] **Gateway Configuration** - Add `vvp-verify` gateway pointing to SIP Verify service
- [ ] **Dialplan Extension** - Route inbound PSTN calls through verification service first
- [ ] **Header Propagation Test** - Validate X-VVP-* headers reach WebRTC client

**Phase 4: Azure Deployment**
- [ ] **Deploy SIP Verify VM** - Azure VM with UDP/TCP 5060 (or share with Sprint 42 VM)
- [ ] **Network Security** - Configure NSG for carrier source IPs
- [ ] **Monitoring** - CloudWatch/Azure Monitor dashboards

**Key Files:**

```
services/sip-verify/                        # NEW SERVICE
├── app/
│   ├── main.py                             # AsyncIO entrypoint
│   ├── config.py                           # Configuration
│   ├── sip/
│   │   ├── parser.py                       # SIP message parser (shared with sip-redirect)
│   │   ├── identity_parser.py              # RFC 8224 Identity header parser
│   │   ├── builder.py                      # SIP response builder
│   │   └── transport.py                    # UDP/TCP server
│   ├── verify/
│   │   ├── handler.py                      # INVITE verification handler
│   │   ├── client.py                       # VVP Verifier API client
│   │   └── response_mapper.py              # Map VerifyResponse → X-VVP-* headers
│   └── models.py                           # VerificationResult, SIPRequest, SIPResponse
├── tests/
│   ├── test_identity_parser.py             # RFC 8224 parsing tests
│   ├── test_handler.py                     # Verification flow tests
│   └── test_response_mapper.py             # Header mapping tests
├── pyproject.toml
└── Dockerfile

services/verifier/app/vvp/
├── api_models.py                           # Update VerifyResponse with brand fields
└── verify_callee.py                        # Ensure brand info returned

services/pbx/config/
├── 00_vvp_verify_gateway.xml               # Gateway to SIP Verify service
└── 01_vvp_verify_dialplan.xml              # Inbound verification routing

common/common/vvp/sip/                      # NEW: Shared SIP utilities
├── __init__.py
├── parser.py                               # Shared SIP parser
├── identity.py                             # RFC 8224 Identity header utilities
└── builder.py                              # Shared response builder
```

**SIP Protocol:**

**Incoming INVITE (from carrier):**
```
INVITE sip:+14155551234@pbx.rcnx.io SIP/2.0
From: <sip:+15551234567@carrier.com>;tag=abc123
To: <sip:+14155551234@pbx.rcnx.io>
Call-ID: xyz789@carrier.com
Identity: eyJ0eXAiOiJwYXNzcG9ydCIsImFsZyI6IkVkRFNBIiwicHB0IjoidnZwIn0.eyJpYXQiOjE3MDcwMDAwMDAsIm9yaWciOnsidG4iOlsiKzE1NTUxMjM0NTY3Il19LCJkZXN0Ijp7InRuIjpbIisxNDE1NTU1MTIzNCJdfSwiZXZkIjoiaHR0cHM6Ly9pc3N1ZXIucmNueC5pby9kb3NzaWVyL0VGdm5vSERZN0kta2FCQmVLbGJEYmtqRzRCYUkwbktMR2FkeEJkak1HZ1NRIn0.signature;info=<https://vvp-witness1.rcnx.io/oobi/EGay...>;alg=EdDSA;ppt=vvp
...
```

**Outgoing 302 (to PBX - VALID verification):**
```
SIP/2.0 302 Moved Temporarily
Via: ...
From: ...
To: ...;tag=vvp-verify
Call-ID: xyz789@carrier.com
CSeq: 1 INVITE
Contact: <sip:+14155551234@pbx.rcnx.io:5060>
X-VVP-Brand-Name: Acme Corporation
X-VVP-Brand-Logo: https://cdn.acme.com/logo.png
X-VVP-Status: VALID
X-VVP-Caller-ID: +15551234567
Content-Length: 0
```

**Outgoing 302 (to PBX - INVALID verification):**
```
SIP/2.0 302 Moved Temporarily
...
Contact: <sip:+14155551234@pbx.rcnx.io:5060>
X-VVP-Brand-Name: Unknown
X-VVP-Status: INVALID
X-VVP-Error: SIGNATURE_INVALID
Content-Length: 0
```

**Outgoing 302 (to PBX - INDETERMINATE):**
```
SIP/2.0 302 Moved Temporarily
...
Contact: <sip:+14155551234@pbx.rcnx.io:5060>
X-VVP-Brand-Name: Acme Corporation
X-VVP-Brand-Logo: https://cdn.acme.com/logo.png
X-VVP-Status: INDETERMINATE
X-VVP-Warning: DOSSIER_FETCH_TIMEOUT
Content-Length: 0
```

**X-Header Response Format:**

| Header | Required | Source | Description |
|--------|----------|--------|-------------|
| `X-VVP-Status` | Yes | `VerifyResponse.overall_status` | VALID, INVALID, or INDETERMINATE |
| `X-VVP-Brand-Name` | Yes | Brand credential `fn` or `org` | Organization display name |
| `X-VVP-Brand-Logo` | No | Brand credential `logo` | Logo URL (may be absent) |
| `X-VVP-Caller-ID` | No | `PASSporT.orig.tn[0]` | Original caller number |
| `X-VVP-Error` | No | `VerifyResponse.errors[0].code` | Error code if INVALID |
| `X-VVP-Warning` | No | - | Warning if INDETERMINATE |

**Verifier API Call:**

```python
# POST /verify-callee
{
    "vvp_identity": {
        "ppt": "vvp",
        "kid": "https://vvp-witness1.rcnx.io/oobi/EGay...",
        "evd": "https://issuer.rcnx.io/dossier/EFvno...",
        "iat": 1707000000,
        "exp": 1707000300
    },
    "passport": "eyJhbGciOiJFZERTQSI...",
    "call_context": {
        "call_id": "xyz789@carrier.com",
        "cseq": "1 INVITE",
        "from_uri": "sip:+15551234567@carrier.com",
        "to_uri": "sip:+14155551234@pbx.rcnx.io"
    }
}
```

**Response Mapping:**

```python
def map_verify_response_to_headers(resp: VerifyResponse) -> dict:
    headers = {
        "X-VVP-Status": resp.overall_status.value,  # VALID/INVALID/INDETERMINATE
    }

    # Extract brand info from claims tree
    brand_claim = find_claim(resp.claims, "brand_verified")
    if brand_claim:
        # Evidence contains brand_credential:SAID, card.fn:matched, etc.
        headers["X-VVP-Brand-Name"] = extract_brand_name(brand_claim)
        logo = extract_brand_logo(brand_claim)
        if logo:
            headers["X-VVP-Brand-Logo"] = logo
    else:
        # Fallback: use identity name from dossier
        headers["X-VVP-Brand-Name"] = resp.issuer_identity.name or "Unknown"

    # Extract caller ID from passport
    if resp.passport_claims and resp.passport_claims.orig_tn:
        headers["X-VVP-Caller-ID"] = resp.passport_claims.orig_tn[0]

    # Add error/warning for non-VALID status
    if resp.overall_status == ClaimStatus.INVALID and resp.errors:
        headers["X-VVP-Error"] = resp.errors[0].code.value
    elif resp.overall_status == ClaimStatus.INDETERMINATE:
        headers["X-VVP-Warning"] = "VERIFICATION_INCOMPLETE"

    return headers
```

**Configuration:**

| Variable | Default | Description |
|----------|---------|-------------|
| `VVP_SIP_VERIFY_HOST` | `0.0.0.0` | Listen address |
| `VVP_SIP_VERIFY_PORT` | `5061` | SIP port (5060 if sharing with signing) |
| `VVP_SIP_VERIFY_TRANSPORT` | `udp` | Transport (udp, tcp, both) |
| `VVP_VERIFIER_URL` | `https://vvp-verifier.rcnx.io` | VVP Verifier API URL |
| `VVP_VERIFY_TIMEOUT` | `5.0` | Verification timeout in seconds |
| `VVP_FALLBACK_STATUS` | `INDETERMINATE` | Status when verification times out |
| `VVP_REDIRECT_TARGET` | `pbx.rcnx.io:5060` | Where to redirect after verification |

**Error Handling:**

| Scenario | SIP Response | X-VVP-Status | X-VVP-Error |
|----------|--------------|--------------|-------------|
| No Identity header | 400 Bad Request | - | - |
| Malformed Identity | 400 Bad Request | - | - |
| Signature invalid | 302 + headers | INVALID | `SIGNATURE_INVALID` |
| Dossier fetch failed | 302 + headers | INDETERMINATE | - |
| Revoked credential | 302 + headers | INVALID | `CREDENTIAL_REVOKED` |
| TN not authorized | 302 + headers | INVALID | `TN_NOT_AUTHORIZED` |
| Verification timeout | 302 + headers | INDETERMINATE | - |
| Verifier unreachable | 302 + headers | INDETERMINATE | - |

**Security:**

1. **TLS for Verifier API** - All calls to VVP Verifier use HTTPS
2. **Source IP filtering** - NSG restricts to known carrier IPs
3. **Rate limiting** - Per-source-IP rate limits to prevent DoS
4. **Audit logging** - All verification requests logged with result
5. **No credential storage** - Service is stateless; no secrets stored

**Relationship to Sprint 42:**

| Aspect | Sprint 42 (Signing) | Sprint 44 (Verification) |
|--------|---------------------|--------------------------|
| Direction | Outbound calls | Inbound calls |
| Input | API key + TN | Identity header + PASSporT |
| Processing | Lookup → Create dossier | Parse → Verify dossier |
| Output | 302 + VVP headers (new) | 302 + VVP headers (verified) |
| Backend | Issuer API | Verifier API |
| Shared | SIP parser, transport, 302 builder | Same infrastructure |

**Exit Criteria:**

- [ ] SIP Verify service listens on UDP/TCP port 5061
- [ ] Parses RFC 8224 `Identity` header from INVITE
- [ ] Extracts and decodes `P-VVP-Identity` JSON
- [ ] Calls VVP Verifier `/verify-callee` with parsed data
- [ ] Returns SIP 302 with X-VVP-* headers based on result
- [ ] Brand name and logo extracted from verification response
- [ ] All three statuses (VALID/INVALID/INDETERMINATE) handled correctly
- [ ] PBX receives and propagates headers to WebRTC client
- [ ] End-to-end test: carrier → SIP Verify → PBX → WebRTC with VVP display
- [ ] Error cases return appropriate X-VVP-Error codes
- [ ] Timeout/unreachable falls back to INDETERMINATE
- [ ] Azure VM deployed (or shared with Sprint 42 service)
- [ ] All tests passing

**Test Scenarios:**

| Scenario | Expected Result |
|----------|-----------------|
| Valid VVP call | VALID + brand name + logo displayed |
| Invalid signature | INVALID + "Unknown" brand |
| Revoked credential | INVALID + X-VVP-Error: CREDENTIAL_REVOKED |
| TN not in allocation | INVALID + X-VVP-Error: TN_NOT_AUTHORIZED |
| Dossier fetch timeout | INDETERMINATE + last known brand |
| Missing Identity header | 400 Bad Request (not forwarded) |
| Malformed PASSporT | INVALID + X-VVP-Error: PASSPORT_MALFORMED |

---

## Sprint 45: CI/CD SQLite Persistence Fixes

**Goal:** Fix CI/CD deployment conflicts with SQLite persistence on Azure Files, ensuring reliable deployments without database lock errors.

**Prerequisites:** Sprint 41 (User Management & Mock vLEI) - introduced SQLite persistence.

**Problem Statement:**

Sprint 41 introduced SQLite persistence on Azure Files for multi-tenant data (organizations, users, credentials, TN mappings). However, the current CI/CD deployment pattern causes database lock conflicts:

1. **Multiple Replicas** - Container Apps auto-scales to multiple replicas, but SQLite only supports single-writer mode
2. **Zero-Downtime Deploys** - Old and new revisions run simultaneously during deployment, both trying to access the same database
3. **Azure Files SMB Locking** - SQLite's file-based locking doesn't work reliably over SMB network shares
4. **Stale Lock Files** - Failed deployments can leave orphaned lock files that block subsequent startups

**Symptoms Observed:**
```
sqlalchemy.exc.OperationalError: (sqlite3.OperationalError) database is locked
[SQL: CREATE TABLE organizations (...)]
ERROR: Application startup failed. Exiting.
```

**Root Cause Analysis:**

| Issue | Impact | Current State |
|-------|--------|---------------|
| maxReplicas > 1 | Multiple writers corrupt SQLite | Set to 10 (default) |
| Zero-downtime deploy | Old/new revision race | Both run simultaneously |
| Azure Files SMB | Poor SQLite locking | Network latency exacerbates |
| No startup retry | First lock failure = crash | Immediate exit on lock |

**Recommended Solutions:**

**Option A: Single Replica + Stop-Before-Deploy (Recommended)**
- Force `maxReplicas=1` for issuer service
- Modify CI/CD to deactivate old revision before deploying new one
- Accept brief downtime (30-60s) during deployments
- Simplest solution, maintains SQLite benefits (zero-cost, no external DB)

**Option B: Startup Retry with Backoff**
- Add retry logic in `init_database()` with exponential backoff
- Wait for old revision to terminate and release lock
- Combine with Option A for reliability

**Option C: Migrate to Azure PostgreSQL (Future)**
- Full multi-replica support
- Proper concurrent connections
- Requires infrastructure changes and migration
- Higher cost (Azure Database for PostgreSQL)

**Deliverables:**

- [x] **CI/CD Workflow Changes** (`.github/workflows/deploy.yml`)
  - [x] Add `max-replicas 1` to issuer deployment
  - [x] Add pre-deployment step to deactivate old revision
  - [x] Add wait time between deactivation and new deployment
  - [x] Add health check retry logic after deployment

- [x] **Database Initialization Hardening** (`services/issuer/app/db/session.py`)
  - [x] Add retry with exponential backoff for database initialization
  - [x] Add SQLite PRAGMA settings for better Azure Files compatibility
  - [x] Add connection pool limits (StaticPool for SQLite)

- [x] **Container App Configuration**
  - [x] Document required settings (`maxReplicas: 1`, `minReplicas: 1`)
  - [x] Add health check grace period for database init
  - [x] Document Azure Files limitations

- [x] **Deployment Documentation** (`Documentation/DEPLOYMENT.md`)
  - [x] Document SQLite on Azure Files limitations
  - [x] Document manual recovery procedures for lock situations
  - [x] Document future migration path to PostgreSQL

**Key Files:**

```
.github/workflows/deploy.yml              # CI/CD changes
services/issuer/app/db/session.py         # Database init with retry
services/issuer/app/main.py               # Startup sequence
Documentation/DEPLOYMENT.md              # Deployment documentation
```

**CI/CD Changes (deploy.yml):**

```yaml
deploy-issuer:
  steps:
    # Step 1: Deactivate all active revisions first
    - name: Deactivate old revisions
      run: |
        OLD_REVS=$(az containerapp revision list --name vvp-issuer \
          --resource-group VVP --query "[?properties.active].name" -o tsv)
        for REV in $OLD_REVS; do
          echo "Deactivating $REV..."
          az containerapp revision deactivate --name vvp-issuer \
            --resource-group VVP --revision $REV || true
        done

    # Step 2: Wait for database lock to release
    - name: Wait for lock release
      run: sleep 30

    # Step 3: Deploy new revision with single replica
    - name: Deploy new revision
      run: |
        az containerapp update --name vvp-issuer --resource-group VVP \
          --image ${{ env.IMAGE }} \
          --min-replicas 1 --max-replicas 1

    # Step 4: Health check with retry
    - name: Verify deployment
      run: |
        for i in {1..12}; do
          if curl -sf https://vvp-issuer.rcnx.io/healthz; then
            echo "Health check passed"
            exit 0
          fi
          echo "Attempt $i failed, waiting..."
          sleep 10
        done
        echo "Health check failed after 2 minutes"
        exit 1
```

**Database Init Retry (`session.py`):**

```python
import time
from sqlalchemy.exc import OperationalError

def init_database(max_retries: int = 5, base_delay: float = 2.0):
    """Initialize database with retry for Azure Files lock issues."""
    for attempt in range(max_retries):
        try:
            Base.metadata.create_all(bind=engine)
            log.info("Database initialized successfully")
            return
        except OperationalError as e:
            if "database is locked" in str(e) and attempt < max_retries - 1:
                delay = base_delay * (2 ** attempt)  # Exponential backoff
                log.warning(f"Database locked, retry {attempt+1}/{max_retries} in {delay}s")
                time.sleep(delay)
            else:
                raise
```

**Configuration Changes:**

| Setting | Old Value | New Value | Reason |
|---------|-----------|-----------|--------|
| `maxReplicas` | 10 | 1 | SQLite single-writer |
| `minReplicas` | 1 | 1 | Consistent scaling |
| `activeRevisionsMode` | Single | Single | One active revision |
| Health check grace | 30s | 120s | Allow DB init retry |

**Testing:**

| Test | Expected Result |
|------|-----------------|
| Fresh deployment | New revision starts, DB created |
| Update deployment | Old deactivated, new starts, data preserved |
| Concurrent deploy | Only one revision active at a time |
| Failed startup | Retries, eventually succeeds |
| Manual recovery | Documented procedure restores service |

**Manual Recovery Procedure:**

```bash
# 1. List revisions
az containerapp revision list --name vvp-issuer --resource-group VVP -o table

# 2. Deactivate all problematic revisions
az containerapp revision deactivate --name vvp-issuer --resource-group VVP --revision <name>

# 3. If database is corrupt, delete and restart
az storage file delete --account-name vvpissuerdata --share-name issuer-data \
  --path "vvp_issuer.db" --account-key <key>

# 4. Force new revision
az containerapp update --name vvp-issuer --resource-group VVP \
  --set-env-vars "RESTART_TIMESTAMP=$(date +%s)"
```

**Future Considerations:**

- **PostgreSQL Migration** - When scaling requirements exceed single-replica limits
- **Redis Caching** - For high-read scenarios (TN lookups)
- **Database Backup** - Azure Files snapshots for point-in-time recovery
- **Monitoring** - Alert on database lock errors in logs

**Exit Criteria:**

- [x] CI/CD deploys with deactivate-before-deploy pattern
- [x] Issuer runs with `maxReplicas=1` in production
- [x] Database initialization includes retry logic
- [x] Health check allows time for DB init retry
- [x] Manual recovery procedure documented and tested
- [x] No database lock errors during normal deployment
- [x] All existing tests pass

---

## Sprint 46: PostgreSQL Migration (COMPLETE)

**Goal:** Migrate from SQLite on Azure Files to Azure Database for PostgreSQL for production scalability and zero-downtime deployments.

**Prerequisites:** Sprint 45 (CI/CD SQLite Persistence Fixes) - documented SQLite limitations.

**Problem Statement:**

Sprint 45 implemented workarounds for SQLite on Azure Files, but these are fundamentally anti-patterns:
- Single replica limitation prevents horizontal scaling
- Stop-before-deploy causes 30-60s downtime per deployment
- Stale lock files require manual recovery
- Complex retry logic for database initialization

**Solution:** Azure Database for PostgreSQL Flexible Server (~$16/month)

**Benefits:**

| Aspect | SQLite (Before) | PostgreSQL (After) |
|--------|-----------------|-------------------|
| Replicas | max=1 only | Unlimited scaling |
| Deployment | 30-60s downtime | Zero-downtime |
| Concurrent writes | Single-writer | Full MVCC |
| Connection pooling | StaticPool (1 conn) | QueuePool (10+) |

**Deliverables:**

- [x] **Update dependencies** (`services/issuer/pyproject.toml`)
  - [x] Replace `aiosqlite` with `psycopg[binary]`

- [x] **Refactor database session** (`services/issuer/app/db/session.py`)
  - [x] Add PostgreSQL connection pooling configuration
  - [x] Retain SQLite fallback for local development
  - [x] Remove SQLite-specific retry logic

- [x] **Update configuration** (`services/issuer/app/config.py`)
  - [x] Add `_get_database_url()` function
  - [x] Support PostgreSQL from `VVP_POSTGRES_*` env vars
  - [x] Enforce `sslmode=require` for Azure connections

- [x] **Update CI/CD** (`.github/workflows/deploy.yml`)
  - [x] Add PostgreSQL service container for tests
  - [x] Remove stop-before-deploy pattern
  - [x] Increase `maxReplicas` to 3
  - [x] Add PostgreSQL credentials as env vars

- [x] **Update documentation** (`Documentation/DEPLOYMENT.md`)
  - [x] Document PostgreSQL configuration
  - [x] Remove SQLite workarounds
  - [x] Document local development with SQLite fallback

**Key Files:**

```
services/issuer/pyproject.toml           # Dependencies
services/issuer/app/config.py            # Database URL construction
services/issuer/app/db/session.py        # Engine configuration
.github/workflows/deploy.yml             # CI/CD with PostgreSQL
Documentation/DEPLOYMENT.md              # Deployment docs
```

**Security Configuration:**

| Setting | Value | Purpose |
|---------|-------|---------|
| `sslmode` | require | Enforce TLS connections |
| Public access | None | Container Apps IPs only |
| Credentials | Key Vault → GitHub Secrets | No plaintext exposure |

**Exit Criteria:**

- [x] `psycopg[binary]` added to dependencies
- [x] session.py updated with PostgreSQL pooling
- [x] config.py constructs PostgreSQL URL with SSL
- [x] CI/CD uses PostgreSQL service container for tests
- [x] deploy-issuer job simplified (no stop-before-deploy)
- [x] All existing tests pass (390 tests)

**Infrastructure (Manual Steps Required):**

Before first PostgreSQL deployment:
1. Provision Azure PostgreSQL Flexible Server (B1ms tier)
2. Store credentials in Azure Key Vault
3. Add GitHub Secrets: `POSTGRES_HOST`, `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB`
4. Configure firewall for Container Apps IPs only

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
- "Sprint 34" - Schema management (import, SAID generation, UI)
- "Sprint 35" - End-to-end integration testing (against Azure)
- "Sprint 36" - Key management & rotation
- "Sprint 37" - Session-based authentication (UI login flow)
- "Sprint 38" - OAuth (Microsoft M365) for UI SSO
- "Sprint 39" - Code review remediation (blocking + high priority fixes)
- "Sprint 40" - Vetter certification constraints (geographic/jurisdictional validation)
- "Sprint 41" - User management & mock vLEI (multi-tenant orgs, users, login UI)
- "Sprint 42" - SIP redirect signing service (native SIP/UDP on Azure VM)
- "Sprint 43" - PBX test infrastructure (FusionPBX + WebRTC for testing Sprint 42)
- "Sprint 44" - SIP redirect verification service (verify inbound calls, extract brand info)
- "Sprint 45" - CI/CD SQLite persistence fixes (deployment lock conflicts)
- "Sprint 46" - PostgreSQL migration (zero-downtime deployments)
- "Sprint 47" - SIP monitor core infrastructure + authentication
- "Sprint 48" - SIP monitor real-time and VVP visualization
- "Sprint 49" - SIP monitor polish and deployment

Each sprint follows the pair programming workflow:
1. Plan phase (design, review, approval)
2. Implementation phase (code, test, review)
3. Completion phase (commit, deploy, document)

---

## Sprint 47: SIP Monitor - Core Infrastructure + Authentication (COMPLETE)

**Goal:** Add circular buffer event capture and session-authenticated web dashboard to the production SIP redirect service.

**Prerequisites:** Sprint 43 (PBX Test Infrastructure) COMPLETE.

**Background:**

Engineers need to visualize recent SIP INVITES and VVP headers for debugging. Originally planned for the mock SIP service, this was moved to the production sip-redirect service since the mock is now superseded.

**Implementation Notes:**

The monitoring dashboard was integrated into `services/sip-redirect/` rather than the mock service:
- Mock SIP service archived to `Documentation/archive/mock-sip-sprint47/`
- Dashboard enabled via `VVP_MONITOR_ENABLED=true` environment variable
- aiohttp and bcrypt are optional dependencies (`pip install .[monitor]`)

**Deliverables:**

- [x] **SIPEventBuffer class** - Async deque with max 100 events, add/get_all/get_since/clear methods
- [x] **Handler instrumentation** - Capture events in handle_invite() with full headers, source_addr, service field
- [x] **aiohttp web server** - Bound to localhost:8090 with REST endpoints:
  - `GET /api/events` - Return all buffered events
  - `GET /api/events/since/{id}` - Long-poll for new events
  - `POST /api/clear` - Clear buffer (CSRF protected)
- [x] **Session authentication module** (`auth.py`) - HttpOnly/Secure/SameSite cookies, bcrypt password store, rate limiting
- [x] **Login page** (`login.html`) - Username/password form
- [x] **Basic dashboard** (`index.html`) - Event table with timestamp, service, from→to, status
- [x] **SIPRequest model updates** - Added `headers` dict and `source_addr` for event capture

**Key Files:**

```
services/sip-redirect/app/
├── config.py                     # MODIFIED: MONITOR_* settings
├── main.py                       # MODIFIED: Dashboard startup/shutdown
├── redirect/handler.py           # MODIFIED: _capture_event() function
├── sip/models.py                 # MODIFIED: headers, source_addr fields
├── sip/parser.py                 # MODIFIED: Populate headers dict
├── sip/transport.py              # MODIFIED: Set source_addr
├── monitor/                      # NEW DIRECTORY
│   ├── __init__.py               # Module exports
│   ├── buffer.py                 # SIPEventBuffer
│   ├── auth.py                   # Session auth + rate limiting
│   └── server.py                 # aiohttp web server
└── monitor_web/                  # NEW DIRECTORY
    ├── index.html                # Dashboard page
    ├── login.html                # Login page
    ├── sip-monitor.js            # Client logic
    └── sip-monitor.css           # Styling
```

**Security:**

- Dashboard binds to `127.0.0.1:8090` (localhost only)
- Session cookies: HttpOnly, Secure, SameSite=Strict
- CSRF: POST endpoints require `X-Requested-With` header
- Rate limiting: 5 failed logins per 15 min
- MONITOR_ENABLED defaults to false (opt-in)

**Exit Criteria:**

- [x] Login required to access dashboard
- [x] `/api/events` returns JSON array of captured SIP events
- [x] Basic table renders events in browser
- [x] Events capture all headers and VVP-specific headers
- [x] Buffer limited to 100 events

---

## Sprint 48: SIP Monitor - Real-Time and VVP Visualization

**Goal:** Add WebSocket real-time updates and full VVP PASSporT/header visualization.

**Prerequisites:** Sprint 47 (Core Infrastructure) COMPLETE.

**Deliverables:**

- [x] **WebSocket endpoint** (`GET /ws`) - Stream new events in real-time
- [x] **WebSocket auth** - Validate session cookie on connection
- [x] **Connection management** - 30s idle timeout, 10 per-IP + 50 global limit, auto-restart on crash
- [x] **VVP header parsing** (JavaScript) - Extract Identity, P-VVP-Identity headers
- [x] **PASSporT JWT decode** (JavaScript) - Reuse base64urlDecode and parsing from verifier
- [x] **Tabbed detail view** - Summary, All Headers, VVP Headers, PASSporT, Raw SIP tabs
- [x] **Auto-reconnect** - Exponential backoff on WebSocket disconnect with polling fallback

**Code Reuse:**

From `services/verifier/web/index.html`:
- `base64urlDecode()` function
- JWT header/payload parsing logic
- SIP INVITE Identity header extraction regex

From `services/issuer/web/shared.js`:
- Tab switching logic
- `escapeHtml()` utility

**Key Files:**

```
services/pbx/test/
├── mock_sip_redirect.py          # MODIFY: Add WebSocket endpoint
└── monitor_web/
    ├── index.html                # MODIFY: Add tabbed detail view
    └── sip-monitor.js            # MODIFY: Add WebSocket, JWT parsing
```

**Exit Criteria:**

- [x] New events appear in browser within 100ms
- [x] WebSocket auto-reconnects on disconnect
- [x] JWT header/payload decoded and displayed
- [x] All SIP headers visible in table
- [x] VVP headers highlighted in dedicated tab
- [x] Connection status indicator works

---

## Sprint 49: SIP Monitor - Polish and Deployment

**Goal:** Finalize styling, configure nginx TLS termination, and deploy to PBX.

**Prerequisites:** Sprint 48 (Real-Time and VVP Visualization) COMPLETE.

**Deliverables:**

- [ ] **CSS styling** - Match VVP theme (colors, fonts, badges from WebRTC phone)
- [ ] **nginx reverse proxy** - TLS termination at `https://pbx.rcnx.io/sip-monitor/`
- [ ] **Deployment script** - Using `az vm run-command` pattern from CLAUDE.md
- [ ] **Systemd service update** - Add aiohttp, bcrypt dependencies
- [ ] **User provisioning script** - Generate random initial password, display once
- [ ] **Documentation** - Update README with monitor usage

**Key Files:**

```
services/pbx/
├── test/
│   └── monitor_web/
│       └── sip-monitor.css       # MODIFY: VVP theme
├── config/
│   ├── vvp-mock-sip.service      # MODIFY: Add deps
│   ├── nginx-sip-monitor.conf    # NEW: Reverse proxy config
│   └── users.json.template       # NEW: User store template
└── README.md                     # UPDATE: Monitor documentation
```

**nginx Configuration:**

```nginx
location /sip-monitor/ {
    proxy_pass http://127.0.0.1:8090/;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

**Exit Criteria:**

- [ ] Dashboard accessible at https://pbx.rcnx.io/sip-monitor/
- [ ] Login page appears, admin can authenticate
- [ ] WebSocket uses wss:// (secure)
- [ ] VVP-themed styling applied
- [ ] Test call (71006) captured and visualized
- [ ] Documentation complete
