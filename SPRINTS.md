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
| 38 | OAuth (Microsoft M365) | PLANNED | Sprint 30 |

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
- [ ] Login via UI sets session cookie
- [ ] Write operations work with session auth (no manual API key needed)
- [ ] Session expires after configured duration
- [ ] Logout clears session
- [ ] Both session and API key auth work concurrently
- [ ] UI shows logged-in state and user info
- [ ] All session tests pass

---

## Sprint 38: OAuth (Microsoft M365) (PLANNED)

**Goal:** Add Microsoft M365 OAuth login for the Issuer UI, enabling SSO alongside existing API key and username/password flows.

**Prerequisites:** Sprint 30 (Security Model) complete, Sprint 37 (Session-Based Authentication) complete.

**Background:**
Current UI authentication uses sessions created from API keys or username/password. This sprint adds Microsoft Entra ID (Azure AD) OAuth login to exchange a validated Microsoft identity for a VVP session. The existing API key and user auth remain supported for backward compatibility.

**Deliverables:**
- [ ] OAuth login endpoints (`GET /auth/oauth/m365/start`, `GET /auth/oauth/m365/callback`)
- [ ] Microsoft Entra application registration configuration (tenant ID, client ID, client secret)
- [ ] Token validation and user identity mapping (email -> VVP user record)
- [ ] Optional auto-provisioning for first-time users (configurable)
- [ ] Session creation on successful OAuth callback
- [ ] UI login modal button: “Sign in with Microsoft”
- [ ] Admin configuration visibility for OAuth settings (read-only)
- [ ] Tests for OAuth flow (mocked token exchange and callback)
- [ ] Documentation for setup steps and required Microsoft app permissions

**Key Files:**
```
services/issuer/app/
├── api/
│   └── auth.py              # OAuth start/callback endpoints
├── auth/
│   └── oauth.py             # OAuth helpers, token validation
├── config.py                # OAUTH_* settings
└── main.py                  # Auth router + callback integration
services/issuer/web/
├── shared.js                # Add Microsoft login button + flow
└── styles.css               # OAuth button styles
services/issuer/tests/
└── test_oauth.py            # OAuth flow tests (mocked)
```

**OAuth Flow:**
1. UI clicks “Sign in with Microsoft”
2. `GET /auth/oauth/m365/start` redirects to Microsoft authorization URL
3. User authenticates with Microsoft, returns to callback URL
4. `GET /auth/oauth/m365/callback` exchanges code for tokens
5. Validate ID token (issuer, audience, nonce, expiry)
6. Map email to VVP user; optionally auto-provision
7. Create VVP session and redirect back to UI

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

**Exit Criteria:**
- [ ] OAuth login works end-to-end with Microsoft Entra
- [ ] Session created and UI authenticated after OAuth callback
- [ ] API key and username/password auth still function
- [ ] Token validation and domain restrictions enforced
- [ ] OAuth tests pass (mocked)

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

Each sprint follows the pair programming workflow:
1. Plan phase (design, review, approval)
2. Implementation phase (code, test, review)
3. Completion phase (commit, deploy, document)
