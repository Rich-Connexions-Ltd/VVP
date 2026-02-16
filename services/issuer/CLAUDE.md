# VVP Issuer Service

## What This Service Does
The Issuer manages the full lifecycle of VVP credentials: organization management, KERI identity creation, credential issuance (with vetter constraint enforcement), dossier building, TN mappings, VVP attestation signing, and schema-driven credential management. It provides both a REST API and a multi-page web UI (HTMX + vanilla JS).

## Key Files

| File | Purpose |
|------|---------|
| `app/main.py` | FastAPI app, router mounts, UI routes, lifespan |
| `app/config.py` | All configuration (DB, OAuth, session, witnesses, auth) |
| `app/api/` | API routers (15 router files — all use `get_keri_client()`) |
| `app/api/models.py` | All Pydantic request/response models (~45 models) |
| `app/keri_client.py` | `KeriAgentClient` — HTTP client for KERI Agent (circuit breaker, retry) |
| `app/dossier/builder.py` | `DossierBuilder` — DFS edge walk via KeriAgentClient |
| `app/vetter/service.py` | `VetterCertificationManager` — 7-point validation |
| `app/vetter/constants.py` | Schema SAIDs, ECC/jurisdiction code lists |
| `app/org/mock_vlei.py` | `MockVLEIManager` — dual trust chains (GLEIF+GSMA) |
| `app/auth/api_key.py` | API key auth backend + `Principal` dataclass |
| `app/auth/session.py` | `InMemorySessionStore` + `LoginRateLimiter` |
| `app/auth/roles.py` | System role hierarchy + dependencies |
| `app/auth/org_roles.py` | Organization role hierarchy + dependencies |
| `app/auth/schema_auth.py` | Schema authorization by org type (Sprint 67) |
| `app/auth/scoping.py` | Multi-tenant credential access control |
| `app/auth/oauth.py` | Microsoft OAuth (Entra ID) with PKCE |
| `app/auth/users.py` | File-based user store |
| `app/auth/db_users.py` | `DatabaseUserStore` — DB-backed user auth |
| `app/db/models.py` | SQLAlchemy models (9 tables) + OrgType enum |
| `app/db/session.py` | Database session management |
| `app/audit/logger.py` | Structured audit logging |
| `config/witnesses.json` | Witness pool configuration |

## API Routers (`app/api/`)

| Router | Prefix | Key Endpoints |
|--------|--------|---------------|
| `health.py` | `/` | `GET /livez`, `GET /healthz`, `GET /readyz` (Sprint 68c probe contract) |
| `dashboard.py` | `/` | `GET /api/dashboard/status` |
| `auth.py` | `/auth` | login, logout, status, OAuth M365 start/callback |
| `identity.py` | `/identity` | CRUD + OOBI + rotate (6 endpoints) |
| `organization.py` | `/organizations` | CRUD + `/names` lightweight list (5 endpoints) |
| `org_api_key.py` | `/organizations/{org_id}/api-keys` | CRUD + revoke (4 endpoints) |
| `user.py` | `/users` | CRUD + `/me` + password change/reset (8 endpoints) |
| `registry.py` | `/registry` | CRUD (4 endpoints) |
| `schema.py` | `/schema` | list, get, verify, validate, import, create, delete, weboftrust, authorized (9 endpoints) |
| `session.py` | `/session` | `POST /session/switch-org` (Sprint 67) |
| `credential.py` | `/credential` | issue, list, get, revoke, delete (5 endpoints) |
| `dossier.py` | `/dossier` | create, build, build/info, associated, readiness, get (6 endpoints) |
| `tn.py` | `/tn` | mappings CRUD + lookup + test-lookup (7 endpoints) |
| `vvp.py` | `/vvp` | `POST /vvp/create` (1 endpoint) |
| `vetter_certification.py` | `/` | CRUD + `/organizations/{org_id}/constraints` + `/users/me/constraints` (6 endpoints) |
| `admin.py` | `/admin` | auth reload, status, users, config, settings, benchmarks (20 endpoints) |

**Note:** `main.py` also defines ~27 direct routes for UI pages (all `/ui/*`) and legacy redirects.

## Authentication

Three methods, checked in order by `APIKeyBackend`:
1. **Session cookie** (`vvp_session`) — HttpOnly, SameSite=Lax, CSRF header required for POST/PUT/DELETE/PATCH
2. **API key header** (`X-API-Key`) — file-based (`config/api_keys.json`) or database-backed (org API keys)
3. **Microsoft OAuth** (Entra ID) — PKCE + nonce + state validation, auto-provision with domain whitelist

### Role Hierarchy

**System roles** (in `app/auth/roles.py`):

| Role | Value | Inherits |
|------|-------|----------|
| Admin | `issuer:admin` | All (operator + readonly) |
| Operator | `issuer:operator` | readonly |
| Readonly | `issuer:readonly` | — |

**Organization roles** (in `app/auth/org_roles.py`, Sprint 41+):

| Role | Value | Inherits |
|------|-------|----------|
| Administrator | `org:administrator` | dossier_manager |
| Dossier Manager | `org:dossier_manager` | — |

System admins bypass all org role checks. Combined access functions: `check_credential_access_role()`, `check_credential_write_role()`, `check_credential_admin_role()`.

### Auth-Exempt Paths

Configured in `app/config.py:get_auth_exempt_paths()`:
- Always exempt: `/livez`, `/healthz`, `/readyz`, `/version`, `/auth/*`, `/auth/oauth/*`
- When `VVP_UI_AUTH_ENABLED=false` (default): all `/ui/*` pages, `/login`, `/profile`, legacy redirects, `/ui/walkthrough`

## Multi-Tenancy (Sprint 41+, Sprint 67)

- Organizations are isolated tenants with AID and pseudo-LEI
- **Org types** (Sprint 67): `root_authority` (GLEIF), `qvi`, `vetter_authority` (GSMA), `regular` (default). Enum: `OrgType` in `db/models.py`
- **Trust anchor promotion**: On startup, `MockVLEIManager._promote_trust_anchors()` promotes mock GLEIF/QVI/GSMA to first-class Organization records with correct org_type
- **Schema authorization** (Sprint 67): `app/auth/schema_auth.py` restricts which schemas each org type can issue. `POST /credential/issue` enforces this.
- **Org context switching** (Sprint 67): `POST /session/switch-org` lets admins operate as another org. `Session.home_org_id` (immutable) vs `Session.active_org_id` (mutable). `Session.get()` clones the session with overridden principal.
- API keys scoped to organizations via `OrgAPIKey` + `OrgAPIKeyRole`
- Users belong to organizations via `UserOrgRole` join table
- Credentials tracked per-org via `ManagedCredential`
- Dossier-OSP visibility via `DossierOspAssociation`
- Access scoping in `app/auth/scoping.py`: `can_access_credential()`, `get_org_credentials()`, `validate_dossier_chain_access()`

## Database

SQLAlchemy with PostgreSQL (SQLite for local dev). 9 models in `app/db/models.py`:

| Model | Purpose |
|-------|---------|
| `Organization` | Tenant with AID, pseudo-LEI, LE credential, vetter cert pointer |
| `User` | Authenticated user with system roles, org membership |
| `UserOrgRole` | User ↔ Organization role join table |
| `OrgAPIKey` | Organization-scoped API key (bcrypt hashed) |
| `OrgAPIKeyRole` | API key ↔ role join table |
| `ManagedCredential` | Tracks credential ownership by organization |
| `MockVLEIState` | Persists mock GLEIF/QVI/GSMA infrastructure state |
| `TNMapping` | E.164 phone number → dossier + signing identity |
| `DossierOspAssociation` | Dossier ↔ OSP organization visibility |

## KERI Agent Integration (Sprint 68c)

All KERI operations are delegated to the standalone KERI Agent service via `KeriAgentClient` (`app/keri_client.py`). The issuer has **no `app/keri/` directory** and **no keripy dependency**.

### KeriAgentClient (`app/keri_client.py`)
- Async HTTP client targeting `VVP_KERI_AGENT_URL` (default `http://keri-agent.internal:8002`)
- Bearer token auth via `VVP_KERI_AGENT_AUTH_TOKEN`
- Circuit breaker (5 failures → open for 30s → half-open probe)
- Retry: GET-only retries with exponential backoff, no retry on mutating POST
- Methods: `create_identity()`, `list_identities()`, `issue_credential()`, `revoke_credential()`, `build_dossier()`, `create_vvp_attestation()`, `get_bootstrap_status()`, etc.

### Dossier Assembly (`app/dossier/builder.py`)
DFS edge walk via KeriAgentClient. Credential lookups, CESR retrieval, and edge resolution all go through the agent.

## Vetter Certification (Sprint 61-62)

Organizations can be associated with VetterCertification credentials (geographic ECC + jurisdictional constraints):

- **`app/vetter/service.py`** — `resolve_active_vetter_cert()` (7-point fail-closed validation), issue/revoke
- **`app/vetter/constants.py`** — `VETTER_CERT_SCHEMA_SAID`, `VALID_ECC_CODES`, `VALID_JURISDICTION_CODES`, `KNOWN_EXTENDED_SCHEMA_SAIDS`
- **Mock GSMA** — Separate trust chain from QVI. State: `MockVLEIState.gsma_aid` + `gsma_registry_key`
- **Edge injection** — `_inject_certification_edge()` in `credential.py` auto-populates `certification` edge for extended schemas
- **Constraint validation** — `validate_issuance_constraints()` checks ECC/jurisdiction against schema attributes. Hard/soft enforcement via `ENFORCE_VETTER_CONSTRAINTS`

## Schema-Aware Credential Management (Sprint 65)

- **Dossier readiness**: `GET /dossier/readiness` checks edge slot fulfillment
- **Edge block parsing**: Schema JSON `properties.e.oneOf` parsed for slot definitions
- **Slot statuses**: `ready`, `missing`, `invalid`, `optional_missing`, `optional_unconstrained`
- **Models**: `DossierSlotStatus`, `DossierReadinessResponse`

## VVP Attestation Flow (`POST /vvp/create`)
1. Receive TN from SIP Redirect (with API key auth)
2. Look up TN mapping → get dossier + signing identity
3. Build PASSporT JWT (EdDSA signed by identity's AID)
4. Construct VVP-Identity header (base64url JSON with evd URL)
5. Return `vvp_identity_header`, `passport_jwt`, `identity_header` (RFC 8224)

## Running Tests
```bash
cd services/issuer && ./scripts/run-tests.sh -v
```
Uses `DYLD_LIBRARY_PATH` for libsodium. ~20 test files covering auth, credentials, dossiers, TN mappings, multi-tenancy, vetter certification, walkthrough, readiness.

## Web UI Pages

Located in `web/` — HTML + HTMX + vanilla JS, served as `FileResponse`:

| Path | Page | File |
|------|------|------|
| `/ui/` | Home/landing | `index.html` |
| `/login` | Login | `login.html` |
| `/ui/identity` | Identity management | `identity.html` |
| `/ui/registry` | Registry management | `registry.html` |
| `/ui/schemas` | Schema browser | `schemas.html` |
| `/ui/credentials` | Credential issuance | `credentials.html` |
| `/ui/dossier` | Dossier building | `dossier.html` |
| `/ui/vvp` | VVP attestation | `vvp.html` |
| `/ui/dashboard` | Central dashboard | `dashboard.html` |
| `/ui/admin` | Admin panel | `admin.html` |
| `/ui/vetter` | Vetter certification | `vetter.html` |
| `/ui/tn-mappings` | TN mapping management | `tn-mappings.html` |
| `/ui/benchmarks` | Performance benchmarks | `benchmarks.html` |
| `/ui/help` | Help/documentation | `help.html` |
| `/ui/walkthrough` | Interactive split-pane walkthrough | `walkthrough.html` |
| `/ui/organization-detail` | Organization detail with tabs | `organization-detail.html` |
| `/organizations/ui` | Organization management | `organizations.html` |
| `/users/ui` | User management | `users.html` |
| `/profile` | User profile | `profile.html` |

Legacy paths (`/create`, `/registry/ui`, `/schemas/ui`, `/credentials/ui`, `/dossier/ui`) redirect (302) to `/ui/*` equivalents.

## Key Configuration (`app/config.py`)

| Variable | Default | Purpose |
|----------|---------|---------|
| `VVP_AUTH_ENABLED` | `true` | Global auth toggle |
| `VVP_UI_AUTH_ENABLED` | `false` | Require auth for web UI |
| `VVP_MOCK_VLEI_ENABLED` | `true` | Enable mock vLEI infrastructure |
| `VVP_ISSUER_BASE_URL` | `http://localhost:8001` | Public URL for dossier/OOBI links |
| `VVP_DATABASE_URL` | `sqlite:///{DATA_DIR}/vvp_issuer.db` | SQLAlchemy database URL (PostgreSQL in production) |
| `VVP_ISSUER_DATA_DIR` | auto-detect | Local data directory (database, config) |
| `VVP_SESSION_TTL` | `3600` | Session TTL (seconds) |
| `VVP_LOGIN_RATE_LIMIT_MAX` | `5` | Login attempts before lockout |
| `VVP_OAUTH_M365_ENABLED` | `false` | Enable Microsoft OAuth |
| `VVP_ENFORCE_VETTER_CONSTRAINTS` | `false` | Hard-fail on constraint violations |
| `VVP_WITNESS_THRESHOLD` | `2` | Min witnesses for success |
