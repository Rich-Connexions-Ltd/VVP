# VVP Issuer Service

## What This Service Does
The Issuer manages the full lifecycle of VVP credentials: organization management, KERI identity creation, credential issuance, dossier building, TN mappings, and VVP attestation signing. It provides both a REST API and a multi-page web UI.

## Key Files

| File | Purpose |
|------|---------|
| `app/main.py` | FastAPI app with all router mounts |
| `app/config.py` | Configuration (DB, OAuth, session, witnesses) |
| `app/api/` | All API routers (see below) |
| `app/keri/identity.py` | KERI identity management (inception, rotation) |
| `app/keri/witness.py` | Witness interaction and KEL publishing |
| `app/auth/api_key.py` | API key authentication |
| `app/auth/session.py` | Session management (HttpOnly cookies) |
| `app/auth/oauth.py` | Microsoft OAuth (Entra ID) integration |
| `app/auth/users.py` | User management |
| `app/auth/db_users.py` | Database-backed user store |
| `app/db/models.py` | SQLAlchemy models (Organization, Credential, Dossier, etc.) |
| `app/db/session.py` | Database session management |
| `app/audit/logger.py` | Audit logging |
| `config/witnesses.json` | Witness pool configuration |

## API Routers (`app/api/`)

| Router | Prefix | Purpose |
|--------|--------|---------|
| `health.py` | `/` | Health check |
| `auth.py` | `/auth` | Login/logout/OAuth |
| `organization.py` | `/api/organizations` | Organization CRUD |
| `org_api_key.py` | `/api/organizations/{id}/api-keys` | API key management |
| `identity.py` | `/api/identities` | KERI identity CRUD |
| `registry.py` | `/api/registries` | Credential registry CRUD |
| `credential.py` | `/api/credentials` | Credential issuance/revocation |
| `dossier.py` | `/api/dossiers` | Dossier building/signing |
| `tn.py` | `/api/tn` | TN mapping CRUD + lookup |
| `schema.py` | `/api/schemas` | Schema management |
| `user.py` | `/api/users` | User CRUD |
| `vvp.py` | `/api/vvp` | VVP attestation creation |
| `admin.py` | `/api/admin` | Admin operations |

## Authentication
Three methods:
1. **API key** - Header `X-API-Key` or body field. Used by SIP Redirect.
2. **Session** - HttpOnly cookie `vvp_session`. Used by web UI.
3. **Microsoft OAuth** - Entra ID SSO. Auto-provision with configurable domains.

RBAC roles: `admin`, `dossier_manager`, `viewer`

## Multi-Tenancy (Sprint 41)
- Organizations are isolated tenants
- API keys are scoped to organizations
- Users belong to organizations
- Credentials, dossiers, and TN mappings are per-organization

## Database
SQLAlchemy with SQLite. Key models:
- `Organization` - tenant with AID and auto-issued LE credential
- `Credential` - issued ACDCs with registry reference
- `Dossier` - built credential chains
- `TNMapping` - phone number → dossier + signing identity
- `User` - authenticated users with roles
- `OrgAPIKey` - organization-scoped API keys

## VVP Attestation Flow (`/api/vvp/create`)
1. Receive TN from SIP Redirect (with API key auth)
2. Look up TN mapping → get dossier + signing identity
3. Build PASSporT JWT (EdDSA signed by identity's AID)
4. Construct VVP-Identity header (base64url JSON)
5. Return headers for SIP 302 redirect

## Running Tests
```bash
cd services/issuer && ./scripts/run-tests.sh -v
```
20 test files. Key areas: auth, credentials, dossiers, TN mappings, multi-tenancy.

## Web UI Pages
Located in `web/` - Jinja2 templates + HTMX:
- `/login` - Login page
- `/create` - Identity creation
- `/ui/organizations` - Organization management
- `/ui/credentials` - Credential issuance
- `/ui/dossiers` - Dossier building
- `/ui/tn-mappings` - TN mapping management
- `/ui/admin` - Admin dashboard with audit logs
- `/registry/ui` - Registry management
- `/schemas/ui` - Schema browser
