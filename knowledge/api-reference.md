# VVP API Reference

## Verifier Service API (`services/verifier/`)

Base URL: `https://vvp-verifier.wittytree-2a937ccd.uksouth.azurecontainerapps.io`

### Core Verification Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/verify` | Verify caller identity (main endpoint) |
| `POST` | `/verify-callee` | Verify callee identity (§5B) |
| `POST` | `/check-revocation` | Check credential revocation via TEL |
| `GET` | `/healthz` | Health check |
| `GET` | `/version` | Service version with git SHA |

### Admin Endpoints (gated by `ADMIN_ENDPOINT_ENABLED`)

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/admin` | All configurable items and cache metrics |
| `POST` | `/admin/log-level` | Change log level at runtime |
| `POST` | `/admin/cache/clear` | Clear dossier/revocation/schema cache |
| `POST` | `/admin/witnesses/discover` | Trigger GLEIF witness discovery |

### UI Pages

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/` | Landing page |
| `GET` | `/verify` | Verification mode selection |
| `GET` | `/verify/full` | Full verification explorer (HTMX) |
| `GET` | `/verify/simple` | Simple single-step verification |
| `GET` | `/verify/explore` | Tabbed explorer (JWT/SIP/SAID) |
| `GET` | `/create` | Dossier creation landing |
| `GET` | `/ui/admin` | Admin dashboard |

### POST /verify - Caller Verification

**Headers**: `VVP-Identity: <base64url-encoded JSON>` (required)

**Request Body** (`VerifyRequest`):
```json
{
  "passport_jwt": "eyJhbGciOi...",
  "context": {
    "call_id": "a84b4c76e66710",
    "received_at": "2026-01-23T12:00:00Z",
    "sip": {
      "from_uri": "sip:+447884666200@example.com",
      "to_uri": "sip:+447769710285@example.com",
      "invite_time": "2026-01-23T12:00:00Z",
      "cseq": 314159
    }
  }
}
```

**Response** (`VerifyResponse`):
```json
{
  "request_id": "uuid",
  "overall_status": "VALID|INVALID|INDETERMINATE",
  "claims": [/* ClaimNode tree */],
  "errors": [/* ErrorDetail list */],
  "has_variant_limitations": false,
  "delegation_chain": {/* DelegationChainResponse */},
  "signer_aid": "Eabc...",
  "toip_warnings": [/* ToIPWarningDetail list */],
  "issuer_identities": {"AID": {/* IssuerIdentityInfo */}},
  "vetter_constraints": {"SAID": {/* VetterConstraintInfo */}},
  "brand_name": "Acme Corp",
  "brand_logo_url": "https://..."
}
```

### POST /verify-callee - Callee Verification

Same structure as `/verify` but requires:
- `context.call_id` (REQUIRED)
- `context.sip.cseq` (REQUIRED)
- `VVP-Identity` header (REQUIRED)
- Optional `caller_passport_jwt` for goal overlap check

### POST /check-revocation

**Request**: `{"credential_said": "E...", "registry_said": "E...", "oobi_url": "http://..."}`
**Response**: `{"success": true, "status": "active|revoked|unknown", ...}`

---

## Issuer Service API (`services/issuer/`)

Base URL: `https://vvp-issuer.rcnx.io`

### Health

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/healthz` | Health check with witness status |

### Authentication (`/auth`)

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/auth/login` | Login (API key or email/password) |
| `POST` | `/auth/logout` | Logout (clear session) |
| `GET` | `/auth/status` | Current auth status |
| `GET` | `/auth/oauth/status` | OAuth configuration status |
| `GET` | `/auth/oauth/m365/start` | Start Microsoft OAuth flow |
| `GET` | `/auth/oauth/m365/callback` | OAuth callback handler |

### Organizations (`/api/organizations`)

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/api/organizations` | Create organization (auto-provisions KERI identity + LE credential) |
| `GET` | `/api/organizations` | List organizations |
| `GET` | `/api/organizations/names` | List org names (lightweight, any auth) |
| `GET` | `/api/organizations/{id}` | Get organization details |
| `PATCH` | `/api/organizations/{id}` | Update organization |

#### GET /api/organizations/names (Sprint 63)

Lightweight org name list for any authenticated user. Used by dossier wizard for AP and OSP dropdowns.

**Query Parameters:**
- `purpose` (optional): `ap` (default) or `osp`
  - `ap`: Non-admins see only their own org; admins see all
  - `osp`: All authenticated users see all enabled orgs

**Response:** `OrganizationNameListResponse`
```json
{
  "count": 2,
  "organizations": [
    {"id": "uuid", "name": "ACME Corp"},
    {"id": "uuid", "name": "Example Inc"}
  ]
}
```

### Organization API Keys (`/api/organizations/{id}/api-keys`)

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/api/organizations/{id}/api-keys` | Create API key |
| `GET` | `/api/organizations/{id}/api-keys` | List API keys |
| `GET` | `/api/organizations/{id}/api-keys/{key_id}` | Get API key |
| `DELETE` | `/api/organizations/{id}/api-keys/{key_id}` | Revoke API key |

### KERI Identities (`/api/identities`)

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/api/identities` | Create KERI identity (inception) |
| `GET` | `/api/identities` | List identities |
| `GET` | `/api/identities/{aid}` | Get identity details |
| `GET` | `/api/identities/{aid}/oobi` | Get OOBI URL |
| `POST` | `/api/identities/{aid}/rotate` | Rotate keys |
| `DELETE` | `/api/identities/{aid}` | Delete identity |

### Credential Registries (`/api/registries`)

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/api/registries` | Create credential registry |
| `GET` | `/api/registries` | List registries |
| `GET` | `/api/registries/{key}` | Get registry details |
| `DELETE` | `/api/registries/{key}` | Delete registry |

### Credentials (`/api/credentials`)

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/api/credentials/issue` | Issue ACDC credential |
| `GET` | `/api/credentials` | List credentials |
| `GET` | `/api/credentials/{said}` | Get credential details |
| `POST` | `/api/credentials/{said}/revoke` | Revoke credential |
| `DELETE` | `/api/credentials/{said}` | Delete credential |

#### GET /credential Query Filters (Sprint 63)

- `schema_said` (optional): Filter to credentials matching this schema SAID
- `org_id` (optional, admin-only): Scope credentials to a specific org. Non-admins receive 403. Relationship tagging is computed from the perspective of the specified org.
- `status` (optional): Filter by credential status (e.g., `issued`)

### Dossiers (`/api/dossiers`)

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/api/dossier/create` | Create dossier ACDC with edge validation (Sprint 63) |
| `POST` | `/api/dossier/build` | Build dossier from credential SAID |
| `POST` | `/api/dossier/build/info` | Build info (credential count, format) |
| `GET` | `/api/dossier/associated` | List dossiers associated with principal's org as OSP (Sprint 63) |
| `GET` | `/api/dossier/{said}` | Get public dossier by SAID |

#### POST /api/dossier/create (Sprint 63)

Create a dossier ACDC with server-side edge validation, ACDC issuance, and optional OSP association.

**Auth:** `issuer:operator+` or `org:dossier_manager+`

**Request:** `CreateDossierRequest`
```json
{
  "owner_org_id": "uuid (AP org)",
  "name": "My VVP Dossier (optional)",
  "edges": {
    "vetting": "SAID_of_LE_credential",
    "alloc": "SAID_of_GCD_credential",
    "tnalloc": "SAID_of_TNAlloc_credential",
    "delsig": "SAID_of_delegation_credential",
    "bownr": "SAID_of_brand_credential (optional)",
    "bproxy": "SAID_of_brand_proxy (optional)"
  },
  "osp_org_id": "uuid (optional OSP association)"
}
```

**Response:** `CreateDossierResponse`
```json
{
  "dossier_said": "E...",
  "issuer_aid": "E...",
  "schema_said": "EH1jN4U4...",
  "edge_count": 4,
  "name": "My VVP Dossier",
  "osp_org_id": "uuid or null",
  "dossier_url": "https://vvp-issuer.rcnx.io/api/dossier/E...",
  "publish_results": [{"witness_url": "...", "success": true}]
}
```

**Edge validation:**
- Required: `vetting`, `alloc`, `tnalloc`, `delsig`
- Optional: `bownr`, `bproxy`
- Schema match enforced for constrained edges
- I2I operator validated for `alloc`, `tnalloc`
- `delsig` issuer must be AP's AID (§5.1 step 9)
- `bproxy` required when `bownr` present and OP differs from AP (§6.3.4)
- Per-edge access policy: `ap_org` (5 edges) or `principal` (bproxy only)

#### GET /api/dossier/associated (Sprint 63)

List dossiers associated with the principal's organization as OSP.

**Auth:** `issuer:readonly+` or `org:dossier_manager+`
**Query Parameters:** `org_id` (optional, admin-only): Filter by specific OSP org
**Scoping:** Admins see all; org-scoped principals see only their org's associations

### TN Mappings (`/api/tn`)

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/api/tn/mappings` | Create TN mapping |
| `GET` | `/api/tn/mappings` | List mappings |
| `GET` | `/api/tn/mappings/{id}` | Get mapping details |
| `PATCH` | `/api/tn/mappings/{id}` | Update mapping |
| `DELETE` | `/api/tn/mappings/{id}` | Delete mapping |
| `POST` | `/api/tn/lookup` | Look up TN (used by SIP Redirect) |
| `POST` | `/api/tn/test-lookup/{id}` | Test a specific mapping |

### Schemas (`/api/schemas`)

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/api/schemas` | List schemas |
| `GET` | `/api/schemas/weboftrust/registry` | WebOfTrust schema registry |
| `GET` | `/api/schemas/{said}` | Get schema by SAID |
| `GET` | `/api/schemas/{said}/verify` | Verify schema SAID |
| `POST` | `/api/schemas/validate` | Validate data against schema |
| `POST` | `/api/schemas/import` | Import schema from URL |
| `POST` | `/api/schemas/create` | Create custom schema |
| `DELETE` | `/api/schemas/{said}` | Delete schema |

### VVP Attestation (`/api/vvp`)

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/api/vvp/create` | Create VVP attestation (PASSporT + headers) |

### Users (`/api/users`)

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/api/users` | Create user |
| `GET` | `/api/users` | List users |
| `GET` | `/api/users/me` | Get current user |
| `PATCH` | `/api/users/me/password` | Change own password |
| `GET` | `/api/users/{id}` | Get user |
| `PATCH` | `/api/users/{id}` | Update user |
| `PATCH` | `/api/users/{id}/password` | Reset user password |
| `DELETE` | `/api/users/{id}` | Delete user |

### Admin (`/api/admin`)

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/api/admin/auth/reload` | Reload auth config |
| `GET` | `/api/admin/auth/status` | Auth system status |
| `GET` | `/api/admin/users` | List admin users |
| `POST` | `/api/admin/users` | Create admin user |
| `PATCH` | `/api/admin/users/{email}` | Update admin user |
| `DELETE` | `/api/admin/users/{email}` | Delete admin user |
| `POST` | `/api/admin/users/reload` | Reload users |
| `GET` | `/api/admin/config` | Get configuration |
| `POST` | `/api/admin/log-level` | Set log level |
| `POST` | `/api/admin/witnesses/reload` | Reload witness config |
| `GET` | `/api/admin/stats` | Service statistics |
| `GET` | `/api/admin/scaling` | Scaling status |
| `POST` | `/api/admin/scaling` | Update scaling |
| `GET` | `/api/admin/deployment-tests` | Deployment test history |
| `POST` | `/api/admin/deployment-tests` | Run deployment test |
| `GET` | `/api/admin/benchmarks` | Benchmark results |
| `GET` | `/api/admin/audit-logs` | Audit log viewer |
| `POST` | `/api/admin/mock-vlei/reinitialize` | Clear all data and re-create mock GLEIF/QVI infrastructure |
| `GET` | `/api/admin/features` | Feature flags and cache status |

### Issuer UI Pages

| Path | Purpose |
|------|---------|
| `/login` | Login page |
| `/create` | Identity creation UI |
| `/registry/ui` | Registry management UI |
| `/schemas/ui` | Schema browser UI |
| `/ui/organizations` | Organization management |
| `/ui/credentials` | Credential management |
| `/ui/dossiers` | Dossier management |
| `/ui/tn-mappings` | TN mapping management |
| `/ui/admin` | Admin dashboard |

---

## SIP Redirect Service

**Protocol**: SIP over UDP (not HTTP)
**Port**: 5060

| Input | Processing | Output |
|-------|-----------|--------|
| SIP INVITE with X-VVP-API-Key | Extract caller TN, call Issuer `/api/vvp/create` | SIP 302 with Identity + VVP-Identity headers |

**Status Endpoint** (HTTP):
- `GET http://localhost:8080/health` - Health check
- `GET http://localhost:8080/status` - Status with metrics (requires X-Admin-Key)
