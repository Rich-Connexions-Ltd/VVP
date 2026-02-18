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
| `GET` | `/verify` | Verification mode selection (redirect alias) |
| `GET` | `/verify/` | Verification mode selection (landing page) |
| `GET` | `/simple` | Redirect (301) to `/verify/simple` |
| `GET` | `/verify/full` | Full verification explorer (HTMX) |
| `GET` | `/verify/simple` | Simple single-step verification |
| `GET` | `/verify/explore` | Tabbed explorer (JWT/SIP/SAID) |
| `GET` | `/create` | Dossier creation landing |
| `GET` | `/ui/admin` | Admin dashboard |

### HTMX Endpoints (return HTML fragments)

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/ui/parse-jwt` | Parse PASSporT JWT |
| `POST` | `/ui/parse-sip` | Parse SIP INVITE |
| `POST` | `/ui/fetch-dossier` | Fetch and display dossier |
| `POST` | `/ui/check-revocation` | Revocation check fragment |
| `POST` | `/ui/credential-graph` | Credential chain visualization |
| `POST` | `/ui/revocation-badge` | Revocation status badge |
| `GET` | `/ui/revocation-status` | Revocation polling endpoint |
| `POST` | `/ui/verify-result` | Full verify result display |
| `GET` | `/ui/credential/{said}` | Single credential detail |
| `POST` | `/ui/browse-said` | SAID browser |
| `POST` | `/ui/jwt-explore` | JWT explorer fragment |
| `POST` | `/ui/sip-explore` | SIP explorer fragment |
| `POST` | `/ui/simple-verify` | Simple verify fragment |

### Data Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/proxy-fetch` | Proxy dossier fetch (JSON) |
| `POST` | `/credential-graph` | Credential graph data (JSON) |

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

### Error Responses (Sprint 68b)

All issuer endpoints use consistent HTTP status codes:

| Status | Meaning | When |
|--------|---------|------|
| 400 | Bad Request | Validation failure, invalid input |
| 401 | Unauthorized | Missing/invalid API key or session |
| 403 | Forbidden | Insufficient role, revoked credentials |
| 404 | Not Found | Resource doesn't exist |
| 503 | Service Unavailable | KERI agent unreachable (all KERI-dependent endpoints) |
| 500 | Internal Server Error | Unexpected error |

**503 KERI Agent Unavailable**: When the KERI Agent service is down, all endpoints that require KERI operations (identity, registry, credential, dossier, VVP, organization creation) return HTTP 503. This applies to both read and mutation endpoints. Check `/healthz` for service status.

### Health & Dashboard

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/livez` | Liveness probe — always 200 (ACA liveness) |
| `GET` | `/healthz` | Readiness probe — 200 if DB reachable, 503 if not (ACA readiness). Reports KERI Agent status informatively but does NOT fail on agent outage. |
| `GET` | `/readyz` | Full operational readiness — 200 only when DB AND KERI Agent are both up. Used by CI/CD gates and monitoring. |
| `GET` | `/api/dashboard/status` | Dashboard health data (service status, KERI state) |

### Authentication (`/auth`)

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/auth/login` | Login (API key or email/password) |
| `POST` | `/auth/logout` | Logout (clear session) |
| `GET` | `/auth/status` | Current auth status |
| `GET` | `/auth/oauth/status` | OAuth configuration status |
| `GET` | `/auth/oauth/m365/start` | Start Microsoft OAuth flow |
| `GET` | `/auth/oauth/m365/callback` | OAuth callback handler |

### Organizations (`/organizations`)

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/organizations` | Create organization (auto-provisions KERI identity + LE credential) |
| `GET` | `/organizations` | List organizations |
| `GET` | `/organizations/names` | List org names (lightweight, any auth) |
| `GET` | `/organizations/{org_id}` | Get organization details |
| `PATCH` | `/organizations/{org_id}` | Update organization |

#### GET /organizations/names (Sprint 63, updated Sprint 65)

Lightweight org name list for any authenticated user. Used by dossier wizard for AP and OSP dropdowns.

**Query Parameters:**
- `purpose` (optional): `ap` (default) or `osp`
  - `ap`: Non-admins see only their own org; admins see all. Returns `aid` field.
  - `osp`: All authenticated users see all enabled orgs. No `aid` field.

**Response:** `OrganizationNameListResponse`
```json
{
  "count": 2,
  "organizations": [
    {"id": "uuid", "name": "ACME Corp", "aid": "E..." /* only when purpose=ap */},
    {"id": "uuid", "name": "Example Inc", "aid": "E..."}
  ]
}
```

### Organization API Keys (`/organizations/{org_id}/api-keys`)

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/organizations/{org_id}/api-keys` | Create API key |
| `GET` | `/organizations/{org_id}/api-keys` | List API keys |
| `GET` | `/organizations/{org_id}/api-keys/{key_id}` | Get API key |
| `DELETE` | `/organizations/{org_id}/api-keys/{key_id}` | Revoke API key |

### KERI Identities (`/identity`)

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/identity` | Create KERI identity (inception) |
| `GET` | `/identity` | List identities |
| `GET` | `/identity/{aid}` | Get identity details |
| `GET` | `/identity/{aid}/oobi` | Get OOBI URL |
| `POST` | `/identity/{aid}/rotate` | Rotate keys |
| `DELETE` | `/identity/{aid}` | Delete identity |

### Credential Registries (`/registry`)

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/registry` | Create credential registry |
| `GET` | `/registry` | List registries |
| `GET` | `/registry/{registry_key}` | Get registry details |
| `DELETE` | `/registry/{registry_key}` | Delete registry |

### Credentials (`/credential`)

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/credential/issue` | Issue ACDC credential |
| `GET` | `/credential` | List credentials |
| `GET` | `/credential/{said}` | Get credential details |
| `POST` | `/credential/{said}/revoke` | Revoke credential |
| `DELETE` | `/credential/{said}` | Delete credential |

#### POST /credential/issue — Sprint 67 Validation

In addition to schema validation and edge injection, `POST /credential/issue` enforces:
- **Schema authorization** — org type must be authorized for the schema SAID (`is_schema_authorized()`). Returns 403 if unauthorized.
- **Issuer binding** — org must have an AID and registry_key. Returns 400 if missing (fail-closed).
- **Registry match** — the registry's issuer AID must match the org's AID.

#### GET /credential Query Filters (Sprint 63, 72)

- `schema_said` (optional): Filter to credentials matching this schema SAID
- `org_id` (optional, admin-only): Scope credentials to a specific org. Non-admins receive 403. Relationship tagging is computed from the perspective of the specified org.
- `status` (optional): Filter by credential status (e.g., `issued`)
- `limit` (optional, default=50, range 1-200): Page size for pagination (Sprint 72)
- `offset` (optional, default=0, ge=0): Starting offset for pagination (Sprint 72)

**Pagination response fields** (Sprint 72): `total` (total matching), `limit`, `offset`, `count` (items in current page), `credentials` (array).

### Dossiers (`/dossier`)

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/dossier/create` | Create dossier ACDC with edge validation (Sprint 63) |
| `POST` | `/dossier/build` | Build dossier from credential SAID |
| `POST` | `/dossier/build/info` | Build info (credential count, format) |
| `GET` | `/dossier/associated` | List dossiers associated with principal's org as OSP (Sprint 63) |
| `GET` | `/dossier/{said}` | Get public dossier by SAID |
| `GET` | `/dossier/readiness` | Pre-flight readiness assessment for dossier creation (Sprint 65) |

#### POST /dossier/create (Sprint 63)

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
  "dossier_url": "https://vvp-issuer.rcnx.io/dossier/E...",
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

#### GET /dossier/associated (Sprint 63)

List dossiers associated with the principal's organization as OSP.

**Auth:** `issuer:readonly+` or `org:dossier_manager+`
**Query Parameters:** `org_id` (optional, admin-only): Filter by specific OSP org
**Scoping:** Admins see all; org-scoped principals see only their org's associations

#### GET /dossier/readiness (Sprint 65)

Pre-flight readiness assessment for dossier creation. Analyzes available credentials against dossier schema requirements.

**Auth:** `issuer:admin` or `org:dossier_manager+` (org-scoped principals limited to own org)

**Query Parameters:**
- `org_id` (required): Organization UUID (AP organization)

**Response:** `DossierReadinessResponse`
```json
{
  "org_id": "uuid",
  "org_name": "ACME Corp",
  "ready": false,
  "slots": [
    {
      "edge": "vetting",
      "label": "Legal Entity",
      "required": true,
      "schema_constraint": "EH1jN4U4mWIW09jeCl2hFhg1YPKCAbW5sGPl3hJeAKTf",
      "available_count": 1,
      "total_count": 5,
      "status": "ready"
    },
    {
      "edge": "alloc",
      "label": "Goal Code",
      "required": true,
      "schema_constraint": "EJxnJdxkHbRw2wVFNe4IUOPLt8fEtg9Sr3WyTjlgKoIb",
      "available_count": 0,
      "total_count": 0,
      "status": "missing"
    }
  ],
  "blocking_reason": "Required slot 'alloc' (Goal Code) has no available credentials"
}
```

**Slot Status Values:**
- `ready`: Available credentials meet requirement
- `missing`: Required slot has no credentials
- `invalid`: Credentials exist but all are excluded (revoked, wrong issuer)
- `optional_missing`: Optional slot has no credentials (does not block)
- `optional_unconstrained`: Optional slot with no schema constraint (cannot assess)

**Error Responses:**
- `400 Bad Request`: Organization not enabled, missing AID, or no credential registry
- `403 Forbidden`: Non-admin accessing another org's readiness
- `404 Not Found`: Organization does not exist

### Vetter Certifications (Sprint 61)

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/vetter-certifications` | Issue VetterCertification (admin-only) |
| `GET` | `/vetter-certifications` | List VetterCertifications (admin-only, optional `?organization_id` filter) |
| `GET` | `/vetter-certifications/{said}` | Get VetterCertification by SAID (system role or org member) |
| `DELETE` | `/vetter-certifications/{said}` | Revoke VetterCertification (admin-only) |
| `GET` | `/organizations/{org_id}/constraints` | Get vetter constraints for org (system role or org member) |
| `GET` | `/users/me/constraints` | Current user's org constraints (any auth) |

#### POST /vetter-certifications

Issues a VetterCertification ACDC from mock GSMA to the org's AID. Links the credential SAID to `Organization.vetter_certification_said`. Rejects if org already has an active (non-revoked, non-expired) cert (409).

**Auth:** `issuer:admin`

**Request:** `VetterCertificationCreateRequest`
```json
{
  "organization_id": "uuid",
  "ecc_targets": ["44", "1"],
  "jurisdiction_targets": ["GBR", "USA"],
  "name": "ACME Vetter",
  "certificationExpiry": "2027-01-01T00:00:00Z"
}
```

**Response:** `VetterCertificationResponse`
```json
{
  "said": "E...",
  "issuer_aid": "E... (mock GSMA AID)",
  "vetter_aid": "E... (org AID)",
  "organization_id": "uuid",
  "organization_name": "ACME Corp",
  "ecc_targets": ["44", "1"],
  "jurisdiction_targets": ["GBR", "USA"],
  "name": "ACME Vetter",
  "certificationExpiry": "2027-01-01T00:00:00Z",
  "status": "issued",
  "created_at": "2026-02-15T12:00:00Z"
}
```

**Validation:**
- `ecc_targets`: Must be valid E.164 country calling codes (ITU-T assigned)
- `jurisdiction_targets`: Must be valid ISO 3166-1 alpha-3 codes
- Both lists must be non-empty

#### GET /organizations/{org_id}/constraints

Returns the parsed constraints from the org's active VetterCertification. Null fields if no valid cert.

**Auth:** System role (`admin`/`readonly`/`operator`) or org membership

**Response:** `OrganizationConstraintsResponse`
```json
{
  "organization_id": "uuid",
  "organization_name": "ACME Corp",
  "vetter_certification_said": "E...",
  "ecc_targets": ["44", "1"],
  "jurisdiction_targets": ["GBR", "USA"],
  "certification_status": "issued",
  "certification_expiry": "2027-01-01T00:00:00Z"
}
```

#### GET /users/me/constraints

Convenience endpoint — resolves current user's org and returns constraints. Returns 404 if user has no org.

**Auth:** Any authenticated user

### TN Mappings (`/tn`)

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/tn/mappings` | Create TN mapping |
| `GET` | `/tn/mappings` | List mappings |
| `GET` | `/tn/mappings/{mapping_id}` | Get mapping details |
| `PATCH` | `/tn/mappings/{mapping_id}` | Update mapping |
| `DELETE` | `/tn/mappings/{mapping_id}` | Delete mapping |
| `POST` | `/tn/lookup` | Look up TN (used by SIP Redirect) |
| `POST` | `/tn/test-lookup/{mapping_id}` | Test a specific mapping |

#### POST /tn/lookup

Internal endpoint for SIP Redirect service. Authenticates via API key (not session) and returns the dossier/identity for a given TN.

**Request:** `{ "tn": "+15551234567", "api_key": "..." }`

**Lookup order:**
1. Direct lookup: find TNMapping where `tn` matches and `organization_id` matches the API key's org
2. OSP delegation fallback: if direct lookup fails, join `DossierOspAssociation` with `TNMapping` to find mappings where the dossier has been delegated to the API key's org as OSP
3. TN ownership validation: checks the **owner org's** TN Allocation credentials (even when found via OSP delegation)

**Response:** `{ "found": true, "tn": "...", "organization_id": "...", "organization_name": "...", "dossier_said": "...", "identity_name": "...", "brand_name": "...", "brand_logo_url": "...", "error": null }`

When found via OSP delegation, the response contains the **owner org's** data (organization_id, identity_name, dossier_said) since the signing identity and dossier belong to the accountable party.

### Schemas (`/schema`, `/schemas`)

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/schema` | List schemas |
| `GET` | `/schema/authorized` | List schemas authorized for org type (Sprint 67) |
| `GET` | `/schemas/authorized` | Compat alias for `/schema/authorized` (Sprint 67) |
| `GET` | `/schema/weboftrust/registry` | WebOfTrust schema registry |
| `GET` | `/schema/{said}` | Get schema by SAID |
| `GET` | `/schema/{said}/verify` | Verify schema SAID |
| `POST` | `/schema/validate` | Validate data against schema |
| `POST` | `/schema/import` | Import schema from URL |
| `POST` | `/schema/create` | Create custom schema |
| `DELETE` | `/schema/{said}` | Delete schema by SAID |

**`GET /schema/authorized`** query params: `organization_id` (optional, defaults to principal's org). Cross-org queries require `issuer:admin` role (403 otherwise). Returns `SchemaListResponse` filtered by org type's authorized schemas.

### Session (`/session`)

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/session/switch-org` | Switch admin org context (Sprint 67) |

**`POST /session/switch-org`** — Admin-only. Body: `{ "organization_id": "uuid" }` (null to revert to home org). Emits `session.switch_org` audit event. Returns `SwitchOrgResponse` with active/home org details.

### VVP Attestation (`/vvp`)

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/vvp/create` | Create VVP attestation (PASSporT + headers) |

### Users (`/users`)

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/users` | Create user |
| `GET` | `/users` | List users |
| `GET` | `/users/me` | Get current user |
| `PATCH` | `/users/me/password` | Change own password |
| `GET` | `/users/{user_id}` | Get user |
| `PATCH` | `/users/{user_id}` | Update user |
| `PATCH` | `/users/{user_id}/password` | Change user password (admin) |
| `DELETE` | `/users/{user_id}` | Delete user |

### Admin (`/admin`)

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/admin/auth/reload` | Reload auth config |
| `GET` | `/admin/auth/status` | Auth system status |
| `GET` | `/admin/users` | List admin users |
| `POST` | `/admin/users` | Create admin user |
| `PATCH` | `/admin/users/{email}` | Update admin user |
| `DELETE` | `/admin/users/{email}` | Delete admin user |
| `POST` | `/admin/users/reload` | Reload users |
| `GET` | `/admin/config` | Get configuration |
| `POST` | `/admin/log-level` | Set log level |
| `POST` | `/admin/witnesses/reload` | Reload witness config |
| `GET` | `/admin/stats` | Service statistics |
| `GET` | `/admin/scaling` | Scaling status |
| `POST` | `/admin/scaling` | Update scaling |
| `GET` | `/admin/deployment-tests` | Deployment test history |
| `POST` | `/admin/deployment-tests` | Run deployment test |
| `GET` | `/admin/benchmarks` | Benchmark results |
| `GET` | `/admin/audit-logs` | Audit log viewer |
| `POST` | `/admin/mock-vlei/reinitialize` | Clear all data and re-create mock GLEIF/QVI infrastructure |
| `GET` | `/admin/settings/vetter-enforcement` | Get vetter constraint enforcement status |
| `PUT` | `/admin/settings/vetter-enforcement` | Toggle vetter constraint enforcement (query: `enabled=true\|false`) |

### PBX Management (`/pbx`) — Sprint 71

All endpoints require `issuer:admin` role. Router: `app/api/pbx.py`.

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/pbx/config` | Get PBX config singleton (creates with defaults if absent) |
| `PUT` | `/pbx/config` | Update config (extensions, API key, caller ID) |
| `POST` | `/pbx/deploy` | Generate dialplan XML and deploy to PBX via Azure VM run-command |
| `GET` | `/pbx/dialplan-preview` | Preview generated dialplan as `application/xml` |

**`PUT /pbx/config`** — Body: `UpdatePBXConfigRequest` with optional fields: `api_key_org_id`, `api_key_id`, `api_key_value` (plaintext), `extensions` (list of `PBXExtension`), `default_caller_id` (E.164). Validates: extension range 1000-1009, no duplicate ext numbers, E.164 format.

**`POST /pbx/deploy`** — Body: `{ "dry_run": true|false }`. Dry run returns generated XML without deploying. Real deploy: base64-encodes XML, invokes Azure VM run-command on PBX VM (backup, write, `fs_cli reloadxml`).

### Issuer UI Pages (all `GET`, return HTML)

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/ui/` | Home/landing page |
| `GET` | `/login` | Login page |
| `GET` | `/ui/identity` | Identity management |
| `GET` | `/ui/registry` | Registry management |
| `GET` | `/ui/schemas` | Schema browser |
| `GET` | `/ui/credentials` | Credential management |
| `GET` | `/ui/dossier` | Dossier management |
| `GET` | `/ui/vvp` | VVP attestation |
| `GET` | `/ui/dashboard` | Central dashboard |
| `GET` | `/ui/admin` | Admin panel |
| `GET` | `/ui/vetter` | Vetter certification |
| `GET` | `/ui/tn-mappings` | TN mapping management |
| `GET` | `/ui/benchmarks` | Performance benchmarks |
| `GET` | `/ui/help` | Help/documentation |
| `GET` | `/ui/walkthrough` | Interactive split-pane walkthrough (Sprint 66) |
| `GET` | `/ui/organization-detail` | Organization detail page with tabs (Sprint 67) |
| `GET` | `/ui/pbx` | PBX management (Sprint 71) |
| `GET` | `/organizations/ui` | Organization management |
| `GET` | `/users/ui` | User management |
| `GET` | `/profile` | User profile |
| `GET` | `/vvp/ui` | VVP UI redirect |
| `GET` | `/admin/benchmarks/ui` | Benchmarks UI redirect |

Legacy redirects (all `GET`, return 302): `/create` → `/ui/identity`, `/registry/ui` → `/ui/registry`, `/schemas/ui` → `/ui/schemas`, `/credentials/ui` → `/ui/credentials`, `/dossier/ui` → `/ui/dossier`

---

## KERI Agent Service API (`services/keri-agent/`)

Base URL: `http://keri-agent.internal:8002` (internal only)

**Auth**: Bearer token via `Authorization: Bearer <VVP_KERI_AGENT_AUTH_TOKEN>`

### Health & Bootstrap

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/healthz` | Readiness probe (KERI managers initialized) |
| `GET` | `/bootstrap/status` | Mock vLEI bootstrap status |

### Admin

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/admin/seeds/export?passphrase=<passphrase>` | Export encrypted KERI seed backup |

#### GET /admin/seeds/export (Sprint 69)

Disaster recovery endpoint that exports all KERI key material as an AES-256-GCM encrypted JSON payload. The passphrase is used to derive the encryption key via PBKDF2-SHA256.

**Auth:** Bearer token (`Authorization: Bearer <VVP_KERI_AGENT_AUTH_TOKEN>`)

**Query Parameters:**
- `passphrase` (required): Minimum 8 characters. Used as input to PBKDF2-SHA256 key derivation.

**Response** (200):
```json
{
  "v": 1,
  "alg": "AES-256-GCM",
  "kdf": "PBKDF2-SHA256",
  "iterations": 600000,
  "salt": "<base64-encoded>",
  "iv": "<base64-encoded>",
  "ciphertext": "<base64-encoded>",
  "tag": "<base64-encoded>"
}
```

**Decrypted payload contains:**
- `habery_salt` — Habery-level salt for key derivation
- `identity_seeds` — Signing key seeds for all identities
- `registry_seeds` — Registry inception key seeds
- `rotation_seeds` — Pre-rotated next-key seeds
- `credential_seeds` — Credential-specific key material
- `counts` — Summary counts of exported items

**Error Responses:**
- `400 Bad Request`: Passphrase missing or shorter than 8 characters
- `401 Unauthorized`: Missing or invalid bearer token

### Identity

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/identity` | Create KERI identity (inception) |
| `GET` | `/identity` | List identities |
| `GET` | `/identity/{aid}` | Get identity details |
| `GET` | `/identity/{aid}/oobi` | Get OOBI URL |
| `POST` | `/identity/{aid}/rotate` | Rotate keys |
| `DELETE` | `/identity/{aid}` | Delete identity |

### Registry

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/registry` | Create credential registry |
| `GET` | `/registry` | List registries |
| `GET` | `/registry/{registry_key}` | Get registry details |
| `DELETE` | `/registry/{registry_key}` | Delete registry |

### Credential

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/credential/issue` | Issue ACDC credential |
| `GET` | `/credential` | List credentials |
| `GET` | `/credential/{said}` | Get credential details |
| `GET` | `/credential/{said}/cesr` | Get credential in CESR format |
| `POST` | `/credential/{said}/revoke` | Revoke credential |
| `DELETE` | `/credential/{said}` | Delete credential |

### Dossier

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/dossier/build` | Build dossier from credential SAID (DFS edge walk) |

### VVP Attestation

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/vvp/create` | Create VVP attestation (PASSporT signing + header construction) |

---

## SIP Redirect Service

**Protocol**: SIP over UDP (not HTTP)
**Port**: 5060

| Input | Processing | Output |
|-------|-----------|--------|
| SIP INVITE with X-VVP-API-Key | Extract caller TN, call Issuer `/vvp/create` | SIP 302 with Identity + VVP-Identity headers |

**Status Endpoint** (HTTP):
- `GET http://localhost:8080/health` - Health check
- `GET http://localhost:8080/status` - Status with metrics (requires X-Admin-Key)
