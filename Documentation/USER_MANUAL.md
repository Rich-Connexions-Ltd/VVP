# VVP System Operator User Manual

## Table of Contents

1. [Introduction](#1-introduction)
2. [System Architecture](#2-system-architecture)
3. [Deployed Infrastructure](#3-deployed-infrastructure)
4. [Getting Started](#4-getting-started)
5. [Organization Management](#5-organization-management)
6. [Credential Management](#6-credential-management)
7. [Call Signing](#7-call-signing)
8. [Call Verification](#8-call-verification)
9. [Monitoring and Diagnostics](#9-monitoring-and-diagnostics)
10. [CLI Tools](#10-cli-tools)
11. [Operational Scripts](#11-operational-scripts)
12. [E2E Testing](#12-e2e-testing)
13. [Troubleshooting](#13-troubleshooting)
14. [Configuration Reference](#14-configuration-reference)
15. [Quick Reference](#15-quick-reference)

---

## 1. Introduction

The **Verifiable Voice Protocol (VVP)** system enables cryptographically verifiable proof-of-rights for VoIP calls. It extends STIR/SHAKEN by replacing X.509 certificate chains with KERI-based decentralized identifiers and ACDC credentials, enabling independent verification of caller identity, brand, and telephone number authority.

This manual is the primary operational reference for VVP system operators. It covers day-to-day administration tasks including organization management, credential issuance, call signing configuration, monitoring, and troubleshooting.

**Audience:** System operators, integration engineers, and administrators responsible for deploying, configuring, and maintaining the VVP system.

**How to use this manual:**

- **New operators** should start with [Getting Started](#4-getting-started), then follow through [Organization Management](#5-organization-management) and [Credential Management](#6-credential-management) to provision their first organization end-to-end.
- **Integration engineers** configuring a PBX for VVP signing should read [Call Signing](#7-call-signing) for the SIP header requirements.
- **Operations staff** should familiarise themselves with [Monitoring and Diagnostics](#9-monitoring-and-diagnostics), [Operational Scripts](#11-operational-scripts), and [Troubleshooting](#13-troubleshooting).

---

## 2. System Architecture

The VVP system consists of six deployed services that work together to sign outbound calls with verifiable credentials and verify inbound calls.

```
                                    ┌─────────────────────────────────────────────────┐
                                    │              Azure UK South                      │
                                    │                                                  │
┌──────────────────┐                │  ┌─────────────┐  ┌─────────────┐  ┌──────────┐ │
│   Enterprise     │   SIP INVITE   │  │ VVP Issuer  │  │ VVP Verifier│  │  KERI    │ │
│   PBX / SBC      │ + X-VVP-API-Key│  │ Credentials │  │ Validation  │  │ Witnesses│ │
└────────┬─────────┘                │  │ & Identity  │  │ & Claims    │  │ (3-node) │ │
         │                          │  └──────▲──────┘  └──────▲──────┘  └────▲─────┘ │
         ▼                          │         │ HTTPS          │ HTTPS        │ OOBI  │
┌──────────────────┐                │         │               │              │        │
│   VVP PBX VM     │                └─────────┼───────────────┼──────────────┼────────┘
│                  │                          │               │              │
│ ┌──────────────┐ │                          │               │              │
│ │ SIP Signer   │─┼──────────────────────────┘               │              │
│ │ (UDP 5070)   │ │                                          │              │
│ └──────────────┘ │                                          │              │
│ ┌──────────────┐ │                                          │              │
│ │ SIP Verifier │─┼──────────────────────────────────────────┘              │
│ │ (UDP 5071)   │ │                                                         │
│ └──────────────┘ │                                                         │
│ ┌──────────────┐ │                                                         │
│ │ FreeSWITCH   │─┼─────────────────────────────────────────────────────────┘
│ │ (5060/7443)  │ │
│ └──────────────┘ │
└──────────────────┘
```

### Component Roles

| # | Service | Role | Production URL |
|---|---------|------|----------------|
| 1 | **VVP Issuer** | Organization, credential, and dossier management; VVP attestation creation | `https://vvp-issuer.rcnx.io` |
| 2 | **VVP Verifier** | VVP-Identity and PASSporT verification; claim tree construction | `https://vvp-verifier.rcnx.io` |
| 3 | **SIP Redirect (Signer)** | Intercepts outbound SIP calls, requests VVP attestation from Issuer, returns 302 with VVP headers | `pbx.rcnx.io:5070` (UDP) |
| 4 | **SIP Verify** | Intercepts inbound SIP calls, sends VVP headers to Verifier API, returns 302 with verification result | `pbx.rcnx.io:5071` (UDP) |
| 5 | **KERI Witnesses (x3)** | Key event receipting, OOBI resolution, KEL/TEL storage | `vvp-witness{1,2,3}.rcnx.io` |
| 6 | **PBX (FreeSWITCH)** | SIP call routing, WebRTC gateway, test infrastructure | `pbx.rcnx.io` |

### Call Signing Flow

1. Enterprise PBX dials a number with VVP prefix (e.g. `7XXXX`)
2. FreeSWITCH routes SIP INVITE to **SIP Redirect** service (port 5070) with `X-VVP-API-Key` header
3. SIP Redirect extracts caller TN and calls **Issuer** API (`POST /api/vvp/create`) with the API key
4. Issuer looks up TN mapping, builds PASSporT JWT (Ed25519 signed), constructs VVP-Identity header
5. Issuer returns `vvp_identity_header` and `passport_jwt` to SIP Redirect
6. SIP Redirect returns SIP 302 with `P-VVP-Identity` and `P-VVP-Passport` headers
7. PBX follows redirect and forwards call to carrier with VVP attestation attached

### Call Verification Flow

1. Inbound SIP INVITE arrives at FreeSWITCH with VVP headers (`P-VVP-Identity`, `P-VVP-Passport`)
2. FreeSWITCH routes to **SIP Verify** service (port 5071)
3. SIP Verify extracts VVP headers and calls **Verifier** API (`POST /verify-callee`)
4. Verifier parses VVP-Identity, resolves OOBI to fetch signer's KEL from **Witnesses**
5. Verifier validates PASSporT signature, fetches dossier, validates credential chain (ACDC DAG)
6. Verifier checks revocation status via TEL, validates TN authorization
7. Verifier returns claim tree with status: VALID, INVALID, or INDETERMINATE
8. SIP Verify returns 302 with `X-VVP-Status`, `X-VVP-Brand-Name`, `X-VVP-Brand-Logo` headers
9. PBX displays verified brand information to the callee

> **Deep reference:** [architecture.md](../knowledge/architecture.md) | [DEPLOYMENT.md](DEPLOYMENT.md)

---

## 3. Deployed Infrastructure

For the complete infrastructure reference including Azure Container Apps configuration, DNS, health endpoints, CI/CD pipeline, secrets management, and PBX VM details, see [DEPLOYMENT.md](DEPLOYMENT.md).

---

## 4. Getting Started

This section walks a new operator through their first login, dashboard overview, and initial orientation.

### Accessing the Issuer UI

The VVP Issuer web interface is available at:

- **Production:** `https://vvp-issuer.rcnx.io`
- **Local development:** `http://localhost:8001`

### Login Methods

The Issuer supports three authentication methods:

| Method | How to Use | Best For |
|--------|-----------|----------|
| **Microsoft 365 SSO** | Click "Sign in with Microsoft" on the login page. Uses Azure Entra ID OAuth. Auto-provisions user accounts for configured domains. | Enterprise operators with M365 tenants |
| **API Key** | Include `X-API-Key` header in HTTP requests. API keys are created per-organization (see [Organization Management](#5-organization-management)). | Programmatic access, SIP Redirect service |
| **Email/Password** | Enter credentials on the login page. Accounts created by administrators. | Development and testing |

After successful authentication, you are redirected to the Issuer dashboard.

### Dashboard Overview

The Issuer admin dashboard (`https://vvp-issuer.rcnx.io/ui/admin`) provides:

- **System health** — Live status of Issuer, Verifier, and Witnesses
- **Statistics** — Organization count, credential count, active TN mappings
- **Audit log** — Filterable event log showing all administrative actions (org creation, credential issuance, API key usage, TN mapping changes)
- **Quick actions** — Links to organization creation, credential issuance, and TN management

### Verifier UI Overview

The VVP Verifier web interface is available at `https://vvp-verifier.rcnx.io` and requires no authentication. It provides:

- **Verify page** — Paste a VVP-Identity header and PASSporT to run full verification and see the claim tree
- **Diagnostics** — View verification phases, timing, and error details
- **Brand display** — Preview how verified brand information (name, logo) appears

---

## 5. Organization Management

Organizations are the primary tenants in the VVP system. Each organization has its own KERI identifier (AID), credentials, dossiers, TN mappings, and API keys.

### Creating an Organization

1. Navigate to **Organizations** (`https://vvp-issuer.rcnx.io/ui/organizations`)
2. Click **"Create Organization"**
3. Enter the organization name (e.g. "ACME Telecom Ltd")
4. Click **"Create"**

When an organization is created, the system automatically:
- Creates a KERI Autonomic Identifier (AID) for the organization
- Generates a pseudo-LEI (Legal Entity Identifier)
- Issues a Legal Entity (LE) credential anchored to the GLEIF trust root
- Establishes a credential registry (TEL) for issuance and revocation tracking

The organization is now ready for credential issuance and TN mapping.

### Creating API Keys

API keys provide programmatic access scoped to a specific organization.

1. Navigate to the organization's detail page
2. Click **"Create API Key"**
3. Select the role(s) for this key:

| Role | Permissions |
|------|-------------|
| `org:administrator` | Full organization management (users, keys, credentials, mappings) |
| `org:dossier_manager` | Credential issuance, dossier building, TN mapping management |
| `org:viewer` | Read-only access to organization data |

4. Click **"Create"**
5. **Copy the API key immediately** — it is shown only once and cannot be retrieved later

The SIP Redirect service uses an API key with at least the `org:dossier_manager` role to request VVP attestation for outbound calls.

### User Management

Administrators can manage users within their organization:

1. Navigate to **Users** on the organization detail page
2. Click **"Add User"** to invite a new user by email
3. Assign the user to the organization with an appropriate role
4. The user can then log in via M365 SSO or email/password

Users are scoped to organizations — a user belongs to one organization and can only access that organization's resources.

---

## 6. Credential Management

VVP uses ACDC (Authentic Chained Data Container) credentials arranged in a directed acyclic graph (DAG) called a **dossier**. The dossier provides the cryptographic evidence chain backing a call's attestation, from the GLEIF trust root through to the specific telephone number being used.

The typical credential chain is: **GLEIF Root → QVI → Legal Entity (LE) → TN Allocation → Dossier**. TN Allocation credentials define which telephone number ranges an organization is authorized to use. TN mappings then associate specific phone numbers with a built dossier and signing identity.

> **Full guide:** [CREATING_DOSSIERS.md](CREATING_DOSSIERS.md)

---

## 7. Call Signing

The SIP Redirect service (port 5070 UDP) intercepts outbound SIP INVITEs, requests VVP attestation from the Issuer, and returns a SIP 302 redirect with VVP headers attached.

**Required request headers:**

| Header | Purpose |
|--------|---------|
| `X-VVP-API-Key` | Organization API key for authentication |

**Response headers (SIP 302):**

| Header | Description |
|--------|-------------|
| `P-VVP-Identity` | Base64url-encoded VVP identity claims (JSON with `ppt`, `kid`, `evd`, `iat`) |
| `P-VVP-Passport` | PASSporT JWT credential (EdDSA signed) |
| `X-VVP-Brand-Name` | Organization display name |
| `X-VVP-Brand-Logo` | Brand logo URL |
| `X-VVP-Status` | Attestation result (`VALID`, `INVALID`, `INDETERMINATE`) |

**Error responses:** 401 (missing/invalid API key), 403 (rate limited or unauthorized TN), 404 (TN not mapped), 500 (issuer unreachable). Rate limiting defaults to 10 requests/second per API key with burst size of 50 (token bucket algorithm).

> **Full reference:** [SIP_SIGNER.md](SIP_SIGNER.md)

---

## 8. Call Verification

The SIP Verify service (port 5071 UDP) intercepts inbound SIP INVITEs containing VVP headers, sends them to the Verifier API for validation, and returns the verification result.

**Expected inbound headers:**

| Header | Description |
|--------|-------------|
| `P-VVP-Identity` | VVP identity claims (JSON with `ppt`, `kid` OOBI URL, `evd` dossier URL, `iat`) |
| `P-VVP-Passport` | PASSporT JWT credential |

**Result headers (SIP 302):**

| Header | Description |
|--------|-------------|
| `X-VVP-Status` | Verification result |
| `X-VVP-Brand-Name` | Verified organization name |
| `X-VVP-Brand-Logo` | Verified logo URL |
| `X-VVP-Error` | Error code (when status is INVALID or INDETERMINATE) |

**Verification status meanings:**

| Status | Meaning | Callee Action |
|--------|---------|---------------|
| `VALID` | Caller identity verified and cryptographically proven | Display brand name and logo |
| `INVALID` | Verification failed (see `X-VVP-Error`) | Show warning or block per policy |
| `INDETERMINATE` | Unable to determine (verifier issue) | Allow call without verification display |
| `NO_VVP` | No VVP headers present | Treat as unverified call |

**Error codes (INVALID):** `SIGNATURE_INVALID`, `CREDENTIAL_REVOKED`, `TN_NOT_AUTHORIZED`, `DOSSIER_INVALID`, `IAT_DRIFT`, `TOKEN_EXPIRED`. **Error codes (INDETERMINATE):** `VERIFIER_TIMEOUT`, `VERIFIER_UNREACHABLE`, `VERIFIER_ERROR`.

> **Full reference:** [SIP_VERIFIER.md](SIP_VERIFIER.md)

---

## 9. Monitoring and Diagnostics

### Central Service Dashboard

The Issuer admin dashboard at `https://vvp-issuer.rcnx.io/ui/admin` provides a centralized view of system health including real-time status of all services, credential statistics, and recent activity. The dashboard auto-refreshes.

### Issuer Admin Dashboard

| Feature | Description |
|---------|-------------|
| **System health** | Live green/red status for Issuer, Verifier, and all 3 Witnesses |
| **Statistics** | Organization count, credential count, active TN mappings, recent API calls |
| **Audit log** | All administrative events with timestamps, user, action type, and details |

### Audit Log Viewer

The audit log (`https://vvp-issuer.rcnx.io/ui/admin`) records:

| Event Type | Examples |
|------------|---------|
| Organization events | Org created, org updated, org disabled |
| Credential events | Credential issued, credential revoked, dossier built |
| API key events | Key created, key revoked, key used |
| TN mapping events | Mapping created, mapping updated, mapping disabled |
| Authentication events | Login success, login failure, OAuth flow |

Filter by event type, organization, user, or date range.

### System Health Check Script

Run the automated health check to verify all services:

```bash
./scripts/system-health-check.sh              # Basic health check
./scripts/system-health-check.sh --e2e        # Health + end-to-end call test
./scripts/system-health-check.sh --e2e --timing  # Health + E2E + cache timing
./scripts/system-health-check.sh --json       # JSON output
./scripts/system-health-check.sh --verbose    # Full HTTP responses
./scripts/system-health-check.sh --local      # Check local Docker stack
```

The script checks: Azure Container Apps (Verifier, Issuer, 3 Witnesses), PBX VM services (FreeSWITCH, SIP Redirect, SIP Verify), cross-service connectivity, and optionally runs E2E call tests.

### SIP Call Test Script

Test SIP signing and verification flows directly:

```bash
python3 scripts/sip-call-test.py --test sign     # Test signing only
python3 scripts/sip-call-test.py --test verify    # Test verification only
python3 scripts/sip-call-test.py --test chain     # Full sign→verify chain
python3 scripts/sip-call-test.py --test all       # Both signing and verification
python3 scripts/sip-call-test.py --json           # JSON output
```

> **Note:** This script sends raw UDP SIP INVITEs and must run on the PBX VM (services listen on localhost). Deploy it via `az vm run-command` or use the health check script's `--e2e` flag which handles this automatically.

### Verifier UI Diagnostics

The Verifier UI at `https://vvp-verifier.rcnx.io` shows verification phase timing, claim tree structure, and detailed error information for any verification attempt. No authentication is required.

### SIP Redirect Status Endpoint

The SIP Redirect service exposes a status endpoint at `http://localhost:8085/status` on the PBX VM. It reports the service version, uptime, and recent request statistics. Access it via:

```bash
az vm run-command invoke --resource-group VVP --name vvp-pbx \
  --command-id RunShellScript --scripts "curl -s http://localhost:8085/status"
```

### Monitoring Issue Quick Reference

| Symptom | Likely Cause | Action |
|---------|-------------|--------|
| Dashboard shows red for a service | Service unhealthy or unreachable | Run `./scripts/system-health-check.sh --verbose` to identify which service and error |
| Audit log shows no recent events | Issuer may have restarted or lost DB connection | Check Issuer health: `curl -s https://vvp-issuer.rcnx.io/healthz` |
| Health check reports Witness down | Witness container may have restarted | Check witness OOBI: `curl -s https://vvp-witness1.rcnx.io/oobi` |
| E2E test fails at signing | SIP Redirect cannot reach Issuer | Check PBX→Issuer connectivity from the PBX VM |
| E2E test fails at verification | SIP Verify cannot reach Verifier | Check PBX→Verifier connectivity from the PBX VM |

---

## 10. CLI Tools

The VVP CLI provides commands for parsing and analyzing JWTs, ACDCs, CESR streams, dossiers, and KERI structures. Install with `pip install -e 'common[cli]'`. Commands are chainable via stdin/stdout piping (use `-` for stdin input).

Key commands: `vvp jwt parse`, `vvp identity parse`, `vvp dossier fetch/parse/validate`, `vvp acdc parse`, `vvp cesr parse`, `vvp said compute/validate`, `vvp kel parse/validate`, `vvp graph build`. Output format controlled with `-f json|pretty|table`.

> **Full reference:** [CLI_USAGE.md](CLI_USAGE.md)

---

## 11. Operational Scripts

### `scripts/system-health-check.sh`

**Purpose:** Comprehensive service health monitoring covering all VVP components.

| Flag | Effect |
|------|--------|
| `--local` | Check local Docker Compose stack (localhost URLs) |
| `--restart` | Deactivate issuer revision and restart services before checking |
| `--e2e` | Run end-to-end SIP signing + verification tests on PBX |
| `--timing` | Measure TN lookup cache performance (requires `--e2e`) |
| `--json` | Output results as JSON |
| `--verbose` | Show full HTTP response bodies |

**Phases:** (0) Restart if requested → (1) Azure Container Apps health → (2) PBX VM services → (3) Cross-service connectivity → (4) E2E call test.

**Exit codes:** `0` = all passed, `1` = one or more failures, `2` = script error.

### `scripts/sip-call-test.py`

**Purpose:** Send real UDP SIP INVITE messages to test signing and verification flows.

| Flag | Effect |
|------|--------|
| `--test sign` | Test signing flow (SIP Redirect → Issuer) |
| `--test verify` | Test verification flow (SIP Verify → Verifier) |
| `--test chain` | Full sign→verify chain with real PASSporT |
| `--test all` | Both signing and verification (default) |
| `--timing` | Enable cache timing metrics |
| `--timing-count N` | Number of timing iterations |
| `--json` | JSON output |
| `--host HOST` | Override SIP host (default: `127.0.0.1`) |
| `--port PORT` | Override SIP port |

**Environment variables:** `VVP_SIP_REDIRECT_HOST`, `VVP_SIP_REDIRECT_PORT` (default 5070), `VVP_SIP_VERIFY_HOST`, `VVP_SIP_VERIFY_PORT` (default 5071), `VVP_TEST_API_KEY`, `VVP_TEST_ORIG_TN` (default +441923311000), `VVP_TEST_DEST_TN` (default +441923311006).

### `scripts/bootstrap-issuer.py`

**Purpose:** Re-provision the Issuer after an LMDB or PostgreSQL database wipe. Creates mock vLEI infrastructure, test organization, API keys, TN allocation credentials, and TN mappings.

**Steps (sequential):**
1. Reinitialize mock vLEI (GLEIF + QVI)
2. Create organization (generates AID, pseudo-LEI, LE credential, registry)
3. Create API key (roles: `org:administrator`, `org:dossier_manager`)
4. Issue TN Allocation credentials (UK + US ranges)
5. Create TN mapping (E.164 number → dossier + identity)
6. Verify dossier builds correctly

| Flag | Effect |
|------|--------|
| `--url URL` | Issuer base URL (default: `https://vvp-issuer.rcnx.io`) |
| `--admin-key KEY` | System admin API key |
| `--org-name NAME` | Organization name (default: `ACME Inc`) |
| `--tn TN` | Test telephone number (default: `+15551001006`) |
| `--brand-name NAME` | Brand name override |
| `--brand-logo URL` | Brand logo URL |
| `--skip-reinit` | Skip mock vLEI re-initialization |
| `--json` | Output summary as JSON |

### `scripts/run-integration-tests.sh`

**Purpose:** Run integration tests against local, Docker, or Azure environments.

| Flag | Effect |
|------|--------|
| `--local` | Test against local stack (`localhost:8000`/`8001`) |
| `--docker` | Test against Docker Compose stack |
| `--azure` | Test against Azure deployment (`rcnx.io` URLs) |
| `-v` | Verbose pytest output |
| `-k PATTERN` | Run tests matching pattern |

Pre-flight checks verify `/healthz` endpoints respond before running tests. Sets `DYLD_LIBRARY_PATH` for libsodium automatically.

### `scripts/monitor-azure-deploy.sh`

**Purpose:** Poll Azure Container Apps health endpoints after deployment to confirm the new revision is healthy.

**Usage:** `./scripts/monitor-azure-deploy.sh [max_attempts]` (default: 10 attempts, 30s interval).

**Exit codes:** `0` = healthy, `1` = timeout.

### `scripts/restart-issuer.sh`

**Purpose:** Restart the local Issuer development server (uvicorn). Kills existing processes on port 8001, starts uvicorn with `--reload`, verifies health endpoint.

**Usage:** `./scripts/restart-issuer.sh`

---

## 12. E2E Testing

End-to-end testing verifies the complete VVP flow: call signing, credential verification, and brand display. The fastest method is the automated system health check with E2E flag (`./scripts/system-health-check.sh --e2e`). For manual testing, register two WebRTC phones at `https://pbx.rcnx.io/app/vvp-phone/sip-phone.html` as extensions 1001 and 1006, then dial `71006` from 1001 — the `7` prefix routes through VVP signing and verification. Extension 1006 should ring with verified brand information displayed.

> **Full guide:** [E2E_TEST.md](../E2E_TEST.md)

---

## 13. Troubleshooting

### Signing Issues

| Symptom | Cause | Solution |
|---------|-------|----------|
| SIP 401 Unauthorized | API key missing from INVITE, API key invalid or revoked, or organization disabled | Verify `X-VVP-API-Key` header is present. Check key is valid: `journalctl -u vvp-sip-redirect \| grep "auth.failure"` on PBX |
| SIP 403 Forbidden | Rate limit exceeded (>10 req/s per key) or TN not covered by organization's TN Allocation credentials | Check rate limit status; verify TN Allocation credentials cover the originating number |
| SIP 404 Not Found | No TN mapping exists for the originating number, or mapping is disabled | Navigate to TN Mappings UI, verify the TN exists in E.164 format (e.g. `+441923311000`), click "Test" on the mapping |
| SIP 500 Internal Error | Issuer service unreachable from PBX, dossier does not exist, or signing identity missing | Check issuer health: `curl -s https://vvp-issuer.rcnx.io/healthz`. Check PBX→Issuer connectivity. Review SIP Redirect logs: `journalctl -u vvp-sip-redirect -n 100` on PBX |
| VVP headers always empty/None | Issuer response field name mismatch (`vvp_identity` vs `vvp_identity_header`) | Ensure SIP Redirect extracts `vvp_identity_header` and `passport_jwt` fields (fixed in Sprint 53) |

### Verification Issues (ErrorCode Reference)

The VVP Verifier uses 30 error codes across 9 layers. Each code indicates a specific verification failure:

**Protocol Layer**

| Error Code | Meaning | Likely Cause |
|------------|---------|-------------|
| `VVP_IDENTITY_MISSING` | No VVP-Identity header found | Signing service did not attach headers; check SIP Redirect logs |
| `VVP_IDENTITY_INVALID` | VVP-Identity header malformed | Header is not valid base64url JSON or missing required fields (`ppt`, `kid`, `evd`, `iat`) |
| `VVP_OOBI_FETCH_FAILED` | Could not resolve OOBI URL from `kid` field | Witness unreachable or `kid` URL malformed. Check witness health |
| `VVP_OOBI_CONTENT_INVALID` | OOBI response is not valid KERI content | Witness returned unexpected response. Check witness version |
| `PASSPORT_MISSING` | No PASSporT JWT found | Signing service did not generate PASSporT; check Issuer logs |
| `PASSPORT_PARSE_FAILED` | PASSporT JWT is malformed | JWT structure invalid. Use `vvp jwt parse` CLI to inspect |
| `PASSPORT_EXPIRED` | PASSporT `exp` or `iat` timestamp out of range | Clock drift between signer and verifier exceeds 300s, or PASSporT too old |

**Crypto Layer**

| Error Code | Meaning | Likely Cause |
|------------|---------|-------------|
| `PASSPORT_SIG_INVALID` | Ed25519 signature verification failed | Signing key has been rotated, or PASSporT was tampered with |
| `PASSPORT_FORBIDDEN_ALG` | JWT uses non-EdDSA algorithm | PASSporT must use EdDSA (Ed25519). Other algorithms are rejected |
| `ACDC_SAID_MISMATCH` | Credential SAID does not match computed hash | Credential was modified after issuance |
| `ACDC_PROOF_MISSING` | Credential lacks required proof/signature | ACDC was not properly signed during issuance |

**Evidence Layer**

| Error Code | Meaning | Likely Cause |
|------------|---------|-------------|
| `DOSSIER_URL_MISSING` | No `evd` URL in VVP-Identity header | Signing service did not populate the evidence URL |
| `DOSSIER_FETCH_FAILED` | Could not download dossier from `evd` URL | Issuer unreachable, URL points to localhost instead of public URL, or network error |
| `DOSSIER_PARSE_FAILED` | Dossier content is not valid | Dossier format incorrect or corrupted |
| `DOSSIER_GRAPH_INVALID` | Credential DAG structure invalid | Missing credentials in chain, circular references, or broken edges |

**KERI Layer**

| Error Code | Meaning | Likely Cause |
|------------|---------|-------------|
| `KERI_RESOLUTION_FAILED` | Could not resolve AID key state | Witnesses unreachable or AID not published. Check witness connectivity |
| `KERI_STATE_INVALID` | Key state is inconsistent | Key event log corrupted or incomplete |

**Revocation Layer**

| Error Code | Meaning | Likely Cause |
|------------|---------|-------------|
| `CREDENTIAL_REVOKED` | One or more credentials in the chain are revoked | Credential was explicitly revoked via TEL. Re-issue if needed |

**Authorization Layer**

| Error Code | Meaning | Likely Cause |
|------------|---------|-------------|
| `AUTHORIZATION_FAILED` | Credential chain does not establish authority | Issuer is not authorized in the trust chain |
| `TN_RIGHTS_INVALID` | Caller TN not covered by TN Allocation credentials | TN Allocation does not include the calling number. Issue new TN Allocation credential covering the range |

**Contextual Alignment Layer**

| Error Code | Meaning | Likely Cause |
|------------|---------|-------------|
| `CONTEXT_MISMATCH` | Call context does not match credential claims | Credential was issued for a different context than the current call |

**Brand/Business Logic Layer**

| Error Code | Meaning | Likely Cause |
|------------|---------|-------------|
| `BRAND_CREDENTIAL_INVALID` | Brand credential is invalid or missing | Brand information in dossier is malformed |
| `GOAL_REJECTED` | Call goal/purpose rejected by policy | Goal code in PASSporT does not meet verifier policy |

**Callee Verification Layer**

| Error Code | Meaning | Likely Cause |
|------------|---------|-------------|
| `DIALOG_MISMATCH` | SIP dialog parameters do not match PASSporT claims | Call-ID or From/To mismatch between SIP and PASSporT |
| `ISSUER_MISMATCH` | Credential issuer does not match expected issuer | Credential chain references unexpected issuer AID |

**Vetter Constraint Layer**

| Error Code | Meaning | Likely Cause |
|------------|---------|-------------|
| `VETTER_ECC_UNAUTHORIZED` | Vetter ECC authorization failed | Entity Category Code not recognized or unauthorized |
| `VETTER_JURISDICTION_UNAUTHORIZED` | Vetter jurisdiction check failed | Issuer jurisdiction does not match expected jurisdiction |
| `VETTER_CERTIFICATION_MISSING` | Vetter certification credential missing | Required QVI certification credential not in chain |
| `VETTER_CERTIFICATION_INVALID` | Vetter certification credential invalid | QVI certification is malformed, expired, or revoked |

**Verifier Layer**

| Error Code | Meaning | Likely Cause |
|------------|---------|-------------|
| `INTERNAL_ERROR` | Unexpected verifier error | Bug or resource exhaustion in verifier. Check verifier logs |

### Infrastructure Issues

| Symptom | Cause | Solution |
|---------|-------|----------|
| Issuer fails to start (LMDB lock) | Two issuer revisions running simultaneously; LMDB lock blocks new revision | Deactivate the old Active revision: `az containerapp revision deactivate`, then restart the new revision |
| Issuer returns 503 (database) | PostgreSQL connection pool exhausted under load | Check connection pool configuration. Restart issuer if pool is stuck |
| Witness returns non-200 on OOBI | Witness container restarted or not yet synced | Wait 30-60s for witness to sync. Health check: `curl -s https://vvp-witness1.rcnx.io/oobi` |
| PBX unreachable | Azure VM stopped or network security group blocking | Check VM status: `az vm show --resource-group VVP --name vvp-pbx --query powerState`. Verify NSG rules |
| WebRTC phone cannot register | FreeSWITCH WSS (port 7443) not configured or SSL certificate expired | Check FreeSWITCH WSS: `az vm run-command invoke --resource-group VVP --name vvp-pbx --command-id RunShellScript --scripts "fs_cli -x 'sofia status profile internal'"` |
| OAuth login fails (redirect_uri_mismatch) | OAuth callback URLs configured for localhost, not production URL | Update Azure App Registration redirect URIs to match production domain |
| SIP Monitor dashboard stops updating | WebSocket idle timeout (no calls for 10+ seconds) | Refresh the browser. WebSocket keepalive was added in Sprint 53 |
| Dossier verification returns INDETERMINATE | `evd` URL in VVP-Identity points to `localhost:8001` instead of public URL | Configure issuer public URL so dossier URLs use `https://vvp-issuer.rcnx.io` |
| Deploy fails with Azure VM Conflict | Only one `az vm run-command` can execute per VM at a time | Serialize VM commands. Wait for previous command to complete before issuing next |
| SIP INVITE timeout (32s) | VVP verification exceeds SIP Timer B default | Timer B extended to 35s in dialplan. If still timing out, check network latency to Verifier |

### Historical Bug Fixes (Sprints 42-53)

These issues have been fixed but may recur if configuration regresses:

| Symptom | Root Cause | Sprint | Resolution |
|---------|-----------|--------|------------|
| VVP headers always None in 302 | Field name mismatch: extracted `vvp_identity` instead of `vvp_identity_header` | 53 | Fixed field name extraction in SIP Redirect client |
| Health check reports wrong port | Version check used port 8080 (occupied by FusionPBX), actual status port is 8085 | 53 | Health check updated to use correct port |
| Database locked on Azure Files | SQLite + multiple replicas over SMB network share | 45-46 | Migrated to PostgreSQL; single-replica for LMDB |
| SIP INVITE retransmission crash | No deduplication of retransmitted INVITEs | 53 | Added transaction deduplication in SIP transport |
| macOS base64 flag incompatibility | BSD vs GNU base64 flags differ | 53 | Health check uses portable base64 flags |
| JSON serialization crash in SIP Monitor | Non-serializable Python types in WebSocket events | 48 | Added custom JSON encoder |
| Unauthorized TNs accepted for signing | Incomplete TN Allocation ownership validation | 42 | Added full TN Allocation credential chain validation |
| WebRTC calls fail to ring | Dialplan used `verto_contact()` instead of `sofia_contact()` | 43 | Updated dialplan to use correct contact function |
| SIP failures invisible in logs | Error scenarios logged at debug level | 53 | Upgraded to error level with tracebacks |

### Debugging Tools

| Tool | Purpose | Usage |
|------|---------|-------|
| **System health check** | Verify all services are responsive | `./scripts/system-health-check.sh --verbose` |
| **SIP trace** | Inspect raw SIP messages on PBX | `az vm run-command invoke ... --scripts "fs_cli -x 'sofia loglevel all 9'"` then check `/var/log/freeswitch/freeswitch.log` |
| **Issuer log inspection** | View issuer application logs | `az containerapp logs show -n vvp-issuer -g VVP --tail 100` |
| **SIP Redirect logs** | View SIP signing service logs | `az vm run-command invoke ... --scripts "journalctl -u vvp-sip-redirect -n 100 --no-pager"` |
| **Audit log filtering** | Filter admin events by type/date/user | Issuer admin dashboard → Audit Log tab |
| **VVP CLI** | Parse and inspect JWTs, credentials, dossiers | `vvp jwt parse token.jwt`, `vvp dossier validate dossier.json` |
| **Verifier UI** | Interactive verification with phase timing | `https://vvp-verifier.rcnx.io` |

---

## 14. Configuration Reference

For environment variables, service configuration, port assignments, health endpoint URLs, Azure Container Apps settings, and secrets management, see [DEPLOYMENT.md](DEPLOYMENT.md).

---

## 15. Quick Reference

### Service URLs

| Service | Production URL | Health Check |
|---------|---------------|-------------|
| VVP Issuer | `https://vvp-issuer.rcnx.io` | `GET /healthz` → `{"ok": true}` |
| VVP Verifier | `https://vvp-verifier.rcnx.io` | `GET /healthz` → `{"ok": true}` |
| SIP Redirect (Signer) | `pbx.rcnx.io:5070` (UDP) | Status: `http://localhost:8085/status` (PBX only) |
| SIP Verify | `pbx.rcnx.io:5071` (UDP) | — |
| KERI Witness 1 | `https://vvp-witness1.rcnx.io` | `GET /oobi` → HTTP 200 |
| KERI Witness 2 | `https://vvp-witness2.rcnx.io` | `GET /oobi` → HTTP 200 |
| KERI Witness 3 | `https://vvp-witness3.rcnx.io` | `GET /oobi` → HTTP 200 |
| PBX (FreeSWITCH) | `pbx.rcnx.io` (SIP 5060, WSS 7443) | — |
| Issuer UI | `https://vvp-issuer.rcnx.io/ui/admin` | — |
| Verifier UI | `https://vvp-verifier.rcnx.io` | — |
| WebRTC Phone | `https://pbx.rcnx.io/app/vvp-phone/sip-phone.html` | — |

### Test Phone Numbers

| Extension | Phone Number (E.164) | Description |
|-----------|---------------------|-------------|
| 1001 | +441923311000 | Test extension 1 |
| 1006 | +441923311006 | Test extension 2 |

### VVP Dial Prefix

Prefix `7` before an extension number to route through VVP signing and verification:

| Dial | Route |
|------|-------|
| `71006` | Ext 1001 → VVP signing → VVP verification → Ext 1006 |
| `71001` | Ext 1006 → VVP signing → VVP verification → Ext 1001 |
| `1006` | Direct call (no VVP) |

### Common Operations

| Task | Where |
|------|-------|
| Create an organization | Issuer UI → Organizations → Create |
| Create an API key | Issuer UI → Organization → API Keys → Create |
| Issue TN Allocation | Issuer UI → Credentials → Issue |
| Build a dossier | Issuer UI → Dossiers → Build |
| Create a TN mapping | Issuer UI → TN Mappings → Create |
| Test TN mapping | Issuer UI → TN Mappings → click "Test" |
| Verify a call manually | Verifier UI → paste VVP-Identity + PASSporT |
| Run health check | `./scripts/system-health-check.sh` |
| Run E2E test | `./scripts/system-health-check.sh --e2e` |
| Bootstrap after DB wipe | `python3 scripts/bootstrap-issuer.py --url https://vvp-issuer.rcnx.io` |
| View audit log | Issuer UI → Admin → Audit Log |

### Key PBX Files

| File | Purpose |
|------|---------|
| `/etc/freeswitch/dialplan/public.xml` | Main dialplan with VVP routes |
| `/opt/vvp/sip-redirect/` | SIP signing service |
| `/opt/vvp/sip-verify/` | SIP verification service |
| `/etc/systemd/system/vvp-sip-redirect.service` | SIP Redirect systemd unit |
| `/etc/systemd/system/vvp-sip-verify.service` | SIP Verify systemd unit |

### Related Documentation

| Document | Description |
|----------|-------------|
| [DEPLOYMENT.md](DEPLOYMENT.md) | Infrastructure, CI/CD, secrets, Azure configuration |
| [SIP_SIGNER.md](SIP_SIGNER.md) | SIP signing service full reference |
| [SIP_VERIFIER.md](SIP_VERIFIER.md) | SIP verification service full reference |
| [CREATING_DOSSIERS.md](CREATING_DOSSIERS.md) | Credential chain and dossier creation guide |
| [CLI_USAGE.md](CLI_USAGE.md) | VVP command-line tools reference |
| [E2E_TEST.md](../E2E_TEST.md) | End-to-end testing walkthrough |
| [architecture.md](../knowledge/architecture.md) | Deep system architecture reference |
| [README.md](../README.md) | Project overview and quickstart |
