# VVP System Deployment Architecture

**Version:** 1.3
**Last Updated:** 2026-02-06
**Status:** Source of Truth for VVP Infrastructure

---

## Overview

The VVP (Verified Voice Protocol) system consists of multiple interconnected services for issuing, signing, and verifying caller identity credentials. This document provides the authoritative reference for where each component is deployed, how they connect, and the CI/CD pipeline that maintains them.

### System Diagram

```
                                    ┌─────────────────────────────────────────────────────────────────┐
                                    │                     Azure UK South                               │
                                    │                                                                  │
┌──────────────────┐                │  ┌─────────────────────────────────────────────────────────────┐ │
│   Enterprise     │                │  │              Azure Container Apps Environment                │ │
│   PBX/SBC        │                │  │                                                             │ │
│                  │   SIP INVITE   │  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │ │
│                  │ + X-VVP-API-Key│  │  │ VVP Issuer  │  │ VVP Verifier│  │   KERI Witnesses    │ │ │
└────────┬─────────┘                │  │  │             │  │             │  │  ┌───┐ ┌───┐ ┌───┐ │ │ │
         │                          │  │  │ Port 443    │  │ Port 443    │  │  │wan│ │wil│ │wes│ │ │ │
         │                          │  │  │             │  │             │  │  └───┘ └───┘ └───┘ │ │ │
         ▼                          │  │  └──────▲──────┘  └──────▲──────┘  └──────────▲──────────┘ │ │
┌──────────────────┐                │  │         │               │                     │           │ │
│   Azure VM       │                │  └─────────┼───────────────┼─────────────────────┼───────────┘ │
│   vvp-pbx        │                │            │               │                     │             │
│                  │                │            │ HTTPS         │ HTTPS              │ OOBI        │
│ ┌──────────────┐ │                │            │               │                     │             │
│ │ FreeSWITCH   │─┼────────────────┼────────────┘               │                     │             │
│ │ (5060/5080)  │ │                │                            │                     │             │
│ └──────────────┘ │                │                            │                     │             │
│        │         │                │            ┌───────────────┴─────────────────────┘             │
│        ▼         │                │            │                                                   │
│ ┌──────────────┐ │                │            ▼                                                   │
│ │ SIP Signer   │ │ 302 + VVP      │    ┌─────────────┐                                            │
│ │ (UDP 5070)   │─┼─headers────────┼───>│   Carrier   │                                            │
│ └──────────────┘ │                │    │   Network   │                                            │
│        │         │                │    └─────────────┘                                            │
│        ▼         │                │            │                                                   │
│ ┌──────────────┐ │                │            │ Inbound + Identity                               │
│ │ SIP Verifier │ │                │            ▼                                                   │
│ │ (UDP 5071)   │─┼─────HTTPS──────┼──> VVP Verifier API                                           │
│ └──────────────┘ │                │                                                               │
│        │         │                └───────────────────────────────────────────────────────────────┘
│        ▼         │
│ ┌──────────────┐ │                ┌───────────────────┐
│ │ WebRTC WSS   │ │                │   Browser/WebRTC  │
│ │ (7443)       │◄┼────────────────┤   Client          │
│ └──────────────┘ │                │   (VVP Phone)     │
└──────────────────┘                └───────────────────┘
```

---

## Component Inventory

### Azure Container Apps (Managed)

| Component | Container App Name | Custom Domain | Health Endpoint | CI/CD |
|-----------|-------------------|---------------|-----------------|-------|
| **VVP Issuer** | `vvp-issuer` | `vvp-issuer.rcnx.io` | `/healthz` | GitHub Actions |
| **VVP Verifier** | `vvp-verifier` | `vvp-verifier.rcnx.io` | `/healthz` | GitHub Actions |
| **Witness 1 (wan)** | `vvp-witness1` | `vvp-witness1.rcnx.io` | `/oobi/{AID}/controller` | GitHub Actions |
| **Witness 2 (wil)** | `vvp-witness2` | `vvp-witness2.rcnx.io` | `/oobi/{AID}/controller` | GitHub Actions |
| **Witness 3 (wes)** | `vvp-witness3` | `vvp-witness3.rcnx.io` | `/oobi/{AID}/controller` | GitHub Actions |

### Azure VM (Manual Management)

| Component | VM Name | DNS | Ports | Management |
|-----------|---------|-----|-------|------------|
| **VVP PBX** | `vvp-pbx` | `pbx.rcnx.io` | See below | Azure CLI |

**PBX Services:**

| Service | Port | Protocol | Status | Description |
|---------|------|----------|--------|-------------|
| FreeSWITCH Internal | 5060 | UDP/TCP | Active | SIP for registered extensions |
| FreeSWITCH External | 5080 | UDP/TCP | Active | External SIP (PSTN, trunks) |
| FreeSWITCH WSS | 7443 | WSS | Active | WebRTC SIP over WebSocket |
| **SIP Signer (Live)** | 5070 | UDP | **Deployed** | VVP signing service (`services/sip-redirect/`) |
| **SIP Signer (Production)** | 5060/5061 | UDP/TLS | Future | Standard SIP ports for enterprise |
| **SIP Verifier (Live)** | 5071 | UDP | **Deployed (CI/CD)** | VVP verification service (`services/sip-verify/`) |
| **SIP Status (Signer)** | 8080 | HTTP | Deployed | `/status` endpoint (admin auth required) |
| FusionPBX Admin | 443 | HTTPS | Active | Web administration |

**Note:** Production SIP ports (5060/5061) are reserved for future enterprise deployment. Current live testing uses 5070 (signer) and 5071 (verifier).

---

## Service Details

### 1. VVP Issuer (`vvp-issuer.rcnx.io`)

**Purpose:** Issue ACDC credentials, manage organizations, users, and dossiers.

**Source:** `services/issuer/`

**Key Endpoints:**

| Endpoint | Description |
|----------|-------------|
| `/healthz` | Health check |
| `/identity` | KERI identity management |
| `/registry` | Credential registry management |
| `/credential/issue` | Issue ACDC credentials |
| `/dossier/build` | Assemble dossiers |
| `/dossiers/{said}` | Serve dossier JSON (evd URL for verification) |
| `/tn/mappings` | TN-to-dossier mappings |
| `/organizations` | Organization management |
| `/users` | User management |
| `/auth/login` | Session authentication |
| `/ui/*` | Web UI pages |

**Environment Variables (Production):**

```bash
VVP_WITNESS_CONFIG=/srv/config/witnesses-azure.json
VVP_AUTH_ENABLED=true
VVP_SESSION_SECRET=<secret>
VVP_DATABASE_URL=sqlite:///data/vvp-issuer/vvp_issuer.db
VVP_MOCK_VLEI_ENABLED=true
GIT_SHA=<commit>
```

**Persistent Storage:**

- Database: `/data/vvp-issuer/vvp_issuer.db`
- KERI keystores: `/data/vvp-issuer/keystores/`
- KERI databases: `/data/vvp-issuer/databases/`

---

### 2. VVP Verifier (`vvp-verifier.rcnx.io`)

**Purpose:** Verify VVP-Identity headers, PASSporTs, and dossier credential chains.

**Source:** `services/verifier/`

**Key Endpoints:**

| Endpoint | Description |
|----------|-------------|
| `/healthz` | Health check |
| `/verify` | Verify dossier (full verification) |
| `/verify-callee` | Verify for inbound call context |
| `/` | Web UI for verification |

**Environment Variables (Production):**

```bash
VVP_LOCAL_WITNESS_URLS=https://vvp-witness1.rcnx.io,https://vvp-witness2.rcnx.io,https://vvp-witness3.rcnx.io
VVP_GLEIF_WITNESS_DISCOVERY=false
GIT_SHA=<commit>
```

---

### 3. KERI Witnesses

**Purpose:** Provide witness receipts for KERI key events, enabling AID resolution.

**Source:** `services/witness/`

**Deterministic AIDs:**

| Witness | AID |
|---------|-----|
| wan (witness1) | `BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha` |
| wil (witness2) | `BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM` |
| wes (witness3) | `BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX` |

**OOBI URLs:**

```
https://vvp-witness1.rcnx.io/oobi/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha/controller
https://vvp-witness2.rcnx.io/oobi/BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM/controller
https://vvp-witness3.rcnx.io/oobi/BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX/controller
```

---

### 4. VVP PBX (`pbx.rcnx.io`)

**Purpose:** Test infrastructure for VVP SIP flows, WebRTC client hosting.

**Platform:** FusionPBX (FreeSWITCH) on Debian

**Source:** `services/pbx/`

**Key Components:**

| Component | Location | Description |
|-----------|----------|-------------|
| Dialplan | `/etc/freeswitch/dialplan/public.xml` | VVP routing rules |
| Mock SIP Services | `/opt/vvp/mock/mock_sip_redirect.py` | Signing & verification |
| Systemd Unit | `/etc/systemd/system/vvp-mock-sip.service` | Service management |
| WebRTC Client | `services/pbx/webrtc/vvp-phone/` | VVP Phone UI |

**Test Flow (VVP Loopback):**

1. Register extension 1001 via SIP.js WebRTC (`wss://pbx.rcnx.io:7443`)
2. Dial `71006` (7 prefix triggers VVP signing flow)
3. Call routes: 1001 → SIP Signer (5070) → Extension 1006
4. Extension 1006 receives call with VVP brand headers

---

### 5. SIP Redirect Signing Service

**Purpose:** Add VVP attestation headers to outbound SIP calls.

**Source:** `services/sip-redirect/`

**Status:**
| Aspect | Status |
|--------|--------|
| Code | Complete (Sprint 42) |
| Deployment | **Live on port 5070** |
| CI/CD | Not automated (manual deployment) |

**Flow:**

```
Enterprise SBC ──SIP INVITE + X-VVP-API-Key──> SIP Signer (UDP 5070)
                                                    │
                                                    ▼ HTTPS
                                              VVP Issuer API
                                              (/tn/lookup, /vvp/create)
                                                    │
                                                    ▼
Enterprise SBC <──SIP 302 + VVP Headers─────────────┘
```

**Response Headers:**

| Header | Description |
|--------|-------------|
| `P-VVP-Identity` | Base64url VVP-Identity JSON |
| `P-VVP-Passport` | PASSporT JWT |
| `X-VVP-Brand-Name` | Organization name |
| `X-VVP-Brand-Logo` | Logo URL (optional) |
| `X-VVP-Status` | VALID, INVALID, or INDETERMINATE |

**See also:** [SIP_SIGNER.md](SIP_SIGNER.md) for detailed configuration

---

### 6. SIP Redirect Verification Service

**Purpose:** Verify VVP attestation on inbound SIP calls.

**Source:** `services/sip-verify/`

**Status:**
| Aspect | Status |
|--------|--------|
| Code | Complete (Sprint 44) |
| Deployment | **Live on port 5071** |
| CI/CD | **Automated** (atomic symlink deploy with rollback) |

**Flow:**

```
Carrier SBC ──SIP INVITE + Identity Header──> SIP Verifier (UDP 5071)
                                                    │
                                                    ▼ HTTPS
                                              VVP Verifier API
                                              (/verify-callee)
                                                    │
                                                    ▼
PBX/WebRTC <──SIP 302 + X-VVP Headers───────────────┘
```

**See also:** [SIP_VERIFIER.md](SIP_VERIFIER.md) for detailed configuration

---

## CI/CD Pipeline

> **Full documentation:** See [CICD.md](CICD.md) for comprehensive pipeline documentation including all job details, dependency graphs, deployment strategies, troubleshooting, and rollback procedures.

**Trigger:** Push to `main` branch

**Workflows:**
- `.github/workflows/deploy.yml` — Build, test, and deploy all services
- `.github/workflows/integration-tests.yml` — Nightly and manual integration tests

**Key features:**
- **Path-based change detection** — Only changed services are tested and deployed
- **6 deployment targets** — Verifier, Issuer, 3 Witnesses (Container Apps) + 3 PBX VM services
- **Automatic rollback** — SIP services on PBX VM roll back on failure via atomic symlink switch
- **Serialized VM deploys** — PBX jobs chain sequentially to avoid Azure run-command conflicts
- **Post-deployment tests** — Integration tests run against Azure after deploy, results reported to admin dashboard
- **OIDC authentication** — No static Azure credentials stored in GitHub

---

## PBX Management

### Azure CLI Commands

The PBX VM is managed via Azure CLI (SSH keys not configured for Claude Code).

**VM Details:**

| Property | Value |
|----------|-------|
| Resource Group | `VVP` |
| VM Name | `vvp-pbx` |
| DNS | `pbx.rcnx.io` |

**Common Commands:**

```bash
# Run a command on the PBX
az vm run-command invoke \
  --resource-group VVP \
  --name vvp-pbx \
  --command-id RunShellScript \
  --scripts "command here"

# Check mock SIP service status
az vm run-command invoke --resource-group VVP --name vvp-pbx \
  --command-id RunShellScript \
  --scripts "systemctl status vvp-mock-sip --no-pager"

# View service logs
az vm run-command invoke --resource-group VVP --name vvp-pbx \
  --command-id RunShellScript \
  --scripts "journalctl -u vvp-mock-sip -n 50 --no-pager"

# Reload FreeSWITCH dialplan
az vm run-command invoke --resource-group VVP --name vvp-pbx \
  --command-id RunShellScript \
  --scripts "fs_cli -x 'reloadxml'"

# Check registered extensions
az vm run-command invoke --resource-group VVP --name vvp-pbx \
  --command-id RunShellScript \
  --scripts "fs_cli -x 'sofia status profile internal reg'"

# Restart FreeSWITCH
az vm run-command invoke --resource-group VVP --name vvp-pbx \
  --command-id RunShellScript \
  --scripts "systemctl restart freeswitch"
```

**Deploy a File to PBX:**

```bash
# Base64 encode and deploy (stdin pipe doesn't work with az vm run-command)
FILE_CONTENT=$(cat path/to/local/file | base64)
az vm run-command invoke --resource-group VVP --name vvp-pbx \
  --command-id RunShellScript \
  --scripts "echo '$FILE_CONTENT' | base64 -d > /remote/path/file"
```

---

## Local Development

### Docker Compose

**File:** `docker-compose.yml`

**Services:**

| Service | Command | Ports |
|---------|---------|-------|
| `witnesses` | `docker compose up -d` | 5632-5634 (TCP), 5642-5644 (HTTP) |
| `verifier` | `docker compose --profile full up` | 8000 |
| `issuer` | `docker compose --profile full up` | 8001 |

**Local URLs:**

| Service | URL |
|---------|-----|
| Issuer | http://localhost:8001 |
| Issuer UI | http://localhost:8001/create |
| Verifier | http://localhost:8000 |
| Witness (wan) | http://localhost:5642 |
| Witness (wil) | http://localhost:5643 |
| Witness (wes) | http://localhost:5644 |

---

## Health Monitoring

### Health Endpoints

| Service | Endpoint | Expected Response |
|---------|----------|-------------------|
| Issuer | `https://vvp-issuer.rcnx.io/healthz` | `200 OK` |
| Verifier | `https://vvp-verifier.rcnx.io/healthz` | `200 OK` |
| Witness 1 | `https://vvp-witness1.rcnx.io/oobi/{AID}/controller` | `200/202` |
| Witness 2 | `https://vvp-witness2.rcnx.io/oobi/{AID}/controller` | `200/202` |
| Witness 3 | `https://vvp-witness3.rcnx.io/oobi/{AID}/controller` | `200/202` |

### Quick Health Check Script

```bash
#!/bin/bash
echo "=== VVP Health Check ==="

# Container Apps
curl -s -o /dev/null -w "Issuer:   %{http_code}\n" https://vvp-issuer.rcnx.io/healthz
curl -s -o /dev/null -w "Verifier: %{http_code}\n" https://vvp-verifier.rcnx.io/healthz

# Witnesses
curl -s -o /dev/null -w "Witness1: %{http_code}\n" \
  https://vvp-witness1.rcnx.io/oobi/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha/controller
curl -s -o /dev/null -w "Witness2: %{http_code}\n" \
  https://vvp-witness2.rcnx.io/oobi/BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM/controller
curl -s -o /dev/null -w "Witness3: %{http_code}\n" \
  https://vvp-witness3.rcnx.io/oobi/BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX/controller

# PBX (via Azure CLI)
echo "PBX: (check via Azure CLI)"
```

---

## DNS Records

| Domain | Type | Target | Description |
|--------|------|--------|-------------|
| `vvp-issuer.rcnx.io` | CNAME | Azure Container App | Issuer service |
| `vvp-verifier.rcnx.io` | CNAME | Azure Container App | Verifier service |
| `vvp-witness1.rcnx.io` | CNAME | Azure Container App | Witness 1 |
| `vvp-witness2.rcnx.io` | CNAME | Azure Container App | Witness 2 |
| `vvp-witness3.rcnx.io` | CNAME | Azure Container App | Witness 3 |
| `pbx.rcnx.io` | A | Azure VM Public IP | PBX/SIP services |

---

## Secrets & Configuration

### GitHub Secrets

| Secret | Purpose | Status |
|--------|---------|--------|
| `AZURE_CLIENT_ID` | OIDC authentication | Required |
| `AZURE_TENANT_ID` | OIDC authentication | Required |
| `AZURE_SUBSCRIPTION_ID` | Azure subscription | Required |
| `AZURE_RG` | Resource group name | Required |
| `ACR_NAME` | Container registry name | Required |
| `ACR_LOGIN_SERVER` | Registry login URL | Required |
| `AZURE_CONTAINERAPP_NAME` | Verifier container app | Required |
| `VVP_ADMIN_API_KEY` | Admin API key for tests | Required |
| `AZURE_STORAGE_CONNECTION_STRING` | Blob storage for dossier hosting | Required |
| `AZURE_STORAGE_ACCOUNT` | Storage account name for SIP deployments | **New** |
| `VVP_SIP_STATUS_ADMIN_KEY` | Admin key for SIP `/status` endpoint | **New** |

> **Note:** The `AZURE_STORAGE_ACCOUNT` and `VVP_SIP_STATUS_ADMIN_KEY` secrets must be
> configured in GitHub repository settings before SIP service CI/CD will work.

### Issuer Configuration Files

| File | Location (Local) | Location (Azure) |
|------|-----------------|------------------|
| `api_keys.json` | `config/api_keys.json` | `/srv/config/api_keys.json` |
| `witnesses.json` | `config/witnesses.json` | `/srv/config/witnesses.json` |
| `witnesses-azure.json` | `config/witnesses-azure.json` | `/srv/config/witnesses-azure.json` |

---

## Deployment Gaps & TODOs

### Implementation Status

| Component | Code | Deployment | CI/CD |
|-----------|------|------------|-------|
| `services/sip-redirect/` | Complete (Sprint 42) | **Live on 5070** | **Automated** |
| `services/sip-verify/` | Complete (Sprint 44) | **Live on 5071** | **Automated** |
| PBX dialplan | Complete | Manual via Azure CLI | **Automated** |
| Mock SIP service | Legacy | **Stopped** | N/A |

> **CI/CD Note:** SIP redirect deployment uses atomic symlink switching with automatic
> rollback on failure. Requires `AZURE_STORAGE_ACCOUNT` and `VVP_SIP_STATUS_ADMIN_KEY` secrets.

### CI/CD Coverage

All services are now automated in CI/CD. See [CICD.md](CICD.md) for full details.

> **Note:** SIP Redirect, SIP Verify, and PBX Configuration are all automated in CI/CD.
> See `.github/workflows/deploy.yml` for the `deploy-sip-redirect`, `deploy-sip-verify`, and `deploy-pbx-config` jobs.

### Future Improvements

1. ~~**Automate SIP Services Deployment**~~ - ✅ Completed (sip-redirect + sip-verify)
2. ~~**Add SIP Verify Deployment**~~ - ✅ Completed with atomic deploy and rollback
3. **PBX Infrastructure-as-Code** - Terraform/Bicep for VM provisioning
4. **Monitoring Dashboard** - Centralized health monitoring
5. **Alerting** - PagerDuty/Slack integration for failures
6. **Blue-Green Deployment** - Zero-downtime updates for Container Apps
7. **Azure Key Vault** - Dynamic secrets management for VM services

---

## Rollback Procedures

### Container Apps

```bash
# List recent revisions
az containerapp revision list \
  --name vvp-issuer \
  --resource-group VVP \
  --query "[].name" -o tsv

# Activate a previous revision
az containerapp revision activate \
  --name vvp-issuer \
  --resource-group VVP \
  --revision <revision-name>
```

### PBX

```bash
# Restore dialplan from backup
az vm run-command invoke --resource-group VVP --name vvp-pbx \
  --command-id RunShellScript \
  --scripts "cp /etc/freeswitch/dialplan/public.xml.bak /etc/freeswitch/dialplan/public.xml && fs_cli -x 'reloadxml'"
```

---

## Contact & Support

| Issue | Action |
|-------|--------|
| Container App issues | Check Azure Portal, review CI/CD logs |
| PBX issues | Azure CLI commands, check FreeSWITCH logs |
| DNS issues | Check rcnx.io DNS provider |
| Certificate issues | Azure managed certs (Container Apps), Let's Encrypt (PBX) |

---

## Test Environment

### Trial Dossier (Acme Corp)

For testing VVP signing and verification, use these pre-configured test assets:

| Setting | Value |
|---------|-------|
| **Organization** | Acme Corp |
| **Test TN** | `+441923311000` |
| **API Key** | `vvp_test_acme_corp_api_key_12345678901234567890` |
| **Dossier SAID** | `ETnAllocationSAIDforAcmeCorpExtension1001` |

**Test Fixtures Location:** `services/sip-redirect/tests/fixtures/`

See [SIP_SIGNER.md](SIP_SIGNER.md) for PBX configuration instructions.

### API Key Registration

To use the test API key with the SIP signer:

1. Register the API key in the issuer database
2. Associate it with the Acme Corp organization
3. Create TN mapping for `+441923311000`

**Note:** The test API key is for development only and should not be used in production.

---

## PBX Service Deployment

### Deploying SIP Redirect Service

**Prerequisites:**
- Python 3.11+ on PBX VM
- `common` package deployed to `/opt/vvp/common-pkg/`
- httpx library installed

**Deployment Steps:**

```bash
# 1. Package the service
cd services/sip-redirect
tar -czf sip-redirect.tar.gz app/ pyproject.toml

# 2. Deploy via Azure CLI (base64 encode for transfer)
FILE=$(cat sip-redirect.tar.gz | base64)
az vm run-command invoke --resource-group VVP --name vvp-pbx \
  --command-id RunShellScript \
  --scripts "echo '$FILE' | base64 -d | tar -xzf - -C /opt/vvp/sip-redirect"

# 3. Restart the service
az vm run-command invoke --resource-group VVP --name vvp-pbx \
  --command-id RunShellScript \
  --scripts "systemctl restart vvp-sip-redirect"

# 4. Verify status
az vm run-command invoke --resource-group VVP --name vvp-pbx \
  --command-id RunShellScript \
  --scripts "systemctl status vvp-sip-redirect --no-pager"
```

### Environment Variables for SIP Services

**File:** `/etc/vvp/sip-redirect.env` (mode 0600, root-only)

| Variable | Value | Description |
|----------|-------|-------------|
| `VVP_ISSUER_URL` | `https://vvp-issuer.rcnx.io` | Issuer API for TN lookup |
| `VVP_SIP_LISTEN_PORT` | `5070` | SIP listen port |
| `VVP_STATUS_ADMIN_KEY` | `<secret>` | Admin key for /status endpoint |
| `PYTHONPATH` | `/opt/vvp/common-pkg/common` | Common package location |

**Systemd Unit:** `/etc/systemd/system/vvp-sip-redirect.service`

```ini
[Unit]
Description=VVP SIP Redirect Signing Service
After=network.target

[Service]
Type=simple
User=root
EnvironmentFile=/etc/vvp/sip-redirect.env
WorkingDirectory=/opt/vvp/sip-redirect
ExecStart=/usr/bin/python3 -m app.main
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

---

## TN Mapping Configuration

Before the SIP signer can attest calls, TN mappings must exist:

1. Access issuer UI: `https://vvp-issuer.rcnx.io/ui/tn-mappings`
2. Create organization with API key (`dossier_manager` role)
3. Create TN mapping linking phone number to dossier
4. Configure PBX dialplan with the organization's API key

### Required Fields

| Field | Description | Example |
|-------|-------------|---------|
| Telephone Number | E.164 format | `+441923311000` |
| Dossier SAID | Credential chain identifier | `EFvnoHDY7I...` |
| Signing Identity | KERI AID for signing | `EJccSRTfXYF6...` |

---

## Database Configuration

The issuer uses SQLite with automatic path detection:

| Priority | Path | Use Case |
|----------|------|----------|
| 1 | `VVP_ISSUER_DATA_DIR` env var | Explicit override |
| 2 | `/data/vvp-issuer` | Docker/Azure volume mount |
| 3 | `~/.vvp-issuer` | Local development |
| 4 | `/tmp/vvp-issuer` | Container fallback |

**Data Directory Contents:**
- `keystores/` - KERI keystores (AID private keys)
- `databases/` - KERI LMDB databases (key event logs)

### PostgreSQL Database (Sprint 46)

The issuer uses Azure Database for PostgreSQL Flexible Server for multi-tenant data storage.

**Connection Configuration:**

| Environment Variable | Description |
|---------------------|-------------|
| `VVP_POSTGRES_HOST` | PostgreSQL server hostname |
| `VVP_POSTGRES_USER` | Database username |
| `VVP_POSTGRES_PASSWORD` | Database password |
| `VVP_POSTGRES_DB` | Database name |

The connection URL is constructed with `sslmode=require` for encrypted connections.

**Container App Settings:**

| Setting | Value | Reason |
|---------|-------|--------|
| `minReplicas` | 1 | Ensure availability |
| `maxReplicas` | 3 | Allow horizontal scaling |

**Security Configuration:**

| Setting | Value |
|---------|-------|
| SSL/TLS | Required (`sslmode=require`) |
| Firewall | Container Apps IPs only |
| Credentials | GitHub Secrets via Key Vault |

**Connection Pooling (session.py):**

```python
# PostgreSQL connection pool settings
pool_size = 5          # Base pool size
max_overflow = 10      # Additional connections if needed
pool_recycle = 1800    # Recycle connections every 30 min
pool_pre_ping = True   # Verify connections before use
```

### Local Development (SQLite Fallback)

For local development without PostgreSQL, the issuer falls back to SQLite:

```bash
# Default local database location
~/.vvp-issuer/vvp_issuer.db
```

SQLite is configured with appropriate PRAGMAs for local development:
- `foreign_keys=ON` - Enforce referential integrity
- `journal_mode=WAL` - Write-ahead logging
- `busy_timeout=5000` - 5 second lock timeout

---

## TLS/Certificate Configuration

### Container Apps (Azure Managed)

Azure Container Apps automatically manages TLS certificates for custom domains. No manual renewal required.

### PBX (Let's Encrypt)

**Certificate Location:** `/etc/letsencrypt/live/pbx.rcnx.io/`

**Renewal:** Automatic via certbot timer

```bash
# Check certificate status
az vm run-command invoke --resource-group VVP --name vvp-pbx \
  --command-id RunShellScript \
  --scripts "certbot certificates"

# Force renewal
az vm run-command invoke --resource-group VVP --name vvp-pbx \
  --command-id RunShellScript \
  --scripts "certbot renew --force-renewal"
```

---

## Log Access

### Container Apps

```bash
# View issuer logs
az containerapp logs show --name vvp-issuer --resource-group VVP --tail 100

# Stream verifier logs
az containerapp logs show --name vvp-verifier --resource-group VVP --follow
```

### PBX VM

```bash
# SIP signer logs
az vm run-command invoke --resource-group VVP --name vvp-pbx \
  --command-id RunShellScript \
  --scripts "journalctl -u vvp-sip-redirect -n 100 --no-pager"

# FreeSWITCH logs
az vm run-command invoke --resource-group VVP --name vvp-pbx \
  --command-id RunShellScript \
  --scripts "tail -100 /var/log/freeswitch/freeswitch.log"
```

---

## Network Security Groups

### PBX VM NSG Rules

| Priority | Name | Port | Protocol | Source | Action |
|----------|------|------|----------|--------|--------|
| 100 | Allow-SIP | 5060 | UDP/TCP | Any | Allow |
| 110 | Allow-SIPS | 5061 | TCP | Any | Allow |
| 120 | Allow-SIP-Signer | 5070 | UDP | Any | Allow |
| 130 | Allow-SIP-Verifier | 5071 | UDP | Any | Allow |
| 140 | Allow-WSS | 7443 | TCP | Any | Allow |
| 150 | Allow-HTTPS | 443 | TCP | Any | Allow |
| 160 | Allow-RTP | 16384-32768 | UDP | Any | Allow |
| 200 | Allow-Status | 8080 | TCP | Trusted IPs | Allow |

---

## Secrets Management

### VM-Local Secrets

Secrets are stored in `/etc/vvp/*.env` files with restricted permissions (mode 0600).

**Never** pass secrets inline in `az vm run-command` scripts (they appear in process args).

### Setup (One-Time)

```bash
# On PBX VM
mkdir -p /etc/vvp
chmod 700 /etc/vvp

# Create secrets file
cat > /etc/vvp/sip-redirect.env << 'EOF'
VVP_ISSUER_URL=https://vvp-issuer.rcnx.io
VVP_STATUS_ADMIN_KEY=<admin-key-here>
VVP_SIP_LISTEN_PORT=5070
PYTHONPATH=/opt/vvp/common-pkg/common
EOF

chmod 600 /etc/vvp/sip-redirect.env
```

### Future Enhancement

Use Azure Key Vault with VM Managed Identity for dynamic secret fetching.

---

## Dialplan Configuration

### File Locations

| File | Purpose |
|------|---------|
| `/etc/freeswitch/dialplan/public.xml` | Inbound calls from external sources |
| `/etc/freeswitch/dialplan/default.xml` | Calls from registered internal extensions |

### Reload After Changes

```bash
az vm run-command invoke --resource-group VVP --name vvp-pbx \
  --command-id RunShellScript \
  --scripts "fs_cli -x 'reloadxml'"
```

---

## CI/CD Conditional Deployment

All services use path-based change detection. See [CICD.md](CICD.md) for full details.

| Service | Trigger Paths | Notes |
|---------|--------------|-------|
| Verifier | `services/verifier/**`, `common/**` | Conditional |
| Issuer | `services/issuer/**`, `common/**` | Conditional |
| Witnesses | `services/witness/**` | Conditional, matrix deploy |
| SIP Redirect | `services/sip-redirect/**`, `common/**` | Conditional, atomic deploy |
| SIP Verify | `services/sip-verify/**`, `common/**` | Conditional, atomic deploy |
| PBX Config | `services/pbx/config/**` | Conditional, dialplan reload |

---

## Related Documentation

| Document | Description |
|----------|-------------|
| [CICD.md](CICD.md) | **Comprehensive CI/CD pipeline documentation** |
| [SIP_SIGNER.md](SIP_SIGNER.md) | SIP signing service admin guide |
| [SIP_VERIFIER.md](SIP_VERIFIER.md) | SIP verification service admin guide |
| `CLAUDE.md` | Development workflow and permissions |
| `SPRINTS.md` | Sprint roadmap and deliverables |

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.3 | 2026-02-07 | Updated CI/CD section to reference new CICD.md. Fixed outdated SIP verify status (now live + automated). Updated conditional deployment table. |
| 1.2 | 2026-02-07 | Sprint 46: PostgreSQL migration. Updated database section for Azure PostgreSQL, removed SQLite workarounds. |
| 1.1 | 2026-02-06 | Added missing sections: Test Environment, PBX Deployment, TN Mapping, Database Config, TLS, Logs, NSG, Secrets, Related Docs. Updated SIP service status. |
| 1.0 | 2026-02-06 | Initial comprehensive deployment document |
