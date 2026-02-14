# VVP Deployment Reference

## CI/CD Pipeline

### GitHub Actions (`deploy.yml`)
**Repo**: `Rich-Connexions-Ltd/VVP`
**Trigger**: Push to `main` branch, or `workflow_dispatch`
**Target**: Azure Container Apps (UK South region)

**Workflow dispatch inputs:**
- `force_all` (boolean) — Deploy ALL services regardless of changed paths
- `lock_wait_seconds` (string, default `120`) — Max seconds to poll for LMDB lock release

### Deployment Flow
```
Push to main
  → GitHub Actions triggered
    → Build Docker image
    → Push to Azure Container Registry
    → Deploy to Azure Container Apps
    → Health check verification
```

### Deployment Jobs

The pipeline has separate jobs triggered by path filters:

| Job | Trigger Paths | Target |
|-----|---------------|--------|
| `deploy-verifier` | `services/verifier/**`, `common/**` | Azure Container Apps |
| `deploy-issuer` | `services/issuer/**`, `common/**` | Azure Container Apps (LMDB single-revision) |
| `deploy-sip-redirect` | `services/sip-redirect/**`, `common/**` | PBX VM via `az vm run-command` |
| `deploy-sip-verify` | `services/sip-verify/**`, `common/**` | PBX VM via `az vm run-command` |
| `build-witness-image` + `deploy-witnesses` | `services/witness/**` | Azure Container Apps (3 witnesses) |
| `deploy-pbx-config` | `services/pbx/config/**` | PBX VM FreeSWITCH dialplan |

All path filters are bypassed when `force_all=true` is passed via workflow dispatch.

### Issuer LMDB Constraint

The issuer uses LMDB (keripy) on a shared Azure Files volume. **Two revisions CANNOT run simultaneously** — the LMDB lock blocks the new revision's startup. CI/CD uses a 4-phase stop-before-deploy sequence:

1. **Scale to zero** — `--min-replicas 0 --max-replicas 0` forces container shutdown faster than deactivation alone
2. **Deactivate revisions** — with up to 3 retries per revision to handle transient Azure API failures
3. **Poll until stopped** — checks both `runningState` and `replicas` count, with 120s timeout (configurable via `lock_wait_seconds` workflow input). **Fails hard** on timeout instead of proceeding
4. **Lock release buffer** — 10s sleep after all revisions report stopped, to allow the Azure Files mount to release the LMDB file lock

Brief downtime is ~30-40s. The deploy step restores `--min-replicas 1 --max-replicas 3`.

**Verification timeout**: Issuer version check polls for **5 minutes** (16 intervals of 10-20s) because LMDB/Habery initialization on Azure Files takes ~3 minutes.

### SIP Redirect Deploy

Deploys via tarball upload to Azure Blob Storage, then single `az vm run-command` that downloads, extracts, symlink-switches, updates systemd, and restarts. Uses a single run-command to avoid Azure serialization conflicts (only one run-command per VM at a time).

Version verification uses `az vm run-command` to curl `localhost:8085/version` (port not externally accessible via NSG).

### Verifying Deployment
```bash
# Verifier health check
curl https://vvp-verifier.wittytree-2a937ccd.uksouth.azurecontainerapps.io/healthz

# Issuer health check
curl https://vvp-issuer.rcnx.io/healthz

# SIP redirect version (via PBX)
az vm run-command invoke --resource-group VVP --name vvp-pbx \
  --command-id RunShellScript --scripts "curl -s http://localhost:8085/version"

# Monitor deployment
gh run watch -R Rich-Connexions-Ltd/VVP

# Force deploy all services (workflow dispatch)
gh workflow run "Build and deploy to Azure Container Apps" -R Rich-Connexions-Ltd/VVP -f force_all=true
```

---

## Docker Configuration

### Docker Compose Profiles
```bash
# Default: witnesses only
docker compose up -d

# Full stack: witnesses + verifier + issuer
docker compose --profile full up -d

# View logs
docker compose logs -f

# Stop all
docker compose down
```

### Service Ports (Local Development)

| Service | Port | Protocol |
|---------|------|----------|
| Verifier | 8000 | HTTP |
| Issuer | 8001 | HTTP |
| Witness wan | 5642 | HTTP |
| Witness wil | 5643 | HTTP |
| Witness wes | 5644 | HTTP |

### Service URLs (Production)

| Service | URL |
|---------|-----|
| Verifier | `https://vvp-verifier.wittytree-2a937ccd.uksouth.azurecontainerapps.io` |
| Issuer | `https://vvp-issuer.rcnx.io` |
| PBX | `pbx.rcnx.io` |

---

## Azure Infrastructure

### Container Apps
- **Region**: UK South
- **Platform**: Azure Container Apps
- **Registry**: Azure Container Registry

### PBX VM
- **Name**: `vvp-pbx`
- **Resource Group**: `VVP`
- **DNS**: `pbx.rcnx.io`
- **Platform**: FusionPBX (FreeSWITCH) on Debian

### PBX Management (via Azure CLI)
```bash
# Run command on PBX
az vm run-command invoke --resource-group VVP --name vvp-pbx \
  --command-id RunShellScript --scripts "your command"

# Check SIP service status
az vm run-command invoke --resource-group VVP --name vvp-pbx \
  --command-id RunShellScript --scripts "systemctl status vvp-sip-redirect"

# Deploy file to PBX (base64 encoding required - stdin piping doesn't work)
FILE_CONTENT=$(cat local/file | base64)
az vm run-command invoke --resource-group VVP --name vvp-pbx \
  --command-id RunShellScript --scripts "echo '$FILE_CONTENT' | base64 -d > /remote/path"
```

### Key PBX Paths

| Path | Purpose |
|------|---------|
| `/etc/freeswitch/dialplan/public.xml` | Main dialplan |
| `/etc/vvp/sip-redirect.env` | SIP redirect config (env vars including GIT_SHA, VVP_STATUS_HTTP_PORT=8085) |
| `/var/log/vvp-sip/audit-*.jsonl` | Audit logs |

### PBX Ports

| Service | Port | Protocol |
|---------|------|----------|
| FreeSWITCH Internal SIP | 5060 | UDP/TCP |
| FreeSWITCH External SIP | 5080 | UDP/TCP |
| FreeSWITCH WebSocket | 7443 | WSS |
| SIP Redirect (Signing) | 5070 | UDP |
| SIP Verify (Verification) | 5071 | UDP |
| SIP Redirect Status | 8085 | HTTP (localhost only, not exposed via NSG) |

---

## Environment Variables

### Verifier
| Variable | Default | Purpose |
|----------|---------|---------|
| `TRUSTED_ROOT_AIDS` | GLEIF AIDs | Comma-separated trusted root identifiers |
| `MAX_PASSPORT_VALIDITY_SECONDS` | 300 | Maximum PASSporT age |
| `CLOCK_SKEW_SECONDS` | 300 | Allowed clock drift |

### Issuer
| Variable | Default | Purpose |
|----------|---------|---------|
| `DATABASE_URL` | `sqlite:///data/vvp.db` | Database connection |
| `OAUTH_M365_CLIENT_ID` | - | Microsoft OAuth client ID |
| `OAUTH_M365_TENANT_ID` | - | Microsoft OAuth tenant |
| `SESSION_TTL_SECONDS` | 3600 | Session timeout |

### SIP Redirect
| Variable | Default | Purpose |
|----------|---------|---------|
| `VVP_ISSUER_URL` | `http://localhost:8001` | Issuer API endpoint |
| `VVP_SIP_LISTEN_PORT` | 5060 | SIP UDP listen port (PBX overrides to 5070) |
| `VVP_STATUS_HTTP_PORT` | 8080 | Status endpoint port (PBX overrides to 8085) |
| `VVP_STATUS_ADMIN_KEY` | *(none)* | Admin key for /status |
| `VVP_RATE_LIMIT_RPS` | 10.0 | Requests per second |
| `VVP_RATE_LIMIT_BURST` | 50 | Burst size |
| `VVP_TN_CACHE_TTL` | 300 | TN lookup cache TTL (seconds) |
| `VVP_TN_CACHE_MAX_ENTRIES` | 1000 | TN lookup cache max entries |
| `VVP_MONITOR_ENABLED` | false | Enable monitoring dashboard |
| `GIT_SHA` | unknown | Version tracking (injected by CI/CD) |

---

## Running Locally

### Prerequisites
- Python 3.12+
- libsodium (`brew install libsodium` on macOS)
- Docker Desktop (for witnesses)

### Quick Start
```bash
# Start witnesses
docker compose up -d

# Install common package
pip install -e common/

# Run verifier
cd services/verifier && pip install -e . && uvicorn app.main:app --port 8000

# Run issuer
cd services/issuer && pip install -e . && uvicorn app.main:app --port 8001
```

### Running Tests
```bash
# Always use the test runner (handles libsodium path)
./scripts/run-tests.sh              # All tests
./scripts/run-tests.sh -v           # Verbose
./scripts/run-tests.sh -k "test_x"  # Specific pattern
```

### Operational Scripts

| Script | Purpose |
|--------|---------|
| `scripts/system-health-check.sh` | 4-phase health check (container apps, PBX, connectivity, E2E SIP). Use `--e2e --timing` for full validation with cache timing. |
| `scripts/sip-call-test.py` | SIP INVITE test tool. Modes: `--test sign`, `--test verify`, `--test chain`. Timing: `--timing --timing-count N --timing-threshold X`. |
| `scripts/bootstrap-issuer.py` | Re-provision issuer after LMDB/Postgres wipe. Creates mock vLEI, org, API key, TN allocations, TN mappings. Stdlib-only (runs on PBX). |
| `scripts/test_sip_call_test.py` | 21 CLI regression tests for sip-call-test.py. Run via `python3 -m pytest scripts/test_sip_call_test.py`. |

### Issuer Recovery (LMDB/Postgres Wipe)

After an LMDB corruption or database reset:
```bash
# Re-provision the complete credential chain
python3 scripts/bootstrap-issuer.py --url https://vvp-issuer.rcnx.io --admin-key <key>
```
This creates: mock GLEIF/QVI infrastructure → test org → org API key → TN allocation credentials → TN mappings.
