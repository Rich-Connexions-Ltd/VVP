# VVP CI/CD Pipeline Documentation

**Version:** 1.0
**Last Updated:** 2026-02-07
**Workflow Files:** `.github/workflows/deploy.yml`, `.github/workflows/integration-tests.yml`

---

## Overview

The VVP monorepo uses GitHub Actions for continuous integration and deployment. Two workflows automate the full lifecycle:

| Workflow | File | Trigger | Purpose |
|----------|------|---------|---------|
| **Build and Deploy** | `deploy.yml` | Push to `main`, manual | Test, build, and deploy all services |
| **Integration Tests** | `integration-tests.yml` | Nightly, manual, push to `tests/` | End-to-end integration testing |

All workflows authenticate to Azure using **OIDC workload identity federation** (no static credentials stored in GitHub).

---

## Pipeline Architecture

### Build and Deploy (`deploy.yml`)

```
Push to main
     │
     ▼
┌──────────────────┐
│  Detect Changes   │  paths-filter determines which services changed
└────────┬─────────┘
         │
    ┌────┴────┬──────────┬──────────────┬───────────────┐
    ▼         ▼          ▼              ▼               ▼
┌────────┐ ┌────────┐ ┌──────────┐ ┌──────────┐ ┌────────────┐
│  Test  │ │  Test  │ │   Test   │ │   Test   │ │  (no test  │
│Verifier│ │ Issuer │ │SIP Redir.│ │SIP Verify│ │  for PBX)  │
└───┬────┘ └───┬────┘ └────┬─────┘ └────┬─────┘ └─────┬──────┘
    │          │           │             │              │
    ▼          ▼           │             │              │
┌────────┐ ┌────────┐     │             │              │
│ Deploy │ │ Deploy │     │             │              │
│Verifier│ │ Issuer │     │             │              │
└───┬────┘ └───┬────┘     │             │              │
    │          │           ▼             │              │
    │          │    ┌──────────────┐     │              │
    │          │    │Deploy SIP    │     │              │
    │          │    │Redirect (VM) │     │              │
    │          │    └──────┬───────┘     │              │
    │          │           │             ▼              │
    │          │           │    ┌──────────────┐        │
    │          │           │    │Deploy SIP    │        │
    │          │           │    │Verify (VM)   │        │
    │          │           │    └──────┬───────┘        │
    │          │           │           │                ▼
    │          │           │           │     ┌────────────────┐
    │          │           │           │     │Deploy PBX      │
    │          │           │           │     │Config (VM)     │
    │          │           │           │     └────────────────┘
    ▼          ▼           │           │
┌─────────────────────┐    │           │
│Build Witness Image  │    │           │
└──────────┬──────────┘    │           │
           ▼               │           │
┌─────────────────────┐    │           │
│Deploy Witnesses (x3)│    │           │
└──────────┬──────────┘    │           │
           ▼               │           │
┌─────────────────────┐    │           │
│Verify Witnesses     │    │           │
└──────────┬──────────┘    │           │
           │               │           │
    ┌──────┴───────────────┘           │
    ▼                                  │
┌─────────────────────┐                │
│Post-Deploy Tests    │                │
│(Integration)        │                │
└─────────────────────┘
```

**Key design decisions:**

- **Path-based change detection** skips unnecessary builds (e.g., witness changes don't rebuild issuer)
- **PBX VM jobs run sequentially** to avoid Azure `az vm run-command` conflicts (only one run-command allowed per VM at a time)
- **Container App deploys run in parallel** since they target separate Azure resources
- **Post-deployment tests** only run when issuer or verifier changes

---

## Change Detection

The `changes` job uses [dorny/paths-filter](https://github.com/dorny/paths-filter) to determine which services were modified:

| Output | Trigger Paths | What Deploys |
|--------|--------------|--------------|
| `verifier` | `services/verifier/**`, `common/**` | Verifier Container App |
| `issuer` | `services/issuer/**`, `common/**` | Issuer Container App |
| `witness` | `services/witness/**` | All 3 witness Container Apps |
| `sip-redirect` | `services/sip-redirect/**`, `common/**` | SIP Signer on PBX VM |
| `sip-verify` | `services/sip-verify/**`, `common/**` | SIP Verifier on PBX VM |
| `pbx-config` | `services/pbx/config/**` | FreeSWITCH dialplan on PBX VM |

Changes to `common/` trigger rebuilds of verifier, issuer, sip-redirect, and sip-verify since they all depend on the shared package.

---

## Jobs Reference

### Test Jobs

All test jobs run on `ubuntu-latest` with Python 3.12 and libsodium.

| Job | Condition | Database | Coverage Threshold |
|-----|-----------|----------|--------------------|
| `test-verifier` | verifier changed | None | 79% |
| `test-issuer` | issuer changed | PostgreSQL 16 (service container) | 60% |
| `test-sip-redirect` | sip-redirect changed | None | None |
| `test-sip-verify` | sip-verify changed | None | None |

**Common test setup:**
1. Checkout code
2. Install Python 3.12 + libsodium
3. Install `common/` package (`pip install -e common/`)
4. Install service dependencies
5. Run `pytest` with coverage

The issuer test job starts a PostgreSQL 16 service container with health checks and connects via `VVP_DATABASE_URL`.

---

### Container App Deployments

Three services deploy to Azure Container Apps via the same pattern:

```
Build Docker image → Push to ACR → az containerapp update
```

#### deploy-verifier

| Property | Value |
|----------|-------|
| **Depends on** | `changes`, `test-verifier` |
| **Condition** | `verifier == 'true' && !failure()` |
| **Container App** | `vvp-verifier` |
| **Replicas** | min=1 |
| **Env vars set** | `GIT_SHA`, `GITHUB_REPOSITORY`, `VVP_LOCAL_WITNESS_URLS` |

#### deploy-issuer

| Property | Value |
|----------|-------|
| **Depends on** | `changes`, `test-issuer` |
| **Condition** | `issuer == 'true' && !failure()` |
| **Container App** | `vvp-issuer` |
| **Replicas** | min=1, max=3 |
| **Env vars set** | `GIT_SHA`, `GITHUB_REPOSITORY`, `VVP_WITNESS_CONFIG`, `VVP_POSTGRES_HOST`, `VVP_POSTGRES_USER`, `VVP_POSTGRES_PASSWORD`, `VVP_POSTGRES_DB` |

#### deploy-witnesses

Witnesses use a **two-phase deployment**:

1. **build-witness-image** — Builds and pushes a single Docker image to ACR
2. **deploy-witnesses** — Deploys to 3 Container Apps using a matrix strategy

| Witness | Container App | AID | HTTP Port | TCP Port |
|---------|---------------|-----|-----------|----------|
| wan | `vvp-witness1` | `BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha` | 5642 | 5632 |
| wil | `vvp-witness2` | `BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM` | 5643 | 5633 |
| wes | `vvp-witness3` | `BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX` | 5644 | 5634 |

After deployment, the **verify-witnesses** job checks each witness's OOBI endpoint responds with HTTP 200/202.

---

### PBX VM Deployments

Three jobs deploy to the Azure VM `vvp-pbx`. These jobs are **serialized** to prevent Azure `az vm run-command` conflicts:

```
deploy-sip-redirect → deploy-sip-verify → deploy-pbx-config
```

Each subsequent job lists the previous as a dependency with `!failure()`, so it runs even if the previous job was **skipped** (no changes), but blocks if it actually **failed**.

#### Deployment Strategy: Atomic Symlink Switch

Both SIP services use the same zero-downtime deployment pattern:

```
1. Package service as tar.gz
2. Upload to Azure Blob Storage
3. Generate short-lived SAS URL (5 min expiry)
4. Download on VM via SAS URL (no az CLI needed on VM)
5. Extract to versioned directory: /opt/vvp/{service}/releases/{SHA}
6. Atomic symlink switch:
     ln -sfn releases/{SHA} current.new
     mv -Tf current.new current
7. Cleanup old releases (keep last 3)
8. Restart systemd service
9. Verify health
```

**Automatic rollback** is built in: if any step fails, the `Rollback on failure` step activates the previous release via symlink and restarts the service.

#### deploy-sip-redirect

| Property | Value |
|----------|-------|
| **Depends on** | `changes`, `test-sip-redirect` |
| **Target** | VM `vvp-pbx`, port UDP 5070 |
| **Service unit** | `vvp-sip-redirect.service` |
| **Env file** | `/etc/vvp/sip-redirect.env` |
| **Install dir** | `/opt/vvp/sip-redirect/current/` |
| **Python** | `/opt/vvp/venv/bin/python3` (venv with aiohttp, bcrypt) |
| **Health check** | HTTP 200 on `http://pbx.rcnx.io:8080/status` (admin auth) |

#### deploy-sip-verify

| Property | Value |
|----------|-------|
| **Depends on** | `changes`, `test-sip-verify`, **`deploy-sip-redirect`** |
| **Target** | VM `vvp-pbx`, port UDP 5071 |
| **Service unit** | `vvp-sip-verify.service` |
| **Env file** | `/etc/vvp/sip-verify.env` |
| **Install dir** | `/opt/vvp/sip-verify/current/` |
| **Python** | `/usr/bin/python3` |
| **Health check** | `ss -ulnp | grep :5071` on VM |

#### deploy-pbx-config

| Property | Value |
|----------|-------|
| **Depends on** | `changes`, **`deploy-sip-redirect`**, **`deploy-sip-verify`** |
| **Target** | VM `vvp-pbx` |
| **What it deploys** | `services/pbx/config/public-sip.xml` → `/etc/freeswitch/dialplan/public.xml` |
| **Method** | Base64 encode, transfer via `az vm run-command`, decode on VM |
| **Post-deploy** | `fs_cli -x 'reloadxml'` |
| **Backup** | Timestamped copy to `/etc/freeswitch/dialplan/backup/` |

---

### Post-Deployment Tests

| Property | Value |
|----------|-------|
| **Depends on** | `changes`, `deploy-verifier`, `deploy-issuer` |
| **Condition** | Verifier or issuer changed, no failures |
| **Environment** | `VVP_TEST_MODE=azure` |
| **Targets** | `https://vvp-issuer.rcnx.io`, `https://vvp-verifier.rcnx.io` |
| **Test suite** | `tests/integration/` (excludes benchmarks) |
| **Results** | Submitted to `/admin/deployment-tests` endpoint |
| **Artifacts** | Test output + errors uploaded on failure (7 day retention) |

The test runner:
1. Waits up to 5 minutes for both services to be healthy
2. Runs integration tests with `pytest`
3. Parses pass/fail counts from output
4. POSTs results JSON to the issuer's admin endpoint for dashboard display

---

## Integration Tests Workflow (`integration-tests.yml`)

A separate workflow for comprehensive end-to-end testing:

| Trigger | Behavior |
|---------|----------|
| **Nightly (2 AM UTC)** | Runs local tests, then Azure tests |
| **Manual dispatch** | Choose `local` or `azure` mode |
| **Push to `tests/integration/`** | Runs local tests only |

### integration-local

- Starts full Docker Compose stack (witnesses + verifier + issuer)
- Waits for services to be healthy (up to 2.5 minutes)
- Runs tests with `VVP_TEST_MODE=local`
- Excludes Azure-specific tests (`-m "integration and not azure"`)
- Uploads JUnit XML results and benchmark output
- Collects Docker logs on failure
- 30 minute timeout

### integration-azure

- Only runs on schedule or manual `azure` mode
- Depends on `integration-local` passing first
- Authenticates to Azure via OIDC
- Runs full test suite against live Azure services
- Uses production API keys via GitHub secrets
- 45 minute timeout

---

## Authentication

### Azure OIDC (Workload Identity Federation)

All Azure operations use OIDC — no static credentials:

```yaml
- uses: azure/login@v2
  with:
    client-id: ${{ secrets.AZURE_CLIENT_ID }}
    tenant-id: ${{ secrets.AZURE_TENANT_ID }}
    subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
```

The GitHub Actions workflow requests an OIDC token, which Azure AD validates against the federated credential configuration. This requires:
- `id-token: write` permission on the workflow
- A federated credential configured on the Azure AD app registration for the GitHub repo

### Azure Container Registry

After OIDC login, ACR authentication uses the Azure CLI:

```yaml
- run: az acr login -n "${{ secrets.ACR_NAME }}"
```

---

## Secrets Reference

| Secret | Used By | Purpose |
|--------|---------|---------|
| `AZURE_CLIENT_ID` | All deploy jobs | OIDC authentication to Azure |
| `AZURE_TENANT_ID` | All deploy jobs | Azure AD tenant |
| `AZURE_SUBSCRIPTION_ID` | All deploy jobs | Azure subscription |
| `AZURE_RG` | All deploy jobs | Resource group name (`VVP`) |
| `ACR_NAME` | Container App deploys | Container Registry name |
| `ACR_LOGIN_SERVER` | Container App deploys | Registry login URL (e.g., `vvpacr.azurecr.io`) |
| `AZURE_CONTAINERAPP_NAME` | Verifier deploy | Verifier Container App name |
| `AZURE_STORAGE_ACCOUNT` | SIP service deploys | Storage account for deployment artifacts |
| `AZURE_STORAGE_CONNECTION_STRING` | Integration tests | Blob storage for dossier hosting |
| `VVP_ADMIN_API_KEY` | Post-deploy tests | Admin API key for test result submission |
| `VVP_SIP_STATUS_ADMIN_KEY` | SIP redirect deploy | Admin key for `/status` health check |
| `POSTGRES_HOST` | Issuer deploy | PostgreSQL server hostname |
| `POSTGRES_USER` | Issuer deploy | PostgreSQL username |
| `POSTGRES_PASSWORD` | Issuer deploy | PostgreSQL password |
| `POSTGRES_DB` | Issuer deploy | PostgreSQL database name |

---

## Deployment Targets Summary

| Service | Platform | Method | URL |
|---------|----------|--------|-----|
| **Verifier** | Azure Container App | Docker image → ACR → `az containerapp update` | `https://vvp-verifier.rcnx.io` |
| **Issuer** | Azure Container App | Docker image → ACR → `az containerapp update` | `https://vvp-issuer.rcnx.io` |
| **Witnesses (x3)** | Azure Container Apps | Docker image → ACR → matrix deploy | `https://vvp-witness{1,2,3}.rcnx.io` |
| **SIP Signer** | Azure VM (`vvp-pbx`) | tar.gz → Blob Storage → SAS URL → atomic symlink | `UDP pbx.rcnx.io:5070` |
| **SIP Verifier** | Azure VM (`vvp-pbx`) | tar.gz → Blob Storage → SAS URL → atomic symlink | `UDP pbx.rcnx.io:5071` |
| **PBX Config** | Azure VM (`vvp-pbx`) | Base64 file transfer → `fs_cli reloadxml` | N/A |

---

## Rollback Procedures

### Container Apps (Verifier, Issuer, Witnesses)

```bash
# List recent revisions
az containerapp revision list \
  --name vvp-issuer \
  --resource-group VVP \
  --query "[].{name:name, active:properties.active, created:properties.createdTime}" \
  -o table

# Activate a previous revision
az containerapp revision activate \
  --name vvp-issuer \
  --resource-group VVP \
  --revision <revision-name>

# Or redeploy a previous image
az containerapp update \
  --name vvp-issuer \
  --resource-group VVP \
  --image <acr-login-server>/vvp-issuer:<previous-sha>
```

### SIP Services (Automatic)

The CI/CD pipeline includes automatic rollback on failure. For manual rollback:

```bash
# List available releases
az vm run-command invoke --resource-group VVP --name vvp-pbx \
  --command-id RunShellScript \
  --scripts "ls -lt /opt/vvp/sip-redirect/releases/ | head -5"

# Switch to previous release
az vm run-command invoke --resource-group VVP --name vvp-pbx \
  --command-id RunShellScript \
  --scripts "
    PREV=\$(ls -t /opt/vvp/sip-redirect/releases | sed -n '2p')
    ln -sfn /opt/vvp/sip-redirect/releases/\$PREV /opt/vvp/sip-redirect/current
    systemctl restart vvp-sip-redirect
    echo 'Rolled back to: '\$PREV
  "
```

### PBX Configuration

```bash
# List backups
az vm run-command invoke --resource-group VVP --name vvp-pbx \
  --command-id RunShellScript \
  --scripts "ls -lt /etc/freeswitch/dialplan/backup/"

# Restore from backup
az vm run-command invoke --resource-group VVP --name vvp-pbx \
  --command-id RunShellScript \
  --scripts "
    LATEST=\$(ls -t /etc/freeswitch/dialplan/backup/ | head -1)
    cp /etc/freeswitch/dialplan/backup/\$LATEST /etc/freeswitch/dialplan/public.xml
    chown www-data:www-data /etc/freeswitch/dialplan/public.xml
    fs_cli -x 'reloadxml'
    echo 'Restored: '\$LATEST
  "
```

---

## Troubleshooting

### Azure VM Run-Command Conflicts

**Symptom:** `(Conflict) Run command extension execution is in progress`

**Cause:** Multiple `az vm run-command invoke` calls executing against the same VM simultaneously. Azure only allows one run-command per VM at a time.

**Fix:** PBX VM deployment jobs are serialized via dependency chain:
```
deploy-sip-redirect → deploy-sip-verify → deploy-pbx-config
```

Each job uses `!failure()` in its condition so it still runs when the previous job was skipped (no changes), but blocks on actual failures.

### Container App Not Starting

```bash
# Check recent logs
az containerapp logs show --name vvp-issuer --resource-group VVP --tail 50

# Check revision status
az containerapp revision list --name vvp-issuer --resource-group VVP \
  --query "[0].{status:properties.runningStatus, health:properties.healthState}" -o table

# Check if image exists in ACR
az acr repository show-tags --name <acr-name> --repository vvp-issuer --top 5 -o table
```

### SIP Service Not Listening

```bash
# Check service status
az vm run-command invoke --resource-group VVP --name vvp-pbx \
  --command-id RunShellScript \
  --scripts "systemctl status vvp-sip-redirect --no-pager"

# Check port binding
az vm run-command invoke --resource-group VVP --name vvp-pbx \
  --command-id RunShellScript \
  --scripts "ss -ulnp | grep -E ':(5070|5071)'"

# Check recent logs
az vm run-command invoke --resource-group VVP --name vvp-pbx \
  --command-id RunShellScript \
  --scripts "journalctl -u vvp-sip-redirect -n 50 --no-pager"

# Verify symlink points to valid release
az vm run-command invoke --resource-group VVP --name vvp-pbx \
  --command-id RunShellScript \
  --scripts "ls -la /opt/vvp/sip-redirect/current"
```

### Post-Deployment Test Failures

```bash
# Check the GitHub Actions run artifacts for test_output.txt and errors.txt

# Manually verify services are up
curl -sf https://vvp-issuer.rcnx.io/healthz && echo "Issuer OK"
curl -sf https://vvp-verifier.rcnx.io/healthz && echo "Verifier OK"

# Re-run integration tests manually
gh workflow run integration-tests.yml -f mode=azure
```

### Coverage Threshold Failures

If tests pass but coverage is below the threshold:

| Service | Threshold | Flag |
|---------|-----------|------|
| Verifier | 79% | `--cov-fail-under=79` |
| Issuer | 60% | `--cov-fail-under=60` |

Add tests to increase coverage, or (temporarily) lower the threshold in `deploy.yml`.

---

## Manual Operations

### Trigger Deployment Without Code Changes

```bash
# Manual workflow dispatch
gh workflow run deploy.yml

# Or re-run a specific failed run
gh run rerun <run-id>

# Re-run only failed jobs
gh run rerun <run-id> --failed
```

### Monitor a Running Deployment

```bash
# Watch the latest run
gh run watch

# Watch a specific run
gh run watch <run-id> --exit-status

# List recent runs
gh run list --limit 5
```

### Force Deploy a Specific Service

Since the pipeline uses path-based change detection, you can force a deploy by touching a file:

```bash
# Force issuer deploy
echo "# deploy $(date +%s)" >> services/issuer/pyproject.toml
git add services/issuer/pyproject.toml && git commit -m "Trigger issuer deploy" && git push

# Force all PBX deploys (careful: they run sequentially)
echo "# deploy $(date +%s)" >> services/sip-redirect/pyproject.toml
echo "# deploy $(date +%s)" >> services/sip-verify/pyproject.toml
git add -A && git commit -m "Trigger PBX service deploys" && git push
```

---

## Job Dependency Graph

Complete dependency map for all jobs:

```
changes ─┬─► test-verifier ──► deploy-verifier ─┬─► post-deployment-tests
         │                                       │
         ├─► test-issuer ───► deploy-issuer ─────┘
         │
         ├─► test-verifier ─┬─► build-witness-image ─► deploy-witnesses ─► verify-witnesses
         │   test-issuer ───┘
         │
         ├─► test-sip-redirect ─► deploy-sip-redirect ─► deploy-sip-verify
         │                                                       │
         ├─► test-sip-verify ───────────────────────────────────┘
         │                                                       │
         └───────────────────────────────────────────────► deploy-pbx-config
```

**Legend:**
- `─►` = dependency (right job waits for left)
- All deploy jobs use `!failure()` so they run when dependencies are skipped but not when they fail

---

## Related Documentation

| Document | Description |
|----------|-------------|
| [DEPLOYMENT.md](DEPLOYMENT.md) | System architecture, component inventory, infrastructure |
| [AZURE_DEPLOYMENT.md](AZURE_DEPLOYMENT.md) | Azure resource provisioning (one-time setup) |
| [AZURE_RESTORE.md](AZURE_RESTORE.md) | Disaster recovery procedures |
| [SIP_SIGNER.md](SIP_SIGNER.md) | SIP signing service configuration |
| [SIP_VERIFIER.md](SIP_VERIFIER.md) | SIP verification service configuration |

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-02-07 | Initial comprehensive CI/CD documentation |
