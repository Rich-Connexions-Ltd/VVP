# VVP Deployment Reference

## CI/CD Pipeline

### GitHub Actions (`deploy.yml`)
**Repo**: `Rich-Connexions-Ltd/VVP`
**Trigger**: Push to `main` branch, or `workflow_dispatch`
**Target**: Azure Container Apps (UK South region)

**Workflow dispatch inputs:**
- `force_all` (boolean) — Deploy ALL services regardless of changed paths
- `lock_wait_seconds` (string, default `120`) — Max seconds to poll for LMDB lock release
- `test_suite` (choice: `auto`/`all`/`issuer`/`e2e`, default `auto`) — Post-deployment integration test suite

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
| `deploy-keri-agent` | `services/keri-agent/**`, `keripy/**`, `common/**` | Azure Container Apps (LMDB single-revision, internal-only) |
| `deploy-issuer` | `services/issuer/**`, `common/**` | Azure Container Apps (no LMDB, fast ~30s deploy) |
| `deploy-sip-redirect` | `services/sip-redirect/**`, `common/**` | PBX VM via `az vm run-command` |
| `deploy-sip-verify` | `services/sip-verify/**`, `common/**` | PBX VM via `az vm run-command` |
| `build-witness-image` + `deploy-witnesses` | `services/witness/**` | Azure Container Apps (3 witnesses) |
| `deploy-pbx-config` | `services/pbx/config/**` | PBX VM FreeSWITCH dialplan |

**Deploy ordering**: When both keri-agent and issuer change (e.g., `common/**` change), keri-agent deploys first. The issuer's `deploy-issuer` job depends on `deploy-keri-agent` completing successfully. This ensures the KERI Agent is healthy before the issuer starts routing to it.

All path filters are bypassed when `force_all=true` is passed via workflow dispatch.

### KERI Agent LMDB Constraint (Sprint 68c)

The KERI Agent (not the issuer) uses LMDB (keripy) on a shared Azure Files volume. **Two KERI Agent revisions CANNOT run simultaneously** — the LMDB lock blocks the new revision's startup. CI/CD uses a 3-phase stop-before-deploy sequence with self-healing activation:

1. **Deactivate revisions** — with up to 3 retries per revision to handle transient Azure API failures. (We do NOT use `az containerapp update --min-replicas 0` because that creates a phantom intermediate revision as a side effect, which can leave the new revision `active=false`.)
2. **Poll until stopped** — checks both `runningState` and `replicas` count, with 120s timeout (configurable via `lock_wait_seconds` workflow input). **Fails hard** on timeout instead of proceeding.
3. **Lock release buffer** — 10s sleep after all revisions report stopped, to allow the Azure Files mount to release the LMDB file lock.

After the deploy step (`az containerapp update --min-replicas 1 --max-replicas 1`), two self-healing checks run:

- **Ensure new revision is active** — queries `latestRevisionName`, checks `active` state. If `active=false`, explicitly calls `az containerapp revision activate`. Fails the pipeline if activation cannot be achieved.
- **Verify KERI Agent health** — polls `/healthz` (readiness) for up to 7 minutes (LMDB/Habery initialization on Azure Files takes ~3 minutes). Fails if health check never succeeds.

KERI Agent downtime during redeploy is ~5-6 minutes (stop old revision ~60s + LMDB init ~3-4 min + verification). The issuer continues serving KERI-free routes (auth, users, schemas, dashboard) during this window; KERI-dependent routes return 503.

**Issuer probe contract** (Sprint 68c): Three-endpoint probe model:
- `GET /livez` — Always 200. Liveness probe. ACA should never kill the container due to dependency failures.
- `GET /healthz` — 200 if DB reachable, 503 if DB unreachable. ACA readiness probe removes replica from rotation when DB is down.
- `GET /readyz` — 200 only when DB AND KERI Agent are both up. Used by CI/CD deploy gates and monitoring.

The issuer intentionally stays in ACA rotation (`/healthz` returns 200) when only the KERI Agent is down, since KERI-free routes (auth, users, schemas, dashboard, UI) remain available. KERI-dependent routes return 503 via the circuit breaker in `KeriAgentClient`.

**Issuer deploys** (when only issuer code changes) are fast (~30s) with no LMDB handling — standard blue-green deployment. Version check polls for 2 minutes.

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

# Full stack: witnesses + verifier + keri-agent + issuer
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
| KERI Agent | 8002 | HTTP (internal only) |
| Witness wan | 5642 | HTTP |
| Witness wil | 5643 | HTTP |
| Witness wes | 5644 | HTTP |

### Service URLs (Production)

| Service | URL |
|---------|-----|
| Verifier | `https://vvp-verifier.wittytree-2a937ccd.uksouth.azurecontainerapps.io` |
| KERI Agent | `vvp-keri-agent` (internal-only, port 8002) |
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

### Verifier (`services/verifier/app/core/config.py`)

#### Core
| Variable | Default | Purpose |
|----------|---------|---------|
| `VVP_TRUSTED_ROOT_AIDS` | GLEIF Root AID | Comma-separated trusted root identifiers |
| `VVP_LOCAL_WITNESS_URLS` | *(none)* | Comma-separated witness URLs for KEL resolution |
| `VVP_SIP_TIMING_TOLERANCE` | `30` | SIP contextual alignment timing tolerance (seconds) |
| `VVP_CONTEXT_REQUIRED` | `false` | Require CallContext in verify requests |
| `ADMIN_ENDPOINT_ENABLED` | `true` | Enable `/admin/*` endpoints |
| `SCHEMA_VALIDATION_STRICT` | `true` | Strict schema validation mode |
| `TIER2_KEL_RESOLUTION_ENABLED` | `true` | Enable Tier 2 KEL resolution |

#### Callee Verification
| Variable | Default | Purpose |
|----------|---------|---------|
| `VVP_CALLEE_TN_RIGHTS_REQUIRED` | true | Require TN rights check on callee |
| `VVP_ACCEPTED_GOALS` | *(all)* | Allowed goal types |
| `VVP_REJECT_UNKNOWN_GOALS` | false | Reject unrecognized goals |
| `VVP_GEO_CONSTRAINTS_ENFORCED` | `true` | Enforce geographic constraints |

#### Caching
| Variable | Default | Purpose |
|----------|---------|---------|
| `VVP_DOSSIER_CACHE_TTL` | `300` | Dossier cache TTL (seconds) |
| `VVP_DOSSIER_CACHE_MAX_ENTRIES` | `100` | Max dossier cache entries |
| `VVP_IDENTITY_CACHE_TTL` | `300` | Identity cache TTL |
| `VVP_SCHEMA_CACHE_TTL` | `300` | Schema cache TTL |
| `VVP_VERIFICATION_CACHE_ENABLED` | `true` | Enable verification result cache |
| `VVP_VERIFICATION_CACHE_TTL` | `3600` | Verification cache TTL |
| `VVP_VERIFICATION_CACHE_MAX_ENTRIES` | `200` | Max verification cache entries |

#### Schema Resolution
| Variable | Default | Purpose |
|----------|---------|---------|
| `VVP_SCHEMA_RESOLVER_ENABLED` | `true` | Enable remote schema resolution |
| `VVP_SCHEMA_RESOLVER_CACHE_TTL` | `3600` | Schema resolver cache TTL |
| `VVP_SCHEMA_RESOLVER_CACHE_MAX_ENTRIES` | `200` | Max resolver cache entries |
| `VVP_SCHEMA_RESOLVER_TIMEOUT` | `5` | Resolver HTTP timeout |
| `VVP_SCHEMA_REGISTRY_URLS` | GLEIF + Provenant + GitHub | Schema registry base URLs |
| `VVP_SCHEMA_OOBI_RESOLUTION` | `false` | Enable OOBI-based schema resolution |

#### KERI/vLEI Chain Resolution
| Variable | Default | Purpose |
|----------|---------|---------|
| `VVP_VLEI_CHAIN_RESOLUTION` | `true` | Enable vLEI chain resolution |
| `VVP_VLEI_CHAIN_MAX_DEPTH` | `3` | Max chain resolution depth |
| `VVP_VLEI_CHAIN_MAX_CONCURRENT` | `5` | Max concurrent chain fetches |
| `VVP_VLEI_CHAIN_MAX_TOTAL_FETCHES` | `10` | Max total chain fetches |
| `VVP_VLEI_CHAIN_TIMEOUT` | `10` | Chain resolution timeout |
| `VVP_ALLOW_AGGREGATE_DOSSIERS` | `false` | Allow multi-root dossiers |
| `VVP_DEFAULT_EVD_URL_PATTERN` | Provenant demo URL | Default evidence URL pattern |

#### External SAID Resolution
| Variable | Default | Purpose |
|----------|---------|---------|
| `VVP_EXTERNAL_SAID_RESOLUTION` | `true` | Enable external SAID lookups |
| `VVP_EXTERNAL_SAID_TIMEOUT` | `5` | External SAID HTTP timeout |
| `VVP_EXTERNAL_SAID_MAX_DEPTH` | `3` | Max external SAID depth |
| `VVP_EXTERNAL_SAID_CACHE_TTL` | `300` | External SAID cache TTL |
| `VVP_EXTERNAL_SAID_CACHE_MAX_ENTRIES` | `500` | Max external SAID cache entries |

#### Identity Discovery
| Variable | Default | Purpose |
|----------|---------|---------|
| `VVP_IDENTITY_DISCOVERY_ENABLED` | `false` | Enable OOBI-based identity discovery |
| `VVP_IDENTITY_DISCOVERY_TIMEOUT` | `3` | Discovery timeout |

#### GLEIF Witness
| Variable | Default | Purpose |
|----------|---------|---------|
| `VVP_GLEIF_WITNESS_OOBI` | GLEIF Root OOBI URL | GLEIF witness OOBI URL |
| `VVP_GLEIF_WITNESS_DISCOVERY` | `true` | Auto-discover GLEIF witnesses |
| `VVP_GLEIF_WITNESS_CACHE_TTL` | `300` | GLEIF witness cache TTL |
| `VVP_TEL_CLIENT_TIMEOUT` | `10` | TEL client timeout |

#### Vetter Constraints
| Variable | Default | Purpose |
|----------|---------|---------|
| `VVP_ENFORCE_VETTER_CONSTRAINTS` | false | Enforce ECC/jurisdiction constraints |
| `VVP_OPERATOR_VIOLATION_SEVERITY` | INDETERMINATE | Severity for vetter violations |

#### Revocation
| Variable | Default | Purpose |
|----------|---------|---------|
| `VVP_REVOCATION_RECHECK_INTERVAL` | `300` | Interval between revocation re-checks |
| `VVP_REVOCATION_CHECK_CONCURRENCY` | `1` | Max concurrent revocation checks |

### Issuer (`services/issuer/app/config.py`)

#### Core
| Variable | Default | Purpose |
|----------|---------|---------|
| `VVP_ISSUER_BASE_URL` | `http://localhost:8001` | Public base URL for dossier/OOBI URLs |
| `VVP_ISSUER_DATA_DIR` | auto-detect | Local data directory for SQLite/config (priority: env → /data/vvp-issuer → ~/.vvp-issuer → /tmp). LMDB is managed by KERI Agent, not the issuer. |
| `VVP_ISSUER_PORT` | `8001` | HTTP listen port |
| `VVP_DATABASE_URL` | `sqlite:///{DATA_DIR}/vvp_issuer.db` | Database connection string |
| `VVP_POSTGRES_HOST` | *(none)* | PostgreSQL host (overrides DATABASE_URL) |
| `VVP_POSTGRES_USER` | `vvpadmin` | PostgreSQL username |
| `VVP_POSTGRES_PASSWORD` | *(none)* | PostgreSQL password |
| `VVP_POSTGRES_DB` | `vvpissuer` | PostgreSQL database name |
| `ADMIN_ENDPOINT_ENABLED` | `true` | Enable `/admin/*` endpoints |
| `VVP_DASHBOARD_SERVICES` | local defaults | JSON dashboard service config |

#### KERI/Witness
| Variable | Default | Purpose |
|----------|---------|---------|
| `VVP_WITNESS_CONFIG` | `config/witnesses.json` | Witness pool config file |
| `VVP_WITNESS_TIMEOUT` | 10 | Witness HTTP timeout |
| `VVP_WITNESS_THRESHOLD` | 2 | Min witnesses for receipt threshold |
| `VVP_DEFAULT_KEY_COUNT` | 1 | Default signing keys for new identities |
| `VVP_DEFAULT_KEY_THRESHOLD` | `"1"` | Default signing threshold |
| `VVP_DEFAULT_NEXT_KEY_COUNT` | 1 | Default pre-rotated next keys |
| `VVP_DEFAULT_NEXT_THRESHOLD` | `"1"` | Default next key threshold |
| `VVP_MOCK_VLEI_ENABLED` | true | Enable mock GLEIF/QVI infrastructure |
| `VVP_MOCK_GLEIF_NAME` | `mock-gleif` | Mock GLEIF identity name |
| `VVP_MOCK_QVI_NAME` | `mock-qvi` | Mock QVI identity name |
| `VVP_MOCK_GSMA_NAME` | `mock-gsma` | Mock GSMA identity name |

#### Authentication
| Variable | Default | Purpose |
|----------|---------|---------|
| `VVP_AUTH_ENABLED` | true | Enable API key authentication |
| `VVP_UI_AUTH_ENABLED` | false | Enable UI authentication (separate from API) |
| `VVP_DOCS_AUTH_EXEMPT` | false | Exempt /docs and /redoc from auth |
| `VVP_AUTH_RELOAD_ENABLED` | `true` | Enable periodic auth config reload |
| `VVP_AUTH_RELOAD_INTERVAL` | `60` | Auth reload interval (seconds) |
| `VVP_API_KEYS_FILE` | `config/api_keys.json` | Path to API keys JSON file |
| `VVP_API_KEYS` | *(none)* | Inline API keys JSON |
| `VVP_USERS_FILE` | `config/users.json` | Path to users JSON file |
| `VVP_USERS` | *(none)* | Inline users JSON |

#### Sessions
| Variable | Default | Purpose |
|----------|---------|---------|
| `VVP_SESSION_TTL` | 3600 | Session timeout (seconds) |
| `VVP_SESSION_SECURE` | `true` | Secure cookie flag |
| `VVP_SESSION_CLEANUP_INTERVAL` | 300 | Session cleanup interval |
| `VVP_LOGIN_RATE_LIMIT_MAX` | 5 | Max login attempts per window |
| `VVP_LOGIN_RATE_LIMIT_WINDOW` | `900` | Login rate limit window (seconds) |

#### OAuth (Microsoft 365)
| Variable | Default | Purpose |
|----------|---------|---------|
| `VVP_OAUTH_M365_ENABLED` | false | Enable M365 SSO |
| `VVP_OAUTH_M365_TENANT_ID` | *(none)* | Azure AD tenant ID |
| `VVP_OAUTH_M365_CLIENT_ID` | *(none)* | OAuth client ID |
| `VVP_OAUTH_M365_CLIENT_SECRET` | *(none)* | OAuth client secret |
| `VVP_OAUTH_M365_REDIRECT_URI` | *(none)* | OAuth redirect URI |
| `VVP_OAUTH_M365_AUTO_PROVISION` | false | Auto-create users on first OAuth login |
| `VVP_OAUTH_M365_ALLOWED_DOMAINS` | *(all)* | Restrict OAuth to specific email domains |
| `VVP_OAUTH_M365_DEFAULT_ROLES` | `issuer:readonly` | Default roles for auto-provisioned users |
| `VVP_OAUTH_STATE_TTL` | `600` | OAuth state parameter TTL |

#### Dashboard
| Variable | Default | Purpose |
|----------|---------|---------|
| `VVP_DASHBOARD_REQUEST_TIMEOUT` | 5 | Dashboard health check timeout |
| `VVP_DASHBOARD_SIP_REDIRECT_URL` | *(none)* | SIP redirect service URL |
| `VVP_DASHBOARD_SIP_REDIRECT_HEALTH` | `/healthz` | SIP redirect health path |
| `VVP_DASHBOARD_SIP_VERIFY_URL` | *(none)* | SIP verify service URL |
| `VVP_DASHBOARD_SIP_VERIFY_HEALTH` | `/healthz` | SIP verify health path |
| `VVP_DASHBOARD_SIP_MONITOR_URL` | *(none)* | SIP monitor URL |

#### Vetter Constraints
| Variable | Default | Purpose |
|----------|---------|---------|
| `VVP_ENFORCE_VETTER_CONSTRAINTS` | false | Enforce vetter constraints on issuance |
| `AZURE_SUBSCRIPTION_ID` | *(none)* | Azure subscription for config management |
| `AZURE_RESOURCE_GROUP` | *(none)* | Azure resource group |

### SIP Services

| Variable | Default | Purpose |
|----------|---------|---------|
| `VVP_ISSUER_URL` | `http://localhost:8001` | Issuer API endpoint |
| `VVP_VERIFIER_URL` | `http://localhost:8000` | Verifier API endpoint |
| `VVP_SIP_LISTEN_PORT` | 5060 | SIP UDP listen port (PBX overrides to 5070) |
| `VVP_SIP_VERIFY_PORT` | 5071 | SIP verify listen port |
| `VVP_REDIRECT_TARGET` | *(none)* | SIP redirect target |
| `VVP_MONITOR_ENABLED` | false | Enable SIP monitoring dashboard |
| `VVP_TEST_MODE` | false | Enable test mode |
| `VVP_TEST_API_KEY` | *(none)* | Test API key for E2E |
| `VVP_AZURE_STORAGE_CONNECTION_STRING` | *(none)* | Azure blob storage for PBX deploys |
| `GIT_SHA` | unknown | Version tracking (injected by CI/CD) |

### Witnesses (Docker)

| Variable | Default | Purpose |
|----------|---------|---------|
| `WITNESS_NAME` | *(set per container)* | Witness identity name |
| `HTTP_PORT` | *(set per container)* | Witness HTTP port |
| `TCP_PORT` | *(set per container)* | Witness TCP port |
| `KERI_DB_PATH` | `/data/keri` | KERI database path |
| `LOG_LEVEL` | `info` | Witness log level |

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
| `scripts/bootstrap-issuer.py` | Re-provision issuer after Postgres/KERI Agent wipe. Creates mock vLEI, org, API key, TN allocations, TN mappings. Stdlib-only (runs on PBX). |
| `scripts/test_sip_call_test.py` | 21 CLI regression tests for sip-call-test.py. Run via `python3 -m pytest scripts/test_sip_call_test.py`. |

### Issuer Recovery (Postgres/KERI Agent Wipe)

After a KERI Agent LMDB corruption or issuer database reset:
```bash
# Re-provision the complete credential chain
python3 scripts/bootstrap-issuer.py --url https://vvp-issuer.rcnx.io --admin-key <key>
```
This creates: mock GLEIF/QVI infrastructure → test org → org API key → TN allocation credentials → TN mappings.
