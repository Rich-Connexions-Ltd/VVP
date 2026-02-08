# VVP Deployment Reference

## CI/CD Pipeline

### GitHub Actions (`deploy.yml`)
**Trigger**: Push to `main` branch
**Target**: Azure Container Apps (UK South region)

### Deployment Flow
```
Push to main
  → GitHub Actions triggered
    → Build Docker image
    → Push to Azure Container Registry
    → Deploy to Azure Container Apps
    → Health check verification
```

### Verifying Deployment
```bash
# Verifier health check
curl https://vvp-verifier.wittytree-2a937ccd.uksouth.azurecontainerapps.io/healthz

# Monitor deployment
gh run watch
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
| `/etc/vvp-sip/config.env` | SIP redirect config |
| `/var/log/vvp-sip/audit-*.jsonl` | Audit logs |

### PBX Ports

| Service | Port | Protocol |
|---------|------|----------|
| FreeSWITCH Internal SIP | 5060 | UDP/TCP |
| FreeSWITCH External SIP | 5080 | UDP/TCP |
| FreeSWITCH WebSocket | 7443 | WSS |
| SIP Redirect | 5060 | UDP |
| SIP Redirect Status | 8080 | HTTP |

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
| `VVP_SIP_LISTEN_PORT` | 5060 | SIP UDP listen port |
| `VVP_RATE_LIMIT_RPS` | 10.0 | Requests per second |
| `VVP_RATE_LIMIT_BURST` | 50 | Burst size |
| `VVP_STATUS_ADMIN_KEY` | *(none)* | Admin key for /status |

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
