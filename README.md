# VVP — Verifiable Voice Protocol

![Status](https://img.shields.io/badge/status-active-success.svg) ![Python](https://img.shields.io/badge/python-3.12%2B-blue.svg)

The **Verifiable Voice Protocol (VVP)** system enables cryptographically verifiable proof-of-rights for VoIP calls. It extends STIR/SHAKEN by replacing X.509 certificate chains with [KERI](https://keri.one)-based decentralized identifiers and ACDC credentials, enabling independent verification of caller identity, brand, and telephone number authority.

The system consists of multiple services that work together: an **Issuer** for credential and identity management, a **Verifier** for call verification, **SIP Redirect** services for call signing and verification at the network level, a **PBX** test infrastructure, and shared **KERI Witnesses** for decentralized key event receipting.

## Key Concepts

| Concept | Description |
|---------|-------------|
| **VVP** | A protocol for conveying verifiable assertions alongside real-time voice communications |
| **KERI** | Decentralized key management using Key Event Logs (KELs) — no central PKI required |
| **ACDC** | Authentic Chained Data Containers — structured, verifiable credentials for expressing chained claims |
| **Dossier** | A DAG of ACDC credentials that provides backing evidence for a call |
| **PASSporT** | JWT token (RFC 8225) extended with VVP-specific fields for caller attestation |

> See the [Glossary](Documentation/GLOSSARY.md) for complete terminology definitions.

## Architecture

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

## Services

| Service | Source | Purpose | Production URL |
|---------|--------|---------|----------------|
| **Issuer** | `services/issuer/` | Organization, credential, and dossier management | `https://vvp-issuer.rcnx.io` |
| **Verifier** | `services/verifier/` | VVP-Identity and PASSporT verification | `https://vvp-verifier.rcnx.io` |
| **SIP Redirect (Signer)** | `services/sip-redirect/` | Adds VVP attestation to outbound SIP calls | `pbx.rcnx.io:5070` (UDP) |
| **SIP Verify** | `services/sip-verify/` | Verifies VVP attestation on inbound SIP calls | `pbx.rcnx.io:5071` (UDP) |
| **Witnesses** | `services/witness/` | KERI witness nodes for key event receipts | `vvp-witness{1,2,3}.rcnx.io` |
| **PBX** | `services/pbx/` | FusionPBX/FreeSWITCH test infrastructure | `pbx.rcnx.io` |
| **Common** | `common/` | Shared library (models, CESR, SAID, schemas) | — (installed as package) |

## Quick Start

### Prerequisites

- **Python 3.12+**
- **libsodium** (cryptographic operations)
- **Docker** (for local witness network)

### Installation

```bash
# Clone
git clone https://github.com/andrewbalercnx/vvp-verifier.git
cd vvp-verifier

# Create virtual environment
python3 -m venv .venv && source .venv/bin/activate

# Install common library
pip install -e common/

# Install services (pick what you need)
pip install -e services/verifier/
pip install -e services/issuer/
pip install -e 'common[cli]'          # VVP CLI tools

# Install libsodium (macOS)
brew install libsodium
```

### Running the Local Stack

```bash
# Start KERI witnesses only
docker compose up -d

# Start full stack (witnesses + verifier + issuer)
docker compose --profile full up -d
```

### Local Service URLs

| Service | URL |
|---------|-----|
| Issuer | http://localhost:8001 |
| Issuer UI | http://localhost:8001/create |
| Verifier | http://localhost:8000 |
| Witness (wan) | http://localhost:5642 |
| Witness (wil) | http://localhost:5643 |
| Witness (wes) | http://localhost:5644 |

### Running a Service Directly

```bash
# Verifier
cd services/verifier && uvicorn app.main:app --reload --port 8000

# Issuer
cd services/issuer && uvicorn app.main:app --reload --port 8001
```

## CLI Tools

The VVP CLI provides commands for parsing and analyzing JWTs, ACDCs, CESR streams, dossiers, and KERI structures:

```bash
vvp jwt parse token.jwt              # Parse PASSporT JWT
vvp identity parse identity.txt      # Parse VVP-Identity header
vvp dossier fetch "$URL"             # Fetch and parse dossier
vvp acdc parse credential.json       # Parse ACDC credential
vvp cesr parse stream.cesr           # Parse CESR stream
vvp said compute - < data.json       # Compute SAID
vvp kel parse identifier.cesr        # Parse Key Event Log
vvp graph build - < dossier.json     # Build credential graph
```

> Full reference: [CLI Usage Guide](Documentation/CLI_USAGE.md)

## Operational Scripts

| Script | Purpose |
|--------|---------|
| `scripts/system-health-check.sh` | Check health of all VVP services (Azure + PBX) |
| `scripts/sip-call-test.py` | Test SIP signing and verification flows |
| `scripts/bootstrap-issuer.py` | Provision issuer with test org, credentials, and TN mappings |
| `scripts/run-integration-tests.sh` | Run integration tests against deployed services |

```bash
# Health check all production services
./scripts/system-health-check.sh

# Health check with E2E verification test
./scripts/system-health-check.sh --e2e

# Test SIP signing flow
python3 scripts/sip-call-test.py --test sign --host pbx.rcnx.io --port 5070

# Bootstrap issuer with test data
python3 scripts/bootstrap-issuer.py --url https://vvp-issuer.rcnx.io
```

## Testing

Each service has its own test suite. Use the provided scripts to handle library paths:

```bash
# From repo root — run verifier tests
./scripts/run-tests.sh

# Run specific service tests
cd services/verifier && ./scripts/run-tests.sh -v
cd services/issuer && ./scripts/run-tests.sh -v

# Run with coverage
./scripts/run-tests.sh --cov=app --cov-report=term-missing

# Run integration tests against Azure
./scripts/run-integration-tests.sh
```

## Deployment

The system deploys to **Azure UK South** via GitHub Actions CI/CD:

- **Container Apps**: Verifier, Issuer, 3 Witnesses (push to `main` triggers deploy)
- **PBX VM**: SIP Redirect, SIP Verify, PBX config (automated with atomic deploy + rollback)

```bash
# Verify deployment health
curl -s https://vvp-verifier.rcnx.io/healthz | jq .
curl -s https://vvp-issuer.rcnx.io/healthz | jq .
```

> Full details: [Deployment Architecture](Documentation/DEPLOYMENT.md) | [CI/CD Pipeline](Documentation/CICD.md)

## Project Structure

```
VVP/
├── common/                     # Shared library (pip install -e common/)
│   └── vvp/
│       ├── core/               # Logging, exceptions
│       ├── models/             # ACDC, dossier data models
│       ├── canonical/          # KERI/CESR serialization, SAID
│       ├── schema/             # Schema registry, validation
│       ├── sip/                # Shared SIP models
│       └── utils/              # TN normalization utilities
├── services/
│   ├── verifier/               # VVP Verifier service
│   │   ├── app/                # FastAPI application
│   │   ├── tests/              # Test suite (1800+ tests)
│   │   └── web/                # Verification UI
│   ├── issuer/                 # VVP Issuer service
│   │   ├── app/                # FastAPI application
│   │   ├── tests/              # Test suite (420+ tests)
│   │   └── web/                # Multi-page management UI
│   ├── sip-redirect/           # SIP signing service
│   │   ├── app/                # Async UDP SIP server
│   │   └── tests/              # Test suite with fixtures
│   ├── sip-verify/             # SIP verification service
│   │   ├── app/                # Async UDP SIP server
│   │   └── tests/              # Test suite
│   ├── witness/                # KERI witness Docker config
│   └── pbx/                    # PBX config, dialplan, WebRTC
│       ├── config/             # FreeSWITCH dialplan
│       └── webrtc/             # VVP Phone WebRTC client
├── scripts/                    # Operational and dev scripts
├── knowledge/                  # Deep reference documentation
├── Documentation/              # Specs, guides, archived plans
├── keripy/                     # Vendored KERI library
├── docker-compose.yml          # Local dev stack
├── pyproject.toml              # Workspace definition
└── SPRINTS.md                  # Sprint roadmap
```

## Documentation

### Operator Guides

| Document | Description |
|----------|-------------|
| [E2E Test Walkthrough](E2E_TEST.md) | Step-by-step end-to-end testing guide |
| [CLI Tools Guide](Documentation/CLI_USAGE.md) | VVP command-line tools reference |
| [User Manual Requirements](PLAN_Sprint55.md) | Requirements for comprehensive system operator manual (planned) |

### Infrastructure & Deployment

| Document | Description |
|----------|-------------|
| [Deployment Architecture](Documentation/DEPLOYMENT.md) | Service inventory, DNS, Azure, PBX management |
| [CI/CD Pipeline](Documentation/CICD.md) | GitHub Actions workflow documentation |
| [SIP Signing Service](Documentation/SIP_SIGNER.md) | SIP redirect signing admin guide |
| [SIP Verification Service](Documentation/SIP_VERIFIER.md) | SIP redirect verification admin guide |

### Protocol & Design

| Document | Description |
|----------|-------------|
| [VVP Specification v1.5](Documentation/VVP_Verifier_Specification_v1.5.md) | Normative VVP protocol specification |
| [VVP Documentation](Documentation/VVP_Verifier_Documentation.md) | Protocol background and architecture |
| [Glossary](Documentation/GLOSSARY.md) | VVP, KERI, ACDC terminology |
| [Creating Dossiers](Documentation/CREATING_DOSSIERS.md) | Guide to creating credentials and dossiers |

### Developer Reference

| Document | Description |
|----------|-------------|
| [Development Guide](Documentation/DEVELOPMENT.md) | Developer quickstart and testing |
| [Implementation Checklist](Documentation/VVP_Implementation_Checklist.md) | 182-item implementation tracker |
| [Sprint Roadmap](SPRINTS.md) | Full sprint history and roadmap |
