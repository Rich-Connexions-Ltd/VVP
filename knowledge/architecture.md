# VVP System Architecture

## System Abstract

The VVP (Verifiable Voice Protocol) system enables cryptographically verifiable proof-of-rights for VoIP calls. It extends STIR/SHAKEN by replacing X.509 certificate chains with KERI-based decentralized identifiers and ACDC credentials.

The system consists of three services plus shared infrastructure:

```
┌─────────────┐     ┌──────────────┐     ┌─────────────────┐
│ SIP Redirect │────▶│   Issuer     │     │    Verifier      │
│ (signs calls)│     │ (credentials)│     │ (validates calls) │
└──────┬──────┘     └──────┬───────┘     └────────┬────────┘
       │                   │                      │
       │            ┌──────┴───────┐              │
       └───────────▶│   Common     │◀─────────────┘
                    │ (shared code) │
                    └──────┬───────┘
                           │
                    ┌──────┴───────┐
                    │ KERI Witnesses│
                    │ (3-node pool) │
                    └──────────────┘
```

---

## Service Architecture

### 1. Verifier Service (`services/verifier/`)

**Purpose**: Validates VVP claims in VoIP calls. Takes PASSporT JWT + VVP-Identity header → produces a hierarchical Claim Tree.

**Stack**: Python 3.12+, FastAPI, Ed25519 (PyNaCl/libsodium)

**Key Directories**:
| Directory | Purpose |
|-----------|---------|
| `app/main.py` | FastAPI app, routes, middleware |
| `app/core/config.py` | Configuration constants |
| `app/vvp/verify.py` | Orchestrator - main verification pipeline |
| `app/vvp/header.py` | VVP-Identity header parsing |
| `app/vvp/passport.py` | PASSporT JWT parsing |
| `app/vvp/keri/` | KERI integration (CESR, KEL resolver, TEL client) |
| `app/vvp/acdc/` | ACDC credential handling (models, verifier, schema) |
| `app/vvp/dossier/` | Dossier handling (parser, validator, cache) |
| `app/vvp/authorization.py` | Authorization chain validation (TNAlloc, delegation) |
| `app/vvp/api_models.py` | Request/Response Pydantic models |
| `app/vvp/exceptions.py` | Domain exceptions |
| `web/` | Static UI for JWT parsing and verification testing |
| `tests/` | Test suite |

**Deployed at**: `https://vvp-verifier.wittytree-2a937ccd.uksouth.azurecontainerapps.io`

### 2. Issuer Service (`services/issuer/`)

**Purpose**: Manages organizations, KERI identities, credential issuance, dossier building, and TN mappings. Provides the signing infrastructure for VVP calls.

**Stack**: Python 3.12+, FastAPI, SQLAlchemy (SQLite), KERI (keripy)

**Key Directories**:
| Directory | Purpose |
|-----------|---------|
| `app/main.py` | FastAPI app with all routers |
| `app/api/` | API routers (health, identity, registry, credential, dossier, auth, organization, tn_mapping, schema, admin, vvp) |
| `app/keri/` | KERI integration (identity management, witness interaction) |
| `app/auth/` | Authentication (API keys, sessions, OAuth M365, RBAC) |
| `app/db/` | Database models and session management |
| `app/audit/` | Audit logging |
| `app/config.py` | Configuration |
| `web/` | Multi-page web UI (create, registry, schemas, login, organizations, credentials, dossiers, tn-mappings, admin) |
| `config/witnesses.json` | Witness pool configuration |
| `tests/` | Test suite |

**Deployed at**: `https://vvp-issuer.rcnx.io`

### 3. SIP Redirect Service (`services/sip-redirect/`)

**Purpose**: SIP proxy that intercepts outbound calls, looks up TN mappings from the Issuer, signs calls with VVP headers, and returns a 302 redirect.

**Stack**: Python 3.11+, asyncio UDP, SIP protocol

**Key Directories**:
| Directory | Purpose |
|-----------|---------|
| `app/main.py` | Entry point, SIP UDP server |
| `app/sip/parser.py` | SIP message parsing (RFC 3261) |
| `app/sip/builder.py` | SIP response construction |
| `app/sip/handler.py` | INVITE handling, TN lookup, VVP signing |
| `app/issuer_client.py` | HTTP client for Issuer API |
| `app/config.py` | Configuration |

**Runs on**: PBX server (`pbx.rcnx.io`), port 5060 UDP

### 4. Common Library (`common/`)

**Purpose**: Shared code installed as a package (`pip install -e common/`). Used by all services.

**Key Modules**:
| Module | Purpose |
|--------|---------|
| `vvp/core/` | Logging, exceptions |
| `vvp/models/` | ACDC and dossier data models |
| `vvp/canonical/` | KERI canonical serialization, CESR encoding, SAID computation |
| `vvp/schema/` | Schema registry, store, validator |
| `vvp/sip/models.py` | Shared SIP data models |
| `vvp/utils/tn_utils.py` | Telephone number utilities |

---

## Data Flow

### Verification Flow (Verifier)
```
SIP INVITE with VVP headers
  → API POST /verify
    → Phase 2: Parse VVP-Identity header (base64url JSON)
    → Phase 3: Parse PASSporT JWT, bind to VVP-Identity
    → Phase 4: Verify PASSporT signature (resolve KEL via OOBI)
    → Phase 5: Fetch dossier from evd URL, parse CESR/JSON
    → Phase 6: Build DAG, validate structure (cycles, single root)
    → Phase 7-8: Verify ACDC signatures, check SAIDs
    → Phase 9: Check revocation status via TEL
    → Phase 10: Validate credential chain (walk to trusted root)
    → Phase 11: Check authorization (TN rights, delegation)
  → Return Claim Tree (VALID | INVALID | INDETERMINATE)
```

### Call Signing Flow (SIP Redirect → Issuer)
```
PBX dials 7XXXX (VVP prefix)
  → SIP INVITE to SIP Redirect (port 5060)
    → Extract caller TN from From header
    → POST /api/vvp/create to Issuer API (with API key)
      → Issuer looks up TN mapping
      → Issuer builds PASSporT JWT (Ed25519 signed)
      → Issuer returns VVP-Identity + Identity headers
    → SIP 302 Redirect with VVP headers
  → PBX follows redirect to destination with VVP attestation
```

---

## Infrastructure

### KERI Witness Pool
Three witnesses run in Docker (or on PBX):
| Witness | HTTP Port | Purpose |
|---------|-----------|---------|
| wan | 5642 | Primary witness |
| wil | 5643 | Secondary witness |
| wes | 5644 | Tertiary witness |

### Deployment
- **CI/CD**: Push to `main` → GitHub Actions → Azure Container Apps
- **Verifier**: Azure Container Apps (UK South)
- **Issuer**: Azure Container Apps (UK South)
- **SIP Redirect**: Deployed on PBX VM (`pbx.rcnx.io`) via Azure CLI
- **PBX**: Azure VM running FusionPBX/FreeSWITCH on Debian

### Docker Compose Profiles
| Profile | Services |
|---------|----------|
| (default) | 3 witnesses |
| `full` | witnesses + verifier + issuer |

---

## Layered Architecture (per service)

```
Layer 1: Interface     → HTTP routes, middleware, request/response models
Layer 2: Orchestration → Pipeline coordination, phase management
Layer 3: Domain Logic  → Business rules, credential verification, authorization
Layer 4: Infrastructure → KERI resolution, HTTP clients, database, caching
Layer 5: External      → Witnesses, CDN, web endpoints
```

Each layer only depends on layers below it. Domain logic never calls HTTP directly.
