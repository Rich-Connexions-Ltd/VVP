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
| `app/vvp/vetter/` | Vetter constraint validation (constraints, certification, traversal) |
| `app/vvp/api_models.py` | Request/Response Pydantic models |
| `app/vvp/exceptions.py` | Domain exceptions |
| `web/` | Static UI for verification, JWT parsing, SIP explore, admin |
| `tests/` | Test suite |

**Deployed at**: `https://vvp-verifier.wittytree-2a937ccd.uksouth.azurecontainerapps.io`

### 2. Issuer Service (`services/issuer/`)

**Purpose**: Manages organizations, KERI identities, credential issuance, dossier building, and TN mappings. Provides the signing infrastructure for VVP calls.

**Stack**: Python 3.12+, FastAPI, SQLAlchemy (SQLite), KERI (keripy)

**Key Directories**:
| Directory | Purpose |
|-----------|---------|
| `app/main.py` | FastAPI app with all routers |
| `app/api/` | API routers (health, identity, registry, credential, dossier, auth, organization, tn_mapping, schema, admin, vvp, vetter_certification, session) |
| `app/vetter/` | Vetter certification business logic and constants (Sprint 61) |
| `app/keri/` | KERI integration (identity management, witness interaction) |
| `app/auth/` | Authentication (API keys, sessions, OAuth M365, RBAC) |
| `app/db/` | Database models and session management |
| `app/audit/` | Audit logging |
| `app/config.py` | Configuration |
| `web/` | Multi-page web UI (20 pages: identity, registry, schemas, credentials, dossier, vvp, dashboard, admin, vetter, tn-mappings, benchmarks, help, walkthrough, organizations, organization-detail, users, profile, login, 404) |
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

**Runs on**: PBX server (`pbx.rcnx.io`), port 5070 UDP

### 3b. SIP Verify Service (`services/sip-verify/`)

**Purpose**: SIP proxy that receives redirected calls, verifies VVP headers via the Verifier API, and adds brand/vetter status headers before delivery.

**Runs on**: PBX server (`pbx.rcnx.io`), port 5071 UDP (or OSS verifier at port 5072)

### 4. Common Library (`common/`)

**Purpose**: Shared code installed as a package (`pip install -e common/`). Used by all services.

**Key Modules**:
| Module | Purpose |
|--------|---------|
| `vvp/core/` | Logging, exceptions |
| `vvp/models/` | ACDC and dossier data models |
| `vvp/canonical/` | KERI canonical serialization, CESR encoding, SAID computation |
| `vvp/schema/` | Schema registry, store, validator |
| `vvp/sip/models.py` | Shared SIP data models (SIPRequest, SIPResponse) |
| `vvp/sip/builder.py` | SIP response builders (302, 400, 401, 403, 404, 500) |
| `vvp/sip/parser.py` | SIP message parser |
| `vvp/sip/transport.py` | SIP UDP transport |
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
    → Phase 11b: Vetter constraint evaluation (ECC, jurisdiction)
  → Return Claim Tree (VALID | INVALID | INDETERMINATE)
```

### Call Signing Flow (SIP Redirect → Issuer)
```
PBX dials 7XXXX (VVP prefix)
  → SIP INVITE to SIP Redirect (port 5070)
    → Extract caller TN from From header
    → POST /vvp/create to Issuer API (with API key)
      → Issuer looks up TN mapping
      → Issuer builds PASSporT JWT (Ed25519 signed)
      → Issuer returns VVP-Identity + Identity headers
    → SIP 302 Redirect with VVP headers
  → PBX follows redirect to SIP Verify (port 5071)
    → Verify VVP headers via Verifier API
    → Add brand/vetter status headers
    → Deliver to destination extension
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

### Mock Trust Infrastructure (Issuer)

The issuer bootstraps two parallel mock trust chains on startup:

**QVI Chain** (existing): Mock GLEIF root -> Mock QVI -> LE credentials for orgs
- State stored in `MockVLEIState.gleif_aid`, `qvi_aid`, `gleif_registry_key`, `qvi_registry_key`

**GSMA Chain** (Sprint 61): Mock GSMA -> VetterCertification credentials for orgs
- State stored in `MockVLEIState.gsma_aid`, `gsma_registry_key`
- Bootstrapped by `_bootstrap_gsma()` in `app/org/mock_vlei.py`
- Config: `MOCK_GSMA_NAME` in `app/config.py`
- VetterCerts issued via `mock_vlei.issue_vetter_certification()`

**Trust Anchor Promotion** (Sprint 67): After bootstrapping, `_promote_trust_anchors()` promotes mock GLEIF, QVI, and GSMA to first-class `Organization` records with appropriate `org_type`:
- GLEIF → `root_authority`, QVI → `qvi`, GSMA → `vetter_authority`
- Three-strategy matching: persisted `MockVLEIState.*_org_id` → find existing org by AID → create new
- Idempotent and safe on every startup; name collisions handled with disambiguators
- State: `MockVLEIState.gleif_org_id`, `qvi_org_id`, `gsma_org_id`

### Organization Type Hierarchy (Sprint 67)

Organizations have an `org_type` (enum `OrgType`) that determines their role in the trust chain:

```
root_authority    GLEIF — issues QVI credentials
     └── qvi              QVI — issues LE, Extended LE credentials
vetter_authority  GSMA — issues VetterCert, Governance credentials
     └── regular           Standard org — issues Brand, TNAlloc, DE/GCD credentials
```

### Schema Authorization (Sprint 67)

Each org type is restricted to issuing specific credential schemas. Defined in `app/auth/schema_auth.py`:

| Org Type | Authorized Schemas |
|----------|-------------------|
| `root_authority` | QVI |
| `qvi` | LE, Extended LE |
| `vetter_authority` | VetterCertification, GSMA Governance |
| `regular` | Extended Brand, TNAlloc, Extended TNAlloc, DE/GCD |

Enforcement: `POST /credential/issue` checks `is_schema_authorized(org.org_type, schema_said)` and rejects unauthorized schemas (403). The credential UI filters schemas via `GET /schema/authorized`.

### Admin Org Context Switching (Sprint 67)

System admins can switch their session's "active org" to operate on behalf of another organization:
- `POST /session/switch-org` — sets `Session.active_org_id`
- `Session.get()` returns a cloned session with overridden `principal.organization_id`
- `Session.home_org_id` (immutable) preserves the admin's actual org
- Passing `organization_id=null` reverts to home org

**Vetter Module** (`app/vetter/`):
- `service.py`: `resolve_active_vetter_cert()` performs 7-point validation (existence, schema match, not revoked, issuer is GSMA, issuee matches org AID, not expired). Also contains `issue_vetter_certification()`, `revoke_vetter_certification()`, `get_org_constraints()`.
- `constants.py`: `VETTER_CERT_SCHEMA_SAID`, `VALID_ECC_CODES`, `VALID_JURISDICTION_CODES`, `KNOWN_EXTENDED_SCHEMA_SAIDS`.

**Extended Schema Edge Injection**: When issuing credentials with extended schemas (Extended LE, Brand, TNAlloc), `_inject_certification_edge()` in `app/api/credential.py` auto-populates the `certification` edge with the org's active VetterCertification SAID. Detection uses `schema_requires_certification_edge()` which checks the schema JSON for `oneOf` edge blocks, with `KNOWN_EXTENDED_SCHEMA_SAIDS` as a fail-closed fallback.

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
