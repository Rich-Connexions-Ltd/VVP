# VVP Verifier Service

## What This Service Does
The Verifier validates VVP (Verifiable Voice Protocol) claims in VoIP calls. It takes a PASSporT JWT + VVP-Identity header and produces a hierarchical Claim Tree with status VALID/INVALID/INDETERMINATE. Includes vetter constraint enforcement (Sprint 62) and a rich HTMX-based web UI for interactive exploration.

## Key Files

| File | Purpose |
|------|---------|
| `app/main.py` | FastAPI app, all routes (~33 endpoints), middleware |
| `app/core/config.py` | Configuration constants (trusted roots, algorithms, timeouts) |
| `app/vvp/verify.py` | **Main orchestrator** — `verify_vvp()` runs the 11-phase pipeline |
| `app/vvp/verify_callee.py` | Callee verification (SS5B) |
| `app/vvp/header.py` | VVP-Identity header parsing (base64url JSON) |
| `app/vvp/passport.py` | PASSporT JWT parsing (EdDSA only) |
| `app/vvp/authorization.py` | Authorization chain validation (TN rights, delegation) |
| `app/vvp/api_models.py` | Pydantic models, ErrorCode registry (30 codes incl. 4 VETTER_*) |
| `app/vvp/exceptions.py` | VVPIdentityError, PassportError |
| `app/vvp/keri/cesr.py` | CESR stream parsing (count codes, signatures) |
| `app/vvp/keri/kel_resolver.py` | KEL resolution via OOBI |
| `app/vvp/keri/tel_client.py` | TEL client for revocation checking |
| `app/vvp/keri/witness_pool.py` | Witness pool management |
| `app/vvp/acdc/verifier.py` | ACDC credential chain validation |
| `app/vvp/acdc/acdc.py` | ACDC dataclass and type inference |
| `app/vvp/acdc/schema_registry.py` | Schema SAID -> credential type mapping |
| `app/vvp/dossier/parser.py` | Dossier parsing (CESR or JSON) |
| `app/vvp/dossier/validator.py` | DAG construction, cycle detection |
| `app/vvp/dossier/cache.py` | Dossier cache with SAID-based invalidation |
| `app/vvp/vetter/` | Vetter constraint module (Sprint 62) |
| `app/vvp/vetter/constraints.py` | ECC + jurisdiction constraint checking |
| `app/vvp/vetter/certification.py` | VetterCertification credential validation |
| `app/vvp/vetter/country_codes.py` | E.164 country code -> ISO mapping |
| `app/vvp/vetter/traversal.py` | Credential chain walk for cert backlinks |

## Verification Pipeline (verify.py)

Phases 1-11 in `verify_vvp()`:

| Phase | Name | Description |
|-------|------|-------------|
| 1 | Parse VVP-Identity | Extract kid, evd, iat, exp from base64url header |
| 2 | Parse PASSporT | Validate EdDSA alg, extract JWT claims |
| 3 | Verify Signature | Resolve KEL via OOBI, Ed25519 verify |
| 4 | Fetch Dossier | HTTP GET evd URL, parse CESR/JSON |
| 5 | Build DAG | Cycle detection, single root, ToIP checks |
| 6 | Verify ACDC | SAID match, signature check |
| 7 | Check Revocation | TEL lookup (inline, OOBI, witness) |
| 8 | Validate Chain | Recursive walk to trusted root |
| 9 | Authorization | TN rights, delegation path |
| 10 | Context Alignment | SIP context matching |
| 11 | Vetter Constraints | ECC/jurisdiction validation (Sprint 62) |

### Phase 11: Vetter Constraints (Sprint 62)

Validates geographic and jurisdictional authorization:
- Extracts country code from TN using E.164 prefix mapping
- Walks credential chain looking for VetterCertification backlinks
- Checks ECC (country code) and jurisdiction targets against cert
- **INDETERMINATE** status used for constraint failures (not INVALID)
- 4 error codes: `VETTER_ECC_UNAUTHORIZED`, `VETTER_JURISDICTION_UNAUTHORIZED`, `VETTER_CERTIFICATION_MISSING`, `VETTER_CERTIFICATION_INVALID`
- Controlled by `VVP_ENFORCE_VETTER_CONSTRAINTS` config

### INDETERMINATE Status

Used when verification cannot produce a definitive VALID/INVALID result:
- Dossier fetch failures (cached partial results)
- Revocation check incomplete
- Vetter constraint failures (Phase 11)
- Returns `EvidenceStatus.INDETERMINATE` with amber badge styling in UI

## API Endpoints

### Core Verification
| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/verify` | Main verification (VerifyRequest -> VerifyResponse) |
| `POST` | `/verify-callee` | Callee verification (SS5B) |
| `POST` | `/check-revocation` | TEL revocation check |
| `GET` | `/healthz` | Health check |
| `GET` | `/version` | Version info |

### Admin
| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/admin` | Config and metrics (gated) |
| `POST` | `/admin/log-level` | Change log level |
| `POST` | `/admin/cache/clear` | Clear dossier cache |
| `POST` | `/admin/witnesses/discover` | Discover witnesses |

### Web UI Pages
| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/` | Landing page |
| `GET` | `/verify` | Full verification UI |
| `GET` | `/verify/full` | Full verification (alias) |
| `GET` | `/verify/simple` | Simple verification UI |
| `GET` | `/verify/explore` | JWT/SIP explorer |
| `GET` | `/create` | PASSporT creation tool |
| `GET` | `/simple` | Simple verify (alias) |
| `GET` | `/ui/admin` | Admin panel UI |

### HTMX Endpoints (return HTML fragments)
| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/ui/parse-jwt` | Parse PASSporT JWT |
| `POST` | `/ui/parse-sip` | Parse SIP INVITE |
| `POST` | `/ui/fetch-dossier` | Fetch and display dossier |
| `POST` | `/ui/check-revocation` | Revocation badge |
| `POST` | `/ui/credential-graph` | Credential chain visualization |
| `POST` | `/ui/revocation-badge` | Revocation status badge |
| `GET` | `/ui/revocation-status` | Revocation polling |
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

## Running Tests
```bash
./scripts/run-tests.sh -v
```
62 test files covering all components. See `knowledge/test-patterns.md` for details.

## Configuration (Sprint 80)

| Variable | Default | Purpose |
|----------|---------|---------|
| `VVP_TEL_ISSUER_URL` | *(empty)* | Issuer TEL facade URL for revocation checks. HTTPS required unless `VVP_ALLOW_HTTP=true`. |
| `VVP_ALLOW_HTTP` | `false` | Allow HTTP for TEL Issuer URL (dev only) |

## Known Workarounds
See `Documentation/DOSSIER_WORKAROUNDS.md` for:
- Provenant demo schema SAIDs added to registry
- `did:web:` to OOBI URL conversion
- `attest.creds` evidence URL format
- "issuer" edge name for DE credentials

## Spec Reference
- `Documentation/VVP_Verifier_Specification_v1.5.md` (authoritative)
- `Documentation/VVP_Implementation_Checklist.md` (182/182 items complete)
