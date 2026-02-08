# VVP Verifier Service

## What This Service Does
The Verifier validates VVP (Verifiable Voice Protocol) claims in VoIP calls. It takes a PASSporT JWT + VVP-Identity header and produces a hierarchical Claim Tree with status VALID/INVALID/INDETERMINATE.

## Key Files

| File | Purpose |
|------|---------|
| `app/main.py` | FastAPI app, routes, middleware |
| `app/core/config.py` | Configuration constants (trusted roots, algorithms, timeouts) |
| `app/vvp/verify.py` | **Main orchestrator** - `verify_vvp()` runs the 11-phase pipeline |
| `app/vvp/verify_callee.py` | Callee verification (§5B) |
| `app/vvp/header.py` | VVP-Identity header parsing (base64url JSON) |
| `app/vvp/passport.py` | PASSporT JWT parsing (EdDSA only) |
| `app/vvp/authorization.py` | Authorization chain validation (TN rights, delegation) |
| `app/vvp/api_models.py` | All Pydantic request/response models, ErrorCode registry |
| `app/vvp/exceptions.py` | VVPIdentityError, PassportError |
| `app/vvp/keri/cesr.py` | CESR stream parsing (count codes, signatures) |
| `app/vvp/keri/kel_resolver.py` | KEL resolution via OOBI |
| `app/vvp/keri/tel_client.py` | TEL client for revocation checking |
| `app/vvp/keri/witness_pool.py` | Witness pool management |
| `app/vvp/acdc/verifier.py` | ACDC credential chain validation |
| `app/vvp/acdc/acdc.py` | ACDC dataclass and type inference |
| `app/vvp/acdc/schema_registry.py` | Schema SAID → credential type mapping |
| `app/vvp/dossier/parser.py` | Dossier parsing (CESR or JSON) |
| `app/vvp/dossier/validator.py` | DAG construction, cycle detection |
| `app/vvp/dossier/cache.py` | Dossier cache with SAID-based invalidation |

## Verification Pipeline (verify.py)
Phases 2-11 in `verify_vvp()`:
1. Parse VVP-Identity header → kid, evd, iat, exp
2. Parse PASSporT JWT → validate EdDSA alg, extract claims
3. Verify signature → resolve KEL via OOBI, Ed25519 verify
4. Fetch dossier → HTTP GET evd URL, parse CESR/JSON
5. Build DAG → cycle detection, single root, ToIP checks
6. Verify ACDC integrity → SAID match, signature check
7. Check revocation → TEL lookup (inline, OOBI, witness)
8. Validate chain → recursive walk to trusted root
9. Check authorization → TN rights, delegation path
10. Contextual alignment → SIP context matching
11. Brand/business logic → optional claims

## API Endpoints
- `POST /verify` - Main verification (VerifyRequest → VerifyResponse)
- `POST /verify-callee` - Callee verification (VerifyCalleeRequest)
- `POST /check-revocation` - TEL revocation check
- `GET /healthz` - Health check
- `GET /admin` - Config and metrics (gated)

## Running Tests
```bash
./scripts/run-tests.sh -v
```
62 test files covering all components. See `knowledge/test-patterns.md` for details.

## Known Workarounds
See `Documentation/DOSSIER_WORKAROUNDS.md` for:
- Provenant demo schema SAIDs added to registry
- `did:web:` to OOBI URL conversion
- `attest.creds` evidence URL format
- "issuer" edge name for DE credentials

## Spec Reference
- `Documentation/VVP_Verifier_Specification_v1.5.md` (authoritative)
- `Documentation/VVP_Implementation_Checklist.md` (182/182 items complete)
