# VVP Verifier Architecture

## System Overview

The VVP Verifier is a standalone service that validates VVP-signed SIP calls. It operates at the intersection of two protocol domains:

1. **SIP signalling** -- Receives SIP INVITE messages containing VVP headers, returns SIP 302 redirects or error responses.
2. **KERI/ACDC verification** -- Resolves KERI identifiers, validates ACDC credential chains, checks revocation status via the Transaction Event Log (TEL).

```
                    ┌──────────────────────────────────────────┐
                    │              VVP Verifier                 │
 SIP INVITE ───────►  ┌─────────────────┐  ┌───────────────┐  │
 (UDP :5060)        │  │  SIP Transport   │  │  HTTP API     │  │◄── POST /verify
                    │  │  parser/builder  │  │  FastAPI       │  │    (TCP :8000)
                    │  └────────┬────────┘  └───────┬───────┘  │
                    │           │                    │          │
                    │           ▼                    ▼          │
                    │  ┌─────────────────────────────────────┐  │
                    │  │       9-Phase Verification Pipeline  │  │
                    │  └─────────────────────────────────────┘  │
                    │           │                               │
                    │           ▼                               │
                    │  ┌───────────────┐  ┌─────────────────┐  │
                    │  │  Result Cache  │  │  Revocation BG  │  │
                    │  │  (LRU + TTL)  │  │  Checker        │  │
                    │  └───────────────┘  └─────────────────┘  │
                    └──────────────────────────────────────────┘
                               │
                    ┌──────────┼──────────┐
                    ▼          ▼          ▼
               Witnesses    Dossier    TEL Servers
               (OOBI)      (HTTP)     (Revocation)
```

## Module Map

| Module | Responsibility |
|--------|---------------|
| `app/sip/parser.py` | RFC 3261 SIP message parser (request and response) |
| `app/sip/builder.py` | SIP response construction (302, 4xx/5xx) with VVP headers |
| `app/sip/models.py` | `SIPRequest` / `SIPResponse` dataclasses with serialization |
| `app/sip/handler.py` | SIP INVITE handler -- orchestrates parse, verify, respond |
| `app/sip/transport.py` | asyncio UDP transport for SIP message I/O |
| `app/vvp/header.py` | VVP-Identity header parser (base64url JSON) |
| `app/vvp/passport.py` | PASSporT JWT parser, payload validation, binding checks |
| `app/vvp/signature.py` | Ed25519 signature verification via pysodium |
| `app/vvp/dossier.py` | HTTP dossier fetch with timeout, size limits, content negotiation |
| `app/vvp/acdc.py` | ACDC credential parsing, SAID verification, DAG construction |
| `app/vvp/cache.py` | Two-tier verification result cache with LRU eviction and TTL |
| `app/vvp/revocation.py` | Background TEL polling for credential revocation detection |
| `app/vvp/authorization.py` | TN-to-AID authorization chain validation |
| `app/vvp/models.py` | Pydantic models: `VerifyRequest`, `VerifyResponse`, `ClaimNode`, `ErrorDetail` |
| `app/vvp/exceptions.py` | Typed exception hierarchy mapped to `ErrorCode` values |
| `app/vvp/canonical.py` | KERI canonical JSON serialization for SAID computation |
| `app/vvp/cesr.py` | CESR (Composable Event Streaming Representation) codec |
| `app/vvp/schema.py` | Schema SAID registry and credential type validation |
| `app/vvp/tel.py` | TEL (Transaction Event Log) HTTP client for revocation queries |
| `app/config.py` | Configuration: normative constants, env-var overrides, fingerprinting |

## 9-Phase Verification Pipeline

Every verification request passes through the following phases. Phases 1-3 always execute; phases 4-9 execute only when earlier phases succeed. Cached results skip phases 4-7.

### Phase 1: Header Parse

Parse and validate the VVP-Identity header (base64url-encoded JSON).

- Extract `ppt`, `kid`, `evd`, `iat`, and optional `exp`
- Validate `iat` is not in the future (beyond clock skew)
- Default `exp` to `iat + MAX_TOKEN_AGE_SECONDS` when omitted
- **Error**: `VVP_IDENTITY_MISSING`, `VVP_IDENTITY_INVALID`

### Phase 2: PASSporT Parse

Parse the compact-serialised JWT into header, payload, and signature.

- Validate algorithm (`EdDSA` only; reject forbidden algorithms)
- Validate `ppt` equals `"vvp"`
- Extract `orig`, `dest`, `evd`, `iat`, optional `exp` and `card`
- Validate telephone number format (E.164)
- **Error**: `PASSPORT_MISSING`, `PASSPORT_PARSE_FAILED`, `PASSPORT_FORBIDDEN_ALG`

### Phase 3: Binding Validation

Verify consistency between the PASSporT JWT and VVP-Identity header.

- `ppt` match (strict equality)
- `kid` match (strict equality)
- `iat` drift within 5 seconds (normative)
- `exp` consistency and expiry checks
- **Error**: `PASSPORT_PARSE_FAILED`, `PASSPORT_EXPIRED`

### Phase 4: Signature Verification

Verify the Ed25519 signature on the PASSporT JWT.

- Derive the 32-byte Ed25519 verification key from the `kid` AID
- Reconstruct the signing input (`header.payload`)
- Verify the detached signature using pysodium
- **Error**: `PASSPORT_SIG_INVALID`, `KERI_RESOLUTION_FAILED`

### Phase 5: Dossier Fetch

Retrieve the ACDC evidence dossier from the `evd` URL.

- HTTP GET with configurable timeout and size limit
- Content-type negotiation (CESR, JSON)
- **Error**: `DOSSIER_URL_MISSING`, `DOSSIER_FETCH_FAILED`

### Phase 6: Dossier Parse & DAG Construction

Parse the dossier content and build the credential graph.

- Parse CESR or JSON credential stream
- Construct a directed acyclic graph (DAG) of credentials
- Verify SAID (Self-Addressing Identifier) for each credential
- **Error**: `DOSSIER_PARSE_FAILED`, `DOSSIER_GRAPH_INVALID`, `ACDC_SAID_MISMATCH`

### Phase 7: Chain Verification

Walk the credential chain from the signing credential to a trusted root.

- Verify each edge (issuer AID of child == subject AID of parent)
- Check credential types against schema registry
- Verify ACDC proof fields
- **Error**: `ACDC_PROOF_MISSING`, `AUTHORIZATION_FAILED`

### Phase 8: Authorization Validation

Verify the signer is authorized for the originating telephone number.

- Locate TN Allocation credential(s) in the chain
- Verify the allocated TN range covers the originating number
- **Error**: `TN_RIGHTS_INVALID`

### Phase 9: Revocation Check

Check credential revocation status via the TEL.

- Query TEL servers for each credential SAID
- Update revocation status in cache
- **Error**: `CREDENTIAL_REVOKED`

## Two-Tier Caching Design

The verifier uses a two-tier caching architecture to balance freshness with performance:

### Tier 1: Dossier Cache

- **Key**: Dossier URL
- **TTL**: 300 seconds (configurable)
- **Max entries**: 100 (configurable)
- **Purpose**: Avoid redundant HTTP fetches of the same dossier

### Tier 2: Verification Result Cache

- **Key**: `(dossier_url, passport_kid)` compound key
- **TTL**: 3600 seconds (configurable)
- **Max entries**: 200 (configurable)
- **Eviction**: LRU (Least Recently Used)
- **Purpose**: Cache the expensive DAG construction, chain walk, and ACDC signature verification

On a **cache hit**, per-request phases (header parse, PASSporT parse, binding, signature) still execute to validate the current request's freshness, but the dossier-derived artifacts (DAG, chain claims) are reused.

### Config Fingerprint Invalidation

Each cache entry records a configuration fingerprint (SHA256 of validation-affecting settings). If the application restarts with different trusted roots, clock skew, or token age settings, all existing cache entries are transparently invalidated on access.

### Background Revocation

A background task periodically re-checks the revocation status of credentials in cached entries. Revocation is a **sticky** state: once a credential is marked `REVOKED`, it can never be downgraded. Revocation updates propagate across all `kid` variants for the same dossier URL.

## Spec Compliance Matrix

| Spec Section | Feature | Status |
|-------------|---------|--------|
| §3.2 | Claim status model (VALID/INVALID/INDETERMINATE) | Implemented |
| §3.3A | Status derivation (INVALID > INDETERMINATE > VALID) | Implemented |
| §4.1 | Verify request/response model | Implemented |
| §4.1A | VVP-Identity header parsing | Implemented |
| §4.2 | Error codes with recoverability | Implemented |
| §4.3 | Claim tree structure | Implemented |
| §5.0 | EdDSA (Ed25519) mandate | Implemented |
| §5.1 | Algorithm gate (allow/forbid lists) | Implemented |
| §5.2A | iat drift <= 5 seconds | Implemented |
| §5.2B | exp validity and token age | Implemented |
| §5.3 | CESR/base64url signature decoding | Implemented |
| §5.4 | PASSporT binding validation | Implemented |
| §5A | Verification result caching | Implemented |

## Capabilities Signaling

Every `VerifyResponse` includes a `capabilities` dictionary that declares the implementation status of each feature. This allows consuming systems to make informed decisions about whether the verification result is complete for their use case.

The three capability states are:

| State | Meaning |
|-------|---------|
| `implemented` | Feature is fully operational and tested |
| `not_implemented` | Feature is defined in the spec but not yet built |
| `rejected` | Feature has been intentionally excluded from this implementation |

## Supported Identifier Types

| Prefix | Type | Support |
|--------|------|---------|
| `B` | Non-transferable Ed25519 (44 chars) | Implemented (Tier 1) |
| `D` | Transferable Ed25519 (44 chars) | Rejected (requires KEL) |
| `1AAB` | Non-transferable Ed25519 (48 chars, long form) | Not implemented |
| `1AAC` | Transferable secp256k1 | Not implemented |

The verifier is limited to **Tier 1 non-transferable Ed25519 identifiers** (`B` prefix). Transferable identifiers require KERI Event Log (KEL) resolution infrastructure, which is excluded from this standalone deployment.
