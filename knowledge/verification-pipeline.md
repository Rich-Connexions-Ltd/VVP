# VVP Verification Pipeline

The verification pipeline is the core algorithm of the VVP Verifier. It transforms raw inputs (PASSporT JWT + VVP-Identity header) into a hierarchical Claim Tree.

**Orchestrator**: `services/verifier/app/vvp/verify.py:verify_vvp()`

---

## Pipeline Phases

### Phase 2: Parse VVP-Identity Header
**File**: `app/vvp/header.py:parse_vvp_identity()`

Decodes the `VVP-Identity` header (base64url-encoded JSON).

**Input**: Raw header string
**Output**: Parsed `VVPIdentity` with fields:
- `ppt` - Protocol type (e.g., "vvp", "shaken")
- `kid` - OOBI reference to signer's KERI resources
- `evd` - OOBI reference to evidence (dossier) URL
- `iat` - Issued-at timestamp (Unix epoch)
- `exp` - Optional expiry timestamp

**Validation**:
- Base64url decode must succeed
- JSON must be valid
- `kid` and `evd` must be present as OOBI references
- `iat` must be within ±300s clock skew (configurable)
- If `exp` absent, enforce max age of 300s from `iat`
- Future `iat` beyond clock skew → reject

**Errors**: `VVP_IDENTITY_MISSING`, `VVP_IDENTITY_INVALID`

---

### Phase 3: Parse and Bind PASSporT
**File**: `app/vvp/passport.py:parse_passport()`, `validate_passport_binding()`

Parses the PASSporT JWT (header.payload.signature) and binds it to the VVP-Identity.

**JWT Structure**:
```
Header: { "alg": "EdDSA", "ppt": "vvp", "typ": "passport", "kid": "..." }
Payload: { "iat": N, "orig": {...}, "dest": {...}, "evd": "...", "attest": {...} }
Signature: Ed25519 signature bytes
```

**Algorithm Policy** (spec §5.0, §5.1):
- **ONLY** accept `EdDSA` (Ed25519)
- **REJECT**: `none`, `ES256`, `HMAC*`, `RS*`, all others

**Evidence URL Extraction** (two formats):
1. Top-level `evd` field
2. `attest.creds[0]` with `evd:` prefix (VVP 1.0 format)

**Binding Validation**:
- `kid` in JWT header must match `kid` in VVP-Identity
- `iat` must be consistent between JWT and VVP-Identity

**Errors**: `PASSPORT_MISSING`, `PASSPORT_PARSE_FAILED`, `PASSPORT_FORBIDDEN_ALG`, `PASSPORT_EXPIRED`

---

### Phase 4: Verify Signature (Tier 2)
**File**: `app/vvp/verify.py:verify_passport_signature_tier2_with_key_state()`
**File**: `app/vvp/keri/kel_resolver.py`
**File**: `app/vvp/keri/cache.py` (range-based key state cache)

Resolves the signer's key state via OOBI and verifies the PASSporT signature.

**Algorithm**:
1. Extract AID from `kid` (supports OOBI URL and `did:web:` format)
2. Check range-based key state cache for cached entry covering reference time
3. On cache miss: resolve KEL via OOBI endpoint → parse establishment events
4. Find key state valid at reference time T (walk KEL chronologically)
5. Cache result with `[valid_from, valid_until)` range for future lookups
6. Reconstruct JWT signing input: `base64url(header).base64url(payload)`
7. Verify Ed25519 signature against public key

**Key State Resolution** (Sprint 78: range-based cache):
- HTTP GET to OOBI URL via shared HTTP client (connection pooling)
- SSRF validation before fetch (DNS resolution + IP range blocking)
- Parse KEL events → find last establishment event at/before time T
- Cache entries cover validity windows `[valid_from, valid_until)`
- `valid_until` = timestamp of next establishment event, or None if most recent
- Freshness guard: entries with `valid_until=None` expire after `VVP_KEY_STATE_FRESHNESS_WINDOW_SECONDS` (default 120s, configurable 10-3600s)
- Higher KEL sequence number wins tie-breaks when multiple entries cover same time
- Shared `httpx.AsyncClient` with `follow_redirects=False` (SSRF prevention)

**Errors**: `PASSPORT_SIG_INVALID`, `KERI_RESOLUTION_FAILED`, `KERI_STATE_INVALID`

---

### Phase 5: Fetch and Parse Dossier
**Files**: `app/vvp/dossier/parser.py`, `app/vvp/keri/cesr.py`, `app/vvp/dossier/validator.py`

Fetches the dossier from the evidence URL and parses it into a DAG of ACDC credentials.

**Fetch**:
- HTTP GET to `evd` URL
- Accept `application/json`, `application/json+cesr`, `application/cesr`
- Cache with SAID-based invalidation (`app/vvp/dossier/cache.py`)

**Parse** (two modes):
1. **CESR Stream**: Detected by version marker (`-_AAA`) or count code prefix
   - Iterates through binary stream
   - Extracts JSON events (ACDCs) and binary attachments (signatures)
   - Maps signatures to preceding ACDC
2. **JSON Fallback**: Standard JSON array of ACDC objects

**Permissive Fallback**: If strict CESR parsing fails (unknown attachment types), falls back to brace-matching extraction of JSON objects. Ensures forward compatibility.

**DAG Construction** (`validator.py:build_dag()`):
- Parse edges from each ACDC to build graph
- Cycle detection via 3-color DFS (White/Gray/Black)
- Root finding: nodes with no incoming edges
- Enforce single root (unless aggregate mode)
- ToIP compliance warnings (non-blocking)

**Output**: `DossierDAG` containing `ACDCNode` objects with parent/child relationships

**Errors**: `DOSSIER_URL_MISSING`, `DOSSIER_FETCH_FAILED`, `DOSSIER_PARSE_FAILED`, `DOSSIER_GRAPH_INVALID`

---

### Phase 6-8: Verify ACDC Integrity
**Files**: `app/vvp/acdc/verifier.py`, `app/vvp/acdc/acdc.py`

For each ACDC in the dossier:
1. Verify SAID matches content hash (Blake3-256 of most-compact-form)
2. Verify ACDC signature against issuer's key state
3. Validate schema SAID against known vLEI schemas

**Errors**: `ACDC_SAID_MISMATCH`, `ACDC_PROOF_MISSING`

---

### Phase 9: Check Revocation
**File**: `app/vvp/keri/tel_client.py`, `app/vvp/verify.py:check_dossier_revocations()`

For each credential in the chain:

**Strategy** (ordered by priority):
1. **Inline TEL** (fast path): Check for TEL events in the dossier stream itself
2. **OOBI Resolution**: Use credential's `ri` (Registry ID) to construct OOBI URL
3. **Issuer TEL Source** (Sprint 80): Query `VVP_TEL_ISSUER_URL` for CESR-encoded TEL events. Verifies credential binding (`i` field match) and sequence consistency (iss=0, rev=1). Only active when `VVP_TEL_ISSUER_URL` is configured. Falls through to witnesses on error/unknown.
4. **Witness Pool**: Query configured witness pool

**TEL Event Types**:
| Event | Meaning | Status |
|-------|---------|--------|
| `iss` | Simple issuance | ACTIVE |
| `bis` | Backreference issuance | ACTIVE |
| `rev` | Simple revocation | REVOKED |
| `brv` | Backreference revocation | REVOKED |

**Errors**: `CREDENTIAL_REVOKED`

---

### Phase 10-11: Validate Authorization Chain
**File**: `app/vvp/acdc/verifier.py:validate_credential_chain()`, `app/vvp/authorization.py`

Recursive walk from leaf credential to trusted root.

**Algorithm** (see `knowledge/keri-primer.md` for details):
1. Depth control (prevent infinite loops)
2. Type-specific edge rules (APE→LE, DE→APE/DE, TNAlloc→jurisdiction)
3. Schema SAID governance validation
4. Issuee binding check (no bearer tokens)
5. Root check against `TRUSTED_ROOT_AIDS`
6. External resolution for references outside dossier
7. Compact variant handling → INDETERMINATE if unresolvable

**Authorization Checks**:
- TNAlloc credential must contain the calling TN
- Delegation chain must be unbroken
- PASSporT signer AID must appear in the authorization path

**Errors**: `AUTHORIZATION_FAILED`, `TN_RIGHTS_INVALID`

### Phase 11b: Vetter Constraint Evaluation (Sprint 62)
**File**: `app/vvp/vetter/constraints.py`, `app/vvp/verify.py`, `app/vvp/verify_callee.py`

Evaluates whether each credential in the dossier was issued by a vetter authorized for its geographic scope. Runs after dossier validation succeeds.

**Algorithm**:
1. Walk dossier credentials, find `certification` edges linking to VetterCertification ACDCs
2. Extract `ecc_targets` (E.164 country codes) and `jurisdiction_targets` (ISO 3166-1 alpha-3) from VetterCert
3. For TN credentials: check calling TN's country code against `ecc_targets`
4. For Identity/Brand credentials: check jurisdiction against `jurisdiction_targets`
5. Derive overall status: VALID (all pass), INVALID (cert found but scope mismatch → triggers WARNING), INDETERMINATE (cert missing)

**WARNING status (Sprint 75, §8.4)**:
- When vetter_status == INVALID AND `ENFORCE_VETTER_CONSTRAINTS=false` (default): overall_status is upgraded to WARNING post-derivation (not INDETERMINATE or VALID) if no other claim produced INVALID.
- WARNING is non-blocking: the call is still delivered; callee sees `X-VVP-Status: WARNING` and `X-VVP-Warning-Reason: vetter_not_authorised_for_jurisdiction`.
- Priority: INVALID > WARNING > INDETERMINATE > VALID. WARNING cannot override INVALID from other phases.
- `vetter_warning_reason` field in VerifyResponse carries the machine-readable reason string.

**Claim**: `vetter_constraints` (OPTIONAL — required=False, does not block overall VALID when INDETERMINATE)

**Response field**: `vetter_constraints: Dict[str, VetterConstraintInfo]` keyed by credential SAID; `vetter_warning_reason: Optional[str]`

**SIP propagation**: `X-VVP-Vetter-Status` header (PASS / FAIL-ECC / FAIL-JURISDICTION / FAIL-ECC-JURISDICTION / INDETERMINATE); `X-VVP-Warning-Reason` header when WARNING

**Errors**: `VETTER_ECC_UNAUTHORIZED`, `VETTER_JURISDICTION_UNAUTHORIZED`, `VETTER_CERTIFICATION_MISSING`

---

## Claim Tree Output

The final output is a recursive tree of claims:

```
caller_verified (root)
├── passport_verified (REQUIRED)
│   ├── timing_valid (REQUIRED)
│   ├── signature_valid (REQUIRED)
│   └── binding_valid (REQUIRED)
├── dossier_verified (REQUIRED)
│   ├── structure_valid (REQUIRED)
│   ├── acdc_signatures_valid (REQUIRED)
│   └── revocation_clear (REQUIRED)
├── authorization_valid (REQUIRED)
│   ├── party_authorized (REQUIRED)
│   └── tn_rights_valid (REQUIRED)
├── context_aligned (REQUIRED or OPTIONAL per policy)
├── brand_verified (OPTIONAL)
│   ├── brand_logo_hash (Sprint 79) — Blake3-256 SAID of logo if HASH param present
│   └── brand_errors — BrandErrorCode enum (HASH_DOWNGRADE, PROPERTY_MISMATCH, etc.)
├── vetter_constraints (OPTIONAL, Sprint 62)
└── business_logic_verified (OPTIONAL)
```

**Status Propagation**:
- REQUIRED child INVALID → parent INVALID
- REQUIRED child INDETERMINATE → parent INDETERMINATE
- OPTIONAL child INVALID → parent unaffected
- All REQUIRED children VALID → parent MAY be VALID

**Overall Status Derivation** (`api_models.py`):
- Any root-level INVALID → overall INVALID
- Any root-level INDETERMINATE → overall INDETERMINATE
- All VALID → overall VALID

---

## Configuration Constants
**File**: `app/core/config.py`

| Constant | Default | Spec Reference |
|----------|---------|----------------|
| `CLOCK_SKEW_SECONDS` | 300 | §4.1A |
| `MAX_PASSPORT_VALIDITY_SECONDS` | 300 | §5.2B |
| `MAX_IAT_DRIFT_SECONDS` | 5 | §5.2A |
| `TRUSTED_ROOT_AIDS` | GLEIF + QVI AIDs | §5.1-7 |
| `ALLOWED_ALGORITHMS` | `["EdDSA"]` | §5.0, §5.1 |
