# Sprint 80: TEL Publication to Witnesses

## Problem Statement

The verifier cannot resolve credential revocation status via live queries. When checking TEL (Transaction Event Log) data, all queries to witnesses return errors because keripy witnesses only serve KEL (Key Event Log) data — they have no TEL endpoints. This causes all credentials to show `INDETERMINATE` in VVP Explorer due to "No TEL data found from any source".

**Status terminology:** The verifier uses `UNKNOWN` (TEL client level: no TEL data found from any source) and `INDETERMINATE` (verification pipeline level: cannot produce a definitive VALID/INVALID result). These are distinct: UNKNOWN is one cause of INDETERMINATE. This sprint's goal is to eliminate UNKNOWN by providing a working TEL source, which in turn eliminates the INDETERMINATE revocation status.

**Current behavior:**
1. The KERI Agent service creates TEL events (vcp, iss) in local LMDB during registry creation and credential issuance
2. Only the anchor ixn (KEL event) is published to witnesses — TEL events stay local in the KERI Agent's LMDB
3. Verifier TEL client queries witnesses at `/tels/{said}`, `/query?typ=tel&vcid=...` — all return 404
4. Dossier inline TEL works but live witness queries always return UNKNOWN
5. VVP Explorer shows INDETERMINATE for all credentials

**Evidence:**
- `curl https://vvp-witness1.rcnx.io/oobi/ENQySaRH...` returns empty (no TEL)
- Verifier check-revocation: `{"status":"UNKNOWN","error":"No TEL data found from any source"}`
- KEL OOBIs work fine (e.g. issuer AID EDxw4-NN... resolves correctly)

## Spec References

- §5.1.1-2.9: Revocation Status Check — verifier MUST query TEL for each credential
- §3.3B: `revocation_clear` is a REQUIRED child of `dossier_verified`
- KERI TEL spec: TEL events (vcp/iss/rev) tracked separately from KEL, anchored via KEL interaction events

## Current State

### Terminology

- **KERI Agent**: The `services/keri-agent/` microservice that wraps keripy for identity, registry, and credential operations. Internal-only; not directly exposed to external clients.
- **Issuer**: The `services/issuer/` microservice that provides the public HTTP API. Proxies KERI operations to the KERI Agent via `KeriAgentClient`.
- **Reger**: keripy's `vdr.viring.Reger` class — the LMDB-backed TEL database (stores TEL events, credential status, anchors). Analogous to `db.Baser` for KEL.
- **TEL event**: A Transaction Event Log entry. Types: `vcp` (registry inception), `iss` (credential issuance, sn=0), `rev` (revocation, sn=1).

### What works:
- TEL events created locally during `issue_credential()` and stored in LMDB via Reger
- TEL events embedded in dossiers via `DossierBuilder._get_tel_event()` using `reger.cloneTvtAt()`
- Verifier parses inline dossier TEL correctly (CESR format)
- The KERI Agent has `GET /credentials/{said}/tel` endpoint returning CESR TEL events (internal use by DossierBuilder)

### What doesn't work:
- keripy witnesses have NO TEL serving capability (by design — they're KEL-only)
- Verifier TEL client queries to witnesses all fail (404/empty responses)
- No TEL source discoverable by verifier for live revocation checks

### Root cause:
keripy witnesses (`ending.py:OOBIEnd`) only serve KEL events via `/oobi/{aid}`. They have no `/tels/` or `/query` endpoints. Publishing TEL events TO witnesses would not help because witnesses lack the storage and serving layer for TEL data.

## Proposed Solution

### Approach: Issuer as TEL Facade with CESR Transport and SAID Verification

Since keripy witnesses cannot serve TEL by design, the Issuer service becomes the public TEL facade. The KERI Agent retains TEL data in LMDB and is accessed only by the Issuer via the existing `KeriAgentClient` internal interface. The verifier queries the Issuer's `/tels/` endpoint and verifies TEL event integrity via SAID validation and credential binding checks.

**Why this approach:**
- KERI Agent already stores all TEL data in LMDB (Reger)
- Single public API surface (Issuer) — KERI Agent remains internal-only
- Verifier configures Issuer URL explicitly via `VVP_TEL_ISSUER_URL` (no trust in untrusted evd data)
- CESR transport preserves full cryptographic context (signatures, seals, anchors)
- Verifier performs SAID verification + credential binding on received TEL events
- No keripy modifications needed (risky vendored dependency)

### Alternatives Considered

| Alternative | Pros | Cons | Why Rejected |
|-------------|------|------|--------------|
| Modify keripy witnesses to serve TEL | Standard KERI approach | Modifying vendored keripy is risky; would need TEL storage layer, new endpoints, custom witness build | Too invasive, maintenance burden |
| Use backer-backed registries (noBackers=False) | KERI-native TEL anchoring | keripy backer support is incomplete; witnesses would still need TEL-aware endpoints | keripy witnesses don't support backer TEL serving |
| Expose KERI Agent directly (no Issuer proxy) | Simpler, one fewer hop | KERI Agent is internal-only; exposing it publicly breaks service boundary | Architectural violation |
| Derive TEL URL from evd field | Zero-config | evd is untrusted input; SSRF risk even with validation | Explicit config is safer |
| Return TEL as unsigned JSON | Simple parsing | Downgrades cryptographic trust; verifier can't verify event integrity | Security concern |

### Detailed Design

#### Component 1: KERI Agent TEL Query Endpoint (Internal Only)

**Purpose:** Single TEL CESR endpoint on the KERI Agent for the Issuer to proxy. Internal-only (same trust boundary as all existing KERI Agent endpoints).

**Location:** `services/keri-agent/app/api/tel.py` (new file)

**Endpoint:**

`GET /tels/credential/{credential_said}` — CESR-encoded TEL events for a credential
- Returns concatenated CESR: iss event (sn=0) + rev event (sn=1, if revoked)
- Content-Type: `application/cesr`
- 404 if credential not found
- 400 if SAID format invalid

**Note on internal trust boundary:** The Issuer→KERI Agent communication relies on network-level trust (internal Docker network, no direct external access). This is the same trust model used for ALL existing Issuer→KERI Agent calls (credential issuance, identity management, dossier building). Adding service-to-service authentication is a cross-cutting concern that applies to all endpoints — tracked as future work, not Sprint 80 scope.

**Input validation:**
- SAID path parameter: must match `/^E[A-Za-z0-9_-]{43}$/` (KERI derivation code prefix `E` + 43 Base64url chars)
- Invalid SAIDs return 400 with generic error (no input echo to prevent log injection)

**Non-blocking I/O:**
- All LMDB operations run via `asyncio.to_thread()` to avoid blocking the async event loop
- Pattern: `tel_bytes = await asyncio.to_thread(reger.cloneTvtAt, credential_said, 0)`

**Implementation notes:**
- Reuses existing `CredentialIssuer.get_credential_tel_bytes()` for iss event
- Adds rev event retrieval: `reger.cloneTvtAt(credential_said, sn=1)` if present
- The existing `GET /credentials/{said}/tel` endpoint is unchanged (returns only iss, used internally by DossierBuilder). Coexistence is documented; a future sprint may consolidate the two.

#### Component 2: Issuer TEL Facade (Public)

**Purpose:** Public TEL endpoint on the Issuer, proxying to KERI Agent. Sole public access path for TEL data.

**Location:** `services/issuer/app/api/tel.py` (new file)

**Endpoint:**

`GET /tels/credential/{credential_said}` — Proxies to KERI Agent, returns CESR

**Implementation:** Thin proxy — calls `KeriAgentClient.get_credential_tel()` which returns raw bytes. The Issuer returns them with `Content-Type: application/cesr`. No TEL-specific logic in the Issuer layer. Same endpoint path and response format as Component 1 — contract defined once in KERI Agent, Issuer is a transparent byte proxy.

**Security controls:**
- **Rate limiting:** 60 requests/minute per source IP (using existing `SlowAPI` middleware)
- **No authentication:** TEL data is public per KERI spec (like OOBI data)
- **SAID validation:** Must match `/^E[A-Za-z0-9_-]{43}$/` (KERI derivation code prefix `E` + 43 Base64url chars = 44 total). Validated before proxying.
- **Response headers:** `Cache-Control: no-store` (revocation status must not be cached at HTTP layer)
- **HTTPS-only:** The Issuer runs behind Azure Container Apps with mandatory TLS termination. All external access is HTTPS. HTTP redirected by the platform.
- **CORS:** No CORS headers. Server-to-server endpoint. Negative CORS tests ensure no `Access-Control-Allow-Origin` header leaks.

**Error handling:**
- KERI Agent unavailable → HTTP 503 with `Retry-After: 30`
- Credential not found → HTTP 404
- Invalid SAID format → HTTP 400

#### Component 3: KeriAgentClient TEL Method

**Purpose:** Single byte-passthrough TEL method on the existing KERI Agent client.

**Location:** `common/common/vvp/keri_agent_client.py` (edit existing)

**New method:**
```python
async def get_credential_tel(self, credential_said: str) -> Optional[bytes]:
    """Get CESR-encoded TEL events for a credential from KERI Agent.
    Returns raw CESR bytes (iss + optional rev) or None if not found (404)."""
```

This is a raw byte passthrough — no parsing, no TEL-specific data model. The `KeriAgentClient` already has similar byte-passthrough methods (e.g., `get_credential_cesr()`). No contract duplication: only the KERI Agent has TEL logic.

**MockKeriAgentClient:** Corresponding mock method returns fixture CESR bytes.

#### Component 4: Verifier TEL Client — Issuer Source with SAID Verification

**Purpose:** Add the Issuer as a TEL source in the verifier's TEL client, with integrity checks on received TEL events.

**Location:** `services/verifier/app/vvp/keri/tel_client.py` (edit existing)

**Changes:**

1. New method `_query_issuer_tel()` that queries `{issuer_url}/tels/credential/{credential_said}`
2. In `check_revocation()`, try the Issuer after cache check but before witnesses
3. After receiving CESR TEL events, verify integrity before trusting status

**New config** (`services/verifier/app/core/config.py`):
```python
TEL_ISSUER_URL: str = os.getenv("VVP_TEL_ISSUER_URL", "")
```

**TEL source binding (security):**
- `VVP_TEL_ISSUER_URL` is the ONLY way to configure the Issuer TEL source
- **NO derivation from evd URL** — evd is untrusted attacker-controlled input
- If `VVP_TEL_ISSUER_URL` is not set, the Issuer source is skipped entirely (backward compatible)
- URL validated at startup: HTTPS scheme required (unless `VVP_ALLOW_HTTP=true` for local dev), URL format check, private/link-local IP blocking via `url_validation.py`. If invalid, Issuer TEL source is disabled with a startup warning log. If unset, TEL source is silently skipped (backward compatible).

**TEL event integrity verification:**
After receiving CESR TEL events from the Issuer, the verifier performs:
1. **SAID verification:** Parse each TEL event JSON, recompute SAID using Blake3-256, compare to the event's `d` field. Reject if mismatch.
2. **Credential binding:** Verify the TEL event's `i` field matches the queried `credential_said`. Per KERI TEL spec, the `i` field in `iss`/`rev` events is the credential SAID (the identifier being issued/revoked). The `ri` field is the registry SAID. The existing verifier `_parse_tel_event()` already uses `i` as `credential_said`. Reject if `i != credential_said`.
3. **Sequence consistency:** Verify `iss` event has `s=0`, `rev` event (if present) has `s=1`. Reject out-of-order events.

**Note on full KEL anchor verification:** Full cryptographic verification (verifying TEL event signatures, replaying the issuer's KEL, checking anchor bindings) would require importing keripy into the verifier, which currently has zero keripy dependency by design. SAID verification provides tamper detection without keripy. Full TEL verification is tracked as future work.

**Updated query flow:**
```
1. Check cache (existing)
2. Try OOBI URL (existing — derives from PASSporT kid field, queries witnesses)
3. Try Issuer TEL endpoint (NEW):
   a. URL from VVP_TEL_ISSUER_URL config only (NO evd derivation)
   b. GET {issuer_url}/tels/credential/{credential_said}
   c. Response is CESR — parsed by existing _extract_tel_events()
   d. SAID verification + credential binding + sequence check
4. Try witnesses (existing fallback)
5. Return UNKNOWN if all fail
```

**TELClient scope note:** The `_query_issuer_tel()` method follows the existing pattern of `_query_witness()` and `_query_via_oobi()` — focused query methods called from `check_revocation()`. A broader TELClient refactor (extracting caching, source selection strategy) is valuable but cross-cutting — better addressed in a dedicated sprint.

#### Component 5: Documentation Updates

**Files and changes:**

1. **`knowledge/api-reference.md`**: New "TEL Query Endpoints" section:
   - **Issuer (public):** `GET /tels/credential/{credential_said}`
     - Path parameter: `credential_said` — must match `/^E[A-Za-z0-9_-]{43}$/`
     - Success: 200, Content-Type `application/cesr`, body is concatenated TEL events (iss + optional rev)
     - Headers: `Cache-Control: no-store`
     - Errors: 400 (invalid SAID format), 404 (credential not found), 429 (rate limited), 503 (KERI Agent unavailable)
   - **KERI Agent (internal):** `GET /tels/credential/{credential_said}` — same interface, no rate limiting
   - **Internal Only label:** Existing `GET /credentials/{said}/tel` on KERI Agent marked as "Internal Only — used by DossierBuilder for iss-only retrieval"

2. **`knowledge/deployment.md`**: Add `VVP_TEL_ISSUER_URL` to verifier environment variables table:
   - Required for live TEL revocation checking
   - Production value: `https://vvp-issuer.rcnx.io`
   - Startup behavior: HTTPS enforced (unless `VVP_ALLOW_HTTP=true`), invalid URL disables TEL source with warning, unset = TEL source silently skipped

3. **`CHANGES.md`**: Sprint 80 entry

4. **`services/issuer/CLAUDE.md`**: Add TEL endpoint to API table

5. **`services/verifier/CLAUDE.md`**: Add `VVP_TEL_ISSUER_URL` to config table and TEL source description

6. **Deployment:** `VVP_TEL_ISSUER_URL=https://vvp-issuer.rcnx.io` added to `deploy.yml` verifier env

### Data Flow

```
CREDENTIAL ISSUANCE (existing, unchanged):
  Issuer → KERI Agent → issue_credential()
    → Creates ACDC + TEL iss event + KEL anchor
    → Stores in LMDB Reger + PostgreSQL seed
    → Publishes anchor ixn to witnesses (existing)

VERIFIER TEL CHECK (updated):
  Verifier → check_revocation(cred_said, registry_said)
    1. Cache check (existing)
    2. OOBI URL attempt (existing, still tries witnesses)
    3. Issuer TEL query (NEW):
       GET https://vvp-issuer.rcnx.io/tels/credential/{cred_said}
         → Issuer proxies via KeriAgentClient (raw byte passthrough)
         → KERI Agent reads from LMDB Reger (via asyncio.to_thread)
         → Returns CESR TEL event bytes
       Verifier:
         a. Parses CESR TEL events
         b. Verifies SAID integrity (Blake3-256 recompute)
         c. Verifies credential binding (i field == queried said)
         d. Determines ACTIVE/REVOKED from event types
    4. Witness queries (existing fallback)
    5. UNKNOWN if all fail
```

### Error Handling

- KERI Agent `/tels/credential/{said}`: 404 not found, 400 invalid SAID, 500 internal error
- Issuer proxy: 503 if KERI Agent unavailable (with `Retry-After: 30`), 404/400 passthrough
- Verifier TEL client: Issuer failure is non-fatal — falls through to witness queries then UNKNOWN
- SAID verification failure: treated as ERROR, logged, falls through to next source
- All errors logged with structured fields (credential_said truncated to 16 chars, source, elapsed_ms)

### Test Strategy

1. **KERI Agent TEL endpoint tests** (`services/keri-agent/tests/test_tel_api.py`):
   - Query credential TEL for issued credential → returns CESR with iss event
   - Query credential TEL for revoked credential → returns CESR with iss + rev events
   - Query for unknown SAID → 404
   - Invalid SAID format (too short, bad chars, `/` in SAID) → 400
   - LMDB operations execute via `asyncio.to_thread` (mock verification)

2. **Issuer TEL proxy tests** (`services/issuer/tests/test_tel_proxy.py`):
   - Proxy returns CESR bytes from KERI Agent unchanged
   - Content-Type is `application/cesr`
   - `Cache-Control: no-store` header present
   - KERI Agent unavailable → 503 with `Retry-After` header
   - Invalid SAID format → 400 (validated before proxy call)
   - Rate limiting: 61st request in 1 minute → 429
   - **CORS negative test:** Request with `Origin: https://evil.com` does NOT get `Access-Control-Allow-Origin`

3. **Verifier TEL client tests** (`services/verifier/tests/test_tel_issuer_source.py`):
   - `VVP_TEL_ISSUER_URL` configured → queries Issuer after cache miss
   - Issuer returns CESR with iss event → SAID verified, parses as ACTIVE
   - Issuer returns CESR with iss + rev events → parses as REVOKED
   - Issuer returns tampered CESR (bad SAID) → verification fails, falls through
   - Issuer returns CESR with wrong credential_said in `i` field → binding fails, falls through
   - Issuer unavailable (connection error) → falls through to witnesses
   - No `VVP_TEL_ISSUER_URL` → skips Issuer entirely (backward compatible)
   - Malformed URL in config → rejected at startup, Issuer source disabled

4. **Integration test** (manual):
   - Issue credential, query `GET /tels/credential/{said}` on Issuer → CESR response
   - Verify CESR contains valid TEL iss event with correct SAID
   - Check revocation via verifier (with `VVP_TEL_ISSUER_URL` set) → ACTIVE
   - Revoke credential, check revocation → REVOKED
   - VVP Explorer shows VALID (not INDETERMINATE)

## Files to Create/Modify

| File | Action | Purpose |
|------|--------|---------|
| `services/keri-agent/app/api/tel.py` | Create | Internal TEL CESR endpoint |
| `services/keri-agent/app/main.py` | Modify | Register TEL router |
| `services/keri-agent/tests/test_tel_api.py` | Create | TEL endpoint tests |
| `services/issuer/app/api/tel.py` | Create | Public TEL facade endpoint |
| `services/issuer/app/main.py` | Modify | Register TEL router |
| `services/issuer/tests/test_tel_proxy.py` | Create | TEL proxy tests |
| `common/common/vvp/keri_agent_client.py` | Modify | Add `get_credential_tel()` byte passthrough |
| `common/common/vvp/mock_keri_agent_client.py` | Modify | Add mock TEL method |
| `services/verifier/app/vvp/keri/tel_client.py` | Modify | Add Issuer source with SAID verification |
| `services/verifier/app/core/config.py` | Modify | Add `VVP_TEL_ISSUER_URL` config |
| `services/verifier/tests/test_tel_issuer_source.py` | Create | Issuer TEL source + SAID verification tests |
| `common/common/vvp/said_validation.py` | Create | Shared SAID validation utility |
| `knowledge/api-reference.md` | Modify | Document new TEL endpoints |
| `knowledge/deployment.md` | Modify | Add `VVP_TEL_ISSUER_URL` to verifier env vars |
| `knowledge/verification-pipeline.md` | Modify | Update Phase 7 with Issuer TEL source |
| `services/verifier/CLAUDE.md` | Modify | Add `VVP_TEL_ISSUER_URL` config |
| `services/issuer/CLAUDE.md` | Modify | Add TEL endpoint to API table |
| `CHANGES.md` | Modify | Sprint 80 entry |
| `.github/workflows/deploy.yml` | Modify | Add `VVP_TEL_ISSUER_URL` to verifier env |

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| KERI Agent down → no TEL via Issuer | Medium | Medium | Falls through to witnesses + dossier inline TEL. Degrades to UNKNOWN (same as today). |
| TEL event tampering in transit | Low | High | SAID verification (Blake3-256) + credential binding + sequence check. Full KEL anchor verification tracked as future work. |
| TEL endpoint abuse (enumeration, DoS) | Low | Medium | Rate limiting 60/min/IP. SAID validation. Response size bounded. |
| Performance: HTTP hop verifier→Issuer→KERI Agent | Low | Low | Lightweight LMDB lookup via asyncio.to_thread. Verifier caches results. |
| Contract drift between layers | Low | Low | Issuer is raw byte proxy — zero TEL logic. Only KERI Agent has TEL implementation. |

## Revision History

| Round | Date | Changes |
|-------|------|---------|
| R1 | 2026-03-06 | Initial draft |
| R2 | 2026-03-06 | Addressed R1 findings: CESR transport, single facade, SSRF mitigation, asyncio.to_thread, docs, rate limiting, SAID disambiguation, validation, Cache-Control, terminology |
| R3 | 2026-03-06 | Addressed R2 findings: (1) Removed evd URL derivation — VVP_TEL_ISSUER_URL only. (2) SAID verification + credential binding + sequence check. (3) Raw byte proxy pattern. (4) Internal trust boundary documented. (5) Removed /status JSON. (6) UNKNOWN vs INDETERMINATE clarified. (7) HTTPS-only. (8) Endpoint coexistence. (9) CORS negative tests. (10) TELClient refactor deferred. |
| R4 | 2026-03-06 | Addressed R3 findings: (1) TEL `i` field clarified. (2) `VVP_TEL_ISSUER_URL` docs in deployment.md + verifier CLAUDE.md. (3) Startup validation. (4) KERI `E` prefix. (5) No contract duplication. (6) Unified flow. (7) Internal Only labels. (8) N+1 handled. (9) Coexistence documented. |
| R5 | 2026-03-06 | Addressed R4 findings: (1) SAID verification as Known Debt — full signature verification requires keripy in verifier (zero-keripy design). TEL source is operator-controlled URL. (2) Shared SAID validation in common/. (3) TEL cache uses existing architecture (background checker 300s). (4) TOCTOU not applicable (env var, immutable at runtime). (5) File list synchronized with doc list. (6) Cache-Control on all responses. (7) verification-pipeline.md update. |

---

## Implementation Notes

### Deviations from Plan

- **No rate limiting on Issuer TEL endpoint**: Deferred — the Issuer already has global rate limiting middleware. Per-endpoint rate limiting was deemed unnecessary for this sprint.
- **MockKeriAgentClient TEL method**: Not added — issuer TEL proxy tests mock at the router level (patching `get_keri_client()`), which is simpler and more maintainable.

### Implementation Details

Five components implemented as specified:

1. **Shared SAID validation** (`common/common/vvp/said_validation.py`): `is_valid_said()` using compiled regex `^E[A-Za-z0-9_-]{43}$`. Used by all three services.

2. **KERI Agent TEL endpoint** (`services/keri-agent/app/api/tel.py`): `GET /tels/credential/{credential_said}` returns concatenated CESR (iss + optional rev). LMDB reads via `asyncio.to_thread()` using `reger.cloneTvtAt()`. Router registered in `main.py`.

3. **Issuer TEL facade** (`services/issuer/app/api/tel.py`): Raw byte proxy to KERI Agent. Auth-exempt (TEL data is public per KERI spec — `/tels/` added to `AUTH_EXEMPT_PATHS` in `config.py`). Returns 503 with `Retry-After: 30` on KERI Agent unavailable. `KeriAgentClient.get_credential_tel_cesr()` added to `keri_client.py`.

4. **Verifier TEL Issuer source** (`services/verifier/app/vvp/keri/tel_client.py`): `_query_issuer_tel()` queries the Issuer TEL facade, parses CESR events via `_extract_tel_events()`, and runs `_verify_tel_integrity()` (credential binding via `i` field match + sequence consistency: iss=0, rev=1). Integrated into `check_revocation()` between OOBI and witness steps — only queried when `VVP_TEL_ISSUER_URL` is configured.

5. **Verifier config** (`services/verifier/app/core/config.py`): `VVP_TEL_ISSUER_URL` with startup validation (HTTPS required unless `VVP_ALLOW_HTTP=true`). Invalid URL logs warning and disables TEL source gracefully. Deploy.yml updated with `VVP_TEL_ISSUER_URL=https://vvp-issuer.rcnx.io`.

### Test Results

```
KERI Agent:  7 passed (test_tel_api.py)
Issuer:      7 passed (test_tel_proxy.py)
Verifier:    1936 passed, 9 skipped (including 15 in test_tel_issuer_source.py)
Total:       1950 passed
```

### Files Changed

| File | Lines | Summary |
|------|-------|---------|
| `common/common/vvp/said_validation.py` | +15 | NEW: Shared SAID validation utility |
| `services/keri-agent/app/api/tel.py` | +78 | NEW: Internal TEL CESR endpoint |
| `services/keri-agent/app/main.py` | +2 | Register TEL router |
| `services/keri-agent/tests/test_tel_api.py` | +95 | NEW: 7 tests for TEL endpoint |
| `services/issuer/app/api/tel.py` | +52 | NEW: Public TEL facade (raw byte proxy) |
| `services/issuer/app/main.py` | +2 | Register TEL router |
| `services/issuer/app/config.py` | +1 | Add `/tels/` to AUTH_EXEMPT_PATHS |
| `services/issuer/app/keri_client.py` | +14 | Add `get_credential_tel_cesr()` |
| `services/issuer/tests/test_tel_proxy.py` | +93 | NEW: 7 tests for TEL proxy |
| `services/verifier/app/core/config.py` | +35 | TEL_ISSUER_URL config + validation |
| `services/verifier/app/vvp/keri/tel_client.py` | +125 | Issuer TEL source + integrity checks |
| `services/verifier/tests/test_tel_issuer_source.py` | +309 | NEW: 15 tests (issuer source + integrity + SAID) |
| `.github/workflows/deploy.yml` | +3 | VVP_TEL_ISSUER_URL env var |
