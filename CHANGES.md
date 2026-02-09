# VVP Verifier Change Log

## Sprint 53: E2E System Validation & Cache Timing

**Date:** 2026-02-09
**Status:** APPROVED (Pair Review — 6 plan revisions, 1 code review round)

### Summary

Validated the full VVP system health check and SIP call test scripts against production. Added timing instrumentation (`--timing`, `--timing-count`, `--timing-threshold`, `--test chain`) to measure cache effectiveness via chained sign→verify mode. Fixed a pre-existing bug in SIP redirect that silently dropped P-VVP-Identity and P-VVP-Passport headers. Created a bootstrap script for complete issuer asset provisioning after LMDB/Postgres recovery.

### Files Created

| File | Description |
|------|-------------|
| `scripts/bootstrap-issuer.py` | 5-step bootstrap: reinit mock vLEI → create org → API key → TN allocation → TN mapping |
| `scripts/test_sip_call_test.py` | 21 CLI regression tests for timing flags, chain mode, JSON schema |

### Files Modified

| File | Changes |
|------|---------|
| `scripts/sip-call-test.py` | Added `--timing`, `--timing-count`, `--timing-threshold`, `--timing-delay`, `--test chain`, `--verifier-url`, cache metrics snapshot, chained sign→verify timing |
| `scripts/system-health-check.sh` | Added `--timing` flag, `_run_timing_tests()` for Phase 4, timing in JSON output |
| `services/issuer/app/api/admin.py` | Added `POST /admin/mock-vlei/reinitialize` — clears 6 tables, resets singleton, re-initializes infrastructure |
| `services/sip-redirect/app/redirect/client.py` | Fixed VVP header field names: `vvp_identity` → `vvp_identity_header`, `passport` → `passport_jwt` |
| `services/pbx/config/public-sip.xml` | Updated loopback dialplan API key to match bootstrapped org key |
| `services/issuer/config/api_keys.json` | Updated dev-admin key hash |

### Key Results

- **Sign test:** 302 VALID with P-VVP-Identity, P-VVP-Passport, P-VVP-Brand-Name headers
- **Verify test:** Verifier responds to SIP verification requests
- **Chain timing:** 3.0x speedup (cold=42ms, cached=14ms)
- **Issuer unit tests:** 422 tests pass
- **CLI regression tests:** 21 tests pass

### Bug Fix: SIP Redirect VVP Header Extraction

The sip-redirect client extracted `data.get("vvp_identity")` and `data.get("passport")` from the issuer `/vvp/create` response, but the issuer returns `vvp_identity_header` and `passport_jwt`. This caused P-VVP-Identity and P-VVP-Passport headers to be silently `None` in all 302 redirect responses.

### Additional Files Modified (Post-Archival Fixes)

| File | Changes |
|------|---------|
| `.github/workflows/deploy.yml` | Combined deploy+restart into single `az vm run-command` to avoid serialization conflict; changed version verification from external curl to `az vm run-command` with `localhost:8085`; added 15s sleep before verification |
| `scripts/system-health-check.sh` | Fixed SIP-Redirect health check to use `pbx_run` with `localhost:8085` instead of external curl; batched PBX checks into single `az vm run-command` calls; added retry logic with 15s backoff; fixed macOS `base64` compatibility |
| `services/sip-redirect/app/redirect/handler.py` | Upgraded monitoring log levels (debug→error with traceback for failures, added info log for successful captures) |
| `services/sip-redirect/app/sip/transport.py` | INVITE transaction deduplication (Sprint 53 fix for retransmission race) |
| `services/pbx/config/public-sip.xml` | Extended SIP Timer B timeout to 35s, updated loopback dialplan API key |

### Bug Fix: CI/CD SIP Redirect Deploy Verification

The deploy pipeline verified the SIP redirect version by curling `http://pbx.rcnx.io:8080/version` externally. This failed because: (a) the status server listens on port 8085 (`VVP_STATUS_HTTP_PORT=8085`), not 8080 (occupied by FusionPBX PHP); (b) port 8085 is not exposed through Azure NSG. Fixed by using `az vm run-command` with `localhost:8085`.

### Bug Fix: Azure VM Run-Command Serialization

Azure allows only one `az vm run-command` per VM at a time. The deploy pipeline had separate steps for "deploy code" and "update systemd + restart", causing the second to fail with `Conflict`. Fixed by combining into a single run-command. Same issue in `system-health-check.sh` fixed by batching PBX checks and adding retry logic.

### Commits

- `6389b8b` — Sprint 53: Add cache timing instrumentation and CLI regression tests
- `a142c61` — Add admin mock-vlei reinitialize endpoint and issuer bootstrap script
- `ca8e54f` — Fix SIP redirect VVP header extraction and enhance bootstrap script
- `1b000f7` — Fix loopback call: INVITE deduplication, correct PSTN numbers
- `293d091` — Add OVC brand logo to issuer static assets
- `c801e57` — Fix issuer deploy: deactivate ALL active revisions, not just traffic>0
- `c7f440e` — Fix SIP redirect deploy verification: use correct port via az CLI
- `58e1971` — Fix SIP redirect deploy: combine VM commands to avoid serialization conflict
- `c8bada0` — Fix system health check: correct PBX port, batch az commands, fix macOS base64

---

## Sprint 51: Verification Result Caching

**Date:** 2026-02-08
**Status:** APPROVED (Pair Review — 11 plan revisions, 2 code review rounds)

### Summary

Cache dossier-derived verification artifacts (chain validation, ACDC signatures, revocation status) keyed by `(dossier_url, passport_kid)`. On cache hit, skip expensive Phases 5, 5.5, and 9 while always re-running per-request phases (PASSporT validation, authorization, SIP context, brand, vetter constraints). VALID-only caching policy prevents sticky failures from transient conditions.

Background revocation checker re-checks credential status asynchronously via TEL, updating all kid variants atomically. Stale revocation data produces INDETERMINATE per §5C.2.

### Files Created

| File | Description |
|------|-------------|
| `services/verifier/app/vvp/verification_cache.py` | VerificationResultCache, CachedDossierVerification, RevocationStatus, config fingerprint, metrics |
| `services/verifier/app/vvp/revocation_checker.py` | BackgroundRevocationChecker with URL-deduped async queue |
| `services/verifier/tests/test_verification_cache.py` | 28 unit tests for cache operations |
| `services/verifier/tests/test_background_revocation_checker.py` | 7 unit tests for revocation worker |
| `services/verifier/tests/test_verify_caching.py` | 16 integration tests for cache-first verify_vvp() flow |

### Files Modified

| File | Changes |
|------|---------|
| `services/verifier/app/vvp/verify.py` | Cache-first flow after Phase 4; conditional guards on Phases 5, 5.5, 9; cache storage on VALID chain result |
| `services/verifier/app/vvp/api_models.py` | Added `revocation_pending` field to VerifyResponse |
| `services/verifier/app/core/config.py` | 5 config constants: CACHE_ENABLED, MAX_ENTRIES, TTL, RECHECK_INTERVAL, CHECK_CONCURRENCY |
| `services/verifier/app/main.py` | Lifespan context manager for background revocation worker |
| `services/verifier/tests/conftest.py` | Reset verification cache + revocation checker singletons |
| `services/verifier/tests/vectors/conftest.py` | Same reset additions |

### Test Results

1803 tests passed, 0 failures, 9 skipped (51 new tests).

### Commits

- `45c34b2` — Sprint 51: Verification result cache with background revocation
- `2188561` — Sprint 51: Fix code review findings — TEL API + concurrency config
- `609a8b0` — Sprint 51: Archive plan, update CHANGES.md and SPRINTS.md

---

## Sprint 52: Central Service Dashboard

**Date:** 2026-02-08
**Status:** APPROVED (Pair Review)

### Summary

Added a central service dashboard to the issuer service at `/ui/dashboard` that aggregates health from all VVP services (verifier, issuer, witnesses, SIP redirect, SIP verify) via a backend proxy endpoint. Features configurable per-service health paths, 2xx acceptance, safe JSON parsing, parallel checks with timeout, and 30-second auto-refresh UI.

### Files Created

| File | Description |
|------|-------------|
| `services/issuer/app/api/dashboard.py` | Health aggregation API with parallel httpx checks |
| `services/issuer/web/dashboard.html` | Dashboard UI with auto-refresh and grouped service cards |
| `services/issuer/tests/test_dashboard.py` | 23 tests (unit + integration) |

### Files Modified

| File | Description |
|------|-------------|
| `services/issuer/app/config.py` | Dashboard env vars (VVP_DASHBOARD_SERVICES, SIP URLs, timeout) + auth exemption |
| `services/issuer/app/main.py` | Dashboard router + /ui/dashboard route registration |
| `services/issuer/web/index.html` | Added "Dashboard" nav link |

### Key Features

- **Configurable services**: JSON array env var with per-service name, URL, health_path, category
- **2xx acceptance**: Any 2xx status treated as healthy (not just 200)
- **Safe JSON parsing**: Non-JSON health responses don't crash — version stays null
- **URL normalization**: Handles trailing/leading slash edge cases
- **Auth alignment**: Follows existing UI_AUTH_ENABLED pattern (Microsoft SSO, password, API key)

### Test Results

```
23 passed (test_dashboard.py)
422 passed, 5 skipped (full issuer suite)
```

### Commits

- `dc118a9` Sprint 52: Central Service Dashboard
- `32aecb2` Sprint 52: HTML-escape dynamic content in dashboard cards

---

## Sprint 34: Schema Management

**Date:** 2026-02-01
**Status:** APPROVED (Pair Review)

### Summary

Added schema management capabilities to VVP Issuer: SAID computation using keripy's `Saider.saidify()`, schema import from WebOfTrust/schema repository with version pinning, user schema storage with metadata handling, and enhanced UI with import/create/verify functionality.

### Files Created

| File | Description |
|------|-------------|
| `services/issuer/app/schema/said.py` | SAID computation module using keripy Saider |
| `services/issuer/app/schema/importer.py` | WebOfTrust schema import service |
| `services/issuer/app/schema/__init__.py` | Module exports |
| `services/issuer/tests/test_said.py` | SAID computation tests (19 tests) |
| `services/issuer/tests/test_import.py` | Import service tests (14 tests) |
| `services/issuer/app/Documentation/PLAN_Sprint34.md` | Archived plan |

### Files Modified

| File | Description |
|------|-------------|
| `services/issuer/app/schema/store.py` | Added user schema storage, metadata stripping |
| `services/issuer/app/api/schema.py` | Added import/create/delete/verify endpoints |
| `services/issuer/app/api/models.py` | Added request/response models for new endpoints |
| `services/issuer/web/schemas.html` | Enhanced UI with tabbed interface |
| `services/issuer/tests/test_schema.py` | Added metadata stripping and verify tests |
| `SPRINTS.md` | Added Sprint 34 definition |

### Key Features

- **SAID Computation**: Uses `keri.core.coring.Saider.saidify()` for KERI-compliant SAIDs
- **Version Pinning**: `VVP_SCHEMA_REPO_REF` env var to pin WebOfTrust repo version
- **Metadata Handling**: `_source` field stored separately, stripped before verification
- **Storage Separation**: Embedded (read-only) vs user-added (writable) schemas

### New API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/schema/weboftrust/registry` | GET | List schemas in WebOfTrust registry |
| `/schema/import` | POST | Import schema from URL or WebOfTrust |
| `/schema/create` | POST | Create new schema with auto-SAID |
| `/schema/{said}` | DELETE | Remove user-added schema |
| `/schema/{said}/verify` | GET | Verify schema SAID |

### Test Results

```
tests/test_schema.py - 13 passed
tests/test_said.py - 19 passed
tests/test_import.py - 14 passed, 1 skipped
Total: 47 passed, 1 skipped
```

---

## Sprint 27: Local Witness Infrastructure

**Date:** 2026-01-31
**Status:** APPROVED (Pair Review)

### Summary

Set up local KERI witness infrastructure for VVP Issuer development. Uses `gleif/keri:latest` Docker image with `kli witness demo` to run three deterministic demo witnesses (wan, wil, wes). Added environment variable override for verifier to use local witnesses instead of Provenant staging.

### Files Created

| File | Description |
|------|-------------|
| `docker-compose.yml` | Docker orchestration for witnesses + optional verifier |
| `scripts/local-witnesses.sh` | Start/stop script with health checks |
| `services/issuer/config/witnesses.json` | Witness config for Sprint 28 issuer |
| `services/issuer/config/.gitkeep` | Placeholder for git |
| `services/verifier/tests/test_local_witnesses.py` | Integration tests |
| `services/verifier/app/Documentation/PLAN_Sprint27.md` | Archived plan |

### Files Modified

| File | Description |
|------|-------------|
| `services/verifier/app/core/config.py` | Added `VVP_LOCAL_WITNESS_URLS` env var support |
| `SPRINTS.md` | Fixed port documentation, updated exit criteria |

### Known Witness AIDs

| Name | AID | HTTP Port |
|------|-----|-----------|
| wan | `BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha` | 5642 |
| wil | `BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM` | 5643 |
| wes | `BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX` | 5644 |

### Usage

```bash
# Start local witnesses
./scripts/local-witnesses.sh start

# Configure verifier for local witnesses
export VVP_LOCAL_WITNESS_URLS=http://127.0.0.1:5642,http://127.0.0.1:5643,http://127.0.0.1:5644

# Verify OOBI endpoint
curl http://127.0.0.1:5642/oobi/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha/controller
```

---

## Phase 0: Monorepo Refactoring (Foundation)

**Date:** 2026-01-31
**Status:** APPROVED (Pair Review)

### Summary

Created shared `common/` package to enable code sharing between verifier and future issuer services. This is the foundation for the VVP-Issuer service that will add credential issuance capabilities.

### Files Created

| File | Description |
|------|-------------|
| `common/__init__.py` | Package root |
| `common/vvp/__init__.py` | VVP namespace |
| `common/vvp/core/__init__.py` | Core exports |
| `common/vvp/core/exceptions.py` | VVPError, ACDCError, KeriError, DossierError |
| `common/vvp/core/logging.py` | JsonFormatter, configure_logging() |
| `common/vvp/models/__init__.py` | Model exports |
| `common/vvp/models/acdc.py` | ACDC, ACDCChainResult dataclasses |
| `common/vvp/models/dossier.py` | DossierDAG, ACDCNode, ToIPWarningCode |
| `common/vvp/canonical/__init__.py` | Canonical serialization exports |
| `common/vvp/canonical/keri_canonical.py` | FIELD_ORDER, canonical_serialize() |
| `common/vvp/schema/__init__.py` | Schema registry exports |
| `common/vvp/schema/registry.py` | KNOWN_SCHEMA_SAIDS, is_known_schema() |
| `common/vvp/utils/__init__.py` | Utility exports |
| `common/vvp/utils/tn_utils.py` | TNRange, parse_tn_allocation(), is_subset() |
| `common/pyproject.toml` | Package configuration |

### Files Modified (Compatibility Shims)

| File | Description |
|------|-------------|
| `app/vvp/acdc/models.py` | Re-exports from common.vvp.models.acdc |
| `app/vvp/dossier/models.py` | Re-exports from common.vvp.models.dossier |
| `app/vvp/acdc/schema_registry.py` | Re-exports from common.vvp.schema.registry |
| `app/vvp/acdc/exceptions.py` | Re-exports from common.vvp.core.exceptions |
| `app/vvp/keri/keri_canonical.py` | Re-exports from common.vvp.canonical.keri_canonical |
| `app/logging_config.py` | Re-exports from common.vvp.core.logging |
| `app/vvp/tn_utils.py` | Re-exports from common.vvp.utils.tn_utils |

### Files Modified (Direct Imports)

| File | Description |
|------|-------------|
| `app/main.py` | Uses common.vvp.core.logging |
| `app/vvp/authorization.py` | Uses common.vvp.models, common.vvp.utils.tn_utils |
| `app/vvp/ui/credential_viewmodel.py` | Uses common.vvp.models, common.vvp.schema.registry |

### Documentation

| File | Description |
|------|-------------|
| `app/Documentation/PLAN_VVP_Issuer_Infrastructure.md` | Full 6-phase implementation plan |

### Key Decisions

- **Compatibility shims** allow gradual migration without breaking existing imports
- **API models kept verifier-specific** - ClaimStatus/ErrorCode remain in `app/vvp/api_models.py`
- **Shared code only** - Models, canonical serialization, schema registry, utilities extracted

### Test Results

- All 1564 tests pass (17.09s)
- No import errors

---

## Sprint 25: External SAID Resolution from Witnesses

**Date:** 2026-01-28
**Commit:** 5cd969f

### Files Changed

| File | Action | Description |
|------|--------|-------------|
| `app/core/config.py` | Modified | Added 5 configuration constants for external SAID resolution feature |
| `app/vvp/keri/credential_cache.py` | Created | Credential-specific LRU cache with TTL expiration |
| `app/vvp/keri/credential_resolver.py` | Created | CredentialResolver class for fetching missing credentials from witnesses |
| `app/vvp/acdc/verifier.py` | Modified | Integrated resolver into chain validation, made walk_chain() async |
| `app/vvp/verify.py` | Modified | Pass resolver and witness URLs when feature enabled |
| `app/vvp/keri/__init__.py` | Modified | Export new credential resolver and cache components |
| `tests/test_credential_cache.py` | Created | Unit tests for credential cache (LRU eviction, TTL, metrics) |
| `tests/test_credential_resolver.py` | Created | Unit tests for resolver with mocked HTTP |
| `tests/test_acdc.py` | Modified | Integration tests for external resolution |
| `app/Documentation/PLAN_ExternalSAIDResolution.md` | Created | Archived implementation plan |

### Summary

Implemented external SAID resolution to fetch missing credentials from KERI witnesses when compact ACDCs have edge references not included in the dossier. Per VVP §2.2, instead of immediately returning INDETERMINATE, the verifier now attempts to resolve external credentials from witnesses.

**Key Features:**

1. **Configuration (opt-in, disabled by default):**
   - `VVP_EXTERNAL_SAID_RESOLUTION` - Enable/disable feature
   - `VVP_EXTERNAL_SAID_TIMEOUT` - HTTP timeout (default: 5.0s)
   - `VVP_EXTERNAL_SAID_MAX_DEPTH` - Max recursion depth (default: 3)
   - `VVP_EXTERNAL_SAID_CACHE_TTL` - Cache TTL (default: 300s)
   - `VVP_EXTERNAL_SAID_CACHE_MAX_ENTRIES` - Cache max size (default: 500)

2. **CredentialResolver Module:**
   - Fetches credentials from `/credentials/{said}` witness endpoints
   - Parallel witness queries (up to 3) for faster resolution
   - Recursion guard prevents infinite loops
   - Metrics tracking (attempts, successes, failures, cache hits)

3. **CredentialCache Module:**
   - LRU eviction when max_entries exceeded
   - TTL-based expiration
   - Singleton pattern with get/reset functions
   - Cache metrics (hits, misses, evictions, expirations)

4. **Verifier Integration:**
   - `walk_chain()` made async to support async resolution
   - Resolution attempted before INDETERMINATE fallback
   - Resolved credentials added to `dossier_acdcs` for continued validation
   - **Signature verification** for resolved credentials with signatures
   - Resolved credentials without signatures → INDETERMINATE

5. **Error Handling:**
   - Network/timeout errors → INDETERMINATE
   - SAID mismatch → INDETERMINATE
   - Key resolution failed → INDETERMINATE
   - Signature invalid → **INVALID** (cryptographic failure)
   - No signature present → INDETERMINATE
   - Recursion limit → INDETERMINATE

6. **CESR Response Parsing:**
   - Uses `parse_cesr_stream()` for proper CESR attachment handling
   - Extracts controller signatures from `-A` attachments
   - Falls back to plain JSON if CESR parsing fails

**Design Decisions:**

- Feature disabled by default to avoid unexpected network calls
- Separated from TEL client (different concern: credential fetching vs revocation)
- Externally resolved credentials with signatures are cryptographically verified
- Externally resolved credentials without signatures produce INDETERMINATE (not VALID)
- Only signature verification failure produces INVALID; all other failures are recoverable

### Spec References

- §2.2: "Uncertainty must be explicit" - INDETERMINATE when verification cannot determine status
- §1.4: Verifiers MUST support ACDC variants (compact, partial, aggregate)
- §6.3.x: Credential chain validation rules

### Code Review

- **Initial review:** CHANGES_REQUESTED - missing signature verification, CESR parsing issues, cache config not wired
- **Follow-up #1:** CHANGES_REQUESTED - signature verification for credentials WITH signatures still missing
- **Follow-up #2:** APPROVED - all issues addressed

### Test Results

```
1463 passed in 99.32s
```

---

## Completing Tier 2 KERI Verification

**Date:** 2026-01-28
**Commit:** 239af25

### Files Changed

| File | Action | Description |
|------|--------|-------------|
| `app/vvp/keri/kel_parser.py` | Modified | Flip defaults to `use_canonical=True`, `validate_saids=True`; add `compute_kel_event_said()` routing; fix key decoding for CESR qb64 lead bytes |
| `app/vvp/keri/cesr.py` | Modified | Binary CESR parsing, -D/-V attachment handling, counter table, framing validation, signature lead byte fix |
| `app/vvp/keri/keri_canonical.py` | Modified | Version string validation |
| `app/vvp/keri/kel_resolver.py` | Modified | Remove TEST-ONLY warnings, update docstrings |
| `app/vvp/keri/signature.py` | Modified | Remove TEST-ONLY warnings |
| `app/vvp/keri/exceptions.py` | Modified | Add `CESRFramingError`, `CESRMalformedError`, `UnsupportedSerializationKind` |
| `app/core/config.py` | Modified | Add `TIER2_KEL_RESOLUTION_ENABLED` env var support |
| `app/vvp/acdc/parser.py` | Modified | Document ACDC SAID computation |
| `app/vvp/acdc/schema_fetcher.py` | Modified | Document schema SAID (sorted keys is correct) |
| `tests/test_cesr_negative.py` | Created | Negative tests for CESR framing/counter errors |
| `tests/test_keripy_integration.py` | Created | 23 golden tests comparing to keripy reference |
| `tests/test_witness_receipts.py` | Modified | Fix CESR B-prefix encoding for test keypairs |
| `tests/test_kel_integration.py` | Modified | Fix CESR B-prefix encoding for test keypairs |
| `tests/fixtures/keri/binary_kel.json` | Created | Binary CESR KEL stream with signatures |
| `tests/fixtures/keri/witness_receipts_keripy.json` | Created | Witness receipts fixture with valid signatures |
| `scripts/generate_keripy_fixtures.py` | Created | Fixture generation script using vendored keripy |
| `app/Documentation/PLAN_Tier2Completion.md` | Created | Archived implementation plan |

### Summary

Completed Tier 2 KERI verification capabilities, enabling production-grade KERI witness integration.

**Phase 1: Canonicalization Foundation**
- Flipped `validate_kel_chain()` defaults to safe values (`use_canonical=True`, `validate_saids=True`)
- Added explicit `compute_kel_event_said()` to separate KEL from ACDC SAID computation
- Documented SAID computation differences (KEL uses field ordering, schemas use sorted keys)

**Phase 2: CESR Binary Support**
- Implemented version string parser with deterministic MGPK/CBOR rejection
- Completed -D transferable receipt quadruple parsing
- Completed -V/-\-V attachment group parsing with framing validation
- Added comprehensive negative tests for CESR error conditions

**Phase 3: Production Enablement**
- Removed TEST-ONLY warnings from `kel_resolver.py` and `signature.py`
- Added `TIER2_KEL_RESOLUTION_ENABLED` environment variable support
- Production mode now uses strict validation by default

**Phase 4: Golden Fixtures**
- Created fixture generation script using vendored keripy (v2.0.0-dev5)
- Generated binary CESR fixtures with real Ed25519 signatures
- Fixed CESR signature decoding: strip 2 lead bytes from indexed signatures (88-char qb64 → 66 bytes → 64-byte sig)
- Fixed KERI key decoding: handle CESR qb64 lead bytes (0x04 for B-prefix, 0x0c for D-prefix)
- Added witness receipts fixture with properly signed receipts
- Fixed test helpers to use proper CESR B-prefix encoding (`0x04 || public_key`)

**Key Technical Details:**

1. **CESR Indexed Signatures**: 88-char qb64 decodes to 66 bytes; first 2 are code/index, remaining 64 are Ed25519 signature
2. **CESR Key Lead Bytes**: B-prefix (Ed25519N) uses 0x04, D-prefix (Ed25519) uses 0x0c
3. **Rotation Signing**: Rotation events signed by PRIOR key, not new key

### Test Results

```
1408 passed, 19 warnings in 97.81s
```

### Review History

- Phase 1: APPROVED
- Phase 2: APPROVED
- Phase 3: APPROVED
- Phase 4 Rev 0: CHANGES_REQUESTED - Rotation key fix, validate_kel_chain test
- Phase 4 Rev 1: CHANGES_REQUESTED - CESR signature/key lead byte handling
- Phase 4 Rev 2: APPROVED - All fixes applied

---

## AID to Identity Resolution Enhancement

**Date:** 2026-01-27
**Commit:** d0b7cb1

### Files Changed

| File | Action | Description |
|------|--------|-------------|
| `app/vvp/identity.py` | Created | Core identity extraction module with configurable well-known AIDs registry, `IssuerIdentity` dataclass, `build_issuer_identity_map()` function |
| `app/vvp/api_models.py` | Modified | Added `IssuerIdentityInfo` model and `issuer_identities` field to `VerifyResponse` |
| `app/vvp/verify.py` | Modified | Integrated identity extraction after Phase 5.5, includes delegation chain AIDs via well-known lookup |
| `app/vvp/ui/credential_viewmodel.py` | Modified | Expanded `VCardInfo` with FN, ADR, TEL, EMAIL, URL fields; imports from `identity.py` to avoid duplication |
| `tests/test_identity.py` | Created | 22 unit tests for identity extraction, well-known resolution, lids field handling, vCard ORG fallback |
| `tests/test_credential_viewmodel.py` | Modified | Added 9 new tests for expanded vCard field parsing |
| `app/Documentation/PLAN_AID_Identity_Resolution.md` | Created | Archived implementation plan |

### Summary

Exposed semantic identity (legal name, LEI) of credential issuers in the API response. Per KERI design, an AID alone represents cryptographic control, not semantic identity. This enhancement extracts identity from LE credentials in the dossier and includes it in `VerifyResponse.issuer_identities`.

**Key Features:**

1. **API Response Extension:**
   - `IssuerIdentityInfo` model with `aid`, `legal_name`, `lei`, `source_said`, `identity_source`
   - `VerifyResponse.issuer_identities` optional field (None when no dossier present)
   - `identity_source`: "dossier" (from credentials including vCard) vs "wellknown" (static registry)

2. **Identity Extraction Module (`app/vvp/identity.py`):**
   - Decoupled from UI layer for use in core verification flow
   - `build_issuer_identity_map()` extracts identity from LE credentials
   - Checks `legalName`, `LEI`, `lids` field (string, dict, list variants), and vCard ORG
   - `get_wellknown_identity()` provides fallback for root issuers

3. **Configurable Well-Known AIDs:**
   - `_DEFAULT_WELLKNOWN_AIDS` built-in registry (GLEIF, Provenant, etc.)
   - Overridable via `WELLKNOWN_AIDS_FILE` environment variable (JSON format)
   - Falls back to defaults on file not found or invalid JSON

4. **Delegation Chain Integration:**
   - Delegation chain AIDs included when dossier-sourced identity exists
   - Well-known lookup for delegation chain members not in dossier

5. **Expanded vCard Parsing:**
   - New fields: `fn` (full name), `adr` (address), `tel` (telephone), `email`, `url`
   - Case-insensitive field name parsing

**Design Decisions (per Reviewer):**

1. **Include delegation chain AIDs?** → Yes, optionally when dossier-sourced identity exists
2. **Add organization_type field?** → Deferred until normative source identified
3. **Well-known AIDs configurable?** → Yes, via `WELLKNOWN_AIDS_FILE` env var with built-in defaults

### Checklist Items Completed

- Identity extraction decoupled from UI layer
- API response extended with `issuer_identities` field (backwards compatible)
- vCard field extraction expanded per RFC 6350
- Well-known AIDs configurable via environment variable

### Test Results

```
1245 passed in 70.12s
```

### Review History

- Plan Rev 0: CHANGES_REQUESTED - Wrong function reference (`verify_vvp_identity()` → `verify_vvp()`)
- Plan Rev 1: APPROVED
- Code Rev: APPROVED

---

## ToIP Dossier Specification Warnings

**Date:** 2026-01-27
**Commit:** 3907254

### Files Changed

| File | Action | Description |
|------|--------|-------------|
| `app/vvp/dossier/models.py` | Modified | Added `ToIPWarningCode` enum (6 codes) and `DossierWarning` dataclass; added `warnings` field to `DossierDAG` |
| `app/vvp/dossier/validator.py` | Modified | Added `_collect_toip_warnings()` and 6 helper functions for warning detection |
| `app/vvp/dossier/__init__.py` | Modified | Exported `DossierWarning` and `ToIPWarningCode` |
| `app/vvp/api_models.py` | Modified | Added `ToIPWarningDetail` model and `toip_warnings` field to `VerifyResponse` |
| `app/vvp/verify.py` | Modified | Propagate DAG warnings to API response with logging |
| `app/Documentation/VVP_Verifier_Specification_v1.5.md` | Modified | Added §6.1C Edge Structure, §6.1D Dossier Versioning, updated §5A Step 8 |
| `tests/test_dossier.py` | Modified | Added `TestToIPWarnings` class with 15 test cases |
| `app/Documentation/PLAN_ToIP_Warnings.md` | Created | Archived implementation plan |

### Summary

Implemented non-blocking warnings for ToIP Verifiable Dossiers Specification v0.6 compliance. Where ToIP requirements are stricter than VVP, warnings are emitted but verification is not failed. This provides transparency for dossier producers without breaking compatibility.

**Warning Codes:**

| Code | Condition |
|------|-----------|
| `EDGE_MISSING_SCHEMA` | Edge has `n` but no `s` (schema SAID) |
| `EDGE_NON_OBJECT_FORMAT` | Edge is direct SAID string, not `{n,s}` object |
| `DOSSIER_HAS_ISSUEE` | Root dossier ACDC has issuee (`a.i`) or registry (`ri`) field |
| `DOSSIER_HAS_PREV_EDGE` | Dossier has `prev` edge indicating versioning |
| `EVIDENCE_IN_ATTRIBUTES` | Evidence-like data in attributes (`a`) instead of edges (`e`) |
| `JOINT_ISSUANCE_OPERATOR` | Joint issuance operators (`thr`/`fin`/`rev`) detected |

**Key Design Decisions:**

1. **Non-blocking warnings**: Warnings do not affect validation result per §6.1C-D
2. **DAG-level collection**: Warnings collected during `validate_dag()` and stored on `DossierDAG.warnings`
3. **API propagation**: Warnings serialized to `VerifyResponse.toip_warnings` as optional array
4. **Immutable warnings**: `DossierWarning` is a frozen dataclass for thread safety

**Spec Updates:**

- §6.1C Edge Structure: Documents ToIP edge format requirements and warning behavior
- §6.1D Dossier Versioning: Documents `prev` edge handling and SHOULD requirements
- §5A Step 8: Added two-layer verification model (cryptographic vs semantic)

### Checklist Items Completed

- ToIP warning infrastructure added to dossier validation layer
- API response extended with `toip_warnings` field (backwards compatible)
- VVP Specification v1.5 updated with new sections

### Test Results

```
1214 passed, 19 warnings in 66.90s
```

### Review History

- Rev 0: CHANGES_REQUESTED - Missing `prev` edge warning, no warning for direct SAID strings
- Rev 1: APPROVED - Added `DOSSIER_HAS_PREV_EDGE` and `EDGE_NON_OBJECT_FORMAT` codes

---

## Sprint 25: Delegation Chain UI Visibility

**Date:** 2026-01-27
**Commit:** d4df2ae

### Files Changed

| File | Action | Description |
|------|--------|-------------|
| `app/vvp/api_models.py` | Modified | Added `DelegationNodeResponse`, `DelegationChainResponse` models; extended `VerifyResponse` with `delegation_chain` and `signer_aid` fields |
| `app/vvp/keri/signature.py` | Modified | Refactored Tier 2 verification with shared `_verify_passport_signature_tier2_impl()`, added `verify_passport_signature_tier2_with_key_state()` |
| `app/vvp/keri/__init__.py` | Modified | Exported `verify_passport_signature_tier2_with_key_state` |
| `app/vvp/verify.py` | Modified | Added `_build_delegation_response()` helper, captures delegation chain and signer AID in verification flow |
| `app/vvp/ui/credential_viewmodel.py` | Modified | Added `build_delegation_chain_info()` function for API→UI view model conversion |
| `app/main.py` | Modified | Added `/ui/verify-result` endpoint with proper VVP-Identity header construction |
| `app/templates/partials/verify_result.html` | Created | Verification result template with delegation chain visualization |
| `tests/test_delegation_ui.py` | Created | 20 unit tests for delegation UI models and functions |
| `tests/test_verify.py` | Modified | Updated mocks for new `verify_passport_signature_tier2_with_key_state` function |
| `tests/test_dossier_cache.py` | Modified | Updated mocks for new function signature |
| `tests/vectors/runner.py` | Modified | Updated mocks for new function signature |
| `app/Documentation/PLAN_Sprint25.md` | Created | Archived implementation plan |

### Summary

Surfaces delegation chain information in the UI when verification results are available. The backend already computes delegation chain data during Tier 2 signature verification, but this data was previously lost.

**Key Features:**

1. **API Response Extension:**
   - `DelegationNodeResponse` model for individual chain nodes
   - `DelegationChainResponse` model for complete chain with validation status
   - `VerifyResponse.delegation_chain` optional field (backwards compatible)
   - `VerifyResponse.signer_aid` for credential-to-delegation mapping

2. **Tier 2 Verification Refactor:**
   - Shared `_verify_passport_signature_tier2_impl()` to avoid duplication
   - New `verify_passport_signature_tier2_with_key_state()` returns (KeyState, auth_status)
   - Proper INVALID vs INDETERMINATE status mapping based on authorization result

3. **Delegation Status Mapping (per reviewer feedback):**
   - `chain.valid=True, auth_status="VALID"` → VALID
   - `chain.valid=True, auth_status="INVALID"` → INVALID (definitive failure)
   - `chain.valid=True, auth_status="INDETERMINATE"` → INDETERMINATE (incomplete)
   - `chain.valid=False` → INVALID (chain structure invalid)

4. **UI Verify Result Endpoint (`/ui/verify-result`):**
   - Parses PASSporT JWT to extract `kid` and `iat` for VVP-Identity header (§5.2)
   - Performs full verification via `verify_vvp()`
   - Builds delegation_info and attaches to credentials where issuer == signer_aid
   - Returns delegation banner and chain visualization

5. **Credential-to-Delegation Mapping:**
   - Delegation applies to the PASSporT signer (kid AID)
   - Attached to credentials where issuer AID matches signer AID
   - Dossier-level banner shown when no credential matches

### Checklist Items Completed

- UI: Delegation chain visualization on verification results
- API: Delegation chain data in VerifyResponse
- Backend: Capture delegation data during Tier 2 verification

### Test Results

```
1198 passed, 20 warnings in 69.86s
```

### Review History

- Plan Rev 0: CHANGES_REQUESTED - Status mapping and credential mapping issues
- Plan Rev 1: APPROVED
- Code Rev 0: CHANGES_REQUESTED - VVP-Identity header used evd_url instead of kid
- Code Rev 1 (Sprint 25.1): APPROVED - Fixed to parse PASSporT JWT for kid/iat

---

## Sprint 24: UI Enhancement - Evidence, Validation & Schema Visibility

**Date:** 2026-01-27
**Commit:** cfdcce6

### Files Changed

| File | Action | Description |
|------|--------|-------------|
| `app/vvp/ui/credential_viewmodel.py` | Modified | Added EvidenceStatus enum, 10 new dataclasses (ValidationCheckResult, ValidationSummary, ErrorBucketItem, ErrorBucket, SchemaValidationInfo, EvidenceFetchRecord, EvidenceTimeline, DelegationNode, DelegationChainInfo, DossierViewModel), extended VariantLimitations and CredentialCardViewModel, added build_schema_info/build_validation_summary/build_error_buckets helpers |
| `app/templates/base.html` | Modified | Added ~60 lines CSS for validation summary strip, error buckets, schema panel, evidence timeline, delegation chain |
| `app/templates/partials/validation_summary.html` | Created | Validation dashboard strip with check icons and status badges |
| `app/templates/partials/error_buckets.html` | Created | INVALID/INDETERMINATE separation per §2.2 with remediation hints |
| `app/templates/partials/schema_panel.html` | Created | Schema validation details with registry source and field errors |
| `app/templates/partials/evidence_timeline.html` | Created | Fetch timeline with cache metrics and status legend |
| `app/templates/partials/delegation_chain.html` | Created | Multi-level delegation chain visualization |
| `app/templates/partials/credential_card.html` | Modified | Added per-credential validation checks, schema panel include, delegation chain include, enhanced limitation banner |
| `app/templates/partials/dossier.html` | Modified | Added dossier-level validation summary, error buckets, evidence timeline includes |
| `app/main.py` | Modified | Evidence collection in `/ui/fetch-dossier`, wired build_schema_info, populated validation_checks per credential |
| `app/Documentation/PLAN_Sprint24_UI.md` | Created | Archived implementation plan |

### Summary

Enhanced VVP Verifier UI to surface new backend capabilities from Sprint 24, improving verification transparency and user experience.

**Key Features:**

1. **Validation Summary Dashboard (§2.2):**
   - Per-credential validation check strip showing Chain/Schema/Revocation status
   - Color-coded severity indicators (success/warning/error)
   - Spec reference tooltips on hover

2. **Error/Warning Buckets (§2.2):**
   - Clear separation of INVALID (errors) vs INDETERMINATE (warnings)
   - Remediation hints for actionable guidance
   - Auto-expands when errors present

3. **Schema Validation Panel (§6.3):**
   - Registry source display (GLEIF governance vs fetched)
   - Validation status with field error details
   - Collapsible with auto-expand on errors

4. **Evidence Fetch Timeline:**
   - Records for DOSSIER, SCHEMA, TEL fetch operations
   - EvidenceStatus enum: SUCCESS, FAILED, CACHED, INDETERMINATE
   - Cache hit rate and total fetch time metrics
   - Status legend for clarity

5. **Delegation Chain Visualization:**
   - Multi-level chain from leaf to root
   - Node authorization status badges
   - Auto-expand when chain validation fails
   - (Note: delegation_info populated during /verify, not /ui/fetch-dossier)

6. **Enhanced Variant Limitations:**
   - `verification_impact` field for spec-compliant messaging
   - `remediation_hints` list for user guidance

**View Model Extensions:**
- `EvidenceStatus` enum for consistent status values across components
- `chain_status` field on CredentialCardViewModel for accurate per-category reporting
- `DossierViewModel` for top-level dossier display context

### Checklist Items Completed

- UI: Validation summary dashboard
- UI: Error/warning bucket separation (§2.2)
- UI: Schema validation panel
- UI: Evidence fetch timeline with cache metrics
- UI: Delegation chain visualization (template ready, data from /verify)
- UI: Enhanced variant limitation display

### Test Results

```
1178 passed in 66.78s
```

### Review History

- Rev 0: CHANGES_REQUESTED - build_schema_info never called, validation_checks not populated, delegation_info N/A
- Rev 1: APPROVED - schema_info wired, validation_checks built, delegation_info accepted as N/A for fetch path

---

## Sprint 23: URL-Keyed Dossier Cache with SAID Index

**Date:** 2026-01-26
**Commit:** 7e49dc6

### Files Changed

| File | Action | Description |
|------|--------|-------------|
| `app/vvp/dossier/cache.py` | Created | DossierCache with URL primary key, SAID→URL secondary index, LRU eviction |
| `app/vvp/dossier/__init__.py` | Modified | Export DossierCache, CachedDossier, CacheMetrics |
| `app/vvp/verify.py` | Modified | Cache lookup before fetch, store after parse, invalidation on revocation |
| `app/vvp/keri/cache.py` | Modified | Added CacheMetrics dataclass for consistent metrics |
| `app/vvp/keri/tel_client.py` | Modified | Added cache_metrics() method |
| `app/core/config.py` | Modified | Added DOSSIER_CACHE_TTL_SECONDS, DOSSIER_CACHE_MAX_ENTRIES |
| `app/main.py` | Modified | Added cache metrics to /admin endpoint |
| `pyproject.toml` | Modified | Added blake3>=0.3.0 dependency |
| `tests/conftest.py` | Created | Root fixture to reset cache before each test |
| `tests/test_dossier_cache.py` | Created | 51 tests for cache operations and verify_vvp integration |
| `tests/vectors/conftest.py` | Modified | Added cache reset fixture for test vectors |
| `tests/vectors/runner.py` | Modified | Added KEY_ROTATED_BEFORE_T mock handler |
| `tests/vectors/data/v12_key_rotated_before_t.json` | Created | Tier 2 test vector for key rotation scenario |
| `app/Documentation/VVP_Implementation_Checklist.md` | Modified | Updated to 99% (180/182 items) |

### Summary

Implemented Phase 14 caching requirements (14.2, 14.6, 14.7) per VVP spec §5C.2.

**Key Features:**

1. **URL-Keyed Dossier Cache (14.2):**
   - Primary index: URL → CachedDossier (URL available pre-fetch)
   - Secondary index: credential SAID → set of URLs containing it
   - LRU eviction with configurable max_entries (default: 100)
   - TTL-based expiration (default: 300s per §5C.2 freshness)
   - Thread-safe with asyncio.Lock

2. **Cache Invalidation on Revocation (14.6):**
   - `invalidate_by_said()` uses secondary index to find affected dossiers
   - Integrated into `check_dossier_revocations()` flow
   - Cascading invalidation when credential revoked

3. **Cache Metrics/Logging (14.7):**
   - CacheMetrics dataclass: hits, misses, evictions, invalidations
   - `hit_rate()` calculation for monitoring
   - Metrics exposed via /admin endpoint

4. **verify_vvp Integration:**
   - Cache lookup before `fetch_dossier()` call
   - Cache store after successful parse
   - Evidence trail: `cache_hit={url}` in claims

5. **Test Vector v12 (15.7):**
   - Key rotated before reference time T scenario
   - Mock via `mock_key_state_error: "KEY_ROTATED_BEFORE_T"`
   - Expected: INVALID with `KERI_STATE_INVALID`

### Checklist Items Completed

- 14.2: SAID-based dossier cache (URL-keyed with SAID secondary index)
- 14.6: Cache invalidation on revocation
- 14.7: Cache metrics/logging
- 15.7: Key rotated before T test vector

### Test Results

```
1103 passed in 6.12s
```

### Review History

- Rev 0: CHANGES_REQUESTED - verify.py doesn't use cache (get/put missing)
- Rev 1: CHANGES_REQUESTED - Integration tests don't exercise verify_vvp directly
- Rev 2: APPROVED - verify_vvp integration tests exercise cache behavior

---

## Sprint 22: Credential Card & Chain Graph Enhancements (Completion)

**Date:** 2026-01-26
**Commit:** 355d27a

### Files Changed

| File | Action | Description |
|------|--------|-------------|
| `app/vvp/ui/credential_viewmodel.py` | Modified | Added AttributeSection, formatting functions, tooltips, raw_contents, redaction detection |
| `app/vvp/ui/__init__.py` | Modified | Export AttributeSection |
| `app/templates/partials/credential_card.html` | Modified | Collapsible sections, edge links, tooltips, Raw Contents, inline revocation |
| `app/templates/partials/credential_graph.html` | Modified | SVG container, edges data attribute |
| `app/templates/base.html` | Modified | CSS for sections/connectors/tooltips/highlight/redaction, JS functions |
| `tests/test_credential_viewmodel.py` | Modified | 66 new tests for Sprint 22 features |
| `scripts/run-tests.sh` | Created | Test runner script with DYLD_LIBRARY_PATH |
| `app/Documentation/PLAN_Sprint22.md` | Created | Archived implementation plan |

### Summary

Completed Sprint 22 Credential Card & Chain Graph Enhancements per approved plan.

**Key Features:**

1. **Collapsible Attribute Sections:**
   - Attributes grouped by category (Identity, Dates & Times, Permissions, Numbers & Ranges, Other)
   - All sections initially expanded with collapsible `<details>` elements
   - Value formatting: booleans as "Yes"/"No", dates human-readable, nested objects flattened

2. **Clickable Edge Links:**
   - Edge links scroll to and highlight target credential
   - `highlightCredential(said)` JS function with 2-second pulse animation
   - Toast notification when target not in current view

3. **SVG Chain Connectors:**
   - Bezier curves connecting parent/child credentials
   - Color-coded by edge type (vetting=green, delegation=blue, issued_by=purple, jl=orange)
   - Responsive: hidden on mobile (<768px), redraw on resize/toggle

4. **Field Tooltips:**
   - Normative descriptions from ToIP ACDC specification
   - `.has-tooltip` CSS class with dotted underline and cursor help

5. **Raw Contents Section:**
   - Collapsed section with all ACDC fields and tooltips
   - Recursively flattened nested dicts with dot notation

6. **Redaction Masking:**
   - ACDC partial disclosure placeholders (`_`, `_:type`, `#`, `[REDACTED]`) → "(redacted)"
   - `.attr-redacted` CSS class with muted italic styling

7. **Inline Revocation Display:**
   - Revocation status badges displayed inline (not lazy-loaded via HTMX)
   - ACTIVE/REVOKED/UNKNOWN with appropriate colors and tooltips

### Test Results

```
999 passed, 20 warnings in 5.63s
```

### Review History

- Rev 0: CHANGES_REQUESTED - Redaction masking not applied to `_build_attribute_sections`
- Rev 1: APPROVED

---

## Sprint 22: Enhanced Credential Card UI (View-Model Foundation)

**Date:** 2026-01-26
**Commit:** 97b4e98

### Files Changed

| File | Action | Description |
|------|--------|-------------|
| `app/vvp/ui/__init__.py` | Created | UI module exports |
| `app/vvp/ui/credential_viewmodel.py` | Created | View-model dataclasses and adapter for credential cards |
| `app/templates/partials/credential_card.html` | Modified | Dual-path template (vm + legacy acdc) |
| `app/templates/partials/revocation_badge.html` | Created | Single revocation badge partial for HTMX lazy load |
| `app/templates/base.html` | Modified | CSS for card enhancements, indeterminate status |
| `app/main.py` | Modified | Added `/ui/revocation-badge` and `/ui/credential/{said}` endpoints |
| `tests/test_credential_viewmodel.py` | Created | 33 unit tests for view-model adapter |
| `app/Documentation/PLAN_Credential_Card_UI.md` | Modified | Added implementation notes |

### Summary

Implemented view-model pattern for credential card UI per Sprint 21 plan, decoupling templates from raw ACDC field variations.

**Key Changes:**

1. **View-Model Adapter:**
   - `CredentialCardViewModel` normalizes ACDC data for templates
   - Primary/secondary attribute extraction per credential type (APE, DE, TNAlloc, LE)
   - Edge normalization handles string, dict with n/d, and list formats
   - Variant limitation detection for compact/partial credentials

2. **Status vs Revocation Separation:**
   - `status`: ClaimStatus (VALID/INVALID/INDETERMINATE) from chain validation
   - `revocation`: RevocationStatus (ACTIVE/REVOKED/UNKNOWN) from TEL

3. **Redaction Detection:**
   - Detects `"_"` full redaction placeholder
   - Detects `"_:type"` typed placeholders (e.g., `"_:string"`)
   - Surfaces limitations in UI banners

4. **HTMX Endpoints:**
   - `/ui/revocation-badge`: Lazy revocation badge with OOBI query support
   - `/ui/credential/{said}`: Placeholder for chain expansion (pending session storage)

5. **Template Backwards Compatibility:**
   - Template accepts both `vm` (new) and `acdc` (legacy) for gradual migration

---

## Sprint 21: ACDC Variant Support (Phase 8.9 / §1.4)

**Date:** 2026-01-26
**Commit:** 5727fb2

### Files Changed

| File | Action | Description |
|------|--------|-------------|
| `app/vvp/acdc/models.py` | Modified | Added `variant` field to ACDC dataclass, updated `credential_type` for compact detection |
| `app/vvp/acdc/parser.py` | Modified | Removed variant rejection block, variants now stored in model |
| `app/vvp/acdc/verifier.py` | Modified | Compact edge refs → INDETERMINATE, partial placeholder handling |
| `app/vvp/dossier/models.py` | Modified | Added `root_saids`, `is_aggregate` fields to DossierDAG |
| `app/vvp/dossier/validator.py` | Modified | Multi-root support via `find_roots()`, aggregate gating |
| `app/core/config.py` | Modified | Added `VVP_ALLOW_AGGREGATE_DOSSIERS` env var |
| `app/vvp/verify.py` | Modified | Chain status aggregation gated by `dag.is_aggregate` |
| `tests/test_acdc.py` | Modified | Added compact/partial/aggregate variant tests |
| `tests/test_verify.py` | Modified | Added `verify_vvp`-level integration tests for aggregation |
| `app/Documentation/VVP_Implementation_Checklist.md` | Modified | Updated 8.9, 15.9 complete (96% overall) |

### Summary

Implemented VVP §1.4 MUST requirement for ACDC variants: compact, partial, and aggregate.

**Key Changes:**

1. **Variant Detection & Storage (§1.4):**
   - `detect_acdc_variant()` identifies full/compact/partial variants
   - Variants stored in `ACDC.variant` field for downstream handling
   - No longer rejected at parse time

2. **Compact Variant Handling:**
   - External edge refs (SAID not in dossier) → `INDETERMINATE` (not raise)
   - Edge-based credential type detection for compact ACDCs
   - Log message: "Cannot verify edge target {SAID} (compact variant)"

3. **Partial Variant Handling:**
   - Placeholder issuee (`"_"` or `"_:*"`) → `INDETERMINATE`
   - Cannot verify binding with redacted fields

4. **Aggregate Dossier Support (§6.1):**
   - `VVP_ALLOW_AGGREGATE_DOSSIERS` env var (default: false)
   - Multi-root DAGs accepted when enabled
   - `dag.is_aggregate` flag for downstream logic

5. **Chain Status Aggregation:**
   - Non-aggregate: at least one valid chain suffices (prior behavior)
   - Aggregate: ALL chains must validate (stricter requirement)
   - Prevents false positives when multiple independent trust hierarchies

### Checklist Items Completed

- 8.9: Handle ACDC variants (compact, partial, aggregate)
- 15.9: Valid ACDC variant test vector

### Test Results

```
899 passed in 5.09s
```

---

## Sprint 20: Test Vectors & CI Integration (Phase 15 Completion)

**Date:** 2026-01-26
**Commit:** 7988be3

### Files Changed

| File | Action | Description |
|------|--------|-------------|
| `.github/workflows/deploy.yml` | Modified | Added test job before deploy with libsodium verification |
| `pyproject.toml` | Modified | Added test dependencies |
| `pytest.ini` | Modified | Added asyncio_mode config and e2e marker |
| `app/vvp/verify.py` | Modified | Added KeyNotYetValidError and ACDCSAIDMismatch handlers |
| `tests/vectors/schema.py` | Modified | Added mock config fields for Tier 2/3 vectors |
| `tests/vectors/runner.py` | Modified | Added mock handlers using actual exception types |
| `tests/vectors/data/v04_iat_before_inception.json` | Modified | Completed with KERI_STATE_INVALID error code |
| `tests/vectors/data/v07_said_mismatch.json` | Modified | Completed with ACDC_SAID_MISMATCH error code |
| `tests/vectors/data/v09_tnalloc_mismatch.json` | Created | TNAlloc mismatch vector |
| `tests/vectors/data/v10_revoked_credential.json` | Created | Revoked credential vector |
| `tests/vectors/data/v11_delegation_invalid.json` | Created | Delegation chain invalid vector |
| `tests/vectors/test_vectors.py` | Modified | Updated expected vector count to 11 |
| `tests/test_trial_dossier_e2e.py` | Created | E2E integration tests with @pytest.mark.e2e marker |
| `app/Documentation/PLAN_Sprint20.md` | Created | Archived implementation plan |

### Summary

Completed Phase 15 (Test Vectors & CI Integration) per VVP spec §10.2 and §4.2A.

**Key Changes:**

1. **CI Infrastructure (Item 15.14):**
   - Test job runs before deployment in GitHub Actions
   - libsodium installation with verification steps
   - 80% coverage threshold enforced

2. **Exception Handlers in verify.py:**
   - `KeyNotYetValidError` → `KERI_STATE_INVALID` (for v04)
   - `ACDCSAIDMismatch` → `ACDC_SAID_MISMATCH` (for v07)

3. **Tier 2 Vectors (Items 15.7, 15.8):**
   - v04: iat before inception → `KERI_STATE_INVALID`
   - v07: SAID mismatch → `ACDC_SAID_MISMATCH`

4. **Tier 3 Vectors (Items 15.10-15.12):**
   - v09: TNAlloc mismatch → `TN_RIGHTS_INVALID`
   - v10: Revoked credential → `CREDENTIAL_REVOKED`
   - v11: Delegation chain invalid → `AUTHORIZATION_FAILED`

5. **E2E Integration Tests:**
   - `test_trial_dossier_e2e.py` with `@pytest.mark.e2e` marker
   - Tests real Provenant trial dossier parsing and DAG building
   - Skippable via `pytest -m "not e2e"` if flaky

### Checklist Items Completed

- 15.7: iat before inception → INVALID (v04)
- 15.8: SAID mismatch → INVALID (v07)
- 15.10: TNAlloc mismatch → INVALID (v09)
- 15.11: Delegation chain invalid → INVALID (v11)
- 15.12: Revoked credential → INVALID (v10)
- 15.14: CI integration (GitHub Actions)

### Test Results

```
886 passed in 5.19s
```

All 11 vectors pass with correct error codes per §4.2A.

---

## Sprint 19: Callee Verification (Phase 12) + Sprint 18 Fixes

**Date:** 2026-01-26
**Commit:** 64437ff

### Files Changed

| File | Action | Description |
|------|--------|-------------|
| `app/vvp/verify_callee.py` | Created | Callee verification module implementing VVP §5B (14 steps) |
| `app/vvp/goal.py` | Modified | Added goal overlap validation (`is_goal_subset()`, `validate_goal_overlap()`, `verify_goal_overlap()`) |
| `app/vvp/api_models.py` | Modified | Added `VerifyCalleeRequest`, `DIALOG_MISMATCH`, `ISSUER_MISMATCH` error codes |
| `app/vvp/sip_context.py` | Modified | Added `context_required` and `timing_tolerance` parameters (Sprint 18 fixes A1/A2) |
| `app/vvp/verify.py` | Modified | Added `_find_signer_de_credential()`, `_get_acdc_issuee()`, plumbed config values (Sprint 18 fix A3) |
| `app/main.py` | Modified | Added POST /verify-callee endpoint with callee-specific SIP context validation |
| `tests/test_verify_callee.py` | Created | 35 unit tests for callee verification |
| `tests/test_verify.py` | Modified | Added 6 tests for Sprint 18 config fixes |
| `tests/test_models.py` | Modified | Updated error code count (24→26) |

### Summary

Completed Phase 12 (Callee Verification per VVP §5B) and Sprint 18 code review fixes.

**Part A: Sprint 18 Code Review Fixes:**

1. **A1: CONTEXT_ALIGNMENT_REQUIRED not applied** (High)
   - Added `context_required` parameter to `verify_sip_context_alignment()`
   - When `True`, missing SIP context returns INVALID (not INDETERMINATE)

2. **A2: SIP_TIMING_TOLERANCE_SECONDS not used** (Medium)
   - Plumbed `SIP_TIMING_TOLERANCE_SECONDS` config through to verification
   - Custom timing tolerance now respected (default 30s)

3. **A3: DE selection uses first DE instead of signer's DE** (Medium)
   - Created `_find_signer_de_credential()` to find DE by signer AID
   - Prevents false positives/negatives with multiple DEs in dossier

**Part B: Phase 12 Callee Verification (15 items):**

1. **Dialog Matching (§5B Step 1)**
   - `validate_dialog_match()` validates call-id and cseq against SIP INVITE
   - Missing or mismatched values return INVALID (DIALOG_MISMATCH)

2. **Issuer Verification (§5B Step 9)**
   - `validate_issuer_match()` ensures dossier issuer AID matches PASSporT kid
   - Mismatched issuer returns INVALID (ISSUER_MISMATCH)

3. **Goal Overlap Verification (§5B Step 14)**
   - `is_goal_subset()` - hierarchical goal comparison (e.g., "billing.payment" ⊂ "billing")
   - `validate_goal_overlap()` - one goal must be subset of the other
   - `verify_goal_overlap()` - returns ClaimBuilder, REQUIRED when both goals present

4. **Callee TN Rights (§5B Step 12)**
   - `validate_callee_tn_rights()` validates callee can RECEIVE at the number
   - Uses existing `_find_credentials_by_type()` infrastructure

5. **New Error Codes**
   - `DIALOG_MISMATCH` - call-id/cseq don't match SIP INVITE (non-recoverable)
   - `ISSUER_MISMATCH` - dossier issuer != passport kid (non-recoverable)

6. **Claim Tree (per §3.3B)**
   ```
   callee_verified (root)
   ├── passport_verified (REQUIRED)
   │   ├── dialog_matched (REQUIRED)
   │   ├── timing_valid (REQUIRED)
   │   └── signature_valid (REQUIRED)
   ├── dossier_verified (REQUIRED)
   │   ├── structure_valid (REQUIRED)
   │   ├── acdc_signatures_valid (REQUIRED)
   │   ├── revocation_clear (REQUIRED)
   │   └── issuer_matched (REQUIRED)
   ├── tn_rights_valid (REQUIRED)
   ├── brand_verified (REQUIRED when card present)
   └── goal_overlap_verified (REQUIRED when both goals present)
   ```

### Checklist Items Completed

**Phase 12 (15/15):** 12.1-12.15 (Callee Verification)
- 12.1: Created verify_callee.py module
- 12.2: Dialog matching (call-id, cseq)
- 12.3: Timing alignment (iat validation)
- 12.4: Expiration analysis (exp policy)
- 12.5: Key identifier extraction (kid)
- 12.6: Signature verification
- 12.7: Dossier fetch and validation
- 12.8: Issuer verification (dossier issuer == kid)
- 12.9: Revocation status check
- 12.10: Phone number rights (callee receiving)
- 12.11: Brand attributes verification
- 12.12: Goal overlap verification
- 12.13: Added POST /verify-callee endpoint
- 12.14: Unit tests (35 tests)
- 12.15: Unknown claims in passport ignored

### Test Results

```
875 passed in 5.00s
```

---

## Sprint 18: Brand/Business Logic & SIP Contextual Alignment

**Date:** 2026-01-25
**Commit:** `8d9d697`

### Files Changed

| File | Action | Description |
|------|--------|-------------|
| `app/vvp/api_models.py` | Modified | Added SipContext model, CONTEXT_MISMATCH/BRAND_CREDENTIAL_INVALID/GOAL_REJECTED error codes |
| `app/vvp/sip_context.py` | Created | SIP URI parsing, E.164 normalization, context alignment validation |
| `app/vvp/brand.py` | Created | Brand credential verification, vCard validation, JL and proxy checks |
| `app/vvp/goal.py` | Created | Goal policy, signer constraints (hours, geographies) |
| `app/core/config.py` | Modified | Added Sprint 18 config: SIP_TIMING_TOLERANCE, ACCEPTED_GOALS, GEO_CONSTRAINTS_ENFORCED |
| `app/vvp/verify.py` | Modified | Integrated context_aligned, brand_verified, business_logic_verified claims |
| `tests/test_sip_context.py` | Created | 36 tests for SIP context alignment |
| `tests/test_brand.py` | Created | 22 tests for brand verification |
| `tests/test_goal.py` | Created | 24 tests for goal/business logic |
| `tests/test_verify.py` | Modified | Updated mock passports, claim tree assertions for new structure |
| `tests/test_models.py` | Modified | Updated error code count (21→24) |
| `tests/vectors/data/v*.json` | Modified | Added context_aligned claim to all vectors |
| `app/Documentation/VVP_Implementation_Checklist.md` | Modified | Phase 11 and 13 complete, overall 91% |

### Summary

Completed Phase 11 (Brand/Business Logic) and Phase 13 (SIP Contextual Alignment) per VVP spec §5.1.1-2.2, §5.1.1-2.12, §5.1.1-2.13.

**Key Changes:**

1. **SIP Contextual Alignment (Phase 13):**
   - SipContext model with from_uri, to_uri, invite_time, cseq
   - URI parsing: sip:, sips:, tel: formats with E.164 normalization
   - orig/dest alignment validation against SIP headers
   - Timing tolerance: 30s default (VVP_SIP_TIMING_TOLERANCE configurable)
   - context_aligned claim: INDETERMINATE when SIP context absent

2. **Brand Verification (Phase 11):**
   - vCard format validation (warn on unknown fields, don't fail)
   - Brand credential location by indicator fields (fn, org, logo, url, photo)
   - Attribute matching between card and credential
   - JL validation: brand credential MUST link to vetting (§6.3.7)
   - Brand proxy: INDETERMINATE when delegation present but proxy missing (§6.3.4)

3. **Business Logic (Phase 11):**
   - Goal acceptance policy (whitelist, reject_unknown flag)
   - Signer constraints extraction from DE credential (hours, geographies)
   - Hours validation with overnight range support (e.g., 22-06)
   - Geographic constraints: INDETERMINATE when GeoIP unavailable

4. **Claim Tree Updates:**
   - context_aligned: OPTIONAL by default (CONTEXT_ALIGNMENT_REQUIRED configurable)
   - brand_verified: REQUIRED when card present (per Reviewer feedback)
   - business_logic_verified: REQUIRED when goal present (per Reviewer feedback)

### Checklist Items Completed

**Phase 11 (17/17):** 11.1-11.17 (Brand and Business Logic)
**Phase 13 (6/6):** 13.1-13.6 (SIP Contextual Alignment)

### Test Results

```
834 passed, 2 skipped in 5.47s
```

---

## Sprint 17: APE Vetting Edge & Schema Validation

**Date:** 2026-01-25
**Commit:** `54f507b`

### Files Changed

| File | Action | Description |
|------|--------|-------------|
| `app/vvp/acdc/verifier.py` | Modified | Fixed is_root bypass for APE vetting edges; added `validate_ape_vetting_target()` |
| `app/vvp/keri/key_parser.py` | Modified | Added documentation for §4.2 single-sig AID enforcement |
| `tests/test_acdc.py` | Modified | Added 4 new tests for APE vetting validation, added `KNOWN_LE_SCHEMA` constant |
| `app/Documentation/VVP_Implementation_Checklist.md` | Modified | Phase 10 100% complete, overall 79% |

### Summary

Completed remaining MUST requirements in Phase 10 (Authorization Verification) per VVP spec §6.3.3, §4.2, and §6.3.5.

**Key Changes:**

1. **APE Vetting Edge Always Required (§6.3.3):**
   - Fixed `validate_edge_semantics()` to not skip required edge checks for APE credentials
   - Previous code allowed `is_root=True` to bypass vetting edge requirement
   - APE credentials MUST have vetting edge → LE credential, even when issued by trusted root

2. **APE Vetting Target Validation (§6.3.3, §6.3.5):**
   - Added `validate_ape_vetting_target()` function
   - Validates vetting target credential type is LE (not TNAlloc, DE, etc.)
   - Validates vetting LE credential uses known vLEI schema SAID
   - Respects `SCHEMA_VALIDATION_STRICT` config flag

3. **Single-Sig AID Documentation (§4.2):**
   - Added comprehensive documentation to `key_parser.py`
   - Only B/D prefixes accepted (Ed25519 single-sig codes)
   - Multi-sig AIDs (E, F, M prefixes) rejected
   - Item 10.18 already enforced, now documented

4. **Test Updates:**
   - Added `KNOWN_LE_SCHEMA` constant for test fixtures
   - Updated 4 existing tests to use known LE schema SAID
   - Added 4 new Sprint 17 tests for APE vetting validation

### Checklist Items Completed

- 10.12: APE must include vetting edge → LE credential
- 10.18: kid AID single-sig validation (already enforced, documented)
- 10.19: Vetting credential must conform to LE vLEI schema

### Test Results

```
752 passed, 2 skipped in 4.89s
```

---

## Sprint 16: Delegation Authorization (Case B)

**Date:** 2026-01-25
**Commit:** `6e5387d`

### Files Changed

| File | Action | Description |
|------|--------|-------------|
| `app/vvp/authorization.py` | Modified | Added `_find_delegation_target()`, `_verify_delegation_chain()` for Case B delegation |
| `tests/test_authorization.py` | Modified | Added 9 new tests for Case B delegation scenarios (45 total) |

### Summary

Implemented VVP Specification §5A Step 10 Case B: Delegation chain validation.

**Key Changes:**

1. **Delegation Chain Validation (Case B):**
   - `_find_delegation_target()`: Finds credential referenced by DE's delegation edge
   - `_verify_delegation_chain()`: Walks DE → APE chain to identify accountable party
   - DE issuee must match PASSporT signer (OP is delegate)
   - Chain terminates when APE credential reached
   - APE issuee is the accountable party (used for TN rights binding)

2. **Multi-Level Delegation:**
   - Supports nested delegation: DE → DE → ... → APE
   - Maximum chain depth of 10 (configurable)
   - Cycle detection prevents infinite loops

3. **Error Handling:**
   - No DE for signer → INVALID
   - Missing delegation target → INVALID
   - Circular delegation → INVALID
   - Chain too deep → INVALID

4. **TN Rights Binding:**
   - TNAlloc must be bound to accountable party (APE issuee), not delegate
   - Ensures proper authorization chain even with delegation

### Checklist Items Completed

- 10.5: Case B - verify delegation credential chain
- 10.14: If delegation, verify DE includes delegated signer credential
- 10.17: Verify OP is issuee of delegated signer credential

### Revision 1 (Review Fixes)

**Issues Addressed:**
- [High]: Case B selection now only uses delegation when DE issuee matches signer
- [Medium]: All matching DEs are tried; first valid chain wins

**Changes:**
- Refactored `_verify_delegation_chain()` into `_walk_de_chain()` + `_verify_delegation_chain()`
- `verify_party_authorization()` now filters DEs by issuee == signer before deciding Case B
- Unrelated DEs (issuee != signer) no longer force Case B; falls back to Case A

### Test Results

```
748 passed, 2 skipped in 4.77s
```

---

## Sprint 15: Authorization Verification (§5A Steps 10-11)

**Date:** 2026-01-25
**Commit:** `82c88a0`

### Files Changed

| File | Action | Description |
|------|--------|-------------|
| `app/vvp/authorization.py` | Created | Authorization module with party authorization and TN rights validation (~265 lines) |
| `app/vvp/api_models.py` | Modified | Added `AUTHORIZATION_FAILED`, `TN_RIGHTS_INVALID` error codes |
| `app/vvp/verify.py` | Modified | Wired `authorization_valid` claim into claim tree (~98 lines added) |
| `tests/test_authorization.py` | Created | 36 unit tests for authorization verification |
| `tests/vectors/data/v*.json` | Modified | Updated expected claim tree structure for authorization claims |
| `REVIEW.md` | Modified | Added Sprint 15 review records |
| `app/Documentation/PLAN_Sprint15.md` | Created | Archived implementation plan |

### Summary

Implemented VVP Specification §5A Steps 10-11: Party authorization and TN rights validation for Case A (no delegation).

**Key Changes:**

1. **Party Authorization (Step 10):**
   - `verify_party_authorization()` finds APE credential where issuee == PASSporT signer AID
   - Case A (no delegation): Direct match proves OP is accountable party
   - Case B (DE delegation): Returns INDETERMINATE (deferred to future sprint)
   - Error code: `AUTHORIZATION_FAILED`

2. **TN Rights Validation (Step 11):**
   - `verify_tn_rights()` validates orig.tn is covered by TNAlloc credential
   - **Binding requirement**: TNAlloc must be issued to the accountable party (issuee match)
   - When party authorization fails: TN rights returns INDETERMINATE (no party to bind to)
   - Uses existing `tn_utils.py` for E.164 parsing and subset validation
   - Error code: `TN_RIGHTS_INVALID`

3. **Claim Tree Structure:**
   ```
   caller_authorised
   ├── passport_verified (REQUIRED)
   ├── dossier_verified (REQUIRED)
   └── authorization_valid (REQUIRED)      ← NEW
       ├── party_authorized (REQUIRED)     ← NEW
       └── tn_rights_valid (REQUIRED)      ← NEW
   ```

4. **AuthorizationContext Dataclass:**
   - `pss_signer_aid`: AID extracted from PASSporT kid header
   - `orig_tn`: E.164 phone number from passport.payload.orig["tn"]
   - `dossier_acdcs`: All ACDC credentials parsed from the dossier

### Review History

- **Rev 0**: CHANGES_REQUESTED - TN rights not bound to accountable party
- **Rev 1**: APPROVED - Added `authorized_aid` parameter, TNAlloc issuee binding

### Checklist Items Completed

- 10.2: Extract originating party AID from PASSporT
- 10.4: Case A - verify orig = accountable (via APE issuee)
- 10.6: Locate TNAlloc in dossier
- 10.7: Compare orig field to TNAlloc credential (bound to accountable party)
- 10.9: Add caller_authorized claim to tree
- 10.10: Add tn_rights_valid claim to tree
- 10.11: Unit tests for authorization

### Test Results

```
737 passed, 2 skipped in 4.79s
```

---

## Sprint 14: Tier 2 Completion - Schema, Edge Semantics, TNAlloc

**Date:** 2026-01-25
**Commit:** `0b7fe93`

### Files Changed

| File | Action | Description |
|------|--------|-------------|
| `app/vvp/acdc/schema_registry.py` | Created | Versioned schema SAID registry with vLEI governance sources |
| `app/vvp/acdc/verifier.py` | Modified | Added `validate_edge_semantics()`, integrated into chain validation, strict schema validation |
| `app/vvp/acdc/parser.py` | Modified | Added `detect_acdc_variant()` for explicit variant rejection |
| `app/vvp/tn_utils.py` | Created | E.164 parsing, wildcard support, range subset validation |
| `tests/test_acdc.py` | Modified | Added 19 tests for edge semantics and variant detection |
| `tests/test_tn_utils.py` | Created | 15 tests for TN utilities |
| `app/Documentation/PLAN_Phase14.md` | Created | Archived implementation plan |

### Summary

Completed remaining Tier 2 ACDC validation requirements per spec §6.3.x and §1.4.

**Key Changes:**

1. **Schema SAID Validation (§6.3.x):**
   - `validate_schema_said()` now defaults to `strict=True`
   - Known LE schema SAIDs from vLEI governance framework
   - APE/DE/TNAlloc schemas accept any (pending governance publication)
   - Versioned registry in `schema_registry.py` with source documentation

2. **Edge Relationship Semantics (§6.3.3/§6.3.4/§6.3.6):**
   - `validate_edge_semantics()` validates credential type-specific edge rules
   - APE: MUST have vetting edge → LE credential
   - DE: MUST have delegation edge → APE or DE credential
   - TNAlloc: Should have JL edge → parent TNAlloc (unless root)
   - Integrated into `walk_chain()` for automatic enforcement
   - Missing required edge targets raise `ACDCChainInvalid`

3. **ACDC Variant Detection (§1.4 explicit handling):**
   - `detect_acdc_variant()` detects full, compact, and partial variants
   - Full variants: expanded `a` field present → accepted
   - Compact variants: missing/string `a` field → `ParseError`
   - Partial variants: `"_"` placeholders → `ParseError`
   - Documented non-compliance until full variant support implemented

4. **TNAlloc Phone Number Validation (§6.3.6):**
   - E.164 format validation with `+` prefix requirement
   - Wildcard support (`+1555*` → range expansion)
   - Hyphenated range parsing (`+15550000000-+15559999999`)
   - `is_subset()` validates child ranges covered by parent
   - Mixed list/range/dict inputs supported

### Checklist Items Completed

- 8.6: ACDC schema SAID validation (strict by default)
- 8.8: Edge/relationship semantic validation
- 8.9: ACDC variants (explicit rejection with documented non-compliance)
- 8.11: TNAlloc JL validation with phone number range subset

### Test Results

```
701 passed, 2 skipped, 20 warnings in 4.81s
```

---

## Phase 13B: Separation of Concerns Refactoring

**Date:** 2026-01-25
**Commit:** `dd95391`

### Files Changed

| File | Action | Description |
|------|--------|-------------|
| `app/main.py` | Modified | Refactored `/ui/parse-jwt` to use domain layer `parse_passport()`, added permissive decode mode with spec reference mapping, removed dead code (`_base64url_decode`, `_parse_jwt_logic`, `_extract_acdcs_from_dossier`) |
| `app/vvp/dossier/parser.py` | Modified | Added Provenant wrapper format support (`{"details": "..."}`) and permissive CESR extraction fallback |
| `app/templates/partials/jwt_result.html` | Modified | Added validation warning display with spec section references in table format |
| `tests/test_ui_endpoints.py` | Created | 14 integration tests for UI endpoint behavior and domain layer alignment |
| `tests/test_dossier.py` | Modified | Added 2 tests for Provenant wrapper format parsing |
| `CLAUDE.md` | Modified | Added pre-authorization for pytest with DYLD_LIBRARY_PATH |

### Summary

Phase 13B refactors the HTMX UI layer to properly delegate to the domain layer, fixing separation of concerns violations introduced in Phase 13.

**Key Changes:**

1. **Domain Layer Delegation (§5.0-5.2):**
   - `/ui/parse-jwt` now uses `parse_passport()` from `app/vvp/passport.py`
   - Removed duplicate base64url decoding and JWT parsing logic
   - Domain layer validation errors properly propagated to UI

2. **Permissive Decode Mode:**
   - JWT content shown even when validation fails
   - Validation errors displayed separately with "Validation Warning" banner
   - Spec section references mapped to error messages (20+ patterns)
   - Users can see decoded content and understand why validation failed

3. **Spec Reference Mapping:**
   - `SPEC_SECTION_MAP` dictionary maps error patterns to spec sections
   - Examples: `forbidden algorithm` → `§5.0, §5.1`, `orig.tn must be a single phone number` → `§4.2`
   - Template displays spec section and description alongside error message

4. **Provenant Dossier Format Support:**
   - Added handling for `{"details": "...CESR content..."}` wrapper format
   - Permissive CESR extraction when strict parsing fails (unknown attachment codes)
   - Filters KEL events from ACDCs using schema SAID format check
   - Deduplicates credentials by SAID

5. **Dead Code Removal:**
   - Deleted `_base64url_decode()` - replaced by domain layer
   - Deleted `_parse_jwt_logic()` - replaced by `parse_passport()`
   - Deleted `_extract_acdcs_from_dossier()` - no longer used

### Test Coverage

- 14 new UI endpoint integration tests
- 2 new Provenant wrapper format tests
- 621 total tests passing

---

## Sprint 12: Tier 2 Completion - PASSporT & ACDC Validation

**Date:** 2026-01-25
**Commit:** `7b72747`

### Files Changed

| File | Action | Description |
|------|--------|-------------|
| `app/vvp/passport.py` | Modified | E.164 phone validation, typ header validation |
| `app/vvp/acdc/verifier.py` | Modified | Added `validate_issuee_binding()` for bearer token check |
| `app/vvp/acdc/__init__.py` | Modified | Export new validation functions |
| `app/vvp/keri/kel_resolver.py` | Modified | Enable witness validation in strict mode |
| `tests/test_passport.py` | Modified | Added E.164 and typ validation tests |
| `tests/test_acdc.py` | Modified | Added issuee binding tests |
| `tests/test_signature.py` | Modified | Fixed fixtures for E.164 validation |
| `tests/test_kel_resolver.py` | Modified | Fixed witness validation test |
| `app/Documentation/VVP_Implementation_Checklist.md` | Modified | Updated to 68% complete |

### Summary

Completed remaining Tier 2 validation requirements per VVP spec §4.2, §6.3.5, and §7.3.

**Key Changes:**

1. **E.164 Phone Number Validation (§4.2):**
   - `orig.tn` must be single string (not array) in E.164 format
   - `dest.tn` must be array of E.164 phone numbers
   - Pattern: `+[1-9][0-9]{1,14}` per ITU-T E.164

2. **typ Header Validation (RFC8225):**
   - If `typ` header present, must be "passport"
   - Missing typ is allowed (optional field)

3. **Issuee Binding Validation (§6.3.5):**
   - Credentials must not be bearer tokens
   - Non-root credentials must have issuee field (`i`, `issuee`, or `holder`)
   - Root credentials (from trusted AIDs) may omit issuee

4. **Witness Signature Validation (§7.3):**
   - `validate_witnesses=strict_validation` in KEL resolution
   - Strict mode validates witness receipt signatures
   - Non-strict mode allows for testing without full witness setup

### Checklist Items Completed

- 3.14: `orig.tn` single phone number validation
- 3.15: `typ` header validation
- 3.16: E.164 format validation
- 7.16: Witness receipt signature validation
- 8.12: Issuee binding validation

---

## Phase 11: Tier 2 Integration & Compliance

**Date:** 2026-01-25
**Commit:** `b766b00`

### Files Changed

| File | Action | Description |
|------|--------|-------------|
| `app/vvp/verify.py` | Modified | Added Phase 5.5 chain_verified claim, Tier 2 PASSporT routing, ACDC chain validation integration, leaf credential selection |
| `app/vvp/keri/kel_resolver.py` | Modified | Added `strict_validation` parameter to `_fetch_and_validate_oobi()` for production vs test mode |
| `app/vvp/dossier/parser.py` | Modified | CESR format detection and signature extraction |
| `app/vvp/dossier/__init__.py` | Modified | Export signature dict from `parse_dossier()` |
| `app/core/config.py` | Modified | Added `SCHEMA_VALIDATION_STRICT` configuration flag |
| `tests/test_dossier.py` | Modified | Added CESR signature extraction test with mocking |
| `app/Documentation/PLAN_Phase11.md` | Created | Archived implementation plan |

### Summary

Integrated Tier 2 verification components into the main verification flow per spec §4.2, §5A Step 8, and §6.3.x.

**Key Changes:**

1. **ACDC Chain Validation Integration (§6.3.x):**
   - `chain_verified` claim added as REQUIRED child of `dossier_verified`
   - Chain validation starts from leaf credentials (APE/DE/TNAlloc), not just DAG root
   - `_find_leaf_credentials()` helper identifies credentials not referenced by edges
   - At least one leaf must validate to a trusted root

2. **Strict OOBI KEL Validation (§4.2):**
   - `_fetch_and_validate_oobi()` now accepts `strict_validation` parameter
   - Production mode: canonical KERI validation with SAID checks
   - Test mode: allows placeholder SAIDs and non-canonical serialization
   - ACDC signature verification uses strict key resolution

3. **PASSporT-Optional Chain Verification (§5A Step 8):**
   - Chain verification runs when dossier is present, even if PASSporT is absent
   - PSS signer binding for DE credentials only enforced when PASSporT available

4. **CESR Signature Extraction:**
   - Dossier parser detects CESR format and extracts controller signatures
   - Returns `Tuple[List[ACDCNode], Dict[str, bytes]]` with SAID→signature mapping
   - Signatures verified against issuer key state in production mode

5. **Schema Validation Configuration:**
   - `SCHEMA_VALIDATION_STRICT` flag (default True per spec)
   - False is a documented policy deviation for testing

**Spec Compliance:**
- §4.2: OOBI MUST resolve to valid KEL (enforced via strict validation)
- §5A Step 8: Dossier cryptographic verification MUST be performed
- §6.3.3-6: ACDC schema/credential type rules enforced from leaves

---

## Phase 10: Tier 2 Completion - ACDC & Crypto Finalization

**Date:** 2026-01-25
**Commit:** `a8d0833`

### Files Changed

| File | Action | Description |
|------|--------|-------------|
| `app/core/config.py` | Modified | Added `TRUSTED_ROOT_AIDS` with multi-root support via env var |
| `app/vvp/keri/cesr.py` | Modified | Added `decode_pss_signature()` for CESR PSS signatures |
| `app/vvp/keri/kel_parser.py` | Modified | Enhanced `validate_witness_receipts()` |
| `app/vvp/keri/kel_resolver.py` | Modified | Added `_fetch_and_validate_oobi()` for §4.2 OOBI KEL validation |
| `app/vvp/keri/oobi.py` | Modified | Added `validate_oobi_is_kel()` |
| `app/vvp/keri/signature.py` | Modified | Moved pysodium to lazy import inside functions |
| `app/vvp/passport.py` | Modified | Integrated CESR PSS signature auto-detection in `_decode_signature()` |
| `app/vvp/acdc/__init__.py` | Created | Package exports for ACDC verification |
| `app/vvp/acdc/exceptions.py` | Created | ACDCError hierarchy (Parse, SAID, Signature, Chain) |
| `app/vvp/acdc/models.py` | Created | ACDC and ACDCChainResult dataclasses |
| `app/vvp/acdc/parser.py` | Created | ACDC parsing and SAID validation with Blake3 |
| `app/vvp/acdc/verifier.py` | Created | Chain validation, schema validation, credential type validation |
| `tests/test_cesr_pss.py` | Created | 8 tests for PSS signature decoding |
| `tests/test_witness_receipts.py` | Created | 8 tests for witness validation |
| `tests/test_acdc.py` | Created | 38 tests for ACDC verification |
| `tests/test_trusted_roots.py` | Created | 7 tests for root configuration |
| `tests/test_passport.py` | Modified | 6 new tests for CESR signature integration |
| `app/Documentation/PLAN_Phase10.md` | Created | Archived implementation plan |

### Summary

Completed Tier 2 verification components: ACDC chain validation, CESR PSS signature decoding, OOBI KEL validation, and trusted root configuration.

**Key Changes:**

1. **Root of Trust Configuration (§5.1-7):**
   - `TRUSTED_ROOT_AIDS` frozenset from `VVP_TRUSTED_ROOT_AIDS` env var
   - Default: GLEIF External AID for production vLEI ecosystem
   - Supports multiple comma-separated roots

2. **PSS CESR Signature Decoding (§6.3.1):**
   - `decode_pss_signature()` handles 0A/0B/0C/0D/AA prefixed CESR signatures
   - Auto-detection in `_decode_signature()` with fallback to base64url

3. **OOBI KEL Validation (§4.2):**
   - `_fetch_and_validate_oobi()` validates KEL structure during resolution
   - Checks: KEL data present, inception event first, chain integrity

4. **ACDC Chain Validation (§6.3.x):**
   - `validate_credential_chain()` walks edges to trusted root
   - Credential type-specific validation: APE, DE, TNAlloc
   - `pss_signer_aid` parameter for DE signer binding per §6.3.4
   - Schema SAID validation against known vLEI governance schemas

5. **Lazy pysodium Import:**
   - Moved import inside functions to avoid load-time errors

**Spec Compliance:**
- §4.2: OOBI must resolve to valid KEL
- §5.1-7: Root of trust configuration
- §6.3.1: PSS CESR signature format
- §6.3.3: APE credential validation (vetting edge required)
- §6.3.4: DE credential validation (PSS signer must match delegate)
- §6.3.6: TNAlloc credential validation (TN subset of parent)

---

## Phase 9.4: TEL Resolution Architecture Fix

**Date:** 2026-01-25
**Commit:** `4de5855`

### Files Changed

| File | Action | Description |
|------|--------|-------------|
| `app/vvp/verify.py` | Modified | Added `_query_registry_tel()` helper, inline TEL parsing with latin-1 decoding, registry OOBI discovery |
| `app/vvp/keri/tel_client.py` | Modified | Added detailed logging to `parse_dossier_tel()` |
| `tests/test_revocation_checker.py` | Modified | Added 7 new tests for inline TEL, registry OOBI, binary-safe parsing |
| `app/main.py` | Modified | Added `POST /admin/log-level` endpoint for runtime log level changes |
| `tests/test_admin.py` | Modified | Added 6 tests for log level endpoint |
| `app/Documentation/PLAN_Phase9.4.md` | Created | Archived implementation plan |

### Summary

Fixed TEL resolution architecture so revocation checking works correctly instead of always returning INDETERMINATE.

**Problem:** The previous implementation queried the wrong endpoints (PASSporT signer's KERIA agent instead of registry witnesses), causing all TEL queries to return 404.

**Solution:**
1. **Inline TEL Parsing**: Check if TEL events are embedded in the raw dossier using binary-safe latin-1 decoding
2. **Registry OOBI Discovery**: Derive registry OOBI URL from base OOBI pattern (`{scheme}://{netloc}/oobi/{registry_said}`)
3. **Fallback Chain**: Inline TEL → Registry OOBI witnesses → Default witnesses

**Key Changes:**
- `check_dossier_revocations()` now accepts `raw_dossier` parameter for inline TEL parsing
- Latin-1 decoding preserves all byte values (byte-transparent) for CESR streams
- Evidence format standardized: `revocation_source:{dossier|witness}` with summary counts
- Runtime log level endpoint: `POST /admin/log-level` with `{"level": "DEBUG"}` body
- 440 tests passing (20 revocation tests)

**Spec Compliance:**
- §5.1.1-2.9: Revocation status checking via correct TEL sources
- §6.1B: Inline TEL events in CESR dossier format supported

---

## Phase 9.3: Revocation Integration & Admin Endpoint

**Date:** 2026-01-25
**Commit:** `c08c0bb`

### Files Changed

| File | Action | Description |
|------|--------|-------------|
| `app/vvp/verify.py` | Modified | Added `check_dossier_revocations()`, integrated `revocation_clear` under `dossier_verified` per §3.3B |
| `app/vvp/api_models.py` | Modified | Added `CREDENTIAL_REVOKED` error code |
| `app/main.py` | Modified | Added `/admin` endpoint for configuration visibility |
| `app/core/config.py` | Modified | Added `ADMIN_ENDPOINT_ENABLED` flag |
| `app/vvp/keri/tel_client.py` | Modified | Added INFO-level logging throughout |
| `app/logging_config.py` | Modified | Added `VVP_LOG_LEVEL` env var support |
| `tests/test_revocation_checker.py` | Created | Revocation checking tests (11 tests) |
| `tests/test_admin.py` | Created | Admin endpoint tests (9 tests) |
| `tests/test_models.py` | Modified | Updated error code count for CREDENTIAL_REVOKED |
| `tests/vectors/runner.py` | Modified | Added TEL client mock for deterministic tests |
| `app/Documentation/VVP_Implementation_Checklist.md` | Modified | Updated to v3.3, Phase 9 100% complete |

### Summary

Integrated revocation checking into the main verification flow per spec §5.1.1-2.9.

**Key Changes:**
- `revocation_clear` claim is now a REQUIRED child of `dossier_verified` per §3.3B
- `dossier_verified` status propagates from `revocation_clear` per §3.3A
- `CREDENTIAL_REVOKED` errors emitted for each revoked credential
- `/admin` endpoint exposes all configuration values (gated by `ADMIN_ENDPOINT_ENABLED`)
- INFO-level logging added to TEL client for debugging
- 480 tests passing (11 new revocation tests, 9 new admin tests)

**Spec Compliance:**
- §5.1.1-2.9: Revocation status checking for all ACDCs in dossier
- §3.3B: `revocation_clear` placed under `dossier_verified`
- §3.3A: Status propagation (INVALID > INDETERMINATE > VALID)

---

## CESR Parsing & Provenant Witness Integration

**Date:** 2026-01-25
**Commit:** `565c8bf`

### Files Changed

| File | Action | Description |
|------|--------|-------------|
| `app/vvp/keri/cesr.py` | Created | CESR stream parser for `application/json+cesr` |
| `app/vvp/keri/keri_canonical.py` | Created | KERI canonical field ordering per spec |
| `app/vvp/keri/tel_client.py` | Created | TEL client with Provenant staging witnesses |
| `app/vvp/keri/kel_parser.py` | Modified | Enhanced with CESR attachment parsing |
| `app/vvp/keri/kel_resolver.py` | Modified | Pass content-type to parser |
| `app/vvp/keri/oobi.py` | Modified | Improved OOBI URL handling |
| `ROADMAP.md` | Created | Strategic roadmap with tier architecture |
| `app/Documentation/VVP_Implementation_Checklist.md` | Modified | Updated to v3.2 (60% complete) |
| `scripts/test_witness_resolution.py` | Created | Standalone witness test script |
| `tests/test_cesr_parser.py` | Created | CESR parser unit tests |
| `tests/test_canonicalization.py` | Created | Canonical ordering tests |
| `tests/fixtures/keri/*.json` | Created | Test fixtures from keripy |

### Summary

Integrated with Provenant staging witnesses for live KERI ecosystem testing.

**Key Changes:**
- CESR stream parsing for witness OOBI responses
- KERI-compliant field ordering for serialization
- TEL client infrastructure for revocation checking
- Provenant witness endpoints: witness4/5/6.stage.provenant.net:5631
- Verified live resolution with test AID `EGay5ufBqAanbhFa_qe-KMFUPJHn8J0MFba96yyWRrLF`

**Documentation:**
- Created ROADMAP.md with tier architecture overview
- Updated checklist to reflect implementation progress (60%)
- Archived old spec versions (v1.1, v1.2, v1.3)

### Normative Note: `kid` Field Semantics

Per VVP draft and KERI specifications:

> **`kid` is an OOBI reference to a KERI autonomous identifier whose historical key state, witness receipts, and delegations MUST be resolved and validated to determine which signing key was authorised at the PASSporT reference time.**

This means `kid` is NOT a generic JWT key ID - resolution requires OOBI dereferencing and KEL validation at reference time T.

---

## Phase 7: KERI Key State Resolution (Tier 2)

**Date:** 2026-01-24
**Commit:** `850df11`

### Files Changed

| File | Action | Description |
|------|--------|-------------|
| `app/core/config.py` | Modified | Added `TIER2_KEL_RESOLUTION_ENABLED` feature flag |
| `app/vvp/keri/exceptions.py` | Modified | Added KELChainInvalidError, KeyNotYetValidError, DelegationNotSupportedError, OOBIContentInvalidError |
| `app/vvp/keri/cache.py` | Created | Key state cache with LRU eviction and TTL |
| `app/vvp/keri/kel_parser.py` | Created | KEL event parser with chain validation |
| `app/vvp/keri/oobi.py` | Created | OOBI dereferencer for fetching KEL data |
| `app/vvp/keri/kel_resolver.py` | Created | Key state resolver at reference time T |
| `app/vvp/keri/signature.py` | Modified | Added verify_passport_signature_tier2 |
| `app/vvp/keri/__init__.py` | Modified | Updated exports for Tier 2 |
| `tests/test_kel_parser.py` | Created | KEL parser unit tests |
| `tests/test_kel_chain.py` | Created | Chain validation tests |
| `tests/test_kel_cache.py` | Created | Cache behavior tests |
| `tests/test_kel_resolver.py` | Created | Resolver tests |
| `tests/test_kel_integration.py` | Created | End-to-end integration tests |
| `app/Documentation/PLAN_Phase7.md` | Created | Archived phase plan |

### Summary

Implemented Tier 2 KERI key state resolution for historical key verification per VVP §5A Step 4 and §5D.

**Components:**
- OOBI dereferencer for fetching KEL data from witness endpoints
- KEL event parser with chain continuity and signature validation
- Key state resolver that determines signing keys valid at reference time T
- LRU cache keyed by (AID, establishment_digest) with time-based secondary index

**Feature Gating:**
- `TIER2_KEL_RESOLUTION_ENABLED = False` by default
- Tier 2 is TEST-ONLY due to limitations:
  - JSON-only (CESR binary format not supported)
  - Signature canonicalization uses JSON sorted-keys (not KERI-compliant Blake3)
  - SAID validation disabled by default
- Tests use `_allow_test_mode=True` to bypass feature gate

### Spec Sections Implemented

- §5A Step 4: Resolve issuer key state at reference time T
- §5C.2: Key state cache (AID + timestamp → rotation-sensitive)
- §5D: Historical verification capabilities

### Test Results

```
97 passed (Phase 7 tests)
368 passed, 2 skipped (full test suite)
```

---

## Phase 9: VVP Verifier Specification v1.5

**Date:** 2026-01-24
**Commit:** `953e694`

### Files Changed

| File | Action | Description |
|------|--------|-------------|
| `app/Documentation/VVP_Verifier_Specification_v1.5.md` | Created | Complete verification algorithm specification |
| `app/Documentation/PLAN_Phase9.md` | Created | Archived plan for Phase 9 |

### Summary

Extended VVP_Verifier_Specification_v1.4_FINAL with complete verification algorithms per authoritative VVP draft §5.

**New Sections:**
- §3.3B: Complete claim tree structure for caller and callee verification
- §4.2A: 8 new error codes (CREDENTIAL_REVOKED, CONTEXT_MISMATCH, AUTHORIZATION_FAILED, TN_RIGHTS_INVALID, BRAND_CREDENTIAL_INVALID, GOAL_REJECTED, DIALOG_MISMATCH, ISSUER_MISMATCH)
- §4.4: SIP Context Fields normative section
- §5A: 13-step Caller Verification Algorithm per VVP §5.1
- §5B: 14-step Callee Verification Algorithm per VVP §5.2
- §5C: Efficiency and Caching guidance per VVP §5.3
- §5D: Historical Verification capabilities per VVP §5.4
- §9: Full pseudocode for caller and callee verification with explicit claim node initialization
- §10.2: Test vectors tiered by implementation phase (Tier 1/2/3)
- §12: Implementation Tiers (Tier 1/2/3)
- Appendix A: Spec §5 Traceability Matrix

**Key Design Decisions:**
- SIP context absence produces INDETERMINATE, not rejection (policy-driven)
- Replay tolerance (30s) distinguished from iat binding tolerance (5s)
- `issuer_matched` placed under `dossier_verified` in callee claim tree
- Step-to-claim mapping tables added to prevent drift

### Spec Sections Implemented

- VVP §5.1.1-2.1 through §5.1.1-2.13: Caller verification algorithm
- VVP §5.2-2.1 through §5.2-2.14: Callee verification algorithm
- VVP §5.3: Efficiency and caching
- VVP §5.4: Historical verification

---

## Phase 3: PASSporT JWT Verification

**Date:** 2026-01-23
**Commit:** `38197e6`

### Files Changed

| File | Action | Description |
|------|--------|-------------|
| `app/vvp/exceptions.py` | Modified | Added PassportError exception class |
| `app/vvp/passport.py` | Created | PASSporT JWT parser and validator per §5.0-§5.4 |
| `tests/test_passport.py` | Created | 68 unit tests for PASSporT parsing |

### Summary

- Created `PassportError` exception class with factory methods:
  - `missing()` → `PASSPORT_MISSING`
  - `parse_failed(reason)` → `PASSPORT_PARSE_FAILED` (binding violations, structure errors)
  - `forbidden_alg(alg)` → `PASSPORT_FORBIDDEN_ALG`
  - `expired(reason)` → `PASSPORT_EXPIRED` (actual expiry policy failures only)
- Created frozen dataclasses: `PassportHeader`, `PassportPayload`, `Passport`
- Implemented `parse_passport(jwt)` function:
  - JWT structure parsing (header.payload.signature)
  - Algorithm enforcement: accept EdDSA only, reject none/ES256/HMAC/RSA (§5.0, §5.1)
  - Header validation: require `alg`, `ppt`, `kid`; ignore `typ` (§5.2)
  - Payload validation: require `iat`, `orig`, `dest`, `evd` (local policy)
  - Support optional fields: `iss`, `exp`, `card`, `goal`, `call-reason`→`call_reason`, `origid`
  - Validate `ppt` = "vvp" per §5.2
- Implemented `validate_passport_binding(passport, vvp_identity, now)` function:
  - `ppt` binding: PASSporT ppt must match VVP-Identity ppt (§5.2)
  - `kid` binding: strict equality in Phase 3 (§5.2)
  - `iat` drift: ≤5 seconds between PASSporT and VVP-Identity (§5.2A)
  - `exp > iat` validation (§5.2A)
  - `exp` drift: ≤5 seconds when both present (§5.2A)
  - Expiry policy: max validity 300s, clock skew ±300s (§5.2B)
- Preserved raw header/payload and signature bytes for Phase 4 signature verification

### Error Code Usage

| Error Code | Used For |
|------------|----------|
| `PASSPORT_MISSING` | JWT is None or empty |
| `PASSPORT_PARSE_FAILED` | Malformed JWT, invalid base64/JSON, missing fields, binding violations (ppt/kid mismatch, iat drift, exp mismatch) |
| `PASSPORT_FORBIDDEN_ALG` | Algorithm not in allowed list (only EdDSA accepted) |
| `PASSPORT_EXPIRED` | Token expired, validity window exceeded, max-age exceeded |

### Spec Sections Implemented

- §5.0 PASSporT Non-compliance Note
- §5.1 Allowed Algorithms (EdDSA only)
- §5.2 Header Binding Rules (ppt, kid)
- §5.2A Temporal Binding Rules (iat drift ≤5s, exp consistency)
- §5.2B PASSporT Expiry Policy (max validity 300s, clock skew ±300s)
- §5.4 Failure Mapping

### Checklist Tasks Completed

- [x] 3.1 - Create `app/vvp/passport.py` module
- [x] 3.2 - Parse JWT structure (header.payload.signature)
- [x] 3.3 - Reject `alg=none`
- [x] 3.4 - Reject ES256, HMAC, RSA algorithms
- [x] 3.5 - Accept only EdDSA (Ed25519)
- [x] 3.6 - Return PASSPORT_FORBIDDEN_ALG for algorithm violations
- [x] 3.7 - Extract header claims: `alg`, `typ` (ignored), `ppt`, `kid`
- [x] 3.8 - Extract VVP payload claims: `iat` (required), `orig`, `dest`, `evd` (local policy)
- [x] 3.9 - Extract optional VVP claims: `iss`, `card`, `goal`, `call-reason`, `origid`, `exp`
- [x] 3.10 - Validate `ppt` = "vvp" and matches VVP-Identity ppt (§5.2)
- [x] 3.11 - Validate `kid` binding (strict equality in Phase 3) (§5.2)
- [x] 3.12 - Defer signature verification (placeholder for Phase 4)
- [x] 3.13 - Unit tests for PASSporT parsing

### Test Results

```
139 passed in 0.22s (68 new + 71 from Phase 1+2)
```

---

## Phase 2: VVP-Identity Header Parser

**Date:** 2026-01-23
**Commit:** `70fd80f`

### Files Changed

| File | Action | Description |
|------|--------|-------------|
| `app/vvp/exceptions.py` | Created | Typed exceptions with error codes |
| `app/vvp/header.py` | Created | VVP-Identity header parser per §4.1A/B |
| `tests/test_header.py` | Created | 38 unit tests for header parsing |

### Summary

- Created `VVPIdentityError` exception class with factory methods for `VVP_IDENTITY_MISSING` and `VVP_IDENTITY_INVALID`
- Created `VVPIdentity` frozen dataclass with fields: `ppt`, `kid`, `evd`, `iat`, `exp`
- Implemented `parse_vvp_identity()` function:
  - Base64url decoding with padding fix
  - JSON parsing with UTF-8 validation
  - Required field validation: `ppt`, `kid`, `evd`, `iat`
  - Type validation: strings must be non-empty, integers must be actual integers (not booleans)
  - Clock skew validation for `iat` (±300s configurable)
  - Optional `exp` handling (defaults to `iat + MAX_TOKEN_AGE_SECONDS`)
- Treats `kid`/`evd` as opaque OOBI references (no URL validation)
- Does NOT validate `ppt` value (deferred to Phase 3/5 per §5.2)
- Distinguishes `VVP_IDENTITY_MISSING` (absent header) from `VVP_IDENTITY_INVALID` (parse/validation errors)

### Spec Sections Implemented

- §4.1A VVP-Identity Header (Decoded)
- §4.1B OOBI Semantics for kid/evd
- §4.2A Error Codes: VVP_IDENTITY_MISSING, VVP_IDENTITY_INVALID

### Checklist Tasks Completed

- [x] 2.1 - Create `app/vvp/header.py` module
- [x] 2.2 - Implement base64url decoding of VVP-Identity header
- [x] 2.3 - Parse JSON with fields: `ppt`, `kid`, `evd`, `iat`, `exp`
- [x] 2.4 - Validate `ppt` field exists (value validation deferred to Phase 3)
- [x] 2.5 - Validate `kid` and `evd` are present as opaque strings
- [x] 2.6 - Implement clock skew validation (±300s) on `iat`
- [x] 2.7 - Handle optional `exp`; if absent, use `iat` + 300s max age
- [x] 2.8 - Reject future `iat` beyond clock skew
- [x] 2.9 - Return structured errors: `VVP_IDENTITY_MISSING` vs `VVP_IDENTITY_INVALID`
- [x] 2.10 - Unit tests for header parsing

### Test Results

```
71 passed in 0.26s (38 new + 33 from Phase 1)
```

---

## Phase 1: Core Infrastructure

**Date:** 2026-01-23
**Commit:** `9546f37`

### Files Changed

| File | Action | Description |
|------|--------|-------------|
| `.gitignore` | Created | Python/IDE/OS ignores |
| `app/core/__init__.py` | Created | Empty package init |
| `app/core/config.py` | Created | Configuration constants per §4.1A, §5.2A/B |
| `app/vvp/api_models.py` | Replaced | Models per §3.2, §4.1-4.3, §4.2A |
| `app/vvp/verify.py` | Updated | Use new models (placeholder returns INDETERMINATE) |
| `tests/__init__.py` | Created | Test package init |
| `tests/test_models.py` | Created | 33 unit tests for Phase 1 models |
| `CLAUDE.md` | Created | Project instructions for Claude Code |
| `CHANGES.md` | Created | This change log |

### Summary

- Defined `ClaimStatus` enum (VALID, INVALID, INDETERMINATE) per §3.2
- Defined `ClaimNode` with `{required, node}` children structure per §4.3B
- Defined `ChildLink` model for explicit required/optional child relationships
- Defined `CallContext` model per §4.1
- Defined `VerifyRequest` model with required `passport_jwt` and `context` per §4.1
- Defined `VerifyResponse` model with `overall_status`, `claims`, `errors` per §4.2/§4.3
- Defined `ErrorDetail` model per §4.2
- Created 18 error codes per §4.2A with `ERROR_RECOVERABILITY` mapping
- Implemented `derive_overall_status()` function per §4.3A precedence rules
- Created configuration constants: clock skew (±300s), max token age (300s), max iat drift (5s), allowed algorithms (EdDSA)
- Updated `verify.py` to use new models (placeholder implementation)
- Created 33 unit tests covering all Phase 1 models

### Spec Sections Implemented

- §3.2 Claim Status
- §4.1 Request Models
- §4.2 Error Envelope
- §4.2A Error Code Registry
- §4.3 Response Models
- §4.3A overall_status Derivation
- §4.3B Claim Node Schema
- §4.1A, §5.2A/B Configuration Constants

### Checklist Tasks Completed

- [x] 1.1 - Create `app/core/config.py`
- [x] 1.2 - Define `ClaimStatus` enum
- [x] 1.3 - Define `ClaimNode` model
- [x] 1.4 - Define `VerifyRequest` model
- [x] 1.5 - Define `VerifyResponse` model
- [x] 1.6 - Define `ErrorDetail` model
- [x] 1.7 - Create error code constants
- [x] 1.8 - Implement `overall_status` derivation

### Test Results

```
33 passed in 0.14s
```
