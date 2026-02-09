# Sprint 54: Dossier Verification Performance — Characterization & Optimization

## Problem Statement

A single `verify_vvp()` call involves multiple sequential and parallel external HTTP calls, CPU-bound parsing, and in-memory caching operations. There is no instrumentation to identify where time is actually spent, which external endpoints are slow or dead, and which phases dominate latency. Without characterization data we cannot make evidence-based optimization decisions.

Additionally, several external endpoints are queried speculatively (e.g., schema registries, witness TEL endpoints, GLEIF discovery). When these endpoints are unreachable or slow, they silently add seconds of timeout to every verification request — potentially dominating total latency even though their failure is non-fatal.

## Goals

1. **Characterize** — Add structured timing instrumentation aligned with the dossier parsing algorithm document (`knowledge/dossier-parsing-algorithm.md`) and the verification pipeline phases, so we can measure real-world latency per algorithm stage.
2. **Produce an annotated algorithm document** — Update `knowledge/dossier-parsing-algorithm.md` with measured average timing per stage, using a suite of test dossiers of varying complexity.
3. **Surface dead endpoints** — Detect and log external endpoints that consistently fail or timeout, and expose this via a health/metrics endpoint.
4. **Optimize hot paths** — Apply targeted code-level optimizations to the highest-impact areas identified during the exploration phase.
5. **Background slow checks** — Move non-blocking external calls (revocation, schema resolution) out of the critical path where possible.

## Spec References

- §9: Verification orchestration (phases 2–13)
- §5C.2: Freshness policy (cache TTLs)
- §6.1B: Dossier fetch constraints (timeout 5s, size 1MB)
- §5.1.1-2.9: Revocation checking

## Current State

### Dossier Parsing Algorithm Stages (from `knowledge/dossier-parsing-algorithm.md`)

The dossier parsing pipeline has five stages. These must be the primary timing instrumentation points:

| Stage | Name | Source | Type |
|-------|------|--------|------|
| 1 | Format Detection & Raw Parsing | `dossier/parser.py:parse_dossier()` | CPU |
| 2 | CESR Stream Parsing | `keri/cesr.py:parse_cesr_stream()` | CPU |
| 3 | ACDC Extraction & Filtering | `dossier/parser.py` (lines 216-267) | CPU |
| 4 | DAG Construction & Structural Validation | `dossier/validator.py` | CPU |
| 4a | Build node index | `build_dag()` | CPU |
| 4b | Edge extraction | `extract_edge_targets()` | CPU |
| 4c | Cycle detection | `detect_cycle()` | CPU |
| 4d | Root identification | `find_roots()` | CPU |
| 4e | ToIP compliance warnings | `_collect_toip_warnings()` | CPU |
| 5 | Credential Integrity & Chain Validation | `verify.py` orchestration | CPU+I/O |
| 5a | SAID verification | `acdc/parser.py:validate_acdc_said()` | CPU |
| 5b | Variant detection | `detect_acdc_variant()` | CPU |
| 5c | Edge operator validation | `validate_all_edge_operators()` | CPU |
| 5d | Edge schema validation | `validate_all_edge_schemas()` | CPU+I/O |
| 5e | Credential type inference | `ACDC.credential_type` | CPU |

### Verification Pipeline Phases (from `verify.py`)

These wrap the dossier stages in a broader verification context:

| Phase | Name | Type | External Calls | Timeout |
|-------|------|------|---------------|---------|
| 2 | VVP-Identity Parse | CPU | None | — |
| 3 | PASSporT Parse + Bind | CPU | None | — |
| Cache | Verification cache lookup | CPU/Mem | None | — |
| 4 | KERI Signature (Tier 2) | **I/O** | OOBI fetch → KEL parse → key state | 5s |
| 5 | Dossier Fetch | **I/O** | HTTP GET dossier URL | 5s |
| 5-parse | Dossier Parse (Stages 1-4) | CPU | None | — |
| 5.5 | ACDC Chain Validation (Stage 5) | **I/O+CPU** | Schema fetch + External SAID resolution | 5s/source |
| 9 | Revocation Check | **I/O** | TEL queries to 6+ witnesses | 10s/witness |
| 10-11 | Authorization + Context | CPU | None | — |
| 11 | Brand + Business Logic | CPU | None | — |
| 40 | Vetter Constraints | CPU | None | — |

### Complete Timing Point Map

The following table defines every instrumentation point, cross-referenced to both the algorithm document and verify.py. This is the **authoritative list** of timer names:

| Timer Name | Algorithm Stage | Pipeline Phase | What It Measures |
|---|---|---|---|
| `vvp_identity_parse` | — | Phase 2 | VVP-Identity header decode + validate |
| `passport_parse` | — | Phase 3 | PASSporT JWT parse + binding |
| `cache_lookup` | — | Cache | Verification cache get (hit or miss) |
| `keri_signature` | — | Phase 4 | OOBI fetch + KEL parse + key state resolution |
| `keri_signature.oobi_fetch` | — | Phase 4 (sub) | HTTP fetch of OOBI URL |
| `keri_signature.kel_parse` | — | Phase 4 (sub) | KEL stream parse + chain validation |
| `keri_signature.key_state` | — | Phase 4 (sub) | Key state at time T lookup |
| `dossier_fetch` | — | Phase 5 | HTTP GET of evd URL |
| `dossier_parse` | Stages 1-3 | Phase 5 | Format detection + CESR/JSON parse + ACDC extraction |
| `dossier_parse.format_detect` | Stage 1 | Phase 5 (sub) | `_is_cesr_stream()` heuristic check |
| `dossier_parse.cesr_stream` | Stage 2 | Phase 5 (sub) | `parse_cesr_stream()` — JSON + attachment parsing |
| `dossier_parse.acdc_extract` | Stage 3 | Phase 5 (sub) | ACDC filtering from CESRMessages |
| `dag_build` | Stage 4a | Phase 5 | `build_dag()` — SAID index |
| `dag_validate` | Stage 4b-4e | Phase 5 | Edge extraction + cycle + roots + ToIP warnings |
| `dag_validate.edges` | Stage 4b | Phase 5 (sub) | `extract_edge_targets()` |
| `dag_validate.cycle` | Stage 4c | Phase 5 (sub) | `detect_cycle()` DFS |
| `dag_validate.roots` | Stage 4d | Phase 5 (sub) | `find_roots()` |
| `dag_validate.toip` | Stage 4e | Phase 5 (sub) | `_collect_toip_warnings()` |
| `chain_validate` | Stage 5 | Phase 5.5 | Full chain validation per leaf |
| `chain_validate.said_verify` | Stage 5a | Phase 5.5 (sub) | `validate_acdc_said()` per credential |
| `chain_validate.variant` | Stage 5b | Phase 5.5 (sub) | `detect_acdc_variant()` |
| `chain_validate.operators` | Stage 5c | Phase 5.5 (sub) | `validate_all_edge_operators()` |
| `chain_validate.schemas` | Stage 5d | Phase 5.5 (sub) | `validate_all_edge_schemas()` (may involve I/O) |
| `chain_validate.schema_fetch` | Stage 5d (I/O) | Phase 5.5 (sub) | Individual schema HTTP fetch |
| `chain_validate.type_infer` | Stage 5e | Phase 5.5 (sub) | `credential_type` property |
| `acdc_sig_verify` | — | Phase 5.5 | ACDC signature verification (issuer key resolve + Ed25519) |
| `revocation_check` | — | Phase 9 | Inline TEL check + dossier TEL parse |
| `revocation_check.inline_tel` | — | Phase 9 (sub) | `parse_dossier_tel()` per credential |
| `revocation_check.witness_query` | — | Phase 9 (sub) | HTTP TEL query to witnesses |
| `authorization` | — | Phase 10-11 | Authorization + TN rights validation |
| `sip_context` | — | Phase 13 | SIP context alignment |
| `brand_verify` | — | Phase 11 | Brand verification |
| `business_logic` | — | Phase 11 | Goal/business logic |
| `vetter_constraints` | — | Phase 40 | Vetter certification constraints |
| `claim_tree_build` | — | Phase 6 | Build and propagate claim tree |
| `total` | — | — | End-to-end verify_vvp() wall clock |

### External HTTP Call Inventory

| Call Site | File | Endpoint Pattern | Timeout | Failure Mode | Impact |
|-----------|------|-----------------|---------|-------------|--------|
| Dossier fetch | `common/vvp/dossier/fetch.py` | `{evd_url}` (user-supplied) | 5s | FetchError → INDETERMINATE | Blocks Phase 5 |
| OOBI dereference | `keri/oobi.py:81` | `{kid_oobi_url}` | 5s | ResolutionFailedError → INDETERMINATE | Blocks Phase 4 |
| Schema fetch (legacy) | `acdc/schema_fetcher.py:67` | `schema.gleif.org/{said}`, `schema.provenant.net/{said}` | 10s | ResolutionFailedError → INDETERMINATE | Per-credential in Phase 5.5 |
| Schema resolve (new) | `acdc/schema_resolver.py:411` | Same registries + GitHub raw | 5s | None → INDETERMINATE | Per-credential in Phase 5.5 |
| TEL via OOBI | `keri/tel_client.py:291` | `{witness}/query?typ=tel&vcid={said}` | 10s | ERROR → tries next witness | Per-credential in Phase 9 |
| TEL via witness | `keri/tel_client.py:344` | `{witness}/query?typ=tel&vcid={said}`, `{witness}/tels/{said}` | 10s | ERROR → tries next witness | Per-credential in Phase 9 |
| GLEIF witness discovery | `keri/witness_pool.py` | `gleif.org/.well-known/keri/oobi/{root_aid}` | implicit | Degrades to Provenant-only | Lazy, first-use |
| External SAID resolution | `keri/credential_resolver.py` | `{witness}/credentials/{said}` | 5s | None → INDETERMINATE | Per-missing-edge in Phase 5.5 |

### Key Observations

1. **New `httpx.AsyncClient` per call** — Every external HTTP call creates and tears down a fresh `httpx.AsyncClient`. No TCP connection reuse, no HTTP/2 multiplexing, repeated TLS handshakes. Worst case: 10+ separate TCP connections per verification.

2. **TEL queries are sequential per witness** — `check_revocation()` in `tel_client.py:250` iterates witnesses sequentially, creating a new `httpx.AsyncClient` per witness per credential. With 6 Provenant witnesses at 10s timeout, worst case is 60s+ for one credential.

3. **Schema registries may be unreachable** — `schema.gleif.org` and `schema.provenant.net` are external third-party endpoints. If down, each schema fetch adds 5-10s of timeout per credential.

4. **No metrics on endpoint health** — No tracking of which endpoints consistently fail. A dead witness eats its full timeout before being skipped.

5. **Revocation is on the critical path** — Phase 9 runs inline. For cache misses, TEL queries block the response.

6. **`compute_config_fingerprint()` per cache get** — SHA-256 hash of 6 config values that never change at runtime.

7. **O(n) LRU eviction** — Both `VerificationResultCache` and `KeyStateCache` use `list.remove()` for LRU tracking.

8. **Lazy imports in hot loops** — `pysodium`, `blake3`, `base64`, `math`, `re` imported inside functions called per-signature, per-event, per-SAID.

## Test Dossier Matrix

Performance characterization requires dossiers of varying complexity. The matrix below defines the test serials. Rows marked **Provenant** will use real dossiers fetched from the Provenant staging environment; rows marked **Synthetic** will be constructed programmatically.

### Complexity Dimensions

| Dimension | Low | Medium | High |
|---|---|---|---|
| **Credential count** | 1-2 | 3-5 | 6+ |
| **Chain depth** | 1 (single ACDC) | 2-3 (LE→QVI) | 4+ (APE→LE→QVI→GLEIF) |
| **Wire format** | Plain JSON | JSON+CESR attachments | Full CESR binary stream |
| **Delegation** | None | Single DE | Multi-level delegation |
| **Variant** | Full (all attrs) | Compact (SAID attrs) | Partial (selective disclosure) |
| **Inline TEL** | None | Present for some creds | Present for all creds |

### Test Serial Definitions

| Serial ID | Source | Complexity | Credentials | Chain Depth | Format | Delegation | Purpose |
|---|---|---|---|---|---|---|---|
| `PERF-S1` | Synthetic | Minimal | 1 | 1 | JSON | None | Baseline: single ACDC, no edges |
| `PERF-S2` | Synthetic | Simple | 3 | 3 | JSON | None | Linear chain: TN→LE→QVI |
| `PERF-S3` | Synthetic | Medium | 5 | 3 | JSON | Single DE | Chain with delegation edge |
| `PERF-S4` | Synthetic | JSON+CESR | 3 | 3 | CESR | None | CESR parsing overhead |
| `PERF-S5` | Synthetic | Compact | 3 | 3 | JSON | None | Compact variants (SAID attrs) |
| `PERF-P1` | Provenant | Real-world | TBD | TBD | CESR | TBD | Provenant dossier — simple |
| `PERF-P2` | Provenant | Real-world | TBD | TBD | CESR | TBD | Provenant dossier — medium |
| `PERF-P3` | Provenant | Real-world | TBD | TBD | CESR | TBD | Provenant dossier — complex |
| `PERF-P4` | Provenant | Real-world | TBD | TBD | CESR | TBD | Provenant dossier — edge case |
| `PERF-E1` | Existing | Complex | 6+ | 4+ | JSON | Multi | `tests/fixtures/trial_dossier.json` |
| `PERF-E2` | Existing | Simple | 3 | 3 | JSON | None | SIP-redirect `acme_dossier.json` |

The Provenant serials (`PERF-P*`) will be populated with real dossier SAIDs provided by the user. Each SAID will be resolved via the default EVD URL pattern:
```
https://origin.demo.provenant.net/v1/agent/public/{SAID}/dossier.cesr
```

Once SAIDs are provided, the `conftest.py` will be updated with the concrete values and their known characteristics (credential count, chain depth, etc.).

### Test Harness

**File:** `services/verifier/tests/perf/test_dossier_perf.py` (new)

A dedicated performance characterization test suite that:

1. Loads each test serial (synthetic from builders, Provenant from network, existing from fixtures)
2. Runs the dossier-only pipeline (`parse_dossier()` → `build_dag()` → `validate_dag()`) with timing hooks to isolate CPU parsing from I/O
3. Runs the full `verify_vvp()` pipeline with timing instrumentation for Provenant dossiers (requires network)
4. Collects timing data per algorithm stage for each serial
5. Outputs a timing report table (markdown) showing avg/p50/p95 per stage per serial
6. The report is used to annotate the algorithm document

Test isolation:
- **Offline tests** (PERF-S*, PERF-E*): Run without network. Use pre-fetched fixtures or synthetic builders. These measure pure CPU parsing performance.
- **Online tests** (PERF-P*): Require network access to Provenant staging. Gated by `--run-perf-online` pytest marker. These measure end-to-end latency including all I/O.

**Synthetic dossier builder:**

**File:** `services/verifier/tests/perf/dossier_builder.py` (new)

```python
class TestDossierBuilder:
    """Builds synthetic dossiers of specified complexity for perf testing.

    Each builder returns raw bytes in the target wire format, suitable for
    passing directly to parse_dossier(). SAIDs are computed correctly so
    that Stage 5a (SAID verification) passes.
    """

    def build_single_acdc(self) -> bytes:
        """PERF-S1: Single ACDC, plain JSON, no edges."""

    def build_linear_chain(self, depth: int = 3) -> bytes:
        """PERF-S2: TN->LE->QVI linear chain."""

    def build_with_delegation(self, de_count: int = 1) -> bytes:
        """PERF-S3: Chain with delegation edges."""

    def build_cesr_stream(self, depth: int = 3) -> bytes:
        """PERF-S4: Same as S2 but in CESR wire format with attachments."""

    def build_compact_variants(self, depth: int = 3) -> bytes:
        """PERF-S5: Chain where attributes are SAID strings (compact)."""
```

## Proposed Solution

### Approach

A phased approach: **instrument first** (aligned to the algorithm doc), **measure** using the test dossier matrix, **optimize** based on data, then **background** slow non-critical work.

### Alternatives Considered

| Alternative | Pros | Cons | Why Rejected |
|---|---|---|---|
| Rewrite in Rust/C | Maximum performance | Massive effort, breaks codebase | Disproportionate to problem |
| Add async parallelism to all phases | Reduces wall-clock time | Complicates error handling, some phases depend on prior | Partial — apply only where safe |
| Full caching layer (Redis/memcached) | Distributes across instances | Operational complexity, VVP runs single-instance | Over-engineered for current scale |

### Detailed Design

#### Part 1: Timing Instrumentation (aligned to algorithm doc)

**File:** `services/verifier/app/vvp/timing.py` (new)

A lightweight phase timer supporting hierarchical (nested) timing:

```python
@dataclass
class PhaseTimer:
    """Collects per-phase timing for a verification request.

    Supports nested sub-phases via dotted names (e.g., "dossier_parse.cesr_stream").
    """
    timings: Dict[str, float]  # phase_name -> elapsed_ms
    _stack: List[Tuple[str, float]]  # (phase_name, start_time) stack

    def start(self, phase: str) -> None: ...
    def stop(self) -> float: ...
    def to_dict(self) -> Dict[str, float]: ...
    def to_summary_table(self) -> str:
        """Format timings as a markdown table for the algorithm doc."""
```

**Integration:** Every timer name from the "Complete Timing Point Map" table above is instrumented. Sub-phases use context managers or explicit start/stop:

```python
timer.start("dossier_parse")
timer.start("dossier_parse.format_detect")
is_cesr = _is_cesr_stream(raw)
timer.stop()  # stops format_detect
timer.start("dossier_parse.cesr_stream")
messages = cesr.parse_cesr_stream(raw)
timer.stop()  # stops cesr_stream
timer.start("dossier_parse.acdc_extract")
nodes = [parse_acdc(m) for m in messages]
timer.stop()  # stops acdc_extract
timer.stop()  # stops dossier_parse (total)
```

#### Part 2: Endpoint Health Tracker

**File:** `services/verifier/app/vvp/endpoint_health.py` (new)

Track success/failure/latency for external endpoints:

```python
@dataclass
class EndpointStats:
    url_pattern: str           # e.g. "schema.gleif.org/*"
    total_requests: int
    successes: int
    failures: int
    timeouts: int
    avg_latency_ms: float
    p95_latency_ms: float
    last_success: Optional[float]
    last_failure: Optional[float]
    consecutive_failures: int

class EndpointHealthTracker:
    """Tracks health of external endpoints with circuit breaker."""

    def record_success(self, url: str, latency_ms: float): ...
    def record_failure(self, url: str, error: str): ...
    def record_timeout(self, url: str): ...
    def is_healthy(self, url: str) -> bool: ...  # circuit breaker
    def get_stats(self) -> Dict[str, EndpointStats]: ...
```

**Circuit breaker:** After N consecutive failures (default 5), mark endpoint as unhealthy for M seconds (default 60). Skip unhealthy endpoints to avoid wasting timeout budget. Auto-recover by probing periodically.

**Integration:** Wrap all `httpx` calls in endpoint health recording. Expose via `/healthz/endpoints` API.

#### Part 3: Code-Level Optimizations

**3a. Module-level imports for hot-path dependencies**

Move these imports from function-level to module-level:

| File | Import | Call Frequency |
|------|--------|---------------|
| `keri/kel_parser.py:718` | `import pysodium` | Per signature |
| `keri/kel_parser.py:753,867` | `import blake3` | Per KEL event |
| `keri/cesr.py:298,324,415,875` | `import base64` | Per CESR segment |
| `keri/kel_parser.py:956` | `import math` | Per witness validation |
| `keri/signature.py:46,227` | `import pysodium` | Per verification |
| `canonical/keri_canonical.py:133` | `import re` | Per SAID computation |
| `verify.py:235` | `from urllib.parse import urlparse` | Duplicate — already at line 21 |
| `verify.py:851` | `import time as _time` | Per request |
| `verify.py:1203,1484` | `from datetime import datetime, timezone` | Per request |

**3b. OrderedDict for LRU caches**

Replace `list`-based `_access_order` with `OrderedDict` in:
- `verification_cache.py` (`VerificationResultCache`)
- `keri/cache.py` (`KeyStateCache`)

This changes `_touch()` from O(n) `list.remove()` + `list.append()` to O(1) `OrderedDict.move_to_end()`.

**3c. Cache `compute_config_fingerprint()`**

In `verification_cache.py`, compute the config fingerprint once at module load and store in a module-level variable. Config values come from `os.getenv()` at import time and never change.

**3d. B64 lookup table**

In `cesr.py`, replace `B64_CHARS.index(char)` (O(64) linear scan per char) with a pre-built `dict` lookup (O(1)).

**3e. Pre-compile regex patterns**

Move regex compilation to module level:
- `cesr.py:190` — CESR version string pattern
- `canonical/keri_canonical.py:167` — compact form version pattern

**3f. Shared `httpx.AsyncClient` for schema and TEL operations**

Create a module-level `httpx.AsyncClient` that is reused across calls (connection pooling, keepalive). Initialize on first use, close on shutdown.

- `acdc/schema_fetcher.py:67` — schema fetches
- `acdc/schema_resolver.py:411,501` — schema resolution
- `keri/tel_client.py:291,344` — TEL queries

This is the single highest-impact I/O optimization — connection reuse eliminates TCP+TLS handshake latency for repeated calls to the same host.

#### Part 4: Background Non-Critical Checks

**4a. Speculative revocation checking**

When verification cache hits, revocation data is already available. When it's stale, the current code enqueues a background re-check but still returns INDETERMINATE. This is correct. No change needed — just ensure the background checker actually runs (verify `RevocationChecker` is functional).

**4b. Schema prefetch on startup**

For the known vLEI schema SAIDs (embedded in `schema_store.py`), the embedded store already short-circuits network fetches. No change needed.

**4c. Witness TEL queries in parallel**

Change `tel_client.py` `check_revocation()` from sequential witness iteration to parallel `asyncio.as_completed()` with first-success-wins. This is the single most impactful latency optimization for Phase 9.

```python
# Current (sequential):
for witness_url in witness_urls:
    result = await self._query_witness(...)
    if result.status != CredentialStatus.ERROR:
        return result

# Proposed (parallel first-success):
tasks = [self._query_witness(cred, reg, url) for url in witness_urls]
for coro in asyncio.as_completed(tasks):
    result = await coro
    if result.status != CredentialStatus.ERROR:
        # Cancel remaining tasks
        for t in tasks: t.cancel()
        return result
```

#### Part 5: Annotated Algorithm Document

**Deliverable:** Updated `knowledge/dossier-parsing-algorithm.md`

After running the perf test suite across all test serials, the algorithm document will be updated with a new section:

```markdown
## Performance Characteristics

Measured on [environment description], [date].

### Per-Stage Timing (averaged across test serials)

| Stage | PERF-S1 | PERF-S2 | PERF-S4 | PERF-P1 | PERF-P3 | PERF-E1 |
|-------|---------|---------|---------|---------|---------|---------|
| 1. Format Detection | Xms | Xms | Xms | Xms | Xms | Xms |
| 2. CESR Stream Parse | — | — | Xms | Xms | Xms | — |
| 3. ACDC Extraction | Xms | Xms | Xms | Xms | Xms | Xms |
| 4a. Build DAG | Xms | Xms | Xms | Xms | Xms | Xms |
| 4b. Edge Extraction | Xms | Xms | Xms | Xms | Xms | Xms |
| 4c. Cycle Detection | Xms | Xms | Xms | Xms | Xms | Xms |
| 4d. Root ID | Xms | Xms | Xms | Xms | Xms | Xms |
| 4e. ToIP Warnings | Xms | Xms | Xms | Xms | Xms | Xms |
| 5a. SAID Verify | Xms | Xms | Xms | Xms | Xms | Xms |
| 5c. Edge Operators | Xms | Xms | Xms | Xms | Xms | Xms |
| 5d. Schema Validate | Xms | Xms | Xms | Xms | Xms | Xms |
| **Parse Total** | Xms | Xms | Xms | Xms | Xms | Xms |

### Per-Phase Timing (full verify_vvp pipeline, cold cache)

| Phase | PERF-S2 | PERF-P1 | PERF-P3 | PERF-E1 |
|-------|---------|---------|---------|---------|
| Dossier Fetch (I/O) | Xms | Xms | Xms | — |
| Dossier Parse (CPU) | Xms | Xms | Xms | Xms |
| Chain Validate | Xms | Xms | Xms | Xms |
| Schema Fetch (I/O) | Xms | Xms | Xms | Xms |
| Revocation (I/O) | Xms | Xms | Xms | Xms |
| Authorization (CPU) | Xms | Xms | Xms | Xms |
| **Total** | Xms | Xms | Xms | Xms |
```

This gives readers of the algorithm document concrete understanding of where time goes for each complexity tier.

### Data Flow

```
verify_vvp() request arrives
  |
  +-- Phase 2-3: CPU parse (microseconds) -- timer records
  |
  +-- Cache check -- O(1) with OrderedDict -- timer records
  |   +-- (hit) -> skip phases 4-9, use cached artifacts
  |
  +-- Phase 4: OOBI fetch -- health tracker records success/fail
  |   +-- uses shared httpx client (connection reuse)
  |
  +-- Phase 5: Dossier fetch -- health tracker records
  |   +-- uses shared httpx client
  |
  +-- Phase 5 parse (Stages 1-4):
  |   +-- timer: dossier_parse.format_detect (Stage 1)
  |   +-- timer: dossier_parse.cesr_stream   (Stage 2)
  |   +-- timer: dossier_parse.acdc_extract  (Stage 3)
  |   +-- timer: dag_build                   (Stage 4a)
  |   +-- timer: dag_validate.edges          (Stage 4b)
  |   +-- timer: dag_validate.cycle          (Stage 4c)
  |   +-- timer: dag_validate.roots          (Stage 4d)
  |   +-- timer: dag_validate.toip           (Stage 4e)
  |
  +-- Phase 5.5: Chain validation (Stage 5)
  |   +-- timer: chain_validate.said_verify  (Stage 5a)
  |   +-- timer: chain_validate.variant      (Stage 5b)
  |   +-- timer: chain_validate.operators    (Stage 5c)
  |   +-- timer: chain_validate.schemas      (Stage 5d, may involve I/O)
  |   +-- timer: chain_validate.type_infer   (Stage 5e)
  |
  +-- Phase 9: Revocation -- parallel witness queries
  |   +-- skip unhealthy witnesses (circuit breaker)
  |
  +-- Phases 10-40: CPU-only (microseconds)
  |
  +-- Response includes optional timing breakdown
```

### Error Handling

- Endpoint health tracker failures are non-fatal (degrade gracefully to no circuit breaking).
- Timing instrumentation failures are non-fatal (log warning, continue without timing).
- Shared httpx client is created lazily; if creation fails, falls back to per-call clients.
- Provenant test dossiers that return HTTP errors are logged and excluded from timing averages.

### Test Strategy

1. **Unit tests for `PhaseTimer`** — verify timing collection, start/stop semantics, nested phases.
2. **Unit tests for `EndpointHealthTracker`** — verify circuit breaker logic, stats accumulation.
3. **Unit tests for LRU optimization** — verify OrderedDict-based cache maintains correct eviction order.
4. **Integration test for parallel TEL queries** — mock witnesses, verify first-success-wins behavior.
5. **Perf test suite** (`tests/perf/test_dossier_perf.py`) — runs all test serials, produces timing report.
6. **Regression tests** — all existing tests must pass unchanged (optimizations are behavioral no-ops).

## Files to Create/Modify

| File | Action | Purpose |
|------|--------|---------|
| `services/verifier/app/vvp/timing.py` | Create | Phase timer instrumentation (hierarchical) |
| `services/verifier/app/vvp/endpoint_health.py` | Create | Endpoint health tracking + circuit breaker |
| `services/verifier/tests/perf/__init__.py` | Create | Package init |
| `services/verifier/tests/perf/conftest.py` | Create | Provenant SAID fixtures + env config |
| `services/verifier/tests/perf/dossier_builder.py` | Create | Synthetic dossier builder for test serials |
| `services/verifier/tests/perf/test_dossier_perf.py` | Create | Perf characterization test suite |
| `knowledge/dossier-parsing-algorithm.md` | Modify | Add Performance Characteristics section with measured timings |
| `services/verifier/app/vvp/verify.py` | Modify | Add timing instrumentation to all phases |
| `services/verifier/app/vvp/dossier/parser.py` | Modify | Add timing hooks for Stages 1-3 |
| `services/verifier/app/vvp/dossier/validator.py` | Modify | Add timing hooks for Stages 4a-4e |
| `services/verifier/app/vvp/verification_cache.py` | Modify | OrderedDict LRU, cached config fingerprint |
| `services/verifier/app/vvp/keri/cache.py` | Modify | OrderedDict LRU |
| `services/verifier/app/vvp/keri/kel_parser.py` | Modify | Module-level imports (pysodium, blake3, math) |
| `services/verifier/app/vvp/keri/cesr.py` | Modify | Module-level imports, B64 lookup table, pre-compiled regex |
| `services/verifier/app/vvp/keri/signature.py` | Modify | Module-level pysodium import |
| `services/verifier/app/vvp/keri/tel_client.py` | Modify | Parallel witness queries, shared httpx client, health tracking |
| `services/verifier/app/vvp/acdc/schema_fetcher.py` | Modify | Shared httpx client |
| `services/verifier/app/vvp/acdc/schema_resolver.py` | Modify | Shared httpx client, health tracking |
| `services/verifier/app/vvp/keri/oobi.py` | Modify | Shared httpx client, health tracking |
| `common/common/vvp/canonical/keri_canonical.py` | Modify | Module-level re import, pre-compiled regex |
| `common/common/vvp/dossier/fetch.py` | Modify | Shared httpx client, health tracking |
| `services/verifier/app/main.py` | Modify | Register httpx client lifecycle, health endpoint |
| `services/verifier/tests/test_timing.py` | Create | PhaseTimer unit tests |
| `services/verifier/tests/test_endpoint_health.py` | Create | EndpointHealthTracker unit tests |
| `services/verifier/tests/test_parallel_tel.py` | Create | Parallel TEL query tests |

## Open Questions

1. **Should timing data be in the API response by default?** Recommendation: off by default, enabled via `VVP_TIMING_ENABLED=true` env var for profiling.
2. **Circuit breaker thresholds** — 5 consecutive failures / 60s cooldown are reasonable defaults. Should these be configurable?
3. **Shared httpx client lifetime** — Should it live for the app lifetime (with connection pool limits) or be recreated periodically?
4. **Provenant dossier SAIDs** — User to provide SAIDs for PERF-P1 through PERF-P4. These should cover a range from simple to complex real-world dossiers.

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Shared httpx client leaks connections | Low | Medium | Configure pool limits, add shutdown hook |
| Parallel TEL queries overload witnesses | Low | Low | Limit to 3 concurrent per credential |
| Circuit breaker incorrectly marks healthy endpoint | Low | Medium | Conservative thresholds, auto-recovery probe |
| Module-level imports fail on missing deps | Low | High | Keep try/except for optional deps (blake3) |
| Timing instrumentation adds overhead | Very Low | Very Low | Timestamps are nanosecond-resolution, negligible |
| Provenant staging dossiers unavailable | Medium | Low | Graceful skip in test suite, synthetic serials still run |

## Exit Criteria

1. All existing tests pass unchanged
2. `PhaseTimer` captures timing for all phases/stages in the Complete Timing Point Map
3. `EndpointHealthTracker` records stats for all external HTTP calls
4. `/healthz/endpoints` API returns endpoint health data
5. LRU caches use O(1) operations (OrderedDict)
6. Lazy imports moved to module level for hot-path code
7. TEL witness queries run in parallel
8. Shared httpx client reused across calls
9. Timing logs visible at INFO level for production profiling
10. `knowledge/dossier-parsing-algorithm.md` updated with Performance Characteristics section containing measured timings from test serial runs
11. Test dossier matrix (PERF-S1..S5, PERF-P1..P4, PERF-E1..E2) exercised with timing data collected
