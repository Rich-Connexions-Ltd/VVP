# Dossier Parsing Algorithm: From Raw Bytes to Parsed Credential DAG

The dossier parsing pipeline transforms raw bytes (received via HTTP from an evidence URL) into a validated directed acyclic graph of ACDC credentials. The algorithm has five distinct stages.

## Stage 1: Format Detection and Raw Parsing

**Entry point:** `services/verifier/app/vvp/dossier/parser.py:parse_dossier()` (line 183)

The parser first determines the wire format of the incoming bytes using `_is_cesr_stream()` (line 135), which applies three heuristics:

1. **CESR version marker** — bytes start with `-_AAA` (the KERI ACDC Protocol Stack prefix)
2. **Bare count code** — bytes start with `-` (a CESR attachment group)
3. **JSON + CESR attachments** — bytes start with `{` (JSON), and after the balanced-brace JSON object ends, the next non-whitespace byte is `-` (indicating trailing CESR attachments)

If none match, the data is treated as **plain JSON** (single object or array). There is also a special case for the **Provenant wrapper format** where the real content is nested inside a `{"details": "..."}` envelope (line 276), which recurses back into `parse_dossier()`.

## Stage 2: CESR Stream Parsing (Binary Wire Format)

**Module:** `services/verifier/app/vvp/keri/cesr.py:parse_cesr_stream()` (line 613)

When CESR format is detected, the stream is parsed into a sequence of `CESRMessage` objects, each containing a JSON event and its trailing cryptographic attachments.

The parser alternates between two modes as it walks the byte stream:

**JSON event extraction** — When a `{` is encountered, `_find_json_end()` (line 555) uses brace-depth tracking (respecting string escapes) to find the matching `}`. The bytes between are decoded as UTF-8 JSON.

**Attachment parsing** — Immediately after each JSON event, the parser looks for CESR count codes (lines starting with `-`). Each count code has a 2-character "hard code" identifying the attachment type, and a 2-character base64 "soft code" encoding the item count:

| Count Code | Attachment Type | Item Size |
|---|---|---|
| `-A##` | Controller indexed signatures | 88 chars each |
| `-B##` | Witness indexed signatures | 88 chars each |
| `-C##` | Non-transferable receipt couples | 132 chars (44 AID + 88 sig) |
| `-D##` | Transferable receipt quadruples | 200 chars (44 prefix + 24 snu + 44 digest + 88 sig) |
| `-V##` | Attachment group (quadlet count) | Wraps nested codes |

Each 88-character indexed signature is decoded: the first 2 characters are a derivation code (`0A`, `0B`, etc.) encoding the signer index, and the remaining 86 characters are URL-safe base64 encoding 64 bytes of Ed25519 signature. The full 88 chars are decoded as a CESR primitive, and the 2 lead bytes are stripped to yield the raw 64-byte signature.

The `-V` attachment group is a container — its count is in quadlets (4-byte groups), and the parser recurses into the group to parse the nested `-A`/`-B`/`-C`/`-D` codes within its declared boundary.

**Fallback:** If strict CESR parsing raises any exception, the parser falls back to `_extract_json_events_permissive()` (line 78), which scans the entire byte stream for balanced-brace JSON objects without attempting to interpret CESR attachments. Signatures are not available in permissive mode.

## Stage 3: ACDC Extraction and Filtering

**Back in:** `parser.py:parse_dossier()` (lines 216-267)

A CESR stream often contains both **KEL events** (key event log entries: inception, rotation, interaction) and **ACDCs** (credentials). The parser distinguishes them:

- **KEL events** have a `"t"` field (event type like `icp`, `rot`, `ixn`) and a numeric `"s"` (sequence number). These are skipped.
- **ACDCs** lack `"t"`, have required fields `"d"` (SAID), `"i"` (issuer), and `"s"` (schema SAID where the value starts with `E`, indicating a Blake3-256 CESR-encoded hash).

Each qualifying event is passed to `parse_acdc()` (line 25), which validates that `d`, `i`, and `s` are present strings, and constructs an `ACDCNode` (defined in `common/common/vvp/models/dossier.py:97`):

```
ACDCNode(said, issuer, schema, attributes, edges, rules, raw)
```

The first controller signature from each `CESRMessage` (if any) is stored in a `signatures` dict keyed by SAID. In permissive mode, SAIDs are deduplicated to handle the common case of seeing the same credential repeated with different KEL context.

## Stage 4: DAG Construction and Structural Validation

**Module:** `services/verifier/app/vvp/dossier/validator.py`

### 4a. Build the node index

`build_dag()` (line 56) creates a `DossierDAG` and indexes each `ACDCNode` by its SAID. Duplicate SAIDs raise `GraphError`.

### 4b. Edge extraction

`extract_edge_targets()` (line 24) inspects each node's `e` (edges) field. Edges are a dict of labeled references. Each edge value is either:
- A **structured object** `{"n": "<target SAID>", "s": "<schema SAID>", "o": "<operator>"}` — the `n` field is the target.
- A **bare SAID string** — the string itself is the target.
- The key `"d"` is the edge block's own SAID and is skipped.

### 4c. Cycle detection

`detect_cycle()` (line 78) runs three-color DFS (WHITE/GRAY/BLACK). A back-edge to a GRAY node proves a cycle. Dangling references (edges pointing outside the dossier) are ignored — they may reference external credentials resolvable via the witness pool.

### 4d. Root identification

`find_roots()` (line 132) collects all SAIDs that are never the target of any edge. This set must contain exactly one SAID for a standard dossier (the root of the credential chain, typically an LE credential). Multiple roots are allowed only if aggregate dossier support is enabled via configuration.

### 4e. ToIP compliance warnings

`_collect_toip_warnings()` (line 234) scans every node for informational (non-blocking) issues:
- `EDGE_MISSING_SCHEMA` — structured edge with `n` but no `s`
- `EDGE_NON_OBJECT_FORMAT` — bare SAID edge instead of `{n, s}` object
- `DOSSIER_HAS_ISSUEE` — root credential has an issuee field or registry ID
- `DOSSIER_HAS_PREV_EDGE` — versioning edge present
- `EVIDENCE_IN_ATTRIBUTES` — evidence-like fields in `a` instead of `e`
- `JOINT_ISSUANCE_OPERATOR` — `thr`/`fin`/`rev` operators in rules block

### Result

A fully populated `DossierDAG`:

```
DossierDAG(
    nodes: {SAID -> ACDCNode},
    root_said: str,
    root_saids: [str],
    is_aggregate: bool,
    warnings: [DossierWarning]
)
```

## Stage 5: Credential Integrity and Chain Validation

After the DAG is constructed, each credential undergoes deeper validation (orchestrated from `verify.py`):

### 5a. SAID verification

`services/verifier/app/vvp/acdc/parser.py:validate_acdc_said()` (line 132) recomputes each credential's self-addressing identifier:

1. Replace the `d` field with a placeholder of matching length (`E###...###`)
2. Serialize to **ACDC canonical JSON** with deterministic field ordering: `v, d, i, s, a, e, r` — no whitespace, UTF-8 encoded (line 202, `_acdc_canonical_serialize()`)
3. Compute Blake3-256 hash of the canonical bytes
4. CESR-encode with `E` derivation code prefix -> 44-character SAID
5. Compare to the credential's declared `d` field

### 5b. Variant detection

`detect_acdc_variant()` (line 13) classifies each credential:
- **Full** — attributes is a dict, no underscore placeholders -> complete verification possible
- **Compact** — attributes is absent or is a SAID string -> external resolution needed
- **Partial** — any value is `"_"` or `"_:<type>"` (selective disclosure) -> redacted fields unverifiable

### 5c. Edge operator validation

`validate_all_edge_operators()` (line 732) checks every edge against its declared operator:
- **I2I** (default): `child.issuer == parent.issuee` — strict authority chain
- **DI2I**: allows delegated issuers via DE credentials in the dossier
- **NI2I**: permissive, always passes (reference-only edges)

DI2I validation (`_check_dossier_delegation()`, line 565) walks a chain of DE (Delegate Entity) credentials looking for a path from the child's issuer to the parent's issuee, with cycle detection and a configurable max depth of 10.

### 5d. Edge schema validation

`validate_all_edge_schemas()` (line 824) checks that when an edge declares a schema constraint (`"s"` field), the target credential's actual schema SAID matches.

### 5e. Credential type inference

The `ACDC.credential_type` property (`common/common/vvp/models/acdc.py:71`) identifies credential types (LE, APE, DE, TNAlloc, OOR, etc.) using a priority chain: schema SAID registry lookup -> edge-name heuristics -> attribute inspection.

## Data Flow Summary

```
HTTP Response (raw bytes)
    |
    +-- CESR stream? --> parse_cesr_stream() --> [CESRMessage]
    |                        |                       |
    |                        | (on failure)          +-- Filter: skip KEL events
    |                        v                       |   (has "t" field)
    |                   _extract_json_events_        |
    |                   permissive()                 +-- parse_acdc() per event
    |                                                |
    +-- JSON? --> json.loads() --> parse_acdc()      |
    |                                                |
    +-- Provenant? --> unwrap "details" --> recurse   |
    |                                                v
    |                                    [ACDCNode], {SAID -> sig_bytes}
    |
    v
build_dag()          ->  DossierDAG with SAID-indexed nodes
detect_cycle()       ->  Verify DAG property (no back edges)
find_roots()         ->  Identify root credential(s)
_collect_toip_warnings() -> Informational compliance warnings
    |
    v
validate_acdc_said() ->  Cryptographic integrity (Blake3-256)
detect_acdc_variant()->  Full / Compact / Partial classification
validate_edge_operators() -> I2I/DI2I/NI2I chain constraints
validate_edge_schemas()   -> Type-safety on edge targets
    |
    v
Fully validated DossierDAG with:
  - Root credential identified
  - All SAIDs verified
  - Edge constraints checked
  - Credential types inferred
  - Warnings collected
```

## Design Principles

The key design principle throughout is **graceful degradation**: strict CESR parsing falls back to permissive JSON extraction; compact/partial variants produce INDETERMINATE rather than INVALID; ToIP warnings are informational rather than blocking. This reflects the VVP spec's section 2.2 principle that "uncertainty must be explicit" — the system distinguishes between definitively invalid credentials and those that simply cannot be fully verified with the available evidence.

## Performance Characteristics

Measured with `tests/perf/test_dossier_perf.py` (Sprint 54). All times are wall-clock milliseconds on a single core. The `verify.py` orchestrator accepts an optional `PhaseTimer` parameter for per-request instrumentation.

### Per-Stage Timing (representative fixtures)

| Stage | trial_dossier.json (129 KB, 6 ACDCs, Provenant wrapper) | acme_dossier.json (1.8 KB, 3 ACDCs, plain JSON) |
|---|---|---|
| **1. Format Detection** (`_is_cesr_stream`) | 6.1 ms | <0.01 ms |
| **1-3. parse_dossier** (detect + parse + extract) | 58.7 ms (first call) / 12.0 ms avg (warm) | 0.07 ms |
| **4a. DAG Construction** (`build_dag`) | 0.01 ms | 0.01 ms |
| **4b. DAG Validation** (`validate_dag`) | 0.07 ms | 0.04 ms |
| **5a. SAID Verification** (`validate_acdc_said`) | 124 ms | 0.01 ms |

**Key observations:**

- **Format detection is O(n) for JSON-then-CESR**: `_is_cesr_stream()` must scan the entire JSON body (brace-depth tracking) before checking for a trailing `-` CESR attachment code. For the 129 KB Provenant wrapper this costs ~6 ms. For bare CESR (prefix check) or short JSON (<2 KB) it is <0.01 ms.
- **SAID verification dominates CPU time**: Blake3 hashing each credential's canonical form is the most expensive offline operation (124 ms for 6 ACDCs). This is proportional to credential count and payload size.
- **DAG construction and validation are negligible**: Even for 50-credential chains, `build_dag` + `validate_dag` < 0.2 ms combined.
- **First-call overhead**: The initial `parse_dossier` call includes import-time costs (~58 ms). Subsequent calls average 12 ms for the trial dossier.

### Scaling by Credential Count (synthetic linear chains)

| Credentials | Bytes | parse_dossier (ms) | DAG build+validate (ms) | Total (ms) |
|---|---|---|---|---|
| 3 | 999 | 0.018 | 0.030 | 0.048 |
| 5 | 1,739 | 0.020 | 0.023 | 0.042 |
| 10 | 3,589 | 0.058 | 0.049 | 0.107 |
| 20 | 7,298 | 0.058 | 0.076 | 0.134 |
| 50 | 18,428 | 0.141 | 0.193 | 0.334 |
| 100 | 36,978 | 0.264 | 0.365 | 0.630 |

Scaling is approximately linear. A 100-credential chain (37 KB) completes all offline stages in <1 ms.

### Variance (20 iterations, trial_dossier.json)

| Stage | avg (ms) | median (ms) | min (ms) | max (ms) | stdev (ms) |
|---|---|---|---|---|---|
| parse_dossier | 12.26 | 11.98 | 11.63 | 14.18 | 0.78 |
| dag_build | 0.005 | 0.004 | 0.003 | 0.010 | 0.002 |
| dag_validate | 0.048 | 0.046 | 0.039 | 0.063 | 0.007 |

Low variance (CV < 7% for parse_dossier) indicates stable, predictable performance.

### Timing Instrumentation

The `verify.py` orchestrator is instrumented with optional `PhaseTimer` hooks at these boundaries:

| Timer Phase | verify.py Section | What It Measures |
|---|---|---|
| `total` | Full `verify_vvp()` | End-to-end verification |
| `phase2_identity` | VVP-Identity header parse | Header parsing (pure CPU) |
| `phase3_passport` | PASSporT parse + binding | JWT decode + field validation |
| `phase4_signature` | KERI signature verification | OOBI resolution (network) + Ed25519 verify |
| `phase5_dossier` | Dossier fetch + parse + validate | HTTP fetch (network) + stages 1-4 |
| `phase5_5_chain` | ACDC chain verification | Schema validation + edge operators |
| `phase9_revocation` | Revocation checking | TEL queries (network) |
| `phase6_claim_tree` | Claim tree construction | Pure CPU tree assembly |

Usage:
```python
from app.vvp.timing import PhaseTimer
timer = PhaseTimer()
request_id, response = await verify_vvp(req, timer=timer)
print(timer.to_summary_table())
```

## Key Source Files

| File | Responsibility |
|---|---|
| `services/verifier/app/vvp/dossier/parser.py` | Format detection, raw bytes -> ACDCNode list |
| `services/verifier/app/vvp/keri/cesr.py` | CESR binary stream -> JSON events + signatures |
| `services/verifier/app/vvp/dossier/validator.py` | ACDCNode list -> DossierDAG with root, cycles, warnings |
| `services/verifier/app/vvp/acdc/parser.py` | ACDC dict -> parsed ACDC, SAID verification, variant detection |
| `common/common/vvp/models/dossier.py` | ACDCNode, DossierDAG, warning data models |
| `common/common/vvp/models/acdc.py` | ACDC model with credential type inference |
| `services/verifier/app/vvp/verify.py` | Orchestration of entire verification pipeline |
