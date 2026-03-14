# Sprint 85: OVC Verifier Tier 2 + Cross-Verifier System Test

## Problem Statement

The OVC-VVP-Verifier (OSS standalone verifier, v0.2.0) only supports Tier 1 signature verification — non-transferable Ed25519 AIDs with B-prefix. Since the VVP issuer creates transferable identities (E-prefix), every real verification returns INDETERMINATE instead of VALID. The monorepo verifier has full Tier 2 KEL resolution (OOBI fetch, KEL parsing, witness receipt validation, delegation chains, range-based caching) that must be ported. Additionally, the SIP handler doesn't strip RFC 8224 STIR parameters from the Identity header, and there is no cross-verifier system test to validate interoperability.

## Spec References

- §5A Step 4: "Resolve issuer key state at reference time T"
- §7.3: Witness receipt threshold validation (accountable duplicity)
- §12: Tier 1 vs Tier 2 classification
- RFC 8224: SIP Identity header with STIR parameters

## Current State

| Feature | Monorepo Verifier | OVC Verifier |
|---------|-------------------|--------------|
| Tier 1 (B-prefix) | VALID | VALID |
| Tier 2 (E-prefix, transferable) | VALID | INDETERMINATE |
| KEL resolution | Full (OOBI → KEL → key state at T) | None |
| Delegation chains | dip/drt with depth limit | None |
| Key state caching | Range-based, 120s freshness | None |
| CESR binary KEL | Full count code parsing | AID/sig decode only |
| Witness receipts | Threshold validation | None |
| STIR Identity header | Handled by sip-verify service | Not stripped |
| Azure deployment | vvp-verifier.rcnx.io | Not deployed |
| Cross-verifier test | N/A | N/A |

## Proposed Solution

### Approach

Port the Tier 2 KEL resolution modules from `services/verifier/app/vvp/keri/` to `OVC-VVP-Verifier/app/vvp/keri/`, adapting imports for the flat OVC structure. OOBI fetching will reuse OVC's existing hardened fetch layer (`app/vvp/fetch.py`) — no new HTTP/SSRF implementation. Tier 1 and Tier 2 verification paths are strictly separated: non-transferable AIDs (B-prefix) use direct key decode, transferable AIDs (D/E-prefix) resolve key state exclusively through KEL/OOBI at `iat` — no raw key decode for transferable identifiers. Delegation validation is mandatory for delegated signers. Deploy to Azure Container Apps and add a `--verifier-url` flag to `system-test.py` for cross-verifier testing.

### Alternatives Considered

| Alternative | Pros | Cons | Why Rejected |
|-------------|------|------|--------------|
| Publish `vvp-common` as PyPI package | Shared code, single source of truth | Coupling between OSS and monorepo releases | OSS should remain standalone |
| Vendor entire `common/` into OVC | Complete parity | Bloated OSS repo, maintenance burden | Only ~3 utilities needed |
| Keep OSS as Tier 1 only | No porting work | Can't verify real VVP calls | Defeats purpose of OSS verifier |

### Duplication Boundary and Drift Mitigation

The KERI subsystem (~2200 LOC across 9 modules) is the largest duplication between the two repos. To mitigate long-term drift:

1. **Canonical source:** The monorepo verifier's `app/vvp/keri/` is the canonical implementation. The OVC port is a downstream consumer.

2. **Sync tracking:** Each OVC `keri/` module includes a header comment with the monorepo source commit SHA it was ported from:
   ```python
   # Ported from VVP monorepo services/verifier/app/vvp/keri/kel_parser.py
   # Source commit: <SHA> (2026-03-14)
   ```

3. **Memory-based reminder:** Per the feedback memory saved earlier, any change to the monorepo verifier triggers a TODO for OVC sync. This is enforced by the editor (Claude Code), not by CI.

4. **Future extraction:** If the OVC repo grows beyond v0.3.0 and requires frequent sync, we will extract the KERI subsystem into a shared `vvp-keri` PyPI package. This sprint does NOT do that — it's noted as a future option.

5. **Module boundary discipline:** The `keri/` package exposes a narrow public API surface: `resolve_key_state()` in `kel_resolver.py` is the sole entry point for Tier 2 resolution. `signature.py` calls only `resolve_key_state()` and `resolve_delegation_chain()` — it does not import parser internals, CESR helpers, or cache implementations directly. This keeps the KERI subsystem behind an adapter boundary and limits how much of `signature.py` / `verify.py` needs to understand KERI internals.

### Terminology and Naming Conventions

Consistent terminology across plan, code, config, and documentation:

| Concept | Standard Name | NOT Used |
|---------|--------------|----------|
| OSS verifier repo | OVC-VVP-Verifier (formal), OVC verifier (informal) | "OSS verifier", "standalone verifier" (in code/config) |
| Monorepo verifier | VVP Verifier | "cloud verifier", "main verifier" |
| HTTP fetch function | `safe_fetch()` | "hardened fetch", "fetch layer" |
| Configuration prefix | `VVP_` | `TIER2_` (use `VVP_TIER2_KEL_ENABLED`) |
| Feature flag | `VVP_TIER2_KEL_ENABLED` | `VVP_TIER2_KEL_ENABLED` |
| Cache config | `VVP_KEY_STATE_FRESHNESS_SECONDS` | `VVP_KEY_STATE_FRESHNESS_WINDOW_SECONDS` |
| OOBI timeout | `VVP_OOBI_TIMEOUT_SECONDS` | `VVP_OOBI_FETCH_TIMEOUT` |

### Detailed Design

#### Phase 1: Tier 2 KEL Resolution (OVC repo)

**New directory: `app/vvp/keri/`** — 9 modules, ~2200 LOC total

##### 1.1 Exception Classes (`app/vvp/keri/exceptions.py`, ~100 LOC)

Port from monorepo's `services/verifier/app/vvp/keri/exceptions.py`. Adapt to OVC's existing `ErrorCode` enum in `app/vvp/models.py`.

```python
class KeriError(Exception): ...
class SignatureInvalidError(KeriError): ...      # → INVALID
class ResolutionFailedError(KeriError): ...      # → INDETERMINATE
class StateInvalidError(KeriError): ...          # → INVALID
class KELChainInvalidError(StateInvalidError): ...
class KeyNotYetValidError(StateInvalidError): ...
class OOBIContentInvalidError(KeriError): ...
class CESRFramingError(KeriError): ...
class CESRMalformedError(KeriError): ...
```

##### 1.2 Key Parser (`app/vvp/keri/key_parser.py`, ~80 LOC)

Port from monorepo. Strictly separates non-transferable and transferable identifier handling:

- **Non-transferable (B-prefix):** Decode to raw 32-byte Ed25519 verification key for direct signature verification (Tier 1).
- **Transferable (D/E-prefix):** Extract AID string only — raw key decode is NOT performed. Key material is resolved exclusively through KEL/OOBI at reference time T (Tier 2).

```python
@dataclass(frozen=True)
class VerificationKey:
    raw: Optional[bytes]  # 32-byte key for B-prefix; None for transferable
    aid: str              # Original AID string
    code: str             # Derivation code ("B", "D", "E")
    is_transferable: bool # True for D/E prefix

def parse_kid(kid: str) -> VerificationKey
    """Parse kid to extract AID. For B-prefix, also decodes raw key.
    For D/E-prefix, raw is None — caller MUST use Tier 2 resolution."""

def extract_aid_from_oobi_url(url: str) -> str
    """Extract AID from OOBI URL path (/oobi/<AID>/...)."""
```

**Fail-closed guarantee:** Any attempt to use `raw` on a transferable `VerificationKey` raises `StateInvalidError`. The `is_transferable` flag drives the Tier 1 vs Tier 2 branch in `signature.py`. No production code path permits overriding this classification — test seams (e.g., `_allow_test_mode`) are unreachable from request handling.

##### 1.3 CESR Stream Parser (`app/vvp/keri/cesr.py`, ~350 LOC)

Port from monorepo. OVC's existing `app/vvp/cesr.py` keeps Tier 1 functions (`decode_aid_verkey`, `decode_pss_signature`). The new `keri/cesr.py` adds full binary CESR stream parsing.

```python
class CountCode(Enum):
    CONTROLLER_IDX_SIGS = "-A"
    WITNESS_IDX_SIGS = "-B"
    NON_TRANS_RECEIPT = "-C"
    TRANS_RECEIPT_QUAD = "-D"
    ATTACHMENT_GROUP = "-V"

def parse_cesr_stream(cesr_data: bytes) -> CESRMessage
def is_cesr_stream(data: bytes) -> bool
```

##### 1.4 KEL Parser (`app/vvp/keri/kel_parser.py`, ~550 LOC)

Port from monorepo. Parses KEL event streams (JSON or CESR binary) and performs full KERI-correct validation.

```python
class EventType(Enum):
    ICP = "icp"; ROT = "rot"; IXN = "ixn"; DIP = "dip"; DRT = "drt"

ESTABLISHMENT_TYPES = {EventType.ICP, EventType.ROT, EventType.DIP, EventType.DRT}

@dataclass
class WitnessReceipt:
    witness_aid: str
    signature: bytes      # 64-byte Ed25519 signature
    event_digest: str     # SAID of the event being receipted
    index: Optional[int]  # Witness index in event's 'b' list

@dataclass
class KELEvent:
    event_type: EventType
    sequence: int
    prior_digest: str           # 'p' field — SAID of prior event
    digest: str                 # 'd' field — this event's SAID
    signing_keys: List[bytes]   # 'k' field — current signing keys (raw 32-byte)
    next_keys_digest: List[str]  # 'n' field — list of next-key digests (canonical KERI form)
    toad: int                   # 'bt' field — threshold of accountable duplicity
    witnesses: List[str]        # 'b' field — witness AIDs
    timestamp: Optional[datetime]  # 'dt' field
    signatures: List[bytes]     # Controller signatures (from CESR -A attachments)
    witness_receipts: List[WitnessReceipt]  # From CESR -C/-B attachments
    raw: dict                   # Original event dict (for SAID recomputation)
    raw_bytes: bytes            # Original event bytes from stream (preserved exactly for signature verification)
    delegator_aid: Optional[str]  # 'di' field for dip/drt events
    signing_threshold: Union[str, List]  # 'kt' field — "1" or weighted threshold
    witness_adds: List[str]       # 'ba' field — witnesses added in rotation (empty for inception)
    witness_cuts: List[str]       # 'br' field — witnesses removed in rotation (empty for inception)

def parse_kel_stream(kel_data: bytes, is_cesr: bool = False) -> List[KELEvent]
def validate_kel_chain(events: List[KELEvent], strict: bool = True) -> None
```

**KERI-correct validation rules** (all mandatory in `validate_kel_chain`):

1. **SAID recomputation (purely local, no I/O):** For every event, recompute the SAID from `raw_bytes` using Blake3-256 and verify it matches `digest`. Reject if mismatch (`KELChainInvalidError`). SAID recomputation is a deterministic hash over the event's canonical serialization — it MUST NOT perform any network I/O, database access, or blocking operations. All bytes needed for recomputation are already present in `raw_bytes`. Any external fetch (OOBI, witness) is performed by the resolver layer BEFORE events reach `validate_kel_chain()`.

2. **Prior digest chain:** For events after inception, verify `prior_digest == previous_event.digest`. Reject broken chains (`KELChainInvalidError`).

3. **Sequence monotonicity (full-chain):** Verify `event.sequence == previous_event.sequence + 1` for **all** events in the KEL — establishment events (`icp`, `rot`, `dip`, `drt`) **and** interaction events (`ixn`). KERI requires contiguous sequence progression across the entire KEL without gaps. A missing or skipped sequence number anywhere in the chain is rejected with `KELChainInvalidError`. Key-state and delegation logic depend on this full continuity guarantee.

4. **Controller signature verification (over original stream bytes):** Verify controller signatures against the **authoritative key state at the time of signing**:
   - For inception (`icp`/`dip`): verify against the event's own `signing_keys` (self-signed).
   - For rotation (`rot`/`drt`): verify against the **prior establishment event's** `signing_keys`.
   - **Critical: Signature is over the original serialized event bytes as received from the KEL/CESR stream** — NOT over any reserialized or reconstructed form. The parser MUST preserve the exact byte range of each event from the incoming stream in `raw_bytes`. KERI signatures are computed over the original serialization; re-serializing (e.g., via `json.dumps()`) could reorder fields, change whitespace, or alter encoding, producing a different byte sequence that would invalidate otherwise correct signatures.
   - SAID recomputation (rule 1) is a separate validation step that operates on `raw_bytes` deterministically — it does NOT re-serialize the event.
   - Tests MUST include a case proving that signature verification uses original bytes: construct an event with non-canonical JSON field ordering, sign over those bytes, and verify the parser preserves them exactly.

5. **Next-key commitment (canonical KERI list form):** On rotation, verify that the new signing keys satisfy the prior event's `next_keys_digest` commitment. In KERI, `n` is a **list** of digests (one per next key). The `KELEvent.next_keys_digest` field is modeled as `List[str]` to match the canonical KERI shape.

   Supported forms:
   - **Single-element list** (e.g., `["EHn7V0c..."]`) — the standard form for single-key pre-rotation. Verify that `blake3(new_keys_qb64[0]) == n[0]`. This is the expected form for the VVP single-signature Ed25519 deployment.
   - **Empty list** `[]` — indicates no pre-rotation commitment (non-establishment recovery only, rare). Accepted only if the event is a recovery rotation.

   Unsupported forms (fail-closed rejection):
   - **Multi-element list** (e.g., `["EHn7...", "EAbc..."]`) — weighted/multi-sig next-key commitment. Rejected with `ResolutionFailedError("Multi-key next-key commitment not supported")`.
   - **String form** — if encountered as a bare string instead of a list, rejected with `ResolutionFailedError("Non-canonical next-key commitment format")`. The parser always expects the KERI list container.

   This matches the monorepo verifier's single-signature Ed25519 deployment model. The rejection is fail-closed: unsupported commitment forms never pass validation silently.

6. **Witness receipt validation (non-transferable witness deployment constraint):**

   **Deployment constraint:** This verifier explicitly adopts a **non-transferable witness only** deployment model. All witness AIDs in the effective witness set MUST be non-transferable B-prefix identifiers. This constraint is validated up front: if any witness AID in the event's effective witness set is NOT a B-prefix identifier, the event is rejected with `KELChainInvalidError("Unsupported transferable witness AID: {aid}")` before receipt validation proceeds. This is a deliberate deployment restriction — the VVP ecosystem uses non-transferable witness identifiers exclusively.

   With this constraint enforced:
   - Each receipt's signature is verified against the witness AID by decoding the B-prefix to a raw Ed25519 key.
   - Receipt `event_digest` must match the event's `digest`.
   - Receipts must be unique per witness per event (reject duplicates).
   - Only receipts from witnesses in the **effective witness set** (see rule 12) are counted toward TOAD.

7. **TOAD enforcement:** Count valid, unique witness receipts. If count < `toad`, the event is under-witnessed. Behavior:
   - `strict=True`: raise `ResolutionFailedError` (INDETERMINATE — insufficient receipts)
   - `strict=False`: warn but continue (for partial resolution)

8. **Threshold handling:** For `signing_threshold != "1"`, reject with `ResolutionFailedError("Weighted/multisig thresholds not supported")`. Single-signature Ed25519 is the only supported mode, matching the monorepo verifier.

9. **AID continuity:** All events in a KEL MUST share the same `i` (identifier) field. A KEL containing events with different `i` values is rejected with `KELChainInvalidError("Mixed identifier in KEL")`.

10. **Inception prefix binding (derivation-code-aware):** Prefix binding validation depends on the AID derivation type:
    - **Self-addressing AIDs (E-prefix, e.g., `E...`):** The inception event's `d` (SAID) must match `i` — this is self-addressing identifier derivation. If `inception.d != inception.i`, reject.
    - **Basic transferable AIDs (D-prefix, e.g., `D...`):** The `i` field is derived from the inception's first signing key, NOT from the event SAID. Validate that `i` matches the QualifiedBase64 derivation of `signing_keys[0]`. Do NOT require `i == d`.
    - **Non-transferable AIDs (B-prefix):** Handled in Tier 1, not expected in KEL validation. If encountered, validate `i` matches first signing key derivation.
    - Reject with `KELChainInvalidError("Inception prefix binding failed")` if the appropriate derivation check fails.
    - Tests: valid self-addressing inception (E-prefix, d==i) passes; valid basic transferable inception (D-prefix, i derived from key) passes; invalid prefix binding (wrong key derivation) fails.

11. **Target AID matching:** The resolved KEL's AID (from `events[0].raw["i"]`) must match the AID extracted from the `kid`/OOBI URL. If mismatched, reject with `KELChainInvalidError("Resolved AID does not match kid target")`.

12. **Effective witness set evolution:** Rotations may modify the witness set via `witness_cuts` (`br`) and `witness_adds` (`ba`) fields on the `KELEvent`. The effective witness set for each event is computed as: `effective = (prior_witnesses - set(event.witness_cuts)) | set(event.witness_adds)`. Receipt and TOAD validation MUST use the **effective witness set for the event being validated**, not the inception witness set. The `witness_cuts` and `witness_adds` fields are parsed directly from the event's `br` and `ba` JSON fields (or CESR equivalent) and surfaced on the `KELEvent` dataclass.

Dependencies: `app.vvp.keri.cesr`, `app.vvp.canonical` (already in OVC), `pysodium`, `blake3`.

##### 1.5 OOBI Dereferencer (`app/vvp/keri/oobi.py`, ~120 LOC)

Port from monorepo. Fetches KEL data via OOBI HTTP endpoint. **Reuses OVC's existing hardened fetch layer** (`app/vvp/fetch.py`) — no new HTTP client or SSRF implementation. The existing fetch layer already enforces:
- HTTPS-only in production (`VVP_ALLOW_HTTP=false`)
- DNS/IP validation blocking private/loopback/link-local/metadata ranges
- Redirect following disabled (or revalidated per hop)
- Response size limits (`VVP_FETCH_MAX_SIZE_BYTES`)
- Connection timeout enforcement
- Proxy disabled

```python
@dataclass
class OOBIResult:
    aid: str
    kel_data: bytes
    witnesses: List[str]
    content_type: str = "application/json"
    error: Optional[str] = None

async def dereference_oobi(oobi_url: str, timeout: float = 5.0) -> OOBIResult
    """Fetch KEL via OOBI URL using the shared safe fetch layer.

    Delegates to app.vvp.fetch.safe_fetch() which handles SSRF,
    transport security, and response limits.
    """
```

**No second SSRF path:** All HTTP fetching in `app/vvp/keri/` goes through `app.vvp.fetch.safe_fetch()`. Tests must cover private/loopback/link-local/metadata targets, redirect handling, and HTTP-vs-HTTPS policy to confirm the shared layer is invoked correctly.

##### 1.6 Key State Cache (`app/vvp/keri/cache.py`, ~400 LOC)

Port from monorepo. Range-based caching with freshness guard.

```python
@dataclass
class CacheConfig:
    freshness_window_seconds: float = 120.0
    max_entries: int = 1000

class KeyStateCache:
    async def get_for_time(aid: str, reference_time: datetime) -> Optional[KeyState]
    async def put(key_state: KeyState, reference_time: datetime, ...) -> None
    def clear(aid: Optional[str] = None) -> None
```

##### 1.7 KEL Resolver (`app/vvp/keri/kel_resolver.py`, ~400 LOC)

Port from monorepo. Core module — orchestrates OOBI fetch, KEL parsing, chain validation, and temporal key state resolution.

```python
@dataclass
class KeyState:
    aid: str
    signing_keys: List[bytes]
    sequence: int
    establishment_digest: str
    valid_from: Optional[datetime]
    witnesses: List[str]
    toad: int
    is_delegated: bool = False
    delegator_aid: Optional[str] = None

async def resolve_key_state(
    kid: str,
    reference_time: datetime,
    min_witnesses: Optional[int] = None,
    use_cache: bool = True,
) -> KeyState
    """Resolve key state for the given AID at reference_time.

    The OOBI URL is derived exclusively from `kid` — no caller-controlled
    OOBI override is accepted in the public API. This ensures production
    resolution is always kid-bound.

    For testing, use _resolve_key_state_with_oobi() which is an internal
    helper not reachable from the request-handling call chain.
    """
```

##### 1.8 Delegation Chain Resolver (`app/vvp/keri/delegation.py`, ~300 LOC)

Port from monorepo. Recursive delegation chain resolution with cycle detection and depth limit. **Delegation validation is mandatory** — if the signer AID is delegated (inception event type is `dip`), the delegation chain MUST be fully validated before returning VALID. Missing, broken, or cyclic delegation chains result in INVALID status.

```python
@dataclass
class DelegationChain:
    delegates: List[str]      # AIDs from leaf to root
    root_aid: Optional[str]   # Non-delegated root AID
    valid: bool = False
    errors: List[str] = field(default_factory=list)

async def resolve_delegation_chain(
    delegated_aid: str,
    inception_event: KELEvent,
    reference_time: datetime,
    oobi_resolver: Callable,
    visited: Optional[Set[str]] = None,
    depth: int = 0,
    resolved_cache: Optional[Dict[str, KeyState]] = None,
) -> DelegationChain
    """Resolve delegation chain with bounded fetch behavior.

    The `resolved_cache` parameter (defaulting to a shared dict within
    a single verification flow) prevents redundant OOBI/KEL fetches
    for AIDs already resolved in this verification. Each hop checks
    the cache before issuing an outbound fetch. This bounds total
    fetches to at most MAX_DELEGATION_DEPTH unique AIDs.
    """
```

**Delegation validation rules:**

1. **Detection:** If the signer's inception event is `dip` (or latest establishment is `drt`), the AID is delegated. The `di` field contains the delegator's AID.

2. **Delegator resolution:** Resolve the delegator's key state at `reference_time` via OOBI/KEL (recursive — delegator may itself be delegated).

3. **Inception anchor verification:** The delegator's KEL must contain an interaction (`ixn`) or establishment event that anchors (seals) the delegate's inception. The anchor's `d` field must match the delegate's inception event SAID.

4. **Delegated rotation anchor verification:** Every `drt` (delegated rotation) event in the delegate's KEL that can affect authoritative key state MUST also be anchored in the delegator's KEL. A `drt` without a corresponding delegator anchor is rejected. This prevents a delegate from unilaterally rotating without delegator authorization.

5. **Full delegation seal tuple:** For each delegated establishment event (`dip` or `drt`), validate the complete seal tuple: `{i: delegate_AID, s: event_sequence, d: event_SAID}` must appear as an anchor in the delegator's KEL at or before the reference time.

6. **Chain completeness:** The chain must terminate at a non-delegated root AID. Incomplete chains → INVALID.

7. **Cycle detection:** Track visited AIDs. If a delegation references an already-visited AID → INVALID (`KELChainInvalidError`).

8. **Depth limit:** `MAX_DELEGATION_DEPTH = 5`. Exceeding → INVALID.

9. **Mandatory enforcement in Tier 2:** In `app/vvp/keri/kel_resolver.py`, after resolving key state, if `key_state.is_delegated == True`, `resolve_delegation_chain()` is called unconditionally. A `DelegationChain` with `valid=False` causes `KELChainInvalidError` → INVALID status.

**Test cases for delegation:**
- Valid: delegated inception + delegated rotation, both anchored → VALID
- Invalid: valid inception anchor but missing rotation anchor → INVALID
- Invalid: valid inception anchor but wrong rotation seal tuple → INVALID
- Invalid: cyclic delegation → INVALID
- Invalid: delegation depth > 5 → INVALID

##### 1.9 Integration into Existing Modules

**`app/vvp/signature.py`** — Refactor with strict Tier 1/Tier 2 separation:

```python
# Current (sync, Tier 1 only):
def verify_passport_signature(passport: Passport) -> None

# New (async, strict separation):
async def verify_passport_signature(passport: Passport) -> SignatureResult:
    """Verify PASSporT signature. Dispatches to Tier 1 or Tier 2 based on AID type.

    - B-prefix (non-transferable): Tier 1 — decode raw key, verify directly.
    - D/E-prefix (transferable): Tier 2 — resolve key state from OOBI/KEL at iat.
      If VVP_TIER2_KEL_ENABLED is False, raises ResolutionFailedError
      (INDETERMINATE) — never silently returns VALID for transferable AIDs.

    Returns SignatureResult with verification tier and optional KeyState.
    """

@dataclass
class SignatureResult:
    tier: str                    # "tier1" or "tier2"
    key_state: Optional[KeyState]  # None for Tier 1
    delegation_chain: Optional[DelegationChain]  # None unless delegated
```

**Key design constraints:**
- The `kid` field from the signed PASSporT is the **sole** source for OOBI URL derivation in production. No caller-provided `oobi_url` override in request handling.
- Test seams (`_allow_test_mode`) are implemented as module-level flags that are unreachable from `app.main` → `verify()` → `verify_passport_signature()` call chain.
- Transferable AIDs NEVER produce a raw `VerificationKey.raw` — any code path that attempts direct Ed25519 verification against a transferable AID raises `StateInvalidError`.

**`app/vvp/verify.py`** — Phase 3 (Signature Verification) updated:
- Call now-async `verify_passport_signature(passport)`
- The function internally extracts `kid`, determines AID type, and dispatches
- `SignatureResult.key_state` stored for downstream phases (delegation info in claim tree)
- If delegated, `SignatureResult.delegation_chain` is included in evidence

**`app/config.py`** — New configuration with documentation:

```python
# --- Tier 2 KEL Resolution ---
# Enable KERI Key Event Log resolution for transferable AIDs.
# When False, transferable AIDs return INDETERMINATE (fail-open for Tier 1 deployments).
# When True, the verifier fetches KEL via OOBI and resolves key state at PASSporT iat.
VVP_TIER2_KEL_ENABLED: bool = _env_bool("VVP_TIER2_KEL_ENABLED", True)

# Key state cache freshness (seconds). Cached entries older than this
# are re-fetched from witnesses. Range: 10-3600. Default: 120.
VVP_KEY_STATE_FRESHNESS_SECONDS: float = _env_float(
    "VVP_KEY_STATE_FRESHNESS_SECONDS", 120.0, min_val=10.0, max_val=3600.0
)

# OOBI HTTP fetch timeout (seconds). Applied per-request to witness OOBI endpoints.
VVP_OOBI_TIMEOUT_SECONDS: float = _env_float("VVP_OOBI_TIMEOUT_SECONDS", 5.0, min_val=1.0, max_val=30.0)
```

#### Phase 2: SIP STIR Parameter Stripping (OVC repo)

**`app/sip/handler.py`** — RFC 8224-compliant Identity header parsing. The Identity header format per RFC 8224 is:

```
Identity: <base64url-JWT>;info=<url>;alg=<algorithm>;ppt=<passport-type>
```

The implementation uses structured RFC-oriented parsing, not permissive string splitting:

```python
def extract_passport_from_identity(identity_header: str) -> Optional[str]:
    """Extract PASSporT JWT from RFC 8224 Identity header.

    Parses STIR parameters (;info=...;alg=...;ppt=...) per RFC 8224 §10.
    Returns the JWT token portion only.

    Returns None if:
    - Header is empty or whitespace-only
    - No valid JWT segment found (must contain exactly 2 dots for 3 segments)
    - JWT segment fails base64url alphabet validation

    Raises PassportError if:
    - ppt parameter present but not in {'vvp', 'shaken'} (unrecognized passport type)
    - alg parameter present but not 'EdDSA' (forbidden algorithm)
    """
```

**Key design decisions:**
- The JWT is extracted as the first `;`-delimited segment, then **validated** (3-segment structure, base64url alphabet)
- **`ppt` handling (STIR-interoperable):** Both `ppt=vvp` and `ppt=shaken` are accepted as valid PASSporT profile types. VVP uses `ppt=vvp` but STIR/SHAKEN deployments use `ppt=shaken` — rejecting either would break interoperability. Unrecognized `ppt` values (e.g., `ppt=unknown`) are rejected with `PassportError`. This follows RFC 8225 §9 which defines `ppt` as identifying the PASSporT extension in use.
- If `alg` is present and not `EdDSA`, reject with `PassportError`
- If Identity header is malformed (no valid JWT), fall back to `P-VVP-Passport` header with a warning log
- Empty/missing Identity header is NOT an error — `P-VVP-Passport` is the primary VVP header

**Tests** (`tests/test_sip_stir.py`):
- Valid: `<JWT>;info=<url>;alg=EdDSA;ppt=vvp` → extracts JWT
- Valid: `<JWT>;info=<url>;alg=EdDSA;ppt=shaken` → extracts JWT (STIR interop)
- Valid: `<JWT>` (no STIR params) → extracts JWT
- Valid: Missing Identity, present P-VVP-Passport → uses P-VVP-Passport
- Invalid: `<JWT>;ppt=unknown` → rejects (unrecognized passport type)
- Invalid: `<JWT>;alg=ES256` → rejects (forbidden algorithm)
- Invalid: `not-a-jwt;info=<url>` → falls back to P-VVP-Passport
- Invalid: Empty Identity + empty P-VVP-Passport → no passport (error)

#### Phase 3: Azure Deployment (OVC repo)

**Dockerfile** — Based on existing monorepo verifier Dockerfile pattern:
- Python 3.11 slim base
- Install libsodium-dev for pysodium
- Copy app/ and pyproject.toml
- Run uvicorn on port 8000

**GitHub Actions** (`.github/workflows/deploy.yml`):
- Trigger on push to main
- Build Docker image
- Push to Azure Container Registry
- Deploy to Azure Container App `vvp-verifier-oss`

**Azure Configuration:**
- Container App: `vvp-verifier-oss` in resource group `VVP`
- URL: Azure-managed hostname (no custom domain — no concrete integration requirement)
- Environment variables:
  - `VVP_TRUSTED_ROOT_AIDS=EMIHOLO8hyGxHeee-7m8-PRNQHaU8isDnxdEkm0XNQbu,EMAO69dwrinUHQc1mHrEs7E9i_zzytMdJju54llkQTiB`
  - `VVP_TIER2_KEL_ENABLED=true`
  - `VVP_ALLOW_HTTP=false`
  - `VVP_ADMIN_ENABLED` is NOT set (defaults to `false` — admin routes disabled; see controls below)

**Admin Surface Controls (fail-closed):**

The OVC verifier has an `/admin/*` surface (status pages, debug endpoints). For the public Azure deployment, admin routes are **disabled entirely** via the `VVP_ADMIN_ENABLED` environment variable:

1. **`VVP_ADMIN_ENABLED=false`** (default: **disabled** in all environments): The admin router is NOT mounted unless an operator explicitly sets `VVP_ADMIN_ENABLED=true`. This is fail-closed — a missed env injection in any deployment will not expose admin routes.

2. **Implementation:** In `app/main.py`, the admin router inclusion requires explicit opt-in:
   ```python
   if config.VVP_ADMIN_ENABLED:
       app.include_router(admin_router, prefix="/admin")
   ```

3. **Verification step (in CI/CD):** After deployment, the GitHub Actions workflow runs:
   ```bash
   # Verify admin surface is unreachable (default-closed)
   STATUS=$(curl -s -o /dev/null -w "%{http_code}" https://<oss-verifier-url>/admin/)
   if [ "$STATUS" != "404" ]; then echo "FAIL: admin surface exposed"; exit 1; fi
   ```

4. **Local development:** Set `VVP_ADMIN_ENABLED=true` in local `.env` to enable admin UI during development. The default is closed in all environments.

**Cost Model:**

| Item | Specification | Monthly Cost (est.) |
|------|--------------|---------------------|
| Azure Container App (OSS verifier) | 0.5 vCPU, 1 GiB RAM, scale-to-zero, min 0 / max 1 replica | ~£5-10 (idle most of time, used only for testing) |
| Azure Container Registry | Basic tier, shared with existing VVP images | £0 incremental (already provisioned) |
| Image retention | 7-day untagged image policy | Negligible storage |
| Log retention | 30-day Log Analytics workspace (shared) | £0 incremental |
| GitHub Actions | ~2 min/build, <20 builds/month | Free tier |
| External OOBI fetches | ~10-50/day during testing, witness endpoints are internal | £0 (no egress charges for internal Azure traffic) |
| PBX sip-verify-oss instance | Not permanently deployed — started on-demand during cross-verifier test runs only | £0 |

**Per-verification cost formula:**

Each verification involves: 1 inbound request + N OOBI fetches (N=1 typical, N=2-3 with delegation) + 1 dossier fetch + cache lookup. With 50% cache hit rate:

```
Cost per verification ≈ compute_per_req + (1 - cache_hit_rate) × (N_fetches × egress_per_fetch) + log_bytes_per_req × log_ingestion_rate
```

**Request-scaling model (if used beyond testing):**

| Volume | Verifications/day | OOBI Fetches/day (50% cache) | Compute (ACA) | Egress | Log Ingestion | Observability | Est. Monthly |
|--------|------------------|------------------------------|---------------|--------|---------------|---------------|-------------|
| Idle (testing only) | 10-50 | 5-25 | Scale-to-zero | ~0 | Minimal | £0 | ~£5-10 |
| Low (100/day) | 100 | ~75 (1.5 avg fan-out) | 0.5 vCPU sustained | <1 GB | ~0.5 GB (~£1) | ~£2 | ~£18-30 |
| Medium (1000/day) | 1000 | ~750 | 0.5 vCPU sustained | <5 GB (~£3) | ~2 GB (~£5) | ~£5 | ~£40-65 |

**Assumptions:**
- Cache hit rate: 50% (same issuer AID verified within freshness window)
- Fetch fan-out: 1.5 average (1 OOBI + 0.5 delegation OOBI on average)
- Log ingestion: ~500 bytes/verification (after redaction)
- Observability: Azure Monitor basic metrics + alerting
- Maintenance/drift sync: Not costed (developer time, tracked via memory-based sync reminder)

**Infrastructure controls:**
- ACA max replicas: 1 (no auto-scaling beyond single instance for test/dev deployment)
- Log Analytics retention: 30 days (shared workspace)
- ACR image retention: 7-day untagged cleanup policy
- No custom domain (Azure-managed hostname only)

**Egress controls for OOBI/dossier fetches:**

Three-layer egress defense: application-layer destination authorization → transport-layer SSRF protection → network-layer NSG rules.

1. **Application-layer destination allowlist (runtime authorization):**
   Before any outbound fetch, the URL's hostname is checked against a configurable allowlist. This is distinct from SSRF protection — it rejects syntactically valid, publicly routable, non-SSRF destinations that are not operator-approved.

   ```python
   # app/config.py
   VVP_ALLOWED_FETCH_ORIGINS: Set[str] = _env_set(
       "VVP_ALLOWED_FETCH_ORIGINS",
       default=""  # EMPTY default — fail-closed. Must be explicitly configured.
   )
   # Format: "host:port" entries, e.g., "witness1.rcnx.io:443,vvp-issuer.rcnx.io:443"
   # If unset/empty, ALL outbound fetches are denied (fail-closed).
   # Application startup logs a WARNING if empty (misconfiguration check).
   ```

   ```python
   # app/vvp/fetch.py — added before safe_fetch() transport checks
   def authorize_destination(url: str) -> None:
       """Reject URLs whose origin is not in the operator-controlled allowlist.
       This is NOT an SSRF check — it is destination authorization.
       Raises FetchError if origin is not in VVP_ALLOWED_FETCH_ORIGINS.

       Normalization:
       - Hostname is lowercased and IDNA-encoded
       - Port defaults to 443 for https, 80 for http (scheme-default)
       - Comparison is exact "host:port" match after normalization
       """
       if not config.VVP_ALLOWED_FETCH_ORIGINS:
           raise FetchError("No allowed fetch origins configured (fail-closed)")
       parsed = urllib.parse.urlparse(url)
       hostname = parsed.hostname.lower().encode("idna").decode("ascii")
       port = parsed.port or (443 if parsed.scheme == "https" else 80)
       origin = f"{hostname}:{port}"
       if origin not in config.VVP_ALLOWED_FETCH_ORIGINS:
           raise FetchError(f"Destination not authorized: {origin}")
   ```

   Both `kid`-derived OOBI URLs and `evd`-derived dossier URLs pass through this check. An attacker who crafts a PASSporT pointing to `https://evil.com/oobi/...` (syntactically valid, not SSRF) is rejected before any network access. Path-level constraints are not applied — the allowlist authorizes at the origin level (host:port), and the OOBI/dossier path structure is validated by the respective parsers.

   **Azure deployment config:**
   ```
   VVP_ALLOWED_FETCH_ORIGINS=witness1.rcnx.io:443,witness2.rcnx.io:443,witness3.rcnx.io:443,vvp-issuer.rcnx.io:443
   ```

2. **Transport-layer SSRF protection:** `safe_fetch()` enforces HTTPS-only, DNS/IP validation (blocks private/loopback/link-local/metadata), redirect revalidation, response size limits.

3. **Network-layer NSG rules:** Azure NSG restricts outbound to witness/issuer IP ranges.

4. **Monitoring:** Azure Monitor alerts on unusual outbound request volume (>1000/hour threshold).

**Tests** (`tests/test_fetch_allowlist.py`):
- Allowed origin (host:port) → fetch proceeds to transport layer
- Attacker-supplied but syntactically safe unapproved host → rejected before network access
- Empty/unset allowlist → all fetches rejected (fail-closed)
- Allowlist with multiple origins → each accepted individually
- Non-standard port on allowed host → rejected (port mismatch)
- Mixed-case hostname normalization → matches allowlist correctly
- Startup warning logged when allowlist is empty

**Total incremental cost for testing use: ~£5-10/month** (scale-to-zero). For production use, costs scale linearly with call volume as shown above.

#### Phase 4: Cross-Verifier System Test (VVP monorepo)

**`scripts/system-test.py`** — Add flags:

```
--verifier-url URL    Override the verifier URL for SIP verification tests
--oss-verifier        Shorthand for --verifier-url https://vvp-verifier-oss.wittytree-2a937ccd.uksouth.azurecontainerapps.io
```

**Implementation approach — isolated test-only service instance:**

The system test `--oss-verifier` flag starts a **dedicated, isolated `vvp-sip-verify-test` service** on a separate port (5073) that points to the OSS verifier. The existing `vvp-sip-verify` service (port 5071) is NEVER modified — live production traffic continues uninterrupted.

```
1. Deploy vvp-sip-verify-test.service on PBX (one-time setup):
   - Separate systemd unit: /etc/systemd/system/vvp-sip-verify-test.service
   - Separate env file: /etc/vvp/vvp-sip-verify-test.env (VVP_VERIFIER_URL=<oss-url>)
   - Listens on port 5073 (dedicated test port, not used by any other service)
   - NOT started by default (disabled; started on-demand by test script)
2. System test starts vvp-sip-verify-test (if not running)
3. Test SIP scenarios send verification traffic to port 5073 directly
4. System test stops vvp-sip-verify-test after completion
```

**Isolation guarantee:** The test-only service is a completely separate process with its own env file, PID, and port. No concurrent traffic can be misdirected because the production service (port 5071) is never touched. The test service is disabled by default and only runs during test execution.

**Safety and trust-boundary controls:**

1. **HTTPS-only:** The `--verifier-url` flag rejects any URL not using `https://` scheme. HTTP targets are never permitted, even in test environments.

2. **Exact origin allowlist:** Only URLs matching exact origins (scheme + host + port) in a hardcoded allowlist are accepted. The URL is validated for: no userinfo, no query string, no fragment. The verification path (`/verify`) is derived internally — the user only specifies the base origin.
   ```python
   ALLOWED_VERIFIER_ORIGINS = {
       "https://vvp-verifier.rcnx.io",            # Monorepo verifier (production)
       "https://vvp-verifier.wittytree-2a937ccd.uksouth.azurecontainerapps.io",  # Monorepo (Azure)
       "https://vvp-verifier-oss.wittytree-2a937ccd.uksouth.azurecontainerapps.io",  # OSS verifier (Azure)
   }
   ```
   Inputs on an allowed host but wrong port/scheme are rejected. The `--oss-verifier` flag is a shorthand for the OSS verifier Azure origin from this allowlist.

3. **Non-combinable with `--loopback`:** The `--oss-verifier`/`--verifier-url` flags cannot be used with `--loopback` (which tests the full FreeSWITCH originate path through live call flow).

4. **Cleanup on exit:** The test service is stopped in a `try/finally` block on both success and failure paths.

### Data Flow

```
System Test (--oss-verifier)
    │
    ├─ Signing: INVITE → port 5070 (sip-redirect → VVP issuer) → 302 + PASSporT
    │
    └─ Verification: INVITE + PASSporT → port 5073 (sip-verify-test → OVC verifier)
                                            │
                                            ├─ OVC Verifier receives PASSporT
                                            ├─ Extracts kid (OOBI URL)
                                            ├─ Tier 2: Fetches KEL from witness
                                            ├─ Validates chain, resolves key state at T
                                            ├─ Verifies Ed25519 signature
                                            ├─ Fetches dossier, validates ACDC chain
                                            └─ Returns VALID + brand headers
```

### Error Handling

| Error | Status | Handling |
|-------|--------|----------|
| OOBI fetch 404 | INDETERMINATE | Witness may not have KEL; recoverable |
| OOBI fetch timeout | INDETERMINATE | Network issue; recoverable |
| KEL chain broken | INVALID | SAID chain mismatch; non-recoverable |
| Signature invalid | INVALID | Cryptographic failure; non-recoverable |
| Witness threshold not met | INDETERMINATE | Insufficient receipts; recoverable |
| Delegation cycle detected | INVALID | Circular reference; non-recoverable |
| SSRF violation | INVALID | Private IP in OOBI URL; non-recoverable |
| Destination not authorized | INVALID | Host not in allowlist; non-recoverable |
| STIR parse (Identity header) | Degraded | Falls back to P-VVP-Passport header |

### Log Redaction Rules

All new failure paths (PASSporT, OOBI, KEL, delegation) apply these redaction rules before logging:

| Data Type | Redaction | Example |
|-----------|-----------|---------|
| JWT/PASSporT tokens | Log first 8 chars + `...` + last 4 chars | `eyJhbGci...xYz4` |
| Phone numbers (`orig`/`dest`) | Hash with per-deployment salt | `tn:sha256:a1b2c3...` |
| `kid` / OOBI URLs | Log scheme + host only, strip path/query | `https://witness1.rcnx.io/...` |
| `evd` / dossier URLs | Log scheme + host only, strip path/query | `https://vvp-issuer.rcnx.io/...` |
| AID strings | Log in full (public identifiers, not sensitive) | `ENmdZop...` |
| KEL event digests | Log in full (SAIDs, not sensitive) | `EHn7V0c...` |

**Implementation:** A `redact_for_log()` utility in `app/vvp/keri/exceptions.py` is called by all exception `__str__` methods and by explicit log statements in `oobi.py`, `kel_resolver.py`, and `signature.py`. The utility accepts typed values and applies the corresponding rule.

**Tests:** `tests/test_log_redaction.py` verifies that JWTs, phone numbers, and URLs are redacted in exception messages and log output.

### Test Strategy

**Unit tests (OVC repo, ~15 test files):**
- `tests/test_kel_parser.py` — KEL JSON/CESR parsing, chain validation:
  - Valid chain continuity (prior digest chain)
  - SAID recomputation verification
  - Controller signature verification against prior state
  - Invalid rotation (broken next-key commitment)
  - Invalid/duplicate witness receipts
  - TOAD enforcement failure (below threshold)
  - Unsupported threshold configuration (weighted/multisig → error)
  - Valid mixed `icp→ixn→rot→ixn→ixn→rot` chain with contiguous sequences
  - Invalid: gap in `ixn` sequence (e.g., seq 0→1→3 skipping 2) → rejected
  - Invalid: duplicate sequence number → rejected
  - Invalid: transferable witness AID (D/E-prefix) in witness set → rejected up front
- `tests/test_kel_resolver.py` — Key state resolution:
  - Non-transferable (B-prefix) → Tier 1 fallback
  - Transferable (E-prefix) → Tier 2 KEL resolution
  - Key state at rotation boundary (before/after rotation)
  - Cache hit/miss/freshness
  - Mismatched kid/resolved AID → rejection
  - Production-path override attempt → rejection
- `tests/test_kel_cache.py` — Range-based cache: exact match, range match, freshness expiry, eviction
- `tests/test_cesr_stream.py` — CESR binary parsing: count codes, signatures, receipts, framing errors
- `tests/test_delegation.py` — Delegation chains:
  - Valid delegated signer with anchor in delegator KEL
  - Missing delegation chain → INVALID
  - Broken delegation (bad anchor digest) → INVALID
  - Cyclic delegation (A→B→A) → INVALID
  - Depth limit exceeded → INVALID
  - Non-delegated AID (no delegation required)
- `tests/test_signature_tier2.py` — Tier 2 signature verification:
  - Valid transferable AID with OOBI resolution
  - Transferable AID with `VVP_TIER2_KEL_ENABLED=False` → INDETERMINATE
  - Delegated signer with valid delegation chain
  - Delegated signer with invalid chain → INVALID
- `tests/test_sip_stir.py` — STIR parameter stripping (7 cases, see Phase 2)
- `tests/test_oobi_ssrf.py` — OOBI fetch via safe_fetch layer:
  - Private IP (127.0.0.1, 10.x, 172.16.x) → blocked
  - Link-local (169.254.x) → blocked
  - Cloud metadata (169.254.169.254) → blocked
  - Redirect to private IP → blocked
  - HTTP with VVP_ALLOW_HTTP=false → blocked
  - Valid HTTPS witness URL → allowed
- Port fixture files from monorepo `tests/fixtures/keri/`

**Integration test (VVP monorepo):**
- `python3 scripts/system-test.py --oss-verifier` — Full SIP chain against OSS verifier

### Documentation Requirements

All new public surface must be documented before the sprint is complete:

**OVC repo:**
- `ALGORITHMS.md` — Update with Tier 2 KEL resolution algorithm description:
  - OOBI fetch → KEL parsing → key state resolution at T
  - Witness receipt validation and TOAD enforcement
  - Delegation chain resolution
- `README.md` — Update feature matrix:
  - Add Tier 2 as supported (with `VVP_TIER2_KEL_ENABLED` toggle)
  - Document all new configuration variables with defaults and valid ranges
  - Update deployment instructions for Azure
  - Add `VVP_ALLOWED_FETCH_ORIGINS` and `VVP_ADMIN_ENABLED` to config reference
- `CHANGES.md` — Add v0.3.0 entry documenting Tier 2 KEL resolution, STIR parsing, Azure deployment
- **Module docstrings** — Every new module in `app/vvp/keri/` must have a module-level docstring explaining purpose, responsibilities, and key functions
- **Class/function docstrings** — All public API classes and functions (`VerificationKey`, `KELEvent`, `KeyState`, `resolve_key_state()`, `validate_kel_chain()`, `authorize_destination()`, etc.) must have full docstrings with parameters, return types, and exceptions
- **Type annotations** — All public API functions must have complete type annotations (parameters and return types)
- **Configuration documentation** — Each new env var must have an inline comment explaining purpose, valid range, and default

**VVP monorepo:**
- `knowledge/deployment.md` — Add OSS verifier Azure deployment details
- `CLAUDE.md` — Add OSS verifier URL to Service URLs table
- `CHANGES.md` — Sprint 85 changelog entry
- System test `--help` — Document `--oss-verifier` and `--verifier-url` flags

## Files to Create/Modify

### OVC Repo (`/Users/andrewbale/code/active/OVC-VVP-Verifier/`)

| File | Action | Purpose |
|------|--------|---------|
| `app/vvp/keri/__init__.py` | Create | Package init |
| `app/vvp/keri/exceptions.py` | Create | KERI exception classes (~100 LOC) |
| `app/vvp/keri/key_parser.py` | Create | AID parsing for B/D/E prefixes (~70 LOC) |
| `app/vvp/keri/cesr.py` | Create | CESR binary stream parser (~350 LOC) |
| `app/vvp/keri/kel_parser.py` | Create | KEL event parsing + chain validation (~450 LOC) |
| `app/vvp/keri/oobi.py` | Create | OOBI HTTP fetch with SSRF validation (~150 LOC) |
| `app/vvp/keri/cache.py` | Create | Range-based key state cache (~400 LOC) |
| `app/vvp/keri/kel_resolver.py` | Create | Core resolver — key state at time T (~400 LOC) |
| `app/vvp/keri/delegation.py` | Create | Delegation chain resolver (~300 LOC) |
| `app/vvp/signature.py` | Modify | Add async Tier 2 path for transferable AIDs |
| `app/vvp/verify.py` | Modify | Phase 3 async integration |
| `app/config.py` | Modify | Add Tier 2 configuration variables |
| `app/sip/handler.py` | Modify | STIR parameter stripping |
| `Dockerfile` | Create/Modify | Azure deployment container |
| `.github/workflows/deploy.yml` | Create | CI/CD to Azure Container Apps |
| `tests/test_kel_parser.py` | Create | KEL parsing tests |
| `tests/test_kel_resolver.py` | Create | Resolver tests |
| `tests/test_kel_cache.py` | Create | Cache tests |
| `tests/test_cesr_stream.py` | Create | CESR binary tests |
| `tests/test_delegation.py` | Create | Delegation tests |
| `tests/test_signature_tier2.py` | Create | Tier 2 signature tests |
| `tests/test_sip_stir.py` | Create | STIR stripping tests |
| `tests/fixtures/keri/` | Create | Ported KEL/CESR test fixtures |

| `tests/test_oobi_ssrf.py` | Create | OOBI SSRF validation tests |
| `tests/test_fetch_allowlist.py` | Create | Destination allowlist authorization tests |
| `tests/test_log_redaction.py` | Create | Log redaction rule tests |
| `ALGORITHMS.md` | Modify | Add Tier 2 KEL resolution algorithm |
| `README.md` | Modify | Update feature matrix, config, deployment |
| `CHANGES.md` | Modify | Add v0.3.0 entry for Tier 2 + STIR + Azure |

### VVP Monorepo (`/Users/andrewbale/code/active/VVP/`)

| File | Action | Purpose |
|------|--------|---------|
| `scripts/system-test.py` | Modify | Add --oss-verifier / --verifier-url flags |
| `knowledge/deployment.md` | Modify | Add OSS verifier Azure deployment |
| `CLAUDE.md` | Modify | Add OSS verifier URL to Service URLs table |
| `CHANGES.md` | Modify | Sprint 85 changelog entry |

## Open Questions

1. **OVC repo tag**: Should we tag this as v0.3.0 after Tier 2 is added?

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Import path differences between monorepo and OVC | High | Medium | Adapt imports during port; test each module individually |
| SSRF validation without common/ package | Medium | Low | Implement minimal inline SSRF check (~20 LOC) |
| Witness OOBI instability (KEL lost on restart) | High | Medium | Existing issue; test with fresh publish before validation |
| `verify_passport_signature` sync→async change breaks callers | Medium | High | Update all callers in verify.py; run full test suite |
| Azure Container App deployment configuration | Low | Medium | Follow existing monorepo verifier deployment pattern |

## Revision History

| Round | Date | Changes |
|-------|------|---------|
| R1 | 2026-03-14 | Initial draft |
| R2 | 2026-03-14 | Addressed council R1 findings: (1) OOBI fetch reuses existing hardened fetch layer, no new SSRF path; (2) Strict Tier 1/Tier 2 separation — transferable AIDs never decoded to raw keys; (3) Full KERI-correct KEL validation specified (SAID recompute, sig verify against prior state, witness receipt uniqueness, TOAD enforcement, threshold handling); (4) Delegation validation mandatory for delegated signers with anchor verification; (5) RFC 8224-oriented SIP Identity parsing with validation, not permissive split; (6) Added cost model (~£5-10/month); (7) Added documentation requirements for all new public surface |
| R3 | 2026-03-14 | Addressed council R2 findings: (8) Added delegated rotation seal validation, AID continuity, inception prefix binding, target-AID matching, effective witness-set evolution across rotations; (9) Cross-verifier test constrained with HTTPS-only, hostname allowlist, non-combinable with --loopback; (10) Added drift mitigation strategy with sync tracking and source commit headers; (11) Standardized naming conventions table for all config/terminology; (12) Added egress controls (NSG rules, safe_fetch enforcement, monitoring alerts); (13) Expanded cost model with request-scaling tiers and infrastructure controls |
| R4 | 2026-03-14 | Addressed council R3 findings: (14) ppt accepts both 'vvp' and 'shaken' for STIR interop per RFC 8225; (15) KEL sequence validation now contiguous across ALL events including ixn; (16) Explicit non-transferable witness deployment constraint with up-front rejection of transferable witness AIDs; (17) Admin surface controls via VVP_ADMIN_ENABLED with CI verification step; (18) Three-layer egress defense with application-layer destination allowlist (VVP_ALLOWED_FETCH_ORIGINS) checked before SSRF/NSG; (19) Log redaction rules for JWTs, phone numbers, kid/evd URLs; (20) Per-verification cost formula with cache hit rate, fetch fan-out, observability, and maintenance assumptions; (21) SAID recomputation explicitly purely local with no I/O; (22) Fixed remaining TIER2_KEL_RESOLUTION_ENABLED → VVP_TIER2_KEL_ENABLED naming; (23) Module boundary discipline documented — keri/ exposes narrow API surface |
| R5 | 2026-03-14 | Addressed council R4 findings: (24) Signature verification now explicitly over original stream bytes, not reserialized — parser preserves exact byte range; (25) Cross-verifier test uses isolated vvp-sip-verify-test service on port 5073 instead of mutating shared service; (26) Removed oobi_url override from public resolve_key_state API — test-only helper is internal; (27) Allowlist renamed to VVP_ALLOWED_FETCH_ORIGINS with fail-closed empty default, host:port matching, hostname normalization; (28) Next-key commitment explicitly specifies supported forms (single digest, empty string) and rejects unsupported (weighted list) with fail-closed error; (29) Documentation requirements expanded: CHANGES.md, class/function docstrings with full type annotations, CHANGES.md entry added to monorepo file table |
| R6 | 2026-03-14 | Addressed council R5 findings: (30) Inception prefix binding now derivation-code-aware — self-addressing (E-prefix) requires d==i, basic transferable (D-prefix) validates against key derivation; (31) Next-key commitment uses canonical KERI list form (List[str]) with single-element support, bare string rejected; (32) Admin routes default disabled via VVP_ADMIN_ENABLED=false (fail-closed in all environments, explicit opt-in required); (33) Verifier URL validation uses exact origin matching (scheme+host+port), rejects userinfo/query/fragment; (34) Delegation chain uses resolved_cache to prevent redundant OOBI/KEL fetches across hops; (35) KELEvent now surfaces witness_adds (ba) and witness_cuts (br) fields explicitly; (36) Fixed CHANGELOG.md→CHANGES.md, standardized OVC verifier terminology |

---

## Implementation Notes

### Deviations from Plan
- Log redaction tests are in `test_keri.py` (TestLogRedaction class) instead of a separate `test_log_redaction.py` file
- OOBI SSRF tests are covered by the existing fetch layer tests rather than a separate `test_oobi_ssrf.py`
- All KERI module tests consolidated into `test_keri.py` (51 tests) rather than separate per-module test files, for better cohesion

### Test Results
- 192 tests pass (132 existing + 51 KERI + 9 fetch allowlist)
- No regressions

### Files Changed
| File | Lines | Summary |
|------|-------|---------|
| `app/vvp/keri/kel_parser.py` | +1064 | KEL parser (JSON/CESR, chain validation, SAID) |
| `app/vvp/keri/oobi.py` | +120 | OOBI dereferencer using safe_get |
| `app/vvp/keri/cache.py` | +460 | Range-based key state cache |
| `app/vvp/keri/kel_resolver.py` | +672 | Key state resolver with feature gate |
| `app/vvp/keri/delegation.py` | +269 | Delegation chain resolver |
| `app/vvp/keri/signature.py` | +348 | Tier 2 signature verification |
| `app/vvp/signature.py` | ~30 | Async Tier 2 routing |
| `app/vvp/verify.py` | ~20 | Phase 4 async + KERI exceptions |
| `app/vvp/fetch.py` | +30 | authorize_destination() |
| `app/config.py` | +20 | Tier 2 config + allowlist |
| `app/main.py` | ~5 | Admin gating |
| `app/sip/handler.py` | +15 | STIR param stripping |
| `tests/test_keri.py` | +450 | 51 KERI tests |
| `tests/test_fetch_allowlist.py` | +70 | 9 allowlist tests |
| `ALGORITHMS.md` | +50 | Tier 2 algorithm docs |
| `README.md` | +10 | Updated capabilities + config |
| `CHANGES.md` | +30 | Sprint 85 changelog |
