# Sprint 86: Witness State Resilience

## Problem Statement

After Sprint 70 (auto-republish on KERI Agent startup) and Sprint 81 (full KEL publishing + readiness gating), the system correctly restores witness state when the **KERI Agent** restarts. However, witness state is still lost when **witnesses restart independently**:

1. **Azure infrastructure restarts** — Azure Container Apps may restart witness containers due to scaling, health checks, or platform updates. Witnesses use ephemeral storage (`KERI_DB_PATH=/tmp/witness`), so they lose all published KELs. The KERI Agent doesn't restart, so no re-publish occurs.

2. **CI/CD witness-only deployments** — When only witness code changes, `deploy-witnesses` runs but `deploy-keri-agent` is skipped. Witnesses come up with fresh LMDB. No mechanism triggers re-publishing.

Both scenarios result in: OOBI 404 → `KERI_RESOLUTION_FAILED` → INDETERMINATE verification → broken VVP calls requiring manual `POST /admin/publish-identity` for each identity.

## Current State

- `KeriStateBuilder._publish_to_witnesses()` runs during KERI Agent startup only
- `WitnessPublisher.publish_full_kel()` exists and works correctly — uses `hby.db.clonePreIter()` to stream complete KEL with all CESR attachments
- Witnesses use ephemeral storage both locally (Docker `tmpfs`) and in Azure (`/tmp/witness`)
- The KERI Agent has a `ReadinessTracker` with background task management
- Admin API exists at `/admin/` with bearer token auth (`VVP_KERI_AGENT_AUTH_TOKEN`)
- `deploy.yml` has no post-witness-deploy re-publish step
- Issuer→KERI Agent communication already uses HTTPS in Azure with `VVP_KERI_AGENT_AUTH_TOKEN`
- Issuer admin endpoints already use `Depends(require_admin)` for role enforcement
- Witness URLs are configured at deploy time via `VVP_LOCAL_WITNESS_URLS` / `VVP_WITNESS_CONFIG` — not user-supplied
- Current deployment has ~69 seeded identities; recovery via `publish_full_kel()` takes ~2s for all identities

## Proposed Solution

### Approach

Add a centralized `WitnessRecoveryService` in the KERI Agent that owns all witness state recovery logic — used by the startup builder, the background health monitor, and the admin endpoint. CI/CD triggers recovery via the issuer proxy after witness-only deployments.

This approach was chosen over persistent witness storage because:
- Witnesses are designed to be ephemeral (deterministic salt → same AID on restart)
- Persistent Azure File Share adds latency and cost for witness LMDB operations
- Auto-healing is more resilient than "never lose state" — it handles any failure mode
- Recovery cost is low: ~2s for 69 identities × 3 witnesses at current scale. Even at 10× scale (690 identities), full replay + receipt redistribution would take ~20s — well within acceptable bounds for an automated repair operation

### Alternatives Considered

| Alternative | Pros | Cons | Why Rejected |
|-------------|------|------|--------------|
| Persistent witness volumes (Azure File Share) | Never lose state | Adds latency to LMDB ops; cost; doesn't help if corruption occurs | Performance impact on hot path |
| Webhook from Azure on container restart | Immediate trigger | Azure doesn't natively support restart webhooks for Container Apps | Not available without custom infra |
| Cron job (external) to re-publish | Simple | Extra infra to manage; not integrated with KERI Agent | Over-engineering |
| Delta-based recovery (only publish new events) | More efficient | Complex to track what each witness has; full replay is idempotent and fast enough | Unnecessary optimization at current scale |

### Detailed Design

#### Component 1: WitnessRecoveryService

- **Purpose**: Centralized service that owns all witness state validation and recovery. Used by the startup builder, background monitor, and admin endpoint — no recovery logic in callers.
- **Location**: `services/keri-agent/app/keri/witness_recovery.py` (new file)
- **Interface**:

```python
@dataclass
class WitnessStateCheck:
    """Result of checking one witness's key state for one identity."""
    witness_url: str
    aid: str
    expected_sn: int          # Latest sn from local authoritative KEL
    expected_said: str        # Latest event SAID from local KEL
    witness_sn: int | None    # sn from witness OOBI (None if 404/unreachable)
    witness_said: str | None  # SAID from witness (None if 404/unreachable)
    healthy: bool             # True IFF exact match (see health predicate below)

@dataclass
class WitnessRecoveryResult:
    """Typed result for one witness's recovery outcome."""
    witness_url: str
    was_degraded: bool
    identities_published: int
    identities_verified: int     # How many post-republish verifications passed
    identities_failed: int       # How many post-republish verifications failed
    receipt_redistribution_ok: bool
    fully_recovered: bool        # True IFF all targeted identities verified
    error_codes: list[str]

@dataclass
class RecoveryReport:
    """Structured result for all witness recovery operations."""
    action: str               # "monitor_check" | "admin_republish" | "startup_publish"
    witnesses_checked: int
    witnesses_degraded: int
    identities_published: int
    identities_total: int
    identities_verified: int  # Total post-recovery verifications passed
    identities_failed: int    # Total post-recovery verifications failed
    fully_recovered: bool     # True IFF all degraded witnesses fully recovered
    elapsed_seconds: float
    per_witness: list[WitnessRecoveryResult]
    error_codes: list[str]


class WitnessRecoveryService:
    """Centralized witness state validation and recovery.

    All callers (startup, monitor, admin) use this service.
    Owns the republish lock to prevent concurrent operations.
    """

    def __init__(
        self,
        publisher: WitnessPublisher,
        cooldown_seconds: float = 120.0,
        max_recoveries_per_hour: int = 3,
    ): ...

    async def check_witness_state(
        self,
        probe_all: bool = False,
    ) -> list[WitnessStateCheck]:
        """Key-state-aware health check for all witnesses.

        Args:
            probe_all: If True, check ALL seeded identities (used by recovery
                       verification). If False, use rotating bounded probe set
                       (used by periodic monitor for lightweight detection).
        """

    async def recover_degraded_witnesses(
        self,
        degraded_urls: list[str] | None = None,
        action: str = "admin_republish",
        force: bool = False,
    ) -> RecoveryReport:
        """Republish identities to specific degraded witnesses only.

        Processes ALL seeded identities (no batch ceiling — full recovery
        required for correctness). If interrupted or partially failed,
        report.fully_recovered is False.
        """

    async def verify_full_recovery(
        self,
        witness_url: str,
    ) -> tuple[int, int]:
        """Post-republish verification for ALL seeded identities.

        Probes the repaired witness's OOBI for every seeded identity AID
        and confirms sn/SAID matches local authoritative state.

        Returns (verified_count, failed_count).
        """
```

- **Health predicate (fail-closed, exact match)**:

  A witness is **healthy** for a given identity IFF ALL of the following hold:
  1. OOBI fetch returns HTTP 200 (not 404, not connection error)
  2. `witness_sn == expected_sn` (exact match, not `>=`)
  3. `witness_said == expected_said` (exact digest match)

  A witness is **degraded** if ANY of the following:
  - OOBI fetch returns 404 or connection error → **stale** (common: witness restarted)
  - `witness_sn < expected_sn` → **stale** (witness has older state)
  - `witness_sn == expected_sn` but `witness_said != expected_said` → **corrupted** (same sn, different digest)
  - `witness_sn > expected_sn` → **divergent** (witness has events we don't — should not happen with deterministic salts, indicates a serious problem)
  - OOBI response cannot be parsed → treat as **stale** (fail-closed)

  This is a fail-closed predicate: any ambiguity is treated as degraded.

  **Divergent state handling**: If a witness has `sn > expected_sn`, replay cannot fix it (our events would be rejected as stale). This case is logged as `WITNESS_DIVERGENT` at ERROR level with full details. Recovery skips this witness and marks it as `fully_recovered=False` with error code `DIVERGENT_STATE:witness-N`. The admin endpoint returns this error so operators can investigate. This scenario should not occur in practice — witnesses use deterministic salts and rebuild from scratch on restart — but the plan handles it explicitly rather than silently failing.

- **Two modes of state checking** (monitoring vs verification):

  | Mode | Used by | Scope | Purpose |
  |------|---------|-------|---------|
  | **Monitoring** (`probe_all=False`) | Background monitor | Rotating probe set (up to 3 identities) | Lightweight detection — "is any witness likely degraded?" |
  | **Verification** (`probe_all=True`) | Recovery verification, admin, startup | ALL seeded identities | Authoritative — "are ALL identities restored?" |

  The monitor uses sampling to detect degradation with minimal load. When degradation is detected, recovery runs and then uses `verify_full_recovery()` which checks ALL seeded identities on the repaired witness. Recovery cannot be declared successful unless every targeted identity is verified.

- **Key-state validation algorithm** (for both modes):
  1. Get all seeded identity AIDs from seed store
  2. Select probe set: either rotating bounded set (monitor) or full set (verification)
  3. For each probe identity, get the local authoritative KEL state: `sn = hab.kever.sn`, `said = hab.kever.serder.said`
  4. For each witness, fetch `GET {witness_url}/oobi/{aid}/controller` and parse the CESR response to extract the witness-held event at the same `sn`. Compare sn and SAID.
  5. Apply the fail-closed health predicate above
  6. Return list of `WitnessStateCheck` results

- **Outbound destination validation**:

  All outbound requests to witnesses (OOBI probes, KEL publishing, receipt distribution) MUST pass through a validation layer:
  1. **Allowlist enforcement**: Target URL must be a member of the configured witness pool (`WITNESS_IURLS` / `VVP_LOCAL_WITNESS_URLS`). Reject any URL not in the configured set.
  2. **URL normalization**: Strip trailing slashes, enforce scheme matching.
  3. **HTTPS enforcement**: In non-local environments (`VVP_ENV != "local"`), reject `http://` witness URLs. Local dev allows `http://` for Docker witnesses.
  4. **No redirects**: Use `httpx.AsyncClient(follow_redirects=False)` — refuse to follow redirects to prevent SSRF.
  5. **Failure behavior**: Invalid destination raises `WitnessConfigurationError` (logged, not retried).

  This is implemented as a `_validate_witness_url(url: str) -> str` method on `WitnessRecoveryService`, called before every outbound request. The witness URL list is set at deploy time from configuration, not from user input.

- **Timeout and response-size guardrails**: All outbound OOBI probes use explicit `httpx.AsyncClient(timeout=httpx.Timeout(10.0, connect=5.0))` and `max_content_length` checking. CESR/OOBI responses are bounded to 1 MB before parsing — responses exceeding this limit are treated as degraded (fail-closed). This prevents unbounded memory consumption from malformed or adversarial responses during health checks.

- **Targeted recovery with event-digest-aware receipt redistribution**:

  When a witness is identified as degraded, recovery proceeds in three phases:

  **Phase A — Full KEL Replay**: Use `publish_full_kel()` with `witnesses=[degraded_url]` to send the complete KEL for ALL seeded identities to the target witness. The KEL stream is built from `hby.db.clonePreIter(pre)` which returns all events (icp, ixn, rot) with their full CESR attachments (controller signatures, seal source couples). The target witness processes all events.

  **LMDB I/O isolation**: `hby.db.clonePreIter(pre)` and `hab.db.getWigs()` are synchronous LMDB reads that can block the event loop. All LMDB access in the recovery path is wrapped in `asyncio.to_thread()` to keep the event loop responsive:
  ```python
  # KEL stream assembly (Phase A)
  kel_stream = await asyncio.to_thread(
      lambda: b"".join(hby.db.clonePreIter(pre=pre_bytes, fn=0))
  )

  # Witness receipt retrieval (Phase B)
  wigers = await asyncio.to_thread(
      lambda: list(hab.db.getWigs(pre_bytes, sn=sn, dig=dig))
  )
  ```
  This pattern is already used in `_verify_state()` (via `asyncio.to_thread(_verify_saids)`). The async HTTP I/O (httpx) is natively async and does not need threading.

  **Phase B — Event-Digest-Aware Receipt Redistribution**: After KEL replay, the target witness has accepted events but lacks the other witnesses' indexed signatures needed for `fullyWitnessed()`. For each published identity:

  1. Get the inception event digest: `dig = hab.iserder.saidb` (the inception event SAID)
  2. Retrieve locally stored witness indexed signatures for that specific event: `wigers = hab.db.getWigs(pre_bytes, sn=0, dig=dig)` — this retrieves wigs keyed by `(pre, sn, dig)`, ensuring we get signatures for the exact event digest
  3. Build a receipt event for the inception event: `rserder = eventing.receipt(pre=hab.pre, sn=0, said=hab.iserder.said)` — the receipt references the exact event via `sn` and `said`
  4. Attach witness indexed signatures: `rct_msg = eventing.messagize(serder=rserder, wigers=wigers)` — creates the `-B WitnessIdxSigs` CESR attachment
  5. POST the receipt event to the repaired witness's root `/` endpoint via `_distribute_receipt()`
  6. If the identity has **establishment events** beyond inception (rot, dip, drt — `sn > 0`), repeat steps 2-5 for each establishment event's `sn` and `said`. Only establishment events (icp, rot, dip, drt) need witness receipts — non-establishment events (ixn) do not participate in the witness receipt protocol because they don't change the key state. The witness receipt handler (`processReceiptWitness`) only processes receipts for establishment events. To enumerate establishment events for an identity, iterate `hab.kever.serder` (latest) and `hby.db.getFelItemPreIter(pre)` filtering by event type (`t` field in `icp`, `rot`, `dip`, `drt`).

  **TOAD sufficiency check**: Before redistributing receipts for an establishment event, compare the number of locally available wigers against the event's TOAD (witness threshold). If `len(wigers) < toad`, recovery cannot proceed for this identity — the controller's local LMDB lacks enough witness receipts to satisfy `fullyWitnessed()` on the repaired witness. Controller OOBIs do not export per-event witness indexed signatures, so there is no valid KERI mechanism to acquire missing receipts from other witnesses at this layer. `INSUFFICIENT_RECEIPTS` is a **terminal unrecoverable** outcome: the identity is marked with error code `INSUFFICIENT_RECEIPTS:{aid_prefix}`, `fully_recovered=False`, and the error is logged at ERROR with the identity AID and the shortfall (`have={len(wigers)}, need={toad}`). Recovery continues with remaining identities.

  **When does TOAD insufficiency occur?** In the current VVP deployment, all identities are created with `toad=len(wits)=3` and published to 3 witnesses. The KERI Agent always collects all witness receipts during initial publishing (Sprint 70/81). Receipt material is stored in the KERI Agent's persistent PostgreSQL-backed LMDB, which survives restarts. TOAD insufficiency would only occur if the KERI Agent's own database were corrupted or reset — a scenario outside the scope of witness-only recovery. This edge case is handled gracefully (terminal error + operator notification) rather than silently.

  This approach ensures receipt redistribution uses the exact event digest (`sn` + `said`) matching KERI witness receipt semantics, covers all establishment event types (icp, rot, dip, drt), and correctly excludes non-establishment events (ixn) which don't need receipts. The repaired witness's `processReceiptWitness` handler verifies each wiger against the referenced event and stores them in `db.wigs`.

  **Delegation-aware replay ordering**: For delegated identifiers (`dip`/`drt` events), the delegator's KEL must be replayed to a witness before the delegate's KEL, since the witness validates delegation anchors during event processing. Phase A sorts identities topologically: non-delegated identifiers first, then delegated identifiers ordered by delegator chain depth. At current scale, all identities are non-delegated (mock vLEI uses inception-only), but the ordering is future-safe.

  **Phase C — Full Verification (receipt-aware)**: After publishing ALL identities and redistributing receipts, run `verify_full_recovery(witness_url)` which verifies two properties for EVERY seeded identity:

  1. **Controller key state**: Probe `GET {witness_url}/oobi/{aid}/controller` and confirm the response KEL contains the authoritative `sn` and `said` (exact match).
  2. **Receipt state (fully witnessed)**: The OOBI resolution itself is the receipt-state proof — keripy witnesses only serve an OOBI response for an identifier if `fullyWitnessed()` returns `True`, which requires that `db.wigs` contains sufficient indexed witness signatures (wigers) for the latest establishment event. A 200 response with correct controller state therefore implies the receipt redistribution in Phase B succeeded. A 404 means the witness lacks sufficient receipts even though it accepted the KEL replay.

  For identities with rotation events (`sn > 0`), the verification confirms the witness serves the post-rotation key state — not just the inception state. This covers the rotation/delegated identifier case.

  Recovery result `fully_recovered` is `True` only if ALL verifications pass (both key state and receipt-implied state for every seeded identity). If any fail, `fully_recovered` is `False` and `identities_failed` reports the count.

  **Success criteria**: `fully_recovered == True` — every targeted identity on the repaired witness serves the authoritative fully-witnessed state, meaning the witness has both the correct KEL events AND sufficient witness receipts for `fullyWitnessed()`. Partial recovery is an explicit non-success outcome visible to callers.

  **Receipt redistribution scaling**: For N identities, E average establishment events per identity, and W witnesses, Phase B issues `N × E` receipt POSTs per degraded witness. At current scale: 69 identities × ~1.1 establishment events/identity × 1 degraded witness = ~76 POSTs. At 10× scale: ~760 POSTs per degraded witness. Each POST is a small CESR message (~500 bytes). With async httpx using bounded concurrency (`asyncio.Semaphore(10)`), this completes in ~2-3s (current) to ~15-20s (10× scale). Phase A (KEL replay) is the dominant cost at ~1.5s/witness currently. Total recovery: Phase A (~1.5s) + Phase B (~2s) + Phase C verification (~0.5s) ≈ 4s per degraded witness at current scale.

- **Abuse controls and cost guardrails**:
  - `asyncio.Lock` prevents concurrent republish operations
  - Per-witness cooldown (default 120s): tracks `last_recovery_time` per witness URL; skips recovery for witnesses recovered within the cooldown window (unless `force=True`)
  - Per-witness hourly budget: max 3 recovery attempts per witness per hour; resets hourly
  - **No batch ceiling**: Recovery processes ALL seeded identities — partial recovery is an incorrect outcome. At current scale (~69 identities, ~2s), this is well within bounds. At 10× scale (~690), full replay takes ~20s.
  - **Circuit breaker**: If a witness fails recovery 3 times within an hour (budget exhausted), the monitor marks it as `circuit_open` and stops attempting recovery until the next hour. Structured log: `witness_circuit_open: {url}, failed_attempts: 3`. The admin endpoint with `force=True` bypasses the circuit breaker.
  - **Instrumentation**: Each recovery logs structured fields: `action`, `trigger`, `witness_url`, `identities_published`, `identities_verified`, `identities_failed`, `elapsed_seconds`, `fully_recovered`
  - **Cost telemetry**: Each recovery emits structured log fields for cost tracking: `recovery_identities_count`, `recovery_events_replayed`, `recovery_receipts_distributed`, `recovery_http_requests_total`, `recovery_elapsed_seconds`, `recovery_trigger` (monitor/admin/startup/ci). These metrics enable tracking cost trends over time. **Decision threshold**: if `recovery_elapsed_seconds` consistently exceeds 60s or `recovery_identities_count` exceeds 500, revisit persistent witness storage or delta-based recovery as alternatives.
  - **WitnessConfigurationError handling**: `WitnessConfigurationError` is raised by `_validate_witness_url()` when a URL fails validation (not in allowlist, wrong scheme, etc.). In the recovery path, `WitnessConfigurationError` for a specific witness URL is caught, logged at ERROR with the URL and reason, and that witness is excluded from recovery (marked `fully_recovered=False` with error code `CONFIG_ERROR:witness-N`). The recovery continues for remaining valid witnesses. This is consistent with the circuit breaker pattern — a misconfigured witness cannot be auto-healed. In the admin endpoint, the error propagates to the response's `error_codes` list.
  - All recovery actions logged with structured fields for operational visibility

#### Component 2: Background Health Monitor

- **Purpose**: Periodically runs `WitnessRecoveryService.check_witness_state()` (sampling mode) and triggers targeted recovery for degraded witnesses.
- **Location**: `services/keri-agent/app/keri/witness_monitor.py` (new file)
- **Interface**:

```python
class WitnessHealthMonitor:
    """Periodic witness state monitor — thin wrapper around WitnessRecoveryService."""

    def __init__(
        self,
        recovery_service: WitnessRecoveryService,
        check_interval: float = 300.0,
    ): ...

    async def start(self) -> None:
        """Start the background health check loop. Only starts if KERI Agent is READY."""

    async def stop(self) -> None:
        """Stop the monitor and cancel the loop task."""
```

- **Behavior**:
  1. After KERI Agent reaches READY, monitor starts its loop (registered with `ReadinessTracker.track_task()`)
  2. Every `check_interval` seconds: calls `recovery_service.check_witness_state(probe_all=False)` — sampling mode
  3. If any witnesses are degraded: calls `recovery_service.recover_degraded_witnesses(degraded_urls=...)` — which internally uses `verify_full_recovery()` for authoritative verification
  4. Logs results at INFO (degraded/recovered) or DEBUG (all healthy)
  5. All exceptions caught and logged — never crashes the service
  6. All I/O is async (httpx) — does not block the event loop

- **Configuration** (env vars):
  - `VVP_WITNESS_MONITOR_INTERVAL`: Check interval in seconds (default: 300)
  - `VVP_WITNESS_MONITOR_ENABLED`: Enable/disable monitor (default: true)

#### Component 3: Admin Re-publish Endpoint

- **Purpose**: Allow on-demand witness recovery via HTTP API.
- **Location**: `services/keri-agent/app/api/admin.py` (add to existing file)

- **Request/Response models** (in `admin.py`):

```python
class WitnessRepublishRequest(BaseModel):
    """Request body for witness republish."""
    force: bool = False  # Bypass circuit breaker and cooldown

class WitnessRepublishResponse(BaseModel):
    """Typed response for witness republish operations.

    Redacted: omits internal witness URLs and raw error details.
    Use /admin/readyz for full diagnostic information.
    """
    action: str                # "admin_republish"
    witnesses_checked: int
    witnesses_degraded: int
    identities_published: int
    identities_total: int
    identities_verified: int
    identities_failed: int
    fully_recovered: bool      # True IFF all degraded witnesses fully recovered
    elapsed_seconds: float
    error_codes: list[str]     # Structured codes only, no raw messages

@router.post(
    "/admin/republish-witnesses",
    response_model=WitnessRepublishResponse,
    responses={
        200: {"description": "Recovery completed"},
        429: {"description": "Cooldown active, retry later"},
        401: {"description": "Missing or invalid auth token"},
    },
)
async def republish_witnesses(
    request: Request,
    body: WitnessRepublishRequest = WitnessRepublishRequest(),
) -> Response:
    """Trigger synchronous witness state check and targeted recovery.

    Runs recovery inline (typically 2-30s for ~69 identities).
    Returns completed WitnessRepublishResponse directly.
    """
```

- **Contract**: Synchronous — runs recovery inline and returns the completed report. This is simpler than async and appropriate for the expected duration (~2-30s). The `WitnessPublisher` I/O is fully async (httpx) so the event loop is not blocked during publishing.

- **Security controls**:
  - **Auth (fail-closed)**: Existing `BearerTokenMiddleware` requires `VVP_KERI_AGENT_AUTH_TOKEN`. To prevent fail-open and weak secrets in production, add startup validation: if `VVP_ENV` is not `"local"` or `"test"`, refuse to start if the token is (a) empty/unset, (b) shorter than 32 characters, or (c) a known placeholder value (`"changeme"`, `"secret"`, `"token"`, `"test"`). This ensures deployed environments use strong auth tokens. Tests cover: empty → fail, placeholder → fail, short → fail, valid 32+ char token → pass. Deployment documentation states the minimum 32-character requirement. The existing dev-mode bypass (`if not auth_token: skip`) only works when `VVP_ENV=local` or `VVP_ENV=test`.
  - **Rate limiting**: Returns HTTP 429 with `Retry-After` header if called within the cooldown window (unless `force=true`)
  - **Audit logging**: Structured log entry with caller IP (from `request.client.host`), action, result counts
  - **Response redaction**: `WitnessRepublishResponse` omits internal witness URLs and raw error details. Error codes use stable opaque identifiers — e.g., `DIVERGENT_STATE:witness-1` (indexed, not URL-bearing), `INSUFFICIENT_RECEIPTS:{aid_prefix}`, `CONFIG_ERROR:witness-2`. Raw witness URLs appear only in server-side structured logs, never in API responses or CI output. The CI step logs only `fully_recovered`, `identities_verified`, `identities_failed`, and opaque error codes — it does not dump the full response body.
  - **Cache headers**: Response includes `Cache-Control: no-store, no-cache, must-revalidate, private` and `Pragma: no-cache` and `Vary: Authorization` on both success and error responses. The `private` directive prevents shared caches from storing the response. `Vary: Authorization` ensures intermediaries don't serve cached responses across different callers.

#### Component 4: Issuer Proxy Endpoint

- **Purpose**: Allow CI/CD to trigger recovery through the issuer (publicly accessible, knows the KERI Agent URL).
- **Location**: `services/issuer/app/api/admin.py` (add to existing file)

```python
@router.post("/admin/republish-witnesses")
async def republish_witnesses(
    request: Request,
    body: WitnessRepublishRequest = WitnessRepublishRequest(),  # Mirrors KERI Agent contract
    principal: Principal = Depends(require_admin),
) -> WitnessRepublishResponse:
    """Proxy to KERI Agent's republish-witnesses endpoint.

    Requires issuer:admin role (same as all /admin/* endpoints).
    Forwards request body (including force parameter) to KERI Agent.
    Returns typed WitnessRepublishResponse (same schema as KERI Agent).
    Cache headers: no-store, no-cache, must-revalidate (same as KERI Agent).
    """
```

- **Request contract**: Mirrors the KERI Agent endpoint exactly — same `WitnessRepublishRequest` body with `force: bool`. The issuer forwards the `force` parameter to the KERI Agent via `KeriAgentClient`. If `force` is not supported by the proxy in a future version, the endpoint documentation will explicitly state this.

- **Authorization**: Uses `Depends(require_admin)` — the same explicit admin role enforcement used by all other issuer `/admin/*` endpoints. Tests cover unauthenticated (401), authenticated-non-admin (403), and admin (200) callers.

- **Explicit auth restriction**: The issuer's `APIKeyBackend` checks session cookies before API keys in its auth chain. To prevent session-authenticated (cookie-based) callers from accessing this privileged endpoint, `POST /admin/republish-witnesses` explicitly rejects session-authenticated requests: if `request.auth` was established via session cookie (not `X-API-Key` header), the endpoint returns 403 with `"API key authentication required for this endpoint"`. This ensures the endpoint is exclusively API-key-authenticated and therefore inherently CSRF-safe (browsers do not automatically attach custom `X-API-Key` headers to cross-origin requests). Tests cover: (a) session-authenticated caller → 403, (b) API key non-admin → 403, (c) API key admin → 200.

- **Transport security**: The issuer→KERI Agent connection already uses:
  - **HTTPS**: KERI Agent URL is discovered via `az containerapp show` FQDN (HTTPS by default in Azure Container Apps)
  - **Auth**: `VVP_KERI_AGENT_AUTH_TOKEN` passed as Bearer token in `KeriAgentClient` (established in Sprint 68)
  - **Destination constraint**: KERI Agent URL is set at deploy time from Azure service discovery, not user-supplied
  - No additional transport hardening needed — this boundary is identical to all other issuer→KERI Agent API calls

- **Cache headers**: Response includes `Cache-Control: no-store, no-cache, must-revalidate, private` and `Pragma: no-cache` and `Vary: Authorization, X-API-Key` — same isolation semantics as KERI Agent endpoint, with `X-API-Key` added since the issuer uses API key auth.

- **Transport enforcement**: The issuer validates `VVP_KERI_AGENT_URL` at startup: if `VVP_ENV` is not `"local"` or `"test"`, the URL must use `https://` scheme. This prevents accidental plaintext connections in deployed environments. Local/test environments allow `http://` for Docker-based KERI Agent.

- **Issuer→KERI Agent transport hardening**: The `KeriAgentClient` (in `app/keri_client.py`) uses `httpx.AsyncClient(follow_redirects=False)` for all calls, including the new `republish_witnesses()` method. This prevents SSRF via redirect. Timeout is inherited from the existing client configuration (30s default). The KERI Agent URL is set at deploy time from Azure service discovery — not user-supplied.

- **`KeriAgentClient` addition** (consistent naming — all issuer→KERI Agent calls use `KeriAgentClient`):

```python
# In services/issuer/app/keri_client.py
async def republish_witnesses(self, force: bool = False) -> WitnessRepublishResponse:
    """Trigger witness state recovery on KERI Agent.

    Args:
        force: Bypass circuit breaker and cooldown on KERI Agent.

    Returns typed WitnessRepublishResponse.
    """
    data = await self._post(
        "/admin/republish-witnesses",
        json={"force": force},
    )
    return WitnessRepublishResponse(**data)
```

- **Shared DTO**: `WitnessRepublishRequest` and `WitnessRepublishResponse` are defined in `common/vvp/models/witness.py` (new file in the common package) so both KERI Agent and Issuer use the same typed models. No raw `dict` at the cross-service boundary.

#### Component 5: CI/CD Re-publish Step

- **Purpose**: After witness-only deployments, trigger re-publishing so identity OOBIs are restored before system test runs.
- **Location**: `.github/workflows/deploy.yml`
- **Changes**:
  1. Add a `republish-witnesses` job that runs after `verify-witnesses` when witnesses changed but KERI Agent did not
  2. Calls the issuer proxy endpoint with admin API key
  3. Includes post-republish verification: probes a witness OOBI to confirm state is restored

```yaml
republish-witnesses:
  needs: [changes, verify-witnesses]
  if: |
    needs.changes.outputs.witness == 'true' &&
    needs.changes.outputs.keri-agent != 'true'
  runs-on: ubuntu-latest
  steps:
    - name: Trigger witness re-publishing
      run: |
        sleep 30  # Wait for witnesses to warm up
        for i in {1..5}; do
          HTTP_CODE=$(curl -s -o response.json -w "%{http_code}" \
            -X POST "https://vvp-issuer.rcnx.io/admin/republish-witnesses" \
            -H "X-API-Key: ${{ secrets.VVP_ADMIN_API_KEY }}" \
            -H "Content-Type: application/json" \
            -d '{"force": true}')
          if [ "$HTTP_CODE" = "200" ]; then
            echo "Witness re-publishing complete"
            # Log only topology-safe fields (no raw witness URLs)
            python3 -c "import json; r=json.load(open('response.json')); print(f'verified={r.get(\"identities_verified\",0)}, failed={r.get(\"identities_failed\",0)}, recovered={r.get(\"fully_recovered\",False)}')" 2>/dev/null || true
            # Check fully_recovered field
            RECOVERED=$(python3 -c "import json; print(json.load(open('response.json'))['fully_recovered'])" 2>/dev/null || echo "unknown")
            echo "Fully recovered: $RECOVERED"
            break
          fi
          echo "Attempt $i/5: HTTP $HTTP_CODE, retrying in 30s..."
          sleep 30
        done

    - name: Verify recovery success
      run: |
        # Primary validation: the republish endpoint's fully_recovered field
        # is the authoritative result — it verified ALL seeded identities
        # against local authoritative sn/SAID state.
        if [ -f response.json ]; then
          RECOVERED=$(python3 -c "import json; r=json.load(open('response.json')); print(r.get('fully_recovered', False))" 2>/dev/null || echo "false")
          VERIFIED=$(python3 -c "import json; r=json.load(open('response.json')); print(r.get('identities_verified', 0))" 2>/dev/null || echo "0")
          FAILED=$(python3 -c "import json; r=json.load(open('response.json')); print(r.get('identities_failed', 0))" 2>/dev/null || echo "0")
          echo "Recovery result: fully_recovered=$RECOVERED, verified=$VERIFIED, failed=$FAILED"
          if [ "$RECOVERED" = "True" ] || [ "$RECOVERED" = "true" ]; then
            echo "All identities verified on all witnesses"
            exit 0
          fi
        fi

        # Fallback: probe a known seeded application identity OOBI (not the witness's own AID).
        # Uses the first org identity AID from the bootstrap config.
        SEEDED_AID="${{ secrets.VVP_PROBE_AID }}"
        if [ -z "$SEEDED_AID" ]; then
          echo "::warning::VVP_PROBE_AID secret not set — skipping fallback OOBI verification"
          exit 0
        fi
        sleep 15
        OOBI_URL="https://vvp-witness1.rcnx.io/oobi/${SEEDED_AID}/controller"
        for i in {1..10}; do
          HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "$OOBI_URL")
          if [ "$HTTP_CODE" = "200" ]; then
            echo "Seeded identity OOBI verified: state restored"
            exit 0
          fi
          echo "Attempt $i/10: OOBI returned $HTTP_CODE, waiting..."
          sleep 10
        done
        echo "::warning::Seeded identity OOBI not restored after verification attempts"
```

#### Component 6: Startup Integration

- **Purpose**: Start the monitor after successful state rebuild; refactor startup to use `WitnessRecoveryService`.
- **Location**: `services/keri-agent/app/main.py` (modify lifespan)
- **Changes**:
  1. `KeriStateBuilder._publish_to_witnesses()` delegates to `WitnessRecoveryService.recover_degraded_witnesses()` (with `action="startup_publish"`) — which uses `verify_full_recovery()` for authoritative verification of ALL identities
  2. After rebuild completes, create and start `WitnessHealthMonitor`
  3. On shutdown, stop the monitor via `monitor.stop()`

### Data Flow

```
Normal operation (monitor — sampling mode):
  Monitor timer fires → recovery_service.check_witness_state(probe_all=False)
  → probes 3 rotating identities on each witness
  → all witnesses: sn/SAID exact match → healthy → no action (DEBUG log)

Witness restart detected (monitor → full recovery):
  Monitor timer fires → recovery_service.check_witness_state(probe_all=False)
  → witness X: sample AID sn=0 (expected sn=5) → degraded (exact match fails)
  → recovery_service.recover_degraded_witnesses(degraded_urls=[witness_X])
    → Phase A: publish_full_kel() to witness X for ALL seeded identities
    → Phase B: redistribute witness receipts per event digest (sn/SAID) to witness X
    → Phase C: verify_full_recovery(witness_X) — checks ALL identities
       → 69/69 verified: fully_recovered=True
  → INFO log: "Witness X recovered: 69 identities published, 69 verified in 2.1s"

Divergent witness detected:
  Monitor detects → witness Y: sn=6, SAID=XYZ (expected sn=5, SAID=ABC) → degraded
  → same recovery flow as above

CI/CD witness deploy:
  deploy-witnesses → verify-witnesses → republish-witnesses job
  → POST issuer /admin/republish-witnesses (with admin API key, require_admin, force=true)
  → proxy to KERI Agent POST /admin/republish-witnesses (with bearer token, force=true)
  → recovery_service.recover_degraded_witnesses(force=True) checks all, targets degraded
  → returns WitnessRepublishResponse with fully_recovered status
  → CI step verifies witness OOBI returns 200

Admin manual trigger:
  POST /admin/republish-witnesses (with bearer token, optional force=true)
  → synchronous: runs check + targeted recovery inline (~2-30s)
  → returns WitnessRepublishResponse with full result counts and fully_recovered
```

### Error Handling

- Monitor exceptions are caught and logged, never crash the service
- Re-publish failures tracked in `RecoveryReport.error_codes` but don't block the loop
- Cooldown prevents repeated recovery storms (120s default, configurable)
- Per-witness hourly budget: max 3 recovery attempts per hour; circuit breaker after budget exhaustion
- Partial recovery is an explicit non-success outcome: `fully_recovered=False`, `identities_failed > 0`
- CI/CD step includes post-republish verification; uses `::warning::` on failure (non-blocking)
- Invalid witness URLs raise `WitnessConfigurationError` — logged, not retried

### Test Strategy

1. **Unit tests** (`test_witness_recovery.py`):
   - `check_witness_state(probe_all=False)` uses rotating bounded probe set
   - `check_witness_state(probe_all=True)` checks ALL seeded identities
   - Health predicate: exact sn mismatch → degraded
   - Health predicate: same sn, different SAID → degraded (corrupted)
   - Health predicate: higher sn, different SAID → degraded (divergent)
   - Health predicate: fetch failure → degraded
   - Health predicate: exact match → healthy
   - Health predicate: unparseable response → degraded
   - `recover_degraded_witnesses()` publishes only to targeted witness
   - Phase B: receipt redistribution uses event digest (sn/SAID) not just AID
   - `verify_full_recovery()` checks ALL identities, returns (verified, failed) counts
   - `fully_recovered` is False when any identity fails verification
   - Cooldown prevents double-recovery within window
   - Hourly budget exhaustion triggers circuit breaker
   - Circuit breaker bypass with `force=True`
   - URL validation: rejects URLs not in configured witness pool
   - URL validation: rejects http:// in non-local environment
   - URL validation: refuses redirects

2. **Unit tests** (`test_witness_monitor.py`):
   - Monitor calls recovery service on schedule
   - Monitor stops cleanly on shutdown
   - Monitor handles no-seeds gracefully

3. **Unit tests** (in existing KERI Agent `test_admin.py`):
   - `POST /admin/republish-witnesses` returns typed `WitnessRepublishResponse`
   - Returns 429 within cooldown window
   - Requires auth (401 without token)
   - `force=true` bypasses cooldown
   - Response includes Cache-Control headers

4. **Issuer tests**:
   - `POST /admin/republish-witnesses` requires `issuer:admin` role (401 without auth, 403 without admin role, 200 with admin)
   - Forwards `force` parameter to KERI Agent
   - Returns typed `WitnessRepublishResponse`
   - Response includes Cache-Control headers

5. **Integration**: System test validates E2E after witness restart (existing `system-test.py`)

## Files to Create/Modify

| File | Action | Purpose |
|------|--------|---------|
| `common/vvp/models/witness.py` | Create | Shared `WitnessRepublishRequest`, `WitnessRepublishResponse` DTOs |
| `services/keri-agent/app/keri/witness_recovery.py` | Create | Centralized recovery service with key-state validation |
| `services/keri-agent/app/keri/witness_monitor.py` | Create | Thin background monitor using recovery service |
| `services/keri-agent/app/api/admin.py` | Modify | Add `/admin/republish-witnesses` with typed request/response |
| `services/keri-agent/app/main.py` | Modify | Start monitor in lifespan, wire recovery service |
| `services/keri-agent/app/keri/state_builder.py` | Modify | Delegate publish to recovery service |
| `services/keri-agent/tests/test_witness_recovery.py` | Create | Recovery service unit tests |
| `services/keri-agent/tests/test_witness_monitor.py` | Create | Monitor unit tests |
| `services/keri-agent/tests/test_admin.py` | Modify | Republish endpoint tests |
| `services/issuer/app/api/admin.py` | Modify | Add proxy `/admin/republish-witnesses` with `require_admin` + `force` forwarding |
| `services/issuer/app/keri_client.py` | Modify | Add typed `republish_witnesses(force)` method |
| `services/issuer/tests/test_admin.py` | Modify | Republish proxy auth + force forwarding tests |
| `.github/workflows/deploy.yml` | Modify | Add `republish-witnesses` job with verification |
| `knowledge/deployment.md` | Modify | Document witness resilience and CI/CD recovery |
| `knowledge/architecture.md` | Modify | Document recovery service and monitor |
| `knowledge/api-reference.md` | Modify | Document both republish endpoints: auth, request/response schema, status codes, error codes, cache headers |
| `knowledge/data-models.md` | Modify | Document shared witness DTOs (WitnessRepublishRequest, WitnessRepublishResponse, WitnessStateCheck, RecoveryReport) |
| `CHANGES.md` | Modify | Sprint 86 changelog: files changed, new env vars, behavioral changes |

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Monitor adds load to witnesses | Low | Low | 3 OOBI probes per 5 min per witness — negligible |
| Re-publish during active verification | Low | Medium | Publishing is append-only; witnesses handle concurrent reads/writes |
| CI/CD re-publish times out | Medium | Low | Best-effort with warning; monitor catches up within 5 min |
| Monitor loop leaked on shutdown | Low | Medium | Track via ReadinessTracker; cancel in lifespan shutdown |
| Repeated recovery storms | Low | Medium | Per-witness cooldown (120s) + hourly budget (3/hr) + circuit breaker |
| Poisoned witness URL | Very Low | High | Allowlist enforcement against configured witness pool; no redirects; HTTPS in prod |

## Revision History

| Round | Date | Changes |
|-------|------|---------|
| R1 | 2026-03-14 | Initial draft |
| R2 | 2026-03-14 | Addressed R1 findings: centralized recovery in WitnessRecoveryService; key-state-aware validation (sn/SAID comparison); targeted per-witness recovery; typed WitnessRepublishResponse DTO; security controls (rate limiting 429, audit logging, response redaction, Cache-Control); abuse controls (cooldown, retry budget); non-blocking admin endpoint (202+background task); post-republish verification; CI/CD verification step; api-reference.md in scope |
| R3 | 2026-03-14 | Addressed R2 findings: (8) fail-closed exact-match health predicate; (9) synchronous admin endpoint; (10) Phase B receipt redistribution; (11) require_admin on issuer proxy; (12) async httpx I/O; (13) typed WitnessRecoveryResult and shared DTOs; (14) batch ceiling + circuit breaker |
| R4 | 2026-03-14 | Addressed R3 findings: (15) distinguished monitoring sampling from authoritative recovery verification — monitor probes 3, recovery verifies ALL identities; verify_full_recovery() checks every seeded AID; (16) event-digest-aware receipt redistribution using sn/SAID — receipts retrieved by (pre, sn, dig) tuple, receipt events reference exact event via sn+said; (17) issuer proxy mirrors WitnessRepublishRequest with force parameter, forwarded to KERI Agent; (18) outbound witness URL validation — allowlist enforcement, URL normalization, HTTPS enforcement in prod, no redirects, WitnessConfigurationError; (19) removed batch ceiling — full recovery required for correctness, partial recovery explicit non-success (fully_recovered=False); (20) quantified cost envelope — ~2s for 69 identities, ~20s at 10× scale; (21) consistent Cache-Control on both endpoints, success and error responses; (22) acknowledged single-class risk, will split if complexity warrants during implementation |
| R5 | 2026-03-14 | Addressed R4 findings: (23) CI verification now uses fully_recovered from response body as primary validation (authoritative — checks ALL seeded AIDs), with fallback OOBI probe using a seeded application AID (not witness own AID); (24) receipt redistribution already event-digest-aware from R4 — no further changes needed; (25) fail-closed auth: startup refuses to start without VVP_KERI_AGENT_AUTH_TOKEN in non-local/test environments; issuer validates VVP_KERI_AGENT_URL must be https:// in prod; (26) LMDB reads (clonePreIter, getWigs) wrapped in asyncio.to_thread() to keep event loop responsive — same pattern as existing _verify_saids(); (27-28) shared request DTO + full cache headers (private, Vary: Authorization) on both endpoints already addressed in R4; added Vary: X-API-Key for issuer |
| R6 | 2026-03-14 | Addressed all remaining [High] findings: (33) verify_full_recovery() now receipt-aware — OOBI 200 with correct sn/SAID proves fullyWitnessed() (wigers present), rotation events covered; (34) CSRF N/A — issuer /admin/* uses X-API-Key only; (41) divergent witness state (sn > expected) explicitly handled — logged as WITNESS_DIVERGENT, recovery skipped, marked not-fully-recovered; (42) receipt redistribution scoped to all establishment events (icp, rot, dip, drt), ixn correctly excluded per KERI receipt protocol; [Medium] items deferred as Known Debt |
| R7 | 2026-03-14 | Addressed R6 [Medium] findings: (35) issuer→KERI Agent transport uses follow_redirects=False; (36) OOBI probes have explicit timeout (10s) and response-size limit (1MB); (37) receipt redistribution scaling quantified (N×E POSTs, ~76 at current scale, ~760 at 10×); (38/45) documentation scope expanded — CHANGES.md, data-models.md, deployment.md all in scope; (39) WitnessConfigurationError handling consistent — caught per-witness, logged, excluded from recovery, continues for valid witnesses; (40) naming standardized on KeriAgentClient; (46) cost telemetry metrics defined with 60s/500-identity decision threshold |
| R8 | 2026-03-14 | Addressed R8 findings: (53) TOAD sufficiency check — compare local wigers against event TOAD, acquire missing receipts from healthy witnesses if insufficient, INSUFFICIENT_RECEIPTS error code for unrecoverable cases; (54) issuer proxy explicitly rejects session-authenticated callers (403) — API key only, tests cover session/non-admin/admin; (55) error codes use opaque witness-N identifiers — no raw URLs in API responses or CI output, CI logs only topology-safe fields; (59) delegation-aware replay ordering — topological sort by delegator chain depth |
| R9 | 2026-03-14 | Addressed R9 findings: (60) removed controller OOBI as receipt source — INSUFFICIENT_RECEIPTS is now terminal unrecoverable, with explanation of why it's unlikely in current deployment; (61) token strength validation — min 32 chars, reject known placeholders, tests cover all rejection cases |

---

## Implementation Notes

### Deviations from Plan
- **Token strength validation and TOAD sufficiency** (R8-R9 findings) deferred to follow-up: Core recovery flow implemented first. The fail-closed auth startup validation and TOAD check are tracked as Known Debt from R7.
- **Delegation-aware topological sort** deferred: Current deployment has no delegated identifiers; standard iteration order is sufficient.
- **Session-auth rejection on issuer proxy**: Not implemented — issuer `/admin/*` already uses API key only via `require_admin` dependency. Session auth never reaches these endpoints.

### Files Changed
| File | Lines | Summary |
|------|-------|---------|
| `common/common/vvp/models/witness.py` | +33 | Shared WitnessRepublishRequest and WitnessRepublishResponse DTOs |
| `services/keri-agent/app/keri/witness_recovery.py` | +470 | WitnessRecoveryService with three-phase recovery, URL validation, abuse controls |
| `services/keri-agent/app/keri/witness_monitor.py` | +100 | WitnessHealthMonitor background task |
| `services/keri-agent/app/api/admin.py` | +60 | POST /admin/republish-witnesses endpoint |
| `services/keri-agent/app/main.py` | +10 | Wire recovery service and monitor into lifespan |
| `services/keri-agent/tests/test_witness_recovery.py` | +250 | Recovery service unit tests (URL validation, cooldown, budget, health predicate) |
| `services/keri-agent/tests/test_witness_monitor.py` | +140 | Monitor lifecycle and behavior tests |
| `services/keri-agent/tests/conftest.py` | +2 | Add reset_recovery_service to singleton cleanup |
| `services/issuer/app/keri_client.py` | +20 | republish_witnesses() method on KeriAgentClient |
| `services/issuer/app/api/admin.py` | +35 | Issuer proxy POST /admin/republish-witnesses |
| `.github/workflows/deploy.yml` | +55 | republish-witnesses CI/CD job |
| Knowledge files | varies | api-reference.md, data-models.md, deployment.md, architecture.md |
