# Sprint 48 (addendum): Full SIP Call Flow Event Capture

## Problem Statement

The SIP Monitor dashboard currently only captures the incoming INVITE to the signing service (port 5070). It shows request SIP headers but none of the VVP-specific response headers that prove the signing worked. Additionally, the verification service (port 5071) generates no events at all. This means the dashboard shows only 1 of the 4 observable stages of a VVP call:

| Stage | Service | Port | Currently Captured |
|-------|---------|------|--------------------|
| 1. Signing INVITE (request) | sip-redirect | 5070 | Yes (headers only since Sprint 55 fix) |
| 2. Signing 302 (response) | sip-redirect | 5070 | No — VVP response headers not captured |
| 3. Verification INVITE (request) | sip-verify | 5071 | No — separate process, no event capture |
| 4. Verification 302 (response) | sip-verify | 5071 | No — separate process, no event capture |

## Proposed Solution

### Approach

Capture all 4 stages by:
1. **Adding `response_vvp_headers` to the event model** — stores VVP headers from SIP responses (P-VVP-Identity, P-VVP-Passport, X-VVP-Brand-Name, X-VVP-Status, etc.)
2. **Enriching signing events** — pass the `SIPResponse` object to `_capture_event` so response VVP headers are included
3. **Adding an HTTP event ingestion endpoint** to the monitor server (`POST /api/events/ingest`, localhost-only, no auth) so the verification service can push events
4. **Adding event capture to the verification handler** — POSTs events to the monitor's ingestion endpoint via HTTP

### Alternatives Considered

| Alternative | Pros | Cons | Why Rejected |
|-------------|------|------|--------------|
| Shared file/mmap buffer | No HTTP overhead | Complex IPC, needs coordination | Over-engineered for low-volume SIP events |
| Verification service runs its own dashboard | Independent | Two dashboards, split view | Poor UX, no unified call flow |
| Move both services into one process | Shared buffer, simple | Major architectural change | Disproportionate effort, breaks service isolation |

### Detailed Design

#### Component 1: SIPEvent `response_vvp_headers` field

**Location**: `services/sip-redirect/app/monitor/buffer.py`

Add field to `SIPEvent` dataclass:
```python
response_vvp_headers: dict  # VVP headers from SIP response
```

Default to `{}` in `buffer.add()` if not provided (backward compatible).

**Serialization**: `SIPEvent` is a `@dataclass`, and the buffer uses `dataclasses.asdict(event)` in `get_all()`, `get_since()`, and `_notify_subscribers()` (see `buffer.py` lines 90-109, 144-166). Since `asdict()` automatically includes all dataclass fields, adding `response_vvp_headers: dict` ensures it appears in all API responses (`/api/events`, `/api/events/since/{id}`) and WebSocket push payloads with no additional serialization changes needed. Existing events created before this change will have `response_vvp_headers={}` (default factory).

#### Component 2: Signing handler — capture response VVP headers

**Location**: `services/sip-redirect/app/redirect/handler.py`

Update `_capture_event()` signature to accept an optional `response: SIPResponse` parameter. Extract VVP-specific headers from the response:
- `P-VVP-Identity` → `response.vvp_identity`
- `P-VVP-Passport` → `response.vvp_passport`
- `X-VVP-Status` → `response.vvp_status`
- `X-VVP-Brand-Name` → `response.brand_name`
- `X-VVP-Brand-Logo` → `response.brand_logo_url`

Update all `_capture_event()` call sites to pass the `response` object where available (the successful 302 path at line 239).

#### Component 3: Monitor event ingestion endpoint

**Location**: `services/sip-redirect/app/monitor/server.py`

Add `POST /api/events/ingest` handler:
- **No authentication** — localhost-only access
- **Loopback enforcement** — uses `request.transport.get_extra_info('peername')` (peer socket address, NOT proxy headers like X-Forwarded-For/X-Real-IP) to verify the request originates from localhost. Accepts both IPv4 `127.0.0.1` and IPv6 `::1`. If `peername` is `None` (e.g., UNIX socket or unavailable transport), the request is allowed (fail-open for local transports). Rejects with 403 if peername is present but not a loopback address. nginx does NOT proxy this path (confirmed: only `/sip-monitor/` location block proxies to port 8090; documented in a code comment for future maintainers).
- **Schema validation** — enforces required fields with explicit defaults:
  ```python
  REQUIRED_FIELDS = {"service", "method", "request_uri", "call_id", "response_code"}
  OPTIONAL_WITH_DEFAULTS = {
      "source_addr": "unknown",
      "from_tn": None,
      "to_tn": None,
      "api_key_prefix": None,
      "headers": {},
      "vvp_headers": {},
      "response_vvp_headers": {},
      "vvp_status": "INDETERMINATE",
      "redirect_uri": None,
      "error": None,
  }
  ```
  Missing required fields → 400. Optional fields filled with defaults. Extra/unknown keys silently ignored. `vvp_status` is optional with default `"INDETERMINATE"` — this handles error paths and pre-response events where the VVP status is not yet determined.
- **Returns** `{"ok": true, "event_id": <id>}`

Route registration:
```python
app.router.add_post("/api/events/ingest", handle_event_ingest)
```

#### Component 4: Verification service — event capture

**Location**: `services/sip-verify/app/verify/handler.py`

Add `_capture_event()` function (similar to signing handler but POSTs via HTTP):
- Extracts request headers and VVP headers from `SIPRequest`
- Extracts response VVP headers from `SIPResponse`
- POSTs to `http://127.0.0.1:{MONITOR_PORT}/api/events/ingest`
- Uses `aiohttp.ClientSession` (or httpx) for async HTTP
- Silently catches errors (monitoring must never break call processing)

**Location**: `services/sip-verify/app/config.py`

Add configuration:
```python
VVP_MONITOR_URL = os.getenv("VVP_MONITOR_URL", "http://127.0.0.1:8090")
VVP_MONITOR_ENABLED = os.getenv("VVP_MONITOR_ENABLED", "true").lower() == "true"
```

Event fields:
- `service`: `"VERIFICATION"`
- `source_addr`: from request
- `headers`: all request SIP headers
- `vvp_headers`: request VVP headers (Identity, P-VVP-Identity, P-VVP-Passport)
- `response_vvp_headers`: response VVP headers (X-VVP-Status, X-VVP-Brand-Name, X-VVP-Brand-Logo, X-VVP-Caller-ID, X-VVP-Error)
- `response_code`: 302 or error code
- `vvp_status`: VALID/INVALID/INDETERMINATE

#### Component 5: Dashboard UI — display response VVP headers

**Location**: `services/sip-redirect/app/monitor_web/sip-monitor.js`

Update the event detail view to display response VVP headers:

1. **Rename existing "VVP Headers" tab** to **"Request VVP"** — shows VVP headers from the incoming SIP request (X-VVP-API-Key for signing, Identity/P-VVP-* for verification)
2. **Add new "Response VVP" tab** — shows VVP headers from the SIP response:
   - For signing: P-VVP-Identity, P-VVP-Passport, X-VVP-Status, X-VVP-Brand-Name, X-VVP-Brand-Logo
   - For verification: X-VVP-Status, X-VVP-Brand-Name, X-VVP-Brand-Logo, X-VVP-Caller-ID, X-VVP-Error
3. **Update status badge rendering** — `getVvpStatusClass()` should prefer `response_vvp_headers["X-VVP-Status"]` when present (this is the definitive status), falling back to `vvp_headers` for backward compatibility with events that predate this change.
4. **Update event row** — show the `service` badge (SIGNING vs VERIFICATION) which is already in the template; no change needed.

The "All Headers" tab continues to show all raw SIP request headers. The "Summary" tab continues to show from/to TN, call-id, response code, etc. Each event represents one SIP transaction (request + response combined), with the `service` field distinguishing SIGNING from VERIFICATION.

### Data Flow

```
FreeSWITCH
    │
    ├── INVITE ──→ sip-redirect (5070)
    │                 │
    │                 ├── _capture_event(request, response) ──→ buffer.add()
    │                 │     service="SIGNING"                      │
    │                 │     headers={SIP headers}                  │
    │                 │     vvp_headers={X-VVP-API-Key}            │
    │                 │     response_vvp_headers={P-VVP-*,X-VVP-*}│
    │                 │                                            │
    │                 └── 302 + VVP headers ──→ FreeSWITCH         │
    │                                                              │
    ├── INVITE + VVP headers ──→ sip-verify (5071)                 │
    │                 │                                            │
    │                 ├── _capture_event() ──HTTP POST──→ /api/events/ingest
    │                 │     service="VERIFICATION"                 │
    │                 │     headers={SIP + Identity headers}       │
    │                 │     vvp_headers={Identity, P-VVP-*}        │
    │                 │     response_vvp_headers={X-VVP-*}         │
    │                 │                                            │
    │                 └── 302 + X-VVP-* headers ──→ FreeSWITCH     ▼
    │                                                         Dashboard
    └── (call continues with brand display)                   (WebSocket)
```

### Error Handling

- Verification event POST failures are caught silently (`log.debug`) — monitoring never blocks call processing
- Ingestion endpoint validates JSON structure, returns 400 for malformed requests
- HTTP timeout for verification→monitor POST: 1 second (fire-and-forget semantics)

### Test Strategy

**`services/sip-redirect/tests/test_monitor_buffer.py`** (update existing):
- Test `SIPEvent` with `response_vvp_headers` field
- Test backward compatibility (events without `response_vvp_headers`)

**`services/sip-redirect/tests/test_monitor_ingest.py`** (new):
- Test `POST /api/events/ingest` with valid event data
- Test peer socket loopback check (reject non-127.0.0.1 peername)
- Test missing required fields → 400
- Test optional fields filled with defaults
- Test event appears in buffer after ingest
- Test `response_vvp_headers` populated and retrievable via `/api/events`

**`services/sip-verify/tests/test_handler_events.py`** (new):
- Test `_capture_event` extracts correct headers from request/response
- Test HTTP POST is made to monitor URL
- Test failure handling (monitor unreachable)

## Files to Create/Modify

| File | Action | Purpose |
|------|--------|---------|
| `services/sip-redirect/app/monitor/buffer.py` | Modify | Add `response_vvp_headers` to `SIPEvent` |
| `services/sip-redirect/app/redirect/handler.py` | Modify | Pass `SIPResponse` to `_capture_event`, extract response VVP headers |
| `services/sip-redirect/app/monitor/server.py` | Modify | Add `POST /api/events/ingest` endpoint |
| `services/sip-verify/app/verify/handler.py` | Modify | Add `_capture_event()` with HTTP POST to monitor |
| `services/sip-verify/app/config.py` | Modify | Add `VVP_MONITOR_URL`, `VVP_MONITOR_ENABLED` |
| `services/sip-redirect/app/monitor_web/sip-monitor.js` | Modify | Add "Response VVP" tab, rename "VVP Headers" to "Request VVP", update status badge logic |
| `common/common/vvp/sip/models.py` | No change | Already updated with `headers`/`source_addr` |
| `common/common/vvp/sip/parser.py` | No change | Already updated with `all_headers` collection |

## Deployment

1. Deploy updated `buffer.py`, `handler.py`, `server.py` to sip-redirect release on PBX
2. Deploy updated `handler.py`, `config.py` to sip-verify release on PBX
3. Add `VVP_MONITOR_URL=http://127.0.0.1:8090` and `VVP_MONITOR_ENABLED=true` to `/etc/vvp/sip-verify.env`
4. Clear all `__pycache__`, restart both services
5. Deploy updated common package (`models.py`, `parser.py`) already done

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Verification event POST adds latency to calls | Low | Medium | 1s timeout, fire-and-forget, async |
| Monitor service down → verification events lost | Low | Low | Events are ephemeral anyway; audit log is the durable record |
| Ingestion endpoint abused from network | Low | Low | Localhost-only check; nginx doesn't proxy `/api/events/ingest` |

---

## Implementation Notes

### Deviations from Plan
- No deviations. Implementation follows plan exactly.

### Test Results
- sip-redirect: 113 tests passed (11 new: 5 buffer + 6 ingest)
- sip-verify: 46 tests passed (5 new: handler event capture)

### Files Changed

| File | Lines | Summary |
|------|-------|---------|
| `services/sip-redirect/app/monitor/buffer.py` | ~3 | Added `response_vvp_headers: dict` to SIPEvent, default in `add()` |
| `services/sip-redirect/app/redirect/handler.py` | ~25 | Added `response` param to `_capture_event`, extract response VVP headers |
| `services/sip-redirect/app/monitor/server.py` | ~50 | Added `POST /api/events/ingest` handler with loopback enforcement |
| `services/sip-redirect/app/monitor_web/index.html` | ~2 | Renamed "VVP Headers" tab to "Request VVP", added "Response VVP" tab |
| `services/sip-redirect/app/monitor_web/sip-monitor.js` | ~50 | Added `renderResponseVvpTab`, updated `getVvpStatusClass` to prefer response headers |
| `services/sip-verify/app/config.py` | ~10 | Added `VVP_MONITOR_URL`, `VVP_MONITOR_ENABLED`, `VVP_MONITOR_TIMEOUT` |
| `services/sip-verify/app/verify/handler.py` | ~90 | Added `_capture_event()` with HTTP POST, capture at all return points |
| `services/sip-redirect/tests/test_monitor_buffer.py` | +100 | New: 5 tests for response_vvp_headers in buffer |
| `services/sip-redirect/tests/test_monitor_ingest.py` | +156 | New: 6 tests for ingestion endpoint |
| `services/sip-verify/tests/test_handler_events.py` | +145 | New: 5 tests for verification event capture |
