# Sprint 52: Central Service Dashboard

## Problem Statement

The VVP ecosystem now spans 6+ services across Azure Container Apps and an Azure VM — verifier, issuer, 3 KERI witnesses, SIP redirect (signing), SIP verify, and FreeSWITCH PBX. Each has its own health endpoint and UI, but there is no single-pane-of-glass view. Operators must check each service individually to assess system health. This sprint adds a central dashboard to the issuer service that aggregates health from all services and provides quick navigation.

## Current State

- Issuer home page (`/ui/`) shows only its own health status (healthy/unhealthy dot + version)
- Verifier has its own `/healthz` endpoint
- SIP services have their own status pages
- KERI witnesses have health endpoints
- No unified view — operators must visit each service individually

## Proposed Solution

### Approach

Host the dashboard on the issuer service at `/ui/dashboard`. The issuer is already the management hub with 13+ UI pages, admin tools, and user management. A backend proxy endpoint (`GET /api/dashboard/status`) polls all service health endpoints server-side using `httpx.AsyncClient`, avoiding CORS issues. No new service or deployment infrastructure needed.

### Alternatives Considered

| Alternative | Pros | Cons | Why Rejected |
|-------------|------|------|--------------|
| Standalone dashboard service | Clean separation | New deployment, new Container App, more infrastructure to manage | Over-engineering for a status page |
| Client-side polling from browser | No backend needed | CORS blocks cross-origin health checks; exposes internal URLs to client | Browser can't reach PBX or witnesses directly |
| Grafana/external monitoring | Industry standard | Requires additional infrastructure (Grafana, Prometheus), complex setup | Too heavy for current needs |

### Detailed Design

#### Component 1: Dashboard Configuration (`services/issuer/app/config.py`)

Add new environment variables for service URLs:

```python
# Dashboard service definitions — JSON array of service objects
# Each service object: {"name": "Display Name", "url": "http://...", "health_path": "/healthz", "category": "core|sip|witness|infrastructure"}
# Default includes verifier, issuer, and 3 local witnesses with their known health paths.
VVP_DASHBOARD_SERVICES = _parse_json_list("VVP_DASHBOARD_SERVICES", json.dumps([
    {"name": "Verifier", "url": "http://localhost:8000", "health_path": "/healthz", "category": "core"},
    {"name": "Issuer", "url": "http://localhost:8001", "health_path": "/healthz", "category": "core"},
    {"name": "Witness wan", "url": "http://localhost:5642", "health_path": "/health", "category": "witness"},
    {"name": "Witness wil", "url": "http://localhost:5643", "health_path": "/health", "category": "witness"},
    {"name": "Witness wes", "url": "http://localhost:5644", "health_path": "/health", "category": "witness"},
]))

# SIP services — separate because they may use UDP probes or custom health paths
VVP_DASHBOARD_SIP_REDIRECT_URL = os.getenv("VVP_DASHBOARD_SIP_REDIRECT_URL", "")
VVP_DASHBOARD_SIP_REDIRECT_HEALTH = os.getenv("VVP_DASHBOARD_SIP_REDIRECT_HEALTH", "/healthz")
VVP_DASHBOARD_SIP_VERIFY_URL = os.getenv("VVP_DASHBOARD_SIP_VERIFY_URL", "")
VVP_DASHBOARD_SIP_VERIFY_HEALTH = os.getenv("VVP_DASHBOARD_SIP_VERIFY_HEALTH", "/healthz")
VVP_DASHBOARD_SIP_MONITOR_URL = os.getenv("VVP_DASHBOARD_SIP_MONITOR_URL", "")

# PBX — optional, added to VVP_DASHBOARD_SERVICES if operator configures it
# (no separate PBX config — operators add an entry to VVP_DASHBOARD_SERVICES
#  with category "infrastructure" and whatever health_path their PBX exposes)

# Timeout for each health check
VVP_DASHBOARD_REQUEST_TIMEOUT = float(os.getenv("VVP_DASHBOARD_REQUEST_TIMEOUT", "5.0"))
```

Key design decisions addressing reviewer feedback:

- **Configurable health paths**: Each service in `VVP_DASHBOARD_SERVICES` has its own `health_path` field (e.g., `/healthz` for issuer/verifier, `/health` for witnesses). No hardcoded assumption that all services use `/healthz`.
- **Explicit service names**: Each service object includes a `name` field for display (e.g., "Witness wan", "Witness wil"), resolving the reviewer's concern about identifying witnesses.
- **SIP redirect + SIP verify**: Both SIP services are separately configurable with their own URL and health path, covering the full sprint scope.
- A small helper `_parse_json_list()` parses a JSON array string from the env var.

#### Component 2: Health Aggregation API (`services/issuer/app/api/dashboard.py`)

- **Router**: `APIRouter(tags=["dashboard"])` following the `health.py` pattern
- **Endpoint**: `GET /api/dashboard/status`
- **Behavior**:
  1. Creates an `httpx.AsyncClient` with the configured timeout
  2. Fires health checks in parallel using `asyncio.gather()` to all configured services
  3. Each check hits the service's `/healthz` endpoint (or equivalent)
  4. Catches timeouts and connection errors gracefully — marks service as `unhealthy` with error detail
  5. Returns a JSON response with:
     - `overall_status`: `"healthy"` (all up), `"degraded"` (some down), `"unhealthy"` (all down)
     - `services`: list of service status objects, each with:
       - `name`: Human-readable service name
       - `url`: Base URL of the service
       - `status`: `"healthy"` | `"unhealthy"` | `"unknown"`
       - `response_time_ms`: Response time in milliseconds (null if unreachable)
       - `version`: Version string if available (null otherwise)
       - `error`: Error message if unhealthy (null otherwise)
       - `category`: `"core"` | `"sip"` | `"witness"` | `"infrastructure"`
     - `checked_at`: ISO timestamp of the check
     - `sip_monitor_url`: Direct link to SIP monitor dashboard (for UI convenience)

- **Service check logic** (per service — uses configurable `health_path`):
  ```python
  def _build_health_url(base_url: str, health_path: str) -> str:
      """Build health check URL with proper slash normalization."""
      return base_url.rstrip("/") + "/" + health_path.lstrip("/")

  async def _check_service(client, name, url, health_path, category):
      health_url = _build_health_url(url, health_path)
      start = time.monotonic()
      try:
          resp = await client.get(health_url)
          elapsed = (time.monotonic() - start) * 1000
          is_healthy = 200 <= resp.status_code < 300  # Any 2xx = healthy

          # Safe JSON parsing — some services return plain text or empty body
          version = None
          try:
              data = resp.json()
              version = data.get("version") or data.get("git_sha")
          except Exception:
              pass  # Non-JSON response is fine — version just stays None

          return {
              "name": name,
              "url": url,
              "status": "healthy" if is_healthy else "unhealthy",
              "response_time_ms": round(elapsed, 1),
              "version": version,
              "error": None if is_healthy else f"HTTP {resp.status_code}",
              "category": category,
          }
      except Exception as e:
          elapsed = (time.monotonic() - start) * 1000
          return {
              "name": name,
              "url": url,
              "status": "unhealthy",
              "response_time_ms": round(elapsed, 1),
              "version": None,
              "error": str(e),
              "category": category,
          }
  ```

  Key robustness decisions (addressing reviewer feedback):
  - **URL normalization**: `_build_health_url()` strips trailing/leading slashes to avoid `http://host//healthz` or `http://hosthealthz`
  - **2xx acceptance**: Any 2xx status code is treated as healthy (not just 200), since some services return 204
  - **Safe JSON parsing**: `resp.json()` wrapped in try/except — non-JSON health responses (plain text, empty body) are treated as healthy with `version=None`

- Services to check (built dynamically from config — skips services with empty URLs):
  - **Core/Witnesses**: Iterated from `VVP_DASHBOARD_SERVICES` JSON array — each entry has `name`, `url`, `health_path`, `category`
  - **SIP Redirect**: `VVP_DASHBOARD_SIP_REDIRECT_URL` + `VVP_DASHBOARD_SIP_REDIRECT_HEALTH` (category: `sip`)
  - **SIP Verify**: `VVP_DASHBOARD_SIP_VERIFY_URL` + `VVP_DASHBOARD_SIP_VERIFY_HEALTH` (category: `sip`)
  - **SIP Monitor**: URL stored separately (`VVP_DASHBOARD_SIP_MONITOR_URL`) — not health-checked, just linked in UI
  - **Infrastructure**: PBX or other services — added as entries in `VVP_DASHBOARD_SERVICES` with `category: "infrastructure"` and the appropriate HTTP `health_path`. No special TCP probe — all health checks are HTTP-based for consistency and reliability. If a service doesn't expose HTTP health, it is not monitored (operators can add an HTTP health proxy if needed).

#### Component 3: Dashboard UI (`services/issuer/web/dashboard.html`)

Single-page HTML following existing issuer patterns (vanilla CSS/JS, `shared.js`, same header/nav):

**Layout:**
1. **Overall status banner** at top — green/amber/red background with text ("All Systems Operational" / "Degraded" / "Outage")
2. **Core Services** section — Verifier and Issuer cards
3. **SIP Services** section — highlighted with teal accent, prominent "Open SIP Monitor" button
4. **KERI Witnesses** section — 3 witness cards (wan, wil, wes)
5. **Infrastructure** section — PBX status
6. **Auto-refresh** — 30-second polling with countdown timer shown in UI

**Card design:**
- Reuses `.feature-card` hover/shadow pattern from `index.html`
- Each card shows: service name, status dot (green/red), response time, version (if available)
- Error details shown in small red text below if unhealthy

**JavaScript:**
- `fetchStatus()` — calls `GET /api/dashboard/status`, updates all cards
- `startAutoRefresh()` — sets 30-second interval, shows countdown
- Manual refresh button
- No external dependencies — pure vanilla JS

#### Component 4: Route Registration (`services/issuer/app/main.py`)

```python
from app.api import dashboard

# UI route
@app.get("/ui/dashboard", response_class=FileResponse)
def ui_dashboard():
    """Serve the central service dashboard."""
    return FileResponse(WEB_DIR / "dashboard.html", media_type="text/html")

# API router
app.include_router(dashboard.router)
```

#### Component 5: Auth & Nav Link

- **Auth alignment**: The dashboard follows the same auth pattern as all other issuer UI pages. When `UI_AUTH_ENABLED=false` (default), `/ui/dashboard` and `/api/dashboard/status` are exempt — consistent with how `/ui/admin`, `/ui/schemas`, etc. are already exempt. When `UI_AUTH_ENABLED=true`, the dashboard requires authentication like all other UI pages. This is not a new departure — it's the existing pattern.
- Add `/ui/dashboard` and `/api/dashboard/status` to the `if not UI_AUTH_ENABLED:` block in `get_auth_exempt_paths()` (same block that exempts all other `/ui/*` routes)
- Add "Dashboard" link to nav bar in `index.html` (and `dashboard.html`)

### Data Flow

```
Browser → GET /api/dashboard/status
  → Issuer backend (dashboard.py)
    → asyncio.gather(
        httpx.get(verifier + /healthz),          # core (from VVP_DASHBOARD_SERVICES)
        httpx.get(issuer + /healthz),             # core (from VVP_DASHBOARD_SERVICES)
        httpx.get(sip-redirect + health_path),    # sip (from env vars)
        httpx.get(sip-verify + health_path),      # sip (from env vars)
        httpx.get(witness-wan + /health),          # witness (from VVP_DASHBOARD_SERVICES)
        httpx.get(witness-wil + /health),          # witness (from VVP_DASHBOARD_SERVICES)
        httpx.get(witness-wes + /health),          # witness (from VVP_DASHBOARD_SERVICES)
      )
    ← Aggregated JSON response
  ← Browser renders cards (grouped by category)
```

All health checks are HTTP-based — no TCP probes. This eliminates protocol ambiguity (UDP vs TCP) and keeps the implementation uniform.

### Error Handling

- Each service check is independent — one failure doesn't affect others
- Timeout per service: configurable via `VVP_DASHBOARD_REQUEST_TIMEOUT` (default 5s)
- Connection refused / timeout → `status: "unhealthy"`, `error: "Connection refused"` etc.
- Overall status computed: all healthy → `healthy`, some unhealthy → `degraded`, all unhealthy → `unhealthy`, no services configured → `unknown`
- Empty URL config → service skipped (not shown on dashboard)
- UI banner reflects `unknown` state with grey background and "No Services Configured" text

### Test Strategy

`services/issuer/tests/test_dashboard.py`:

1. **API response structure** — Mock httpx responses, verify JSON schema matches expected format (all required fields present)
2. **All healthy** — Mock all services returning 200, verify `overall_status: "healthy"`
3. **Partial failure** — Some services timeout/error, verify `overall_status: "degraded"` and individual error details
4. **All down** — All services unreachable, verify `overall_status: "unhealthy"`
5. **Timeout handling** — Mock slow responses, verify timeout is respected and error message indicates timeout
6. **Connection refused** — Mock connection error (e.g., `httpx.ConnectError`), verify graceful degradation with error detail
7. **Empty config** — No service URLs configured, verify `overall_status: "unknown"` and empty services list (not "healthy", since nothing was checked)
8. **Mixed service categories** — Configure services across core, sip, witness, infrastructure categories, verify correct grouping in response
9. **Configurable health paths** — Verify services use their `health_path` field, not a hardcoded `/healthz`
10. **UI route** — Verify `/ui/dashboard` returns HTML with status 200

11. **Non-JSON health response** — Mock a service returning 200 with plain text body, verify it's marked healthy with `version: null` (no crash)
12. **204 No Content response** — Mock a service returning 204, verify it's marked healthy (2xx acceptance)
13. **URL normalization** — Verify trailing/leading slash combinations produce correct URLs (unit test `_build_health_url`)

Tests will mock `httpx.AsyncClient` to avoid real network requests, following the project's existing test patterns with `pytest-asyncio` and the `client` fixture. The mock will be applied at the `httpx.AsyncClient` level using `unittest.mock.patch` to intercept outgoing requests.

## Files to Create/Modify

| File | Action | Purpose |
|------|--------|---------|
| `services/issuer/app/api/dashboard.py` | **Create** | Health aggregation API router |
| `services/issuer/app/config.py` | Modify | Add dashboard URL env vars + helper |
| `services/issuer/app/main.py` | Modify | Register dashboard router + `/ui/dashboard` route |
| `services/issuer/web/dashboard.html` | **Create** | Dashboard page (HTML + CSS + JS) |
| `services/issuer/web/index.html` | Modify | Add "Dashboard" nav link |
| `services/issuer/tests/test_dashboard.py` | **Create** | API + UI tests |

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Health checks slow down dashboard load | Medium | Low | Parallel checks + 5s timeout cap; UI shows loading state |
| Service URLs misconfigured in production | Medium | Low | Empty URLs are skipped; dashboard still works with partial config |
| CORS when SIP monitor is on different origin | Low | Low | Backend proxies all checks; SIP monitor link opens in new tab |

## Open Questions

None — the sprint definition is well-specified.

---

## Implementation Notes

### Deviations from Plan

- **PBX TCP probe removed** — Following reviewer feedback, PBX health checks use the same HTTP-based approach as all other services. Operators can add PBX as an entry in `VVP_DASHBOARD_SERVICES` with an HTTP health endpoint if available.
- **Auth follows existing pattern** — Dashboard routes are added to the `if not UI_AUTH_ENABLED` exemption block alongside all other UI routes. No special auth handling needed — `shared.js` handles Microsoft SSO, email/password, and API key authentication automatically.

### Test Results

```
23 passed in 1.03s (test_dashboard.py)
422 passed, 5 skipped total (full issuer suite)
```

### Files Changed

| File | Lines | Summary |
|------|-------|---------|
| `services/issuer/app/api/dashboard.py` | +134 | Health aggregation API with parallel checks |
| `services/issuer/app/config.py` | +28 | Dashboard service config env vars |
| `services/issuer/app/main.py` | +8 | Dashboard router + UI route registration |
| `services/issuer/web/dashboard.html` | +248 | Dashboard page with auto-refresh |
| `services/issuer/web/index.html` | +1 | Dashboard nav link |
| `services/issuer/tests/test_dashboard.py` | +273 | 23 tests covering API + UI + unit |
