import base64
import html
import json
import logging
import os
import time
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Form, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
import httpx

from contextlib import asynccontextmanager

from common.vvp.core.logging import configure_logging
from app.vvp.api_models import VerifyRequest, VerifyCalleeRequest
from app.vvp.exceptions import PassportError
from app.vvp.passport import parse_passport
from app.vvp.verify import verify_vvp
from app.vvp.verify_callee import verify_callee_vvp
from app.vvp.dossier import get_dossier_cache, CachedDossier, fetch_dossier as cached_fetch_dossier

configure_logging()
log = logging.getLogger("vvp")


@asynccontextmanager
async def lifespan(app):
    """Manage application lifecycle — start/stop background workers."""
    from app.core.config import VVP_VERIFICATION_CACHE_ENABLED
    if VVP_VERIFICATION_CACHE_ENABLED:
        from app.vvp.revocation_checker import get_revocation_checker
        checker = get_revocation_checker()
        await checker.start()
        log.info("Background revocation checker started (lifespan)")
    yield
    if VVP_VERIFICATION_CACHE_ENABLED:
        from app.vvp.revocation_checker import get_revocation_checker
        checker = get_revocation_checker()
        await checker.stop()
        log.info("Background revocation checker stopped (lifespan)")

# Default test JWT for simple verification page
DEFAULT_TEST_JWT = """eyJhbGciOiJFZERTQSIsInR5cCI6InBhc3Nwb3J0IiwicHB0IjoidnZwIiwia2lkIjoiaHR0cDovL3dpdG5lc3M1LnN0YWdlLnByb3ZlbmFudC5uZXQ6NTYzMS9vb2JpL0VHYXk1dWZCcUFhbmJoRmFfcWUtS01GVVBKSG44SjBNRmJhOTZ5eVdSckxGL3dpdG5lc3MifQ.eyJvcmlnIjp7InRuIjpbIjQ0Nzg4NDY2NjIwMCJdfSwiZGVzdCI6eyJ0biI6WyI0NDc3Njk3MTAyODUiXX0sImlhdCI6MTc2OTE4MzMwMiwiY2FyZCI6WyJDQVRFR09SSUVTOiIsIkxPR087SEFTSD1zaGEyNTYtNDBiYWM2ODZhM2YwYjQ4MjUzZGU1NWIzNGY1NTJjODA3MGJhZjIyZjgxMjU1YWFjNDQ5NzIxYzg3OWM3MTZhNDtWQUxVRT1VUkk6aHR0cHM6Ly9vcmlnaW4tY2VsbC1mcmFua2Z1cnQuczMuZXUtY2VudHJhbC0xLmFtYXpvbmF3cy5jb20vYnJhbmQtYXNzZXRzL3JpY2gtY29ubmV4aW9ucy9sb2dvLnBuZyIsIk5PVEU7TEVJOjk4NDUwMERFRTc1MzdBMDdZNjE1IiwiT1JHOlJpY2ggQ29ubmV4aW9ucyJdLCJjYWxsX3JlYXNvbiI6bnVsbCwiZ29hbCI6bnVsbCwiZXZkIjoiaHR0cHM6Ly9vcmlnaW4uZGVtby5wcm92ZW5hbnQubmV0L3YxL2FnZW50L3B1YmxpYy9FSGxWWFVKLWRZS3F0UGR2enRkQ0ZKRWJreXI2elgyZFgxMmh3ZEU5eDhleS9kb3NzaWVyLmNlc3IiLCJvcmlnSWQiOiIiLCJleHAiOjE3NjkxODM2MDIsInJlcXVlc3RfaWQiOiIifQ.OvoaiAwt1dgPb6gLkK7ufWoL2qzdtmudyyiL38oqB0wfaicGSG4B_QFtHY2vS2w-PYZ6LhN9dWXpsOHtpKAXCw""".strip()

# Default test SIP INVITE for tabbed explorer
DEFAULT_TEST_SIP = """INVITE sip:+447769710285@example.com SIP/2.0
Via: SIP/2.0/UDP 192.168.1.100:5060;branch=z9hG4bK776asdhds
Max-Forwards: 70
To: <sip:+447769710285@example.com>
From: <sip:+447884666200@example.com>;tag=1928301774
Call-ID: a84b4c76e66710@192.168.1.100
CSeq: 314159 INVITE
Contact: <sip:alice@192.168.1.100>
Content-Type: application/sdp
Content-Length: 0
Identity: eyJhbGciOiJFZERTQSIsInR5cCI6InBhc3Nwb3J0IiwicHB0IjoidnZwIiwia2lkIjoiaHR0cDovL3dpdG5lc3M1LnN0YWdlLnByb3ZlbmFudC5uZXQ6NTYzMS9vb2JpL0VHYXk1dWZCcUFhbmJoRmFfcWUtS01GVVBKSG44SjBNRmJhOTZ5eVdSckxGL3dpdG5lc3MifQ.eyJvcmlnIjp7InRuIjpbIjQ0Nzg4NDY2NjIwMCJdfSwiZGVzdCI6eyJ0biI6WyI0NDc3Njk3MTAyODUiXX0sImlhdCI6MTc2OTE4MzMwMiwiY2FyZCI6WyJDQVRFR09SSUVTOiIsIkxPR087SEFTSD1zaGEyNTYtNDBiYWM2ODZhM2YwYjQ4MjUzZGU1NWIzNGY1NTJjODA3MGJhZjIyZjgxMjU1YWFjNDQ5NzIxYzg3OWM3MTZhNDtWQUxVRT1VUkk6aHR0cHM6Ly9vcmlnaW4tY2VsbC1mcmFua2Z1cnQuczMuZXUtY2VudHJhbC0xLmFtYXpvbmF3cy5jb20vYnJhbmQtYXNzZXRzL3JpY2gtY29ubmV4aW9ucy9sb2dvLnBuZyIsIk5PVEU7TEVJOjk4NDUwMERFRTc1MzdBMDdZNjE1IiwiT1JHOlJpY2ggQ29ubmV4aW9ucyJdLCJjYWxsX3JlYXNvbiI6bnVsbCwiZ29hbCI6bnVsbCwiZXZkIjoiaHR0cHM6Ly9vcmlnaW4uZGVtby5wcm92ZW5hbnQubmV0L3YxL2FnZW50L3B1YmxpYy9FSGxWWFVKLWRZS3F0UGR2enRkQ0ZKRWJreXI2elgyZFgxMmh3ZEU5eDhleS9kb3NzaWVyLmNlc3IiLCJvcmlnSWQiOiIiLCJleHAiOjE3NjkxODM2MDIsInJlcXVlc3RfaWQiOiIifQ.OvoaiAwt1dgPb6gLkK7ufWoL2qzdtmudyyiL38oqB0wfaicGSG4B_QFtHY2vS2w-PYZ6LhN9dWXpsOHtpKAXCw
""".strip()

# Default test SAID for tabbed explorer (extracted from sample JWT evd claim)
DEFAULT_TEST_SAID = "EHlVXUJ-dYKqtPdvztdCFJEbkyr6zX2dX12hwdE9x8ey"

app = FastAPI(title="VVP Verifier", version="0.1.0", lifespan=lifespan)

# Template setup
templates_dir = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(templates_dir))

# Keep static mount for backwards compatibility (will be removed after migration verified)
app.mount("/static", StaticFiles(directory="web"), name="static")

@app.get("/")
def landing(request: Request):
    """Serve the main landing page describing VVP."""
    return templates.TemplateResponse("landing.html", {"request": request})


@app.get("/verify")
@app.get("/verify/")
def verify_landing(request: Request):
    """Serve the verification landing page with mode descriptions."""
    return templates.TemplateResponse("verify_landing.html", {"request": request})


@app.get("/verify/full")
def verify_full(request: Request):
    """Serve the full verification explorer page using HTMX templates."""
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/verify/simple")
def verify_simple(request: Request):
    """Serve the simple verification page with single-step workflow."""
    return templates.TemplateResponse("simple.html", {
        "request": request,
        "default_jwt": DEFAULT_TEST_JWT,
    })


@app.get("/verify/explore")
def verify_explore(request: Request):
    """Serve the tabbed explorer page with JWT/SIP/SAID inputs."""
    return templates.TemplateResponse("tabbed_explorer.html", {
        "request": request,
        "default_jwt": DEFAULT_TEST_JWT,
        "default_sip": DEFAULT_TEST_SIP,
        "default_said": DEFAULT_TEST_SAID,
    })


@app.get("/create")
def create_landing(request: Request):
    """Serve the dossier creation landing page."""
    return templates.TemplateResponse("create_landing.html", {"request": request})


@app.get("/ui/admin")
def ui_admin(request: Request):
    """Serve the admin dashboard page.

    Gated by ADMIN_ENDPOINT_ENABLED - returns 404 if disabled.
    """
    from app.core.config import ADMIN_ENDPOINT_ENABLED

    if not ADMIN_ENDPOINT_ENABLED:
        return templates.TemplateResponse(
            "404.html",
            {"request": request},
            status_code=404
        )
    return templates.TemplateResponse("admin.html", {"request": request})


@app.get("/healthz")
def healthz():
    return {"ok": True}

@app.middleware("http")
async def req_log(request: Request, call_next):
    start = time.time()
    route = request.url.path
    remote = request.client.host if request.client else "-"
    resp = await call_next(request)
    duration_ms = int((time.time() - start) * 1000)
    log.info(f"request_complete status={resp.status_code} duration_ms={duration_ms}",
             extra={"request_id":"-", "route":route, "remote_addr":remote})
    return resp

@app.post("/verify")
async def verify(req: VerifyRequest, request: Request):
    vvp_identity_header = request.headers.get("VVP-Identity")
    req_id, resp = await verify_vvp(req, vvp_identity_header)
    log.info("verify_called", extra={"request_id":req_id, "route":"/verify",
                                    "remote_addr": request.client.host if request.client else "-"})
    return JSONResponse(resp.model_dump())


@app.post("/verify-callee")
async def verify_callee(req: VerifyCalleeRequest, request: Request):
    """Verify callee identity per VVP §5B.

    Sprint 19 - Phase 12: Callee verification validates the called party's
    identity and rights. This endpoint implements the 14-step callee
    verification algorithm specified in VVP §5B.

    Requirements:
    - VVP-Identity header is REQUIRED
    - context.call_id is REQUIRED (for dialog matching)
    - context.sip.cseq is REQUIRED (for dialog matching)
    - caller_passport_jwt is OPTIONAL (for goal overlap check)

    The callee PASSporT MUST contain call-id and cseq claims matching
    the SIP INVITE values.
    """
    # Validate callee-specific requirements (per approved plan)
    # call_id is in CallContext, cseq is in SipContext
    if not req.context.call_id:
        return JSONResponse(
            status_code=400,
            content={"detail": "call_id required in context for callee verification"}
        )
    if not req.context.sip:
        return JSONResponse(
            status_code=400,
            content={"detail": "SIP context required for callee verification"}
        )
    if req.context.sip.cseq is None:
        return JSONResponse(
            status_code=400,
            content={"detail": "cseq required in SIP context for callee verification"}
        )

    vvp_identity_header = request.headers.get("VVP-Identity")
    if not vvp_identity_header:
        return JSONResponse(
            status_code=400,
            content={"detail": "VVP-Identity header required for callee verification"}
        )

    req_id, resp = await verify_callee_vvp(
        vvp_identity_header,
        req.passport_jwt,
        req.context,
        req.caller_passport_jwt,
    )

    log.info("verify_callee_called", extra={
        "request_id": req_id,
        "route": "/verify-callee",
        "remote_addr": request.client.host if request.client else "-"
    })

    return JSONResponse(resp.model_dump())


@app.get("/version")
def version():
    """Return service version with GitHub commit link."""
    # GIT_SHA is injected at deploy time by GitHub Actions
    git_sha = os.getenv("GIT_SHA", "unknown")
    repo = os.getenv("GITHUB_REPOSITORY", "andrewbalercnx/vvp-verifier")

    result = {"git_sha": git_sha}
    if git_sha != "unknown":
        result["github_url"] = f"https://github.com/{repo}/commit/{git_sha}"
        result["short_sha"] = git_sha[:7]

    return result


@app.get("/admin")
def admin():
    """Return all configurable items for operator visibility.

    Gated by ADMIN_ENDPOINT_ENABLED (default: True for dev, False for prod).
    """
    from app.core.config import (
        MAX_IAT_DRIFT_SECONDS,
        ALLOWED_ALGORITHMS,
        CLOCK_SKEW_SECONDS,
        MAX_TOKEN_AGE_SECONDS,
        MAX_PASSPORT_VALIDITY_SECONDS,
        ALLOW_PASSPORT_EXP_OMISSION,
        DOSSIER_FETCH_TIMEOUT_SECONDS,
        DOSSIER_MAX_SIZE_BYTES,
        DOSSIER_MAX_REDIRECTS,
        TIER2_KEL_RESOLUTION_ENABLED,
        ADMIN_ENDPOINT_ENABLED,
        DOSSIER_CACHE_TTL_SECONDS,
        DOSSIER_CACHE_MAX_ENTRIES,
        VVP_VERIFICATION_CACHE_ENABLED,
    )
    from app.vvp.keri.tel_client import TELClient, get_tel_client
    from app.vvp.keri.witness_pool import get_witness_pool
    from app.vvp.dossier.cache import get_dossier_cache

    if not ADMIN_ENDPOINT_ENABLED:
        return JSONResponse(
            status_code=404,
            content={"detail": "Admin endpoint disabled"}
        )

    return {
        "normative": {
            "max_iat_drift_seconds": MAX_IAT_DRIFT_SECONDS,
            "allowed_algorithms": list(ALLOWED_ALGORITHMS),
        },
        "configurable": {
            "clock_skew_seconds": CLOCK_SKEW_SECONDS,
            "max_token_age_seconds": MAX_TOKEN_AGE_SECONDS,
            "max_passport_validity_seconds": MAX_PASSPORT_VALIDITY_SECONDS,
            "allow_passport_exp_omission": ALLOW_PASSPORT_EXP_OMISSION,
        },
        "policy": {
            "dossier_fetch_timeout_seconds": DOSSIER_FETCH_TIMEOUT_SECONDS,
            "dossier_max_size_bytes": DOSSIER_MAX_SIZE_BYTES,
            "dossier_max_redirects": DOSSIER_MAX_REDIRECTS,
        },
        "features": {
            "tier2_kel_resolution_enabled": TIER2_KEL_RESOLUTION_ENABLED,
            "admin_endpoint_enabled": ADMIN_ENDPOINT_ENABLED,
            "verification_cache_enabled": VVP_VERIFICATION_CACHE_ENABLED,
        },
        "witnesses": {
            "legacy_default_urls": TELClient.DEFAULT_WITNESSES,
            "witness_pool": get_witness_pool().get_status(),
        },
        "environment": {
            "log_level": logging.getLogger().getEffectiveLevel(),
            "log_level_name": logging.getLevelName(logging.getLogger().getEffectiveLevel()),
        },
        "cache_config": {
            "dossier_cache_ttl_seconds": DOSSIER_CACHE_TTL_SECONDS,
            "dossier_cache_max_entries": DOSSIER_CACHE_MAX_ENTRIES,
        },
        "cache_metrics": {
            "dossier": get_dossier_cache().metrics().to_dict(),
            "revocation": get_tel_client().cache_metrics(),
            "verification": _get_verification_cache_metrics(),
        }
    }


def _get_verification_cache_metrics() -> dict:
    """Get verification cache metrics for admin endpoint."""
    from app.vvp.verification_cache import get_verification_cache
    ver_cache = get_verification_cache()
    m = ver_cache.metrics()
    total = m.hits + m.misses
    return {
        "hits": m.hits,
        "misses": m.misses,
        "hit_rate": round(m.hits / total, 4) if total > 0 else 0.0,
        "entries": ver_cache.size,
        "evictions": m.evictions,
        "version_mismatches": m.version_mismatches,
        "config_mismatches": m.config_mismatches,
        "revocation_checks": m.revocation_checks,
        "revocations_found": m.revocations_found,
    }


class LogLevelRequest(BaseModel):
    level: str


@app.post("/admin/log-level")
def set_log_level(req: LogLevelRequest):
    """Change log level at runtime (DEBUG, INFO, WARNING, ERROR, CRITICAL).

    Gated by ADMIN_ENDPOINT_ENABLED.
    """
    from app.core.config import ADMIN_ENDPOINT_ENABLED

    if not ADMIN_ENDPOINT_ENABLED:
        return JSONResponse(
            status_code=404,
            content={"detail": "Admin endpoint disabled"}
        )

    valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
    level_upper = req.level.upper()

    if level_upper not in valid_levels:
        return JSONResponse(
            status_code=400,
            content={"detail": f"Invalid log level. Must be one of: {valid_levels}"}
        )

    # Set level on root logger and all vvp loggers
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, level_upper))

    # Also update the vvp logger explicitly
    vvp_logger = logging.getLogger("vvp")
    vvp_logger.setLevel(getattr(logging, level_upper))

    log.info(f"Log level changed to {level_upper}")

    return {
        "success": True,
        "log_level": level_upper,
        "message": f"Log level set to {level_upper}"
    }


class CacheClearRequest(BaseModel):
    cache_type: str


@app.post("/admin/cache/clear")
async def admin_cache_clear(req: CacheClearRequest):
    """Clear specified cache (dossier, revocation, schema).

    Gated by ADMIN_ENDPOINT_ENABLED.
    """
    from app.core.config import ADMIN_ENDPOINT_ENABLED

    if not ADMIN_ENDPOINT_ENABLED:
        return JSONResponse(
            status_code=404,
            content={"detail": "Admin endpoint disabled"}
        )

    valid_types = ["dossier", "revocation", "schema", "verification"]
    cache_type = req.cache_type.lower()

    if cache_type not in valid_types:
        return JSONResponse(
            status_code=400,
            content={"detail": f"Invalid cache type. Must be one of: {valid_types}"}
        )

    try:
        if cache_type == "dossier":
            cache = get_dossier_cache()
            await cache.clear()
            log.info("Dossier cache cleared via admin endpoint")
        elif cache_type == "revocation":
            from app.vvp.keri.tel_client import get_tel_client
            client = get_tel_client()
            client.clear_cache()
            log.info("Revocation cache cleared via admin endpoint")
        elif cache_type == "verification":
            from app.vvp.verification_cache import get_verification_cache
            ver_cache = get_verification_cache()
            await ver_cache.clear()
            log.info("Verification cache cleared via admin endpoint")
        # Schema cache clear would go here if implemented

        return {"success": True, "cache_type": cache_type, "message": f"{cache_type} cache cleared"}
    except Exception as e:
        log.error(f"Failed to clear {cache_type} cache: {e}")
        return JSONResponse(
            status_code=500,
            content={"detail": f"Failed to clear cache: {str(e)}"}
        )


@app.post("/admin/witnesses/discover")
async def admin_witness_discover():
    """Trigger immediate GLEIF witness discovery.

    Gated by ADMIN_ENDPOINT_ENABLED.
    Forces rediscovery by resetting the discovery flag.
    """
    from app.core.config import ADMIN_ENDPOINT_ENABLED

    if not ADMIN_ENDPOINT_ENABLED:
        return JSONResponse(
            status_code=404,
            content={"detail": "Admin endpoint disabled"}
        )

    try:
        from app.vvp.keri.witness_pool import get_witness_pool

        pool = get_witness_pool()

        # Check if GLEIF discovery is actually enabled
        gleif_enabled = pool._gleif_discovery_enabled
        gleif_url = pool._gleif_oobi_url

        if not gleif_enabled or not gleif_url:
            return {
                "success": False,
                "gleif_enabled": gleif_enabled,
                "gleif_url_configured": bool(gleif_url),
                "message": "GLEIF discovery not configured. Set GLEIF_OOBI_URL environment variable.",
                "configured_witnesses": pool.configured_count,
                "discovered_witnesses": pool.discovered_count
            }

        # Force rediscovery by resetting the discovery flag
        pool._gleif_discovered = False
        await pool._ensure_gleif_discovered()

        log.info(f"GLEIF witness discovery triggered via admin endpoint, found {pool.discovered_count} GLEIF witnesses")

        return {
            "success": True,
            "gleif_enabled": True,
            "configured_witnesses": pool.configured_count,
            "discovered_witnesses": pool.discovered_count,
            "total_witnesses": pool.total_count,
            "message": f"Discovered {pool.discovered_count} GLEIF witnesses"
        }
    except Exception as e:
        log.error(f"Failed to discover witnesses: {e}")
        return JSONResponse(
            status_code=500,
            content={"detail": f"Failed to discover witnesses: {str(e)}"}
        )


class ProxyFetchRequest(BaseModel):
    url: str


async def _fetch_dossier_logic(evd_url: str) -> dict:
    """
    Fetch a dossier from the evidence URL.
    Shared logic used by /proxy-fetch JSON endpoint and /ui/fetch-dossier.
    """
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(evd_url)
        content_type = resp.headers.get("content-type", "")

        if "json" in content_type or evd_url.endswith(".json"):
            return {"data": resp.json(), "content_type": content_type, "raw": None}
        else:
            return {"data": resp.text, "content_type": content_type, "raw": resp.text}


class RevocationCheckRequest(BaseModel):
    credential_said: str
    registry_said: str | None = None
    oobi_url: str | None = None


@app.post("/check-revocation")
async def check_revocation(req: RevocationCheckRequest):
    """
    Check revocation status for a credential by querying KERI witnesses/watchers.

    This queries the TEL (Transaction Event Log) to determine if a credential
    has been revoked. It tries:
    1. OOBI URL if provided
    2. Known witness endpoints
    3. Returns UNKNOWN if no TEL data found
    """
    from app.vvp.keri.tel_client import get_tel_client, CredentialStatus

    try:
        client = get_tel_client()
        result = await client.check_revocation(
            credential_said=req.credential_said,
            registry_said=req.registry_said,
            oobi_url=req.oobi_url
        )

        response = {
            "success": True,
            "status": result.status.value,
            "credential_said": result.credential_said,
            "registry_said": result.registry_said,
            "source": result.source,
        }

        if result.issuance_event:
            response["issuance"] = {
                "datetime": result.issuance_event.datetime,
                "sequence": result.issuance_event.sequence,
                "type": result.issuance_event.event_type,
            }

        if result.revocation_event:
            response["revocation"] = {
                "datetime": result.revocation_event.datetime,
                "sequence": result.revocation_event.sequence,
                "type": result.revocation_event.event_type,
            }

        if result.error:
            response["error"] = result.error

        return response

    except Exception as e:
        log.error(f"Revocation check failed: {e}")
        return {
            "success": False,
            "status": "ERROR",
            "error": str(e)
        }


@app.post("/proxy-fetch")
async def proxy_fetch(req: ProxyFetchRequest):
    """Proxy endpoint to fetch dossiers (avoids CORS issues in browser).

    Uses shared _fetch_dossier_logic() to ensure consistent behavior with UI endpoints.
    """
    try:
        result = await _fetch_dossier_logic(req.url)
        return {
            "success": True,
            "data": result["data"],
            "content_type": result["content_type"],
        }
    except httpx.TimeoutException:
        return {"success": False, "error": "Timeout fetching URL"}
    except httpx.RequestError as e:
        return {"success": False, "error": f"Request failed: {str(e)}"}
    except Exception as e:
        return {"success": False, "error": str(e)}


class CredentialGraphRequest(BaseModel):
    """Request to build credential graph from dossier."""
    dossier: dict  # Raw dossier data with 'acdcs' array
    revocation_status: dict | None = None  # Optional SAID -> status mapping


@app.post("/credential-graph")
async def credential_graph(req: CredentialGraphRequest):
    """Build a credential graph from dossier ACDCs for visualization.

    Returns a graph structure with nodes (credentials) and edges (relationships)
    suitable for rendering as a directed graph in the UI.

    The graph includes:
    - Credential nodes from the dossier
    - Synthetic root nodes for trusted issuers
    - Edges showing credential relationships (vetting, delegation, issued_by)
    - Layer information for hierarchical visualization
    """
    from app.core.config import TRUSTED_ROOT_AIDS
    from app.vvp.acdc import (
        ACDC,
        CredentialStatus,
        build_credential_graph,
        credential_graph_to_dict,
        parse_acdc,
    )

    try:
        # Parse ACDCs from dossier
        dossier_acdcs: dict[str, ACDC] = {}
        acdcs_data = req.dossier.get("acdcs", [])

        if not acdcs_data:
            return {"success": False, "error": "No ACDCs found in dossier"}

        for acdc_data in acdcs_data:
            try:
                acdc = parse_acdc(acdc_data)
                dossier_acdcs[acdc.said] = acdc
            except Exception as e:
                log.warning(f"Failed to parse ACDC: {e}")
                continue

        if not dossier_acdcs:
            return {"success": False, "error": "No valid ACDCs parsed from dossier"}

        # Parse revocation status if provided
        revocation: dict[str, CredentialStatus] | None = None
        if req.revocation_status:
            revocation = {}
            for said, status_str in req.revocation_status.items():
                try:
                    revocation[said] = CredentialStatus(status_str)
                except ValueError:
                    pass

        # Build the graph
        graph = build_credential_graph(
            dossier_acdcs=dossier_acdcs,
            trusted_roots=set(TRUSTED_ROOT_AIDS),
            revocation_status=revocation,
        )

        return {
            "success": True,
            "graph": credential_graph_to_dict(graph),
        }

    except Exception as e:
        log.error(f"Failed to build credential graph: {e}")
        return {"success": False, "error": str(e)}


# =============================================================================
# HTMX UI Endpoints
# These endpoints return HTML fragments for HTMX partial page updates.
# They delegate to the domain layer for parsing/validation.
# =============================================================================


def _parse_sip_invite_logic(sip_invite: str) -> dict:
    """
    Parse a SIP INVITE message and extract headers.
    Returns the Identity header JWT if found.
    """
    lines = sip_invite.strip().split("\n")
    headers = {}
    identity_header = None

    for line in lines:
        line = line.strip()
        if ":" in line:
            key, value = line.split(":", 1)
            key = key.strip()
            value = value.strip()
            headers[key] = value

            if key.lower() == "identity":
                # Extract JWT from Identity header (format: JWT;info=...)
                identity_header = value.split(";")[0].strip()

    return {
        "identity_header": identity_header,
        "other_headers": {k: v for k, v in headers.items() if k.lower() != "identity"},
    }


# =============================================================================
# Spec Section Mapping for Validation Errors
# Maps error patterns to VVP specification sections for user reference.
# =============================================================================

SPEC_SECTION_MAP = {
    # Algorithm validation
    "forbidden algorithm": ("§5.0, §5.1", "VVP mandates EdDSA (Ed25519) only"),

    # ppt validation
    "ppt must be 'vvp'": ("§5.2", "PASSporT ppt claim must be 'vvp'"),
    "ppt mismatch": ("§5.2", "PASSporT ppt must match VVP-Identity ppt"),

    # kid validation
    "kid mismatch": ("§5.2", "PASSporT kid must match VVP-Identity kid"),

    # Temporal validation
    "iat drift": ("§5.2A", "iat drift must be ≤ 5 seconds"),
    "exp must be greater than iat": ("§5.2A", "Expiry must be after issuance"),
    "exp drift": ("§5.2A", "exp drift must be ≤ 5 seconds"),
    "exp absent but VVP-Identity exp": ("§5.2A", "PASSporT exp required when VVP-Identity exp present"),

    # Expiry policy
    "validity window exceeds": ("§5.2B", "exp - iat must be ≤ 300 seconds"),
    "token expired": ("§5.2B", "PASSporT has expired"),
    "max-age exceeded": ("§5.2B", "Token age exceeds max-age policy"),

    # Phone number validation
    "orig.tn must be an array": ("§4.2", "orig.tn must be an array with single phone number"),
    "orig.tn must contain exactly one": ("§4.2", "orig.tn array must contain exactly one phone number"),
    "orig.tn[0] must be a string": ("§4.2", "orig.tn[0] must be a string type"),
    "orig.tn[0] must be E.164": ("§4.2", "Phone numbers must be E.164 format"),
    "dest.tn must be an array": ("RFC8225", "dest.tn must be an array per RFC8225"),
    "dest.tn array must not be empty": ("RFC8225", "dest.tn array cannot be empty"),
    "dest.tn[": ("§4.2", "Each dest.tn entry must be valid E.164"),

    # typ header
    "typ must be 'passport'": ("RFC8225", "typ header must be 'passport' when present"),

    # Required fields
    "missing required field": ("§5.2A", "Required PASSporT field missing"),
    "orig.tn is required": ("§4.2", "orig.tn claim is required"),
    "dest.tn is required": ("RFC8225", "dest.tn claim is required"),

    # Structure validation
    "JWT must have 3 parts": ("RFC7519", "JWT must be header.payload.signature"),
    "base64url decode failed": ("RFC7519", "Invalid base64url encoding"),
    "JSON parse failed": ("RFC7519", "Invalid JSON in JWT part"),
}


def _get_spec_reference(error_message: str) -> dict | None:
    """Get spec section reference for an error message.

    Returns dict with section and description, or None if no match.
    """
    error_lower = error_message.lower()
    for pattern, (section, description) in SPEC_SECTION_MAP.items():
        if pattern.lower() in error_lower:
            return {"section": section, "description": description}
    return None


def _decode_jwt_permissive(jwt_str: str) -> dict:
    """Decode JWT parts without validation (for UI display).

    Returns dict with header, payload, signature even if content is invalid.
    This is UI-specific - domain layer validation happens separately.
    """
    parts = jwt_str.split(".")
    if len(parts) != 3:
        raise ValueError(f"Invalid JWT format (expected 3 parts, got {len(parts)})")

    def b64url_decode(data: str) -> bytes:
        padded = data + "=" * (-len(data) % 4)
        return base64.urlsafe_b64decode(padded)

    header = json.loads(b64url_decode(parts[0]).decode("utf-8"))
    payload = json.loads(b64url_decode(parts[1]).decode("utf-8"))
    signature = parts[2]

    return {"header": header, "payload": payload, "signature": signature}


@app.post("/ui/parse-jwt")
async def ui_parse_jwt(request: Request, jwt: str = Form(...)):
    """Parse a JWT and return HTML fragment with decoded contents.

    Uses permissive decoding for display, then validates with domain layer.
    Shows both decoded contents AND validation errors (if any).
    """
    # Preprocessing: strip ;ppt=vvp suffix if present (UI convenience)
    if ";" in jwt:
        jwt = jwt.split(";")[0]
    jwt = jwt.strip()

    validation_errors: list[dict] = []  # List of {message, spec_section, spec_description}

    # Step 1: Permissive decode for display
    try:
        decoded = _decode_jwt_permissive(jwt)
        header_dict = decoded["header"]
        payload_dict = decoded["payload"]
        signature_str = decoded["signature"]
    except Exception as e:
        # Can't even decode - show error
        return templates.TemplateResponse(
            "partials/jwt_result.html",
            {"request": request, "error": f"JWT decode failed: {e}"},
        )

    # Step 2: Validate with domain layer (collect errors with spec references)
    validation_warnings: list[dict] = []  # Warnings (non-fatal, e.g., E.164 format)
    try:
        passport = parse_passport(jwt)
        # If validation passes, use validated signature (bytes -> hex)
        signature_str = passport.signature.hex()
        # Collect any warnings (e.g., non-E.164 phone numbers)
        for warning in passport.warnings:
            validation_warnings.append({
                "message": warning,
                "spec_section": "§4.2",
                "spec_description": "E.164 phone number format recommended",
            })
    except PassportError as e:
        spec_ref = _get_spec_reference(e.message)
        validation_errors.append({
            "message": e.message,
            "spec_section": spec_ref["section"] if spec_ref else None,
            "spec_description": spec_ref["description"] if spec_ref else None,
        })
    except Exception as e:
        validation_errors.append({
            "message": f"Validation error: {e}",
            "spec_section": None,
            "spec_description": None,
        })

    # Format timestamps for display
    iat_formatted = ""
    exp_formatted = ""
    if payload_dict.get("iat"):
        try:
            iat_formatted = datetime.fromtimestamp(
                payload_dict["iat"], tz=timezone.utc
            ).isoformat()
        except (TypeError, ValueError):
            pass
    if payload_dict.get("exp"):
        try:
            exp_formatted = datetime.fromtimestamp(
                payload_dict["exp"], tz=timezone.utc
            ).isoformat()
        except (TypeError, ValueError):
            pass

    return templates.TemplateResponse(
        "partials/jwt_result.html",
        {
            "request": request,
            "header": header_dict,
            "payload": payload_dict,
            "signature": signature_str,
            "iat_formatted": iat_formatted,
            "exp_formatted": exp_formatted,
            "validation_errors": validation_errors,
            "validation_warnings": validation_warnings,
        },
    )


@app.post("/ui/parse-sip")
async def ui_parse_sip(request: Request, sip_invite: str = Form(...)):
    """Parse a SIP INVITE and return HTML fragment with extracted headers."""
    try:
        result = _parse_sip_invite_logic(sip_invite)

        return templates.TemplateResponse(
            "partials/sip_result.html",
            {
                "request": request,
                "identity_header": result["identity_header"],
                "other_headers": result["other_headers"],
            },
        )
    except Exception as e:
        return templates.TemplateResponse(
            "partials/sip_result.html",
            {"request": request, "error": str(e)},
        )


@app.post("/ui/fetch-dossier")
async def ui_fetch_dossier(
    request: Request,
    evd_url: str = Form(...),
    kid_url: str = Form(""),
):
    """Fetch dossier and return HTML fragment with credentials.

    Uses Sprint 21/22 view-model path for enhanced credential display:
    - Collapsible attribute sections with tooltips
    - Formatted dates, booleans, arrays
    - Redaction masking for partial disclosure
    - Edge link navigation
    - Inline revocation status from dossier TEL data
    """
    from app.vvp.dossier.parser import parse_dossier
    from app.vvp.dossier import build_dag
    from app.vvp.acdc import parse_acdc
    from app.vvp.ui.credential_viewmodel import (
        build_credential_card_vm,
        build_issuer_identity_map_async,
        build_validation_summary,
        build_error_buckets,
        build_schema_info_with_fetch,
        EvidenceStatus,
        EvidenceFetchRecord,
        EvidenceTimeline,
        DossierViewModel,
        ValidationCheckResult,
    )
    from app.vvp.keri.tel_client import TELClient, CredentialStatus

    start_time = time.time()
    cache_hit = False
    # Sprint 24: Track evidence fetch operations for timeline display
    evidence_records: list[EvidenceFetchRecord] = []

    try:
        # Check dossier cache first (§5.1.1-2.7)
        dossier_cache = get_dossier_cache()
        cached = await dossier_cache.get(evd_url)

        if cached:
            # Cache hit - use cached data
            cache_hit = True
            raw_bytes = cached.raw_content
            raw_text = raw_bytes.decode("utf-8")
            nodes = list(cached.dag.nodes.values())
            signatures = {}  # Signatures not stored in cache
            log.info(f"UI dossier cache hit: {evd_url[:50]}...")
            # Sprint 24: Record cache hit
            evidence_records.append(EvidenceFetchRecord(
                source_type="DOSSIER",
                url=evd_url,
                status=EvidenceStatus.CACHED,
                latency_ms=0,
                cache_hit=True,
            ))
        else:
            # Cache miss - fetch from network
            fetch_start = time.time()
            raw_bytes = await cached_fetch_dossier(evd_url)
            fetch_latency = int((time.time() - fetch_start) * 1000)
            raw_text = raw_bytes.decode("utf-8")
            nodes, signatures = parse_dossier(raw_bytes)

            # Build DAG and chain info for caching with auto-revocation check
            dag = build_dag(nodes)
            contained_saids = set(dag.nodes.keys())

            # Build chain_info for background revocation check
            from app.vvp.acdc.graph import build_credential_graph, build_all_credential_chains
            from app.vvp.acdc import parse_acdc, ACDC

            dossier_acdcs: Dict[str, ACDC] = {}
            for node in nodes:
                try:
                    acdc_dict = node.raw.copy() if node.raw else {}
                    acdc_dict["d"] = node.said
                    acdc_dict["i"] = node.issuer
                    acdc_dict["s"] = node.schema
                    if node.attributes:
                        acdc_dict["a"] = node.attributes
                    if node.edges:
                        acdc_dict["e"] = node.edges
                    acdc = parse_acdc(acdc_dict)
                    dossier_acdcs[acdc.said] = acdc
                except Exception as e:
                    log.debug(f"Skipping credential {node.said[:16]} for chain check: {e}")

            chain_info = None
            if dossier_acdcs:
                graph = build_credential_graph(
                    dossier_acdcs=dossier_acdcs,
                    trusted_roots=set(TRUSTED_ROOT_AIDS),
                )
                chain_info = build_all_credential_chains(graph)

            cached_dossier = CachedDossier(
                dag=dag,
                raw_content=raw_bytes,
                fetch_timestamp=time.time(),
                content_type="application/json+cesr",
                contained_saids=contained_saids,
            )

            # Cache with auto-start background revocation check
            await dossier_cache.put(
                evd_url,
                cached_dossier,
                chain_info=chain_info,
                dossier_data=raw_text,
                oobi_url=kid_url if kid_url else None,
            )
            log.info(f"UI dossier cached: {evd_url[:50]}... (saids={len(contained_saids)})")
            # Sprint 24: Record fetch success
            evidence_records.append(EvidenceFetchRecord(
                source_type="DOSSIER",
                url=evd_url,
                status=EvidenceStatus.SUCCESS,
                latency_ms=fetch_latency,
                cache_hit=False,
            ))
            # Assign cached variable for chain revocation check below
            cached = cached_dossier

        fetch_elapsed = time.time() - start_time

        # Note: Background revocation check auto-started by put() above
        # Read cached revocation status if available (from background check)
        revocation_cache: dict[str, dict] = {}
        if cached and cached.chain_revocation:
            for said, cred_result in cached.chain_revocation.credential_results.items():
                revocation_cache[said] = {
                    "status": cred_result.status.value,
                    "checked_at": cached.chain_revocation.checked_at,
                    "source": cred_result.source or "cached",
                    "error": cred_result.error,
                }
            # Record TEL check from cache
            evidence_records.append(EvidenceFetchRecord(
                source_type="TEL",
                url="chain-revocation (cached)",
                status=EvidenceStatus.CACHED if cached.chain_revocation.check_complete else EvidenceStatus.INDETERMINATE,
                latency_ms=0,
                cache_hit=True,
            ))
        elif cached and cached.chain_revocation_in_progress:
            # Background check still running - show as pending for all credentials
            for said in cached.contained_saids:
                revocation_cache[said] = {
                    "status": "PENDING",
                    "checked_at": None,
                    "source": "background_check",
                    "error": None,
                }
            evidence_records.append(EvidenceFetchRecord(
                source_type="TEL",
                url="chain-revocation (pending)",
                status=EvidenceStatus.INDETERMINATE,
                latency_ms=0,
                cache_hit=False,
                error="Background revocation check in progress",
            ))

        # Collect all SAIDs for edge availability checking
        all_saids = {node.said for node in nodes}

        # Build view-models for each credential (Sprint 21/22 enhanced display)
        credential_vms = []
        acdcs_for_graph = []  # Keep raw dicts for graph building
        parsed_acdcs = []  # Parsed ACDCs for identity map

        # First pass: parse all ACDCs and build raw dicts
        for node in nodes:
            # Build raw dict for backwards compatibility and graph
            acdc_dict = node.raw.copy() if node.raw else {}
            acdc_dict["d"] = node.said
            acdc_dict["i"] = node.issuer
            acdc_dict["s"] = node.schema
            if node.attributes:
                acdc_dict["a"] = node.attributes
            if node.edges:
                acdc_dict["e"] = node.edges
            acdcs_for_graph.append(acdc_dict)

            # Parse ACDC
            try:
                acdc = parse_acdc(acdc_dict)
                parsed_acdcs.append((acdc, acdc_dict, node.said))
            except Exception as e:
                log.warning(f"Failed to parse ACDC {node.said[:16]}: {e}")
                # Keep dict for fallback
                acdc_dict["type"] = _infer_credential_type(node.attributes)
                parsed_acdcs.append((None, acdc_dict, node.said))

        # Build issuer identity map from LE credentials with OOBI fallback
        issuer_identities = await build_issuer_identity_map_async(
            [acdc for acdc, _, _ in parsed_acdcs if acdc is not None],
            oobi_url=kid_url if kid_url else None,
            discover_missing=True,
        )

        # Second pass: build view-models with issuer identities
        for acdc, acdc_dict, said in parsed_acdcs:
            # Get revocation result if available
            revocation_result = revocation_cache.get(said)

            if acdc is not None:
                try:
                    vm = build_credential_card_vm(
                        acdc=acdc,
                        chain_result=None,  # No chain validation at fetch time
                        revocation_result=revocation_result,
                        available_saids=all_saids,
                        issuer_identities=issuer_identities,
                    )

                    # Sprint 24: Build schema_info for each credential with schema fetch
                    schema_start = time.time()
                    schema_info = await build_schema_info_with_fetch(acdc)
                    schema_latency = int((time.time() - schema_start) * 1000)
                    vm.schema_info = schema_info

                    # Sprint 24: Record schema evidence (registry check)
                    evidence_records.append(EvidenceFetchRecord(
                        source_type="SCHEMA",
                        url=f"schema:{acdc.schema_said[:16]}...",
                        status=(EvidenceStatus.SUCCESS if schema_info.has_governance
                               else EvidenceStatus.INDETERMINATE),
                        latency_ms=schema_latency,
                        cache_hit=False,
                        error=None if schema_info.has_governance else "Schema not in governance registry",
                    ))

                    # Sprint 24: Build per-credential validation_checks
                    checks = []

                    # Chain status check
                    chain_severity = ("success" if vm.chain_status == "VALID"
                                     else "error" if vm.chain_status == "INVALID"
                                     else "warning")
                    checks.append(ValidationCheckResult(
                        name="Chain",
                        status=vm.chain_status,
                        short_reason="Credential chain",
                        spec_ref="§5.1.1",
                        severity=chain_severity,
                    ))

                    # Schema status check
                    schema_severity = ("success" if schema_info.validation_status == "VALID"
                                      else "error" if schema_info.validation_status == "INVALID"
                                      else "warning")
                    checks.append(ValidationCheckResult(
                        name="Schema",
                        status=schema_info.validation_status,
                        short_reason=schema_info.registry_source,
                        spec_ref="§6.3",
                        severity=schema_severity,
                    ))

                    # Revocation status check
                    rev_state = vm.revocation.state
                    rev_severity = ("success" if rev_state == "ACTIVE"
                                   else "error" if rev_state == "REVOKED"
                                   else "warning")
                    rev_status = ("VALID" if rev_state == "ACTIVE"
                                 else "INVALID" if rev_state == "REVOKED"
                                 else "INDETERMINATE")
                    checks.append(ValidationCheckResult(
                        name="Revocation",
                        status=rev_status,
                        short_reason=rev_state,
                        spec_ref="§5.1.1-2.9",
                        severity=rev_severity,
                    ))

                    vm.validation_checks = checks

                    credential_vms.append(vm)
                except Exception as e:
                    log.warning(f"Failed to build view-model for {said[:16]}: {e}")
                    # Fall back to including raw dict (will use legacy template path)
                    credential_vms.append(acdc_dict)
            else:
                # Already have fallback dict with type
                credential_vms.append(acdc_dict)

        total_elapsed = time.time() - start_time
        total_elapsed_ms = int(total_elapsed * 1000)

        # Sprint 24: Build evidence timeline from records
        cache_hits = sum(1 for r in evidence_records if r.cache_hit)
        failed_count = sum(1 for r in evidence_records if r.status == EvidenceStatus.FAILED)
        evidence_timeline = EvidenceTimeline(
            records=evidence_records,
            total_fetch_time_ms=total_elapsed_ms,
            cache_hit_rate=cache_hits / max(len(evidence_records), 1),
            failed_count=failed_count,
        )

        # Sprint 24: Filter to only CredentialCardViewModel instances for validation summary
        # (legacy dict fallbacks don't have the required fields)
        vm_only = [vm for vm in credential_vms if hasattr(vm, "chain_status")]

        # Sprint 24: Build validation summary and error buckets
        validation_summary = build_validation_summary(vm_only) if vm_only else None
        error_buckets = build_error_buckets(vm_only) if vm_only else []

        # Sprint 24: Build top-level dossier view model
        dossier_vm = DossierViewModel(
            evd_url=evd_url,
            credentials=vm_only,
            validation_summary=validation_summary,
            evidence_timeline=evidence_timeline,
            error_buckets=error_buckets,
            total_time_ms=total_elapsed_ms,
        )

        return templates.TemplateResponse(
            "partials/dossier.html",
            {
                "request": request,
                "credential_vms": credential_vms,
                "dossier_vm": dossier_vm,  # Sprint 24: top-level view model
                "acdcs": acdcs_for_graph,  # Keep for graph building
                "evd_url": evd_url,  # For chain revocation polling
                "kid_url": kid_url,
                "dossier_stream": raw_text,
                "raw_data": raw_text[:5000] if len(raw_text) > 5000 else raw_text,
                "fetch_time": round(fetch_elapsed, 2),
                "total_time": round(total_elapsed, 2),
            },
        )
    except httpx.TimeoutException:
        return templates.TemplateResponse(
            "partials/dossier.html",
            {"request": request, "error": "Timeout fetching dossier", "evd_url": evd_url},
        )
    except Exception as e:
        log.error(f"Failed to fetch/parse dossier: {e}")
        return templates.TemplateResponse(
            "partials/dossier.html",
            {"request": request, "error": str(e), "evd_url": evd_url},
        )


def _infer_credential_type(attributes: Any) -> str:
    """Infer credential type from attributes for legacy template path."""
    if not isinstance(attributes, dict):
        return "UNKNOWN"
    if "tn" in attributes:
        return "TNAlloc"
    elif "legalName" in attributes or "LEI" in attributes:
        return "LE"
    elif "role" in attributes:
        return "APE"
    elif "vcard" in attributes:
        return "LE"
    return "UNKNOWN"


@app.post("/ui/check-revocation")
async def ui_check_revocation(
    request: Request,
    acdcs: str = Form(...),
    kid_url: str = Form(""),
    dossier_stream: str = Form(""),
):
    """Check revocation status for credentials and return HTML fragment.

    First tries to parse TEL events from the dossier stream (instant, no network).
    If no inline TEL data found, queries witnesses/registrars for live TEL state.

    Per KERI spec, revocation status is tracked in the Transaction Event Log (TEL)
    maintained by the issuer's registrars. The dossier may contain a snapshot of
    TEL state at creation time, but live queries are needed to detect revocations
    that occurred after the dossier was created.
    """
    from app.vvp.keri.tel_client import TELClient, CredentialStatus, get_tel_client

    try:
        # Unescape HTML entities (form value may have &quot; etc. from template escaping)
        unescaped = html.unescape(acdcs)
        log.debug(f"check-revocation received acdcs (first 200 chars): {acdcs[:200]}")
        log.debug(f"check-revocation unescaped (first 200 chars): {unescaped[:200]}")
        acdc_list = json.loads(unescaped)

        # Use singleton TEL client for live queries (with witness pool)
        client = get_tel_client()
        results = []

        # Unescape dossier stream and kid_url if provided
        dossier_data = html.unescape(dossier_stream) if dossier_stream else ""
        oobi_url = html.unescape(kid_url) if kid_url else None

        for acdc in acdc_list:
            said = acdc.get("d", "")
            registry_said = acdc.get("ri")

            # First try dossier-embedded TEL data (instant, no network)
            if dossier_data:
                try:
                    result = client.parse_dossier_tel(
                        dossier_data=dossier_data,
                        credential_said=said,
                        registry_said=registry_said,
                    )
                    if result.status != CredentialStatus.UNKNOWN:
                        results.append({
                            "said": said,
                            "status": result.status.value,
                            "source": f"{result.source} (dossier snapshot)",
                            "error": result.error,
                        })
                        continue  # Found status from dossier
                except Exception as e:
                    log.debug(f"Dossier TEL parse failed for {said[:20]}: {e}")

            # No inline TEL data - query witnesses/registrars for live status
            try:
                result = await client.check_revocation(
                    credential_said=said,
                    registry_said=registry_said,
                    oobi_url=oobi_url,
                )
                results.append({
                    "said": said,
                    "status": result.status.value,
                    "source": f"{result.source} (live query)" if result.source else "live query",
                    "error": result.error,
                })
            except Exception as e:
                log.warning(f"Live TEL query failed for {said[:20]}: {e}")
                results.append({
                    "said": said,
                    "status": "UNKNOWN",
                    "source": None,
                    "error": f"Live query failed: {e}",
                })

        return templates.TemplateResponse(
            "partials/revocation.html",
            {"request": request, "results": results},
        )
    except Exception as e:
        return templates.TemplateResponse(
            "partials/revocation.html",
            {"request": request, "error": str(e)},
        )


@app.post("/ui/credential-graph")
async def ui_credential_graph(
    request: Request,
    dossier_data: str = Form(...),
):
    """Build credential graph and return HTML fragment.

    Uses Sprint 21/22 view-model path for enhanced credential display.
    """
    from app.core.config import TRUSTED_ROOT_AIDS
    from app.vvp.acdc import (
        ACDC,
        CredentialStatus,
        build_credential_graph,
        credential_graph_to_dict,
        parse_acdc,
    )
    from app.vvp.ui.credential_viewmodel import build_credential_card_vm, build_issuer_identity_map_async

    try:
        # Unescape HTML entities (form value may have &quot; etc. from template escaping)
        unescaped = html.unescape(dossier_data)
        log.debug(f"credential-graph received dossier_data (first 200 chars): {dossier_data[:200]}")
        log.debug(f"credential-graph unescaped (first 200 chars): {unescaped[:200]}")
        acdc_list = json.loads(unescaped)
        dossier_acdcs: dict[str, ACDC] = {}

        for acdc_data in acdc_list:
            try:
                acdc = parse_acdc(acdc_data)
                dossier_acdcs[acdc.said] = acdc
            except Exception as e:
                log.warning(f"Failed to parse ACDC: {e}")
                continue

        if not dossier_acdcs:
            return templates.TemplateResponse(
                "partials/credential_graph.html",
                {"request": request, "error": "No valid ACDCs parsed"},
            )

        # Build issuer identity map from LE credentials (no OOBI URL available here)
        issuer_identities = await build_issuer_identity_map_async(
            list(dossier_acdcs.values()),
            oobi_url=None,  # No kid_url available at graph render time
            discover_missing=False,  # Skip OOBI discovery since no URL
        )

        graph = build_credential_graph(
            dossier_acdcs=dossier_acdcs,
            trusted_roots=set(TRUSTED_ROOT_AIDS),
            revocation_status=None,
        )

        graph_dict = credential_graph_to_dict(graph)

        # Build view-models for each credential (Sprint 21/22 enhanced display)
        all_saids = set(dossier_acdcs.keys())
        credential_vms: dict[str, Any] = {}
        for said, acdc in dossier_acdcs.items():
            try:
                vm = build_credential_card_vm(
                    acdc=acdc,
                    chain_result=None,
                    revocation_result=None,
                    available_saids=all_saids,
                    issuer_identities=issuer_identities,
                )
                credential_vms[said] = vm
            except Exception as e:
                log.warning(f"Failed to build view-model for graph node {said[:16]}: {e}")

        return templates.TemplateResponse(
            "partials/credential_graph.html",
            {"request": request, "graph": graph_dict, "credential_vms": credential_vms},
        )
    except Exception as e:
        log.error(f"Failed to build credential graph: {e}")
        return templates.TemplateResponse(
            "partials/credential_graph.html",
            {"request": request, "error": str(e)},
        )


# =============================================================================
# Sprint 21: Credential Card UI Endpoints
# =============================================================================


@app.post("/ui/revocation-badge")
async def ui_revocation_badge(
    request: Request,
    credential_said: str = Form(...),
    oobi_url: str = Form(""),
    dossier_stream: str = Form(""),
):
    """Return revocation badge HTML for a single credential.

    Used for lazy loading via HTMX. Returns a single <span class="badge">
    element for the credential's revocation status.

    Query order:
    1. Parse inline dossier TEL data (instant, no network)
    2. Query via OOBI URL if provided (network call)
    3. Return UNKNOWN if no TEL data available

    Args:
        credential_said: The SAID of the credential to check.
        oobi_url: Optional OOBI URL for witness discovery.
        dossier_stream: Optional inline dossier data with TEL events.
    """
    from app.vvp.keri.tel_client import TELClient, CredentialStatus
    from app.vvp.ui.credential_viewmodel import RevocationStatus
    from datetime import datetime, timezone

    try:
        client = TELClient(timeout=2.0)

        # 1. Try to parse TEL from inline dossier data (instant, no network)
        dossier_data = html.unescape(dossier_stream) if dossier_stream else ""

        if dossier_data:
            try:
                result = client.parse_dossier_tel(
                    dossier_data=dossier_data,
                    credential_said=credential_said,
                    registry_said=None,
                )
                if result.status != CredentialStatus.UNKNOWN:
                    revocation = RevocationStatus(
                        state=result.status.value,
                        checked_at=datetime.now(timezone.utc).isoformat(),
                        source=result.source or "dossier",
                        error=result.error,
                    )
                    return templates.TemplateResponse(
                        "partials/revocation_badge.html",
                        {"request": request, "revocation": revocation},
                    )
            except Exception as e:
                log.debug(f"Dossier TEL parse failed for {credential_said[:20]}: {e}")

        # 2. Try OOBI query if URL provided (network call)
        oobi = html.unescape(oobi_url) if oobi_url else ""
        if oobi:
            try:
                result = await client.check_revocation(
                    credential_said=credential_said,
                    registry_said=None,
                    oobi_url=oobi,
                )
                revocation = RevocationStatus(
                    state=result.status.value,
                    checked_at=datetime.now(timezone.utc).isoformat(),
                    source=result.source or "oobi",
                    error=result.error,
                )
                return templates.TemplateResponse(
                    "partials/revocation_badge.html",
                    {"request": request, "revocation": revocation},
                )
            except Exception as e:
                log.debug(f"OOBI revocation query failed for {credential_said[:20]}: {e}")

        # 3. No TEL data available - return UNKNOWN
        revocation = RevocationStatus(
            state="UNKNOWN",
            checked_at=datetime.now(timezone.utc).isoformat(),
            source="unknown",
            error="TEL data not available (no inline data or OOBI)",
        )
        return templates.TemplateResponse(
            "partials/revocation_badge.html",
            {"request": request, "revocation": revocation},
        )

    except Exception as e:
        log.error(f"Revocation badge error for {credential_said[:20]}: {e}")
        revocation = RevocationStatus(
            state="UNKNOWN",
            error=str(e),
        )
        return templates.TemplateResponse(
            "partials/revocation_badge.html",
            {"request": request, "revocation": revocation},
        )


@app.get("/ui/revocation-status")
async def ui_revocation_status(evd_url: str):
    """Poll for chain revocation status of a cached dossier.

    Returns JSON with the current state of the background chain revocation check.
    UI can poll this endpoint to update revocation badges when the check completes.

    Response states:
    - pending: Background check is running
    - complete: Check finished, results available
    - not_cached: Dossier not in cache
    - not_started: Dossier cached but no check started yet

    Returns:
        JSON with status and optional chain revocation results.
    """
    from app.vvp.keri.tel_client import CredentialStatus

    cache = get_dossier_cache()
    cached = await cache.get(evd_url)

    if cached is None:
        return {"status": "not_cached"}

    if cached.chain_revocation_in_progress:
        return {"status": "pending"}

    if cached.chain_revocation:
        result = cached.chain_revocation
        return {
            "status": "complete",
            "chain_status": result.chain_status.value,
            "revoked_credentials": result.revoked_credentials,
            "credential_results": {
                said: {
                    "status": r.status.value,
                    "source": r.source,
                    "error": r.error,
                }
                for said, r in result.credential_results.items()
            },
            "check_complete": result.check_complete,
            "errors": result.errors,
            "checked_at": result.checked_at,
        }

    return {"status": "not_started"}


@app.post("/ui/verify-result")
async def ui_verify_result(
    request: Request,
    passport_jwt: str = Form(...),
    evd_url: str = Form(""),
    call_id: str = Form(""),
    use_jwt_time: str = Form(""),
):
    """Perform full verification and return HTML with delegation chain info.

    Sprint 25: Combines /verify with UI view-model building to surface:
    - Complete claim tree
    - Delegation chain visualization (if delegated identifier)
    - Validation summary and error buckets
    - Per-credential validation checks

    Args:
        use_jwt_time: If "on" or "true", use the JWT's iat as reference time
            for expiry validation. This allows testing with old JWTs.

    The delegation chain is attached to credentials where the issuer AID
    matches the signer AID (from PASSporT kid).
    """
    from app.vvp.api_models import (
        VerifyRequest,
        CallContext,
    )
    from app.vvp.header import parse_vvp_identity, VVPIdentity
    from app.vvp.dossier.parser import parse_dossier
    from app.vvp.dossier import build_dag
    from app.vvp.acdc import parse_acdc
    from app.vvp.ui.credential_viewmodel import (
        build_credential_card_vm,
        build_issuer_identity_map_async,
        build_validation_summary,
        build_error_buckets,
        build_schema_info_with_fetch,
        build_delegation_chain_info,
        EvidenceStatus,
        EvidenceFetchRecord,
        EvidenceTimeline,
        DossierViewModel,
        ValidationCheckResult,
    )
    from app.vvp.keri.tel_client import TELClient, CredentialStatus

    start_time = time.time()
    evidence_records: list[EvidenceFetchRecord] = []

    try:
        # Sprint 25.1 fix: Parse PASSporT to extract kid for VVP-Identity header
        # Per §5.2, the VVP-Identity kid must match the PASSporT kid
        vvp_identity_header = None
        passport_kid = None
        passport_iat = None

        try:
            # Parse JWT to extract kid from header
            jwt_parts = passport_jwt.split(".")
            if len(jwt_parts) >= 2:
                import base64
                # Decode header
                header_padded = jwt_parts[0] + "=" * (-len(jwt_parts[0]) % 4)
                header_bytes = base64.urlsafe_b64decode(header_padded)
                header_dict = json.loads(header_bytes)
                passport_kid = header_dict.get("kid")

                # Decode payload to get iat
                payload_padded = jwt_parts[1] + "=" * (-len(jwt_parts[1]) % 4)
                payload_bytes = base64.urlsafe_b64decode(payload_padded)
                payload_dict = json.loads(payload_bytes)
                passport_iat = payload_dict.get("iat")
        except Exception as e:
            log.warning(f"Failed to parse PASSporT for VVP-Identity: {e}")

        # Build VVP-Identity header using PASSporT kid (not evd_url)
        # VVP-Identity header is a base64url-encoded JSON object per §4.1A
        if passport_kid and evd_url and passport_iat:
            import base64
            identity_obj = {
                "kid": passport_kid,
                "ppt": "vvp",
                "evd": evd_url,
                "iat": passport_iat,
            }
            identity_json = json.dumps(identity_obj, separators=(',', ':'))
            # Base64url encode without padding
            vvp_identity_header = base64.urlsafe_b64encode(
                identity_json.encode('utf-8')
            ).decode('utf-8').rstrip('=')

        # Build request
        verify_req = VerifyRequest(
            passport_jwt=passport_jwt,
            context=CallContext(
                call_id=call_id or "ui-verify",
                received_at=datetime.now(timezone.utc).isoformat(),
            )
        )

        # Run verification
        # If use_jwt_time is set, use the JWT's iat as reference time
        # This allows testing with old JWTs that would otherwise be expired
        reference_time = None
        if use_jwt_time in ("on", "true", "1") and passport_iat:
            reference_time = passport_iat

        verify_start = time.time()
        req_id, verify_response = await verify_vvp(verify_req, vvp_identity_header, reference_time=reference_time)
        verify_latency = int((time.time() - verify_start) * 1000)

        evidence_records.append(EvidenceFetchRecord(
            source_type="VERIFY",
            url="/verify",
            status=EvidenceStatus.SUCCESS if verify_response.overall_status.value != "INVALID" else EvidenceStatus.FAILED,
            latency_ms=verify_latency,
            cache_hit=False,
        ))

        # Parse dossier for credential display (if evd_url provided)
        credential_vms = []
        dossier_vm = None

        if evd_url:
            try:
                # Fetch dossier
                fetch_start = time.time()
                raw_bytes = await cached_fetch_dossier(evd_url)
                fetch_latency = int((time.time() - fetch_start) * 1000)
                raw_text = raw_bytes.decode("utf-8")
                nodes, signatures = parse_dossier(raw_bytes)

                evidence_records.append(EvidenceFetchRecord(
                    source_type="DOSSIER",
                    url=evd_url,
                    status=EvidenceStatus.SUCCESS,
                    latency_ms=fetch_latency,
                    cache_hit=False,
                ))

                # Collect all SAIDs for edge availability checking
                all_saids = {node.said for node in nodes}

                # Parse TEL data from dossier for revocation status
                tel_client = TELClient(timeout=2.0)
                revocation_cache: dict[str, dict] = {}
                for node in nodes:
                    try:
                        result = tel_client.parse_dossier_tel(
                            dossier_data=raw_text,
                            credential_said=node.said,
                            registry_said=node.raw.get("ri") if node.raw else None,
                        )
                        if result.status != CredentialStatus.UNKNOWN:
                            revocation_cache[node.said] = {
                                "status": result.status.value,
                                "checked_at": datetime.now(timezone.utc).isoformat(),
                                "source": result.source or "dossier",
                                "error": result.error,
                            }
                    except Exception:
                        pass

                # Parse all ACDCs
                parsed_acdcs = []
                for node in nodes:
                    acdc_dict = node.raw.copy() if node.raw else {}
                    acdc_dict["d"] = node.said
                    acdc_dict["i"] = node.issuer
                    acdc_dict["s"] = node.schema
                    if node.attributes:
                        acdc_dict["a"] = node.attributes
                    if node.edges:
                        acdc_dict["e"] = node.edges

                    try:
                        acdc = parse_acdc(acdc_dict)
                        parsed_acdcs.append((acdc, acdc_dict, node.said))
                    except Exception as e:
                        log.warning(f"Failed to parse ACDC {node.said[:16]}: {e}")

                # Build issuer identity map
                issuer_identities = await build_issuer_identity_map_async(
                    [acdc for acdc, _, _ in parsed_acdcs if acdc is not None],
                    oobi_url=evd_url if evd_url else None,
                    discover_missing=True,
                )

                # Build delegation info from verify response
                delegation_info = build_delegation_chain_info(
                    verify_response.delegation_chain,
                    issuer_identities,
                )

                # Resolve key states for display (Sprint 26: KeyStateInfo)
                # Resolve ALL issuer AIDs using witness pool to construct OOBI URLs
                key_states: dict[str, Any] = {}
                from app.vvp.keri import resolve_key_state, get_witness_pool

                # Collect unique issuer AIDs from all credentials
                issuer_aids = {acdc.issuer_aid for acdc, _, _ in parsed_acdcs if acdc is not None}
                log.debug(f"Resolving key states for {len(issuer_aids)} issuer AIDs...")

                # Get witness URLs from the pool (triggers GLEIF discovery)
                pool = get_witness_pool()
                witnesses = await pool.get_all_witnesses()
                witness_urls = [w.url for w in witnesses]

                for aid in issuer_aids:
                    if aid in key_states:
                        continue
                    # Try each witness to construct an OOBI URL
                    for witness_url in witness_urls:
                        try:
                            oobi_url = f"{witness_url}/oobi/{aid}"
                            key_state = await resolve_key_state(
                                kid=aid,
                                oobi_url=oobi_url,
                                reference_time=None,  # Use current time for display
                                _allow_test_mode=False,
                            )
                            key_states[aid] = key_state
                            log.debug(f"Resolved key state for issuer {aid[:16]}... via {witness_url}")
                            break  # Success, move to next AID
                        except Exception as e:
                            log.debug(f"Could not resolve {aid[:16]}... via {witness_url}: {e}")
                            continue  # Try next witness

                # Build view-models for each credential
                for acdc, acdc_dict, said in parsed_acdcs:
                    if acdc is None:
                        continue

                    revocation_result = revocation_cache.get(said)

                    try:
                        vm = build_credential_card_vm(
                            acdc=acdc,
                            chain_result=None,
                            revocation_result=revocation_result,
                            available_saids=all_saids,
                            issuer_identities=issuer_identities,
                            key_states=key_states,
                        )

                        # Build schema info with fetch
                        schema_info = await build_schema_info_with_fetch(acdc)
                        vm.schema_info = schema_info

                        # Sprint 25: Attach delegation_info to credentials where issuer == signer_aid
                        if delegation_info and verify_response.signer_aid:
                            if vm.issuer.aid == verify_response.signer_aid:
                                vm.delegation_info = delegation_info

                        # Build per-credential validation checks
                        checks = []
                        chain_severity = ("success" if vm.chain_status == "VALID"
                                         else "error" if vm.chain_status == "INVALID"
                                         else "warning")
                        checks.append(ValidationCheckResult(
                            name="Chain",
                            status=vm.chain_status,
                            short_reason="Credential chain",
                            spec_ref="§5.1.1",
                            severity=chain_severity,
                        ))

                        schema_severity = ("success" if schema_info.validation_status == "VALID"
                                          else "error" if schema_info.validation_status == "INVALID"
                                          else "warning")
                        checks.append(ValidationCheckResult(
                            name="Schema",
                            status=schema_info.validation_status,
                            short_reason=schema_info.registry_source,
                            spec_ref="§6.3",
                            severity=schema_severity,
                        ))

                        rev_state = vm.revocation.state
                        rev_severity = ("success" if rev_state == "ACTIVE"
                                       else "error" if rev_state == "REVOKED"
                                       else "warning")
                        rev_status = ("VALID" if rev_state == "ACTIVE"
                                     else "INVALID" if rev_state == "REVOKED"
                                     else "INDETERMINATE")
                        checks.append(ValidationCheckResult(
                            name="Revocation",
                            status=rev_status,
                            short_reason=rev_state,
                            spec_ref="§5.1.1-2.9",
                            severity=rev_severity,
                        ))

                        vm.validation_checks = checks
                        credential_vms.append(vm)

                    except Exception as e:
                        log.warning(f"Failed to build view-model for {said[:16]}: {e}")

                total_elapsed_ms = int((time.time() - start_time) * 1000)

                # Build evidence timeline
                cache_hits = sum(1 for r in evidence_records if r.cache_hit)
                failed_count = sum(1 for r in evidence_records if r.status == EvidenceStatus.FAILED)
                evidence_timeline = EvidenceTimeline(
                    records=evidence_records,
                    total_fetch_time_ms=total_elapsed_ms,
                    cache_hit_rate=cache_hits / max(len(evidence_records), 1),
                    failed_count=failed_count,
                )

                # Build validation summary and error buckets
                validation_summary = build_validation_summary(credential_vms) if credential_vms else None
                error_buckets = build_error_buckets(credential_vms) if credential_vms else []

                # Build dossier view model
                dossier_vm = DossierViewModel(
                    evd_url=evd_url,
                    credentials=credential_vms,
                    validation_summary=validation_summary,
                    evidence_timeline=evidence_timeline,
                    error_buckets=error_buckets,
                    total_time_ms=total_elapsed_ms,
                )

            except Exception as e:
                log.error(f"Failed to fetch/parse dossier for verify-result: {e}")
                evidence_records.append(EvidenceFetchRecord(
                    source_type="DOSSIER",
                    url=evd_url,
                    status=EvidenceStatus.FAILED,
                    error=str(e),
                ))

        # Convert verify_response to dict for Jinja2 serialization
        # (ClaimNode objects are not JSON serializable by default)
        verify_response_dict = verify_response.model_dump(mode='json')

        return templates.TemplateResponse(
            "partials/verify_result.html",
            {
                "request": request,
                "verify_response": verify_response_dict,
                "credential_vms": credential_vms,
                "dossier_vm": dossier_vm,
                "delegation_info": build_delegation_chain_info(
                    verify_response.delegation_chain,
                    issuer_identities if 'issuer_identities' in dir() else None,
                ) if verify_response.delegation_chain else None,
            },
        )

    except Exception as e:
        log.error(f"Verification failed: {e}")
        return templates.TemplateResponse(
            "partials/verify_result.html",
            {
                "request": request,
                "error": str(e),
            },
        )


@app.get("/ui/credential/{said}")
async def ui_credential_card(
    request: Request,
    said: str,
):
    """Return credential card HTML for chain expansion.

    Used for HTMX chain expansion - fetches a single credential from
    the session cache and returns its card HTML.

    Note: This endpoint requires credentials to be stored in session
    during the initial verification flow. If the credential is not
    found, returns a 404 error fragment.
    """
    from app.vvp.ui.credential_viewmodel import (
        CredentialCardViewModel,
        build_credential_card_vm,
        RevocationStatus,
        IssuerInfo,
        AttributeDisplay,
        EdgeLink,
        VariantLimitations,
        RawACDCData,
    )

    # For now, return a placeholder since we don't have session storage
    # In a full implementation, this would fetch from session/cache
    # TODO: Implement session-based credential storage for chain expansion

    # Return a "not found" card for now
    return templates.TemplateResponse(
        "partials/toast.html",
        {
            "request": request,
            "message": f"Credential {said[:16]}... not in session",
            "type": "warning",
        },
    )


# =============================================================================
# Simple Verification Page (Single-step workflow)
# =============================================================================


@app.get("/simple")
def simple_redirect():
    """Redirect /simple to /verify/simple for backwards compatibility."""
    return RedirectResponse(url="/verify/simple", status_code=301)


@app.post("/ui/browse-said")
async def ui_browse_said(
    request: Request,
    evd_url: str = Form(...),
):
    """Browse dossier by SAID - shows SVG graph like simple-verify but without JWT.

    This endpoint is used when the user enters a dossier SAID directly
    (without a PASSporT JWT). It fetches the dossier, builds the credential
    graph, and returns the same SVG visualization as simple-verify.
    """
    from app.vvp.dossier.parser import parse_dossier
    from app.vvp.dossier.validator import build_dag
    from app.vvp.acdc import (
        parse_acdc,
        credential_graph_to_dict,
        ACDC,
    )
    from app.vvp.acdc.graph import build_credential_graph_with_resolution, build_credential_graph, build_all_credential_chains
    from app.vvp.ui.credential_viewmodel import (
        build_credential_card_vm,
        build_issuer_identity_map_async,
        build_schema_info_with_fetch,
        ValidationCheckResult,
    )
    from app.vvp.keri.tel_client import TELClient, CredentialStatus
    from app.vvp.keri import get_credential_resolver
    from app.core.config import TRUSTED_ROOT_AIDS

    try:
        # Check cache first
        dossier_cache = get_dossier_cache()
        cached = await dossier_cache.get(evd_url)

        if cached:
            # Cache hit - use cached data
            raw_bytes = cached.raw_content
            raw_text = raw_bytes.decode("utf-8")
            nodes = list(cached.dag.nodes.values())
            log.info(f"browse-said cache hit: {evd_url[:50]}...")
        else:
            # Cache miss - fetch and cache with auto-revocation check
            raw_bytes = await cached_fetch_dossier(evd_url)
            raw_text = raw_bytes.decode("utf-8")
            nodes, signatures = parse_dossier(raw_bytes)

            # Build DAG and chain info
            dag = build_dag(nodes)
            contained_saids = set(dag.nodes.keys())

            # Build chain_info for background revocation check
            dossier_acdcs_for_chain: Dict[str, ACDC] = {}
            for node in nodes:
                try:
                    acdc_dict = node.raw.copy() if node.raw else {}
                    acdc_dict["d"] = node.said
                    acdc_dict["i"] = node.issuer
                    acdc_dict["s"] = node.schema
                    if node.attributes:
                        acdc_dict["a"] = node.attributes
                    if node.edges:
                        acdc_dict["e"] = node.edges
                    acdc = parse_acdc(acdc_dict)
                    dossier_acdcs_for_chain[acdc.said] = acdc
                except Exception as e:
                    log.debug(f"Skipping credential {node.said[:16]} for chain check: {e}")

            chain_info = None
            if dossier_acdcs_for_chain:
                graph_for_chain = build_credential_graph(
                    dossier_acdcs=dossier_acdcs_for_chain,
                    trusted_roots=set(TRUSTED_ROOT_AIDS),
                )
                chain_info = build_all_credential_chains(graph_for_chain)

            cached_dossier = CachedDossier(
                dag=dag,
                raw_content=raw_bytes,
                fetch_timestamp=time.time(),
                content_type="application/json+cesr",
                contained_saids=contained_saids,
            )

            # Cache with auto-start background revocation check
            await dossier_cache.put(
                evd_url,
                cached_dossier,
                chain_info=chain_info,
                dossier_data=raw_text,
                oobi_url=evd_url,
            )
            cached = cached_dossier
            log.info(f"browse-said cached: {evd_url[:50]}... (saids={len(contained_saids)})")

        # Read revocation status from cache if available
        revocation_cache: dict[str, dict] = {}
        if cached and cached.chain_revocation:
            for said, cred_result in cached.chain_revocation.credential_results.items():
                revocation_cache[said] = {
                    "status": cred_result.status.value,
                    "checked_at": cached.chain_revocation.checked_at,
                    "source": cred_result.source or "cached",
                    "error": cred_result.error,
                }
        elif cached and cached.chain_revocation_in_progress:
            # Background check still running - show as pending
            for said in cached.contained_saids:
                revocation_cache[said] = {
                    "status": "PENDING",
                    "checked_at": None,
                    "source": "background_check",
                    "error": None,
                }

        # Collect all SAIDs for edge availability checking
        all_saids = {node.said for node in nodes}

        # Parse all ACDCs
        dossier_acdcs = {}
        parsed_acdcs = []
        for node in nodes:
            acdc_dict = node.raw.copy() if node.raw else {}
            acdc_dict["d"] = node.said
            acdc_dict["i"] = node.issuer
            acdc_dict["s"] = node.schema
            if node.attributes:
                acdc_dict["a"] = node.attributes
            if node.edges:
                acdc_dict["e"] = node.edges

            try:
                acdc = parse_acdc(acdc_dict)
                dossier_acdcs[acdc.said] = acdc
                parsed_acdcs.append((acdc, acdc_dict, node.said))
            except Exception as e:
                log.warning(f"Failed to parse ACDC {node.said[:16]}: {e}")

        # Build identity map first (sync) - for graph display names
        from app.vvp.identity import build_issuer_identity_map
        sync_identities = build_issuer_identity_map(
            [acdc for acdc, _, _ in parsed_acdcs if acdc is not None]
        )

        # Build credential graph with deep vLEI chain resolution
        credential_resolver = get_credential_resolver()
        graph = await build_credential_graph_with_resolution(
            dossier_acdcs=dossier_acdcs,
            trusted_roots=set(TRUSTED_ROOT_AIDS),
            revocation_status=None,
            issuer_identities=sync_identities,
            credential_resolver=credential_resolver,
            resolve_chain=True,
        )
        graph_dict = credential_graph_to_dict(graph)

        # Build view-models for all credentials (async adds OOBI discovery)
        issuer_identities = await build_issuer_identity_map_async(
            [acdc for acdc, _, _ in parsed_acdcs if acdc is not None],
            oobi_url=evd_url,
            discover_missing=True,
        )

        # Resolve key states for display
        key_states: dict[str, Any] = {}
        from app.vvp.keri import resolve_key_state, get_witness_pool

        issuer_aids = {acdc.issuer_aid for acdc, _, _ in parsed_acdcs if acdc is not None}
        log.debug(f"Resolving key states for {len(issuer_aids)} issuer AIDs...")

        pool = get_witness_pool()
        witnesses = await pool.get_all_witnesses()
        witness_urls = [w.url for w in witnesses]

        for aid in issuer_aids:
            if aid in key_states:
                continue
            for witness_url in witness_urls:
                try:
                    oobi_url_try = f"{witness_url}/oobi/{aid}"
                    key_state = await resolve_key_state(
                        kid=aid,
                        oobi_url=oobi_url_try,
                        reference_time=None,
                        _allow_test_mode=False,
                    )
                    key_states[aid] = key_state
                    log.debug(f"Resolved key state for issuer {aid[:16]}... via {witness_url}")
                    break
                except Exception as e:
                    log.debug(f"Could not resolve {aid[:16]}... via {witness_url}: {e}")
                    continue

        credential_vms: dict[str, Any] = {}
        for acdc, acdc_dict, said in parsed_acdcs:
            if acdc is None:
                continue

            revocation_result = revocation_cache.get(said)

            try:
                vm = build_credential_card_vm(
                    acdc=acdc,
                    chain_result=None,
                    revocation_result=revocation_result,
                    available_saids=all_saids,
                    issuer_identities=issuer_identities,
                    key_states=key_states,
                )

                schema_info = await build_schema_info_with_fetch(acdc)
                vm.schema_info = schema_info

                # Build per-credential validation checks
                checks = []
                chain_severity = ("success" if vm.chain_status == "VALID"
                                 else "error" if vm.chain_status == "INVALID"
                                 else "warning")
                checks.append(ValidationCheckResult(
                    name="Chain",
                    status=vm.chain_status,
                    short_reason="Credential chain",
                    spec_ref="§5.1.1",
                    severity=chain_severity,
                ))

                schema_severity = ("success" if schema_info.validation_status == "VALID"
                                  else "error" if schema_info.validation_status == "INVALID"
                                  else "warning")
                checks.append(ValidationCheckResult(
                    name="Schema",
                    status=schema_info.validation_status,
                    short_reason=schema_info.registry_source,
                    spec_ref="§6.3",
                    severity=schema_severity,
                ))

                rev_state = vm.revocation.state
                rev_severity = ("success" if rev_state == "ACTIVE"
                               else "error" if rev_state == "REVOKED"
                               else "warning")
                rev_status = ("VALID" if rev_state == "ACTIVE"
                             else "INVALID" if rev_state == "REVOKED"
                             else "INDETERMINATE")
                checks.append(ValidationCheckResult(
                    name="Revocation",
                    status=rev_status,
                    short_reason=rev_state,
                    spec_ref="§5.1.1-2.9",
                    severity=rev_severity,
                ))

                vm.validation_checks = checks
                credential_vms[said] = vm

            except Exception as e:
                log.warning(f"Failed to build view-model for {said[:16]}: {e}")

        return templates.TemplateResponse(
            "partials/simple_result.html",
            {
                "request": request,
                "verify_response": None,  # No JWT verification
                "graph": graph_dict,
                "credential_vms": credential_vms,
            },
        )

    except httpx.TimeoutException:
        return templates.TemplateResponse(
            "partials/simple_result.html",
            {"request": request, "error": f"Timeout fetching dossier from {evd_url}"},
        )
    except Exception as e:
        log.error(f"Browse SAID failed: {e}")
        return templates.TemplateResponse(
            "partials/simple_result.html",
            {"request": request, "error": str(e)},
        )


@app.post("/ui/jwt-explore")
async def ui_jwt_explore(
    request: Request,
    jwt: str = Form(...),
    use_jwt_time: str = Form(""),
):
    """Parse JWT and explore credential chain - returns SVG graph with click-to-select.

    Similar to simple-verify but focused on exploration rather than full verification.
    Extracts evd URL from JWT, fetches dossier, and builds credential graph.
    """
    from app.vvp.dossier.parser import parse_dossier
    from app.vvp.acdc import (
        parse_acdc,
        credential_graph_to_dict,
    )
    from app.vvp.acdc.graph import build_credential_graph_with_resolution
    from app.vvp.ui.credential_viewmodel import (
        build_credential_card_vm,
        build_issuer_identity_map_async,
        build_schema_info_with_fetch,
        ValidationCheckResult,
    )
    from app.vvp.keri.tel_client import CredentialStatus
    from app.vvp.keri import get_credential_resolver
    from app.core.config import TRUSTED_ROOT_AIDS

    try:
        # Step 1: Parse JWT to extract evd URL
        jwt = jwt.strip()
        if ";" in jwt:
            jwt = jwt.split(";")[0]

        try:
            jwt_parts = jwt.split(".")
            if len(jwt_parts) < 2:
                raise ValueError("Invalid JWT format")

            payload_padded = jwt_parts[1] + "=" * (-len(jwt_parts[1]) % 4)
            payload_bytes = base64.urlsafe_b64decode(payload_padded)
            payload_dict = json.loads(payload_bytes)
            evd_url = payload_dict.get("evd")

            if not evd_url:
                return templates.TemplateResponse(
                    "partials/simple_result.html",
                    {"request": request, "error": "JWT does not contain an 'evd' (evidence) URL"},
                )
        except Exception as e:
            return templates.TemplateResponse(
                "partials/simple_result.html",
                {"request": request, "error": f"Failed to parse JWT: {e}"},
            )

        # Step 2: Check cache first, then fetch if needed
        from app.vvp.dossier.validator import build_dag
        from app.vvp.acdc import ACDC
        from app.vvp.acdc.graph import build_credential_graph, build_all_credential_chains

        dossier_cache = get_dossier_cache()
        cached = await dossier_cache.get(evd_url)

        if cached:
            # Cache hit
            raw_bytes = cached.raw_content
            raw_text = raw_bytes.decode("utf-8")
            nodes = list(cached.dag.nodes.values())
            log.info(f"jwt-explore cache hit: {evd_url[:50]}...")
        else:
            # Cache miss - fetch and cache with auto-revocation
            raw_bytes = await cached_fetch_dossier(evd_url)
            raw_text = raw_bytes.decode("utf-8")
            nodes, signatures = parse_dossier(raw_bytes)

            dag = build_dag(nodes)
            contained_saids = set(dag.nodes.keys())

            # Build chain_info for background revocation check
            dossier_acdcs_for_chain: Dict[str, ACDC] = {}
            for node in nodes:
                try:
                    acdc_dict = node.raw.copy() if node.raw else {}
                    acdc_dict["d"] = node.said
                    acdc_dict["i"] = node.issuer
                    acdc_dict["s"] = node.schema
                    if node.attributes:
                        acdc_dict["a"] = node.attributes
                    if node.edges:
                        acdc_dict["e"] = node.edges
                    acdc = parse_acdc(acdc_dict)
                    dossier_acdcs_for_chain[acdc.said] = acdc
                except Exception as e:
                    log.debug(f"Skipping credential {node.said[:16]} for chain check: {e}")

            chain_info = None
            if dossier_acdcs_for_chain:
                graph_for_chain = build_credential_graph(
                    dossier_acdcs=dossier_acdcs_for_chain,
                    trusted_roots=set(TRUSTED_ROOT_AIDS),
                )
                chain_info = build_all_credential_chains(graph_for_chain)

            cached_dossier = CachedDossier(
                dag=dag,
                raw_content=raw_bytes,
                fetch_timestamp=time.time(),
                content_type="application/json+cesr",
                contained_saids=contained_saids,
            )

            await dossier_cache.put(
                evd_url,
                cached_dossier,
                chain_info=chain_info,
                dossier_data=raw_text,
                oobi_url=evd_url,
            )
            cached = cached_dossier
            log.info(f"jwt-explore cached: {evd_url[:50]}... (saids={len(contained_saids)})")

        # Read revocation status from cache if available
        revocation_cache: dict[str, dict] = {}
        if cached and cached.chain_revocation:
            for said, cred_result in cached.chain_revocation.credential_results.items():
                revocation_cache[said] = {
                    "status": cred_result.status.value,
                    "checked_at": cached.chain_revocation.checked_at,
                    "source": cred_result.source or "cached",
                    "error": cred_result.error,
                }
        elif cached and cached.chain_revocation_in_progress:
            # Background check still running - show as pending
            for said in cached.contained_saids:
                revocation_cache[said] = {
                    "status": "PENDING",
                    "checked_at": None,
                    "source": "background_check",
                    "error": None,
                }

        all_saids = {node.said for node in nodes}

        # Parse ACDCs
        dossier_acdcs = {}
        parsed_acdcs = []
        for node in nodes:
            acdc_dict = node.raw.copy() if node.raw else {}
            acdc_dict["d"] = node.said
            acdc_dict["i"] = node.issuer
            acdc_dict["s"] = node.schema
            if node.attributes:
                acdc_dict["a"] = node.attributes
            if node.edges:
                acdc_dict["e"] = node.edges

            try:
                acdc = parse_acdc(acdc_dict)
                dossier_acdcs[acdc.said] = acdc
                parsed_acdcs.append((acdc, acdc_dict, node.said))
            except Exception as e:
                log.warning(f"Failed to parse ACDC {node.said[:16]}: {e}")

        # Build identity map
        from app.vvp.identity import build_issuer_identity_map
        sync_identities = build_issuer_identity_map(
            [acdc for acdc, _, _ in parsed_acdcs if acdc is not None]
        )

        # Build credential graph with deep vLEI chain resolution
        credential_resolver = get_credential_resolver()
        graph = await build_credential_graph_with_resolution(
            dossier_acdcs=dossier_acdcs,
            trusted_roots=set(TRUSTED_ROOT_AIDS),
            revocation_status=None,
            issuer_identities=sync_identities,
            credential_resolver=credential_resolver,
            resolve_chain=True,
        )
        graph_dict = credential_graph_to_dict(graph)

        # Build view-models for credentials
        issuer_identities = await build_issuer_identity_map_async(
            [acdc for acdc, _, _ in parsed_acdcs if acdc is not None],
            oobi_url=evd_url,
            discover_missing=True,
        )

        # Resolve key states
        key_states: dict[str, Any] = {}
        from app.vvp.keri import resolve_key_state, get_witness_pool

        issuer_aids = {acdc.issuer_aid for acdc, _, _ in parsed_acdcs if acdc is not None}
        pool = get_witness_pool()
        witnesses = await pool.get_all_witnesses()
        witness_urls = [w.url for w in witnesses]

        for aid in issuer_aids:
            if aid in key_states:
                continue
            for witness_url in witness_urls:
                try:
                    oobi_url_try = f"{witness_url}/oobi/{aid}"
                    key_state = await resolve_key_state(
                        kid=aid,
                        oobi_url=oobi_url_try,
                        reference_time=None,
                        _allow_test_mode=False,
                    )
                    key_states[aid] = key_state
                    break
                except Exception:
                    continue

        credential_vms: dict[str, Any] = {}
        for acdc, acdc_dict, said in parsed_acdcs:
            if acdc is None:
                continue

            revocation_result = revocation_cache.get(said)

            try:
                vm = build_credential_card_vm(
                    acdc=acdc,
                    chain_result=None,
                    revocation_result=revocation_result,
                    available_saids=all_saids,
                    issuer_identities=issuer_identities,
                    key_states=key_states,
                )

                schema_info = await build_schema_info_with_fetch(acdc)
                vm.schema_info = schema_info

                # Build per-credential validation checks
                checks = []
                chain_severity = ("success" if vm.chain_status == "VALID"
                                 else "error" if vm.chain_status == "INVALID"
                                 else "warning")
                checks.append(ValidationCheckResult(
                    name="Chain",
                    status=vm.chain_status,
                    short_reason="Credential chain",
                    spec_ref="§5.1.1",
                    severity=chain_severity,
                ))

                schema_severity = ("success" if schema_info.validation_status == "VALID"
                                  else "error" if schema_info.validation_status == "INVALID"
                                  else "warning")
                checks.append(ValidationCheckResult(
                    name="Schema",
                    status=schema_info.validation_status,
                    short_reason=schema_info.registry_source,
                    spec_ref="§6.3",
                    severity=schema_severity,
                ))

                rev_state = vm.revocation.state
                rev_severity = ("success" if rev_state == "ACTIVE"
                               else "error" if rev_state == "REVOKED"
                               else "warning")
                rev_status = ("VALID" if rev_state == "ACTIVE"
                             else "INVALID" if rev_state == "REVOKED"
                             else "INDETERMINATE")
                checks.append(ValidationCheckResult(
                    name="Revocation",
                    status=rev_status,
                    short_reason=rev_state,
                    spec_ref="§5.1.1-2.9",
                    severity=rev_severity,
                ))

                vm.validation_checks = checks
                credential_vms[said] = vm

            except Exception as e:
                log.warning(f"Failed to build view-model for {said[:16]}: {e}")

        return templates.TemplateResponse(
            "partials/simple_result.html",
            {
                "request": request,
                "verify_response": None,
                "graph": graph_dict,
                "credential_vms": credential_vms,
            },
        )

    except httpx.TimeoutException:
        return templates.TemplateResponse(
            "partials/simple_result.html",
            {"request": request, "error": f"Timeout fetching dossier"},
        )
    except Exception as e:
        log.error(f"JWT explore failed: {e}")
        return templates.TemplateResponse(
            "partials/simple_result.html",
            {"request": request, "error": str(e)},
        )


@app.post("/ui/sip-explore")
async def ui_sip_explore(
    request: Request,
    sip_invite: str = Form(...),
    use_jwt_time: str = Form(""),
):
    """Extract JWT from SIP INVITE and explore credential chain.

    Parses the SIP INVITE to extract the Identity header (JWT),
    then delegates to jwt-explore logic.
    """
    try:
        # Parse SIP INVITE to extract Identity header
        result = _parse_sip_invite_logic(sip_invite)
        identity_jwt = result.get("identity_header")

        if not identity_jwt:
            return templates.TemplateResponse(
                "partials/simple_result.html",
                {"request": request, "error": "No Identity header found in SIP INVITE"},
            )

        # Delegate to jwt-explore logic
        return await ui_jwt_explore(request, identity_jwt, use_jwt_time)

    except Exception as e:
        log.error(f"SIP explore failed: {e}")
        return templates.TemplateResponse(
            "partials/simple_result.html",
            {"request": request, "error": str(e)},
        )


@app.post("/ui/simple-verify")
async def ui_simple_verify(
    request: Request,
    jwt: str = Form(...),
    use_jwt_time: str = Form(""),
):
    """One-step verification returning graph with click-to-select credential cards.

    Combines JWT parsing, dossier fetching, full verification, and graph building
    into a single operation. Returns a combined result page with:
    - Verification status banner
    - SVG credential graph (click to select)
    - Full credential cards for each credential
    """
    from app.vvp.api_models import (
        VerifyRequest,
        CallContext,
    )
    from app.vvp.dossier.parser import parse_dossier
    from app.vvp.acdc import (
        parse_acdc,
        credential_graph_to_dict,
    )
    from app.vvp.acdc.graph import build_credential_graph_with_resolution
    from app.vvp.ui.credential_viewmodel import (
        build_credential_card_vm,
        build_issuer_identity_map_async,
        build_schema_info_with_fetch,
        build_delegation_chain_info,
        ValidationCheckResult,
    )
    from app.vvp.keri.tel_client import TELClient, CredentialStatus
    from app.vvp.keri import get_credential_resolver
    from app.core.config import TRUSTED_ROOT_AIDS

    try:
        # Step 1: Parse JWT to extract evd URL, kid, and iat
        jwt = jwt.strip()
        if ";" in jwt:
            jwt = jwt.split(";")[0]

        try:
            jwt_parts = jwt.split(".")
            if len(jwt_parts) < 2:
                raise ValueError("Invalid JWT format")

            header_padded = jwt_parts[0] + "=" * (-len(jwt_parts[0]) % 4)
            header_bytes = base64.urlsafe_b64decode(header_padded)
            header_dict = json.loads(header_bytes)
            passport_kid = header_dict.get("kid")

            payload_padded = jwt_parts[1] + "=" * (-len(jwt_parts[1]) % 4)
            payload_bytes = base64.urlsafe_b64decode(payload_padded)
            payload_dict = json.loads(payload_bytes)
            passport_iat = payload_dict.get("iat")
            evd_url = payload_dict.get("evd")

            if not evd_url:
                return templates.TemplateResponse(
                    "partials/simple_result.html",
                    {"request": request, "error": "JWT does not contain an 'evd' (evidence) URL"},
                )
        except Exception as e:
            return templates.TemplateResponse(
                "partials/simple_result.html",
                {"request": request, "error": f"Failed to parse JWT: {e}"},
            )

        # Step 2: Build VVP-Identity header from JWT
        vvp_identity_header = None
        if passport_kid and evd_url and passport_iat:
            identity_obj = {
                "kid": passport_kid,
                "ppt": "vvp",
                "evd": evd_url,
                "iat": passport_iat,
            }
            identity_json = json.dumps(identity_obj, separators=(',', ':'))
            vvp_identity_header = base64.urlsafe_b64encode(
                identity_json.encode('utf-8')
            ).decode('utf-8').rstrip('=')

        # Step 3: Run verification
        verify_req = VerifyRequest(
            passport_jwt=jwt,
            context=CallContext(
                call_id="simple-verify",
                received_at=datetime.now(timezone.utc).isoformat(),
            )
        )

        reference_time = None
        if use_jwt_time in ("on", "true", "1") and passport_iat:
            reference_time = passport_iat

        req_id, verify_response = await verify_vvp(verify_req, vvp_identity_header, reference_time=reference_time)

        # Step 4: Fetch dossier and build ACDCs
        raw_bytes = await cached_fetch_dossier(evd_url)
        raw_text = raw_bytes.decode("utf-8")
        nodes, signatures = parse_dossier(raw_bytes)

        # Collect all SAIDs for edge availability checking
        all_saids = {node.said for node in nodes}

        # Parse TEL data from dossier for revocation status
        tel_client = TELClient(timeout=2.0)
        revocation_cache: dict[str, dict] = {}
        for node in nodes:
            try:
                result = tel_client.parse_dossier_tel(
                    dossier_data=raw_text,
                    credential_said=node.said,
                    registry_said=node.raw.get("ri") if node.raw else None,
                )
                if result.status != CredentialStatus.UNKNOWN:
                    revocation_cache[node.said] = {
                        "status": result.status.value,
                        "checked_at": datetime.now(timezone.utc).isoformat(),
                        "source": result.source or "dossier",
                        "error": result.error,
                    }
            except Exception:
                pass

        # Parse all ACDCs
        dossier_acdcs = {}
        parsed_acdcs = []
        for node in nodes:
            acdc_dict = node.raw.copy() if node.raw else {}
            acdc_dict["d"] = node.said
            acdc_dict["i"] = node.issuer
            acdc_dict["s"] = node.schema
            if node.attributes:
                acdc_dict["a"] = node.attributes
            if node.edges:
                acdc_dict["e"] = node.edges

            try:
                acdc = parse_acdc(acdc_dict)
                dossier_acdcs[acdc.said] = acdc
                parsed_acdcs.append((acdc, acdc_dict, node.said))
            except Exception as e:
                log.warning(f"Failed to parse ACDC {node.said[:16]}: {e}")

        # Step 5: Build identity map first (sync) - for graph display names
        from app.vvp.identity import build_issuer_identity_map
        sync_identities = build_issuer_identity_map(
            [acdc for acdc, _, _ in parsed_acdcs if acdc is not None]
        )

        # Build credential graph with deep vLEI chain resolution
        # This fetches QVI credentials via e.qvi edges to reach GLEIF root
        credential_resolver = get_credential_resolver()
        graph = await build_credential_graph_with_resolution(
            dossier_acdcs=dossier_acdcs,
            trusted_roots=set(TRUSTED_ROOT_AIDS),
            revocation_status=None,
            issuer_identities=sync_identities,
            credential_resolver=credential_resolver,
            resolve_chain=True,
        )
        graph_dict = credential_graph_to_dict(graph)

        # Step 6: Build view-models for all credentials (async adds OOBI discovery)
        issuer_identities = await build_issuer_identity_map_async(
            [acdc for acdc, _, _ in parsed_acdcs if acdc is not None],
            oobi_url=evd_url,
            discover_missing=True,
        )

        delegation_info = build_delegation_chain_info(
            verify_response.delegation_chain,
            issuer_identities,
        ) if verify_response.delegation_chain else None

        # Resolve key states for display (Sprint 26: KeyStateInfo)
        # Resolve ALL issuer AIDs using witness pool to construct OOBI URLs
        key_states: dict[str, Any] = {}
        from app.vvp.keri import resolve_key_state, get_witness_pool

        # Collect unique issuer AIDs from all credentials
        issuer_aids = {acdc.issuer_aid for acdc, _, _ in parsed_acdcs if acdc is not None}
        log.debug(f"Resolving key states for {len(issuer_aids)} issuer AIDs...")

        # Get witness URLs from the pool (triggers GLEIF discovery)
        pool = get_witness_pool()
        witnesses = await pool.get_all_witnesses()
        witness_urls = [w.url for w in witnesses]

        for aid in issuer_aids:
            if aid in key_states:
                continue
            # Try each witness to construct an OOBI URL
            for witness_url in witness_urls:
                try:
                    oobi_url = f"{witness_url}/oobi/{aid}"
                    key_state = await resolve_key_state(
                        kid=aid,
                        oobi_url=oobi_url,
                        reference_time=reference_time,
                        _allow_test_mode=False,
                    )
                    key_states[aid] = key_state
                    log.debug(f"Resolved key state for issuer {aid[:16]}... via {witness_url}")
                    break  # Success, move to next AID
                except Exception as e:
                    log.debug(f"Could not resolve {aid[:16]}... via {witness_url}: {e}")
                    continue  # Try next witness

        credential_vms: dict[str, Any] = {}
        for acdc, acdc_dict, said in parsed_acdcs:
            if acdc is None:
                continue

            revocation_result = revocation_cache.get(said)

            try:
                vm = build_credential_card_vm(
                    acdc=acdc,
                    chain_result=None,
                    revocation_result=revocation_result,
                    available_saids=all_saids,
                    issuer_identities=issuer_identities,
                    key_states=key_states,
                )

                schema_info = await build_schema_info_with_fetch(acdc)
                vm.schema_info = schema_info

                if delegation_info and verify_response.signer_aid:
                    if vm.issuer.aid == verify_response.signer_aid:
                        vm.delegation_info = delegation_info

                # Build per-credential validation checks
                checks = []
                chain_severity = ("success" if vm.chain_status == "VALID"
                                 else "error" if vm.chain_status == "INVALID"
                                 else "warning")
                checks.append(ValidationCheckResult(
                    name="Chain",
                    status=vm.chain_status,
                    short_reason="Credential chain",
                    spec_ref="§5.1.1",
                    severity=chain_severity,
                ))

                schema_severity = ("success" if schema_info.validation_status == "VALID"
                                  else "error" if schema_info.validation_status == "INVALID"
                                  else "warning")
                checks.append(ValidationCheckResult(
                    name="Schema",
                    status=schema_info.validation_status,
                    short_reason=schema_info.registry_source,
                    spec_ref="§6.3",
                    severity=schema_severity,
                ))

                rev_state = vm.revocation.state
                rev_severity = ("success" if rev_state == "ACTIVE"
                               else "error" if rev_state == "REVOKED"
                               else "warning")
                rev_status = ("VALID" if rev_state == "ACTIVE"
                             else "INVALID" if rev_state == "REVOKED"
                             else "INDETERMINATE")
                checks.append(ValidationCheckResult(
                    name="Revocation",
                    status=rev_status,
                    short_reason=rev_state,
                    spec_ref="§5.1.1-2.9",
                    severity=rev_severity,
                ))

                vm.validation_checks = checks
                credential_vms[said] = vm

            except Exception as e:
                log.warning(f"Failed to build view-model for {said[:16]}: {e}")

        # Convert verify_response to dict for Jinja2 serialization
        verify_response_dict = verify_response.model_dump(mode='json')

        return templates.TemplateResponse(
            "partials/simple_result.html",
            {
                "request": request,
                "verify_response": verify_response_dict,
                "graph": graph_dict,
                "credential_vms": credential_vms,
            },
        )

    except httpx.TimeoutException:
        return templates.TemplateResponse(
            "partials/simple_result.html",
            {"request": request, "error": f"Timeout fetching dossier from {evd_url}"},
        )
    except Exception as e:
        log.error(f"Simple verification failed: {e}")
        return templates.TemplateResponse(
            "partials/simple_result.html",
            {"request": request, "error": str(e)},
        )


# -----------------------------------------------------------------------------
# Custom 404 Handler
# -----------------------------------------------------------------------------

@app.exception_handler(404)
async def not_found_handler(request: Request, exc):
    """Serve custom 404 page for browser requests, JSON for API clients."""
    accept = request.headers.get("accept", "")
    if "text/html" in accept:
        return templates.TemplateResponse(
            "404.html",
            {"request": request},
            status_code=404
        )
    # Return JSON for API clients
    return JSONResponse(
        status_code=404,
        content={"detail": "Not found"}
    )