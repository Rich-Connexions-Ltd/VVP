import logging, time
import os
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import httpx

from app.logging_config import configure_logging
from app.vvp.api_models import VerifyRequest
from app.vvp.verify import verify_vvp

configure_logging()
log = logging.getLogger("vvp")

app = FastAPI(title="VVP Verifier", version="0.1.0")
app.mount("/static", StaticFiles(directory="web"), name="static")

@app.get("/")
def index():
    return FileResponse("web/index.html")

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


@app.get("/version")
def version():
    # GIT_SHA is injected at deploy time by GitHub Actions
    return {"git_sha": os.getenv("GIT_SHA", "unknown")}


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
    )
    from app.vvp.keri.tel_client import TELClient

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
        },
        "witnesses": {
            "default_witness_urls": TELClient.DEFAULT_WITNESSES,
        },
        "environment": {
            "log_level": logging.getLogger().getEffectiveLevel(),
            "log_level_name": logging.getLevelName(logging.getLogger().getEffectiveLevel()),
        }
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


class ProxyFetchRequest(BaseModel):
    url: str


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
    """Proxy endpoint to fetch dossiers (avoids CORS issues in browser)."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(req.url)
            content_type = resp.headers.get("content-type", "")

            # Try to parse as JSON
            if "json" in content_type or req.url.endswith(".json"):
                return {"success": True, "data": resp.json(), "content_type": content_type}
            else:
                # Return raw text for CESR or other formats
                return {"success": True, "data": resp.text, "content_type": content_type}
    except httpx.TimeoutException:
        return {"success": False, "error": "Timeout fetching URL"}
    except httpx.RequestError as e:
        return {"success": False, "error": f"Request failed: {str(e)}"}
    except Exception as e:
        return {"success": False, "error": str(e)}