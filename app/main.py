import base64
import html
import json
import logging
import os
import time
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, Form, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
import httpx

from app.logging_config import configure_logging
from app.vvp.api_models import VerifyRequest
from app.vvp.exceptions import PassportError
from app.vvp.passport import parse_passport
from app.vvp.verify import verify_vvp

configure_logging()
log = logging.getLogger("vvp")

app = FastAPI(title="VVP Verifier", version="0.1.0")

# Template setup
templates_dir = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(templates_dir))

# Keep static mount for backwards compatibility (will be removed after migration verified)
app.mount("/static", StaticFiles(directory="web"), name="static")

@app.get("/")
def index(request: Request):
    """Serve the main verification page using HTMX templates."""
    return templates.TemplateResponse("index.html", {"request": request})

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
    "orig.tn must be a single phone number": ("§4.2", "orig.tn must be a single string, not array"),
    "orig.tn must be a string": ("§4.2", "orig.tn must be a string type"),
    "orig.tn must be E.164": ("§4.2", "Phone numbers must be E.164 format"),
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
    try:
        passport = parse_passport(jwt)
        # If validation passes, use validated signature (bytes -> hex)
        signature_str = passport.signature.hex()
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
    """Fetch dossier and return HTML fragment with credentials."""
    from app.vvp.dossier.parser import parse_dossier

    try:
        # Fetch raw dossier bytes
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(evd_url)
            raw_bytes = resp.content
            raw_text = resp.text

        # Use the existing CESR-aware dossier parser
        nodes, signatures = parse_dossier(raw_bytes)

        # Convert ACDCNode objects to dicts for template rendering
        acdcs = []
        for node in nodes:
            acdc = node.raw.copy() if node.raw else {}
            acdc["d"] = node.said
            acdc["i"] = node.issuer
            acdc["s"] = node.schema

            # Infer credential type from attributes
            attrs = node.attributes if isinstance(node.attributes, dict) else {}
            if "tn" in attrs:
                acdc["type"] = "TNAlloc"
            elif "legalName" in attrs or "LEI" in attrs:
                acdc["type"] = "LE"
            elif "role" in attrs:
                acdc["type"] = "APE"
            elif "vcard" in attrs:
                acdc["type"] = "LE"
            else:
                acdc["type"] = "UNKNOWN"

            acdcs.append(acdc)

        return templates.TemplateResponse(
            "partials/dossier.html",
            {
                "request": request,
                "acdcs": acdcs,
                "kid_url": kid_url,
                "dossier_stream": raw_text,
                "raw_data": raw_text[:5000] if len(raw_text) > 5000 else raw_text,
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


@app.post("/ui/check-revocation")
async def ui_check_revocation(
    request: Request,
    acdcs: str = Form(...),
    kid_url: str = Form(""),
    dossier_stream: str = Form(""),
):
    """Check revocation status for credentials and return HTML fragment.

    Extracts TEL events from the dossier stream (instant, no network).
    If no inline TEL data found, returns UNKNOWN - witness TEL endpoints
    are typically not publicly accessible.
    """
    from app.vvp.keri.tel_client import TELClient, CredentialStatus

    try:
        # Unescape HTML entities (form value may have &quot; etc. from template escaping)
        unescaped = html.unescape(acdcs)
        log.debug(f"check-revocation received acdcs (first 200 chars): {acdcs[:200]}")
        log.debug(f"check-revocation unescaped (first 200 chars): {unescaped[:200]}")
        acdc_list = json.loads(unescaped)

        # Use TEL client for parsing dossier TEL data
        client = TELClient(timeout=2.0)
        results = []

        # Unescape dossier stream if provided
        dossier_data = html.unescape(dossier_stream) if dossier_stream else ""

        for acdc in acdc_list:
            said = acdc.get("d", "")
            registry_said = acdc.get("ri")

            # Try to parse TEL from inline dossier data (instant, no network)
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
                            "source": result.source,
                            "error": result.error,
                        })
                        continue  # Found status from dossier
                except Exception as e:
                    log.debug(f"Dossier TEL parse failed for {said[:20]}: {e}")

            # No inline TEL data found - return UNKNOWN
            # (Witness TEL endpoints are typically not publicly accessible)
            results.append({
                "said": said,
                "status": "UNKNOWN",
                "source": None,
                "error": "TEL data not in dossier (live witness query disabled)",
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
    """Build credential graph and return HTML fragment."""
    from app.core.config import TRUSTED_ROOT_AIDS
    from app.vvp.acdc import (
        ACDC,
        CredentialStatus,
        build_credential_graph,
        credential_graph_to_dict,
        parse_acdc,
    )

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

        graph = build_credential_graph(
            dossier_acdcs=dossier_acdcs,
            trusted_roots=set(TRUSTED_ROOT_AIDS),
            revocation_status=None,
        )

        graph_dict = credential_graph_to_dict(graph)

        return templates.TemplateResponse(
            "partials/credential_graph.html",
            {"request": request, "graph": graph_dict},
        )
    except Exception as e:
        log.error(f"Failed to build credential graph: {e}")
        return templates.TemplateResponse(
            "partials/credential_graph.html",
            {"request": request, "error": str(e)},
        )