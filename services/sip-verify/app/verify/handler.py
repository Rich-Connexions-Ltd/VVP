"""SIP INVITE verification handler.

Sprint 44: Handles incoming SIP INVITEs with VVP headers:
1. Parse Identity header (RFC 8224) to get PASSporT + OOBI
2. Decode P-VVP-Identity header (base64url JSON)
3. Build VerifyCalleeRequest from SIP headers
4. Call VVP Verifier POST /verify-callee with VVP-Identity header
5. Map VerifyResponse to X-VVP-* headers
6. Return SIP 302 redirect

Sprint 48: Added event capture for monitoring dashboard via HTTP POST
to the sip-redirect monitor's ingestion endpoint.
"""

import asyncio
import logging
import time
from datetime import datetime, timezone
from typing import Optional

import httpx

from common.vvp.sip import (
    SIPRequest,
    SIPResponse,
    build_302_redirect,
    build_400_bad_request,
)

from ..audit import log_verification
from ..config import (
    VVP_REDIRECT_TARGET,
    VVP_FALLBACK_STATUS,
    VVP_MONITOR_URL,
    VVP_MONITOR_ENABLED,
    VVP_MONITOR_TIMEOUT,
)
from .identity_parser import parse_identity_header, IdentityParseError
from .vvp_identity import decode_vvp_identity, VVPIdentityDecodeError
from .client import get_verifier_client, VerifyResult

log = logging.getLogger(__name__)

# Lazy-initialized persistent HTTP session for monitor
_monitor_session: Optional[httpx.AsyncClient] = None


def _get_monitor_session() -> httpx.AsyncClient:
    """Get or create a persistent HTTP session for monitor integration."""
    global _monitor_session
    if _monitor_session is None:
        _monitor_session = httpx.AsyncClient(timeout=VVP_MONITOR_TIMEOUT)
    return _monitor_session


async def _do_capture_event(event_data: dict, vvp_status: str, response_code: int) -> None:
    """Post event data to the monitor ingestion endpoint.

    This is the actual HTTP call — meant to be run as a background task
    via asyncio.create_task so it doesn't block the SIP call path.
    """
    try:
        session = _get_monitor_session()
        url = f"{VVP_MONITOR_URL}/api/events/ingest"
        resp = await session.post(url, json=event_data)
        log.info(f"Monitor event captured: VERIFICATION {vvp_status} (code={response_code}, monitor_status={resp.status_code})")
    except Exception as e:
        log.warning(f"Failed to capture monitor event: {e}")


async def _capture_event(
    request: SIPRequest,
    response: Optional[SIPResponse],
    response_code: int,
    vvp_status: str,
    error: Optional[str] = None,
) -> None:
    """Capture SIP verification event for monitoring dashboard (fire-and-forget).

    Builds the event dict and schedules the HTTP POST as a background task.
    Never blocks the SIP call path — monitoring must not affect call latency.

    Args:
        request: The SIP INVITE request
        response: The SIP response (for extracting response VVP headers)
        response_code: SIP response code (302, 400, etc.)
        vvp_status: VVP verification status
        error: Error message if any
    """
    if not VVP_MONITOR_ENABLED:
        return

    # Extract request VVP headers
    vvp_headers = {}
    for name, value in request.headers.items():
        name_lower = name.lower()
        if name_lower.startswith("x-vvp-") or name_lower.startswith("p-vvp-"):
            vvp_headers[name] = value
        elif name_lower == "identity":
            vvp_headers["Identity"] = value

    # Extract response VVP headers
    response_vvp_headers = {}
    if response is not None:
        if response.vvp_identity:
            response_vvp_headers["P-VVP-Identity"] = response.vvp_identity
        if response.vvp_passport:
            response_vvp_headers["P-VVP-Passport"] = response.vvp_passport
        if response.vvp_status:
            response_vvp_headers["X-VVP-Status"] = response.vvp_status
        if response.brand_name:
            response_vvp_headers["X-VVP-Brand-Name"] = response.brand_name
        if response.brand_logo_url:
            response_vvp_headers["X-VVP-Brand-Logo"] = response.brand_logo_url
        if response.caller_id:
            response_vvp_headers["X-VVP-Caller-ID"] = response.caller_id
        if response.error_code:
            response_vvp_headers["X-VVP-Error"] = response.error_code
        if response.vetter_status:
            response_vvp_headers["X-VVP-Vetter-Status"] = response.vetter_status
        if response.warning_reason:
            response_vvp_headers["X-VVP-Warning-Reason"] = response.warning_reason

    event_data = {
        "service": "VERIFICATION",
        "source_addr": request.source_addr or "unknown",
        "method": request.method,
        "request_uri": request.request_uri,
        "call_id": request.call_id or "",
        "from_tn": request.from_tn,
        "to_tn": request.to_tn,
        "headers": dict(request.headers),
        "vvp_headers": vvp_headers,
        "response_code": response_code,
        "vvp_status": vvp_status,
        "response_vvp_headers": response_vvp_headers,
        "error": error,
        "raw_request": request.raw.decode("utf-8", errors="replace") if request.raw else None,
        "raw_response": response.to_bytes().decode("utf-8", errors="replace") if response else None,
    }

    # Fire-and-forget: schedule HTTP POST as background task
    asyncio.create_task(_do_capture_event(event_data, vvp_status, response_code))


async def handle_verify_invite(request: SIPRequest) -> Optional[SIPResponse]:
    """Handle incoming SIP INVITE with VVP verification.

    Flow:
    1. Validate request has required VVP headers
    2. Parse RFC 8224 Identity header to extract PASSporT
    3. Decode P-VVP-Identity to get OOBI and dossier URLs
    4. Call Verifier /verify-callee endpoint
    5. Build SIP 302 response with X-VVP-* headers

    Args:
        request: Parsed SIP INVITE request

    Returns:
        SIP 302 redirect response with VVP headers, or None to silently
        drop the request (e.g. FreeSWITCH retransmit without VVP headers).
    """
    start_time = time.time()

    # Determine contact URI for 302 redirect.
    # VVP_REDIRECT_TARGET is host:port only (e.g. "127.0.0.1:5080"),
    # so we build a proper SIP URI with the destination TN.
    if VVP_REDIRECT_TARGET:
        dest = request.to_tn or request.request_uri
        contact_uri = f"sip:{dest}@{VVP_REDIRECT_TARGET}"
    else:
        contact_uri = request.request_uri

    # Silently ignore bare INVITEs without VVP headers.
    # FreeSWITCH sends a second INVITE when natively following the
    # verification 302 Contact URI; this duplicate lacks VVP headers
    # and should be dropped rather than generating a 400 response.
    if not request.has_verification_headers:
        log.debug(f"Ignoring bare INVITE (no VVP headers), call_id={request.call_id}")
        return None

    # Parse Identity header (RFC 8224)
    passport_jwt: Optional[str] = None
    oobi_url: Optional[str] = None

    if request.identity_header:
        try:
            identity = parse_identity_header(request.identity_header)
            passport_jwt = identity.passport_jwt
            oobi_url = identity.info_url
            log.debug(f"Parsed Identity header: alg={identity.algorithm}, ppt={identity.ppt}")
        except IdentityParseError as e:
            log.warning(f"Failed to parse Identity header: {e}")
            resp = build_400_bad_request(request, reason=f"Invalid Identity header: {e}")
            await _capture_event(request, resp, 400, "INDETERMINATE", error=f"Invalid Identity header: {e}")
            return resp

    # Decode P-VVP-Identity header
    kid: Optional[str] = None
    evd: Optional[str] = None
    identity_iat: Optional[int] = None
    identity_exp: Optional[int] = None

    if request.p_vvp_identity:
        try:
            vvp_identity = decode_vvp_identity(request.p_vvp_identity)
            kid = vvp_identity.kid
            evd = vvp_identity.evd
            identity_iat = vvp_identity.iat
            identity_exp = vvp_identity.exp
            log.debug(f"Decoded P-VVP-Identity: kid={kid[:50]}..., evd={evd[:50]}...")
        except VVPIdentityDecodeError as e:
            log.warning(f"Failed to decode P-VVP-Identity: {e}")
            resp = build_400_bad_request(request, reason=f"Invalid P-VVP-Identity: {e}")
            await _capture_event(request, resp, 400, "INDETERMINATE", error=f"Invalid P-VVP-Identity: {e}")
            return resp

    # Use OOBI from Identity header info parameter as fallback for kid
    if not kid and oobi_url:
        kid = oobi_url

    # Use P-VVP-Passport as fallback for PASSporT JWT
    if not passport_jwt and request.p_vvp_passport:
        passport_jwt = request.p_vvp_passport

    # Validate we have required fields
    if not passport_jwt:
        log.warning(f"No PASSporT found, call_id={request.call_id}")
        resp = build_400_bad_request(request, reason="No PASSporT JWT found")
        await _capture_event(request, resp, 400, "INDETERMINATE", error="No PASSporT JWT found")
        return resp

    if not kid:
        log.warning(f"No OOBI URL found, call_id={request.call_id}")
        resp = build_400_bad_request(request, reason="No OOBI URL found (kid)")
        await _capture_event(request, resp, 400, "INDETERMINATE", error="No OOBI URL found (kid)")
        return resp

    if not evd:
        log.warning(f"No dossier URL found, call_id={request.call_id}")
        resp = build_400_bad_request(request, reason="No dossier URL found (evd)")
        await _capture_event(request, resp, 400, "INDETERMINATE", error="No dossier URL found (evd)")
        return resp

    # Extract CSeq number from header (e.g., "1 INVITE" -> 1)
    cseq_num = 1
    if request.cseq:
        parts = request.cseq.split()
        if parts and parts[0].isdigit():
            cseq_num = int(parts[0])

    # Extract call-id and cseq from PASSporT payload for dialog matching.
    # In a FreeSWITCH 302-redirect chain, each bridge leg gets a new SIP
    # Call-ID, so the INVITE arriving at sip-verify has a different call-id
    # than the original INVITE that sip-redirect signed into the PASSporT.
    # The verifier compares the context call_id against the PASSporT's
    # call-id claim, so we must send the ORIGINAL call-id (from the PASSporT).
    passport_call_id = request.call_id
    passport_cseq = cseq_num
    try:
        import base64, json
        # PASSporT is header.payload.signature — decode the payload
        jwt_parts = passport_jwt.split(".")
        if len(jwt_parts) >= 2:
            payload_b64 = jwt_parts[1]
            payload_b64 += "=" * (4 - len(payload_b64) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))
            if "call-id" in payload:
                passport_call_id = payload["call-id"]
                log.debug(f"Using PASSporT call-id for dialog match: {passport_call_id}")
            if "cseq" in payload:
                passport_cseq = payload["cseq"]
                log.debug(f"Using PASSporT cseq for dialog match: {passport_cseq}")
    except Exception as e:
        log.warning(f"Failed to extract call-id/cseq from PASSporT: {e}")

    # Build invite time from current time
    now = datetime.now(timezone.utc)
    invite_time = now.isoformat()

    # Use iat from VVP-Identity, or fall back to current time
    iat = identity_iat if identity_iat is not None else int(now.timestamp())

    # Build clean SIP URIs from TNs for the verifier context.
    # SIP To/From headers include display name, angle brackets, and tag
    # parameters (e.g. '"name" <sip:+441923311006@host>;tag=abc'), but the
    # verifier's extract_tn_from_sip_uri() expects bare SIP URIs.
    from_uri = f"sip:{request.from_tn}@pbx" if request.from_tn else request.from_header
    to_uri = f"sip:{request.to_tn}@pbx" if request.to_tn else request.to_header

    # Call Verifier API
    client = get_verifier_client()
    result = await client.verify_callee(
        passport_jwt=passport_jwt,
        call_id=passport_call_id,
        from_uri=from_uri,
        to_uri=to_uri,
        invite_time=invite_time,
        cseq=passport_cseq,
        kid=kid,
        evd=evd,
        iat=iat,
        exp=identity_exp,
    )

    # Calculate processing time
    processing_time_ms = (time.time() - start_time) * 1000

    # Log verification event
    log_verification(
        call_id=request.call_id,
        from_tn=request.from_tn or "",
        to_tn=request.to_tn or "",
        vvp_status=result.status,
        brand_name=result.brand_name,
        error_code=result.error_code,
        processing_time_ms=processing_time_ms,
    )

    # Sprint 60: Brand derived ONLY from verified dossier evidence.
    # No fallback to incoming SIP headers.

    # Build 302 redirect with VVP headers
    response = build_302_redirect(
        request,
        contact_uri=contact_uri,
        vvp_identity=request.p_vvp_identity,  # Pass through
        vvp_passport=request.p_vvp_passport,  # Pass through
        vvp_status=result.status,
        brand_name=result.brand_name,
        brand_logo_url=result.brand_logo_url,
        caller_id=result.caller_id,
        error_code=result.error_code if result.status == "INVALID" else None,
        vetter_status=result.vetter_status,  # Sprint 62
        warning_reason=result.warning_reason,  # Sprint 75: vetter scope mismatch
    )

    warning_suffix = f", warning={result.warning_reason}" if result.warning_reason else ""
    log.info(
        f"Verification complete: call_id={request.call_id}, "
        f"status={result.status}, "
        f"brand={result.brand_name or 'none'}, "
        f"time_ms={processing_time_ms:.1f}{warning_suffix}"
    )

    await _capture_event(request, response, 302, result.status)
    return response
