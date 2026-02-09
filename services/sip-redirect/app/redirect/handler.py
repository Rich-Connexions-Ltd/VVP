"""SIP INVITE handler.

Sprint 42: Processes SIP INVITEs and returns VVP-attested redirects.
Sprint 47: Added event capture for monitoring dashboard.
"""

import logging
from typing import Optional

from app.audit import get_audit_logger
from app.auth.api_key import APIKeyCache, extract_api_key
from app.auth.rate_limiter import RateLimiter
from app.config import RATE_LIMIT_RPS, RATE_LIMIT_BURST, API_KEY_CACHE_TTL, MONITOR_ENABLED
from app.redirect.client import get_issuer_client
from app.sip.models import SIPRequest, SIPResponse
from app.sip.builder import (
    build_302_redirect,
    build_401_unauthorized,
    build_403_forbidden,
    build_404_not_found,
    build_500_error,
)

log = logging.getLogger(__name__)

# Module-level singletons
_rate_limiter = RateLimiter(requests_per_second=RATE_LIMIT_RPS, burst_size=RATE_LIMIT_BURST)
_api_key_cache = APIKeyCache(ttl_seconds=API_KEY_CACHE_TTL)


def get_rate_limiter() -> RateLimiter:
    """Get the module-level rate limiter instance.

    Used by status endpoint to report rate limit state.
    """
    return _rate_limiter


async def _capture_event(
    request: SIPRequest,
    response_code: int,
    vvp_status: str,
    api_key_prefix: Optional[str] = None,
    redirect_uri: Optional[str] = None,
    error: Optional[str] = None,
) -> None:
    """Capture SIP event for monitoring dashboard.

    Args:
        request: The SIP request
        response_code: HTTP-style response code (302, 401, etc.)
        vvp_status: VVP status (VALID, INVALID, INDETERMINATE)
        api_key_prefix: First 8 chars of API key
        redirect_uri: Contact URI from redirect response
        error: Error message if any
    """
    if not MONITOR_ENABLED:
        return

    try:
        from app.monitor.buffer import get_event_buffer

        # Extract VVP headers from request
        vvp_headers = {}
        for name, value in request.headers.items():
            name_lower = name.lower()
            if name_lower.startswith("x-vvp-") or name_lower.startswith("p-vvp-"):
                vvp_headers[name] = value
            elif name_lower == "identity":
                vvp_headers["Identity"] = value

        buffer = get_event_buffer()
        await buffer.add({
            "service": "SIGNING",  # Sprint 47: Always SIGNING for sip-redirect
            "source_addr": request.source_addr or "unknown",
            "method": request.method,
            "request_uri": request.request_uri,
            "call_id": request.call_id or "",
            "from_tn": request.from_tn,
            "to_tn": request.to_tn,
            "api_key_prefix": api_key_prefix,
            "headers": dict(request.headers),
            "vvp_headers": vvp_headers,
            "response_code": response_code,
            "vvp_status": vvp_status,
            "redirect_uri": redirect_uri,
            "error": error,
        })
        log.info(f"Monitor event captured: {request.method} {vvp_status} (code={response_code})")
    except Exception as e:
        log.error(f"Failed to capture event for monitoring: {e}", exc_info=True)


async def handle_invite(request: SIPRequest) -> SIPResponse:
    """Handle SIP INVITE with VVP attestation.

    Flow:
    1. Extract and validate API key
    2. Check rate limit
    3. Look up TN mapping via issuer
    4. Create VVP headers via issuer
    5. Return 302 redirect with VVP headers

    Args:
        request: Parsed SIP INVITE request

    Returns:
        SIPResponse with VVP attestation or error
    """
    audit = get_audit_logger()

    # Verify this is an INVITE
    if not request.is_invite:
        log.warning(f"Unexpected method: {request.method}")
        return build_403_forbidden(request, f"Method {request.method} not supported")

    # Extract metadata for audit
    from_tn = request.from_tn
    to_tn = request.to_tn
    call_id = request.call_id
    api_key = extract_api_key(request)
    api_key_prefix = api_key[:8] if api_key else None

    # Audit: Log INVITE received
    audit.log(
        action="invite.received",
        call_id=call_id,
        from_tn=from_tn,
        to_tn=to_tn,
        api_key_prefix=api_key_prefix,
    )

    # Check for API key
    if not api_key:
        audit.log(
            action="invite.rejected",
            call_id=call_id,
            status_code=401,
            vvp_status="INVALID",
            details={"reason": "Missing API key"},
        )
        await _capture_event(request, 401, "INVALID", error="Missing API key")
        return build_401_unauthorized(request, "Missing X-VVP-API-Key header")

    # Check rate limit
    if not _rate_limiter.check(api_key):
        retry_after = _rate_limiter.get_retry_after(api_key)
        audit.log(
            action="invite.rate_limited",
            call_id=call_id,
            api_key_prefix=api_key_prefix,
            status_code=403,
            vvp_status="INVALID",
            details={"retry_after": retry_after},
        )
        await _capture_event(request, 403, "INVALID", api_key_prefix, error="Rate limit exceeded")
        return build_403_forbidden(request, "Rate limit exceeded")

    # Check if from_tn was extracted
    if not from_tn:
        audit.log(
            action="invite.rejected",
            call_id=call_id,
            status_code=400,
            vvp_status="INVALID",
            details={"reason": "Could not extract originating TN"},
        )
        await _capture_event(request, 400, "INVALID", api_key_prefix, error="Missing From TN")
        return build_403_forbidden(request, "Could not extract originating TN from From header")

    try:
        # Look up TN mapping
        client = await get_issuer_client()
        lookup_result = await client.lookup_tn(from_tn, api_key)

        if not lookup_result.found:
            audit.log(
                action="invite.tn_not_found",
                call_id=call_id,
                from_tn=from_tn,
                api_key_prefix=api_key_prefix,
                status_code=404,
                vvp_status="INVALID",
                details={"error": lookup_result.error},
            )
            await _capture_event(request, 404, "INVALID", api_key_prefix, error=lookup_result.error)
            return build_404_not_found(request, lookup_result.error or f"No mapping for {from_tn}")

        # Create VVP headers
        vvp_result = await client.create_vvp(
            api_key=api_key,
            identity_name=lookup_result.identity_name,
            dossier_said=lookup_result.dossier_said,
            orig_tn=from_tn,
            dest_tn=to_tn or "",
        )

        if not vvp_result.success:
            audit.log(
                action="invite.vvp_create_failed",
                call_id=call_id,
                from_tn=from_tn,
                api_key_prefix=api_key_prefix,
                status_code=500,
                vvp_status="INDETERMINATE",
                details={"error": vvp_result.error},
            )
            await _capture_event(request, 500, "INDETERMINATE", api_key_prefix, error=vvp_result.error)
            return build_500_error(request, vvp_result.error or "Failed to create VVP headers")

        # Build successful redirect
        # Contact URI is the original request URI (enterprise routes the call)
        contact_uri = request.request_uri

        response = build_302_redirect(
            request=request,
            contact_uri=contact_uri,
            vvp_identity=vvp_result.vvp_identity,
            vvp_passport=vvp_result.vvp_passport,
            vvp_status="VALID",
            brand_name=lookup_result.brand_name,
            brand_logo_url=lookup_result.brand_logo_url,
        )

        audit.log(
            action="invite.completed",
            call_id=call_id,
            from_tn=from_tn,
            to_tn=to_tn,
            api_key_prefix=api_key_prefix,
            status_code=302,
            vvp_status="VALID",
            details={
                "org_id": lookup_result.organization_id,
                "org_name": lookup_result.organization_name,
            },
        )

        await _capture_event(request, 302, "VALID", api_key_prefix, redirect_uri=contact_uri)
        return response

    except Exception as e:
        log.error(f"Error handling INVITE: {e}")
        audit.log(
            action="invite.error",
            call_id=call_id,
            from_tn=from_tn,
            api_key_prefix=api_key_prefix,
            status_code=500,
            vvp_status="INDETERMINATE",
            details={"error": str(e)},
        )
        await _capture_event(request, 500, "INDETERMINATE", api_key_prefix, error=str(e))
        return build_500_error(request, "Internal server error")
