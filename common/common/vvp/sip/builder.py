"""SIP response builder.

Sprint 44: Builds SIP responses with RFC 3261 compliance.
Supports both signing (302 redirect) and verification (302 with X-VVP-* headers).

All responses MUST copy these headers from request (RFC 3261 section 8.2.6.2):
- Via: All Via headers in same order
- From: Exactly as received
- To: As received, with added tag if not present
- Call-ID: Exactly as received
- CSeq: Exactly as received
"""

import uuid
from typing import Optional

from common.vvp.sip.models import SIPRequest, SIPResponse


def _add_to_tag(to_header: str) -> str:
    """Add tag parameter to To header if not present.

    RFC 3261 requires a tag in To header for all responses.

    Args:
        to_header: Original To header value

    Returns:
        To header with tag parameter
    """
    if ";tag=" in to_header.lower():
        return to_header

    # Generate a unique tag
    tag = uuid.uuid4().hex[:16]
    return f"{to_header};tag={tag}"


def _copy_transaction_headers(request: SIPRequest, response: SIPResponse) -> None:
    """Copy required transaction headers from request to response.

    Per RFC 3261 section 8.2.6.2, responses MUST include the same
    Via, From, To, Call-ID, and CSeq headers as the request.
    """
    response.via = list(request.via)  # Copy all Via headers
    response.from_header = request.from_header
    response.to_header = _add_to_tag(request.to_header)
    response.call_id = request.call_id
    response.cseq = request.cseq


def build_302_redirect(
    request: SIPRequest,
    contact_uri: str,
    identity: Optional[str] = None,
    vvp_identity: Optional[str] = None,
    vvp_passport: Optional[str] = None,
    vvp_status: str = "VALID",
    brand_name: Optional[str] = None,
    brand_logo_url: Optional[str] = None,
    caller_id: Optional[str] = None,
    error_code: Optional[str] = None,
    vetter_status: Optional[str] = None,
) -> SIPResponse:
    """Build 302 Moved Temporarily response with VVP headers.

    Used for both signing (VVP attestation) and verification (VVP validation).

    The response includes:
    - Identity: RFC 8224 Identity header (Sprint 57)
    - Contact: Redirect destination
    - P-VVP-Identity: Base64url VVP-Identity header
    - P-VVP-Passport: Signed PASSporT JWT
    - X-VVP-Brand-Name: Organization name (optional)
    - X-VVP-Brand-Logo: Logo URL (optional)
    - X-VVP-Caller-ID: Caller's phone number (optional)
    - X-VVP-Status: VALID | INVALID | INDETERMINATE
    - X-VVP-Vetter-Status: PASS | FAIL-ECC | FAIL-JURISDICTION | ... (Sprint 62)
    - X-VVP-Error: Error code if INVALID (optional)

    Args:
        request: Original SIP INVITE request
        contact_uri: Redirect destination URI
        identity: RFC 8224 Identity header value (Sprint 57)
        vvp_identity: Base64url encoded VVP-Identity header
        vvp_passport: Signed PASSporT JWT
        vvp_status: Verification status (default: VALID)
        brand_name: Organization name for display
        brand_logo_url: Logo URL for display
        caller_id: Caller's phone number
        error_code: Error code if INVALID
        vetter_status: Vetter constraint status (Sprint 62)

    Returns:
        SIPResponse ready to send
    """
    response = SIPResponse(
        status_code=302,
        reason_phrase="Moved Temporarily",
        contact=f"<{contact_uri}>",
        identity=identity,
        vvp_identity=vvp_identity,
        vvp_passport=vvp_passport,
        vvp_status=vvp_status,
        brand_name=brand_name,
        brand_logo_url=brand_logo_url,
        caller_id=caller_id,
        error_code=error_code,
        vetter_status=vetter_status,
    )
    _copy_transaction_headers(request, response)
    return response


def build_400_bad_request(
    request: SIPRequest,
    reason: str,
) -> SIPResponse:
    """Build 400 Bad Request response.

    Used when the request is malformed (missing required headers,
    unparseable Identity header, etc.).

    Args:
        request: Original SIP INVITE request
        reason: Human-readable error reason

    Returns:
        SIPResponse ready to send
    """
    response = SIPResponse(
        status_code=400,
        reason_phrase="Bad Request",
        error_reason=reason,
    )
    _copy_transaction_headers(request, response)
    return response


def build_401_unauthorized(
    request: SIPRequest,
    reason: str,
    vvp_status: str = "INVALID",
) -> SIPResponse:
    """Build 401 Unauthorized response.

    Used when authentication fails (missing or invalid API key).

    Args:
        request: Original SIP INVITE request
        reason: Human-readable error reason
        vvp_status: Verification status (default: INVALID)

    Returns:
        SIPResponse ready to send
    """
    response = SIPResponse(
        status_code=401,
        reason_phrase="Unauthorized",
        vvp_status=vvp_status,
        error_reason=reason,
    )
    _copy_transaction_headers(request, response)
    return response


def build_403_forbidden(
    request: SIPRequest,
    reason: str,
    vvp_status: str = "INVALID",
) -> SIPResponse:
    """Build 403 Forbidden response.

    Used when authentication succeeds but authorization fails
    (e.g., rate limited, TN not authorized).

    Args:
        request: Original SIP INVITE request
        reason: Human-readable error reason
        vvp_status: Verification status (default: INVALID)

    Returns:
        SIPResponse ready to send
    """
    response = SIPResponse(
        status_code=403,
        reason_phrase="Forbidden",
        vvp_status=vvp_status,
        error_reason=reason,
    )
    _copy_transaction_headers(request, response)
    return response


def build_404_not_found(
    request: SIPRequest,
    reason: str,
    vvp_status: str = "INVALID",
) -> SIPResponse:
    """Build 404 Not Found response.

    Used when the telephone number has no mapping.

    Args:
        request: Original SIP INVITE request
        reason: Human-readable error reason
        vvp_status: Verification status (default: INVALID)

    Returns:
        SIPResponse ready to send
    """
    response = SIPResponse(
        status_code=404,
        reason_phrase="Not Found",
        vvp_status=vvp_status,
        error_reason=reason,
    )
    _copy_transaction_headers(request, response)
    return response


def build_500_error(
    request: SIPRequest,
    reason: str,
    vvp_status: str = "INDETERMINATE",
) -> SIPResponse:
    """Build 500 Server Internal Error response.

    Used when an internal error prevents VVP processing.

    Args:
        request: Original SIP INVITE request
        reason: Human-readable error reason
        vvp_status: Verification status (default: INDETERMINATE)

    Returns:
        SIPResponse ready to send
    """
    response = SIPResponse(
        status_code=500,
        reason_phrase="Server Internal Error",
        vvp_status=vvp_status,
        error_reason=reason,
    )
    _copy_transaction_headers(request, response)
    return response
