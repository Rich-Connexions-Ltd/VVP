"""SIP response builder.

Sprint 42: Builds SIP responses with RFC 3261 compliance.

All responses MUST copy these headers from request (RFC 3261 section 8.2.6.2):
- Via: All Via headers in same order
- From: Exactly as received
- To: As received, with added tag if not present
- Call-ID: Exactly as received
- CSeq: Exactly as received
"""

import uuid
from typing import Optional

from app.sip.models import SIPRequest, SIPResponse


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


def build_100_trying(request: SIPRequest) -> SIPResponse:
    """Build 100 Trying provisional response.

    Sent immediately on INVITE receipt to reset SIP Timer B (32s), allowing
    the signing service time to complete TN lookup and VVP credential creation.

    Per RFC 3261 section 8.2.6.2, 100 Trying MUST NOT add a To tag.

    Args:
        request: Original SIP INVITE request

    Returns:
        SIPResponse ready to send immediately
    """
    response = SIPResponse(
        status_code=100,
        reason_phrase="Trying",
    )
    response.via = list(request.via)
    response.from_header = request.from_header
    response.to_header = request.to_header  # No tag for 100 Trying (RFC 3261)
    response.call_id = request.call_id
    response.cseq = request.cseq
    return response


def build_302_redirect(
    request: SIPRequest,
    contact_uri: str,
    identity: Optional[str] = None,
    vvp_identity: str = "",
    vvp_passport: str = "",
) -> SIPResponse:
    """Build 302 Moved Temporarily response with STIR attestation headers.

    Sprint 60: Signing 302 contains ONLY STIR/VVP attestation headers.
    No X-VVP-* headers — brand/status are derived by the verification
    service from the dossier evidence referenced by the PASSporT evd field.

    Headers included:
    - Identity: RFC 8224 Identity header (Sprint 57)
    - Contact: Redirect destination
    - P-VVP-Identity: Base64url VVP-Identity header
    - P-VVP-Passport: Signed PASSporT JWT

    Args:
        request: Original SIP INVITE request
        contact_uri: Redirect destination URI
        identity: RFC 8224 Identity header value (Sprint 57)
        vvp_identity: Base64url encoded VVP-Identity header
        vvp_passport: Signed PASSporT JWT

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
