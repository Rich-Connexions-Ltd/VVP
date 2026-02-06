"""SIP INVITE verification handler.

Sprint 44: Handles incoming SIP INVITEs with VVP headers:
1. Parse Identity header (RFC 8224) to get PASSporT + OOBI
2. Decode P-VVP-Identity header (base64url JSON)
3. Build VerifyCalleeRequest from SIP headers
4. Call VVP Verifier POST /verify-callee with VVP-Identity header
5. Map VerifyResponse to X-VVP-* headers
6. Return SIP 302 redirect
"""

import logging
import time
from datetime import datetime, timezone
from typing import Optional

from common.vvp.sip import (
    SIPRequest,
    SIPResponse,
    build_302_redirect,
    build_400_bad_request,
)

from ..audit import log_verification
from ..config import VVP_REDIRECT_TARGET, VVP_FALLBACK_STATUS
from .identity_parser import parse_identity_header, IdentityParseError
from .vvp_identity import decode_vvp_identity, VVPIdentityDecodeError
from .client import get_verifier_client, VerifyResult

log = logging.getLogger(__name__)


async def handle_verify_invite(request: SIPRequest) -> SIPResponse:
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
        SIP 302 redirect response with VVP headers
    """
    start_time = time.time()

    # Determine contact URI for 302 redirect
    contact_uri = VVP_REDIRECT_TARGET or request.request_uri

    # Validate required headers for verification (400 per Sprint 44)
    if not request.has_verification_headers:
        log.warning(f"INVITE missing verification headers, call_id={request.call_id}")
        return build_400_bad_request(
            request,
            reason="Missing VVP verification headers (Identity or P-VVP-Identity required)",
        )

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
            return build_400_bad_request(request, reason=f"Invalid Identity header: {e}")

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
            return build_400_bad_request(request, reason=f"Invalid P-VVP-Identity: {e}")

    # Use OOBI from Identity header info parameter as fallback for kid
    if not kid and oobi_url:
        kid = oobi_url

    # Use P-VVP-Passport as fallback for PASSporT JWT
    if not passport_jwt and request.p_vvp_passport:
        passport_jwt = request.p_vvp_passport

    # Validate we have required fields
    if not passport_jwt:
        log.warning(f"No PASSporT found, call_id={request.call_id}")
        return build_400_bad_request(request, reason="No PASSporT JWT found")

    if not kid:
        log.warning(f"No OOBI URL found, call_id={request.call_id}")
        return build_400_bad_request(request, reason="No OOBI URL found (kid)")

    if not evd:
        log.warning(f"No dossier URL found, call_id={request.call_id}")
        return build_400_bad_request(request, reason="No dossier URL found (evd)")

    # Extract CSeq number from header (e.g., "1 INVITE" -> 1)
    cseq_num = 1
    if request.cseq:
        parts = request.cseq.split()
        if parts and parts[0].isdigit():
            cseq_num = int(parts[0])

    # Build invite time from current time
    now = datetime.now(timezone.utc)
    invite_time = now.isoformat()

    # Use iat from VVP-Identity, or fall back to current time
    iat = identity_iat if identity_iat is not None else int(now.timestamp())

    # Call Verifier API
    client = get_verifier_client()
    result = await client.verify_callee(
        passport_jwt=passport_jwt,
        call_id=request.call_id,
        from_uri=request.from_header,
        to_uri=request.to_header,
        invite_time=invite_time,
        cseq=cseq_num,
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
    )

    log.info(
        f"Verification complete: call_id={request.call_id}, "
        f"status={result.status}, "
        f"brand={result.brand_name or 'none'}, "
        f"time_ms={processing_time_ms:.1f}"
    )

    return response
