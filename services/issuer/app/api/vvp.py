"""VVP header creation API endpoint.

Creates VVP-Identity headers and signed PASSporT JWTs for telephone calls.
This is the issuer-side implementation per VVP spec §4.1A, §5.0-§5.4, §6.3.1.
"""

import logging

from fastapi import APIRouter, HTTPException

from app.api.models import CreateVVPRequest, CreateVVPResponse, ErrorResponse
from app.auth.api_key import Principal
from app.auth.roles import check_credential_write_role, require_auth
from app.keri.identity import get_identity_manager
from app.vvp.exceptions import (
    IdentityNotAvailableError,
    InvalidPhoneNumberError,
    VVPCreationError,
)
from app.vvp.header import create_vvp_identity_header, MAX_VALIDITY_SECONDS
from app.vvp.oobi import build_dossier_url, build_issuer_oobi
from app.vvp.passport import create_passport
from app.config import WITNESS_OOBI_BASE_URLS, VVP_ISSUER_BASE_URL

log = logging.getLogger(__name__)

router = APIRouter(prefix="/vvp", tags=["vvp"])


def _get_issuer_base_url() -> str:
    """Get the issuer's base URL for dossier URLs."""
    return VVP_ISSUER_BASE_URL


def _get_witness_url() -> str:
    """Get a witness URL for OOBI construction.

    Uses the first configured witness OOBI base URL.
    """
    if WITNESS_OOBI_BASE_URLS:
        return WITNESS_OOBI_BASE_URLS[0]
    # Fallback for development
    return "http://localhost:5642"


@router.post(
    "/create",
    response_model=CreateVVPResponse,
    responses={
        400: {"model": ErrorResponse, "description": "Invalid request"},
        404: {"model": ErrorResponse, "description": "Identity not found"},
        500: {"model": ErrorResponse, "description": "Signing failed"},
    },
)
async def create_vvp_attestation(
    body: CreateVVPRequest,
    principal: Principal = require_auth,
) -> CreateVVPResponse:
    """Create VVP-Identity header and PASSporT for a telephone call.

    Creates both artifacts required for VVP attestation:
    - VVP-Identity header (base64url-encoded JSON)
    - PASSporT JWT (signed with Ed25519, PSS CESR signature format)

    Both share the same iat/exp timestamps and kid/evd references to ensure
    binding per §5.2A.

    **Authentication:** Requires `issuer:operator` role or `org:dossier_manager` role.

    **Phone Number Format:** E.164 (e.g., "+14155551234")

    **Validity:** exp_seconds capped at 300 per §5.2B normative requirement.

    **Dossier URL:** Auto-generated as {ISSUER_BASE_URL}/dossier/{dossier_said}
    The dossier must exist and be accessible at that URL for verifier fetch.
    """
    # Check authorization (accepts issuer:operator+ OR org:dossier_manager+)
    check_credential_write_role(principal)

    try:
        # Get identity info
        identity_mgr = await get_identity_manager()
        identity = await identity_mgr.get_identity_by_name(body.identity_name)
        if identity is None:
            raise HTTPException(
                status_code=404,
                detail=f"Identity not found: {body.identity_name}",
            )

        # Construct URLs
        issuer_base_url = _get_issuer_base_url()
        witness_url = _get_witness_url()

        issuer_oobi = build_issuer_oobi(identity.aid, witness_url)
        dossier_url = build_dossier_url(body.dossier_said, issuer_base_url)

        # Cap exp_seconds to normative maximum (§5.2B)
        exp_seconds = min(body.exp_seconds, MAX_VALIDITY_SECONDS)

        # Create VVP-Identity header (this sets iat/exp)
        vvp_header = create_vvp_identity_header(
            issuer_oobi=issuer_oobi,
            dossier_url=dossier_url,
            exp_seconds=exp_seconds,
        )

        # Create PASSporT with SAME iat/exp for binding (§5.2A)
        passport = await create_passport(
            identity_name=body.identity_name,
            issuer_oobi=issuer_oobi,
            orig_tn=body.orig_tn,
            dest_tn=body.dest_tn,
            dossier_url=dossier_url,
            iat=vvp_header.iat,
            exp=vvp_header.exp,
        )

        log.info(
            f"Created VVP attestation: identity={body.identity_name}, "
            f"orig={body.orig_tn}, dossier={body.dossier_said[:16]}..."
        )

        return CreateVVPResponse(
            vvp_identity_header=vvp_header.encoded,
            passport_jwt=passport.jwt,
            dossier_url=dossier_url,
            kid_oobi=issuer_oobi,
            iat=vvp_header.iat,
            exp=vvp_header.exp,
        )

    except InvalidPhoneNumberError as e:
        log.warning(f"Invalid phone number: {e}")
        raise HTTPException(status_code=400, detail=str(e))

    except IdentityNotAvailableError as e:
        log.warning(f"Identity not available: {e}")
        raise HTTPException(status_code=404, detail=str(e))

    except VVPCreationError as e:
        log.error(f"VVP creation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

    except Exception as e:
        log.exception(f"Unexpected error creating VVP attestation: {e}")
        raise HTTPException(status_code=500, detail=f"Internal error: {e}")
