"""VVP header creation API endpoint.

Creates VVP-Identity headers and signed PASSporT JWTs for telephone calls.
This is the issuer-side implementation per VVP spec §4.1A, §5.0-§5.4, §6.3.1.

Sprint 68c: PASSporT signing delegated to KERI Agent via create_vvp_attestation().
Sprint 76: Per-step timing instrumentation via PhaseTimer.
"""

import logging

from fastapi import APIRouter, HTTPException

from app.api.models import CreateVVPRequest, CreateVVPResponse, ErrorResponse
from app.auth.api_key import Principal
from app.auth.roles import check_credential_write_role, require_auth
from app.keri_client import get_keri_client, KeriAgentUnavailableError
from common.vvp.dossier.trust import TrustDecision
from common.vvp.models.keri_agent import CreateVVPAttestationRequest
from common.vvp.timing import PhaseTimer

from app.vvp.attestation_cache import get_attestation_cache
from app.vvp.card import build_card_claim
from app.vvp.dossier_service import check_dossier_revocation
from app.vvp.exceptions import (
    IdentityNotAvailableError,
    InvalidPhoneNumberError,
    VVPCreationError,
)
from app.vvp.oobi import build_dossier_url, build_issuer_oobi
from app.vvp.passport import validate_e164
from app.config import WITNESS_OOBI_BASE_URLS, VVP_ISSUER_BASE_URL

log = logging.getLogger(__name__)

# §5.2B: PASSporT validity capped at 300 seconds
MAX_VALIDITY_SECONDS = 300

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
        403: {"model": ErrorResponse, "description": "Revoked credentials"},
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

    **Revocation Checking:** Before signing, checks credential revocation
    status from cache. If any credential in the chain is revoked, returns 403.
    The ``revocation_status`` field indicates the check result:
    - "TRUSTED": Credentials active or status still pending (safe to sign)
    - Response 403: Revoked credentials detected (signing rejected)
    """
    # Sprint 76: Per-step timing instrumentation
    timer = PhaseTimer()
    timer.start("total")

    # Check authorization (accepts issuer:operator+ OR org:dossier_manager+)
    check_credential_write_role(principal)

    try:
        # Validate phone numbers before sending to agent
        validate_e164(body.orig_tn, "orig_tn")
        for i, tn in enumerate(body.dest_tn):
            validate_e164(tn, f"dest_tn[{i}]")

        if not body.dest_tn:
            raise InvalidPhoneNumberError("dest_tn must have at least one phone number")

        # Sprint 76: Check attestation cache for intermediate results
        client = get_keri_client()
        attest_cache = get_attestation_cache()
        cached = attest_cache.get(body.identity_name, body.dossier_said)

        if cached is not None:
            # Cache hit — skip identity resolve, revocation, constraints, brand extraction
            timer.record("cache", 0.0)
            issuer_oobi = cached.issuer_oobi
            dossier_url = cached.dossier_url
            card = cached.card

            # Still check revocation (fast — DossierCache hit)
            async with timer.aphase("revocation_check"):
                trust, revocation_warning = await check_dossier_revocation(
                    dossier_url=dossier_url,
                    dossier_said=body.dossier_said,
                )
            if trust == TrustDecision.UNTRUSTED:
                log.warning(
                    f"Rejecting VVP creation - revoked credentials: {body.dossier_said}"
                )
                raise HTTPException(
                    status_code=403,
                    detail="Credential chain contains revoked credentials",
                )
        else:
            # Cache miss — full computation path
            # Get identity info via KERI Agent
            async with timer.aphase("identity_resolve"):
                identity = await client.get_identity(body.identity_name)
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

            # Check dossier revocation status before signing
            async with timer.aphase("revocation_check"):
                trust, revocation_warning = await check_dossier_revocation(
                    dossier_url=dossier_url,
                    dossier_said=body.dossier_said,
                )

            if trust == TrustDecision.UNTRUSTED:
                log.warning(
                    f"Rejecting VVP creation - revoked credentials: {body.dossier_said}"
                )
                raise HTTPException(
                    status_code=403,
                    detail="Credential chain contains revoked credentials",
                )

            if revocation_warning:
                log.info(f"VVP creation proceeding with warning: {revocation_warning}")

            # Sprint 62: Signing-time vetter constraint validation (ECC + jurisdiction)
            from app.vetter.constraints import validate_signing_constraints
            from app.config import ENFORCE_VETTER_CONSTRAINTS

            async with timer.aphase("signing_constraints"):
                signing_violations = await validate_signing_constraints(
                    orig_tn=body.orig_tn,
                    dossier_said=body.dossier_said,
                )
            failed_constraints = [v for v in signing_violations if not v.is_authorized]
            if failed_constraints:
                detail = "; ".join(
                    f"{v.credential_type} {v.check_type}: {v.reason}"
                    for v in failed_constraints
                )
                if ENFORCE_VETTER_CONSTRAINTS:
                    raise HTTPException(
                        status_code=403,
                        detail=f"Signing constraint violation: {detail}",
                    )
                else:
                    log.warning(f"Signing constraint warning (soft): {detail}")

            # Sprint 58: Extract brand attributes for vCard card claim.
            card = None
            try:
                from app.dossier.builder import get_dossier_builder

                async with timer.aphase("brand_extraction"):
                    builder = await get_dossier_builder()
                    content = await builder.build(body.dossier_said, include_tel=False)

                    for said in content.credential_saids:
                        cred_info = await client.get_credential(said)
                        if cred_info and cred_info.attributes:
                            card = build_card_claim(cred_info.attributes)
                            if card is not None:
                                log.debug(f"Card claim from credential {said[:16]}...")
                                break
            except Exception as e:
                log.warning(f"Failed to extract card claim from credentials: {e}")

            # Store in attestation cache for next call
            attest_cache.put(
                identity_name=body.identity_name,
                dossier_said=body.dossier_said,
                identity_aid=identity.aid,
                issuer_oobi=issuer_oobi,
                dossier_url=dossier_url,
                card=card,
            )

        # Cap exp_seconds to normative maximum (§5.2B)
        exp_seconds = min(body.exp_seconds, MAX_VALIDITY_SECONDS)

        # Delegate PASSporT signing + header creation to KERI Agent
        async with timer.aphase("attestation_signing"):
            attestation = await client.create_vvp_attestation(
                CreateVVPAttestationRequest(
                    identity_name=body.identity_name,
                    dossier_said=body.dossier_said,
                    orig_tn=body.orig_tn,
                    dest_tn=body.dest_tn,
                    exp_seconds=exp_seconds,
                    call_id=body.call_id,
                    cseq=str(body.cseq) if body.cseq is not None else None,
                    card=card,
                    dossier_url=dossier_url,
                    kid_oobi=issuer_oobi,
                )
            )

        timer.stop()  # total
        timing_dict = timer.to_dict()

        log.info(
            f"Created VVP attestation: identity={body.identity_name}, "
            f"orig={body.orig_tn}, dossier={body.dossier_said[:16]}... "
            f"timing=[{timer.to_log_str()}]"
        )

        return CreateVVPResponse(
            vvp_identity_header=attestation.vvp_identity_header,
            passport_jwt=attestation.passport_jwt,
            identity_header=attestation.identity_header,
            dossier_url=attestation.dossier_url,
            kid_oobi=attestation.kid_oobi,
            iat=attestation.iat,
            exp=attestation.exp,
            revocation_status=trust.value,
            timing_ms=timing_dict,
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

    except KeriAgentUnavailableError as e:
        log.warning(f"KERI agent unavailable during VVP creation: {e}")
        raise HTTPException(status_code=503, detail=str(e))

    except HTTPException:
        # Re-raise intentional HTTPException responses (404, 403, etc.)
        # so they are not swallowed by the generic handler below.
        raise

    except Exception as e:
        log.exception(f"Unexpected error creating VVP attestation: {e}")
        raise HTTPException(status_code=500, detail=f"Internal error: {e}")
