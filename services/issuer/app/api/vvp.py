"""VVP header creation API endpoint.

Creates VVP-Identity headers and signed PASSporT JWTs for telephone calls.
This is the issuer-side implementation per VVP spec §4.1A, §5.0-§5.4, §6.3.1.

Sprint 68c: PASSporT signing delegated to KERI Agent via create_vvp_attestation().
Sprint 76: Per-step timing instrumentation via PhaseTimer.
Sprint 77: Combined /vvp/create-for-tn endpoint — TN lookup + VVP creation in
           one request, halving bcrypt overhead vs two separate calls.
"""

import logging

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db.session import get_db

from app.api.models import CreateVVPFromTNRequest, CreateVVPRequest, CreateVVPResponse, ErrorResponse
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
            # Cache hit — skip identity resolve, brand extraction
            timer.record("cache", 0.0)
            issuer_oobi = cached.issuer_oobi
            dossier_url = cached.dossier_url
            card = cached.card
        else:
            # Cache miss — minimal blocking path.
            # Only resolve identity AID (1 KERI Agent call).
            # Brand extraction runs in background to avoid KERI Agent contention.
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

            # First call: no card (brand extraction deferred to background).
            # Subsequent calls will have the card from the attestation cache.
            card = None

            # Store minimal entry in attestation cache now (no card yet)
            attest_cache.put(
                identity_name=body.identity_name,
                dossier_said=body.dossier_said,
                identity_aid=identity.aid,
                issuer_oobi=issuer_oobi,
                dossier_url=dossier_url,
                card=None,
            )

            # Background: extract brand card and update cache entry
            import asyncio
            asyncio.create_task(
                _background_extract_brand(
                    attest_cache, client, body.identity_name,
                    body.dossier_said, identity.aid, issuer_oobi, dossier_url,
                )
            )

        # Revocation check runs on every request (fast — DossierCache hit on repeat calls)
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
        # Runs on EVERY request (cache hit and miss) because orig_tn varies per call
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


@router.post(
    "/create-for-tn",
    response_model=CreateVVPResponse,
    responses={
        400: {"model": ErrorResponse, "description": "Invalid request or TN not found"},
        403: {"model": ErrorResponse, "description": "Revoked credentials"},
        404: {"model": ErrorResponse, "description": "TN not mapped"},
        500: {"model": ErrorResponse, "description": "Signing failed"},
    },
)
async def create_vvp_attestation_from_tn(
    body: CreateVVPFromTNRequest,
    principal: Principal = require_auth,
    db: Session = Depends(get_db),
) -> CreateVVPResponse:
    """Create VVP attestation using just the originating TN.

    Sprint 77: Combined endpoint that performs TN lookup and VVP creation in a
    single authenticated request. The SIP redirect service can call this instead
    of making two separate requests (/tn/lookup then /vvp/create), which halves
    the bcrypt verification overhead — one auth check via the middleware instead
    of two.

    TN ownership is validated against the org's TN Allocation credentials.
    The dossier SAID and identity name are resolved from the TN mapping.

    **Authentication:** Requires `issuer:operator` or `org:dossier_manager` role.
    """
    from app.tn.lookup import lookup_tn_with_validation

    timer = PhaseTimer()
    timer.start("total")

    check_credential_write_role(principal)

    # Validate orig_tn before doing any lookups
    try:
        validate_e164(body.orig_tn, "orig_tn")
        for i, tn in enumerate(body.dest_tn):
            validate_e164(tn, f"dest_tn[{i}]")
    except InvalidPhoneNumberError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # TN lookup — use the already-authenticated principal's org to avoid a
    # second bcrypt.  We derive the API key from the request headers only if
    # the TN lookup path truly needs it; here we pass "" and let the
    # lookup function use the principal's org_id directly.
    async with timer.aphase("tn_lookup"):
        # Look up TN ownership using the principal's org_id directly,
        # bypassing a second bcrypt verification.
        from app.tn.store import TNMappingStore
        from app.db.models import Organization

        tn = body.orig_tn
        if not tn.startswith("+"):
            tn = f"+{tn}"

        org_id = principal.organization_id

        # Direct TN mapping lookup (no auth — principal already authenticated)
        store = TNMappingStore(db)
        mapping = store.get_by_tn(tn, org_id) if org_id else None
        owner_org_id = org_id

        if not mapping and org_id:
            # OSP delegation fallback
            from app.tn.lookup import _lookup_via_osp_delegation
            mapping = _lookup_via_osp_delegation(db, tn, org_id)
            if mapping:
                owner_org_id = mapping.organization_id
                log.info(f"TN {tn} resolved via OSP delegation (combined endpoint)")

        if not mapping:
            raise HTTPException(status_code=404, detail=f"No TN mapping found for {tn}")
        if not mapping.enabled:
            raise HTTPException(status_code=404, detail=f"TN mapping for {tn} is disabled")

        # TN ownership validation
        from app.tn.lookup import validate_tn_ownership
        if owner_org_id and not await validate_tn_ownership(db, owner_org_id, tn):
            raise HTTPException(
                status_code=403,
                detail=f"TN {tn} not covered by organization's TN Allocation credentials",
            )

        identity_name = mapping.identity_name
        dossier_said = mapping.dossier_said

    if not identity_name or not dossier_said:
        raise HTTPException(status_code=400, detail="TN mapping is missing identity or dossier")

    # Delegate to the core VVP creation logic via a synthetic CreateVVPRequest
    vvp_body = CreateVVPRequest(
        identity_name=identity_name,
        dossier_said=dossier_said,
        orig_tn=body.orig_tn,
        dest_tn=body.dest_tn,
        exp_seconds=body.exp_seconds,
        call_id=body.call_id,
        cseq=body.cseq,
    )

    # Run the core creation logic (shares cache, revocation, signing paths)
    result = await create_vvp_attestation(vvp_body, principal)

    # Merge timing: prepend tn_lookup into the result timing_ms
    if result.timing_ms is not None:
        merged = {"tn_lookup": timer.timings.get("tn_lookup", 0.0)}
        merged.update(result.timing_ms)
        result = result.model_copy(update={"timing_ms": merged})

    log.info(
        f"create-for-tn: tn={tn}, identity={identity_name}, dossier={dossier_said[:16]}..."
    )
    return result


async def _background_extract_brand(
    attest_cache,
    client,
    identity_name: str,
    dossier_said: str,
    identity_aid: str,
    issuer_oobi: str,
    dossier_url: str,
) -> None:
    """Background task: extract brand card from dossier credentials and update cache.

    The first signing call proceeds without brand data (card=None).
    This populates the attestation cache with the card for subsequent calls.
    """
    try:
        from app.dossier.builder import get_dossier_builder

        builder = await get_dossier_builder()
        content = await builder.build(dossier_said, include_tel=False)

        card = None
        for said in content.credential_saids:
            cred_info = await client.get_credential(said)
            if cred_info and cred_info.attributes:
                card = build_card_claim(cred_info.attributes)
                if card is not None:
                    log.info(f"Background brand extraction: card from credential {said[:16]}...")
                    break

        if card is not None:
            # Update the cache entry with the card
            attest_cache.put(
                identity_name=identity_name,
                dossier_said=dossier_said,
                identity_aid=identity_aid,
                issuer_oobi=issuer_oobi,
                dossier_url=dossier_url,
                card=card,
            )
            log.info(f"Background brand extraction complete: {identity_name}")
        else:
            log.info(f"Background brand extraction: no card found for {dossier_said[:16]}...")
    except Exception as e:
        log.warning(f"Background brand extraction failed: {e}")
