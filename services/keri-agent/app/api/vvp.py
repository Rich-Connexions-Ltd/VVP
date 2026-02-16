"""VVP attestation creation endpoint for the KERI Agent.

The /vvp/create endpoint does everything: get identity, build dossier,
extract card claim, create VVP-Identity header, sign PASSporT JWT.
This keeps all signing in one service.

Sprint 68: KERI Agent Service Extraction.
"""
import logging
import time

from fastapi import APIRouter, HTTPException

from common.vvp.models.keri_agent import (
    CreateVVPAttestationRequest,
    VVPAttestationResponse,
)
from app.config import VVP_ISSUER_BASE_URL, WITNESS_OOBI_BASE_URLS
from app.keri.identity import get_identity_manager
from app.keri.issuer import get_credential_issuer
from app.dossier.builder import get_dossier_builder
from app.vvp.card import build_card_claim
from app.vvp.header import create_vvp_identity_header
from app.vvp.oobi import build_issuer_oobi, build_dossier_url
from app.vvp.identity import build_identity_header
from app.vvp.passport import create_passport
from app.vvp.exceptions import VVPCreationError

router = APIRouter(prefix="/vvp", tags=["vvp"])
log = logging.getLogger(__name__)


@router.post("/create", response_model=VVPAttestationResponse)
async def create_vvp_attestation(request: CreateVVPAttestationRequest):
    """Create a VVP attestation (PASSporT + VVP-Identity header).

    This is the complete attestation flow:
    1. Resolve signing identity
    2. Build dossier from root credential
    3. Extract brand card claim from dossier
    4. Create VVP-Identity header
    5. Sign PASSporT JWT
    6. Build RFC 8224 Identity header
    """
    # 1. Resolve signing identity
    identity_mgr = await get_identity_manager()
    id_info = await identity_mgr.get_identity_by_name(request.identity_name)
    if id_info is None:
        raise HTTPException(
            status_code=404,
            detail=f"Signing identity not found: {request.identity_name}",
        )

    # 2. Build OOBI URL for the signing identity
    if not WITNESS_OOBI_BASE_URLS:
        raise HTTPException(
            status_code=500,
            detail="No witness OOBI base URLs configured",
        )
    issuer_oobi = build_issuer_oobi(id_info.aid, WITNESS_OOBI_BASE_URLS[0])

    # 3. Build dossier URL
    dossier_url = build_dossier_url(request.dossier_said, VVP_ISSUER_BASE_URL)

    # 4. Build dossier and extract card claim
    card = None
    try:
        builder = await get_dossier_builder()
        dossier = await builder.build(request.dossier_said)

        # Find brand credential and extract card claim
        issuer = await get_credential_issuer()
        for said in dossier.credential_saids:
            cred_info = await issuer.get_credential(said)
            if cred_info and cred_info.attributes:
                card_claim = build_card_claim(cred_info.attributes)
                if card_claim:
                    card = card_claim
                    break
    except Exception as e:
        log.warning(f"Dossier build/card extraction failed (proceeding without card): {e}")

    # 5. Create timestamps
    iat = int(time.time())
    exp_seconds = min(request.exp_seconds, 300)
    exp = iat + exp_seconds

    # 6. Create VVP-Identity header
    vvp_header = create_vvp_identity_header(
        issuer_oobi=issuer_oobi,
        dossier_url=dossier_url,
        iat=iat,
        exp_seconds=exp_seconds,
    )

    # 7. Sign PASSporT JWT
    try:
        passport = await create_passport(
            identity_name=request.identity_name,
            issuer_oobi=issuer_oobi,
            orig_tn=request.orig_tn,
            dest_tn=[request.dest_tn],
            dossier_url=dossier_url,
            iat=iat,
            exp=exp,
            card=card,
            call_id=request.call_id,
            cseq=int(request.cseq) if request.cseq else None,
        )
    except VVPCreationError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # 8. Build RFC 8224 Identity header
    identity_header = build_identity_header(passport.jwt, issuer_oobi)

    return VVPAttestationResponse(
        vvp_identity_header=vvp_header.encoded,
        passport_jwt=passport.jwt,
        identity_header=identity_header,
        dossier_url=dossier_url,
        kid_oobi=issuer_oobi,
        iat=iat,
        exp=exp,
    )
