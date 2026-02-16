"""Dossier build/get endpoints for the KERI Agent.

Sprint 68: KERI Agent Service Extraction.
"""
import logging

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response

from common.vvp.models.keri_agent import (
    BuildDossierRequest,
    DossierResponse,
)
from app.dossier.builder import get_dossier_builder
from app.dossier.exceptions import DossierBuildError

router = APIRouter(prefix="/dossiers", tags=["dossiers"])
log = logging.getLogger(__name__)

# In-memory cache for built dossiers (SAID -> DossierContent)
_dossier_cache: dict[str, object] = {}


@router.post("/build", response_model=DossierResponse, status_code=201)
async def build_dossier(request: BuildDossierRequest):
    """Build a dossier from a credential chain."""
    builder = await get_dossier_builder()

    try:
        if request.root_saids and len(request.root_saids) > 1:
            content = await builder.build_aggregate(
                root_saids=request.root_saids,
                include_tel=request.include_tel,
            )
        else:
            content = await builder.build(
                root_said=request.root_said,
                include_tel=request.include_tel,
            )
    except DossierBuildError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        log.error(f"Dossier build failed: {e}")
        raise HTTPException(status_code=500, detail=f"Dossier build failed: {e}")

    # Cache the built dossier for GET retrieval
    _dossier_cache[content.root_said] = content

    return DossierResponse(
        root_said=content.root_said,
        root_saids=content.root_saids,
        credential_saids=content.credential_saids,
        is_aggregate=content.is_aggregate,
        warnings=content.warnings,
    )


@router.get("/{said}", response_model=DossierResponse)
async def get_dossier(said: str):
    """Get a previously built dossier by root SAID."""
    content = _dossier_cache.get(said)
    if content is None:
        raise HTTPException(status_code=404, detail=f"Dossier not found: {said}")

    return DossierResponse(
        root_said=content.root_said,
        root_saids=content.root_saids,
        credential_saids=content.credential_saids,
        is_aggregate=content.is_aggregate,
        warnings=content.warnings,
    )


@router.get("/{said}/cesr")
async def get_dossier_cesr(said: str):
    """Get dossier as concatenated CESR stream."""
    content = _dossier_cache.get(said)
    if content is None:
        raise HTTPException(status_code=404, detail=f"Dossier not found: {said}")

    # Concatenate all credential CESR bytes + TEL events
    cesr_stream = bytearray()
    for cred_said in content.credential_saids:
        if cred_said in content.credentials:
            cesr_stream.extend(content.credentials[cred_said])
        if cred_said in content.tel_events:
            cesr_stream.extend(content.tel_events[cred_said])

    return Response(content=bytes(cesr_stream), media_type="application/cesr")
