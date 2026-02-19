"""Identity CRUD endpoints for the KERI Agent.

Sprint 68: KERI Agent Service Extraction.
"""
import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import Response

from common.vvp.models.keri_agent import (
    CreateIdentityRequest,
    IdentityResponse,
    RotateKeysRequest,
    RotationResponse,
)
from app.keri.identity import get_identity_manager
from app.keri.witness import get_witness_publisher
from app.keri.exceptions import (
    IdentityNotFoundError,
    NonTransferableIdentityError,
    InvalidRotationThresholdError,
)
from app.config import WITNESS_OOBI_BASE_URLS

router = APIRouter(prefix="/identities", tags=["identities"])
log = logging.getLogger(__name__)


@router.post("", response_model=IdentityResponse, status_code=201)
async def create_identity(request: CreateIdentityRequest):
    """Create a new KERI identity."""
    mgr = await get_identity_manager()
    try:
        info = await mgr.create_identity(
            name=request.name,
            transferable=request.transferable,
            icount=request.key_count,
            isith=request.key_threshold,
            ncount=request.next_key_count,
            nsith=request.next_threshold,
            metadata=request.metadata,
        )
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))

    return IdentityResponse(
        aid=info.aid,
        name=info.name,
        created_at=info.created_at,
        witness_count=info.witness_count,
        key_count=info.key_count,
        sequence_number=info.sequence_number,
        transferable=info.transferable,
    )


@router.get("", response_model=list[IdentityResponse])
async def list_identities(
    aid: Optional[str] = Query(None, description="Filter by AID"),
):
    """List all managed identities, optionally filtered by AID."""
    mgr = await get_identity_manager()

    if aid:
        info = await mgr.get_identity(aid)
        if info is None:
            return []
        return [
            IdentityResponse(
                aid=info.aid,
                name=info.name,
                created_at=info.created_at,
                witness_count=info.witness_count,
                key_count=info.key_count,
                sequence_number=info.sequence_number,
                transferable=info.transferable,
            )
        ]

    identities = await mgr.list_identities()
    return [
        IdentityResponse(
            aid=info.aid,
            name=info.name,
            created_at=info.created_at,
            witness_count=info.witness_count,
            key_count=info.key_count,
            sequence_number=info.sequence_number,
            transferable=info.transferable,
        )
        for info in identities
    ]


@router.get("/{name}", response_model=IdentityResponse)
async def get_identity(name: str):
    """Get identity by name."""
    mgr = await get_identity_manager()
    info = await mgr.get_identity_by_name(name)
    if info is None:
        raise HTTPException(status_code=404, detail=f"Identity not found: {name}")
    return IdentityResponse(
        aid=info.aid,
        name=info.name,
        created_at=info.created_at,
        witness_count=info.witness_count,
        key_count=info.key_count,
        sequence_number=info.sequence_number,
        transferable=info.transferable,
    )


@router.post("/{name}/rotate", response_model=RotationResponse)
async def rotate_keys(name: str, request: RotateKeysRequest):
    """Rotate identity keys."""
    mgr = await get_identity_manager()
    info = await mgr.get_identity_by_name(name)
    if info is None:
        raise HTTPException(status_code=404, detail=f"Identity not found: {name}")

    try:
        result = await mgr.rotate_identity(
            aid=info.aid,
            next_key_count=request.new_key_count,
            next_threshold=request.new_threshold,
        )
    except IdentityNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except NonTransferableIdentityError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except InvalidRotationThresholdError as e:
        raise HTTPException(status_code=400, detail=str(e))

    return RotationResponse(
        aid=result.aid,
        name=result.name,
        previous_sequence_number=result.previous_sequence_number,
        new_sequence_number=result.new_sequence_number,
        new_key_count=result.new_key_count,
    )


@router.get("/{name}/oobi")
async def get_oobi(name: str):
    """Get OOBI URL for an identity."""
    mgr = await get_identity_manager()
    info = await mgr.get_identity_by_name(name)
    if info is None:
        raise HTTPException(status_code=404, detail=f"Identity not found: {name}")

    if not WITNESS_OOBI_BASE_URLS:
        raise HTTPException(status_code=500, detail="No witness OOBI base URLs configured")

    oobi_url = mgr.get_oobi_url(info.aid, WITNESS_OOBI_BASE_URLS[0])
    return {"aid": info.aid, "name": name, "oobi": oobi_url}


@router.get("/{name}/kel")
async def get_kel(name: str):
    """Get serialized KEL for an identity."""
    mgr = await get_identity_manager()
    info = await mgr.get_identity_by_name(name)
    if info is None:
        raise HTTPException(status_code=404, detail=f"Identity not found: {name}")

    try:
        kel_bytes = await mgr.get_kel_bytes(info.aid)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

    return Response(content=kel_bytes, media_type="application/cesr")


@router.post("/{name}/publish")
async def publish_identity(name: str):
    """Publish identity to witnesses."""
    mgr = await get_identity_manager()
    info = await mgr.get_identity_by_name(name)
    if info is None:
        raise HTTPException(status_code=404, detail=f"Identity not found: {name}")

    try:
        # Use inception msg (not full KEL) — after registry/credential anchoring,
        # getKelIter can return ixn at fn=0 instead of icp, which breaks Phase 2
        # receipt distribution (ixn events have no witness list in "b" field).
        inception_bytes = await mgr.get_inception_msg(info.aid)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

    publisher = get_witness_publisher()
    result = await publisher.publish_oobi(info.aid, inception_bytes, hby=mgr.hby)

    return {
        "aid": info.aid,
        "name": name,
        "success_count": result.success_count,
        "total_count": result.total_count,
        "threshold_met": result.threshold_met,
    }


@router.get("/{name}/witness-status")
async def get_witness_status(name: str):
    """Check whether the identity's inception event has witness receipts.

    Returns witness_receipts_present=True when the LMDB wigs database has
    at least one witness indexed signature for the inception event (sn=0).
    This indicates the identity has been successfully published to and receipted
    by at least one witness.
    """
    from keri.db.dbing import dgKey
    mgr = await get_identity_manager()
    info = await mgr.get_identity_by_name(name)
    if info is None:
        raise HTTPException(status_code=404, detail=f"Identity not found: {name}")

    hab = mgr.hby.habByPre(info.aid)
    if hab is None:
        raise HTTPException(status_code=404, detail=f"HAB not found for: {name}")

    # Use hab.iserder.saidb for inception digest (resilient to LMDB sn=0 corruption)
    icp_digest = hab.iserder.saidb
    dgkey = dgKey(hab.pre.encode("utf-8"), icp_digest)
    wigs = list(hab.db.getWigs(dgkey))
    receipt_count = len(wigs)

    return {
        "aid": info.aid,
        "name": name,
        "witness_receipts_present": receipt_count > 0,
        "receipt_count": receipt_count,
    }


@router.delete("/{name}", status_code=204)
async def delete_identity(name: str):
    """Delete an identity by name."""
    mgr = await get_identity_manager()
    info = await mgr.get_identity_by_name(name)
    if info is None:
        raise HTTPException(status_code=404, detail=f"Identity not found: {name}")

    try:
        await mgr.delete_identity(info.aid)
    except IdentityNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        if "active registry" in str(e).lower():
            raise HTTPException(
                status_code=409,
                detail=f"Cannot delete identity with active registries: {name}",
            )
        raise
