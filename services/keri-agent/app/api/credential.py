"""Credential issue/revoke/list/get endpoints for the KERI Agent.

Sprint 68: KERI Agent Service Extraction.
"""
import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import Response

from common.vvp.models.keri_agent import (
    IssueCredentialRequest,
    CredentialResponse,
    RevokeCredentialRequest,
)
from app.keri.issuer import get_credential_issuer
from app.keri.identity import get_identity_manager
from app.keri.witness import get_witness_publisher

router = APIRouter(prefix="/credentials", tags=["credentials"])
log = logging.getLogger(__name__)


def _info_to_response(info) -> CredentialResponse:
    """Convert CredentialInfo to CredentialResponse."""
    return CredentialResponse(
        said=info.said,
        issuer_aid=info.issuer_aid,
        recipient_aid=info.recipient_aid,
        registry_key=info.registry_key,
        schema_said=info.schema_said,
        issuance_dt=info.issuance_dt,
        status=info.status,
        revocation_dt=info.revocation_dt,
        attributes=info.attributes,
        edges=info.edges,
        rules=info.rules,
    )


@router.post("/issue", response_model=CredentialResponse, status_code=201)
async def issue_credential(request: IssueCredentialRequest):
    """Issue a new ACDC credential."""
    issuer = await get_credential_issuer()
    identity_mgr = await get_identity_manager()

    # Verify identity exists
    id_info = await identity_mgr.get_identity_by_name(request.identity_name)
    if id_info is None:
        raise HTTPException(
            status_code=404,
            detail=f"Identity not found: {request.identity_name}",
        )

    try:
        info, acdc_bytes = await issuer.issue_credential(
            registry_name=request.registry_name,
            schema_said=request.schema_said,
            attributes=request.attributes,
            recipient_aid=request.recipient_aid,
            edges=request.edges,
            rules=request.rules,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Publish to witnesses if requested
    if request.publish:
        try:
            publisher = get_witness_publisher()
            anchor_bytes = await issuer.get_anchor_ixn_bytes(info.said)
            await publisher.publish_event(id_info.aid, anchor_bytes)
        except Exception as e:
            log.warning(f"Failed to publish credential to witnesses: {e}")

    return _info_to_response(info)


@router.post("/{said}/revoke", response_model=CredentialResponse)
async def revoke_credential(said: str, request: RevokeCredentialRequest):
    """Revoke an issued credential."""
    issuer = await get_credential_issuer()

    try:
        info = await issuer.revoke_credential(said)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        # keripy raises LikelyDuplicitousError for already-revoked credentials
        if "Duplicitous" in type(e).__name__ or "already revoked" in str(e).lower():
            raise HTTPException(status_code=400, detail=f"Credential already revoked: {said}")
        raise

    # Publish revocation to witnesses if requested
    if request.publish:
        try:
            publisher = get_witness_publisher()
            anchor_bytes = await issuer.get_anchor_ixn_bytes(said)
            await publisher.publish_event(info.issuer_aid, anchor_bytes)
        except Exception as e:
            log.warning(f"Failed to publish revocation to witnesses: {e}")

    return _info_to_response(info)


@router.get("", response_model=list[CredentialResponse])
async def list_credentials(
    registry_key: Optional[str] = Query(None, description="Filter by registry key"),
    status: Optional[str] = Query(None, description="Filter by status (issued/revoked)"),
):
    """List credentials with optional filtering."""
    issuer = await get_credential_issuer()
    credentials = await issuer.list_credentials(
        registry_key=registry_key,
        status=status,
    )
    return [_info_to_response(c) for c in credentials]


@router.get("/{said}", response_model=CredentialResponse)
async def get_credential(said: str):
    """Get credential detail by SAID."""
    issuer = await get_credential_issuer()
    info = await issuer.get_credential(said)
    if info is None:
        raise HTTPException(status_code=404, detail=f"Credential not found: {said}")
    return _info_to_response(info)


@router.get("/{said}/cesr")
async def get_credential_cesr(said: str):
    """Get CESR-encoded credential with SealSourceTriples attachment."""
    issuer = await get_credential_issuer()
    cesr_bytes = await issuer.get_credential_bytes(said)
    if cesr_bytes is None:
        raise HTTPException(status_code=404, detail=f"Credential not found: {said}")
    return Response(content=cesr_bytes, media_type="application/cesr")


@router.delete("/{said}", status_code=204)
async def delete_credential(said: str):
    """Delete a credential from local storage."""
    issuer = await get_credential_issuer()
    info = await issuer.get_credential(said)
    if info is None:
        raise HTTPException(status_code=404, detail=f"Credential not found: {said}")

    try:
        await issuer.delete_credential(said)
    except Exception as e:
        log.error(f"Failed to delete credential {said}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to delete credential: {e}")
