"""Registry CRUD endpoints for the KERI Agent.

Sprint 68: KERI Agent Service Extraction.
"""
import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import Response

from common.vvp.models.keri_agent import (
    CreateRegistryRequest,
    RegistryResponse,
)
from app.keri.registry import get_registry_manager
from app.keri.identity import get_identity_manager

router = APIRouter(prefix="/registries", tags=["registries"])
log = logging.getLogger(__name__)


@router.post("", response_model=RegistryResponse, status_code=201)
async def create_registry(request: CreateRegistryRequest):
    """Create a new credential registry."""
    mgr = await get_registry_manager()
    identity_mgr = await get_identity_manager()

    # Resolve identity name to AID
    info = await identity_mgr.get_identity_by_name(request.identity_name)
    if info is None:
        raise HTTPException(
            status_code=404,
            detail=f"Identity not found: {request.identity_name}",
        )

    try:
        registry_info = await mgr.create_registry(
            name=request.name,
            issuer_aid=info.aid,
        )
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))

    return RegistryResponse(
        registry_key=registry_info.registry_key,
        name=registry_info.name,
        identity_aid=info.aid,
        identity_name=request.identity_name,
        credential_count=0,
    )


@router.get("", response_model=list[RegistryResponse])
async def list_registries(
    registry_key: Optional[str] = Query(None, description="Filter by registry key"),
):
    """List all managed registries, optionally filtered by registry key."""
    mgr = await get_registry_manager()
    identity_mgr = await get_identity_manager()

    if registry_key:
        reg = await mgr.get_registry(registry_key)
        if reg is None:
            return []
        id_info = await identity_mgr.get_identity(reg.issuer_aid)
        identity_name = id_info.name if id_info else ""
        try:
            from app.keri.issuer import get_credential_issuer
            issuer = await get_credential_issuer()
            creds = await issuer.list_credentials(registry_key=reg.registry_key)
            cred_count = len(creds)
        except Exception:
            cred_count = 0
        return [RegistryResponse(
            registry_key=reg.registry_key,
            name=reg.name,
            identity_aid=reg.issuer_aid,
            identity_name=identity_name,
            credential_count=cred_count,
        )]

    registries = await mgr.list_registries()

    result = []
    for reg in registries:
        # Resolve AID to name
        id_info = await identity_mgr.get_identity(reg.issuer_aid)
        identity_name = id_info.name if id_info else ""

        # Count credentials in this registry
        issuer = None
        try:
            from app.keri.issuer import get_credential_issuer
            issuer = await get_credential_issuer()
            creds = await issuer.list_credentials(registry_key=reg.registry_key)
            cred_count = len(creds)
        except Exception:
            cred_count = 0

        result.append(RegistryResponse(
            registry_key=reg.registry_key,
            name=reg.name,
            identity_aid=reg.issuer_aid,
            identity_name=identity_name,
            credential_count=cred_count,
        ))
    return result


@router.get("/{name}", response_model=RegistryResponse)
async def get_registry(name: str):
    """Get registry by name."""
    mgr = await get_registry_manager()
    identity_mgr = await get_identity_manager()

    reg = await mgr.get_registry_by_name(name)
    if reg is None:
        raise HTTPException(status_code=404, detail=f"Registry not found: {name}")

    id_info = await identity_mgr.get_identity(reg.issuer_aid)
    identity_name = id_info.name if id_info else ""

    try:
        from app.keri.issuer import get_credential_issuer
        issuer = await get_credential_issuer()
        creds = await issuer.list_credentials(registry_key=reg.registry_key)
        cred_count = len(creds)
    except Exception:
        cred_count = 0

    return RegistryResponse(
        registry_key=reg.registry_key,
        name=reg.name,
        identity_aid=reg.issuer_aid,
        identity_name=identity_name,
        credential_count=cred_count,
    )


@router.get("/{name}/tel")
async def get_tel(name: str):
    """Get serialized TEL inception event for a registry."""
    mgr = await get_registry_manager()

    reg = await mgr.get_registry_by_name(name)
    if reg is None:
        raise HTTPException(status_code=404, detail=f"Registry not found: {name}")

    try:
        tel_bytes = await mgr.get_tel_bytes(reg.registry_key)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

    return Response(content=tel_bytes, media_type="application/cesr")


@router.delete("/{name}")
async def delete_registry(name: str):
    """Delete a registry from local storage.

    Sprint 68b: Added for issuer migration.
    Note: This only removes the registry locally. TEL events in the
    KERI ecosystem cannot be truly deleted.
    """
    mgr = await get_registry_manager()

    reg = await mgr.get_registry_by_name(name)
    if reg is None:
        raise HTTPException(status_code=404, detail=f"Registry not found: {name}")

    await mgr.delete_registry(reg.registry_key)
    return {"deleted": True, "name": name, "registry_key": reg.registry_key}
