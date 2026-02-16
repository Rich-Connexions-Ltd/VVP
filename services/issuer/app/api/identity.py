"""Identity management endpoints.

Sprint 68b: Migrated from direct app.keri.* imports to KeriAgentClient.
All KERI operations are delegated to the KERI Agent service. Witness
publishing is handled internally by the agent during identity creation
and rotation.
"""
import logging

from fastapi import APIRouter, HTTPException, Request

from app.api.models import (
    CreateIdentityRequest,
    CreateIdentityResponse,
    DeleteResponse,
    IdentityResponse,
    IdentityListResponse,
    OobiResponse,
    RotateIdentityRequest,
    RotateIdentityResponse,
)
from app.auth.api_key import Principal
from app.auth.roles import require_admin, require_readonly
from app.audit import get_audit_logger
from app.keri_client import get_keri_client, KeriAgentUnavailableError
from common.vvp.models.keri_agent import (
    CreateIdentityRequest as AgentCreateIdentityRequest,
    RotateKeysRequest,
)

log = logging.getLogger(__name__)
router = APIRouter(prefix="/identity", tags=["identity"])


def _agent_to_issuer_identity(agent_id) -> IdentityResponse:
    """Map agent IdentityResponse DTO to issuer IdentityResponse model."""
    return IdentityResponse(
        aid=agent_id.aid,
        name=agent_id.name,
        created_at=agent_id.created_at,
        witness_count=agent_id.witness_count,
        key_count=agent_id.key_count,
        sequence_number=agent_id.sequence_number,
        transferable=agent_id.transferable,
    )


async def _resolve_aid(client, aid: str):
    """Resolve AID to agent identity. Raises 404 if not found."""
    identity = await client.get_identity_by_aid(aid)
    if identity is None:
        raise HTTPException(status_code=404, detail=f"Identity not found: {aid}")
    return identity


@router.post("", response_model=CreateIdentityResponse)
async def create_identity(
    request: CreateIdentityRequest,
    http_request: Request,
    principal: Principal = require_admin,
) -> CreateIdentityResponse:
    """Create a new KERI identity.

    Creates an identity with the specified parameters. The KERI Agent
    handles witness publishing internally during creation.

    Requires: issuer:admin role
    """
    audit = get_audit_logger()

    try:
        client = get_keri_client()

        # Build agent request with defaults for optional fields
        agent_req = AgentCreateIdentityRequest(
            name=request.name,
            transferable=request.transferable,
            key_count=request.key_count or 1,
            key_threshold=request.key_threshold or "1",
            next_key_count=request.next_key_count or 1,
            next_threshold=request.next_threshold or "1",
        )

        # Create identity via KERI Agent
        agent_identity = await client.create_identity(agent_req)

        # Get OOBI URL from agent
        oobi_urls = []
        try:
            oobi = await client.get_oobi(agent_identity.name)
            if oobi:
                oobi_urls = [oobi]
        except Exception:
            log.debug(f"Could not get OOBI for {agent_identity.name}")

        # Audit log the creation
        audit.log_access(
            action="identity.create",
            principal_id=principal.key_id,
            resource=agent_identity.aid,
            details={"name": request.name},
            request=http_request,
        )

        return CreateIdentityResponse(
            identity=_agent_to_issuer_identity(agent_identity),
            oobi_urls=oobi_urls,
            publish_results=None,  # Agent handles publishing internally
        )

    except KeriAgentUnavailableError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except HTTPException:
        raise
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        log.error(f"Failed to create identity: {e}")
        raise HTTPException(status_code=500, detail="Internal error creating identity")


@router.get("", response_model=IdentityListResponse)
async def list_identities() -> IdentityListResponse:
    """List all managed identities.

    This endpoint is public (no auth required) for UI access.
    """
    try:
        client = get_keri_client()
        agent_identities = await client.list_identities()

        return IdentityListResponse(
            identities=[_agent_to_issuer_identity(i) for i in agent_identities],
            count=len(agent_identities),
        )
    except KeriAgentUnavailableError as e:
        raise HTTPException(status_code=503, detail=str(e))


@router.get("/{aid}", response_model=IdentityResponse)
async def get_identity(aid: str) -> IdentityResponse:
    """Get identity information by AID.

    This endpoint is public (no auth required) for UI access.
    """
    try:
        client = get_keri_client()
        identity = await _resolve_aid(client, aid)
        return _agent_to_issuer_identity(identity)
    except KeriAgentUnavailableError as e:
        raise HTTPException(status_code=503, detail=str(e))


@router.get("/{aid}/oobi", response_model=OobiResponse)
async def get_oobi(aid: str) -> OobiResponse:
    """Get OOBI URLs for an identity.

    This endpoint is public (no auth required) for UI access.
    """
    try:
        client = get_keri_client()
        identity = await _resolve_aid(client, aid)

        oobi_urls = []
        try:
            oobi = await client.get_oobi(identity.name)
            if oobi:
                oobi_urls = [oobi]
        except Exception:
            log.debug(f"Could not get OOBI for {identity.name}")

        return OobiResponse(aid=aid, oobi_urls=oobi_urls)
    except KeriAgentUnavailableError as e:
        raise HTTPException(status_code=503, detail=str(e))


@router.post("/{aid}/rotate", response_model=RotateIdentityResponse)
async def rotate_identity(
    aid: str,
    request: RotateIdentityRequest,
    http_request: Request,
    principal: Principal = require_admin,
) -> RotateIdentityResponse:
    """Rotate the keys for an identity.

    The KERI Agent handles witness publishing internally during rotation.

    Requires: issuer:admin role

    Raises:
        404: Identity not found
        400: Non-transferable identity or invalid threshold
        503: KERI Agent unavailable
    """
    audit = get_audit_logger()

    try:
        client = get_keri_client()
        identity = await _resolve_aid(client, aid)

        # Perform rotation via KERI Agent
        rotation = await client.rotate_keys(
            identity.name,
            RotateKeysRequest(
                new_key_count=request.next_key_count,
                new_threshold=request.next_threshold,
            ),
        )

        # Audit log the rotation
        audit.log_access(
            action="identity.rotate",
            principal_id=principal.key_id,
            resource=aid,
            details={
                "previous_sn": rotation.previous_sequence_number,
                "new_sn": rotation.new_sequence_number,
            },
            request=http_request,
        )

        # Get updated identity info from agent
        updated = await client.get_identity_by_aid(aid)
        if updated is None:
            updated = identity  # Fallback

        return RotateIdentityResponse(
            identity=_agent_to_issuer_identity(updated),
            previous_sequence_number=rotation.previous_sequence_number,
            publish_results=None,  # Agent handles publishing internally
            publish_threshold_met=True,  # Agent handles internally
        )

    except KeriAgentUnavailableError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"Failed to rotate identity: {e}")
        raise HTTPException(status_code=500, detail="Internal error rotating identity")


@router.delete("/{aid}", response_model=DeleteResponse)
async def delete_identity(
    aid: str,
    http_request: Request,
    principal: Principal = require_admin,
) -> DeleteResponse:
    """Delete an identity from local storage.

    Note: This only removes the identity from local storage. The identity
    still exists in the KERI ecosystem (witnesses, watchers, etc.) and
    cannot be truly deleted from the global state.

    Requires: issuer:admin role
    """
    audit = get_audit_logger()

    try:
        client = get_keri_client()
        identity = await _resolve_aid(client, aid)

        # Delete via KERI Agent
        await client.delete_identity(identity.name)

        # Audit log the deletion
        audit.log_access(
            action="identity.delete",
            principal_id=principal.key_id,
            resource=aid,
            details={"name": identity.name},
            request=http_request,
        )

        return DeleteResponse(
            deleted=True,
            resource_type="identity",
            resource_id=aid,
            message=f"Identity '{identity.name}' removed from local storage. Note: The identity still exists in the KERI ecosystem.",
        )

    except KeriAgentUnavailableError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"Failed to delete identity: {e}")
        raise HTTPException(status_code=500, detail="Internal error deleting identity")
