"""Registry management endpoints.

Sprint 68b: Migrated from direct app.keri.* imports to KeriAgentClient.
All KERI operations are delegated to the KERI Agent service. Witness
publishing is handled internally by the agent during registry creation.
"""
import logging

from fastapi import APIRouter, HTTPException, Request

from app.api.models import (
    CreateRegistryRequest,
    CreateRegistryResponse,
    DeleteResponse,
    RegistryResponse,
    RegistryListResponse,
)
from app.auth.api_key import Principal
from app.auth.roles import require_admin, require_readonly
from app.audit import get_audit_logger
from app.keri_client import get_keri_client, KeriAgentUnavailableError
from common.vvp.models.keri_agent import (
    CreateRegistryRequest as AgentCreateRegistryRequest,
)

log = logging.getLogger(__name__)
router = APIRouter(prefix="/registry", tags=["registry"])


def _agent_to_issuer_registry(agent_reg) -> RegistryResponse:
    """Map agent RegistryResponse DTO to issuer RegistryResponse model."""
    return RegistryResponse(
        registry_key=agent_reg.registry_key,
        name=agent_reg.name,
        issuer_aid=agent_reg.identity_aid,
        created_at=None,  # Agent doesn't track this
        sequence_number=0,  # Agent doesn't expose this
        no_backers=getattr(agent_reg, 'no_backers', True),
    )


@router.post("", response_model=CreateRegistryResponse)
async def create_registry(
    request: CreateRegistryRequest,
    http_request: Request,
    principal: Principal = require_admin,
) -> CreateRegistryResponse:
    """Create a new credential registry.

    Creates a TEL (Transaction Event Log) registry for tracking
    credential issuance and revocation. The KERI Agent handles
    witness publishing internally.

    Requires: issuer:admin role
    """
    audit = get_audit_logger()

    try:
        client = get_keri_client()

        # Resolve identity name for the agent request
        if request.identity_name:
            identity_name = request.identity_name
            # Verify identity exists
            identity = await client.get_identity(identity_name)
            if identity is None:
                raise HTTPException(
                    status_code=404,
                    detail=f"Identity not found: {identity_name}",
                )
        elif request.issuer_aid:
            # Resolve AID to name
            identity = await client.get_identity_by_aid(request.issuer_aid)
            if identity is None:
                raise HTTPException(
                    status_code=404,
                    detail=f"Identity not found: {request.issuer_aid}",
                )
            identity_name = identity.name
        else:
            raise HTTPException(
                status_code=400,
                detail="Either identity_name or issuer_aid is required",
            )

        # Create registry via KERI Agent
        agent_reg = await client.create_registry(AgentCreateRegistryRequest(
            name=request.name,
            identity_name=identity_name,
            no_backers=request.no_backers,
        ))

        # Audit log the creation
        audit.log_access(
            action="registry.create",
            principal_id=principal.key_id,
            resource=agent_reg.registry_key,
            details={"name": request.name, "issuer_aid": agent_reg.identity_aid},
            request=http_request,
        )

        return CreateRegistryResponse(
            registry=_agent_to_issuer_registry(agent_reg),
            publish_results=None,  # Agent handles publishing internally
        )

    except KeriAgentUnavailableError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except HTTPException:
        raise
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        log.exception(f"Failed to create registry: {e}")
        raise HTTPException(status_code=500, detail="Internal error creating registry")


@router.get("", response_model=RegistryListResponse)
async def list_registries() -> RegistryListResponse:
    """List all managed registries.

    This endpoint is public (no auth required) for UI access.
    """
    try:
        client = get_keri_client()
        agent_registries = await client.list_registries()

        return RegistryListResponse(
            registries=[_agent_to_issuer_registry(r) for r in agent_registries],
            count=len(agent_registries),
        )
    except KeriAgentUnavailableError as e:
        raise HTTPException(status_code=503, detail=str(e))


@router.get("/{registry_key}", response_model=RegistryResponse)
async def get_registry(registry_key: str) -> RegistryResponse:
    """Get registry information by registry key.

    This endpoint is public (no auth required) for UI access.
    """
    try:
        client = get_keri_client()
        agent_reg = await client.get_registry_by_key(registry_key)

        if agent_reg is None:
            raise HTTPException(
                status_code=404,
                detail=f"Registry not found: {registry_key}",
            )

        return _agent_to_issuer_registry(agent_reg)
    except KeriAgentUnavailableError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        log.exception(f"Failed to get registry {registry_key}: {e}")
        raise HTTPException(status_code=500, detail="Internal error getting registry")


@router.delete("/{registry_key}", response_model=DeleteResponse)
async def delete_registry(
    registry_key: str,
    http_request: Request,
    principal: Principal = require_admin,
) -> DeleteResponse:
    """Delete a registry from local storage.

    Note: This only removes the registry from local storage. The registry
    and its TEL events still exist in the KERI ecosystem and cannot be
    truly deleted from the global state.

    Requires: issuer:admin role
    """
    audit = get_audit_logger()

    try:
        client = get_keri_client()

        # Look up registry by key to get name
        agent_reg = await client.get_registry_by_key(registry_key)
        if agent_reg is None:
            raise HTTPException(
                status_code=404,
                detail=f"Registry not found: {registry_key}",
            )

        # Delete via KERI Agent
        await client.delete_registry(agent_reg.name)

        # Audit log the deletion
        audit.log_access(
            action="registry.delete",
            principal_id=principal.key_id,
            resource=registry_key,
            details={"name": agent_reg.name},
            request=http_request,
        )

        return DeleteResponse(
            deleted=True,
            resource_type="registry",
            resource_id=registry_key,
            message=f"Registry '{agent_reg.name}' removed from local storage. Note: The registry still exists in the KERI ecosystem.",
        )

    except KeriAgentUnavailableError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        log.exception(f"Failed to delete registry: {e}")
        raise HTTPException(status_code=500, detail="Internal error deleting registry")
