"""Registry management endpoints."""
import logging

from fastapi import APIRouter, HTTPException, Request

from app.api.models import (
    CreateRegistryRequest,
    CreateRegistryResponse,
    RegistryResponse,
    RegistryListResponse,
    WitnessPublishResult,
)
from app.auth.api_key import Principal
from app.auth.roles import require_admin, require_readonly
from app.audit import get_audit_logger
from app.config import WITNESS_IURLS
from app.keri.identity import get_identity_manager
from app.keri.registry import get_registry_manager
from app.keri.witness import get_witness_publisher

log = logging.getLogger(__name__)
router = APIRouter(prefix="/registry", tags=["registry"])


@router.post("", response_model=CreateRegistryResponse)
async def create_registry(
    request: CreateRegistryRequest,
    http_request: Request,
    principal: Principal = require_admin,
) -> CreateRegistryResponse:
    """Create a new credential registry.

    Creates a TEL (Transaction Event Log) registry for tracking
    credential issuance and revocation.

    Requires: issuer:admin role
    """
    identity_mgr = await get_identity_manager()
    registry_mgr = await get_registry_manager()
    audit = get_audit_logger()

    try:
        # Resolve issuer AID from name or AID
        if request.issuer_aid:
            issuer_aid = request.issuer_aid
            # Verify identity exists
            info = await identity_mgr.get_identity(issuer_aid)
            if info is None:
                raise HTTPException(status_code=404, detail=f"Identity not found: {issuer_aid}")
        elif request.identity_name:
            info = await identity_mgr.get_identity_by_name(request.identity_name)
            if info is None:
                raise HTTPException(status_code=404, detail=f"Identity not found: {request.identity_name}")
            issuer_aid = info.aid
        else:
            raise HTTPException(status_code=400, detail="Either identity_name or issuer_aid is required")

        # Create the registry
        registry_info = await registry_mgr.create_registry(
            name=request.name,
            issuer_aid=issuer_aid,
            no_backers=request.no_backers,
        )

        # Publish anchoring IXN event to witnesses
        # Note: Witnesses receipt KEL events (ixn), not TEL events (vcp) directly.
        # The registry vcp is anchored to the issuer's KEL via an ixn event.
        publish_results: list[WitnessPublishResult] | None = None
        if request.publish_to_witnesses and WITNESS_IURLS:
            try:
                # Get the anchoring ixn event from the issuer's KEL
                ixn_bytes = await registry_mgr.get_anchor_ixn_bytes(registry_info.registry_key)
                publisher = get_witness_publisher()
                result = await publisher.publish_event(registry_info.issuer_aid, ixn_bytes)

                publish_results = [
                    WitnessPublishResult(
                        url=wr.url,
                        success=wr.success,
                        error=wr.error,
                    )
                    for wr in result.witnesses
                ]

                if not result.threshold_met:
                    log.warning(
                        f"Witness threshold not met for registry {registry_info.registry_key[:16]}...: "
                        f"{result.success_count}/{result.total_count}"
                    )
            except Exception as e:
                log.error(f"Failed to publish anchor ixn to witnesses: {e}")
                # Don't fail registry creation if witness publishing fails

        # Audit log the creation
        audit.log_access(
            action="registry.create",
            principal_id=principal.key_id,
            resource=registry_info.registry_key,
            details={"name": request.name, "issuer_aid": issuer_aid},
            request=http_request,
        )

        return CreateRegistryResponse(
            registry=RegistryResponse(
                registry_key=registry_info.registry_key,
                name=registry_info.name,
                issuer_aid=registry_info.issuer_aid,
                created_at=registry_info.created_at,
                sequence_number=registry_info.sequence_number,
                no_backers=registry_info.no_backers,
            ),
            publish_results=publish_results,
        )

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        log.exception(f"Failed to create registry: {e}")
        raise HTTPException(status_code=500, detail="Internal error creating registry")


@router.get("", response_model=RegistryListResponse)
async def list_registries() -> RegistryListResponse:
    """List all managed registries.

    This endpoint is public (no auth required) for UI access.
    """
    registry_mgr = await get_registry_manager()
    registries = await registry_mgr.list_registries()

    return RegistryListResponse(
        registries=[
            RegistryResponse(
                registry_key=r.registry_key,
                name=r.name,
                issuer_aid=r.issuer_aid,
                created_at=r.created_at or None,
                sequence_number=r.sequence_number,
                no_backers=r.no_backers,
            )
            for r in registries
        ],
        count=len(registries),
    )


@router.get("/{registry_key}", response_model=RegistryResponse)
async def get_registry(registry_key: str) -> RegistryResponse:
    """Get registry information by registry key.

    This endpoint is public (no auth required) for UI access.
    """
    try:
        registry_mgr = await get_registry_manager()
        info = await registry_mgr.get_registry(registry_key)

        if info is None:
            raise HTTPException(status_code=404, detail=f"Registry not found: {registry_key}")

        return RegistryResponse(
            registry_key=info.registry_key,
            name=info.name,
            issuer_aid=info.issuer_aid,
            created_at=info.created_at or None,
            sequence_number=info.sequence_number,
            no_backers=info.no_backers,
        )
    except HTTPException:
        raise
    except Exception as e:
        log.exception(f"Failed to get registry {registry_key}: {e}")
        raise HTTPException(status_code=500, detail="Internal error getting registry")
