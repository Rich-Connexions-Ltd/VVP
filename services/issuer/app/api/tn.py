"""TN Mapping API endpoints for SIP redirect signing.

Sprint 42: Maps telephone numbers to dossiers for VVP attestation.
"""

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.api.models import (
    CreateTNMappingRequest,
    UpdateTNMappingRequest,
    TNMappingResponse,
    TNMappingListResponse,
    TNLookupRequest,
    TNLookupResponse,
)
from app.auth.api_key import Principal
from app.auth.roles import (
    require_auth,
    check_credential_access_role,
    check_credential_write_role,
    check_credential_admin_role,
)
from app.auth.scoping import can_access_credential
from app.audit import get_audit_logger
from app.db.session import get_db
from app.db.models import Organization
from app.tn.store import TNMappingStore
from app.tn.lookup import lookup_tn_with_validation

log = logging.getLogger(__name__)
router = APIRouter(prefix="/tn", tags=["tn-mapping"])


def _get_org_or_403(db: Session, principal: Principal) -> Organization:
    """Get principal's organization or raise 403."""
    if not principal.organization_id:
        raise HTTPException(
            status_code=403,
            detail="Organization membership required for TN mapping operations",
        )
    org = db.query(Organization).filter(
        Organization.id == principal.organization_id
    ).first()
    if not org:
        raise HTTPException(status_code=403, detail="Organization not found")
    return org


def _mapping_to_response(mapping) -> TNMappingResponse:
    """Convert TNMapping model to response."""
    return TNMappingResponse(
        id=mapping.id,
        tn=mapping.tn,
        organization_id=mapping.organization_id,
        dossier_said=mapping.dossier_said,
        identity_name=mapping.identity_name,
        brand_name=mapping.brand_name,
        brand_logo_url=mapping.brand_logo_url,
        enabled=mapping.enabled,
        created_at=mapping.created_at.isoformat() if mapping.created_at else "",
        updated_at=mapping.updated_at.isoformat() if mapping.updated_at else "",
    )


async def _extract_brand_info(dossier_said: str) -> tuple[Optional[str], Optional[str]]:
    """Extract brand name and logo URL from dossier credentials.

    Walks the credential chain looking for brand/identity credentials
    that contain brand_name and logo_url attributes.

    Returns:
        Tuple of (brand_name, logo_url), either may be None
    """
    try:
        from app.keri_client import get_keri_client
        client = get_keri_client()

        # Get root credential
        root_cred = await client.get_credential(dossier_said)
        if not root_cred:
            return None, None

        # Look for brand info in root credential attributes
        attrs = root_cred.attributes or {}
        brand_name = (
            attrs.get("brand_name")
            or attrs.get("LEI_name")
            or attrs.get("entityName")
            or attrs.get("name")
        )
        logo_url = attrs.get("logo_url") or attrs.get("brandLogo") or attrs.get("logo")

        return brand_name, logo_url
    except Exception as e:
        log.warning(f"Failed to extract brand info from {dossier_said}: {e}")
        return None, None


@router.post("/mappings", response_model=TNMappingResponse)
async def create_tn_mapping(
    body: CreateTNMappingRequest,
    http_request: Request,
    principal: Principal = require_auth,
    db: Session = Depends(get_db),
) -> TNMappingResponse:
    """Create a TN mapping for SIP redirect signing.

    Maps a telephone number to a dossier and signing identity.

    **Authorization:** Requires org:dossier_manager+ or issuer:operator+ role.
    """
    check_credential_write_role(principal)
    audit = get_audit_logger()

    # Get organization (non-system admins must have org)
    if principal.is_system_admin and not principal.organization_id:
        raise HTTPException(
            status_code=400,
            detail="System admin must specify organization context for TN mappings",
        )
    org = _get_org_or_403(db, principal)

    # Verify dossier access
    if not can_access_credential(db, principal, body.dossier_said):
        raise HTTPException(
            status_code=403,
            detail=f"Access denied to dossier {body.dossier_said[:16]}...",
        )

    # Check for duplicate TN in this org
    store = TNMappingStore(db)
    if store.exists(body.tn, org.id):
        raise HTTPException(
            status_code=409,
            detail=f"TN {body.tn} is already mapped in this organization",
        )

    # Extract brand info from dossier
    brand_name, brand_logo_url = await _extract_brand_info(body.dossier_said)

    # Create mapping
    try:
        mapping = store.create(
            org_id=org.id,
            tn=body.tn,
            dossier_said=body.dossier_said,
            identity_name=body.identity_name,
            brand_name=brand_name,
            brand_logo_url=brand_logo_url,
        )
    except Exception as e:
        log.error(f"Failed to create TN mapping: {e}")
        raise HTTPException(status_code=500, detail="Failed to create TN mapping")

    audit.log(
        action="tn_mapping.create",
        principal=principal.key_id,
        resource_type="tn_mapping",
        resource_id=mapping.id,
        details={"tn": body.tn, "dossier_said": body.dossier_said},
    )

    log.info(f"Created TN mapping: {body.tn} -> {body.dossier_said[:16]}...")
    return _mapping_to_response(mapping)


@router.get("/mappings", response_model=TNMappingListResponse)
async def list_tn_mappings(
    principal: Principal = require_auth,
    db: Session = Depends(get_db),
) -> TNMappingListResponse:
    """List TN mappings for the principal's organization.

    **Authorization:** Requires org:dossier_manager+ or issuer:readonly+ role.
    """
    check_credential_access_role(principal)

    store = TNMappingStore(db)

    # System admins see all, org users see their org's mappings
    if principal.is_system_admin and not principal.organization_id:
        mappings = store.list_all()
    else:
        if not principal.organization_id:
            return TNMappingListResponse(count=0, mappings=[])
        mappings = store.list_by_org(principal.organization_id)

    return TNMappingListResponse(
        count=len(mappings),
        mappings=[_mapping_to_response(m) for m in mappings],
    )


@router.get("/mappings/{mapping_id}", response_model=TNMappingResponse)
async def get_tn_mapping(
    mapping_id: str,
    principal: Principal = require_auth,
    db: Session = Depends(get_db),
) -> TNMappingResponse:
    """Get a specific TN mapping.

    **Authorization:** Requires org membership or system role.
    """
    check_credential_access_role(principal)

    store = TNMappingStore(db)
    mapping = store.get(mapping_id)
    if not mapping:
        raise HTTPException(status_code=404, detail="TN mapping not found")

    # Check org access
    if not principal.is_system_admin and mapping.organization_id != principal.organization_id:
        raise HTTPException(status_code=403, detail="Access denied")

    return _mapping_to_response(mapping)


@router.patch("/mappings/{mapping_id}", response_model=TNMappingResponse)
async def update_tn_mapping(
    mapping_id: str,
    body: UpdateTNMappingRequest,
    http_request: Request,
    principal: Principal = require_auth,
    db: Session = Depends(get_db),
) -> TNMappingResponse:
    """Update a TN mapping.

    **Authorization:** Requires org:dossier_manager+ or issuer:operator+ role.
    """
    check_credential_write_role(principal)
    audit = get_audit_logger()

    store = TNMappingStore(db)
    mapping = store.get(mapping_id)
    if not mapping:
        raise HTTPException(status_code=404, detail="TN mapping not found")

    # Check org access
    if not principal.is_system_admin and mapping.organization_id != principal.organization_id:
        raise HTTPException(status_code=403, detail="Access denied")

    changes = {}

    # Prepare update kwargs
    update_kwargs = {}

    if body.dossier_said is not None and body.dossier_said != mapping.dossier_said:
        # Verify access to new dossier
        if not can_access_credential(db, principal, body.dossier_said):
            raise HTTPException(
                status_code=403,
                detail=f"Access denied to dossier {body.dossier_said[:16]}...",
            )
        changes["dossier_said"] = {"old": mapping.dossier_said, "new": body.dossier_said}
        update_kwargs["dossier_said"] = body.dossier_said
        # Re-extract brand info
        brand_name, brand_logo_url = await _extract_brand_info(body.dossier_said)
        update_kwargs["brand_name"] = brand_name
        update_kwargs["brand_logo_url"] = brand_logo_url

    if body.identity_name is not None and body.identity_name != mapping.identity_name:
        changes["identity_name"] = {"old": mapping.identity_name, "new": body.identity_name}
        update_kwargs["identity_name"] = body.identity_name

    # Allow direct brand_name override (takes precedence over auto-extracted)
    if body.brand_name is not None and body.brand_name != mapping.brand_name:
        changes["brand_name"] = {"old": mapping.brand_name, "new": body.brand_name}
        update_kwargs["brand_name"] = body.brand_name

    # Allow direct brand_logo_url override
    if body.brand_logo_url is not None and body.brand_logo_url != mapping.brand_logo_url:
        changes["brand_logo_url"] = {"old": mapping.brand_logo_url, "new": body.brand_logo_url}
        update_kwargs["brand_logo_url"] = body.brand_logo_url

    if body.enabled is not None and body.enabled != mapping.enabled:
        changes["enabled"] = {"old": mapping.enabled, "new": body.enabled}
        update_kwargs["enabled"] = body.enabled

    if update_kwargs:
        mapping = store.update(mapping_id, **update_kwargs)
        if not mapping:
            raise HTTPException(status_code=500, detail="Failed to update TN mapping")

        audit.log(
            action="tn_mapping.update",
            principal=principal.key_id,
            resource_type="tn_mapping",
            resource_id=mapping_id,
            details={"changes": changes},
        )
        log.info(f"Updated TN mapping {mapping_id[:8]}...")

    return _mapping_to_response(mapping)


@router.delete("/mappings/{mapping_id}")
async def delete_tn_mapping(
    mapping_id: str,
    http_request: Request,
    principal: Principal = require_auth,
    db: Session = Depends(get_db),
) -> dict:
    """Delete a TN mapping.

    **Authorization:** Requires org:administrator or issuer:admin role.
    """
    check_credential_admin_role(principal)
    audit = get_audit_logger()

    store = TNMappingStore(db)
    mapping = store.get(mapping_id)
    if not mapping:
        raise HTTPException(status_code=404, detail="TN mapping not found")

    # Check org access
    if not principal.is_system_admin and mapping.organization_id != principal.organization_id:
        raise HTTPException(status_code=403, detail="Access denied")

    tn = mapping.tn
    if not store.delete(mapping_id):
        raise HTTPException(status_code=500, detail="Failed to delete TN mapping")

    audit.log(
        action="tn_mapping.delete",
        principal=principal.key_id,
        resource_type="tn_mapping",
        resource_id=mapping_id,
        details={"tn": tn},
    )

    log.info(f"Deleted TN mapping: {tn}")

    return {"success": True, "message": f"TN mapping for {tn} deleted"}


@router.post("/lookup", response_model=TNLookupResponse)
async def lookup_tn(
    body: TNLookupRequest,
    db: Session = Depends(get_db),
) -> TNLookupResponse:
    """Internal endpoint for TN lookup from SIP service.

    Authenticates the API key and looks up the TN mapping.
    Returns found=false with error if TN not found for the authenticated org.

    **Note:** This endpoint does its own API key validation since
    it needs to look up the TN scoped to the org owning the key.
    It does NOT require the standard auth middleware.
    """
    result = await lookup_tn_with_validation(
        db=db,
        tn=body.tn,
        api_key=body.api_key,
        validate_ownership=True,  # Enforce TN ownership validation
    )

    return TNLookupResponse(
        found=result.found,
        tn=result.tn,
        organization_id=result.organization_id,
        organization_name=result.organization_name,
        dossier_said=result.dossier_said,
        identity_name=result.identity_name,
        brand_name=result.brand_name,
        brand_logo_url=result.brand_logo_url,
        error=result.error,
    )


@router.post("/test-lookup/{mapping_id}", response_model=TNLookupResponse)
async def test_tn_lookup(
    mapping_id: str,
    principal: Principal = require_auth,
    db: Session = Depends(get_db),
) -> TNLookupResponse:
    """Test TN lookup for a specific mapping using session auth.

    This endpoint allows UI users to verify their TN mapping configuration
    without requiring an API key. Session auth proves org membership.

    Unlike /tn/lookup (used by SIP Redirect), this endpoint:
    - Uses session auth instead of API key auth
    - Validates the mapping has all required fields
    - Does NOT create an actual attestation

    **Authorization:** Requires org:readonly+ or issuer:readonly+ role.
    """
    check_credential_access_role(principal)
    audit = get_audit_logger()

    # Get the mapping
    store = TNMappingStore(db)
    mapping = store.get(mapping_id)
    if not mapping:
        raise HTTPException(status_code=404, detail="TN mapping not found")

    # Verify org access
    if not principal.is_system_admin and mapping.organization_id != principal.organization_id:
        raise HTTPException(status_code=403, detail="Access denied")

    # Check mapping is enabled
    if not mapping.enabled:
        audit.log(
            action="tn_mapping.test_lookup",
            principal=principal.key_id,
            resource_type="tn_mapping",
            resource_id=mapping_id,
            status="error",
            details={"tn": mapping.tn, "error": "disabled"},
        )
        return TNLookupResponse(
            found=False,
            tn=mapping.tn,
            error="TN mapping is disabled",
        )

    # Validate all required fields are present
    validation_errors = []
    if not mapping.dossier_said:
        validation_errors.append("Missing dossier SAID")
    if not mapping.identity_name:
        validation_errors.append("Missing signing identity")

    # Verify dossier still exists
    if mapping.dossier_said:
        try:
            from app.keri_client import get_keri_client
            client = get_keri_client()
            cred = await client.get_credential(mapping.dossier_said)
            if not cred:
                validation_errors.append(f"Dossier {mapping.dossier_said[:16]}... not found")
        except Exception as e:
            log.warning(f"Failed to verify dossier {mapping.dossier_said[:16]}...: {e}")
            validation_errors.append(f"Could not verify dossier: {str(e)}")

    if validation_errors:
        error_msg = "; ".join(validation_errors)
        audit.log(
            action="tn_mapping.test_lookup",
            principal=principal.key_id,
            resource_type="tn_mapping",
            resource_id=mapping_id,
            status="error",
            details={"tn": mapping.tn, "errors": validation_errors},
        )
        return TNLookupResponse(
            found=False,
            tn=mapping.tn,
            error=error_msg,
        )

    # Get organization name for display
    org = db.query(Organization).filter(Organization.id == mapping.organization_id).first()

    audit.log(
        action="tn_mapping.test_lookup",
        principal=principal.key_id,
        resource_type="tn_mapping",
        resource_id=mapping_id,
        status="success",
        details={"tn": mapping.tn},
    )

    return TNLookupResponse(
        found=True,
        tn=mapping.tn,
        organization_id=mapping.organization_id,
        organization_name=org.name if org else None,
        dossier_said=mapping.dossier_said,
        identity_name=mapping.identity_name,
        brand_name=mapping.brand_name,
        brand_logo_url=mapping.brand_logo_url,
    )
