"""Organization management endpoints.

Sprint 41: Multi-tenant organization management with mock vLEI credentials.
"""

import logging
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.auth.api_key import Principal
from app.auth.roles import require_admin, require_auth
from app.api.models import OrganizationNameListResponse, OrganizationNameResponse
from app.audit import get_audit_logger
from app.db.session import get_db
from app.db.models import Organization, ManagedCredential, OrgType
from app.config import MOCK_VLEI_ENABLED
from app.keri_client import KeriAgentUnavailableError
from app.org.lei_generator import generate_pseudo_lei
from app.org.mock_vlei import get_mock_vlei_manager

log = logging.getLogger(__name__)
router = APIRouter(prefix="/organizations", tags=["organizations"])


# =============================================================================
# Request/Response Models
# =============================================================================


class CreateOrganizationRequest(BaseModel):
    """Request to create a new organization."""

    name: str = Field(..., min_length=1, max_length=255, description="Organization name")


class OrganizationResponse(BaseModel):
    """Response containing organization information."""

    id: str = Field(..., description="Organization ID (UUID)")
    name: str = Field(..., description="Organization name")
    pseudo_lei: str = Field(..., description="Pseudo-LEI (20 characters)")
    aid: Optional[str] = Field(None, description="KERI AID for the organization")
    le_credential_said: Optional[str] = Field(
        None, description="Legal Entity credential SAID"
    )
    registry_key: Optional[str] = Field(None, description="TEL registry prefix")
    vetter_certification_said: Optional[str] = Field(
        None, description="Active VetterCertification SAID"
    )
    org_type: str = Field("regular", description="Organization type: root_authority, qvi, vetter_authority, regular")
    enabled: bool = Field(..., description="Whether the organization is enabled")
    created_at: str = Field(..., description="Creation timestamp (ISO8601)")
    updated_at: str = Field(..., description="Last update timestamp (ISO8601)")


class OrganizationListResponse(BaseModel):
    """Response containing a list of organizations."""

    count: int = Field(..., description="Total number of organizations")
    organizations: list[OrganizationResponse] = Field(
        ..., description="List of organizations"
    )


class UpdateOrganizationRequest(BaseModel):
    """Request to update an organization."""

    model_config = {"extra": "forbid"}

    name: Optional[str] = Field(None, min_length=1, max_length=255)
    enabled: Optional[bool] = Field(None)


# =============================================================================
# Endpoints
# =============================================================================


@router.post("", response_model=OrganizationResponse)
async def create_organization(
    body: CreateOrganizationRequest,
    http_request: Request,
    principal: Principal = require_admin,
    db: Session = Depends(get_db),
) -> OrganizationResponse:
    """Create a new organization with mock vLEI credentials.

    Creates:
    - Organization record with pseudo-LEI
    - KERI identity (AID) for the organization
    - Credential registry for the organization
    - Legal Entity credential from mock-qvi

    **Authentication:** Requires `issuer:admin` role.
    """
    audit = get_audit_logger()

    # Check for duplicate name
    existing = db.query(Organization).filter(Organization.name == body.name).first()
    if existing:
        raise HTTPException(status_code=409, detail="Organization name already exists")

    # Generate org ID and pseudo-LEI
    org_id = str(uuid.uuid4())
    pseudo_lei = generate_pseudo_lei(body.name, org_id)

    # Create organization record first (without KERI data)
    org = Organization(
        id=org_id,
        name=body.name,
        pseudo_lei=pseudo_lei,
        enabled=True,
    )
    db.add(org)
    db.flush()  # Get the ID assigned

    # Create KERI identity and credentials if mock vLEI is enabled
    if MOCK_VLEI_ENABLED:
        try:
            from app.keri_client import get_keri_client
            from common.vvp.models.keri_agent import (
                CreateIdentityRequest as AgentCreateIdentityRequest,
                CreateRegistryRequest as AgentCreateRegistryRequest,
            )

            client = get_keri_client()
            mock_vlei = get_mock_vlei_manager()

            # Create KERI identity for org via agent
            org_identity_name = f"org-{org_id[:8]}"
            org_identity = await client.create_identity(AgentCreateIdentityRequest(
                name=org_identity_name,
                transferable=True,
            ))
            org.aid = org_identity.aid
            log.info(f"Created org identity: {org_identity.aid[:16]}...")

            # Agent handles witness publishing internally during create_identity

            # Create credential registry for org via agent
            org_registry_name = f"{org_identity_name}-registry"
            org_registry = await client.create_registry(AgentCreateRegistryRequest(
                name=org_registry_name,
                identity_name=org_identity_name,
            ))
            org.registry_key = org_registry.registry_key
            log.info(f"Created org registry: {org_registry.registry_key[:16]}...")

            # Issue LE credential from mock-qvi
            le_cred_said = await mock_vlei.issue_le_credential(
                org_name=body.name,
                org_aid=org_identity.aid,
                pseudo_lei=pseudo_lei,
            )
            org.le_credential_said = le_cred_said
            log.info(f"Issued LE credential: {le_cred_said[:16]}...")

            # Record the LE credential as managed by this org
            from app.org.trust_anchors import get_trust_anchor_manager
            tam_state = get_trust_anchor_manager().get_mock_vlei_state()
            managed_cred = ManagedCredential(
                said=le_cred_said,
                organization_id=org_id,
                schema_said="ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY",
                issuer_aid=tam_state.qvi_aid if tam_state else "",
            )
            db.add(managed_cred)

        except KeriAgentUnavailableError as e:
            log.warning(f"KERI agent unavailable during org creation: {e}")
            raise HTTPException(status_code=503, detail=str(e))
        except RuntimeError as e:
            # Trust-anchor state not ready (bootstrap probe hasn't synced yet)
            if "not initialized" in str(e).lower():
                log.warning(f"Trust anchor not ready during org creation: {e}")
                raise HTTPException(status_code=503, detail=str(e))
            raise HTTPException(
                status_code=500,
                detail=f"Failed to create KERI infrastructure: {str(e)}",
            )
        except Exception as e:
            log.exception(f"Failed to create KERI infrastructure for org: {e}")
            raise HTTPException(
                status_code=500,
                detail=f"Failed to create KERI infrastructure: {str(e)}",
            )

    db.commit()
    db.refresh(org)

    audit.log(
        action="organization.create",
        principal=principal.key_id,
        resource_type="organization",
        resource_id=org_id,
        details={"name": body.name, "pseudo_lei": pseudo_lei},
    )

    log.info(f"Created organization: {body.name} ({org_id[:8]}...)")

    return OrganizationResponse(
        id=org.id,
        name=org.name,
        pseudo_lei=org.pseudo_lei,
        aid=org.aid,
        le_credential_said=org.le_credential_said,
        registry_key=org.registry_key,
        vetter_certification_said=org.vetter_certification_said,
        org_type=org.org_type or "regular",
        enabled=org.enabled,
        created_at=org.created_at.isoformat(),
        updated_at=org.updated_at.isoformat(),
    )


@router.get("", response_model=OrganizationListResponse)
async def list_organizations(
    principal: Principal = require_admin,
    db: Session = Depends(get_db),
) -> OrganizationListResponse:
    """List all organizations.

    **Authentication:** Requires `issuer:admin` role.
    """
    orgs = db.query(Organization).order_by(Organization.created_at.desc()).all()

    return OrganizationListResponse(
        count=len(orgs),
        organizations=[
            OrganizationResponse(
                id=org.id,
                name=org.name,
                pseudo_lei=org.pseudo_lei,
                aid=org.aid,
                le_credential_said=org.le_credential_said,
                registry_key=org.registry_key,
                vetter_certification_said=org.vetter_certification_said,
                org_type=org.org_type or "regular",
                enabled=org.enabled,
                created_at=org.created_at.isoformat(),
                updated_at=org.updated_at.isoformat(),
            )
            for org in orgs
        ],
    )


@router.get("/names", response_model=OrganizationNameListResponse)
async def list_organization_names(
    purpose: str = Query("ap", description="Purpose: 'ap' for AP selection, 'osp' for OSP selection"),
    principal: Principal = require_auth,
    db: Session = Depends(get_db),
) -> OrganizationNameListResponse:
    """List organization names (lightweight: id, name, and AID).

    Sprint 63: Used by the dossier creation wizard for org dropdowns.
    Sprint 65: Added AID field for recipient-org selection in credential edge UI.

    Scoping depends on purpose:
    - ``purpose=ap`` (default): Admin sees all enabled orgs; non-admin sees own org only.
    - ``purpose=osp``: All authenticated users see all enabled orgs (org names are not
      sensitive; server-side validation enforces association consistency).

    **Authentication:** Any authenticated user.
    """
    if purpose not in ("ap", "osp"):
        raise HTTPException(status_code=400, detail=f"Invalid purpose: {purpose}. Use 'ap' or 'osp'.")

    if purpose == "osp" or principal.is_system_admin:
        orgs = (
            db.query(Organization.id, Organization.name, Organization.aid)
            .filter(Organization.enabled == True)  # noqa: E712
            .order_by(Organization.name)
            .all()
        )
    else:
        orgs = (
            db.query(Organization.id, Organization.name, Organization.aid)
            .filter(
                Organization.id == principal.organization_id,
                Organization.enabled == True,  # noqa: E712
            )
            .all()
        )

    # AID is only exposed for 'ap' purpose (needed for recipient-org selection
    # in credential edge UI). OSP purpose returns id + name only.
    include_aid = purpose == "ap"
    return OrganizationNameListResponse(
        organizations=[
            OrganizationNameResponse(
                id=o.id, name=o.name, aid=o.aid if include_aid else None
            )
            for o in orgs
        ],
        count=len(orgs),
    )


@router.get("/{org_id}", response_model=OrganizationResponse)
async def get_organization(
    org_id: str,
    principal: Principal = require_auth,
    db: Session = Depends(get_db),
) -> OrganizationResponse:
    """Get organization by ID.

    **Authentication:** Requires:
    - `issuer:admin` or `issuer:readonly` system role, OR
    - Membership in the organization (any org role)
    """
    org = db.query(Organization).filter(Organization.id == org_id).first()
    if org is None:
        raise HTTPException(status_code=404, detail="Organization not found")

    # Sprint 41: Check access - system roles OR org membership
    has_system_access = (
        "issuer:admin" in principal.roles or
        "issuer:readonly" in principal.roles or
        "issuer:operator" in principal.roles
    )
    is_org_member = principal.organization_id == org_id

    if not has_system_access and not is_org_member:
        raise HTTPException(
            status_code=403,
            detail="Access denied. Requires system role or organization membership.",
        )

    return OrganizationResponse(
        id=org.id,
        name=org.name,
        pseudo_lei=org.pseudo_lei,
        aid=org.aid,
        le_credential_said=org.le_credential_said,
        registry_key=org.registry_key,
        vetter_certification_said=org.vetter_certification_said,
        org_type=org.org_type or "regular",
        enabled=org.enabled,
        created_at=org.created_at.isoformat(),
        updated_at=org.updated_at.isoformat(),
    )


@router.patch("/{org_id}", response_model=OrganizationResponse)
async def update_organization(
    org_id: str,
    body: UpdateOrganizationRequest,
    http_request: Request,
    principal: Principal = require_admin,
    db: Session = Depends(get_db),
) -> OrganizationResponse:
    """Update an organization.

    **Authentication:** Requires `issuer:admin` role.
    """
    audit = get_audit_logger()

    org = db.query(Organization).filter(Organization.id == org_id).first()
    if org is None:
        raise HTTPException(status_code=404, detail="Organization not found")

    changes = {}
    if body.name is not None and body.name != org.name:
        # Check for duplicate name
        existing = db.query(Organization).filter(
            Organization.name == body.name,
            Organization.id != org_id,
        ).first()
        if existing:
            raise HTTPException(status_code=409, detail="Organization name already exists")
        changes["name"] = {"old": org.name, "new": body.name}
        org.name = body.name

    if body.enabled is not None and body.enabled != org.enabled:
        changes["enabled"] = {"old": org.enabled, "new": body.enabled}
        org.enabled = body.enabled

    if changes:
        db.commit()
        db.refresh(org)

        audit.log(
            action="organization.update",
            principal=principal.key_id,
            resource_type="organization",
            resource_id=org_id,
            details={"changes": changes},
        )
        log.info(f"Updated organization: {org_id[:8]}... - {list(changes.keys())}")

    return OrganizationResponse(
        id=org.id,
        name=org.name,
        pseudo_lei=org.pseudo_lei,
        aid=org.aid,
        le_credential_said=org.le_credential_said,
        registry_key=org.registry_key,
        vetter_certification_said=org.vetter_certification_said,
        org_type=org.org_type or "regular",
        enabled=org.enabled,
        created_at=org.created_at.isoformat(),
        updated_at=org.updated_at.isoformat(),
    )
