"""VetterCertification API endpoints.

Sprint 61: CRUD for VetterCertification credentials + constraint visibility.
"""

import logging

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.auth.api_key import Principal
from app.auth.roles import require_auth, check_credential_admin_role
from app.db.session import get_db
from app.db.models import ManagedCredential, Organization
from app.api.models import (
    OrganizationConstraintsResponse,
    VetterCertificationCreateRequest,
    VetterCertificationListResponse,
    VetterCertificationResponse,
)
from app.vetter.constants import VETTER_CERT_SCHEMA_SAID
from app.vetter.service import (
    _resolve_cert_attributes,
    get_org_constraints,
    issue_vetter_certification,
    revoke_vetter_certification,
)

log = logging.getLogger(__name__)
router = APIRouter(tags=["vetter-certifications"])


@router.post("/vetter-certifications", response_model=VetterCertificationResponse)
async def create_vetter_certification(
    body: VetterCertificationCreateRequest,
    principal: Principal = require_auth,
    db: Session = Depends(get_db),
) -> VetterCertificationResponse:
    """Issue a VetterCertification credential for an organization.

    **Authentication:** Requires `issuer:admin` or `org:administrator` role.
    """
    check_credential_admin_role(principal)
    result = await issue_vetter_certification(
        db=db,
        organization_id=body.organization_id,
        ecc_targets=body.ecc_targets,
        jurisdiction_targets=body.jurisdiction_targets,
        name=body.name,
        certification_expiry=body.certification_expiry,
    )
    return VetterCertificationResponse(**result)


@router.get("/vetter-certifications", response_model=VetterCertificationListResponse)
async def list_vetter_certifications(
    organization_id: str = Query(None, description="Filter by organization ID"),
    principal: Principal = require_auth,
    db: Session = Depends(get_db),
) -> VetterCertificationListResponse:
    """List VetterCertification credentials.

    **Authentication:** Requires `issuer:admin` or `org:administrator` role.
    """
    check_credential_admin_role(principal)
    query = db.query(ManagedCredential).filter(
        ManagedCredential.schema_said == VETTER_CERT_SCHEMA_SAID
    )
    if organization_id:
        query = query.filter(ManagedCredential.organization_id == organization_id)

    managed_creds = query.order_by(ManagedCredential.created_at.desc()).all()

    certifications = []
    for mc in managed_creds:
        org = db.query(Organization).filter(Organization.id == mc.organization_id).first()
        attrs = await _resolve_cert_attributes(mc.said)
        certifications.append(
            VetterCertificationResponse(
                said=mc.said,
                issuer_aid=mc.issuer_aid,
                vetter_aid=org.aid if org else "",
                organization_id=mc.organization_id,
                organization_name=org.name if org else "",
                ecc_targets=attrs["ecc_targets"],
                jurisdiction_targets=attrs["jurisdiction_targets"],
                name=attrs["name"],
                certification_expiry=attrs["certification_expiry"],
                status=attrs["status"],
                created_at=mc.created_at.isoformat(),
            )
        )

    return VetterCertificationListResponse(
        certifications=certifications,
        count=len(certifications),
    )


@router.get(
    "/vetter-certifications/{said}",
    response_model=VetterCertificationResponse,
)
async def get_vetter_certification(
    said: str,
    principal: Principal = require_auth,
    db: Session = Depends(get_db),
) -> VetterCertificationResponse:
    """Get a VetterCertification by SAID.

    **Authentication:** System role (admin/readonly/operator) can read any cert.
    Org-scoped principals can only read certs linked to their own org.
    """
    managed = (
        db.query(ManagedCredential)
        .filter(
            ManagedCredential.said == said,
            ManagedCredential.schema_said == VETTER_CERT_SCHEMA_SAID,
        )
        .first()
    )
    if managed is None:
        raise HTTPException(status_code=404, detail="VetterCertification not found")

    # Authorization: system roles can read any; org principals only their own
    has_system_role = (
        "issuer:admin" in principal.roles
        or "issuer:readonly" in principal.roles
        or "issuer:operator" in principal.roles
    )
    if not has_system_role:
        if principal.organization_id != managed.organization_id:
            raise HTTPException(
                status_code=403,
                detail="Access denied. You can only view your organization's certifications.",
            )

    org = db.query(Organization).filter(Organization.id == managed.organization_id).first()
    attrs = await _resolve_cert_attributes(managed.said)

    return VetterCertificationResponse(
        said=managed.said,
        issuer_aid=managed.issuer_aid,
        vetter_aid=org.aid if org else "",
        organization_id=managed.organization_id,
        organization_name=org.name if org else "",
        ecc_targets=attrs["ecc_targets"],
        jurisdiction_targets=attrs["jurisdiction_targets"],
        name=attrs["name"],
        certification_expiry=attrs["certification_expiry"],
        status=attrs["status"],
        created_at=managed.created_at.isoformat(),
    )


@router.delete(
    "/vetter-certifications/{said}",
    response_model=VetterCertificationResponse,
)
async def delete_vetter_certification(
    said: str,
    principal: Principal = require_auth,
    db: Session = Depends(get_db),
) -> VetterCertificationResponse:
    """Revoke a VetterCertification.

    **Authentication:** Requires `issuer:admin` or `org:administrator` role.
    """
    check_credential_admin_role(principal)
    result = await revoke_vetter_certification(db=db, said=said)
    return VetterCertificationResponse(**result)


@router.get(
    "/organizations/{org_id}/constraints",
    response_model=OrganizationConstraintsResponse,
)
async def get_organization_constraints(
    org_id: str,
    principal: Principal = require_auth,
    db: Session = Depends(get_db),
) -> OrganizationConstraintsResponse:
    """Get vetter constraints for an organization.

    **Authentication:** System role OR organization membership.
    """
    # Access check (same as GET /organizations/{org_id})
    has_system_access = (
        "issuer:admin" in principal.roles
        or "issuer:readonly" in principal.roles
        or "issuer:operator" in principal.roles
    )
    is_org_member = principal.organization_id == org_id

    if not has_system_access and not is_org_member:
        raise HTTPException(
            status_code=403,
            detail="Access denied. Requires system role or organization membership.",
        )

    result = await get_org_constraints(db=db, organization_id=org_id)
    return OrganizationConstraintsResponse(**result)


@router.get(
    "/users/me/constraints",
    response_model=OrganizationConstraintsResponse,
)
async def get_my_constraints(
    principal: Principal = require_auth,
    db: Session = Depends(get_db),
) -> OrganizationConstraintsResponse:
    """Get vetter constraints for the current user's organization.

    **Authentication:** Any authenticated user.
    """
    if not principal.organization_id:
        raise HTTPException(
            status_code=404,
            detail="No organization associated with current user.",
        )

    result = await get_org_constraints(db=db, organization_id=principal.organization_id)
    return OrganizationConstraintsResponse(**result)
