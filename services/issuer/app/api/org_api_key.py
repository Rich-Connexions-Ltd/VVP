"""Organization API key management endpoints.

Sprint 41: API keys scoped to organizations for programmatic access.
"""

import logging
import secrets
import uuid
from typing import Optional

import bcrypt
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.auth.api_key import Principal
from app.auth.roles import require_auth
from app.audit import get_audit_logger
from app.db.session import get_db
from app.db.models import Organization, OrgAPIKey, OrgAPIKeyRole

log = logging.getLogger(__name__)
router = APIRouter(prefix="/organizations/{org_id}/api-keys", tags=["org-api-keys"])


# =============================================================================
# Request/Response Models
# =============================================================================


class CreateOrgAPIKeyRequest(BaseModel):
    """Request to create an organization API key."""

    name: str = Field(..., min_length=1, max_length=255, description="Key name")
    roles: list[str] = Field(
        ...,
        min_length=1,
        description="Roles for the key (org:administrator, org:dossier_manager)",
    )


class OrgAPIKeyResponse(BaseModel):
    """Response containing organization API key information."""

    id: str = Field(..., description="Key ID (UUID)")
    name: str = Field(..., description="Key name")
    roles: list[str] = Field(..., description="Assigned roles")
    organization_id: str = Field(..., description="Organization ID")
    revoked: bool = Field(..., description="Whether the key is revoked")
    created_at: str = Field(..., description="Creation timestamp (ISO8601)")


class OrgAPIKeyCreatedResponse(OrgAPIKeyResponse):
    """Response from API key creation, includes the raw key."""

    raw_key: str = Field(
        ...,
        description="The raw API key (only shown once, store securely)",
    )


class OrgAPIKeyListResponse(BaseModel):
    """Response containing a list of organization API keys."""

    count: int = Field(..., description="Total number of keys")
    api_keys: list[OrgAPIKeyResponse] = Field(..., description="List of API keys")


# =============================================================================
# Helper Functions
# =============================================================================


VALID_ORG_ROLES = {"org:administrator", "org:dossier_manager"}


def validate_org_roles(roles: list[str]) -> None:
    """Validate that all roles are valid organization roles."""
    invalid_roles = set(roles) - VALID_ORG_ROLES
    if invalid_roles:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid organization roles: {invalid_roles}. Valid roles: {VALID_ORG_ROLES}",
        )


def generate_api_key() -> tuple[str, str]:
    """Generate a new API key and its bcrypt hash.

    Returns:
        Tuple of (raw_key, hashed_key)
    """
    # Generate a secure random key (32 bytes = 256 bits)
    raw_key = secrets.token_urlsafe(32)
    # Hash with bcrypt
    hashed = bcrypt.hashpw(raw_key.encode(), bcrypt.gensalt(rounds=12))
    return raw_key, hashed.decode()


def _check_org_admin_access(
    principal: Principal,
    org_id: str,
    db: Session,
) -> Organization:
    """Check that the principal has admin access to the organization.

    System admins (issuer:admin) can access any org.
    Org admins (org:administrator) can only access their own org.

    Returns the Organization if access is granted.
    Raises HTTPException if access denied or org not found.
    """
    org = db.query(Organization).filter(Organization.id == org_id).first()
    if org is None:
        raise HTTPException(status_code=404, detail="Organization not found")

    # System admins can access any org
    if "issuer:admin" in principal.roles:
        return org

    # Sprint 41: Check org:administrator role for own org
    if (
        principal.organization_id == org_id and
        "org:administrator" in principal.roles
    ):
        return org

    raise HTTPException(
        status_code=403,
        detail="Insufficient permissions. Requires issuer:admin or org:administrator role.",
    )


# =============================================================================
# Endpoints
# =============================================================================


@router.post("", response_model=OrgAPIKeyCreatedResponse)
async def create_org_api_key(
    org_id: str,
    body: CreateOrgAPIKeyRequest,
    http_request: Request,
    principal: Principal = require_auth,
    db: Session = Depends(get_db),
) -> OrgAPIKeyCreatedResponse:
    """Create a new API key for an organization.

    The raw API key is returned ONLY in this response.
    Store it securely - it cannot be retrieved later.

    **Authentication:** Requires `issuer:admin` role or `org:administrator` for the org.
    """
    audit = get_audit_logger()

    # Validate access and get org
    org = _check_org_admin_access(principal, org_id, db)

    # Validate roles
    validate_org_roles(body.roles)

    # Generate key
    raw_key, hashed_key = generate_api_key()
    key_id = str(uuid.uuid4())

    # Create key record
    api_key = OrgAPIKey(
        id=key_id,
        name=body.name,
        key_hash=hashed_key,
        key_prefix=raw_key[:8],
        organization_id=org_id,
        revoked=False,
    )
    db.add(api_key)

    # Add roles
    for role in body.roles:
        role_record = OrgAPIKeyRole(
            key_id=key_id,
            role=role,
        )
        db.add(role_record)

    db.commit()
    db.refresh(api_key)

    audit.log(
        action="org_api_key.create",
        principal=principal.key_id,
        resource_type="org_api_key",
        resource_id=key_id,
        details={"name": body.name, "org_id": org_id, "roles": body.roles},
    )

    log.info(f"Created org API key: {body.name} for org {org_id[:8]}...")

    return OrgAPIKeyCreatedResponse(
        id=api_key.id,
        name=api_key.name,
        roles=body.roles,
        organization_id=api_key.organization_id,
        revoked=api_key.revoked,
        created_at=api_key.created_at.isoformat(),
        raw_key=raw_key,
    )


@router.get("", response_model=OrgAPIKeyListResponse)
async def list_org_api_keys(
    org_id: str,
    principal: Principal = require_auth,
    db: Session = Depends(get_db),
) -> OrgAPIKeyListResponse:
    """List all API keys for an organization.

    **Authentication:** Requires `issuer:admin` role or `org:administrator` for the org.
    """
    # Validate access
    _check_org_admin_access(principal, org_id, db)

    # Get keys
    keys = (
        db.query(OrgAPIKey)
        .filter(OrgAPIKey.organization_id == org_id)
        .order_by(OrgAPIKey.created_at.desc())
        .all()
    )

    # Build response with roles
    api_keys = []
    for key in keys:
        roles = [r.role for r in key.roles]
        api_keys.append(
            OrgAPIKeyResponse(
                id=key.id,
                name=key.name,
                roles=roles,
                organization_id=key.organization_id,
                revoked=key.revoked,
                created_at=key.created_at.isoformat(),
            )
        )

    return OrgAPIKeyListResponse(count=len(api_keys), api_keys=api_keys)


@router.get("/{key_id}", response_model=OrgAPIKeyResponse)
async def get_org_api_key(
    org_id: str,
    key_id: str,
    principal: Principal = require_auth,
    db: Session = Depends(get_db),
) -> OrgAPIKeyResponse:
    """Get details of an organization API key.

    **Authentication:** Requires `issuer:admin` role or `org:administrator` for the org.
    """
    # Validate access
    _check_org_admin_access(principal, org_id, db)

    # Get key
    key = (
        db.query(OrgAPIKey)
        .filter(OrgAPIKey.id == key_id, OrgAPIKey.organization_id == org_id)
        .first()
    )
    if key is None:
        raise HTTPException(status_code=404, detail="API key not found")

    roles = [r.role for r in key.roles]

    return OrgAPIKeyResponse(
        id=key.id,
        name=key.name,
        roles=roles,
        organization_id=key.organization_id,
        revoked=key.revoked,
        created_at=key.created_at.isoformat(),
    )


@router.delete("/{key_id}")
async def revoke_org_api_key(
    org_id: str,
    key_id: str,
    http_request: Request,
    principal: Principal = require_auth,
    db: Session = Depends(get_db),
) -> dict:
    """Revoke an organization API key.

    Revoked keys cannot be used for authentication.

    **Authentication:** Requires `issuer:admin` role or `org:administrator` for the org.
    """
    audit = get_audit_logger()

    # Validate access
    _check_org_admin_access(principal, org_id, db)

    # Get key
    key = (
        db.query(OrgAPIKey)
        .filter(OrgAPIKey.id == key_id, OrgAPIKey.organization_id == org_id)
        .first()
    )
    if key is None:
        raise HTTPException(status_code=404, detail="API key not found")

    if key.revoked:
        raise HTTPException(status_code=400, detail="API key is already revoked")

    key.revoked = True
    db.commit()

    audit.log(
        action="org_api_key.revoke",
        principal=principal.key_id,
        resource_type="org_api_key",
        resource_id=key_id,
        details={"name": key.name, "org_id": org_id},
    )

    log.info(f"Revoked org API key: {key.name} ({key_id[:8]}...)")

    return {"success": True, "message": "API key revoked"}
