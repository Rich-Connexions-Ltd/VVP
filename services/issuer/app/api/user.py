"""User management endpoints.

Sprint 41: Database-backed user CRUD with organization scoping.
"""

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.orm import Session

from app.auth.api_key import Principal
from app.auth.roles import require_admin, require_auth
from app.auth.org_roles import OrgRole, validate_org_roles
from app.auth.db_users import get_db_user_store, hash_password
from app.audit import get_audit_logger
from app.db.session import get_db
from app.db.models import User, Organization

log = logging.getLogger(__name__)
router = APIRouter(prefix="/users", tags=["users"])


# =============================================================================
# Request/Response Models
# =============================================================================


class CreateUserRequest(BaseModel):
    """Request to create a new user."""

    email: EmailStr = Field(..., description="User's email address")
    name: str = Field(..., min_length=1, max_length=255, description="Display name")
    password: str | None = Field(
        None,
        min_length=8,
        description="Password (min 8 chars, omit for OAuth users)",
    )
    system_roles: list[str] = Field(
        default=[],
        description="System roles (issuer:admin, issuer:operator, issuer:readonly)",
    )
    org_roles: list[str] = Field(
        default=[],
        description="Organization roles (org:administrator, org:dossier_manager)",
    )
    organization_id: str | None = Field(
        None,
        description="Organization UUID (required for org roles)",
    )
    is_oauth_user: bool = Field(
        default=False,
        description="Whether this is an OAuth-provisioned user (no password)",
    )


class UpdateUserRequest(BaseModel):
    """Request to update a user."""

    name: str | None = Field(None, min_length=1, max_length=255, description="Display name")
    system_roles: list[str] | None = Field(
        None,
        description="System roles (issuer:admin, issuer:operator, issuer:readonly)",
    )
    org_roles: list[str] | None = Field(
        None,
        description="Organization roles (org:administrator, org:dossier_manager)",
    )
    organization_id: str | None = Field(
        None,
        description="Organization UUID",
    )
    enabled: bool | None = Field(None, description="Whether user is enabled")


class ChangePasswordRequest(BaseModel):
    """Request to change password."""

    current_password: str = Field(..., description="Current password for verification")
    new_password: str = Field(..., min_length=8, description="New password (min 8 chars)")


class ResetPasswordRequest(BaseModel):
    """Request to reset a user's password (admin only)."""

    new_password: str = Field(..., min_length=8, description="New password (min 8 chars)")


class UserResponse(BaseModel):
    """User information response."""

    id: str = Field(..., description="User ID (UUID)")
    email: str = Field(..., description="Email address")
    name: str = Field(..., description="Display name")
    system_roles: list[str] = Field(..., description="System roles")
    org_roles: list[str] = Field(..., description="Organization roles")
    organization_id: str | None = Field(..., description="Organization ID")
    organization_name: str | None = Field(None, description="Organization name")
    enabled: bool = Field(..., description="Whether user is enabled")
    is_oauth_user: bool = Field(..., description="Whether user is OAuth-provisioned")
    created_at: str = Field(..., description="Creation timestamp (ISO8601)")


class UserListResponse(BaseModel):
    """Response containing a list of users."""

    count: int = Field(..., description="Total number of users")
    users: list[UserResponse] = Field(..., description="List of users")


class CurrentUserResponse(UserResponse):
    """Current user information with additional context."""

    pass


# =============================================================================
# Helper Functions
# =============================================================================


VALID_SYSTEM_ROLES = {"issuer:admin", "issuer:operator", "issuer:readonly"}


def validate_system_roles(roles: list[str]) -> None:
    """Validate that all roles are valid system roles."""
    invalid_roles = set(roles) - VALID_SYSTEM_ROLES
    if invalid_roles:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid system roles: {invalid_roles}. Valid roles: {VALID_SYSTEM_ROLES}",
        )


def _user_to_response(user: User, org_name: str | None = None) -> UserResponse:
    """Convert a User model to a UserResponse."""
    org_roles = [r.role for r in user.org_roles]
    system_roles = user.system_roles.split(",") if user.system_roles else []

    return UserResponse(
        id=user.id,
        email=user.email,
        name=user.name,
        system_roles=system_roles,
        org_roles=org_roles,
        organization_id=user.organization_id,
        organization_name=org_name,
        enabled=user.enabled,
        is_oauth_user=user.is_oauth_user,
        created_at=user.created_at.isoformat(),
    )


def _get_org_name(db: Session, org_id: str | None) -> str | None:
    """Get organization name by ID."""
    if not org_id:
        return None
    org = db.query(Organization).filter(Organization.id == org_id).first()
    return org.name if org else None


def _check_user_access(
    principal: Principal,
    target_user: User,
    require_admin_for_other: bool = True,
) -> None:
    """Check if principal can access target user.

    Args:
        principal: The authenticated principal
        target_user: The user being accessed
        require_admin_for_other: If True, require admin to access other users

    Raises:
        HTTPException: If access denied
    """
    # System admins can access anyone
    if principal.is_system_admin:
        return

    # Users can access themselves
    if principal.key_id == f"user:{target_user.email}":
        return

    # Org admins can access users in their org
    if (
        principal.organization_id
        and principal.organization_id == target_user.organization_id
        and OrgRole.ADMINISTRATOR.value in principal.roles
    ):
        return

    if require_admin_for_other:
        raise HTTPException(status_code=403, detail="Insufficient permissions")


# =============================================================================
# Endpoints
# =============================================================================


@router.post("", response_model=UserResponse)
async def create_user(
    body: CreateUserRequest,
    http_request: Request,
    principal: Principal = require_admin,
    db: Session = Depends(get_db),
) -> UserResponse:
    """Create a new user.

    **Authentication:** Requires `issuer:admin` role.

    System admins can create users in any organization.
    """
    audit = get_audit_logger()
    store = get_db_user_store()

    # Validate roles
    if body.system_roles:
        validate_system_roles(body.system_roles)
    if body.org_roles:
        validate_org_roles(body.org_roles)

    # Validate organization exists if specified
    if body.organization_id:
        org = db.query(Organization).filter(Organization.id == body.organization_id).first()
        if not org:
            raise HTTPException(status_code=404, detail="Organization not found")

    # OAuth users don't have passwords
    if body.is_oauth_user and body.password:
        raise HTTPException(
            status_code=400,
            detail="OAuth users cannot have a password",
        )

    # Non-OAuth users must have a password
    if not body.is_oauth_user and not body.password:
        raise HTTPException(
            status_code=400,
            detail="Password required for non-OAuth users",
        )

    try:
        user = store.create_user(
            db=db,
            email=body.email,
            name=body.name,
            password=body.password,
            system_roles=body.system_roles,
            org_roles=body.org_roles,
            organization_id=body.organization_id,
            is_oauth_user=body.is_oauth_user,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    audit.log(
        action="user.create",
        principal=principal.key_id,
        resource_type="user",
        resource_id=user.id,
        details={
            "email": user.email,
            "organization_id": body.organization_id,
            "is_oauth_user": body.is_oauth_user,
        },
    )

    org_name = _get_org_name(db, body.organization_id)
    return _user_to_response(user, org_name)


@router.get("", response_model=UserListResponse)
async def list_users(
    organization_id: str | None = None,
    include_disabled: bool = False,
    principal: Principal = require_admin,
    db: Session = Depends(get_db),
) -> UserListResponse:
    """List all users.

    **Authentication:** Requires `issuer:admin` role.

    System admins can see all users across all organizations.
    Filter by organization_id to see only users in a specific org.
    """
    store = get_db_user_store()

    users_data = store.list_users(
        db=db,
        organization_id=organization_id,
        include_disabled=include_disabled,
    )

    # Enrich with org names
    users = []
    for u in users_data:
        org_name = _get_org_name(db, u.get("organization_id"))
        users.append(UserResponse(
            id=u["id"],
            email=u["email"],
            name=u["name"],
            system_roles=u["system_roles"],
            org_roles=u["org_roles"],
            organization_id=u["organization_id"],
            organization_name=org_name,
            enabled=u["enabled"],
            is_oauth_user=u["is_oauth_user"],
            created_at=u["created_at"],
        ))

    return UserListResponse(count=len(users), users=users)


@router.get("/me", response_model=CurrentUserResponse)
async def get_current_user(
    principal: Principal = require_auth,
    db: Session = Depends(get_db),
) -> CurrentUserResponse:
    """Get the current authenticated user's information.

    **Authentication:** Any authenticated user (including org-only principals).
    """
    # Extract email from key_id (format: "user:email@example.com")
    if not principal.key_id.startswith("user:"):
        # API key or other principal type
        return CurrentUserResponse(
            id=principal.key_id,
            email=principal.key_id,
            name=principal.name,
            system_roles=list(principal.roles),
            org_roles=[],
            organization_id=principal.organization_id,
            organization_name=_get_org_name(db, principal.organization_id),
            enabled=True,
            is_oauth_user=False,
            created_at="",
        )

    email = principal.key_id[5:]  # Remove "user:" prefix
    store = get_db_user_store()
    user = store.get_user_by_email(db, email)

    if not user:
        # User not in DB (file-based or OAuth user without DB record) —
        # fall back to Principal info so the profile page still works.
        system_roles = [r for r in principal.roles if r.startswith("issuer:")]
        org_roles = [r for r in principal.roles if r.startswith("org:")]
        return CurrentUserResponse(
            id=principal.key_id,
            email=email,
            name=principal.name,
            system_roles=system_roles,
            org_roles=org_roles,
            organization_id=principal.organization_id,
            organization_name=_get_org_name(db, principal.organization_id),
            enabled=True,
            is_oauth_user=False,
            created_at="",
        )

    org_name = _get_org_name(db, user.organization_id)
    return CurrentUserResponse(**_user_to_response(user, org_name).model_dump())


@router.patch("/me/password")
async def change_own_password(
    body: ChangePasswordRequest,
    http_request: Request,
    principal: Principal = require_auth,
    db: Session = Depends(get_db),
) -> dict:
    """Change the current user's password.

    **Authentication:** Any authenticated user (including org-only principals).

    Requires current password verification.
    """
    audit = get_audit_logger()

    # Extract email from key_id
    if not principal.key_id.startswith("user:"):
        raise HTTPException(
            status_code=400,
            detail="Password change not supported for API key authentication",
        )

    email = principal.key_id[5:]
    store = get_db_user_store()
    user = store.get_user_by_email(db, email)

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.is_oauth_user:
        raise HTTPException(
            status_code=400,
            detail="OAuth users cannot change password",
        )

    # Verify current password
    import bcrypt as bcrypt_lib
    try:
        if not bcrypt_lib.checkpw(
            body.current_password.encode(),
            user.password_hash.encode(),
        ):
            raise HTTPException(status_code=401, detail="Current password is incorrect")
    except Exception:
        raise HTTPException(status_code=401, detail="Current password is incorrect")

    # Update password
    store.change_password(db, user.id, body.new_password)

    audit.log(
        action="user.password_change",
        principal=principal.key_id,
        resource_type="user",
        resource_id=user.id,
        details={"self_change": True},
    )

    return {"success": True, "message": "Password changed successfully"}


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: str,
    principal: Principal = require_auth,
    db: Session = Depends(get_db),
) -> UserResponse:
    """Get a user by ID.

    **Authentication:** Requires `issuer:admin` role, `org:administrator` for same org,
    or accessing own account (including org-only principals).
    """
    store = get_db_user_store()
    user = store.get_user_by_id(db, user_id)

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    _check_user_access(principal, user)

    org_name = _get_org_name(db, user.organization_id)
    return _user_to_response(user, org_name)


@router.patch("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: str,
    body: UpdateUserRequest,
    http_request: Request,
    principal: Principal = require_auth,
    db: Session = Depends(get_db),
) -> UserResponse:
    """Update a user.

    **Authentication:**
    - `issuer:admin` can update any user
    - `org:administrator` can update users in their org (except system roles)
    - Users can update their own name only (including org-only principals)
    """
    audit = get_audit_logger()
    store = get_db_user_store()

    user = store.get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Check access permissions
    is_self = principal.key_id == f"user:{user.email}"
    is_system_admin = principal.is_system_admin
    is_org_admin = (
        principal.organization_id
        and principal.organization_id == user.organization_id
        and OrgRole.ADMINISTRATOR.value in principal.roles
    )

    if not is_self and not is_system_admin and not is_org_admin:
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    # Validate what can be updated based on role
    if not is_system_admin:
        # Only system admins can change system roles
        if body.system_roles is not None:
            raise HTTPException(
                status_code=403,
                detail="Only system admins can modify system roles",
            )

        # Only system admins can change organization assignment
        if body.organization_id is not None and body.organization_id != user.organization_id:
            raise HTTPException(
                status_code=403,
                detail="Only system admins can change organization assignment",
            )

        # Non-admins can only update their own name
        if is_self and not is_org_admin:
            if body.org_roles is not None or body.enabled is not None:
                raise HTTPException(
                    status_code=403,
                    detail="You can only update your own name",
                )

    # Validate roles if provided
    if body.system_roles:
        validate_system_roles(body.system_roles)
    if body.org_roles:
        validate_org_roles(body.org_roles)

    # Validate organization exists if specified
    if body.organization_id:
        org = db.query(Organization).filter(Organization.id == body.organization_id).first()
        if not org:
            raise HTTPException(status_code=404, detail="Organization not found")

    # Update user
    updated_user = store.update_user(
        db=db,
        user_id=user_id,
        name=body.name,
        system_roles=body.system_roles,
        org_roles=body.org_roles,
        organization_id=body.organization_id,
        enabled=body.enabled,
    )

    if not updated_user:
        raise HTTPException(status_code=404, detail="User not found")

    audit.log(
        action="user.update",
        principal=principal.key_id,
        resource_type="user",
        resource_id=user_id,
        details={
            "name": body.name,
            "system_roles": body.system_roles,
            "org_roles": body.org_roles,
            "organization_id": body.organization_id,
            "enabled": body.enabled,
        },
    )

    org_name = _get_org_name(db, updated_user.organization_id)
    return _user_to_response(updated_user, org_name)


@router.patch("/{user_id}/password")
async def reset_user_password(
    user_id: str,
    body: ResetPasswordRequest,
    http_request: Request,
    principal: Principal = require_admin,
    db: Session = Depends(get_db),
) -> dict:
    """Reset a user's password (admin only).

    **Authentication:** Requires `issuer:admin` role.

    This endpoint does not require current password verification.
    """
    audit = get_audit_logger()
    store = get_db_user_store()

    user = store.get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.is_oauth_user:
        raise HTTPException(
            status_code=400,
            detail="OAuth users cannot have a password",
        )

    store.change_password(db, user_id, body.new_password)

    audit.log(
        action="user.password_reset",
        principal=principal.key_id,
        resource_type="user",
        resource_id=user_id,
        details={"admin_reset": True},
    )

    log.info(f"Password reset for user {user.email} by {principal.key_id}")

    return {"success": True, "message": "Password reset successfully"}


@router.delete("/{user_id}")
async def delete_user(
    user_id: str,
    http_request: Request,
    principal: Principal = require_admin,
    db: Session = Depends(get_db),
) -> dict:
    """Delete a user.

    **Authentication:** Requires `issuer:admin` role.
    """
    audit = get_audit_logger()
    store = get_db_user_store()

    user = store.get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Prevent self-deletion
    if principal.key_id == f"user:{user.email}":
        raise HTTPException(
            status_code=400,
            detail="Cannot delete your own account",
        )

    email = user.email
    success = store.delete_user(db, user_id)

    if not success:
        raise HTTPException(status_code=404, detail="User not found")

    audit.log(
        action="user.delete",
        principal=principal.key_id,
        resource_type="user",
        resource_id=user_id,
        details={"email": email},
    )

    return {"success": True, "message": "User deleted"}
