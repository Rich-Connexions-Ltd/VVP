"""Admin endpoints for VVP Issuer.

Provides administrative operations like API key config reload,
configuration viewing, log level control, service statistics,
and Azure Container App scaling management.
All endpoints require issuer:admin role.
"""

import logging
import os
from pathlib import Path

from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel

from app.auth.api_key import get_api_key_store, Principal
from app.auth.roles import require_admin
from app.auth.users import get_user_store, hash_password
from app.audit import get_audit_logger

log = logging.getLogger(__name__)
router = APIRouter(prefix="/admin", tags=["admin"])


class AuthReloadResponse(BaseModel):
    """Response for auth reload endpoint."""

    success: bool
    key_count: int
    version: int
    message: str


@router.post("/auth/reload", response_model=AuthReloadResponse)
async def reload_auth_config(
    request: Request,
    principal: Principal = require_admin,
) -> AuthReloadResponse:
    """Reload API keys configuration from file.

    Forces an immediate reload of the API keys configuration,
    picking up any new, modified, or revoked keys.

    Requires: issuer:admin role
    """
    store = get_api_key_store()
    audit = get_audit_logger()

    success = store.reload()

    if success:
        audit.log_auth_reload(
            principal_id=principal.key_id,
            key_count=store.key_count,
            request=request,
        )
        return AuthReloadResponse(
            success=True,
            key_count=store.key_count,
            version=store.version,
            message=f"Reloaded {store.key_count} API keys",
        )
    else:
        return AuthReloadResponse(
            success=False,
            key_count=store.key_count,
            version=store.version,
            message="Failed to reload API keys",
        )


class AuthStatusResponse(BaseModel):
    """Response for auth status endpoint."""

    enabled: bool
    key_count: int
    version: int
    reload_interval: int


@router.get("/auth/status", response_model=AuthStatusResponse)
async def get_auth_status(
    principal: Principal = require_admin,
) -> AuthStatusResponse:
    """Get current authentication status.

    Returns information about the current auth configuration.

    Requires: issuer:admin role
    """
    from app.config import AUTH_ENABLED, AUTH_RELOAD_INTERVAL

    store = get_api_key_store()

    return AuthStatusResponse(
        enabled=AUTH_ENABLED,
        key_count=store.key_count,
        version=store.version,
        reload_interval=AUTH_RELOAD_INTERVAL,
    )


# =============================================================================
# User Management Endpoints
# =============================================================================


class UserResponse(BaseModel):
    """User information response (without password hash)."""

    email: str
    name: str
    roles: list[str]
    enabled: bool


class UsersListResponse(BaseModel):
    """Response for listing all users."""

    users: list[UserResponse]
    count: int


class CreateUserRequest(BaseModel):
    """Request to create a new user."""

    email: str
    name: str
    password: str
    roles: list[str] | None = None  # Defaults to ["issuer:readonly"]
    enabled: bool = True


class UpdateUserRequest(BaseModel):
    """Request to update a user."""

    name: str | None = None
    password: str | None = None
    roles: list[str] | None = None
    enabled: bool | None = None


class UserReloadResponse(BaseModel):
    """Response for user config reload."""

    success: bool
    user_count: int
    message: str


@router.get("/users", response_model=UsersListResponse)
async def list_users(
    principal: Principal = require_admin,
) -> UsersListResponse:
    """List all configured users.

    Returns user information without password hashes.

    Requires: issuer:admin role
    """
    user_store = get_user_store()
    users = user_store.list_users()

    return UsersListResponse(
        users=[UserResponse(**u) for u in users],
        count=len(users),
    )


@router.post("/users", response_model=UserResponse)
async def create_user(
    req: CreateUserRequest,
    request: Request,
    principal: Principal = require_admin,
) -> UserResponse:
    """Create a new user.

    Creates a user with the specified credentials. The password is
    automatically hashed with bcrypt.

    Note: This updates the in-memory store. To persist, update the
    users.json config file.

    Requires: issuer:admin role
    """
    import json
    from pathlib import Path
    from app.auth.users import UserConfig

    audit = get_audit_logger()
    user_store = get_user_store()

    # Check if user already exists
    if user_store.get_user(req.email):
        raise HTTPException(
            status_code=409,
            detail=f"User with email '{req.email}' already exists",
        )

    # Hash password
    password_hash = hash_password(req.password)

    # Create user config
    roles = req.roles if req.roles else ["issuer:readonly"]
    new_user = UserConfig(
        email=req.email.lower(),
        name=req.name,
        password_hash=password_hash,
        roles=set(roles),
        enabled=req.enabled,
    )

    # Add to store
    user_store._users[new_user.email] = new_user

    # Persist to config file
    from app.config import USERS_FILE

    config_path = Path(USERS_FILE)
    if config_path.exists():
        try:
            config_data = json.loads(config_path.read_text())
        except (json.JSONDecodeError, OSError):
            config_data = {"users": []}
    else:
        config_data = {"users": []}

    config_data["users"].append({
        "email": new_user.email,
        "name": new_user.name,
        "password_hash": new_user.password_hash,
        "roles": list(new_user.roles),
        "enabled": new_user.enabled,
    })

    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(json.dumps(config_data, indent=2))

    audit.log_access(
        principal_id=principal.key_id,
        resource="admin/users",
        action="create",
        request=request,
        details={"email": new_user.email, "roles": list(new_user.roles)},
    )

    log.info(f"User {new_user.email} created by {principal.key_id}")

    return UserResponse(
        email=new_user.email,
        name=new_user.name,
        roles=list(new_user.roles),
        enabled=new_user.enabled,
    )


@router.patch("/users/{email}", response_model=UserResponse)
async def update_user(
    email: str,
    req: UpdateUserRequest,
    request: Request,
    principal: Principal = require_admin,
) -> UserResponse:
    """Update an existing user.

    Can update name, password, roles, or enabled status.
    Leave fields as null to keep existing values.

    Note: This updates the in-memory store and persists to config file.

    Requires: issuer:admin role
    """
    import json
    from pathlib import Path

    audit = get_audit_logger()
    user_store = get_user_store()

    # Find user
    user = user_store.get_user(email)
    if not user:
        raise HTTPException(
            status_code=404,
            detail=f"User with email '{email}' not found",
        )

    # Track what was updated
    updates = {}

    if req.name is not None:
        user.name = req.name
        updates["name"] = req.name

    if req.password is not None:
        user.password_hash = hash_password(req.password)
        updates["password"] = "(changed)"

    if req.roles is not None:
        user.roles = set(req.roles)
        updates["roles"] = req.roles

    if req.enabled is not None:
        user.enabled = req.enabled
        updates["enabled"] = req.enabled

    # Persist to config file
    from app.config import USERS_FILE

    config_path = Path(USERS_FILE)
    if config_path.exists():
        try:
            config_data = json.loads(config_path.read_text())
        except (json.JSONDecodeError, OSError):
            config_data = {"users": []}
    else:
        config_data = {"users": []}

    # Update or add user in config
    user_found = False
    for u in config_data.get("users", []):
        if u.get("email", "").lower() == email.lower():
            u["name"] = user.name
            u["password_hash"] = user.password_hash
            u["roles"] = list(user.roles)
            u["enabled"] = user.enabled
            user_found = True
            break

    if not user_found:
        config_data["users"].append({
            "email": user.email,
            "name": user.name,
            "password_hash": user.password_hash,
            "roles": list(user.roles),
            "enabled": user.enabled,
        })

    config_path.write_text(json.dumps(config_data, indent=2))

    audit.log_access(
        principal_id=principal.key_id,
        resource=f"admin/users/{email}",
        action="update",
        request=request,
        details=updates,
    )

    log.info(f"User {email} updated by {principal.key_id}: {updates}")

    return UserResponse(
        email=user.email,
        name=user.name,
        roles=list(user.roles),
        enabled=user.enabled,
    )


@router.delete("/users/{email}")
async def delete_user(
    email: str,
    request: Request,
    principal: Principal = require_admin,
) -> dict:
    """Delete a user.

    Removes user from memory and config file.
    Any active sessions for this user will be invalidated.

    Requires: issuer:admin role
    """
    import json
    from pathlib import Path

    audit = get_audit_logger()
    user_store = get_user_store()

    # Find user
    user = user_store.get_user(email)
    if not user:
        raise HTTPException(
            status_code=404,
            detail=f"User with email '{email}' not found",
        )

    # Remove from store
    del user_store._users[email.lower()]

    # Invalidate all sessions for this user
    from app.auth.session import get_session_store

    session_store = get_session_store()
    deleted_sessions = await session_store.delete_by_key_id(f"user:{email.lower()}")

    # Persist to config file
    from app.config import USERS_FILE

    config_path = Path(USERS_FILE)
    if config_path.exists():
        try:
            config_data = json.loads(config_path.read_text())
            config_data["users"] = [
                u for u in config_data.get("users", [])
                if u.get("email", "").lower() != email.lower()
            ]
            config_path.write_text(json.dumps(config_data, indent=2))
        except (json.JSONDecodeError, OSError) as e:
            log.warning(f"Failed to update config file: {e}")

    audit.log_access(
        principal_id=principal.key_id,
        resource=f"admin/users/{email}",
        action="delete",
        request=request,
        details={"sessions_invalidated": deleted_sessions},
    )

    log.info(f"User {email} deleted by {principal.key_id}")

    return {
        "success": True,
        "message": f"User {email} deleted",
        "sessions_invalidated": deleted_sessions,
    }


@router.post("/users/reload", response_model=UserReloadResponse)
async def reload_users(
    request: Request,
    principal: Principal = require_admin,
) -> UserReloadResponse:
    """Reload users configuration from file.

    Forces an immediate reload of the users configuration,
    picking up any new, modified, or removed users.

    Requires: issuer:admin role
    """
    user_store = get_user_store()
    audit = get_audit_logger()

    success = user_store.reload()

    if success:
        audit.log_access(
            principal_id=principal.key_id,
            resource="admin/users/reload",
            action="reload",
            request=request,
            details={"user_count": user_store.user_count},
        )
        return UserReloadResponse(
            success=True,
            user_count=user_store.user_count,
            message=f"Reloaded {user_store.user_count} users",
        )
    else:
        return UserReloadResponse(
            success=False,
            user_count=user_store.user_count,
            message="Failed to reload users",
        )


# =============================================================================
# Vetter Constraint Enforcement Toggle (Sprint 62)
# =============================================================================


class VetterEnforcementResponse(BaseModel):
    """Response for vetter enforcement setting."""

    enforce_vetter_constraints: bool
    message: str


@router.get("/settings/vetter-enforcement", response_model=VetterEnforcementResponse)
async def get_vetter_enforcement(
    principal: Principal = require_admin,
) -> VetterEnforcementResponse:
    """Get current vetter constraint enforcement setting.

    When false (default): issuer logs warnings but allows credentials
    that violate vetter constraints (e.g., TN outside vetter's ECC scope).
    When true: issuer rejects such credentials with 403.

    The verifier always evaluates constraints regardless of this setting.

    Requires: issuer:admin role
    """
    from app.config import ENFORCE_VETTER_CONSTRAINTS

    return VetterEnforcementResponse(
        enforce_vetter_constraints=ENFORCE_VETTER_CONSTRAINTS,
        message="Enforcement ON — violations are rejected"
        if ENFORCE_VETTER_CONSTRAINTS
        else "Enforcement OFF — violations are logged as warnings",
    )


@router.put("/settings/vetter-enforcement", response_model=VetterEnforcementResponse)
async def set_vetter_enforcement(
    request: Request,
    enabled: bool = True,
    principal: Principal = require_admin,
) -> VetterEnforcementResponse:
    """Toggle vetter constraint enforcement at runtime.

    Set enabled=true to block credential issuance that violates vetter
    constraints (ECC/jurisdiction). Set enabled=false to allow issuing
    mis-vetted credentials (logged as warnings) for testing.

    The verifier always evaluates constraints regardless of this setting.

    Requires: issuer:admin role
    """
    from app.config import set_enforce_vetter_constraints

    set_enforce_vetter_constraints(enabled)
    audit = get_audit_logger()

    audit.log_access(
        principal_id=principal.key_id,
        resource="admin/settings/vetter-enforcement",
        action="update",
        request=request,
        details={"enforce_vetter_constraints": enabled},
    )

    log.info(
        f"Vetter constraint enforcement {'ENABLED' if enabled else 'DISABLED'} "
        f"by {principal.key_id}"
    )

    return VetterEnforcementResponse(
        enforce_vetter_constraints=enabled,
        message="Enforcement ON — violations are rejected"
        if enabled
        else "Enforcement OFF — violations are logged as warnings",
    )


# =============================================================================
# Configuration Endpoints
# =============================================================================


class ConfigResponse(BaseModel):
    """Full configuration snapshot."""

    persistence: dict
    witnesses: dict
    identity_defaults: dict
    auth: dict
    environment: dict


def _get_gsma_aid() -> str:
    """Get the GSMA AID from mock vLEI state (Sprint 62).

    Operators need this to add to verifier VVP_TRUSTED_ROOT_AIDS.
    Returns empty string if GSMA identity not yet bootstrapped.

    Sprint 68b: Reads via TrustAnchorManager.get_mock_vlei_state()
    (DB-backed, canonical read path).
    """
    try:
        from app.org.trust_anchors import get_trust_anchor_manager
        state = get_trust_anchor_manager().get_mock_vlei_state()
        if state and state.gsma_aid:
            return state.gsma_aid
    except Exception:
        pass
    return ""


@router.get("/config", response_model=ConfigResponse)
async def get_config(
    principal: Principal = require_admin,
) -> ConfigResponse:
    """Get current service configuration.

    Returns all configuration values organized by category.

    Requires: issuer:admin role
    """
    from app.config import (
        DATA_DIR,
        KEYSTORE_DIR,
        DATABASE_DIR,
        WITNESS_CONFIG_PATH,
        WITNESS_IURLS,
        WITNESS_AIDS,
        WITNESS_TIMEOUT_SECONDS,
        WITNESS_RECEIPT_THRESHOLD,
        DEFAULT_KEY_COUNT,
        DEFAULT_KEY_THRESHOLD,
        DEFAULT_NEXT_KEY_COUNT,
        DEFAULT_NEXT_THRESHOLD,
        AUTH_ENABLED,
        AUTH_RELOAD_INTERVAL,
        AUTH_RELOAD_ENABLED,
        ADMIN_ENDPOINT_ENABLED,
    )

    store = get_api_key_store()

    return ConfigResponse(
        persistence={
            "data_dir": str(DATA_DIR),
            "keystore_dir": str(KEYSTORE_DIR),
            "database_dir": str(DATABASE_DIR),
        },
        witnesses={
            "config_path": WITNESS_CONFIG_PATH,
            "iurls": WITNESS_IURLS,
            "aids": WITNESS_AIDS,
            "timeout_seconds": WITNESS_TIMEOUT_SECONDS,
            "receipt_threshold": WITNESS_RECEIPT_THRESHOLD,
        },
        identity_defaults={
            "key_count": DEFAULT_KEY_COUNT,
            "key_threshold": DEFAULT_KEY_THRESHOLD,
            "next_key_count": DEFAULT_NEXT_KEY_COUNT,
            "next_threshold": DEFAULT_NEXT_THRESHOLD,
        },
        auth={
            "enabled": AUTH_ENABLED,
            "key_count": store.key_count,
            "version": store.version,
            "reload_interval": AUTH_RELOAD_INTERVAL,
            "reload_enabled": AUTH_RELOAD_ENABLED,
            "admin_endpoint_enabled": ADMIN_ENDPOINT_ENABLED,
        },
        environment={
            "log_level": logging.getLogger().getEffectiveLevel(),
            "log_level_name": logging.getLevelName(logging.getLogger().getEffectiveLevel()),
            "gsma_aid": _get_gsma_aid(),  # Sprint 62: for verifier trusted roots config
        },
    )


# =============================================================================
# Log Level Control
# =============================================================================


class LogLevelRequest(BaseModel):
    """Request to change log level."""

    level: str


class LogLevelResponse(BaseModel):
    """Response for log level change."""

    success: bool
    log_level: str
    message: str


@router.post("/log-level", response_model=LogLevelResponse)
async def set_log_level(
    req: LogLevelRequest,
    principal: Principal = require_admin,
) -> LogLevelResponse:
    """Change log level at runtime.

    Valid levels: DEBUG, INFO, WARNING, ERROR, CRITICAL

    Requires: issuer:admin role
    """
    valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
    level_upper = req.level.upper()

    if level_upper not in valid_levels:
        return LogLevelResponse(
            success=False,
            log_level=logging.getLevelName(logging.getLogger().getEffectiveLevel()),
            message=f"Invalid log level. Must be one of: {valid_levels}",
        )

    # Set level on root logger and vvp-issuer logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, level_upper))

    vvp_logger = logging.getLogger("vvp-issuer")
    vvp_logger.setLevel(getattr(logging, level_upper))

    log.info(f"Log level changed to {level_upper} by {principal.key_id}")

    return LogLevelResponse(
        success=True,
        log_level=level_upper,
        message=f"Log level set to {level_upper}",
    )


# =============================================================================
# Witness Configuration Reload
# =============================================================================


class WitnessReloadResponse(BaseModel):
    """Response for witness config reload."""

    success: bool
    witness_count: int
    message: str


@router.post("/witnesses/reload", response_model=WitnessReloadResponse)
async def reload_witness_config(
    request: Request,
    principal: Principal = require_admin,
) -> WitnessReloadResponse:
    """Reload witness configuration from file.

    Re-reads the witness configuration file and updates
    the in-memory configuration.

    Requires: issuer:admin role
    """
    import json

    from app.config import WITNESS_CONFIG_PATH

    audit = get_audit_logger()

    try:
        config_path = Path(WITNESS_CONFIG_PATH)
        if not config_path.exists():
            return WitnessReloadResponse(
                success=False,
                witness_count=0,
                message=f"Witness config not found: {WITNESS_CONFIG_PATH}",
            )

        config_data = json.loads(config_path.read_text())
        new_iurls = config_data.get("iurls", [])

        # Update the module-level config
        import app.config

        app.config.WITNESS_CONFIG = config_data
        app.config.WITNESS_IURLS = new_iurls
        app.config.WITNESS_AIDS = config_data.get("witness_aids", {})
        app.config.WITNESS_PORTS = config_data.get("ports", {})

        audit.log_access(
            principal_id=principal.key_id,
            resource="admin/witnesses/reload",
            action="reload",
            request=request,
        )

        log.info(f"Witness config reloaded by {principal.key_id}: {len(new_iurls)} witnesses")

        return WitnessReloadResponse(
            success=True,
            witness_count=len(new_iurls),
            message=f"Reloaded {len(new_iurls)} witness URLs",
        )

    except json.JSONDecodeError as e:
        return WitnessReloadResponse(
            success=False,
            witness_count=0,
            message=f"Invalid JSON in witness config: {e}",
        )
    except Exception as e:
        log.error(f"Failed to reload witness config: {e}")
        return WitnessReloadResponse(
            success=False,
            witness_count=0,
            message=f"Failed to reload: {e}",
        )


# =============================================================================
# Service Statistics
# =============================================================================


class StatsResponse(BaseModel):
    """Service statistics."""

    identities: int
    registries: int
    credentials: int
    schemas: int


@router.get("/stats", response_model=StatsResponse)
async def get_stats(
    principal: Principal = require_admin,
) -> StatsResponse:
    """Get service statistics.

    Returns counts of identities, registries, credentials, and schemas.

    Requires: issuer:admin role
    """
    from app.keri_client import get_keri_client

    try:
        client = get_keri_client()
        identities = await client.list_identities()
        registries = await client.list_registries()
        credentials = await client.list_credentials()

        # Count schemas from schema store
        from common.vvp.schema import get_schema_store

        schema_store = get_schema_store()
        schema_count = len(schema_store.list_schemas())

        return StatsResponse(
            identities=len(identities),
            registries=len(registries),
            credentials=len(credentials),
            schemas=schema_count,
        )

    except HTTPException:
        raise
    except Exception as e:
        from app.keri_client import KeriAgentUnavailableError
        if isinstance(e, KeriAgentUnavailableError):
            raise HTTPException(status_code=503, detail=str(e))
        log.error(f"Failed to get stats: {e}")
        return StatsResponse(
            identities=0,
            registries=0,
            credentials=0,
            schemas=0,
        )


# =============================================================================
# Azure Container App Scaling
# =============================================================================

# Azure configuration from environment
AZURE_SUBSCRIPTION_ID = os.getenv("AZURE_SUBSCRIPTION_ID")
AZURE_RESOURCE_GROUP = os.getenv("AZURE_RESOURCE_GROUP", "VVP")
AZURE_CONTAINER_APPS = ["vvp-issuer", "vvp-verifier", "vvp-witness1", "vvp-witness2", "vvp-witness3"]


class ContainerAppScale(BaseModel):
    """Scaling configuration for a single Container App."""

    name: str
    min_replicas: int
    max_replicas: int


class ScaleStatusResponse(BaseModel):
    """Response with scaling status for all Container Apps."""

    success: bool
    apps: list[ContainerAppScale]
    message: str


class ScaleUpdateRequest(BaseModel):
    """Request to update minimum replicas."""

    min_replicas: int  # 0 or 1
    apps: list[str] | None = None  # Specific apps, or all if None


class ScaleUpdateResponse(BaseModel):
    """Response for scale update."""

    success: bool
    updated: list[str]
    failed: list[str]
    message: str


def _get_container_app_client():
    """Get Azure Container Apps management client.

    Uses DefaultAzureCredential which supports:
    - Managed Identity (in Azure)
    - Azure CLI (local development)
    - Environment variables (CI/CD)
    """
    if not AZURE_SUBSCRIPTION_ID:
        raise HTTPException(
            status_code=503,
            detail="AZURE_SUBSCRIPTION_ID not configured. Scaling requires Azure credentials.",
        )

    try:
        from azure.identity import DefaultAzureCredential
        from azure.mgmt.appcontainers import ContainerAppsAPIClient

        credential = DefaultAzureCredential()
        return ContainerAppsAPIClient(credential, AZURE_SUBSCRIPTION_ID)
    except ImportError:
        raise HTTPException(
            status_code=503,
            detail="Azure SDK not installed. Install azure-identity and azure-mgmt-appcontainers.",
        )
    except Exception as e:
        raise HTTPException(
            status_code=503,
            detail=f"Failed to authenticate with Azure: {e}",
        )


@router.get("/scaling", response_model=ScaleStatusResponse)
async def get_scaling_status(
    principal: Principal = require_admin,
) -> ScaleStatusResponse:
    """Get current scaling configuration for all Container Apps.

    Returns min/max replica settings for issuer, verifier, and witnesses.

    Requires: issuer:admin role
    """
    client = _get_container_app_client()
    apps = []
    errors = []

    for app_name in AZURE_CONTAINER_APPS:
        try:
            app = client.container_apps.get(AZURE_RESOURCE_GROUP, app_name)
            scale = app.template.scale
            apps.append(ContainerAppScale(
                name=app_name,
                min_replicas=scale.min_replicas or 0,
                max_replicas=scale.max_replicas or 10,
            ))
        except Exception as e:
            log.warning(f"Failed to get scaling for {app_name}: {e}")
            errors.append(f"{app_name}: {e}")

    return ScaleStatusResponse(
        success=len(errors) == 0,
        apps=apps,
        message="OK" if not errors else f"Errors: {'; '.join(errors)}",
    )


@router.post("/scaling", response_model=ScaleUpdateResponse)
async def update_scaling(
    req: ScaleUpdateRequest,
    request: Request,
    principal: Principal = require_admin,
) -> ScaleUpdateResponse:
    """Update minimum replicas for Container Apps.

    Set min_replicas to:
    - 0: Scale to zero when idle (cost-saving)
    - 1: Keep at least one instance warm (lower latency)

    Note: Witnesses with LMDB storage should use min_replicas=1
    and max_replicas=1 to maintain single-writer constraint.

    Requires: issuer:admin role
    """
    if req.min_replicas not in [0, 1]:
        raise HTTPException(
            status_code=400,
            detail="min_replicas must be 0 or 1",
        )

    client = _get_container_app_client()
    audit = get_audit_logger()

    target_apps = req.apps if req.apps else AZURE_CONTAINER_APPS
    updated = []
    failed = []

    for app_name in target_apps:
        if app_name not in AZURE_CONTAINER_APPS:
            failed.append(f"{app_name}: not a VVP app")
            continue

        try:
            # Get current app config
            app = client.container_apps.get(AZURE_RESOURCE_GROUP, app_name)

            # For witnesses, enforce maxReplicas=1 for LMDB safety
            max_replicas = app.template.scale.max_replicas or 1
            if app_name.startswith("vvp-witness"):
                max_replicas = 1

            # Update scale config
            app.template.scale.min_replicas = req.min_replicas
            app.template.scale.max_replicas = max_replicas

            # Apply update (this is a long-running operation)
            client.container_apps.begin_update(
                AZURE_RESOURCE_GROUP,
                app_name,
                app,
            ).result()  # Wait for completion

            updated.append(app_name)
            log.info(f"Updated {app_name} min_replicas to {req.min_replicas}")

        except Exception as e:
            log.error(f"Failed to update {app_name}: {e}")
            failed.append(f"{app_name}: {e}")

    # Audit log
    audit.log_access(
        principal_id=principal.key_id,
        resource="admin/scaling",
        action="update",
        request=request,
        details={
            "min_replicas": req.min_replicas,
            "updated": updated,
            "failed": failed,
        },
    )

    return ScaleUpdateResponse(
        success=len(failed) == 0,
        updated=updated,
        failed=failed,
        message=f"Updated {len(updated)} apps" if not failed else f"Partial update: {len(updated)} succeeded, {len(failed)} failed",
    )


# =============================================================================
# Performance Benchmark Results
# =============================================================================

# Benchmark results storage paths
# Primary: production path or env override
# Fallback: local test output directory
BENCHMARK_RESULTS_DIR = Path(os.getenv("VVP_BENCHMARK_RESULTS_DIR", "/data/vvp-issuer/benchmarks"))
# Local fallback for development (relative to repo root)
BENCHMARK_LOCAL_DIR = Path(__file__).parent.parent.parent.parent.parent / "tests" / "integration" / "benchmarks" / "output"


class BenchmarkMetrics(BaseModel):
    """Metrics for a single benchmark test."""

    count: int
    min: float
    max: float
    mean: float
    p50: float
    p95: float
    p99: float


class BenchmarkResult(BaseModel):
    """Single benchmark run result."""

    timestamp: str
    mode: str
    tests: dict[str, BenchmarkMetrics]


class BenchmarkThreshold(BaseModel):
    """Threshold configuration for a metric."""

    p95_target: float
    p99_max: float


class BenchmarkResultsResponse(BaseModel):
    """Response with benchmark results and history."""

    latest: BenchmarkResult | None
    history: list[BenchmarkResult]
    thresholds: dict[str, BenchmarkThreshold]


# =============================================================================
# Deployment Test Results
# =============================================================================

# Deployment test results storage
DEPLOYMENT_TEST_RESULTS_FILE = Path(os.getenv(
    "VVP_DEPLOYMENT_TEST_RESULTS",
    "/data/vvp-issuer/deployment_tests.json"
))
# Local fallback for development
DEPLOYMENT_TEST_LOCAL_FILE = Path(__file__).parent.parent.parent / "deployment_tests.json"


class DeploymentTestResult(BaseModel):
    """Single deployment test run result."""

    timestamp: str
    git_sha: str
    passed: bool
    total_tests: int
    passed_tests: int
    failed_tests: int
    duration_seconds: float
    issuer_url: str
    verifier_url: str
    details: dict | None = None
    errors: list[str] | None = None


class DeploymentTestHistoryResponse(BaseModel):
    """Response with deployment test history."""

    latest: DeploymentTestResult | None
    history: list[DeploymentTestResult]


class DeploymentTestSubmission(BaseModel):
    """Request to submit deployment test results."""

    git_sha: str
    passed: bool
    total_tests: int
    passed_tests: int
    failed_tests: int
    duration_seconds: float
    issuer_url: str
    verifier_url: str
    details: dict | None = None
    errors: list[str] | None = None


def _get_deployment_test_file() -> Path:
    """Get the deployment test results file path."""
    if DEPLOYMENT_TEST_RESULTS_FILE.parent.exists():
        return DEPLOYMENT_TEST_RESULTS_FILE
    # Fall back to local file
    return DEPLOYMENT_TEST_LOCAL_FILE


def _load_deployment_test_history() -> list[DeploymentTestResult]:
    """Load deployment test history from file."""
    import json

    results = []
    test_file = _get_deployment_test_file()

    if test_file.exists():
        try:
            data = json.loads(test_file.read_text())
            for item in data.get("results", []):
                results.append(DeploymentTestResult(**item))
        except Exception as e:
            log.warning(f"Failed to load deployment test history: {e}")

    return results


def _save_deployment_test_history(results: list[DeploymentTestResult]) -> None:
    """Save deployment test history to file."""
    import json

    test_file = _get_deployment_test_file()

    # Ensure parent directory exists
    test_file.parent.mkdir(parents=True, exist_ok=True)

    data = {
        "results": [r.model_dump() for r in results[-20:]]  # Keep last 20
    }
    test_file.write_text(json.dumps(data, indent=2))


@router.get("/deployment-tests", response_model=DeploymentTestHistoryResponse)
async def get_deployment_tests() -> DeploymentTestHistoryResponse:
    """Get deployment test results history.

    Returns the latest deployment test run and historical results (up to 20).
    Shows pass/fail status for post-deployment integration tests.

    This endpoint is public (no auth required) as deployment status is not sensitive.
    """
    history = _load_deployment_test_history()

    # Sort by timestamp descending
    history.sort(key=lambda r: r.timestamp, reverse=True)

    return DeploymentTestHistoryResponse(
        latest=history[0] if history else None,
        history=history[:20],
    )


@router.post("/deployment-tests", response_model=DeploymentTestResult)
async def submit_deployment_test(
    submission: DeploymentTestSubmission,
    request: Request,
    principal: Principal = require_admin,
) -> DeploymentTestResult:
    """Submit deployment test results.

    Called by CI/CD pipeline after running post-deployment integration tests.
    Stores results for viewing in the admin dashboard.

    Requires: issuer:admin role
    """
    from datetime import datetime, timezone

    audit = get_audit_logger()

    # Create result with timestamp
    result = DeploymentTestResult(
        timestamp=datetime.now(timezone.utc).isoformat(),
        **submission.model_dump(),
    )

    # Load existing history, add new result, save
    history = _load_deployment_test_history()
    history.append(result)
    _save_deployment_test_history(history)

    # Audit log
    audit.log_access(
        principal_id=principal.key_id,
        resource="admin/deployment-tests",
        action="submit",
        request=request,
        details={
            "git_sha": result.git_sha,
            "passed": result.passed,
            "total_tests": result.total_tests,
        },
    )

    log.info(
        f"Deployment test result submitted by {principal.key_id}: "
        f"{result.passed_tests}/{result.total_tests} passed (SHA: {result.git_sha[:8]})"
    )

    return result


@router.get("/benchmarks", response_model=BenchmarkResultsResponse)
async def get_benchmark_results(
    principal: Principal = require_admin,
) -> BenchmarkResultsResponse:
    """Get integration test benchmark results.

    Returns the latest benchmark run and historical results (up to 10).
    Also includes configurable thresholds for pass/fail determination.

    Requires: issuer:admin role
    """
    import json
    from datetime import datetime

    # Define thresholds (can be overridden via env vars)
    thresholds = {
        "single_credential": BenchmarkThreshold(
            p95_target=float(os.getenv("VVP_BENCHMARK_SINGLE_P95", "5.0")),
            p99_max=float(os.getenv("VVP_BENCHMARK_SINGLE_P99", "10.0")),
        ),
        "chained_credential": BenchmarkThreshold(
            p95_target=float(os.getenv("VVP_BENCHMARK_CHAINED_P95", "10.0")),
            p99_max=float(os.getenv("VVP_BENCHMARK_CHAINED_P99", "20.0")),
        ),
        "concurrent_verification": BenchmarkThreshold(
            p95_target=float(os.getenv("VVP_BENCHMARK_CONCURRENT_P95", "15.0")),
            p99_max=float(os.getenv("VVP_BENCHMARK_CONCURRENT_P99", "30.0")),
        ),
    }

    history = []

    def load_from_directory(dir_path: Path) -> None:
        """Load benchmark results from a directory."""
        if not dir_path.exists():
            return

        # Load timestamped result files
        result_files = sorted(
            dir_path.glob("benchmark_results_*.json"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )[:10]

        for result_file in result_files:
            try:
                data = json.loads(result_file.read_text())
                # Check if we already have this timestamp
                if any(r.timestamp == data.get("timestamp") for r in history):
                    continue
                tests = {}
                for test_name, metrics in data.get("tests", {}).items():
                    tests[test_name] = BenchmarkMetrics(**metrics)
                history.append(BenchmarkResult(
                    timestamp=data.get("timestamp", ""),
                    mode=data.get("mode", "unknown"),
                    tests=tests,
                ))
            except Exception as e:
                log.warning(f"Failed to load benchmark result {result_file}: {e}")

        # Also check for a single benchmark_results.json
        single_result_file = dir_path / "benchmark_results.json"
        if single_result_file.exists():
            try:
                data = json.loads(single_result_file.read_text())
                if not any(r.timestamp == data.get("timestamp") for r in history):
                    tests = {}
                    for test_name, metrics in data.get("tests", {}).items():
                        tests[test_name] = BenchmarkMetrics(**metrics)
                    history.insert(0, BenchmarkResult(
                        timestamp=data.get("timestamp", ""),
                        mode=data.get("mode", "unknown"),
                        tests=tests,
                    ))
            except Exception as e:
                log.warning(f"Failed to load benchmark result: {e}")

    # Load from primary directory (production/CI)
    load_from_directory(BENCHMARK_RESULTS_DIR)

    # Also check local test output directory (development)
    if BENCHMARK_LOCAL_DIR.exists():
        load_from_directory(BENCHMARK_LOCAL_DIR)

    # Sort by timestamp descending and limit to 10
    history.sort(key=lambda r: r.timestamp, reverse=True)
    history = history[:10]

    return BenchmarkResultsResponse(
        latest=history[0] if history else None,
        history=history,
        thresholds=thresholds,
    )


# =============================================================================
# Audit Log Viewer
# =============================================================================


class AuditLogEntry(BaseModel):
    """Single audit log entry."""

    action: str
    principal: str
    resource: str | None = None
    status: str
    details: dict | None = None
    request_id: str | None = None
    timestamp: str


class AuditLogResponse(BaseModel):
    """Response for audit log endpoint."""

    count: int
    events: list[AuditLogEntry]
    buffer_size: int
    max_buffer_size: int


@router.get("/audit-logs", response_model=AuditLogResponse)
async def get_audit_logs(
    limit: int = 100,
    action: str | None = None,
    status: str | None = None,
    principal: Principal = require_admin,
) -> AuditLogResponse:
    """Get recent audit log entries from memory buffer.

    Returns recent audit events for diagnostics and monitoring.
    Events are stored in an in-memory ring buffer (max 1000 events).

    Query parameters:
    - limit: Max events to return (default 100)
    - action: Filter by action prefix (e.g., "auth.", "tn_mapping.")
    - status: Filter by status (e.g., "success", "denied", "error")

    Requires: issuer:admin role
    """
    audit = get_audit_logger()

    events = audit.get_recent_events(
        limit=limit,
        action_filter=action,
        status_filter=status,
    )

    stats = audit.get_buffer_stats()

    return AuditLogResponse(
        count=len(events),
        events=[AuditLogEntry(**e) for e in events],
        buffer_size=stats["buffer_size"],
        max_buffer_size=stats["max_buffer_size"],
    )


# =============================================================================
# Mock vLEI Re-initialization
# =============================================================================


class MockVLEIReinitializeResponse(BaseModel):
    """Response for mock vLEI re-initialization."""

    success: bool
    gleif_aid: str | None = None
    qvi_aid: str | None = None
    qvi_credential_said: str | None = None
    tables_cleared: list[str]
    message: str


@router.post("/publish-identity/{name}")
async def publish_identity(
    name: str,
    request: Request,
    principal: Principal = require_admin,
):
    """Publish an identity's KEL to witnesses.

    Useful after key rotations to sync witness state.
    Requires: issuer:admin role.
    """
    from app.keri_client import get_keri_client

    client = get_keri_client()
    try:
        await client.publish_identity(name)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Publish failed: {e}")

    return {"name": name, "published": True}


class MockVLEIReinitializeRequest(BaseModel):
    """Request body for mock vLEI re-initialization."""
    clear_regular_orgs: bool = False


@router.post("/mock-vlei/reinitialize", response_model=MockVLEIReinitializeResponse)
async def reinitialize_mock_vlei(
    request: Request,
    body: MockVLEIReinitializeRequest = None,
    principal: Principal = require_admin,
) -> MockVLEIReinitializeResponse:
    """Clear stale mock vLEI state and re-initialize from scratch.

    This endpoint:
    1. Clears all Postgres tables that depend on mock vLEI state
    2. Resets the in-memory MockVLEIManager singleton
    3. Re-creates mock-gleif, mock-qvi identities, registries, and QVI credential

    By default, only system org types (root_authority, qvi, vetter_authority) are
    cleared. Pass clear_regular_orgs=true to also delete regular orgs and all their
    data (API keys, credentials, TN mappings). Use this for a full clean restart
    when KERI Agent seeds have been wiped.

    WARNING: clear_regular_orgs=true deletes ALL organizations and their data.
    Use only when the KERI Agent has been wiped and issuer org data is stale.

    Requires: issuer:admin role
    """
    from app.db.session import get_db_session
    from app.db.models import (
        MockVLEIState as MockVLEIStateModel,
        Organization,
        OrgAPIKey,
        OrgAPIKeyRole,
        ManagedCredential,
        TNMapping,
        User,
        UserOrgRole,
        DossierOspAssociation,
        OrgType,
        PBXConfig,
    )
    import app.org.mock_vlei as mock_vlei_module
    from app.org.mock_vlei import get_mock_vlei_manager

    if body is None:
        body = MockVLEIReinitializeRequest()

    audit = get_audit_logger()
    tables_cleared = []

    # System org types that belong to the mock vLEI hierarchy (always recreated)
    SYSTEM_ORG_TYPES = {
        OrgType.ROOT_AUTHORITY.value,
        OrgType.QVI.value,
        OrgType.VETTER_AUTHORITY.value,
    }

    # 1. Clear only system-level mock vLEI data — preserve regular orgs and their data
    try:
        with get_db_session() as db:
            # Collect IDs of system orgs (root_authority, qvi, vetter_authority)
            system_org_ids = [
                row.id
                for row in db.query(Organization.id).filter(
                    Organization.org_type.in_(SYSTEM_ORG_TYPES)
                )
            ]

            if system_org_ids:
                # Delete dossier-osp associations owned by system orgs
                count = (
                    db.query(DossierOspAssociation)
                    .filter(DossierOspAssociation.owner_org_id.in_(system_org_ids))
                    .delete(synchronize_session=False)
                )
                tables_cleared.append(f"dossier_osp_associations (system, {count})")

                # Delete TN mappings for system orgs
                count = (
                    db.query(TNMapping)
                    .filter(TNMapping.organization_id.in_(system_org_ids))
                    .delete(synchronize_session=False)
                )
                tables_cleared.append(f"tn_mappings (system, {count})")

                # Delete credentials for system orgs
                count = (
                    db.query(ManagedCredential)
                    .filter(ManagedCredential.organization_id.in_(system_org_ids))
                    .delete(synchronize_session=False)
                )
                tables_cleared.append(f"managed_credentials (system, {count})")

                # Delete API key roles for system orgs' keys
                system_key_ids = [
                    row.id
                    for row in db.query(OrgAPIKey.id).filter(
                        OrgAPIKey.organization_id.in_(system_org_ids)
                    )
                ]
                if system_key_ids:
                    count = (
                        db.query(OrgAPIKeyRole)
                        .filter(OrgAPIKeyRole.key_id.in_(system_key_ids))
                        .delete(synchronize_session=False)
                    )
                    tables_cleared.append(f"org_api_key_roles (system, {count})")

                    # Null out PBX config references before deleting API keys
                    db.query(PBXConfig).filter(
                        PBXConfig.api_key_id.in_(system_key_ids)
                    ).update(
                        {"api_key_id": None, "api_key_org_id": None, "api_key_value": None},
                        synchronize_session=False,
                    )

                # Delete API keys for system orgs
                count = (
                    db.query(OrgAPIKey)
                    .filter(OrgAPIKey.organization_id.in_(system_org_ids))
                    .delete(synchronize_session=False)
                )
                tables_cleared.append(f"org_api_keys (system, {count})")

                # Delete user-org roles for system orgs
                count = (
                    db.query(UserOrgRole)
                    .filter(UserOrgRole.org_id.in_(system_org_ids))
                    .delete(synchronize_session=False)
                )
                tables_cleared.append(f"user_org_roles (system, {count})")

                # Delete users whose primary org is a system org
                count = (
                    db.query(User)
                    .filter(User.organization_id.in_(system_org_ids))
                    .delete(synchronize_session=False)
                )
                tables_cleared.append(f"users (system, {count})")

                # Delete system orgs themselves
                count = (
                    db.query(Organization)
                    .filter(Organization.id.in_(system_org_ids))
                    .delete(synchronize_session=False)
                )
                tables_cleared.append(f"organizations (system, {count})")

            # Optionally clear regular orgs and all their data
            if body.clear_regular_orgs:
                regular_org_ids = [
                    row.id
                    for row in db.query(Organization.id).filter(
                        Organization.org_type.notin_(SYSTEM_ORG_TYPES)
                    )
                ]
                if regular_org_ids:
                    db.query(DossierOspAssociation).filter(
                        DossierOspAssociation.owner_org_id.in_(regular_org_ids)
                    ).delete(synchronize_session=False)
                    db.query(TNMapping).filter(
                        TNMapping.organization_id.in_(regular_org_ids)
                    ).delete(synchronize_session=False)
                    db.query(ManagedCredential).filter(
                        ManagedCredential.organization_id.in_(regular_org_ids)
                    ).delete(synchronize_session=False)
                    regular_key_ids = [
                        row.id
                        for row in db.query(OrgAPIKey.id).filter(
                            OrgAPIKey.organization_id.in_(regular_org_ids)
                        )
                    ]
                    if regular_key_ids:
                        db.query(OrgAPIKeyRole).filter(
                            OrgAPIKeyRole.key_id.in_(regular_key_ids)
                        ).delete(synchronize_session=False)
                        # Null out PBX config API key reference to avoid FK violation
                        db.query(PBXConfig).filter(
                            PBXConfig.api_key_id.in_(regular_key_ids)
                        ).update(
                            {"api_key_id": None, "api_key_org_id": None, "api_key_value": None},
                            synchronize_session=False,
                        )
                    db.query(OrgAPIKey).filter(
                        OrgAPIKey.organization_id.in_(regular_org_ids)
                    ).delete(synchronize_session=False)
                    db.query(UserOrgRole).filter(
                        UserOrgRole.org_id.in_(regular_org_ids)
                    ).delete(synchronize_session=False)
                    db.query(User).filter(
                        User.organization_id.in_(regular_org_ids)
                    ).delete(synchronize_session=False)
                    count = db.query(Organization).filter(
                        Organization.id.in_(regular_org_ids)
                    ).delete(synchronize_session=False)
                    tables_cleared.append(f"organizations (regular, {count})")
                    log.info(f"Cleared {count} regular orgs and all their data")

            # Always clear mock vLEI state (will be rebuilt by initialize())
            count = db.query(MockVLEIStateModel).delete()
            tables_cleared.append(f"mock_vlei_state ({count})")

        log.info(f"Cleared tables: {tables_cleared}")
    except Exception as e:
        log.error(f"Failed to clear Postgres tables: {e}")
        return MockVLEIReinitializeResponse(
            success=False,
            tables_cleared=tables_cleared,
            message=f"Failed to clear database: {e}",
        )

    # 2. Reset the in-memory singleton
    mock_vlei_module._mock_vlei_manager = None

    # 3. Re-initialize
    try:
        manager = get_mock_vlei_manager()
        state = await manager.initialize()

        audit.log_access(
            principal_id=principal.key_id,
            resource="admin/mock-vlei/reinitialize",
            action="reinitialize",
            request=request,
            details={"tables_cleared": tables_cleared},
        )

        log.info(
            f"Mock vLEI re-initialized: gleif={state.gleif_aid[:16]}..., "
            f"qvi={state.qvi_aid[:16]}..."
        )

        return MockVLEIReinitializeResponse(
            success=True,
            gleif_aid=state.gleif_aid,
            qvi_aid=state.qvi_aid,
            qvi_credential_said=state.qvi_credential_said,
            tables_cleared=tables_cleared,
            message="Mock vLEI infrastructure re-initialized successfully",
        )
    except Exception as e:
        log.error(f"Failed to re-initialize mock vLEI: {e}")
        return MockVLEIReinitializeResponse(
            success=False,
            tables_cleared=tables_cleared,
            message=f"Tables cleared but re-initialization failed: {e}",
        )


# =============================================================================
# Sprint 73: Bulk Cleanup Endpoints
# =============================================================================


class BulkCredentialCleanupRequest(BaseModel):
    """Request for bulk credential cleanup."""
    organization_id: str | None = None
    schema_said: str | None = None
    before: str | None = None  # ISO datetime string
    dry_run: bool = False


class BulkCredentialCleanupResponse(BaseModel):
    """Response for bulk credential cleanup."""
    deleted_count: int
    deleted_saids: list[str]
    failed: list[dict]
    blocked_saids: list[str]
    dry_run: bool


class BulkIdentityCleanupRequest(BaseModel):
    """Request for bulk identity cleanup."""
    organization_id: str | None = None
    name_pattern: str | None = None
    metadata_type: str | None = None
    cascade_credentials: bool = False
    force: bool = False
    dry_run: bool = False


class BulkIdentityCleanupResponse(BaseModel):
    """Response for bulk identity cleanup."""
    deleted_count: int
    deleted_names: list[str]
    failed: list[dict]
    blocked_names: list[dict]
    cascaded_credential_count: int
    dry_run: bool


@router.post("/cleanup/credentials", response_model=BulkCredentialCleanupResponse)
async def bulk_cleanup_credentials(
    body: BulkCredentialCleanupRequest,
    request: Request,
    principal: Principal = require_admin,
) -> BulkCredentialCleanupResponse:
    """Bulk delete credentials by organization, schema, or date.

    Queries the issuer's managed_credentials table for matching SAIDs,
    sends a single batch request to the KERI Agent, then cleans up
    managed_credentials rows.

    Requires: issuer:admin role
    """
    from app.db.session import get_db_session
    from app.db.models import ManagedCredential
    from app.keri_client import get_keri_client, KeriAgentUnavailableError

    audit = get_audit_logger()

    # Query matching SAIDs from issuer DB
    with get_db_session() as db:
        query = db.query(ManagedCredential)
        if body.organization_id:
            query = query.filter(ManagedCredential.organization_id == body.organization_id)
        if body.schema_said:
            query = query.filter(ManagedCredential.schema_said == body.schema_said)
        if body.before:
            from datetime import datetime as dt
            try:
                before_dt = dt.fromisoformat(body.before.replace("Z", "+00:00"))
                query = query.filter(ManagedCredential.created_at < before_dt)
            except ValueError:
                raise HTTPException(status_code=400, detail=f"Invalid date format: {body.before}")

        matching = query.all()
        target_saids = [m.said for m in matching]

    if not target_saids:
        return BulkCredentialCleanupResponse(
            deleted_count=0, deleted_saids=[], failed=[],
            blocked_saids=[], dry_run=body.dry_run,
        )

    if body.dry_run:
        return BulkCredentialCleanupResponse(
            deleted_count=len(target_saids),
            deleted_saids=target_saids,
            failed=[],
            blocked_saids=[],
            dry_run=True,
        )

    # Send batch to KERI Agent
    try:
        client = get_keri_client()
        agent_result = await client.bulk_cleanup_credentials(target_saids)
    except KeriAgentUnavailableError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except Exception as e:
        log.error(f"KERI Agent bulk credential cleanup failed: {e}")
        raise HTTPException(status_code=500, detail="KERI Agent bulk cleanup failed")

    deleted_saids = agent_result.get("deleted_saids", [])

    # Clean up issuer metadata for successfully deleted credentials
    if deleted_saids:
        with get_db_session() as db:
            db.query(ManagedCredential).filter(
                ManagedCredential.said.in_(deleted_saids)
            ).delete(synchronize_session="fetch")

    audit.log_access(
        action="admin.bulk_cleanup_credentials",
        principal_id=principal.key_id,
        resource="credentials",
        details={
            "deleted_count": len(deleted_saids),
            "organization_id": body.organization_id,
            "schema_said": body.schema_said,
        },
        request=request,
    )

    return BulkCredentialCleanupResponse(
        deleted_count=len(deleted_saids),
        deleted_saids=deleted_saids,
        failed=agent_result.get("failed", []),
        blocked_saids=agent_result.get("blocked_saids", []),
        dry_run=False,
    )


@router.post("/cleanup/identities", response_model=BulkIdentityCleanupResponse)
async def bulk_cleanup_identities(
    body: BulkIdentityCleanupRequest,
    request: Request,
    principal: Principal = require_admin,
) -> BulkIdentityCleanupResponse:
    """Bulk delete identities by organization, name pattern, or metadata.

    Sends filter criteria to the KERI Agent for processing.
    If cascade_credentials=true, also deletes credentials issued by the identities.

    Requires: issuer:admin role
    """
    from app.keri_client import get_keri_client, KeriAgentUnavailableError

    audit = get_audit_logger()

    # Build KERI Agent request
    agent_body: dict = {
        "cascade_credentials": body.cascade_credentials,
        "force": body.force,
        "dry_run": body.dry_run,
    }

    if body.name_pattern:
        agent_body["name_pattern"] = body.name_pattern

    if body.metadata_type:
        agent_body["metadata_type"] = body.metadata_type

    # If org filter, look up identities for that org
    if body.organization_id:
        from app.db.session import get_db_session
        from app.db.models import Organization
        with get_db_session() as db:
            org = db.query(Organization).filter_by(id=body.organization_id).first()
            if org and org.aid:
                # Find identity name from KERI Agent
                try:
                    client = get_keri_client()
                    identities = await client.list_identities()
                    org_names = [i.name for i in identities if i.aid == org.aid]
                    if org_names:
                        agent_body["names"] = org_names
                    else:
                        return BulkIdentityCleanupResponse(
                            deleted_count=0, deleted_names=[], failed=[],
                            blocked_names=[], cascaded_credential_count=0,
                            dry_run=body.dry_run,
                        )
                except KeriAgentUnavailableError as e:
                    raise HTTPException(status_code=503, detail=str(e))

    try:
        client = get_keri_client()
        agent_result = await client.bulk_cleanup_identities(agent_body)
    except KeriAgentUnavailableError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except Exception as e:
        log.error(f"KERI Agent bulk identity cleanup failed: {e}")
        raise HTTPException(status_code=500, detail="KERI Agent bulk cleanup failed")

    audit.log_access(
        action="admin.bulk_cleanup_identities",
        principal_id=principal.key_id,
        resource="identities",
        details={
            "deleted_count": agent_result.get("deleted_count", 0),
            "organization_id": body.organization_id,
            "name_pattern": body.name_pattern,
        },
        request=request,
    )

    return BulkIdentityCleanupResponse(
        deleted_count=agent_result.get("deleted_count", 0),
        deleted_names=agent_result.get("deleted_names", []),
        failed=agent_result.get("failed", []),
        blocked_names=agent_result.get("blocked_names", []),
        cascaded_credential_count=agent_result.get("cascaded_credential_count", 0),
        dry_run=body.dry_run,
    )
