"""Admin endpoints for VVP Issuer.

Provides administrative operations like API key config reload,
configuration viewing, log level control, and service statistics.
All endpoints require issuer:admin role.
"""

import logging
from pathlib import Path

from fastapi import APIRouter, Request
from pydantic import BaseModel

from app.auth.api_key import get_api_key_store, Principal
from app.auth.roles import require_admin
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
# Configuration Endpoints
# =============================================================================


class ConfigResponse(BaseModel):
    """Full configuration snapshot."""

    persistence: dict
    witnesses: dict
    identity_defaults: dict
    auth: dict
    environment: dict


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
    from app.keri.identity import get_identity_manager
    from app.keri.registry import get_registry_manager
    from app.keri.issuer import get_credential_issuer

    try:
        identity_mgr = await get_identity_manager()
        identities = await identity_mgr.list_identities()

        registry_mgr = await get_registry_manager()
        registries = await registry_mgr.list_registries()

        credential_issuer = await get_credential_issuer()
        credentials = await credential_issuer.list_credentials()

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

    except Exception as e:
        log.error(f"Failed to get stats: {e}")
        return StatsResponse(
            identities=0,
            registries=0,
            credentials=0,
            schemas=0,
        )
