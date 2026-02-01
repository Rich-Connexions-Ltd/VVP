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
