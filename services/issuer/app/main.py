"""VVP Issuer FastAPI application."""
import logging
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from starlette.middleware.authentication import AuthenticationMiddleware

from common.vvp.core.logging import configure_logging
from app.api import admin, credential, health, identity, registry, schema
from app.auth.api_key import APIKeyBackend, get_api_key_store
from app.config import AUTH_ENABLED, get_auth_exempt_paths
from app.keri.identity import get_identity_manager, close_identity_manager
from app.keri.issuer import get_credential_issuer, close_credential_issuer
from app.keri.registry import get_registry_manager, close_registry_manager

# Web directory for static files
WEB_DIR = Path(__file__).parent.parent / "web"

configure_logging()
log = logging.getLogger("vvp-issuer")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler for startup/shutdown."""
    # Startup: Initialize managers
    log.info("Starting VVP Issuer service...")
    try:
        # Initialize API key store if auth is enabled
        if AUTH_ENABLED:
            store = get_api_key_store()
            log.info(f"Auth enabled: loaded {store.key_count} API keys")
        else:
            log.warning("Auth disabled: VVP_AUTH_ENABLED=false")

        await get_identity_manager()
        await get_registry_manager()
        await get_credential_issuer()
        log.info("VVP Issuer service started")
    except Exception as e:
        log.error(f"Failed to initialize managers: {e}")
        raise

    yield

    # Shutdown: Close managers
    log.info("Shutting down VVP Issuer service...")
    await close_credential_issuer()
    await close_registry_manager()
    await close_identity_manager()
    log.info("VVP Issuer service stopped")


app = FastAPI(
    title="VVP Issuer",
    version="0.1.0",
    description="VVP Credential Issuer Service",
    lifespan=lifespan,
)


# -----------------------------------------------------------------------------
# Authentication Middleware
# -----------------------------------------------------------------------------

def on_auth_error(conn, exc):
    """Handle authentication errors."""
    return JSONResponse(
        status_code=401,
        content={"detail": str(exc)},
        headers={"WWW-Authenticate": "ApiKey"},
    )


if AUTH_ENABLED:
    app.add_middleware(
        AuthenticationMiddleware,
        backend=APIKeyBackend(exempt_paths=get_auth_exempt_paths()),
        on_error=on_auth_error,
    )


# -----------------------------------------------------------------------------
# Static UI Routes (must be before API routers to avoid path conflicts)
# -----------------------------------------------------------------------------

@app.get("/version")
def version():
    """Return service version."""
    return {"git_sha": os.getenv("GIT_SHA", "unknown")}


@app.get("/create", response_class=FileResponse)
def create_identity_ui():
    """Serve the identity creation web UI."""
    return FileResponse(WEB_DIR / "create.html", media_type="text/html")


@app.get("/registry/ui", response_class=FileResponse)
def registry_ui():
    """Serve the registry management web UI."""
    return FileResponse(WEB_DIR / "registry.html", media_type="text/html")


@app.get("/schemas/ui", response_class=FileResponse)
def schemas_ui():
    """Serve the schema browser web UI."""
    return FileResponse(WEB_DIR / "schemas.html", media_type="text/html")


@app.get("/credentials/ui", response_class=FileResponse)
def credentials_ui():
    """Serve the credential management web UI."""
    return FileResponse(WEB_DIR / "credentials.html", media_type="text/html")


# -----------------------------------------------------------------------------
# API Routers
# -----------------------------------------------------------------------------

app.include_router(health.router)
app.include_router(identity.router)
app.include_router(registry.router)
app.include_router(schema.router)
app.include_router(credential.router)
app.include_router(admin.router)


@app.middleware("http")
async def request_logging(request: Request, call_next):
    """Log all requests with timing."""
    start = time.time()
    response = await call_next(request)
    duration_ms = int((time.time() - start) * 1000)

    log.info(
        f"request_complete status={response.status_code} duration_ms={duration_ms}",
        extra={
            "route": request.url.path,
            "method": request.method,
            "status": response.status_code,
        },
    )
    return response
