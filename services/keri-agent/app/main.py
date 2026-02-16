"""VVP KERI Agent FastAPI application.

Standalone service owning all LMDB/keripy state. Exposes a REST API
for identity, registry, credential, dossier, VVP, and bootstrap operations.

Sprint 68: KERI Agent Service Extraction.
"""
import logging
import os
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from common.vvp.core.logging import configure_logging
from app.auth import BearerTokenMiddleware
from app.config import MOCK_VLEI_ENABLED
from app.keri.identity import get_identity_manager, close_identity_manager
from app.keri.issuer import get_credential_issuer, close_credential_issuer
from app.keri.registry import get_registry_manager, close_registry_manager

configure_logging()
log = logging.getLogger("vvp-keri-agent")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler for startup/shutdown."""
    log.info("Starting VVP KERI Agent service...")

    try:
        # Initialize KERI managers (Habery, Regery, CredentialIssuer)
        await get_identity_manager()
        await get_registry_manager()
        await get_credential_issuer()

        # Initialize mock vLEI infrastructure if enabled
        if MOCK_VLEI_ENABLED:
            from app.mock_vlei import get_mock_vlei_manager
            mock_vlei = get_mock_vlei_manager()
            await mock_vlei.initialize()
            log.info("Mock vLEI infrastructure initialized")
        else:
            log.info("Mock vLEI disabled (VVP_MOCK_VLEI_ENABLED=false)")

        log.info("VVP KERI Agent service started")
    except Exception as e:
        log.error(f"Failed to initialize KERI managers: {e}")
        raise

    yield

    # Shutdown: Close managers in reverse order
    log.info("Shutting down VVP KERI Agent service...")
    await close_credential_issuer()
    await close_registry_manager()
    await close_identity_manager()
    log.info("VVP KERI Agent service stopped")


app = FastAPI(
    title="VVP KERI Agent",
    version="0.1.0",
    description="VVP KERI Agent Service — LMDB/keripy state management",
    lifespan=lifespan,
)


# -----------------------------------------------------------------------------
# Authentication Middleware
# -----------------------------------------------------------------------------

app.add_middleware(BearerTokenMiddleware)


# -----------------------------------------------------------------------------
# API Routers
# -----------------------------------------------------------------------------

from app.api import health, identity, registry, credential, dossier, vvp, bootstrap  # noqa: E402

app.include_router(health.router)
app.include_router(identity.router)
app.include_router(registry.router)
app.include_router(credential.router)
app.include_router(dossier.router)
app.include_router(vvp.router)
app.include_router(bootstrap.router)


# -----------------------------------------------------------------------------
# Version Endpoint
# -----------------------------------------------------------------------------

@app.get("/version")
def version():
    """Return service version with GitHub commit link."""
    git_sha = os.getenv("GIT_SHA", "unknown")
    repo = os.getenv("GITHUB_REPOSITORY", "Rich-Connexions-Ltd/VVP")

    result = {"service": "keri-agent", "git_sha": git_sha}
    if git_sha != "unknown":
        result["github_url"] = f"https://github.com/{repo}/commit/{git_sha}"
        result["short_sha"] = git_sha[:7]

    return result


# -----------------------------------------------------------------------------
# Request Logging Middleware
# -----------------------------------------------------------------------------

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
