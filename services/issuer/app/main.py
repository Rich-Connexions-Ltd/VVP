"""VVP Issuer FastAPI application."""
import asyncio
import logging
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.authentication import AuthenticationMiddleware

from common.vvp.core.logging import configure_logging
from app.api import admin, auth, credential, dashboard, dossier, health, identity, organization, org_api_key, registry, schema, tn, user, vvp
from app.auth.api_key import APIKeyBackend, get_api_key_store
from app.auth.session import get_session_store
from app.config import (
    AUTH_ENABLED,
    SESSION_CLEANUP_INTERVAL,
    MOCK_VLEI_ENABLED,
    get_auth_exempt_paths,
)
from app.keri.identity import get_identity_manager, close_identity_manager
from app.keri.issuer import get_credential_issuer, close_credential_issuer
from app.keri.registry import get_registry_manager, close_registry_manager

# Web directory for static files
WEB_DIR = Path(__file__).parent.parent / "web"

configure_logging()
log = logging.getLogger("vvp-issuer")


async def _session_cleanup_task():
    """Periodically clean up expired sessions."""
    while True:
        await asyncio.sleep(SESSION_CLEANUP_INTERVAL)
        try:
            store = get_session_store()
            count = await store.cleanup_expired()
            if count > 0:
                log.debug(f"Session cleanup: removed {count} expired sessions")
        except Exception as e:
            log.error(f"Session cleanup error: {e}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler for startup/shutdown."""
    # Startup: Initialize managers
    log.info("Starting VVP Issuer service...")
    cleanup_task = None

    try:
        # Initialize database (Sprint 41: Multi-tenancy)
        from app.db.session import init_database
        init_database()

        # Initialize API key store if auth is enabled
        if AUTH_ENABLED:
            store = get_api_key_store()
            log.info(f"Auth enabled: loaded {store.key_count} API keys")

            # Start session cleanup background task
            cleanup_task = asyncio.create_task(_session_cleanup_task())
            log.info(f"Session cleanup task started (interval: {SESSION_CLEANUP_INTERVAL}s)")
        else:
            log.warning("Auth disabled: VVP_AUTH_ENABLED=false")

        await get_identity_manager()
        await get_registry_manager()
        await get_credential_issuer()

        # Initialize mock vLEI infrastructure if enabled (Sprint 41)
        if MOCK_VLEI_ENABLED:
            from app.org.mock_vlei import get_mock_vlei_manager
            mock_vlei = get_mock_vlei_manager()
            await mock_vlei.initialize()
            log.info("Mock vLEI infrastructure initialized")
        else:
            log.info("Mock vLEI disabled (VVP_MOCK_VLEI_ENABLED=false)")

        log.info("VVP Issuer service started")
    except Exception as e:
        log.error(f"Failed to initialize managers: {e}")
        raise

    yield

    # Shutdown: Close managers
    log.info("Shutting down VVP Issuer service...")

    # Cancel session cleanup task
    if cleanup_task:
        cleanup_task.cancel()
        try:
            await cleanup_task
        except asyncio.CancelledError:
            pass
        log.info("Session cleanup task stopped")

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
# Static Files
# -----------------------------------------------------------------------------

app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")


# -----------------------------------------------------------------------------
# UI Routes (under /ui/ prefix to avoid conflicts with API routes)
# -----------------------------------------------------------------------------

@app.get("/version")
def version():
    """Return service version with GitHub commit link."""
    git_sha = os.getenv("GIT_SHA", "unknown")
    repo = os.getenv("GITHUB_REPOSITORY", "andrewbalercnx/vvp-verifier")

    result = {"git_sha": git_sha}
    if git_sha != "unknown":
        result["github_url"] = f"https://github.com/{repo}/commit/{git_sha}"
        result["short_sha"] = git_sha[:7]

    return result


@app.get("/")
def root_redirect():
    """Redirect root to UI home."""
    return RedirectResponse(url="/ui/", status_code=302)


@app.get("/ui/", response_class=FileResponse)
def ui_home():
    """Serve the issuer home page."""
    return FileResponse(WEB_DIR / "index.html", media_type="text/html")


@app.get("/ui/identity", response_class=FileResponse)
def ui_identity():
    """Serve the identity management web UI."""
    return FileResponse(WEB_DIR / "create.html", media_type="text/html")


@app.get("/ui/registry", response_class=FileResponse)
def ui_registry():
    """Serve the registry management web UI."""
    return FileResponse(WEB_DIR / "registry.html", media_type="text/html")


@app.get("/ui/schemas", response_class=FileResponse)
def ui_schemas():
    """Serve the schema browser web UI."""
    return FileResponse(WEB_DIR / "schemas.html", media_type="text/html")


@app.get("/ui/credentials", response_class=FileResponse)
def ui_credentials():
    """Serve the credential management web UI."""
    return FileResponse(WEB_DIR / "credentials.html", media_type="text/html")


@app.get("/ui/dossier", response_class=FileResponse)
def ui_dossier():
    """Serve the dossier assembly web UI."""
    return FileResponse(WEB_DIR / "dossier.html", media_type="text/html")


@app.get("/ui/vvp", response_class=FileResponse)
def ui_vvp():
    """Serve the VVP header creation web UI."""
    return FileResponse(WEB_DIR / "vvp.html", media_type="text/html")


@app.get("/vvp/ui")
def redirect_vvp_ui():
    """Redirect legacy /vvp/ui to /ui/vvp."""
    return RedirectResponse(url="/ui/vvp", status_code=302)


@app.get("/ui/admin", response_class=FileResponse)
def ui_admin():
    """Serve the admin management web UI."""
    return FileResponse(WEB_DIR / "admin.html", media_type="text/html")


@app.get("/ui/help", response_class=FileResponse)
def ui_help():
    """Serve the help and recipes web UI."""
    return FileResponse(WEB_DIR / "help.html", media_type="text/html")


@app.get("/ui/vetter", response_class=FileResponse)
def ui_vetter():
    """Serve the vetter certification web UI."""
    return FileResponse(WEB_DIR / "vetter.html", media_type="text/html")


@app.get("/ui/benchmarks", response_class=FileResponse)
def ui_benchmarks():
    """Serve the integration test benchmarks web UI."""
    return FileResponse(WEB_DIR / "benchmarks.html", media_type="text/html")


@app.get("/ui/dashboard", response_class=FileResponse)
def ui_dashboard():
    """Serve the central service dashboard (Sprint 52)."""
    return FileResponse(WEB_DIR / "dashboard.html", media_type="text/html")


@app.get("/ui/tn-mappings", response_class=FileResponse)
def ui_tn_mappings():
    """Serve the TN mapping management web UI (Sprint 42)."""
    return FileResponse(WEB_DIR / "tn-mappings.html", media_type="text/html")


# -----------------------------------------------------------------------------
# Sprint 41: User Management & Multi-tenancy UI Routes
# -----------------------------------------------------------------------------

@app.get("/login", response_class=FileResponse)
def ui_login():
    """Serve the dedicated login page."""
    return FileResponse(WEB_DIR / "login.html", media_type="text/html")


@app.get("/users/ui", response_class=FileResponse)
def ui_users():
    """Serve the user management web UI."""
    return FileResponse(WEB_DIR / "users.html", media_type="text/html")


@app.get("/organizations/ui", response_class=FileResponse)
def ui_organizations():
    """Serve the organization management web UI."""
    return FileResponse(WEB_DIR / "organizations.html", media_type="text/html")


@app.get("/profile", response_class=FileResponse)
def ui_profile():
    """Serve the user profile page."""
    return FileResponse(WEB_DIR / "profile.html", media_type="text/html")


# -----------------------------------------------------------------------------
# Backwards-compatible Redirects (302 during rollout, switch to 301 later)
# -----------------------------------------------------------------------------

@app.get("/create")
def redirect_create():
    """Redirect legacy /create to new /ui/identity."""
    return RedirectResponse(url="/ui/identity", status_code=302)


@app.get("/registry/ui")
def redirect_registry():
    """Redirect legacy /registry/ui to new /ui/registry."""
    return RedirectResponse(url="/ui/registry", status_code=302)


@app.get("/schemas/ui")
def redirect_schemas():
    """Redirect legacy /schemas/ui to new /ui/schemas."""
    return RedirectResponse(url="/ui/schemas", status_code=302)


@app.get("/credentials/ui")
def redirect_credentials():
    """Redirect legacy /credentials/ui to new /ui/credentials."""
    return RedirectResponse(url="/ui/credentials", status_code=302)


@app.get("/dossier/ui")
def redirect_dossier():
    """Redirect legacy /dossier/ui to new /ui/dossier."""
    return RedirectResponse(url="/ui/dossier", status_code=302)


@app.get("/admin/benchmarks/ui")
def redirect_benchmarks():
    """Redirect /admin/benchmarks/ui to /ui/benchmarks."""
    return RedirectResponse(url="/ui/benchmarks", status_code=302)


# -----------------------------------------------------------------------------
# API Routers
# -----------------------------------------------------------------------------

app.include_router(health.router)
app.include_router(dashboard.router)  # Sprint 52: Central dashboard
app.include_router(auth.router)
app.include_router(identity.router)
app.include_router(organization.router)  # Sprint 41: Organization management
app.include_router(org_api_key.router)  # Sprint 41: Organization API key management
app.include_router(user.router)  # Sprint 41: User management
app.include_router(registry.router)
app.include_router(schema.router)
app.include_router(credential.router)
app.include_router(dossier.router)
app.include_router(vvp.router)
app.include_router(tn.router)  # Sprint 42: TN mapping for SIP redirect
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


# -----------------------------------------------------------------------------
# Custom 404 Handler
# -----------------------------------------------------------------------------

@app.exception_handler(404)
async def not_found_handler(request: Request, exc):
    """Serve custom 404 page for browser requests, JSON for API clients."""
    accept = request.headers.get("accept", "")
    if "text/html" in accept:
        return FileResponse(
            WEB_DIR / "404.html",
            status_code=404,
            media_type="text/html"
        )
    # Return JSON for API clients
    return JSONResponse(
        status_code=404,
        content={"detail": "Not found"}
    )
