"""Health check endpoints.

Sprint 68c: Three-endpoint probe contract.

| Endpoint    | Purpose                          | Status     | Consumer              |
|-------------|----------------------------------|------------|-----------------------|
| GET /livez  | Liveness — is the process alive? | Always 200 | ACA liveness probe    |
| GET /healthz| Readiness — DB reachable?        | 200 / 503  | ACA readiness probe   |
| GET /readyz | Full operational — all deps up?  | 200 / 503  | CI/CD gates, alerting |

Design: /healthz does NOT proxy KERI Agent health. KERI-dependent routes
are gated at request level via app.state.keri_agent_ready + circuit breaker.
The issuer intentionally stays "healthy" when only the KERI Agent is down,
so ACA keeps it in rotation for KERI-free routes (auth, users, schemas, UI).

Source of truth: app.state.keri_agent_ready is the authoritative flag for
agent availability, set by the bootstrap probe on initial sync. Both
/healthz (informational) and /readyz (gating) use this flag.
"""
import logging

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.db.session import SessionLocal

log = logging.getLogger(__name__)
router = APIRouter(tags=["health"])


@router.get("/livez")
async def livez():
    """Liveness probe — always 200.

    Indicates the process is alive. Never returns 503 for dependency
    failures (prevents ACA from killing the container in restart loops).
    """
    return {"status": "alive", "service": "issuer"}


@router.get("/healthz")
async def healthz(request: Request):
    """Readiness probe — 200 if DB reachable, 503 if DB unreachable.

    Used by ACA readiness probe to remove replica from rotation when
    the database is unavailable (since all routes except /livez need DB).
    Reports KERI Agent status (informational, does not affect status code).
    """
    db_status = "connected"

    # Check database connectivity
    try:
        db = SessionLocal()
        try:
            db.execute(text("SELECT 1"))
        finally:
            db.close()
    except Exception as e:
        log.warning(f"Health check: DB unavailable: {e}")
        db_status = "unavailable"

    # Report KERI Agent status from authoritative app state flag
    keri_ready = getattr(request.app.state, "keri_agent_ready", False)
    keri_agent_status = "connected" if keri_ready else "unavailable"

    body = {
        "status": "ok" if db_status == "connected" else "unhealthy",
        "database": db_status,
        "keri_agent": keri_agent_status,
    }

    if db_status != "connected":
        return JSONResponse(content=body, status_code=503)

    return body


@router.get("/readyz")
async def readyz(request: Request):
    """Full operational readiness — 200 only when DB AND agent are up.

    Used by CI/CD deploy gates, system-health-check.sh, and alerting.
    Returns 503 if either database or KERI Agent is unavailable.
    """
    db_status = "connected"
    keri_agent_status = "connected"

    # Check database connectivity
    try:
        db = SessionLocal()
        try:
            db.execute(text("SELECT 1"))
        finally:
            db.close()
    except Exception as e:
        log.warning(f"Readyz: DB unavailable: {e}")
        db_status = "unavailable"

    # Check KERI Agent readiness via authoritative app state flag
    keri_ready = getattr(request.app.state, "keri_agent_ready", False)
    if not keri_ready:
        keri_agent_status = "unavailable"

    ready = db_status == "connected" and keri_agent_status == "connected"
    body = {
        "ready": ready,
        "database": db_status,
        "keri_agent": keri_agent_status,
    }

    if not ready:
        return JSONResponse(content=body, status_code=503)

    return body
