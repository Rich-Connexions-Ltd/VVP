"""Health check endpoints for the KERI Agent.

Four-tier probe design:
- /livez      — Liveness: is the process alive? Always 200.
- /healthz    — Basic readiness: is LMDB accessible? 200 or 503.
- /readyz     — Full readiness: is rebuild + publishing + verification
                complete? 200 only when READY, 503 otherwise.
                Minimal response (state only) for unauthenticated probe.
- /admin/readyz — Full diagnostic readyz. Requires admin auth.
- /stats      — Counts of identities, registries, credentials.

Sprint 68: KERI Agent Service Extraction.
Sprint 81: /readyz readiness probe + admin diagnostic endpoint.
"""
import logging

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from common.vvp.models.keri_agent import AgentHealthResponse, AgentStatsResponse

router = APIRouter(tags=["health"])
log = logging.getLogger(__name__)


@router.get("/livez")
async def livez():
    """Liveness probe — always returns 200."""
    return {"status": "alive"}


@router.get("/healthz", response_model=AgentHealthResponse)
async def healthz():
    """Basic readiness probe — checks LMDB accessibility."""
    try:
        from app.keri.identity import get_identity_manager
        from app.keri.registry import get_registry_manager
        from app.keri.issuer import get_credential_issuer

        identity_mgr = await get_identity_manager()
        registry_mgr = await get_registry_manager()
        issuer = await get_credential_issuer()

        identity_count = len(list(identity_mgr.hby.prefixes))
        registry_count = len(registry_mgr.regery.regs)
        credential_count = sum(1 for _ in registry_mgr.regery.reger.creds.getItemIter())

        return AgentHealthResponse(
            status="ok",
            identity_count=identity_count,
            registry_count=registry_count,
            credential_count=credential_count,
            lmdb_accessible=True,
        )
    except Exception as e:
        log.error(f"Health check failed: {e}")
        return JSONResponse(
            status_code=503,
            content=AgentHealthResponse(
                status="unhealthy",
                identity_count=0,
                registry_count=0,
                credential_count=0,
                lmdb_accessible=False,
            ).model_dump(),
        )


@router.get("/readyz")
async def readyz():
    """Readiness probe for Azure Container Apps and CI deploy gates.

    Returns:
        200 + minimal state when READY
        503 + minimal state when not READY

    Response body contains only {"state": "ready"|"failed"|...}.
    No operational metadata exposed. For diagnostics, use /admin/readyz.
    """
    from app.keri.readiness import get_readiness_tracker

    tracker = get_readiness_tracker()
    body = tracker.report.to_probe_dict()
    status = 200 if tracker.is_ready else 503

    return JSONResponse(
        status_code=status,
        content=body,
        headers={"Cache-Control": "no-store"},
    )


@router.get("/admin/readyz")
async def admin_readyz(request: Request):
    """Full diagnostic readyz for operators.

    Returns the complete rebuild report including error codes,
    timing, and verification details. Protected by bearer token auth
    (handled by BearerTokenMiddleware on non-health endpoints).

    Returns:
        200 + full report when READY
        503 + full report when not READY
    """
    from app.keri.readiness import get_readiness_tracker

    tracker = get_readiness_tracker()
    body = tracker.report.to_internal_dict()
    status = 200 if tracker.is_ready else 503

    return JSONResponse(
        status_code=status,
        content=body,
        headers={
            "Cache-Control": "private, no-store",
            "Vary": "Authorization",
        },
    )


@router.get("/stats", response_model=AgentStatsResponse)
async def stats():
    """Return counts of managed identities, registries, and credentials."""
    try:
        from app.keri.identity import get_identity_manager
        from app.keri.registry import get_registry_manager

        identity_mgr = await get_identity_manager()
        registry_mgr = await get_registry_manager()

        identity_count = len(list(identity_mgr.hby.prefixes))
        registry_count = len(registry_mgr.regery.regs)
        credential_count = sum(1 for _ in registry_mgr.regery.reger.creds.getItemIter())

        return AgentStatsResponse(
            identity_count=identity_count,
            registry_count=registry_count,
            credential_count=credential_count,
        )
    except Exception as e:
        log.error(f"Stats check failed: {e}")
        return AgentStatsResponse(
            identity_count=0,
            registry_count=0,
            credential_count=0,
        )
