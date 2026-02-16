"""Health check endpoints for the KERI Agent.

Three-tier probe design:
- /livez  — Liveness: is the process alive? Always 200.
- /healthz — Readiness: is LMDB accessible? 200 or 503.
- /stats  — Counts of identities, registries, credentials.

Sprint 68: KERI Agent Service Extraction.
"""
import logging

from fastapi import APIRouter

from common.vvp.models.keri_agent import AgentHealthResponse, AgentStatsResponse

router = APIRouter(tags=["health"])
log = logging.getLogger(__name__)


@router.get("/livez")
async def livez():
    """Liveness probe — always returns 200."""
    return {"status": "alive"}


@router.get("/healthz", response_model=AgentHealthResponse)
async def healthz():
    """Readiness probe — checks LMDB accessibility."""
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
        from fastapi.responses import JSONResponse
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
