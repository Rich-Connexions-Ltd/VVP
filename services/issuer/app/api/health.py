"""Health check endpoints."""
import logging

from fastapi import APIRouter

from app.api.models import HealthResponse
from app.keri_client import get_keri_client, KeriAgentUnavailableError

log = logging.getLogger(__name__)
router = APIRouter(tags=["health"])


@router.get("/healthz", response_model=HealthResponse)
async def healthz() -> HealthResponse:
    """Health check endpoint.

    Returns service status and KERI Agent identity count.
    Sprint 68b: Delegates to KERI Agent health endpoint.
    """
    try:
        client = get_keri_client()
        agent_health = await client.health()
        return HealthResponse(
            ok=agent_health.status == "ok",
            identities_loaded=agent_health.identity_count,
        )
    except KeriAgentUnavailableError:
        # Agent unavailable — issuer itself is OK, just can't count identities
        return HealthResponse(ok=True, identities_loaded=0)
    except Exception as e:
        log.warning(f"Health check warning: {e}")
        return HealthResponse(ok=True, identities_loaded=0)
