"""Mock vLEI bootstrap endpoints for the KERI Agent.

Sprint 68: KERI Agent Service Extraction.
"""
import logging

from fastapi import APIRouter, HTTPException

from common.vvp.models.keri_agent import BootstrapStatusResponse
import app.config as _config
from app.mock_vlei import get_mock_vlei_manager

router = APIRouter(prefix="/bootstrap", tags=["bootstrap"])
log = logging.getLogger(__name__)


@router.get("/status", response_model=BootstrapStatusResponse)
async def get_bootstrap_status():
    """Get current bootstrap state."""
    mgr = get_mock_vlei_manager()
    state = mgr.state

    if state is None:
        return BootstrapStatusResponse(initialized=False)

    return _build_status_response(state)


def _build_status_response(state) -> BootstrapStatusResponse:
    """Build BootstrapStatusResponse from mock vLEI state."""
    return BootstrapStatusResponse(
        initialized=state.initialized,
        gleif_aid=state.gleif_aid,
        gleif_registry_key=state.gleif_registry_key,
        qvi_aid=state.qvi_aid,
        qvi_registry_key=state.qvi_registry_key,
        gsma_aid=state.gsma_aid or None,
        gsma_registry_key=state.gsma_registry_key or None,
        gleif_name="mock-gleif",
        qvi_name="mock-qvi",
        gsma_name="mock-gsma" if state.gsma_aid else None,
        qvi_credential_said=state.qvi_credential_said or None,
        gsma_governance_said=state.gsma_governance_said or None,
    )


@router.post("/mock-vlei", response_model=BootstrapStatusResponse)
async def initialize_mock_vlei():
    """Initialize mock vLEI infrastructure.

    Idempotent — safe to call multiple times.
    """
    if not _config.MOCK_VLEI_ENABLED:
        raise HTTPException(
            status_code=403,
            detail="Mock vLEI is disabled (VVP_MOCK_VLEI_ENABLED=false)",
        )

    try:
        mgr = get_mock_vlei_manager()
        state = await mgr.initialize()
    except Exception as e:
        log.error(f"Mock vLEI initialization failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

    return _build_status_response(state)


@router.post("/reinitialize", response_model=BootstrapStatusResponse)
async def reinitialize_mock_vlei():
    """Re-initialize mock vLEI infrastructure.

    Requires VVP_MOCK_VLEI_ENABLED=true. This is a destructive operation
    that recreates all mock identities and credentials.
    """
    if not _config.MOCK_VLEI_ENABLED:
        raise HTTPException(
            status_code=403,
            detail="Mock vLEI is disabled (VVP_MOCK_VLEI_ENABLED=false)",
        )

    try:
        from app.mock_vlei import reset_mock_vlei_manager
        reset_mock_vlei_manager()

        mgr = get_mock_vlei_manager()
        state = await mgr.initialize()
    except Exception as e:
        log.error(f"Mock vLEI re-initialization failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

    return _build_status_response(state)
