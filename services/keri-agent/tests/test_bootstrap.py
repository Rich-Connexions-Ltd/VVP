"""Tests for KERI Agent mock vLEI bootstrap endpoints.

Sprint 68: KERI Agent Service Extraction.
"""
import importlib
import os
import tempfile

import pytest
from httpx import AsyncClient, ASGITransport

from app.keri.identity import reset_identity_manager, close_identity_manager
from app.keri.registry import reset_registry_manager, close_registry_manager
from app.keri.issuer import reset_credential_issuer, close_credential_issuer
from app.keri.persistence import reset_persistence_manager
from app.keri.witness import reset_witness_publisher
from app.dossier.builder import reset_dossier_builder
from app.mock_vlei import reset_mock_vlei_manager


def _reset_all():
    reset_identity_manager()
    reset_registry_manager()
    reset_credential_issuer()
    reset_persistence_manager()
    reset_witness_publisher()
    reset_dossier_builder()
    reset_mock_vlei_manager()


def _restore_env(key, original):
    if original is not None:
        os.environ[key] = original
    elif key in os.environ:
        del os.environ[key]


@pytest.fixture
async def client_with_mock_vlei():
    """Create test client with mock vLEI ENABLED.

    Note: The ASGI test transport does NOT run FastAPI lifespan handlers,
    so mock vLEI is not auto-initialized. Tests must explicitly call
    POST /bootstrap/mock-vlei to initialize it.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        original_data_dir = os.environ.get("VVP_KERI_AGENT_DATA_DIR")
        original_auth_token = os.environ.get("VVP_KERI_AGENT_AUTH_TOKEN")
        original_mock_vlei = os.environ.get("VVP_MOCK_VLEI_ENABLED")

        os.environ["VVP_KERI_AGENT_DATA_DIR"] = tmpdir
        os.environ["VVP_KERI_AGENT_AUTH_TOKEN"] = ""
        os.environ["VVP_MOCK_VLEI_ENABLED"] = "true"

        _reset_all()

        import app.config as config_module
        importlib.reload(config_module)
        import app.main as main_module
        importlib.reload(main_module)

        async with AsyncClient(
            transport=ASGITransport(app=main_module.app),
            base_url="http://test",
        ) as async_client:
            yield async_client

        await close_credential_issuer()
        await close_registry_manager()
        await close_identity_manager()

        _reset_all()

        _restore_env("VVP_KERI_AGENT_DATA_DIR", original_data_dir)
        _restore_env("VVP_KERI_AGENT_AUTH_TOKEN", original_auth_token)
        _restore_env("VVP_MOCK_VLEI_ENABLED", original_mock_vlei)

        importlib.reload(config_module)


# =============================================================================
# Bootstrap Status Tests
# =============================================================================


@pytest.mark.asyncio
async def test_bootstrap_status_not_initialized(client: AsyncClient):
    """Test bootstrap status when mock vLEI is not initialized."""
    response = await client.get("/bootstrap/status")
    assert response.status_code == 200
    data = response.json()
    assert data["initialized"] is False


@pytest.mark.asyncio
async def test_bootstrap_init_then_status(client_with_mock_vlei: AsyncClient):
    """Test bootstrap status after explicit mock vLEI initialization."""
    # Explicitly initialize mock vLEI via API
    init_response = await client_with_mock_vlei.post("/bootstrap/mock-vlei")
    assert init_response.status_code == 200

    # Now check status
    response = await client_with_mock_vlei.get("/bootstrap/status")
    assert response.status_code == 200
    data = response.json()

    assert data["initialized"] is True
    assert data["gleif_aid"] is not None
    assert data["gleif_aid"].startswith("E")
    assert data["qvi_aid"] is not None
    assert data["qvi_aid"].startswith("E")
    assert data["gleif_registry_key"] is not None
    assert data["qvi_registry_key"] is not None
    assert data["gleif_name"] == "mock-gleif"
    assert data["qvi_name"] == "mock-qvi"
    # Sprint 68b: credential SAID fields for issuer edge construction
    assert data["qvi_credential_said"] is not None
    assert len(data["qvi_credential_said"]) == 44


# =============================================================================
# Mock vLEI Initialization Tests
# =============================================================================


@pytest.mark.asyncio
async def test_mock_vlei_disabled(client: AsyncClient):
    """Test that mock vLEI init returns 403 when disabled."""
    response = await client.post("/bootstrap/mock-vlei")
    assert response.status_code == 403
    assert "disabled" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_mock_vlei_idempotent(client_with_mock_vlei: AsyncClient):
    """Test that mock vLEI init is idempotent."""
    # First call
    response1 = await client_with_mock_vlei.post("/bootstrap/mock-vlei")
    assert response1.status_code == 200
    data1 = response1.json()

    # Second call should return same data
    response2 = await client_with_mock_vlei.post("/bootstrap/mock-vlei")
    assert response2.status_code == 200
    data2 = response2.json()

    assert data1["gleif_aid"] == data2["gleif_aid"]
    assert data1["qvi_aid"] == data2["qvi_aid"]


# =============================================================================
# Reinitialize Tests
# =============================================================================


@pytest.mark.asyncio
async def test_reinitialize_disabled(client: AsyncClient):
    """Test that reinitialize returns 403 when mock vLEI is disabled."""
    response = await client.post("/bootstrap/reinitialize")
    assert response.status_code == 403
    assert "disabled" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_reinitialize_creates_new_state(client_with_mock_vlei: AsyncClient):
    """Test that reinitialize creates fresh identities."""
    # Initialize first
    init_response = await client_with_mock_vlei.post("/bootstrap/mock-vlei")
    assert init_response.status_code == 200
    old_gleif_aid = init_response.json()["gleif_aid"]

    # Reinitialize
    response = await client_with_mock_vlei.post("/bootstrap/reinitialize")
    assert response.status_code == 200
    data = response.json()

    assert data["initialized"] is True
    assert data["gleif_aid"] is not None
    assert data["gleif_aid"].startswith("E")
