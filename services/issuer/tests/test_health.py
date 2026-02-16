"""Tests for health check endpoints.

Sprint 68c: Three-endpoint probe contract.
"""
import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_livez_always_200(client: AsyncClient):
    """Test liveness endpoint always returns 200."""
    response = await client.get("/livez")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "alive"


@pytest.mark.asyncio
async def test_healthz_returns_ok_with_db(client: AsyncClient):
    """Test readiness endpoint returns ok when DB is available."""
    response = await client.get("/healthz")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["database"] == "connected"
    assert "keri_agent" in data


@pytest.mark.asyncio
async def test_readyz_returns_503_without_agent(client: AsyncClient):
    """Test full operational readiness returns 503 when agent not ready.

    In test setup, app.state.keri_agent_ready is False (no bootstrap probe
    runs in tests), so /readyz should return 503.
    """
    response = await client.get("/readyz")
    # Agent not ready in test env — expect 503
    assert response.status_code == 503
    data = response.json()
    assert data["ready"] is False
    assert data["database"] == "connected"
    assert data["keri_agent"] == "unavailable"


@pytest.mark.asyncio
async def test_readyz_returns_200_when_agent_ready(client: AsyncClient):
    """Test /readyz returns 200 when both DB and agent are ready."""
    # Set agent ready flag
    client._transport.app.state.keri_agent_ready = True  # type: ignore[attr-defined]
    try:
        response = await client.get("/readyz")
        assert response.status_code == 200
        data = response.json()
        assert data["ready"] is True
        assert data["database"] == "connected"
        assert data["keri_agent"] == "connected"
    finally:
        # Reset
        client._transport.app.state.keri_agent_ready = False  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_version_endpoint(client: AsyncClient):
    """Test version endpoint returns git_sha."""
    response = await client.get("/version")
    assert response.status_code == 200
    data = response.json()
    assert "git_sha" in data
