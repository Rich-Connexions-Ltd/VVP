"""Tests for KERI Agent health check endpoints.

Sprint 68: KERI Agent Service Extraction.
"""
import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_livez_returns_ok(client: AsyncClient):
    """Test liveness probe returns ok."""
    response = await client.get("/livez")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "alive"


@pytest.mark.asyncio
async def test_healthz_returns_ok(client: AsyncClient):
    """Test readiness probe returns ok when LMDB is accessible."""
    response = await client.get("/healthz")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["lmdb_accessible"] is True


@pytest.mark.asyncio
async def test_stats_returns_counts(client: AsyncClient):
    """Test stats endpoint returns identity/registry/credential counts."""
    response = await client.get("/stats")
    assert response.status_code == 200
    data = response.json()
    assert "identity_count" in data
    assert "registry_count" in data
    assert "credential_count" in data
    assert data["identity_count"] >= 0
    assert data["registry_count"] >= 0
    assert data["credential_count"] >= 0


@pytest.mark.asyncio
async def test_version_endpoint(client: AsyncClient):
    """Test version endpoint returns service info."""
    response = await client.get("/version")
    assert response.status_code == 200
    data = response.json()
    assert data["service"] == "keri-agent"
    assert "git_sha" in data
