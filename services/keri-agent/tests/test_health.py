"""Tests for KERI Agent health check endpoints.

Sprint 68: KERI Agent Service Extraction.
Sprint 81: /readyz and /admin/readyz readiness probes.
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


@pytest.mark.asyncio
async def test_readyz_returns_state(client: AsyncClient):
    """Test /readyz returns state field with Cache-Control header."""
    response = await client.get("/readyz")
    data = response.json()
    assert "state" in data
    assert len(data) == 1  # Only state field (minimal probe)
    assert response.headers.get("cache-control") == "no-store"


@pytest.mark.asyncio
async def test_readyz_not_ready_returns_503(client: AsyncClient):
    """/readyz returns 503 when tracker is not READY (initial state)."""
    from app.keri.readiness import get_readiness_tracker, ReadinessState, reset_readiness_tracker
    reset_readiness_tracker()
    tracker = get_readiness_tracker()
    # Tracker starts in NOT_STARTED — not ready
    assert tracker.state == ReadinessState.NOT_STARTED
    response = await client.get("/readyz")
    assert response.status_code == 503
    assert response.json()["state"] == "not_started"


@pytest.mark.asyncio
async def test_readyz_ready_returns_200(client: AsyncClient):
    """/readyz returns 200 when tracker is READY."""
    from app.keri.readiness import get_readiness_tracker, ReadinessState

    tracker = get_readiness_tracker()
    await tracker.transition(ReadinessState.READY)

    response = await client.get("/readyz")
    assert response.status_code == 200
    assert response.json()["state"] == "ready"


@pytest.mark.asyncio
async def test_admin_readyz_returns_full_report(client: AsyncClient):
    """/admin/readyz returns full diagnostic report."""
    from app.keri.readiness import get_readiness_tracker, ReadinessState

    tracker = get_readiness_tracker()
    await tracker.transition(ReadinessState.READY)

    response = await client.get("/admin/readyz")
    assert response.status_code == 200
    data = response.json()
    assert data["state"] == "ready"
    # Full report has nested sections
    assert "identities" in data
    assert "registries" in data
    assert "credentials" in data
    assert "verification" in data
    assert "witnesses" in data
    assert "error_codes" in data
    assert response.headers.get("cache-control") == "private, no-store"
    assert "authorization" in response.headers.get("vary", "").lower()


@pytest.mark.asyncio
async def test_admin_readyz_503_when_not_ready(client: AsyncClient):
    """/admin/readyz returns 503 with full report when not READY."""
    from app.keri.readiness import get_readiness_tracker, ReadinessState, reset_readiness_tracker

    reset_readiness_tracker()
    tracker = get_readiness_tracker()
    await tracker.transition(ReadinessState.FAILED)

    response = await client.get("/admin/readyz")
    assert response.status_code == 503
    data = response.json()
    assert data["state"] == "failed"
    assert "identities" in data
