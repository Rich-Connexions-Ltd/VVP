"""Tests for central service dashboard (Sprint 52)."""
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from httpx import AsyncClient

from app.api.dashboard import _build_health_url, _compute_overall_status


# =============================================================================
# Unit tests: _build_health_url
# =============================================================================


class TestBuildHealthUrl:
    """URL normalization tests."""

    def test_basic(self):
        assert _build_health_url("http://localhost:8000", "/healthz") == "http://localhost:8000/healthz"

    def test_trailing_slash_on_base(self):
        assert _build_health_url("http://localhost:8000/", "/healthz") == "http://localhost:8000/healthz"

    def test_no_leading_slash_on_path(self):
        assert _build_health_url("http://localhost:8000", "healthz") == "http://localhost:8000/healthz"

    def test_both_slashes(self):
        assert _build_health_url("http://localhost:8000/", "/healthz") == "http://localhost:8000/healthz"

    def test_custom_health_path(self):
        assert _build_health_url("http://localhost:5642", "/health") == "http://localhost:5642/health"

    def test_nested_path(self):
        assert _build_health_url("http://svc:8080", "/api/health") == "http://svc:8080/api/health"


# =============================================================================
# Unit tests: _compute_overall_status
# =============================================================================


class TestComputeOverallStatus:
    """Overall status computation tests."""

    def test_all_healthy(self):
        results = [{"status": "healthy"}, {"status": "healthy"}]
        assert _compute_overall_status(results) == "healthy"

    def test_all_unhealthy(self):
        results = [{"status": "unhealthy"}, {"status": "unhealthy"}]
        assert _compute_overall_status(results) == "unhealthy"

    def test_mixed_degraded(self):
        results = [{"status": "healthy"}, {"status": "unhealthy"}]
        assert _compute_overall_status(results) == "degraded"

    def test_empty_unknown(self):
        assert _compute_overall_status([]) == "unknown"

    def test_single_healthy(self):
        assert _compute_overall_status([{"status": "healthy"}]) == "healthy"

    def test_single_unhealthy(self):
        assert _compute_overall_status([{"status": "unhealthy"}]) == "unhealthy"


# =============================================================================
# API integration tests
# =============================================================================


def _mock_response(status_code=200, json_data=None, text="OK"):
    """Create a mock httpx.Response."""
    response = AsyncMock(spec=httpx.Response)
    response.status_code = status_code
    if json_data is not None:
        response.json = lambda: json_data
    else:
        response.json = lambda: (_ for _ in ()).throw(ValueError("No JSON"))
    return response


@pytest.mark.asyncio
async def test_dashboard_status_all_healthy(client: AsyncClient):
    """All services healthy returns overall healthy status."""
    mock_resp = _mock_response(200, {"ok": True, "version": "1.0"})

    with patch("app.api.dashboard.httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client_cls.return_value = mock_client

        response = await client.get("/api/dashboard/status")

    assert response.status_code == 200
    data = response.json()
    assert data["overall_status"] == "healthy"
    assert isinstance(data["services"], list)
    assert len(data["services"]) > 0
    assert "checked_at" in data

    # Verify service structure
    svc = data["services"][0]
    assert "name" in svc
    assert "url" in svc
    assert "status" in svc
    assert "response_time_ms" in svc
    assert "category" in svc
    assert svc["status"] == "healthy"


@pytest.mark.asyncio
async def test_dashboard_status_partial_failure(client: AsyncClient):
    """Some services down returns degraded status."""
    healthy_resp = _mock_response(200, {"ok": True})
    error_resp = _mock_response(500)

    call_count = 0

    async def mock_get(url):
        nonlocal call_count
        call_count += 1
        # First call healthy, rest unhealthy
        return healthy_resp if call_count == 1 else error_resp

    with patch("app.api.dashboard.httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.get = mock_get
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client_cls.return_value = mock_client

        response = await client.get("/api/dashboard/status")

    assert response.status_code == 200
    data = response.json()
    assert data["overall_status"] == "degraded"

    # Should have mix of healthy and unhealthy
    statuses = {s["status"] for s in data["services"]}
    assert "healthy" in statuses
    assert "unhealthy" in statuses


@pytest.mark.asyncio
async def test_dashboard_status_all_down(client: AsyncClient):
    """All services down returns unhealthy status."""
    async def mock_get(url):
        raise httpx.ConnectError("Connection refused")

    with patch("app.api.dashboard.httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.get = mock_get
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client_cls.return_value = mock_client

        response = await client.get("/api/dashboard/status")

    assert response.status_code == 200
    data = response.json()
    assert data["overall_status"] == "unhealthy"

    for svc in data["services"]:
        assert svc["status"] == "unhealthy"
        assert svc["error"] is not None


@pytest.mark.asyncio
async def test_dashboard_status_timeout(client: AsyncClient):
    """Timeout returns unhealthy with error detail."""
    async def mock_get(url):
        raise httpx.TimeoutException("Read timed out")

    with patch("app.api.dashboard.httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.get = mock_get
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client_cls.return_value = mock_client

        response = await client.get("/api/dashboard/status")

    assert response.status_code == 200
    data = response.json()
    assert data["overall_status"] == "unhealthy"
    for svc in data["services"]:
        assert svc["status"] == "unhealthy"
        assert "timed out" in svc["error"].lower() or "timeout" in svc["error"].lower()


@pytest.mark.asyncio
async def test_dashboard_status_empty_config(client: AsyncClient):
    """Empty service config returns unknown status."""
    with patch("app.api.dashboard.DASHBOARD_SERVICES", []), \
         patch("app.api.dashboard.DASHBOARD_SIP_REDIRECT_URL", ""), \
         patch("app.api.dashboard.DASHBOARD_SIP_VERIFY_URL", ""):
        response = await client.get("/api/dashboard/status")

    assert response.status_code == 200
    data = response.json()
    assert data["overall_status"] == "unknown"
    assert data["services"] == []


@pytest.mark.asyncio
async def test_dashboard_status_non_json_response(client: AsyncClient):
    """Service returning non-JSON 200 is still marked healthy."""
    # Simulates a service that returns plain text on its health endpoint
    plain_resp = _mock_response(200)  # json() will raise ValueError

    with patch("app.api.dashboard.httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=plain_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client_cls.return_value = mock_client

        response = await client.get("/api/dashboard/status")

    assert response.status_code == 200
    data = response.json()
    # Should still be healthy — JSON parse failure doesn't affect status
    for svc in data["services"]:
        assert svc["status"] == "healthy"
        assert svc["version"] is None  # No version extracted


@pytest.mark.asyncio
async def test_dashboard_status_204_response(client: AsyncClient):
    """Service returning 204 No Content is marked healthy (2xx acceptance)."""
    resp_204 = _mock_response(204)

    with patch("app.api.dashboard.httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=resp_204)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client_cls.return_value = mock_client

        response = await client.get("/api/dashboard/status")

    assert response.status_code == 200
    data = response.json()
    for svc in data["services"]:
        assert svc["status"] == "healthy"


@pytest.mark.asyncio
async def test_dashboard_status_categories(client: AsyncClient):
    """Services are assigned correct categories."""
    mock_resp = _mock_response(200, {"ok": True})

    with patch("app.api.dashboard.httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client_cls.return_value = mock_client

        response = await client.get("/api/dashboard/status")

    data = response.json()
    categories = {s["category"] for s in data["services"]}
    # Default config has core and witness categories
    assert "core" in categories
    assert "witness" in categories


@pytest.mark.asyncio
async def test_dashboard_ui_route(client: AsyncClient):
    """Dashboard UI route serves HTML page."""
    response = await client.get("/ui/dashboard")
    assert response.status_code == 200
    assert "text/html" in response.headers.get("content-type", "")


@pytest.mark.asyncio
async def test_dashboard_status_sip_monitor_url(client: AsyncClient):
    """SIP monitor URL is included in response when configured."""
    mock_resp = _mock_response(200, {"ok": True})

    with patch("app.api.dashboard.httpx.AsyncClient") as mock_client_cls, \
         patch("app.api.dashboard.DASHBOARD_SIP_MONITOR_URL", "https://sip-monitor.example.com"):
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client_cls.return_value = mock_client

        response = await client.get("/api/dashboard/status")

    data = response.json()
    assert data["sip_monitor_url"] == "https://sip-monitor.example.com"


@pytest.mark.asyncio
async def test_dashboard_status_version_extraction(client: AsyncClient):
    """Version is extracted from JSON health response."""
    mock_resp = _mock_response(200, {"ok": True, "git_sha": "abc1234"})

    with patch("app.api.dashboard.httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client_cls.return_value = mock_client

        response = await client.get("/api/dashboard/status")

    data = response.json()
    for svc in data["services"]:
        assert svc["version"] == "abc1234"
