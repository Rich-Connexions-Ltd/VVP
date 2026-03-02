"""Tests for VVP Phone PWA routes."""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_phone_route_returns_html(client: AsyncClient):
    """GET /phone serves the PWA index page."""
    response = await client.get("/phone")
    assert response.status_code == 200
    assert "text/html" in response.headers.get("content-type", "")
    assert "VVP Phone" in response.text


@pytest.mark.asyncio
async def test_phone_service_worker_route(client: AsyncClient):
    """GET /phone/sw.js serves the service worker with correct headers."""
    response = await client.get("/phone/sw.js")
    assert response.status_code == 200
    content_type = response.headers.get("content-type", "")
    assert "javascript" in content_type
    assert response.headers.get("service-worker-allowed") == "/phone"


@pytest.mark.asyncio
async def test_phone_manifest_accessible(client: AsyncClient):
    """PWA manifest is accessible via static mount."""
    response = await client.get("/static/phone/manifest.json")
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "VVP Phone"
    assert data["start_url"] == "/phone"
    assert data["display"] == "standalone"


@pytest.mark.asyncio
async def test_phone_css_accessible(client: AsyncClient):
    """Phone CSS is accessible via static mount."""
    response = await client.get("/static/phone/css/phone.css")
    assert response.status_code == 200
    assert "text/css" in response.headers.get("content-type", "")


@pytest.mark.asyncio
async def test_phone_js_accessible(client: AsyncClient):
    """Phone JS files are accessible via static mount."""
    for js_file in ["app.js", "vvp-display.js", "ui.js"]:
        response = await client.get(f"/static/phone/js/{js_file}")
        assert response.status_code == 200, f"{js_file} not accessible"
        assert "javascript" in response.headers.get("content-type", "")
