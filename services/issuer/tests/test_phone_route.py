"""Tests confirming routes removed from the issuer in Sprint 77.

Sprint 77: Phone PWA moved to pbx.rcnx.io/phone/. PBX management UI moved to
pbx.rcnx.io/pbx-admin/. The issuer no longer serves these routes — they return 404.
All assertions use follow_redirects=False to confirm a genuine 404, not a redirect
chain (e.g., auth redirect) that masks the result.
"""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_phone_route_removed(client: AsyncClient):
    """/phone returns 404 — route removed in Sprint 77 (moved to pbx.rcnx.io/phone/)."""
    response = await client.get("/phone", follow_redirects=False)
    assert response.status_code == 404
    assert len(response.history) == 0


@pytest.mark.asyncio
async def test_phone_service_worker_removed(client: AsyncClient):
    """/phone/sw.js returns 404 — removed in Sprint 77."""
    response = await client.get("/phone/sw.js", follow_redirects=False)
    assert response.status_code == 404
    assert len(response.history) == 0


@pytest.mark.asyncio
async def test_pbx_ui_route_removed(client: AsyncClient):
    """/ui/pbx returns 404 — PBX management UI moved to pbx.rcnx.io/pbx-admin/."""
    response = await client.get("/ui/pbx", follow_redirects=False)
    assert response.status_code == 404
    assert len(response.history) == 0


@pytest.mark.asyncio
async def test_static_phone_assets_removed(client: AsyncClient):
    """/static/phone/index.html returns 404 — phone/ directory removed from web/."""
    response = await client.get("/static/phone/index.html", follow_redirects=False)
    assert response.status_code == 404
    assert len(response.history) == 0


@pytest.mark.asyncio
async def test_static_phone_sw_removed(client: AsyncClient):
    """/static/phone/sw.js returns 404 — phone/ directory removed from web/."""
    response = await client.get("/static/phone/sw.js", follow_redirects=False)
    assert response.status_code == 404
    assert len(response.history) == 0
