"""Tests for PbxCorsMiddleware — path-scoped CORS for the PBX portal.

Sprint 77: PBX Portal Migration — validates that cross-origin requests from
https://pbx.rcnx.io are permitted only to the allowlisted /pbx/* paths, and
that non-PBX origins and non-PBX paths never receive CORS headers.
"""

import pytest
from httpx import AsyncClient

PBX_ORIGIN = "https://pbx.rcnx.io"
OTHER_ORIGIN = "https://evil.example.com"

_PREFLIGHT_HEADERS = {
    "Origin": PBX_ORIGIN,
    "Access-Control-Request-Method": "GET",
}


@pytest.mark.asyncio
class TestCorsPreflightAllowedPaths:
    """OPTIONS preflight from pbx.rcnx.io to allowlisted /pbx/* paths."""

    async def test_preflight_pbx_config_returns_cors_headers(self, client: AsyncClient):
        """Preflight to /pbx/config from pbx.rcnx.io returns 200 with CORS headers."""
        resp = await client.options("/pbx/config", headers=_PREFLIGHT_HEADERS)
        assert resp.status_code == 200
        assert resp.headers.get("access-control-allow-origin") == PBX_ORIGIN
        assert "Vary" in resp.headers
        assert "Origin" in resp.headers["Vary"]
        # Verify specific security-relevant header values defined in the plan
        assert resp.headers.get("access-control-max-age") == "3600"
        assert "GET" in (resp.headers.get("access-control-allow-methods") or "")
        assert "X-API-Key" in (resp.headers.get("access-control-allow-headers") or "")

    async def test_preflight_pbx_config_credentials_false(self, client: AsyncClient):
        """Preflight to /pbx/config returns Access-Control-Allow-Credentials: false."""
        resp = await client.options("/pbx/config", headers=_PREFLIGHT_HEADERS)
        assert resp.headers.get("access-control-allow-credentials") == "false"

    async def test_preflight_pbx_deploy_returns_cors_headers(self, client: AsyncClient):
        """Preflight to /pbx/deploy from pbx.rcnx.io returns CORS headers."""
        resp = await client.options("/pbx/deploy", headers=_PREFLIGHT_HEADERS)
        assert resp.status_code == 200
        assert resp.headers.get("access-control-allow-origin") == PBX_ORIGIN

    async def test_preflight_pbx_dialplan_preview_returns_cors_headers(self, client: AsyncClient):
        """Preflight to /pbx/dialplan-preview from pbx.rcnx.io returns CORS headers."""
        resp = await client.options("/pbx/dialplan-preview", headers=_PREFLIGHT_HEADERS)
        assert resp.status_code == 200
        assert resp.headers.get("access-control-allow-origin") == PBX_ORIGIN

    async def test_preflight_facade_names_returns_cors_headers(self, client: AsyncClient):
        """Preflight to /pbx/organizations/names from pbx.rcnx.io returns CORS headers."""
        resp = await client.options("/pbx/organizations/names", headers=_PREFLIGHT_HEADERS)
        assert resp.status_code == 200
        assert resp.headers.get("access-control-allow-origin") == PBX_ORIGIN

    async def test_preflight_facade_api_keys_returns_cors_headers(self, client: AsyncClient):
        """Preflight to /pbx/organizations/{id}/api-keys returns CORS headers."""
        resp = await client.options(
            "/pbx/organizations/some-org-id/api-keys",
            headers=_PREFLIGHT_HEADERS,
        )
        assert resp.status_code == 200
        assert resp.headers.get("access-control-allow-origin") == PBX_ORIGIN


@pytest.mark.asyncio
class TestCorsPreflightBlockedPaths:
    """OPTIONS preflight from pbx.rcnx.io to non-allowlisted paths must not get CORS headers."""

    async def test_preflight_organizations_root_no_cors(self, client: AsyncClient):
        """Preflight from pbx.rcnx.io to /organizations returns no CORS headers."""
        resp = await client.options(
            "/organizations",
            headers=_PREFLIGHT_HEADERS,
        )
        assert "access-control-allow-origin" not in resp.headers

    async def test_preflight_identity_no_cors(self, client: AsyncClient):
        """Preflight from pbx.rcnx.io to /identity returns no CORS headers."""
        resp = await client.options(
            "/identity",
            headers=_PREFLIGHT_HEADERS,
        )
        assert "access-control-allow-origin" not in resp.headers

    async def test_preflight_pbx_root_no_cors(self, client: AsyncClient):
        """/pbx root is not in the allowlist — no CORS headers."""
        resp = await client.options(
            "/pbx",
            headers=_PREFLIGHT_HEADERS,
        )
        assert "access-control-allow-origin" not in resp.headers

    async def test_preflight_pbx_config_extra_segment_no_cors(self, client: AsyncClient):
        """/pbx/config/extra is not in the allowlist — no CORS headers."""
        resp = await client.options(
            "/pbx/config/extra",
            headers=_PREFLIGHT_HEADERS,
        )
        assert "access-control-allow-origin" not in resp.headers


@pytest.mark.asyncio
class TestCorsBlockedOrigins:
    """Requests from non-pbx.rcnx.io origins must never get CORS headers."""

    async def test_preflight_wrong_origin_no_cors(self, client: AsyncClient):
        """Preflight from a different origin to /pbx/config returns no CORS headers."""
        resp = await client.options(
            "/pbx/config",
            headers={
                "Origin": OTHER_ORIGIN,
                "Access-Control-Request-Method": "GET",
            },
        )
        assert "access-control-allow-origin" not in resp.headers

    async def test_get_wrong_origin_no_cors(self, client: AsyncClient):
        """GET from a non-PBX origin to /pbx/config returns no CORS headers."""
        from app.db.session import init_database
        init_database()

        resp = await client.get("/pbx/config", headers={"Origin": OTHER_ORIGIN})
        assert "access-control-allow-origin" not in resp.headers

    async def test_no_origin_header_no_cors(self, client: AsyncClient):
        """GET /pbx/config without Origin header returns no CORS headers."""
        from app.db.session import init_database
        init_database()

        resp = await client.get("/pbx/config")
        assert "access-control-allow-origin" not in resp.headers


@pytest.mark.asyncio
class TestCorsActualRequests:
    """Actual (non-preflight) requests from pbx.rcnx.io get CORS response headers."""

    async def test_get_pbx_config_from_pbx_origin_has_cors_headers(self, client: AsyncClient):
        """GET /pbx/config from pbx.rcnx.io includes CORS response headers."""
        from app.db.session import init_database
        init_database()

        resp = await client.get("/pbx/config", headers={"Origin": PBX_ORIGIN})
        assert resp.headers.get("access-control-allow-origin") == PBX_ORIGIN
        assert "Origin" in resp.headers.get("Vary", "")
        assert resp.headers.get("access-control-allow-credentials") == "false"

    async def test_get_facade_names_from_pbx_origin_has_cors_headers(self, client: AsyncClient):
        """GET /pbx/organizations/names from pbx.rcnx.io includes CORS response headers."""
        from app.db.session import init_database
        init_database()

        resp = await client.get(
            "/pbx/organizations/names", headers={"Origin": PBX_ORIGIN}
        )
        assert resp.status_code == 200
        assert resp.headers.get("access-control-allow-origin") == PBX_ORIGIN
        assert "Origin" in resp.headers.get("Vary", "")
        assert resp.headers.get("access-control-allow-credentials") == "false"

    async def test_get_facade_api_keys_from_pbx_origin_has_cors_headers(self, client: AsyncClient):
        """GET /pbx/organizations/{org_id}/api-keys from pbx.rcnx.io includes CORS headers."""
        from app.db.session import init_database
        from app.db.session import SessionLocal
        from app.db.models import Organization
        init_database()

        db = SessionLocal()
        try:
            org_id = "test-cors-actual-org"
            db.query(Organization).filter(Organization.id == org_id).delete()
            db.commit()
            db.add(Organization(
                id=org_id,
                name="CORS Actual Test Org",
                pseudo_lei="XCORSACT01",
                enabled=True,
            ))
            db.commit()
        finally:
            db.close()

        resp = await client.get(
            f"/pbx/organizations/{org_id}/api-keys",
            headers={"Origin": PBX_ORIGIN},
        )
        assert resp.status_code == 200
        assert resp.headers.get("access-control-allow-origin") == PBX_ORIGIN
        assert "Origin" in resp.headers.get("Vary", "")
        assert resp.headers.get("access-control-allow-credentials") == "false"
