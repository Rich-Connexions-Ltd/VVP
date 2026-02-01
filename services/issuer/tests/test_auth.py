"""Tests for authentication and authorization."""
import pytest
from httpx import AsyncClient

from tests.conftest import (
    TEST_ADMIN_KEY,
    TEST_OPERATOR_KEY,
    TEST_READONLY_KEY,
    TEST_REVOKED_KEY,
)


class TestAuthentication:
    """Tests for API key authentication."""

    async def test_unauthenticated_request_returns_401(
        self, client_with_auth: AsyncClient
    ):
        """Unauthenticated requests to protected endpoints return 401."""
        # Use POST /identity which requires admin auth (GET is public for UI access)
        response = await client_with_auth.post(
            "/identity",
            json={"name": "test", "publish_to_witnesses": False},
        )
        assert response.status_code == 401

    async def test_invalid_key_returns_401(
        self, client_with_auth: AsyncClient, invalid_headers: dict
    ):
        """Invalid API key returns 401."""
        response = await client_with_auth.get("/identity", headers=invalid_headers)
        assert response.status_code == 401
        assert "Invalid API key" in response.json()["detail"]

    async def test_revoked_key_returns_401(
        self, client_with_auth: AsyncClient, revoked_headers: dict
    ):
        """Revoked API key returns 401."""
        response = await client_with_auth.get("/identity", headers=revoked_headers)
        assert response.status_code == 401

    async def test_valid_key_authenticates(
        self, client_with_auth: AsyncClient, readonly_headers: dict
    ):
        """Valid API key successfully authenticates."""
        response = await client_with_auth.get("/identity", headers=readonly_headers)
        assert response.status_code == 200

    async def test_health_exempt_from_auth(self, client_with_auth: AsyncClient):
        """Health endpoint is exempt from authentication."""
        response = await client_with_auth.get("/healthz")
        assert response.status_code == 200

    async def test_version_exempt_from_auth(self, client_with_auth: AsyncClient):
        """Version endpoint is exempt from authentication."""
        response = await client_with_auth.get("/version")
        assert response.status_code == 200


class TestAuthorization:
    """Tests for role-based authorization."""

    async def test_readonly_can_read_identities(
        self, client_with_auth: AsyncClient, readonly_headers: dict
    ):
        """Readonly role can read identities."""
        response = await client_with_auth.get("/identity", headers=readonly_headers)
        assert response.status_code == 200

    async def test_readonly_cannot_create_identity(
        self, client_with_auth: AsyncClient, readonly_headers: dict
    ):
        """Readonly role cannot create identities."""
        response = await client_with_auth.post(
            "/identity",
            json={"name": "test-identity", "publish_to_witnesses": False},
            headers=readonly_headers,
        )
        assert response.status_code == 403
        assert "Insufficient permissions" in response.json()["detail"]

    async def test_operator_cannot_create_identity(
        self, client_with_auth: AsyncClient, operator_headers: dict
    ):
        """Operator role cannot create identities (requires admin)."""
        response = await client_with_auth.post(
            "/identity",
            json={"name": "test-identity", "publish_to_witnesses": False},
            headers=operator_headers,
        )
        assert response.status_code == 403

    async def test_admin_can_create_identity(
        self, client_with_auth: AsyncClient, admin_headers: dict
    ):
        """Admin role can create identities."""
        response = await client_with_auth.post(
            "/identity",
            json={"name": "test-auth-identity", "publish_to_witnesses": False},
            headers=admin_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert "identity" in data
        assert data["identity"]["name"] == "test-auth-identity"

    async def test_readonly_can_read_schemas(
        self, client_with_auth: AsyncClient, readonly_headers: dict
    ):
        """Readonly role can list schemas."""
        response = await client_with_auth.get("/schema", headers=readonly_headers)
        assert response.status_code == 200

    async def test_readonly_can_read_registries(
        self, client_with_auth: AsyncClient, readonly_headers: dict
    ):
        """Readonly role can list registries."""
        response = await client_with_auth.get("/registry", headers=readonly_headers)
        assert response.status_code == 200


class TestAdminEndpoints:
    """Tests for admin endpoints."""

    async def test_admin_auth_status(
        self, client_with_auth: AsyncClient, admin_headers: dict
    ):
        """Admin can check auth status."""
        response = await client_with_auth.get(
            "/admin/auth/status", headers=admin_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["enabled"] is True
        assert data["key_count"] >= 3  # At least our test keys

    async def test_readonly_cannot_access_admin(
        self, client_with_auth: AsyncClient, readonly_headers: dict
    ):
        """Readonly role cannot access admin endpoints."""
        response = await client_with_auth.get(
            "/admin/auth/status", headers=readonly_headers
        )
        assert response.status_code == 403

    async def test_admin_auth_reload(
        self, client_with_auth: AsyncClient, admin_headers: dict
    ):
        """Admin can reload auth config."""
        response = await client_with_auth.post(
            "/admin/auth/reload", headers=admin_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert "key_count" in data


class TestAuthDisabled:
    """Tests for behavior when auth is disabled."""

    async def test_unauthenticated_allowed_when_disabled(self, client: AsyncClient):
        """Unauthenticated requests work when auth is disabled."""
        response = await client.get("/identity")
        assert response.status_code == 200

    async def test_create_identity_allowed_when_disabled(self, client: AsyncClient):
        """Identity creation works when auth is disabled."""
        response = await client.post(
            "/identity",
            json={"name": "test-no-auth", "publish_to_witnesses": False},
        )
        assert response.status_code == 200
