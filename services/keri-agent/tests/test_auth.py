"""Tests for KERI Agent bearer token authentication.

Sprint 68: KERI Agent Service Extraction.
"""
import pytest
from httpx import AsyncClient


# =============================================================================
# Bearer Token Auth Tests
# =============================================================================


@pytest.mark.asyncio
async def test_auth_disabled_allows_all(client: AsyncClient):
    """Test that when auth token is empty, all requests are allowed."""
    response = await client.get("/identities")
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_auth_health_exempt(client_with_auth: AsyncClient):
    """Test that health probes are exempt from auth."""
    response = await client_with_auth.get("/livez")
    assert response.status_code == 200

    response = await client_with_auth.get("/healthz")
    assert response.status_code == 200

    response = await client_with_auth.get("/version")
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_auth_missing_token_returns_401(client_with_auth: AsyncClient):
    """Test 401 when no token is provided."""
    response = await client_with_auth.get("/identities")
    assert response.status_code == 401
    assert "missing" in response.json()["detail"].lower() or "auth" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_auth_wrong_token_returns_401(client_with_auth: AsyncClient):
    """Test 401 when wrong token is provided."""
    response = await client_with_auth.get(
        "/identities",
        headers={"Authorization": "Bearer wrong-token"},
    )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_auth_correct_token_succeeds(
    client_with_auth: AsyncClient, auth_headers: dict
):
    """Test that correct bearer token allows access."""
    response = await client_with_auth.get(
        "/identities",
        headers=auth_headers,
    )
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_auth_malformed_header_returns_401(client_with_auth: AsyncClient):
    """Test 401 with malformed Authorization header."""
    response = await client_with_auth.get(
        "/identities",
        headers={"Authorization": "Basic dXNlcjpwYXNz"},
    )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_auth_post_requires_token(
    client_with_auth: AsyncClient, auth_headers: dict
):
    """Test that POST endpoints also require auth."""
    # Without token
    response = await client_with_auth.post(
        "/identities",
        json={"name": "test-auth"},
    )
    assert response.status_code == 401

    # With token
    response = await client_with_auth.post(
        "/identities",
        json={"name": "test-auth"},
        headers=auth_headers,
    )
    assert response.status_code == 201
