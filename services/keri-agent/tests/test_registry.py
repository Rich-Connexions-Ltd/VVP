"""Tests for KERI Agent credential registry management endpoints.

Sprint 68: KERI Agent Service Extraction.
"""
import uuid

import pytest
from httpx import AsyncClient


def unique_name(prefix: str = "test") -> str:
    """Generate unique name for test resources."""
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


async def create_test_identity(client: AsyncClient, name: str = None) -> dict:
    """Helper to create a test identity for registry tests."""
    name = name or unique_name("identity")
    response = await client.post(
        "/identities",
        json={"name": name},
    )
    assert response.status_code == 201, f"Failed to create identity: {response.text}"
    return response.json()


# =============================================================================
# Registry Creation Tests
# =============================================================================


@pytest.mark.asyncio
async def test_create_registry(client: AsyncClient):
    """Test registry creation via API."""
    identity = await create_test_identity(client)
    identity_name = identity["name"]

    registry_name = unique_name("registry")
    response = await client.post(
        "/registries",
        json={
            "name": registry_name,
            "identity_name": identity_name,
        },
    )
    assert response.status_code == 201, f"Registry creation failed: {response.text}"
    data = response.json()

    assert data["name"] == registry_name
    assert data["identity_aid"] == identity["aid"]
    assert data["identity_name"] == identity_name
    assert data["registry_key"].startswith("E")
    assert data["credential_count"] == 0


@pytest.mark.asyncio
async def test_create_registry_identity_not_found(client: AsyncClient):
    """Test 404 when identity name doesn't exist."""
    response = await client.post(
        "/registries",
        json={
            "name": unique_name("orphan-registry"),
            "identity_name": "nonexistent-identity",
        },
    )
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_duplicate_registry_name_rejected(client: AsyncClient):
    """Test that duplicate registry names are rejected."""
    identity = await create_test_identity(client)
    registry_name = unique_name("duplicate-registry")

    response1 = await client.post(
        "/registries",
        json={
            "name": registry_name,
            "identity_name": identity["name"],
        },
    )
    assert response1.status_code == 201

    response2 = await client.post(
        "/registries",
        json={
            "name": registry_name,
            "identity_name": identity["name"],
        },
    )
    assert response2.status_code == 409
    assert "already exists" in response2.json()["detail"].lower()


# =============================================================================
# Registry Retrieval Tests
# =============================================================================


@pytest.mark.asyncio
async def test_get_registry(client: AsyncClient):
    """Test getting registry by name."""
    identity = await create_test_identity(client)
    registry_name = unique_name("get-registry")

    create_response = await client.post(
        "/registries",
        json={
            "name": registry_name,
            "identity_name": identity["name"],
        },
    )
    assert create_response.status_code == 201
    registry_key = create_response.json()["registry_key"]

    get_response = await client.get(f"/registries/{registry_name}")
    assert get_response.status_code == 200
    data = get_response.json()

    assert data["registry_key"] == registry_key
    assert data["name"] == registry_name
    assert data["identity_aid"] == identity["aid"]


@pytest.mark.asyncio
async def test_registry_not_found(client: AsyncClient):
    """Test 404 for unknown registry name."""
    response = await client.get("/registries/nonexistent-registry")
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_list_registries(client: AsyncClient):
    """Test listing all registries."""
    identity = await create_test_identity(client)

    name1 = unique_name("list-1")
    name2 = unique_name("list-2")

    await client.post(
        "/registries",
        json={"name": name1, "identity_name": identity["name"]},
    )
    await client.post(
        "/registries",
        json={"name": name2, "identity_name": identity["name"]},
    )

    response = await client.get("/registries")
    assert response.status_code == 200
    data = response.json()

    assert isinstance(data, list)
    assert len(data) >= 2

    registry_names = [r["name"] for r in data]
    assert name1 in registry_names
    assert name2 in registry_names


# =============================================================================
# TEL Bytes Tests
# =============================================================================


@pytest.mark.asyncio
async def test_get_tel_bytes(client: AsyncClient):
    """Test GET /registries/{name}/tel returns CESR data."""
    identity = await create_test_identity(client)
    registry_name = unique_name("tel")

    create_response = await client.post(
        "/registries",
        json={
            "name": registry_name,
            "identity_name": identity["name"],
        },
    )
    assert create_response.status_code == 201

    tel_response = await client.get(f"/registries/{registry_name}/tel")
    assert tel_response.status_code == 200
    assert tel_response.headers.get("content-type") == "application/cesr"
    assert len(tel_response.content) > 0


@pytest.mark.asyncio
async def test_get_tel_not_found(client: AsyncClient):
    """Test 404 for TEL of unknown registry."""
    response = await client.get("/registries/nonexistent-registry/tel")
    assert response.status_code == 404


# =============================================================================
# Sprint 68b: Registry Key Query Param Tests
# =============================================================================


@pytest.mark.asyncio
async def test_list_registries_filter_by_key(client: AsyncClient):
    """Test GET /registries?registry_key={key} returns matching registry."""
    # Create identity + registry
    name = unique_name("reg-filter")
    id_response = await client.post("/identities", json={"name": name})
    assert id_response.status_code == 201

    reg_response = await client.post(
        "/registries",
        json={"name": f"reg-{name}", "identity_name": name},
    )
    assert reg_response.status_code == 201
    registry_key = reg_response.json()["registry_key"]

    # Filter by key
    response = await client.get(f"/registries?registry_key={registry_key}")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["registry_key"] == registry_key


@pytest.mark.asyncio
async def test_list_registries_filter_by_unknown_key(client: AsyncClient):
    """Test GET /registries?registry_key={unknown} returns empty list."""
    response = await client.get("/registries?registry_key=ENotARealKey11111111111111111111111111111111")
    assert response.status_code == 200
    assert response.json() == []
