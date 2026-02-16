"""Tests for credential registry management endpoints."""
import uuid

import pytest
from httpx import AsyncClient


def unique_name(prefix: str = "test") -> str:
    """Generate unique name for test registry."""
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


async def create_test_identity(client: AsyncClient, name: str = None) -> dict:
    """Helper to create a test identity for registry tests."""
    name = name or unique_name("identity")
    response = await client.post(
        "/identity",
        json={"name": name, "publish_to_witnesses": False},
    )
    assert response.status_code == 200, f"Failed to create identity: {response.text}"
    return response.json()["identity"]


@pytest.mark.asyncio
async def test_create_registry(client: AsyncClient):
    """Test registry creation via API using identity name."""
    # Create identity first
    identity = await create_test_identity(client)
    identity_name = identity["name"]

    # Create registry
    registry_name = unique_name("registry")
    response = await client.post(
        "/registry",
        json={
            "name": registry_name,
            "identity_name": identity_name,
            "publish_to_witnesses": False,
        },
    )
    assert response.status_code == 200, f"Registry creation failed: {response.text}"
    data = response.json()

    assert "registry" in data
    registry = data["registry"]
    assert registry["name"] == registry_name
    assert registry["issuer_aid"] == identity["aid"]
    assert registry["registry_key"].startswith("E")  # KERI prefixes start with E
    assert registry["sequence_number"] == 0
    assert registry["no_backers"] is True


@pytest.mark.asyncio
async def test_create_registry_by_aid(client: AsyncClient):
    """Test registry creation using issuer_aid instead of identity_name."""
    # Create identity first
    identity = await create_test_identity(client)
    issuer_aid = identity["aid"]

    # Create registry using AID
    registry_name = unique_name("registry-aid")
    response = await client.post(
        "/registry",
        json={
            "name": registry_name,
            "issuer_aid": issuer_aid,
            "publish_to_witnesses": False,
        },
    )
    assert response.status_code == 200, f"Registry creation failed: {response.text}"
    data = response.json()

    registry = data["registry"]
    assert registry["issuer_aid"] == issuer_aid
    assert registry["name"] == registry_name


@pytest.mark.asyncio
async def test_create_registry_identity_not_found(client: AsyncClient):
    """Test 404 when identity name doesn't exist."""
    response = await client.post(
        "/registry",
        json={
            "name": unique_name("orphan-registry"),
            "identity_name": "nonexistent-identity",
            "publish_to_witnesses": False,
        },
    )
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_create_registry_aid_not_found(client: AsyncClient):
    """Test 404 when issuer AID doesn't exist."""
    response = await client.post(
        "/registry",
        json={
            "name": unique_name("orphan-registry"),
            "issuer_aid": "Eunknown123456789012345678901234567890123",
            "publish_to_witnesses": False,
        },
    )
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_create_registry_missing_identity(client: AsyncClient):
    """Test 400 when neither identity_name nor issuer_aid provided."""
    response = await client.post(
        "/registry",
        json={
            "name": unique_name("bad-registry"),
            "publish_to_witnesses": False,
        },
    )
    assert response.status_code == 422  # Pydantic validation error


@pytest.mark.asyncio
async def test_create_registry_with_witness_publish_disabled(client: AsyncClient):
    """Test registry creation with witness publishing disabled."""
    identity = await create_test_identity(client)

    registry_name = unique_name("no-publish")
    response = await client.post(
        "/registry",
        json={
            "name": registry_name,
            "identity_name": identity["name"],
            "publish_to_witnesses": False,
        },
    )
    assert response.status_code == 200
    data = response.json()

    # Registry should be created
    assert data["registry"]["registry_key"].startswith("E")
    # No publish results when publishing is disabled
    assert data["publish_results"] is None


@pytest.mark.asyncio
async def test_get_registry(client: AsyncClient):
    """Test getting registry by registry key."""
    # Create identity and registry
    identity = await create_test_identity(client)
    registry_name = unique_name("get-registry")

    create_response = await client.post(
        "/registry",
        json={
            "name": registry_name,
            "identity_name": identity["name"],
            "publish_to_witnesses": False,
        },
    )
    assert create_response.status_code == 200
    registry_key = create_response.json()["registry"]["registry_key"]

    # Get by registry key
    get_response = await client.get(f"/registry/{registry_key}")
    assert get_response.status_code == 200

    registry = get_response.json()
    assert registry["registry_key"] == registry_key
    assert registry["name"] == registry_name
    assert registry["issuer_aid"] == identity["aid"]


@pytest.mark.asyncio
async def test_registry_not_found(client: AsyncClient):
    """Test 404 for unknown registry key."""
    response = await client.get("/registry/Eunknown123456789012345678901234567890123")
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_list_registries(client: AsyncClient):
    """Test listing all registries."""
    identity = await create_test_identity(client)

    # Create a few registries
    name1 = unique_name("list-1")
    name2 = unique_name("list-2")

    await client.post(
        "/registry",
        json={"name": name1, "identity_name": identity["name"], "publish_to_witnesses": False},
    )
    await client.post(
        "/registry",
        json={"name": name2, "identity_name": identity["name"], "publish_to_witnesses": False},
    )

    # List all
    response = await client.get("/registry")
    assert response.status_code == 200
    data = response.json()

    assert "registries" in data
    assert data["count"] >= 2

    # Verify our registries are in the list
    registry_names = [r["name"] for r in data["registries"]]
    assert name1 in registry_names
    assert name2 in registry_names


@pytest.mark.asyncio
async def test_duplicate_registry_name_rejected(client: AsyncClient):
    """Test that duplicate registry names are rejected."""
    identity = await create_test_identity(client)
    registry_name = unique_name("duplicate-registry")

    # Create first
    response1 = await client.post(
        "/registry",
        json={
            "name": registry_name,
            "identity_name": identity["name"],
            "publish_to_witnesses": False,
        },
    )
    assert response1.status_code == 200

    # Try to create with same name
    response2 = await client.post(
        "/registry",
        json={
            "name": registry_name,
            "identity_name": identity["name"],
            "publish_to_witnesses": False,
        },
    )
    assert response2.status_code == 400
    assert "already exists" in response2.json()["detail"].lower()


@pytest.mark.asyncio
async def test_registry_with_backers(client: AsyncClient):
    """Test registry creation with no_backers=False."""
    identity = await create_test_identity(client)

    registry_name = unique_name("with-backers")
    response = await client.post(
        "/registry",
        json={
            "name": registry_name,
            "identity_name": identity["name"],
            "no_backers": False,
            "publish_to_witnesses": False,
        },
    )
    assert response.status_code == 200
    data = response.json()

    registry = data["registry"]
    assert registry["no_backers"] is False


@pytest.mark.asyncio
@pytest.mark.integration
async def test_registry_witness_publishing_integration():
    """Integration test: Verify TEL publishing to witnesses works.

    This test requires Docker witnesses to be running:
        docker compose up -d witnesses

    Run with: pytest -m integration --no-header -rN

    The test verifies:
    1. Registry creation succeeds
    2. TEL events are published to all witnesses
    3. All witnesses accept the events
    """
    import httpx
    import os

    issuer_url = os.getenv("VVP_ISSUER_URL", "http://localhost:8001")

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            health = await client.get(f"{issuer_url}/healthz")
            if health.status_code != 200:
                pytest.skip("Issuer not running")
    except Exception:
        pytest.skip("Cannot connect to issuer")

    async with httpx.AsyncClient(timeout=30.0) as client:
        # First create an identity
        identity_name = f"integ-issuer-{uuid.uuid4().hex[:8]}"
        id_response = await client.post(
            f"{issuer_url}/identity",
            json={"name": identity_name, "publish_to_witnesses": True},
        )
        assert id_response.status_code == 200
        identity = id_response.json()["identity"]

        # Create registry with witness publishing
        registry_name = f"integ-registry-{uuid.uuid4().hex[:8]}"
        response = await client.post(
            f"{issuer_url}/registry",
            json={
                "name": registry_name,
                "identity_name": identity_name,
                "publish_to_witnesses": True,
            },
        )

        assert response.status_code == 200, f"Registry creation failed: {response.text}"
        data = response.json()

        # Verify registry was created
        registry = data["registry"]
        assert registry["name"] == registry_name
        assert registry["issuer_aid"] == identity["aid"]
        assert registry["registry_key"].startswith("E")

        # Verify publishing results
        publish_results = data.get("publish_results")
        assert publish_results is not None, "Expected publish_results"
        assert len(publish_results) == 3, "Expected 3 witness results"

        # All witnesses should have accepted the TEL event
        success_count = sum(1 for r in publish_results if r["success"])
        assert success_count == 3, (
            f"Expected all 3 witnesses to succeed, got {success_count}. "
            f"Results: {publish_results}"
        )


# =============================================================================
# Delete Tests
# =============================================================================


@pytest.mark.asyncio
async def test_delete_registry_success(client: AsyncClient):
    """Test successful registry deletion via API."""
    # Create identity and registry
    identity = await create_test_identity(client)
    registry_name = unique_name("delete-registry")

    create_response = await client.post(
        "/registry",
        json={
            "name": registry_name,
            "identity_name": identity["name"],
            "publish_to_witnesses": False,
        },
    )
    assert create_response.status_code == 200
    registry_key = create_response.json()["registry"]["registry_key"]

    # Delete the registry
    delete_response = await client.delete(f"/registry/{registry_key}")
    assert delete_response.status_code == 200
    data = delete_response.json()

    assert data["deleted"] is True
    assert data["resource_type"] == "registry"
    assert data["resource_id"] == registry_key
    assert "message" in data

    # Verify registry is no longer found
    get_response = await client.get(f"/registry/{registry_key}")
    assert get_response.status_code == 404


@pytest.mark.asyncio
async def test_delete_registry_not_found(client: AsyncClient):
    """Test 404 when deleting non-existent registry."""
    response = await client.delete("/registry/Eunknown123456789012345678901234567890123")
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()
