"""Tests for identity management endpoints."""
import uuid

import pytest
from httpx import AsyncClient


def unique_name(prefix: str = "test") -> str:
    """Generate unique name for test identity."""
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


@pytest.mark.asyncio
async def test_create_identity(client: AsyncClient):
    """Test identity creation via API."""
    name = unique_name("create")
    response = await client.post(
        "/identity",
        json={"name": name, "transferable": True},
    )
    assert response.status_code == 200
    data = response.json()

    assert "identity" in data
    identity = data["identity"]
    assert identity["name"] == name
    assert identity["aid"].startswith("E")  # KERI AIDs start with E
    assert identity["transferable"] is True
    assert identity["key_count"] >= 1
    assert identity["sequence_number"] == 0

    # Check OOBI URLs are generated
    assert "oobi_urls" in data


@pytest.mark.asyncio
@pytest.mark.skip(reason="Non-transferable with witnesses has keripy SAID validation issue")
async def test_create_identity_non_transferable(client: AsyncClient):
    """Test creating non-transferable identity.

    Note: Non-transferable identities with witnesses have a keripy serialization
    issue that needs investigation. Skipping for now.
    """
    name = unique_name("non-transfer")
    response = await client.post(
        "/identity",
        json={"name": name, "transferable": False},
    )
    assert response.status_code == 200
    data = response.json()

    identity = data["identity"]
    assert identity["transferable"] is False


@pytest.mark.asyncio
async def test_get_identity_by_aid(client: AsyncClient):
    """Test getting identity by AID."""
    name = unique_name("get-by-aid")
    # Create identity first
    create_response = await client.post(
        "/identity",
        json={"name": name},
    )
    assert create_response.status_code == 200
    aid = create_response.json()["identity"]["aid"]

    # Get by AID
    get_response = await client.get(f"/identity/{aid}")
    assert get_response.status_code == 200
    assert get_response.json()["aid"] == aid
    assert get_response.json()["name"] == name


@pytest.mark.asyncio
async def test_identity_not_found(client: AsyncClient):
    """Test 404 for unknown AID."""
    response = await client.get("/identity/Eunknown123456789012345678901234567890123")
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_list_identities(client: AsyncClient):
    """Test listing all identities."""
    name1 = unique_name("list-1")
    name2 = unique_name("list-2")

    # Create a few identities
    await client.post("/identity", json={"name": name1})
    await client.post("/identity", json={"name": name2})

    # List all
    response = await client.get("/identity")
    assert response.status_code == 200
    data = response.json()

    assert "identities" in data
    assert data["count"] >= 2


@pytest.mark.asyncio
async def test_get_oobi(client: AsyncClient):
    """Test OOBI URL generation endpoint."""
    name = unique_name("oobi")
    # Create identity first
    create_response = await client.post(
        "/identity",
        json={"name": name},
    )
    assert create_response.status_code == 200
    aid = create_response.json()["identity"]["aid"]

    # Get OOBI URLs
    oobi_response = await client.get(f"/identity/{aid}/oobi")
    assert oobi_response.status_code == 200
    data = oobi_response.json()

    assert data["aid"] == aid
    assert "oobi_urls" in data
    # OOBI URLs should contain the AID
    for url in data["oobi_urls"]:
        assert aid in url
        assert "/oobi/" in url


@pytest.mark.asyncio
async def test_duplicate_name_rejected(client: AsyncClient):
    """Test that duplicate names are rejected."""
    name = unique_name("duplicate")

    # Create first
    response1 = await client.post("/identity", json={"name": name})
    assert response1.status_code == 200

    # Try to create with same name
    response2 = await client.post("/identity", json={"name": name})
    assert response2.status_code == 400
    assert "already exists" in response2.json()["detail"].lower()


@pytest.mark.asyncio
async def test_create_identity_with_publish_disabled(client: AsyncClient):
    """Test creating identity without publishing to witnesses."""
    name = unique_name("no-publish")
    response = await client.post(
        "/identity",
        json={"name": name, "publish_to_witnesses": False},
    )
    assert response.status_code == 200
    data = response.json()

    # Identity should be created
    assert data["identity"]["aid"].startswith("E")
    # No publish results when publishing is disabled
    assert data["publish_results"] is None


@pytest.mark.asyncio
@pytest.mark.integration
async def test_witness_publishing_integration():
    """Integration test: Verify witness publishing works.

    This test requires Docker witnesses to be running:
        docker compose up -d witnesses

    Run with: pytest -m integration --no-header -rN

    The test verifies:
    1. Identity creation succeeds
    2. Witness publishing sends events to all witnesses
    3. All witnesses accept the events (HTTP 200)

    NOTE: Full OOBI resolution requires the complete witness receipt
    protocol (collecting and distributing receipts between all witnesses).
    The current implementation gets events TO witnesses but doesn't
    complete the full receipt distribution needed for fullyWitnessed status.
    This is acceptable for Sprint 28 - full witness integration is planned
    for a future sprint.
    """
    import httpx
    import os

    # Skip if not running against Docker
    issuer_url = os.getenv("VVP_ISSUER_URL", "http://localhost:8001")

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            # Check issuer is running
            health = await client.get(f"{issuer_url}/healthz")
            if health.status_code != 200:
                pytest.skip("Issuer not running")
    except Exception:
        pytest.skip("Cannot connect to issuer")

    async with httpx.AsyncClient(timeout=30.0) as client:
        # Create identity with witness publishing
        import uuid
        name = f"integ-test-{uuid.uuid4().hex[:8]}"

        response = await client.post(
            f"{issuer_url}/identity",
            json={"name": name, "publish_to_witnesses": True},
        )

        assert response.status_code == 200, f"Identity creation failed: {response.text}"
        data = response.json()

        # Verify identity was created
        identity = data["identity"]
        assert identity["name"] == name
        assert identity["aid"].startswith("E")
        assert identity["witness_count"] == 3

        # Verify publishing results
        publish_results = data.get("publish_results")
        assert publish_results is not None, "Expected publish_results"
        assert len(publish_results) == 3, "Expected 3 witness results"

        # All witnesses should have accepted the event
        success_count = sum(1 for r in publish_results if r["success"])
        assert success_count == 3, (
            f"Expected all 3 witnesses to succeed, got {success_count}. "
            f"Results: {publish_results}"
        )

        # Verify OOBI URLs are generated
        oobi_urls = data.get("oobi_urls")
        assert oobi_urls is not None
        assert len(oobi_urls) == 3
        for url in oobi_urls:
            assert identity["aid"] in url
            assert "/oobi/" in url


# =============================================================================
# Rotation API Tests
# =============================================================================


@pytest.mark.asyncio
async def test_rotate_endpoint_success(client: AsyncClient):
    """Test rotation via API endpoint."""
    name = unique_name("api-rotate")

    # Create identity first
    create_response = await client.post(
        "/identity",
        json={"name": name, "transferable": True},
    )
    assert create_response.status_code == 200
    aid = create_response.json()["identity"]["aid"]
    original_sn = create_response.json()["identity"]["sequence_number"]
    assert original_sn == 0

    # Rotate keys
    rotate_response = await client.post(
        f"/identity/{aid}/rotate",
        json={"publish_to_witnesses": False},
    )
    assert rotate_response.status_code == 200
    data = rotate_response.json()

    # Verify response
    assert data["previous_sequence_number"] == 0
    assert data["identity"]["sequence_number"] == 1
    assert data["identity"]["aid"] == aid


@pytest.mark.asyncio
async def test_rotate_endpoint_not_found(client: AsyncClient):
    """Test rotation of non-existent identity returns 404."""
    response = await client.post(
        "/identity/Enonexistent12345678901234567890123456789012/rotate",
        json={},
    )
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


@pytest.mark.asyncio
@pytest.mark.skip(reason="Sprint 68b: threshold validation moved to KERI Agent service")
async def test_rotate_endpoint_invalid_threshold(client: AsyncClient):
    """Test rotation with invalid threshold returns 400."""
    name = unique_name("api-rotate-invalid")

    # Create identity first
    create_response = await client.post(
        "/identity",
        json={"name": name, "transferable": True},
    )
    assert create_response.status_code == 200
    aid = create_response.json()["identity"]["aid"]

    # Try to rotate with invalid threshold
    rotate_response = await client.post(
        f"/identity/{aid}/rotate",
        json={"next_key_count": 1, "next_threshold": "5"},  # Threshold > key count
    )
    assert rotate_response.status_code == 400
    assert "threshold" in rotate_response.json()["detail"].lower()


# =============================================================================
# Delete Tests
# =============================================================================


@pytest.mark.asyncio
async def test_delete_identity_success(client: AsyncClient):
    """Test successful identity deletion via API."""
    name = unique_name("delete")

    # Create identity first
    create_response = await client.post(
        "/identity",
        json={"name": name, "publish_to_witnesses": False},
    )
    assert create_response.status_code == 200
    aid = create_response.json()["identity"]["aid"]

    # Delete the identity
    delete_response = await client.delete(f"/identity/{aid}")
    assert delete_response.status_code == 200
    data = delete_response.json()

    assert data["deleted"] is True
    assert data["resource_type"] == "identity"
    assert data["resource_id"] == aid
    assert "message" in data

    # Verify identity is no longer found
    get_response = await client.get(f"/identity/{aid}")
    assert get_response.status_code == 404


@pytest.mark.asyncio
async def test_delete_identity_not_found(client: AsyncClient):
    """Test 404 when deleting non-existent identity."""
    response = await client.delete("/identity/Eunknown123456789012345678901234567890123")
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()
