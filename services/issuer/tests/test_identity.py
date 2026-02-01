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
async def test_identity_persists_across_restart(temp_dir):
    """Test that identities persist after manager restart.

    This simulates a service restart by:
    1. Creating an identity with a fresh manager
    2. Closing the manager
    3. Creating a new manager pointing to the same storage
    4. Verifying the identity is still present
    """
    from app.keri.identity import IssuerIdentityManager

    name = unique_name("persist")

    # Create first manager and identity
    mgr1 = IssuerIdentityManager(
        name="test-persist",
        base_dir=temp_dir,
        temp=False,  # Use persistent storage
    )
    await mgr1.initialize()

    info = await mgr1.create_identity(name=name)
    aid = info.aid
    assert aid.startswith("E")

    # Close and recreate manager (simulates restart)
    await mgr1.close()

    # Create new manager pointing to same storage
    mgr2 = IssuerIdentityManager(
        name="test-persist",
        base_dir=temp_dir,
        temp=False,
    )
    await mgr2.initialize()

    # Verify identity still exists
    restored = await mgr2.get_identity(aid)
    assert restored is not None
    assert restored.aid == aid
    assert restored.name == name

    # Also verify it appears in list
    identities = await mgr2.list_identities()
    assert any(i.aid == aid for i in identities)

    await mgr2.close()


@pytest.mark.asyncio
async def test_get_kel_bytes(temp_dir):
    """Test that KEL bytes can be retrieved for publishing."""
    from app.keri.identity import IssuerIdentityManager

    name = unique_name("kel")

    mgr = IssuerIdentityManager(
        name="test-kel",
        base_dir=temp_dir,
        temp=True,
    )
    await mgr.initialize()

    # Create identity
    info = await mgr.create_identity(name=name)
    aid = info.aid

    # Get KEL bytes
    kel_bytes = await mgr.get_kel_bytes(aid)

    # Verify we got something
    assert kel_bytes is not None
    assert len(kel_bytes) > 0
    # KEL should contain the AID
    assert aid.encode() in kel_bytes

    await mgr.close()


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
# Rotation Tests
# =============================================================================


@pytest.mark.asyncio
async def test_rotate_identity_success(temp_dir):
    """Test successful identity key rotation."""
    from app.keri.identity import IssuerIdentityManager

    name = unique_name("rotate")

    mgr = IssuerIdentityManager(
        name="test-rotate",
        base_dir=temp_dir,
        temp=True,
    )
    await mgr.initialize()

    # Create transferable identity
    info = await mgr.create_identity(name=name, transferable=True)
    assert info.sequence_number == 0

    # Rotate keys
    result = await mgr.rotate_identity(info.aid)

    # Verify sequence number incremented
    assert result.previous_sequence_number == 0
    assert result.new_sequence_number == 1
    assert result.aid == info.aid
    assert result.name == name
    assert result.new_key_count >= 1

    # Verify rotation event bytes are present
    assert result.rotation_event_bytes is not None
    assert len(result.rotation_event_bytes) > 0

    # Verify identity state is updated
    updated = await mgr.get_identity(info.aid)
    assert updated.sequence_number == 1

    await mgr.close()


@pytest.mark.asyncio
async def test_rotate_identity_not_found(temp_dir):
    """Test rotation of non-existent identity raises error."""
    from app.keri.identity import IssuerIdentityManager
    from app.keri.exceptions import IdentityNotFoundError

    mgr = IssuerIdentityManager(
        name="test-rotate-notfound",
        base_dir=temp_dir,
        temp=True,
    )
    await mgr.initialize()

    # Try to rotate non-existent identity
    with pytest.raises(IdentityNotFoundError):
        await mgr.rotate_identity("Enonexistent12345678901234567890123456789012")

    await mgr.close()


@pytest.mark.asyncio
async def test_rotate_invalid_threshold(temp_dir):
    """Test rotation with invalid threshold raises error."""
    from app.keri.identity import IssuerIdentityManager
    from app.keri.exceptions import InvalidRotationThresholdError

    mgr = IssuerIdentityManager(
        name="test-rotate-threshold",
        base_dir=temp_dir,
        temp=True,
    )
    await mgr.initialize()

    # Create identity
    info = await mgr.create_identity(name=unique_name("threshold"))

    # Try to rotate with threshold > key count
    with pytest.raises(InvalidRotationThresholdError):
        await mgr.rotate_identity(
            info.aid,
            next_key_count=1,
            next_threshold="2",  # Threshold exceeds key count
        )

    await mgr.close()


@pytest.mark.asyncio
async def test_rotate_with_custom_next_threshold(temp_dir):
    """Test rotation with custom next key configuration."""
    from app.keri.identity import IssuerIdentityManager

    mgr = IssuerIdentityManager(
        name="test-rotate-custom",
        base_dir=temp_dir,
        temp=True,
    )
    await mgr.initialize()

    # Create identity
    info = await mgr.create_identity(name=unique_name("custom"))

    # Rotate with custom next key count
    result = await mgr.rotate_identity(
        info.aid,
        next_key_count=2,
        next_threshold="1",
    )

    assert result.new_sequence_number == 1
    # Rotation should succeed with valid threshold
    assert result.rotation_event_bytes is not None

    await mgr.close()


@pytest.mark.asyncio
async def test_rotation_event_bytes_valid(temp_dir):
    """Test that rotation event bytes contain expected content."""
    from app.keri.identity import IssuerIdentityManager

    mgr = IssuerIdentityManager(
        name="test-rotate-bytes",
        base_dir=temp_dir,
        temp=True,
    )
    await mgr.initialize()

    # Create identity
    info = await mgr.create_identity(name=unique_name("bytes"))

    # Rotate keys
    result = await mgr.rotate_identity(info.aid)

    # Verify rotation event contains the AID
    assert info.aid.encode() in result.rotation_event_bytes

    await mgr.close()


@pytest.mark.asyncio
async def test_rotation_persists_across_restart(temp_dir):
    """Test that rotated key state survives manager restart."""
    from app.keri.identity import IssuerIdentityManager

    name = unique_name("persist-rotate")

    # Create first manager and identity
    mgr1 = IssuerIdentityManager(
        name="test-rotate-persist",
        base_dir=temp_dir,
        temp=False,  # Use persistent storage
    )
    await mgr1.initialize()

    info = await mgr1.create_identity(name=name)
    assert info.sequence_number == 0

    # Rotate keys
    result = await mgr1.rotate_identity(info.aid)
    assert result.new_sequence_number == 1

    # Close and recreate manager (simulates restart)
    await mgr1.close()

    # Create new manager pointing to same storage
    mgr2 = IssuerIdentityManager(
        name="test-rotate-persist",
        base_dir=temp_dir,
        temp=False,
    )
    await mgr2.initialize()

    # Verify rotated state persisted
    restored = await mgr2.get_identity(info.aid)
    assert restored is not None
    assert restored.sequence_number == 1  # Still 1 after restart

    await mgr2.close()


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
