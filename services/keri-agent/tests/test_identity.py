"""Tests for KERI Agent identity management endpoints.

Sprint 68: KERI Agent Service Extraction.
"""
import uuid

import pytest
from httpx import AsyncClient


def unique_name(prefix: str = "test") -> str:
    """Generate unique name for test identity."""
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


# =============================================================================
# Create Tests
# =============================================================================


@pytest.mark.asyncio
async def test_create_identity(client: AsyncClient):
    """Test identity creation via API."""
    name = unique_name("create")
    response = await client.post(
        "/identities",
        json={"name": name, "transferable": True},
    )
    assert response.status_code == 201
    data = response.json()

    assert data["name"] == name
    assert data["aid"].startswith("E")  # KERI AIDs start with E
    assert data["transferable"] is True
    assert data["key_count"] >= 1
    assert data["sequence_number"] == 0
    assert "created_at" in data


@pytest.mark.asyncio
async def test_create_identity_with_defaults(client: AsyncClient):
    """Test identity creation uses sensible defaults."""
    name = unique_name("defaults")
    response = await client.post(
        "/identities",
        json={"name": name},
    )
    assert response.status_code == 201
    data = response.json()

    assert data["transferable"] is True
    assert data["key_count"] >= 1


@pytest.mark.asyncio
async def test_duplicate_name_rejected(client: AsyncClient):
    """Test that duplicate names are rejected with 409."""
    name = unique_name("duplicate")

    response1 = await client.post("/identities", json={"name": name})
    assert response1.status_code == 201

    response2 = await client.post("/identities", json={"name": name})
    assert response2.status_code == 409
    assert "already exists" in response2.json()["detail"].lower()


# =============================================================================
# Get Tests
# =============================================================================


@pytest.mark.asyncio
async def test_get_identity_by_name(client: AsyncClient):
    """Test getting identity by name."""
    name = unique_name("get-by-name")
    create_response = await client.post(
        "/identities",
        json={"name": name},
    )
    assert create_response.status_code == 201
    aid = create_response.json()["aid"]

    get_response = await client.get(f"/identities/{name}")
    assert get_response.status_code == 200
    data = get_response.json()
    assert data["aid"] == aid
    assert data["name"] == name


@pytest.mark.asyncio
async def test_identity_not_found(client: AsyncClient):
    """Test 404 for unknown identity name."""
    response = await client.get("/identities/nonexistent-identity")
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_list_identities(client: AsyncClient):
    """Test listing all identities."""
    name1 = unique_name("list-1")
    name2 = unique_name("list-2")

    await client.post("/identities", json={"name": name1})
    await client.post("/identities", json={"name": name2})

    response = await client.get("/identities")
    assert response.status_code == 200
    data = response.json()

    assert isinstance(data, list)
    assert len(data) >= 2

    names = [i["name"] for i in data]
    assert name1 in names
    assert name2 in names


# =============================================================================
# Rotation Tests
# =============================================================================


@pytest.mark.asyncio
async def test_rotate_identity_success(client: AsyncClient):
    """Test successful identity key rotation via API."""
    name = unique_name("api-rotate")
    create_response = await client.post(
        "/identities",
        json={"name": name, "transferable": True},
    )
    assert create_response.status_code == 201
    aid = create_response.json()["aid"]
    assert create_response.json()["sequence_number"] == 0

    rotate_response = await client.post(
        f"/identities/{name}/rotate",
        json={},
    )
    assert rotate_response.status_code == 200
    data = rotate_response.json()

    assert data["aid"] == aid
    assert data["previous_sequence_number"] == 0
    assert data["new_sequence_number"] == 1
    assert data["new_key_count"] >= 1


@pytest.mark.asyncio
async def test_rotate_identity_not_found(client: AsyncClient):
    """Test rotation of non-existent identity returns 404."""
    response = await client.post(
        "/identities/nonexistent-identity/rotate",
        json={},
    )
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_rotate_invalid_threshold(client: AsyncClient):
    """Test rotation with invalid threshold returns 400."""
    name = unique_name("rotate-invalid")
    create_response = await client.post(
        "/identities",
        json={"name": name, "transferable": True},
    )
    assert create_response.status_code == 201

    rotate_response = await client.post(
        f"/identities/{name}/rotate",
        json={"new_key_count": 1, "new_threshold": "5"},
    )
    assert rotate_response.status_code == 400
    assert "threshold" in rotate_response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_rotate_with_custom_next_threshold(client: AsyncClient):
    """Test rotation with custom next key configuration."""
    name = unique_name("rotate-custom")
    create_response = await client.post(
        "/identities",
        json={"name": name, "transferable": True},
    )
    assert create_response.status_code == 201

    rotate_response = await client.post(
        f"/identities/{name}/rotate",
        json={"new_key_count": 2, "new_threshold": "1"},
    )
    assert rotate_response.status_code == 200
    assert rotate_response.json()["new_sequence_number"] == 1


# =============================================================================
# Persistence Tests (unit-level, no API)
# =============================================================================


@pytest.mark.asyncio
async def test_identity_persists_across_restart(temp_dir):
    """Test that identities persist after manager restart."""
    from app.keri.identity import IssuerIdentityManager

    name = unique_name("persist")

    mgr1 = IssuerIdentityManager(
        name="test-persist",
        base_dir=temp_dir,
        temp=False,
    )
    await mgr1.initialize()

    info = await mgr1.create_identity(name=name)
    aid = info.aid
    assert aid.startswith("E")

    await mgr1.close()

    mgr2 = IssuerIdentityManager(
        name="test-persist",
        base_dir=temp_dir,
        temp=False,
    )
    await mgr2.initialize()

    restored = await mgr2.get_identity(aid)
    assert restored is not None
    assert restored.aid == aid
    assert restored.name == name

    identities = await mgr2.list_identities()
    assert any(i.aid == aid for i in identities)

    await mgr2.close()


@pytest.mark.asyncio
async def test_get_kel_bytes(temp_dir):
    """Test that KEL bytes can be retrieved."""
    from app.keri.identity import IssuerIdentityManager

    name = unique_name("kel")

    mgr = IssuerIdentityManager(
        name="test-kel",
        base_dir=temp_dir,
        temp=True,
    )
    await mgr.initialize()

    info = await mgr.create_identity(name=name)
    aid = info.aid

    kel_bytes = await mgr.get_kel_bytes(aid)
    assert kel_bytes is not None
    assert len(kel_bytes) > 0
    assert aid.encode() in kel_bytes

    await mgr.close()


@pytest.mark.asyncio
async def test_rotation_persists_across_restart(temp_dir):
    """Test that rotated key state survives manager restart."""
    from app.keri.identity import IssuerIdentityManager

    name = unique_name("persist-rotate")

    mgr1 = IssuerIdentityManager(
        name="test-rotate-persist",
        base_dir=temp_dir,
        temp=False,
    )
    await mgr1.initialize()

    info = await mgr1.create_identity(name=name)
    result = await mgr1.rotate_identity(info.aid)
    assert result.new_sequence_number == 1

    await mgr1.close()

    mgr2 = IssuerIdentityManager(
        name="test-rotate-persist",
        base_dir=temp_dir,
        temp=False,
    )
    await mgr2.initialize()

    restored = await mgr2.get_identity(info.aid)
    assert restored is not None
    assert restored.sequence_number == 1

    await mgr2.close()


# =============================================================================
# KEL/OOBI API Tests
# =============================================================================


@pytest.mark.asyncio
async def test_get_kel_endpoint(client: AsyncClient):
    """Test GET /identities/{name}/kel returns CESR data."""
    name = unique_name("kel-api")
    create_response = await client.post(
        "/identities",
        json={"name": name},
    )
    assert create_response.status_code == 201

    kel_response = await client.get(f"/identities/{name}/kel")
    assert kel_response.status_code == 200
    assert kel_response.headers.get("content-type") == "application/cesr"
    assert len(kel_response.content) > 0


# =============================================================================
# Sprint 68b: AID Query Param Tests
# =============================================================================


@pytest.mark.asyncio
async def test_list_identities_filter_by_aid(client: AsyncClient):
    """Test GET /identities?aid={aid} returns matching identity."""
    name = unique_name("aid-filter")
    create_response = await client.post("/identities", json={"name": name})
    assert create_response.status_code == 201
    aid = create_response.json()["aid"]

    response = await client.get(f"/identities?aid={aid}")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["aid"] == aid
    assert data[0]["name"] == name


@pytest.mark.asyncio
async def test_list_identities_filter_by_unknown_aid(client: AsyncClient):
    """Test GET /identities?aid={unknown} returns empty list."""
    response = await client.get("/identities?aid=ENotARealAIDxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
    assert response.status_code == 200
    assert response.json() == []


# =============================================================================
# Sprint 68b: Delete Identity Tests
# =============================================================================


@pytest.mark.asyncio
async def test_delete_identity(client: AsyncClient):
    """Test DELETE /identities/{name} removes identity."""
    name = unique_name("delete")
    create_response = await client.post("/identities", json={"name": name})
    assert create_response.status_code == 201

    delete_response = await client.delete(f"/identities/{name}")
    assert delete_response.status_code == 204

    # Verify it's gone
    get_response = await client.get(f"/identities/{name}")
    assert get_response.status_code == 404


@pytest.mark.asyncio
async def test_delete_identity_not_found(client: AsyncClient):
    """Test DELETE /identities/{name} returns 404 for unknown."""
    response = await client.delete("/identities/nonexistent-identity")
    assert response.status_code == 404
