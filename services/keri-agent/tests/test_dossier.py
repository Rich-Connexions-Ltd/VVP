"""Tests for KERI Agent dossier build/get endpoints.

Sprint 68: KERI Agent Service Extraction.
"""
import uuid

import pytest
from httpx import AsyncClient


# TN Allocation schema SAID
TN_ALLOCATION_SCHEMA = "EFvnoHDY7I-kaBBeKlbDbkjG4BaI0nKLGadxBdjMGgSQ"


def unique_name(prefix: str = "test") -> str:
    """Generate unique name for test resources."""
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


async def create_test_identity(client: AsyncClient, name: str = None) -> dict:
    """Helper to create a test identity."""
    name = name or unique_name("identity")
    response = await client.post(
        "/identities",
        json={"name": name},
    )
    assert response.status_code == 201, f"Failed to create identity: {response.text}"
    return response.json()


async def create_test_registry(
    client: AsyncClient, identity_name: str, registry_name: str = None
) -> dict:
    """Helper to create a test registry."""
    registry_name = registry_name or unique_name("registry")
    response = await client.post(
        "/registries",
        json={
            "name": registry_name,
            "identity_name": identity_name,
        },
    )
    assert response.status_code == 201, f"Failed to create registry: {response.text}"
    return response.json()


async def issue_test_credential(
    client: AsyncClient,
    identity_name: str,
    registry_name: str,
    edges: dict = None,
) -> str:
    """Issue a test credential and return its SAID."""
    response = await client.post(
        "/credentials/issue",
        json={
            "identity_name": identity_name,
            "registry_name": registry_name,
            "schema_said": TN_ALLOCATION_SCHEMA,
            "attributes": {
                "numbers": {"tn": [f"+1202555{uuid.uuid4().hex[:4]}"]},
                "channel": "voice",
                "doNotOriginate": False,
            },
            "edges": edges,
            "publish": False,
        },
    )
    assert response.status_code == 201, f"Failed to issue credential: {response.text}"
    return response.json()["said"]


# =============================================================================
# Single Credential Dossier
# =============================================================================


@pytest.mark.asyncio
async def test_build_single_credential_dossier(client: AsyncClient):
    """Test building a dossier with a single credential."""
    identity = await create_test_identity(client)
    registry = await create_test_registry(client, identity["name"])
    cred_said = await issue_test_credential(client, identity["name"], registry["name"])

    response = await client.post(
        "/dossiers/build",
        json={
            "root_said": cred_said,
            "include_tel": True,
        },
    )
    assert response.status_code == 201, f"Dossier build failed: {response.text}"
    data = response.json()

    assert data["root_said"] == cred_said
    assert cred_said in data["credential_saids"]
    assert data["is_aggregate"] is False


@pytest.mark.asyncio
async def test_get_dossier_by_said(client: AsyncClient):
    """Test retrieving a previously built dossier."""
    identity = await create_test_identity(client)
    registry = await create_test_registry(client, identity["name"])
    cred_said = await issue_test_credential(client, identity["name"], registry["name"])

    # Build it first
    build_response = await client.post(
        "/dossiers/build",
        json={"root_said": cred_said},
    )
    assert build_response.status_code == 201

    # Get it by SAID
    get_response = await client.get(f"/dossiers/{cred_said}")
    assert get_response.status_code == 200
    data = get_response.json()

    assert data["root_said"] == cred_said


@pytest.mark.asyncio
async def test_get_dossier_not_found(client: AsyncClient):
    """Test 404 when dossier hasn't been built yet."""
    response = await client.get("/dossiers/Enonexistent12345678901234567890123456789012")
    assert response.status_code == 404


# =============================================================================
# Chained Credentials Dossier
# =============================================================================


@pytest.mark.asyncio
async def test_build_chained_dossier(client: AsyncClient):
    """Test building a dossier with chained credentials (edge references)."""
    identity = await create_test_identity(client)
    registry = await create_test_registry(client, identity["name"])

    # Issue root credential
    root_said = await issue_test_credential(client, identity["name"], registry["name"])

    # Issue child credential with edge to root
    child_said = await issue_test_credential(
        client,
        identity["name"],
        registry["name"],
        edges={"parent": {"n": root_said, "s": TN_ALLOCATION_SCHEMA}},
    )

    # Build dossier from child (should include both)
    response = await client.post(
        "/dossiers/build",
        json={"root_said": child_said, "include_tel": True},
    )
    assert response.status_code == 201
    data = response.json()

    # Both credentials should be in the dossier
    assert child_said in data["credential_saids"]
    assert root_said in data["credential_saids"]


# =============================================================================
# CESR Format
# =============================================================================


@pytest.mark.asyncio
async def test_get_dossier_cesr(client: AsyncClient):
    """Test GET /dossiers/{said}/cesr returns CESR data."""
    identity = await create_test_identity(client)
    registry = await create_test_registry(client, identity["name"])
    cred_said = await issue_test_credential(client, identity["name"], registry["name"])

    # Build first
    build_response = await client.post(
        "/dossiers/build",
        json={"root_said": cred_said, "include_tel": True},
    )
    assert build_response.status_code == 201

    # Get CESR
    cesr_response = await client.get(f"/dossiers/{cred_said}/cesr")
    assert cesr_response.status_code == 200
    assert cesr_response.headers.get("content-type") == "application/cesr"
    assert len(cesr_response.content) > 0


@pytest.mark.asyncio
async def test_get_dossier_cesr_not_found(client: AsyncClient):
    """Test 404 for CESR of unknown dossier."""
    response = await client.get("/dossiers/Enonexistent12345678901234567890123456789012/cesr")
    assert response.status_code == 404


# =============================================================================
# Error Cases
# =============================================================================


@pytest.mark.asyncio
async def test_build_dossier_credential_not_found(client: AsyncClient):
    """Test error when root credential doesn't exist."""
    response = await client.post(
        "/dossiers/build",
        json={"root_said": "Enonexistent12345678901234567890123456789012"},
    )
    # Should return 400 or 500 depending on builder error
    assert response.status_code in (400, 500)


@pytest.mark.asyncio
async def test_dangling_edge_warning(client: AsyncClient):
    """Test that dossier handles missing edge targets with warnings."""
    identity = await create_test_identity(client)
    registry = await create_test_registry(client, identity["name"])

    # Issue credential with edge pointing to nonexistent credential
    cred_said = await issue_test_credential(
        client,
        identity["name"],
        registry["name"],
        edges={"missing": {"n": "Enonexistent12345678901234567890123456789012", "s": TN_ALLOCATION_SCHEMA}},
    )

    # Build dossier - should succeed with warnings
    response = await client.post(
        "/dossiers/build",
        json={"root_said": cred_said},
    )
    # Should succeed (200/201) with warnings about the dangling edge
    assert response.status_code in (200, 201)
    data = response.json()

    # The credential itself should be in the dossier
    assert cred_said in data["credential_saids"]
    # Should have warnings about the dangling edge
    assert len(data["warnings"]) > 0
