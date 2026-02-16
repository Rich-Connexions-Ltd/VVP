"""Tests for KERI Agent ACDC credential issuance endpoints.

Sprint 68: KERI Agent Service Extraction.

Note: Unlike the issuer tests, the KERI Agent tests do NOT require
Organization/DB context or schema authorization. Those are business
logic concerns handled by the issuer.
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


async def setup_identity_and_registry(client: AsyncClient) -> tuple[dict, dict]:
    """Helper to set up identity and registry for credential tests.

    Returns (identity, registry).
    """
    identity = await create_test_identity(client)
    registry = await create_test_registry(client, identity["name"])
    return identity, registry


# =============================================================================
# Basic Issuance Tests
# =============================================================================


@pytest.mark.asyncio
async def test_issue_credential_basic(client: AsyncClient):
    """Test basic credential issuance via API."""
    identity, registry = await setup_identity_and_registry(client)

    response = await client.post(
        "/credentials/issue",
        json={
            "identity_name": identity["name"],
            "registry_name": registry["name"],
            "schema_said": TN_ALLOCATION_SCHEMA,
            "attributes": {
                "numbers": {"tn": ["+12025551234"]},
                "channel": "voice",
                "doNotOriginate": False,
            },
            "publish": False,
        },
    )
    assert response.status_code == 201, f"Credential issuance failed: {response.text}"
    data = response.json()

    assert data["said"].startswith("E")
    assert data["issuer_aid"] == identity["aid"]
    assert data["registry_key"] == registry["registry_key"]
    assert data["schema_said"] == TN_ALLOCATION_SCHEMA
    assert data["status"] == "issued"
    assert data["revocation_dt"] is None


@pytest.mark.asyncio
async def test_issue_credential_with_recipient(client: AsyncClient):
    """Test credential issuance with recipient AID."""
    identity, registry = await setup_identity_and_registry(client)
    recipient = await create_test_identity(client)

    response = await client.post(
        "/credentials/issue",
        json={
            "identity_name": identity["name"],
            "registry_name": registry["name"],
            "schema_said": TN_ALLOCATION_SCHEMA,
            "attributes": {
                "numbers": {"tn": ["+12025551234"]},
                "channel": "sms",
                "doNotOriginate": True,
            },
            "recipient_aid": recipient["aid"],
            "publish": False,
        },
    )
    assert response.status_code == 201, f"Credential issuance failed: {response.text}"
    data = response.json()

    assert data["recipient_aid"] == recipient["aid"]


# =============================================================================
# Error Cases
# =============================================================================


@pytest.mark.asyncio
async def test_issue_credential_identity_not_found(client: AsyncClient):
    """Test 404 when identity doesn't exist."""
    identity, registry = await setup_identity_and_registry(client)

    response = await client.post(
        "/credentials/issue",
        json={
            "identity_name": "nonexistent-identity",
            "registry_name": registry["name"],
            "schema_said": TN_ALLOCATION_SCHEMA,
            "attributes": {"test": "data"},
            "publish": False,
        },
    )
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_issue_credential_registry_not_found(client: AsyncClient):
    """Test 400 when registry doesn't exist."""
    identity, registry = await setup_identity_and_registry(client)

    response = await client.post(
        "/credentials/issue",
        json={
            "identity_name": identity["name"],
            "registry_name": "nonexistent-registry",
            "schema_said": TN_ALLOCATION_SCHEMA,
            "attributes": {"test": "data"},
            "publish": False,
        },
    )
    assert response.status_code == 400
    assert "not found" in response.json()["detail"].lower()


# =============================================================================
# Get Credential Tests
# =============================================================================


@pytest.mark.asyncio
async def test_get_credential(client: AsyncClient):
    """Test getting credential by SAID."""
    identity, registry = await setup_identity_and_registry(client)

    issue_response = await client.post(
        "/credentials/issue",
        json={
            "identity_name": identity["name"],
            "registry_name": registry["name"],
            "schema_said": TN_ALLOCATION_SCHEMA,
            "attributes": {
                "numbers": {"tn": ["+12025551234"]},
                "channel": "voice",
                "doNotOriginate": False,
            },
            "publish": False,
        },
    )
    assert issue_response.status_code == 201
    cred_said = issue_response.json()["said"]

    response = await client.get(f"/credentials/{cred_said}")
    assert response.status_code == 200
    data = response.json()

    assert data["said"] == cred_said
    assert data["status"] == "issued"
    assert "attributes" in data


@pytest.mark.asyncio
async def test_get_credential_not_found(client: AsyncClient):
    """Test 404 when credential doesn't exist."""
    response = await client.get("/credentials/Enonexistent12345678901234567890123456789012")
    assert response.status_code == 404


# =============================================================================
# List Credentials Tests
# =============================================================================


@pytest.mark.asyncio
async def test_list_credentials(client: AsyncClient):
    """Test listing all credentials."""
    identity, registry = await setup_identity_and_registry(client)

    for i in range(2):
        response = await client.post(
            "/credentials/issue",
            json={
                "identity_name": identity["name"],
                "registry_name": registry["name"],
                "schema_said": TN_ALLOCATION_SCHEMA,
                "attributes": {
                    "numbers": {"tn": [f"+1202555123{i}"]},
                    "channel": "voice",
                    "doNotOriginate": False,
                },
                "publish": False,
            },
        )
        assert response.status_code == 201

    response = await client.get("/credentials")
    assert response.status_code == 200
    data = response.json()

    assert isinstance(data, list)
    assert len(data) >= 2


@pytest.mark.asyncio
async def test_list_credentials_filter_by_registry(client: AsyncClient):
    """Test listing credentials filtered by registry key."""
    identity, registry1 = await setup_identity_and_registry(client)
    registry2 = await create_test_registry(client, identity["name"])

    # Issue credential to registry1
    await client.post(
        "/credentials/issue",
        json={
            "identity_name": identity["name"],
            "registry_name": registry1["name"],
            "schema_said": TN_ALLOCATION_SCHEMA,
            "attributes": {
                "numbers": {"tn": ["+12025551111"]},
                "channel": "voice",
                "doNotOriginate": False,
            },
            "publish": False,
        },
    )

    # Issue credential to registry2
    await client.post(
        "/credentials/issue",
        json={
            "identity_name": identity["name"],
            "registry_name": registry2["name"],
            "schema_said": TN_ALLOCATION_SCHEMA,
            "attributes": {
                "numbers": {"tn": ["+12025552222"]},
                "channel": "voice",
                "doNotOriginate": False,
            },
            "publish": False,
        },
    )

    response = await client.get(f"/credentials?registry_key={registry1['registry_key']}")
    assert response.status_code == 200
    data = response.json()

    for cred in data:
        assert cred["registry_key"] == registry1["registry_key"]


@pytest.mark.asyncio
async def test_list_credentials_filter_by_status(client: AsyncClient):
    """Test listing credentials filtered by status."""
    identity, registry = await setup_identity_and_registry(client)

    await client.post(
        "/credentials/issue",
        json={
            "identity_name": identity["name"],
            "registry_name": registry["name"],
            "schema_said": TN_ALLOCATION_SCHEMA,
            "attributes": {
                "numbers": {"tn": ["+12025551234"]},
                "channel": "voice",
                "doNotOriginate": False,
            },
            "publish": False,
        },
    )

    response = await client.get("/credentials?status=issued")
    assert response.status_code == 200
    data = response.json()

    for cred in data:
        assert cred["status"] == "issued"


# =============================================================================
# Revocation Tests
# =============================================================================


@pytest.mark.asyncio
async def test_revoke_credential(client: AsyncClient):
    """Test credential revocation."""
    identity, registry = await setup_identity_and_registry(client)

    issue_response = await client.post(
        "/credentials/issue",
        json={
            "identity_name": identity["name"],
            "registry_name": registry["name"],
            "schema_said": TN_ALLOCATION_SCHEMA,
            "attributes": {
                "numbers": {"tn": ["+12025551234"]},
                "channel": "voice",
                "doNotOriginate": False,
            },
            "publish": False,
        },
    )
    assert issue_response.status_code == 201
    cred_said = issue_response.json()["said"]

    response = await client.post(
        f"/credentials/{cred_said}/revoke",
        json={"publish": False},
    )
    assert response.status_code == 200
    data = response.json()

    assert data["said"] == cred_said
    assert data["status"] == "revoked"
    assert data["revocation_dt"] is not None


@pytest.mark.asyncio
async def test_revoke_credential_not_found(client: AsyncClient):
    """Test 400 when credential doesn't exist."""
    response = await client.post(
        "/credentials/Enonexistent12345678901234567890123456789012/revoke",
        json={"publish": False},
    )
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_revoke_credential_already_revoked(client: AsyncClient):
    """Test 400 when credential is already revoked."""
    identity, registry = await setup_identity_and_registry(client)

    issue_response = await client.post(
        "/credentials/issue",
        json={
            "identity_name": identity["name"],
            "registry_name": registry["name"],
            "schema_said": TN_ALLOCATION_SCHEMA,
            "attributes": {
                "numbers": {"tn": ["+12025551234"]},
                "channel": "voice",
                "doNotOriginate": False,
            },
            "publish": False,
        },
    )
    assert issue_response.status_code == 201
    cred_said = issue_response.json()["said"]

    # Revoke once
    response = await client.post(
        f"/credentials/{cred_said}/revoke",
        json={"publish": False},
    )
    assert response.status_code == 200

    # Try to revoke again
    response = await client.post(
        f"/credentials/{cred_said}/revoke",
        json={"publish": False},
    )
    assert response.status_code == 400
    assert "already revoked" in response.json()["detail"].lower()


# =============================================================================
# CESR Bytes Tests
# =============================================================================


@pytest.mark.asyncio
async def test_get_credential_cesr(client: AsyncClient):
    """Test GET /credentials/{said}/cesr returns CESR data."""
    identity, registry = await setup_identity_and_registry(client)

    issue_response = await client.post(
        "/credentials/issue",
        json={
            "identity_name": identity["name"],
            "registry_name": registry["name"],
            "schema_said": TN_ALLOCATION_SCHEMA,
            "attributes": {
                "numbers": {"tn": ["+12025551234"]},
                "channel": "voice",
                "doNotOriginate": False,
            },
            "publish": False,
        },
    )
    assert issue_response.status_code == 201
    cred_said = issue_response.json()["said"]

    cesr_response = await client.get(f"/credentials/{cred_said}/cesr")
    assert cesr_response.status_code == 200
    assert cesr_response.headers.get("content-type") == "application/cesr"
    assert len(cesr_response.content) > 0


@pytest.mark.asyncio
async def test_get_credential_cesr_not_found(client: AsyncClient):
    """Test 404 for CESR of unknown credential."""
    response = await client.get("/credentials/Enonexistent12345678901234567890123456789012/cesr")
    assert response.status_code == 404


# =============================================================================
# Sprint 68b: Delete Credential Tests
# =============================================================================


@pytest.mark.asyncio
async def test_delete_credential(client: AsyncClient):
    """Test DELETE /credentials/{said} removes credential."""
    identity, registry = await setup_identity_and_registry(client)
    issue_response = await client.post(
        "/credentials/issue",
        json={
            "identity_name": identity["name"],
            "registry_name": registry["name"],
            "schema_said": TN_ALLOCATION_SCHEMA,
            "attributes": {
                "numbers": {"tn": ["+12025559999"]},
                "channel": "voice",
                "doNotOriginate": False,
            },
            "publish": False,
        },
    )
    assert issue_response.status_code == 201
    said = issue_response.json()["said"]

    delete_response = await client.delete(f"/credentials/{said}")
    assert delete_response.status_code == 204

    # Verify it's gone
    get_response = await client.get(f"/credentials/{said}")
    assert get_response.status_code == 404


@pytest.mark.asyncio
async def test_delete_credential_not_found(client: AsyncClient):
    """Test DELETE /credentials/{said} returns 404 for unknown."""
    response = await client.delete("/credentials/Enonexistent12345678901234567890123456789012")
    assert response.status_code == 404
