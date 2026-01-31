"""Tests for ACDC credential issuance endpoints."""
import uuid

import pytest
from httpx import AsyncClient


# TN Allocation schema SAID
TN_ALLOCATION_SCHEMA = "EFvnoHDY7I-kaBBeKlbDbkjG4BaI0nKLGadxBdjMGgSQ"

# Legal Entity schema SAID
LEGAL_ENTITY_SCHEMA = "ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY"


def unique_name(prefix: str = "test") -> str:
    """Generate unique name for test resources."""
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


async def create_test_identity(client: AsyncClient, name: str = None) -> dict:
    """Helper to create a test identity."""
    name = name or unique_name("identity")
    response = await client.post(
        "/identity",
        json={"name": name, "publish_to_witnesses": False},
    )
    assert response.status_code == 200, f"Failed to create identity: {response.text}"
    return response.json()["identity"]


async def create_test_registry(
    client: AsyncClient, identity_name: str, registry_name: str = None
) -> dict:
    """Helper to create a test registry."""
    registry_name = registry_name or unique_name("registry")
    response = await client.post(
        "/registry",
        json={
            "name": registry_name,
            "identity_name": identity_name,
            "publish_to_witnesses": False,
        },
    )
    assert response.status_code == 200, f"Failed to create registry: {response.text}"
    return response.json()["registry"]


async def setup_identity_and_registry(client: AsyncClient) -> tuple[dict, dict]:
    """Helper to set up identity and registry for credential tests."""
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
        "/credential/issue",
        json={
            "registry_name": registry["name"],
            "schema_said": TN_ALLOCATION_SCHEMA,
            "attributes": {
                "numbers": {"tn": ["+12025551234"]},
                "channel": "voice",
                "doNotOriginate": False,
            },
            "publish_to_witnesses": False,
        },
    )
    assert response.status_code == 200, f"Credential issuance failed: {response.text}"
    data = response.json()

    assert "credential" in data
    cred = data["credential"]
    assert cred["said"].startswith("E")  # KERI SAIDs start with E
    assert cred["issuer_aid"] == identity["aid"]
    assert cred["registry_key"] == registry["registry_key"]
    assert cred["schema_said"] == TN_ALLOCATION_SCHEMA
    assert cred["status"] == "issued"
    assert cred["revocation_dt"] is None


@pytest.mark.asyncio
async def test_issue_credential_with_recipient(client: AsyncClient):
    """Test credential issuance with recipient AID."""
    identity, registry = await setup_identity_and_registry(client)

    # Create another identity as recipient
    recipient = await create_test_identity(client)

    response = await client.post(
        "/credential/issue",
        json={
            "registry_name": registry["name"],
            "schema_said": TN_ALLOCATION_SCHEMA,
            "attributes": {
                "numbers": {"tn": ["+12025551234"]},
                "channel": "sms",
                "doNotOriginate": True,
            },
            "recipient_aid": recipient["aid"],
            "publish_to_witnesses": False,
        },
    )
    assert response.status_code == 200, f"Credential issuance failed: {response.text}"
    data = response.json()

    cred = data["credential"]
    assert cred["recipient_aid"] == recipient["aid"]


@pytest.mark.asyncio
async def test_issue_credential_private(client: AsyncClient):
    """Test credential issuance with privacy-preserving nonces."""
    identity, registry = await setup_identity_and_registry(client)

    response = await client.post(
        "/credential/issue",
        json={
            "registry_name": registry["name"],
            "schema_said": TN_ALLOCATION_SCHEMA,
            "attributes": {
                "numbers": {"tn": ["+12025551234"]},
                "channel": "voice",
                "doNotOriginate": False,
            },
            "private": True,
            "publish_to_witnesses": False,
        },
    )
    assert response.status_code == 200, f"Credential issuance failed: {response.text}"
    data = response.json()

    # Credential should be issued successfully
    cred = data["credential"]
    assert cred["status"] == "issued"


# =============================================================================
# Error Cases
# =============================================================================


@pytest.mark.asyncio
async def test_issue_credential_registry_not_found(client: AsyncClient):
    """Test 400 when registry doesn't exist."""
    response = await client.post(
        "/credential/issue",
        json={
            "registry_name": "nonexistent-registry",
            "schema_said": TN_ALLOCATION_SCHEMA,
            "attributes": {
                "numbers": {"tn": ["+12025551234"]},
                "channel": "voice",
                "doNotOriginate": False,
            },
            "publish_to_witnesses": False,
        },
    )
    assert response.status_code == 400
    assert "not found" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_issue_credential_schema_not_found(client: AsyncClient):
    """Test 400 when schema doesn't exist."""
    identity, registry = await setup_identity_and_registry(client)

    response = await client.post(
        "/credential/issue",
        json={
            "registry_name": registry["name"],
            "schema_said": "Enonexistent12345678901234567890123456789012",
            "attributes": {"test": "data"},
            "publish_to_witnesses": False,
        },
    )
    assert response.status_code == 400
    assert "schema not found" in response.json()["detail"].lower()


# =============================================================================
# Get Credential Tests
# =============================================================================


@pytest.mark.asyncio
async def test_get_credential(client: AsyncClient):
    """Test getting credential by SAID."""
    identity, registry = await setup_identity_and_registry(client)

    # Issue a credential first
    issue_response = await client.post(
        "/credential/issue",
        json={
            "registry_name": registry["name"],
            "schema_said": TN_ALLOCATION_SCHEMA,
            "attributes": {
                "numbers": {"tn": ["+12025551234"]},
                "channel": "voice",
                "doNotOriginate": False,
            },
            "publish_to_witnesses": False,
        },
    )
    assert issue_response.status_code == 200
    cred_said = issue_response.json()["credential"]["said"]

    # Get the credential
    response = await client.get(f"/credential/{cred_said}")
    assert response.status_code == 200, f"Get credential failed: {response.text}"
    data = response.json()

    assert data["said"] == cred_said
    assert data["status"] == "issued"
    assert "attributes" in data
    assert data["attributes"]["channel"] == "voice"


@pytest.mark.asyncio
async def test_get_credential_not_found(client: AsyncClient):
    """Test 404 when credential doesn't exist."""
    response = await client.get("/credential/Enonexistent12345678901234567890123456789012")
    assert response.status_code == 404


# =============================================================================
# List Credentials Tests
# =============================================================================


@pytest.mark.asyncio
async def test_list_credentials(client: AsyncClient):
    """Test listing all credentials."""
    identity, registry = await setup_identity_and_registry(client)

    # Issue two credentials
    for i in range(2):
        response = await client.post(
            "/credential/issue",
            json={
                "registry_name": registry["name"],
                "schema_said": TN_ALLOCATION_SCHEMA,
                "attributes": {
                    "numbers": {"tn": [f"+1202555123{i}"]},
                    "channel": "voice",
                    "doNotOriginate": False,
                },
                "publish_to_witnesses": False,
            },
        )
        assert response.status_code == 200

    # List credentials
    response = await client.get("/credential")
    assert response.status_code == 200
    data = response.json()

    assert data["count"] >= 2
    assert len(data["credentials"]) >= 2


@pytest.mark.asyncio
async def test_list_credentials_filter_by_registry(client: AsyncClient):
    """Test listing credentials filtered by registry key."""
    identity, registry1 = await setup_identity_and_registry(client)
    registry2 = await create_test_registry(client, identity["name"])

    # Issue credential to registry1
    response = await client.post(
        "/credential/issue",
        json={
            "registry_name": registry1["name"],
            "schema_said": TN_ALLOCATION_SCHEMA,
            "attributes": {
                "numbers": {"tn": ["+12025551111"]},
                "channel": "voice",
                "doNotOriginate": False,
            },
            "publish_to_witnesses": False,
        },
    )
    assert response.status_code == 200

    # Issue credential to registry2
    response = await client.post(
        "/credential/issue",
        json={
            "registry_name": registry2["name"],
            "schema_said": TN_ALLOCATION_SCHEMA,
            "attributes": {
                "numbers": {"tn": ["+12025552222"]},
                "channel": "voice",
                "doNotOriginate": False,
            },
            "publish_to_witnesses": False,
        },
    )
    assert response.status_code == 200

    # List credentials filtered by registry1
    response = await client.get(f"/credential?registry_key={registry1['registry_key']}")
    assert response.status_code == 200
    data = response.json()

    # Should only include credentials from registry1
    for cred in data["credentials"]:
        assert cred["registry_key"] == registry1["registry_key"]


@pytest.mark.asyncio
async def test_list_credentials_filter_by_status(client: AsyncClient):
    """Test listing credentials filtered by status."""
    identity, registry = await setup_identity_and_registry(client)

    # Issue a credential
    issue_response = await client.post(
        "/credential/issue",
        json={
            "registry_name": registry["name"],
            "schema_said": TN_ALLOCATION_SCHEMA,
            "attributes": {
                "numbers": {"tn": ["+12025551234"]},
                "channel": "voice",
                "doNotOriginate": False,
            },
            "publish_to_witnesses": False,
        },
    )
    assert issue_response.status_code == 200

    # List only issued credentials
    response = await client.get("/credential?status=issued")
    assert response.status_code == 200
    data = response.json()

    for cred in data["credentials"]:
        assert cred["status"] == "issued"


# =============================================================================
# Revocation Tests
# =============================================================================


@pytest.mark.asyncio
async def test_revoke_credential(client: AsyncClient):
    """Test credential revocation."""
    identity, registry = await setup_identity_and_registry(client)

    # Issue a credential
    issue_response = await client.post(
        "/credential/issue",
        json={
            "registry_name": registry["name"],
            "schema_said": TN_ALLOCATION_SCHEMA,
            "attributes": {
                "numbers": {"tn": ["+12025551234"]},
                "channel": "voice",
                "doNotOriginate": False,
            },
            "publish_to_witnesses": False,
        },
    )
    assert issue_response.status_code == 200
    cred_said = issue_response.json()["credential"]["said"]

    # Revoke the credential
    response = await client.post(
        f"/credential/{cred_said}/revoke",
        json={"reason": "Testing revocation", "publish_to_witnesses": False},
    )
    assert response.status_code == 200, f"Revocation failed: {response.text}"
    data = response.json()

    cred = data["credential"]
    assert cred["said"] == cred_said
    assert cred["status"] == "revoked"
    assert cred["revocation_dt"] is not None


@pytest.mark.asyncio
async def test_revoke_credential_not_found(client: AsyncClient):
    """Test 400 when credential doesn't exist."""
    response = await client.post(
        "/credential/Enonexistent12345678901234567890123456789012/revoke",
        json={"publish_to_witnesses": False},
    )
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_revoke_credential_already_revoked(client: AsyncClient):
    """Test 400 when credential is already revoked."""
    identity, registry = await setup_identity_and_registry(client)

    # Issue a credential
    issue_response = await client.post(
        "/credential/issue",
        json={
            "registry_name": registry["name"],
            "schema_said": TN_ALLOCATION_SCHEMA,
            "attributes": {
                "numbers": {"tn": ["+12025551234"]},
                "channel": "voice",
                "doNotOriginate": False,
            },
            "publish_to_witnesses": False,
        },
    )
    assert issue_response.status_code == 200
    cred_said = issue_response.json()["credential"]["said"]

    # Revoke once
    response = await client.post(
        f"/credential/{cred_said}/revoke",
        json={"publish_to_witnesses": False},
    )
    assert response.status_code == 200

    # Try to revoke again
    response = await client.post(
        f"/credential/{cred_said}/revoke",
        json={"publish_to_witnesses": False},
    )
    assert response.status_code == 400
    assert "already revoked" in response.json()["detail"].lower()


# =============================================================================
# Authorization Tests
# =============================================================================


@pytest.mark.asyncio
async def test_issue_requires_operator_role(client_with_auth: AsyncClient, readonly_headers: dict):
    """Test that credential issuance requires operator role."""
    response = await client_with_auth.post(
        "/credential/issue",
        json={
            "registry_name": "test",
            "schema_said": TN_ALLOCATION_SCHEMA,
            "attributes": {"test": "data"},
        },
        headers=readonly_headers,
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_revoke_requires_admin_role(
    client_with_auth: AsyncClient, operator_headers: dict, admin_headers: dict
):
    """Test that credential revocation requires admin role."""
    # Create identity and registry with admin
    response = await client_with_auth.post(
        "/identity",
        json={"name": unique_name("auth-test"), "publish_to_witnesses": False},
        headers=admin_headers,
    )
    if response.status_code != 200:
        pytest.skip("Could not create identity for auth test")

    identity = response.json()["identity"]

    response = await client_with_auth.post(
        "/registry",
        json={
            "name": unique_name("auth-registry"),
            "identity_name": identity["name"],
            "publish_to_witnesses": False,
        },
        headers=admin_headers,
    )
    if response.status_code != 200:
        pytest.skip("Could not create registry for auth test")

    registry = response.json()["registry"]

    # Issue credential with operator
    response = await client_with_auth.post(
        "/credential/issue",
        json={
            "registry_name": registry["name"],
            "schema_said": TN_ALLOCATION_SCHEMA,
            "attributes": {
                "numbers": {"tn": ["+12025551234"]},
                "channel": "voice",
                "doNotOriginate": False,
            },
            "publish_to_witnesses": False,
        },
        headers=operator_headers,
    )
    if response.status_code != 200:
        pytest.skip(f"Could not issue credential for auth test: {response.text}")

    cred_said = response.json()["credential"]["said"]

    # Try to revoke with operator (should fail)
    response = await client_with_auth.post(
        f"/credential/{cred_said}/revoke",
        json={"publish_to_witnesses": False},
        headers=operator_headers,
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_list_credentials_readonly_allowed(
    client_with_auth: AsyncClient, readonly_headers: dict
):
    """Test that listing credentials is allowed for readonly role."""
    response = await client_with_auth.get(
        "/credential",
        headers=readonly_headers,
    )
    assert response.status_code == 200


# =============================================================================
# Anchor IXN Tests
# =============================================================================


@pytest.mark.asyncio
async def test_get_anchor_ixn_bytes_for_issued_credential(client: AsyncClient):
    """Test that get_anchor_ixn_bytes returns a valid KEL event for issued credential."""
    from app.keri.issuer import get_credential_issuer

    identity, registry = await setup_identity_and_registry(client)

    # Issue a credential
    issue_response = await client.post(
        "/credential/issue",
        json={
            "registry_name": registry["name"],
            "schema_said": TN_ALLOCATION_SCHEMA,
            "attributes": {
                "numbers": {"tn": ["+12025551234"]},
                "channel": "voice",
                "doNotOriginate": False,
            },
            "publish_to_witnesses": False,
        },
    )
    assert issue_response.status_code == 200
    cred_said = issue_response.json()["credential"]["said"]

    # Get the anchor IXN bytes
    issuer = await get_credential_issuer()
    anchor_bytes = await issuer.get_anchor_ixn_bytes(cred_said)

    # Verify it's valid CESR - should start with the JSON event
    assert anchor_bytes is not None
    assert len(anchor_bytes) > 0
    # KEL events are JSON followed by CESR attachments
    # The JSON portion starts with '{'
    assert anchor_bytes[0:1] == b"{"


@pytest.mark.asyncio
async def test_get_anchor_ixn_bytes_for_revoked_credential(client: AsyncClient):
    """Test that get_anchor_ixn_bytes returns revocation anchor after revoke."""
    from app.keri.issuer import get_credential_issuer

    identity, registry = await setup_identity_and_registry(client)

    # Issue a credential
    issue_response = await client.post(
        "/credential/issue",
        json={
            "registry_name": registry["name"],
            "schema_said": TN_ALLOCATION_SCHEMA,
            "attributes": {
                "numbers": {"tn": ["+12025551234"]},
                "channel": "voice",
                "doNotOriginate": False,
            },
            "publish_to_witnesses": False,
        },
    )
    assert issue_response.status_code == 200
    cred_said = issue_response.json()["credential"]["said"]

    # Get anchor bytes for issuance
    issuer = await get_credential_issuer()
    iss_anchor_bytes = await issuer.get_anchor_ixn_bytes(cred_said)

    # Revoke the credential
    revoke_response = await client.post(
        f"/credential/{cred_said}/revoke",
        json={"publish_to_witnesses": False},
    )
    assert revoke_response.status_code == 200

    # Get anchor bytes after revocation - should be the revocation anchor
    rev_anchor_bytes = await issuer.get_anchor_ixn_bytes(cred_said)

    # Both should be valid KEL events
    assert iss_anchor_bytes is not None
    assert rev_anchor_bytes is not None
    # The revocation anchor should be different (later sequence number)
    assert rev_anchor_bytes != iss_anchor_bytes


# =============================================================================
# Integration Tests (require running witnesses)
# =============================================================================


@pytest.mark.asyncio
@pytest.mark.integration
async def test_credential_witness_publishing_integration():
    """Integration test: Verify credential anchor IXN publishing to witnesses.

    This test requires the full stack to be running:
        docker compose --profile full up -d

    Run with: pytest -m integration --no-header -rN

    The test verifies:
    1. Credential issuance succeeds with witness publishing
    2. Anchor IXN is published to all witnesses
    3. All witnesses accept the anchoring event
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
        # First create an identity with witness publishing
        identity_name = f"integ-issuer-{uuid.uuid4().hex[:8]}"
        id_response = await client.post(
            f"{issuer_url}/identity",
            json={"name": identity_name, "publish_to_witnesses": True},
        )
        assert id_response.status_code == 200
        identity = id_response.json()["identity"]

        # Create registry with witness publishing
        registry_name = f"integ-registry-{uuid.uuid4().hex[:8]}"
        reg_response = await client.post(
            f"{issuer_url}/registry",
            json={
                "name": registry_name,
                "identity_name": identity_name,
                "publish_to_witnesses": True,
            },
        )
        assert reg_response.status_code == 200

        # Issue credential with witness publishing
        response = await client.post(
            f"{issuer_url}/credential/issue",
            json={
                "registry_name": registry_name,
                "schema_said": TN_ALLOCATION_SCHEMA,
                "attributes": {
                    "numbers": {"tn": ["+12025551234"]},
                    "channel": "voice",
                    "doNotOriginate": False,
                },
                "publish_to_witnesses": True,
            },
        )

        assert response.status_code == 200, f"Credential issuance failed: {response.text}"
        data = response.json()

        # Verify credential was created
        credential = data["credential"]
        assert credential["said"].startswith("E")
        assert credential["status"] == "issued"

        # Verify publishing results
        publish_results = data.get("publish_results")
        assert publish_results is not None, "Expected publish_results"
        assert len(publish_results) == 3, "Expected 3 witness results"

        # All witnesses should have accepted the anchor IXN
        success_count = sum(1 for r in publish_results if r["success"])
        assert success_count == 3, (
            f"Expected all 3 witnesses to succeed, got {success_count}. "
            f"Results: {publish_results}"
        )
