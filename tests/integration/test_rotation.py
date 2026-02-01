"""Integration tests for identity key rotation.

These tests verify key rotation functionality across the issuer service,
including witness publishing and state persistence.

Run with:
    pytest tests/integration/test_rotation.py -v
"""

import uuid

import pytest
import pytest_asyncio

from .helpers import IssuerClient


def unique_name(prefix: str = "rotate") -> str:
    """Generate unique name for test identity."""
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


@pytest.mark.asyncio
async def test_rotation_via_api(issuer_client: IssuerClient):
    """Test key rotation through the API.

    Verifies:
    - Rotation endpoint returns correct response
    - Sequence number increments
    - Identity state is updated
    """
    # Create identity
    name = unique_name("api-rotate")
    create_result = await issuer_client.create_identity(name, publish_to_witnesses=False)
    identity = create_result["identity"]
    aid = identity["aid"]
    assert identity["sequence_number"] == 0

    # Rotate keys
    rotate_result = await issuer_client.rotate_identity(
        aid, publish_to_witnesses=False
    )

    # Verify response
    assert rotate_result["previous_sequence_number"] == 0
    assert rotate_result["identity"]["sequence_number"] == 1
    assert rotate_result["identity"]["aid"] == aid

    # Verify state is persisted
    updated = await issuer_client.get_identity(aid)
    assert updated["sequence_number"] == 1


@pytest.mark.asyncio
async def test_multiple_rotations(issuer_client: IssuerClient):
    """Test multiple consecutive key rotations.

    Verifies:
    - Each rotation increments sequence number
    - State remains consistent after multiple rotations
    """
    # Create identity
    name = unique_name("multi-rotate")
    create_result = await issuer_client.create_identity(name, publish_to_witnesses=False)
    identity = create_result["identity"]
    aid = identity["aid"]

    # Perform multiple rotations
    for expected_sn in range(1, 4):
        rotate_result = await issuer_client.rotate_identity(
            aid, publish_to_witnesses=False
        )
        assert rotate_result["identity"]["sequence_number"] == expected_sn
        assert rotate_result["previous_sequence_number"] == expected_sn - 1

    # Verify final state
    final = await issuer_client.get_identity(aid)
    assert final["sequence_number"] == 3


@pytest.mark.asyncio
async def test_rotation_with_witness_publishing(issuer_client: IssuerClient):
    """Test key rotation with witness publishing enabled.

    Verifies:
    - Rotation succeeds with publish_to_witnesses=True
    - Response includes publish results
    """
    # Create identity with witness publishing
    name = unique_name("witness-rotate")
    create_result = await issuer_client.create_identity(name, publish_to_witnesses=True)
    identity = create_result["identity"]
    aid = identity["aid"]

    # Rotate keys with witness publishing
    rotate_result = await issuer_client.rotate_identity(
        aid, publish_to_witnesses=True
    )

    # Verify rotation succeeded
    assert rotate_result["identity"]["sequence_number"] == 1

    # Check publish results are present
    if rotate_result.get("publish_results"):
        # If witnesses are available, check results
        for result in rotate_result["publish_results"]:
            assert "witness_url" in result
            assert "success" in result


@pytest.mark.asyncio
async def test_rotation_with_custom_key_config(issuer_client: IssuerClient):
    """Test rotation with custom next key configuration.

    Verifies:
    - Rotation accepts custom next_key_count and next_threshold
    - Rotation succeeds with valid configuration
    """
    # Create identity
    name = unique_name("custom-rotate")
    create_result = await issuer_client.create_identity(name, publish_to_witnesses=False)
    identity = create_result["identity"]
    aid = identity["aid"]

    # Rotate with custom configuration
    rotate_result = await issuer_client.rotate_identity(
        aid,
        next_key_count=2,
        next_threshold="1",
        publish_to_witnesses=False,
    )

    # Verify rotation succeeded
    assert rotate_result["identity"]["sequence_number"] == 1


@pytest.mark.asyncio
async def test_rotation_invalid_threshold_rejected(issuer_client: IssuerClient):
    """Test that invalid threshold configuration is rejected.

    Verifies:
    - API returns 400 for threshold > key count
    """
    import httpx

    # Create identity
    name = unique_name("invalid-rotate")
    create_result = await issuer_client.create_identity(name, publish_to_witnesses=False)
    identity = create_result["identity"]
    aid = identity["aid"]

    # Try to rotate with invalid threshold
    with pytest.raises(httpx.HTTPStatusError) as exc_info:
        await issuer_client.rotate_identity(
            aid,
            next_key_count=1,
            next_threshold="5",  # Invalid: threshold > key count
            publish_to_witnesses=False,
        )

    assert exc_info.value.response.status_code == 400
    assert "threshold" in exc_info.value.response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_rotation_not_found(issuer_client: IssuerClient):
    """Test rotation of non-existent identity returns 404."""
    import httpx

    fake_aid = "Enonexistent12345678901234567890123456789012"

    with pytest.raises(httpx.HTTPStatusError) as exc_info:
        await issuer_client.rotate_identity(fake_aid, publish_to_witnesses=False)

    assert exc_info.value.response.status_code == 404
    assert "not found" in exc_info.value.response.json()["detail"].lower()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_credential_still_valid_after_rotation(
    issuer_client: IssuerClient,
    tn_allocation_schema: str,
):
    """Test that credentials issued before rotation remain valid.

    This is an important security property: existing credentials should
    still verify even after the issuer rotates their keys.

    Verifies:
    - Credential issued pre-rotation is still accessible post-rotation
    - Credential status is unchanged after rotation
    """
    # Create identity and registry
    name = unique_name("cred-rotate")
    create_result = await issuer_client.create_identity(name, publish_to_witnesses=False)
    identity = create_result["identity"]
    aid = identity["aid"]

    reg_name = f"reg-{uuid.uuid4().hex[:8]}"
    await issuer_client.create_registry(name=reg_name, identity_name=name)

    # Issue credential before rotation
    cred_result = await issuer_client.issue_credential(
        registry_name=reg_name,
        schema_said=tn_allocation_schema,
        attributes={
            "d": "",  # Will be auto-filled
            "i": aid,
            "LEI": "254900OPPU84GM83MG36",
            "tn": "123-456-7890",
            "tns": "US",
            "dt": "2024-01-01T00:00:00Z",
        },
        publish_to_witnesses=False,
    )
    cred_said = cred_result["credential"]["said"]

    # Rotate issuer keys
    rotate_result = await issuer_client.rotate_identity(aid, publish_to_witnesses=False)
    assert rotate_result["identity"]["sequence_number"] == 1

    # Verify credential is still accessible
    cred = await issuer_client.get_credential(cred_said)
    assert cred["said"] == cred_said
    assert cred["status"] == "issued"
