"""Tests for dossier assembly.

Tests the DossierBuilder, format serializers, and API endpoints.
Critically tests compatibility with verifier's parse_dossier().
"""

import json
import sys
import uuid
from pathlib import Path

import pytest
from httpx import AsyncClient

# Add verifier to path for import compatibility tests
VERIFIER_PATH = Path(__file__).parent.parent.parent / "verifier"
sys.path.insert(0, str(VERIFIER_PATH))


# Schema SAIDs
TN_ALLOCATION_SCHEMA = "EFvnoHDY7I-kaBBeKlbDbkjG4BaI0nKLGadxBdjMGgSQ"
LEGAL_ENTITY_SCHEMA = "ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY"


def unique_name(prefix: str = "test") -> str:
    """Generate unique name for test resources."""
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


# =============================================================================
# Test Fixtures and Helpers
# =============================================================================


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


async def issue_test_credential(
    client: AsyncClient,
    registry_name: str,
    schema_said: str = TN_ALLOCATION_SCHEMA,
    attributes: dict = None,
    edges: dict = None,
) -> dict:
    """Helper to issue a test credential."""
    if attributes is None:
        attributes = {
            "numbers": {"tn": ["+12025551234"]},
            "channel": "voice",
            "doNotOriginate": False,
        }

    response = await client.post(
        "/credential/issue",
        json={
            "registry_name": registry_name,
            "schema_said": schema_said,
            "attributes": attributes,
            "edges": edges,
            "publish_to_witnesses": False,
        },
    )
    assert response.status_code == 200, f"Failed to issue credential: {response.text}"
    return response.json()["credential"]


async def setup_identity_and_registry(client: AsyncClient) -> tuple[dict, dict]:
    """Helper to set up identity and registry for tests."""
    identity = await create_test_identity(client)
    registry = await create_test_registry(client, identity["name"])
    return identity, registry


# =============================================================================
# Unit Tests: Edge Extraction
# =============================================================================


def test_extract_edge_targets_structured():
    """Test extracting targets from structured edges (dict with 'n' key)."""
    from app.dossier.builder import DossierBuilder

    builder = DossierBuilder()
    edges = {
        "d": "Eedge_block_said",  # Should be skipped
        "vetting": {"n": "Etarget_said_1", "s": "Eschema"},
        "auth": {"n": "Etarget_said_2", "s": "Eschema"},
    }

    targets = builder._extract_edge_targets(edges)
    assert len(targets) == 2
    assert "Etarget_said_1" in targets
    assert "Etarget_said_2" in targets
    assert "Eedge_block_said" not in targets


def test_extract_edge_targets_direct_said():
    """Test extracting targets from direct SAID string edges."""
    from app.dossier.builder import DossierBuilder

    builder = DossierBuilder()
    edges = {
        "d": "Eedge_block_said",
        "parent": "Eparent_cred_said",  # Direct SAID string
        "source": "Esource_cred_said",
    }

    targets = builder._extract_edge_targets(edges)
    assert len(targets) == 2
    assert "Eparent_cred_said" in targets
    assert "Esource_cred_said" in targets


def test_extract_edge_targets_mixed():
    """Test extracting from mixed edge types."""
    from app.dossier.builder import DossierBuilder

    builder = DossierBuilder()
    edges = {
        "d": "Eedge_block_said",
        "structured": {"n": "Estructured_target", "s": "Eschema"},
        "direct": "Edirect_target",
    }

    targets = builder._extract_edge_targets(edges)
    assert len(targets) == 2
    assert "Estructured_target" in targets
    assert "Edirect_target" in targets


def test_extract_edge_targets_skips_non_said():
    """Test that non-SAID strings are skipped."""
    from app.dossier.builder import DossierBuilder

    builder = DossierBuilder()
    edges = {
        "valid": "Evalid_said",
        "invalid": "not_a_said",  # Doesn't start with E
        "also_invalid": {"n": "not_a_said"},
    }

    targets = builder._extract_edge_targets(edges)
    assert len(targets) == 1
    assert "Evalid_said" in targets


# =============================================================================
# Unit Tests: Format Serializers
# =============================================================================


def test_serialize_json_produces_array():
    """Test JSON serialization produces array of objects."""
    from app.dossier.builder import DossierContent
    from app.dossier.formats import serialize_json

    content = DossierContent(
        root_said="Eroot",
        root_saids=["Eroot"],
        credential_saids=["Ecred1", "Ecred2"],
        credentials_json={
            "Ecred1": {"v": "ACDC10JSON...", "d": "Ecred1", "i": "Eissuer"},
            "Ecred2": {"v": "ACDC10JSON...", "d": "Ecred2", "i": "Eissuer"},
        },
    )

    result = serialize_json(content)
    parsed = json.loads(result)

    assert isinstance(parsed, list)
    assert len(parsed) == 2
    assert parsed[0]["d"] == "Ecred1"
    assert parsed[1]["d"] == "Ecred2"


def test_serialize_cesr_concatenates():
    """Test CESR serialization concatenates credentials and TEL events."""
    from app.dossier.builder import DossierContent
    from app.dossier.formats import serialize_cesr

    content = DossierContent(
        root_said="Eroot",
        root_saids=["Eroot"],
        credential_saids=["Ecred1", "Ecred2"],
        credentials={
            "Ecred1": b'{"d":"Ecred1"}-ABC',
            "Ecred2": b'{"d":"Ecred2"}-DEF',
        },
        tel_events={
            "Ecred1": b'{"t":"iss"}',
            "Ecred2": b'{"t":"iss"}',
        },
    )

    result = serialize_cesr(content)

    # Credentials should come first
    assert b'{"d":"Ecred1"}' in result
    assert b'{"d":"Ecred2"}' in result
    # TEL events after
    assert b'{"t":"iss"}' in result
    # Check order: credentials before TEL
    cred1_pos = result.find(b'{"d":"Ecred1"}')
    tel_pos = result.find(b'{"t":"iss"}')
    assert cred1_pos < tel_pos


def test_serialize_dossier_content_types():
    """Test correct content-types for each format."""
    from app.dossier.builder import DossierContent
    from app.dossier.formats import DossierFormat, serialize_dossier

    content = DossierContent(
        root_said="Eroot",
        root_saids=["Eroot"],
        credential_saids=["Ecred1"],
        credentials={"Ecred1": b'{"d":"Ecred1"}'},
        credentials_json={"Ecred1": {"d": "Ecred1"}},
    )

    _, cesr_type = serialize_dossier(content, DossierFormat.CESR)
    assert cesr_type == "application/cesr"

    _, json_type = serialize_dossier(content, DossierFormat.JSON)
    assert json_type == "application/json"


# =============================================================================
# Integration Tests: Single Credential Dossier
# =============================================================================


@pytest.mark.asyncio
async def test_build_single_credential_dossier(client: AsyncClient):
    """Test building dossier with single credential (no edges)."""
    identity, registry = await setup_identity_and_registry(client)
    credential = await issue_test_credential(client, registry["name"])

    response = await client.post(
        "/dossier/build",
        json={"root_said": credential["said"], "format": "json"},
    )
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/json"

    # Parse response as JSON array
    dossier = response.json()
    assert isinstance(dossier, list)
    assert len(dossier) == 1
    assert dossier[0]["d"] == credential["said"]


@pytest.mark.asyncio
async def test_build_dossier_cesr_format(client: AsyncClient):
    """Test building dossier in CESR format."""
    identity, registry = await setup_identity_and_registry(client)
    credential = await issue_test_credential(client, registry["name"])

    response = await client.post(
        "/dossier/build",
        json={"root_said": credential["said"], "format": "cesr"},
    )
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/cesr"

    # CESR should contain the credential SAID
    content = response.content
    assert credential["said"].encode() in content


@pytest.mark.asyncio
async def test_build_dossier_info_endpoint(client: AsyncClient):
    """Test getting dossier metadata without content."""
    identity, registry = await setup_identity_and_registry(client)
    credential = await issue_test_credential(client, registry["name"])

    response = await client.post(
        "/dossier/build/info",
        json={"root_said": credential["said"], "format": "json"},
    )
    assert response.status_code == 200
    data = response.json()

    assert "dossier" in data
    dossier = data["dossier"]
    assert dossier["root_said"] == credential["said"]
    assert dossier["credential_count"] == 1
    assert dossier["is_aggregate"] is False
    assert dossier["format"] == "json"
    assert dossier["content_type"] == "application/json"
    assert dossier["size_bytes"] > 0


@pytest.mark.asyncio
async def test_get_dossier_by_said(client: AsyncClient):
    """Test getting dossier by credential SAID."""
    identity, registry = await setup_identity_and_registry(client)
    credential = await issue_test_credential(client, registry["name"])

    response = await client.get(
        f"/dossier/{credential['said']}",
        params={"format": "json"},
    )
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/json"

    dossier = response.json()
    assert isinstance(dossier, list)
    assert len(dossier) == 1


# =============================================================================
# Integration Tests: Chained Credentials
# =============================================================================


@pytest.mark.asyncio
async def test_build_chained_dossier(client: AsyncClient):
    """Test building dossier with chained credentials (root -> leaf)."""
    identity, registry = await setup_identity_and_registry(client)

    # Issue leaf credential first
    leaf = await issue_test_credential(client, registry["name"])

    # Issue root credential with edge to leaf
    root = await issue_test_credential(
        client,
        registry["name"],
        edges={"auth": {"n": leaf["said"], "s": TN_ALLOCATION_SCHEMA}},
    )

    response = await client.post(
        "/dossier/build",
        json={"root_said": root["said"], "format": "json"},
    )
    assert response.status_code == 200

    dossier = response.json()
    assert isinstance(dossier, list)
    assert len(dossier) == 2

    # Check both credentials are present
    saids = [cred["d"] for cred in dossier]
    assert root["said"] in saids
    assert leaf["said"] in saids


@pytest.mark.asyncio
async def test_dossier_topological_order(client: AsyncClient):
    """Test credentials are in topological order (dependencies first)."""
    identity, registry = await setup_identity_and_registry(client)

    # Create chain: root -> mid -> leaf
    leaf = await issue_test_credential(client, registry["name"])
    mid = await issue_test_credential(
        client,
        registry["name"],
        edges={"source": {"n": leaf["said"], "s": TN_ALLOCATION_SCHEMA}},
    )
    root = await issue_test_credential(
        client,
        registry["name"],
        edges={"auth": {"n": mid["said"], "s": TN_ALLOCATION_SCHEMA}},
    )

    response = await client.post(
        "/dossier/build",
        json={"root_said": root["said"], "format": "json"},
    )
    assert response.status_code == 200

    dossier = response.json()
    assert len(dossier) == 3

    # Find positions in array
    saids = [cred["d"] for cred in dossier]
    leaf_pos = saids.index(leaf["said"])
    mid_pos = saids.index(mid["said"])
    root_pos = saids.index(root["said"])

    # Topological order: dependencies come before dependents
    assert leaf_pos < mid_pos, "Leaf should come before mid"
    assert mid_pos < root_pos, "Mid should come before root"


# =============================================================================
# Integration Tests: Error Cases
# =============================================================================


@pytest.mark.asyncio
async def test_build_dossier_not_found(client: AsyncClient):
    """Test building dossier with non-existent credential."""
    response = await client.post(
        "/dossier/build",
        json={"root_said": "Enonexistent_credential_said"},
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_build_dossier_invalid_format(client: AsyncClient):
    """Test building dossier with invalid format."""
    identity, registry = await setup_identity_and_registry(client)
    credential = await issue_test_credential(client, registry["name"])

    response = await client.post(
        "/dossier/build",
        json={"root_said": credential["said"], "format": "invalid"},
    )
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_dangling_edge_warning(client: AsyncClient):
    """Test warning when edge target doesn't exist."""
    identity, registry = await setup_identity_and_registry(client)

    # Issue credential with edge to non-existent credential
    root = await issue_test_credential(
        client,
        registry["name"],
        edges={"missing": {"n": "Enonexistent_said", "s": TN_ALLOCATION_SCHEMA}},
    )

    response = await client.post(
        "/dossier/build/info",
        json={"root_said": root["said"]},
    )
    assert response.status_code == 200
    data = response.json()

    # Should still succeed but with warnings
    assert data["dossier"]["credential_count"] == 1  # Only root
    assert len(data["dossier"]["warnings"]) > 0
    assert "not found" in data["dossier"]["warnings"][0].lower()


# =============================================================================
# Verifier Compatibility Tests
# =============================================================================


@pytest.mark.asyncio
async def test_json_format_verifier_compatible(client: AsyncClient):
    """Test JSON format can be parsed by verifier's parse_dossier.

    CRITICAL: This test ensures issuer dossiers work with the verifier.
    If this test fails, fix the issuer - NOT the verifier.
    """
    try:
        from app.vvp.dossier.parser import parse_dossier
    except ImportError:
        pytest.skip("Verifier's parse_dossier not available")

    identity, registry = await setup_identity_and_registry(client)
    credential = await issue_test_credential(client, registry["name"])

    response = await client.post(
        "/dossier/build",
        json={"root_said": credential["said"], "format": "json"},
    )
    assert response.status_code == 200

    # Parse with verifier's parser
    nodes, signatures = parse_dossier(response.content)

    assert len(nodes) == 1
    assert nodes[0].said == credential["said"]


@pytest.mark.asyncio
async def test_cesr_format_verifier_compatible(client: AsyncClient):
    """Test CESR format can be parsed by verifier's parse_dossier.

    CRITICAL: This test ensures issuer dossiers work with the verifier.
    If this test fails, fix the issuer - NOT the verifier.
    """
    try:
        from app.vvp.dossier.parser import parse_dossier
    except ImportError:
        pytest.skip("Verifier's parse_dossier not available")

    identity, registry = await setup_identity_and_registry(client)
    credential = await issue_test_credential(client, registry["name"])

    response = await client.post(
        "/dossier/build",
        json={"root_said": credential["said"], "format": "cesr"},
    )
    assert response.status_code == 200

    # Parse with verifier's parser
    nodes, signatures = parse_dossier(response.content)

    assert len(nodes) >= 1  # At least the root credential
    saids = [node.said for node in nodes]
    assert credential["said"] in saids


@pytest.mark.asyncio
async def test_chained_dossier_verifier_compatible(client: AsyncClient):
    """Test chained dossier can be parsed by verifier.

    CRITICAL: Tests that edge-linked credentials are properly included.
    """
    try:
        from app.vvp.dossier.parser import parse_dossier
    except ImportError:
        pytest.skip("Verifier's parse_dossier not available")

    identity, registry = await setup_identity_and_registry(client)
    leaf = await issue_test_credential(client, registry["name"])
    root = await issue_test_credential(
        client,
        registry["name"],
        edges={"auth": {"n": leaf["said"], "s": TN_ALLOCATION_SCHEMA}},
    )

    response = await client.post(
        "/dossier/build",
        json={"root_said": root["said"], "format": "json"},
    )
    assert response.status_code == 200

    nodes, _ = parse_dossier(response.content)

    assert len(nodes) == 2
    saids = [node.said for node in nodes]
    assert root["said"] in saids
    assert leaf["said"] in saids
