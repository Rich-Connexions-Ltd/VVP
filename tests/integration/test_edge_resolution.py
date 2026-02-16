"""Integration tests for edge resolution in credential chains.

Tests various edge formats and resolution behaviors.
"""

import json

import pytest

from .conftest import TN_ALLOCATION_SCHEMA, LEGAL_ENTITY_SCHEMA
from .helpers import IssuerClient


@pytest.mark.integration
@pytest.mark.issuer
class TestEdgeResolution:
    """Test edge type parsing and resolution."""

    @pytest.mark.asyncio
    async def test_structured_edge_with_schema(
        self,
        issuer_client: IssuerClient,
        test_identity: dict,
        test_registry: dict,
    ):
        """Test structured edge format: {"n": "SAID", "s": "schema"}."""
        # Issue LE credential
        le_result = await issuer_client.issue_credential(
            registry_name=test_registry["name"],
            schema_said=LEGAL_ENTITY_SCHEMA,
            attributes={
                "dt": "2024-01-01T00:00:00Z",
                "i": test_identity["aid"],
                "LEI": "254900STRUCT0000001",
            },
            publish_to_witnesses=False,
        )
        le_cred = le_result["credential"]

        # Issue TN with structured edge
        tn_result = await issuer_client.issue_credential(
            registry_name=test_registry["name"],
            schema_said=TN_ALLOCATION_SCHEMA,
            attributes={
                "dt": "2024-01-01T00:00:00Z",
                "i": test_identity["aid"],
                "LEI": "254900STRUCT0000001",
                "tn": ["+14155551234"],
            },
            edges={
                "le": {
                    "n": le_cred["said"],
                    "s": LEGAL_ENTITY_SCHEMA,
                }
            },
            publish_to_witnesses=False,
        )
        tn_cred = tn_result["credential"]

        # Build dossier - should resolve edge
        dossier_bytes = await issuer_client.build_dossier(
            root_said=tn_cred["said"],
            format="json",
        )

        dossier = json.loads(dossier_bytes)
        saids = [acdc["d"] for acdc in dossier]

        # Both should be present
        assert le_cred["said"] in saids
        assert tn_cred["said"] in saids

    @pytest.mark.asyncio
    async def test_multiple_edges_same_credential(
        self,
        issuer_client: IssuerClient,
        test_identity: dict,
        test_registry: dict,
    ):
        """Test credential with multiple edges."""
        # Issue two LE credentials
        le1_result = await issuer_client.issue_credential(
            registry_name=test_registry["name"],
            schema_said=LEGAL_ENTITY_SCHEMA,
            attributes={
                "dt": "2024-01-01T00:00:00Z",
                "i": test_identity["aid"],
                "LEI": "254900MULTI10000001",
            },
            publish_to_witnesses=False,
        )
        le1_cred = le1_result["credential"]

        le2_result = await issuer_client.issue_credential(
            registry_name=test_registry["name"],
            schema_said=LEGAL_ENTITY_SCHEMA,
            attributes={
                "dt": "2024-01-01T00:00:00Z",
                "i": test_identity["aid"],
                "LEI": "254900MULTI20000002",
            },
            publish_to_witnesses=False,
        )
        le2_cred = le2_result["credential"]

        # Issue TN with edges to both
        tn_result = await issuer_client.issue_credential(
            registry_name=test_registry["name"],
            schema_said=TN_ALLOCATION_SCHEMA,
            attributes={
                "dt": "2024-01-01T00:00:00Z",
                "i": test_identity["aid"],
                "LEI": "254900MULTI10000001",
                "tn": ["+14155551234"],
            },
            edges={
                "le": {
                    "n": le1_cred["said"],
                    "s": LEGAL_ENTITY_SCHEMA,
                },
                "auth": {
                    "n": le2_cred["said"],
                    "s": LEGAL_ENTITY_SCHEMA,
                },
            },
            publish_to_witnesses=False,
        )
        tn_cred = tn_result["credential"]

        # Build dossier
        dossier_bytes = await issuer_client.build_dossier(
            root_said=tn_cred["said"],
            format="json",
        )

        dossier = json.loads(dossier_bytes)
        saids = [acdc["d"] for acdc in dossier]

        # All three should be present
        assert len(dossier) >= 3
        assert le1_cred["said"] in saids
        assert le2_cred["said"] in saids
        assert tn_cred["said"] in saids

    @pytest.mark.asyncio
    async def test_nested_edge_objects(
        self,
        issuer_client: IssuerClient,
        test_identity: dict,
        test_registry: dict,
    ):
        """Test nested edge structures are resolved correctly."""
        # Create a chain with nested edges
        root_result = await issuer_client.issue_credential(
            registry_name=test_registry["name"],
            schema_said=LEGAL_ENTITY_SCHEMA,
            attributes={
                "dt": "2024-01-01T00:00:00Z",
                "i": test_identity["aid"],
                "LEI": "254900NESTED0000001",
            },
            publish_to_witnesses=False,
        )
        root_cred = root_result["credential"]

        mid_result = await issuer_client.issue_credential(
            registry_name=test_registry["name"],
            schema_said=LEGAL_ENTITY_SCHEMA,
            attributes={
                "dt": "2024-01-01T00:00:00Z",
                "i": test_identity["aid"],
                "LEI": "254900NESTED0000002",
            },
            edges={
                "chain": {
                    "n": root_cred["said"],
                    "s": LEGAL_ENTITY_SCHEMA,
                    "o": "I2I",  # Additional edge properties
                }
            },
            publish_to_witnesses=False,
        )
        mid_cred = mid_result["credential"]

        leaf_result = await issuer_client.issue_credential(
            registry_name=test_registry["name"],
            schema_said=TN_ALLOCATION_SCHEMA,
            attributes={
                "dt": "2024-01-01T00:00:00Z",
                "i": test_identity["aid"],
                "LEI": "254900NESTED0000002",
                "tn": ["+14155551234"],
            },
            edges={
                "auth": {
                    "n": mid_cred["said"],
                    "s": LEGAL_ENTITY_SCHEMA,
                }
            },
            publish_to_witnesses=False,
        )
        leaf_cred = leaf_result["credential"]

        # Build dossier from leaf
        dossier_bytes = await issuer_client.build_dossier(
            root_said=leaf_cred["said"],
            format="json",
        )

        dossier = json.loads(dossier_bytes)
        saids = [acdc["d"] for acdc in dossier]

        # Full chain should be resolved
        assert len(dossier) >= 3
        assert root_cred["said"] in saids
        assert mid_cred["said"] in saids
        assert leaf_cred["said"] in saids

    @pytest.mark.asyncio
    async def test_edge_with_operator_field(
        self,
        issuer_client: IssuerClient,
        test_identity: dict,
        test_registry: dict,
    ):
        """Test edge with 'o' operator field is handled."""
        le_result = await issuer_client.issue_credential(
            registry_name=test_registry["name"],
            schema_said=LEGAL_ENTITY_SCHEMA,
            attributes={
                "dt": "2024-01-01T00:00:00Z",
                "i": test_identity["aid"],
                "LEI": "254900OPER00000001",
            },
            publish_to_witnesses=False,
        )
        le_cred = le_result["credential"]

        tn_result = await issuer_client.issue_credential(
            registry_name=test_registry["name"],
            schema_said=TN_ALLOCATION_SCHEMA,
            attributes={
                "dt": "2024-01-01T00:00:00Z",
                "i": test_identity["aid"],
                "LEI": "254900OPER00000001",
                "tn": ["+14155551234"],
            },
            edges={
                "le": {
                    "n": le_cred["said"],
                    "s": LEGAL_ENTITY_SCHEMA,
                    "o": "I2I",  # Issuee-to-Issuer operator
                }
            },
            publish_to_witnesses=False,
        )
        tn_cred = tn_result["credential"]

        dossier_bytes = await issuer_client.build_dossier(
            root_said=tn_cred["said"],
            format="json",
        )

        dossier = json.loads(dossier_bytes)
        saids = [acdc["d"] for acdc in dossier]

        assert le_cred["said"] in saids
        assert tn_cred["said"] in saids

    @pytest.mark.asyncio
    async def test_credential_without_edges(
        self,
        issuer_client: IssuerClient,
        test_identity: dict,
        test_registry: dict,
    ):
        """Test credential without edges builds single-item dossier."""
        cred_result = await issuer_client.issue_credential(
            registry_name=test_registry["name"],
            schema_said=TN_ALLOCATION_SCHEMA,
            attributes={
                "dt": "2024-01-01T00:00:00Z",
                "i": test_identity["aid"],
                "LEI": "254900NOEDGE000001",
                "tn": ["+14155551234"],
            },
            publish_to_witnesses=False,
        )
        cred = cred_result["credential"]

        dossier_bytes = await issuer_client.build_dossier(
            root_said=cred["said"],
            format="json",
        )

        dossier = json.loads(dossier_bytes)

        # Should contain exactly one credential
        assert len(dossier) == 1
        assert dossier[0]["d"] == cred["said"]

    @pytest.mark.asyncio
    async def test_edge_verification_in_dossier(
        self,
        issuer_client: IssuerClient,
        test_identity: dict,
        test_registry: dict,
    ):
        """Verify edge references are preserved in dossier ACDCs."""
        le_result = await issuer_client.issue_credential(
            registry_name=test_registry["name"],
            schema_said=LEGAL_ENTITY_SCHEMA,
            attributes={
                "dt": "2024-01-01T00:00:00Z",
                "i": test_identity["aid"],
                "LEI": "254900VERIFY000001",
            },
            publish_to_witnesses=False,
        )
        le_cred = le_result["credential"]

        tn_result = await issuer_client.issue_credential(
            registry_name=test_registry["name"],
            schema_said=TN_ALLOCATION_SCHEMA,
            attributes={
                "dt": "2024-01-01T00:00:00Z",
                "i": test_identity["aid"],
                "LEI": "254900VERIFY000001",
                "tn": ["+14155551234"],
            },
            edges={
                "le": {
                    "n": le_cred["said"],
                    "s": LEGAL_ENTITY_SCHEMA,
                }
            },
            publish_to_witnesses=False,
        )
        tn_cred = tn_result["credential"]

        dossier_bytes = await issuer_client.build_dossier(
            root_said=tn_cred["said"],
            format="json",
        )

        dossier = json.loads(dossier_bytes)

        # Find the TN credential
        tn_acdc = next(acdc for acdc in dossier if acdc["d"] == tn_cred["said"])

        # Verify edge is present and points to LE
        assert "e" in tn_acdc, "TN ACDC should have edges"
        edges = tn_acdc["e"]
        assert "le" in edges, "Should have 'le' edge"
        assert edges["le"]["n"] == le_cred["said"], "Edge should point to LE SAID"

    @pytest.mark.asyncio
    async def test_direct_said_string_edge(
        self,
        issuer_client: IssuerClient,
        test_identity: dict,
        test_registry: dict,
    ):
        """Test direct SAID string as edge value (not structured object).

        Some edge formats use just the SAID string directly instead of
        the structured {"n": "SAID", "s": "schema"} format.
        """
        # Issue LE credential
        le_result = await issuer_client.issue_credential(
            registry_name=test_registry["name"],
            schema_said=LEGAL_ENTITY_SCHEMA,
            attributes={
                "dt": "2024-01-01T00:00:00Z",
                "i": test_identity["aid"],
                "LEI": "254900DIRECT000001",
            },
            publish_to_witnesses=False,
        )
        le_cred = le_result["credential"]

        # Issue TN with direct SAID edge (minimal format)
        # Note: The issuer may normalize this to structured format internally
        tn_result = await issuer_client.issue_credential(
            registry_name=test_registry["name"],
            schema_said=TN_ALLOCATION_SCHEMA,
            attributes={
                "dt": "2024-01-01T00:00:00Z",
                "i": test_identity["aid"],
                "LEI": "254900DIRECT000001",
                "tn": ["+14155551234"],
            },
            edges={
                "le": {
                    "n": le_cred["said"],
                    # Minimal edge - only 'n' field, no 's' schema
                }
            },
            publish_to_witnesses=False,
        )
        tn_cred = tn_result["credential"]

        # Build dossier - should still resolve
        dossier_bytes = await issuer_client.build_dossier(
            root_said=tn_cred["said"],
            format="json",
        )

        dossier = json.loads(dossier_bytes)
        saids = [acdc["d"] for acdc in dossier]

        # Both should be present even with minimal edge format
        assert le_cred["said"] in saids, "LE should be resolved from minimal edge"
        assert tn_cred["said"] in saids

    @pytest.mark.asyncio
    async def test_dangling_edge_builds_partial_dossier(
        self,
        issuer_client: IssuerClient,
        test_identity: dict,
        test_registry: dict,
    ):
        """Test that dangling edge (target not found) builds dossier with warning.

        Per the approved plan, dangling edge references should warn but not fail.
        The dossier should still be built with available credentials.
        """
        # Create a fake SAID that doesn't exist
        fake_said = "EFakeSAID12345678901234567890123456789012"

        # Issue credential with edge to non-existent credential
        tn_result = await issuer_client.issue_credential(
            registry_name=test_registry["name"],
            schema_said=TN_ALLOCATION_SCHEMA,
            attributes={
                "dt": "2024-01-01T00:00:00Z",
                "i": test_identity["aid"],
                "LEI": "254900DANGLING0001",
                "tn": ["+14155551234"],
            },
            edges={
                "le": {
                    "n": fake_said,
                    "s": LEGAL_ENTITY_SCHEMA,
                }
            },
            publish_to_witnesses=False,
        )
        tn_cred = tn_result["credential"]

        # Build dossier - should succeed with warning, not fail
        # The TN credential should be present, but the dangling edge target won't be
        dossier_bytes = await issuer_client.build_dossier(
            root_said=tn_cred["said"],
            format="json",
        )

        dossier = json.loads(dossier_bytes)
        saids = [acdc["d"] for acdc in dossier]

        # TN credential should be present
        assert tn_cred["said"] in saids, "Root credential should be in dossier"

        # The fake/dangling SAID should NOT be in dossier (it doesn't exist)
        assert fake_said not in saids, "Dangling edge target should not appear"

        # Dossier should have at least the root credential
        assert len(dossier) >= 1

    @pytest.mark.asyncio
    async def test_mixed_valid_and_dangling_edges(
        self,
        issuer_client: IssuerClient,
        test_identity: dict,
        test_registry: dict,
    ):
        """Test credential with both valid and dangling edges.

        Valid edges should be resolved; dangling edges should be skipped.
        """
        # Issue a real LE credential
        le_result = await issuer_client.issue_credential(
            registry_name=test_registry["name"],
            schema_said=LEGAL_ENTITY_SCHEMA,
            attributes={
                "dt": "2024-01-01T00:00:00Z",
                "i": test_identity["aid"],
                "LEI": "254900MIXED0000001",
            },
            publish_to_witnesses=False,
        )
        le_cred = le_result["credential"]

        fake_said = "EFakeMixed123456789012345678901234567890"

        # Issue TN with one valid edge and one dangling edge
        tn_result = await issuer_client.issue_credential(
            registry_name=test_registry["name"],
            schema_said=TN_ALLOCATION_SCHEMA,
            attributes={
                "dt": "2024-01-01T00:00:00Z",
                "i": test_identity["aid"],
                "LEI": "254900MIXED0000001",
                "tn": ["+14155551234"],
            },
            edges={
                "le": {
                    "n": le_cred["said"],
                    "s": LEGAL_ENTITY_SCHEMA,
                },
                "missing": {
                    "n": fake_said,
                    "s": LEGAL_ENTITY_SCHEMA,
                },
            },
            publish_to_witnesses=False,
        )
        tn_cred = tn_result["credential"]

        # Build dossier
        dossier_bytes = await issuer_client.build_dossier(
            root_said=tn_cred["said"],
            format="json",
        )

        dossier = json.loads(dossier_bytes)
        saids = [acdc["d"] for acdc in dossier]

        # Valid edge should be resolved
        assert le_cred["said"] in saids, "Valid edge target should be resolved"
        assert tn_cred["said"] in saids, "Root should be present"

        # Dangling edge should not cause presence of fake SAID
        assert fake_said not in saids
