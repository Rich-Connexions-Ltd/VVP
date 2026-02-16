"""Integration tests for aggregate dossiers with multiple roots.

Tests dossiers containing multiple independent credential trees.
"""

import json

import pytest

from .conftest import TN_ALLOCATION_SCHEMA, LEGAL_ENTITY_SCHEMA
from .helpers import IssuerClient


@pytest.mark.integration
@pytest.mark.issuer
class TestAggregateDossiers:
    """Test aggregate dossiers with multiple root credentials."""

    @pytest.mark.asyncio
    async def test_aggregate_two_roots(
        self,
        issuer_client: IssuerClient,
        test_identity: dict,
        test_registry: dict,
    ):
        """Test aggregate dossier with two independent root credentials."""
        # Issue first credential
        cred1_result = await issuer_client.issue_credential(
            registry_name=test_registry["name"],
            schema_said=TN_ALLOCATION_SCHEMA,
            attributes={
                "dt": "2024-01-01T00:00:00Z",
                "i": test_identity["aid"],
                "LEI": "254900FIRST00000001",
                "tn": ["+14155551111"],
            },
            publish_to_witnesses=False,
        )
        cred1 = cred1_result["credential"]

        # Issue second credential (independent)
        cred2_result = await issuer_client.issue_credential(
            registry_name=test_registry["name"],
            schema_said=TN_ALLOCATION_SCHEMA,
            attributes={
                "dt": "2024-01-01T00:00:00Z",
                "i": test_identity["aid"],
                "LEI": "254900SECOND0000002",
                "tn": ["+14155552222"],
            },
            publish_to_witnesses=False,
        )
        cred2 = cred2_result["credential"]

        # Build aggregate dossier
        dossier_bytes = await issuer_client.build_aggregate_dossier(
            root_saids=[cred1["said"], cred2["said"]],
            format="json",
        )

        dossier = json.loads(dossier_bytes)
        saids = [acdc["d"] for acdc in dossier]

        # Both credentials should be present
        assert len(dossier) >= 2
        assert cred1["said"] in saids
        assert cred2["said"] in saids

    @pytest.mark.asyncio
    async def test_aggregate_with_shared_dependency(
        self,
        issuer_client: IssuerClient,
        test_identity: dict,
        test_registry: dict,
    ):
        """Test aggregate dossier where roots share a common dependency.

        Structure:
        LE (shared)
        ├── TN1 (edge to LE)
        └── TN2 (edge to LE)

        Dossier should deduplicate the shared LE.
        """
        # Issue shared LE credential
        le_result = await issuer_client.issue_credential(
            registry_name=test_registry["name"],
            schema_said=LEGAL_ENTITY_SCHEMA,
            attributes={
                "dt": "2024-01-01T00:00:00Z",
                "i": test_identity["aid"],
                "LEI": "254900SHARED0000001",
            },
            publish_to_witnesses=False,
        )
        le_cred = le_result["credential"]

        # Issue TN1 with edge to LE
        tn1_result = await issuer_client.issue_credential(
            registry_name=test_registry["name"],
            schema_said=TN_ALLOCATION_SCHEMA,
            attributes={
                "dt": "2024-01-01T00:00:00Z",
                "i": test_identity["aid"],
                "LEI": "254900SHARED0000001",
                "tn": ["+14155551111"],
            },
            edges={
                "le": {
                    "n": le_cred["said"],
                    "s": LEGAL_ENTITY_SCHEMA,
                }
            },
            publish_to_witnesses=False,
        )
        tn1_cred = tn1_result["credential"]

        # Issue TN2 with edge to same LE
        tn2_result = await issuer_client.issue_credential(
            registry_name=test_registry["name"],
            schema_said=TN_ALLOCATION_SCHEMA,
            attributes={
                "dt": "2024-01-01T00:00:00Z",
                "i": test_identity["aid"],
                "LEI": "254900SHARED0000001",
                "tn": ["+14155552222"],
            },
            edges={
                "le": {
                    "n": le_cred["said"],
                    "s": LEGAL_ENTITY_SCHEMA,
                }
            },
            publish_to_witnesses=False,
        )
        tn2_cred = tn2_result["credential"]

        # Build aggregate dossier with both TN roots
        dossier_bytes = await issuer_client.build_aggregate_dossier(
            root_saids=[tn1_cred["said"], tn2_cred["said"]],
            format="json",
        )

        dossier = json.loads(dossier_bytes)
        saids = [acdc["d"] for acdc in dossier]

        # All three should be present, LE only once
        assert tn1_cred["said"] in saids
        assert tn2_cred["said"] in saids
        assert le_cred["said"] in saids

        # LE should appear exactly once (deduplicated)
        assert saids.count(le_cred["said"]) == 1

    @pytest.mark.asyncio
    async def test_aggregate_maintains_order(
        self,
        issuer_client: IssuerClient,
        test_identity: dict,
        test_registry: dict,
    ):
        """Test aggregate dossier maintains topological order."""
        # Issue LE
        le_result = await issuer_client.issue_credential(
            registry_name=test_registry["name"],
            schema_said=LEGAL_ENTITY_SCHEMA,
            attributes={
                "dt": "2024-01-01T00:00:00Z",
                "i": test_identity["aid"],
                "LEI": "254900ORDER00000001",
            },
            publish_to_witnesses=False,
        )
        le_cred = le_result["credential"]

        # Issue TN with edge to LE
        tn_result = await issuer_client.issue_credential(
            registry_name=test_registry["name"],
            schema_said=TN_ALLOCATION_SCHEMA,
            attributes={
                "dt": "2024-01-01T00:00:00Z",
                "i": test_identity["aid"],
                "LEI": "254900ORDER00000001",
                "tn": ["+14155551111"],
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

        # Issue independent credential
        indep_result = await issuer_client.issue_credential(
            registry_name=test_registry["name"],
            schema_said=TN_ALLOCATION_SCHEMA,
            attributes={
                "dt": "2024-01-01T00:00:00Z",
                "i": test_identity["aid"],
                "LEI": "254900INDEP00000002",
                "tn": ["+14155553333"],
            },
            publish_to_witnesses=False,
        )
        indep_cred = indep_result["credential"]

        # Build aggregate
        dossier_bytes = await issuer_client.build_aggregate_dossier(
            root_saids=[tn_cred["said"], indep_cred["said"]],
            format="json",
        )

        dossier = json.loads(dossier_bytes)
        saids = [acdc["d"] for acdc in dossier]

        # LE must come before TN
        if le_cred["said"] in saids and tn_cred["said"] in saids:
            le_idx = saids.index(le_cred["said"])
            tn_idx = saids.index(tn_cred["said"])
            assert le_idx < tn_idx, "LE should come before TN in aggregate"

    @pytest.mark.asyncio
    async def test_single_root_via_aggregate_endpoint(
        self,
        issuer_client: IssuerClient,
        test_identity: dict,
        test_registry: dict,
    ):
        """Test aggregate endpoint works with single root."""
        cred_result = await issuer_client.issue_credential(
            registry_name=test_registry["name"],
            schema_said=TN_ALLOCATION_SCHEMA,
            attributes={
                "dt": "2024-01-01T00:00:00Z",
                "i": test_identity["aid"],
                "LEI": "254900SINGLE0000001",
                "tn": ["+14155551234"],
            },
            publish_to_witnesses=False,
        )
        cred = cred_result["credential"]

        # Build "aggregate" with single root
        dossier_bytes = await issuer_client.build_aggregate_dossier(
            root_saids=[cred["said"]],
            format="json",
        )

        dossier = json.loads(dossier_bytes)
        assert len(dossier) >= 1
        assert dossier[0]["d"] == cred["said"]
