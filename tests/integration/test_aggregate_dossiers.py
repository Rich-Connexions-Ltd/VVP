"""Integration tests for aggregate dossiers with multiple roots.

Tests dossiers containing multiple independent credential trees.
"""

import json

import pytest

from .helpers import IssuerClient


@pytest.mark.integration
@pytest.mark.issuer
class TestAggregateDossiers:
    """Test aggregate dossiers with multiple root credentials."""

    @pytest.mark.asyncio
    async def test_aggregate_two_roots(
        self,
        issuer_client: IssuerClient,
        two_standalone_tn_credentials: dict,
    ):
        """Test aggregate dossier with two independent root credentials."""
        cred1 = two_standalone_tn_credentials["cred1"]
        cred2 = two_standalone_tn_credentials["cred2"]

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
        shared_dependency_credentials: dict,
    ):
        """Test aggregate dossier where roots share a common dependency.

        Structure:
        LE (shared)
        ├── TN1 (edge to LE)
        └── TN2 (edge to LE)

        Dossier should deduplicate the shared LE.
        """
        le_cred = shared_dependency_credentials["le"]
        tn1_cred = shared_dependency_credentials["tn1"]
        tn2_cred = shared_dependency_credentials["tn2"]

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
        le_tn_chain: dict,
        standalone_tn_credential: dict,
    ):
        """Test aggregate dossier maintains topological order."""
        le_cred = le_tn_chain["le"]
        tn_cred = le_tn_chain["tn"]
        indep_cred = standalone_tn_credential

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
        standalone_tn_credential: dict,
    ):
        """Test aggregate endpoint works with single root."""
        cred = standalone_tn_credential

        # Build "aggregate" with single root
        dossier_bytes = await issuer_client.build_aggregate_dossier(
            root_saids=[cred["said"]],
            format="json",
        )

        dossier = json.loads(dossier_bytes)
        assert len(dossier) >= 1
        assert dossier[0]["d"] == cred["said"]
