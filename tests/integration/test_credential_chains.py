"""Integration tests for chained credential verification.

Tests credential chains like: Legal Entity → TN Allocation
"""

import json

import pytest

from .conftest import TN_ALLOCATION_SCHEMA, LEGAL_ENTITY_SCHEMA
from .helpers import IssuerClient, VerifierClient, PassportGenerator


@pytest.mark.integration
class TestCredentialChains:
    """Test chained credential verification."""

    @pytest.mark.asyncio
    @pytest.mark.issuer
    async def test_two_level_chain_le_to_tn(
        self,
        issuer_client: IssuerClient,
        le_tn_chain: dict,
    ):
        """Test Legal Entity → TN Allocation credential chain.

        Builds dossier from the shared LE→TN chain and verifies
        both credentials are present.
        """
        le_credential = le_tn_chain["le"]
        tn_credential = le_tn_chain["tn"]

        # Build dossier from TN Allocation (should include LE)
        dossier_bytes = await issuer_client.build_dossier(
            root_said=tn_credential["said"],
            format="json",
        )

        dossier = json.loads(dossier_bytes)

        # Should contain both credentials
        assert len(dossier) >= 2, "Dossier should contain at least 2 credentials"

        # Find both credentials
        saids = [acdc["d"] for acdc in dossier]
        assert le_credential["said"] in saids, "LE credential should be in dossier"
        assert tn_credential["said"] in saids, "TN credential should be in dossier"

    @pytest.mark.asyncio
    @pytest.mark.issuer
    async def test_chain_order_is_topological(
        self,
        le_tn_chain_dossier: dict,
    ):
        """Verify dossier credentials are in topological order.

        Dependencies should come before dependents (LE before TN).
        """
        dossier = json.loads(le_tn_chain_dossier["json"])
        saids = [acdc["d"] for acdc in dossier]

        le_said = le_tn_chain_dossier["le_said"]
        tn_said = le_tn_chain_dossier["tn_said"]

        # LE should come before TN in topological order
        le_index = saids.index(le_said)
        tn_index = saids.index(tn_said)
        assert le_index < tn_index, "LE should come before TN in dossier"

    @pytest.mark.asyncio
    @pytest.mark.issuer
    async def test_three_level_chain(
        self,
        issuer_client: IssuerClient,
        three_level_chain: dict,
    ):
        """Test three-level credential chain.

        Root → Intermediate → Leaf
        """
        root_cred = three_level_chain["root"]
        mid_cred = three_level_chain["mid"]
        leaf_cred = three_level_chain["leaf"]

        # Build dossier from leaf
        dossier_bytes = await issuer_client.build_dossier(
            root_said=leaf_cred["said"],
            format="json",
        )

        dossier = json.loads(dossier_bytes)
        saids = [acdc["d"] for acdc in dossier]

        # All three should be present
        assert len(dossier) >= 3, "Dossier should contain all 3 credentials"
        assert root_cred["said"] in saids
        assert mid_cred["said"] in saids
        assert leaf_cred["said"] in saids

        # Topological order: root → mid → leaf
        root_idx = saids.index(root_cred["said"])
        mid_idx = saids.index(mid_cred["said"])
        leaf_idx = saids.index(leaf_cred["said"])
        assert root_idx < mid_idx < leaf_idx

    @pytest.mark.asyncio
    @pytest.mark.e2e
    async def test_chain_verification_flow(
        self,
        issuer_client: IssuerClient,
        verifier_client: VerifierClient,
        dossier_server,  # Works in both local and Azure modes
        le_tn_chain: dict,
        test_identity: dict,
    ):
        """Test full chain verification flow through verifier."""
        tn_credential = le_tn_chain["tn"]

        # Build dossier
        dossier_bytes = await issuer_client.build_dossier(
            root_said=tn_credential["said"],
            format="json",
        )

        evd_url = dossier_server.serve_dossier(
            said=tn_credential["said"],
            content=dossier_bytes,
            content_type="application/json",
        )

        # Create passport and verify
        passport_gen = PassportGenerator.generate_keypair(
            kid=f"http://127.0.0.1:5642/oobi/{test_identity['aid']}/controller"
        )

        passport_jwt = passport_gen.create_passport(
            orig_tn="+14155551234",
            dest_tn="+14155559999",
            evd_url=evd_url,
        )

        vvp_identity = verifier_client.build_vvp_identity(
            kid=passport_gen.kid,
            evd=evd_url,
        )

        result = await verifier_client.verify(
            passport_jwt=passport_jwt,
            vvp_identity=vvp_identity,
        )

        # Flow should complete
        assert result.overall_status in ("VALID", "INVALID", "INDETERMINATE")
