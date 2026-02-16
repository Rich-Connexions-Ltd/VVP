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
        test_identity: dict,
        test_registry: dict,
    ):
        """Test Legal Entity → TN Allocation credential chain.

        Issues:
        1. Legal Entity credential (root)
        2. TN Allocation credential with edge to LE (leaf)

        Then builds dossier and verifies chain structure.
        """
        # 1. Issue Legal Entity credential (root)
        le_result = await issuer_client.issue_credential(
            registry_name=test_registry["name"],
            schema_said=LEGAL_ENTITY_SCHEMA,
            attributes={
                "dt": "2024-01-01T00:00:00Z",
                "i": test_identity["aid"],
                "LEI": "254900OPPU84GM83MG36",
            },
            publish_to_witnesses=False,
        )
        le_credential = le_result["credential"]

        # 2. Issue TN Allocation with edge to LE
        tn_result = await issuer_client.issue_credential(
            registry_name=test_registry["name"],
            schema_said=TN_ALLOCATION_SCHEMA,
            attributes={
                "dt": "2024-01-01T00:00:00Z",
                "i": test_identity["aid"],
                "LEI": "254900OPPU84GM83MG36",
                "tn": ["+14155551234"],
            },
            edges={
                "le": {
                    "n": le_credential["said"],
                    "s": LEGAL_ENTITY_SCHEMA,
                }
            },
            publish_to_witnesses=False,
        )
        tn_credential = tn_result["credential"]

        # 3. Build dossier from TN Allocation (should include LE)
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
        issuer_client: IssuerClient,
        test_identity: dict,
        test_registry: dict,
    ):
        """Verify dossier credentials are in topological order.

        Dependencies should come before dependents (LE before TN).
        """
        # Issue chain
        le_result = await issuer_client.issue_credential(
            registry_name=test_registry["name"],
            schema_said=LEGAL_ENTITY_SCHEMA,
            attributes={
                "dt": "2024-01-01T00:00:00Z",
                "i": test_identity["aid"],
                "LEI": "254900OPPU84GM83MG36",
            },
            publish_to_witnesses=False,
        )
        le_credential = le_result["credential"]

        tn_result = await issuer_client.issue_credential(
            registry_name=test_registry["name"],
            schema_said=TN_ALLOCATION_SCHEMA,
            attributes={
                "dt": "2024-01-01T00:00:00Z",
                "i": test_identity["aid"],
                "LEI": "254900OPPU84GM83MG36",
                "tn": ["+14155551234"],
            },
            edges={
                "le": {
                    "n": le_credential["said"],
                    "s": LEGAL_ENTITY_SCHEMA,
                }
            },
            publish_to_witnesses=False,
        )
        tn_credential = tn_result["credential"]

        dossier_bytes = await issuer_client.build_dossier(
            root_said=tn_credential["said"],
            format="json",
        )

        dossier = json.loads(dossier_bytes)
        saids = [acdc["d"] for acdc in dossier]

        # LE should come before TN in topological order
        le_index = saids.index(le_credential["said"])
        tn_index = saids.index(tn_credential["said"])
        assert le_index < tn_index, "LE should come before TN in dossier"

    @pytest.mark.asyncio
    @pytest.mark.issuer
    async def test_three_level_chain(
        self,
        issuer_client: IssuerClient,
        test_identity: dict,
        test_registry: dict,
    ):
        """Test three-level credential chain.

        Root → Intermediate → Leaf
        """
        # Level 1: Root credential
        root_result = await issuer_client.issue_credential(
            registry_name=test_registry["name"],
            schema_said=LEGAL_ENTITY_SCHEMA,
            attributes={
                "dt": "2024-01-01T00:00:00Z",
                "i": test_identity["aid"],
                "LEI": "254900ROOT0000000001",
            },
            publish_to_witnesses=False,
        )
        root_cred = root_result["credential"]

        # Level 2: Intermediate credential with edge to root
        mid_result = await issuer_client.issue_credential(
            registry_name=test_registry["name"],
            schema_said=LEGAL_ENTITY_SCHEMA,
            attributes={
                "dt": "2024-01-01T00:00:00Z",
                "i": test_identity["aid"],
                "LEI": "254900MIDDLE00000002",
            },
            edges={
                "auth": {
                    "n": root_cred["said"],
                    "s": LEGAL_ENTITY_SCHEMA,
                }
            },
            publish_to_witnesses=False,
        )
        mid_cred = mid_result["credential"]

        # Level 3: Leaf credential with edge to intermediate
        leaf_result = await issuer_client.issue_credential(
            registry_name=test_registry["name"],
            schema_said=TN_ALLOCATION_SCHEMA,
            attributes={
                "dt": "2024-01-01T00:00:00Z",
                "i": test_identity["aid"],
                "LEI": "254900MIDDLE00000002",
                "tn": ["+14155551234"],
            },
            edges={
                "le": {
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
        test_identity: dict,
        test_registry: dict,
    ):
        """Test full chain verification flow through verifier."""
        # Issue chain
        le_result = await issuer_client.issue_credential(
            registry_name=test_registry["name"],
            schema_said=LEGAL_ENTITY_SCHEMA,
            attributes={
                "dt": "2024-01-01T00:00:00Z",
                "i": test_identity["aid"],
                "LEI": "254900OPPU84GM83MG36",
            },
            publish_to_witnesses=False,
        )
        le_credential = le_result["credential"]

        tn_result = await issuer_client.issue_credential(
            registry_name=test_registry["name"],
            schema_said=TN_ALLOCATION_SCHEMA,
            attributes={
                "dt": "2024-01-01T00:00:00Z",
                "i": test_identity["aid"],
                "LEI": "254900OPPU84GM83MG36",
                "tn": ["+14155551234"],
            },
            edges={
                "le": {
                    "n": le_credential["said"],
                    "s": LEGAL_ENTITY_SCHEMA,
                }
            },
            publish_to_witnesses=False,
        )
        tn_credential = tn_result["credential"]

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
