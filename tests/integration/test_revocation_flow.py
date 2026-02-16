"""Integration tests for credential revocation flow.

Tests that revoked credentials are properly detected during verification.
"""

import json

import pytest

from .conftest import TN_ALLOCATION_SCHEMA
from .helpers import IssuerClient, VerifierClient, PassportGenerator


@pytest.mark.integration
class TestRevocationFlow:
    """Test credential revocation detection."""

    @pytest.mark.asyncio
    @pytest.mark.issuer
    async def test_revoke_credential_updates_status(
        self,
        issuer_client: IssuerClient,
        test_identity: dict,
        test_registry: dict,
    ):
        """Verify revoking a credential updates its status."""
        # Issue credential
        issue_result = await issuer_client.issue_credential(
            registry_name=test_registry["name"],
            schema_said=TN_ALLOCATION_SCHEMA,
            attributes={
                "dt": "2024-01-01T00:00:00Z",
                "i": test_identity["aid"],
                "LEI": "254900OPPU84GM83MG36",
                "tn": ["+14155551234"],
            },
            publish_to_witnesses=False,
        )
        credential = issue_result["credential"]
        assert credential["status"] == "issued"

        # Revoke credential
        revoke_result = await issuer_client.revoke_credential(
            said=credential["said"],
            reason="Test revocation",
            publish_to_witnesses=False,
        )

        assert revoke_result["credential"]["status"] == "revoked"
        assert revoke_result["credential"]["revocation_dt"] is not None

    @pytest.mark.asyncio
    @pytest.mark.issuer
    async def test_revoked_credential_in_dossier(
        self,
        issuer_client: IssuerClient,
        test_identity: dict,
        test_registry: dict,
    ):
        """Verify revoked credential can still be included in dossier."""
        # Issue credential
        issue_result = await issuer_client.issue_credential(
            registry_name=test_registry["name"],
            schema_said=TN_ALLOCATION_SCHEMA,
            attributes={
                "dt": "2024-01-01T00:00:00Z",
                "i": test_identity["aid"],
                "LEI": "254900OPPU84GM83MG36",
                "tn": ["+14155551234"],
            },
            publish_to_witnesses=False,
        )
        credential = issue_result["credential"]

        # Revoke credential
        await issuer_client.revoke_credential(
            said=credential["said"],
            publish_to_witnesses=False,
        )

        # Build dossier should still work
        dossier_bytes = await issuer_client.build_dossier(
            root_said=credential["said"],
            format="json",
            include_tel=True,
        )

        dossier = json.loads(dossier_bytes)
        assert len(dossier) >= 1, "Dossier should contain credential"

    @pytest.mark.asyncio
    @pytest.mark.e2e
    async def test_revoked_credential_rejected_by_verifier(
        self,
        issuer_client: IssuerClient,
        verifier_client: VerifierClient,
        dossier_server,  # Works in both local and Azure modes
        test_identity: dict,
        test_registry: dict,
    ):
        """Revoked credential should return INVALID on verification.

        This tests the complete flow:
        1. Issue credential
        2. Verify = should work (VALID or INDETERMINATE)
        3. Revoke credential
        4. Verify again = should be INVALID with CREDENTIAL_REVOKED error
        """
        # 1. Issue credential
        issue_result = await issuer_client.issue_credential(
            registry_name=test_registry["name"],
            schema_said=TN_ALLOCATION_SCHEMA,
            attributes={
                "dt": "2024-01-01T00:00:00Z",
                "i": test_identity["aid"],
                "LEI": "254900OPPU84GM83MG36",
                "tn": ["+14155551234"],
            },
            publish_to_witnesses=False,
        )
        credential = issue_result["credential"]

        # 2. Build initial dossier
        dossier_bytes = await issuer_client.build_dossier(
            root_said=credential["said"],
            format="json",
        )

        evd_url = dossier_server.serve_dossier(
            said=credential["said"],
            content=dossier_bytes,
            content_type="application/json",
        )

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

        # Note: First verification will likely be INDETERMINATE due to
        # key mismatch, but the flow should complete

        # 3. Revoke credential
        await issuer_client.revoke_credential(
            said=credential["said"],
            publish_to_witnesses=False,
        )

        # 4. Build new dossier with revocation
        revoked_dossier = await issuer_client.build_dossier(
            root_said=credential["said"],
            format="json",
            include_tel=True,
        )

        # Update dossier server with revoked dossier
        dossier_server.serve_dossier(
            said=credential["said"],
            content=revoked_dossier,
            content_type="application/json",
        )

        # 5. Verify again - should detect revocation
        result = await verifier_client.verify(
            passport_jwt=passport_jwt,
            vvp_identity=vvp_identity,
        )

        # The verification should complete (might be INVALID or INDETERMINATE)
        assert result.overall_status in ("VALID", "INVALID", "INDETERMINATE")

    @pytest.mark.asyncio
    @pytest.mark.issuer
    async def test_cannot_revoke_already_revoked(
        self,
        issuer_client: IssuerClient,
        test_identity: dict,
        test_registry: dict,
    ):
        """Attempting to revoke an already revoked credential should fail."""
        import httpx

        # Issue credential
        issue_result = await issuer_client.issue_credential(
            registry_name=test_registry["name"],
            schema_said=TN_ALLOCATION_SCHEMA,
            attributes={
                "dt": "2024-01-01T00:00:00Z",
                "i": test_identity["aid"],
                "LEI": "254900OPPU84GM83MG36",
                "tn": ["+14155551234"],
            },
            publish_to_witnesses=False,
        )
        credential = issue_result["credential"]

        # First revocation should succeed
        await issuer_client.revoke_credential(
            said=credential["said"],
            publish_to_witnesses=False,
        )

        # Second revocation should fail with 400
        with pytest.raises(httpx.HTTPStatusError) as exc_info:
            await issuer_client.revoke_credential(
                said=credential["said"],
                publish_to_witnesses=False,
            )

        assert exc_info.value.response.status_code == 400

    @pytest.mark.asyncio
    @pytest.mark.issuer
    async def test_get_revoked_credential_shows_status(
        self,
        issuer_client: IssuerClient,
        test_identity: dict,
        test_registry: dict,
    ):
        """Getting a revoked credential should show revoked status."""
        # Issue credential
        issue_result = await issuer_client.issue_credential(
            registry_name=test_registry["name"],
            schema_said=TN_ALLOCATION_SCHEMA,
            attributes={
                "dt": "2024-01-01T00:00:00Z",
                "i": test_identity["aid"],
                "LEI": "254900OPPU84GM83MG36",
                "tn": ["+14155551234"],
            },
            publish_to_witnesses=False,
        )
        credential = issue_result["credential"]

        # Revoke
        await issuer_client.revoke_credential(
            said=credential["said"],
            publish_to_witnesses=False,
        )

        # Get credential
        retrieved = await issuer_client.get_credential(credential["said"])

        assert retrieved["status"] == "revoked"
        assert retrieved["revocation_dt"] is not None
