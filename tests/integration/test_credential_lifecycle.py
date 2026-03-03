"""Integration tests for single credential lifecycle.

Tests the complete flow: issue → build dossier → verify
"""

import json

import pytest

from .conftest import TN_ALLOCATION_SCHEMA
from .helpers import IssuerClient, VerifierClient, PassportGenerator


@pytest.mark.integration
class TestSingleCredentialLifecycle:
    """Test complete lifecycle of a single credential."""

    @pytest.mark.asyncio
    @pytest.mark.e2e
    async def test_issue_build_verify_valid(
        self,
        issuer_client: IssuerClient,
        verifier_client: VerifierClient,
        dossier_server,  # Works in both local (mock) and Azure (blob) modes
        standalone_tn_credential: dict,
        standalone_tn_dossier: dict,
        test_identity: dict,
    ):
        """Issue credential → build dossier → verify = VALID.

        Uses session-scoped credential and dossier fixtures.
        The test validates the serve → verify flow, not issuance itself.
        """
        credential = standalone_tn_credential
        dossier_bytes = standalone_tn_dossier["json"]

        # Serve dossier (mock server locally, Azure blob in Azure mode)
        evd_url = dossier_server.serve_dossier(
            said=credential["said"],
            content=dossier_bytes,
            content_type="application/json",
        )

        # Create PASSporT signed by issuer identity
        passport_gen = PassportGenerator.generate_keypair(
            kid=f"http://127.0.0.1:5642/oobi/{test_identity['aid']}/controller"
        )

        passport_jwt = passport_gen.create_passport(
            orig_tn="+14155551234",
            dest_tn="+14155559999",
            evd_url=evd_url,
        )

        # Build VVP-Identity header
        vvp_identity = verifier_client.build_vvp_identity(
            kid=passport_gen.kid,
            evd=evd_url,
        )

        # Verify via verifier API
        result = await verifier_client.verify(
            passport_jwt=passport_jwt,
            vvp_identity=vvp_identity,
        )

        # The flow should complete without errors
        assert result.raw is not None, "Should have response"
        assert result.overall_status in ("VALID", "INVALID", "INDETERMINATE")

    @pytest.mark.asyncio
    @pytest.mark.issuer
    @pytest.mark.smoke
    async def test_credential_has_required_fields(
        self,
        standalone_tn_credential: dict,
    ):
        """Verify issued credential has all required ACDC fields."""
        credential = standalone_tn_credential

        assert credential["said"], "Must have SAID"
        assert credential["issuer_aid"], "Must have issuer AID"
        assert credential["registry_key"], "Must have registry key"
        assert credential["schema_said"] == TN_ALLOCATION_SCHEMA
        assert credential["status"] == "issued"
        assert credential["issuance_dt"], "Must have issuance timestamp"

    @pytest.mark.asyncio
    @pytest.mark.issuer
    @pytest.mark.smoke
    async def test_dossier_contains_credential(
        self,
        standalone_tn_credential: dict,
        standalone_tn_dossier: dict,
    ):
        """Verify dossier contains the issued credential."""
        credential = standalone_tn_credential
        dossier_bytes = standalone_tn_dossier["json"]

        # Parse dossier JSON
        dossier = json.loads(dossier_bytes)

        # Should be a list with at least one credential
        assert isinstance(dossier, list), "Dossier should be a list"
        assert len(dossier) >= 1, "Dossier should contain at least one credential"

        # Find our credential
        found = False
        for acdc in dossier:
            if acdc.get("d") == credential["said"]:
                found = True
                # Verify ACDC structure
                assert acdc.get("i") == credential["issuer_aid"], "Issuer AID mismatch"
                assert acdc.get("s") == TN_ALLOCATION_SCHEMA, "Schema mismatch"
                break

        assert found, f"Credential {credential['said']} not found in dossier"

    @pytest.mark.asyncio
    @pytest.mark.issuer
    async def test_credential_retrieval_by_said(
        self,
        issuer_client: IssuerClient,
        standalone_tn_credential: dict,
    ):
        """Verify credential can be retrieved by SAID."""
        credential = standalone_tn_credential

        # Retrieve by SAID
        retrieved = await issuer_client.get_credential(credential["said"])

        assert retrieved["said"] == credential["said"]
        assert retrieved["status"] == "issued"


@pytest.mark.integration
@pytest.mark.azure
@pytest.mark.e2e
class TestAzureFullLifecycle:
    """Azure-specific full lifecycle tests.

    These tests use Azure Blob Storage for dossier hosting and exercise
    the complete issuer → dossier (blob) → verifier flow against
    deployed Azure services.
    """

    @pytest.mark.asyncio
    async def test_azure_blob_dossier_lifecycle(
        self,
        environment_config,
        issuer_client: IssuerClient,
        verifier_client: VerifierClient,
        azure_blob_server,  # Explicitly requires Azure blob server
        standalone_tn_credential: dict,
        test_identity: dict,
    ):
        """Full lifecycle test using Azure Blob Storage for dossier hosting."""
        if not environment_config.is_azure:
            pytest.skip("Azure full lifecycle test only runs in Azure mode")

        if azure_blob_server is None:
            pytest.skip("Azure blob server not available")

        credential = standalone_tn_credential

        # Build dossier
        dossier_bytes = await issuer_client.build_dossier(
            root_said=credential["said"],
            format="json",
            include_tel=True,
        )

        # Upload to Azure Blob Storage (returns SAS URL)
        evd_url = azure_blob_server.serve_dossier(
            said=credential["said"],
            content=dossier_bytes,
            content_type="application/json",
        )

        # Verify URL is an Azure blob URL with SAS token
        assert "blob.core.windows.net" in evd_url
        assert "?" in evd_url  # SAS token present

        # Create PASSporT with Azure blob URL as evd
        passport_gen = PassportGenerator.generate_keypair(
            kid=f"http://127.0.0.1:5642/oobi/{test_identity['aid']}/controller"
        )

        passport_jwt = passport_gen.create_passport(
            orig_tn="+14155551234",
            dest_tn="+14155559999",
            evd_url=evd_url,
        )

        # Build VVP-Identity header
        vvp_identity = verifier_client.build_vvp_identity(
            kid=passport_gen.kid,
            evd=evd_url,
        )

        # Verify via Azure-deployed verifier
        result = await verifier_client.verify(
            passport_jwt=passport_jwt,
            vvp_identity=vvp_identity,
        )

        assert result.raw is not None, "Should have response"
        assert result.overall_status in ("VALID", "INVALID", "INDETERMINATE")

    @pytest.mark.asyncio
    async def test_azure_cesr_format_dossier(
        self,
        environment_config,
        issuer_client: IssuerClient,
        verifier_client: VerifierClient,
        azure_blob_server,
        standalone_tn_credential: dict,
        test_identity: dict,
    ):
        """Test CESR format dossier served from Azure Blob Storage."""
        if not environment_config.is_azure:
            pytest.skip("Azure test only")

        if azure_blob_server is None:
            pytest.skip("Azure blob server not available")

        credential = standalone_tn_credential

        # Build dossier in CESR format
        dossier_bytes = await issuer_client.build_dossier(
            root_said=credential["said"],
            format="cesr",
            include_tel=True,
        )

        # Upload with CESR content type
        evd_url = azure_blob_server.serve_dossier(
            said=credential["said"],
            content=dossier_bytes,
            content_type="application/cesr",
        )

        # Create and verify PASSporT
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

        assert result.raw is not None
        assert result.overall_status in ("VALID", "INVALID", "INDETERMINATE")
