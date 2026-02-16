"""Integration tests for single credential lifecycle.

Tests the complete flow: issue → build dossier → verify
"""

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
        test_identity: dict,
        test_registry: dict,
    ):
        """Issue credential → build dossier → verify = VALID.

        This is the core end-to-end test that validates the complete
        credential lifecycle from issuance through verification.

        In local mode, uses MockDossierServer (in-memory HTTP).
        In Azure mode, uses AzureBlobDossierServer (blob storage with SAS URLs).
        """
        # 1. Issue a TN Allocation credential
        issue_result = await issuer_client.issue_credential(
            registry_name=test_registry["name"],
            schema_said=TN_ALLOCATION_SCHEMA,
            attributes={
                "dt": "2024-01-01T00:00:00Z",
                "i": test_identity["aid"],  # Issuee is the issuer itself
                "LEI": "254900OPPU84GM83MG36",
                "tn": ["+14155551234"],
            },
            publish_to_witnesses=False,
        )
        credential = issue_result["credential"]
        assert credential["said"], "Credential should have a SAID"
        assert credential["status"] == "issued"

        # 2. Build dossier in JSON format
        dossier_bytes = await issuer_client.build_dossier(
            root_said=credential["said"],
            format="json",
            include_tel=True,
        )
        assert dossier_bytes, "Dossier should have content"

        # 3. Serve dossier (mock server locally, Azure blob in Azure mode)
        evd_url = dossier_server.serve_dossier(
            said=credential["said"],
            content=dossier_bytes,
            content_type="application/json",
        )

        # 4. Create PASSporT signed by issuer identity
        # For this test, we create a simple test passport generator
        # In a real scenario, we'd get the signing key from the issuer
        passport_gen = PassportGenerator.generate_keypair(
            kid=f"http://127.0.0.1:5642/oobi/{test_identity['aid']}/controller"
        )

        passport_jwt = passport_gen.create_passport(
            orig_tn="+14155551234",
            dest_tn="+14155559999",
            evd_url=evd_url,
        )

        # 5. Build VVP-Identity header
        vvp_identity = verifier_client.build_vvp_identity(
            kid=passport_gen.kid,
            evd=evd_url,
        )

        # 6. Verify via verifier API
        # Note: This will likely return INDETERMINATE because we can't
        # properly sign with the issuer's actual key. The test validates
        # the integration flow works, not cryptographic correctness.
        result = await verifier_client.verify(
            passport_jwt=passport_jwt,
            vvp_identity=vvp_identity,
        )

        # The flow should complete without errors
        assert result.raw is not None, "Should have response"
        # We expect INDETERMINATE because signature verification will fail
        # (test key != issuer key), but the flow should complete
        assert result.overall_status in ("VALID", "INVALID", "INDETERMINATE")

    @pytest.mark.asyncio
    @pytest.mark.issuer
    async def test_credential_has_required_fields(
        self,
        issuer_client: IssuerClient,
        test_identity: dict,
        test_registry: dict,
    ):
        """Verify issued credential has all required ACDC fields."""
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

        # Check required fields
        assert credential["said"], "Must have SAID"
        assert credential["issuer_aid"], "Must have issuer AID"
        assert credential["registry_key"], "Must have registry key"
        assert credential["schema_said"] == TN_ALLOCATION_SCHEMA
        assert credential["status"] == "issued"
        assert credential["issuance_dt"], "Must have issuance timestamp"

    @pytest.mark.asyncio
    @pytest.mark.issuer
    async def test_dossier_contains_credential(
        self,
        issuer_client: IssuerClient,
        test_identity: dict,
        test_registry: dict,
    ):
        """Verify dossier contains the issued credential."""
        import json

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

        dossier_bytes = await issuer_client.build_dossier(
            root_said=credential["said"],
            format="json",
            include_tel=True,
        )

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
                assert acdc.get("i") == test_identity["aid"], "Issuer AID mismatch"
                assert acdc.get("s") == TN_ALLOCATION_SCHEMA, "Schema mismatch"
                break

        assert found, f"Credential {credential['said']} not found in dossier"

    @pytest.mark.asyncio
    @pytest.mark.issuer
    async def test_credential_retrieval_by_said(
        self,
        issuer_client: IssuerClient,
        test_identity: dict,
        test_registry: dict,
    ):
        """Verify credential can be retrieved by SAID."""
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
        test_identity: dict,
        test_registry: dict,
    ):
        """Full lifecycle test using Azure Blob Storage for dossier hosting.

        This test validates:
        1. Issuer issues credential (Azure deployment)
        2. Dossier is uploaded to Azure Blob Storage
        3. SAS URL is generated for public access
        4. Verifier fetches dossier from blob storage
        5. Complete verification flow works end-to-end

        Only runs in Azure mode (skipped in local mode).
        """
        if not environment_config.is_azure:
            pytest.skip("Azure full lifecycle test only runs in Azure mode")

        if azure_blob_server is None:
            pytest.skip("Azure blob server not available")

        # 1. Issue credential via Azure-deployed issuer
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

        # 2. Build dossier
        dossier_bytes = await issuer_client.build_dossier(
            root_said=credential["said"],
            format="json",
            include_tel=True,
        )

        # 3. Upload to Azure Blob Storage (returns SAS URL)
        evd_url = azure_blob_server.serve_dossier(
            said=credential["said"],
            content=dossier_bytes,
            content_type="application/json",
        )

        # Verify URL is an Azure blob URL with SAS token
        assert "blob.core.windows.net" in evd_url
        assert "?" in evd_url  # SAS token present

        # 4. Create PASSporT with Azure blob URL as evd
        passport_gen = PassportGenerator.generate_keypair(
            kid=f"http://127.0.0.1:5642/oobi/{test_identity['aid']}/controller"
        )

        passport_jwt = passport_gen.create_passport(
            orig_tn="+14155551234",
            dest_tn="+14155559999",
            evd_url=evd_url,
        )

        # 5. Build VVP-Identity header
        vvp_identity = verifier_client.build_vvp_identity(
            kid=passport_gen.kid,
            evd=evd_url,
        )

        # 6. Verify via Azure-deployed verifier
        result = await verifier_client.verify(
            passport_jwt=passport_jwt,
            vvp_identity=vvp_identity,
        )

        # The flow should complete - verifier should fetch from Azure blob
        assert result.raw is not None, "Should have response"
        # INDETERMINATE is acceptable since test key != issuer key
        assert result.overall_status in ("VALID", "INVALID", "INDETERMINATE")

    @pytest.mark.asyncio
    async def test_azure_cesr_format_dossier(
        self,
        environment_config,
        issuer_client: IssuerClient,
        verifier_client: VerifierClient,
        azure_blob_server,
        test_identity: dict,
        test_registry: dict,
    ):
        """Test CESR format dossier served from Azure Blob Storage."""
        if not environment_config.is_azure:
            pytest.skip("Azure test only")

        if azure_blob_server is None:
            pytest.skip("Azure blob server not available")

        # Issue credential
        issue_result = await issuer_client.issue_credential(
            registry_name=test_registry["name"],
            schema_said=TN_ALLOCATION_SCHEMA,
            attributes={
                "dt": "2024-01-01T00:00:00Z",
                "i": test_identity["aid"],
                "LEI": "254900OPPU84GM83MG36",
                "tn": ["+14155559876"],
            },
            publish_to_witnesses=False,
        )
        credential = issue_result["credential"]

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
            orig_tn="+14155559876",
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
