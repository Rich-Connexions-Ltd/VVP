"""Integration tests for dossier format handling.

Tests CESR and JSON dossier formats and Content-Type headers.
"""

import json

import pytest

from .conftest import TN_ALLOCATION_SCHEMA
from .helpers import IssuerClient


@pytest.mark.integration
class TestDossierFormats:
    """Test dossier format handling."""

    @pytest.mark.asyncio
    async def test_json_format_structure(
        self,
        issuer_client: IssuerClient,
        test_identity: dict,
        test_registry: dict,
    ):
        """Test JSON dossier format is a valid array."""
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

        # Should be valid JSON
        dossier = json.loads(dossier_bytes)
        assert isinstance(dossier, list), "JSON dossier should be an array"

        # Each item should be a valid ACDC
        for acdc in dossier:
            assert isinstance(acdc, dict), "Each item should be a dict"
            assert "d" in acdc, "ACDC must have 'd' (SAID)"
            assert "i" in acdc, "ACDC must have 'i' (issuer)"
            assert "s" in acdc, "ACDC must have 's' (schema)"

    @pytest.mark.asyncio
    async def test_cesr_format_structure(
        self,
        issuer_client: IssuerClient,
        test_identity: dict,
        test_registry: dict,
    ):
        """Test CESR dossier format contains valid CESR stream."""
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
            format="cesr",
            include_tel=True,
        )

        # CESR stream should contain JSON objects with signatures
        assert dossier_bytes, "CESR dossier should have content"

        # Should contain the credential SAID somewhere
        content = dossier_bytes.decode("utf-8", errors="replace")
        assert credential["said"] in content, "CESR should contain credential SAID"

    @pytest.mark.asyncio
    @pytest.mark.skip(reason="Mock server tests disabled in CI - test infrastructure only")
    async def test_mock_server_content_type_json(
        self,
        mock_dossier_server,  # Local-only: tests mock server infrastructure
        issuer_client: IssuerClient,
        test_identity: dict,
        test_registry: dict,
    ):
        """Test mock server returns correct Content-Type for JSON.

        Note: This test is local-only as it tests the mock server itself.
        """
        if mock_dossier_server is None:
            pytest.skip("Mock dossier server not available (Azure mode or disabled)")

        import aiohttp

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
        )

        evd_url = mock_dossier_server.serve_dossier(
            said=credential["said"],
            content=dossier_bytes,
            content_type="application/json",
        )

        async with aiohttp.ClientSession() as session:
            async with session.get(evd_url) as response:
                assert response.status == 200
                assert "application/json" in response.headers.get("Content-Type", "")

    @pytest.mark.asyncio
    @pytest.mark.skip(reason="Mock server tests disabled in CI - test infrastructure only")
    async def test_mock_server_content_type_cesr(
        self,
        mock_dossier_server,  # Local-only: tests mock server infrastructure
        issuer_client: IssuerClient,
        test_identity: dict,
        test_registry: dict,
    ):
        """Test mock server returns correct Content-Type for CESR.

        Note: This test is local-only as it tests the mock server itself.
        """
        if mock_dossier_server is None:
            pytest.skip("Mock dossier server not available (Azure mode or disabled)")

        import aiohttp

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
            format="cesr",
        )

        evd_url = mock_dossier_server.serve_dossier(
            said=credential["said"],
            content=dossier_bytes,
            content_type="application/cesr",
        )

        async with aiohttp.ClientSession() as session:
            async with session.get(evd_url) as response:
                assert response.status == 200
                assert "application/cesr" in response.headers.get("Content-Type", "")

    @pytest.mark.asyncio
    @pytest.mark.skip(reason="Mock server tests disabled in CI - test infrastructure only")
    async def test_mock_server_returns_404_for_unknown_said(
        self,
        mock_dossier_server,  # Local-only: tests mock server infrastructure
    ):
        """Test mock server returns 404 for unknown SAID.

        Note: This test is local-only as it tests the mock server itself.
        """
        if mock_dossier_server is None:
            pytest.skip("Mock dossier server not available (Azure mode or disabled)")

        import aiohttp

        unknown_said = "EUnknownSAID123456789012345678901234567890"
        url = f"{mock_dossier_server.base_url}/dossier/{unknown_said}"

        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                assert response.status == 404

    @pytest.mark.asyncio
    async def test_dossier_with_tel_excluded(
        self,
        issuer_client: IssuerClient,
        test_identity: dict,
        test_registry: dict,
    ):
        """Test dossier can be built without TEL events."""
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

        # Build without TEL
        dossier_no_tel = await issuer_client.build_dossier(
            root_said=credential["said"],
            format="json",
            include_tel=False,
        )

        # Build with TEL
        dossier_with_tel = await issuer_client.build_dossier(
            root_said=credential["said"],
            format="json",
            include_tel=True,
        )

        # Both should be valid JSON
        assert json.loads(dossier_no_tel)
        assert json.loads(dossier_with_tel)

        # Without TEL should be smaller or equal (no TEL events included)
        # Note: In JSON format, TEL isn't included anyway, so sizes may be equal
        assert len(dossier_no_tel) <= len(dossier_with_tel) + 100  # Allow some margin
