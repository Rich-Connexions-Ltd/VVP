"""Agent contract tests for issuer↔agent DTO compatibility.

Sprint 68c: Verifies that shared DTOs in common/vvp/models/keri_agent.py
maintain backward compatibility (N/N-1 rule).
"""

import pytest

from common.vvp.models.keri_agent import (
    CreateVVPAttestationRequest,
    VVPAttestationResponse,
    IssueCredentialRequest,
    CredentialResponse,
    IdentityResponse,
    RegistryResponse,
)


class TestCreateVVPAttestationRequestCompat:
    """Verify dest_tn accepts both scalar string and list (backward compat)."""

    def test_dest_tn_scalar_string_normalized(self):
        """Old-format scalar dest_tn should be accepted and normalized to list."""
        req = CreateVVPAttestationRequest(
            identity_name="test",
            dossier_said="Etest",
            orig_tn="+14155551234",
            dest_tn="+14155559999",  # type: ignore — testing backward compat
        )
        assert isinstance(req.dest_tn, list)
        assert req.dest_tn == ["+14155559999"]

    def test_dest_tn_list_accepted(self):
        """New-format list dest_tn should work directly."""
        req = CreateVVPAttestationRequest(
            identity_name="test",
            dossier_said="Etest",
            orig_tn="+14155551234",
            dest_tn=["+14155559999", "+14155558888"],
        )
        assert isinstance(req.dest_tn, list)
        assert len(req.dest_tn) == 2

    def test_dest_tn_single_element_list(self):
        """Single-element list dest_tn should work."""
        req = CreateVVPAttestationRequest(
            identity_name="test",
            dossier_said="Etest",
            orig_tn="+14155551234",
            dest_tn=["+14155559999"],
        )
        assert req.dest_tn == ["+14155559999"]


class TestDTORequiredFields:
    """Verify required fields are present on shared DTOs."""

    def test_credential_response_has_required_fields(self):
        """CredentialResponse must have the fields issuer code relies on."""
        resp = CredentialResponse(
            said="Etest",
            issuer_aid="Eissuer",
            recipient_aid="Erecip",
            registry_key="Ereg",
            schema_said="Eschema",
            issuance_dt="2025-01-01T00:00:00Z",
            status="issued",
            attributes={"key": "val"},
        )
        assert resp.said == "Etest"
        assert resp.status == "issued"
        assert resp.attributes == {"key": "val"}
        assert resp.schema_said == "Eschema"
        assert resp.issuer_aid == "Eissuer"

    def test_credential_response_optional_edges(self):
        """CredentialResponse.edges should default to None."""
        resp = CredentialResponse(
            said="Etest",
            issuer_aid="Eissuer",
            recipient_aid="Erecip",
            registry_key="Ereg",
            schema_said="Eschema",
            issuance_dt="2025-01-01T00:00:00Z",
            status="issued",
            attributes={},
        )
        assert resp.edges is None

    def test_identity_response_fields(self):
        """IdentityResponse must have all required fields."""
        resp = IdentityResponse(
            aid="Eprefix",
            name="test-id",
            created_at="2025-01-01T00:00:00Z",
            witness_count=3,
            key_count=1,
            sequence_number=0,
            transferable=True,
        )
        assert resp.name == "test-id"
        assert resp.aid == "Eprefix"
        assert resp.transferable is True

    def test_vvp_attestation_response_fields(self):
        """VVPAttestationResponse must have all required fields."""
        resp = VVPAttestationResponse(
            vvp_identity_header="dGVzdA==",
            passport_jwt="header.payload.signature",
            identity_header="Identity: info=<sip:test>;alg=ES256",
            dossier_url="https://issuer.example.com/dossier/Etest",
            kid_oobi="https://witness.example.com/oobi/Eprefix",
            iat=1700000000,
            exp=1700000300,
        )
        assert resp.vvp_identity_header == "dGVzdA=="
        assert resp.passport_jwt == "header.payload.signature"
        assert resp.dossier_url.startswith("https://")
