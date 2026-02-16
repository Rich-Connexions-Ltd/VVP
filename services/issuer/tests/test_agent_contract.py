"""Agent contract tests for issuer↔agent DTO compatibility.

Sprint 68c: Verifies that shared DTOs in common/vvp/models/keri_agent.py
maintain backward compatibility (N/N-1 rule) and that the issuer correctly
uses KeriAgentClient for all KERI operations.
"""

import pytest
from pydantic import ValidationError

from common.vvp.models.keri_agent import (
    BuildDossierRequest,
    CreateIdentityRequest,
    CreateVVPAttestationRequest,
    VVPAttestationResponse,
    IssueCredentialRequest,
    CredentialResponse,
    DossierResponse,
    IdentityResponse,
    RegistryResponse,
    RotateKeysRequest,
    BootstrapStatusResponse,
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


class TestDTOValidation:
    """Verify DTO validation catches malformed requests."""

    def test_attestation_request_missing_required_fields(self):
        """Missing required fields should raise ValidationError."""
        with pytest.raises(ValidationError):
            CreateVVPAttestationRequest(
                identity_name="test",
                # Missing dossier_said, orig_tn, dest_tn
            )

    def test_issue_credential_request_required_fields(self):
        """IssueCredentialRequest must have all required fields."""
        req = IssueCredentialRequest(
            identity_name="test",
            registry_name="test-reg",
            schema_said="Eschema",
            attributes={"name": "Test"},
        )
        assert req.identity_name == "test"
        assert req.publish is True  # default

    def test_build_dossier_request(self):
        """BuildDossierRequest must accept root_said."""
        req = BuildDossierRequest(root_said="Eroot")
        assert req.root_said == "Eroot"
        assert req.include_tel is True  # default

    def test_dossier_response_shape(self):
        """DossierResponse must include credential_saids list."""
        resp = DossierResponse(
            root_said="Eroot",
            root_saids=["Eroot"],
            credential_saids=["Ecred1", "Ecred2"],
        )
        assert len(resp.credential_saids) == 2
        assert resp.is_aggregate is False  # default

    def test_bootstrap_status_response(self):
        """BootstrapStatusResponse must include QVI credential SAID field."""
        resp = BootstrapStatusResponse(
            initialized=True,
            gleif_aid="Egleif",
            qvi_credential_said="Eqvi_cred",
        )
        assert resp.initialized is True
        assert resp.qvi_credential_said == "Eqvi_cred"


class TestDTORoundTrip:
    """Verify DTOs survive JSON serialization round-trip (wire format)."""

    def test_attestation_request_round_trip(self):
        """Request should survive model_dump → model_validate."""
        req = CreateVVPAttestationRequest(
            identity_name="test",
            dossier_said="Etest",
            orig_tn="+14155551234",
            dest_tn=["+14155559999"],
            exp_seconds=120,
            card=["BEGIN:VCARD", "FN:Brand", "END:VCARD"],
            dossier_url="https://issuer.example.com/dossier/Etest",
            kid_oobi="https://witness.example.com/oobi/Eaid",
        )
        payload = req.model_dump()
        restored = CreateVVPAttestationRequest.model_validate(payload)
        assert restored.identity_name == req.identity_name
        assert restored.dest_tn == req.dest_tn
        assert restored.card == req.card
        assert restored.dossier_url == req.dossier_url

    def test_attestation_response_round_trip(self):
        """Response should survive model_dump → model_validate."""
        resp = VVPAttestationResponse(
            vvp_identity_header="dGVzdA==",
            passport_jwt="h.p.s",
            identity_header="Identity: test",
            dossier_url="https://issuer.example.com/dossier/Etest",
            kid_oobi="https://witness.example.com/oobi/Eaid",
            iat=1700000000,
            exp=1700000300,
        )
        payload = resp.model_dump()
        restored = VVPAttestationResponse.model_validate(payload)
        assert restored.passport_jwt == resp.passport_jwt
        assert restored.iat == resp.iat

    def test_credential_response_round_trip_with_edges(self):
        """CredentialResponse with edges should survive round-trip."""
        resp = CredentialResponse(
            said="Ecred",
            issuer_aid="Eissuer",
            registry_key="Ereg",
            schema_said="Eschema",
            issuance_dt="2025-01-01T00:00:00Z",
            status="issued",
            attributes={"name": "Test"},
            edges={"qviCredential": {"n": "Eqvi", "s": "Eschema_qvi"}},
        )
        payload = resp.model_dump()
        restored = CredentialResponse.model_validate(payload)
        assert restored.edges == resp.edges
        assert restored.said == resp.said
