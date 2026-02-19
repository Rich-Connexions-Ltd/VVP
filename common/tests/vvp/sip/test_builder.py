"""Tests for SIP response builder.

Sprint 44: Tests for shared SIP response builder with verification headers.
"""

import pytest

from common.vvp.sip.models import SIPRequest
from common.vvp.sip.builder import (
    build_302_redirect,
    build_400_bad_request,
    build_401_unauthorized,
    build_403_forbidden,
    build_404_not_found,
    build_500_error,
)


@pytest.fixture
def sample_request():
    """Create a sample SIP request for testing."""
    return SIPRequest(
        method="INVITE",
        request_uri="sip:+14155551234@pbx.example.com",
        sip_version="SIP/2.0",
        via=["SIP/2.0/UDP carrier.com:5060;branch=z9hG4bK123"],
        from_header="<sip:+15551234567@carrier.com>;tag=abc123",
        to_header="<sip:+14155551234@pbx.example.com>",
        call_id="xyz789@carrier.com",
        cseq="1 INVITE",
        from_tn="+15551234567",
        to_tn="+14155551234",
    )


class TestBuild302Redirect:
    """Tests for build_302_redirect function."""

    def test_basic_302(self, sample_request):
        """Build basic 302 redirect."""
        response = build_302_redirect(
            sample_request,
            contact_uri="sip:+14155551234@pbx.example.com:5060",
        )

        assert response.status_code == 302
        assert response.reason_phrase == "Moved Temporarily"
        assert "<sip:+14155551234@pbx.example.com:5060>" in response.contact

    def test_302_with_vvp_headers(self, sample_request):
        """Build 302 redirect with VVP headers."""
        response = build_302_redirect(
            sample_request,
            contact_uri="sip:+14155551234@pbx.example.com:5060",
            vvp_identity="eyJwcHQiOiJ2dnAifQ==",
            vvp_passport="eyJhbGciOiJFZERTQSJ9.payload.sig",
            vvp_status="VALID",
            brand_name="Acme Corporation",
            brand_logo_url="https://cdn.acme.com/logo.png",
        )

        assert response.vvp_identity == "eyJwcHQiOiJ2dnAifQ=="
        assert response.vvp_passport == "eyJhbGciOiJFZERTQSJ9.payload.sig"
        assert response.vvp_status == "VALID"
        assert response.brand_name == "Acme Corporation"
        assert response.brand_logo_url == "https://cdn.acme.com/logo.png"

    def test_302_with_caller_id(self, sample_request):
        """Build 302 redirect with caller ID."""
        response = build_302_redirect(
            sample_request,
            contact_uri="sip:+14155551234@pbx.example.com:5060",
            caller_id="+15551234567",
        )

        assert response.caller_id == "+15551234567"

    def test_302_with_error_code(self, sample_request):
        """Build 302 redirect with error code for INVALID status."""
        response = build_302_redirect(
            sample_request,
            contact_uri="sip:+14155551234@pbx.example.com:5060",
            vvp_status="INVALID",
            error_code="SIGNATURE_INVALID",
        )

        assert response.vvp_status == "INVALID"
        assert response.error_code == "SIGNATURE_INVALID"

    def test_302_with_identity_header(self, sample_request):
        """Sprint 57: Build 302 redirect with RFC 8224 Identity header."""
        identity_value = "eyJhbGci.payload.sig;info=<https://w.example.com/oobi/AID>;alg=EdDSA;ppt=vvp"
        response = build_302_redirect(
            sample_request,
            contact_uri="sip:+14155551234@pbx.example.com:5060",
            identity=identity_value,
        )

        assert response.identity == identity_value

    def test_302_copies_transaction_headers(self, sample_request):
        """302 response copies transaction headers from request."""
        response = build_302_redirect(
            sample_request,
            contact_uri="sip:+14155551234@pbx.example.com:5060",
        )

        assert response.via == sample_request.via
        assert response.from_header == sample_request.from_header
        assert response.call_id == sample_request.call_id
        assert response.cseq == sample_request.cseq
        # To header should have tag added
        assert ";tag=" in response.to_header

    def test_302_to_bytes(self, sample_request):
        """302 response serializes correctly."""
        response = build_302_redirect(
            sample_request,
            contact_uri="sip:+14155551234@pbx.example.com:5060",
            vvp_status="VALID",
            brand_name="Acme Corp",
        )

        data = response.to_bytes()
        text = data.decode("utf-8")

        assert "SIP/2.0 302 Moved Temporarily" in text
        assert "Via: SIP/2.0/UDP carrier.com:5060" in text
        assert "Call-ID: xyz789@carrier.com" in text
        assert "X-VVP-Status: VALID" in text
        assert "X-VVP-Brand-Name: Acme Corp" in text
        assert "Content-Length: 0" in text


class TestBuild400BadRequest:
    """Tests for build_400_bad_request function."""

    def test_400_basic(self, sample_request):
        """Build basic 400 response."""
        response = build_400_bad_request(
            sample_request,
            reason="Missing Identity header",
        )

        assert response.status_code == 400
        assert response.reason_phrase == "Bad Request"
        assert response.error_reason == "Missing Identity header"

    def test_400_copies_transaction_headers(self, sample_request):
        """400 response copies transaction headers."""
        response = build_400_bad_request(sample_request, reason="Test")

        assert response.call_id == sample_request.call_id
        assert response.cseq == sample_request.cseq


class TestBuild401Unauthorized:
    """Tests for build_401_unauthorized function."""

    def test_401_basic(self, sample_request):
        """Build basic 401 response."""
        response = build_401_unauthorized(
            sample_request,
            reason="Invalid API key",
        )

        assert response.status_code == 401
        assert response.reason_phrase == "Unauthorized"
        assert response.vvp_status == "INVALID"


class TestBuild403Forbidden:
    """Tests for build_403_forbidden function."""

    def test_403_basic(self, sample_request):
        """Build basic 403 response."""
        response = build_403_forbidden(
            sample_request,
            reason="Rate limit exceeded",
        )

        assert response.status_code == 403
        assert response.reason_phrase == "Forbidden"


class TestBuild404NotFound:
    """Tests for build_404_not_found function."""

    def test_404_basic(self, sample_request):
        """Build basic 404 response."""
        response = build_404_not_found(
            sample_request,
            reason="TN not found",
        )

        assert response.status_code == 404
        assert response.reason_phrase == "Not Found"


class TestBuild500Error:
    """Tests for build_500_error function."""

    def test_500_basic(self, sample_request):
        """Build basic 500 response."""
        response = build_500_error(
            sample_request,
            reason="Internal error",
        )

        assert response.status_code == 500
        assert response.reason_phrase == "Server Internal Error"
        assert response.vvp_status == "INDETERMINATE"


class TestSIPResponseSerialization:
    """Tests for SIPResponse.to_bytes serialization."""

    def test_serialization_includes_all_vvp_headers(self, sample_request):
        """Serialization includes all VVP headers when set."""
        response = build_302_redirect(
            sample_request,
            contact_uri="sip:dest@pbx.example.com",
            vvp_identity="identity123",
            vvp_passport="passport456",
            vvp_status="VALID",
            brand_name="Test Brand",
            brand_logo_url="https://example.com/logo.png",
            caller_id="+15551234567",
        )

        data = response.to_bytes()
        text = data.decode("utf-8")

        assert "P-VVP-Identity: identity123" in text
        assert "P-VVP-Passport: passport456" in text
        assert "X-VVP-Status: VALID" in text
        assert "X-VVP-Brand-Name: Test Brand" in text
        assert "X-VVP-Brand-Logo: https://example.com/logo.png" in text
        assert "X-VVP-Caller-ID: +15551234567" in text

    def test_serialization_includes_error_code(self, sample_request):
        """Serialization includes X-VVP-Error when set."""
        response = build_302_redirect(
            sample_request,
            contact_uri="sip:dest@pbx.example.com",
            vvp_status="INVALID",
            error_code="CREDENTIAL_REVOKED",
        )

        data = response.to_bytes()
        text = data.decode("utf-8")

        assert "X-VVP-Error: CREDENTIAL_REVOKED" in text

    def test_serialization_ends_with_crlf(self, sample_request):
        """Serialization ends with proper CRLF sequence."""
        response = build_302_redirect(
            sample_request,
            contact_uri="sip:dest@pbx.example.com",
        )

        data = response.to_bytes()
        assert data.endswith(b"\r\n\r\n")

    def test_serialization_includes_identity_header(self, sample_request):
        """Sprint 57: Serialization includes Identity header when set."""
        identity_value = (
            "eyJhbGci.payload.sig;"
            "info=<https://witness.example.com/oobi/AID/controller>;"
            "alg=EdDSA;ppt=vvp"
        )
        response = build_302_redirect(
            sample_request,
            contact_uri="sip:dest@pbx.example.com",
            identity=identity_value,
            vvp_identity="identity123",
            vvp_passport="passport456",
        )

        data = response.to_bytes()
        text = data.decode("utf-8")

        assert f"Identity: {identity_value}\r\n" in text

    def test_serialization_omits_identity_header_when_none(self, sample_request):
        """Sprint 57: Identity header absent when not provided."""
        response = build_302_redirect(
            sample_request,
            contact_uri="sip:dest@pbx.example.com",
            vvp_identity="identity123",
            vvp_passport="passport456",
        )

        data = response.to_bytes()
        text = data.decode("utf-8")

        # Use \r\nIdentity: to avoid matching P-VVP-Identity:
        assert "\r\nIdentity: " not in text

    def test_identity_header_before_vvp_headers(self, sample_request):
        """Sprint 57: Identity header appears before P-VVP-* headers."""
        identity_value = "eyJhbGci.payload.sig;info=<https://w.example.com/oobi/AID>;alg=EdDSA;ppt=vvp"
        response = build_302_redirect(
            sample_request,
            contact_uri="sip:dest@pbx.example.com",
            identity=identity_value,
            vvp_identity="identity123",
            vvp_passport="passport456",
        )

        data = response.to_bytes()
        text = data.decode("utf-8")

        identity_pos = text.index("Identity:")
        pvvp_pos = text.index("P-VVP-Identity:")
        assert identity_pos < pvvp_pos

    def test_302_with_warning_reason(self, sample_request):
        """Sprint 75: Build 302 redirect with WARNING status and warning_reason."""
        response = build_302_redirect(
            sample_request,
            contact_uri="sip:dest@pbx.example.com",
            vvp_status="WARNING",
            warning_reason="vetter_not_authorised_for_jurisdiction",
        )

        assert response.vvp_status == "WARNING"
        assert response.warning_reason == "vetter_not_authorised_for_jurisdiction"

    def test_302_warning_reason_in_bytes(self, sample_request):
        """Sprint 75: X-VVP-Warning-Reason header appears in serialised response."""
        response = build_302_redirect(
            sample_request,
            contact_uri="sip:dest@pbx.example.com",
            vvp_status="WARNING",
            warning_reason="vetter_not_authorised_for_jurisdiction",
        )

        text = response.to_bytes().decode("utf-8")
        assert "X-VVP-Warning-Reason: vetter_not_authorised_for_jurisdiction" in text
        assert "X-VVP-Status: WARNING" in text

    def test_302_no_warning_reason_when_none(self, sample_request):
        """Sprint 75: X-VVP-Warning-Reason header is absent when warning_reason is None."""
        response = build_302_redirect(
            sample_request,
            contact_uri="sip:dest@pbx.example.com",
            vvp_status="VALID",
        )

        text = response.to_bytes().decode("utf-8")
        assert "X-VVP-Warning-Reason" not in text
