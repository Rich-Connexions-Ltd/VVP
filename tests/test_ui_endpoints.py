"""
Integration tests for HTMX UI endpoints.

These tests ensure UI endpoints properly delegate to the domain layer
instead of reimplementing parsing logic. This prevents bugs where the
UI layer diverges from the domain layer.

Phase 13B: Separation of Concerns Refactoring.
"""

import base64
import json
import time

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.vvp.passport import parse_passport


client = TestClient(app)


# =============================================================================
# Test Helpers
# =============================================================================

def b64url_encode(data: dict) -> str:
    """Base64url encode a dictionary as JSON."""
    json_bytes = json.dumps(data).encode("utf-8")
    return base64.urlsafe_b64encode(json_bytes).rstrip(b"=").decode("ascii")


def make_jwt(header: dict, payload: dict, signature: str = "c2lnbmF0dXJl") -> str:
    """Create a JWT string from header and payload dicts."""
    return f"{b64url_encode(header)}.{b64url_encode(payload)}.{signature}"


def valid_header() -> dict:
    """Return a valid PASSporT header."""
    return {
        "alg": "EdDSA",
        "ppt": "vvp",
        "kid": "http://witness.example.com/oobi/EExampleAID123",
    }


def valid_payload(iat: int = None) -> dict:
    """Return a valid PASSporT payload."""
    if iat is None:
        iat = int(time.time())
    return {
        "iat": iat,
        "orig": {"tn": "+12025551234"},
        "dest": {"tn": ["+12025555678"]},
        "evd": "http://example.com/dossier",
    }


# =============================================================================
# /ui/parse-jwt Tests
# =============================================================================

class TestUIParseJWT:
    """Test /ui/parse-jwt endpoint uses domain layer correctly."""

    def test_parse_jwt_returns_same_values_as_domain_layer(self):
        """UI endpoint must produce same values as domain layer parse_passport()."""
        jwt = make_jwt(valid_header(), valid_payload())

        # Parse with domain layer
        passport = parse_passport(jwt)

        # Parse with UI endpoint
        response = client.post("/ui/parse-jwt", data={"jwt": jwt})

        # Verify success
        assert response.status_code == 200

        # Verify header values appear in response
        assert passport.header.alg in response.text
        assert passport.header.ppt in response.text
        assert passport.header.kid in response.text

        # Verify payload values appear in response
        assert str(passport.payload.iat) in response.text
        assert passport.payload.evd in response.text

    def test_parse_jwt_handles_ppt_suffix(self):
        """UI endpoint strips ;ppt=vvp suffix (UI convenience)."""
        jwt = make_jwt(valid_header(), valid_payload())
        jwt_with_suffix = f"{jwt};ppt=vvp"

        response = client.post("/ui/parse-jwt", data={"jwt": jwt_with_suffix})

        assert response.status_code == 200
        # Should parse successfully, not error
        assert "error" not in response.text.lower() or "Error" not in response.text

    def test_parse_jwt_invalid_format_shows_error(self):
        """Invalid JWT should show error message from domain layer."""
        response = client.post("/ui/parse-jwt", data={"jwt": "not.valid"})

        assert response.status_code == 200  # HTML response
        # Should contain error message
        assert "error" in response.text.lower() or "Error" in response.text

    def test_parse_jwt_forbidden_algorithm_shows_error(self):
        """Forbidden algorithm should show error from domain layer."""
        header = valid_header()
        header["alg"] = "ES256"  # Forbidden

        jwt = make_jwt(header, valid_payload())
        response = client.post("/ui/parse-jwt", data={"jwt": jwt})

        assert response.status_code == 200
        assert "forbidden" in response.text.lower() or "ES256" in response.text

    def test_parse_jwt_signature_displayed_as_hex(self):
        """Signature should be displayed as hex string."""
        jwt = make_jwt(valid_header(), valid_payload())

        response = client.post("/ui/parse-jwt", data={"jwt": jwt})

        assert response.status_code == 200
        # The base64url signature "c2lnbmF0dXJl" decodes to "signature"
        # which in hex is "7369676e6174757265"
        assert "7369676e6174757265" in response.text


class TestUIParseJWTDomainLayerAlignment:
    """Verify UI endpoint stays aligned with domain layer behavior."""

    def test_missing_required_field_caught(self):
        """Domain layer catches missing required fields."""
        header = valid_header()
        payload = {"iat": int(time.time())}  # Missing orig, dest, evd

        jwt = make_jwt(header, payload)
        response = client.post("/ui/parse-jwt", data={"jwt": jwt})

        assert response.status_code == 200
        # Domain layer should catch missing field
        assert "orig" in response.text or "required" in response.text.lower()

    def test_orig_tn_must_be_string_not_array(self):
        """Domain layer validates orig.tn is string, not array (§4.2)."""
        header = valid_header()
        payload = valid_payload()
        payload["orig"]["tn"] = ["+12025551234"]  # Should be string

        jwt = make_jwt(header, payload)
        response = client.post("/ui/parse-jwt", data={"jwt": jwt})

        assert response.status_code == 200
        # Domain layer should catch this
        assert "array" in response.text.lower() or "string" in response.text.lower()


class TestUIParseJWTPermissiveMode:
    """Test permissive decode - show content even when validation fails."""

    def test_invalid_jwt_shows_content_and_error(self):
        """Invalid JWT should show decoded content AND validation error."""
        header = valid_header()
        payload = valid_payload()
        payload["orig"]["tn"] = ["+12025551234"]  # Invalid: array instead of string

        jwt = make_jwt(header, payload)
        response = client.post("/ui/parse-jwt", data={"jwt": jwt})

        assert response.status_code == 200
        # Should show the content (decoded payload)
        assert "12025551234" in response.text  # Phone number visible
        assert header["alg"] in response.text  # Algorithm visible
        # Should also show validation warning
        assert "Validation Warning" in response.text or "array" in response.text.lower()

    def test_forbidden_alg_shows_content_and_error(self):
        """Forbidden algorithm JWT shows decoded content AND validation error."""
        header = valid_header()
        header["alg"] = "ES256"  # Forbidden algorithm
        payload = valid_payload()

        jwt = make_jwt(header, payload)
        response = client.post("/ui/parse-jwt", data={"jwt": jwt})

        assert response.status_code == 200
        # Should show decoded content
        assert "ES256" in response.text  # Algorithm visible in decoded header
        # Should show validation error
        assert "forbidden" in response.text.lower()

    def test_validation_error_includes_spec_reference(self):
        """Validation errors should include spec section reference."""
        header = valid_header()
        payload = valid_payload()
        payload["orig"]["tn"] = ["+12025551234"]  # Invalid: array instead of string

        jwt = make_jwt(header, payload)
        response = client.post("/ui/parse-jwt", data={"jwt": jwt})

        assert response.status_code == 200
        # Should show spec section reference for orig.tn validation
        assert "§4.2" in response.text  # Spec section for phone number validation

    def test_forbidden_alg_shows_spec_reference(self):
        """Forbidden algorithm should show §5.0/§5.1 spec reference."""
        header = valid_header()
        header["alg"] = "ES256"  # Forbidden algorithm
        payload = valid_payload()

        jwt = make_jwt(header, payload)
        response = client.post("/ui/parse-jwt", data={"jwt": jwt})

        assert response.status_code == 200
        # Should show spec section for algorithm validation
        assert "§5.0" in response.text or "§5.1" in response.text


# =============================================================================
# /ui/fetch-dossier Tests
# =============================================================================

class TestUIFetchDossier:
    """Test /ui/fetch-dossier endpoint uses domain layer correctly."""

    def test_fetch_dossier_endpoint_exists(self):
        """Verify endpoint exists and returns HTML on error."""
        # Invalid URL should return HTML error, not crash
        response = client.post(
            "/ui/fetch-dossier",
            data={"evd_url": "http://invalid.localhost/dossier.cesr"}
        )

        # Should return HTML (200 with error message), not 5xx
        assert response.status_code == 200
        assert "error" in response.text.lower() or "Error" in response.text


# =============================================================================
# /ui/parse-sip Tests
# =============================================================================

class TestUIParseSIP:
    """Test /ui/parse-sip endpoint (UI-specific, no domain equivalent)."""

    def test_parse_sip_extracts_identity_header(self):
        """SIP parsing extracts Identity header JWT."""
        sip_invite = """INVITE sip:+12025555678@example.com SIP/2.0
Via: SIP/2.0/UDP 192.0.2.1:5060
From: <sip:+12025551234@example.com>
To: <sip:+12025555678@example.com>
Identity: eyJhbGciOiJFZERTQSJ9.eyJpYXQiOjE3MDAwMDAwMDB9.sig;info=<http://example.com>
"""

        response = client.post("/ui/parse-sip", data={"sip_invite": sip_invite})

        assert response.status_code == 200
        # Should extract the JWT portion
        assert "eyJhbGciOiJFZERTQSJ9" in response.text

    def test_parse_sip_no_identity_header(self):
        """SIP without Identity header shows appropriate message."""
        sip_invite = """INVITE sip:+12025555678@example.com SIP/2.0
Via: SIP/2.0/UDP 192.0.2.1:5060
From: <sip:+12025551234@example.com>
"""

        response = client.post("/ui/parse-sip", data={"sip_invite": sip_invite})

        assert response.status_code == 200
        # Should indicate no Identity header found
        assert "No Identity" in response.text or "not found" in response.text.lower()
