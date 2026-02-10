"""Tests for RFC 8224 Identity header builder (Sprint 57)."""

import importlib.util
import os
import pytest

# Load identity module directly to avoid app.vvp.__init__.py pulling in keripy
_spec = importlib.util.spec_from_file_location(
    "app.vvp.identity",
    os.path.join(os.path.dirname(__file__), "..", "app", "vvp", "identity.py"),
)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
build_identity_header = _mod.build_identity_header


SAMPLE_JWT = "eyJhbGciOiJFZERTQSIsInBwdCI6InZ2cCJ9.eyJpYXQiOjE3MDAwMDAwMDB9.0BAAAA"
SAMPLE_OOBI = "https://witness.example.com/oobi/EBfdlu8R27Fbx/controller"


class TestBuildIdentityHeader:
    """Tests for build_identity_header()."""

    def test_basic_format(self):
        """Test RFC 8224 Identity header format."""
        result = build_identity_header(SAMPLE_JWT, SAMPLE_OOBI)

        # Body is JWT directly (no angle brackets)
        assert result.startswith("eyJhbGci")
        # info is angle-bracketed URI
        assert f";info=<{SAMPLE_OOBI}>" in result
        # alg and ppt are plain tokens
        assert ";alg=EdDSA" in result
        assert ";ppt=vvp" in result

    def test_jwt_not_re_encoded(self):
        """Test that JWT is placed directly — no extra base64url layer."""
        result = build_identity_header(SAMPLE_JWT, SAMPLE_OOBI)

        # The header should start with the exact JWT string
        body = result.split(";")[0]
        assert body == SAMPLE_JWT

    def test_info_angle_bracketed(self):
        """Test info parameter is angle-bracketed per RFC 8224 ABNF."""
        result = build_identity_header(SAMPLE_JWT, SAMPLE_OOBI)

        # Should contain info=<URL> not info="URL"
        assert f";info=<{SAMPLE_OOBI}>" in result
        assert 'info="' not in result

    def test_exact_format(self):
        """RFC 8224 conformance test vector."""
        result = build_identity_header(SAMPLE_JWT, SAMPLE_OOBI)

        expected = (
            f"{SAMPLE_JWT}"
            f";info=<{SAMPLE_OOBI}>"
            f";alg=EdDSA"
            f";ppt=vvp"
        )
        assert result == expected

    def test_validates_absolute_uri(self):
        """Test that non-absolute URIs are rejected."""
        with pytest.raises(ValueError, match="absolute URI"):
            build_identity_header(SAMPLE_JWT, "/oobi/AID/controller")

        with pytest.raises(ValueError, match="absolute URI"):
            build_identity_header(SAMPLE_JWT, "not-a-url")

    def test_http_oobi_accepted(self):
        """Test that HTTP OOBIs are accepted."""
        result = build_identity_header(SAMPLE_JWT, "http://localhost:5642/oobi/AID/controller")
        assert ";info=<http://localhost:5642/oobi/AID/controller>" in result

    def test_https_oobi_accepted(self):
        """Test that HTTPS OOBIs are accepted."""
        result = build_identity_header(SAMPLE_JWT, "https://witness.rcnx.io/oobi/AID/controller")
        assert ";info=<https://witness.rcnx.io/oobi/AID/controller>" in result

    def test_empty_jwt_raises(self):
        """Test that empty JWT raises ValueError."""
        with pytest.raises(ValueError, match="passport_jwt must not be empty"):
            build_identity_header("", SAMPLE_OOBI)

    def test_empty_oobi_raises(self):
        """Test that empty OOBI raises ValueError."""
        with pytest.raises(ValueError, match="issuer_oobi must not be empty"):
            build_identity_header(SAMPLE_JWT, "")

    def test_whitespace_only_jwt_raises(self):
        """Test that whitespace-only JWT raises ValueError."""
        with pytest.raises(ValueError, match="passport_jwt must not be empty"):
            build_identity_header("   ", SAMPLE_OOBI)

    def test_whitespace_only_oobi_raises(self):
        """Test that whitespace-only OOBI raises ValueError."""
        with pytest.raises(ValueError, match="issuer_oobi must not be empty"):
            build_identity_header(SAMPLE_JWT, "   ")


class TestRoundTrip:
    """Test that builder output can be parsed by sip-verify identity parser."""

    @staticmethod
    def _load_parser():
        """Load parse_identity_header from sip-verify without polluting sys.path."""
        _parser_spec = importlib.util.spec_from_file_location(
            "identity_parser",
            os.path.join(
                os.path.dirname(__file__),
                "..", "..", "sip-verify", "app", "verify", "identity_parser.py",
            ),
        )
        _parser_mod = importlib.util.module_from_spec(_parser_spec)
        _parser_spec.loader.exec_module(_parser_mod)
        return _parser_mod.parse_identity_header

    def test_round_trip_with_parser(self):
        """Build Identity header and verify it can be parsed back."""
        parse_identity_header = self._load_parser()

        # Build
        identity_value = build_identity_header(SAMPLE_JWT, SAMPLE_OOBI)

        # Parse
        parsed = parse_identity_header(identity_value)

        # Verify round-trip
        assert parsed.passport_jwt == SAMPLE_JWT
        assert parsed.info_url == SAMPLE_OOBI
        assert parsed.algorithm == "EdDSA"
        assert parsed.ppt == "vvp"

    def test_round_trip_with_whitespace(self):
        """Test parser tolerates whitespace around parameters."""
        parse_identity_header = self._load_parser()

        # Add spaces around semicolons (SIP intermediaries may do this)
        header = f"{SAMPLE_JWT} ; info=<{SAMPLE_OOBI}> ; alg=EdDSA ; ppt=vvp"

        parsed = parse_identity_header(header)

        assert parsed.passport_jwt == SAMPLE_JWT
        assert parsed.info_url == SAMPLE_OOBI
        assert parsed.algorithm == "EdDSA"
        assert parsed.ppt == "vvp"


class TestCardClaimInPassport:
    """Sprint 58: Test that card claim can be included in PASSporT payload."""

    @staticmethod
    def _load_card_builder():
        """Load build_card_claim from card module."""
        _card_spec = importlib.util.spec_from_file_location(
            "app.vvp.card",
            os.path.join(os.path.dirname(__file__), "..", "app", "vvp", "card.py"),
        )
        _card_mod = importlib.util.module_from_spec(_card_spec)
        _card_spec.loader.exec_module(_card_mod)
        return _card_mod.build_card_claim

    def test_card_claim_from_brand_credential(self):
        """Build card from credential attrs and verify vCard fields."""
        build_card_claim = self._load_card_builder()

        attrs = {
            "brandName": "ACME Corp",
            "brandDisplayName": "ACME",
            "logoUrl": "https://cdn.acme.com/logo.png",
            "websiteUrl": "https://www.acme.com",
            "assertionCountry": "USA",
        }

        card = build_card_claim(attrs)

        assert card is not None
        assert card["org"] == "ACME Corp"
        assert card["fn"] == "ACME"
        assert card["logo"] == "https://cdn.acme.com/logo.png"
        assert card["url"] == "https://www.acme.com"

    def test_card_claim_json_serializable(self):
        """Card claim must be JSON-serializable for JWT payload."""
        import json
        build_card_claim = self._load_card_builder()

        attrs = {
            "brandName": "Test Brand",
            "logoUrl": "https://example.com/logo.png",
        }

        card = build_card_claim(attrs)

        # Must round-trip through JSON
        json_str = json.dumps(card)
        restored = json.loads(json_str)
        assert restored == card
