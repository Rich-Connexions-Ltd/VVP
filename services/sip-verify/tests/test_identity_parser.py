"""Tests for RFC 8224 Identity header parser.

Sprint 44: Tests for parsing SIP Identity header.
"""

import base64
import pytest

from app.verify.identity_parser import (
    ParsedIdentityHeader,
    parse_identity_header,
    IdentityParseError,
)


class TestParseIdentityHeader:
    """Tests for parse_identity_header function."""

    def test_parse_basic_identity(self):
        """Parse basic Identity header with angle brackets."""
        # Build a sample PASSporT JWT (just a placeholder for testing)
        passport = "eyJhbGciOiJFZERTQSJ9.eyJpYXQiOjE3MDQwNjcyMDB9.sig"
        encoded = base64.urlsafe_b64encode(passport.encode()).decode().rstrip("=")

        header = f"<{encoded}>;info=https://witness.example.com/oobi/EAbc/witness;alg=EdDSA;ppt=vvp"

        result = parse_identity_header(header)

        assert result.passport_jwt == passport
        assert result.info_url == "https://witness.example.com/oobi/EAbc/witness"
        assert result.algorithm == "EdDSA"
        assert result.ppt == "vvp"

    def test_parse_without_angle_brackets(self):
        """Parse Identity header without angle brackets (legacy format)."""
        passport = "eyJhbGciOiJFZERTQSJ9.eyJpYXQiOjE3MDQwNjcyMDB9.sig"
        encoded = base64.urlsafe_b64encode(passport.encode()).decode().rstrip("=")

        header = f"{encoded};info=https://witness.example.com/oobi/EAbc/witness;alg=EdDSA;ppt=vvp"

        result = parse_identity_header(header)

        assert result.passport_jwt == passport
        assert result.info_url == "https://witness.example.com/oobi/EAbc/witness"

    def test_parse_quoted_info(self):
        """Parse Identity header with quoted info parameter."""
        passport = "test.payload.signature"
        encoded = base64.urlsafe_b64encode(passport.encode()).decode().rstrip("=")

        header = f'<{encoded}>;info="https://witness.example.com/oobi/EAbc/witness";alg=EdDSA;ppt=vvp'

        result = parse_identity_header(header)

        assert result.info_url == "https://witness.example.com/oobi/EAbc/witness"

    def test_parse_missing_ppt(self):
        """Parse Identity header without ppt parameter."""
        passport = "test.payload.signature"
        encoded = base64.urlsafe_b64encode(passport.encode()).decode().rstrip("=")

        header = f"<{encoded}>;info=https://example.com;alg=EdDSA"

        result = parse_identity_header(header)

        assert result.ppt == ""  # Empty when not provided

    def test_parse_empty_header_raises(self):
        """Empty header should raise error."""
        with pytest.raises(IdentityParseError, match="Empty"):
            parse_identity_header("")

    def test_parse_empty_body_raises(self):
        """Empty body should raise error."""
        with pytest.raises(IdentityParseError, match="Empty|Malformed"):
            parse_identity_header("<>;info=https://example.com")

    def test_parse_unclosed_bracket_raises(self):
        """Unclosed angle bracket should raise error."""
        with pytest.raises(IdentityParseError, match="unclosed"):
            parse_identity_header("<body")

    def test_parse_invalid_base64_raises(self):
        """Invalid base64 should raise error."""
        with pytest.raises(IdentityParseError, match="base64|UTF-8"):
            parse_identity_header("<!!!invalid!!!>;info=https://example.com")

    def test_parse_url_encoded_info(self):
        """URL-encoded info parameter should be decoded."""
        passport = "test.payload.signature"
        encoded = base64.urlsafe_b64encode(passport.encode()).decode().rstrip("=")

        # URL-encoded URL
        header = f"<{encoded}>;info=https%3A%2F%2Fexample.com%2Fpath;alg=EdDSA"

        result = parse_identity_header(header)

        assert result.info_url == "https://example.com/path"


class TestParsedIdentityHeader:
    """Tests for ParsedIdentityHeader dataclass."""

    def test_dataclass_fields(self):
        """Verify dataclass has expected fields."""
        header = ParsedIdentityHeader(
            passport_jwt="jwt",
            info_url="https://example.com",
            algorithm="EdDSA",
            ppt="vvp",
            raw_body="encoded",
        )

        assert header.passport_jwt == "jwt"
        assert header.info_url == "https://example.com"
        assert header.algorithm == "EdDSA"
        assert header.ppt == "vvp"
        assert header.raw_body == "encoded"
