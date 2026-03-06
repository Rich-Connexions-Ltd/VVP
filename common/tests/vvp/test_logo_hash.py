"""Tests for logo hash computation and validation."""

import pytest

from common.vvp.logo_hash import (
    LOGO_CONTENT_TYPES,
    LogoFetchError,
    LogoHashMismatchError,
    compute_said_from_bytes,
    redact_url,
    validate_logo_content_type,
    validate_said_format,
)


class TestComputeSaidFromBytes:
    def test_deterministic(self):
        """Same input produces same SAID."""
        data = b"test image bytes"
        said1 = compute_said_from_bytes(data)
        said2 = compute_said_from_bytes(data)
        assert said1 == said2

    def test_e_prefix(self):
        """SAID starts with E (Blake3 derivation code)."""
        said = compute_said_from_bytes(b"test")
        assert said.startswith("E")

    def test_length_44(self):
        """SAID is exactly 44 characters."""
        said = compute_said_from_bytes(b"test")
        assert len(said) == 44

    def test_valid_said_format(self):
        """Computed SAID passes format validation."""
        said = compute_said_from_bytes(b"test")
        assert validate_said_format(said)

    def test_different_data_different_said(self):
        """Different input produces different SAID."""
        said1 = compute_said_from_bytes(b"image1")
        said2 = compute_said_from_bytes(b"image2")
        assert said1 != said2

    def test_empty_bytes(self):
        """Empty input still produces valid SAID."""
        said = compute_said_from_bytes(b"")
        assert len(said) == 44
        assert said.startswith("E")

    def test_large_input(self):
        """Large input produces valid SAID."""
        data = b"x" * (2 * 1024 * 1024)  # 2MB
        said = compute_said_from_bytes(data)
        assert len(said) == 44
        assert said.startswith("E")


class TestValidateSaidFormat:
    def test_valid_said(self):
        assert validate_said_format("E" + "a" * 43) is True

    def test_valid_mixed_chars(self):
        assert validate_said_format("E" + "aB0_-" * 8 + "abc") is True

    def test_wrong_prefix(self):
        assert validate_said_format("A" + "a" * 43) is False

    def test_too_short(self):
        assert validate_said_format("E" + "a" * 42) is False

    def test_too_long(self):
        assert validate_said_format("E" + "a" * 44) is False

    def test_invalid_chars(self):
        assert validate_said_format("E" + "a" * 42 + "!") is False

    def test_empty(self):
        assert validate_said_format("") is False


class TestValidateLogoContentType:
    def test_png(self):
        assert validate_logo_content_type("image/png") is True

    def test_jpeg(self):
        assert validate_logo_content_type("image/jpeg") is True

    def test_webp(self):
        assert validate_logo_content_type("image/webp") is True

    def test_gif(self):
        assert validate_logo_content_type("image/gif") is True

    def test_svg_rejected(self):
        assert validate_logo_content_type("image/svg+xml") is False

    def test_html_rejected(self):
        assert validate_logo_content_type("text/html") is False

    def test_with_charset_parameter(self):
        assert validate_logo_content_type("image/png; charset=utf-8") is True

    def test_case_insensitive(self):
        assert validate_logo_content_type("Image/PNG") is True


class TestRedactUrl:
    def test_strips_query(self):
        assert redact_url("https://cdn.acme.com/logo.png?token=secret") == "https://cdn.acme.com/logo.png"

    def test_strips_fragment(self):
        assert redact_url("https://cdn.acme.com/logo.png#section") == "https://cdn.acme.com/logo.png"

    def test_preserves_path(self):
        assert redact_url("https://cdn.acme.com/path/to/logo.png") == "https://cdn.acme.com/path/to/logo.png"

    def test_no_query_unchanged(self):
        assert redact_url("https://cdn.acme.com/logo.png") == "https://cdn.acme.com/logo.png"
