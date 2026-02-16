"""Tests for PASSporT JWT creation and PSS CESR signature encoding."""

import base64

import pytest

from app.vvp.passport import encode_pss_signature, validate_e164
from app.vvp.exceptions import InvalidPhoneNumberError


class TestEncodePssSignature:
    """Tests for PSS CESR signature encoding."""

    def test_basic_encoding(self):
        """Test basic signature encoding."""
        # 64-byte dummy signature
        sig_bytes = b"\x00" * 64

        result = encode_pss_signature(sig_bytes, index=1)

        assert len(result) == 88
        assert result.startswith("0B")

    def test_index_0_produces_0A_prefix(self):
        """Test that index 0 produces 0A prefix."""
        sig_bytes = b"\x00" * 64

        result = encode_pss_signature(sig_bytes, index=0)

        assert result.startswith("0A")

    def test_index_1_produces_0B_prefix(self):
        """Test that index 1 produces 0B prefix."""
        sig_bytes = b"\x00" * 64

        result = encode_pss_signature(sig_bytes, index=1)

        assert result.startswith("0B")

    def test_index_2_produces_0C_prefix(self):
        """Test that index 2 produces 0C prefix."""
        sig_bytes = b"\x00" * 64

        result = encode_pss_signature(sig_bytes, index=2)

        assert result.startswith("0C")

    def test_index_3_produces_0D_prefix(self):
        """Test that index 3 produces 0D prefix."""
        sig_bytes = b"\x00" * 64

        result = encode_pss_signature(sig_bytes, index=3)

        assert result.startswith("0D")

    def test_wrong_signature_length_raises(self):
        """Test that non-64-byte signature raises ValueError."""
        with pytest.raises(ValueError, match="must be 64 bytes"):
            encode_pss_signature(b"\x00" * 32, index=1)

        with pytest.raises(ValueError, match="must be 64 bytes"):
            encode_pss_signature(b"\x00" * 128, index=1)

    def test_invalid_index_raises(self):
        """Test that invalid index raises ValueError."""
        sig_bytes = b"\x00" * 64

        with pytest.raises(ValueError, match="must be 0-3"):
            encode_pss_signature(sig_bytes, index=-1)

        with pytest.raises(ValueError, match="must be 0-3"):
            encode_pss_signature(sig_bytes, index=4)

    def test_signature_is_base64url_decodable(self):
        """Test that signature part is valid base64url."""
        sig_bytes = bytes(range(64))  # Non-trivial signature

        result = encode_pss_signature(sig_bytes, index=1)

        # Extract signature part (after 2-char prefix)
        sig_b64 = result[2:]
        padded = sig_b64 + "=" * (-len(sig_b64) % 4)

        # Should decode without error
        decoded = base64.urlsafe_b64decode(padded)
        assert decoded == sig_bytes

    def test_round_trip_with_verifier_decode(self):
        """Test that encoded signature can be decoded by verifier logic."""
        # Use a realistic signature pattern
        sig_bytes = bytes([i % 256 for i in range(64)])

        encoded = encode_pss_signature(sig_bytes, index=1)

        # Simulate verifier's decode_pss_signature logic
        assert len(encoded) == 88
        code = encoded[:2]
        assert code == "0B"

        sig_b64 = encoded[2:]
        padded = sig_b64 + "=" * (-len(sig_b64) % 4)
        decoded = base64.urlsafe_b64decode(padded)

        assert decoded == sig_bytes


class TestValidateE164:
    """Tests for E.164 phone number validation."""

    def test_valid_us_number(self):
        """Test valid US phone number."""
        # Should not raise
        validate_e164("+14155551234", "orig_tn")

    def test_valid_uk_number(self):
        """Test valid UK phone number."""
        validate_e164("+442071234567", "dest_tn")

    def test_valid_short_number(self):
        """Test valid short number (min 2 digits after +)."""
        validate_e164("+12", "test")

    def test_valid_long_number(self):
        """Test valid long number (max 15 digits after +)."""
        validate_e164("+123456789012345", "test")

    def test_missing_plus_raises(self):
        """Test number without + raises error."""
        with pytest.raises(InvalidPhoneNumberError):
            validate_e164("14155551234", "test")

    def test_leading_zero_raises(self):
        """Test number with leading zero after + raises error."""
        with pytest.raises(InvalidPhoneNumberError):
            validate_e164("+04155551234", "test")

    def test_too_long_raises(self):
        """Test number longer than 15 digits raises error."""
        with pytest.raises(InvalidPhoneNumberError):
            validate_e164("+1234567890123456", "test")  # 16 digits

    def test_too_short_raises(self):
        """Test number shorter than 2 digits raises error."""
        with pytest.raises(InvalidPhoneNumberError):
            validate_e164("+1", "test")  # Only 1 digit

    def test_non_numeric_raises(self):
        """Test number with non-numeric characters raises error."""
        with pytest.raises(InvalidPhoneNumberError):
            validate_e164("+1415555ABCD", "test")

    def test_spaces_not_allowed(self):
        """Test number with spaces raises error."""
        with pytest.raises(InvalidPhoneNumberError):
            validate_e164("+1 415 555 1234", "test")

    def test_dashes_not_allowed(self):
        """Test number with dashes raises error."""
        with pytest.raises(InvalidPhoneNumberError):
            validate_e164("+1-415-555-1234", "test")

    def test_parentheses_not_allowed(self):
        """Test number with parentheses raises error."""
        with pytest.raises(InvalidPhoneNumberError):
            validate_e164("+1(415)5551234", "test")
