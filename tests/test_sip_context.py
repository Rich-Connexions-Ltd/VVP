"""Tests for SIP contextual alignment (Phase 13).

Tests cover:
- SIP URI parsing (various formats)
- orig/dest alignment validation
- Timing tolerance validation
- Integration with passport verification
"""

import pytest
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass
from typing import Optional, Dict, Any, List

from app.vvp.sip_context import (
    extract_tn_from_sip_uri,
    validate_orig_alignment,
    validate_dest_alignment,
    validate_timing_alignment,
    verify_sip_context_alignment,
    _normalize_to_e164,
    ClaimBuilder,
)
from app.vvp.api_models import ClaimStatus, SipContext


# =============================================================================
# Mock Passport for testing
# =============================================================================


@dataclass
class MockPassportPayload:
    """Mock PASSporT payload for testing."""

    iat: int
    orig: Optional[Dict[str, Any]] = None
    dest: Optional[Dict[str, Any]] = None


@dataclass
class MockPassport:
    """Mock PASSporT for testing."""

    payload: MockPassportPayload


# =============================================================================
# URI Parsing Tests
# =============================================================================


class TestExtractTnFromSipUri:
    """Tests for SIP/TEL URI phone number extraction."""

    def test_sip_uri_with_plus(self):
        """Parse sip:+15551234567@domain.com"""
        result = extract_tn_from_sip_uri("sip:+15551234567@gateway.example.com")
        assert result == "+15551234567"

    def test_sip_uri_without_plus(self):
        """Parse sip:15551234567@domain.com - should normalize to E.164"""
        result = extract_tn_from_sip_uri("sip:15551234567@gateway.example.com")
        assert result == "+15551234567"

    def test_sips_uri(self):
        """Parse sips: (secure SIP) URI"""
        result = extract_tn_from_sip_uri("sips:+15551234567@secure.example.com")
        assert result == "+15551234567"

    def test_sip_uri_with_params(self):
        """Parse sip URI with user=phone parameter"""
        result = extract_tn_from_sip_uri(
            "sip:+15551234567@gateway.example.com;user=phone"
        )
        assert result == "+15551234567"

    def test_tel_uri(self):
        """Parse tel:+15551234567"""
        result = extract_tn_from_sip_uri("tel:+15551234567")
        assert result == "+15551234567"

    def test_tel_uri_with_separators(self):
        """Parse tel:+1-555-123-4567 with visual separators"""
        result = extract_tn_from_sip_uri("tel:+1-555-123-4567")
        assert result == "+15551234567"

    def test_tel_uri_with_spaces(self):
        """Parse tel URI with spaces"""
        result = extract_tn_from_sip_uri("tel:+1 555 123 4567")
        assert result == "+15551234567"

    def test_tel_uri_with_params(self):
        """Parse tel URI with parameters"""
        result = extract_tn_from_sip_uri("tel:+15551234567;ext=1234")
        assert result == "+15551234567"

    def test_invalid_uri_returns_none(self):
        """Invalid URI should return None"""
        assert extract_tn_from_sip_uri("") is None
        assert extract_tn_from_sip_uri("invalid") is None
        assert extract_tn_from_sip_uri("mailto:test@example.com") is None

    def test_sip_uri_non_phone_user(self):
        """SIP URI with non-phone user should return None"""
        result = extract_tn_from_sip_uri("sip:alice@example.com")
        assert result is None

    def test_bare_phone_number(self):
        """Bare phone number (not URI) should be normalized"""
        result = extract_tn_from_sip_uri("+15551234567")
        assert result == "+15551234567"


class TestNormalizeToE164:
    """Tests for E.164 normalization."""

    def test_already_e164(self):
        """Already E.164 format unchanged"""
        assert _normalize_to_e164("+15551234567") == "+15551234567"

    def test_add_plus(self):
        """Add + prefix to bare number"""
        assert _normalize_to_e164("15551234567") == "+15551234567"

    def test_strip_separators(self):
        """Strip visual separators"""
        assert _normalize_to_e164("+1-555-123-4567") == "+15551234567"
        assert _normalize_to_e164("+1.555.123.4567") == "+15551234567"
        assert _normalize_to_e164("+1 555 123 4567") == "+15551234567"

    def test_strip_parens(self):
        """Strip parentheses"""
        assert _normalize_to_e164("+1(555)1234567") == "+15551234567"


# =============================================================================
# Alignment Validation Tests
# =============================================================================


class TestOrigAlignment:
    """Tests for orig.tn / From URI alignment."""

    def test_exact_match_valid(self):
        """Exact match should be valid"""
        valid, evidence = validate_orig_alignment(
            "+15551234567", "sip:+15551234567@gateway.example.com"
        )
        assert valid is True
        assert "orig_aligned" in evidence

    def test_mismatch_invalid(self):
        """Mismatched numbers should be invalid"""
        valid, reason = validate_orig_alignment(
            "+15551234567", "sip:+19995551234@gateway.example.com"
        )
        assert valid is False
        assert "!=" in reason

    def test_normalization_handles_format_diff(self):
        """Different formats should normalize and match"""
        valid, evidence = validate_orig_alignment(
            "+15551234567", "tel:+1-555-123-4567"
        )
        assert valid is True

    def test_invalid_from_uri(self):
        """Invalid From URI should fail"""
        valid, reason = validate_orig_alignment("+15551234567", "invalid")
        assert valid is False
        assert "Could not extract" in reason


class TestDestAlignment:
    """Tests for dest.tn[] / To URI alignment."""

    def test_to_uri_in_array_valid(self):
        """To URI phone in dest.tn array should be valid"""
        valid, evidence = validate_dest_alignment(
            ["+15551234567", "+15559999999"], "sip:+15551234567@gateway.example.com"
        )
        assert valid is True
        assert "dest_aligned" in evidence

    def test_to_uri_not_in_array_invalid(self):
        """To URI phone not in dest.tn array should be invalid"""
        valid, reason = validate_dest_alignment(
            ["+15551234567", "+15559999999"], "sip:+18881111111@gateway.example.com"
        )
        assert valid is False
        assert "not in" in reason

    def test_single_element_array(self):
        """Single element array should work"""
        valid, evidence = validate_dest_alignment(
            ["+15551234567"], "tel:+15551234567"
        )
        assert valid is True

    def test_invalid_to_uri(self):
        """Invalid To URI should fail"""
        valid, reason = validate_dest_alignment(["+15551234567"], "invalid")
        assert valid is False
        assert "Could not extract" in reason


class TestTimingAlignment:
    """Tests for iat / invite_time alignment."""

    def test_within_tolerance_valid(self):
        """iat within tolerance should be valid"""
        now = datetime.now(timezone.utc)
        iat = int(now.timestamp())

        valid, evidence = validate_timing_alignment(iat, now, tolerance_seconds=30)
        assert valid is True
        assert "timing_aligned" in evidence

    def test_exceeds_tolerance_invalid(self):
        """iat outside tolerance should be invalid"""
        now = datetime.now(timezone.utc)
        iat = int((now - timedelta(seconds=60)).timestamp())  # 60 seconds ago

        valid, reason = validate_timing_alignment(iat, now, tolerance_seconds=30)
        assert valid is False
        assert "exceeds" in reason

    def test_exact_match(self):
        """Exact timestamp match should be valid"""
        now = datetime.now(timezone.utc)
        iat = int(now.timestamp())

        valid, evidence = validate_timing_alignment(iat, now, tolerance_seconds=0)
        assert valid is True

    def test_custom_tolerance(self):
        """Custom tolerance should be respected"""
        now = datetime.now(timezone.utc)
        iat = int((now - timedelta(seconds=45)).timestamp())

        # Should fail with 30s tolerance
        valid1, _ = validate_timing_alignment(iat, now, tolerance_seconds=30)
        assert valid1 is False

        # Should pass with 60s tolerance
        valid2, _ = validate_timing_alignment(iat, now, tolerance_seconds=60)
        assert valid2 is True


# =============================================================================
# Integration Tests
# =============================================================================


class TestContextAlignmentIntegration:
    """Integration tests for full context alignment."""

    def test_sip_context_absent_indeterminate(self):
        """Missing SIP context should result in INDETERMINATE"""
        passport = MockPassport(
            payload=MockPassportPayload(
                iat=int(datetime.now(timezone.utc).timestamp()),
                orig={"tn": ["+15551234567"]},
                dest={"tn": ["+15559999999"]},
            )
        )

        claim = verify_sip_context_alignment(passport, None)

        assert claim.status == ClaimStatus.INDETERMINATE
        assert "SIP context not provided" in claim.reasons[0]
        assert "sip_context:absent" in claim.evidence

    def test_all_fields_align_valid(self):
        """All fields aligned should result in VALID"""
        now = datetime.now(timezone.utc)
        passport = MockPassport(
            payload=MockPassportPayload(
                iat=int(now.timestamp()),
                orig={"tn": ["+15551234567"]},
                dest={"tn": ["+15559999999"]},
            )
        )
        sip = SipContext(
            from_uri="sip:+15551234567@gateway.example.com",
            to_uri="sip:+15559999999@gateway.example.com",
            invite_time=now.isoformat(),
        )

        claim = verify_sip_context_alignment(passport, sip)

        assert claim.status == ClaimStatus.VALID
        assert len(claim.reasons) == 0
        assert "orig_aligned" in str(claim.evidence)
        assert "dest_aligned" in str(claim.evidence)
        assert "timing_aligned" in str(claim.evidence)

    def test_orig_mismatch_invalid(self):
        """orig mismatch should result in INVALID"""
        now = datetime.now(timezone.utc)
        passport = MockPassport(
            payload=MockPassportPayload(
                iat=int(now.timestamp()),
                orig={"tn": ["+15551234567"]},
                dest={"tn": ["+15559999999"]},
            )
        )
        sip = SipContext(
            from_uri="sip:+18881111111@gateway.example.com",  # Different number
            to_uri="sip:+15559999999@gateway.example.com",
            invite_time=now.isoformat(),
        )

        claim = verify_sip_context_alignment(passport, sip)

        assert claim.status == ClaimStatus.INVALID
        assert "orig.tn" in claim.reasons[0] or "!=" in claim.reasons[0]

    def test_dest_mismatch_invalid(self):
        """dest mismatch should result in INVALID"""
        now = datetime.now(timezone.utc)
        passport = MockPassport(
            payload=MockPassportPayload(
                iat=int(now.timestamp()),
                orig={"tn": ["+15551234567"]},
                dest={"tn": ["+15559999999"]},
            )
        )
        sip = SipContext(
            from_uri="sip:+15551234567@gateway.example.com",
            to_uri="sip:+18881111111@gateway.example.com",  # Not in dest.tn
            invite_time=now.isoformat(),
        )

        claim = verify_sip_context_alignment(passport, sip)

        assert claim.status == ClaimStatus.INVALID
        assert "not in" in claim.reasons[0]

    def test_timing_mismatch_invalid(self):
        """Timing outside tolerance should result in INVALID"""
        now = datetime.now(timezone.utc)
        old_time = now - timedelta(seconds=120)  # 2 minutes ago

        passport = MockPassport(
            payload=MockPassportPayload(
                iat=int(old_time.timestamp()),  # Old iat
                orig={"tn": ["+15551234567"]},
                dest={"tn": ["+15559999999"]},
            )
        )
        sip = SipContext(
            from_uri="sip:+15551234567@gateway.example.com",
            to_uri="sip:+15559999999@gateway.example.com",
            invite_time=now.isoformat(),  # Current time
        )

        claim = verify_sip_context_alignment(passport, sip, timing_tolerance=30)

        assert claim.status == ClaimStatus.INVALID
        assert "exceeds" in claim.reasons[0]

    def test_missing_orig_tn(self):
        """Missing orig.tn should result in INVALID"""
        now = datetime.now(timezone.utc)
        passport = MockPassport(
            payload=MockPassportPayload(
                iat=int(now.timestamp()),
                orig={},  # Missing tn
                dest={"tn": ["+15559999999"]},
            )
        )
        sip = SipContext(
            from_uri="sip:+15551234567@gateway.example.com",
            to_uri="sip:+15559999999@gateway.example.com",
            invite_time=now.isoformat(),
        )

        claim = verify_sip_context_alignment(passport, sip)

        assert claim.status == ClaimStatus.INVALID
        assert "missing orig.tn" in claim.reasons[0]

    def test_missing_dest_tn(self):
        """Missing dest.tn should result in INVALID"""
        now = datetime.now(timezone.utc)
        passport = MockPassport(
            payload=MockPassportPayload(
                iat=int(now.timestamp()),
                orig={"tn": ["+15551234567"]},
                dest={},  # Missing tn
            )
        )
        sip = SipContext(
            from_uri="sip:+15551234567@gateway.example.com",
            to_uri="sip:+15559999999@gateway.example.com",
            invite_time=now.isoformat(),
        )

        claim = verify_sip_context_alignment(passport, sip)

        assert claim.status == ClaimStatus.INVALID
        assert "missing dest.tn" in claim.reasons[0]

    def test_invalid_invite_time_format(self):
        """Invalid invite_time format should result in INDETERMINATE"""
        now = datetime.now(timezone.utc)
        passport = MockPassport(
            payload=MockPassportPayload(
                iat=int(now.timestamp()),
                orig={"tn": ["+15551234567"]},
                dest={"tn": ["+15559999999"]},
            )
        )
        sip = SipContext(
            from_uri="sip:+15551234567@gateway.example.com",
            to_uri="sip:+15559999999@gateway.example.com",
            invite_time="not-a-valid-timestamp",
        )

        claim = verify_sip_context_alignment(passport, sip)

        assert claim.status == ClaimStatus.INDETERMINATE
        assert "Could not parse" in claim.reasons[0]

    def test_z_suffix_timestamp(self):
        """RFC3339 timestamp with Z suffix should parse correctly"""
        now = datetime.now(timezone.utc)
        passport = MockPassport(
            payload=MockPassportPayload(
                iat=int(now.timestamp()),
                orig={"tn": ["+15551234567"]},
                dest={"tn": ["+15559999999"]},
            )
        )
        sip = SipContext(
            from_uri="sip:+15551234567@gateway.example.com",
            to_uri="sip:+15559999999@gateway.example.com",
            invite_time=now.strftime("%Y-%m-%dT%H:%M:%SZ"),  # Z suffix
        )

        claim = verify_sip_context_alignment(passport, sip)

        # Should successfully parse and validate
        assert claim.status == ClaimStatus.VALID or "timing" in str(claim.evidence)
