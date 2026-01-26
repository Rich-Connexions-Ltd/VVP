"""Tests for brand credential verification (Phase 11).

Tests cover:
- vCard format validation
- Brand credential location
- Brand attribute verification
- Brand JL (join link) to vetting
- Brand proxy in delegation scenarios
"""

import pytest
from dataclasses import dataclass
from typing import Optional, Dict, Any, List

from app.vvp.brand import (
    validate_vcard_format,
    find_brand_credential,
    verify_brand_attributes,
    verify_brand_jl,
    verify_brand_proxy,
    verify_brand,
    VCARD_FIELDS,
    ClaimBuilder,
)
from app.vvp.api_models import ClaimStatus


# =============================================================================
# Mock ACDC and Passport for testing
# =============================================================================


@dataclass
class MockACDC:
    """Mock ACDC credential for testing."""

    said: str
    issuer_aid: str
    attributes: Optional[Dict[str, Any]] = None
    edges: Optional[Dict[str, Any]] = None
    raw: Optional[Dict[str, Any]] = None

    def __post_init__(self):
        if self.raw is None:
            self.raw = {}
        if self.attributes is not None:
            self.raw["a"] = self.attributes
        if self.edges is not None:
            self.raw["e"] = self.edges


@dataclass
class MockPassportPayload:
    """Mock PASSporT payload for testing."""

    card: Optional[Dict[str, Any]] = None


@dataclass
class MockPassport:
    """Mock PASSporT for testing."""

    payload: MockPassportPayload


# =============================================================================
# vCard Format Validation Tests
# =============================================================================


class TestVCardValidation:
    """Tests for vCard format validation."""

    def test_valid_vcard_fields(self):
        """Known vCard fields should not produce warnings"""
        card = {"fn": "ACME Corp", "org": "ACME", "tel": "+15551234567"}
        warnings = validate_vcard_format(card)
        assert len(warnings) == 0

    def test_unknown_fields_warn(self):
        """Unknown fields should produce warnings but not fail"""
        card = {"fn": "ACME Corp", "customField": "value", "anotherCustom": "123"}
        warnings = validate_vcard_format(card)
        assert len(warnings) == 2
        assert "customField" in warnings[0]
        assert "anotherCustom" in warnings[1]

    def test_case_insensitive_fields(self):
        """vCard fields should be case-insensitive"""
        card = {"FN": "ACME Corp", "ORG": "ACME"}
        warnings = validate_vcard_format(card)
        assert len(warnings) == 0

    def test_empty_card(self):
        """Empty card should produce no warnings"""
        warnings = validate_vcard_format({})
        assert len(warnings) == 0


# =============================================================================
# Brand Credential Location Tests
# =============================================================================


class TestFindBrandCredential:
    """Tests for locating brand credential in dossier."""

    def test_find_brand_credential(self):
        """Should find credential with brand indicators"""
        dossier = {
            "ABC123": MockACDC(
                said="ABC123",
                issuer_aid="ISSUER1",
                attributes={"fn": "ACME Corp", "org": "ACME", "logo": "https://example.com/logo.png"},
            ),
            "XYZ789": MockACDC(
                said="XYZ789",
                issuer_aid="ISSUER2",
                attributes={"tn": "+15551234567"},  # Not a brand credential
            ),
        }

        result = find_brand_credential(dossier)
        assert result is not None
        assert result.said == "ABC123"

    def test_no_brand_credential(self):
        """Should return None when no brand credential found"""
        dossier = {
            "XYZ789": MockACDC(
                said="XYZ789",
                issuer_aid="ISSUER1",
                attributes={"tn": "+15551234567"},  # Not a brand credential
            ),
        }

        result = find_brand_credential(dossier)
        assert result is None

    def test_multiple_brand_credentials(self):
        """Should return first brand credential found"""
        dossier = {
            "ABC123": MockACDC(
                said="ABC123",
                issuer_aid="ISSUER1",
                attributes={"fn": "ACME Corp", "org": "ACME"},
            ),
            "DEF456": MockACDC(
                said="DEF456",
                issuer_aid="ISSUER2",
                attributes={"fn": "Other Corp", "logo": "https://other.com/logo.png"},
            ),
        }

        result = find_brand_credential(dossier)
        assert result is not None
        # Should find one of them
        assert result.said in ["ABC123", "DEF456"]


# =============================================================================
# Brand Attribute Verification Tests
# =============================================================================


class TestBrandAttributeVerification:
    """Tests for brand attribute justification."""

    def test_attributes_match_credential(self):
        """Card values matching credential should pass"""
        card = {"fn": "ACME Corp", "org": "ACME"}
        brand = MockACDC(
            said="ABC123",
            issuer_aid="ISSUER1",
            attributes={"fn": "ACME Corp", "org": "ACME", "extra": "value"},
        )

        valid, result = verify_brand_attributes(card, brand)
        assert valid is True
        assert "fn" in str(result)

    def test_attribute_mismatch_invalid(self):
        """Card values not matching credential should fail"""
        card = {"fn": "ACME Corp", "org": "Different Org"}
        brand = MockACDC(
            said="ABC123",
            issuer_aid="ISSUER1",
            attributes={"fn": "ACME Corp", "org": "ACME"},
        )

        valid, result = verify_brand_attributes(card, brand)
        assert valid is False
        assert any("org" in r for r in result)

    def test_extra_card_attributes_invalid(self):
        """Card attributes not in credential should fail"""
        card = {"fn": "ACME Corp", "email": "contact@acme.com"}
        brand = MockACDC(
            said="ABC123",
            issuer_aid="ISSUER1",
            attributes={"fn": "ACME Corp"},  # Missing email
        )

        valid, result = verify_brand_attributes(card, brand)
        assert valid is False
        assert any("email" in r for r in result)


# =============================================================================
# Brand JL (Join Link) Tests
# =============================================================================


class TestBrandJL:
    """Tests for brand credential join link to vetting."""

    def test_jl_to_vetting_valid(self):
        """Brand with JL to vetting credential should pass"""
        brand = MockACDC(
            said="ABC123",
            issuer_aid="ISSUER1",
            attributes={"fn": "ACME Corp"},
            edges={"jl": "VETTING123"},
        )
        dossier = {
            "ABC123": brand,
            "VETTING123": MockACDC(said="VETTING123", issuer_aid="VETTER"),
        }

        valid, evidence = verify_brand_jl(brand, dossier)
        assert valid is True
        assert "jl_valid" in evidence

    def test_missing_jl_invalid(self):
        """Brand without JL edge should fail"""
        brand = MockACDC(
            said="ABC123",
            issuer_aid="ISSUER1",
            attributes={"fn": "ACME Corp"},
            edges={},  # No JL
        )

        valid, reason = verify_brand_jl(brand, {})
        assert valid is False
        assert "no edges" in reason or "missing JL" in reason

    def test_jl_external_reference(self):
        """JL to external (not in dossier) should still pass"""
        brand = MockACDC(
            said="ABC123",
            issuer_aid="ISSUER1",
            attributes={"fn": "ACME Corp"},
            edges={"vetting": "EXTERNAL123"},
        )

        valid, evidence = verify_brand_jl(brand, {"ABC123": brand})
        assert valid is True
        assert "external" in evidence


# =============================================================================
# Brand Proxy in Delegation Tests
# =============================================================================


class TestBrandProxyDelegation:
    """Tests for brand proxy in delegation scenarios."""

    def test_no_delegation_no_proxy_needed(self):
        """Without delegation, proxy is not required"""
        brand = MockACDC(said="BRAND123", issuer_aid="ISSUER1")

        valid, evidence = verify_brand_proxy(None, brand, {})
        assert valid is True
        assert "no_delegation" in evidence

    def test_delegation_with_brand_proxy_valid(self):
        """DE with brand proxy edge should pass"""
        brand = MockACDC(said="BRAND123", issuer_aid="ISSUER1")
        de = MockACDC(
            said="DE123",
            issuer_aid="ISSUER1",
            edges={"brand": "BRAND123"},
        )

        valid, evidence = verify_brand_proxy(de, brand, {})
        assert valid is True
        assert "brand_proxy" in evidence

    def test_delegation_missing_brand_proxy_indeterminate(self):
        """DE without brand proxy should result in failure"""
        brand = MockACDC(said="BRAND123", issuer_aid="ISSUER1")
        de = MockACDC(
            said="DE123",
            issuer_aid="ISSUER1",
            edges={"auth": "OTHER123"},  # No brand proxy
        )

        valid, reason = verify_brand_proxy(de, brand, {})
        assert valid is False
        assert "missing brand proxy" in reason


# =============================================================================
# Integration Tests
# =============================================================================


class TestBrandVerificationIntegration:
    """Integration tests for full brand verification."""

    def test_no_card_no_claim(self):
        """No card in passport should return None"""
        passport = MockPassport(payload=MockPassportPayload(card=None))

        result = verify_brand(passport, {})
        assert result is None

    def test_brand_valid(self):
        """Valid brand verification should pass"""
        passport = MockPassport(
            payload=MockPassportPayload(card={"fn": "ACME Corp", "org": "ACME"})
        )
        brand = MockACDC(
            said="BRAND123",
            issuer_aid="ISSUER1",
            attributes={"fn": "ACME Corp", "org": "ACME", "url": "https://acme.com"},
            edges={"jl": "VETTING123"},
        )
        dossier = {
            "BRAND123": brand,
            "VETTING123": MockACDC(said="VETTING123", issuer_aid="VETTER"),
        }

        result = verify_brand(passport, dossier)
        assert result is not None
        assert result.status == ClaimStatus.VALID

    def test_no_brand_credential_invalid(self):
        """Missing brand credential should be INVALID"""
        passport = MockPassport(
            payload=MockPassportPayload(card={"fn": "ACME Corp"})
        )

        result = verify_brand(passport, {})
        assert result is not None
        assert result.status == ClaimStatus.INVALID
        assert "No brand credential" in result.reasons[0]

    def test_brand_missing_jl_invalid(self):
        """Brand without JL to vetting should be INVALID"""
        passport = MockPassport(
            payload=MockPassportPayload(card={"fn": "ACME Corp", "org": "ACME"})
        )
        brand = MockACDC(
            said="BRAND123",
            issuer_aid="ISSUER1",
            attributes={"fn": "ACME Corp", "org": "ACME"},
            edges={},  # No JL
        )

        result = verify_brand(passport, {"BRAND123": brand})
        assert result is not None
        assert result.status == ClaimStatus.INVALID
        assert "no edges" in result.reasons[0] or "missing JL" in result.reasons[0]

    def test_brand_proxy_missing_indeterminate(self):
        """Missing brand proxy in delegation should be INDETERMINATE"""
        passport = MockPassport(
            payload=MockPassportPayload(card={"fn": "ACME Corp", "org": "ACME"})
        )
        brand = MockACDC(
            said="BRAND123",
            issuer_aid="ISSUER1",
            attributes={"fn": "ACME Corp", "org": "ACME"},
            edges={"jl": "VETTING123"},
        )
        de = MockACDC(
            said="DE123",
            issuer_aid="ISSUER1",
            edges={"auth": "OTHER123"},  # No brand proxy
        )
        dossier = {
            "BRAND123": brand,
            "VETTING123": MockACDC(said="VETTING123", issuer_aid="VETTER"),
        }

        result = verify_brand(passport, dossier, de_credential=de)
        assert result is not None
        assert result.status == ClaimStatus.INDETERMINATE
        assert "missing brand proxy" in result.reasons[0]

    def test_unknown_vcard_fields_warn_not_fail(self):
        """Unknown vCard fields should warn but not fail"""
        passport = MockPassport(
            payload=MockPassportPayload(
                card={"fn": "ACME Corp", "org": "ACME", "customField": "value"}
            )
        )
        brand = MockACDC(
            said="BRAND123",
            issuer_aid="ISSUER1",
            attributes={"fn": "ACME Corp", "org": "ACME", "customField": "value"},
            edges={"jl": "VETTING123"},
        )
        dossier = {
            "BRAND123": brand,
            "VETTING123": MockACDC(said="VETTING123", issuer_aid="VETTER"),
        }

        result = verify_brand(passport, dossier)
        assert result is not None
        # Should still pass, but with warning in evidence
        assert result.status == ClaimStatus.VALID
        assert any("warning" in ev for ev in result.evidence)
