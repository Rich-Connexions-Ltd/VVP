"""Tests for brand credential verification (Phase 11).

Tests cover:
- vCard format validation
- Brand credential location
- Brand attribute verification
- Brand JL (join link) to vetting
- Brand proxy in delegation scenarios
- Sprint 44: Brand info extraction (brand_name, brand_logo_url)
- Sprint 58: vCard array format (RFC 6350 property strings)
"""

import pytest
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List

from app.vvp.brand import (
    validate_vcard_format,
    find_brand_credential,
    verify_brand_attributes,
    verify_brand_jl,
    verify_brand_proxy,
    verify_brand,
    extract_brand_info,
    parse_vcard_properties,
    BrandInfo,
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

    card: Optional[List[str]] = None


@dataclass
class MockPassport:
    """Mock PASSporT for testing."""

    payload: MockPassportPayload


# =============================================================================
# vCard Property String Parsing Tests
# =============================================================================


class TestParseVCardProperties:
    """Tests for parse_vcard_properties helper."""

    def test_basic_properties(self):
        """Parses simple NAME:value properties."""
        card = ["ORG:ACME Corp", "NICKNAME:ACME"]
        props = parse_vcard_properties(card)
        assert props == {"org": "ACME Corp", "nickname": "ACME"}

    def test_logo_with_params(self):
        """Strips ;VALUE=URI parameter from LOGO property."""
        card = ["LOGO;VALUE=URI:https://cdn.acme.com/logo.png"]
        props = parse_vcard_properties(card)
        assert props == {"logo": "https://cdn.acme.com/logo.png"}

    def test_url_with_colon_in_value(self):
        """Handles colons in values (URLs)."""
        card = ["URL:https://www.acme.com"]
        props = parse_vcard_properties(card)
        assert props == {"url": "https://www.acme.com"}

    def test_empty_list(self):
        """Empty list returns empty dict."""
        assert parse_vcard_properties([]) == {}

    def test_skips_invalid_entries(self):
        """Skips non-string and no-colon entries."""
        card = ["ORG:ACME", 42, "", "nocolon", "URL:https://example.com"]
        props = parse_vcard_properties(card)
        assert props == {"org": "ACME", "url": "https://example.com"}

    def test_case_insensitive_keys(self):
        """Property names are lowercased."""
        card = ["ORG:ACME", "Nickname:Display", "url:https://example.com"]
        props = parse_vcard_properties(card)
        assert "org" in props
        assert "nickname" in props
        assert "url" in props


# =============================================================================
# vCard Format Validation Tests
# =============================================================================


class TestVCardValidation:
    """Tests for vCard format validation."""

    def test_valid_vcard_fields(self):
        """Known vCard fields should not produce warnings"""
        card = ["FN:ACME Corp", "ORG:ACME", "TEL:+15551234567"]
        warnings = validate_vcard_format(card)
        assert len(warnings) == 0

    def test_unknown_fields_warn(self):
        """Unknown fields should produce warnings but not fail"""
        card = ["FN:ACME Corp", "CUSTOMFIELD:value", "ANOTHERCUSTOM:123"]
        warnings = validate_vcard_format(card)
        assert len(warnings) == 2
        assert "customfield" in warnings[0]
        assert "anothercustom" in warnings[1]

    def test_case_insensitive_fields(self):
        """vCard fields should be case-insensitive"""
        card = ["FN:ACME Corp", "ORG:ACME"]
        warnings = validate_vcard_format(card)
        assert len(warnings) == 0

    def test_empty_card(self):
        """Empty card should produce no warnings"""
        warnings = validate_vcard_format([])
        assert len(warnings) == 0

    def test_nickname_is_valid(self):
        """NICKNAME is a known vCard field."""
        card = ["NICKNAME:ACME Corp"]
        warnings = validate_vcard_format(card)
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
        card = ["FN:ACME Corp", "ORG:ACME"]
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
        card = ["FN:ACME Corp", "ORG:Different Org"]
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
        card = ["FN:ACME Corp", "EMAIL:contact@acme.com"]
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
    """Integration tests for full brand verification.

    Sprint 44: verify_brand now returns (claim, brand_info) tuple.
    Sprint 58: card is a list of vCard property strings.
    """

    def test_no_card_no_claim(self):
        """No card in passport should return (None, None)"""
        passport = MockPassport(payload=MockPassportPayload(card=None))

        claim, brand_info = verify_brand(passport, {})
        assert claim is None
        assert brand_info is None

    def test_brand_valid(self):
        """Valid brand verification should pass"""
        passport = MockPassport(
            payload=MockPassportPayload(card=["FN:ACME Corp", "ORG:ACME"])
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

        claim, brand_info = verify_brand(passport, dossier)
        assert claim is not None
        assert claim.status == ClaimStatus.VALID
        # Sprint 44: Also verify brand info extraction
        assert brand_info is not None
        assert brand_info.brand_name == "ACME"  # org takes precedence over fn

    def test_no_brand_credential_invalid(self):
        """Missing brand credential should be INVALID"""
        passport = MockPassport(
            payload=MockPassportPayload(card=["FN:ACME Corp"])
        )

        claim, brand_info = verify_brand(passport, {})
        assert claim is not None
        assert claim.status == ClaimStatus.INVALID
        assert "No brand credential" in claim.reasons[0]
        # Sprint 44: Brand info still extracted even if verification fails
        assert brand_info is not None
        assert brand_info.brand_name == "ACME Corp"

    def test_brand_missing_jl_invalid(self):
        """Brand without JL to vetting should be INVALID"""
        passport = MockPassport(
            payload=MockPassportPayload(card=["FN:ACME Corp", "ORG:ACME"])
        )
        brand = MockACDC(
            said="BRAND123",
            issuer_aid="ISSUER1",
            attributes={"fn": "ACME Corp", "org": "ACME"},
            edges={},  # No JL
        )

        claim, brand_info = verify_brand(passport, {"BRAND123": brand})
        assert claim is not None
        assert claim.status == ClaimStatus.INVALID
        assert "no edges" in claim.reasons[0] or "missing JL" in claim.reasons[0]

    def test_brand_proxy_missing_indeterminate(self):
        """Missing brand proxy in delegation should be INDETERMINATE"""
        passport = MockPassport(
            payload=MockPassportPayload(card=["FN:ACME Corp", "ORG:ACME"])
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

        claim, brand_info = verify_brand(passport, dossier, de_credential=de)
        assert claim is not None
        assert claim.status == ClaimStatus.INDETERMINATE
        assert "missing brand proxy" in claim.reasons[0]

    def test_unknown_vcard_fields_warn_not_fail(self):
        """Unknown vCard fields should warn but not fail"""
        passport = MockPassport(
            payload=MockPassportPayload(
                card=["FN:ACME Corp", "ORG:ACME", "CUSTOMFIELD:value"]
            )
        )
        brand = MockACDC(
            said="BRAND123",
            issuer_aid="ISSUER1",
            attributes={"fn": "ACME Corp", "org": "ACME", "customfield": "value"},
            edges={"jl": "VETTING123"},
        )
        dossier = {
            "BRAND123": brand,
            "VETTING123": MockACDC(said="VETTING123", issuer_aid="VETTER"),
        }

        claim, brand_info = verify_brand(passport, dossier)
        assert claim is not None
        # Should still pass, but with warning in evidence
        assert claim.status == ClaimStatus.VALID
        assert any("warning" in ev for ev in claim.evidence)


# =============================================================================
# Sprint 44/58: Brand Info Extraction Tests
# =============================================================================


class TestExtractBrandInfo:
    """Tests for extract_brand_info function (Sprint 44/58).

    Card is now a list of vCard property strings per VVP §4.1.2.
    """

    def test_extract_org_as_brand_name(self):
        """ORG property should be used as brand_name"""
        card = ["FN:John Doe", "ORG:ACME Corporation"]
        info = extract_brand_info(card)
        assert info.brand_name == "ACME Corporation"

    def test_extract_nickname_when_no_org(self):
        """NICKNAME property should be fallback when ORG not present"""
        card = ["NICKNAME:ACME Display Name"]
        info = extract_brand_info(card)
        assert info.brand_name == "ACME Display Name"

    def test_extract_fn_when_no_org_or_nickname(self):
        """FN property should be fallback when ORG and NICKNAME not present"""
        card = ["FN:ACME Full Name"]
        info = extract_brand_info(card)
        assert info.brand_name == "ACME Full Name"

    def test_extract_logo_url_from_property(self):
        """LOGO;VALUE=URI: property should have URL extracted"""
        card = ["ORG:ACME", "LOGO;VALUE=URI:https://cdn.acme.com/logo.png"]
        info = extract_brand_info(card)
        assert info.brand_logo_url == "https://cdn.acme.com/logo.png"

    def test_extract_empty_card(self):
        """Empty card should return empty BrandInfo"""
        card = []
        info = extract_brand_info(card)
        assert info.brand_name is None
        assert info.brand_logo_url is None

    def test_non_url_logo_ignored(self):
        """Non-URL logo values should be ignored"""
        card = ["ORG:ACME", "LOGO:base64,iVBORw0KGgo..."]
        info = extract_brand_info(card)
        assert info.brand_logo_url is None

    def test_http_logo_url(self):
        """HTTP URLs should be extracted (not just HTTPS)"""
        card = ["ORG:ACME", "LOGO;VALUE=URI:http://cdn.acme.com/logo.png"]
        info = extract_brand_info(card)
        assert info.brand_logo_url == "http://cdn.acme.com/logo.png"


# =============================================================================
# Sprint 58: Extended Brand Credential Compatibility Tests
# =============================================================================


class TestExtendedBrandCredentialFinder:
    """Tests for find_brand_credential with Extended Brand Credential field names."""

    def test_find_extended_brand_credential(self):
        """Should find credential with Extended Brand Credential attributes."""
        dossier = {
            "BRAND1": MockACDC(
                said="BRAND1",
                issuer_aid="VETTER1",
                attributes={
                    "brandName": "ACME Corporation",
                    "brandDisplayName": "ACME",
                    "logoUrl": "https://cdn.acme.com/logo.png",
                    "websiteUrl": "https://www.acme.com",
                    "assertionCountry": "USA",
                },
            ),
            "LE1": MockACDC(
                said="LE1",
                issuer_aid="ISSUER1",
                attributes={"entityName": "ACME Inc", "LEI": "1234567890"},
            ),
        }

        result = find_brand_credential(dossier)
        assert result is not None
        assert result.said == "BRAND1"

    def test_mixed_vcard_and_credential_fields(self):
        """Should find credential with mix of vCard and credential field names."""
        dossier = {
            "BRAND1": MockACDC(
                said="BRAND1",
                issuer_aid="VETTER1",
                attributes={"brandName": "Test", "logoUrl": "https://example.com/logo.png"},
            ),
        }

        result = find_brand_credential(dossier)
        assert result is not None

    def test_find_minimal_brand_name_only(self):
        """Should find credential with only brandName (schema-required field)."""
        dossier = {
            "BRAND1": MockACDC(
                said="BRAND1",
                issuer_aid="VETTER1",
                attributes={"brandName": "Minimal Corp", "assertionCountry": "USA"},
            ),
        }

        result = find_brand_credential(dossier)
        assert result is not None
        assert result.said == "BRAND1"


class TestVCardToCredentialMapping:
    """Tests for vCard-to-credential field name mapping in verify_brand_attributes.

    Sprint 58: card is now a list of vCard property strings.
    """

    def test_vcard_org_matches_brand_name(self):
        """card ORG: should match credential brandName."""
        card = ["ORG:ACME Corporation"]
        brand = MockACDC(
            said="BRAND1",
            issuer_aid="VETTER1",
            attributes={"brandName": "ACME Corporation", "assertionCountry": "USA"},
        )

        valid, result = verify_brand_attributes(card, brand)
        assert valid is True
        assert any("org" in r for r in result)

    def test_vcard_nickname_matches_brand_display_name(self):
        """card NICKNAME: should match credential brandDisplayName."""
        card = ["NICKNAME:ACME Corp"]
        brand = MockACDC(
            said="BRAND1",
            issuer_aid="VETTER1",
            attributes={"brandName": "ACME Corporation", "brandDisplayName": "ACME Corp"},
        )

        valid, result = verify_brand_attributes(card, brand)
        assert valid is True

    def test_vcard_nickname_falls_back_to_brand_name(self):
        """card NICKNAME: should match credential brandName when brandDisplayName absent."""
        card = ["NICKNAME:ACME Corporation"]
        brand = MockACDC(
            said="BRAND1",
            issuer_aid="VETTER1",
            attributes={"brandName": "ACME Corporation"},
        )

        valid, result = verify_brand_attributes(card, brand)
        assert valid is True

    def test_vcard_logo_matches_logo_url(self):
        """card LOGO: should match credential logoUrl."""
        card = ["LOGO;VALUE=URI:https://cdn.acme.com/logo.png"]
        brand = MockACDC(
            said="BRAND1",
            issuer_aid="VETTER1",
            attributes={"logoUrl": "https://cdn.acme.com/logo.png"},
        )

        valid, result = verify_brand_attributes(card, brand)
        assert valid is True

    def test_vcard_url_matches_website_url(self):
        """card URL: should match credential websiteUrl."""
        card = ["URL:https://www.acme.com"]
        brand = MockACDC(
            said="BRAND1",
            issuer_aid="VETTER1",
            attributes={"websiteUrl": "https://www.acme.com"},
        )

        valid, result = verify_brand_attributes(card, brand)
        assert valid is True

    def test_full_card_matches_extended_brand_credential(self):
        """Full vCard card claim should validate against Extended Brand Credential."""
        card = [
            "ORG:ACME Corporation",
            "NICKNAME:ACME Corp",
            "LOGO;VALUE=URI:https://cdn.acme.com/logo.png",
            "URL:https://www.acme.com",
        ]
        brand = MockACDC(
            said="BRAND1",
            issuer_aid="VETTER1",
            attributes={
                "brandName": "ACME Corporation",
                "brandDisplayName": "ACME Corp",
                "logoUrl": "https://cdn.acme.com/logo.png",
                "websiteUrl": "https://www.acme.com",
                "assertionCountry": "USA",
            },
        )

        valid, result = verify_brand_attributes(card, brand)
        assert valid is True
        assert len(result) == 4  # All 4 fields matched

    def test_value_mismatch_fails(self):
        """Mismatched values should fail even with correct field mapping."""
        card = ["ORG:Wrong Name"]
        brand = MockACDC(
            said="BRAND1",
            issuer_aid="VETTER1",
            attributes={"brandName": "ACME Corporation"},
        )

        valid, result = verify_brand_attributes(card, brand)
        assert valid is False
        assert any("org" in r for r in result)


# =============================================================================
# Sprint 44: Additional Edge Case Tests for Coverage
# =============================================================================


class TestFindBrandCredentialEdgeCases:
    """Edge case tests for find_brand_credential function."""

    def test_find_credential_via_raw_dict(self):
        """Should find brand credential via raw dict when attributes is None."""

        @dataclass
        class RawOnlyACDC:
            said: str
            issuer_aid: str
            attributes: Any = None  # No attributes property
            raw: Dict[str, Any] = None

            def __post_init__(self):
                if self.raw is None:
                    self.raw = {}

        dossier = {
            "ABC123": RawOnlyACDC(
                said="ABC123",
                issuer_aid="ISSUER1",
                raw={"a": {"fn": "ACME Corp", "org": "ACME", "logo": "https://acme.com"}},
            ),
        }

        result = find_brand_credential(dossier)
        assert result is not None
        assert result.said == "ABC123"

    def test_skip_non_dict_attrs(self):
        """Should skip credentials where attrs is not a dict."""

        @dataclass
        class BadAttrsACDC:
            said: str
            issuer_aid: str
            attributes: Any = None
            raw: Dict[str, Any] = None

        dossier = {
            "BAD123": BadAttrsACDC(
                said="BAD123",
                issuer_aid="ISSUER1",
                attributes="not-a-dict",  # Invalid type
            ),
            "GOOD456": MockACDC(
                said="GOOD456",
                issuer_aid="ISSUER2",
                attributes={"fn": "ACME Corp", "org": "ACME"},
            ),
        }

        result = find_brand_credential(dossier)
        # Should skip BAD123 and find GOOD456
        assert result is not None
        assert result.said == "GOOD456"


class TestVerifyBrandAttributesEdgeCases:
    """Edge case tests for verify_brand_attributes function."""

    def test_verify_via_raw_dict(self):
        """Should verify attributes via raw dict when attributes is None."""

        @dataclass
        class RawOnlyBrand:
            said: str
            issuer_aid: str
            attributes: Any = None
            raw: Dict[str, Any] = None

        brand = RawOnlyBrand(
            said="BRAND123",
            issuer_aid="ISSUER1",
            raw={"a": {"fn": "ACME Corp", "org": "ACME"}},
        )
        card = ["FN:ACME Corp", "ORG:ACME"]

        valid, result = verify_brand_attributes(card, brand)
        assert valid is True

    def test_non_dict_attrs_returns_invalid(self):
        """Should return invalid when credential attrs is not a dict."""

        @dataclass
        class BadAttrsBrand:
            said: str
            issuer_aid: str
            attributes: Any = None
            raw: Dict[str, Any] = None

        brand = BadAttrsBrand(
            said="BRAND123",
            issuer_aid="ISSUER1",
            raw={"a": "not-a-dict"},
        )
        card = ["FN:ACME Corp"]

        valid, result = verify_brand_attributes(card, brand)
        assert valid is False
        assert "no attributes" in result[0]
