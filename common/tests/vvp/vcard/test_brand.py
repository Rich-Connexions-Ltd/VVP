"""Tests for brand projection from vCard and scalar attributes."""

import pytest

from common.vvp.vcard.brand import (
    NormalizedBrand,
    extract_brand_from_scalars,
    extract_brand_from_vcard,
    normalize_brand,
)


class TestExtractBrandFromVCard:
    def test_full_vcard(self):
        lines = [
            "ORG:ACME Corporation",
            "NICKNAME:ACME Corp",
            "LOGO;HASH=EK2r6EnDXre1234567890123456789012345678901;VALUE=URI:https://cdn.acme.com/logo.png",
            "URL:https://www.acme.com",
            "TEL;VALUE=URI:tel:+441923311000",
        ]
        brand = extract_brand_from_vcard(lines)
        assert brand.name == "ACME Corporation"
        assert brand.display_name == "ACME Corp"
        assert brand.logo_url == "https://cdn.acme.com/logo.png"
        assert brand.logo_hash == "EK2r6EnDXre1234567890123456789012345678901"
        assert brand.website_url == "https://www.acme.com"

    def test_minimal_vcard(self):
        lines = ["ORG:Simple Brand"]
        brand = extract_brand_from_vcard(lines)
        assert brand.name == "Simple Brand"
        assert brand.display_name is None
        assert brand.logo_url is None
        assert brand.logo_hash is None
        assert brand.website_url is None

    def test_logo_without_hash(self):
        lines = [
            "ORG:ACME",
            "LOGO;VALUE=URI:https://cdn.acme.com/logo.png",
        ]
        brand = extract_brand_from_vcard(lines)
        assert brand.logo_url == "https://cdn.acme.com/logo.png"
        assert brand.logo_hash is None

    def test_logo_without_value_uri_param(self):
        lines = [
            "ORG:ACME",
            "LOGO:https://cdn.acme.com/logo.png",
        ]
        brand = extract_brand_from_vcard(lines)
        assert brand.logo_url == "https://cdn.acme.com/logo.png"


class TestExtractBrandFromScalars:
    def test_full_scalars(self):
        attrs = {
            "brandName": "ACME Corporation",
            "brandDisplayName": "ACME Corp",
            "logoUrl": "https://cdn.acme.com/logo.png",
            "websiteUrl": "https://www.acme.com",
        }
        brand = extract_brand_from_scalars(attrs)
        assert brand.name == "ACME Corporation"
        assert brand.display_name == "ACME Corp"
        assert brand.logo_url == "https://cdn.acme.com/logo.png"
        assert brand.logo_hash is None  # Scalar schema never has hash
        assert brand.website_url == "https://www.acme.com"

    def test_minimal_scalars(self):
        attrs = {"brandName": "Simple"}
        brand = extract_brand_from_scalars(attrs)
        assert brand.name == "Simple"
        assert brand.logo_url is None


class TestNormalizeBrand:
    def test_prefers_vcard_over_scalars(self):
        attrs = {
            "vcard": ["ORG:VCard Brand", "URL:https://vcard.com"],
            "brandName": "Scalar Brand",
        }
        brand = normalize_brand(attrs)
        assert brand is not None
        assert brand.name == "VCard Brand"

    def test_falls_back_to_scalars(self):
        attrs = {"brandName": "Scalar Brand", "logoUrl": "https://example.com/logo.png"}
        brand = normalize_brand(attrs)
        assert brand is not None
        assert brand.name == "Scalar Brand"
        assert brand.logo_url == "https://example.com/logo.png"

    def test_returns_none_for_non_brand(self):
        attrs = {"someField": "value", "otherField": 123}
        assert normalize_brand(attrs) is None

    def test_empty_vcard_falls_back(self):
        attrs = {"vcard": [], "brandName": "Fallback"}
        brand = normalize_brand(attrs)
        assert brand is not None
        assert brand.name == "Fallback"

    def test_vcard_non_list_falls_back(self):
        attrs = {"vcard": "not a list", "brandName": "Fallback"}
        brand = normalize_brand(attrs)
        assert brand is not None
        assert brand.name == "Fallback"
