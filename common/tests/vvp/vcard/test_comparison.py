"""Tests for credential vCard vs card claim comparison."""

import pytest

from common.vvp.vcard.comparison import ComparisonResult, vcard_properties_match


class TestVCardPropertiesMatch:
    def test_identical_match(self):
        cred = ["ORG:ACME Corporation", "URL:https://acme.com"]
        card = ["ORG:ACME Corporation", "URL:https://acme.com"]
        result = vcard_properties_match(cred, card)
        assert result.match is True
        assert result.mismatches == []

    def test_card_subset_of_credential(self):
        cred = ["ORG:ACME Corporation", "NICKNAME:ACME", "URL:https://acme.com"]
        card = ["ORG:ACME Corporation"]
        result = vcard_properties_match(cred, card)
        assert result.match is True

    def test_value_mismatch(self):
        cred = ["ORG:ACME Corporation"]
        card = ["ORG:Evil Corp"]
        result = vcard_properties_match(cred, card)
        assert result.match is False
        assert len(result.mismatches) == 1
        assert "ORG" in result.mismatches[0]

    def test_property_in_card_not_in_credential(self):
        cred = ["ORG:ACME"]
        card = ["ORG:ACME", "PHOTO:https://evil.com/fake.png"]
        result = vcard_properties_match(cred, card)
        assert result.match is False
        assert "PHOTO" in result.mismatches[0]

    def test_case_insensitive_matching(self):
        cred = ["org:ACME"]
        card = ["ORG:ACME"]
        result = vcard_properties_match(cred, card)
        assert result.match is True

    def test_multi_value_property_match(self):
        cred = ["TEL:+1111", "TEL:+2222", "ORG:ACME"]
        card = ["TEL:+2222"]  # Subset of TEL values
        result = vcard_properties_match(cred, card)
        assert result.match is True

    def test_multi_value_property_mismatch(self):
        cred = ["TEL:+1111", "TEL:+2222"]
        card = ["TEL:+3333"]  # Not in credential
        result = vcard_properties_match(cred, card)
        assert result.match is False


class TestHashIntegrity:
    def test_both_have_hash_matching(self):
        said = "E" + "a" * 43
        cred = [f"ORG:ACME", f"LOGO;HASH={said};VALUE=URI:https://cdn.acme.com/logo.png"]
        card = [f"ORG:ACME", f"LOGO;HASH={said};VALUE=URI:https://cdn.acme.com/logo.png"]
        result = vcard_properties_match(cred, card)
        assert result.match is True
        assert result.hash_integrity == "verified"

    def test_both_have_hash_mismatch(self):
        said1 = "E" + "a" * 43
        said2 = "E" + "b" * 43
        cred = [f"LOGO;HASH={said1};VALUE=URI:https://cdn.acme.com/logo.png"]
        card = [f"LOGO;HASH={said2};VALUE=URI:https://cdn.acme.com/logo.png"]
        result = vcard_properties_match(cred, card)
        assert result.match is False
        assert "HASH mismatch" in result.mismatches[0]

    def test_hash_downgrade_credential_has_card_omits(self):
        """HASH downgrade: credential has HASH but card claim omits it."""
        said = "E" + "a" * 43
        cred = [f"LOGO;HASH={said};VALUE=URI:https://cdn.acme.com/logo.png"]
        card = ["LOGO;VALUE=URI:https://cdn.acme.com/logo.png"]
        result = vcard_properties_match(cred, card)
        assert result.match is False
        assert result.hash_integrity == "omitted_from_card"
        assert "downgrade" in result.mismatches[0].lower()

    def test_hash_downgrade_logo_absent_from_card(self):
        """HASH downgrade: credential has LOGO with HASH but card has no LOGO at all."""
        said = "E" + "a" * 43
        cred = ["ORG:ACME", f"LOGO;HASH={said};VALUE=URI:https://cdn.acme.com/logo.png"]
        card = ["ORG:ACME"]
        result = vcard_properties_match(cred, card)
        assert result.match is False
        assert result.hash_integrity == "omitted_from_card"

    def test_neither_has_hash(self):
        cred = ["LOGO;VALUE=URI:https://cdn.acme.com/logo.png"]
        card = ["LOGO;VALUE=URI:https://cdn.acme.com/logo.png"]
        result = vcard_properties_match(cred, card)
        assert result.match is True
        assert result.hash_integrity == "missing"

    def test_logo_url_mismatch(self):
        cred = ["LOGO;VALUE=URI:https://cdn.acme.com/logo.png"]
        card = ["LOGO;VALUE=URI:https://evil.com/fake.png"]
        result = vcard_properties_match(cred, card)
        assert result.match is False
        assert "URL mismatch" in result.mismatches[0]
