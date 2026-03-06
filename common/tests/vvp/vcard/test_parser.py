"""Tests for vCard property line parser."""

import pytest

from common.vvp.vcard.parser import (
    VCardProperty,
    find_all_properties,
    find_property,
    parse_vcard_line,
    parse_vcard_lines,
)


class TestParseVCardLine:
    def test_simple_property(self):
        result = parse_vcard_line("ORG:ACME Corporation")
        assert result.name == "ORG"
        assert result.value == "ACME Corporation"
        assert result.params == {}

    def test_property_with_params(self):
        result = parse_vcard_line("LOGO;HASH=EK2r6EnD;VALUE=URI:https://cdn.acme.com/logo.png")
        assert result.name == "LOGO"
        assert result.value == "https://cdn.acme.com/logo.png"
        assert result.params == {"HASH": "EK2r6EnD", "VALUE": "URI"}

    def test_case_insensitive_name(self):
        result = parse_vcard_line("org:ACME")
        assert result.name == "ORG"

    def test_case_insensitive_params(self):
        result = parse_vcard_line("LOGO;hash=EK2r;value=URI:https://example.com")
        assert result.params == {"HASH": "EK2r", "VALUE": "URI"}

    def test_tel_with_uri_value(self):
        result = parse_vcard_line("TEL;VALUE=URI:tel:+441923311000")
        assert result.name == "TEL"
        assert result.value == "tel:+441923311000"
        assert result.params == {"VALUE": "URI"}

    def test_url_property(self):
        result = parse_vcard_line("URL:https://www.acme.com")
        assert result.name == "URL"
        assert result.value == "https://www.acme.com"

    def test_nickname(self):
        result = parse_vcard_line("NICKNAME:ACME Corp")
        assert result.name == "NICKNAME"
        assert result.value == "ACME Corp"

    def test_empty_line(self):
        result = parse_vcard_line("")
        assert result.name == ""
        assert result.value == ""

    def test_no_colon(self):
        result = parse_vcard_line("INVALID")
        assert result.name == ""
        assert result.value == "INVALID"

    def test_bare_parameter(self):
        result = parse_vcard_line("TEL;PREF:+1234567890")
        assert result.params == {"PREF": ""}

    def test_multiple_params_lexicographic(self):
        result = parse_vcard_line("LOGO;HASH=EK2r;VALUE=URI:https://example.com")
        assert "HASH" in result.params
        assert "VALUE" in result.params


class TestParseVCardLines:
    def test_multiple_lines(self):
        lines = [
            "ORG:ACME Corporation",
            "NICKNAME:ACME",
            "URL:https://www.acme.com",
        ]
        results = parse_vcard_lines(lines)
        assert len(results) == 3
        assert results[0].name == "ORG"
        assert results[1].name == "NICKNAME"
        assert results[2].name == "URL"

    def test_skips_blank_lines(self):
        lines = ["ORG:ACME", "", "  ", "URL:https://acme.com"]
        results = parse_vcard_lines(lines)
        assert len(results) == 2

    def test_empty_list(self):
        assert parse_vcard_lines([]) == []


class TestFindProperty:
    def test_find_existing(self):
        props = parse_vcard_lines(["ORG:ACME", "URL:https://acme.com"])
        result = find_property(props, "org")
        assert result is not None
        assert result.value == "ACME"

    def test_find_missing(self):
        props = parse_vcard_lines(["ORG:ACME"])
        assert find_property(props, "LOGO") is None

    def test_find_first_of_multiple(self):
        props = parse_vcard_lines(["TEL:+1111", "TEL:+2222"])
        result = find_property(props, "TEL")
        assert result is not None
        assert result.value == "+1111"


class TestFindAllProperties:
    def test_find_multiple(self):
        props = parse_vcard_lines(["TEL:+1111", "ORG:ACME", "TEL:+2222"])
        results = find_all_properties(props, "TEL")
        assert len(results) == 2
        assert {r.value for r in results} == {"+1111", "+2222"}

    def test_find_none(self):
        props = parse_vcard_lines(["ORG:ACME"])
        assert find_all_properties(props, "TEL") == []
