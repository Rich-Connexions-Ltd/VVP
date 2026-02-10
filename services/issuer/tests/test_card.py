"""Tests for vCard card claim builder (Sprint 58)."""

import base64
import importlib.util
import json
import os
import pytest

# Load card module directly to avoid keripy transitive imports via __init__.py
_spec = importlib.util.spec_from_file_location(
    "app.vvp.card",
    os.path.join(os.path.dirname(__file__), "..", "app", "vvp", "card.py"),
)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
build_card_claim = _mod.build_card_claim


def _card_has(card, prefix):
    """Check if a vCard property string list contains a string starting with prefix."""
    return any(s.startswith(prefix) for s in card)


def _card_value(card, prefix):
    """Get the value portion of a vCard property string matching the prefix."""
    for s in card:
        if s.startswith(prefix):
            # Split on first colon after the property name+params
            _, value = s.split(":", 1)
            return value
    return None


class TestBuildCardClaim:
    """Tests for build_card_claim()."""

    def test_full_brand_attributes(self):
        """All Extended Brand Credential fields map to vCard correctly."""
        attrs = {
            "d": "SAbc123",
            "dt": "2025-01-01T00:00:00Z",
            "i": "EAbc",
            "brandName": "ACME Corporation",
            "brandDisplayName": "ACME Corp",
            "assertionCountry": "USA",
            "logoUrl": "https://cdn.acme.com/logo.png",
            "websiteUrl": "https://www.acme.com",
        }

        card = build_card_claim(attrs)

        assert card is not None
        assert isinstance(card, list)
        assert "ORG:ACME Corporation" in card
        assert "NICKNAME:ACME Corp" in card
        assert "LOGO;VALUE=URI:https://cdn.acme.com/logo.png" in card
        assert "URL:https://www.acme.com" in card

    def test_minimal_brand(self):
        """Only brandName (required) produces ORG + NICKNAME."""
        attrs = {
            "brandName": "Widgets Inc",
            "assertionCountry": "GBR",
        }

        card = build_card_claim(attrs)

        assert card is not None
        assert "ORG:Widgets Inc" in card
        assert "NICKNAME:Widgets Inc" in card
        assert not _card_has(card, "LOGO")
        assert not _card_has(card, "URL:")

    def test_fn_falls_back_to_brand_name(self):
        """When brandDisplayName is absent, NICKNAME falls back to brandName."""
        attrs = {"brandName": "FallbackCo"}

        card = build_card_claim(attrs)

        assert "NICKNAME:FallbackCo" in card
        assert "ORG:FallbackCo" in card

    def test_fn_uses_display_name_when_present(self):
        """When brandDisplayName is present, NICKNAME uses it."""
        attrs = {
            "brandName": "Legal Name LLC",
            "brandDisplayName": "FriendlyBrand",
        }

        card = build_card_claim(attrs)

        assert "NICKNAME:FriendlyBrand" in card
        assert "ORG:Legal Name LLC" in card

    def test_no_brand_attributes(self):
        """Returns None for non-brand credentials."""
        attrs = {
            "d": "SAbc",
            "dt": "2025-01-01T00:00:00Z",
            "entityName": "Some Entity",
            "LEI": "1234567890123456789012",
        }

        card = build_card_claim(attrs)

        assert card is None

    def test_empty_attributes(self):
        """Returns None for empty attributes dict."""
        assert build_card_claim({}) is None

    def test_ignores_non_brand_fields(self):
        """Non-brand fields are not included in the card claim."""
        attrs = {
            "d": "SAbc",
            "u": "nonce123",
            "i": "EAbc",
            "dt": "2025-01-01T00:00:00Z",
            "brandName": "TestBrand",
            "assertionCountry": "USA",
            "legalEntityLEI": "1234567890123456789012",
            "startDate": "2025-01-01T00:00:00Z",
            "endDate": "2026-01-01T00:00:00Z",
        }

        card = build_card_claim(attrs)

        assert card is not None
        # Only ORG and NICKNAME (no logo, no url, no non-brand fields)
        assert len(card) == 2
        assert "ORG:TestBrand" in card
        assert "NICKNAME:TestBrand" in card

    def test_empty_brand_name_returns_none(self):
        """Empty string brandName is treated as absent."""
        attrs = {"brandName": ""}

        assert build_card_claim(attrs) is None

    def test_card_is_list_of_strings(self):
        """Card should be a list of RFC 6350 vCard property strings."""
        attrs = {
            "brandName": "ACME",
            "brandDisplayName": "ACME Inc",
            "logoUrl": "https://example.com/logo.png",
            "websiteUrl": "https://example.com",
        }

        card = build_card_claim(attrs)

        assert isinstance(card, list)
        assert len(card) == 4
        for item in card:
            assert isinstance(item, str)
            assert ":" in item  # All vCard props have NAME:value format


class TestDossierChainCardExtraction:
    """Test card extraction from a dossier credential chain (non-root brand credential).

    Mirrors the logic in /vvp/create that walks content.credential_saids
    to find the brand credential.
    """

    def test_brand_credential_not_root(self):
        """Card claim is found when brand credential is not the root.

        Simulates a dossier chain where the root is an LE credential
        (no brandName) and a child credential is the brand credential.
        """
        # Simulate credential chain returned by DossierBuilder.build()
        chain_credentials = [
            # First: child vetting credential (no brand)
            {"said": "SChild1", "attributes": {"entityName": "Vetting Corp", "LEI": "1234"}},
            # Second: child brand credential (has brandName)
            {"said": "SChild2", "attributes": {
                "brandName": "ACME Corporation",
                "brandDisplayName": "ACME",
                "logoUrl": "https://cdn.acme.com/logo.png",
                "websiteUrl": "https://www.acme.com",
            }},
            # Third: root LE credential (no brand)
            {"said": "SRoot", "attributes": {
                "entityName": "ACME Legal Entity LLC",
                "LEI": "5493001KJTIIGC8Y1R12",
            }},
        ]

        # Reproduce the chain walk from /vvp/create
        card = None
        for cred in chain_credentials:
            card = build_card_claim(cred["attributes"])
            if card is not None:
                break

        assert card is not None
        assert "ORG:ACME Corporation" in card
        assert "NICKNAME:ACME" in card
        assert "LOGO;VALUE=URI:https://cdn.acme.com/logo.png" in card
        assert "URL:https://www.acme.com" in card

    def test_no_brand_credential_in_chain(self):
        """Returns None when no credential in the chain has brand attributes."""
        chain_credentials = [
            {"said": "SChild1", "attributes": {"entityName": "Vetting Corp", "LEI": "1234"}},
            {"said": "SRoot", "attributes": {"entityName": "LE Corp", "LEI": "5678"}},
        ]

        card = None
        for cred in chain_credentials:
            card = build_card_claim(cred["attributes"])
            if card is not None:
                break

        assert card is None

    def test_root_is_brand_credential(self):
        """Card claim works when root itself is the brand credential."""
        chain_credentials = [
            {"said": "SRoot", "attributes": {
                "brandName": "RootBrand",
                "logoUrl": "https://example.com/logo.png",
            }},
        ]

        card = None
        for cred in chain_credentials:
            card = build_card_claim(cred["attributes"])
            if card is not None:
                break

        assert card is not None
        assert "ORG:RootBrand" in card


class TestCardInJWTPayload:
    """Verify card claim is correctly embedded in JWT payload structure."""

    def test_card_embeds_in_jwt_payload(self):
        """Card claim should appear in JWT payload when serialized."""
        card = build_card_claim({
            "brandName": "ACME Corp",
            "logoUrl": "https://cdn.acme.com/logo.png",
        })

        # Simulate what create_passport() does: build payload dict, JSON-encode, base64url
        jwt_payload = {
            "iat": 1700000000,
            "exp": 1700000300,
            "orig": {"tn": ["+15551234567"]},
            "dest": {"tn": ["+14155551234"]},
            "evd": "https://issuer.example.com/dossier/SAbc",
        }
        if card:
            jwt_payload["card"] = card

        # Encode as JWT payload segment
        payload_json = json.dumps(jwt_payload, separators=(",", ":"))
        payload_b64 = base64.urlsafe_b64encode(payload_json.encode()).decode().rstrip("=")

        # Decode and verify card is present as array
        padding = 4 - len(payload_b64) % 4
        decoded = json.loads(base64.urlsafe_b64decode(payload_b64 + "=" * padding))

        assert "card" in decoded
        assert isinstance(decoded["card"], list)
        assert "ORG:ACME Corp" in decoded["card"]
        assert "LOGO;VALUE=URI:https://cdn.acme.com/logo.png" in decoded["card"]

    def test_no_card_when_no_brand(self):
        """JWT payload should not contain card key when no brand data."""
        card = build_card_claim({"entityName": "Not a brand"})

        jwt_payload = {
            "iat": 1700000000,
            "exp": 1700000300,
            "orig": {"tn": ["+15551234567"]},
            "dest": {"tn": ["+14155551234"]},
            "evd": "https://issuer.example.com/dossier/SAbc",
        }
        if card:
            jwt_payload["card"] = card

        assert "card" not in jwt_payload
