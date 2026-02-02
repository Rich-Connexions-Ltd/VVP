"""Tests for issuer identity extraction module.

Tests cover:
- Identity extraction from LE credentials (legalName, LEI)
- Identity extraction from lids field (string, dict, list variants)
- Identity extraction from vCard ORG fallback
- Well-known AID resolution
- Configurable well-known AIDs via env var
"""

import os
import json
import tempfile
import pytest

from app.vvp.acdc.models import ACDC
from app.vvp.identity import (
    IssuerIdentity,
    WELLKNOWN_AIDS,
    build_issuer_identity_map,
    get_wellknown_identity,
    _load_wellknown_aids,
    _DEFAULT_WELLKNOWN_AIDS,
)


class TestIssuerIdentityDataclass:
    """Tests for IssuerIdentity dataclass."""

    def test_basic_creation(self):
        """Create identity with all fields."""
        identity = IssuerIdentity(
            aid="ETestAID123456789012345678901234567890123",
            legal_name="Test Corp",
            lei="12345678901234567890",
            source_said="ESAIDxyz123456789012345678901234567890",
        )
        assert identity.aid == "ETestAID123456789012345678901234567890123"
        assert identity.legal_name == "Test Corp"
        assert identity.lei == "12345678901234567890"
        assert identity.source_said == "ESAIDxyz123456789012345678901234567890"

    def test_optional_fields_default_none(self):
        """Optional fields default to None."""
        identity = IssuerIdentity(aid="ETestAID123456789012345678901234567890123")
        assert identity.legal_name is None
        assert identity.lei is None
        assert identity.source_said is None
        assert identity.role is None

    def test_role_field(self):
        """Identity with role field set."""
        identity = IssuerIdentity(
            aid="ETestAID123456789012345678901234567890123",
            legal_name="Test Corp",
            role="issuee",
        )
        assert identity.role == "issuee"


class TestGetWellknownIdentity:
    """Tests for get_wellknown_identity function."""

    def test_known_aid_returns_identity(self):
        """Known AID returns IssuerIdentity."""
        # GLEIF is in the default well-known AIDs
        identity = get_wellknown_identity("EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao")
        assert identity is not None
        assert identity.legal_name == "GLEIF"
        assert identity.lei == "5493001KJTIIGC8Y1R12"
        assert identity.source_said is None  # No credential source

    def test_unknown_aid_returns_none(self):
        """Unknown AID returns None."""
        identity = get_wellknown_identity("EUnknownAID123456789012345678901234567")
        assert identity is None

    def test_wellknown_identity_has_role(self):
        """Well-known identity has role='wellknown'."""
        gleif_aid = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao"
        identity = get_wellknown_identity(gleif_aid)
        assert identity is not None
        assert identity.role == "wellknown"


class TestBuildIssuerIdentityMap:
    """Tests for build_issuer_identity_map function."""

    def _make_acdc(
        self,
        said: str,
        issuer_aid: str,
        attributes: dict = None,
        edges: dict = None,
    ) -> ACDC:
        """Helper to create test ACDC."""
        return ACDC(
            version="ACDC10JSON000000",
            said=said,
            issuer_aid=issuer_aid,
            schema_said="ESchemaTest1234567890123456789012345678",
            attributes=attributes or {},
            edges=edges,
            rules=None,
            raw={},
        )

    def test_extract_identity_from_legal_name(self):
        """Extract identity from legalName attribute."""
        acdc = self._make_acdc(
            said="ESAID1234567890123456789012345678901234567",
            issuer_aid="EIssuer12345678901234567890123456789012",
            attributes={
                "legalName": "Acme Corporation",
                "issuee": "EIssuee12345678901234567890123456789012",
            },
        )
        result = build_issuer_identity_map([acdc])

        assert "EIssuee12345678901234567890123456789012" in result
        identity = result["EIssuee12345678901234567890123456789012"]
        assert identity.legal_name == "Acme Corporation"
        assert identity.source_said == "ESAID1234567890123456789012345678901234567"

    def test_extract_identity_from_lei(self):
        """Extract identity from LEI attribute."""
        acdc = self._make_acdc(
            said="ESAID1234567890123456789012345678901234567",
            issuer_aid="EIssuer12345678901234567890123456789012",
            attributes={
                "LEI": "12345678901234567890",
                "issuee": "EIssuee12345678901234567890123456789012",
            },
        )
        result = build_issuer_identity_map([acdc])

        assert "EIssuee12345678901234567890123456789012" in result
        identity = result["EIssuee12345678901234567890123456789012"]
        assert identity.lei == "12345678901234567890"

    def test_extract_lei_from_lids_string(self):
        """Extract LEI from lids field when it's a 20-char string."""
        acdc = self._make_acdc(
            said="ESAID1234567890123456789012345678901234567",
            issuer_aid="EIssuer12345678901234567890123456789012",
            attributes={
                "lids": "12345678901234567890",  # 20-char LEI
                "issuee": "EIssuee12345678901234567890123456789012",
            },
        )
        result = build_issuer_identity_map([acdc])

        identity = result["EIssuee12345678901234567890123456789012"]
        assert identity.lei == "12345678901234567890"

    def test_extract_from_lids_dict(self):
        """Extract identity from lids dict with LEI and legalName."""
        acdc = self._make_acdc(
            said="ESAID1234567890123456789012345678901234567",
            issuer_aid="EIssuer12345678901234567890123456789012",
            attributes={
                "lids": {
                    "LEI": "98765432109876543210",
                    "legalName": "Test Company Ltd",
                },
                "issuee": "EIssuee12345678901234567890123456789012",
            },
        )
        result = build_issuer_identity_map([acdc])

        identity = result["EIssuee12345678901234567890123456789012"]
        assert identity.lei == "98765432109876543210"
        assert identity.legal_name == "Test Company Ltd"

    def test_extract_from_lids_list(self):
        """Extract identity from lids list of dicts."""
        acdc = self._make_acdc(
            said="ESAID1234567890123456789012345678901234567",
            issuer_aid="EIssuer12345678901234567890123456789012",
            attributes={
                "lids": [
                    {"lei": "11111111111111111111"},
                    {"legalName": "Another Corp"},
                ],
                "issuee": "EIssuee12345678901234567890123456789012",
            },
        )
        result = build_issuer_identity_map([acdc])

        identity = result["EIssuee12345678901234567890123456789012"]
        assert identity.lei == "11111111111111111111"

    def test_extract_from_vcard_org(self):
        """Extract legal name from vCard ORG field."""
        acdc = self._make_acdc(
            said="ESAID1234567890123456789012345678901234567",
            issuer_aid="EIssuer12345678901234567890123456789012",
            attributes={
                "vcard": [
                    "BEGIN:VCARD",
                    "VERSION:4.0",
                    "ORG:VCard Organization Inc",
                    "END:VCARD",
                ],
                "issuee": "EIssuee12345678901234567890123456789012",
            },
        )
        result = build_issuer_identity_map([acdc])

        identity = result["EIssuee12345678901234567890123456789012"]
        assert identity.legal_name == "VCard Organization Inc"

    def test_vcard_org_case_insensitive(self):
        """vCard ORG parsing is case-insensitive."""
        acdc = self._make_acdc(
            said="ESAID1234567890123456789012345678901234567",
            issuer_aid="EIssuer12345678901234567890123456789012",
            attributes={
                "vcard": ["org:lowercase org name"],
                "issuee": "EIssuee12345678901234567890123456789012",
            },
        )
        result = build_issuer_identity_map([acdc])

        identity = result["EIssuee12345678901234567890123456789012"]
        assert identity.legal_name == "lowercase org name"

    def test_extract_lei_from_vcard(self):
        """Extract LEI from vCard NOTE;LEI field."""
        acdc = self._make_acdc(
            said="ESAID1234567890123456789012345678901234567",
            issuer_aid="EIssuer12345678901234567890123456789012",
            attributes={
                "vcard": [
                    "ORG:Rich Connexions",
                    "NOTE;LEI:984500DEE7537A07Y615",
                    "LOGO;VALUE=URI:https://example.com/logo.png",
                ],
                "issuee": "EIssuee12345678901234567890123456789012",
            },
        )
        result = build_issuer_identity_map([acdc])

        identity = result["EIssuee12345678901234567890123456789012"]
        assert identity.legal_name == "Rich Connexions"
        assert identity.lei == "984500DEE7537A07Y615"

    def test_vcard_lei_case_insensitive(self):
        """vCard NOTE;LEI parsing is case-insensitive."""
        acdc = self._make_acdc(
            said="ESAID1234567890123456789012345678901234567",
            issuer_aid="EIssuer12345678901234567890123456789012",
            attributes={
                "vcard": ["note;lei:ABC123DEF456GHI789JK"],
                "issuee": "EIssuee12345678901234567890123456789012",
            },
        )
        result = build_issuer_identity_map([acdc])

        identity = result["EIssuee12345678901234567890123456789012"]
        assert identity.lei == "ABC123DEF456GHI789JK"

    def test_direct_lei_takes_precedence_over_vcard(self):
        """Direct LEI attribute takes precedence over vCard LEI."""
        acdc = self._make_acdc(
            said="ESAID1234567890123456789012345678901234567",
            issuer_aid="EIssuer12345678901234567890123456789012",
            attributes={
                "LEI": "DIRECT_LEI_12345678901",
                "vcard": ["NOTE;LEI:VCARD_LEI_1234567890"],
                "issuee": "EIssuee12345678901234567890123456789012",
            },
        )
        result = build_issuer_identity_map([acdc])

        identity = result["EIssuee12345678901234567890123456789012"]
        # Direct LEI should be used (it was set first in the logic)
        assert identity.lei == "DIRECT_LEI_12345678901"

    def test_self_issued_credential_uses_issuer(self):
        """Self-issued credential (no issuee) identifies the issuer."""
        acdc = self._make_acdc(
            said="ESAID1234567890123456789012345678901234567",
            issuer_aid="ESelfIssuer12345678901234567890123456789",
            attributes={
                "legalName": "Self-Issued Corp",
                # No issuee field
            },
        )
        result = build_issuer_identity_map([acdc])

        # Should use issuer_aid as the identified AID
        assert "ESelfIssuer12345678901234567890123456789" in result
        identity = result["ESelfIssuer12345678901234567890123456789"]
        assert identity.legal_name == "Self-Issued Corp"

    def test_le_credential_issuee_has_role(self):
        """LE credential identity has role='issuee' when explicit issuee."""
        acdc = self._make_acdc(
            said="ESAID1234567890123456789012345678901234567",
            issuer_aid="EIssuer12345678901234567890123456789012",
            attributes={
                "legalName": "Acme Corporation",
                "issuee": "EIssuee12345678901234567890123456789012",
            },
        )
        result = build_issuer_identity_map([acdc])

        identity = result["EIssuee12345678901234567890123456789012"]
        assert identity.role == "issuee"

    def test_self_issued_credential_has_issuer_role(self):
        """Self-issued LE credential identity has role='issuer'."""
        acdc = self._make_acdc(
            said="ESAID1234567890123456789012345678901234567",
            issuer_aid="ESelfIssuer12345678901234567890123456789",
            attributes={
                "legalName": "Self Corp",
                # No issuee field - self-issued
            },
        )
        result = build_issuer_identity_map([acdc])

        identity = result["ESelfIssuer12345678901234567890123456789"]
        assert identity.role == "issuer"

    def test_wellknown_fallback_has_role(self):
        """Well-known fallback identity has role='wellknown'."""
        gleif_aid = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao"
        acdc = self._make_acdc(
            said="ESAID1234567890123456789012345678901234567",
            issuer_aid=gleif_aid,
            attributes={
                "someField": "someValue",
                # No identity info
            },
        )
        result = build_issuer_identity_map([acdc])

        identity = result[gleif_aid]
        assert identity.role == "wellknown"

    def test_wellknown_fallback_for_issuer(self):
        """Well-known AIDs provide fallback identity for issuers."""
        # Create ACDC issued by GLEIF (well-known AID)
        gleif_aid = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao"
        acdc = self._make_acdc(
            said="ESAID1234567890123456789012345678901234567",
            issuer_aid=gleif_aid,
            attributes={
                # No identity info in this credential
                "someField": "someValue",
            },
        )
        result = build_issuer_identity_map([acdc])

        # GLEIF should be identified via well-known fallback
        assert gleif_aid in result
        identity = result[gleif_aid]
        assert identity.legal_name == "GLEIF"
        assert identity.lei == "5493001KJTIIGC8Y1R12"
        assert identity.source_said is None  # From well-known, not credential

    def test_credential_identity_overrides_wellknown(self):
        """Identity from credential takes precedence over well-known."""
        gleif_aid = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao"
        acdc = self._make_acdc(
            said="ESAID1234567890123456789012345678901234567",
            issuer_aid="EOtherIssuer12345678901234567890123456",
            attributes={
                "legalName": "Override Name for GLEIF",
                "issuee": gleif_aid,
            },
        )
        result = build_issuer_identity_map([acdc])

        # Credential identity should override well-known
        identity = result[gleif_aid]
        assert identity.legal_name == "Override Name for GLEIF"
        assert identity.source_said == "ESAID1234567890123456789012345678901234567"

    def test_empty_list_returns_empty_dict(self):
        """Empty ACDC list returns empty identity map."""
        result = build_issuer_identity_map([])
        assert result == {}

    def test_no_identity_info_excluded(self):
        """Credentials without identity info are excluded."""
        acdc = self._make_acdc(
            said="ESAID1234567890123456789012345678901234567",
            issuer_aid="EUnknownIssuer12345678901234567890123",
            attributes={
                "someField": "someValue",
                # No legalName, LEI, lids, or vcard
            },
        )
        result = build_issuer_identity_map([acdc])

        # Issuer not in well-known, no identity info → empty
        assert len(result) == 0

    def test_edge_target_wellknown_aid_resolved(self):
        """Edge target pointing to well-known AID is resolved."""
        # Provenant Global is a well-known AID
        provenant_aid = "ELW1FqnJZgOBR43UqAXCCFF6Zyz_EXaunivemMEkhRLy"
        acdc = self._make_acdc(
            said="ESAID1234567890123456789012345678901234567",
            issuer_aid="EUnknownIssuer12345678901234567890123",
            attributes={
                "someField": "someValue",
            },
            edges={
                "issuer": provenant_aid,  # Edge points to Provenant Global AID
            },
        )
        result = build_issuer_identity_map([acdc])

        # Provenant Global should be identified via well-known from edge target
        assert provenant_aid in result
        identity = result[provenant_aid]
        assert identity.legal_name == "Provenant Global"
        assert identity.role == "wellknown"

    def test_edge_dict_target_wellknown_aid_resolved(self):
        """Edge target in dict format pointing to well-known AID is resolved."""
        gleif_aid = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao"
        acdc = self._make_acdc(
            said="ESAID1234567890123456789012345678901234567",
            issuer_aid="EUnknownIssuer12345678901234567890123",
            attributes={
                "someField": "someValue",
            },
            edges={
                "auth": {"n": gleif_aid},  # Dict format edge
            },
        )
        result = build_issuer_identity_map([acdc])

        # GLEIF should be identified via well-known from edge target
        assert gleif_aid in result
        identity = result[gleif_aid]
        assert identity.legal_name == "GLEIF"
        assert identity.role == "wellknown"


class TestLoadWellknownAids:
    """Tests for _load_wellknown_aids function."""

    def test_returns_defaults_when_no_env_var(self):
        """Returns default AIDs when WELLKNOWN_AIDS_FILE not set."""
        # Remove env var if set
        old_val = os.environ.pop("WELLKNOWN_AIDS_FILE", None)
        try:
            result = _load_wellknown_aids()
            assert result == _DEFAULT_WELLKNOWN_AIDS
        finally:
            if old_val:
                os.environ["WELLKNOWN_AIDS_FILE"] = old_val

    def test_loads_from_file(self):
        """Loads AIDs from JSON file when WELLKNOWN_AIDS_FILE is set."""
        custom_aids = {
            "ECustomAID123456789012345678901234567890": ["Custom Corp", "11111111111111111111"],
            "EAnotherAID12345678901234567890123456789": ["Another Corp", None],
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(custom_aids, f)
            temp_path = f.name

        try:
            os.environ["WELLKNOWN_AIDS_FILE"] = temp_path
            result = _load_wellknown_aids()

            assert "ECustomAID123456789012345678901234567890" in result
            assert result["ECustomAID123456789012345678901234567890"] == ("Custom Corp", "11111111111111111111")
            assert result["EAnotherAID12345678901234567890123456789"] == ("Another Corp", None)
        finally:
            os.environ.pop("WELLKNOWN_AIDS_FILE", None)
            os.unlink(temp_path)

    def test_returns_defaults_on_file_not_found(self):
        """Returns defaults when file not found."""
        os.environ["WELLKNOWN_AIDS_FILE"] = "/nonexistent/path/aids.json"
        try:
            result = _load_wellknown_aids()
            assert result == _DEFAULT_WELLKNOWN_AIDS
        finally:
            os.environ.pop("WELLKNOWN_AIDS_FILE", None)

    def test_returns_defaults_on_invalid_json(self):
        """Returns defaults when JSON is invalid."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("not valid json {{{")
            temp_path = f.name

        try:
            os.environ["WELLKNOWN_AIDS_FILE"] = temp_path
            result = _load_wellknown_aids()
            assert result == _DEFAULT_WELLKNOWN_AIDS
        finally:
            os.environ.pop("WELLKNOWN_AIDS_FILE", None)
            os.unlink(temp_path)


class TestIdentitySourceDetermination:
    """Tests for identity_source determination in API response."""

    def test_dossier_identity_has_source_said(self):
        """Identity from dossier has source_said set."""
        acdc = ACDC(
            version="ACDC10JSON000000",
            said="ESAID1234567890123456789012345678901234567",
            issuer_aid="EIssuer12345678901234567890123456789012",
            schema_said="ESchema12345678901234567890123456789012",
            attributes={
                "legalName": "Test Corp",
                "issuee": "EIssuee12345678901234567890123456789012",
            },
            edges=None,
            rules=None,
            raw={},
        )
        result = build_issuer_identity_map([acdc])

        identity = result["EIssuee12345678901234567890123456789012"]
        assert identity.source_said is not None  # Dossier source

    def test_wellknown_identity_has_no_source_said(self):
        """Identity from well-known has source_said=None."""
        gleif_aid = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao"
        identity = get_wellknown_identity(gleif_aid)

        assert identity is not None
        assert identity.source_said is None  # Well-known source
