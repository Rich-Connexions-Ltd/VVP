"""Tests for credential card view-model adapter.

Per Sprint 21 plan (PLAN_Credential_Card_UI.md), tests cover:
- Attribute mapping for each credential type
- Edge normalization (str, dict with n, dict with d, lists)
- Variant detection (compact/partial)
- Trusted root checking
- Missing data handling

Per Sprint 22 plan, additional tests cover:
- Attribute formatting (booleans, dates, arrays)
- Nested dict flattening
- Attribute section categorization
"""

import pytest

from app.vvp.acdc.models import ACDC, ACDCChainResult
from app.vvp.ui.credential_viewmodel import (
    AttributeDisplay,
    AttributeSection,
    CredentialCardViewModel,
    EdgeLink,
    IssuerInfo,
    RawACDCData,
    RevocationStatus,
    VariantLimitations,
    _build_attribute_sections,
    _flatten_nested,
    _format_date,
    _format_value,
    _is_iso_date,
    _is_redacted_value,
    build_credential_card_vm,
    normalize_edge,
)


class TestNormalizeEdge:
    """Tests for edge normalization."""

    def test_normalize_edge_string(self):
        """String edge value returns the SAID directly."""
        result = normalize_edge("E" + "A" * 43)
        assert result == "E" + "A" * 43

    def test_normalize_edge_empty_string(self):
        """Empty string returns None."""
        result = normalize_edge("")
        assert result is None

    def test_normalize_edge_dict_with_n(self):
        """Dict with 'n' key extracts the node SAID."""
        result = normalize_edge({"n": "E" + "B" * 43, "s": "schema"})
        assert result == "E" + "B" * 43

    def test_normalize_edge_dict_with_d(self):
        """Dict with 'd' key extracts the digest SAID."""
        result = normalize_edge({"d": "E" + "C" * 43})
        assert result == "E" + "C" * 43

    def test_normalize_edge_dict_prefers_n_over_d(self):
        """Dict with both 'n' and 'd' prefers 'n'."""
        result = normalize_edge({"n": "E" + "N" * 43, "d": "E" + "D" * 43})
        assert result == "E" + "N" * 43

    def test_normalize_edge_list_returns_first_valid(self):
        """List of edges returns first valid SAID."""
        result = normalize_edge([
            None,
            "",
            {"n": "E" + "F" * 43},
        ])
        assert result == "E" + "F" * 43

    def test_normalize_edge_empty_list(self):
        """Empty list returns None."""
        result = normalize_edge([])
        assert result is None

    def test_normalize_edge_none(self):
        """None returns None."""
        result = normalize_edge(None)
        assert result is None

    def test_normalize_edge_invalid_type(self):
        """Invalid type (int, etc.) returns None."""
        result = normalize_edge(12345)
        assert result is None


class TestBuildCredentialCardVM:
    """Tests for the main view-model builder."""

    def _make_acdc(
        self,
        said: str = "E" + "A" * 43,
        issuer: str = "D" + "B" * 43,
        schema: str = "E" + "S" * 43,
        attributes: dict | str | None = None,
        edges: dict | None = None,
        variant: str = "full",
    ) -> ACDC:
        """Helper to create ACDC objects for testing."""
        return ACDC(
            version="ACDC10JSON00011c_",
            said=said,
            issuer_aid=issuer,
            schema_said=schema,
            attributes=attributes or {},
            edges=edges,
            variant=variant,
        )

    def test_basic_vm_fields(self):
        """Basic fields are correctly populated."""
        acdc = self._make_acdc()
        vm = build_credential_card_vm(acdc)

        assert vm.said == acdc.said
        assert vm.schema_said == acdc.schema_said
        assert vm.variant == "full"
        assert vm.status == "INDETERMINATE"  # No chain result

    def test_status_from_chain_result(self):
        """Status is taken from chain result when provided."""
        acdc = self._make_acdc()
        chain_result = ACDCChainResult(
            chain=[acdc],
            root_aid="some_root",
            validated=True,
            status="VALID",
        )

        vm = build_credential_card_vm(acdc, chain_result=chain_result)

        assert vm.status == "VALID"

    def test_revocation_from_result(self):
        """Revocation status is populated from revocation result."""
        acdc = self._make_acdc()
        revocation_result = {
            "status": "ACTIVE",
            "checked_at": "2024-01-01T00:00:00Z",
            "source": "witness",
            "error": None,
        }

        vm = build_credential_card_vm(acdc, revocation_result=revocation_result)

        assert vm.revocation.state == "ACTIVE"
        assert vm.revocation.checked_at == "2024-01-01T00:00:00Z"
        assert vm.revocation.source == "witness"
        assert vm.revocation.error is None

    def test_revocation_default(self):
        """Default revocation status is UNKNOWN."""
        acdc = self._make_acdc()
        vm = build_credential_card_vm(acdc)

        assert vm.revocation.state == "UNKNOWN"
        assert vm.revocation.source == "unknown"


class TestPrimaryAttribute:
    """Tests for primary attribute extraction."""

    def _make_acdc(self, cred_type_attrs: dict, edges: dict | None = None) -> ACDC:
        """Create ACDC with specific attributes for type detection."""
        return ACDC(
            version="ACDC10JSON00011c_",
            said="E" + "A" * 43,
            issuer_aid="D" + "B" * 43,
            schema_said="E" + "S" * 43,
            attributes=cred_type_attrs,
            edges=edges,
            variant="full",
        )

    def test_ape_primary_from_tn(self):
        """APE credential with 'tn' is detected as TNAlloc by ACDC model.

        Note: The ACDC.credential_type property checks attributes before edges,
        so a credential with 'tn' attribute is classified as TNAlloc even if
        it has vetting edges. This is the expected behavior per the model.
        """
        acdc = self._make_acdc(
            {"tn": "+1-555-0100"},
            edges={"vetting": {"n": "E" + "V" * 43}},
        )
        vm = build_credential_card_vm(acdc)

        # Model detects as TNAlloc due to 'tn' attribute
        assert vm.credential_type == "TNAlloc"
        assert vm.primary.label == "Number Block"
        assert vm.primary.value == "+1-555-0100"

    def test_ape_without_tn_attribute(self):
        """APE credential detected via vetting edge when no tn attribute.

        APE credentials in production may have different attribute patterns.
        Detection falls back to edge-based when attributes don't match TNAlloc.
        """
        acdc = self._make_acdc(
            {"subject": "caller", "purpose": "authorization"},
            edges={"vetting": {"n": "E" + "V" * 43}},
        )
        vm = build_credential_card_vm(acdc)

        assert vm.credential_type == "APE"
        # No tn/phone attribute, so shows truncated SAID
        assert "E" in vm.primary.value

    def test_le_primary_from_legalname(self):
        """LE credential extracts legal name."""
        acdc = self._make_acdc({"legalName": "Acme Corporation", "LEI": "123456"})
        vm = build_credential_card_vm(acdc)

        assert vm.primary.label == "Legal Name"
        assert vm.primary.value == "Acme Corporation"

    def test_le_primary_fallback_to_lei(self):
        """LE credential falls back to LEI if no legalName."""
        acdc = self._make_acdc({"LEI": "549300EXAMPLE0LEI00"})
        vm = build_credential_card_vm(acdc)

        assert vm.primary.label == "LEI"
        assert vm.primary.value == "549300EXAMPLE0LEI00"

    def test_tnalloc_primary_from_tn(self):
        """TNAlloc credential extracts number block."""
        acdc = self._make_acdc(
            {"tn": ["+1-555-0000", "+1-555-9999"]},
            edges={"jl": {"n": "E" + "J" * 43}},
        )
        vm = build_credential_card_vm(acdc)

        # Should join multiple values
        assert "555-0000" in vm.primary.value
        assert "555-9999" in vm.primary.value

    def test_unknown_type_shows_said(self):
        """Unknown credential type shows truncated SAID."""
        acdc = self._make_acdc({})
        vm = build_credential_card_vm(acdc)

        assert "E" + "A" * 15 in vm.primary.value  # Truncated SAID


class TestSecondaryAttributes:
    """Tests for secondary attribute extraction."""

    def test_secondary_excludes_primary_field(self):
        """Secondary attributes don't include the primary field."""
        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid="D" + "B" * 43,
            schema_said="E" + "S" * 43,
            attributes={"legalName": "Acme Corp", "LEI": "123", "country": "US"},
            edges=None,
            variant="full",
        )
        vm = build_credential_card_vm(acdc)

        secondary_labels = [a.label for a in vm.secondary]
        # legalName is primary, should not be in secondary
        assert "Legalname" not in secondary_labels
        assert "Legal Name" not in secondary_labels

    def test_secondary_max_three(self):
        """Secondary attributes are limited to 3."""
        attrs = {f"field{i}": f"value{i}" for i in range(10)}
        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid="D" + "B" * 43,
            schema_said="E" + "S" * 43,
            attributes=attrs,
            edges=None,
            variant="full",
        )
        vm = build_credential_card_vm(acdc)

        assert len(vm.secondary) <= 3

    def test_secondary_excludes_internal_fields(self):
        """Secondary attributes exclude d, dt, i, s, v, n and underscore fields."""
        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid="D" + "B" * 43,
            schema_said="E" + "S" * 43,
            attributes={"d": "x", "dt": "y", "_internal": "z", "visible": "show"},
            edges=None,
            variant="full",
        )
        vm = build_credential_card_vm(acdc)

        secondary_labels = [a.label.lower() for a in vm.secondary]
        assert "d" not in secondary_labels
        assert "dt" not in secondary_labels
        assert "_internal" not in secondary_labels


class TestEdgeBuilding:
    """Tests for edge link building."""

    def test_edges_with_availability(self):
        """Edge availability is determined by available_saids."""
        target_said = "E" + "T" * 43
        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid="D" + "B" * 43,
            schema_said="E" + "S" * 43,
            attributes={},
            edges={"vetting": {"n": target_said}},
            variant="full",
        )

        # With target in available set
        vm = build_credential_card_vm(acdc, available_saids={target_said})
        assert vm.edges["vetting"].available is True

        # Without target in available set
        vm = build_credential_card_vm(acdc, available_saids=set())
        assert vm.edges["vetting"].available is False

    def test_edge_labels_mapped(self):
        """Edge keys are mapped to human-readable labels."""
        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid="D" + "B" * 43,
            schema_said="E" + "S" * 43,
            attributes={},
            edges={
                "vetting": {"n": "E" + "1" * 43},
                "le": {"n": "E" + "2" * 43},
                "delegation": {"n": "E" + "3" * 43},
            },
            variant="full",
        )
        vm = build_credential_card_vm(acdc)

        assert vm.edges["vetting"].label == "Vetted By"
        assert vm.edges["le"].label == "Legal Entity"
        assert vm.edges["delegation"].label == "Delegated By"


class TestVariantLimitations:
    """Tests for compact/partial variant detection."""

    def test_compact_variant_detected(self):
        """Compact variant (attributes is SAID string) is detected."""
        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid="D" + "B" * 43,
            schema_said="E" + "S" * 43,
            attributes="E" + "X" * 43,  # SAID reference, not dict
            edges=None,
            variant="compact",
        )
        vm = build_credential_card_vm(acdc)

        assert vm.limitations.is_compact is True
        assert vm.limitations.has_variant_limitations is True

    def test_partial_variant_with_redacted_fields(self):
        """Partial variant with redacted fields is detected."""
        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid="D" + "B" * 43,
            schema_said="E" + "S" * 43,
            attributes={"name": "visible", "secret": "", "hidden": "#"},
            edges=None,
            variant="partial",
        )
        vm = build_credential_card_vm(acdc)

        assert vm.limitations.is_partial is True
        assert "secret" in vm.limitations.redacted_fields
        assert "hidden" in vm.limitations.redacted_fields

    def test_partial_variant_with_underscore_placeholder(self):
        """Partial variant with '_' placeholder is detected."""
        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid="D" + "B" * 43,
            schema_said="E" + "S" * 43,
            attributes={"name": "visible", "issuee": "_"},
            edges=None,
            variant="partial",
        )
        vm = build_credential_card_vm(acdc)

        assert vm.limitations.is_partial is True
        assert "issuee" in vm.limitations.redacted_fields
        assert "name" not in vm.limitations.redacted_fields

    def test_partial_variant_with_typed_placeholder(self):
        """Partial variant with '_:type' placeholder is detected."""
        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid="D" + "B" * 43,
            schema_said="E" + "S" * 43,
            attributes={
                "name": "visible",
                "date": "_:datetime",
                "amount": "_:number",
                "description": "_:string",
            },
            edges=None,
            variant="partial",
        )
        vm = build_credential_card_vm(acdc)

        assert vm.limitations.is_partial is True
        assert "date" in vm.limitations.redacted_fields
        assert "amount" in vm.limitations.redacted_fields
        assert "description" in vm.limitations.redacted_fields
        assert "name" not in vm.limitations.redacted_fields

    def test_missing_edge_targets_tracked(self):
        """Missing edge targets are tracked in limitations."""
        target_said = "E" + "M" * 43
        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid="D" + "B" * 43,
            schema_said="E" + "S" * 43,
            attributes={},
            edges={"parent": {"n": target_said}},
            variant="full",
        )

        # Target not in available set
        vm = build_credential_card_vm(acdc, available_saids=set())

        assert target_said in vm.limitations.missing_edge_targets
        assert vm.limitations.has_variant_limitations is True


class TestIssuerInfo:
    """Tests for issuer information."""

    def test_issuer_aid_truncation(self):
        """Issuer AID is truncated for display."""
        long_aid = "D" + "X" * 43
        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid=long_aid,
            schema_said="E" + "S" * 43,
            attributes={},
            edges=None,
            variant="full",
        )
        vm = build_credential_card_vm(acdc)

        assert vm.issuer.aid == long_aid
        assert len(vm.issuer.aid_short) < len(long_aid)
        assert "..." in vm.issuer.aid_short

    def test_trusted_root_detection(self):
        """Trusted root status is determined from config."""
        # Use the actual GLEIF root from config
        from app.core.config import TRUSTED_ROOT_AIDS

        if TRUSTED_ROOT_AIDS:
            root_aid = next(iter(TRUSTED_ROOT_AIDS))
            acdc = ACDC(
                version="",
                said="E" + "A" * 43,
                issuer_aid=root_aid,
                schema_said="E" + "S" * 43,
                attributes={},
                edges=None,
                variant="full",
            )
            vm = build_credential_card_vm(acdc)
            assert vm.issuer.is_trusted_root is True

        # Non-root AID
        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid="D" + "N" * 43,  # Not a trusted root
            schema_said="E" + "S" * 43,
            attributes={},
            edges=None,
            variant="full",
        )
        vm = build_credential_card_vm(acdc)
        assert vm.issuer.is_trusted_root is False


class TestRawData:
    """Tests for raw data preservation."""

    def test_raw_attributes_preserved(self):
        """Raw attributes are preserved for debug panel."""
        attrs = {"field1": "value1", "nested": {"a": 1}}
        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid="D" + "B" * 43,
            schema_said="E" + "S" * 43,
            attributes=attrs,
            edges=None,
            variant="full",
        )
        vm = build_credential_card_vm(acdc)

        assert vm.raw.attributes == attrs

    def test_source_format_detected(self):
        """Source format is detected from signature presence."""
        # With signature = CESR
        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid="D" + "B" * 43,
            schema_said="E" + "S" * 43,
            attributes={},
            edges=None,
            variant="full",
            signature=b"some_signature",
        )
        vm = build_credential_card_vm(acdc)
        assert vm.raw.source_format == "cesr"

        # Without signature = JSON
        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid="D" + "B" * 43,
            schema_said="E" + "S" * 43,
            attributes={},
            edges=None,
            variant="full",
            signature=None,
        )
        vm = build_credential_card_vm(acdc)
        assert vm.raw.source_format == "json"


# =============================================================================
# Sprint 22: Attribute Formatting Tests
# =============================================================================


class TestIsIsoDate:
    """Tests for ISO date detection."""

    def test_valid_iso_date(self):
        """Valid ISO date is detected."""
        assert _is_iso_date("2024-11-25T20:20:39+00:00") is True

    def test_valid_iso_date_short(self):
        """Date without time is detected."""
        assert _is_iso_date("2024-11-25") is True

    def test_valid_iso_date_with_z(self):
        """Date with Z timezone is detected."""
        assert _is_iso_date("2024-11-25T20:20:39Z") is True

    def test_short_string_not_date(self):
        """Short string is not a date."""
        assert _is_iso_date("2024-11") is False

    def test_invalid_format(self):
        """Invalid format is not a date."""
        assert _is_iso_date("not-a-date") is False
        assert _is_iso_date("11-25-2024") is False

    def test_empty_string(self):
        """Empty string is not a date."""
        assert _is_iso_date("") is False


class TestFormatDate:
    """Tests for date formatting."""

    def test_format_iso_date(self):
        """ISO date is formatted to human-readable."""
        result = _format_date("2024-11-25T20:20:39+00:00")
        assert "Nov" in result
        assert "25" in result
        assert "2024" in result

    def test_format_iso_date_with_z(self):
        """Z timezone is handled."""
        result = _format_date("2024-11-25T20:20:39Z")
        assert "Nov" in result

    def test_invalid_date_returns_original(self):
        """Invalid date returns original string."""
        result = _format_date("not-a-date")
        assert result == "not-a-date"


class TestIsRedactedValue:
    """Tests for redaction placeholder detection."""

    def test_underscore_is_redacted(self):
        """Single underscore is a redaction placeholder."""
        assert _is_redacted_value("_") is True

    def test_typed_placeholder_is_redacted(self):
        """Typed placeholders like _:string are redacted."""
        assert _is_redacted_value("_:string") is True
        assert _is_redacted_value("_:date") is True
        assert _is_redacted_value("_:datetime") is True

    def test_hash_is_redacted(self):
        """Hash marker is a redaction placeholder."""
        assert _is_redacted_value("#") is True

    def test_explicit_redacted_is_redacted(self):
        """Explicit [REDACTED] marker is redacted."""
        assert _is_redacted_value("[REDACTED]") is True

    def test_empty_string_is_redacted(self):
        """Empty string is treated as redacted."""
        assert _is_redacted_value("") is True

    def test_normal_values_not_redacted(self):
        """Normal values are not redaction placeholders."""
        assert _is_redacted_value("hello") is False
        assert _is_redacted_value("549300EXAMPLE") is False
        assert _is_redacted_value("+1-555-0100") is False

    def test_none_not_redacted(self):
        """None is not a redaction placeholder (handled separately)."""
        assert _is_redacted_value(None) is False

    def test_non_string_not_redacted(self):
        """Non-string values are not redaction placeholders."""
        assert _is_redacted_value(42) is False
        assert _is_redacted_value(True) is False
        assert _is_redacted_value(["a", "b"]) is False


class TestFormatValue:
    """Tests for attribute value formatting."""

    def test_format_boolean_true(self):
        """True boolean is formatted as 'Yes' with class."""
        value, css_class = _format_value(True, "key")
        assert value == "Yes"
        assert css_class == "attr-bool-true"

    def test_format_boolean_false(self):
        """False boolean is formatted as 'No' with class."""
        value, css_class = _format_value(False, "key")
        assert value == "No"
        assert css_class == "attr-bool-false"

    def test_format_none(self):
        """None is formatted as em dash."""
        value, css_class = _format_value(None, "key")
        assert value == "—"
        assert css_class == "attr-null"

    def test_format_iso_date_string(self):
        """ISO date string is formatted with class."""
        value, css_class = _format_value("2024-11-25T20:20:39+00:00", "key")
        assert "Nov" in value
        assert css_class == "attr-date"

    def test_format_regular_string(self):
        """Regular string is returned as-is."""
        value, css_class = _format_value("hello world", "key")
        assert value == "hello world"
        assert css_class == ""

    def test_format_list(self):
        """List is joined with commas."""
        value, css_class = _format_value(["a", "b", "c"], "key")
        assert value == "a, b, c"
        assert css_class == "attr-array"

    def test_format_number(self):
        """Number is converted to string."""
        value, css_class = _format_value(42, "key")
        assert value == "42"
        assert css_class == ""

    def test_format_redacted_underscore(self):
        """Underscore placeholder is formatted as redacted."""
        value, css_class = _format_value("_", "key")
        assert value == "(redacted)"
        assert css_class == "attr-redacted"

    def test_format_redacted_typed(self):
        """Typed placeholder is formatted as redacted."""
        value, css_class = _format_value("_:string", "key")
        assert value == "(redacted)"
        assert css_class == "attr-redacted"

    def test_format_redacted_hash(self):
        """Hash marker is formatted as redacted."""
        value, css_class = _format_value("#", "key")
        assert value == "(redacted)"
        assert css_class == "attr-redacted"

    def test_format_redacted_explicit(self):
        """Explicit [REDACTED] is formatted as redacted."""
        value, css_class = _format_value("[REDACTED]", "key")
        assert value == "(redacted)"
        assert css_class == "attr-redacted"


class TestFlattenNested:
    """Tests for nested dict flattening."""

    def test_flatten_simple_dict(self):
        """Simple dict is returned as list of tuples."""
        result = _flatten_nested({"a": 1, "b": 2})
        assert ("a", 1) in result
        assert ("b", 2) in result

    def test_flatten_nested_dict(self):
        """Nested dict is flattened with dot notation."""
        result = _flatten_nested({"numbers": {"rangeStart": "+1234", "rangeEnd": "+5678"}})
        assert ("numbers.rangeStart", "+1234") in result
        assert ("numbers.rangeEnd", "+5678") in result

    def test_flatten_deeply_nested(self):
        """Deeply nested dict is flattened."""
        result = _flatten_nested({"a": {"b": {"c": "deep"}}})
        assert ("a.b.c", "deep") in result

    def test_flatten_skips_excluded_fields(self):
        """Excluded fields (d, dt, i, s, v, n) are skipped."""
        result = _flatten_nested({"d": "x", "dt": "y", "visible": "show"})
        keys = [k for k, v in result]
        assert "d" not in keys
        assert "dt" not in keys
        assert "visible" in keys

    def test_flatten_skips_underscore_fields(self):
        """Fields starting with underscore are skipped."""
        result = _flatten_nested({"_internal": "hidden", "visible": "show"})
        keys = [k for k, v in result]
        assert "_internal" not in keys
        assert "visible" in keys


class TestBuildAttributeSections:
    """Tests for attribute section building."""

    def test_categorizes_dates(self):
        """Date fields are categorized in Dates section."""
        sections = _build_attribute_sections({
            "startDate": "2024-11-25T00:00:00Z",
            "endDate": "2024-12-25T00:00:00Z",
        })
        dates_section = next((s for s in sections if s.name == "Dates & Times"), None)
        assert dates_section is not None
        assert len(dates_section.attributes) == 2

    def test_categorizes_identity(self):
        """Identity fields are categorized in Identity section."""
        sections = _build_attribute_sections({
            "LEI": "549300EXAMPLE",
            "legalName": "Acme Corp",
        })
        identity_section = next((s for s in sections if s.name == "Identity"), None)
        assert identity_section is not None
        labels = [a.label.lower() for a in identity_section.attributes]
        assert any("lei" in l for l in labels)
        assert any("legal" in l for l in labels)

    def test_categorizes_permissions(self):
        """Permission fields are categorized in Permissions section."""
        sections = _build_attribute_sections({
            "doNotOriginate": False,
            "channel": "voice",
        })
        perms_section = next((s for s in sections if s.name == "Permissions"), None)
        assert perms_section is not None
        assert len(perms_section.attributes) == 2

    def test_categorizes_numbers(self):
        """Number/phone fields are categorized in Numbers section."""
        sections = _build_attribute_sections({
            "tn": "+1-555-0100",
        })
        numbers_section = next((s for s in sections if s.name == "Numbers & Ranges"), None)
        assert numbers_section is not None

    def test_unknown_fields_go_to_other(self):
        """Unknown fields are categorized in Other section."""
        sections = _build_attribute_sections({
            "customField": "value",
            "anotherCustom": "data",
        })
        other_section = next((s for s in sections if s.name == "Other Attributes"), None)
        assert other_section is not None
        assert len(other_section.attributes) == 2

    def test_empty_for_non_dict(self):
        """Non-dict attributes return empty sections."""
        sections = _build_attribute_sections("E" + "A" * 43)
        assert sections == []

    def test_empty_for_empty_dict(self):
        """Empty dict returns empty sections."""
        sections = _build_attribute_sections({})
        assert sections == []

    def test_primary_field_excluded(self):
        """Primary field is excluded from sections."""
        sections = _build_attribute_sections(
            {"tn": "+1-555-0100", "channel": "voice"},
            primary_field="tn",
        )
        all_attrs = [a for s in sections for a in s.attributes]
        labels = [a.label.lower() for a in all_attrs]
        assert not any("tn" in l for l in labels)

    def test_flattens_nested_objects(self):
        """Nested objects are flattened into sections."""
        sections = _build_attribute_sections({
            "numbers": {"rangeStart": "+1234", "rangeEnd": "+5678"},
        })
        numbers_section = next((s for s in sections if s.name == "Numbers & Ranges"), None)
        assert numbers_section is not None
        labels = [a.label for a in numbers_section.attributes]
        # Dot notation converted to arrow separator
        assert any("›" in l for l in labels)

    def test_redacted_placeholder_masked(self):
        """Redaction placeholders are displayed as '(redacted)'."""
        sections = _build_attribute_sections({
            "LEI": "_",  # Full redaction placeholder
            "legalName": "_:string",  # Typed placeholder
        })
        identity_section = next((s for s in sections if s.name == "Identity"), None)
        assert identity_section is not None
        for attr in identity_section.attributes:
            assert attr.value == "(redacted)"
            assert attr.css_class == "attr-redacted"

    def test_redacted_hash_marker_masked(self):
        """Hash marker redaction is displayed as '(redacted)'."""
        sections = _build_attribute_sections({
            "customField": "#",
        })
        other_section = next((s for s in sections if s.name == "Other Attributes"), None)
        assert other_section is not None
        attr = other_section.attributes[0]
        assert attr.value == "(redacted)"
        assert attr.css_class == "attr-redacted"

    def test_redacted_explicit_marker_masked(self):
        """Explicit [REDACTED] marker is displayed as '(redacted)'."""
        sections = _build_attribute_sections({
            "customField": "[REDACTED]",
        })
        other_section = next((s for s in sections if s.name == "Other Attributes"), None)
        assert other_section is not None
        attr = other_section.attributes[0]
        assert attr.value == "(redacted)"
        assert attr.css_class == "attr-redacted"


class TestViewModelSections:
    """Tests for sections field in CredentialCardViewModel."""

    def test_vm_has_sections_field(self):
        """CredentialCardViewModel has sections populated."""
        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid="D" + "B" * 43,
            schema_said="E" + "S" * 43,
            attributes={
                "LEI": "549300EXAMPLE",
                "startDate": "2024-01-01T00:00:00Z",
            },
            edges=None,
            variant="full",
        )
        vm = build_credential_card_vm(acdc)

        assert hasattr(vm, "sections")
        assert isinstance(vm.sections, list)
        assert len(vm.sections) > 0

    def test_vm_sections_empty_for_compact(self):
        """Compact variant has empty sections."""
        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid="D" + "B" * 43,
            schema_said="E" + "S" * 43,
            attributes="E" + "X" * 43,  # Compact variant
            edges=None,
            variant="compact",
        )
        vm = build_credential_card_vm(acdc)

        assert vm.sections == []

    def test_vm_secondary_still_populated(self):
        """Secondary field is still populated for backwards compatibility."""
        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid="D" + "B" * 43,
            schema_said="E" + "S" * 43,
            attributes={"field1": "a", "field2": "b", "field3": "c", "field4": "d"},
            edges=None,
            variant="full",
        )
        vm = build_credential_card_vm(acdc)

        assert hasattr(vm, "secondary")
        assert len(vm.secondary) <= 3  # Limited for backwards compat


# =============================================================================
# Sprint 22 Part 2: Tooltip and Raw Contents Tests
# =============================================================================


from app.vvp.ui.credential_viewmodel import (
    FIELD_DESCRIPTIONS,
    _get_field_tooltip,
    _build_raw_contents,
)


class TestFieldDescriptions:
    """Tests for field description mapping."""

    def test_core_acdc_fields_have_descriptions(self):
        """Core ACDC fields (v, d, i, s, a, e, r) have descriptions."""
        core_fields = ["v", "d", "i", "s", "a", "e", "r"]
        for field in core_fields:
            assert field in FIELD_DESCRIPTIONS, f"Missing description for {field}"
            assert len(FIELD_DESCRIPTIONS[field]) > 10, f"Description for {field} too short"

    def test_common_attribute_fields_have_descriptions(self):
        """Common attribute fields have descriptions."""
        common_fields = ["LEI", "legalName", "dt", "tn", "channel"]
        for field in common_fields:
            assert field in FIELD_DESCRIPTIONS, f"Missing description for {field}"


class TestGetFieldTooltip:
    """Tests for tooltip lookup function."""

    def test_exact_match(self):
        """Exact key match returns description."""
        tooltip = _get_field_tooltip("LEI")
        assert "Legal Entity Identifier" in tooltip

    def test_base_key_match(self):
        """Nested key matches on base key."""
        tooltip = _get_field_tooltip("numbers.rangeStart")
        # Should match either "numbers" or "rangeStart"
        assert tooltip != ""

    def test_last_segment_match(self):
        """Nested key matches on last segment when base key not found."""
        # Use a key where base is not in FIELD_DESCRIPTIONS but last segment is
        tooltip = _get_field_tooltip("custom.nested.dt")
        assert "Datetime" in tooltip or "datetime" in tooltip.lower()

    def test_unknown_key_returns_empty(self):
        """Unknown key returns empty string."""
        tooltip = _get_field_tooltip("xyz_unknown_field_abc")
        assert tooltip == ""

    def test_core_field_descriptions(self):
        """Core ACDC fields return appropriate descriptions."""
        assert "SAID" in _get_field_tooltip("d")
        assert "Issuer" in _get_field_tooltip("i")
        assert "Schema" in _get_field_tooltip("s")


class TestBuildRawContents:
    """Tests for raw contents builder."""

    def test_builds_list_of_attribute_displays(self):
        """Returns list of AttributeDisplay objects."""
        result = _build_raw_contents({"d": "E" + "A" * 43, "i": "D" + "B" * 43})
        assert isinstance(result, list)
        assert all(isinstance(a, AttributeDisplay) for a in result)

    def test_includes_all_top_level_fields(self):
        """All top-level fields are included."""
        result = _build_raw_contents({"d": "x", "i": "y", "s": "z"})
        labels = [a.label for a in result]
        assert "d" in labels
        assert "i" in labels
        assert "s" in labels

    def test_flattens_nested_dicts(self):
        """Nested dicts are flattened with dot notation."""
        result = _build_raw_contents({
            "a": {"nested": {"deep": "value"}}
        })
        labels = [a.label for a in result]
        # Should have "a", "a.nested", and "a.nested.deep"
        assert any("a.nested.deep" in l for l in labels)

    def test_formats_arrays(self):
        """Arrays are formatted appropriately."""
        result = _build_raw_contents({"goals": ["a", "b", "c"]})
        goals_attr = next((a for a in result if a.label == "goals"), None)
        assert goals_attr is not None
        assert "a" in goals_attr.value
        assert goals_attr.css_class == "attr-array"

    def test_includes_tooltips(self):
        """Attributes have tooltips where available."""
        result = _build_raw_contents({"d": "E" + "A" * 43, "i": "D" + "B" * 43})
        d_attr = next((a for a in result if a.label == "d"), None)
        assert d_attr is not None
        assert d_attr.tooltip != ""
        assert "SAID" in d_attr.tooltip

    def test_raw_key_preserved(self):
        """Raw key is preserved in AttributeDisplay."""
        result = _build_raw_contents({"LEI": "549300EXAMPLE"})
        lei_attr = next((a for a in result if a.label == "LEI"), None)
        assert lei_attr is not None
        assert lei_attr.raw_key == "LEI"


class TestViewModelRawContents:
    """Tests for raw_contents field in CredentialCardViewModel."""

    def test_vm_has_raw_contents_field(self):
        """CredentialCardViewModel has raw_contents populated."""
        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid="D" + "B" * 43,
            schema_said="E" + "S" * 43,
            attributes={"LEI": "549300EXAMPLE"},
            edges=None,
            variant="full",
        )
        vm = build_credential_card_vm(acdc)

        assert hasattr(vm, "raw_contents")
        assert isinstance(vm.raw_contents, list)
        assert len(vm.raw_contents) > 0

    def test_raw_contents_includes_core_fields(self):
        """Raw contents includes d, i, s fields."""
        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid="D" + "B" * 43,
            schema_said="E" + "S" * 43,
            attributes={},
            edges=None,
            variant="full",
        )
        vm = build_credential_card_vm(acdc)

        labels = [a.label for a in vm.raw_contents]
        assert "d" in labels
        assert "i" in labels
        assert "s" in labels

    def test_raw_contents_attributes_have_tooltips(self):
        """Raw contents attributes have tooltips for known fields."""
        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid="D" + "B" * 43,
            schema_said="E" + "S" * 43,
            attributes={"LEI": "549300EXAMPLE"},
            edges=None,
            variant="full",
        )
        vm = build_credential_card_vm(acdc)

        d_attr = next((a for a in vm.raw_contents if a.label == "d"), None)
        assert d_attr is not None
        assert d_attr.tooltip != ""


class TestAttributeDisplayTooltip:
    """Tests for tooltip field in AttributeDisplay from sections."""

    def test_sections_attributes_have_tooltips(self):
        """Attributes in sections have tooltips for known fields."""
        sections = _build_attribute_sections({
            "LEI": "549300EXAMPLE",
            "legalName": "Acme Corp",
        })
        identity_section = next((s for s in sections if s.name == "Identity"), None)
        assert identity_section is not None

        lei_attr = next((a for a in identity_section.attributes if "LEI" in a.label.upper()), None)
        assert lei_attr is not None
        assert lei_attr.tooltip != ""
        assert "Legal Entity Identifier" in lei_attr.tooltip

    def test_sections_attributes_have_raw_key(self):
        """Attributes in sections preserve raw_key."""
        sections = _build_attribute_sections({
            "LEI": "549300EXAMPLE",
        })
        identity_section = next((s for s in sections if s.name == "Identity"), None)
        lei_attr = next((a for a in identity_section.attributes if "LEI" in a.label.upper()), None)
        assert lei_attr is not None
        assert lei_attr.raw_key == "LEI"

    def test_unknown_fields_have_empty_tooltip(self):
        """Unknown fields have empty tooltip."""
        sections = _build_attribute_sections({
            "xyz_custom_field": "value",
        })
        other_section = next((s for s in sections if s.name == "Other Attributes"), None)
        assert other_section is not None
        custom_attr = next((a for a in other_section.attributes), None)
        assert custom_attr is not None
        assert custom_attr.tooltip == ""


# =============================================================================
# vCard Parsing Tests
# =============================================================================


class TestParseVcardLines:
    """Tests for _parse_vcard_lines function."""

    def test_parse_logo_url(self):
        """LOGO line with VALUE=URI extracts URL."""
        from app.vvp.ui.credential_viewmodel import _parse_vcard_lines

        lines = [
            "LOGO;HASH=sha256-abc123;VALUE=URI:https://example.com/logo.png",
        ]
        info = _parse_vcard_lines(lines)
        assert info.logo_url == "https://example.com/logo.png"

    def test_parse_logo_hash(self):
        """LOGO line extracts HASH value."""
        from app.vvp.ui.credential_viewmodel import _parse_vcard_lines

        lines = [
            "LOGO;HASH=sha256-40bac686a3f0b48253de55b34f552c8070baf22f81255aac449721c879c716a4;VALUE=URI:https://example.com/logo.png",
        ]
        info = _parse_vcard_lines(lines)
        assert info.logo_hash == "sha256-40bac686a3f0b48253de55b34f552c8070baf22f81255aac449721c879c716a4"

    def test_parse_org(self):
        """ORG line extracts organization name."""
        from app.vvp.ui.credential_viewmodel import _parse_vcard_lines

        lines = ["ORG:Rich Connexions"]
        info = _parse_vcard_lines(lines)
        assert info.org == "Rich Connexions"

    def test_parse_lei_from_note(self):
        """NOTE;LEI line extracts LEI."""
        from app.vvp.ui.credential_viewmodel import _parse_vcard_lines

        lines = ["NOTE;LEI:984500DEE7537A07Y615"]
        info = _parse_vcard_lines(lines)
        assert info.lei == "984500DEE7537A07Y615"

    def test_parse_categories(self):
        """CATEGORIES line extracts categories."""
        from app.vvp.ui.credential_viewmodel import _parse_vcard_lines

        lines = ["CATEGORIES:Business,Telecom"]
        info = _parse_vcard_lines(lines)
        assert info.categories == "Business,Telecom"

    def test_parse_full_vcard(self):
        """Full vCard with multiple lines parses correctly."""
        from app.vvp.ui.credential_viewmodel import _parse_vcard_lines

        lines = [
            "CATEGORIES:",
            "LOGO;HASH=sha256-abc;VALUE=URI:https://example.com/logo.png",
            "NOTE;LEI:984500DEE7537A07Y615",
            "ORG:Rich Connexions",
        ]
        info = _parse_vcard_lines(lines)
        assert info.logo_url == "https://example.com/logo.png"
        assert info.org == "Rich Connexions"
        assert info.lei == "984500DEE7537A07Y615"
        assert info.raw_lines == lines

    def test_parse_empty_lines(self):
        """Empty vCard lines returns empty VCardInfo."""
        from app.vvp.ui.credential_viewmodel import _parse_vcard_lines

        info = _parse_vcard_lines([])
        assert info.logo_url is None
        assert info.org is None
        assert info.lei is None

    def test_case_insensitive_parsing(self):
        """Parsing is case-insensitive for field names."""
        from app.vvp.ui.credential_viewmodel import _parse_vcard_lines

        lines = [
            "logo;hash=sha256-abc;value=uri:https://example.com/logo.png",
            "org:Test Org",
        ]
        info = _parse_vcard_lines(lines)
        assert info.logo_url == "https://example.com/logo.png"
        assert info.org == "Test Org"

    def test_parse_fn(self):
        """FN line extracts full name."""
        from app.vvp.ui.credential_viewmodel import _parse_vcard_lines

        lines = ["FN:John Smith"]
        info = _parse_vcard_lines(lines)
        assert info.fn == "John Smith"

    def test_parse_adr(self):
        """ADR line extracts address."""
        from app.vvp.ui.credential_viewmodel import _parse_vcard_lines

        lines = ["ADR:;;123 Main St;City;State;12345;Country"]
        info = _parse_vcard_lines(lines)
        assert info.adr == ";;123 Main St;City;State;12345;Country"

    def test_parse_adr_with_type(self):
        """ADR line with TYPE parameter extracts address."""
        from app.vvp.ui.credential_viewmodel import _parse_vcard_lines

        lines = ["ADR;TYPE=WORK:;;Office Park;Suite 100"]
        info = _parse_vcard_lines(lines)
        assert info.adr == ";;Office Park;Suite 100"

    def test_parse_tel(self):
        """TEL line extracts telephone."""
        from app.vvp.ui.credential_viewmodel import _parse_vcard_lines

        lines = ["TEL:+1-555-123-4567"]
        info = _parse_vcard_lines(lines)
        assert info.tel == "+1-555-123-4567"

    def test_parse_tel_with_type(self):
        """TEL line with TYPE parameter extracts telephone."""
        from app.vvp.ui.credential_viewmodel import _parse_vcard_lines

        lines = ["TEL;TYPE=WORK,VOICE:+1-555-987-6543"]
        info = _parse_vcard_lines(lines)
        assert info.tel == "+1-555-987-6543"

    def test_parse_email(self):
        """EMAIL line extracts email address."""
        from app.vvp.ui.credential_viewmodel import _parse_vcard_lines

        lines = ["EMAIL:contact@example.com"]
        info = _parse_vcard_lines(lines)
        assert info.email == "contact@example.com"

    def test_parse_email_with_type(self):
        """EMAIL line with TYPE parameter extracts email address."""
        from app.vvp.ui.credential_viewmodel import _parse_vcard_lines

        lines = ["EMAIL;TYPE=WORK:work@example.com"]
        info = _parse_vcard_lines(lines)
        assert info.email == "work@example.com"

    def test_parse_url(self):
        """URL line extracts website URL."""
        from app.vvp.ui.credential_viewmodel import _parse_vcard_lines

        lines = ["URL:https://example.com"]
        info = _parse_vcard_lines(lines)
        assert info.url == "https://example.com"

    def test_parse_extended_vcard(self):
        """Full vCard with new fields parses correctly."""
        from app.vvp.ui.credential_viewmodel import _parse_vcard_lines

        lines = [
            "FN:Acme Corp Contact",
            "ORG:Acme Corporation",
            "TEL:+1-555-123-4567",
            "EMAIL:contact@acme.com",
            "ADR:;;100 Main St;New York;NY;10001;USA",
            "URL:https://acme.com",
            "CATEGORIES:Business,Technology",
        ]
        info = _parse_vcard_lines(lines)
        assert info.fn == "Acme Corp Contact"
        assert info.org == "Acme Corporation"
        assert info.tel == "+1-555-123-4567"
        assert info.email == "contact@acme.com"
        assert info.adr == ";;100 Main St;New York;NY;10001;USA"
        assert info.url == "https://acme.com"
        assert info.categories == "Business,Technology"


class TestVmWithVcard:
    """Tests for CredentialCardViewModel with vCard data."""

    def test_vm_has_vcard_when_present(self):
        """View model includes parsed vCard when attribute present."""
        acdc = ACDC(
            version="ACDC10JSON00011c_",
            said="E" + "A" * 43,
            issuer_aid="D" + "B" * 43,
            schema_said="E" + "S" * 43,
            attributes={
                "vcard": [
                    "LOGO;VALUE=URI:https://example.com/logo.png",
                    "ORG:Test Org",
                ]
            },
            edges=None,
            variant="full",
        )
        vm = build_credential_card_vm(acdc)

        assert vm.vcard is not None
        assert vm.vcard.logo_url == "https://example.com/logo.png"
        assert vm.vcard.org == "Test Org"

    def test_vm_vcard_none_when_not_present(self):
        """View model has no vCard when attribute not present."""
        acdc = ACDC(
            version="ACDC10JSON00011c_",
            said="E" + "A" * 43,
            issuer_aid="D" + "B" * 43,
            schema_said="E" + "S" * 43,
            attributes={"LEI": "549300EXAMPLE"},
            edges=None,
            variant="full",
        )
        vm = build_credential_card_vm(acdc)

        assert vm.vcard is None

    def test_vm_vcard_none_for_non_list(self):
        """View model has no vCard when vcard attribute is not a list."""
        acdc = ACDC(
            version="ACDC10JSON00011c_",
            said="E" + "A" * 43,
            issuer_aid="D" + "B" * 43,
            schema_said="E" + "S" * 43,
            attributes={"vcard": "not a list"},
            edges=None,
            variant="full",
        )
        vm = build_credential_card_vm(acdc)

        assert vm.vcard is None


# =============================================================================
# Issuer Identity Resolution Tests
# =============================================================================


class TestIssuerIdentity:
    """Tests for IssuerIdentity dataclass."""

    def test_issuer_identity_fields(self):
        """IssuerIdentity has expected fields."""
        from app.vvp.ui.credential_viewmodel import IssuerIdentity

        identity = IssuerIdentity(
            aid="D" + "A" * 43,
            legal_name="Acme Corp",
            lei="549300EXAMPLE",
            source_said="E" + "B" * 43,
        )
        assert identity.aid == "D" + "A" * 43
        assert identity.legal_name == "Acme Corp"
        assert identity.lei == "549300EXAMPLE"
        assert identity.source_said == "E" + "B" * 43

    def test_issuer_identity_optional_fields(self):
        """IssuerIdentity optional fields default to None."""
        from app.vvp.ui.credential_viewmodel import IssuerIdentity

        identity = IssuerIdentity(aid="D" + "A" * 43)
        assert identity.aid == "D" + "A" * 43
        assert identity.legal_name is None
        assert identity.lei is None
        assert identity.source_said is None


class TestBuildIssuerIdentityMap:
    """Tests for build_issuer_identity_map function."""

    def test_empty_list_returns_empty_map(self):
        """Empty ACDC list returns empty identity map."""
        from app.vvp.ui.credential_viewmodel import build_issuer_identity_map

        result = build_issuer_identity_map([])
        assert result == {}

    def test_extracts_identity_from_le_credential(self):
        """Extracts identity from LE credential with legalName and LEI."""
        from app.vvp.ui.credential_viewmodel import build_issuer_identity_map

        # LE credential about an issuee
        le_acdc = ACDC(
            version="ACDC10JSON00011c_",
            said="E" + "L" * 43,
            issuer_aid="D" + "I" * 43,
            schema_said="E" + "S" * 43,
            attributes={
                "issuee": "D" + "T" * 43,  # Target AID being identified
                "legalName": "Target Corp",
                "LEI": "549300TARGET",
            },
            edges=None,
            variant="full",
        )

        result = build_issuer_identity_map([le_acdc])

        target_aid = "D" + "T" * 43
        assert target_aid in result
        assert result[target_aid].legal_name == "Target Corp"
        assert result[target_aid].lei == "549300TARGET"
        assert result[target_aid].source_said == "E" + "L" * 43

    def test_extracts_identity_from_vcard(self):
        """Extracts organization name from vCard when no legalName."""
        from app.vvp.ui.credential_viewmodel import build_issuer_identity_map

        # LE credential with vCard data
        le_acdc = ACDC(
            version="ACDC10JSON00011c_",
            said="E" + "L" * 43,
            issuer_aid="D" + "I" * 43,
            schema_said="E" + "S" * 43,
            attributes={
                "issuee": "D" + "T" * 43,
                "vcard": [
                    "ORG:VCard Organization",
                    "NOTE;LEI:549300VCARD",
                ],
            },
            edges=None,
            variant="full",
        )

        result = build_issuer_identity_map([le_acdc])

        target_aid = "D" + "T" * 43
        assert target_aid in result
        assert result[target_aid].legal_name == "VCard Organization"

    def test_self_issued_le_identifies_issuer(self):
        """Self-issued LE credential (no issuee) identifies its issuer."""
        from app.vvp.ui.credential_viewmodel import build_issuer_identity_map

        # LE credential without explicit issuee
        le_acdc = ACDC(
            version="ACDC10JSON00011c_",
            said="E" + "L" * 43,
            issuer_aid="D" + "I" * 43,
            schema_said="E" + "S" * 43,
            attributes={
                "legalName": "Self Corp",
                "LEI": "549300SELF",
            },
            edges=None,
            variant="full",
        )

        result = build_issuer_identity_map([le_acdc])

        issuer_aid = "D" + "I" * 43
        assert issuer_aid in result
        assert result[issuer_aid].legal_name == "Self Corp"
        assert result[issuer_aid].lei == "549300SELF"

    def test_ignores_credentials_without_identity(self):
        """Credentials without legalName or LEI are ignored."""
        from app.vvp.ui.credential_viewmodel import build_issuer_identity_map

        # APE credential without identity info
        ape_acdc = ACDC(
            version="ACDC10JSON00011c_",
            said="E" + "P" * 43,
            issuer_aid="D" + "I" * 43,
            schema_said="E" + "S" * 43,
            attributes={
                "issuee": "D" + "T" * 43,
                "role": "Operator",
            },
            edges=None,
            variant="full",
        )

        result = build_issuer_identity_map([ape_acdc])
        assert result == {}

    def test_ignores_compact_variant(self):
        """Compact variant credentials are ignored."""
        from app.vvp.ui.credential_viewmodel import build_issuer_identity_map

        # Compact variant (attributes is None or not a dict)
        compact_acdc = ACDC(
            version="ACDC10JSON00011c_",
            said="E" + "C" * 43,
            issuer_aid="D" + "I" * 43,
            schema_said="E" + "S" * 43,
            attributes=None,
            edges=None,
            variant="compact",
        )

        result = build_issuer_identity_map([compact_acdc])
        assert result == {}

    def test_extracts_lei_from_lids_string(self):
        """Extracts LEI from lids field when it's a direct string."""
        from app.vvp.ui.credential_viewmodel import build_issuer_identity_map

        issuee_aid = "D" + "E" * 43
        # lids as 20-char alphanumeric LEI
        acdc = ACDC(
            version="ACDC10JSON00011c_",
            said="E" + "A" * 43,
            issuer_aid="D" + "I" * 43,
            schema_said="E" + "S" * 43,
            attributes={
                "i": issuee_aid,
                "lids": "12345678901234567890",  # 20-char LEI
            },
        )

        result = build_issuer_identity_map([acdc])
        assert issuee_aid in result
        assert result[issuee_aid].lei == "12345678901234567890"

    def test_extracts_lei_from_lids_dict(self):
        """Extracts LEI from lids field when it's a dict."""
        from app.vvp.ui.credential_viewmodel import build_issuer_identity_map

        issuee_aid = "D" + "E" * 43
        acdc = ACDC(
            version="ACDC10JSON00011c_",
            said="E" + "A" * 43,
            issuer_aid="D" + "I" * 43,
            schema_said="E" + "S" * 43,
            attributes={
                "i": issuee_aid,
                "lids": {"LEI": "98765432109876543210", "legalName": "LIDS Corp"},
            },
        )

        result = build_issuer_identity_map([acdc])
        assert issuee_aid in result
        assert result[issuee_aid].lei == "98765432109876543210"
        assert result[issuee_aid].legal_name == "LIDS Corp"

    def test_extracts_lei_from_lids_array(self):
        """Extracts LEI from lids field when it's an array."""
        from app.vvp.ui.credential_viewmodel import build_issuer_identity_map

        issuee_aid = "D" + "E" * 43
        acdc = ACDC(
            version="ACDC10JSON00011c_",
            said="E" + "A" * 43,
            issuer_aid="D" + "I" * 43,
            schema_said="E" + "S" * 43,
            attributes={
                "i": issuee_aid,
                "lids": [{"lei": "11111111111111111111"}, {"legalName": "Array Corp"}],
            },
        )

        result = build_issuer_identity_map([acdc])
        assert issuee_aid in result
        assert result[issuee_aid].lei == "11111111111111111111"

    def test_wellknown_aids_fallback(self):
        """Well-known AIDs provide identity fallback for issuers not in dossier."""
        from app.vvp.ui.credential_viewmodel import WELLKNOWN_AIDS, build_issuer_identity_map

        # Get a well-known AID (GLEIF)
        gleif_aid = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao"
        assert gleif_aid in WELLKNOWN_AIDS

        # Create a credential issued by GLEIF but no LE cred for GLEIF
        acdc = ACDC(
            version="ACDC10JSON00011c_",
            said="E" + "A" * 43,
            issuer_aid=gleif_aid,
            schema_said="E" + "S" * 43,
            attributes={"role": "QVI"},  # Not an LE credential
        )

        result = build_issuer_identity_map([acdc])
        # GLEIF should be in the map from well-known fallback
        assert gleif_aid in result
        assert result[gleif_aid].legal_name == "GLEIF"

    def test_wellknown_aids_not_used_when_dossier_has_identity(self):
        """Well-known AIDs don't override identity from dossier LE credential."""
        from app.vvp.ui.credential_viewmodel import WELLKNOWN_AIDS, build_issuer_identity_map

        gleif_aid = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao"
        assert gleif_aid in WELLKNOWN_AIDS

        # Create an LE credential that identifies GLEIF with different name
        acdc = ACDC(
            version="ACDC10JSON00011c_",
            said="E" + "A" * 43,
            issuer_aid=gleif_aid,
            schema_said="E" + "S" * 43,
            attributes={
                "i": gleif_aid,  # Self-issued LE
                "legalName": "GLEIF International",  # Different from well-known
                "LEI": "5493001KJTIIGC8Y1R12",
            },
        )

        result = build_issuer_identity_map([acdc])
        # Dossier identity takes precedence
        assert gleif_aid in result
        assert result[gleif_aid].legal_name == "GLEIF International"


class TestIssuerInfoWithIdentity:
    """Tests for IssuerInfo with resolved identity."""

    def test_issuer_info_has_display_name_field(self):
        """IssuerInfo dataclass has display_name field."""
        issuer = IssuerInfo(
            aid="D" + "A" * 43,
            aid_short="DA...",
            is_trusted_root=False,
            display_name="Test Corp",
            lei="549300TEST",
        )
        assert issuer.display_name == "Test Corp"
        assert issuer.lei == "549300TEST"

    def test_issuer_info_display_name_optional(self):
        """IssuerInfo display_name defaults to None."""
        issuer = IssuerInfo(
            aid="D" + "A" * 43,
            aid_short="DA...",
            is_trusted_root=False,
        )
        assert issuer.display_name is None
        assert issuer.lei is None


class TestVmWithIssuerIdentities:
    """Tests for build_credential_card_vm with issuer_identities parameter."""

    def test_vm_uses_identity_map(self):
        """View model uses identity map to populate issuer display_name."""
        from app.vvp.ui.credential_viewmodel import IssuerIdentity

        issuer_aid = "D" + "I" * 43

        acdc = ACDC(
            version="ACDC10JSON00011c_",
            said="E" + "A" * 43,
            issuer_aid=issuer_aid,
            schema_said="E" + "S" * 43,
            attributes={"role": "Operator"},
            edges=None,
            variant="full",
        )

        issuer_identities = {
            issuer_aid: IssuerIdentity(
                aid=issuer_aid,
                legal_name="Issuer Corp",
                lei="549300ISSUER",
            )
        }

        vm = build_credential_card_vm(acdc, issuer_identities=issuer_identities)

        assert vm.issuer.display_name == "Issuer Corp"
        assert vm.issuer.lei == "549300ISSUER"

    def test_vm_without_identity_map(self):
        """View model works without identity map."""
        acdc = ACDC(
            version="ACDC10JSON00011c_",
            said="E" + "A" * 43,
            issuer_aid="D" + "I" * 43,
            schema_said="E" + "S" * 43,
            attributes={"role": "Operator"},
            edges=None,
            variant="full",
        )

        vm = build_credential_card_vm(acdc)

        assert vm.issuer.display_name is None
        assert vm.issuer.lei is None

    def test_vm_with_unknown_issuer(self):
        """View model handles issuer not in identity map."""
        from app.vvp.ui.credential_viewmodel import IssuerIdentity

        other_aid = "D" + "O" * 43

        acdc = ACDC(
            version="ACDC10JSON00011c_",
            said="E" + "A" * 43,
            issuer_aid="D" + "I" * 43,
            schema_said="E" + "S" * 43,
            attributes={"role": "Operator"},
            edges=None,
            variant="full",
        )

        # Identity map has different AID
        issuer_identities = {
            other_aid: IssuerIdentity(
                aid=other_aid,
                legal_name="Other Corp",
            )
        }

        vm = build_credential_card_vm(acdc, issuer_identities=issuer_identities)

        # Should not have display_name since issuer not in map
        assert vm.issuer.display_name is None
