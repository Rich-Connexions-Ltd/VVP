"""Tests for schema document fetching and validation.

Tests for VVP §5.1.1-2.8.3: Validation must compare data structure and values
against the declared schema.
"""

import json
import pytest
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

from app.vvp.acdc.schema_fetcher import (
    SCHEMA_REGISTRIES,
    _schema_cache,
    clear_schema_cache,
    compute_schema_said,
    fetch_schema,
    get_cache_stats,
    get_schema_for_validation,
    verify_schema_said,
)
from app.vvp.acdc.schema_validator import (
    get_required_fields,
    get_schema_type,
    is_valid_json_schema,
    validate_acdc_against_schema,
)
from app.vvp.acdc.exceptions import ACDCChainInvalid
from app.vvp.acdc.models import ACDC
from app.vvp.api_models import ClaimStatus
from app.vvp.keri.exceptions import ResolutionFailedError


# Sample schema document for testing
SAMPLE_SCHEMA = {
    "$id": "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao",
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "Legal Entity Credential",
    "type": "object",
    "required": ["LEI", "legalName"],
    "properties": {
        "LEI": {"type": "string", "pattern": "^[A-Z0-9]{20}$"},
        "legalName": {"type": "string"},
        "i": {"type": "string"},
    },
}

# Valid attributes matching sample schema
VALID_ATTRIBUTES = {
    "LEI": "5493001KJTIIGC8Y1R12",
    "legalName": "Acme Corporation",
    "i": "ETestIssuee000000000000000000000000000000",
}

# Invalid attributes (missing required field)
INVALID_ATTRIBUTES_MISSING = {
    "LEI": "5493001KJTIIGC8Y1R12",
    # Missing "legalName"
}

# Invalid attributes (wrong type)
INVALID_ATTRIBUTES_TYPE = {
    "LEI": 12345,  # Should be string
    "legalName": "Acme Corporation",
}


class TestSchemaValidator:
    """Tests for validate_acdc_against_schema."""

    def test_valid_attributes_pass(self):
        """Attributes matching schema should pass validation."""
        errors = validate_acdc_against_schema(VALID_ATTRIBUTES, SAMPLE_SCHEMA)
        assert errors == []

    def test_missing_required_field_fails(self):
        """Missing required field should return errors."""
        errors = validate_acdc_against_schema(INVALID_ATTRIBUTES_MISSING, SAMPLE_SCHEMA)
        assert len(errors) > 0
        assert any("legalName" in err for err in errors)

    def test_wrong_type_fails(self):
        """Wrong field type should return errors."""
        errors = validate_acdc_against_schema(INVALID_ATTRIBUTES_TYPE, SAMPLE_SCHEMA)
        assert len(errors) > 0
        assert any("LEI" in err or "type" in err.lower() for err in errors)

    def test_empty_attributes_fails(self):
        """Empty attributes should return error."""
        errors = validate_acdc_against_schema({}, SAMPLE_SCHEMA)
        assert len(errors) > 0

    def test_none_attributes_fails(self):
        """None attributes should return error."""
        errors = validate_acdc_against_schema(None, SAMPLE_SCHEMA)
        assert len(errors) > 0

    def test_empty_schema_fails(self):
        """Empty schema should return error."""
        errors = validate_acdc_against_schema(VALID_ATTRIBUTES, {})
        assert len(errors) > 0

    def test_none_schema_fails(self):
        """None schema should return error."""
        errors = validate_acdc_against_schema(VALID_ATTRIBUTES, None)
        assert len(errors) > 0

    def test_max_errors_limit(self):
        """Should limit errors to max_errors."""
        # Schema requiring many fields
        strict_schema = {
            "type": "object",
            "required": ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l"],
        }
        errors = validate_acdc_against_schema({}, strict_schema, max_errors=3)
        # Should have 3 errors + "and more" message
        assert len(errors) <= 4


class TestSchemaHelpers:
    """Tests for schema helper functions."""

    def test_get_required_fields(self):
        """Should extract required fields from schema."""
        required = get_required_fields(SAMPLE_SCHEMA)
        assert "LEI" in required
        assert "legalName" in required

    def test_get_required_fields_empty(self):
        """Should return empty list for schema without required."""
        required = get_required_fields({"type": "object"})
        assert required == []

    def test_get_schema_type_from_id(self):
        """Should get schema type from $id."""
        schema_type = get_schema_type(SAMPLE_SCHEMA)
        assert schema_type == SAMPLE_SCHEMA["$id"]

    def test_get_schema_type_from_title(self):
        """Should fall back to title if no $id."""
        schema = {"title": "Test Schema", "type": "object"}
        schema_type = get_schema_type(schema)
        assert schema_type == "Test Schema"

    def test_is_valid_json_schema_true(self):
        """Valid schema should return True."""
        assert is_valid_json_schema(SAMPLE_SCHEMA) is True

    def test_is_valid_json_schema_false(self):
        """Invalid schema should return False."""
        invalid = {"type": "not-a-type"}
        assert is_valid_json_schema(invalid) is False


class TestComputeSchemaSaid:
    """Tests for SAID computation."""

    def test_compute_schema_said_format(self):
        """Computed SAID should have correct format."""
        # Create a test schema
        test_schema = {
            "$id": "E" + "#" * 43,  # 44-char placeholder
            "type": "object",
            "properties": {"name": {"type": "string"}},
        }
        said = compute_schema_said(test_schema)

        # SAID should be 44 characters starting with 'E'
        assert len(said) == 44
        assert said.startswith("E")

    def test_compute_schema_said_deterministic(self):
        """Same schema should produce same SAID."""
        test_schema = {
            "$id": "E" + "#" * 43,
            "type": "object",
            "properties": {"name": {"type": "string"}},
        }
        said1 = compute_schema_said(test_schema)
        said2 = compute_schema_said(test_schema)
        assert said1 == said2

    def test_compute_schema_said_different_for_different_schemas(self):
        """Different schemas should produce different SAIDs."""
        schema1 = {"$id": "E" + "#" * 43, "type": "object", "properties": {"a": {}}}
        schema2 = {"$id": "E" + "#" * 43, "type": "object", "properties": {"b": {}}}
        said1 = compute_schema_said(schema1)
        said2 = compute_schema_said(schema2)
        assert said1 != said2

    def test_compute_schema_said_preserves_code(self):
        """SAID should use derivation code from original $id."""
        test_schema = {
            "$id": "E" + "x" * 43,  # 'E' code
            "type": "object",
        }
        said = compute_schema_said(test_schema)
        assert said.startswith("E")


class TestVerifySchemaSaid:
    """Tests for SAID verification."""

    def test_verify_matching_said(self):
        """Matching SAID should return True."""
        # Create schema and compute its SAID
        test_schema = {
            "$id": "E" + "#" * 43,
            "type": "object",
        }
        computed_said = compute_schema_said(test_schema)

        # Update schema with computed SAID
        test_schema["$id"] = computed_said

        # Verify should pass
        assert verify_schema_said(test_schema, computed_said) is True

    def test_verify_mismatched_said(self):
        """Mismatched SAID should return False."""
        test_schema = {
            "$id": "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao",
            "type": "object",
        }
        wrong_said = "EWrongSAID00000000000000000000000000000000"
        assert verify_schema_said(test_schema, wrong_said) is False


class TestFetchSchema:
    """Tests for schema fetching."""

    @pytest.fixture(autouse=True)
    def clear_cache(self):
        """Clear schema cache before each test."""
        clear_schema_cache()
        yield
        clear_schema_cache()

    @pytest.mark.asyncio
    async def test_fetch_schema_success(self):
        """Should fetch schema from registry."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = SAMPLE_SCHEMA

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_instance.get.return_value = mock_response
            mock_instance.__aenter__.return_value = mock_instance
            mock_instance.__aexit__.return_value = None
            mock_client.return_value = mock_instance

            result = await fetch_schema("ETestSAID000000000000000000000000000000000")
            assert result == SAMPLE_SCHEMA

    @pytest.mark.asyncio
    async def test_fetch_schema_cache_hit(self):
        """Should return cached schema on second call."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = SAMPLE_SCHEMA

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_instance.get.return_value = mock_response
            mock_instance.__aenter__.return_value = mock_instance
            mock_instance.__aexit__.return_value = None
            mock_client.return_value = mock_instance

            # First call - fetches from network
            said = "ETestSAID000000000000000000000000000000000"
            result1 = await fetch_schema(said)

            # Second call - should use cache
            result2 = await fetch_schema(said)

            # Only one network call should have been made
            assert mock_instance.get.call_count == 1
            assert result1 == result2

    @pytest.mark.asyncio
    async def test_fetch_schema_all_registries_fail(self):
        """Should raise ResolutionFailedError if all registries fail."""
        mock_response = MagicMock()
        mock_response.status_code = 404

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_instance.get.return_value = mock_response
            mock_instance.__aenter__.return_value = mock_instance
            mock_instance.__aexit__.return_value = None
            mock_client.return_value = mock_instance

            with pytest.raises(ResolutionFailedError) as exc_info:
                await fetch_schema("ENotFound0000000000000000000000000000000")

            assert "Failed to fetch schema" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_fetch_schema_tries_multiple_registries(self):
        """Should try multiple registries if first fails."""
        # First registry returns 404, second returns success
        fail_response = MagicMock()
        fail_response.status_code = 404

        success_response = MagicMock()
        success_response.status_code = 200
        success_response.json.return_value = SAMPLE_SCHEMA

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_instance.get.side_effect = [fail_response, success_response]
            mock_instance.__aenter__.return_value = mock_instance
            mock_instance.__aexit__.return_value = None
            mock_client.return_value = mock_instance

            result = await fetch_schema("ETestSAID000000000000000000000000000000000")
            assert result == SAMPLE_SCHEMA
            # Should have tried both registries
            assert mock_instance.get.call_count == 2


class TestGetSchemaForValidation:
    """Tests for get_schema_for_validation."""

    @pytest.fixture(autouse=True)
    def clear_cache(self):
        """Clear schema cache before each test."""
        clear_schema_cache()
        yield
        clear_schema_cache()

    @pytest.mark.asyncio
    async def test_embedded_schema_valid(self):
        """Should accept embedded schema with valid SAID."""
        # Create embedded schema with valid SAID
        embedded = {"$id": "E" + "#" * 43, "type": "object"}
        computed_said = compute_schema_said(embedded)
        embedded["$id"] = computed_said

        # Create ACDC with embedded schema
        acdc = ACDC(
            version="ACDC10JSON000000_",
            said="ETestACDC0000000000000000000000000000000",
            issuer_aid="ETestIssuer0000000000000000000000000000",
            schema_said=computed_said,
            attributes={"test": "value"},
            edges=None,
            raw={"d": "ETestACDC", "i": "ETestIssuer", "s": embedded, "a": {}},
        )

        schema_doc, status = await get_schema_for_validation(acdc)
        assert status == ClaimStatus.VALID
        assert schema_doc == embedded

    @pytest.mark.asyncio
    async def test_embedded_schema_said_mismatch(self):
        """Should raise ACDCChainInvalid for embedded schema SAID mismatch."""
        embedded = {"$id": "EWrongSAID00000000000000000000000000000000", "type": "object"}

        acdc = ACDC(
            version="ACDC10JSON000000_",
            said="ETestACDC0000000000000000000000000000000",
            issuer_aid="ETestIssuer0000000000000000000000000000",
            schema_said="EDifferentSAID00000000000000000000000000",
            attributes={},
            edges=None,
            raw={"d": "ETestACDC", "i": "ETestIssuer", "s": embedded, "a": {}},
        )

        with pytest.raises(ACDCChainInvalid) as exc_info:
            await get_schema_for_validation(acdc)
        assert "SAID mismatch" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_referenced_schema_unavailable(self):
        """Should return INDETERMINATE when schema cannot be fetched."""
        acdc = ACDC(
            version="ACDC10JSON000000_",
            said="ETestACDC0000000000000000000000000000000",
            issuer_aid="ETestIssuer0000000000000000000000000000",
            schema_said="ENotFound0000000000000000000000000000000",
            attributes={},
            edges=None,
            raw={"d": "ETestACDC", "s": "ENotFound0000000000000000000000000000000", "a": {}},
        )

        mock_response = MagicMock()
        mock_response.status_code = 404

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_instance.get.return_value = mock_response
            mock_instance.__aenter__.return_value = mock_instance
            mock_instance.__aexit__.return_value = None
            mock_client.return_value = mock_instance

            schema_doc, status = await get_schema_for_validation(acdc)
            assert status == ClaimStatus.INDETERMINATE
            assert schema_doc == {}

    @pytest.mark.asyncio
    async def test_no_schema_said(self):
        """Should return INDETERMINATE when no schema SAID declared."""
        acdc = ACDC(
            version="ACDC10JSON000000_",
            said="ETestACDC0000000000000000000000000000000",
            issuer_aid="ETestIssuer0000000000000000000000000000",
            schema_said=None,
            attributes={},
            edges=None,
            raw={"d": "ETestACDC", "a": {}},
        )

        schema_doc, status = await get_schema_for_validation(acdc)
        assert status == ClaimStatus.INDETERMINATE
        assert schema_doc == {}


class TestCacheStats:
    """Tests for cache statistics."""

    @pytest.fixture(autouse=True)
    def clear_cache(self):
        """Clear schema cache before each test."""
        clear_schema_cache()
        yield
        clear_schema_cache()

    def test_empty_cache_stats(self):
        """Empty cache should have size 0."""
        stats = get_cache_stats()
        assert stats["size"] == 0
        assert stats["saids"] == []

    @pytest.mark.asyncio
    async def test_cache_stats_after_fetch(self):
        """Cache stats should reflect fetched schemas."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = SAMPLE_SCHEMA

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_instance.get.return_value = mock_response
            mock_instance.__aenter__.return_value = mock_instance
            mock_instance.__aexit__.return_value = None
            mock_client.return_value = mock_instance

            said = "ETestSAID000000000000000000000000000000000"
            await fetch_schema(said)

            stats = get_cache_stats()
            assert stats["size"] == 1
            assert said in stats["saids"]


# =============================================================================
# Additional schema_validator.py coverage tests - Phase 6
# =============================================================================


class TestSchemaValidatorCoverage:
    """Additional tests for schema_validator.py coverage."""

    def test_max_errors_exceeded(self):
        """When errors exceed max_errors, truncation message is added."""
        # Schema that will produce many errors
        strict_schema = {
            "$schema": "http://json-schema.org/draft-07/schema#",
            "type": "object",
            "properties": {
                "field1": {"type": "integer"},
                "field2": {"type": "integer"},
                "field3": {"type": "integer"},
                "field4": {"type": "integer"},
                "field5": {"type": "integer"},
                "field6": {"type": "integer"},
                "field7": {"type": "integer"},
                "field8": {"type": "integer"},
                "field9": {"type": "integer"},
                "field10": {"type": "integer"},
                "field11": {"type": "integer"},
            },
            "required": [
                "field1", "field2", "field3", "field4", "field5",
                "field6", "field7", "field8", "field9", "field10", "field11",
            ],
        }

        # Attributes with wrong types (all strings instead of integers)
        bad_attributes = {
            f"field{i}": "not_an_integer" for i in range(1, 12)
        }

        errors = validate_acdc_against_schema(bad_attributes, strict_schema, max_errors=5)

        # Should have truncation message
        assert len(errors) == 6  # 5 errors + truncation message
        assert "stopped at 5" in errors[-1]

    def test_invalid_schema_document(self):
        """Invalid schema document returns SchemaError message."""
        # Invalid schema (bad type value)
        invalid_schema = {
            "$schema": "http://json-schema.org/draft-07/schema#",
            "type": "not_a_valid_type",  # Invalid type
        }

        attributes = {"some": "data"}

        errors = validate_acdc_against_schema(attributes, invalid_schema)

        # Should have error about invalid schema
        assert len(errors) >= 1
        # The validator should catch this as either a validation error or schema error

    def test_exception_during_validation(self):
        """Unexpected exception during validation is caught and logged."""
        # This is hard to trigger naturally, so we'll use mocking
        with patch(
            "app.vvp.acdc.schema_validator.Draft7Validator",
            side_effect=RuntimeError("Unexpected error")
        ):
            errors = validate_acdc_against_schema(
                {"key": "value"},
                SAMPLE_SCHEMA
            )

        assert len(errors) == 1
        assert "Validation error" in errors[0]
        assert "Unexpected error" in errors[0]

    def test_is_valid_json_schema_with_invalid_schema(self):
        """is_valid_json_schema returns False for invalid schema."""
        invalid_schema = {
            "$schema": "http://json-schema.org/draft-07/schema#",
            "type": "not_valid",  # Invalid type keyword
        }

        result = is_valid_json_schema(invalid_schema)
        assert result is False

    def test_is_valid_json_schema_with_valid_schema(self):
        """is_valid_json_schema returns True for valid schema."""
        valid_schema = {
            "$schema": "http://json-schema.org/draft-07/schema#",
            "type": "object",
            "properties": {
                "name": {"type": "string"}
            }
        }

        result = is_valid_json_schema(valid_schema)
        assert result is True

    def test_empty_attributes_returns_error(self):
        """Empty attributes dict returns specific error."""
        errors = validate_acdc_against_schema({}, SAMPLE_SCHEMA)
        assert len(errors) >= 1
        # Either "empty or missing" error or schema validation errors for missing required fields

    def test_none_attributes_returns_error(self):
        """None attributes returns specific error."""
        errors = validate_acdc_against_schema(None, SAMPLE_SCHEMA)
        assert len(errors) == 1
        assert "empty or missing" in errors[0]

    def test_empty_schema_returns_error(self):
        """Empty schema document returns specific error."""
        errors = validate_acdc_against_schema({"key": "value"}, {})
        assert len(errors) == 1
        assert "Schema document is empty" in errors[0]

    def test_none_schema_returns_error(self):
        """None schema returns specific error."""
        errors = validate_acdc_against_schema({"key": "value"}, None)
        assert len(errors) == 1
        assert "Schema document is empty" in errors[0]
