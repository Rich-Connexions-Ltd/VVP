"""ACDC attribute validation against JSON Schema.

Per VVP §5.1.1-2.8.3, validation must compare data structure and values
against the declared schema.
"""

import logging
from typing import Any, Dict, List, Optional

try:
    import jsonschema
    from jsonschema import Draft7Validator, ValidationError
    JSONSCHEMA_AVAILABLE = True
except ImportError:
    JSONSCHEMA_AVAILABLE = False
    Draft7Validator = None
    ValidationError = Exception

log = logging.getLogger(__name__)


def _extract_attributes_schema(schema_doc: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Extract the attributes ('a' field) schema from a full ACDC schema.

    ACDC schemas typically define the entire ACDC structure with 'a' being
    either a SAID string reference or an object with properties. This function
    extracts the object variant for attribute validation.

    Args:
        schema_doc: The full ACDC schema document

    Returns:
        The attributes schema dict if found, None otherwise
    """
    # Check if this is a full ACDC schema with 'a' in properties
    properties = schema_doc.get("properties", {})
    a_schema = properties.get("a")

    if not a_schema:
        # Not a full ACDC schema or no 'a' field defined
        # Fall back to using the full schema (might be attributes-only schema)
        return None

    # Handle oneOf pattern (SAID string or object)
    if "oneOf" in a_schema:
        for option in a_schema["oneOf"]:
            if option.get("type") == "object":
                return option
        # No object variant found
        return None

    # Direct object schema
    if a_schema.get("type") == "object":
        return a_schema

    # SAID string reference only
    if a_schema.get("type") == "string":
        return None

    return None


def validate_acdc_against_schema(
    acdc_attributes: Dict[str, Any],
    schema_doc: Dict[str, Any],
    max_errors: int = 10,
) -> List[str]:
    """Validate ACDC attributes conform to schema.

    Uses JSON Schema Draft 7 validation (common for vLEI schemas).
    Automatically extracts the attributes schema from full ACDC schemas.

    Args:
        acdc_attributes: The ACDC 'a' field (attributes dict)
        schema_doc: The schema document (JSON Schema format) - can be full
            ACDC schema or attributes-only schema
        max_errors: Maximum validation errors to collect

    Returns:
        List of validation errors (empty if valid)
    """
    if not JSONSCHEMA_AVAILABLE:
        log.warning("jsonschema library not available, skipping schema validation")
        return []

    if not acdc_attributes:
        return ["ACDC attributes are empty or missing"]

    if not schema_doc:
        return ["Schema document is empty"]

    # Try to extract attributes schema from full ACDC schema
    attributes_schema = _extract_attributes_schema(schema_doc)
    if attributes_schema:
        log.debug("Using extracted attributes schema for validation")
        validation_schema = attributes_schema
    else:
        # Fall back to full schema (might be attributes-only or custom schema)
        log.debug("Using full schema for validation (no 'a' field found)")
        validation_schema = schema_doc

    errors: List[str] = []

    try:
        # Use Draft 7 validator (most common for ACDC schemas)
        validator = Draft7Validator(validation_schema)

        for error in validator.iter_errors(acdc_attributes):
            if len(errors) >= max_errors:
                errors.append(f"... and more errors (stopped at {max_errors})")
                break

            # Format error message with path
            path = ".".join(str(p) for p in error.absolute_path) if error.absolute_path else "(root)"
            errors.append(f"{path}: {error.message}")

    except jsonschema.SchemaError as e:
        # Invalid schema document
        errors.append(f"Invalid schema: {e.message}")
    except Exception as e:
        # Unexpected error
        log.exception(f"Schema validation error: {e}")
        errors.append(f"Validation error: {str(e)}")

    return errors


def get_required_fields(schema_doc: Dict[str, Any]) -> List[str]:
    """Extract required fields from a JSON Schema.

    Useful for debugging and error messages.

    Args:
        schema_doc: The schema document

    Returns:
        List of required field names at top level
    """
    return schema_doc.get("required", [])


def get_schema_type(schema_doc: Dict[str, Any]) -> Optional[str]:
    """Get the schema type from $id or title.

    Args:
        schema_doc: The schema document

    Returns:
        Schema type identifier or None
    """
    # Try $id first (contains SAID)
    schema_id = schema_doc.get("$id", "")
    if schema_id:
        return schema_id

    # Fall back to title
    return schema_doc.get("title")


def is_valid_json_schema(schema_doc: Dict[str, Any]) -> bool:
    """Check if a document is a valid JSON Schema.

    Args:
        schema_doc: The document to check

    Returns:
        True if valid JSON Schema structure
    """
    if not JSONSCHEMA_AVAILABLE:
        # Can't validate without library, assume valid
        return True

    try:
        Draft7Validator.check_schema(schema_doc)
        return True
    except jsonschema.SchemaError:
        return False
