"""SAID computation for JSON Schema documents.

This module provides SAID (Self-Addressing Identifier) computation
for JSON Schemas using keripy's Saider class. This ensures correct
KERI-compliant canonicalization and Blake3-256 hashing.

SAID is used as the schema's $id field, providing cryptographic
verification that the schema content has not been modified.
"""

import logging
from typing import Any

from keri.core.coring import MtrDex, Saider

log = logging.getLogger(__name__)


class SAIDComputationError(Exception):
    """Raised when SAID computation fails."""

    pass


class SAIDVerificationError(Exception):
    """Raised when SAID verification fails."""

    pass


def compute_schema_said(schema: dict[str, Any]) -> str:
    """Compute SAID for a JSON Schema.

    Uses keripy's Saider.saidify() which handles:
    - Placeholder injection (44 '#' chars)
    - KERI canonical JSON serialization
    - Blake3-256 hashing
    - CESR encoding

    Args:
        schema: JSON Schema dict. Must have $id field (can be empty/placeholder).

    Returns:
        44-character CESR-encoded SAID string (e.g., "ENPXp1vQ...").

    Raises:
        SAIDComputationError: If SAID computation fails.
    """
    # Ensure schema has $id field (required for saidify)
    if "$id" not in schema:
        raise SAIDComputationError("Schema missing required $id field")

    try:
        saider, _ = Saider.saidify(sad=schema, label="$id", code=MtrDex.Blake3_256)
        return saider.qb64
    except Exception as e:
        raise SAIDComputationError(f"SAID computation failed: {e}") from e


def inject_said(schema: dict[str, Any]) -> dict[str, Any]:
    """Compute SAID and inject into schema $id field.

    Creates a copy of the schema with the computed SAID injected
    into the $id field.

    Args:
        schema: JSON Schema dict. Must have $id field (can be empty/placeholder).

    Returns:
        New schema dict with computed $id SAID.

    Raises:
        SAIDComputationError: If SAID computation fails.
    """
    # Ensure schema has $id field (required for saidify)
    if "$id" not in schema:
        raise SAIDComputationError("Schema missing required $id field")

    try:
        _, saidified = Saider.saidify(sad=schema, label="$id", code=MtrDex.Blake3_256)
        return saidified
    except Exception as e:
        raise SAIDComputationError(f"SAID injection failed: {e}") from e


def verify_schema_said(schema: dict[str, Any]) -> bool:
    """Verify that a schema's $id matches its computed SAID.

    Args:
        schema: JSON Schema dict with $id field containing SAID.

    Returns:
        True if $id matches computed SAID, False otherwise.

    Raises:
        SAIDVerificationError: If verification cannot be performed.
    """
    if "$id" not in schema:
        raise SAIDVerificationError("Schema missing required $id field")

    stored_said = schema["$id"]
    if not stored_said or stored_said.startswith("#"):
        raise SAIDVerificationError("Schema $id is empty or placeholder")

    try:
        computed_said = compute_schema_said(schema)
        return stored_said == computed_said
    except SAIDComputationError as e:
        raise SAIDVerificationError(f"Cannot verify SAID: {e}") from e


def create_schema_template(
    title: str,
    description: str = "",
    credential_type: str = "VerifiableCredential",
    properties: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Create a JSON Schema template for ACDC credentials.

    Creates a basic JSON Schema structure suitable for ACDC credentials.
    The $id field is set to a placeholder; use inject_said() to compute
    and inject the actual SAID.

    Args:
        title: Schema title.
        description: Schema description.
        credential_type: Credential type name.
        properties: Additional properties to include in the schema.

    Returns:
        JSON Schema dict with placeholder $id.
    """
    # SAID placeholder (44 chars)
    placeholder = "#" * 44

    schema = {
        "$id": placeholder,
        "$schema": "http://json-schema.org/draft-07/schema#",
        "title": title,
        "description": description or f"Schema for {title}",
        "type": "object",
        "credentialType": credential_type,
        "version": "1.0.0",
        "properties": {
            "v": {"description": "Version", "type": "string"},
            "d": {"description": "Credential SAID", "type": "string"},
            "i": {"description": "Issuer AID", "type": "string"},
            "ri": {"description": "Registry identifier", "type": "string"},
            "s": {"description": "Schema SAID", "type": "string"},
            "a": {
                "description": "Attributes",
                "type": "object",
                "properties": properties or {},
            },
        },
        "additionalProperties": False,
        "required": ["v", "d", "i", "ri", "s", "a"],
    }

    return schema
