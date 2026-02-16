"""SAID computation for JSON Schema documents.

This module provides SAID (Self-Addressing Identifier) computation
for JSON Schemas using insertion-order JSON canonicalization and Blake3-256
hashing with CESR encoding.

SAID is used as the schema's $id field, providing cryptographic
verification that the schema content has not been modified.

Sprint 68c: Replaced keripy Saider with pure-Python implementation.
Uses insertion-order JSON serialization (no sort_keys) to match keripy's
Saider.saidify() behavior — schema SAIDs depend on key order in the
source JSON file, not alphabetical order.
"""

import base64
import json
import logging
from typing import Any

log = logging.getLogger(__name__)


import blake3 as _blake3_mod


def _blake3_hash(data: bytes) -> bytes:
    """Compute Blake3-256 hash. Blake3 is required — no fallback."""
    return _blake3_mod.blake3(data).digest()


class SAIDComputationError(Exception):
    """Raised when SAID computation fails."""

    pass


class SAIDVerificationError(Exception):
    """Raised when SAID verification fails."""

    pass


def _cesr_encode(raw: bytes, code: str = "E") -> str:
    """Encode raw bytes in CESR format with derivation code.

    For fixed-size codes like 'E' (Blake3-256, 32 bytes):
    1. Compute pad size: ps = (3 - (len(raw) % 3)) % 3
    2. Prepad raw with ps zero bytes
    3. Base64url encode the prepadded bytes
    4. Skip the first ps characters (which encode the zero padding)
    5. Prepend the derivation code

    Args:
        raw: Raw bytes to encode (e.g., 32-byte digest).
        code: Derivation code character (e.g., "E" for Blake3-256).

    Returns:
        CESR-encoded string (e.g., "ENPXp1vQ...").
    """
    ps = (3 - (len(raw) % 3)) % 3
    prepadded = bytes(ps) + raw
    b64 = base64.urlsafe_b64encode(prepadded).decode("ascii")
    trimmed = b64[ps:].rstrip("=")
    return code + trimmed


def compute_schema_said(schema: dict[str, Any]) -> str:
    """Compute SAID for a JSON Schema.

    Algorithm (matches keripy Saider.saidify):
    1. Replace $id field with '#' * 44 placeholder
    2. Serialize to JSON: insertion order, compact separators, UTF-8
    3. Compute Blake3-256 hash of serialized bytes
    4. CESR-encode hash with 'E' prefix (44 chars total)

    Key order is preserved (not sorted) to match keripy's behavior.
    Schema SAIDs depend on the key order in the source JSON file.

    Args:
        schema: JSON Schema dict. Must have $id field (can be empty/placeholder).

    Returns:
        44-character CESR-encoded SAID string (e.g., "ENPXp1vQ...").

    Raises:
        SAIDComputationError: If SAID computation fails.
    """
    if "$id" not in schema:
        raise SAIDComputationError("Schema missing required $id field")

    try:
        data_copy = dict(schema)

        # Placeholder: '#' * 44 — matches keripy Saider.Dummy * Matter.Sizes[code].fs
        data_copy["$id"] = "#" * 44

        # JSON serialization: insertion order, compact, UTF-8
        # Matches keripy dumps(): json.dumps(ked, separators=(",",":"), ensure_ascii=False)
        canonical = json.dumps(data_copy, separators=(",", ":"), ensure_ascii=False)
        canonical_bytes = canonical.encode("utf-8")

        # Blake3-256 hash → CESR encode with 'E' (Blake3-256) prefix
        digest = _blake3_hash(canonical_bytes)
        return _cesr_encode(digest, code="E")

    except SAIDComputationError:
        raise
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
    if "$id" not in schema:
        raise SAIDComputationError("Schema missing required $id field")

    try:
        said = compute_schema_said(schema)
        result = dict(schema)
        result["$id"] = said
        return result
    except SAIDComputationError:
        raise
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
