"""ACDC JSON parsing per spec §6.1A.

Tier 1 implementation parses JSON structure. Tier 2 will add
full CESR parsing for native KERI formats.

ACDC field conventions:
- d: SAID (Self-Addressing Identifier)
- i: Issuer AID
- s: Schema SAID
- a: Attributes (dict or SAID string for compact form)
- e: Edges to other ACDCs
- r: Rules
"""

import json
from typing import List

from .exceptions import ParseError
from .models import ACDCNode

# Required ACDC fields per spec §6.1A
REQUIRED_FIELDS = frozenset({"d", "i", "s"})


def parse_acdc(data: dict) -> ACDCNode:
    """Parse single ACDC from dict.

    Required fields (§6.1A):
    - d: SAID (Self-Addressing Identifier)
    - i: Issuer AID
    - s: Schema SAID

    Optional fields:
    - a: Attributes (dict or SAID string for compact form)
    - e: Edges to other ACDCs
    - r: Rules

    Args:
        data: Dict parsed from JSON

    Returns:
        ACDCNode with extracted fields

    Raises:
        ParseError: If required fields missing or invalid types
    """
    if not isinstance(data, dict):
        raise ParseError(f"ACDC must be object, got {type(data).__name__}")

    missing = REQUIRED_FIELDS - set(data.keys())
    if missing:
        raise ParseError(f"Missing required ACDC fields: {sorted(missing)}")

    # Validate required field types
    said = data["d"]
    if not isinstance(said, str):
        raise ParseError(f"ACDC 'd' field must be string, got {type(said).__name__}")

    issuer = data["i"]
    if not isinstance(issuer, str):
        raise ParseError(f"ACDC 'i' field must be string, got {type(issuer).__name__}")

    schema = data["s"]
    if not isinstance(schema, str):
        raise ParseError(f"ACDC 's' field must be string, got {type(schema).__name__}")

    return ACDCNode(
        said=said,
        issuer=issuer,
        schema=schema,
        attributes=data.get("a"),
        edges=data.get("e"),
        rules=data.get("r"),
        raw=data,
    )


def parse_dossier(raw: bytes) -> List[ACDCNode]:
    """Parse dossier from raw bytes.

    Supports:
    - Single ACDC object: {...}
    - Array of ACDC objects: [{...}, {...}]

    Args:
        raw: Raw bytes from HTTP response

    Returns:
        List of ACDCNode objects

    Raises:
        ParseError: If JSON invalid or structure malformed
    """
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ParseError(f"Invalid JSON: {e}")

    if isinstance(data, dict):
        return [parse_acdc(data)]
    elif isinstance(data, list):
        if not data:
            raise ParseError("Empty ACDC array")
        return [parse_acdc(item) for item in data]
    else:
        raise ParseError(f"Expected object or array, got {type(data).__name__}")
