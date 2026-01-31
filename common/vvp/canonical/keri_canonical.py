"""KERI Canonical Serialization.

Implements KERI-compliant canonical serialization for events, using
the field orderings defined by keripy. This ensures signature verification
and SAID computation produce correct results.

Field orderings are derived from keripy/src/keri/core/serdering.py (v2.0.0-dev5).

This module is shared between verifier and issuer services.
"""

import json
from typing import Any, Dict, List, Optional

# Field orderings per event type from keripy (KERI Protocol v1.0)
# Source: keripy/src/keri/core/serdering.py, commit 1e2bf869
FIELD_ORDER = {
    # Key Event Log events
    "icp": ["v", "t", "d", "i", "s", "kt", "k", "nt", "n", "bt", "b", "c", "a"],
    "rot": ["v", "t", "d", "i", "s", "p", "kt", "k", "nt", "n", "bt", "br", "ba", "a"],
    "ixn": ["v", "t", "d", "i", "s", "p", "a"],
    "dip": ["v", "t", "d", "i", "s", "kt", "k", "nt", "n", "bt", "b", "c", "a", "di"],
    "drt": ["v", "t", "d", "i", "s", "p", "kt", "k", "nt", "n", "bt", "br", "ba", "a"],
    # Receipts
    "rct": ["v", "t", "d", "i", "s"],
    # Query/Reply
    "qry": ["v", "t", "d", "dt", "r", "rr", "q"],
    "rpy": ["v", "t", "d", "dt", "r", "a"],
    "pro": ["v", "t", "d", "dt", "r", "rr", "q"],
    "bar": ["v", "t", "d", "dt", "r", "a"],
    # Exchange
    "exn": ["v", "t", "d", "i", "rp", "p", "dt", "r", "q", "a", "e"],
    # TEL events
    "vcp": ["v", "t", "d", "i", "ii", "s", "c", "bt", "b", "n"],
    "vrt": ["v", "t", "d", "i", "p", "s", "bt", "br", "ba"],
    "iss": ["v", "t", "d", "i", "s", "ri", "dt"],
    "rev": ["v", "t", "d", "i", "s", "ri", "p", "dt"],
    "bis": ["v", "t", "d", "i", "ii", "s", "ra", "dt"],
    "brv": ["v", "t", "d", "i", "s", "p", "ra", "dt"],
}


class CanonicalSerializationError(Exception):
    """Raised when canonical serialization fails."""
    pass


def _order_dict(data: Dict, field_order: List[str]) -> Dict:
    """Reorder dict keys according to field order.

    Args:
        data: Dictionary to reorder.
        field_order: List of field names in desired order.

    Returns:
        Ordered dictionary with fields in specified order.
        Extra fields (not in field_order) are appended at the end.
    """
    result = {}

    # Add fields in specified order
    for field in field_order:
        if field in data:
            result[field] = data[field]

    # Add any extra fields at the end (preserves original order)
    for field in data:
        if field not in result:
            result[field] = data[field]

    return result


def canonical_serialize(event: Dict[str, Any]) -> bytes:
    """Serialize event in KERI canonical field order.

    Args:
        event: Event dictionary with 't' field indicating type.

    Returns:
        Canonical JSON bytes (no whitespace, ordered fields).

    Raises:
        CanonicalSerializationError: If event type unknown or serialization fails.
    """
    if "t" not in event:
        raise CanonicalSerializationError("Event missing 't' (type) field")

    event_type = event["t"]

    if event_type not in FIELD_ORDER:
        raise CanonicalSerializationError(f"Unknown event type: {event_type}")

    # Reorder the event fields
    ordered_event = _order_dict(event, FIELD_ORDER[event_type])

    # Serialize to JSON with no whitespace
    # Use separators=(',', ':') for most compact form
    try:
        return json.dumps(ordered_event, separators=(",", ":"), ensure_ascii=False).encode(
            "utf-8"
        )
    except (TypeError, ValueError) as e:
        raise CanonicalSerializationError(f"JSON serialization failed: {e}") from e


def most_compact_form(event: Dict[str, Any], said_field: str = "d") -> bytes:
    """Generate most compact form with placeholder SAID.

    Used for SAID computation. Replaces the SAID field with a placeholder
    of the correct length, then serializes canonically.

    The placeholder is '#' repeated for the correct SAID length (44 chars
    for Blake3-256 with 'E' derivation code prefix).

    IMPORTANT: For ICP and DIP events with self-addressing identifiers,
    both 'd' (digest) and 'i' (identifier) must be placeholdered because
    they have the same value. This matches KERI spec for self-addressing IDs.

    IMPORTANT: This function also updates the version string ('v' field) to
    reflect the correct serialized size, matching keripy's saidify behavior.

    Args:
        event: Event dictionary.
        said_field: Field containing SAID (usually 'd').

    Returns:
        Canonical bytes with placeholder SAID.

    Raises:
        CanonicalSerializationError: If serialization fails.
    """
    import re

    # SAID for Blake3-256 is 44 characters (E prefix + 43 base64 chars)
    SAID_PLACEHOLDER = "#" * 44

    # Create a copy with the placeholder
    event_copy = dict(event)
    event_copy[said_field] = SAID_PLACEHOLDER

    # For ICP and DIP events with self-addressing identifiers (d == i),
    # the 'i' field must also be placeholdered per KERI spec.
    # This applies when:
    # 1. Computing the initial SAID (d and i are both empty or placeholder)
    # 2. Validating an existing event (d == i already)
    event_type = event.get("t", "")
    if event_type in ("icp", "dip"):
        original_said = event.get(said_field, "")
        original_id = event.get("i", "")
        # Placeholder 'i' if:
        # - Both are equal (including both empty - initial SAID computation)
        # - Or 'i' is explicitly marked as placeholder
        if original_said == original_id or not original_id or original_id.startswith("#"):
            event_copy["i"] = SAID_PLACEHOLDER

    # First serialization to determine size
    raw = canonical_serialize(event_copy)

    # Update version string with correct size if present
    if "v" in event_copy:
        size = len(raw)
        vs = event_copy["v"]

        # Parse version string: KERI10JSON000154_ or similar
        # Format: {PROTO}{MAJOR}{MINOR}{KIND}{SIZE:06x}{TERM}
        match = re.match(r"^([A-Z]{4})(\d)(\d)([A-Z]+)([0-9a-f]{6})(_?)$", vs)
        if match:
            proto, major, minor, kind, _old_size, term = match.groups()
            # Reconstruct with new size
            new_vs = f"{proto}{major}{minor}{kind}{size:06x}{term}"
            event_copy["v"] = new_vs

            # Re-serialize with corrected version string
            raw = canonical_serialize(event_copy)

    return raw


def get_field_order(event_type: str) -> Optional[List[str]]:
    """Get the field order for a given event type.

    Args:
        event_type: The event type (e.g., 'icp', 'rot', 'ixn').

    Returns:
        List of field names in canonical order, or None if unknown type.
    """
    return FIELD_ORDER.get(event_type)
