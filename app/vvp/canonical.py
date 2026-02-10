# Copyright (c) Rich Connexions Ltd. All rights reserved.
# Licensed under the MIT License. See LICENSE for details.

"""KERI canonical serialization.

Implements deterministic JSON serialization following KERI field ordering
rules. Every KERI event type has a normative field order; this module
re-orders arbitrary dicts to that canonical form before serializing to
compact JSON (no whitespace).

The ``most_compact_form`` helper additionally replaces the SAID field with
a ``#``-padded placeholder so that the SAID can be verified by hashing the
serialized output.

References
----------
- KID0003 — Serialization
- KID0009 — Receipt Events
- KERI spec §11 — Field ordering tables
"""

from __future__ import annotations

import json
import re
from typing import Dict, List, Optional, Sequence, Union

__all__ = [
    "FIELD_ORDER",
    "canonical_serialize",
    "most_compact_form",
    "CanonicalSerializationError",
]


class CanonicalSerializationError(Exception):
    """Raised when an event cannot be canonically serialized."""


# ---------------------------------------------------------------------------
# Normative field orders per event type
# ---------------------------------------------------------------------------
# Each entry maps an event *type code* (the ``t`` field value) to the
# ordered list of fields that MUST appear in that order when serialized.
# Fields present in the dict but absent from the order list are appended
# alphabetically after the ordered fields.

FIELD_ORDER: Dict[str, List[str]] = {
    # --- key state events ---
    "icp": ["v", "t", "d", "i", "s", "kt", "k", "nt", "n", "bt", "b", "c", "a"],
    "rot": ["v", "t", "d", "i", "s", "p", "kt", "k", "nt", "n", "bt", "br", "ba", "c", "a"],
    "ixn": ["v", "t", "d", "i", "s", "p", "a"],
    # --- delegated key state events ---
    "dip": ["v", "t", "d", "i", "s", "kt", "k", "nt", "n", "bt", "b", "c", "a", "di"],
    "drt": ["v", "t", "d", "i", "s", "p", "kt", "k", "nt", "n", "bt", "br", "ba", "c", "a", "di"],
    # --- receipt ---
    "rct": ["v", "t", "d", "i", "s"],
    # --- TEL (transaction event log) events ---
    "vcp": ["v", "t", "d", "i", "ii", "s", "c", "bt", "b", "n"],
    "vrt": ["v", "t", "d", "i", "s", "p", "bt", "br", "ba"],
    "iss": ["v", "t", "d", "i", "s", "ri", "dt"],
    "rev": ["v", "t", "d", "i", "s", "ri", "p", "dt"],
    "bis": ["v", "t", "d", "i", "ii", "s", "ra", "dt"],
    "brv": ["v", "t", "d", "i", "ii", "s", "p", "ra", "dt"],
    # --- exchange events ---
    "exn": ["v", "t", "d", "i", "p", "dt", "r", "q", "a", "e"],
    # --- reply / expose ---
    "rpy": ["v", "t", "d", "dt", "r", "a"],
    "exp": ["v", "t", "d", "r", "a"],
    # --- query ---
    "qry": ["v", "t", "d", "dt", "r", "rr", "q"],
    # --- pro (prod) ---
    "pro": ["v", "t", "d", "dt", "r", "rr", "q"],
    # --- bar (bare) ---
    "bar": ["v", "t", "d", "r", "a"],
}

# Version string pattern: e.g.  KERI10JSON000123_
_VERSION_RE = re.compile(r"^([A-Z]{4})(\d{2})([A-Z]{4})([0-9a-f]{6})_$")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _order_dict(
    data: dict,
    field_order: Sequence[str],
) -> dict:
    """Return a new dict with keys in *field_order* first, then remaining
    keys in alphabetical order.  Values that are themselves dicts are
    **not** recursively reordered (KERI ordering is top-level only).
    """
    ordered: dict = {}
    for key in field_order:
        if key in data:
            ordered[key] = data[key]
    # Append any extra fields not in the canonical order, sorted for
    # determinism.
    for key in sorted(data.keys()):
        if key not in ordered:
            ordered[key] = data[key]
    return ordered


def _update_version_size(version_string: str, size: int) -> str:
    """Return *version_string* with the six-hex-digit size field replaced
    by *size*.

    Raises ``CanonicalSerializationError`` if the string doesn't match
    the KERI version format.
    """
    m = _VERSION_RE.match(version_string)
    if not m:
        raise CanonicalSerializationError(
            f"Invalid version string format: {version_string!r}"
        )
    return f"{m.group(1)}{m.group(2)}{m.group(3)}{size:06x}_"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def canonical_serialize(event: dict) -> bytes:
    """Serialize *event* to canonical compact JSON bytes.

    The event's ``t`` field determines which field order to apply.  If
    the event type is not in :data:`FIELD_ORDER` the fields are sorted
    alphabetically (a safe fallback producing deterministic output).

    Returns
    -------
    bytes
        UTF-8 encoded compact JSON with no whitespace.

    Raises
    ------
    CanonicalSerializationError
        If *event* is not a dict or lacks a ``t`` field.
    """
    if not isinstance(event, dict):
        raise CanonicalSerializationError(
            f"Event must be a dict, got {type(event).__name__}"
        )

    event_type: Optional[str] = event.get("t")
    if event_type is None:
        raise CanonicalSerializationError("Event dict has no 't' (type) field")

    order = FIELD_ORDER.get(event_type)
    if order is not None:
        ordered = _order_dict(event, order)
    else:
        # Unknown type — sort alphabetically for determinism
        ordered = dict(sorted(event.items()))

    return json.dumps(ordered, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def most_compact_form(
    event: dict,
    said_field: str = "d",
) -> bytes:
    """Produce the most-compact-form serialization for SAID verification.

    This replaces the SAID field value with a 44-character ``#`` placeholder
    (matching the base64url length of a Blake3-256 digest).  For self-
    addressing inception/delegation events (``icp`` / ``dip``) where the
    ``i`` field equals the ``d`` field, both are replaced.

    The version string's size component is updated to reflect the actual
    serialized byte length.

    Parameters
    ----------
    event : dict
        The KERI event dict (must contain ``t`` and *said_field*).
    said_field : str
        The key holding the SAID value (default ``"d"``).

    Returns
    -------
    bytes
        UTF-8 encoded compact JSON with SAID placeholder(s).

    Raises
    ------
    CanonicalSerializationError
        If required fields are missing.
    """
    if not isinstance(event, dict):
        raise CanonicalSerializationError(
            f"Event must be a dict, got {type(event).__name__}"
        )
    if said_field not in event:
        raise CanonicalSerializationError(
            f"Event has no '{said_field}' field for SAID placeholder"
        )

    placeholder = "#" * 44

    work = dict(event)  # shallow copy
    said_value = work[said_field]
    work[said_field] = placeholder

    # Self-addressing inception / delegation: d == i
    event_type = work.get("t")
    if event_type in ("icp", "dip") and event.get("i") == said_value:
        work["i"] = placeholder

    # Serialize with placeholder to measure size
    ordered = canonical_serialize(work)

    # Update version string if present
    if "v" in work:
        work["v"] = _update_version_size(work["v"], len(ordered))
        ordered = canonical_serialize(work)

    return ordered
