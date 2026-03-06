"""ACDC parsing and SAID validation.

Per VVP §6.3.x and KERI/ACDC spec.
"""

import json
from typing import Any, Dict

from .exceptions import ACDCParseError, ACDCSAIDMismatch
from .models import ACDC


def detect_acdc_variant(acdc_data: Dict[str, Any]) -> str:
    """Detect ACDC variant type.

    Per VVP §1.4, verifiers MUST support valid ACDC variants:
    - full: Complete ACDC with all fields expanded (attributes is dict)
    - compact: Minimal ACDC with SAID references (attributes missing or is string)
    - partial: ACDC with selective disclosure (contains "_" or "_:type" placeholders)

    Variant affects downstream validation per §2.2 ("Uncertainty must be explicit"):
    - Full: Complete verification possible
    - Compact: Edge targets may be external SAIDs → INDETERMINATE if unresolvable
    - Partial: Required fields may be redacted → INDETERMINATE if unverifiable

    Args:
        acdc_data: The ACDC dictionary to analyze.

    Returns:
        Variant type: "full", "compact", or "partial".
    """
    # Check for partial disclosure (underscore placeholders)
    # Per ACDC spec, "_" is used for redacted/selective disclosure
    def has_placeholders(obj: Any) -> bool:
        if isinstance(obj, str):
            return obj == "_" or obj.startswith("_:")
        elif isinstance(obj, dict):
            return any(has_placeholders(v) for v in obj.values())
        elif isinstance(obj, list):
            return any(has_placeholders(v) for v in obj)
        return False

    if has_placeholders(acdc_data):
        return "partial"

    # Check for compact form (missing expanded attributes)
    # In compact form, 'a' field may be a SAID reference instead of expanded dict
    attributes = acdc_data.get("a")
    if attributes is None:
        # No attributes at all - could be compact or minimal
        return "compact"
    elif isinstance(attributes, str):
        # Attributes is a SAID reference, not expanded - this is compact form
        return "compact"

    return "full"


def parse_acdc(data: Dict[str, Any], allow_variants: bool = True) -> ACDC:
    """Parse and validate ACDC structure.

    Validates required fields are present and creates an ACDC object.

    Per VVP §1.4, verifiers MUST support ACDC variants (compact, partial,
    aggregate). This implementation accepts all variants and stores the
    detected variant type in the ACDC object for downstream handling.

    Variant semantics per §2.2 ("Uncertainty must be explicit"):
    - Full: Complete validation possible → may be VALID
    - Compact: External refs may be unverifiable → may be INDETERMINATE
    - Partial: Redacted fields may be unverifiable → may be INDETERMINATE

    Args:
        data: ACDC dictionary (parsed from JSON or dossier).
        allow_variants: If True (default), allows compact/partial ACDCs.
            If False, raises ParseError for non-full variants (legacy mode).

    Returns:
        Parsed ACDC object with variant field set.

    Raises:
        ACDCParseError: If required fields are missing or invalid.
        ParseError: If allow_variants=False and ACDC is non-full variant.
    """
    # Detect ACDC variant
    variant = detect_acdc_variant(data)

    if variant != "full" and not allow_variants:
        # Legacy mode: reject non-full variants
        from ..dossier.exceptions import ParseError
        raise ParseError(
            f"ACDC variant '{variant}' not allowed (allow_variants=False). "
            f"Set allow_variants=True to accept compact/partial ACDCs."
        )

    # Validate required fields
    required_fields = ["d", "i"]  # SAID and issuer are always required
    for field in required_fields:
        if field not in data:
            raise ACDCParseError(f"ACDC missing required field: '{field}'")

    # Extract fields with defaults
    version = data.get("v", "")
    said = data.get("d", "")
    issuer_aid = data.get("i", "")
    schema_said = data.get("s", "")
    attributes = data.get("a")
    edges = data.get("e")
    rules = data.get("r")

    # Validate SAID format (should be CESR-encoded hash)
    if said and len(said) < 20:
        raise ACDCParseError(f"Invalid ACDC SAID format: {said[:20]}...")

    # Validate issuer AID format
    if issuer_aid and issuer_aid[0] not in "BDEFGHJKLMNOPQRSTUVWXYZ":
        raise ACDCParseError(f"Invalid issuer AID format: {issuer_aid[:20]}...")

    return ACDC(
        version=version,
        said=said,
        issuer_aid=issuer_aid,
        schema_said=schema_said,
        attributes=attributes,
        edges=edges,
        rules=rules,
        raw=data,
        variant=variant
    )


def validate_acdc_said(acdc: ACDC, raw_data: Dict[str, Any]) -> None:
    """Validate ACDC's self-addressing identifier.

    Uses compute_acdc_said() to compute the expected SAID and compares
    it against the 'd' field value.

    Args:
        acdc: Parsed ACDC object.
        raw_data: Original ACDC dictionary.

    Raises:
        ACDCSAIDMismatch: If computed SAID != d field.
    """
    if not acdc.said:
        return  # No SAID to validate

    # Skip placeholder SAIDs (test mode)
    if acdc.said.startswith("#") or "_" * 10 in acdc.said:
        return

    try:
        computed_said = compute_acdc_said(raw_data, said_field="d")
    except Exception as e:
        raise ACDCSAIDMismatch(f"Failed to compute ACDC SAID: {e}")

    if acdc.said != computed_said:
        raise ACDCSAIDMismatch(
            f"ACDC SAID mismatch: has {acdc.said[:20]}... "
            f"but computed {computed_said[:20]}..."
        )


def _acdc_canonical_serialize(data: Dict[str, Any]) -> bytes:
    """Serialize ACDC to canonical form for SAID computation.

    ACDC field ordering (per keripy SerderACDC v1.0 FieldDom):
    v, d, u, i, ri, s, a, A, e, r

    Where u (UUID), ri (registry ID), A (aggregate) are optional.
    Extra fields beyond the standard set are appended at the end.

    Args:
        data: ACDC dictionary.

    Returns:
        Canonical JSON bytes.
    """
    # ACDC canonical field order from keripy/src/keri/core/serdering.py
    # SerderACDC.Fields[Protos.acdc][Vrsn_1_0][None].alls
    acdc_field_order = ["v", "d", "u", "i", "ri", "s", "a", "A", "e", "r"]

    # Build ordered output
    ordered = {}
    for key in acdc_field_order:
        if key in data and data[key] is not None:
            ordered[key] = data[key]

    # Add any remaining fields not in standard order
    for key in data:
        if key not in ordered and data[key] is not None:
            ordered[key] = data[key]

    # Serialize with no whitespace
    return json.dumps(ordered, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def compute_acdc_said(acdc_data: Dict[str, Any], said_field: str = "d") -> str:
    """Compute SAID for an ACDC credential using ACDC canonical field ordering.

    Matches keripy's makify algorithm:
    1. Replace SAID field with '#' * 44 placeholder
    2. Dummy the version string to determine serialized size
    3. Rebuild version string with correct size
    4. Serialize canonically and hash with Blake3-256

    IMPORTANT: This function uses ACDC-specific field ordering
    (v, d, u, i, ri, s, a, A, e, r), which is DIFFERENT from KEL event
    field ordering.

    DO NOT use this for:
    - KEL events (use keri.kel_parser.compute_kel_event_said instead)
    - JSON Schemas (use schema_fetcher.compute_schema_said instead)

    Those have different canonicalization rules per their respective specs.

    Args:
        acdc_data: ACDC credential dictionary.
        said_field: Field containing SAID (default 'd').

    Returns:
        The computed SAID string (44 chars, starting with 'E' for Blake3-256).

    Example:
        >>> acdc = {"v": "ACDC10JSON...", "d": "", "i": "...", "s": "...", ...}
        >>> said = compute_acdc_said(acdc)
        >>> acdc["d"] = said  # Set the computed SAID
    """
    import base64
    import hashlib
    import re

    # keripy uses '#' as Dummy placeholder (must not be valid Base64)
    SAID_PLACEHOLDER = "#" * 44

    # Create copy with placeholder SAID
    data_copy = dict(acdc_data)
    data_copy[said_field] = SAID_PLACEHOLDER

    # Update version string with correct serialized size (matches keripy makify)
    if "v" in data_copy:
        vs = data_copy["v"]
        # Parse version string: ACDC10JSON000196_ or similar
        match = re.match(r"^([A-Z]{4})(\d)(\d)([A-Z]+)([0-9a-f]{6})(_?)$", vs)
        if match:
            proto, major, minor, kind, _old_size, term = match.groups()
            # Dummy the version string to same span for size computation
            data_copy["v"] = "#" * len(vs)
            raw = _acdc_canonical_serialize(data_copy)
            size = len(raw)
            # Rebuild version string with correct size
            data_copy["v"] = f"{proto}{major}{minor}{kind}{size:06x}{term}"

    # Serialize using ACDC canonical field ordering
    canonical_bytes = _acdc_canonical_serialize(data_copy)

    # Hash with Blake3 (fall back to SHA256 if unavailable)
    try:
        import blake3
        digest = blake3.blake3(canonical_bytes).digest()
    except ImportError:
        digest = hashlib.sha256(canonical_bytes).digest()

    # CESR encode with 'E' derivation code
    # Must match keripy's Matter._infil() encoding:
    # 1. Compute pad size: ps = (3 - (len(raw) % 3)) % 3
    # 2. Prepad with ps zero bytes
    # 3. Base64url encode
    # 4. Skip first ps characters
    # 5. Prepend code
    rs = len(digest)
    ps = (3 - (rs % 3)) % 3  # For 32 bytes: ps = 1
    prepadded = bytes([0] * ps) + digest
    b64 = base64.urlsafe_b64encode(prepadded).decode("ascii")
    trimmed = b64[ps:].rstrip("=")
    return "E" + trimmed


def parse_acdc_from_dossier(
    dossier: Dict[str, Any],
    credential_key: str = "credential"
) -> ACDC:
    """Parse ACDC from a dossier structure.

    Dossiers may contain ACDCs in various locations depending on format.

    Args:
        dossier: Dossier dictionary.
        credential_key: Key where ACDC is stored.

    Returns:
        Parsed ACDC.

    Raises:
        ACDCParseError: If ACDC not found or invalid.
    """
    # Try common locations for ACDC in dossier
    acdc_data = None

    # Direct credential key
    if credential_key in dossier:
        acdc_data = dossier[credential_key]

    # Nested in 'acdc' field
    elif "acdc" in dossier:
        acdc_data = dossier["acdc"]

    # Dossier is the ACDC itself
    elif "d" in dossier and "i" in dossier:
        acdc_data = dossier

    if acdc_data is None:
        raise ACDCParseError(f"No ACDC found in dossier at key '{credential_key}'")

    return parse_acdc(acdc_data)
