"""ACDC JSON parsing per spec §6.1A.

Tier 1 implementation parses JSON structure. Tier 2 adds
full CESR parsing for native KERI formats with signature extraction.

ACDC field conventions:
- d: SAID (Self-Addressing Identifier)
- i: Issuer AID
- s: Schema SAID
- a: Attributes (dict or SAID string for compact form)
- e: Edges to other ACDCs
- r: Rules
"""

import json
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from .exceptions import ParseError
from .models import ACDCNode

log = logging.getLogger(__name__)

# Required ACDC fields per spec §6.1A
REQUIRED_FIELDS = frozenset({"d", "i", "s"})


def _is_keri_event(obj: dict) -> bool:
    """Return True iff *obj* is positively identified as a KERI protocol event.

    Uses POSITIVE markers only. Objects not identified as KERI fall through
    to parse_acdc and may fail with a proper validation error.

    Discriminators (any one sufficient):
    1. ``"t"`` key present — KERI events always carry message-type; ACDCs never have "t".
    2. ``"v"`` starts with ``"KERI10"`` — KERI versioned messages; ACDCs use ``"ACDC10"``.
    """
    if "t" in obj:
        return True
    if isinstance(obj.get("v"), str) and obj["v"].startswith("KERI10"):
        return True
    return False


@dataclass
class DossierParseResult:
    """Result of parsing a dossier CESR stream.

    Attributes
    ----------
    nodes : list[ACDCNode]
        Parsed ACDC credential objects.
    signatures : dict[str, bytes]
        SAID -> signature bytes extracted from CESR attachments.
        Empty for non-CESR (plain JSON) formats.
    tel_events : list[dict]
        KERI Transaction Event Log events found in the stream.
        Retained for future inline revocation evaluation; not consumed
        by the current verification pipeline.

    Notes
    -----
    ``__iter__`` yields ``(nodes, signatures)`` to preserve backward
    compatibility with code that unpacks the result as a 2-tuple.
    """
    nodes: List[ACDCNode]
    signatures: Dict[str, bytes]
    tel_events: List[dict] = field(default_factory=list)

    def __iter__(self):
        """Yield (nodes, signatures) for backward-compatible tuple unpacking."""
        yield self.nodes
        yield self.signatures


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


def _extract_json_events_permissive(data: bytes) -> List[dict]:
    """Extract JSON objects from a CESR stream without strict attachment parsing.

    This is a fallback for when the strict CESR parser fails due to unsupported
    attachment codes. It extracts JSON events by finding balanced braces.

    Args:
        data: Raw bytes that may contain JSON events with CESR attachments

    Returns:
        List of parsed JSON dictionaries
    """
    events = []
    text = data.decode("utf-8", errors="replace")
    i = 0
    while i < len(text):
        # Find start of JSON object
        if text[i] == "{":
            depth = 0
            in_string = False
            escape = False
            start = i
            for j in range(i, len(text)):
                char = text[j]
                if escape:
                    escape = False
                    continue
                if char == "\\":
                    escape = True
                    continue
                if char == '"':
                    in_string = not in_string
                    continue
                if in_string:
                    continue
                if char == "{":
                    depth += 1
                elif char == "}":
                    depth -= 1
                    if depth == 0:
                        # Found complete JSON object
                        json_str = text[start : j + 1]
                        try:
                            obj = json.loads(json_str)
                            events.append(obj)
                        except json.JSONDecodeError:
                            pass  # Skip malformed JSON
                        i = j + 1
                        break
            else:
                # Couldn't find closing brace
                i += 1
        else:
            i += 1
    return events


def _is_cesr_stream(data: bytes) -> bool:
    """Check if data appears to be a CESR stream (without heavy imports).

    Quick heuristic check to avoid importing full CESR parser for simple JSON.
    """
    if not data:
        return False

    # CESR version marker
    if data[:5] == b"-_AAA":
        return True

    # CESR count code at start
    if data[0:1] == b"-":
        return True

    # JSON with CESR attachments - look for count code after JSON
    if data[0:1] == b"{":
        # Find end of JSON object (simple brace counting)
        depth = 0
        in_string = False
        escape = False
        for i, b in enumerate(data):
            if escape:
                escape = False
                continue
            if b == ord("\\"):
                escape = True
                continue
            if b == ord('"'):
                in_string = not in_string
                continue
            if in_string:
                continue
            if b == ord("{"):
                depth += 1
            elif b == ord("}"):
                depth -= 1
                if depth == 0:
                    # Check for count code after JSON
                    remaining = data[i + 1 :].lstrip()
                    if remaining and remaining[0:1] == b"-":
                        return True
                    break

    return False


def parse_dossier(raw: bytes) -> DossierParseResult:
    """Parse dossier from raw bytes, extracting ACDCs, their signatures, and TEL events.

    Supports:
    - Single ACDC object: {...}
    - Array of ACDC objects: [{...}, {...}]
    - CESR stream with attachments: {...}-A##<sig>...

    For CESR format, signatures are extracted from the attachments.
    KERI TEL events (identified via _is_keri_event) are separated into
    tel_events and retained for future inline revocation evaluation.

    Args:
        raw: Raw bytes from HTTP response

    Returns:
        DossierParseResult with nodes, signatures, and tel_events

    Raises:
        ParseError: If parsing fails or structure is malformed
    """
    signatures: Dict[str, bytes] = {}

    # Check if this is a CESR stream with attachments
    if _is_cesr_stream(raw):
        # Lazy import to avoid triggering pysodium dependency chain
        # when not needed (e.g., for plain JSON dossiers in tests)
        import importlib

        cesr = importlib.import_module("app.vvp.keri.cesr")

        try:
            messages = cesr.parse_cesr_stream(raw)
            nodes = []
            tel_events: List[dict] = []
            for msg in messages:
                event = msg.event_dict
                if _is_keri_event(event):
                    tel_events.append(event)
                    continue
                if "d" in event and "i" in event:
                    try:
                        node = parse_acdc(event)
                        nodes.append(node)
                        if msg.controller_sigs:
                            signatures[node.said] = msg.controller_sigs[0]
                    except ParseError:
                        continue

            if tel_events:
                log.info(
                    "Dossier contains %d inline TEL events (retained)", len(tel_events)
                )
            if not nodes:
                raise ParseError("No ACDCs found in CESR stream")

            return DossierParseResult(nodes=nodes, signatures=signatures, tel_events=tel_events)
        except Exception:
            # Strict CESR parsing failed - fall back to permissive extraction
            events = _extract_json_events_permissive(raw)
            nodes = []
            tel_events = []
            seen_saids: set = set()
            for event in events:
                if _is_keri_event(event):
                    tel_events.append(event)
                    continue
                if "d" not in event or "i" not in event or "s" not in event:
                    continue
                # Schema SAID should start with 'E' (KERI prefix for Blake3-256)
                schema = event.get("s", "")
                if not isinstance(schema, str) or not schema.startswith("E"):
                    continue
                said = event.get("d", "")
                if said in seen_saids:
                    continue
                seen_saids.add(said)
                try:
                    node = parse_acdc(event)
                    nodes.append(node)
                except ParseError:
                    continue

            if tel_events:
                log.info(
                    "Dossier contains %d inline TEL events (retained)", len(tel_events)
                )
            if not nodes:
                raise ParseError("No ACDCs found in CESR stream (permissive mode)")

            return DossierParseResult(nodes=nodes, signatures=signatures, tel_events=tel_events)

    # Plain JSON format - no signatures
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ParseError(f"Invalid JSON: {e}")

    # Handle Provenant wrapper format: {"details": "...CESR content..."}
    if isinstance(data, dict) and "details" in data and isinstance(data["details"], str):
        details_content = data["details"].encode("utf-8")
        if _is_cesr_stream(details_content):
            return parse_dossier(details_content)
        try:
            inner_data = json.loads(details_content)
            if isinstance(inner_data, dict):
                return DossierParseResult(nodes=[parse_acdc(inner_data)], signatures=signatures)
            elif isinstance(inner_data, list):
                if not inner_data:
                    raise ParseError("Empty ACDC array in details")
                return DossierParseResult(
                    nodes=[parse_acdc(item) for item in inner_data], signatures=signatures
                )
        except json.JSONDecodeError:
            return parse_dossier(details_content)

    if isinstance(data, dict):
        return DossierParseResult(nodes=[parse_acdc(data)], signatures=signatures)
    elif isinstance(data, list):
        if not data:
            raise ParseError("Empty ACDC array")
        return DossierParseResult(
            nodes=[parse_acdc(item) for item in data], signatures=signatures
        )
    else:
        raise ParseError(f"Expected object or array, got {type(data).__name__}")
