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
from typing import Dict, List, Tuple

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


def parse_dossier(raw: bytes) -> Tuple[List[ACDCNode], Dict[str, bytes]]:
    """Parse dossier from raw bytes, extracting ACDCs and their signatures.

    Supports:
    - Single ACDC object: {...}
    - Array of ACDC objects: [{...}, {...}]
    - CESR stream with attachments: {...}-A##<sig>...

    For CESR format, signatures are extracted from the attachments and
    returned in a dict mapping SAID -> signature bytes.

    Args:
        raw: Raw bytes from HTTP response

    Returns:
        Tuple of (list of ACDCNode, dict mapping SAID -> signature bytes)

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
            for msg in messages:
                event = msg.event_dict
                # Check if this is an ACDC (has 'd' and 'i' fields)
                if "d" in event and "i" in event:
                    try:
                        node = parse_acdc(event)
                        nodes.append(node)
                        # Extract first controller signature if present
                        if msg.controller_sigs:
                            signatures[node.said] = msg.controller_sigs[0]
                    except ParseError:
                        # Skip non-ACDC events in the stream
                        continue

            if not nodes:
                raise ParseError("No ACDCs found in CESR stream")

            return nodes, signatures
        except Exception:
            # Strict CESR parsing failed - fall back to permissive extraction
            # This extracts JSON events without validating attachments
            # Signatures will not be available in permissive mode
            events = _extract_json_events_permissive(raw)
            nodes = []
            seen_saids: set = set()  # Deduplicate by SAID
            for event in events:
                # Filter for ACDCs vs KEL events:
                # - KEL events have "t" (type: icp, ixn, rot, etc.) and numeric "s" (sequence)
                # - ACDCs don't have "t" and have SAID-format "s" (schema SAID)
                if "t" in event:
                    continue  # This is a KEL event, not an ACDC
                if "d" not in event or "i" not in event or "s" not in event:
                    continue
                # Schema SAID should start with 'E' (KERI prefix for Blake3-256)
                schema = event.get("s", "")
                if not isinstance(schema, str) or not schema.startswith("E"):
                    continue  # Likely a KEL sequence number, not schema SAID
                # Deduplicate
                said = event.get("d", "")
                if said in seen_saids:
                    continue
                seen_saids.add(said)
                try:
                    node = parse_acdc(event)
                    nodes.append(node)
                except ParseError:
                    continue

            if not nodes:
                raise ParseError("No ACDCs found in CESR stream (permissive mode)")

            return nodes, signatures  # signatures empty in permissive mode

    # Plain JSON format - no signatures
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ParseError(f"Invalid JSON: {e}")

    # Handle Provenant wrapper format: {"details": "...CESR content..."}
    if isinstance(data, dict) and "details" in data and isinstance(data["details"], str):
        details_content = data["details"].encode("utf-8")
        # The details field contains CESR stream content
        if _is_cesr_stream(details_content):
            return parse_dossier(details_content)
        # Try parsing as plain JSON
        try:
            inner_data = json.loads(details_content)
            if isinstance(inner_data, dict):
                return [parse_acdc(inner_data)], signatures
            elif isinstance(inner_data, list):
                if not inner_data:
                    raise ParseError("Empty ACDC array in details")
                return [parse_acdc(item) for item in inner_data], signatures
        except json.JSONDecodeError:
            # Not valid JSON inside details, treat as CESR
            return parse_dossier(details_content)

    if isinstance(data, dict):
        return [parse_acdc(data)], signatures
    elif isinstance(data, list):
        if not data:
            raise ParseError("Empty ACDC array")
        return [parse_acdc(item) for item in data], signatures
    else:
        raise ParseError(f"Expected object or array, got {type(data).__name__}")
