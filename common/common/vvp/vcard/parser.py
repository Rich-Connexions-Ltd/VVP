"""RFC 6350 vCard property line parser.

Syntax-only — no domain/brand logic. Handles case-insensitive property
names, parameter parsing, and multi-value properties.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class VCardProperty:
    """Parsed vCard property line."""

    name: str  # Normalized to uppercase (e.g. "LOGO", "ORG")
    value: str  # Everything after the last unescaped colon
    params: dict[str, str] = field(default_factory=dict)  # e.g. {"HASH": "EK2r...", "VALUE": "URI"}


def parse_vcard_line(line: str) -> VCardProperty:
    """Parse a single vCard property line into structured form.

    Format: NAME[;PARAM=VALUE...]:value
    Examples:
        "ORG:ACME Corporation"
        "LOGO;HASH=EK2r...;VALUE=URI:https://cdn.acme.com/logo.png"
        "TEL;VALUE=URI:tel:+441923311000"

    Property names are normalized to uppercase. Parameters are
    case-insensitive for keys (normalized to uppercase).
    """
    if not line or ":" not in line:
        return VCardProperty(name="", value=line or "")

    # Split on first colon that isn't inside a parameter value.
    # Parameters use semicolons, so the first colon after the last
    # semicolon-delimited segment is the property/value separator.
    # But VALUE=URI means the value itself can contain colons.
    # RFC 6350: "name *(";" param) ":" value"
    # Split name+params from value at the first colon
    name_params, _, value = line.partition(":")

    # Parse name and parameters
    parts = name_params.split(";")
    name = parts[0].strip().upper()
    params: dict[str, str] = {}
    for part in parts[1:]:
        if "=" in part:
            pk, _, pv = part.partition("=")
            params[pk.strip().upper()] = pv.strip()
        else:
            # Bare parameter (e.g. "PREF")
            params[part.strip().upper()] = ""

    return VCardProperty(name=name, value=value, params=params)


def parse_vcard_lines(lines: list[str]) -> list[VCardProperty]:
    """Parse multiple vCard property lines.

    Returns list of VCardProperty objects. Empty/blank lines are skipped.
    """
    return [parse_vcard_line(line) for line in lines if line.strip()]


def find_property(properties: list[VCardProperty], name: str) -> VCardProperty | None:
    """Find first property by name (case-insensitive)."""
    name_upper = name.upper()
    for prop in properties:
        if prop.name == name_upper:
            return prop
    return None


def find_all_properties(properties: list[VCardProperty], name: str) -> list[VCardProperty]:
    """Find all properties by name (case-insensitive).

    Useful for multi-value properties like TEL, URL, EMAIL.
    """
    name_upper = name.upper()
    return [p for p in properties if p.name == name_upper]
