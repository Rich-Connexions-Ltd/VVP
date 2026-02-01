"""Dossier format serializers.

Provides serialization to formats the VVP Verifier can consume:
- CESR: Concatenated CESR stream with signature attachments
- JSON: Array of ACDC objects (verifier-compatible)
"""

import json
import logging
from enum import Enum

from app.dossier.builder import DossierContent

log = logging.getLogger(__name__)


class DossierFormat(str, Enum):
    """Dossier output formats."""

    CESR = "cesr"  # application/cesr - CESR stream with attachments
    JSON = "json"  # application/json - JSON array of ACDC objects


# Content-Type headers for each format
CONTENT_TYPES = {
    DossierFormat.CESR: "application/cesr",
    DossierFormat.JSON: "application/json",
}


def serialize_dossier(
    content: DossierContent,
    format: DossierFormat = DossierFormat.CESR,
) -> tuple[bytes, str]:
    """Serialize dossier to bytes with appropriate content-type.

    Args:
        content: Assembled dossier content
        format: Output format (CESR or JSON)

    Returns:
        Tuple of (serialized bytes, content-type header)
    """
    if format == DossierFormat.CESR:
        data = serialize_cesr(content)
    elif format == DossierFormat.JSON:
        data = serialize_json(content)
    else:
        raise ValueError(f"Unknown format: {format}")

    content_type = CONTENT_TYPES[format]
    return data, content_type


def serialize_cesr(content: DossierContent) -> bytes:
    """Serialize dossier as CESR stream.

    Concatenates credentials first, then TEL events.
    Each credential already has signature attachments from signing.serialize().

    Format:
        {ACDC1_JSON}-A##sig1...{ACDC2_JSON}-A##sig2...{TEL_iss1}...{TEL_iss2}...

    Args:
        content: Assembled dossier content

    Returns:
        Concatenated CESR stream bytes
    """
    parts: list[bytes] = []

    # Add credentials in topological order (dependencies first, root last)
    for said in content.credential_saids:
        if said in content.credentials:
            parts.append(content.credentials[said])

    # Add TEL events after credentials
    for said in content.credential_saids:
        if said in content.tel_events:
            parts.append(content.tel_events[said])

    result = b"".join(parts)
    log.debug(f"Serialized CESR dossier: {len(result)} bytes, {len(parts)} parts")
    return result


def serialize_json(content: DossierContent) -> bytes:
    """Serialize dossier as JSON array of ACDC objects.

    This format is directly parseable by the verifier's parse_dossier().
    TEL events are NOT included (verifier resolves them via OOBI/witnesses).

    Format:
        [
          {"v": "ACDC10JSON...", "d": "Exxx", "i": "...", "s": "...", "a": {...}},
          {"v": "ACDC10JSON...", "d": "Eyyy", "i": "...", "s": "...", "a": {...}}
        ]

    Args:
        content: Assembled dossier content

    Returns:
        JSON-encoded array of ACDC objects
    """
    acdc_list: list[dict] = []

    # Add credentials in topological order
    for said in content.credential_saids:
        if said in content.credentials_json:
            acdc_dict = content.credentials_json[said]
            if acdc_dict:
                acdc_list.append(acdc_dict)

    result = json.dumps(acdc_list, separators=(",", ":")).encode("utf-8")
    log.debug(f"Serialized JSON dossier: {len(result)} bytes, {len(acdc_list)} ACDCs")
    return result
