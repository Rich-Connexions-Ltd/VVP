"""VVP-Identity header decoder.

Sprint 44: Decodes the P-VVP-Identity or VVP-Identity header which
contains base64url-encoded JSON with VVP-specific claims.

Header format (base64url-encoded JSON):
{
    "ppt": "vvp",
    "kid": "https://witness.example.com/oobi/{AID}/witness",
    "evd": "https://dossier.example.com/dossiers/{SAID}",
    "iat": 1704067200,
    "exp": 1704153600
}

Fields:
- ppt: PASSporT type, MUST be "vvp"
- kid: OOBI URL for signer key resolution
- evd: Dossier evidence URL
- iat: Issued at timestamp (optional)
- exp: Expiration timestamp (optional)
"""

import base64
import json
import logging
from dataclasses import dataclass
from typing import Optional

log = logging.getLogger(__name__)


class VVPIdentityDecodeError(Exception):
    """Error decoding VVP-Identity header."""

    pass


@dataclass
class VVPIdentityData:
    """Decoded VVP-Identity header data.

    Attributes:
        ppt: PASSporT type ("vvp").
        kid: OOBI URL for key resolution.
        evd: Dossier evidence URL.
        iat: Issued at timestamp (Unix epoch).
        exp: Expiration timestamp (Unix epoch).
    """

    ppt: str
    kid: str
    evd: str
    iat: Optional[int] = None
    exp: Optional[int] = None


def _base64url_decode(data: str) -> bytes:
    """Decode base64url-encoded data (RFC 4648 Section 5).

    Args:
        data: Base64url-encoded string

    Returns:
        Decoded bytes

    Raises:
        VVPIdentityDecodeError: If decoding fails
    """
    # Add padding if needed
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding

    # Replace URL-safe characters
    data = data.replace("-", "+").replace("_", "/")

    try:
        return base64.b64decode(data)
    except Exception as e:
        raise VVPIdentityDecodeError(f"Invalid base64url encoding: {e}")


def decode_vvp_identity(header_value: str) -> VVPIdentityData:
    """Decode P-VVP-Identity or VVP-Identity header.

    The header value is base64url-encoded JSON containing VVP claims.

    Args:
        header_value: Raw header value (base64url-encoded JSON)

    Returns:
        VVPIdentityData with decoded fields

    Raises:
        VVPIdentityDecodeError: If decoding or validation fails
    """
    if not header_value:
        raise VVPIdentityDecodeError("Empty VVP-Identity header")

    header_value = header_value.strip()

    # Decode base64url
    try:
        json_bytes = _base64url_decode(header_value)
        json_str = json_bytes.decode("utf-8")
    except UnicodeDecodeError as e:
        raise VVPIdentityDecodeError(f"VVP-Identity not valid UTF-8: {e}")

    # Parse JSON
    try:
        data = json.loads(json_str)
    except json.JSONDecodeError as e:
        raise VVPIdentityDecodeError(f"VVP-Identity not valid JSON: {e}")

    if not isinstance(data, dict):
        raise VVPIdentityDecodeError("VVP-Identity must be a JSON object")

    # Extract fields
    ppt = data.get("ppt", "")
    kid = data.get("kid", "")
    evd = data.get("evd", "")
    iat = data.get("iat")
    exp = data.get("exp")

    # Validate required fields
    if not ppt:
        raise VVPIdentityDecodeError("VVP-Identity missing ppt field")

    if ppt.lower() != "vvp":
        raise VVPIdentityDecodeError(f"VVP-Identity ppt must be 'vvp', got '{ppt}'")

    if not kid:
        raise VVPIdentityDecodeError("VVP-Identity missing kid field")

    if not evd:
        raise VVPIdentityDecodeError("VVP-Identity missing evd field")

    # Validate URL formats
    if not kid.startswith(("http://", "https://")):
        raise VVPIdentityDecodeError(f"VVP-Identity kid must be an OOBI URL: {kid}")

    if not evd.startswith(("http://", "https://")):
        raise VVPIdentityDecodeError(f"VVP-Identity evd must be a dossier URL: {evd}")

    # Validate timestamp types
    if iat is not None and not isinstance(iat, (int, float)):
        raise VVPIdentityDecodeError(f"VVP-Identity iat must be a number: {iat}")

    if exp is not None and not isinstance(exp, (int, float)):
        raise VVPIdentityDecodeError(f"VVP-Identity exp must be a number: {exp}")

    return VVPIdentityData(
        ppt=ppt,
        kid=kid,
        evd=evd,
        iat=int(iat) if iat is not None else None,
        exp=int(exp) if exp is not None else None,
    )
