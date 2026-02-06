"""RFC 8224 Identity header parser.

Sprint 44: Parses the SIP Identity header per RFC 8224 to extract
the PASSporT JWT and header parameters.

Header format:
    Identity: <base64url-passport>;info=<oobi>;alg=EdDSA;ppt=vvp

The header contains:
- Body: Base64URL-encoded PASSporT JWT
- Parameters:
  - info: OOBI URL for key resolution (REQUIRED per VVP)
  - alg: Signing algorithm (EdDSA for VVP)
  - ppt: PASSporT type (vvp)
"""

import base64
import logging
import re
from dataclasses import dataclass
from typing import Optional
from urllib.parse import unquote

log = logging.getLogger(__name__)


class IdentityParseError(Exception):
    """Error parsing Identity header."""

    pass


@dataclass
class ParsedIdentityHeader:
    """Parsed RFC 8224 Identity header.

    Attributes:
        passport_jwt: Decoded PASSporT JWT string.
        info_url: OOBI URL from info parameter.
        algorithm: Signing algorithm (EdDSA for VVP).
        ppt: PASSporT type (vvp).
        raw_body: Original base64url-encoded body.
    """

    passport_jwt: str
    info_url: str
    algorithm: str
    ppt: str
    raw_body: str


def _base64url_decode(data: str) -> bytes:
    """Decode base64url-encoded data (RFC 4648 Section 5).

    Handles missing padding and URL-safe alphabet.

    Args:
        data: Base64url-encoded string

    Returns:
        Decoded bytes

    Raises:
        IdentityParseError: If decoding fails
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
        raise IdentityParseError(f"Invalid base64url encoding: {e}")


def parse_identity_header(header_value: str) -> ParsedIdentityHeader:
    """Parse RFC 8224 Identity header.

    Per RFC 8224 Section 4.1:
    - Identity-Spec: "<" Identity-Body ">" *( ";" Identity-Params )
    - Identity-Body: base64url-encoded PASSporT
    - Identity-Params: "info" "=" quoted-string
                     | "alg" "=" token
                     | "ppt" "=" token

    Args:
        header_value: Raw Identity header value

    Returns:
        ParsedIdentityHeader with extracted fields

    Raises:
        IdentityParseError: If parsing fails
    """
    if not header_value:
        raise IdentityParseError("Empty Identity header")

    header_value = header_value.strip()

    # Extract body (may or may not be in angle brackets)
    if header_value.startswith("<"):
        # RFC 8224 format: <body>;params
        match = re.match(r"<([^>]+)>(.*)$", header_value)
        if not match:
            raise IdentityParseError("Malformed Identity header: unclosed angle bracket")
        raw_body = match.group(1)
        params_str = match.group(2)
    else:
        # Legacy format without angle brackets: body;params
        parts = header_value.split(";", 1)
        raw_body = parts[0].strip()
        params_str = ";" + parts[1] if len(parts) > 1 else ""

    if not raw_body:
        raise IdentityParseError("Empty Identity body")

    # Decode the PASSporT JWT
    try:
        passport_bytes = _base64url_decode(raw_body)
        passport_jwt = passport_bytes.decode("utf-8")
    except UnicodeDecodeError as e:
        raise IdentityParseError(f"PASSporT not valid UTF-8: {e}")

    # Parse parameters
    params = {}
    if params_str:
        # Match semicolon-separated key=value pairs
        # Values may be quoted or unquoted
        param_pattern = re.compile(r';([a-zA-Z0-9-]+)=(?:"([^"]+)"|([^;]+))')
        for match in param_pattern.finditer(params_str):
            key = match.group(1).lower()
            value = match.group(2) if match.group(2) else match.group(3)
            # URL decode the value
            params[key] = unquote(value.strip())

    # Extract required parameters
    info_url = params.get("info", "")
    algorithm = params.get("alg", "EdDSA")
    ppt = params.get("ppt", "")

    # Validate VVP requirements
    if not info_url:
        log.warning("Identity header missing info parameter (OOBI URL)")

    if algorithm.upper() not in ("EDDSA", "ED25519"):
        log.warning(f"Identity header has non-EdDSA algorithm: {algorithm}")

    if ppt.lower() != "vvp":
        log.warning(f"Identity header has non-VVP ppt: {ppt}")

    return ParsedIdentityHeader(
        passport_jwt=passport_jwt,
        info_url=info_url,
        algorithm=algorithm,
        ppt=ppt,
        raw_body=raw_body,
    )
