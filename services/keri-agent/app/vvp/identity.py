"""RFC 8224 Identity header builder per Sprint 57.

Constructs the standard SIP Identity header value for STIR compliance.
"""

from urllib.parse import urlparse


def build_identity_header(passport_jwt: str, issuer_oobi: str) -> str:
    """Build RFC 8224 Identity header value from PASSporT JWT and OOBI URL."""
    if not passport_jwt or not passport_jwt.strip():
        raise ValueError("passport_jwt must not be empty")

    if not issuer_oobi or not issuer_oobi.strip():
        raise ValueError("issuer_oobi must not be empty")

    parsed = urlparse(issuer_oobi)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError(
            f"issuer_oobi must be an absolute URI (has scheme and host), "
            f"got: {issuer_oobi}"
        )

    return f"{passport_jwt};info=<{issuer_oobi}>;alg=EdDSA;ppt=vvp"
