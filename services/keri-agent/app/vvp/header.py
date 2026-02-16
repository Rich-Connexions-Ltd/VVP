"""VVP-Identity header creation per spec §4.1A.

Creates base64url-encoded JSON headers for VVP attestation.
This is the inverse of services/verifier/app/vvp/header.py (parsing).
"""

import base64
import json
import time
from dataclasses import dataclass
from typing import Optional

# Maximum validity window per §5.2B
MAX_VALIDITY_SECONDS = 300


@dataclass(frozen=True)
class VVPIdentityHeader:
    """Created VVP-Identity header with metadata."""

    encoded: str
    ppt: str
    kid: str
    evd: str
    iat: int
    exp: int


def create_vvp_identity_header(
    issuer_oobi: str,
    dossier_url: str,
    iat: Optional[int] = None,
    exp_seconds: int = 300,
) -> VVPIdentityHeader:
    """Create a VVP-Identity header per §4.1A."""
    if not issuer_oobi or not issuer_oobi.strip():
        raise ValueError("issuer_oobi must not be empty")
    if not dossier_url or not dossier_url.strip():
        raise ValueError("dossier_url must not be empty")

    if iat is None:
        iat = int(time.time())

    exp_seconds = min(exp_seconds, MAX_VALIDITY_SECONDS)
    exp = iat + exp_seconds

    header_obj = {
        "ppt": "vvp",
        "kid": issuer_oobi,
        "evd": dossier_url,
        "iat": iat,
        "exp": exp,
    }

    json_str = json.dumps(header_obj, separators=(",", ":"))
    encoded = base64.urlsafe_b64encode(json_str.encode("utf-8")).decode("ascii").rstrip("=")

    return VVPIdentityHeader(
        encoded=encoded,
        ppt="vvp",
        kid=issuer_oobi,
        evd=dossier_url,
        iat=iat,
        exp=exp,
    )
