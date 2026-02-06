"""VVP SIP Verification components.

Sprint 44: Components for parsing and verifying SIP INVITE VVP headers.
"""

from .identity_parser import ParsedIdentityHeader, parse_identity_header
from .vvp_identity import VVPIdentityData, decode_vvp_identity
from .client import VerifierClient, VerifyResult
from .handler import handle_verify_invite

__all__ = [
    "ParsedIdentityHeader",
    "parse_identity_header",
    "VVPIdentityData",
    "decode_vvp_identity",
    "VerifierClient",
    "VerifyResult",
    "handle_verify_invite",
]
