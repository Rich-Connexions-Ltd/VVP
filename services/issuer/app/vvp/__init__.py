"""VVP header and PASSporT creation for the issuer service.

This module provides the inverse of verifier operations - creating VVP-Identity
headers and signed PASSporT JWTs that telephone service providers include in
SIP INVITE requests.

Spec references:
- §4.1A/§4.1B: VVP-Identity header format
- §5.0-§5.4: PASSporT JWT requirements
- §6.3.1: PSS CESR signature encoding

Sprint 68c: PASSporT signing delegated to KERI Agent. create_passport() removed.
"""

from app.vvp.exceptions import (
    VVPCreationError,
    IdentityNotAvailableError,
    InvalidPhoneNumberError,
    InvalidExpiryError,
)
from app.vvp.oobi import build_issuer_oobi, build_dossier_url
from app.vvp.header import create_vvp_identity_header
from app.vvp.passport import encode_pss_signature, validate_e164

__all__ = [
    # Exceptions
    "VVPCreationError",
    "IdentityNotAvailableError",
    "InvalidPhoneNumberError",
    "InvalidExpiryError",
    # OOBI helpers
    "build_issuer_oobi",
    "build_dossier_url",
    # Header creation
    "create_vvp_identity_header",
    # PASSporT utilities
    "encode_pss_signature",
    "validate_e164",
]
