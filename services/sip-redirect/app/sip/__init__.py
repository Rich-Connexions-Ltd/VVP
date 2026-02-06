"""SIP protocol handling module.

Sprint 44: Re-exports shared SIP utilities from common.vvp.sip.
Local transport.py retained for service-specific configuration.
"""

# Re-export from common shared package
from common.vvp.sip import (
    SIPRequest,
    SIPResponse,
    parse_sip_request,
    normalize_tn,
    extract_tn_from_uri,
    build_302_redirect,
    build_400_bad_request,
    build_401_unauthorized,
    build_403_forbidden,
    build_404_not_found,
    build_500_error,
)

__all__ = [
    "SIPRequest",
    "SIPResponse",
    "parse_sip_request",
    "normalize_tn",
    "extract_tn_from_uri",
    "build_302_redirect",
    "build_400_bad_request",
    "build_401_unauthorized",
    "build_403_forbidden",
    "build_404_not_found",
    "build_500_error",
]
