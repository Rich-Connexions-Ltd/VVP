# VVP Core - Shared configuration, exceptions, and logging

from common.vvp.core.exceptions import (
    VVPError,
    ACDCError,
    ACDCSAIDMismatch,
    ACDCSignatureInvalid,
    ACDCChainInvalid,
    ACDCParseError,
    KeriError,
    CESRFramingError,
    CESRMalformedError,
    DossierError,
    DossierParseError,
)
from common.vvp.core.logging import configure_logging, JsonFormatter

__all__ = [
    "VVPError",
    "ACDCError",
    "ACDCSAIDMismatch",
    "ACDCSignatureInvalid",
    "ACDCChainInvalid",
    "ACDCParseError",
    "KeriError",
    "CESRFramingError",
    "CESRMalformedError",
    "DossierError",
    "DossierParseError",
    "configure_logging",
    "JsonFormatter",
]
