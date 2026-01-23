"""KERI integration module for VVP signature verification.

Phase 4 (Tier 1): Direct Ed25519 verification using public key from KERI AID.
"""

from .exceptions import KeriError, SignatureInvalidError, ResolutionFailedError
from .key_parser import parse_kid_to_verkey, VerificationKey
from .signature import verify_passport_signature

__all__ = [
    "KeriError",
    "SignatureInvalidError",
    "ResolutionFailedError",
    "parse_kid_to_verkey",
    "VerificationKey",
    "verify_passport_signature",
]
