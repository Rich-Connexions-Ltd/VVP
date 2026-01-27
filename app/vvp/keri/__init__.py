"""KERI integration module for VVP signature verification.

Tier 1 (Phase 4): Direct Ed25519 verification using public key from KERI AID.
Tier 2 (Phase 7): Historical key state resolution via KEL lookup.
"""

from .exceptions import (
    KeriError,
    SignatureInvalidError,
    ResolutionFailedError,
    StateInvalidError,
    KELChainInvalidError,
    KeyNotYetValidError,
    DelegationNotSupportedError,
    OOBIContentInvalidError,
)
from .key_parser import parse_kid_to_verkey, VerificationKey
from .signature import (
    verify_passport_signature,
    verify_passport_signature_tier2,
    verify_passport_signature_tier2_with_key_state,
)
from .kel_resolver import KeyState, resolve_key_state, resolve_key_state_tier1_fallback
from .kel_parser import KELEvent, WitnessReceipt, EventType, parse_kel_stream, validate_kel_chain
from .oobi import OOBIResult, dereference_oobi
from .cache import KeyStateCache, CacheConfig

__all__ = [
    # Exceptions
    "KeriError",
    "SignatureInvalidError",
    "ResolutionFailedError",
    "StateInvalidError",
    "KELChainInvalidError",
    "KeyNotYetValidError",
    "DelegationNotSupportedError",
    "OOBIContentInvalidError",
    # Tier 1
    "parse_kid_to_verkey",
    "VerificationKey",
    "verify_passport_signature",
    # Tier 2
    "verify_passport_signature_tier2",
    "verify_passport_signature_tier2_with_key_state",
    "KeyState",
    "resolve_key_state",
    "resolve_key_state_tier1_fallback",
    "KELEvent",
    "WitnessReceipt",
    "EventType",
    "parse_kel_stream",
    "validate_kel_chain",
    "OOBIResult",
    "dereference_oobi",
    "KeyStateCache",
    "CacheConfig",
]
