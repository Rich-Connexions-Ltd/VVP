"""KERI-specific exceptions mapped to VVP error codes.

Per spec §5.4:
- Cryptographic failures → INVALID (non-recoverable)
- Resolution failures → INDETERMINATE (recoverable)
"""

from app.vvp.api_models import ErrorCode


class KeriError(Exception):
    """Base exception for KERI operations.

    Carries an error code that maps to ErrorCode constants per §4.2A.
    """

    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(message)


class SignatureInvalidError(KeriError):
    """Signature is cryptographically invalid.

    Maps to PASSPORT_SIG_INVALID (non-recoverable → INVALID).
    """

    def __init__(self, message: str = "Signature verification failed"):
        super().__init__(ErrorCode.PASSPORT_SIG_INVALID, message)


class ResolutionFailedError(KeriError):
    """Transient failure resolving key state.

    Maps to KERI_RESOLUTION_FAILED (recoverable → INDETERMINATE).
    Used when:
    - kid format is unrecognized
    - kid algorithm is not supported
    - Network/fetch failures (Tier 2)
    """

    def __init__(self, message: str = "KERI resolution failed"):
        super().__init__(ErrorCode.KERI_RESOLUTION_FAILED, message)


class StateInvalidError(KeriError):
    """Key state is cryptographically invalid.

    Maps to KERI_STATE_INVALID (non-recoverable → INVALID).
    Reserved for Tier 2 when KEL validation fails.
    """

    def __init__(self, message: str = "KERI state invalid"):
        super().__init__(ErrorCode.KERI_STATE_INVALID, message)


class KELChainInvalidError(StateInvalidError):
    """KEL chain validation failed.

    Used when:
    - Chain continuity broken (prior_digest doesn't match previous event's digest)
    - Event signature is invalid (not signed by keys from prior event)
    - Inception event is not properly self-signed

    Maps to KERI_STATE_INVALID (non-recoverable → INVALID).
    """

    def __init__(self, message: str = "KEL chain validation failed"):
        super().__init__(message)


class KeyNotYetValidError(StateInvalidError):
    """No establishment event exists at or before reference time T.

    This occurs when the reference time (PASSporT iat) is before the
    AID's inception event, meaning no valid key state existed at that time.

    Maps to KERI_STATE_INVALID (non-recoverable → INVALID).
    """

    def __init__(self, message: str = "No valid key state at reference time"):
        super().__init__(message)


class DelegationNotSupportedError(ResolutionFailedError):
    """Delegated event (dip/drt) detected but not yet supported.

    Delegated identifiers require additional validation of the delegator's
    authorization, which is deferred to a future phase.

    Maps to KERI_RESOLUTION_FAILED (recoverable → INDETERMINATE).
    """

    def __init__(self, message: str = "Delegated events not yet supported"):
        super().__init__(message)


class OOBIContentInvalidError(KeriError):
    """OOBI response has invalid content type or malformed data.

    Maps to VVP_OOBI_CONTENT_INVALID (non-recoverable → INVALID).
    """

    def __init__(self, message: str = "Invalid OOBI content"):
        super().__init__(ErrorCode.VVP_OOBI_CONTENT_INVALID, message)


class CESRFramingError(KeriError):
    """CESR attachment group framing error.

    Raised when the declared byte count in a counter code doesn't match
    the actual bytes consumed during parsing. This indicates either:
    - Truncated stream (declared > actual)
    - Extra bytes in group (declared < actual)

    Maps to KERI_STATE_INVALID (non-recoverable → INVALID).
    """

    def __init__(self, message: str = "CESR framing error"):
        super().__init__(ErrorCode.KERI_STATE_INVALID, message)


class CESRMalformedError(KeriError):
    """CESR stream contains malformed or unknown data.

    Raised when:
    - Unknown counter code encountered (e.g., -X## instead of -A##)
    - Invalid version string format
    - Truncated primitive (not enough bytes for declared type)

    Maps to KERI_STATE_INVALID (non-recoverable → INVALID).
    """

    def __init__(self, message: str = "CESR malformed"):
        super().__init__(ErrorCode.KERI_STATE_INVALID, message)


class UnsupportedSerializationKind(KeriError):
    """CESR version string indicates unsupported serialization kind.

    Raised when the version string indicates MGPK or CBOR serialization.
    Only JSON serialization is currently supported.

    This is a deterministic rejection (not silent skip) per the plan.

    Maps to KERI_RESOLUTION_FAILED (recoverable → INDETERMINATE).
    """

    def __init__(self, kind: str = "unknown"):
        message = (
            f"Serialization kind '{kind}' not supported. "
            f"Only JSON is supported in this version. "
            f"MGPK and CBOR support may be added in a future release."
        )
        super().__init__(ErrorCode.KERI_RESOLUTION_FAILED, message)
