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
