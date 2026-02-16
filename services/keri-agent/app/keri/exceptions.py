"""KERI operation exceptions for VVP KERI Agent.

This module defines custom exceptions for KERI identity and key management
operations, providing specific error types for proper API error handling.
"""


class IdentityNotFoundError(Exception):
    """Raised when an identity AID is not found.

    This occurs when attempting to operate on an AID that does not exist
    in the agent's identity store.
    """

    pass


class NonTransferableIdentityError(Exception):
    """Raised when rotation is attempted on a non-transferable identity.

    Non-transferable identities have a fixed key that cannot be rotated.
    This is by design for ephemeral or single-use identities. To rotate
    keys, the identity must be created with transferable=True.
    """

    pass


class RotationError(Exception):
    """Base class for rotation-related errors.

    Subclasses provide specific error types for different rotation failure modes.
    """

    pass


class InvalidRotationThresholdError(RotationError):
    """Raised when the rotation threshold configuration is invalid.

    This occurs when:
    - next_key_count < 1 (must have at least one next key)
    - next_threshold > next_key_count (for simple numeric thresholds)
    - next_threshold is malformed (invalid format for weighted thresholds)
    """

    pass
