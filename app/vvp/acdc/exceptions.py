"""ACDC verification exceptions.

COMPATIBILITY SHIM: This module re-exports from common.vvp.core.exceptions.
The actual implementation has been moved to the shared common/ package.

For new code, import directly from common.vvp.core:
    from common.vvp.core import ACDCError, ACDCSAIDMismatch
"""

# Re-export from common package
from common.vvp.core.exceptions import (
    ACDCError,
    ACDCSAIDMismatch,
    ACDCSignatureInvalid,
    ACDCChainInvalid,
    ACDCParseError,
)

__all__ = [
    "ACDCError",
    "ACDCSAIDMismatch",
    "ACDCSignatureInvalid",
    "ACDCChainInvalid",
    "ACDCParseError",
]
