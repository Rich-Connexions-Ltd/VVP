"""Telephone Number Utilities for VVP Verifier.

COMPATIBILITY SHIM: This module re-exports from common.vvp.utils.tn_utils.
The actual implementation has been moved to the shared common/ package.

For new code, import directly from common.vvp.utils:
    from common.vvp.utils import tn_utils
"""

# Re-export from common package
from common.vvp.utils.tn_utils import (
    E164_PATTERN,
    E164_WILDCARD_PATTERN,
    TNParseError,
    TNRange,
    find_uncovered_ranges,
    is_subset,
    parse_tn_allocation,
    validate_e164,
)

__all__ = [
    "E164_PATTERN",
    "E164_WILDCARD_PATTERN",
    "TNParseError",
    "TNRange",
    "find_uncovered_ranges",
    "is_subset",
    "parse_tn_allocation",
    "validate_e164",
]
