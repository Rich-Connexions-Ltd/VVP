"""ACDC (Authentic Chained Data Container) models.

COMPATIBILITY SHIM: This module re-exports from common.vvp.models.acdc.
The actual implementation has been moved to the shared common/ package.

For new code, import directly from common.vvp.models:
    from common.vvp.models import ACDC, ACDCChainResult
"""

# Re-export from common package
from common.vvp.models.acdc import (
    ACDC,
    ACDCChainResult,
    _extract_lei_from_vcard,
)

__all__ = [
    "ACDC",
    "ACDCChainResult",
    "_extract_lei_from_vcard",
]
