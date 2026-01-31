"""KERI Canonical Serialization.

COMPATIBILITY SHIM: This module re-exports from common.vvp.canonical.keri_canonical.
The actual implementation has been moved to the shared common/ package.

For new code, import directly from common.vvp.canonical:
    from common.vvp.canonical import keri_canonical
"""

# Re-export from common package
from common.vvp.canonical.keri_canonical import (
    FIELD_ORDER,
    CanonicalSerializationError,
    canonical_serialize,
    get_field_order,
    most_compact_form,
)

__all__ = [
    "FIELD_ORDER",
    "CanonicalSerializationError",
    "canonical_serialize",
    "get_field_order",
    "most_compact_form",
]
