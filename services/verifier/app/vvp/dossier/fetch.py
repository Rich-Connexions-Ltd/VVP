"""HTTP dossier fetch with constraints per spec §6.1B.

COMPATIBILITY SHIM: This module re-exports from common.vvp.dossier.fetch.
The actual implementation has been moved to the shared common/ package.

For new code, import directly from common.vvp.dossier:
    from common.vvp.dossier import fetch_dossier, FetchError
"""

# Re-export from common package
from common.vvp.dossier.fetch import (
    ACCEPTED_CONTENT_TYPES,
    fetch_dossier,
)

__all__ = [
    "fetch_dossier",
    "ACCEPTED_CONTENT_TYPES",
]
