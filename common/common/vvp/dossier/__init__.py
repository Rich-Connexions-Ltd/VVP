"""Shared dossier caching and revocation infrastructure.

This package provides dossier caching with background revocation checking
for both signer (issuer) and verifier services.

Usage:
    from common.vvp.dossier import (
        DossierCache,
        CachedDossier,
        get_dossier_cache,
        fetch_dossier,
        TrustDecision,
        revocation_to_trust,
        FetchError,
    )
"""

from .cache import CachedDossier, CacheMetrics, DossierCache
from .config import (
    DOSSIER_CACHE_MAX_ENTRIES,
    DOSSIER_CACHE_TTL_SECONDS,
    DOSSIER_FETCH_TIMEOUT_SECONDS,
    DOSSIER_MAX_SIZE_BYTES,
)
from .exceptions import DossierError, FetchError, GraphError, ParseError
from .fetch import fetch_dossier
from .trust import TrustDecision, revocation_to_trust

__all__ = [
    # Cache
    "DossierCache",
    "CachedDossier",
    "CacheMetrics",
    # Fetch
    "fetch_dossier",
    # Trust
    "TrustDecision",
    "revocation_to_trust",
    # Exceptions
    "DossierError",
    "FetchError",
    "ParseError",
    "GraphError",
    # Config
    "DOSSIER_CACHE_TTL_SECONDS",
    "DOSSIER_CACHE_MAX_ENTRIES",
    "DOSSIER_FETCH_TIMEOUT_SECONDS",
    "DOSSIER_MAX_SIZE_BYTES",
]
