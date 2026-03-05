"""Shared configuration constants for dossier caching and fetching.

These defaults are derived from VVP spec requirements:
- §5C.2: Freshness policy (300s TTL)
- §6.1B: Fetch constraints (timeout, size, redirects)
"""

import os

# =============================================================================
# DOSSIER CACHE CONFIGURATION
# =============================================================================

# Cache TTL aligned with §5C.2 key state freshness
DOSSIER_CACHE_TTL_SECONDS: float = float(
    os.getenv("VVP_DOSSIER_CACHE_TTL", "300.0")
)

# Maximum cache entries before LRU eviction
DOSSIER_CACHE_MAX_ENTRIES: int = int(
    os.getenv("VVP_DOSSIER_CACHE_MAX_ENTRIES", "100")
)

# =============================================================================
# DOSSIER FETCH CONSTRAINTS (§6.1B)
# =============================================================================

# Fetch timeout (spec requires enforcement but doesn't specify value)
DOSSIER_FETCH_TIMEOUT_SECONDS: int = int(
    os.getenv("VVP_DOSSIER_FETCH_TIMEOUT", "5")
)

# Maximum response size (1 MB default)
DOSSIER_MAX_SIZE_BYTES: int = int(
    os.getenv("VVP_DOSSIER_MAX_SIZE", "1048576")
)

# =============================================================================
# TEL CLIENT CONFIGURATION
# =============================================================================

# TEL query timeout for revocation checks
TEL_CLIENT_TIMEOUT_SECONDS: float = float(
    os.getenv("VVP_TEL_CLIENT_TIMEOUT", "10.0")
)

# =============================================================================
# WITNESS POOL CONFIGURATION
# =============================================================================


def _parse_witness_urls() -> list[str]:
    """Parse witness URLs from environment.

    First checks for local witnesses (VVP_LOCAL_WITNESSES=true), which uses
    docker-compose witness endpoints. Falls back to Provenant staging witnesses.
    """
    if os.getenv("VVP_LOCAL_WITNESSES", "false").lower() == "true":
        return [
            "http://127.0.0.1:5642",
            "http://127.0.0.1:5643",
            "http://127.0.0.1:5644",
        ]

    env_value = os.getenv("VVP_WITNESS_URLS", "")
    if env_value:
        return [url.strip() for url in env_value.split(",") if url.strip()]

    # Default: Provenant staging witnesses
    return [
        "http://witness1.stage.provenant.net:5631",
        "http://witness2.stage.provenant.net:5631",
        "http://witness3.stage.provenant.net:5631",
        "http://witness4.stage.provenant.net:5631",
        "http://witness5.stage.provenant.net:5631",
        "http://witness6.stage.provenant.net:5631",
    ]


# Witness URLs for KERI resolution
PROVENANT_WITNESS_URLS: list[str] = _parse_witness_urls()

# GLEIF witness discovery
GLEIF_WITNESS_OOBI_URL: str = os.getenv(
    "VVP_GLEIF_WITNESS_OOBI",
    "https://gleif.vn.io/.well-known/keri/oobi/EDP1vHcw_wc4M__Fj53-cJaBnZZASd-aMTaSyWEQ-PC2",
)

GLEIF_WITNESS_DISCOVERY_ENABLED: bool = os.getenv(
    "VVP_GLEIF_WITNESS_DISCOVERY", "true"
).lower() == "true"

GLEIF_WITNESS_CACHE_TTL: int = int(
    os.getenv("VVP_GLEIF_WITNESS_CACHE_TTL", "300")
)
