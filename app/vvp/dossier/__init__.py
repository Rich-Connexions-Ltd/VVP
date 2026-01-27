"""Dossier fetching and validation module.

Per VVP Specification v1.4 Section 6.

Tier 1 (MVP): Fetch, parse JSON, validate DAG structure
Tier 2: Full CESR parsing, SAID verification, issuer verification
"""

from .cache import (
    CachedDossier,
    CacheMetrics,
    DossierCache,
    get_dossier_cache,
    reset_dossier_cache,
)
from .exceptions import DossierError, FetchError, GraphError, ParseError
from .fetch import fetch_dossier
from .models import ACDCNode, DossierDAG, DossierWarning, ToIPWarningCode
from .parser import parse_acdc, parse_dossier
from .validator import build_dag, detect_cycle, find_root, validate_dag

__all__ = [
    # Exceptions
    "DossierError",
    "FetchError",
    "ParseError",
    "GraphError",
    # Models
    "ACDCNode",
    "DossierDAG",
    "DossierWarning",
    "ToIPWarningCode",
    # Cache
    "CachedDossier",
    "CacheMetrics",
    "DossierCache",
    "get_dossier_cache",
    "reset_dossier_cache",
    # Functions
    "fetch_dossier",
    "parse_acdc",
    "parse_dossier",
    "build_dag",
    "validate_dag",
    "find_root",
    "detect_cycle",
]
