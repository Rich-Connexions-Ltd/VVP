"""Data models for dossier/ACDC structures.

COMPATIBILITY SHIM: This module re-exports from common.vvp.models.dossier.
The actual implementation has been moved to the shared common/ package.

For new code, import directly from common.vvp.models:
    from common.vvp.models import DossierDAG, ACDCNode
"""

# Re-export from common package
from common.vvp.models.dossier import (
    ACDCNode,
    DossierDAG,
    DossierWarning,
    ToIPWarningCode,
)

__all__ = [
    "ACDCNode",
    "DossierDAG",
    "DossierWarning",
    "ToIPWarningCode",
]
