"""Data models for dossier/ACDC structures.

Defines:
- ACDCNode: Individual ACDC credential node
- DossierDAG: Directed Acyclic Graph of ACDCs
- ToIPWarningCode: Warning codes for ToIP spec compliance
- DossierWarning: Non-blocking warnings for ToIP spec violations

This module is shared between verifier and issuer services.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class ToIPWarningCode(str, Enum):
    """ToIP Verifiable Dossiers Specification v0.6 warning codes.

    These warnings indicate non-compliance with ToIP stricter requirements
    but do NOT fail VVP verification.
    """

    EDGE_MISSING_SCHEMA = "EDGE_MISSING_SCHEMA"  # Edge has 'n' but no 's' (schema SAID)
    EDGE_NON_OBJECT_FORMAT = "EDGE_NON_OBJECT_FORMAT"  # Edge is direct SAID string, not {n,s} object
    DOSSIER_HAS_ISSUEE = "DOSSIER_HAS_ISSUEE"  # Root dossier ACDC has 'issuee' or 'ri'
    DOSSIER_HAS_PREV_EDGE = "DOSSIER_HAS_PREV_EDGE"  # Dossier has 'prev' edge (versioning)
    EVIDENCE_IN_ATTRIBUTES = "EVIDENCE_IN_ATTRIBUTES"  # Evidence-like data in 'a' not 'e'
    JOINT_ISSUANCE_OPERATOR = "JOINT_ISSUANCE_OPERATOR"  # thr/fin/rev operators detected


@dataclass(frozen=True)
class DossierWarning:
    """Warning for ToIP spec violations that don't fail verification.

    These warnings are informational and do not affect the validation result.
    They are propagated to the API response for transparency.

    Attributes:
        code: Warning code from ToIPWarningCode enum.
        message: Human-readable warning message.
        said: SAID of the credential that triggered the warning (optional).
        field_path: JSON path to the problematic field (e.g., "e.vetting").
    """

    code: ToIPWarningCode
    message: str
    said: Optional[str] = None
    field_path: Optional[str] = None


@dataclass(frozen=True)
class ACDCNode:
    """ACDC credential node.

    ACDC (Authentic Chained Data Container) is a KERI-based credential format.
    Each ACDC has a Self-Addressing Identifier (SAID) that cryptographically
    binds the content to its identifier.

    Attributes:
        said: Self-Addressing Identifier (d field)
        issuer: Issuer AID (i field)
        schema: Schema SAID (s field)
        attributes: Attributes block (a field) - may be SAID for compact form
        edges: Edges to other ACDCs (e field)
        rules: Rules block (r field)
        raw: Original parsed data (for SAID recomputation in Tier 2)
    """

    said: str
    issuer: str
    schema: str
    attributes: Optional[Any] = None  # Dict or str (SAID for compact)
    edges: Optional[Dict[str, Any]] = None
    rules: Optional[Dict[str, Any]] = None
    raw: Dict[str, Any] = field(default_factory=dict)

    def __hash__(self) -> int:
        """Hash by SAID for use in sets/dicts."""
        return hash(self.said)


@dataclass
class DossierDAG:
    """DAG of ACDC nodes.

    A dossier is a Directed Acyclic Graph where:
    - Each node is an ACDC identified by its SAID
    - Edges represent credential chaining (e field references)
    - Exactly one root node (no incoming edges) for standard dossiers
    - Multiple roots allowed for aggregate dossiers

    Attributes:
        nodes: Mapping of SAID to ACDCNode
        root_said: SAID of the primary root node (identified during validation)
        root_saids: List of all root SAIDs (for aggregate dossiers)
        is_aggregate: True if dossier has multiple roots (aggregate variant)
        warnings: ToIP spec compliance warnings (non-blocking)
    """

    nodes: Dict[str, ACDCNode] = field(default_factory=dict)
    root_said: Optional[str] = None
    root_saids: List[str] = field(default_factory=list)
    is_aggregate: bool = False
    warnings: List[DossierWarning] = field(default_factory=list)

    def __len__(self) -> int:
        """Return number of nodes in DAG."""
        return len(self.nodes)

    def __contains__(self, said: str) -> bool:
        """Check if SAID exists in DAG."""
        return said in self.nodes

    def get(self, said: str) -> Optional[ACDCNode]:
        """Get node by SAID, or None if not found."""
        return self.nodes.get(said)
