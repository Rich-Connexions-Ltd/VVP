"""Data models for dossier/ACDC structures per spec §6.1.

Defines:
- ACDCNode: Individual ACDC credential node
- DossierDAG: Directed Acyclic Graph of ACDCs
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class ACDCNode:
    """ACDC credential node per spec §6.1A.

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
    """DAG of ACDC nodes per spec §6.1.

    A dossier is a Directed Acyclic Graph where:
    - Each node is an ACDC identified by its SAID
    - Edges represent credential chaining (e field references)
    - Exactly one root node (no incoming edges) for standard dossiers
    - Multiple roots allowed for aggregate dossiers (per §6.1 policy)

    Attributes:
        nodes: Mapping of SAID to ACDCNode
        root_said: SAID of the primary root node (identified during validation)
        root_saids: List of all root SAIDs (for aggregate dossiers)
        is_aggregate: True if dossier has multiple roots (aggregate variant)
    """

    nodes: Dict[str, ACDCNode] = field(default_factory=dict)
    root_said: Optional[str] = None
    root_saids: List[str] = field(default_factory=list)
    is_aggregate: bool = False

    def __len__(self) -> int:
        """Return number of nodes in DAG."""
        return len(self.nodes)

    def __contains__(self, said: str) -> bool:
        """Check if SAID exists in DAG."""
        return said in self.nodes

    def get(self, said: str) -> Optional[ACDCNode]:
        """Get node by SAID, or None if not found."""
        return self.nodes.get(said)
