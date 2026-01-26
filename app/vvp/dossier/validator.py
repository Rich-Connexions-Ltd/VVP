"""DAG validation for dossier per spec §6.1.

Validates:
- No cycles in the credential graph
- Exactly one root node (no incoming edges)
- No duplicate SAIDs
"""

from typing import List, Optional, Set

from .exceptions import GraphError
from .models import ACDCNode, DossierDAG


def extract_edge_targets(acdc: ACDCNode) -> Set[str]:
    """Extract SAIDs of ACDCs referenced in edges.

    Edge structure per ACDC spec:
    - e field is a dict of labeled edges
    - Each edge may have "n" field pointing to target SAID
    - The "d" key in edges is the edge block's own SAID (skip it)

    Args:
        acdc: ACDC node to extract edges from

    Returns:
        Set of SAIDs referenced by this node's edges
    """
    targets: Set[str] = set()
    if not acdc.edges:
        return targets

    for key, value in acdc.edges.items():
        if key == "d":
            # Skip edge block SAID
            continue
        if isinstance(value, dict) and "n" in value:
            # Structured edge with node reference
            targets.add(value["n"])
        elif isinstance(value, str):
            # Direct SAID reference
            targets.add(value)

    return targets


def build_dag(nodes: List[ACDCNode]) -> DossierDAG:
    """Build DAG from list of ACDC nodes.

    Args:
        nodes: List of parsed ACDCNode objects

    Returns:
        DossierDAG with nodes indexed by SAID

    Raises:
        GraphError: If duplicate SAIDs found
    """
    dag = DossierDAG()

    for node in nodes:
        if node.said in dag.nodes:
            raise GraphError(f"Duplicate SAID: {node.said}")
        dag.nodes[node.said] = node

    return dag


def detect_cycle(dag: DossierDAG) -> Optional[List[str]]:
    """Detect cycles using DFS with color marking.

    Uses standard three-color DFS:
    - WHITE (0): Not yet visited
    - GRAY (1): Currently in recursion stack (visiting)
    - BLACK (2): Completely processed

    A cycle exists if we encounter a GRAY node during traversal.

    Args:
        dag: DossierDAG to check

    Returns:
        List of SAIDs forming cycle if found, None otherwise
    """
    WHITE, GRAY, BLACK = 0, 1, 2
    color = {said: WHITE for said in dag.nodes}
    path: List[str] = []

    def dfs(said: str) -> Optional[List[str]]:
        if said not in dag.nodes:
            # Dangling reference - not a cycle issue
            return None

        color[said] = GRAY
        path.append(said)

        for target in extract_edge_targets(dag.nodes[said]):
            if target not in dag.nodes:
                # Dangling reference to external node
                continue
            if color[target] == GRAY:
                # Found back edge = cycle
                cycle_start = path.index(target)
                return path[cycle_start:] + [target]
            if color[target] == WHITE:
                result = dfs(target)
                if result:
                    return result

        path.pop()
        color[said] = BLACK
        return None

    for said in dag.nodes:
        if color[said] == WHITE:
            cycle = dfs(said)
            if cycle:
                return cycle

    return None


def find_roots(dag: DossierDAG, allow_multiple: bool = False) -> List[str]:
    """Find root node(s) (nodes with no incoming edges).

    Per spec §6.1, a valid dossier DAG must have exactly one root node,
    unless local policy explicitly supports multiple roots (aggregate dossiers).

    Args:
        dag: DossierDAG to analyze
        allow_multiple: If True, allows multiple roots (aggregate mode per §1.4)

    Returns:
        List of root SAIDs (1 element for standard, N for aggregate)

    Raises:
        GraphError: If no root found, or multiple roots when not allowed
    """
    # Collect all nodes that are targets of edges
    referenced: Set[str] = set()
    for node in dag.nodes.values():
        referenced.update(extract_edge_targets(node))

    # Root nodes have no incoming edges (not in referenced set)
    roots = [said for said in dag.nodes if said not in referenced]

    if len(roots) == 0:
        raise GraphError(
            "No root node found (all nodes have incoming edges - possible cycle)"
        )
    if len(roots) > 1 and not allow_multiple:
        raise GraphError(
            f"Multiple root nodes found: {sorted(roots)}. "
            "Dossier must have exactly one root. "
            "Enable VVP_ALLOW_AGGREGATE_DOSSIERS for aggregate support."
        )

    return roots


def find_root(dag: DossierDAG) -> str:
    """Find single root node (backward compatibility).

    Per spec §6.1, a valid dossier DAG must have exactly one root node.

    Args:
        dag: DossierDAG to analyze

    Returns:
        SAID of the root node

    Raises:
        GraphError: If no root or multiple roots found
    """
    roots = find_roots(dag, allow_multiple=False)
    return roots[0]


def validate_dag(dag: DossierDAG, allow_aggregate: bool = False) -> None:
    """Validate DAG structure per spec §6.1.

    Checks:
    1. No cycles (would violate DAG property)
    2. Exactly one root node (entry point for verification)
       - Unless allow_aggregate=True (per §1.4 aggregate variant support)

    Note: Dangling edges (references to non-existent nodes) are allowed
    in Tier 1 as they may reference external credentials.

    Args:
        dag: DossierDAG to validate (modified in place with root_said/root_saids)
        allow_aggregate: If True, allows multiple roots (aggregate dossiers per §1.4)

    Raises:
        GraphError: If validation fails
    """
    if not dag.nodes:
        raise GraphError("Empty dossier (no ACDC nodes)")

    # Check for cycles first
    cycle = detect_cycle(dag)
    if cycle:
        cycle_path = " -> ".join(cycle)
        raise GraphError(f"Cycle detected: {cycle_path}")

    # Find and set root(s)
    roots = find_roots(dag, allow_multiple=allow_aggregate)
    dag.root_saids = roots
    dag.root_said = roots[0]  # Primary root for backward compatibility
    dag.is_aggregate = len(roots) > 1
