"""DAG validation for dossier per spec §6.1.

Validates:
- No cycles in the credential graph
- Exactly one root node (no incoming edges)
- No duplicate SAIDs

Also collects ToIP Verifiable Dossiers spec warnings (non-blocking).
"""

from typing import List, Optional, Set

from .exceptions import GraphError
from .models import ACDCNode, DossierDAG, DossierWarning, ToIPWarningCode


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

    Also populates dag.warnings with ToIP spec compliance warnings (non-blocking).

    Note: Dangling edges (references to non-existent nodes) are allowed
    in Tier 1 as they may reference external credentials.

    Args:
        dag: DossierDAG to validate (modified in place with root_said/root_saids/warnings)
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

    # Collect ToIP spec warnings (non-blocking)
    dag.warnings = _collect_toip_warnings(dag)


# -----------------------------------------------------------------------------
# ToIP Verifiable Dossiers Specification v0.6 Warning Checks
# These are informational only and do not affect validation result.
# Per VVP Spec §6.1C-D.
# -----------------------------------------------------------------------------


def _collect_toip_warnings(dag: DossierDAG) -> List[DossierWarning]:
    """Collect ToIP Verifiable Dossiers spec warnings.

    These are informational only and do not affect validation result.

    Args:
        dag: Validated DossierDAG (must have root_saids set)

    Returns:
        List of DossierWarning objects
    """
    warnings: List[DossierWarning] = []

    for said, node in dag.nodes.items():
        # Check EDGE_MISSING_SCHEMA and EDGE_NON_OBJECT_FORMAT
        warnings.extend(_check_edge_schemas(node))

        # Check DOSSIER_HAS_ISSUEE (only for roots)
        if said in dag.root_saids:
            warnings.extend(_check_root_issuee(node))

        # Check DOSSIER_HAS_PREV_EDGE (versioning) - per §6.1D
        warnings.extend(_check_prev_edge(node))

        # Check EVIDENCE_IN_ATTRIBUTES
        warnings.extend(_check_evidence_placement(node))

        # Check JOINT_ISSUANCE_OPERATOR
        warnings.extend(_check_joint_issuance(node))

    return warnings


def _check_edge_schemas(node: ACDCNode) -> List[DossierWarning]:
    """Check edge structure compliance with ToIP spec.

    Per ToIP Verifiable Dossiers v0.6 Section 3.1:
    - Edges MUST be JSON objects with 'n' (node SAID) and 's' (schema SAID)
    - Direct SAID strings are non-compliant with stricter ToIP format
    """
    warnings: List[DossierWarning] = []
    if not node.edges:
        return warnings

    for edge_name, edge_ref in node.edges.items():
        if edge_name == "d":
            continue  # Skip edge block SAID
        if isinstance(edge_ref, dict):
            # Object format - check for missing schema SAID
            if "n" in edge_ref and "s" not in edge_ref:
                warnings.append(
                    DossierWarning(
                        code=ToIPWarningCode.EDGE_MISSING_SCHEMA,
                        message=f"Edge '{edge_name}' has node reference but no schema SAID",
                        said=node.said,
                        field_path=f"e.{edge_name}",
                    )
                )
        elif isinstance(edge_ref, str):
            # Direct SAID string - non-compliant with ToIP v0.6 edge format
            warnings.append(
                DossierWarning(
                    code=ToIPWarningCode.EDGE_NON_OBJECT_FORMAT,
                    message=f"Edge '{edge_name}' is direct SAID string, not ToIP {{n,s}} object format",
                    said=node.said,
                    field_path=f"e.{edge_name}",
                )
            )

    return warnings


def _check_root_issuee(node: ACDCNode) -> List[DossierWarning]:
    """DOSSIER_HAS_ISSUEE: Root dossier ACDC has 'issuee' or 'ri' field.

    Per ToIP spec, dossiers are issuer-only containers without an issuee.
    They are curator's attestations, not credentials issued to someone.
    """
    warnings: List[DossierWarning] = []
    raw = node.raw

    # Check for 'issuee' in attributes (ACDC uses 'i' for issuee in 'a' block)
    attrs = raw.get("a", {})
    if isinstance(attrs, dict):
        if "i" in attrs:
            warnings.append(
                DossierWarning(
                    code=ToIPWarningCode.DOSSIER_HAS_ISSUEE,
                    message="Root dossier ACDC has issuee field (a.i)",
                    said=node.said,
                    field_path="a.i",
                )
            )

    # Check for registry ID (indicates issuance tracking, unusual for dossier root)
    if "ri" in raw:
        warnings.append(
            DossierWarning(
                code=ToIPWarningCode.DOSSIER_HAS_ISSUEE,
                message="Root dossier ACDC has registry ID (ri) field",
                said=node.said,
                field_path="ri",
            )
        )

    return warnings


def _check_evidence_placement(node: ACDCNode) -> List[DossierWarning]:
    """EVIDENCE_IN_ATTRIBUTES: Evidence-like data in 'a' instead of 'e'.

    Per ToIP spec, cryptographic evidence/proofs should be in edges ('e'),
    not in attributes ('a'). The 'a' block is for proximate metadata.
    """
    warnings: List[DossierWarning] = []
    attrs = node.attributes

    if not isinstance(attrs, dict):
        return warnings

    # Evidence-like field patterns that suggest misplaced evidence
    evidence_patterns = {"proof", "signature", "seal", "anchor", "digest", "evidence"}

    for field_name in attrs.keys():
        normalized = field_name.lower()
        for pattern in evidence_patterns:
            if pattern in normalized:
                warnings.append(
                    DossierWarning(
                        code=ToIPWarningCode.EVIDENCE_IN_ATTRIBUTES,
                        message=f"Evidence-like field '{field_name}' in attributes (should be in edges)",
                        said=node.said,
                        field_path=f"a.{field_name}",
                    )
                )
                break  # Only one warning per field

    return warnings


def _check_joint_issuance(node: ACDCNode) -> List[DossierWarning]:
    """JOINT_ISSUANCE_OPERATOR: thr/fin/rev operators detected.

    Joint issuance operators (per ToIP spec Section 4.4) indicate multi-party
    credential issuance which requires special handling not yet fully supported.
    """
    warnings: List[DossierWarning] = []
    rules = node.rules

    if not isinstance(rules, dict):
        return warnings

    # Check for joint issuance operators in rules block
    joint_operators = {"thr", "fin", "rev"}

    for op in joint_operators:
        if op in rules:
            warnings.append(
                DossierWarning(
                    code=ToIPWarningCode.JOINT_ISSUANCE_OPERATOR,
                    message=f"Joint issuance operator '{op}' detected but not fully supported",
                    said=node.said,
                    field_path=f"r.{op}",
                )
            )

    return warnings


def _check_prev_edge(node: ACDCNode) -> List[DossierWarning]:
    """DOSSIER_HAS_PREV_EDGE: Dossier has versioning 'prev' edge.

    Per ToIP spec §4.1.3 and VVP Spec §6.1D, a dossier MAY link to a
    prior version via a 'prev' edge. Verifiers SHOULD record its presence.
    This is informational for audit/compliance scenarios.
    """
    warnings: List[DossierWarning] = []
    if not node.edges:
        return warnings

    if "prev" in node.edges:
        warnings.append(
            DossierWarning(
                code=ToIPWarningCode.DOSSIER_HAS_PREV_EDGE,
                message="Dossier has 'prev' edge indicating versioned dossier chain",
                said=node.said,
                field_path="e.prev",
            )
        )

    return warnings
