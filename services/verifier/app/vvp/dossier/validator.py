"""DAG validation for dossier per spec §6.1.

Validates:
- No cycles in the credential graph
- Exactly one root node (no incoming edges)
- No duplicate SAIDs

Also collects ToIP Verifiable Dossiers spec warnings (non-blocking).
"""

import logging
from typing import Any, Callable, Dict, FrozenSet, List, Optional, Set, Tuple

from common.vvp.models import ACDC
from common.vvp.schema.registry import CredentialClassification, SchemaGovernanceStatus

from ..api_models import ClaimStatus
from .exceptions import GraphError
from .models import (
    ACDCNode,
    DossierDAG,
    DossierWarning,
    EdgeOperator,
    EdgeValidationWarning,
    ToIPWarningCode,
)

log = logging.getLogger(__name__)


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


# -----------------------------------------------------------------------------
# Edge Operator Validation (I2I/DI2I/NI2I)
# Per ACDC specification, edge operators define issuer-issuee constraints.
# -----------------------------------------------------------------------------


def _get_issuee_from_attributes(attributes: Optional[Any]) -> Optional[str]:
    """Extract issuee AID from ACDC attributes block.

    Per ACDC spec, the issuee may be in 'i', 'issuee', or 'holder' field.

    Args:
        attributes: ACDC attributes (dict, str SAID, or None)

    Returns:
        Issuee AID string or None if not found/not a dict
    """
    if not isinstance(attributes, dict):
        return None
    return (
        attributes.get("i") or
        attributes.get("issuee") or
        attributes.get("holder")
    )


def _get_edge_operator(edge_ref: Any) -> EdgeOperator:
    """Extract edge operator from edge reference.

    Per ACDC spec, the 'o' field specifies the operator. If omitted,
    defaults to I2I (Issuer-to-Issuee).

    Args:
        edge_ref: Edge reference (dict or string SAID)

    Returns:
        EdgeOperator enum value (defaults to I2I)
    """
    if isinstance(edge_ref, dict):
        op_str = edge_ref.get("o", "I2I")
        try:
            return EdgeOperator(op_str)
        except ValueError:
            return EdgeOperator.I2I  # Unknown operator defaults to I2I
    return EdgeOperator.I2I  # Bare SAID string defaults to I2I


def validate_i2i_edge(
    child: ACDCNode,
    parent: ACDCNode,
    edge_name: str
) -> Optional[EdgeValidationWarning]:
    """Validate I2I edge constraint: child.issuer == parent.issuee.

    Per ACDC spec, I2I (Issuer-to-Issuee) is the default and strictest
    operator. It requires that the child credential's issuer AID matches
    the parent credential's issuee AID, creating a direct chain of authority.

    Args:
        child: The child ACDCNode (contains the edge)
        parent: The parent ACDCNode (edge target)
        edge_name: Name of the edge (for error reporting)

    Returns:
        EdgeValidationWarning if constraint violated, None if valid
    """
    child_issuer = child.issuer
    parent_issuee = _get_issuee_from_attributes(parent.attributes)

    if not parent_issuee:
        # Parent is bearer credential - I2I doesn't apply
        return None

    if child_issuer != parent_issuee:
        return EdgeValidationWarning(
            operator=EdgeOperator.I2I,
            edge_name=edge_name,
            child_said=child.said,
            parent_said=parent.said,
            constraint_violated=(
                f"issuer {child_issuer[:16]}... != issuee {parent_issuee[:16]}..."
            )
        )
    return None


def validate_di2i_edge(
    child: ACDCNode,
    parent: ACDCNode,
    edge_name: str,
    dossier_nodes: Dict[str, ACDCNode]
) -> Optional[EdgeValidationWarning]:
    """Validate DI2I edge constraint: child.issuer == parent.issuee OR delegated.

    Per ACDC spec, DI2I (Delegated-Issuer-to-Issuee) extends I2I to allow
    the child's issuer to be a delegated AID from the parent's issuee.

    Phase 1 Implementation: Uses dossier-based delegation checking only.
    Looks for DE (Delegate Entity) credentials in the dossier that prove
    the delegation chain from child.issuer to parent.issuee.

    KEL-based delegated AID verification is deferred to a future phase.

    Args:
        child: The child ACDCNode (contains the edge)
        parent: The parent ACDCNode (edge target)
        edge_name: Name of the edge (for error reporting)
        dossier_nodes: All ACDCNodes in the dossier for delegation lookup

    Returns:
        EdgeValidationWarning if constraint violated, None if valid
    """
    child_issuer = child.issuer
    parent_issuee = _get_issuee_from_attributes(parent.attributes)

    if not parent_issuee:
        # Parent is bearer credential - DI2I doesn't apply
        return None

    # Check direct match first (satisfies I2I, therefore DI2I)
    if child_issuer == parent_issuee:
        return None

    # Check dossier-based delegation
    if _check_dossier_delegation(child_issuer, parent_issuee, dossier_nodes):
        return None

    return EdgeValidationWarning(
        operator=EdgeOperator.DI2I,
        edge_name=edge_name,
        child_said=child.said,
        parent_said=parent.said,
        constraint_violated=(
            f"issuer {child_issuer[:16]}... not delegated from {parent_issuee[:16]}..."
        )
    )


def _check_dossier_delegation(
    delegatee_aid: str,
    delegator_aid: str,
    dossier_nodes: Dict[str, ACDCNode],
    max_depth: int = 10
) -> bool:
    """Check if delegatee_aid is delegated from delegator_aid via dossier credentials.

    Looks for a chain: DE(issuee=delegatee) -> ... -> credential(issuee=delegator)

    This checks for DE (Delegate Entity) credentials where the issuee matches
    the delegatee, and the delegation edge chain terminates at a credential
    whose issuee is the delegator.

    Args:
        delegatee_aid: The AID to check as delegatee
        delegator_aid: The AID to check as delegator
        dossier_nodes: All nodes in the dossier
        max_depth: Maximum chain depth to prevent infinite loops

    Returns:
        True if delegation proven via dossier credentials, False otherwise
    """
    # Look for DE credentials where issuee == delegatee_aid
    for node in dossier_nodes.values():
        # Check if this is a DE credential (by credential_type from raw or schema)
        raw = node.raw
        cred_type = raw.get("credential_type") if raw else None
        if not cred_type:
            # Infer from schema or attributes
            attrs = node.attributes if isinstance(node.attributes, dict) else {}
            if "delegate" in str(attrs).lower():
                cred_type = "DE"

        if cred_type != "DE":
            continue

        de_issuee = _get_issuee_from_attributes(node.attributes)
        if de_issuee != delegatee_aid:
            continue

        # Found a DE with issuee == delegatee - walk delegation chain
        visited: Set[str] = {node.said}
        current = node
        depth = 0

        while depth < max_depth:
            target = _find_delegation_target(current, dossier_nodes)
            if not target:
                break
            if target.said in visited:
                break  # Cycle detected

            visited.add(target.said)

            target_issuee = _get_issuee_from_attributes(target.attributes)
            if target_issuee == delegator_aid:
                return True  # Found complete delegation chain

            # Check if target is another DE to continue walking
            target_raw = target.raw
            target_type = target_raw.get("credential_type") if target_raw else None
            if target_type == "DE":
                current = target
                depth += 1
            else:
                break  # Non-DE terminus, chain incomplete

    return False


def _find_delegation_target(
    node: ACDCNode,
    dossier_nodes: Dict[str, ACDCNode]
) -> Optional[ACDCNode]:
    """Find the target of a delegation edge from a DE credential.

    Looks for edges named 'delegation', 'd', 'delegate', 'delegator', or 'issuer'.

    Args:
        node: The DE credential node
        dossier_nodes: All nodes in the dossier

    Returns:
        The target ACDCNode, or None if not found
    """
    if not node.edges:
        return None

    delegation_edge_names = ("delegation", "d", "delegate", "delegator", "issuer")

    for edge_name, edge_ref in node.edges.items():
        if edge_name.lower() not in delegation_edge_names:
            continue

        # Extract target SAID
        target_said = None
        if isinstance(edge_ref, str):
            target_said = edge_ref
        elif isinstance(edge_ref, dict):
            target_said = edge_ref.get("n") or edge_ref.get("d")

        if target_said and target_said in dossier_nodes:
            return dossier_nodes[target_said]

    return None


def validate_ni2i_edge(
    child: ACDCNode,
    parent: ACDCNode,
    edge_name: str
) -> Optional[EdgeValidationWarning]:
    """Validate NI2I edge constraint: no constraint (permissive).

    Per ACDC spec, NI2I (Not-Issuer-to-Issuee) is the permissive operator
    that allows any issuer-issuee relationship. It's used for reference-only
    edges where no authority transfer is implied.

    Args:
        child: The child ACDCNode (contains the edge)
        parent: The parent ACDCNode (edge target)
        edge_name: Name of the edge (for error reporting)

    Returns:
        Always returns None (NI2I has no constraint to violate)
    """
    return None  # NI2I is permissive - always passes


def validate_edge_operator(
    child: ACDCNode,
    parent: ACDCNode,
    edge_name: str,
    edge_ref: Any,
    dossier_nodes: Optional[Dict[str, ACDCNode]] = None
) -> Optional[EdgeValidationWarning]:
    """Validate an edge against its operator constraint.

    Dispatches to the appropriate validator based on the edge operator.

    Args:
        child: The child ACDCNode (contains the edge)
        parent: The parent ACDCNode (edge target)
        edge_name: Name of the edge
        edge_ref: The edge reference (dict or string SAID)
        dossier_nodes: All nodes in dossier (needed for DI2I validation)

    Returns:
        EdgeValidationWarning if constraint violated, None if valid
    """
    operator = _get_edge_operator(edge_ref)

    if operator == EdgeOperator.I2I:
        return validate_i2i_edge(child, parent, edge_name)
    elif operator == EdgeOperator.DI2I:
        return validate_di2i_edge(
            child, parent, edge_name,
            dossier_nodes or {}
        )
    elif operator == EdgeOperator.NI2I:
        return validate_ni2i_edge(child, parent, edge_name)
    else:
        # Unknown operator - treat as I2I (strictest)
        return validate_i2i_edge(child, parent, edge_name)


def validate_all_edge_operators(
    dag: DossierDAG
) -> List[EdgeValidationWarning]:
    """Validate all edge operators in a dossier DAG.

    Checks every edge in the DAG against its operator constraint and
    returns a list of warnings for any violations.

    Args:
        dag: The DossierDAG to validate

    Returns:
        List of EdgeValidationWarning for any constraint violations
    """
    warnings: List[EdgeValidationWarning] = []

    for child_said, child in dag.nodes.items():
        if not child.edges:
            continue

        for edge_name, edge_ref in child.edges.items():
            if edge_name in ("d", "n"):
                continue  # Skip SAID fields

            # Get target SAID
            target_said = None
            if isinstance(edge_ref, str):
                target_said = edge_ref
            elif isinstance(edge_ref, dict):
                target_said = edge_ref.get("n") or edge_ref.get("d")

            if not target_said:
                continue

            # Look up parent in DAG
            parent = dag.nodes.get(target_said)
            if not parent:
                continue  # Dangling reference - can't validate operator

            # Validate the edge operator
            warning = validate_edge_operator(
                child, parent, edge_name, edge_ref, dag.nodes
            )
            if warning:
                warnings.append(warning)

    return warnings


def validate_edge_schema(
    edge_ref: Any,
    target_node: ACDCNode,
    edge_name: str,
    source_said: str
) -> Optional[DossierWarning]:
    """Validate that target credential matches edge schema constraint.

    Per ToIP spec, edges with 's' field should have targets matching that
    schema SAID. This is a type-safety check.

    Policy: Schema constraint violations are warnings only (INDETERMINATE),
    not hard failures, for backward compatibility.

    Args:
        edge_ref: The edge reference (dict or string SAID)
        target_node: The target ACDCNode
        edge_name: Name of the edge
        source_said: SAID of the source credential (for warning)

    Returns:
        DossierWarning if schema mismatch, None if valid or no constraint
    """
    if not isinstance(edge_ref, dict):
        return None  # Bare SAID has no schema constraint

    expected_schema = edge_ref.get("s")
    if not expected_schema:
        return None  # No schema constraint specified

    actual_schema = target_node.schema
    if expected_schema != actual_schema:
        return DossierWarning(
            code=ToIPWarningCode.EDGE_SCHEMA_MISMATCH,
            message=f"Edge '{edge_name}' schema constraint violated",
            said=source_said,
            field_path=f"e.{edge_name}.s",
            details=f"expected {expected_schema[:20]}..., got {actual_schema[:20]}..."
        )

    return None


def validate_all_edge_schemas(dag: DossierDAG) -> List[DossierWarning]:
    """Validate all edge schema constraints in a dossier DAG.

    Args:
        dag: The DossierDAG to validate

    Returns:
        List of DossierWarning for any schema mismatches
    """
    warnings: List[DossierWarning] = []

    for source_said, source in dag.nodes.items():
        if not source.edges:
            continue

        for edge_name, edge_ref in source.edges.items():
            if edge_name in ("d", "n"):
                continue

            # Get target SAID
            target_said = None
            if isinstance(edge_ref, str):
                target_said = edge_ref
            elif isinstance(edge_ref, dict):
                target_said = edge_ref.get("n") or edge_ref.get("d")

            if not target_said:
                continue

            target = dag.nodes.get(target_said)
            if not target:
                continue  # Dangling reference

            warning = validate_edge_schema(edge_ref, target, edge_name, source_said)
            if warning:
                warnings.append(warning)

    return warnings


# ---------------------------------------------------------------------------
# Dossier CVD Root Edge Validation (Sprint 88, Checklist 8.8)
# Validates that the dossier root credential's edges conform to the
# normative dossier schema contract (EH1jN4U4...).
# ---------------------------------------------------------------------------

DOSSIER_CVD_REQUIRED_EDGES: FrozenSet[str] = frozenset({
    "vetting", "alloc", "tnalloc", "delsig",
})
DOSSIER_CVD_OPTIONAL_EDGES: FrozenSet[str] = frozenset({
    "bownr", "bproxy",
})
DOSSIER_CVD_ALL_EDGES: FrozenSet[str] = (
    DOSSIER_CVD_REQUIRED_EDGES | DOSSIER_CVD_OPTIONAL_EDGES
)


def validate_dossier_cvd_edges(
    root_acdc: ACDC,
    dossier_acdcs: Dict[str, ACDC],
    classifications: Dict[str, CredentialClassification],
) -> Tuple[ClaimStatus, List[str]]:
    """Validate dossier CVD root edges per the dossier schema contract.

    The dossier root is a Compact Verifiable Document (CVD) with schema
    EH1jN4U4LMYHmPVI4FYdZ10bIPR7YWKp8TDdZ9Y9Al-P. Its edges are
    structural slots defined by the schema, NOT credential-internal edges.

    Checks:
    1. All 4 required edges are present (vetting, alloc, tnalloc, delsig)
    2. Each edge's target SAID references a credential in the dossier
    3. Each edge's target has GOVERNED classification
    4. Optional edges (bownr, bproxy) are valid if present

    Does NOT re-validate credential-internal edges — those are handled by
    EDGE_RULES in acdc/verifier.py and VLEI_CHAIN_REQUIREMENTS in vlei_chain.py.

    Args:
        root_acdc: The dossier root ACDC credential.
        dossier_acdcs: Map of SAID → ACDC for all credentials in the dossier.
        classifications: Map of SAID → CredentialClassification for each ACDC.

    Returns:
        Tuple of (ClaimStatus, list of evidence/warning strings):
        - VALID if all required edges present with governed targets
        - INVALID if required edges missing or targets not in dossier
        - INDETERMINATE if targets present but non-GOVERNED
    """
    evidence: List[str] = []
    status = ClaimStatus.VALID

    root_edges = root_acdc.edges or {}

    # Check all required edges are present
    for required_edge in sorted(DOSSIER_CVD_REQUIRED_EDGES):
        if required_edge not in root_edges:
            evidence.append(
                f"CVD_MISSING_REQUIRED_EDGE: dossier root missing "
                f"required edge '{required_edge}'"
            )
            status = ClaimStatus.INVALID

    if status == ClaimStatus.INVALID:
        return status, evidence

    # Validate each known edge (required + optional if present)
    for edge_name, edge_ref in root_edges.items():
        if edge_name == "d":
            continue  # Skip edge block SAID

        # Extract target SAID
        target_said = None
        if isinstance(edge_ref, str):
            target_said = edge_ref
        elif isinstance(edge_ref, dict):
            target_said = edge_ref.get("n") or edge_ref.get("d")

        if not target_said:
            continue

        is_required = edge_name in DOSSIER_CVD_REQUIRED_EDGES
        is_known = edge_name in DOSSIER_CVD_ALL_EDGES

        # Check target is in dossier
        if target_said not in dossier_acdcs:
            if is_required:
                evidence.append(
                    f"CVD_TARGET_NOT_IN_DOSSIER: required edge '{edge_name}' "
                    f"target {target_said[:20]}... not found in dossier"
                )
                status = ClaimStatus.INVALID
            elif is_known:
                evidence.append(
                    f"CVD_TARGET_NOT_IN_DOSSIER: optional edge '{edge_name}' "
                    f"target {target_said[:20]}... not found in dossier"
                )
            continue

        # Check target has GOVERNED classification
        classification = classifications.get(target_said)
        if classification and not classification.is_governed:
            code = "CVD_TARGET_NOT_GOVERNED"
            msg = (
                f"{code}: edge '{edge_name}' target "
                f"{target_said[:20]}... has status "
                f"{classification.governance_status.value}"
            )
            evidence.append(msg)
            if status != ClaimStatus.INVALID:
                status = ClaimStatus.INDETERMINATE

    return status, evidence
