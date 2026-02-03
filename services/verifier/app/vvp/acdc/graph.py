"""Credential graph builder for ACDC chain visualization.

Builds a directed graph of credentials from dossier to trusted root,
suitable for UI visualization. Supports multiple roots of trust per dossier.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set

from .models import ACDC
from ..identity import WELLKNOWN_AIDS


class CredentialStatus(str, Enum):
    """Credential revocation status."""
    ACTIVE = "ACTIVE"
    REVOKED = "REVOKED"
    UNKNOWN = "UNKNOWN"


class ResolutionSource(str, Enum):
    """Where the credential was obtained from."""
    DOSSIER = "dossier"
    OOBI = "oobi"
    REGISTRY = "registry"
    SYNTHETIC = "synthetic"  # For trusted root placeholder


@dataclass
class CredentialNode:
    """Node in the credential graph for visualization."""

    # Identity
    said: str
    issuer_aid: str

    # Type and display
    credential_type: str  # LE, APE, DE, TNAlloc, Unknown
    display_name: str

    # Key attributes for display
    attributes: Dict[str, Any] = field(default_factory=dict)

    # Status
    status: CredentialStatus = CredentialStatus.UNKNOWN

    # Graph relationships
    edges_to: List[str] = field(default_factory=list)  # SAIDs this references (parents)

    # Resolution info
    in_dossier: bool = False
    resolution_source: ResolutionSource = ResolutionSource.DOSSIER
    schema_said: str = ""

    # For trusted root nodes (synthetic)
    is_root: bool = False


@dataclass
class CredentialEdge:
    """Edge in the credential graph."""
    from_said: str
    to_said: str
    edge_type: str  # "vetting", "delegation", "jl", "issued_by"


@dataclass
class CredentialGraph:
    """Complete credential chain as a directed graph.

    Supports multiple roots of trust per dossier. Each terminal issuer can
    anchor to a different root, giving the dossier multiple independent
    trust chains.
    """

    nodes: Dict[str, CredentialNode] = field(default_factory=dict)
    edges: List[CredentialEdge] = field(default_factory=list)

    # Root info - Support multiple roots with stable (sorted) ordering
    root_aids: List[str] = field(default_factory=list)  # Sorted list of trusted root AIDs
    trust_paths_valid: Dict[str, bool] = field(default_factory=dict)  # root_aid -> valid

    # Terminal issuers (untrusted chain termini, sorted for deterministic output)
    terminal_issuers: List[str] = field(default_factory=list)

    # Layers for hierarchical visualization (root first)
    layers: List[List[str]] = field(default_factory=list)

    # Errors during graph building
    errors: List[str] = field(default_factory=list)

    @property
    def root_aid(self) -> Optional[str]:
        """First root AID for backwards compatibility.

        Returns the lexicographically first trusted root, or None if no roots.
        Deterministic ordering ensures stable behavior across runs.
        """
        return self.root_aids[0] if self.root_aids else None

    @property
    def trust_path_valid(self) -> bool:
        """True if any trust path is valid."""
        return any(self.trust_paths_valid.values()) if self.trust_paths_valid else False


def _add_root_aid(graph: CredentialGraph, aid: str) -> None:
    """Add a root AID maintaining sorted order for deterministic output."""
    if aid not in graph.root_aids:
        graph.root_aids.append(aid)
        graph.root_aids.sort()


def _add_terminal_issuer(graph: CredentialGraph, aid: str) -> None:
    """Add a terminal issuer maintaining sorted order for deterministic output."""
    if aid not in graph.terminal_issuers:
        graph.terminal_issuers.append(aid)
        graph.terminal_issuers.sort()


def build_credential_graph(
    dossier_acdcs: Dict[str, ACDC],
    trusted_roots: Set[str],
    revocation_status: Optional[Dict[str, CredentialStatus]] = None,
) -> CredentialGraph:
    """Build a credential graph from dossier ACDCs.

    Args:
        dossier_acdcs: ACDCs from the dossier (SAID -> ACDC).
        trusted_roots: Set of trusted root AIDs.
        revocation_status: Optional revocation status for each SAID.

    Returns:
        CredentialGraph suitable for visualization.
    """
    graph = CredentialGraph()
    revocation_status = revocation_status or {}

    # Build nodes from dossier ACDCs
    for said, acdc in dossier_acdcs.items():
        node = _build_node_from_acdc(acdc, revocation_status.get(said))
        node.in_dossier = True
        graph.nodes[said] = node

        # Build edges from this node's edges field
        if acdc.edges:
            for edge_name, edge_ref in acdc.edges.items():
                if edge_name in ('d', 'n'):
                    continue

                target_said = None
                if isinstance(edge_ref, str):
                    target_said = edge_ref
                elif isinstance(edge_ref, dict):
                    target_said = edge_ref.get('n') or edge_ref.get('d')

                if target_said:
                    node.edges_to.append(target_said)
                    graph.edges.append(CredentialEdge(
                        from_said=said,
                        to_said=target_said,
                        edge_type=edge_name
                    ))

    # Add synthetic nodes for issuers that are trusted roots
    _add_issuer_nodes(graph, dossier_acdcs, trusted_roots)

    # Compute layers for hierarchical display
    _compute_layers(graph, trusted_roots)

    # trust_path_valid is now a computed property based on trust_paths_valid dict
    # No explicit assignment needed

    return graph


def _build_node_from_acdc(
    acdc: ACDC,
    status: Optional[CredentialStatus] = None
) -> CredentialNode:
    """Build a CredentialNode from an ACDC."""

    # Extract display attributes
    display_attrs = {}
    if acdc.attributes:
        # Common display fields
        for key in ['LEI', 'lids', 'tn', 'phone', 'name', 'loa', 'dt']:
            if key in acdc.attributes:
                value = acdc.attributes[key]
                # Handle lids array (LEI list)
                if key == 'lids' and isinstance(value, list) and value:
                    display_attrs['LEI'] = value[0]
                else:
                    display_attrs[key] = value

    # Generate display name
    cred_type = acdc.credential_type
    display_name = _generate_display_name(cred_type, display_attrs)

    return CredentialNode(
        said=acdc.said,
        issuer_aid=acdc.issuer_aid,
        credential_type=cred_type,
        display_name=display_name,
        attributes=display_attrs,
        status=status or CredentialStatus.UNKNOWN,
        schema_said=acdc.schema_said or "",
        resolution_source=ResolutionSource.DOSSIER,
    )


def _generate_display_name(cred_type: str, attrs: Dict[str, Any]) -> str:
    """Generate a human-readable display name for a credential."""

    if cred_type == "LE":
        lei = attrs.get('LEI', '')
        if lei:
            return f"Legal Entity: {lei[:20]}..."
        return "Legal Entity Credential"

    elif cred_type == "APE":
        return "Auth Phone Entity"

    elif cred_type == "DE":
        return "Delegate Entity"

    elif cred_type == "TNAlloc":
        tn = attrs.get('tn') or attrs.get('phone')
        if tn:
            if isinstance(tn, list):
                tn = tn[0] if tn else ""
            return f"TN Allocation: {tn}"
        return "TN Allocation"

    return f"Credential ({cred_type})"


def _add_issuer_nodes(
    graph: CredentialGraph,
    dossier_acdcs: Dict[str, ACDC],
    trusted_roots: Set[str]
) -> None:
    """Add synthetic nodes for issuers (trusted roots and chain terminators)."""

    # Find credentials that don't have parents in the dossier (terminal credentials)
    # These need issuer nodes to show the chain terminus
    for said, acdc in dossier_acdcs.items():
        issuer_aid = acdc.issuer_aid

        # Skip if issuer is another credential in the dossier
        # (the edge will be handled by the credential's edges field)
        issuer_is_credential = any(
            other.said == issuer_aid or other.issuer_aid == issuer_aid
            for other_said, other in dossier_acdcs.items()
            if other_said != said
        )

        # Check if this credential has no edges to other dossier credentials
        has_parent_in_dossier = False
        if acdc.edges:
            for edge_name, edge_ref in acdc.edges.items():
                if edge_name in ('d', 'n'):
                    continue
                target_said = None
                if isinstance(edge_ref, str):
                    target_said = edge_ref
                elif isinstance(edge_ref, dict):
                    target_said = edge_ref.get('n') or edge_ref.get('d')
                if target_said and target_said in dossier_acdcs:
                    has_parent_in_dossier = True
                    break

        # Add issuer node for credentials without parents in dossier
        if not has_parent_in_dossier:
            is_trusted = issuer_aid in trusted_roots
            issuer_node_id = f"root:{issuer_aid}" if is_trusted else f"issuer:{issuer_aid}"

            if issuer_node_id not in graph.nodes:
                graph.nodes[issuer_node_id] = CredentialNode(
                    said=issuer_node_id,
                    issuer_aid=issuer_aid,
                    credential_type="ROOT" if is_trusted else "ISSUER",
                    display_name=_get_root_display_name(issuer_aid) if is_trusted else _get_issuer_display_name(issuer_aid),
                    is_root=is_trusted,
                    status=CredentialStatus.ACTIVE if is_trusted else CredentialStatus.UNKNOWN,
                    resolution_source=ResolutionSource.SYNTHETIC,
                )
                if is_trusted:
                    _add_root_aid(graph, issuer_aid)
                    graph.trust_paths_valid[issuer_aid] = True
                else:
                    _add_terminal_issuer(graph, issuer_aid)

            # Add issued_by edge
            graph.edges.append(CredentialEdge(
                from_said=said,
                to_said=issuer_node_id,
                edge_type="issued_by"
            ))
            graph.nodes[said].edges_to.append(issuer_node_id)


def _get_root_display_name(aid: str) -> str:
    """Get display name for a trusted root AID.

    Uses the centralized WELLKNOWN_AIDS registry from identity.py.
    """
    if aid in WELLKNOWN_AIDS:
        name, _ = WELLKNOWN_AIDS[aid]
        return name
    return f"Trusted Root: {aid[:16]}..."


def _get_issuer_display_name(aid: str) -> str:
    """Get display name for an untrusted issuer AID.

    Uses the centralized WELLKNOWN_AIDS registry from identity.py.
    """
    if aid in WELLKNOWN_AIDS:
        name, _ = WELLKNOWN_AIDS[aid]
        return name
    return f"Issuer: {aid[:16]}..."


def _compute_layers(graph: CredentialGraph, trusted_roots: Set[str]) -> None:
    """Compute layers for hierarchical visualization.

    Layer 0 = root/issuer nodes, increasing layers toward leaf credentials.
    """
    if not graph.nodes:
        return

    # Find root nodes (trusted roots) and issuer nodes (untrusted chain terminators)
    # Both serve as starting points for layer computation
    root_nodes = [
        said for said, node in graph.nodes.items()
        if node.is_root or node.credential_type == "ISSUER"
    ]

    if not root_nodes:
        # No root/issuer found - just return nodes in order
        graph.layers = [list(graph.nodes.keys())]
        return

    # BFS from roots to compute layers
    visited: Set[str] = set()
    layers: List[List[str]] = []
    current_layer = root_nodes

    while current_layer:
        layers.append(current_layer)
        visited.update(current_layer)

        # Find nodes that point TO any node in current layer
        next_layer = []
        for said, node in graph.nodes.items():
            if said in visited:
                continue
            # Check if this node has an edge to any node in current layer
            if any(edge_to in current_layer for edge_to in node.edges_to):
                next_layer.append(said)

        current_layer = next_layer

    # Add any remaining nodes not connected to root
    remaining = [said for said in graph.nodes if said not in visited]
    if remaining:
        layers.append(remaining)
        graph.errors.append("Some credentials not connected to trusted root")

    graph.layers = layers


def credential_graph_to_dict(graph: CredentialGraph) -> Dict[str, Any]:
    """Convert CredentialGraph to a JSON-serializable dict for API response.

    Note: rootAids and terminalIssuers are sorted lists for deterministic output.
    trustPathsValid is keyed only by trusted roots (AIDs in rootAids).
    """
    return {
        "nodes": [
            {
                "id": node.said,
                "issuer": node.issuer_aid,
                "type": node.credential_type,
                "displayName": node.display_name,
                "attributes": node.attributes,
                "status": node.status.value,
                "inDossier": node.in_dossier,
                "isRoot": node.is_root,
                "schemaSaid": node.schema_said,
                "edgesTo": node.edges_to,
                # Include edges with their types for UI rendering
                "edges": {
                    edge.edge_type: edge.to_said
                    for edge in graph.edges
                    if edge.from_said == node.said
                },
            }
            for node in graph.nodes.values()
        ],
        "edges": [
            {
                "from": edge.from_said,
                "to": edge.to_said,
                "type": edge.edge_type,
            }
            for edge in graph.edges
        ],
        # Multiple roots support (sorted for deterministic output)
        "rootAids": graph.root_aids,  # All trusted root AIDs (sorted list)
        "rootAid": graph.root_aid,  # Backwards compat (first sorted root)
        "trustPathValid": graph.trust_path_valid,  # True if any path valid
        "trustPathsValid": graph.trust_paths_valid,  # Per-root status (trusted only)
        # Terminal issuers (untrusted chain termini, sorted list)
        "terminalIssuers": graph.terminal_issuers,
        "layers": graph.layers,
        "errors": graph.errors,
    }
