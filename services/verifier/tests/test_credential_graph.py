"""Tests for credential graph builder."""

import pytest

from app.vvp.acdc import (
    ACDC,
    CredentialGraph,
    CredentialNode,
    CredentialStatus,
    ResolutionSource,
    build_credential_graph,
    credential_graph_to_dict,
)


class TestBuildCredentialGraph:
    """Tests for build_credential_graph function."""

    def test_single_credential_from_root(self):
        """Test graph with single credential from trusted root."""
        root_aid = "D" + "R" * 43
        trusted_roots = {root_aid}

        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid=root_aid,
            schema_said="",
            attributes={"LEI": "984500DEE7537A07Y615"},
            raw={}
        )

        dossier = {acdc.said: acdc}
        graph = build_credential_graph(dossier, trusted_roots)

        # Should have 2 nodes: credential + synthetic root
        assert len(graph.nodes) == 2
        assert acdc.said in graph.nodes
        assert graph.root_aid == root_aid
        assert graph.trust_path_valid is True

        # Check credential node
        node = graph.nodes[acdc.said]
        assert node.credential_type == "LE"
        assert node.in_dossier is True
        assert "LEI" in node.attributes

    def test_chain_with_edges(self):
        """Test graph with credential chain via edges."""
        root_aid = "D" + "R" * 43
        le_said = "E" + "L" * 43
        ape_said = "E" + "A" * 43
        trusted_roots = {root_aid}

        # LE credential from root
        le_cred = ACDC(
            version="",
            said=le_said,
            issuer_aid=root_aid,
            schema_said="",
            attributes={"LEI": "984500DEE7537A07Y615"},
            raw={}
        )

        # APE credential with vetting edge to LE
        ape_cred = ACDC(
            version="",
            said=ape_said,
            issuer_aid="D" + "I" * 43,
            schema_said="",
            edges={"vetting": {"n": le_said}},
            raw={}
        )

        dossier = {le_said: le_cred, ape_said: ape_cred}
        graph = build_credential_graph(dossier, trusted_roots)

        # Should have 3 nodes: LE, APE, synthetic root
        assert len(graph.nodes) == 3

        # Check APE node has edge to LE
        ape_node = graph.nodes[ape_said]
        assert le_said in ape_node.edges_to
        assert ape_node.credential_type == "APE"

        # Check edges
        edge_types = {(e.from_said, e.edge_type) for e in graph.edges}
        assert (ape_said, "vetting") in edge_types
        assert (le_said, "issued_by") in edge_types

    def test_layers_computed_correctly(self):
        """Test that layers are computed from root to leaves."""
        root_aid = "D" + "R" * 43
        le_said = "E" + "L" * 43
        ape_said = "E" + "A" * 43
        trusted_roots = {root_aid}

        le_cred = ACDC(
            version="",
            said=le_said,
            issuer_aid=root_aid,
            schema_said="",
            attributes={"LEI": "1234"},
            raw={}
        )

        ape_cred = ACDC(
            version="",
            said=ape_said,
            issuer_aid="D" + "I" * 43,
            schema_said="",
            edges={"vetting": {"n": le_said}},
            raw={}
        )

        dossier = {le_said: le_cred, ape_said: ape_cred}
        graph = build_credential_graph(dossier, trusted_roots)

        # Layer 0 should be root
        assert len(graph.layers) >= 2
        assert any("root:" in said for said in graph.layers[0])

        # LE should come after root
        # APE should come after LE

    def test_no_trusted_root(self):
        """Test graph when no credential chains to root."""
        trusted_roots = {"D" + "X" * 43}  # Different from issuer

        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid="D" + "I" * 43,  # Not in trusted_roots
            schema_said="",
            raw={}
        )

        dossier = {acdc.said: acdc}
        graph = build_credential_graph(dossier, trusted_roots)

        assert graph.root_aid is None
        assert graph.trust_path_valid is False

    def test_revocation_status_applied(self):
        """Test that revocation status is applied to nodes."""
        root_aid = "D" + "R" * 43
        trusted_roots = {root_aid}

        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid=root_aid,
            schema_said="",
            raw={}
        )

        revocation = {acdc.said: CredentialStatus.REVOKED}

        dossier = {acdc.said: acdc}
        graph = build_credential_graph(dossier, trusted_roots, revocation)

        node = graph.nodes[acdc.said]
        assert node.status == CredentialStatus.REVOKED

    def test_empty_dossier(self):
        """Test empty dossier produces empty graph."""
        graph = build_credential_graph({}, {"D" + "R" * 43})

        assert len(graph.nodes) == 0
        assert len(graph.edges) == 0
        assert graph.trust_path_valid is False


class TestCredentialNode:
    """Tests for CredentialNode display name generation."""

    def test_le_display_name_with_lei(self):
        """Test LE credential display name."""
        root_aid = "D" + "R" * 43

        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid=root_aid,
            schema_said="",
            attributes={"LEI": "984500DEE7537A07Y615"},
            raw={}
        )

        dossier = {acdc.said: acdc}
        graph = build_credential_graph(dossier, {root_aid})

        node = graph.nodes[acdc.said]
        assert "Legal Entity" in node.display_name
        assert "984500DEE7537A07Y615" in node.display_name

    def test_tnalloc_display_name(self):
        """Test TNAlloc credential display name."""
        root_aid = "D" + "R" * 43

        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid=root_aid,
            schema_said="",
            attributes={"tn": ["+1555*"]},
            raw={}
        )

        dossier = {acdc.said: acdc}
        graph = build_credential_graph(dossier, {root_aid})

        node = graph.nodes[acdc.said]
        assert "TN Allocation" in node.display_name
        assert "+1555*" in node.display_name


class TestCredentialGraphToDict:
    """Tests for JSON serialization."""

    def test_serialization_format(self):
        """Test that graph serializes to expected format."""
        root_aid = "D" + "R" * 43
        trusted_roots = {root_aid}

        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid=root_aid,
            schema_said="E" + "S" * 43,
            attributes={"LEI": "1234"},
            raw={}
        )

        dossier = {acdc.said: acdc}
        graph = build_credential_graph(dossier, trusted_roots)
        result = credential_graph_to_dict(graph)

        # Check structure
        assert "nodes" in result
        assert "edges" in result
        assert "rootAid" in result
        assert "trustPathValid" in result
        assert "layers" in result

        # Check node structure
        cred_node = next(n for n in result["nodes"] if n["id"] == acdc.said)
        assert cred_node["issuer"] == root_aid
        assert cred_node["type"] == "LE"
        assert cred_node["inDossier"] is True
        assert cred_node["schemaSaid"] == "E" + "S" * 43

    def test_root_node_in_serialization(self):
        """Test that synthetic root node is included."""
        root_aid = "D" + "R" * 43
        trusted_roots = {root_aid}

        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid=root_aid,
            schema_said="",
            raw={}
        )

        dossier = {acdc.said: acdc}
        graph = build_credential_graph(dossier, trusted_roots)
        result = credential_graph_to_dict(graph)

        # Find root node
        root_nodes = [n for n in result["nodes"] if n["isRoot"]]
        assert len(root_nodes) == 1
        assert root_nodes[0]["type"] == "ROOT"


class TestKnownRootDisplayNames:
    """Tests for known root display names."""

    def test_provenant_root_name(self):
        """Test Provenant Global QVI gets proper display name from WELLKNOWN_AIDS."""
        provenant_aid = "ELW1FqnJZgOBR43USMu1RfVE6U1BXl6UFecIDPmJnscQ"
        trusted_roots = {provenant_aid}

        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid=provenant_aid,
            schema_said="",
            raw={}
        )

        dossier = {acdc.said: acdc}
        graph = build_credential_graph(dossier, trusted_roots)

        root_node = next(n for n in graph.nodes.values() if n.is_root)
        assert root_node.display_name == "Provenant Global"

    def test_brand_assure_issuer_name(self):
        """Test Brand assure issuer gets proper display name from WELLKNOWN_AIDS."""
        brand_assure_aid = "EKudJXsXQNzMzEhBHjs5iqZXLSF5fg1Nxs1MD-IAXqDo"
        trusted_roots = set()  # Not a trusted root

        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid=brand_assure_aid,
            schema_said="",
            raw={}
        )

        dossier = {acdc.said: acdc}
        graph = build_credential_graph(dossier, trusted_roots)

        issuer_node = next(n for n in graph.nodes.values() if n.credential_type == "ISSUER")
        assert issuer_node.display_name == "Brand assure"


class TestMultipleRoots:
    """Tests for multiple roots of trust support."""

    def test_multiple_roots_deterministic_ordering(self):
        """Graph returns roots in deterministic (sorted) order."""
        # Create roots - use different prefixes to ensure sort order
        root_z = "EZzz" + "A" * 40  # Lexicographically last
        root_a = "EAaa" + "A" * 40  # Lexicographically first
        trusted_roots = {root_z, root_a}

        acdc1 = ACDC(
            version="",
            said="E" + "1" * 43,
            issuer_aid=root_z,
            schema_said="",
            raw={}
        )
        acdc2 = ACDC(
            version="",
            said="E" + "2" * 43,
            issuer_aid=root_a,
            schema_said="",
            raw={}
        )

        dossier = {acdc1.said: acdc1, acdc2.said: acdc2}
        graph = build_credential_graph(dossier, trusted_roots)

        # Should be sorted alphabetically
        assert graph.root_aids == [root_a, root_z]
        assert graph.root_aid == root_a  # First in sorted order

        # Verify determinism - run multiple times
        for _ in range(10):
            g = build_credential_graph(dossier, trusted_roots)
            assert g.root_aids == [root_a, root_z]
            assert g.root_aid == root_a

    def test_no_trusted_roots_tracks_terminal_issuers(self):
        """Graph handles case with no trusted roots gracefully."""
        untrusted_issuer = "EXyz" + "A" * 40
        trusted_roots = set()  # Empty

        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid=untrusted_issuer,
            schema_said="",
            raw={}
        )

        dossier = {acdc.said: acdc}
        graph = build_credential_graph(dossier, trusted_roots)

        assert graph.root_aids == []
        assert graph.root_aid is None
        assert graph.trust_path_valid is False
        assert graph.terminal_issuers == [untrusted_issuer]

    def test_terminal_issuers_tracked_separately(self):
        """Untrusted chain termini are tracked in terminal_issuers."""
        trusted_root = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao"
        untrusted_issuer = "EXyz" + "A" * 40
        trusted_roots = {trusted_root}

        acdc1 = ACDC(
            version="",
            said="E" + "1" * 43,
            issuer_aid=trusted_root,
            schema_said="",
            raw={}
        )
        acdc2 = ACDC(
            version="",
            said="E" + "2" * 43,
            issuer_aid=untrusted_issuer,
            schema_said="",
            raw={}
        )

        dossier = {acdc1.said: acdc1, acdc2.said: acdc2}
        graph = build_credential_graph(dossier, trusted_roots)

        assert trusted_root in graph.root_aids
        assert untrusted_issuer in graph.terminal_issuers
        assert untrusted_issuer not in graph.root_aids
        assert trusted_root not in graph.terminal_issuers

    def test_trust_paths_valid_per_root(self):
        """Each trusted root has its own validity status."""
        root1 = "EAaa" + "A" * 40
        root2 = "EBbb" + "B" * 40
        trusted_roots = {root1, root2}

        acdc1 = ACDC(
            version="",
            said="E" + "1" * 43,
            issuer_aid=root1,
            schema_said="",
            raw={}
        )
        acdc2 = ACDC(
            version="",
            said="E" + "2" * 43,
            issuer_aid=root2,
            schema_said="",
            raw={}
        )

        dossier = {acdc1.said: acdc1, acdc2.said: acdc2}
        graph = build_credential_graph(dossier, trusted_roots)

        # Both roots should be in trust_paths_valid
        assert root1 in graph.trust_paths_valid
        assert root2 in graph.trust_paths_valid
        assert graph.trust_paths_valid[root1] is True
        assert graph.trust_paths_valid[root2] is True
        assert graph.trust_path_valid is True  # Any valid

    def test_api_response_includes_multiple_roots_fields(self):
        """API response includes new fields for multiple roots."""
        root1 = "EAaa" + "A" * 40
        root2 = "EBbb" + "B" * 40
        untrusted = "EXyz" + "X" * 40
        trusted_roots = {root1, root2}

        acdc1 = ACDC(
            version="",
            said="E" + "1" * 43,
            issuer_aid=root1,
            schema_said="",
            raw={}
        )
        acdc2 = ACDC(
            version="",
            said="E" + "2" * 43,
            issuer_aid=root2,
            schema_said="",
            raw={}
        )
        acdc3 = ACDC(
            version="",
            said="E" + "3" * 43,
            issuer_aid=untrusted,
            schema_said="",
            raw={}
        )

        dossier = {acdc1.said: acdc1, acdc2.said: acdc2, acdc3.said: acdc3}
        graph = build_credential_graph(dossier, trusted_roots)
        result = credential_graph_to_dict(graph)

        # Check new fields exist
        assert "rootAids" in result
        assert "terminalIssuers" in result
        assert "trustPathsValid" in result

        # Check values are correct and sorted
        assert result["rootAids"] == [root1, root2]  # Sorted
        assert result["rootAid"] == root1  # First in sorted order (backwards compat)
        assert result["terminalIssuers"] == [untrusted]
        assert result["trustPathsValid"] == {root1: True, root2: True}
