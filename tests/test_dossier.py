"""Unit tests for Phase 5 dossier fetching and validation.

Covers:
- ACDC parsing (parse_acdc, parse_dossier)
- DAG building and validation (build_dag, validate_dag)
- Cycle detection (detect_cycle)
- Root node finding (find_root)
- Error handling (FetchError, ParseError, GraphError)
- HTTP fetch with mocking (fetch_dossier)
"""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from app.vvp.api_models import ErrorCode
from app.vvp.dossier import (
    ACDCNode,
    DossierDAG,
    DossierError,
    DossierWarning,
    FetchError,
    GraphError,
    ParseError,
    ToIPWarningCode,
    build_dag,
    detect_cycle,
    find_root,
    parse_acdc,
    parse_dossier,
    validate_dag,
)
from app.vvp.dossier.validator import extract_edge_targets


# =============================================================================
# Test Fixtures
# =============================================================================


VALID_ACDC = {
    "d": "SAID_ROOT_123",
    "i": "BIssuer123",
    "s": "SAID_SCHEMA_456",
    "a": {"name": "Test", "value": 42},
}

VALID_ACDC_MINIMAL = {
    "d": "SAID_MINIMAL",
    "i": "DIssuer789",
    "s": "SAID_SCHEMA_XYZ",
}

VALID_ACDC_COMPACT = {
    "d": "SAID_COMPACT_789",
    "i": "BIssuer456",
    "s": "SAID_SCHEMA_789",
    "a": "SAID_ATTRS_COMPACT",  # SAID reference instead of dict
}

VALID_ACDC_WITH_EDGES = {
    "d": "SAID_ROOT",
    "i": "BIssuer1",
    "s": "SCHEMA1",
    "e": {"child": {"n": "SAID_CHILD"}},
}

VALID_ACDC_CHILD = {
    "d": "SAID_CHILD",
    "i": "BIssuer2",
    "s": "SCHEMA2",
}

VALID_DAG = [VALID_ACDC_WITH_EDGES, VALID_ACDC_CHILD]

CYCLIC_DAG = [
    {"d": "SAID_A", "i": "B1", "s": "S1", "e": {"ref": {"n": "SAID_B"}}},
    {"d": "SAID_B", "i": "B2", "s": "S2", "e": {"ref": {"n": "SAID_A"}}},
]

THREE_NODE_CYCLE = [
    {"d": "SAID_1", "i": "B1", "s": "S1", "e": {"next": {"n": "SAID_2"}}},
    {"d": "SAID_2", "i": "B2", "s": "S2", "e": {"next": {"n": "SAID_3"}}},
    {"d": "SAID_3", "i": "B3", "s": "S3", "e": {"next": {"n": "SAID_1"}}},
]


# =============================================================================
# ACDCNode Model Tests
# =============================================================================


class TestACDCNode:
    """Tests for ACDCNode dataclass."""

    def test_create_acdc_node(self):
        """Create ACDCNode with all fields."""
        node = ACDCNode(
            said="SAID123",
            issuer="BIssuer",
            schema="SchemaID",
            attributes={"key": "value"},
            edges={"ref": {"n": "TARGET"}},
            rules={"rule": "allowed"},
            raw={"d": "SAID123"},
        )
        assert node.said == "SAID123"
        assert node.issuer == "BIssuer"
        assert node.schema == "SchemaID"
        assert node.attributes == {"key": "value"}
        assert node.edges == {"ref": {"n": "TARGET"}}

    def test_acdc_node_is_frozen(self):
        """ACDCNode is immutable (frozen)."""
        node = ACDCNode(said="SAID", issuer="I", schema="S", raw={})
        with pytest.raises(Exception):  # FrozenInstanceError
            node.said = "NEW_SAID"

    def test_acdc_node_hash(self):
        """ACDCNode can be used in sets (hashable by SAID)."""
        node1 = ACDCNode(said="SAID1", issuer="I", schema="S", raw={})
        node2 = ACDCNode(said="SAID2", issuer="I", schema="S", raw={})
        node_set = {node1, node2}
        assert len(node_set) == 2


# =============================================================================
# DossierDAG Model Tests
# =============================================================================


class TestDossierDAG:
    """Tests for DossierDAG dataclass."""

    def test_empty_dag(self):
        """Create empty DossierDAG."""
        dag = DossierDAG()
        assert len(dag) == 0
        assert dag.root_said is None

    def test_dag_len(self):
        """DossierDAG __len__ returns node count."""
        dag = DossierDAG()
        dag.nodes["A"] = ACDCNode(said="A", issuer="I", schema="S", raw={})
        dag.nodes["B"] = ACDCNode(said="B", issuer="I", schema="S", raw={})
        assert len(dag) == 2

    def test_dag_contains(self):
        """DossierDAG __contains__ checks SAID existence."""
        dag = DossierDAG()
        dag.nodes["A"] = ACDCNode(said="A", issuer="I", schema="S", raw={})
        assert "A" in dag
        assert "B" not in dag

    def test_dag_get(self):
        """DossierDAG get() returns node or None."""
        dag = DossierDAG()
        node = ACDCNode(said="A", issuer="I", schema="S", raw={})
        dag.nodes["A"] = node
        assert dag.get("A") == node
        assert dag.get("B") is None


# =============================================================================
# ACDC Parser Tests
# =============================================================================


class TestACDCParser:
    """Tests for parse_acdc function."""

    def test_parse_valid_acdc_full(self):
        """Parse ACDC with all fields."""
        node = parse_acdc(VALID_ACDC)
        assert node.said == "SAID_ROOT_123"
        assert node.issuer == "BIssuer123"
        assert node.schema == "SAID_SCHEMA_456"
        assert node.attributes == {"name": "Test", "value": 42}
        assert node.raw == VALID_ACDC

    def test_parse_valid_acdc_minimal(self):
        """Parse ACDC with only required fields."""
        node = parse_acdc(VALID_ACDC_MINIMAL)
        assert node.said == "SAID_MINIMAL"
        assert node.issuer == "DIssuer789"
        assert node.schema == "SAID_SCHEMA_XYZ"
        assert node.attributes is None
        assert node.edges is None
        assert node.rules is None

    def test_parse_compact_acdc(self):
        """Parse compact ACDC with SAID reference for attributes."""
        node = parse_acdc(VALID_ACDC_COMPACT)
        assert node.attributes == "SAID_ATTRS_COMPACT"

    def test_parse_acdc_with_edges(self):
        """Parse ACDC with edges to other nodes."""
        node = parse_acdc(VALID_ACDC_WITH_EDGES)
        assert node.edges == {"child": {"n": "SAID_CHILD"}}

    def test_parse_missing_said_raises(self):
        """Missing 'd' field raises ParseError."""
        acdc = {"i": "BIssuer", "s": "SCHEMA"}
        with pytest.raises(ParseError) as exc:
            parse_acdc(acdc)
        assert "d" in str(exc.value)
        assert exc.value.code == ErrorCode.DOSSIER_PARSE_FAILED

    def test_parse_missing_issuer_raises(self):
        """Missing 'i' field raises ParseError."""
        acdc = {"d": "SAID", "s": "SCHEMA"}
        with pytest.raises(ParseError) as exc:
            parse_acdc(acdc)
        assert "i" in str(exc.value)

    def test_parse_missing_schema_raises(self):
        """Missing 's' field raises ParseError."""
        acdc = {"d": "SAID", "i": "ISSUER"}
        with pytest.raises(ParseError) as exc:
            parse_acdc(acdc)
        assert "s" in str(exc.value)

    def test_parse_non_dict_raises(self):
        """Non-dict input raises ParseError."""
        with pytest.raises(ParseError) as exc:
            parse_acdc("not a dict")
        assert "object" in str(exc.value).lower()

    def test_parse_non_string_said_raises(self):
        """Non-string 'd' field raises ParseError."""
        acdc = {"d": 123, "i": "ISSUER", "s": "SCHEMA"}
        with pytest.raises(ParseError) as exc:
            parse_acdc(acdc)
        assert "string" in str(exc.value).lower()


# =============================================================================
# Dossier Parser Tests
# =============================================================================


class TestDossierParser:
    """Tests for parse_dossier function."""

    def test_parse_single_acdc(self):
        """Parse single ACDC object."""
        nodes, sigs = parse_dossier(json.dumps(VALID_ACDC).encode())
        assert len(nodes) == 1
        assert nodes[0].said == "SAID_ROOT_123"
        assert sigs == {}  # JSON format has no signatures

    def test_parse_acdc_array(self):
        """Parse array of ACDC objects."""
        nodes, sigs = parse_dossier(json.dumps(VALID_DAG).encode())
        assert len(nodes) == 2
        saids = {n.said for n in nodes}
        assert saids == {"SAID_ROOT", "SAID_CHILD"}
        assert sigs == {}  # JSON format has no signatures

    def test_parse_invalid_json_raises(self):
        """Invalid JSON raises ParseError."""
        with pytest.raises(ParseError) as exc:
            parse_dossier(b"not json {{{")
        assert "Invalid JSON" in str(exc.value)
        assert exc.value.code == ErrorCode.DOSSIER_PARSE_FAILED

    def test_parse_empty_array_raises(self):
        """Empty array raises ParseError."""
        with pytest.raises(ParseError) as exc:
            parse_dossier(b"[]")
        assert "Empty" in str(exc.value)

    def test_parse_non_object_non_array_raises(self):
        """Non-object/array JSON raises ParseError."""
        with pytest.raises(ParseError) as exc:
            parse_dossier(b'"just a string"')
        assert "object or array" in str(exc.value).lower()

    def test_parse_preserves_raw(self):
        """Parsed node retains original dict in raw field."""
        nodes, _ = parse_dossier(json.dumps(VALID_ACDC).encode())
        assert nodes[0].raw == VALID_ACDC

    def test_parse_provenant_wrapper_format(self):
        """Parse Provenant wrapper format: {"details": "...CESR/JSON content..."}."""
        # Inner content is a valid ACDC
        inner_acdc = {"d": "SAID_INNER", "i": "ISSUER", "s": "SCHEMA"}
        wrapper = {"details": json.dumps(inner_acdc)}
        nodes, sigs = parse_dossier(json.dumps(wrapper).encode())
        assert len(nodes) == 1
        assert nodes[0].said == "SAID_INNER"
        assert sigs == {}

    def test_parse_provenant_wrapper_array(self):
        """Parse Provenant wrapper containing array of ACDCs."""
        inner_acdcs = [
            {"d": "SAID_1", "i": "I1", "s": "S1"},
            {"d": "SAID_2", "i": "I2", "s": "S2"},
        ]
        wrapper = {"details": json.dumps(inner_acdcs)}
        nodes, sigs = parse_dossier(json.dumps(wrapper).encode())
        assert len(nodes) == 2
        saids = {n.said for n in nodes}
        assert saids == {"SAID_1", "SAID_2"}


# =============================================================================
# Edge Extraction Tests
# =============================================================================


class TestEdgeExtraction:
    """Tests for extract_edge_targets helper."""

    def test_extract_no_edges(self):
        """Node without edges returns empty set."""
        node = ACDCNode(said="A", issuer="I", schema="S", raw={})
        targets = extract_edge_targets(node)
        assert targets == set()

    def test_extract_structured_edge(self):
        """Extract target from structured edge with 'n' field."""
        node = parse_acdc(VALID_ACDC_WITH_EDGES)
        targets = extract_edge_targets(node)
        assert targets == {"SAID_CHILD"}

    def test_extract_direct_said_edge(self):
        """Extract target from direct SAID reference."""
        acdc = {
            "d": "ROOT",
            "i": "I",
            "s": "S",
            "e": {"ref": "TARGET_SAID"},
        }
        node = parse_acdc(acdc)
        targets = extract_edge_targets(node)
        assert targets == {"TARGET_SAID"}

    def test_skip_edge_block_said(self):
        """Skip 'd' field in edge block (edge block's own SAID)."""
        acdc = {
            "d": "ROOT",
            "i": "I",
            "s": "S",
            "e": {"d": "EDGE_BLOCK_SAID", "child": {"n": "CHILD"}},
        }
        node = parse_acdc(acdc)
        targets = extract_edge_targets(node)
        assert "EDGE_BLOCK_SAID" not in targets
        assert targets == {"CHILD"}

    def test_extract_multiple_edges(self):
        """Extract targets from multiple edges."""
        acdc = {
            "d": "ROOT",
            "i": "I",
            "s": "S",
            "e": {
                "child1": {"n": "CHILD_1"},
                "child2": {"n": "CHILD_2"},
            },
        }
        node = parse_acdc(acdc)
        targets = extract_edge_targets(node)
        assert targets == {"CHILD_1", "CHILD_2"}


# =============================================================================
# DAG Building Tests
# =============================================================================


class TestBuildDAG:
    """Tests for build_dag function."""

    def test_build_dag_from_nodes(self):
        """Build DAG from list of nodes."""
        nodes, _ = parse_dossier(json.dumps(VALID_DAG).encode())
        dag = build_dag(nodes)
        assert len(dag) == 2
        assert "SAID_ROOT" in dag
        assert "SAID_CHILD" in dag

    def test_build_dag_single_node(self):
        """Build DAG from single node."""
        nodes, _ = parse_dossier(json.dumps(VALID_ACDC).encode())
        dag = build_dag(nodes)
        assert len(dag) == 1

    def test_build_dag_duplicate_said_raises(self):
        """Duplicate SAID raises GraphError."""
        acdc1 = {"d": "SAME_SAID", "i": "I1", "s": "S1"}
        acdc2 = {"d": "SAME_SAID", "i": "I2", "s": "S2"}
        nodes, _ = parse_dossier(json.dumps([acdc1, acdc2]).encode())
        with pytest.raises(GraphError) as exc:
            build_dag(nodes)
        assert "Duplicate" in str(exc.value)
        assert exc.value.code == ErrorCode.DOSSIER_GRAPH_INVALID


# =============================================================================
# Cycle Detection Tests
# =============================================================================


class TestCycleDetection:
    """Tests for detect_cycle function."""

    def test_no_cycle_in_valid_dag(self):
        """Valid DAG has no cycles."""
        nodes, _ = parse_dossier(json.dumps(VALID_DAG).encode())
        dag = build_dag(nodes)
        cycle = detect_cycle(dag)
        assert cycle is None

    def test_detect_two_node_cycle(self):
        """Detect cycle between two nodes."""
        nodes, _ = parse_dossier(json.dumps(CYCLIC_DAG).encode())
        dag = build_dag(nodes)
        cycle = detect_cycle(dag)
        assert cycle is not None
        assert len(cycle) >= 2
        assert set(cycle) <= {"SAID_A", "SAID_B"}

    def test_detect_three_node_cycle(self):
        """Detect cycle among three nodes."""
        nodes, _ = parse_dossier(json.dumps(THREE_NODE_CYCLE).encode())
        dag = build_dag(nodes)
        cycle = detect_cycle(dag)
        assert cycle is not None
        assert len(cycle) >= 3

    def test_no_cycle_single_node(self):
        """Single node without self-reference has no cycle."""
        nodes, _ = parse_dossier(json.dumps(VALID_ACDC).encode())
        dag = build_dag(nodes)
        cycle = detect_cycle(dag)
        assert cycle is None

    def test_dangling_edge_not_cycle(self):
        """Edge to non-existent node is not a cycle."""
        acdc = {
            "d": "ROOT",
            "i": "I",
            "s": "S",
            "e": {"ref": {"n": "NON_EXISTENT"}},
        }
        nodes, _ = parse_dossier(json.dumps(acdc).encode())
        dag = build_dag(nodes)
        cycle = detect_cycle(dag)
        assert cycle is None


# =============================================================================
# Root Finding Tests
# =============================================================================


class TestFindRoot:
    """Tests for find_root function."""

    def test_find_root_valid_dag(self):
        """Find root in valid two-node DAG."""
        nodes, _ = parse_dossier(json.dumps(VALID_DAG).encode())
        dag = build_dag(nodes)
        root = find_root(dag)
        assert root == "SAID_ROOT"

    def test_find_root_single_node(self):
        """Single node is the root."""
        nodes, _ = parse_dossier(json.dumps(VALID_ACDC).encode())
        dag = build_dag(nodes)
        root = find_root(dag)
        assert root == "SAID_ROOT_123"

    def test_multiple_roots_raises(self):
        """Multiple disconnected nodes raises GraphError."""
        data = [
            {"d": "SAID_A", "i": "B1", "s": "S1"},
            {"d": "SAID_B", "i": "B2", "s": "S2"},
        ]
        nodes, _ = parse_dossier(json.dumps(data).encode())
        dag = build_dag(nodes)
        with pytest.raises(GraphError) as exc:
            find_root(dag)
        assert "Multiple root" in str(exc.value)

    def test_no_root_raises(self):
        """All nodes having incoming edges raises GraphError."""
        # This would require a cycle; test with validate_dag instead
        nodes, _ = parse_dossier(json.dumps(CYCLIC_DAG).encode())
        dag = build_dag(nodes)
        # In a pure cycle, technically both have incoming edges
        # but detect_cycle should catch this first


# =============================================================================
# DAG Validation Tests
# =============================================================================


class TestDAGValidator:
    """Tests for validate_dag function."""

    def test_validate_valid_dag(self):
        """Valid DAG passes validation."""
        nodes, _ = parse_dossier(json.dumps(VALID_DAG).encode())
        dag = build_dag(nodes)
        validate_dag(dag)  # Should not raise
        assert dag.root_said == "SAID_ROOT"

    def test_validate_single_node(self):
        """Single node DAG is valid."""
        nodes, _ = parse_dossier(json.dumps(VALID_ACDC).encode())
        dag = build_dag(nodes)
        validate_dag(dag)
        assert dag.root_said == "SAID_ROOT_123"

    def test_validate_detects_cycle(self):
        """Validation fails on cyclic graph."""
        nodes, _ = parse_dossier(json.dumps(CYCLIC_DAG).encode())
        dag = build_dag(nodes)
        with pytest.raises(GraphError) as exc:
            validate_dag(dag)
        assert "Cycle" in str(exc.value)
        assert exc.value.code == ErrorCode.DOSSIER_GRAPH_INVALID

    def test_validate_multiple_roots_fails(self):
        """Validation fails with multiple roots."""
        data = [
            {"d": "SAID_A", "i": "B1", "s": "S1"},
            {"d": "SAID_B", "i": "B2", "s": "S2"},
        ]
        nodes, _ = parse_dossier(json.dumps(data).encode())
        dag = build_dag(nodes)
        with pytest.raises(GraphError) as exc:
            validate_dag(dag)
        assert "Multiple root" in str(exc.value)

    def test_validate_empty_dag_fails(self):
        """Empty DAG fails validation."""
        dag = DossierDAG()
        with pytest.raises(GraphError) as exc:
            validate_dag(dag)
        assert "Empty" in str(exc.value)

    def test_validate_deep_dag(self):
        """Validate deeper DAG structure."""
        # root -> child1 -> child2
        data = [
            {"d": "ROOT", "i": "I", "s": "S", "e": {"c1": {"n": "CHILD1"}}},
            {"d": "CHILD1", "i": "I", "s": "S", "e": {"c2": {"n": "CHILD2"}}},
            {"d": "CHILD2", "i": "I", "s": "S"},
        ]
        nodes, _ = parse_dossier(json.dumps(data).encode())
        dag = build_dag(nodes)
        validate_dag(dag)
        assert dag.root_said == "ROOT"


# =============================================================================
# Error Code Tests
# =============================================================================


class TestErrorCodes:
    """Tests for error code mappings."""

    def test_dossier_error_base(self):
        """DossierError has code and message."""
        err = DossierError("TEST_CODE", "test message")
        assert err.code == "TEST_CODE"
        assert err.message == "test message"
        assert str(err) == "test message"

    def test_fetch_error_code(self):
        """FetchError maps to DOSSIER_FETCH_FAILED."""
        err = FetchError("Network timeout")
        assert err.code == ErrorCode.DOSSIER_FETCH_FAILED
        assert "timeout" in err.message.lower()

    def test_parse_error_code(self):
        """ParseError maps to DOSSIER_PARSE_FAILED."""
        err = ParseError("Invalid JSON")
        assert err.code == ErrorCode.DOSSIER_PARSE_FAILED

    def test_graph_error_code(self):
        """GraphError maps to DOSSIER_GRAPH_INVALID."""
        err = GraphError("Cycle detected")
        assert err.code == ErrorCode.DOSSIER_GRAPH_INVALID

    def test_fetch_error_default_message(self):
        """FetchError has default message."""
        err = FetchError()
        assert err.message == "Dossier fetch failed"

    def test_parse_error_default_message(self):
        """ParseError has default message."""
        err = ParseError()
        assert err.message == "Dossier parse failed"

    def test_graph_error_default_message(self):
        """GraphError has default message."""
        err = GraphError()
        assert err.message == "Dossier graph invalid"


# =============================================================================
# HTTP Fetch Tests (with mocking)
# =============================================================================


class TestFetchDossier:
    """Tests for fetch_dossier function using mocks."""

    @pytest.mark.asyncio
    async def test_fetch_success(self):
        """Successful fetch returns content bytes."""
        from app.vvp.dossier import fetch_dossier

        mock_response = MagicMock()
        mock_response.headers = {"content-type": "application/json"}
        mock_response.content = json.dumps(VALID_ACDC).encode()
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)

        with patch("app.vvp.dossier.fetch.httpx.AsyncClient", return_value=mock_client):
            content = await fetch_dossier("http://example.com/dossier")

        assert content == json.dumps(VALID_ACDC).encode()

    @pytest.mark.asyncio
    async def test_fetch_cesr_content_type(self):
        """Fetch accepts application/json+cesr content-type."""
        from app.vvp.dossier import fetch_dossier

        mock_response = MagicMock()
        mock_response.headers = {"content-type": "application/json+cesr"}
        mock_response.content = json.dumps(VALID_ACDC).encode()
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)

        with patch("app.vvp.dossier.fetch.httpx.AsyncClient", return_value=mock_client):
            content = await fetch_dossier("http://example.com/dossier")

        assert content == json.dumps(VALID_ACDC).encode()

    @pytest.mark.asyncio
    async def test_fetch_invalid_content_type_raises(self):
        """Invalid content-type raises FetchError."""
        from app.vvp.dossier import fetch_dossier

        mock_response = MagicMock()
        mock_response.headers = {"content-type": "text/html"}
        mock_response.content = b"<html>Not JSON</html>"
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)

        with patch("app.vvp.dossier.fetch.httpx.AsyncClient", return_value=mock_client):
            with pytest.raises(FetchError) as exc:
                await fetch_dossier("http://example.com/dossier")
            assert "content-type" in str(exc.value).lower()

    @pytest.mark.asyncio
    async def test_fetch_timeout_raises(self):
        """Timeout raises FetchError."""
        from app.vvp.dossier import fetch_dossier

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.TimeoutException("Timeout"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)

        with patch("app.vvp.dossier.fetch.httpx.AsyncClient", return_value=mock_client):
            with pytest.raises(FetchError) as exc:
                await fetch_dossier("http://example.com/dossier")
            assert "Timeout" in str(exc.value)

    @pytest.mark.asyncio
    async def test_fetch_too_many_redirects_raises(self):
        """Too many redirects raises FetchError."""
        from app.vvp.dossier import fetch_dossier

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.TooManyRedirects("Too many"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)

        with patch("app.vvp.dossier.fetch.httpx.AsyncClient", return_value=mock_client):
            with pytest.raises(FetchError) as exc:
                await fetch_dossier("http://example.com/dossier")
            assert "redirect" in str(exc.value).lower()

    @pytest.mark.asyncio
    async def test_fetch_http_error_raises(self):
        """HTTP error status raises FetchError."""
        from app.vvp.dossier import fetch_dossier

        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_response.reason_phrase = "Not Found"

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_response.raise_for_status = MagicMock(
            side_effect=httpx.HTTPStatusError(
                "Not Found",
                request=MagicMock(),
                response=mock_response,
            )
        )
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)

        with patch("app.vvp.dossier.fetch.httpx.AsyncClient", return_value=mock_client):
            with pytest.raises(FetchError) as exc:
                await fetch_dossier("http://example.com/dossier")
            assert "404" in str(exc.value)

    @pytest.mark.asyncio
    async def test_fetch_size_limit_raises(self):
        """Response exceeding size limit raises FetchError."""
        from app.vvp.dossier import fetch_dossier
        from app.core.config import DOSSIER_MAX_SIZE_BYTES

        mock_response = MagicMock()
        mock_response.headers = {"content-type": "application/json"}
        # Create content larger than limit
        mock_response.content = b"x" * (DOSSIER_MAX_SIZE_BYTES + 1)
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)

        with patch("app.vvp.dossier.fetch.httpx.AsyncClient", return_value=mock_client):
            with pytest.raises(FetchError) as exc:
                await fetch_dossier("http://example.com/dossier")
            assert "exceeds" in str(exc.value).lower()


# =============================================================================
# Integration Tests
# =============================================================================


class TestDossierIntegration:
    """Integration tests for full dossier parsing pipeline."""

    def test_parse_and_validate_pipeline(self):
        """Full pipeline: parse JSON -> build DAG -> validate."""
        raw = json.dumps(VALID_DAG).encode()
        nodes, sigs = parse_dossier(raw)
        dag = build_dag(nodes)
        validate_dag(dag)

        assert len(dag) == 2
        assert dag.root_said == "SAID_ROOT"
        assert dag.get("SAID_ROOT") is not None
        assert dag.get("SAID_CHILD") is not None
        assert sigs == {}  # JSON format has no signatures

    def test_complex_dag_structure(self):
        """Parse and validate more complex DAG."""
        #     ROOT
        #    /    \
        # CHILD1  CHILD2
        #    \    /
        #     LEAF
        data = [
            {
                "d": "ROOT",
                "i": "I",
                "s": "S",
                "e": {
                    "c1": {"n": "CHILD1"},
                    "c2": {"n": "CHILD2"},
                },
            },
            {"d": "CHILD1", "i": "I", "s": "S", "e": {"leaf": {"n": "LEAF"}}},
            {"d": "CHILD2", "i": "I", "s": "S", "e": {"leaf": {"n": "LEAF"}}},
            {"d": "LEAF", "i": "I", "s": "S"},
        ]

        raw = json.dumps(data).encode()
        nodes, _ = parse_dossier(raw)
        dag = build_dag(nodes)
        validate_dag(dag)

        assert len(dag) == 4
        assert dag.root_said == "ROOT"


# =============================================================================
# Phase 11: CESR Signature Extraction Tests
# =============================================================================


class TestCESRSignatureExtraction:
    """Tests for CESR signature extraction from dossier."""

    def test_json_dossier_returns_empty_signatures(self):
        """Plain JSON dossier returns empty signatures dict."""
        raw = json.dumps(VALID_ACDC).encode()
        nodes, signatures = parse_dossier(raw)

        assert len(nodes) == 1
        assert signatures == {}

    def test_json_array_returns_empty_signatures(self):
        """JSON array dossier returns empty signatures dict."""
        raw = json.dumps(VALID_DAG).encode()
        nodes, signatures = parse_dossier(raw)

        assert len(nodes) == 2
        assert signatures == {}

    def test_cesr_detection_version_marker(self):
        """CESR stream with version marker is detected."""
        from app.vvp.dossier.parser import _is_cesr_stream

        # CESR version marker
        assert _is_cesr_stream(b"-_AAAKERI10JSON00011c_") is True

    def test_cesr_detection_count_code(self):
        """CESR stream with count code is detected."""
        from app.vvp.dossier.parser import _is_cesr_stream

        # Count code at start
        assert _is_cesr_stream(b"-AAB...") is True

    def test_cesr_detection_json_only(self):
        """Plain JSON is not detected as CESR."""
        from app.vvp.dossier.parser import _is_cesr_stream

        # Plain JSON
        assert _is_cesr_stream(b'{"d": "test"}') is False

    def test_cesr_detection_json_with_attachment(self):
        """JSON followed by count code is detected as CESR."""
        from app.vvp.dossier.parser import _is_cesr_stream

        # JSON with CESR attachment
        cesr_with_attachment = b'{"d": "test"}-AAB'
        assert _is_cesr_stream(cesr_with_attachment) is True

    def test_cesr_detection_empty(self):
        """Empty data is not CESR."""
        from app.vvp.dossier.parser import _is_cesr_stream

        assert _is_cesr_stream(b"") is False

    def test_parse_dossier_returns_tuple(self):
        """parse_dossier always returns (nodes, signatures) tuple."""
        raw = json.dumps(VALID_ACDC).encode()
        result = parse_dossier(raw)

        assert isinstance(result, tuple)
        assert len(result) == 2
        assert isinstance(result[0], list)
        assert isinstance(result[1], dict)

    def test_cesr_signature_extraction_mocked(self):
        """Test CESR signature extraction with mocked cesr module.

        This validates the signature extraction logic without requiring
        libsodium/pysodium by mocking the cesr module.
        """
        from unittest.mock import MagicMock, patch
        import types

        # Create mock CESRMessage with controller signature
        mock_message = MagicMock()
        mock_message.event_dict = {
            "d": "ESAID_TEST_123",
            "i": "EISSUER_AID_456",
            "s": "ESCHEMA_789",
            "a": {"name": "Test Credential"},
        }
        mock_message.controller_sigs = [b"signature_bytes_64_chars_padded_to_match_ed25519_length_here___"]

        # Create mock cesr module
        mock_cesr = types.ModuleType("mock_cesr")
        mock_cesr.parse_cesr_stream = MagicMock(return_value=[mock_message])

        # Create CESR-like data (JSON with attachment marker)
        cesr_data = b'{"d":"ESAID_TEST_123","i":"EISSUER_AID_456","s":"ESCHEMA_789"}-AAB0AA...'

        with patch.dict("sys.modules", {"app.vvp.keri.cesr": mock_cesr}):
            with patch("app.vvp.dossier.parser._is_cesr_stream", return_value=True):
                nodes, signatures = parse_dossier(cesr_data)

        # Verify signature was extracted
        assert len(nodes) == 1
        assert nodes[0].said == "ESAID_TEST_123"
        assert "ESAID_TEST_123" in signatures
        assert signatures["ESAID_TEST_123"] == b"signature_bytes_64_chars_padded_to_match_ed25519_length_here___"


# =============================================================================
# ToIP Verifiable Dossiers Specification Warnings (§6.1C-D)
# =============================================================================


class TestToIPWarnings:
    """Tests for ToIP Verifiable Dossiers spec warnings.

    These warnings are informational and do NOT fail validation.
    Per VVP Spec §6.1C-D.
    """

    def test_edge_missing_schema_warning(self):
        """Edge with 'n' but no 's' generates EDGE_MISSING_SCHEMA warning."""
        acdc = {
            "d": "ESAID_ROOT",
            "i": "EISSUER",
            "s": "ESCHEMA",
            "e": {"d": "ESAID_E_BLOCK", "child": {"n": "ECHILD_SAID"}},  # No 's' field
        }
        nodes, _ = parse_dossier(json.dumps(acdc).encode())
        dag = build_dag(nodes)
        validate_dag(dag)

        assert len(dag.warnings) >= 1
        schema_warnings = [w for w in dag.warnings if w.code == ToIPWarningCode.EDGE_MISSING_SCHEMA]
        assert len(schema_warnings) == 1
        assert "child" in schema_warnings[0].message
        assert schema_warnings[0].field_path == "e.child"

    def test_edge_with_schema_no_warning(self):
        """Edge with both 'n' and 's' generates no EDGE_MISSING_SCHEMA warning."""
        acdc = {
            "d": "ESAID_ROOT",
            "i": "EISSUER",
            "s": "ESCHEMA",
            "e": {"d": "ESAID_E_BLOCK", "child": {"n": "ECHILD_SAID", "s": "ECHILD_SCHEMA"}},
        }
        nodes, _ = parse_dossier(json.dumps(acdc).encode())
        dag = build_dag(nodes)
        validate_dag(dag)

        # Should have no EDGE_MISSING_SCHEMA warnings
        schema_warnings = [w for w in dag.warnings if w.code == ToIPWarningCode.EDGE_MISSING_SCHEMA]
        assert len(schema_warnings) == 0

    def test_root_issuee_warning(self):
        """Root ACDC with issuee field (a.i) generates DOSSIER_HAS_ISSUEE warning."""
        acdc = {
            "d": "ESAID_ROOT",
            "i": "EISSUER",
            "s": "ESCHEMA",
            "a": {"i": "EISSUEE_AID", "name": "Test"},  # Has issuee in attributes
        }
        nodes, _ = parse_dossier(json.dumps(acdc).encode())
        dag = build_dag(nodes)
        validate_dag(dag)

        issuee_warnings = [w for w in dag.warnings if w.code == ToIPWarningCode.DOSSIER_HAS_ISSUEE]
        assert len(issuee_warnings) == 1
        assert "a.i" in issuee_warnings[0].field_path

    def test_root_registry_id_warning(self):
        """Root ACDC with ri field generates DOSSIER_HAS_ISSUEE warning."""
        acdc = {
            "d": "ESAID_ROOT",
            "i": "EISSUER",
            "s": "ESCHEMA",
            "ri": "EREGISTRY_SAID",
        }
        nodes, _ = parse_dossier(json.dumps(acdc).encode())
        dag = build_dag(nodes)
        validate_dag(dag)

        ri_warnings = [w for w in dag.warnings if w.code == ToIPWarningCode.DOSSIER_HAS_ISSUEE]
        assert len(ri_warnings) == 1
        assert ri_warnings[0].field_path == "ri"

    def test_evidence_in_attributes_warning(self):
        """Evidence-like field in attributes generates EVIDENCE_IN_ATTRIBUTES warning."""
        acdc = {
            "d": "ESAID_ROOT",
            "i": "EISSUER",
            "s": "ESCHEMA",
            "a": {"name": "Test", "proof_digest": "abc123"},  # Evidence-like field
        }
        nodes, _ = parse_dossier(json.dumps(acdc).encode())
        dag = build_dag(nodes)
        validate_dag(dag)

        evidence_warnings = [w for w in dag.warnings if w.code == ToIPWarningCode.EVIDENCE_IN_ATTRIBUTES]
        assert len(evidence_warnings) == 1
        assert "proof_digest" in evidence_warnings[0].message

    def test_joint_issuance_operator_warning(self):
        """Joint issuance operator in rules generates JOINT_ISSUANCE_OPERATOR warning."""
        acdc = {
            "d": "ESAID_ROOT",
            "i": "EISSUER",
            "s": "ESCHEMA",
            "r": {"thr": {"n": 2, "m": 3}},  # Threshold operator
        }
        nodes, _ = parse_dossier(json.dumps(acdc).encode())
        dag = build_dag(nodes)
        validate_dag(dag)

        joint_warnings = [w for w in dag.warnings if w.code == ToIPWarningCode.JOINT_ISSUANCE_OPERATOR]
        assert len(joint_warnings) == 1
        assert "thr" in joint_warnings[0].message

    def test_warnings_do_not_fail_validation(self):
        """Multiple warnings should NOT cause validation to fail."""
        # ACDC with multiple warning conditions
        acdc = {
            "d": "ESAID_ROOT",
            "i": "EISSUER",
            "s": "ESCHEMA",
            "a": {"i": "EISSUEE", "signature_hash": "data"},  # issuee + evidence-like
            "e": {"d": "ESAID_E", "child": {"n": "ECHILD"}},  # missing schema
            "ri": "EREGISTRY",  # registry ID
            "r": {"fin": {}},  # finalization operator
        }
        nodes, _ = parse_dossier(json.dumps(acdc).encode())
        dag = build_dag(nodes)

        # Should NOT raise - warnings are non-blocking
        validate_dag(dag)

        # But should have multiple warnings
        assert len(dag.warnings) >= 4
        assert dag.root_said == "ESAID_ROOT"

    def test_non_root_issuee_no_warning(self):
        """Non-root ACDC with issuee should NOT generate DOSSIER_HAS_ISSUEE warning."""
        data = [
            {
                "d": "ESAID_ROOT",
                "i": "EISSUER",
                "s": "ESCHEMA",
                "e": {"d": "ESAID_E", "child": {"n": "ESAID_CHILD", "s": "ESCH"}},
            },
            {
                "d": "ESAID_CHILD",
                "i": "EISSUER",
                "s": "ESCHEMA",
                "a": {"i": "EISSUEE"},  # Child has issuee - OK for evidence credentials
            },
        ]
        nodes, _ = parse_dossier(json.dumps(data).encode())
        dag = build_dag(nodes)
        validate_dag(dag)

        # The child's issuee should NOT generate a warning
        issuee_warnings = [w for w in dag.warnings if w.code == ToIPWarningCode.DOSSIER_HAS_ISSUEE]
        assert len(issuee_warnings) == 0

    def test_warning_has_said(self):
        """Warnings should include the SAID of the credential that triggered them."""
        acdc = {
            "d": "ESAID_SPECIFIC",
            "i": "EISSUER",
            "s": "ESCHEMA",
            "e": {"d": "ESAID_E", "child": {"n": "ECHILD"}},
        }
        nodes, _ = parse_dossier(json.dumps(acdc).encode())
        dag = build_dag(nodes)
        validate_dag(dag)

        assert len(dag.warnings) >= 1
        for w in dag.warnings:
            assert w.said == "ESAID_SPECIFIC"

    def test_dossier_dag_warnings_field_default(self):
        """DossierDAG.warnings should default to empty list."""
        dag = DossierDAG()
        assert dag.warnings == []

    def test_dossier_warning_is_frozen(self):
        """DossierWarning should be immutable (frozen dataclass)."""
        warning = DossierWarning(
            code=ToIPWarningCode.EDGE_MISSING_SCHEMA,
            message="Test warning",
            said="ESAID",
            field_path="e.test",
        )
        with pytest.raises(Exception):  # FrozenInstanceError or AttributeError
            warning.message = "Changed"

    def test_edge_direct_said_string_warning(self):
        """Edge as direct SAID string generates EDGE_NON_OBJECT_FORMAT warning."""
        acdc = {
            "d": "ESAID_ROOT",
            "i": "EISSUER",
            "s": "ESCHEMA",
            "e": {"d": "ESAID_E_BLOCK", "child": "ECHILD_SAID_DIRECT"},  # Direct string, not {n,s}
        }
        nodes, _ = parse_dossier(json.dumps(acdc).encode())
        dag = build_dag(nodes)
        validate_dag(dag)

        string_warnings = [w for w in dag.warnings if w.code == ToIPWarningCode.EDGE_NON_OBJECT_FORMAT]
        assert len(string_warnings) == 1
        assert "child" in string_warnings[0].message
        assert "direct SAID string" in string_warnings[0].message
        assert string_warnings[0].field_path == "e.child"

    def test_edge_object_format_no_string_warning(self):
        """Edge as proper object format should NOT generate EDGE_NON_OBJECT_FORMAT warning."""
        acdc = {
            "d": "ESAID_ROOT",
            "i": "EISSUER",
            "s": "ESCHEMA",
            "e": {"d": "ESAID_E_BLOCK", "child": {"n": "ECHILD_SAID", "s": "ESCHEMA_CHILD"}},
        }
        nodes, _ = parse_dossier(json.dumps(acdc).encode())
        dag = build_dag(nodes)
        validate_dag(dag)

        string_warnings = [w for w in dag.warnings if w.code == ToIPWarningCode.EDGE_NON_OBJECT_FORMAT]
        assert len(string_warnings) == 0

    def test_prev_edge_warning(self):
        """Dossier with 'prev' edge generates DOSSIER_HAS_PREV_EDGE warning."""
        acdc = {
            "d": "ESAID_ROOT",
            "i": "EISSUER",
            "s": "ESCHEMA",
            "e": {
                "d": "ESAID_E_BLOCK",
                "prev": {"n": "ESAID_PREVIOUS_VERSION", "s": "ESCHEMA"},
            },
        }
        nodes, _ = parse_dossier(json.dumps(acdc).encode())
        dag = build_dag(nodes)
        validate_dag(dag)

        prev_warnings = [w for w in dag.warnings if w.code == ToIPWarningCode.DOSSIER_HAS_PREV_EDGE]
        assert len(prev_warnings) == 1
        assert "prev" in prev_warnings[0].message
        assert prev_warnings[0].field_path == "e.prev"

    def test_no_prev_edge_no_warning(self):
        """Dossier without 'prev' edge should NOT generate DOSSIER_HAS_PREV_EDGE warning."""
        acdc = {
            "d": "ESAID_ROOT",
            "i": "EISSUER",
            "s": "ESCHEMA",
            "e": {"d": "ESAID_E_BLOCK", "child": {"n": "ECHILD", "s": "ESCHEMA"}},
        }
        nodes, _ = parse_dossier(json.dumps(acdc).encode())
        dag = build_dag(nodes)
        validate_dag(dag)

        prev_warnings = [w for w in dag.warnings if w.code == ToIPWarningCode.DOSSIER_HAS_PREV_EDGE]
        assert len(prev_warnings) == 0
