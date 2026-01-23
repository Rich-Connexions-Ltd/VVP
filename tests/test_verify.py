"""Unit tests for Phase 6 verification orchestration."""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from app.vvp.api_models import (
    ClaimStatus,
    ClaimNode,
    ChildLink,
    ErrorCode,
    VerifyRequest,
    CallContext,
)
from app.vvp.verify import (
    ClaimBuilder,
    to_error_detail,
    _worse_status,
    propagate_status,
    verify_vvp,
)
from app.vvp.exceptions import VVPIdentityError, PassportError
from app.vvp.keri import SignatureInvalidError, ResolutionFailedError
from app.vvp.dossier import FetchError, ParseError, GraphError


# =============================================================================
# Status Propagation Tests
# =============================================================================


class TestWorseStatus:
    """Test _worse_status precedence logic."""

    def test_invalid_wins_over_valid(self):
        assert _worse_status(ClaimStatus.VALID, ClaimStatus.INVALID) == ClaimStatus.INVALID

    def test_invalid_wins_over_indeterminate(self):
        assert _worse_status(ClaimStatus.INDETERMINATE, ClaimStatus.INVALID) == ClaimStatus.INVALID

    def test_indeterminate_over_valid(self):
        assert _worse_status(ClaimStatus.VALID, ClaimStatus.INDETERMINATE) == ClaimStatus.INDETERMINATE

    def test_valid_when_both_valid(self):
        assert _worse_status(ClaimStatus.VALID, ClaimStatus.VALID) == ClaimStatus.VALID

    def test_symmetric_invalid_first(self):
        assert _worse_status(ClaimStatus.INVALID, ClaimStatus.VALID) == ClaimStatus.INVALID

    def test_symmetric_indeterminate_first(self):
        assert _worse_status(ClaimStatus.INDETERMINATE, ClaimStatus.VALID) == ClaimStatus.INDETERMINATE


class TestPropagateStatus:
    """Test status propagation per §3.3A."""

    def test_required_child_invalid_makes_parent_invalid(self):
        child = ClaimNode(name="child", status=ClaimStatus.INVALID, reasons=["fail"])
        parent = ClaimNode(
            name="parent",
            status=ClaimStatus.VALID,
            reasons=[],
            children=[ChildLink(required=True, node=child)],
        )
        assert propagate_status(parent) == ClaimStatus.INVALID

    def test_optional_child_invalid_does_not_affect_parent(self):
        child = ClaimNode(name="child", status=ClaimStatus.INVALID, reasons=["fail"])
        parent = ClaimNode(
            name="parent",
            status=ClaimStatus.VALID,
            reasons=[],
            children=[ChildLink(required=False, node=child)],
        )
        assert propagate_status(parent) == ClaimStatus.VALID

    def test_required_indeterminate_makes_parent_indeterminate(self):
        child = ClaimNode(name="child", status=ClaimStatus.INDETERMINATE, reasons=["unknown"])
        parent = ClaimNode(
            name="parent",
            status=ClaimStatus.VALID,
            reasons=[],
            children=[ChildLink(required=True, node=child)],
        )
        assert propagate_status(parent) == ClaimStatus.INDETERMINATE

    def test_leaf_node_returns_own_status(self):
        leaf = ClaimNode(name="leaf", status=ClaimStatus.VALID, reasons=[])
        assert propagate_status(leaf) == ClaimStatus.VALID

    def test_multiple_required_children_worst_wins(self):
        child1 = ClaimNode(name="child1", status=ClaimStatus.INDETERMINATE, reasons=["timeout"])
        child2 = ClaimNode(name="child2", status=ClaimStatus.INVALID, reasons=["bad"])
        parent = ClaimNode(
            name="parent",
            status=ClaimStatus.VALID,
            reasons=[],
            children=[
                ChildLink(required=True, node=child1),
                ChildLink(required=True, node=child2),
            ],
        )
        assert propagate_status(parent) == ClaimStatus.INVALID

    def test_mixed_required_optional_children(self):
        req_child = ClaimNode(name="req", status=ClaimStatus.INDETERMINATE, reasons=["timeout"])
        opt_child = ClaimNode(name="opt", status=ClaimStatus.INVALID, reasons=["bad"])
        parent = ClaimNode(
            name="parent",
            status=ClaimStatus.VALID,
            reasons=[],
            children=[
                ChildLink(required=True, node=req_child),
                ChildLink(required=False, node=opt_child),
            ],
        )
        # Optional INVALID doesn't affect parent, only required INDETERMINATE
        assert propagate_status(parent) == ClaimStatus.INDETERMINATE

    def test_nested_propagation(self):
        grandchild = ClaimNode(name="grandchild", status=ClaimStatus.INVALID, reasons=["fail"])
        child = ClaimNode(
            name="child",
            status=ClaimStatus.VALID,
            reasons=[],
            children=[ChildLink(required=True, node=grandchild)],
        )
        parent = ClaimNode(
            name="parent",
            status=ClaimStatus.VALID,
            reasons=[],
            children=[ChildLink(required=True, node=child)],
        )
        assert propagate_status(parent) == ClaimStatus.INVALID

    def test_parent_invalid_overrides_valid_children(self):
        child = ClaimNode(name="child", status=ClaimStatus.VALID, reasons=[])
        parent = ClaimNode(
            name="parent",
            status=ClaimStatus.INVALID,
            reasons=["parent failed"],
            children=[ChildLink(required=True, node=child)],
        )
        assert propagate_status(parent) == ClaimStatus.INVALID


# =============================================================================
# ClaimBuilder Tests
# =============================================================================


class TestClaimBuilder:
    """Test ClaimBuilder helper class."""

    def test_starts_valid(self):
        builder = ClaimBuilder("test")
        assert builder.status == ClaimStatus.VALID
        assert builder.reasons == []
        assert builder.evidence == []

    def test_fail_to_invalid(self):
        builder = ClaimBuilder("test")
        builder.fail(ClaimStatus.INVALID, "reason")
        assert builder.status == ClaimStatus.INVALID
        assert "reason" in builder.reasons

    def test_fail_to_indeterminate_from_valid(self):
        builder = ClaimBuilder("test")
        builder.fail(ClaimStatus.INDETERMINATE, "timeout")
        assert builder.status == ClaimStatus.INDETERMINATE

    def test_invalid_not_downgraded_by_indeterminate(self):
        builder = ClaimBuilder("test")
        builder.fail(ClaimStatus.INVALID, "first")
        builder.fail(ClaimStatus.INDETERMINATE, "second")
        assert builder.status == ClaimStatus.INVALID
        assert len(builder.reasons) == 2

    def test_indeterminate_upgraded_to_invalid(self):
        builder = ClaimBuilder("test")
        builder.fail(ClaimStatus.INDETERMINATE, "first")
        builder.fail(ClaimStatus.INVALID, "second")
        assert builder.status == ClaimStatus.INVALID

    def test_add_evidence(self):
        builder = ClaimBuilder("test")
        builder.add_evidence("sig_valid")
        builder.add_evidence("binding_ok")
        assert "sig_valid" in builder.evidence
        assert "binding_ok" in builder.evidence

    def test_build_creates_claim_node(self):
        builder = ClaimBuilder("test_claim")
        builder.fail(ClaimStatus.INDETERMINATE, "reason")
        builder.add_evidence("ev1")
        node = builder.build()
        assert node.name == "test_claim"
        assert node.status == ClaimStatus.INDETERMINATE
        assert "reason" in node.reasons
        assert "ev1" in node.evidence
        assert node.children == []

    def test_build_with_children(self):
        builder = ClaimBuilder("parent")
        child = ClaimNode(name="child", status=ClaimStatus.VALID, reasons=[])
        node = builder.build(children=[ChildLink(required=True, node=child)])
        assert len(node.children) == 1
        assert node.children[0].node.name == "child"


# =============================================================================
# Error Conversion Tests
# =============================================================================


class TestToErrorDetail:
    """Test exception to ErrorDetail conversion."""

    def test_vvp_identity_error_conversion(self):
        exc = VVPIdentityError.missing()
        detail = to_error_detail(exc)
        assert detail.code == ErrorCode.VVP_IDENTITY_MISSING
        assert detail.recoverable is False

    def test_passport_error_conversion(self):
        exc = PassportError.parse_failed("bad jwt")
        detail = to_error_detail(exc)
        assert detail.code == ErrorCode.PASSPORT_PARSE_FAILED
        assert detail.recoverable is False

    def test_signature_invalid_error_conversion(self):
        exc = SignatureInvalidError("bad sig")
        detail = to_error_detail(exc)
        assert detail.code == ErrorCode.PASSPORT_SIG_INVALID
        assert detail.recoverable is False

    def test_resolution_failed_error_conversion(self):
        exc = ResolutionFailedError("network timeout")
        detail = to_error_detail(exc)
        assert detail.code == ErrorCode.KERI_RESOLUTION_FAILED
        assert detail.recoverable is True

    def test_fetch_error_conversion(self):
        exc = FetchError("timeout")
        detail = to_error_detail(exc)
        assert detail.code == ErrorCode.DOSSIER_FETCH_FAILED
        assert detail.recoverable is True

    def test_parse_error_conversion(self):
        exc = ParseError("invalid json")
        detail = to_error_detail(exc)
        assert detail.code == ErrorCode.DOSSIER_PARSE_FAILED
        assert detail.recoverable is False

    def test_graph_error_conversion(self):
        exc = GraphError("cycle detected")
        detail = to_error_detail(exc)
        assert detail.code == ErrorCode.DOSSIER_GRAPH_INVALID
        assert detail.recoverable is False


# =============================================================================
# Integration Tests (Mocked)
# =============================================================================


class TestVerifyVVPIntegration:
    """Integration tests for verify_vvp orchestration."""

    @pytest.fixture
    def valid_context(self):
        return CallContext(call_id="123", received_at="2024-01-01T00:00:00Z")

    @pytest.mark.asyncio
    async def test_missing_vvp_identity_returns_invalid(self, valid_context):
        req = VerifyRequest(passport_jwt="dummy", context=valid_context)
        req_id, resp = await verify_vvp(req, None)

        assert resp.overall_status == ClaimStatus.INVALID
        assert resp.claims is None
        assert len(resp.errors) == 1
        assert resp.errors[0].code == ErrorCode.VVP_IDENTITY_MISSING

    @pytest.mark.asyncio
    async def test_malformed_vvp_identity_returns_invalid(self, valid_context):
        req = VerifyRequest(passport_jwt="dummy", context=valid_context)
        req_id, resp = await verify_vvp(req, "not-valid-format")

        assert resp.overall_status == ClaimStatus.INVALID
        assert resp.claims is None
        assert len(resp.errors) == 1
        assert resp.errors[0].code == ErrorCode.VVP_IDENTITY_INVALID

    @pytest.mark.asyncio
    async def test_invalid_passport_parse_marks_claim_invalid(self, valid_context):
        with (
            patch("app.vvp.verify.parse_vvp_identity") as mock_vvp,
            patch("app.vvp.verify.parse_passport") as mock_passport,
        ):
            mock_vvp.return_value = MagicMock(evd="http://example.com/dossier")
            mock_passport.side_effect = PassportError.parse_failed("bad jwt")

            req = VerifyRequest(passport_jwt="bad", context=valid_context)
            req_id, resp = await verify_vvp(req, "aid=EAbc;evd=http://example.com")

            assert resp.overall_status == ClaimStatus.INVALID
            assert resp.claims is not None
            # Root claim should be INVALID due to required child failure
            assert resp.claims[0].status == ClaimStatus.INVALID
            # passport_verified is first child
            passport_claim = resp.claims[0].children[0].node
            assert passport_claim.name == "passport_verified"
            assert passport_claim.status == ClaimStatus.INVALID

    @pytest.mark.asyncio
    async def test_signature_invalid_marks_passport_invalid(self, valid_context):
        with (
            patch("app.vvp.verify.parse_vvp_identity") as mock_vvp,
            patch("app.vvp.verify.parse_passport") as mock_passport,
            patch("app.vvp.verify.validate_passport_binding") as mock_binding,
            patch("app.vvp.verify.verify_passport_signature") as mock_sig,
        ):
            mock_vvp.return_value = MagicMock(evd="http://example.com/dossier")
            mock_passport.return_value = MagicMock(header=MagicMock(kid="EAbc123456789012345"))
            mock_binding.return_value = None
            mock_sig.side_effect = SignatureInvalidError("bad signature")

            req = VerifyRequest(passport_jwt="test", context=valid_context)
            req_id, resp = await verify_vvp(req, "valid-header")

            assert resp.overall_status == ClaimStatus.INVALID
            passport_claim = resp.claims[0].children[0].node
            assert passport_claim.status == ClaimStatus.INVALID
            assert any("bad signature" in r for r in passport_claim.reasons)

    @pytest.mark.asyncio
    async def test_resolution_failed_marks_passport_indeterminate(self, valid_context):
        with (
            patch("app.vvp.verify.parse_vvp_identity") as mock_vvp,
            patch("app.vvp.verify.parse_passport") as mock_passport,
            patch("app.vvp.verify.validate_passport_binding") as mock_binding,
            patch("app.vvp.verify.verify_passport_signature") as mock_sig,
            patch("app.vvp.verify.fetch_dossier") as mock_fetch,
        ):
            mock_vvp.return_value = MagicMock(evd="http://example.com/dossier")
            mock_passport.return_value = MagicMock(header=MagicMock(kid="EAbc123456789012345"))
            mock_binding.return_value = None
            mock_sig.side_effect = ResolutionFailedError("network error")
            mock_fetch.return_value = b'[]'

            req = VerifyRequest(passport_jwt="test", context=valid_context)
            req_id, resp = await verify_vvp(req, "valid-header")

            # Resolution failure = INDETERMINATE (recoverable)
            passport_claim = resp.claims[0].children[0].node
            assert passport_claim.status == ClaimStatus.INDETERMINATE

    @pytest.mark.asyncio
    async def test_dossier_fetch_failure_marks_dossier_indeterminate(self, valid_context):
        with (
            patch("app.vvp.verify.parse_vvp_identity") as mock_vvp,
            patch("app.vvp.verify.parse_passport") as mock_passport,
            patch("app.vvp.verify.validate_passport_binding") as mock_binding,
            patch("app.vvp.verify.verify_passport_signature") as mock_sig,
            patch("app.vvp.verify.fetch_dossier") as mock_fetch,
        ):
            mock_vvp.return_value = MagicMock(evd="http://example.com/dossier")
            mock_passport.return_value = MagicMock(header=MagicMock(kid="EAbc123456789012345"))
            mock_binding.return_value = None
            mock_sig.return_value = None
            mock_fetch.side_effect = FetchError("timeout")

            req = VerifyRequest(passport_jwt="test", context=valid_context)
            req_id, resp = await verify_vvp(req, "valid-header")

            dossier_claim = resp.claims[0].children[1].node
            assert dossier_claim.name == "dossier_verified"
            assert dossier_claim.status == ClaimStatus.INDETERMINATE

    @pytest.mark.asyncio
    async def test_dossier_parse_failure_marks_dossier_invalid(self, valid_context):
        with (
            patch("app.vvp.verify.parse_vvp_identity") as mock_vvp,
            patch("app.vvp.verify.parse_passport") as mock_passport,
            patch("app.vvp.verify.validate_passport_binding") as mock_binding,
            patch("app.vvp.verify.verify_passport_signature") as mock_sig,
            patch("app.vvp.verify.fetch_dossier") as mock_fetch,
            patch("app.vvp.verify.parse_dossier") as mock_parse,
        ):
            mock_vvp.return_value = MagicMock(evd="http://example.com/dossier")
            mock_passport.return_value = MagicMock(header=MagicMock(kid="EAbc123456789012345"))
            mock_binding.return_value = None
            mock_sig.return_value = None
            mock_fetch.return_value = b'invalid json'
            mock_parse.side_effect = ParseError("invalid json")

            req = VerifyRequest(passport_jwt="test", context=valid_context)
            req_id, resp = await verify_vvp(req, "valid-header")

            dossier_claim = resp.claims[0].children[1].node
            assert dossier_claim.status == ClaimStatus.INVALID

    @pytest.mark.asyncio
    async def test_empty_dossier_marks_dossier_invalid(self, valid_context):
        """Empty dossier response (b'') should trigger parse failure, not bypass validation."""
        with (
            patch("app.vvp.verify.parse_vvp_identity") as mock_vvp,
            patch("app.vvp.verify.parse_passport") as mock_passport,
            patch("app.vvp.verify.validate_passport_binding") as mock_binding,
            patch("app.vvp.verify.verify_passport_signature") as mock_sig,
            patch("app.vvp.verify.fetch_dossier") as mock_fetch,
            patch("app.vvp.verify.parse_dossier") as mock_parse,
        ):
            mock_vvp.return_value = MagicMock(evd="http://example.com/dossier")
            mock_passport.return_value = MagicMock(header=MagicMock(kid="EAbc123456789012345"))
            mock_binding.return_value = None
            mock_sig.return_value = None
            mock_fetch.return_value = b""  # Empty dossier
            mock_parse.side_effect = ParseError("empty dossier")

            req = VerifyRequest(passport_jwt="test", context=valid_context)
            req_id, resp = await verify_vvp(req, "valid-header")

            # Empty dossier should be parsed (not skipped) and fail
            mock_parse.assert_called_once_with(b"")
            dossier_claim = resp.claims[0].children[1].node
            assert dossier_claim.status == ClaimStatus.INVALID
            assert any("DOSSIER_PARSE_FAILED" in str(e.code) for e in resp.errors)

    @pytest.mark.asyncio
    async def test_dossier_graph_error_marks_dossier_invalid(self, valid_context):
        with (
            patch("app.vvp.verify.parse_vvp_identity") as mock_vvp,
            patch("app.vvp.verify.parse_passport") as mock_passport,
            patch("app.vvp.verify.validate_passport_binding") as mock_binding,
            patch("app.vvp.verify.verify_passport_signature") as mock_sig,
            patch("app.vvp.verify.fetch_dossier") as mock_fetch,
            patch("app.vvp.verify.parse_dossier") as mock_parse,
            patch("app.vvp.verify.build_dag") as mock_build,
            patch("app.vvp.verify.validate_dag") as mock_validate,
        ):
            mock_vvp.return_value = MagicMock(evd="http://example.com/dossier")
            mock_passport.return_value = MagicMock(header=MagicMock(kid="EAbc123456789012345"))
            mock_binding.return_value = None
            mock_sig.return_value = None
            mock_fetch.return_value = b'[]'
            mock_parse.return_value = []
            mock_build.return_value = MagicMock()
            mock_validate.side_effect = GraphError("cycle detected")

            req = VerifyRequest(passport_jwt="test", context=valid_context)
            req_id, resp = await verify_vvp(req, "valid-header")

            dossier_claim = resp.claims[0].children[1].node
            assert dossier_claim.status == ClaimStatus.INVALID

    @pytest.mark.asyncio
    async def test_passport_fatal_skips_dossier_fetch(self, valid_context):
        """Per reviewer feedback: skip dossier fetch on non-recoverable passport failure."""
        with (
            patch("app.vvp.verify.parse_vvp_identity") as mock_vvp,
            patch("app.vvp.verify.parse_passport") as mock_passport,
            patch("app.vvp.verify.fetch_dossier") as mock_fetch,
        ):
            mock_vvp.return_value = MagicMock(evd="http://example.com/dossier")
            mock_passport.side_effect = PassportError.parse_failed("bad jwt")
            # fetch_dossier should NOT be called

            req = VerifyRequest(passport_jwt="bad", context=valid_context)
            req_id, resp = await verify_vvp(req, "valid-header")

            # Dossier fetch should not have been called due to passport fatal failure
            mock_fetch.assert_not_called()

            # Dossier should be marked INDETERMINATE (skipped)
            dossier_claim = resp.claims[0].children[1].node
            assert dossier_claim.status == ClaimStatus.INDETERMINATE
            assert "Skipped due to passport" in dossier_claim.reasons[0]

    @pytest.mark.asyncio
    async def test_all_valid_returns_valid_overall(self, valid_context):
        with (
            patch("app.vvp.verify.parse_vvp_identity") as mock_vvp,
            patch("app.vvp.verify.parse_passport") as mock_passport,
            patch("app.vvp.verify.validate_passport_binding") as mock_binding,
            patch("app.vvp.verify.verify_passport_signature") as mock_sig,
            patch("app.vvp.verify.fetch_dossier") as mock_fetch,
            patch("app.vvp.verify.parse_dossier") as mock_parse,
            patch("app.vvp.verify.build_dag") as mock_build,
            patch("app.vvp.verify.validate_dag") as mock_validate,
        ):
            mock_vvp.return_value = MagicMock(evd="http://example.com/dossier")
            mock_passport.return_value = MagicMock(header=MagicMock(kid="EAbc123456789012345"))
            mock_binding.return_value = None
            mock_sig.return_value = None
            mock_fetch.return_value = b'[]'
            mock_parse.return_value = []
            mock_dag = MagicMock()
            mock_dag.root_said = "SAID123"
            mock_build.return_value = mock_dag
            mock_validate.return_value = None

            req = VerifyRequest(passport_jwt="test", context=valid_context)
            req_id, resp = await verify_vvp(req, "valid-header")

            assert resp.overall_status == ClaimStatus.VALID
            assert resp.claims[0].status == ClaimStatus.VALID
            assert resp.claims[0].children[0].node.status == ClaimStatus.VALID
            assert resp.claims[0].children[1].node.status == ClaimStatus.VALID
            assert resp.errors is None

    @pytest.mark.asyncio
    async def test_claim_tree_structure(self, valid_context):
        """Verify the Tier 1 claim tree structure."""
        with (
            patch("app.vvp.verify.parse_vvp_identity") as mock_vvp,
            patch("app.vvp.verify.parse_passport") as mock_passport,
            patch("app.vvp.verify.validate_passport_binding") as mock_binding,
            patch("app.vvp.verify.verify_passport_signature") as mock_sig,
            patch("app.vvp.verify.fetch_dossier") as mock_fetch,
            patch("app.vvp.verify.parse_dossier") as mock_parse,
            patch("app.vvp.verify.build_dag") as mock_build,
            patch("app.vvp.verify.validate_dag") as mock_validate,
        ):
            mock_vvp.return_value = MagicMock(evd="http://example.com/dossier")
            mock_passport.return_value = MagicMock(header=MagicMock(kid="EAbc123456789012345"))
            mock_binding.return_value = None
            mock_sig.return_value = None
            mock_fetch.return_value = b'[]'
            mock_parse.return_value = []
            mock_dag = MagicMock()
            mock_dag.root_said = "SAID123"
            mock_build.return_value = mock_dag
            mock_validate.return_value = None

            req = VerifyRequest(passport_jwt="test", context=valid_context)
            req_id, resp = await verify_vvp(req, "valid-header")

            # Verify tree structure
            assert len(resp.claims) == 1
            root = resp.claims[0]
            assert root.name == "caller_authorised"
            assert len(root.children) == 2

            # Both children should be REQUIRED
            assert root.children[0].required is True
            assert root.children[1].required is True

            # Child names
            assert root.children[0].node.name == "passport_verified"
            assert root.children[1].node.name == "dossier_verified"

    @pytest.mark.asyncio
    async def test_evidence_accumulation(self, valid_context):
        """Verify evidence is accumulated correctly."""
        with (
            patch("app.vvp.verify.parse_vvp_identity") as mock_vvp,
            patch("app.vvp.verify.parse_passport") as mock_passport,
            patch("app.vvp.verify.validate_passport_binding") as mock_binding,
            patch("app.vvp.verify.verify_passport_signature") as mock_sig,
            patch("app.vvp.verify.fetch_dossier") as mock_fetch,
            patch("app.vvp.verify.parse_dossier") as mock_parse,
            patch("app.vvp.verify.build_dag") as mock_build,
            patch("app.vvp.verify.validate_dag") as mock_validate,
        ):
            mock_vvp.return_value = MagicMock(evd="http://example.com/dossier")
            mock_passport.return_value = MagicMock(header=MagicMock(kid="EAbc123456789012345678901234567890"))
            mock_binding.return_value = None
            mock_sig.return_value = None
            mock_fetch.return_value = b'[]'
            mock_parse.return_value = []
            mock_dag = MagicMock()
            mock_dag.root_said = "SAID123"
            mock_build.return_value = mock_dag
            mock_validate.return_value = None

            req = VerifyRequest(passport_jwt="test", context=valid_context)
            req_id, resp = await verify_vvp(req, "valid-header")

            passport_claim = resp.claims[0].children[0].node
            dossier_claim = resp.claims[0].children[1].node

            # Passport evidence
            assert any("kid=" in e for e in passport_claim.evidence)
            assert "binding_valid" in passport_claim.evidence
            assert "signature_valid" in passport_claim.evidence

            # Dossier evidence
            assert any("fetched=" in e for e in dossier_claim.evidence)
            assert any("dag_valid" in e for e in dossier_claim.evidence)
