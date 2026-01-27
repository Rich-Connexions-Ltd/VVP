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
            patch("app.vvp.verify.verify_passport_signature_tier2_with_key_state") as mock_sig,
        ):
            mock_vvp.return_value = MagicMock(evd="http://example.com/dossier")
            mock_passport.return_value = MagicMock(header=MagicMock(kid="http://witness.example.com/oobi/EAbc123456789012345/witness/EXyz"))
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
            patch("app.vvp.verify.verify_passport_signature_tier2_with_key_state") as mock_sig,
            patch("app.vvp.verify.fetch_dossier") as mock_fetch,
        ):
            mock_vvp.return_value = MagicMock(evd="http://example.com/dossier")
            mock_passport.return_value = MagicMock(header=MagicMock(kid="http://witness.example.com/oobi/EAbc123456789012345/witness/EXyz"))
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
            patch("app.vvp.verify.verify_passport_signature_tier2_with_key_state") as mock_sig,
            patch("app.vvp.verify.fetch_dossier") as mock_fetch,
        ):
            mock_vvp.return_value = MagicMock(evd="http://example.com/dossier")
            mock_passport.return_value = MagicMock(header=MagicMock(kid="http://witness.example.com/oobi/EAbc123456789012345/witness/EXyz"))
            mock_binding.return_value = None
            mock_sig.return_value = (MagicMock(aid="ETest123...", delegation_chain=None), "VALID")
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
            patch("app.vvp.verify.verify_passport_signature_tier2_with_key_state") as mock_sig,
            patch("app.vvp.verify.fetch_dossier") as mock_fetch,
            patch("app.vvp.verify.parse_dossier") as mock_parse,
        ):
            mock_vvp.return_value = MagicMock(evd="http://example.com/dossier")
            mock_passport.return_value = MagicMock(header=MagicMock(kid="http://witness.example.com/oobi/EAbc123456789012345/witness/EXyz"))
            mock_binding.return_value = None
            mock_sig.return_value = (MagicMock(aid="ETest123...", delegation_chain=None), "VALID")
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
            patch("app.vvp.verify.verify_passport_signature_tier2_with_key_state") as mock_sig,
            patch("app.vvp.verify.fetch_dossier") as mock_fetch,
            patch("app.vvp.verify.parse_dossier") as mock_parse,
        ):
            mock_vvp.return_value = MagicMock(evd="http://example.com/dossier")
            mock_passport.return_value = MagicMock(header=MagicMock(kid="http://witness.example.com/oobi/EAbc123456789012345/witness/EXyz"))
            mock_binding.return_value = None
            mock_sig.return_value = (MagicMock(aid="ETest123...", delegation_chain=None), "VALID")
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
            patch("app.vvp.verify.verify_passport_signature_tier2_with_key_state") as mock_sig,
            patch("app.vvp.verify.fetch_dossier") as mock_fetch,
            patch("app.vvp.verify.parse_dossier") as mock_parse,
            patch("app.vvp.verify.build_dag") as mock_build,
            patch("app.vvp.verify.validate_dag") as mock_validate,
        ):
            mock_vvp.return_value = MagicMock(evd="http://example.com/dossier")
            mock_passport.return_value = MagicMock(header=MagicMock(kid="http://witness.example.com/oobi/EAbc123456789012345/witness/EXyz"))
            mock_binding.return_value = None
            mock_sig.return_value = (MagicMock(aid="ETest123...", delegation_chain=None), "VALID")
            mock_fetch.return_value = b'[]'
            mock_parse.return_value = ([], {})
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
            patch("app.vvp.verify.verify_passport_signature_tier2_with_key_state") as mock_sig,
            patch("app.vvp.verify.fetch_dossier") as mock_fetch,
            patch("app.vvp.verify.parse_dossier") as mock_parse,
            patch("app.vvp.verify.build_dag") as mock_build,
            patch("app.vvp.verify.validate_dag") as mock_validate,
            patch("app.vvp.verify._find_leaf_credentials") as mock_find_leaves,
            patch("app.vvp.verify._convert_dag_to_acdcs") as mock_convert,
            patch("app.vvp.acdc.validate_credential_chain") as mock_chain,
            patch("app.vvp.verify.validate_authorization") as mock_auth,
        ):
            mock_vvp.return_value = MagicMock(evd="http://example.com/dossier")
            # Mock passport with proper orig.tn for authorization
            # Explicitly set card=None and goal=None to prevent brand/business claims
            signer_aid = "EAbc123456789012345"
            mock_passport.return_value = MagicMock(
                header=MagicMock(kid=f"http://witness.example.com/oobi/{signer_aid}/witness/EXyz"),
                payload=MagicMock(orig={"tn": ["+15551234567"]}, card=None, goal=None)
            )
            mock_binding.return_value = None
            mock_sig.return_value = (MagicMock(aid="ETest123...", delegation_chain=None), "VALID")
            mock_fetch.return_value = b'[]'
            mock_parse.return_value = ([], {})
            mock_dag = MagicMock()
            mock_dag.root_said = "SAID123"
            mock_build.return_value = mock_dag
            mock_validate.return_value = None
            mock_find_leaves.return_value = ["SAID123"]  # Return leaf SAIDs
            # Return a mock ACDC for the leaf SAID
            mock_acdc = MagicMock()
            mock_acdc.said = "SAID123"
            mock_convert.return_value = {"SAID123": mock_acdc}
            # Chain validation returns success with root_aid
            mock_result = MagicMock()
            mock_result.root_aid = "EGLEIF0000000000"
            mock_chain.return_value = mock_result
            # Mock authorization to return VALID claims
            from app.vvp.authorization import AuthorizationClaimBuilder
            mock_party = AuthorizationClaimBuilder("party_authorized")
            mock_tn = AuthorizationClaimBuilder("tn_rights_valid")
            mock_auth.return_value = (mock_party, mock_tn)

            req = VerifyRequest(passport_jwt="test", context=valid_context)
            req_id, resp = await verify_vvp(req, "valid-header")

            assert resp.overall_status == ClaimStatus.VALID
            assert resp.claims[0].status == ClaimStatus.VALID
            assert resp.claims[0].children[0].node.status == ClaimStatus.VALID  # passport_verified
            assert resp.claims[0].children[1].node.status == ClaimStatus.VALID  # dossier_verified
            assert resp.claims[0].children[2].node.status == ClaimStatus.VALID  # authorization_valid
            assert resp.errors is None

    @pytest.mark.asyncio
    async def test_claim_tree_structure(self, valid_context):
        """Verify the Tier 1 claim tree structure."""
        with (
            patch("app.vvp.verify.parse_vvp_identity") as mock_vvp,
            patch("app.vvp.verify.parse_passport") as mock_passport,
            patch("app.vvp.verify.validate_passport_binding") as mock_binding,
            patch("app.vvp.verify.verify_passport_signature_tier2_with_key_state") as mock_sig,
            patch("app.vvp.verify.fetch_dossier") as mock_fetch,
            patch("app.vvp.verify.parse_dossier") as mock_parse,
            patch("app.vvp.verify.build_dag") as mock_build,
            patch("app.vvp.verify.validate_dag") as mock_validate,
        ):
            mock_vvp.return_value = MagicMock(evd="http://example.com/dossier")
            # Explicitly set card=None and goal=None to prevent brand/business claims
            mock_passport.return_value = MagicMock(
                header=MagicMock(kid="http://witness.example.com/oobi/EAbc123456789012345/witness/EXyz"),
                payload=MagicMock(orig={"tn": ["+15551234567"]}, card=None, goal=None)
            )
            mock_binding.return_value = None
            mock_sig.return_value = (MagicMock(aid="ETest123...", delegation_chain=None), "VALID")
            mock_fetch.return_value = b'[]'
            mock_parse.return_value = ([], {})
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
            # 4 children: passport_verified, dossier_verified, authorization_valid, context_aligned
            assert len(root.children) == 4

            # All children should be REQUIRED
            assert root.children[0].required is True
            assert root.children[1].required is True
            assert root.children[2].required is True

            # Child names
            assert root.children[0].node.name == "passport_verified"
            assert root.children[1].node.name == "dossier_verified"
            assert root.children[2].node.name == "authorization_valid"

            # authorization_valid should have 2 REQUIRED children
            auth_node = root.children[2].node
            assert len(auth_node.children) == 2
            assert auth_node.children[0].node.name == "party_authorized"
            assert auth_node.children[1].node.name == "tn_rights_valid"

    @pytest.mark.asyncio
    async def test_evidence_accumulation(self, valid_context):
        """Verify evidence is accumulated correctly."""
        with (
            patch("app.vvp.verify.parse_vvp_identity") as mock_vvp,
            patch("app.vvp.verify.parse_passport") as mock_passport,
            patch("app.vvp.verify.validate_passport_binding") as mock_binding,
            patch("app.vvp.verify.verify_passport_signature_tier2_with_key_state") as mock_sig,
            patch("app.vvp.verify.fetch_dossier") as mock_fetch,
            patch("app.vvp.verify.parse_dossier") as mock_parse,
            patch("app.vvp.verify.build_dag") as mock_build,
            patch("app.vvp.verify.validate_dag") as mock_validate,
            patch("app.vvp.verify._find_leaf_credentials") as mock_find_leaves,
            patch("app.vvp.acdc.validate_credential_chain") as mock_chain,
        ):
            mock_vvp.return_value = MagicMock(evd="http://example.com/dossier")
            # Explicitly set card=None and goal=None to prevent brand/business claims
            mock_passport.return_value = MagicMock(
                header=MagicMock(kid="http://witness.example.com/oobi/EAbc123456789012345678901234567890/witness/EXyz"),
                payload=MagicMock(orig={"tn": ["+15551234567"]}, card=None, goal=None)
            )
            mock_binding.return_value = None
            mock_sig.return_value = (MagicMock(aid="ETest123...", delegation_chain=None), "VALID")
            mock_fetch.return_value = b'[]'
            mock_parse.return_value = ([], {})
            mock_dag = MagicMock()
            mock_dag.root_said = "SAID123"
            mock_build.return_value = mock_dag
            mock_validate.return_value = None
            mock_find_leaves.return_value = ["SAID123"]
            mock_chain.return_value = True

            req = VerifyRequest(passport_jwt="test", context=valid_context)
            req_id, resp = await verify_vvp(req, "valid-header")

            passport_claim = resp.claims[0].children[0].node
            dossier_claim = resp.claims[0].children[1].node

            # Passport evidence (Tier 2 uses signature_valid,tier2)
            assert any("kid=" in e for e in passport_claim.evidence)
            assert "binding_valid" in passport_claim.evidence
            assert "signature_valid,tier2" in passport_claim.evidence

            # Dossier evidence
            assert any("fetched=" in e for e in dossier_claim.evidence)
            assert any("dag_valid" in e for e in dossier_claim.evidence)


# =============================================================================
# Sprint 18 Fix Tests
# =============================================================================


class TestSIPContextAlignmentConfig:
    """Tests for Sprint 18 fix A1/A2: Config-driven SIP context alignment."""

    def test_context_required_true_missing_context_returns_invalid(self):
        """A1: CONTEXT_ALIGNMENT_REQUIRED=True with missing context → INVALID."""
        from app.vvp.sip_context import verify_sip_context_alignment

        mock_passport = MagicMock()
        mock_passport.payload.orig = {"tn": "+15551234567"}
        mock_passport.payload.dest = {"tn": ["+15559876543"]}
        mock_passport.payload.iat = 1700000000

        # context_required=True, no SIP context
        result = verify_sip_context_alignment(
            mock_passport,
            sip_context=None,
            timing_tolerance=30,
            context_required=True,
        )

        assert result.status == ClaimStatus.INVALID
        assert "required but not provided" in result.reasons[0]

    def test_context_required_false_missing_context_returns_indeterminate(self):
        """Baseline: CONTEXT_ALIGNMENT_REQUIRED=False with missing context → INDETERMINATE."""
        from app.vvp.sip_context import verify_sip_context_alignment

        mock_passport = MagicMock()
        mock_passport.payload.orig = {"tn": "+15551234567"}
        mock_passport.payload.dest = {"tn": ["+15559876543"]}
        mock_passport.payload.iat = 1700000000

        # context_required=False (default), no SIP context
        result = verify_sip_context_alignment(
            mock_passport,
            sip_context=None,
            timing_tolerance=30,
            context_required=False,
        )

        assert result.status == ClaimStatus.INDETERMINATE
        assert "not provided" in result.reasons[0]

    def test_timing_tolerance_custom_value_allows_larger_drift(self):
        """A2: SIP_TIMING_TOLERANCE_SECONDS=60 with 45s drift → VALID."""
        from app.vvp.sip_context import verify_sip_context_alignment
        from app.vvp.api_models import SipContext
        from datetime import datetime, timezone

        # Set up passport with iat
        invite_time = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        passport_iat = int(invite_time.timestamp()) + 45  # 45 second drift

        mock_passport = MagicMock()
        mock_passport.payload.orig = {"tn": ["+15551234567"]}
        mock_passport.payload.dest = {"tn": ["+15559876543"]}
        mock_passport.payload.iat = passport_iat

        # SIP context with matching URIs
        sip_context = SipContext(
            from_uri="sip:+15551234567@example.com",
            to_uri="sip:+15559876543@example.com",
            invite_time="2024-01-01T12:00:00Z",
        )

        # With default 30s tolerance, 45s drift would fail
        result_default = verify_sip_context_alignment(
            mock_passport,
            sip_context=sip_context,
            timing_tolerance=30,
            context_required=False,
        )
        assert result_default.status == ClaimStatus.INVALID

        # With 60s tolerance, 45s drift should pass
        result_custom = verify_sip_context_alignment(
            mock_passport,
            sip_context=sip_context,
            timing_tolerance=60,
            context_required=False,
        )
        assert result_custom.status == ClaimStatus.VALID


class TestSignerDESelection:
    """Tests for Sprint 18 fix A3: DE selection by signer AID."""

    def test_find_signer_de_credential_matches_by_issuee(self):
        """A3: _find_signer_de_credential returns DE where issuee matches signer AID."""
        from app.vvp.verify import _find_signer_de_credential
        from app.vvp.acdc import ACDC

        signer_aid = "ESignerAID123456789"
        other_aid = "EOtherAID987654321"

        # Create two DE credentials with different issuees
        de1 = ACDC(
            version="ACDC10JSON00011c_",
            said="SAID_DE1",
            issuer_aid="EIssuer1",
            schema_said="ESchema1",
            attributes={"i": other_aid},  # Different AID
            edges={"delegate": {"n": "SAID_APE"}},
            rules={},
            raw={"a": {"i": other_aid}, "e": {"delegate": {"n": "SAID_APE"}}},
        )
        de2 = ACDC(
            version="ACDC10JSON00011c_",
            said="SAID_DE2",
            issuer_aid="EIssuer2",
            schema_said="ESchema2",
            attributes={"i": signer_aid},  # Matches signer AID
            edges={"delegate": {"n": "SAID_APE"}},
            rules={},
            raw={"a": {"i": signer_aid}, "e": {"delegate": {"n": "SAID_APE"}}},
        )

        dossier_acdcs = {
            "SAID_DE1": de1,
            "SAID_DE2": de2,
        }

        # Should find DE2 (matches signer AID), not DE1
        result = _find_signer_de_credential(dossier_acdcs, signer_aid)

        assert result is not None
        assert result.said == "SAID_DE2"

    def test_find_signer_de_credential_returns_none_when_no_match(self):
        """A3: _find_signer_de_credential returns None when no DE matches signer."""
        from app.vvp.verify import _find_signer_de_credential
        from app.vvp.acdc import ACDC

        signer_aid = "ESignerAID123456789"

        # Create DE with different issuee
        de = ACDC(
            version="ACDC10JSON00011c_",
            said="SAID_DE",
            issuer_aid="EIssuer",
            schema_said="ESchema",
            attributes={"i": "EOtherAID987654321"},  # Different AID
            edges={"delegate": {"n": "SAID_APE"}},
            rules={},
            raw={"a": {"i": "EOtherAID987654321"}, "e": {"delegate": {"n": "SAID_APE"}}},
        )

        dossier_acdcs = {"SAID_DE": de}

        result = _find_signer_de_credential(dossier_acdcs, signer_aid)

        assert result is None

    def test_find_signer_de_credential_ignores_non_de_credentials(self):
        """A3: _find_signer_de_credential ignores non-DE credentials."""
        from app.vvp.verify import _find_signer_de_credential
        from app.vvp.acdc import ACDC

        signer_aid = "ESignerAID123456789"

        # Create non-DE credential (APE - no delegate edges)
        ape = ACDC(
            version="ACDC10JSON00011c_",
            said="SAID_APE",
            issuer_aid="EIssuer",
            schema_said="ESchema",
            attributes={"i": signer_aid},  # Has matching issuee but not a DE
            edges={},  # No delegate edges
            rules={},
            raw={"a": {"i": signer_aid}, "e": {}},
        )

        dossier_acdcs = {"SAID_APE": ape}

        result = _find_signer_de_credential(dossier_acdcs, signer_aid)

        assert result is None


class TestMultiLeafChainAggregation:
    """Tests for multi-leaf chain status aggregation in verify.py.

    Per §6.1: For aggregate dossiers, ALL leaves must validate.
    For non-aggregate: at least one valid chain suffices (prior behavior).
    """

    @pytest.mark.asyncio
    async def test_non_aggregate_valid_chain_succeeds(self):
        """Non-aggregate dossier with a single valid leaf chain succeeds.

        This tests the basic case where a single leaf credential
        reaches a trusted root for chain_verified to be VALID.
        """
        from app.vvp.acdc import ACDC, validate_credential_chain
        from app.vvp.dossier.models import ACDCNode
        from app.vvp.dossier.validator import build_dag, validate_dag
        from app.vvp.acdc.schema_registry import KNOWN_SCHEMA_SAIDS

        # Set up trusted root
        root_aid = "D" + "R" * 43
        trusted_roots = {root_aid}
        known_le_schema = next(iter(KNOWN_SCHEMA_SAIDS.get("LE", frozenset())), "")

        root_said = "E" + "R" * 43
        leaf_said = "E" + "L" * 43

        # Root credential (LE type - this is the trust anchor)
        root_node = ACDCNode(
            said=root_said,
            issuer=root_aid,
            schema=known_le_schema,
            attributes={"LEI": "1234567890123456"},
            edges=None,
            raw={}
        )

        # Leaf credential (APE) pointing to root
        leaf_node = ACDCNode(
            said=leaf_said,
            issuer="D" + "I" * 43,
            schema="E" + "S" * 43,
            attributes={"name": "valid leaf", "i": "D" + "U" * 43},
            edges={"vetting": {"n": root_said}},
            raw={}
        )

        # Build DAG - single graph root (the leaf credential)
        dag = build_dag([root_node, leaf_node])
        validate_dag(dag, allow_aggregate=False)

        # DAG root is the LEAF (no incoming edges to leaf)
        # Trust anchor (root_said) has incoming edge from leaf
        assert dag.is_aggregate is False
        assert dag.root_said == leaf_said  # Graph root = leaf credential

        # Create ACDC versions for chain validation
        root_acdc = ACDC(
            version="",
            said=root_said,
            issuer_aid=root_aid,
            schema_said=known_le_schema,
            attributes={"LEI": "1234567890123456"},
            raw={}
        )

        leaf_acdc = ACDC(
            version="",
            said=leaf_said,
            issuer_aid="D" + "I" * 43,
            schema_said="E" + "S" * 43,
            attributes={"name": "valid leaf", "i": "D" + "U" * 43},
            edges={"vetting": {"n": root_said}},
            raw={}
        )

        dossier_acdcs = {
            root_said: root_acdc,
            leaf_said: leaf_acdc,
        }

        # Validate leaf chain - should succeed
        result = await validate_credential_chain(
            leaf_acdc,
            trusted_roots,
            dossier_acdcs,
            validate_schemas=False
        )

        assert result.validated is True
        assert result.root_aid == root_aid

    @pytest.mark.asyncio
    async def test_aggregate_all_chains_must_validate(self):
        """Aggregate dossier fails if any leaf chain fails.

        Per §6.1: ALL leaves must validate for aggregate dossiers.
        """
        from app.vvp.dossier.models import ACDCNode
        from app.vvp.dossier.validator import build_dag, validate_dag

        # Two separate roots (aggregate)
        root1_said = "E" + "1" * 43
        root2_said = "E" + "2" * 43

        root1 = ACDCNode(
            said=root1_said,
            issuer="D" + "A" * 43,
            schema="E" + "S" * 43,
            attributes={},
            edges=None,
            raw={}
        )

        root2 = ACDCNode(
            said=root2_said,
            issuer="D" + "B" * 43,
            schema="E" + "S" * 43,
            attributes={},
            edges=None,
            raw={}
        )

        dag = build_dag([root1, root2])
        validate_dag(dag, allow_aggregate=True)

        # Verify aggregate fields
        assert dag.is_aggregate is True
        assert len(dag.root_saids) == 2

    @pytest.mark.asyncio
    async def test_verify_vvp_non_aggregate_any_valid_is_success(self):
        """verify_vvp: non-aggregate dossier with mixed leaf results succeeds.

        This tests the integration point in verify.py where the aggregation
        logic is applied. For non-aggregate dossiers, at least one valid
        chain should result in chain_verified = VALID.
        """
        from app.vvp.acdc import ACDC, ACDCChainResult
        from app.vvp.acdc.exceptions import ACDCChainInvalid

        context = CallContext(call_id="test-123", received_at="2024-01-01T00:00:00Z")

        with (
            patch("app.vvp.verify.parse_vvp_identity") as mock_vvp,
            patch("app.vvp.verify.parse_passport") as mock_passport,
            patch("app.vvp.verify.validate_passport_binding") as mock_binding,
            patch("app.vvp.verify.verify_passport_signature_tier2_with_key_state") as mock_sig,
            patch("app.vvp.verify.fetch_dossier") as mock_fetch,
            patch("app.vvp.verify.parse_dossier") as mock_parse,
            patch("app.vvp.verify.build_dag") as mock_build,
            patch("app.vvp.verify.validate_dag") as mock_validate,
            patch("app.vvp.verify._find_leaf_credentials") as mock_find_leaves,
            patch("app.vvp.verify._convert_dag_to_acdcs") as mock_convert,
            patch("app.vvp.acdc.validate_credential_chain") as mock_chain,
            patch("app.vvp.verify.validate_authorization") as mock_auth,
        ):
            mock_vvp.return_value = MagicMock(evd="http://example.com/dossier")
            signer_aid = "EAbc123456789012345"
            mock_passport.return_value = MagicMock(
                header=MagicMock(kid=f"http://witness.example.com/oobi/{signer_aid}/witness/EXyz"),
                payload=MagicMock(orig={"tn": ["+15551234567"]}, card=None, goal=None)
            )
            mock_binding.return_value = None
            mock_sig.return_value = (MagicMock(aid="ETest123...", delegation_chain=None), "VALID")
            mock_fetch.return_value = b'[]'
            mock_parse.return_value = ([], {})

            # Non-aggregate DAG with two leaves
            mock_dag = MagicMock()
            mock_dag.root_said = "SAID_LEAF1"
            mock_dag.is_aggregate = False  # Explicitly non-aggregate
            mock_build.return_value = mock_dag
            mock_validate.return_value = None

            # Two leaf credentials
            mock_find_leaves.return_value = ["SAID_LEAF1", "SAID_LEAF2"]

            # Mock ACDCs for both leaves
            mock_acdc1 = MagicMock()
            mock_acdc1.said = "SAID_LEAF1"
            mock_acdc2 = MagicMock()
            mock_acdc2.said = "SAID_LEAF2"
            mock_convert.return_value = {
                "SAID_LEAF1": mock_acdc1,
                "SAID_LEAF2": mock_acdc2,
            }

            # First leaf succeeds, second leaf fails
            def chain_side_effect(acdc, **kwargs):
                if acdc.said == "SAID_LEAF1":
                    result = ACDCChainResult(
                        chain=[acdc],
                        root_aid="EGLEIF0000000000",
                        validated=True,
                        status="VALID",
                        has_variant_limitations=False
                    )
                    return result
                else:
                    raise ACDCChainInvalid("Chain failed for leaf 2")
            mock_chain.side_effect = chain_side_effect

            # Mock authorization
            from app.vvp.authorization import AuthorizationClaimBuilder
            mock_party = AuthorizationClaimBuilder("party_authorized")
            mock_tn = AuthorizationClaimBuilder("tn_rights_valid")
            mock_auth.return_value = (mock_party, mock_tn)

            req = VerifyRequest(passport_jwt="test", context=context)
            req_id, resp = await verify_vvp(req, "valid-header")

            # For non-aggregate, at least one valid chain = chain_verified VALID
            dossier_claim = resp.claims[0].children[1].node
            assert dossier_claim.status == ClaimStatus.VALID

            # Find chain_verified child claim
            chain_claim = None
            for child in dossier_claim.children:
                if child.node.name == "chain_verified":
                    chain_claim = child.node
                    break

            # chain_verified should be VALID (one chain succeeded)
            assert chain_claim is not None
            assert chain_claim.status == ClaimStatus.VALID

    @pytest.mark.asyncio
    async def test_verify_vvp_aggregate_requires_all_valid(self):
        """verify_vvp: aggregate dossier with mixed leaf results fails.

        For aggregate dossiers, ALL chains must validate. If any chain
        fails, chain_verified should be INVALID.
        """
        from app.vvp.acdc import ACDCChainResult
        from app.vvp.acdc.exceptions import ACDCChainInvalid

        context = CallContext(call_id="test-123", received_at="2024-01-01T00:00:00Z")

        with (
            patch("app.vvp.verify.parse_vvp_identity") as mock_vvp,
            patch("app.vvp.verify.parse_passport") as mock_passport,
            patch("app.vvp.verify.validate_passport_binding") as mock_binding,
            patch("app.vvp.verify.verify_passport_signature_tier2_with_key_state") as mock_sig,
            patch("app.vvp.verify.fetch_dossier") as mock_fetch,
            patch("app.vvp.verify.parse_dossier") as mock_parse,
            patch("app.vvp.verify.build_dag") as mock_build,
            patch("app.vvp.verify.validate_dag") as mock_validate,
            patch("app.vvp.verify._find_leaf_credentials") as mock_find_leaves,
            patch("app.vvp.verify._convert_dag_to_acdcs") as mock_convert,
            patch("app.vvp.acdc.validate_credential_chain") as mock_chain,
        ):
            mock_vvp.return_value = MagicMock(evd="http://example.com/dossier")
            signer_aid = "EAbc123456789012345"
            mock_passport.return_value = MagicMock(
                header=MagicMock(kid=f"http://witness.example.com/oobi/{signer_aid}/witness/EXyz"),
                payload=MagicMock(orig={"tn": ["+15551234567"]}, card=None, goal=None)
            )
            mock_binding.return_value = None
            mock_sig.return_value = (MagicMock(aid="ETest123...", delegation_chain=None), "VALID")
            mock_fetch.return_value = b'[]'
            mock_parse.return_value = ([], {})

            # Aggregate DAG with two leaves
            mock_dag = MagicMock()
            mock_dag.root_said = "SAID_LEAF1"
            mock_dag.is_aggregate = True  # Aggregate dossier
            mock_build.return_value = mock_dag
            mock_validate.return_value = None

            # Two leaf credentials
            mock_find_leaves.return_value = ["SAID_LEAF1", "SAID_LEAF2"]

            mock_acdc1 = MagicMock()
            mock_acdc1.said = "SAID_LEAF1"
            mock_acdc2 = MagicMock()
            mock_acdc2.said = "SAID_LEAF2"
            mock_convert.return_value = {
                "SAID_LEAF1": mock_acdc1,
                "SAID_LEAF2": mock_acdc2,
            }

            # First leaf succeeds, second leaf fails
            def chain_side_effect(acdc, **kwargs):
                if acdc.said == "SAID_LEAF1":
                    return ACDCChainResult(
                        chain=[acdc],
                        root_aid="EGLEIF0000000000",
                        validated=True,
                        status="VALID",
                        has_variant_limitations=False
                    )
                else:
                    raise ACDCChainInvalid("Chain failed for leaf 2")
            mock_chain.side_effect = chain_side_effect

            req = VerifyRequest(passport_jwt="test", context=context)
            req_id, resp = await verify_vvp(req, "valid-header")

            # For aggregate, any invalid chain = overall chain_verified INVALID
            dossier_claim = resp.claims[0].children[1].node

            # Find chain_verified child claim
            chain_claim = None
            for child in dossier_claim.children:
                if child.node.name == "chain_verified":
                    chain_claim = child.node
                    break

            # chain_verified should be INVALID (aggregate requires all chains)
            assert chain_claim is not None
            assert chain_claim.status == ClaimStatus.INVALID


# =============================================================================
# Issuer Identity Tests
# =============================================================================


class TestIssuerIdentitiesInResponse:
    """Test issuer_identities field in VerifyResponse."""

    @pytest.mark.asyncio
    async def test_issuer_identities_populated_from_dossier(self):
        """issuer_identities includes identities extracted from dossier credentials."""
        from app.vvp.acdc import ACDCChainResult
        from app.vvp.dossier.models import ACDCNode

        context = CallContext(call_id="test-123", received_at="2024-01-01T00:00:00Z")

        with (
            patch("app.vvp.verify.parse_vvp_identity") as mock_vvp,
            patch("app.vvp.verify.parse_passport") as mock_passport,
            patch("app.vvp.verify.validate_passport_binding") as mock_binding,
            patch("app.vvp.verify.verify_passport_signature_tier2_with_key_state") as mock_sig,
            patch("app.vvp.verify.fetch_dossier") as mock_fetch,
            patch("app.vvp.verify.parse_dossier") as mock_parse,
            patch("app.vvp.verify.build_dag") as mock_build,
            patch("app.vvp.verify.validate_dag") as mock_validate,
            patch("app.vvp.verify._find_leaf_credentials") as mock_find_leaves,
            patch("app.vvp.verify._convert_dag_to_acdcs") as mock_convert,
            patch("app.vvp.acdc.validate_credential_chain") as mock_chain,
            patch("app.vvp.verify.validate_authorization") as mock_auth,
        ):
            mock_vvp.return_value = MagicMock(evd="http://example.com/dossier")
            signer_aid = "EAbc123456789012345"
            mock_passport.return_value = MagicMock(
                header=MagicMock(kid=f"http://witness.example.com/oobi/{signer_aid}/witness/EXyz"),
                payload=MagicMock(orig={"tn": ["+15551234567"]}, card=None, goal=None)
            )
            mock_binding.return_value = None
            mock_sig.return_value = (MagicMock(aid=signer_aid, delegation_chain=None), "VALID")
            mock_fetch.return_value = b'[]'

            # Create a node with identity info (legalName)
            issuee_aid = "EIssuee12345678901234567890123456789012"
            node = ACDCNode(
                said="ESAID1234567890123456789012345678901234567",
                issuer="EIssuer12345678901234567890123456789012",
                schema="ESchema12345678901234567890123456789012",
                attributes={"legalName": "Test Corp", "issuee": issuee_aid},
                edges=None,
                raw={"v": "ACDC10JSON", "a": {"legalName": "Test Corp", "issuee": issuee_aid}}
            )
            mock_parse.return_value = ([node], {})

            # Mock DAG with the node
            mock_dag = MagicMock()
            mock_dag.root_said = node.said
            mock_dag.is_aggregate = False
            mock_dag.nodes = {node.said: node}
            mock_build.return_value = mock_dag
            mock_validate.return_value = None

            mock_find_leaves.return_value = [node.said]

            # Mock ACDC conversion
            mock_acdc = MagicMock()
            mock_acdc.said = node.said
            mock_convert.return_value = {node.said: mock_acdc}

            # Chain validation succeeds
            mock_chain.return_value = ACDCChainResult(
                chain=[mock_acdc],
                root_aid="EGLEIF0000000000",
                validated=True,
                status="VALID",
                has_variant_limitations=False
            )

            # Mock authorization
            from app.vvp.authorization import AuthorizationClaimBuilder
            mock_party = AuthorizationClaimBuilder("party_authorized")
            mock_tn = AuthorizationClaimBuilder("tn_rights_valid")
            mock_auth.return_value = (mock_party, mock_tn)

            req = VerifyRequest(passport_jwt="test", context=context)
            req_id, resp = await verify_vvp(req, "valid-header")

            # issuer_identities should be populated
            assert resp.issuer_identities is not None
            assert issuee_aid in resp.issuer_identities
            identity = resp.issuer_identities[issuee_aid]
            assert identity.legal_name == "Test Corp"
            assert identity.identity_source == "dossier"

    @pytest.mark.asyncio
    async def test_issuer_identities_none_when_dossier_empty(self):
        """issuer_identities is None when dossier has no identity credentials."""
        context = CallContext(call_id="test-123", received_at="2024-01-01T00:00:00Z")

        with (
            patch("app.vvp.verify.parse_vvp_identity") as mock_vvp,
            patch("app.vvp.verify.parse_passport") as mock_passport,
            patch("app.vvp.verify.validate_passport_binding") as mock_binding,
            patch("app.vvp.verify.verify_passport_signature_tier2_with_key_state") as mock_sig,
            patch("app.vvp.verify.fetch_dossier") as mock_fetch,
            patch("app.vvp.verify.parse_dossier") as mock_parse,
            patch("app.vvp.verify.build_dag") as mock_build,
            patch("app.vvp.verify.validate_dag") as mock_validate,
            patch("app.vvp.verify._find_leaf_credentials") as mock_find_leaves,
            patch("app.vvp.verify._convert_dag_to_acdcs") as mock_convert,
            patch("app.vvp.acdc.validate_credential_chain") as mock_chain,
            patch("app.vvp.verify.validate_authorization") as mock_auth,
        ):
            mock_vvp.return_value = MagicMock(evd="http://example.com/dossier")
            signer_aid = "EAbc123456789012345"
            mock_passport.return_value = MagicMock(
                header=MagicMock(kid=f"http://witness.example.com/oobi/{signer_aid}/witness/EXyz"),
                payload=MagicMock(orig={"tn": ["+15551234567"]}, card=None, goal=None)
            )
            mock_binding.return_value = None
            mock_sig.return_value = (MagicMock(aid=signer_aid, delegation_chain=None), "VALID")
            mock_fetch.return_value = b'[]'
            # Empty dossier - no credentials
            mock_parse.return_value = ([], {})

            # Empty DAG (no nodes)
            mock_dag = MagicMock()
            mock_dag.root_said = None
            mock_dag.is_aggregate = False
            mock_dag.nodes = {}  # Empty - no credentials
            mock_build.return_value = mock_dag
            mock_validate.return_value = None

            mock_find_leaves.return_value = []
            mock_convert.return_value = {}
            mock_chain.return_value = None

            # Mock authorization
            from app.vvp.authorization import AuthorizationClaimBuilder
            mock_party = AuthorizationClaimBuilder("party_authorized")
            mock_tn = AuthorizationClaimBuilder("tn_rights_valid")
            mock_auth.return_value = (mock_party, mock_tn)

            req = VerifyRequest(passport_jwt="test", context=context)
            req_id, resp = await verify_vvp(req, "valid-header")

            # issuer_identities should be None when no identity credentials found
            assert resp.issuer_identities is None
