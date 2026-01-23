"""
Unit tests for Phase 1: Core Infrastructure Models
Per VVP_Verifier_Specification_v1.4_FINAL.md
"""

import pytest
from pydantic import ValidationError

from app.vvp.api_models import (
    ClaimStatus,
    ClaimNode,
    ChildLink,
    CallContext,
    VerifyRequest,
    VerifyResponse,
    ErrorDetail,
    ErrorCode,
    ERROR_RECOVERABILITY,
    derive_overall_status,
)
from app.core.config import (
    CLOCK_SKEW_SECONDS,
    MAX_IAT_DRIFT_SECONDS,
    MAX_TOKEN_AGE_SECONDS,
    MAX_PASSPORT_VALIDITY_SECONDS,
    ALLOWED_ALGORITHMS,
    FORBIDDEN_ALGORITHMS,
)


# =============================================================================
# ClaimStatus Tests (§3.2)
# =============================================================================

class TestClaimStatus:
    """Tests for ClaimStatus enum per §3.2"""

    def test_claim_status_values(self):
        """ClaimStatus enum has exactly 3 values"""
        assert ClaimStatus.VALID.value == "VALID"
        assert ClaimStatus.INVALID.value == "INVALID"
        assert ClaimStatus.INDETERMINATE.value == "INDETERMINATE"

    def test_claim_status_count(self):
        """Exactly 3 status values per §3.2"""
        assert len(ClaimStatus) == 3

    def test_claim_status_json_serialization(self):
        """Enum serializes to string value"""
        assert ClaimStatus.VALID == "VALID"
        assert str(ClaimStatus.VALID.value) == "VALID"


# =============================================================================
# ClaimNode Tests (§4.3B)
# =============================================================================

class TestClaimNode:
    """Tests for ClaimNode with {required, node} children per §4.3B"""

    def test_claim_node_children_structure(self):
        """Children MUST be {required, node} objects per §4.3B"""
        child = ClaimNode(name="child", status=ClaimStatus.VALID)
        parent = ClaimNode(
            name="parent",
            status=ClaimStatus.VALID,
            children=[ChildLink(required=True, node=child)]
        )

        # Serialize and verify structure
        data = parent.model_dump()
        assert data["children"][0]["required"] is True
        assert data["children"][0]["node"]["name"] == "child"

    def test_claim_node_optional_child(self):
        """Optional children have required=False"""
        child = ClaimNode(name="optional_child", status=ClaimStatus.INDETERMINATE)
        parent = ClaimNode(
            name="parent",
            status=ClaimStatus.VALID,
            children=[ChildLink(required=False, node=child)]
        )

        data = parent.model_dump()
        assert data["children"][0]["required"] is False

    def test_claim_node_rejects_bare_children(self):
        """Bare children list without required flag is invalid"""
        with pytest.raises(ValidationError):
            ClaimNode(
                name="test",
                status=ClaimStatus.VALID,
                children=[{"name": "child", "status": "VALID"}]  # Missing required flag
            )

    def test_claim_node_defaults(self):
        """Default values for reasons, evidence, children"""
        node = ClaimNode(name="test", status=ClaimStatus.VALID)
        assert node.reasons == []
        assert node.evidence == []
        assert node.children == []

    def test_claim_node_with_reasons_and_evidence(self):
        """ClaimNode with populated reasons and evidence"""
        node = ClaimNode(
            name="test",
            status=ClaimStatus.INVALID,
            reasons=["signature mismatch", "key expired"],
            evidence=["said:abc123", "said:def456"]
        )
        assert len(node.reasons) == 2
        assert len(node.evidence) == 2


# =============================================================================
# VerifyRequest Tests (§4.1)
# =============================================================================

class TestVerifyRequest:
    """Tests for VerifyRequest per §4.1"""

    def test_verify_request_requires_context(self):
        """context is required per §4.1"""
        with pytest.raises(ValidationError):
            VerifyRequest(passport_jwt="eyJ...")  # Missing context

    def test_verify_request_requires_passport_jwt(self):
        """passport_jwt is required per §4.1"""
        with pytest.raises(ValidationError):
            VerifyRequest(
                context=CallContext(call_id="123", received_at="2026-01-23T12:00:00Z")
            )  # Missing passport_jwt

    def test_verify_request_valid(self):
        """Valid VerifyRequest with all required fields"""
        req = VerifyRequest(
            passport_jwt="eyJhbGciOiJFZERTQSJ9...",
            context=CallContext(call_id="123", received_at="2026-01-23T12:00:00Z")
        )
        assert req.passport_jwt == "eyJhbGciOiJFZERTQSJ9..."
        assert req.context.call_id == "123"
        assert req.context.received_at == "2026-01-23T12:00:00Z"


# =============================================================================
# ErrorCode Tests (§4.2A)
# =============================================================================

class TestErrorCode:
    """Tests for ErrorCode registry per §4.2A"""

    def test_error_code_count(self):
        """18 error codes per §4.2A"""
        codes = [attr for attr in dir(ErrorCode) if not attr.startswith("_")]
        assert len(codes) == 18

    def test_all_error_codes_have_recoverability(self):
        """Every error code must have recoverability defined"""
        for attr in dir(ErrorCode):
            if not attr.startswith("_"):
                code = getattr(ErrorCode, attr)
                assert code in ERROR_RECOVERABILITY, f"Missing recoverability for {code}"

    def test_recoverable_errors(self):
        """Verify correct errors are marked recoverable"""
        recoverable_codes = [
            ErrorCode.VVP_OOBI_FETCH_FAILED,
            ErrorCode.DOSSIER_FETCH_FAILED,
            ErrorCode.KERI_RESOLUTION_FAILED,
            ErrorCode.INTERNAL_ERROR,
        ]
        for code in recoverable_codes:
            assert ERROR_RECOVERABILITY[code] is True, f"{code} should be recoverable"

    def test_non_recoverable_errors(self):
        """Verify crypto/parse errors are non-recoverable"""
        non_recoverable_codes = [
            ErrorCode.PASSPORT_SIG_INVALID,
            ErrorCode.PASSPORT_FORBIDDEN_ALG,
            ErrorCode.ACDC_SAID_MISMATCH,
            ErrorCode.KERI_STATE_INVALID,
        ]
        for code in non_recoverable_codes:
            assert ERROR_RECOVERABILITY[code] is False, f"{code} should be non-recoverable"


# =============================================================================
# derive_overall_status Tests (§4.3A)
# =============================================================================

class TestDeriveOverallStatus:
    """Tests for derive_overall_status per §4.3A precedence rules"""

    def test_all_valid(self):
        """All VALID claims → VALID"""
        claims = [ClaimNode(name="a", status=ClaimStatus.VALID)]
        assert derive_overall_status(claims, None) == ClaimStatus.VALID

    def test_any_invalid(self):
        """Any INVALID claim → INVALID"""
        claims = [
            ClaimNode(name="a", status=ClaimStatus.VALID),
            ClaimNode(name="b", status=ClaimStatus.INVALID)
        ]
        assert derive_overall_status(claims, None) == ClaimStatus.INVALID

    def test_any_indeterminate(self):
        """Any INDETERMINATE (no INVALID) → INDETERMINATE"""
        claims = [
            ClaimNode(name="a", status=ClaimStatus.VALID),
            ClaimNode(name="b", status=ClaimStatus.INDETERMINATE)
        ]
        assert derive_overall_status(claims, None) == ClaimStatus.INDETERMINATE

    def test_non_recoverable_error(self):
        """Non-recoverable errors force INVALID"""
        errors = [ErrorDetail(code="PASSPORT_SIG_INVALID", message="bad sig", recoverable=False)]
        assert derive_overall_status(None, errors) == ClaimStatus.INVALID

    def test_recoverable_error_only(self):
        """Recoverable errors alone yield INDETERMINATE"""
        errors = [ErrorDetail(code="DOSSIER_FETCH_FAILED", message="timeout", recoverable=True)]
        assert derive_overall_status(None, errors) == ClaimStatus.INDETERMINATE

    def test_mixed_errors_and_claims(self):
        """Non-recoverable error takes precedence over claims"""
        claims = [ClaimNode(name="a", status=ClaimStatus.VALID)]
        errors = [ErrorDetail(code="PASSPORT_EXPIRED", message="expired", recoverable=False)]
        assert derive_overall_status(claims, errors) == ClaimStatus.INVALID

    def test_recoverable_error_with_valid_claims(self):
        """Recoverable error with valid claims → INDETERMINATE (error downgrades)"""
        claims = [ClaimNode(name="a", status=ClaimStatus.VALID)]
        errors = [ErrorDetail(code="DOSSIER_FETCH_FAILED", message="timeout", recoverable=True)]
        assert derive_overall_status(claims, errors) == ClaimStatus.INDETERMINATE

    def test_empty_claims_and_errors(self):
        """No claims and no errors → VALID"""
        assert derive_overall_status(None, None) == ClaimStatus.VALID
        assert derive_overall_status([], []) == ClaimStatus.VALID

    def test_invalid_takes_precedence_over_indeterminate(self):
        """INVALID > INDETERMINATE in precedence"""
        claims = [
            ClaimNode(name="a", status=ClaimStatus.INDETERMINATE),
            ClaimNode(name="b", status=ClaimStatus.INVALID),
            ClaimNode(name="c", status=ClaimStatus.VALID)
        ]
        assert derive_overall_status(claims, None) == ClaimStatus.INVALID


# =============================================================================
# Config Tests
# =============================================================================

class TestConfig:
    """Tests for configuration constants - verifies defaults match spec"""

    # Normative values (fixed by spec, cannot be changed)
    def test_max_iat_drift_normative(self):
        """Max iat drift is 5 seconds per §5.2A (NORMATIVE - spec mandated)"""
        assert MAX_IAT_DRIFT_SECONDS == 5

    # Configurable defaults (may be overridden per deployment)
    def test_clock_skew_default(self):
        """Clock skew default is ±300 seconds per §4.1A (configurable)"""
        assert CLOCK_SKEW_SECONDS == 300

    def test_max_token_age_default(self):
        """Max token age default is 300 seconds per §5.2B (configurable)"""
        assert MAX_TOKEN_AGE_SECONDS == 300

    def test_max_passport_validity(self):
        """Max PASSporT validity is 300 seconds per §5.2B"""
        assert MAX_PASSPORT_VALIDITY_SECONDS == 300

    def test_allowed_algorithms(self):
        """EdDSA is the only allowed algorithm per §5.1"""
        assert "EdDSA" in ALLOWED_ALGORITHMS
        assert len(ALLOWED_ALGORITHMS) == 1

    def test_forbidden_algorithms(self):
        """ES256, HMAC, RSA, none are forbidden per §5.0/§5.1"""
        assert "ES256" in FORBIDDEN_ALGORITHMS
        assert "none" in FORBIDDEN_ALGORITHMS
        assert "HS256" in FORBIDDEN_ALGORITHMS
        assert "RS256" in FORBIDDEN_ALGORITHMS


# =============================================================================
# VerifyResponse Tests (§4.2, §4.3)
# =============================================================================

class TestVerifyResponse:
    """Tests for VerifyResponse per §4.2, §4.3"""

    def test_response_with_claims(self):
        """Response with claims (success case)"""
        claim = ClaimNode(name="caller_authorised", status=ClaimStatus.VALID)
        response = VerifyResponse(
            request_id="123e4567-e89b-12d3-a456-426614174000",
            overall_status=ClaimStatus.VALID,
            claims=[claim]
        )
        assert response.overall_status == ClaimStatus.VALID
        assert len(response.claims) == 1
        assert response.errors is None

    def test_response_with_errors(self):
        """Response with errors (failure case)"""
        error = ErrorDetail(
            code=ErrorCode.PASSPORT_SIG_INVALID,
            message="Signature verification failed",
            recoverable=False
        )
        response = VerifyResponse(
            request_id="123e4567-e89b-12d3-a456-426614174000",
            overall_status=ClaimStatus.INVALID,
            errors=[error]
        )
        assert response.overall_status == ClaimStatus.INVALID
        assert response.claims is None
        assert len(response.errors) == 1

    def test_response_with_both_claims_and_errors(self):
        """Response may contain both claims and errors"""
        claim = ClaimNode(name="partial_claim", status=ClaimStatus.INDETERMINATE)
        error = ErrorDetail(
            code=ErrorCode.DOSSIER_FETCH_FAILED,
            message="Timeout",
            recoverable=True
        )
        response = VerifyResponse(
            request_id="123e4567-e89b-12d3-a456-426614174000",
            overall_status=ClaimStatus.INDETERMINATE,
            claims=[claim],
            errors=[error]
        )
        assert response.claims is not None
        assert response.errors is not None
