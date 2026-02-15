"""Tests for Sprint 62: SIP Vetter Status Propagation.

Tests cover:
- SIPResponse vetter_status field and serialization
- build_302_redirect with vetter_status parameter
- VerifyResult vetter_status field
- VerifierClient._derive_vetter_status mapping logic
"""

import pytest

from common.vvp.sip.models import SIPRequest, SIPResponse
from common.vvp.sip.builder import build_302_redirect


# =============================================================================
# SIPResponse vetter_status field
# =============================================================================


class TestSIPResponseVetterStatus:
    """Test vetter_status field on SIPResponse."""

    def test_default_vetter_status_is_none(self):
        resp = SIPResponse(status_code=302, reason_phrase="Moved Temporarily")
        assert resp.vetter_status is None

    def test_vetter_status_set(self):
        resp = SIPResponse(
            status_code=302,
            reason_phrase="Moved Temporarily",
            vetter_status="PASS",
        )
        assert resp.vetter_status == "PASS"

    def test_vetter_status_serialized_in_bytes(self):
        resp = SIPResponse(
            status_code=302,
            reason_phrase="Moved Temporarily",
            vetter_status="FAIL-ECC",
        )
        raw = resp.to_bytes().decode("utf-8")
        assert "X-VVP-Vetter-Status: FAIL-ECC" in raw

    def test_vetter_status_none_not_serialized(self):
        resp = SIPResponse(
            status_code=302,
            reason_phrase="Moved Temporarily",
        )
        raw = resp.to_bytes().decode("utf-8")
        assert "X-VVP-Vetter-Status" not in raw

    def test_vetter_status_fail_jurisdiction(self):
        resp = SIPResponse(
            status_code=302,
            reason_phrase="Moved Temporarily",
            vetter_status="FAIL-JURISDICTION",
        )
        raw = resp.to_bytes().decode("utf-8")
        assert "X-VVP-Vetter-Status: FAIL-JURISDICTION" in raw

    def test_vetter_status_fail_both(self):
        resp = SIPResponse(
            status_code=302,
            reason_phrase="Moved Temporarily",
            vetter_status="FAIL-ECC-JURISDICTION",
        )
        raw = resp.to_bytes().decode("utf-8")
        assert "X-VVP-Vetter-Status: FAIL-ECC-JURISDICTION" in raw


# =============================================================================
# build_302_redirect with vetter_status
# =============================================================================


class TestBuild302RedirectVetterStatus:
    """Test build_302_redirect passes vetter_status through."""

    def _make_request(self):
        return SIPRequest(
            method="INVITE",
            request_uri="sip:+441923311006@pbx",
            via=["SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK123"],
            from_header="<sip:+15551001@pbx>;tag=abc",
            to_header="<sip:+441923311006@pbx>",
            call_id="test-call-id@pbx",
            cseq="1 INVITE",
        )

    def test_vetter_status_pass(self):
        req = self._make_request()
        resp = build_302_redirect(
            req,
            contact_uri="sip:+441923311006@127.0.0.1:5080",
            vetter_status="PASS",
        )
        assert resp.vetter_status == "PASS"
        raw = resp.to_bytes().decode("utf-8")
        assert "X-VVP-Vetter-Status: PASS" in raw

    def test_vetter_status_fail_ecc(self):
        req = self._make_request()
        resp = build_302_redirect(
            req,
            contact_uri="sip:+441923311006@127.0.0.1:5080",
            vetter_status="FAIL-ECC",
        )
        assert resp.vetter_status == "FAIL-ECC"

    def test_vetter_status_none_by_default(self):
        req = self._make_request()
        resp = build_302_redirect(
            req,
            contact_uri="sip:+441923311006@127.0.0.1:5080",
        )
        assert resp.vetter_status is None
        raw = resp.to_bytes().decode("utf-8")
        assert "X-VVP-Vetter-Status" not in raw


# =============================================================================
# VerifierClient._derive_vetter_status
# =============================================================================


class TestDeriveVetterStatus:
    """Test the vetter_constraints → vetter_status mapping."""

    def _derive(self, constraints):
        from app.verify.client import VerifierClient
        return VerifierClient._derive_vetter_status(constraints)

    def test_none_constraints_returns_none(self):
        assert self._derive(None) is None

    def test_empty_list_returns_none(self):
        assert self._derive([]) is None

    def test_all_authorized_returns_pass(self):
        constraints = [
            {"check_type": "ecc", "is_authorized": True},
            {"check_type": "jurisdiction", "is_authorized": True},
        ]
        assert self._derive(constraints) == "PASS"

    def test_ecc_failure_returns_fail_ecc(self):
        constraints = [
            {"check_type": "ecc", "is_authorized": False},
            {"check_type": "jurisdiction", "is_authorized": True},
        ]
        assert self._derive(constraints) == "FAIL-ECC"

    def test_jurisdiction_failure_returns_fail_jurisdiction(self):
        constraints = [
            {"check_type": "ecc", "is_authorized": True},
            {"check_type": "jurisdiction", "is_authorized": False},
        ]
        assert self._derive(constraints) == "FAIL-JURISDICTION"

    def test_both_failures_returns_fail_ecc_jurisdiction(self):
        constraints = [
            {"check_type": "ecc", "is_authorized": False},
            {"check_type": "jurisdiction", "is_authorized": False},
        ]
        assert self._derive(constraints) == "FAIL-ECC-JURISDICTION"

    def test_single_authorized_constraint(self):
        constraints = [
            {"check_type": "ecc", "is_authorized": True},
        ]
        assert self._derive(constraints) == "PASS"

    def test_single_failed_ecc_constraint(self):
        constraints = [
            {"check_type": "ecc", "is_authorized": False},
        ]
        assert self._derive(constraints) == "FAIL-ECC"

    def test_mixed_multiple_constraints(self):
        """Multiple constraints of same type — one failure is enough."""
        constraints = [
            {"check_type": "ecc", "is_authorized": True},
            {"check_type": "ecc", "is_authorized": False},
            {"check_type": "jurisdiction", "is_authorized": True},
        ]
        assert self._derive(constraints) == "FAIL-ECC"
