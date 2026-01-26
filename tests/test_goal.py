"""Tests for business logic/goal verification (Phase 11).

Tests cover:
- Goal policy validation
- Signer constraint extraction
- Hours of operation constraints
- Geographic constraints (INDETERMINATE when GeoIP unavailable)
- Integration tests
"""

import pytest
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional, Dict, Any, FrozenSet

from app.vvp.goal import (
    verify_goal_policy,
    extract_signer_constraints,
    verify_signer_constraints,
    verify_business_logic,
    GoalPolicyConfig,
    SignerConstraints,
    ClaimBuilder,
)
from app.vvp.api_models import ClaimStatus


# =============================================================================
# Mock ACDC and Passport for testing
# =============================================================================


@dataclass
class MockACDC:
    """Mock ACDC credential for testing."""

    said: str
    issuer_aid: str
    attributes: Optional[Dict[str, Any]] = None
    edges: Optional[Dict[str, Any]] = None
    raw: Optional[Dict[str, Any]] = None

    def __post_init__(self):
        if self.raw is None:
            self.raw = {}
        if self.attributes is not None:
            self.raw["a"] = self.attributes
        if self.edges is not None:
            self.raw["e"] = self.edges


@dataclass
class MockPassportPayload:
    """Mock PASSporT payload for testing."""

    goal: Optional[str] = None


@dataclass
class MockPassport:
    """Mock PASSporT for testing."""

    payload: MockPassportPayload


# =============================================================================
# Goal Policy Tests
# =============================================================================


class TestGoalPolicy:
    """Tests for goal acceptance policy."""

    def test_empty_policy_accepts_all(self):
        """Empty policy should accept all goals"""
        valid, evidence = verify_goal_policy("sales", frozenset(), reject_unknown=False)
        assert valid is True
        assert "accept_all" in evidence

    def test_goal_in_whitelist_accepted(self):
        """Goal in whitelist should be accepted"""
        accepted = frozenset({"sales", "support", "callback"})
        valid, evidence = verify_goal_policy("sales", accepted, reject_unknown=True)
        assert valid is True
        assert "in_whitelist" in evidence

    def test_goal_not_in_whitelist_rejected(self):
        """Goal not in whitelist should be rejected when reject_unknown=True"""
        accepted = frozenset({"sales", "support"})
        valid, reason = verify_goal_policy("spam", accepted, reject_unknown=True)
        assert valid is False
        assert "rejected" in reason

    def test_unknown_goal_allowed(self):
        """Unknown goal should be allowed when reject_unknown=False"""
        accepted = frozenset({"sales", "support"})
        valid, evidence = verify_goal_policy("other", accepted, reject_unknown=False)
        assert valid is True
        assert "unknown_allowed" in evidence


# =============================================================================
# Signer Constraints Extraction Tests
# =============================================================================


class TestExtractSignerConstraints:
    """Tests for extracting constraints from DE credential."""

    def test_no_credential_empty_constraints(self):
        """No DE credential should return empty constraints"""
        constraints = extract_signer_constraints(None)
        assert constraints.hours_of_operation is None
        assert constraints.geographies is None

    def test_extract_hours_string_format(self):
        """Should extract hours from string format"""
        de = MockACDC(
            said="DE123",
            issuer_aid="ISSUER1",
            attributes={"hours": "09-17"},
        )

        constraints = extract_signer_constraints(de)
        assert constraints.hours_of_operation == (9, 17)

    def test_extract_hours_list_format(self):
        """Should extract hours from list format"""
        de = MockACDC(
            said="DE123",
            issuer_aid="ISSUER1",
            attributes={"operatingHours": [9, 17]},
        )

        constraints = extract_signer_constraints(de)
        assert constraints.hours_of_operation == (9, 17)

    def test_extract_hours_dict_format(self):
        """Should extract hours from dict format"""
        de = MockACDC(
            said="DE123",
            issuer_aid="ISSUER1",
            attributes={"schedule": {"start": 8, "end": 18}},
        )

        constraints = extract_signer_constraints(de)
        assert constraints.hours_of_operation == (8, 18)

    def test_extract_geographies_list(self):
        """Should extract geographies from list"""
        de = MockACDC(
            said="DE123",
            issuer_aid="ISSUER1",
            attributes={"geo": ["US", "CA", "GB"]},
        )

        constraints = extract_signer_constraints(de)
        assert constraints.geographies == ["US", "CA", "GB"]

    def test_extract_geographies_string(self):
        """Should extract geographies from comma-separated string"""
        de = MockACDC(
            said="DE123",
            issuer_aid="ISSUER1",
            attributes={"countries": "US, CA, GB"},
        )

        constraints = extract_signer_constraints(de)
        assert constraints.geographies == ["US", "CA", "GB"]


# =============================================================================
# Signer Constraints Verification Tests
# =============================================================================


class TestVerifySignerConstraints:
    """Tests for verifying call against signer constraints."""

    def test_no_constraints_valid(self):
        """No constraints should always be valid"""
        constraints = SignerConstraints()
        call_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)

        status, evidence = verify_signer_constraints(constraints, call_time)
        assert status == ClaimStatus.VALID
        assert "no_constraints" in evidence

    def test_hours_constraint_within_valid(self):
        """Call within permitted hours should be valid"""
        constraints = SignerConstraints(hours_of_operation=(9, 17))
        call_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)  # 10:00 UTC

        status, evidence = verify_signer_constraints(constraints, call_time)
        assert status == ClaimStatus.VALID
        assert any("hours_valid" in ev for ev in evidence)

    def test_hours_constraint_outside_invalid(self):
        """Call outside permitted hours should be invalid"""
        constraints = SignerConstraints(hours_of_operation=(9, 17))
        call_time = datetime(2024, 1, 15, 20, 0, 0, tzinfo=timezone.utc)  # 20:00 UTC

        status, reasons = verify_signer_constraints(constraints, call_time)
        assert status == ClaimStatus.INVALID
        assert any("outside permitted hours" in r for r in reasons)

    def test_hours_overnight_range(self):
        """Overnight hour range should work (e.g., 22-06)"""
        constraints = SignerConstraints(hours_of_operation=(22, 6))

        # 23:00 should be valid
        call_time = datetime(2024, 1, 15, 23, 0, 0, tzinfo=timezone.utc)
        status, _ = verify_signer_constraints(constraints, call_time)
        assert status == ClaimStatus.VALID

        # 03:00 should be valid
        call_time = datetime(2024, 1, 15, 3, 0, 0, tzinfo=timezone.utc)
        status, _ = verify_signer_constraints(constraints, call_time)
        assert status == ClaimStatus.VALID

        # 12:00 should be invalid
        call_time = datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        status, _ = verify_signer_constraints(constraints, call_time)
        assert status == ClaimStatus.INVALID

    def test_geo_constraint_no_geoip_indeterminate(self):
        """Geo constraint without GeoIP should be INDETERMINATE"""
        constraints = SignerConstraints(geographies=["US", "CA"])
        call_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)

        status, reasons = verify_signer_constraints(
            constraints, call_time, caller_geo=None, geo_enforced=True
        )
        assert status == ClaimStatus.INDETERMINATE
        assert any("GeoIP unavailable" in r for r in reasons)

    def test_geo_constraint_skip_when_disabled(self):
        """Geo constraint should be skipped when geo_enforced=False"""
        constraints = SignerConstraints(geographies=["US", "CA"])
        call_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)

        status, evidence = verify_signer_constraints(
            constraints, call_time, caller_geo=None, geo_enforced=False
        )
        assert status == ClaimStatus.VALID
        assert any("geo_skipped" in ev for ev in evidence)

    def test_geo_constraint_valid(self):
        """Call from permitted geography should be valid"""
        constraints = SignerConstraints(geographies=["US", "CA"])
        call_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)

        status, evidence = verify_signer_constraints(
            constraints, call_time, caller_geo="US", geo_enforced=True
        )
        assert status == ClaimStatus.VALID
        assert any("geo_valid" in ev for ev in evidence)

    def test_geo_constraint_invalid(self):
        """Call from non-permitted geography should be invalid"""
        constraints = SignerConstraints(geographies=["US", "CA"])
        call_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)

        status, reasons = verify_signer_constraints(
            constraints, call_time, caller_geo="RU", geo_enforced=True
        )
        assert status == ClaimStatus.INVALID
        assert any("not in permitted geographies" in r for r in reasons)


# =============================================================================
# Integration Tests
# =============================================================================


class TestBusinessLogicIntegration:
    """Integration tests for full business logic verification."""

    def test_no_goal_no_claim(self):
        """No goal in passport should return None"""
        passport = MockPassport(payload=MockPassportPayload(goal=None))
        policy = GoalPolicyConfig()

        result = verify_business_logic(passport, {}, None, policy)
        assert result is None

    def test_goal_accepted_policy_valid(self):
        """Goal accepted by policy should be VALID"""
        passport = MockPassport(payload=MockPassportPayload(goal="sales"))
        policy = GoalPolicyConfig(
            accepted_goals=frozenset({"sales", "support"}),
            reject_unknown=True,
        )

        result = verify_business_logic(passport, {}, None, policy)
        assert result is not None
        assert result.status == ClaimStatus.VALID
        assert any("goal_accepted" in ev for ev in result.evidence)

    def test_goal_rejected_by_policy(self):
        """Goal rejected by policy should be INVALID"""
        passport = MockPassport(payload=MockPassportPayload(goal="spam"))
        policy = GoalPolicyConfig(
            accepted_goals=frozenset({"sales", "support"}),
            reject_unknown=True,
        )

        result = verify_business_logic(passport, {}, None, policy)
        assert result is not None
        assert result.status == ClaimStatus.INVALID
        assert any("rejected" in r for r in result.reasons)

    def test_hours_constraint_violation(self):
        """Hours constraint violation should be INVALID"""
        passport = MockPassport(payload=MockPassportPayload(goal="sales"))
        policy = GoalPolicyConfig()
        de = MockACDC(
            said="DE123",
            issuer_aid="ISSUER1",
            attributes={"hours": "09-17"},
        )

        # Call at 23:00 UTC (outside 09-17)
        call_time = datetime(2024, 1, 15, 23, 0, 0, tzinfo=timezone.utc)

        result = verify_business_logic(passport, {}, de, policy, call_time=call_time)
        assert result is not None
        assert result.status == ClaimStatus.INVALID
        assert any("outside permitted hours" in r for r in result.reasons)

    def test_geo_constraint_indeterminate(self):
        """Geo constraint without GeoIP should be INDETERMINATE"""
        passport = MockPassport(payload=MockPassportPayload(goal="sales"))
        policy = GoalPolicyConfig(geo_enforced=True)
        de = MockACDC(
            said="DE123",
            issuer_aid="ISSUER1",
            attributes={"geo": ["US", "CA"]},
        )

        result = verify_business_logic(
            passport, {}, de, policy, caller_geo=None  # No GeoIP
        )
        assert result is not None
        assert result.status == ClaimStatus.INDETERMINATE
        assert any("GeoIP unavailable" in r for r in result.reasons)

    def test_all_constraints_pass(self):
        """All constraints passing should be VALID"""
        passport = MockPassport(payload=MockPassportPayload(goal="sales"))
        policy = GoalPolicyConfig(
            accepted_goals=frozenset({"sales", "support"}),
            geo_enforced=True,
        )
        de = MockACDC(
            said="DE123",
            issuer_aid="ISSUER1",
            attributes={"hours": "09-17", "geo": ["US", "CA"]},
        )

        # Call at 10:00 UTC from US
        call_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)

        result = verify_business_logic(
            passport, {}, de, policy, call_time=call_time, caller_geo="US"
        )
        assert result is not None
        assert result.status == ClaimStatus.VALID
