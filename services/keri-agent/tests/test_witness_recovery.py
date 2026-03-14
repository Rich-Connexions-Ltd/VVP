"""Tests for WitnessRecoveryService.

Sprint 86: Witness State Resilience.
"""
import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.keri.witness_recovery import (
    WitnessConfigurationError,
    WitnessRecoveryService,
    WitnessStateCheck,
    RecoveryReport,
    reset_recovery_service,
)
from app.keri.witness import WitnessPublisher, PublishResult, WitnessResult


@pytest.fixture
def mock_publisher():
    """Create a mock WitnessPublisher."""
    publisher = MagicMock(spec=WitnessPublisher)
    publisher._witness_urls = [
        "http://localhost:5642",
        "http://localhost:5643",
    ]
    publisher.publish_full_kel = AsyncMock(
        return_value=PublishResult(
            aid="test-aid",
            success_count=1,
            total_count=1,
            threshold_met=True,
            witnesses=[WitnessResult(url="http://localhost:5642", success=True)],
        )
    )
    publisher._distribute_receipt = AsyncMock()
    return publisher


@pytest.fixture
def recovery_service(mock_publisher):
    """Create a WitnessRecoveryService with mock publisher."""
    reset_recovery_service()
    svc = WitnessRecoveryService(
        publisher=mock_publisher,
        cooldown_seconds=5.0,
        max_recoveries_per_hour=3,
    )
    # Set witness URLs to match mock publisher
    svc._witness_urls = ["http://localhost:5642", "http://localhost:5643"]
    yield svc
    reset_recovery_service()


class TestURLValidation:
    """Test witness URL validation."""

    def test_valid_url_in_pool(self, recovery_service):
        """URL in configured pool passes validation."""
        result = recovery_service._validate_witness_url("http://localhost:5642")
        assert result == "http://localhost:5642"

    def test_valid_url_trailing_slash(self, recovery_service):
        """Trailing slash is stripped."""
        result = recovery_service._validate_witness_url("http://localhost:5642/")
        assert result == "http://localhost:5642"

    def test_invalid_url_not_in_pool(self, recovery_service):
        """URL not in pool raises WitnessConfigurationError."""
        with pytest.raises(WitnessConfigurationError):
            recovery_service._validate_witness_url("http://evil.example.com")

    @patch.dict("os.environ", {"VVP_ENV": "production"})
    def test_https_required_in_prod(self, recovery_service):
        """HTTP URLs rejected in production environment."""
        # Need to patch the module-level variable
        import app.keri.witness_recovery as wr_module
        original = wr_module.VVP_ENV
        wr_module.VVP_ENV = "production"
        try:
            with pytest.raises(WitnessConfigurationError, match="HTTPS required"):
                recovery_service._validate_witness_url("http://localhost:5642")
        finally:
            wr_module.VVP_ENV = original


class TestCooldownAndBudget:
    """Test abuse controls."""

    def test_no_cooldown_initially(self, recovery_service):
        """No cooldown on first check."""
        assert not recovery_service._check_cooldown("http://localhost:5642")

    def test_cooldown_after_recovery(self, recovery_service):
        """Cooldown is active after recording a recovery."""
        recovery_service._record_recovery("http://localhost:5642")
        assert recovery_service._check_cooldown("http://localhost:5642")

    def test_budget_not_exhausted_initially(self, recovery_service):
        """Budget is not exhausted initially."""
        assert not recovery_service._check_budget("http://localhost:5642")

    def test_budget_exhausted_after_max(self, recovery_service):
        """Budget is exhausted after max recoveries."""
        for _ in range(3):
            recovery_service._record_recovery("http://localhost:5642")
        assert recovery_service._check_budget("http://localhost:5642")

    def test_budget_per_witness(self, recovery_service):
        """Budget is tracked per-witness."""
        for _ in range(3):
            recovery_service._record_recovery("http://localhost:5642")
        # Different witness should not be exhausted
        assert not recovery_service._check_budget("http://localhost:5643")


class TestHealthPredicate:
    """Test the fail-closed health predicate via _probe_witness."""

    @pytest.mark.asyncio
    async def test_healthy_exact_match(self, recovery_service):
        """Exact sn/SAID match → healthy."""
        with patch.object(recovery_service, "_probe_witness") as mock_probe:
            mock_probe.return_value = WitnessStateCheck(
                witness_url="http://localhost:5642",
                aid="test-aid",
                expected_sn=5,
                expected_said="SAID123",
                witness_sn=5,
                witness_said="SAID123",
                healthy=True,
                status="healthy",
            )
            check = await recovery_service._probe_witness(
                "http://localhost:5642", "test-aid", 5, "SAID123"
            )
            assert check.healthy
            assert check.status == "healthy"

    @pytest.mark.asyncio
    async def test_stale_lower_sn(self, recovery_service):
        """Lower sn → stale."""
        check = WitnessStateCheck(
            witness_url="http://localhost:5642",
            aid="test-aid",
            expected_sn=5,
            expected_said="SAID123",
            witness_sn=3,
            witness_said="SAID_OLD",
            status="stale",
        )
        assert not check.healthy
        assert check.status == "stale"

    def test_corrupted_same_sn_different_said(self):
        """Same sn but different SAID → corrupted."""
        check = WitnessStateCheck(
            witness_url="http://localhost:5642",
            aid="test-aid",
            expected_sn=5,
            expected_said="SAID123",
            witness_sn=5,
            witness_said="SAID_DIFFERENT",
            status="corrupted",
        )
        assert not check.healthy
        assert check.status == "corrupted"

    def test_divergent_higher_sn(self):
        """Higher sn → divergent."""
        check = WitnessStateCheck(
            witness_url="http://localhost:5642",
            aid="test-aid",
            expected_sn=5,
            expected_said="SAID123",
            witness_sn=8,
            witness_said="SAID_FUTURE",
            status="divergent",
        )
        assert not check.healthy
        assert check.status == "divergent"

    def test_unreachable(self):
        """Connection failure → unreachable."""
        check = WitnessStateCheck(
            witness_url="http://localhost:5642",
            aid="test-aid",
            expected_sn=5,
            expected_said="SAID123",
            status="unreachable",
        )
        assert not check.healthy


class TestRecoveryReport:
    """Test RecoveryReport structure."""

    def test_default_report(self):
        """Default report has sensible defaults."""
        report = RecoveryReport()
        assert report.action == "admin_republish"
        assert report.fully_recovered is False
        assert report.per_witness == []
        assert report.error_codes == []

    def test_report_with_action(self):
        """Report tracks action type."""
        report = RecoveryReport(action="monitor_check")
        assert report.action == "monitor_check"


class TestRecoverDegradedWitnesses:
    """Test the full recovery flow."""

    @pytest.mark.asyncio
    async def test_no_seeds_returns_recovered(self, recovery_service):
        """When no seeds exist, report is fully_recovered."""
        with patch("app.keri.witness_recovery.get_seed_store") as mock_store, \
             patch("app.keri.identity.get_identity_manager") as mock_mgr:
            mock_store.return_value.get_all_identity_seeds.return_value = []
            mock_mgr.return_value = AsyncMock()

            report = await recovery_service.recover_degraded_witnesses(
                action="test"
            )
            assert report.fully_recovered is True
            assert report.identities_total == 0

    @pytest.mark.asyncio
    async def test_cooldown_skips_recovery(self, recovery_service):
        """Recovery is skipped when cooldown is active."""
        url = "http://localhost:5642"
        recovery_service._record_recovery(url)

        # Mock check_witness_state to return degraded
        with patch.object(recovery_service, "check_witness_state") as mock_check:
            mock_check.return_value = [
                WitnessStateCheck(
                    witness_url=url, aid="aid1",
                    expected_sn=1, expected_said="s1",
                    healthy=False, status="stale",
                ),
            ]
            with patch("app.keri.witness_recovery.get_seed_store") as mock_store, \
                 patch("app.keri.identity.get_identity_manager") as mock_mgr:
                mock_store.return_value.get_all_identity_seeds.return_value = [
                    MagicMock(expected_aid="aid1", name="test")
                ]
                mock_mgr.return_value = AsyncMock()

                report = await recovery_service.recover_degraded_witnesses()

                # Should have cooldown error, not fully recovered
                assert not report.fully_recovered
                assert any("COOLDOWN_ACTIVE" in code for code in report.error_codes)

    @pytest.mark.asyncio
    async def test_force_bypasses_cooldown(self, recovery_service):
        """force=True bypasses cooldown."""
        url = "http://localhost:5642"
        recovery_service._record_recovery(url)

        with patch.object(recovery_service, "check_witness_state") as mock_check, \
             patch.object(recovery_service, "_recover_one_witness") as mock_recover:
            mock_check.return_value = [
                WitnessStateCheck(
                    witness_url=url, aid="aid1",
                    expected_sn=1, expected_said="s1",
                    healthy=False, status="stale",
                ),
            ]
            from app.keri.witness_recovery import WitnessRecoveryResult
            mock_recover.return_value = WitnessRecoveryResult(
                witness_url=url,
                was_degraded=True,
                identities_published=1,
                identities_verified=1,
                fully_recovered=True,
            )

            with patch("app.keri.witness_recovery.get_seed_store") as mock_store, \
                 patch("app.keri.identity.get_identity_manager") as mock_mgr:
                mock_store.return_value.get_all_identity_seeds.return_value = [
                    MagicMock(expected_aid="aid1", name="test")
                ]
                mock_mgr.return_value = AsyncMock()

                report = await recovery_service.recover_degraded_witnesses(
                    force=True
                )

                # Should have called _recover_one_witness despite cooldown
                mock_recover.assert_called_once()

    @pytest.mark.asyncio
    async def test_circuit_breaker_blocks(self, recovery_service):
        """Circuit breaker blocks recovery when budget exhausted."""
        url = "http://localhost:5642"
        recovery_service._circuit_open.add(url)

        with patch.object(recovery_service, "check_witness_state") as mock_check:
            mock_check.return_value = [
                WitnessStateCheck(
                    witness_url=url, aid="aid1",
                    expected_sn=1, expected_said="s1",
                    healthy=False, status="stale",
                ),
            ]
            with patch("app.keri.witness_recovery.get_seed_store") as mock_store, \
                 patch("app.keri.identity.get_identity_manager") as mock_mgr:
                mock_store.return_value.get_all_identity_seeds.return_value = [
                    MagicMock(expected_aid="aid1", name="test")
                ]
                mock_mgr.return_value = AsyncMock()

                report = await recovery_service.recover_degraded_witnesses()
                assert not report.fully_recovered
                assert any("CIRCUIT_OPEN" in code for code in report.error_codes)
