"""Tests for WitnessHealthMonitor.

Sprint 86: Witness State Resilience.
"""
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.keri.witness_monitor import WitnessHealthMonitor
from app.keri.witness_recovery import (
    WitnessRecoveryService,
    WitnessStateCheck,
    RecoveryReport,
    reset_recovery_service,
)


@pytest.fixture
def mock_recovery_service():
    """Create a mock WitnessRecoveryService."""
    svc = MagicMock(spec=WitnessRecoveryService)
    svc.check_witness_state = AsyncMock(return_value=[])
    svc.recover_degraded_witnesses = AsyncMock(
        return_value=RecoveryReport(fully_recovered=True)
    )
    return svc


class TestMonitorLifecycle:
    """Test monitor start/stop lifecycle."""

    @pytest.mark.asyncio
    async def test_start_creates_task(self, mock_recovery_service):
        """Starting the monitor creates a background task."""
        with patch("app.keri.witness_monitor.MONITOR_ENABLED", True):
            monitor = WitnessHealthMonitor(
                recovery_service=mock_recovery_service,
                check_interval=0.1,
            )
            task = await monitor.start()
            assert task is not None
            assert not task.done()
            await monitor.stop()
            assert monitor._task is None

    @pytest.mark.asyncio
    async def test_start_disabled(self, mock_recovery_service):
        """Monitor does not start when disabled."""
        with patch("app.keri.witness_monitor.MONITOR_ENABLED", False):
            monitor = WitnessHealthMonitor(
                recovery_service=mock_recovery_service,
            )
            task = await monitor.start()
            assert task is None

    @pytest.mark.asyncio
    async def test_stop_is_idempotent(self, mock_recovery_service):
        """Stopping when not running doesn't raise."""
        monitor = WitnessHealthMonitor(
            recovery_service=mock_recovery_service,
        )
        await monitor.stop()  # Should not raise


class TestMonitorBehavior:
    """Test monitor check and recovery behavior."""

    @pytest.mark.asyncio
    async def test_calls_check_on_interval(self, mock_recovery_service):
        """Monitor calls check_witness_state on each interval."""
        with patch("app.keri.witness_monitor.MONITOR_ENABLED", True):
            monitor = WitnessHealthMonitor(
                recovery_service=mock_recovery_service,
                check_interval=0.05,
            )
            await monitor.start()
            await asyncio.sleep(0.15)
            await monitor.stop()

            # Should have called check at least once
            mock_recovery_service.check_witness_state.assert_called()
            # Should have been called with probe_all=False (sampling)
            for call in mock_recovery_service.check_witness_state.call_args_list:
                assert call.kwargs.get("probe_all", False) is False

    @pytest.mark.asyncio
    async def test_triggers_recovery_on_degraded(self, mock_recovery_service):
        """Monitor triggers recovery when degraded witnesses detected."""
        mock_recovery_service.check_witness_state.return_value = [
            WitnessStateCheck(
                witness_url="http://localhost:5642",
                aid="test-aid",
                expected_sn=5,
                expected_said="SAID123",
                healthy=False,
                status="stale",
            ),
        ]

        with patch("app.keri.witness_monitor.MONITOR_ENABLED", True):
            monitor = WitnessHealthMonitor(
                recovery_service=mock_recovery_service,
                check_interval=0.05,
            )
            await monitor.start()
            await asyncio.sleep(0.15)
            await monitor.stop()

            mock_recovery_service.recover_degraded_witnesses.assert_called()
            call_kwargs = mock_recovery_service.recover_degraded_witnesses.call_args
            assert call_kwargs.kwargs["action"] == "monitor_check"

    @pytest.mark.asyncio
    async def test_no_recovery_when_healthy(self, mock_recovery_service):
        """Monitor does not trigger recovery when all witnesses healthy."""
        mock_recovery_service.check_witness_state.return_value = [
            WitnessStateCheck(
                witness_url="http://localhost:5642",
                aid="test-aid",
                expected_sn=5,
                expected_said="SAID123",
                healthy=True,
                status="healthy",
            ),
        ]

        with patch("app.keri.witness_monitor.MONITOR_ENABLED", True):
            monitor = WitnessHealthMonitor(
                recovery_service=mock_recovery_service,
                check_interval=0.05,
            )
            await monitor.start()
            await asyncio.sleep(0.15)
            await monitor.stop()

            mock_recovery_service.recover_degraded_witnesses.assert_not_called()

    @pytest.mark.asyncio
    async def test_handles_exception_gracefully(self, mock_recovery_service):
        """Monitor catches exceptions and continues running."""
        mock_recovery_service.check_witness_state.side_effect = RuntimeError("boom")

        with patch("app.keri.witness_monitor.MONITOR_ENABLED", True):
            monitor = WitnessHealthMonitor(
                recovery_service=mock_recovery_service,
                check_interval=0.05,
            )
            await monitor.start()
            await asyncio.sleep(0.15)
            await monitor.stop()

            # Monitor should still have been running (not crashed)
            mock_recovery_service.check_witness_state.assert_called()
