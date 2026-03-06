"""Tests for readiness state machine.

Sprint 81: Robust Post-Update State Restoration.
"""
import asyncio

import pytest

from app.keri.readiness import (
    ReadinessState,
    ReadinessTracker,
    RebuildReport,
    get_readiness_tracker,
    reset_readiness_tracker,
)


@pytest.fixture(autouse=True)
def clean_tracker():
    """Reset singleton between tests."""
    reset_readiness_tracker()
    yield
    reset_readiness_tracker()


class TestReadinessState:
    """Tests for ReadinessState enum values."""

    def test_state_values(self):
        assert ReadinessState.NOT_STARTED.value == "not_started"
        assert ReadinessState.REBUILDING.value == "rebuilding"
        assert ReadinessState.PUBLISHING.value == "publishing"
        assert ReadinessState.VERIFYING.value == "verifying"
        assert ReadinessState.READY.value == "ready"
        assert ReadinessState.FAILED.value == "failed"


class TestRebuildReport:
    """Tests for RebuildReport dataclass."""

    def test_default_state(self):
        report = RebuildReport()
        assert report.state == ReadinessState.NOT_STARTED

    def test_to_probe_dict_minimal(self):
        report = RebuildReport()
        d = report.to_probe_dict()
        assert d == {"state": "not_started"}
        assert len(d) == 1

    def test_to_probe_dict_ready(self):
        report = RebuildReport(state=ReadinessState.READY)
        assert report.to_probe_dict() == {"state": "ready"}

    def test_to_internal_dict_complete(self):
        report = RebuildReport(
            state=ReadinessState.READY,
            total_seconds=12.5,
            identities_rebuilt=5,
            identities_expected=5,
            registries_rebuilt=3,
            registries_expected=3,
            credentials_rebuilt=10,
            credentials_expected=10,
            said_checks_passed=10,
            said_checks_failed=0,
            tel_integrity_passed=10,
            tel_integrity_failed=0,
            witnesses_published=5,
            kel_events_published=15,
            witness_publish_seconds=2.3,
            error_codes=[],
        )
        d = report.to_internal_dict()
        assert d["state"] == "ready"
        assert d["total_seconds"] == 12.5
        assert d["identities"]["rebuilt"] == 5
        assert d["identities"]["expected"] == 5
        assert d["verification"]["said_passed"] == 10
        assert d["witnesses"]["published"] == 5
        assert d["error_codes"] == []

    def test_to_internal_dict_with_errors(self):
        report = RebuildReport(
            state=ReadinessState.FAILED,
            error_codes=["AID_MISMATCH:test", "TEL_MISSING_ISS:abc"],
        )
        d = report.to_internal_dict()
        assert d["state"] == "failed"
        assert len(d["error_codes"]) == 2

    def test_error_codes_mutable_default(self):
        """Verify error_codes default list is not shared between instances."""
        r1 = RebuildReport()
        r2 = RebuildReport()
        r1.error_codes.append("test")
        assert r2.error_codes == []


class TestReadinessTracker:
    """Tests for ReadinessTracker state machine."""

    @pytest.mark.asyncio
    async def test_initial_state(self):
        tracker = ReadinessTracker()
        assert tracker.state == ReadinessState.NOT_STARTED
        assert tracker.is_ready is False

    @pytest.mark.asyncio
    async def test_transition_to_ready(self):
        tracker = ReadinessTracker()
        await tracker.transition(ReadinessState.REBUILDING)
        assert tracker.state == ReadinessState.REBUILDING
        assert tracker.is_ready is False

        await tracker.transition(ReadinessState.READY)
        assert tracker.state == ReadinessState.READY
        assert tracker.is_ready is True

    @pytest.mark.asyncio
    async def test_report_state_tracks_transitions(self):
        tracker = ReadinessTracker()
        await tracker.transition(ReadinessState.PUBLISHING)
        assert tracker.report.state == ReadinessState.PUBLISHING

    @pytest.mark.asyncio
    async def test_ready_event_set_on_ready(self):
        tracker = ReadinessTracker()
        assert not tracker._ready_event.is_set()
        await tracker.transition(ReadinessState.READY)
        assert tracker._ready_event.is_set()

    @pytest.mark.asyncio
    async def test_wait_for_ready_returns_true(self):
        tracker = ReadinessTracker()

        async def _set_ready():
            await asyncio.sleep(0.05)
            await tracker.transition(ReadinessState.READY)

        task = asyncio.create_task(_set_ready())
        result = await tracker.wait_for_ready(timeout=2.0)
        assert result is True
        await task

    @pytest.mark.asyncio
    async def test_wait_for_ready_timeout(self):
        tracker = ReadinessTracker()
        result = await tracker.wait_for_ready(timeout=0.05)
        assert result is False

    @pytest.mark.asyncio
    async def test_track_task(self):
        tracker = ReadinessTracker()

        async def _noop():
            await asyncio.sleep(0.01)

        task = asyncio.create_task(_noop())
        tracker.track_task(task)
        assert task in tracker._background_tasks
        await task
        # Task done callback should discard it
        await asyncio.sleep(0.01)
        assert task not in tracker._background_tasks

    @pytest.mark.asyncio
    async def test_cancel_all_tasks(self):
        tracker = ReadinessTracker()

        async def _long_running():
            await asyncio.sleep(100)

        task = asyncio.create_task(_long_running())
        tracker.track_task(task)
        assert len(tracker._background_tasks) == 1

        await tracker.cancel_all_tasks()
        assert len(tracker._background_tasks) == 0
        assert task.cancelled()

    @pytest.mark.asyncio
    async def test_cancel_no_tasks(self):
        tracker = ReadinessTracker()
        await tracker.cancel_all_tasks()  # Should not raise


class TestSingleton:
    """Tests for module-level singleton management."""

    def test_get_readiness_tracker_returns_same_instance(self):
        t1 = get_readiness_tracker()
        t2 = get_readiness_tracker()
        assert t1 is t2

    def test_reset_creates_new_instance(self):
        t1 = get_readiness_tracker()
        reset_readiness_tracker()
        t2 = get_readiness_tracker()
        assert t1 is not t2
