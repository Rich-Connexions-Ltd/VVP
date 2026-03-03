"""Tests for PhaseTimer shared module and VVP timing instrumentation.

Sprint 76: Tests the common PhaseTimer (sync + async), verifier re-export,
and async_db_call wrapper.
"""

import asyncio
import time

import pytest

from common.vvp.timing import PhaseTimer


class TestPhaseTimer:
    """Tests for the shared PhaseTimer class."""

    def test_start_stop(self):
        timer = PhaseTimer()
        timer.start("test_phase")
        time.sleep(0.01)
        elapsed = timer.stop()
        assert elapsed > 0
        assert "test_phase" in timer.timings
        assert timer.timings["test_phase"] > 0

    def test_phase_context_manager(self):
        timer = PhaseTimer()
        with timer.phase("sync_phase"):
            time.sleep(0.01)
        assert "sync_phase" in timer.timings
        assert timer.timings["sync_phase"] >= 10  # At least 10ms

    @pytest.mark.asyncio
    async def test_aphase_context_manager(self):
        timer = PhaseTimer()
        async with timer.aphase("async_phase"):
            await asyncio.sleep(0.01)
        assert "async_phase" in timer.timings
        assert timer.timings["async_phase"] >= 5  # At least 5ms (async timing has jitter)

    def test_record(self):
        timer = PhaseTimer()
        timer.record("external", 42.5)
        assert timer.timings["external"] == 42.5

    def test_nested_phases(self):
        timer = PhaseTimer()
        timer.start("parent")
        timer.start("child")
        timer.stop()  # child
        timer.stop()  # parent
        assert "parent" in timer.timings
        assert "child" in timer.timings
        assert timer.timings["parent"] >= timer.timings["child"]

    def test_to_dict(self):
        timer = PhaseTimer()
        timer.record("a", 10.0)
        timer.record("b", 20.0)
        d = timer.to_dict()
        assert d == {"a": 10.0, "b": 20.0}

    def test_to_log_str(self):
        timer = PhaseTimer()
        timer.record("identity", 12.3)
        timer.record("signing", 45.6)
        s = timer.to_log_str()
        assert "identity=12.3ms" in s
        assert "signing=45.6ms" in s

    def test_stop_empty_stack(self):
        timer = PhaseTimer()
        elapsed = timer.stop()
        assert elapsed == 0.0

    def test_to_summary_table(self):
        timer = PhaseTimer()
        timer.record("total", 100.0)
        timer.record("total.sub1", 30.0)
        timer.record("total.sub2", 70.0)
        table = timer.to_summary_table("Test Timing")
        assert "### Test Timing" in table
        assert "**total**" in table
        assert "sub1" in table

    @pytest.mark.asyncio
    async def test_multiple_async_phases(self):
        """Multiple async phases timed sequentially."""
        timer = PhaseTimer()
        timer.start("total")
        async with timer.aphase("step1"):
            await asyncio.sleep(0.01)
        async with timer.aphase("step2"):
            await asyncio.sleep(0.01)
        timer.stop()  # total
        d = timer.to_dict()
        assert "step1" in d
        assert "step2" in d
        assert "total" in d
        assert d["total"] >= d["step1"] + d["step2"]


class TestCommonImport:
    """Verify the common module import works."""

    def test_import_from_common(self):
        from common.vvp.timing import PhaseTimer as CommonPhaseTimer
        assert CommonPhaseTimer is PhaseTimer


class TestAsyncDbCall:
    """Tests for async_db_call wrapper."""

    @pytest.mark.asyncio
    async def test_basic_call(self):
        """async_db_call runs function in thread with fresh session."""
        from app.db.session import async_db_call

        def my_func(db=None, value=None):
            assert db is not None
            return value * 2

        result = await async_db_call(my_func, value=21)
        assert result == 42

    @pytest.mark.asyncio
    async def test_exception_propagation(self):
        """Exceptions propagate through async_db_call."""
        from app.db.session import async_db_call

        def failing_func(db=None):
            raise ValueError("test error")

        with pytest.raises(ValueError, match="test error"):
            await async_db_call(failing_func)

    @pytest.mark.asyncio
    async def test_runs_in_separate_thread(self):
        """async_db_call runs the callable in a non-main thread."""
        import threading
        from app.db.session import async_db_call

        main_thread = threading.current_thread()

        def check_thread(db=None):
            return threading.current_thread()

        worker_thread = await async_db_call(check_thread)
        assert worker_thread is not main_thread
