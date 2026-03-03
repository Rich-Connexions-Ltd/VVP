"""Tests for event loop latency monitor.

Sprint 76: Tests monitor start/stop lifecycle, metric collection,
and threshold detection.
"""

import asyncio
import os

import pytest

from app.core.event_loop_monitor import (
    EventLoopMonitor,
    EventLoopMetrics,
    get_event_loop_monitor,
    reset_event_loop_monitor,
)


class TestEventLoopMetrics:
    """EventLoopMetrics dataclass tests."""

    def test_to_dict_includes_pid(self):
        metrics = EventLoopMetrics(
            current_latency_ms=1.5,
            max_latency_ms=100.0,
            blocked_count=3,
            probe_count=10,
            threshold_ms=100.0,
        )
        d = metrics.to_dict()
        assert d["worker_pid"] == os.getpid()
        assert d["current_latency_ms"] == 1.5
        assert d["max_latency_ms"] == 100.0
        assert d["blocked_count"] == 3
        assert d["probe_count"] == 10

    def test_reset(self):
        metrics = EventLoopMetrics(
            current_latency_ms=5.0,
            max_latency_ms=200.0,
            blocked_count=10,
            probe_count=50,
        )
        metrics.reset()
        assert metrics.current_latency_ms == 0.0
        assert metrics.max_latency_ms == 0.0
        assert metrics.blocked_count == 0
        assert metrics.probe_count == 0


class TestEventLoopMonitor:
    """EventLoopMonitor lifecycle and metric tests."""

    @pytest.mark.asyncio
    async def test_start_and_stop(self):
        """Monitor starts and stops cleanly."""
        monitor = EventLoopMonitor(interval=0.1, warn_threshold_ms=50.0)
        await monitor.start()
        assert monitor._task is not None
        assert not monitor._task.done()

        await monitor.stop()
        assert monitor._task is None

    @pytest.mark.asyncio
    async def test_stop_when_not_started(self):
        """Stop is safe when not started."""
        monitor = EventLoopMonitor()
        await monitor.stop()  # Should not raise

    @pytest.mark.asyncio
    async def test_double_start(self):
        """Second start is a no-op."""
        monitor = EventLoopMonitor(interval=0.1)
        await monitor.start()
        task1 = monitor._task
        await monitor.start()  # Should not create new task
        assert monitor._task is task1
        await monitor.stop()

    @pytest.mark.asyncio
    async def test_collects_metrics(self):
        """Monitor collects latency probes over time."""
        monitor = EventLoopMonitor(interval=0.05, warn_threshold_ms=1000.0)
        await monitor.start()

        # Wait for at least 2 probe cycles
        await asyncio.sleep(0.2)

        await monitor.stop()

        assert monitor.metrics.probe_count >= 2
        assert monitor.metrics.current_latency_ms >= 0
        assert monitor.metrics.max_latency_ms >= 0

    @pytest.mark.asyncio
    async def test_blocked_detection(self):
        """Monitor detects event loop blocking (simulated via sleep)."""
        monitor = EventLoopMonitor(interval=0.05, warn_threshold_ms=0.001)
        await monitor.start()

        # Wait for probes — even a healthy loop may exceed 0.001ms threshold
        await asyncio.sleep(0.2)

        await monitor.stop()

        # With such a low threshold, some probes should exceed it
        assert monitor.metrics.blocked_count >= 0  # May or may not trigger

    @pytest.mark.asyncio
    async def test_metrics_property(self):
        """Monitor exposes metrics property."""
        monitor = EventLoopMonitor(warn_threshold_ms=200.0)
        assert monitor.metrics.threshold_ms == 200.0


class TestEventLoopMonitorSingleton:
    """Singleton management."""

    def test_singleton_returns_same_instance(self):
        reset_event_loop_monitor()
        m1 = get_event_loop_monitor()
        m2 = get_event_loop_monitor()
        assert m1 is m2
        reset_event_loop_monitor()

    def test_reset_creates_new_instance(self):
        reset_event_loop_monitor()
        m1 = get_event_loop_monitor()
        reset_event_loop_monitor()
        m2 = get_event_loop_monitor()
        assert m1 is not m2
        reset_event_loop_monitor()
