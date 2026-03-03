"""Event loop latency monitor for detecting blocking operations.

Sprint 76: Periodically measures event loop responsiveness by scheduling
a callback and comparing expected vs actual execution time. If the event
loop is blocked by synchronous operations (e.g., sync DB calls), the
measured latency will be significantly higher than expected.

A healthy async event loop responds to scheduled callbacks within ~1ms.
If it takes >100ms, the loop is being blocked.
"""

import asyncio
import logging
import os
import time
from contextlib import suppress
from dataclasses import dataclass, field
from typing import Optional

log = logging.getLogger(__name__)


@dataclass
class EventLoopMetrics:
    """Collected event loop health metrics."""

    current_latency_ms: float = 0.0
    max_latency_ms: float = 0.0
    blocked_count: int = 0
    probe_count: int = 0
    threshold_ms: float = 100.0

    def to_dict(self) -> dict:
        return {
            "worker_pid": os.getpid(),
            "current_latency_ms": round(self.current_latency_ms, 2),
            "max_latency_ms": round(self.max_latency_ms, 2),
            "blocked_count": self.blocked_count,
            "probe_count": self.probe_count,
            "threshold_ms": self.threshold_ms,
        }

    def reset(self) -> None:
        self.current_latency_ms = 0.0
        self.max_latency_ms = 0.0
        self.blocked_count = 0
        self.probe_count = 0


class EventLoopMonitor:
    """Periodic event loop health check.

    Schedules a callback every `interval` seconds. Measures the actual delay
    between scheduled and actual execution. If > threshold, logs a warning.
    """

    def __init__(
        self,
        interval: float = 5.0,
        warn_threshold_ms: float = 100.0,
    ):
        self._interval = interval
        self._threshold = warn_threshold_ms
        self._metrics = EventLoopMetrics(threshold_ms=warn_threshold_ms)
        self._task: Optional[asyncio.Task] = None

    @property
    def metrics(self) -> EventLoopMetrics:
        return self._metrics

    async def start(self) -> None:
        """Start the monitoring background task."""
        if self._task is not None:
            return
        self._task = asyncio.create_task(self._probe_loop())
        log.info(
            f"Event loop monitor started: interval={self._interval}s, "
            f"threshold={self._threshold}ms, pid={os.getpid()}"
        )

    async def stop(self) -> None:
        """Stop the monitoring background task gracefully."""
        if self._task is None:
            return
        self._task.cancel()
        with suppress(asyncio.CancelledError):
            await self._task
        self._task = None
        log.info("Event loop monitor stopped")

    async def _probe_loop(self) -> None:
        """Main probe loop — runs until cancelled.

        Measures the drift between expected and actual wake-up time from
        asyncio.sleep(interval). If the event loop is blocked by sync ops,
        the sleep will take longer than the configured interval — the excess
        is the measured latency/drift.
        """
        while True:
            try:
                expected_wake = time.monotonic() + self._interval
                await asyncio.sleep(self._interval)
                actual_wake = time.monotonic()
                drift_ms = max(0.0, (actual_wake - expected_wake) * 1000.0)
                self._record_latency(drift_ms)
            except asyncio.CancelledError:
                raise
            except Exception as e:
                log.warning(f"Event loop monitor probe error: {e}")

    def _record_latency(self, latency_ms: float) -> None:
        """Record a latency measurement and check threshold."""
        self._metrics.current_latency_ms = latency_ms
        self._metrics.probe_count += 1

        if latency_ms > self._metrics.max_latency_ms:
            self._metrics.max_latency_ms = latency_ms

        if latency_ms > self._threshold:
            self._metrics.blocked_count += 1
            log.warning(
                f"Event loop blocked: drift={latency_ms:.1f}ms "
                f"(threshold={self._threshold}ms, pid={os.getpid()})"
            )


# Module-level singleton
_monitor: Optional[EventLoopMonitor] = None


def get_event_loop_monitor(
    interval: float = 5.0,
    warn_threshold_ms: float = 100.0,
) -> EventLoopMonitor:
    """Get or create the event loop monitor singleton."""
    global _monitor
    if _monitor is None:
        _monitor = EventLoopMonitor(
            interval=interval,
            warn_threshold_ms=warn_threshold_ms,
        )
    return _monitor


def reset_event_loop_monitor() -> None:
    """Reset the monitor singleton (for testing)."""
    global _monitor
    _monitor = None
