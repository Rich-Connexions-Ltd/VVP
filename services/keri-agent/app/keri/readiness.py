"""Readiness state machine for KERI Agent startup.

Tracks rebuild progress and gates /readyz until state restoration
is complete, verified, and published to witnesses.

Sprint 81: Robust Post-Update State Restoration.
"""
import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum

log = logging.getLogger(__name__)


class ReadinessState(Enum):
    """States for the KERI Agent readiness lifecycle."""

    NOT_STARTED = "not_started"
    REBUILDING = "rebuilding"
    PUBLISHING = "publishing"
    VERIFYING = "verifying"
    READY = "ready"
    FAILED = "failed"


@dataclass
class RebuildReport:
    """Extended rebuild report with verification and witness details."""

    state: ReadinessState = ReadinessState.NOT_STARTED
    started_at: datetime | None = None
    completed_at: datetime | None = None
    total_seconds: float = 0.0

    # Rebuild counts
    identities_rebuilt: int = 0
    rotations_replayed: int = 0
    registries_rebuilt: int = 0
    credentials_rebuilt: int = 0

    # Verification
    identities_expected: int = 0
    registries_expected: int = 0
    credentials_expected: int = 0
    said_checks_passed: int = 0
    said_checks_failed: int = 0
    tel_integrity_passed: int = 0
    tel_integrity_failed: int = 0

    # Witness publishing
    kel_events_published: int = 0
    witnesses_published: int = 0
    witness_publish_seconds: float = 0.0
    witness_retries_pending: int = 0

    # Structured error codes (not raw messages)
    error_codes: list[str] = field(default_factory=list)

    def to_probe_dict(self) -> dict:
        """Minimal dict for unauthenticated readiness probe.

        Contains ONLY the readiness state — no counts, timing, or
        operational metadata.
        """
        return {"state": self.state.value}

    def to_internal_dict(self) -> dict:
        """Full report for authenticated admin diagnostics."""
        return {
            "state": self.state.value,
            "total_seconds": self.total_seconds,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "identities": {
                "rebuilt": self.identities_rebuilt,
                "expected": self.identities_expected,
            },
            "registries": {
                "rebuilt": self.registries_rebuilt,
                "expected": self.registries_expected,
            },
            "credentials": {
                "rebuilt": self.credentials_rebuilt,
                "expected": self.credentials_expected,
            },
            "verification": {
                "said_passed": self.said_checks_passed,
                "said_failed": self.said_checks_failed,
                "tel_passed": self.tel_integrity_passed,
                "tel_failed": self.tel_integrity_failed,
            },
            "witnesses": {
                "published": self.witnesses_published,
                "kel_events": self.kel_events_published,
                "retries_pending": self.witness_retries_pending,
            },
            "error_codes": self.error_codes,
        }


class ReadinessTracker:
    """Asyncio-safe readiness state machine.

    Tracks rebuild progress and background retry tasks.
    Only READY returns 200 from /readyz. All other states return 503.
    """

    def __init__(self):
        self._state = ReadinessState.NOT_STARTED
        self._report = RebuildReport()
        self._background_tasks: set[asyncio.Task] = set()
        self._ready_event = asyncio.Event()

    @property
    def state(self) -> ReadinessState:
        return self._state

    @property
    def report(self) -> RebuildReport:
        return self._report

    @property
    def is_ready(self) -> bool:
        return self._state == ReadinessState.READY

    async def transition(self, new_state: ReadinessState) -> None:
        """Transition to a new readiness state."""
        old = self._state
        self._state = new_state
        self._report.state = new_state
        log.info(f"Readiness: {old.value} -> {new_state.value}")
        if new_state == ReadinessState.READY:
            self._ready_event.set()

    def track_task(self, task: asyncio.Task) -> None:
        """Add a background task to the supervised set."""
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)

    async def cancel_all_tasks(self) -> None:
        """Cancel all tracked background tasks (called on shutdown)."""
        if not self._background_tasks:
            return
        log.info(f"Cancelling {len(self._background_tasks)} background tasks")
        for task in list(self._background_tasks):
            task.cancel()
        await asyncio.gather(*self._background_tasks, return_exceptions=True)
        self._background_tasks.clear()

    async def wait_for_ready(self, timeout: float = 300.0) -> bool:
        """Wait for READY state with timeout. Returns False on timeout."""
        try:
            await asyncio.wait_for(self._ready_event.wait(), timeout=timeout)
            return True
        except asyncio.TimeoutError:
            return False


# Module-level singleton
_tracker: ReadinessTracker | None = None


def get_readiness_tracker() -> ReadinessTracker:
    """Get or create the singleton ReadinessTracker."""
    global _tracker
    if _tracker is None:
        _tracker = ReadinessTracker()
    return _tracker


def reset_readiness_tracker() -> None:
    """Reset the singleton (for testing)."""
    global _tracker
    _tracker = None
