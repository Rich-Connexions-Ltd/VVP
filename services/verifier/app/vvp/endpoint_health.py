"""Endpoint health tracking with circuit breaker for external HTTP calls.

Tracks success/failure/latency for external endpoints and provides a
circuit breaker to skip endpoints that are consistently failing.
"""

import logging
import math
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Circuit breaker defaults
DEFAULT_FAILURE_THRESHOLD = 5
DEFAULT_RECOVERY_TIMEOUT_S = 60.0
DEFAULT_LATENCY_WINDOW = 100  # rolling window size for latency stats


@dataclass
class EndpointStats:
    """Health statistics for a single endpoint pattern."""

    url_pattern: str
    total_requests: int = 0
    successes: int = 0
    failures: int = 0
    timeouts: int = 0
    consecutive_failures: int = 0
    last_success: Optional[float] = None
    last_failure: Optional[float] = None
    _latencies: deque = field(default_factory=lambda: deque(maxlen=DEFAULT_LATENCY_WINDOW))

    @property
    def avg_latency_ms(self) -> float:
        if not self._latencies:
            return 0.0
        return sum(self._latencies) / len(self._latencies)

    @property
    def p95_latency_ms(self) -> float:
        if not self._latencies:
            return 0.0
        sorted_lats = sorted(self._latencies)
        idx = int(math.ceil(0.95 * len(sorted_lats))) - 1
        return sorted_lats[max(0, idx)]

    def to_dict(self) -> dict:
        return {
            "url_pattern": self.url_pattern,
            "total_requests": self.total_requests,
            "successes": self.successes,
            "failures": self.failures,
            "timeouts": self.timeouts,
            "consecutive_failures": self.consecutive_failures,
            "avg_latency_ms": round(self.avg_latency_ms, 2),
            "p95_latency_ms": round(self.p95_latency_ms, 2),
            "last_success": self.last_success,
            "last_failure": self.last_failure,
        }


class EndpointHealthTracker:
    """Tracks health of external endpoints with circuit breaker.

    Thread-safe via a lock on mutations.

    Circuit breaker logic:
    - After `failure_threshold` consecutive failures, the endpoint is
      marked OPEN (unhealthy) for `recovery_timeout` seconds.
    - During OPEN state, `is_healthy()` returns False, signaling callers
      to skip this endpoint.
    - After recovery_timeout, the circuit transitions to HALF-OPEN:
      the next call is allowed through as a probe.
    - If the probe succeeds, circuit closes (healthy). If it fails,
      circuit reopens for another recovery_timeout.
    """

    def __init__(
        self,
        failure_threshold: int = DEFAULT_FAILURE_THRESHOLD,
        recovery_timeout: float = DEFAULT_RECOVERY_TIMEOUT_S,
    ):
        self._failure_threshold = failure_threshold
        self._recovery_timeout = recovery_timeout
        self._stats: Dict[str, EndpointStats] = {}
        self._lock = threading.Lock()

    def _pattern_key(self, url: str) -> str:
        """Normalize URL to a pattern key (scheme + host + port)."""
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"

    def _get_stats(self, url: str) -> EndpointStats:
        key = self._pattern_key(url)
        if key not in self._stats:
            self._stats[key] = EndpointStats(url_pattern=key)
        return self._stats[key]

    def record_success(self, url: str, latency_ms: float) -> None:
        """Record a successful request."""
        with self._lock:
            stats = self._get_stats(url)
            stats.total_requests += 1
            stats.successes += 1
            stats.consecutive_failures = 0
            stats.last_success = time.monotonic()
            stats._latencies.append(latency_ms)

    def record_failure(self, url: str, error: str = "") -> None:
        """Record a failed request (non-timeout)."""
        with self._lock:
            stats = self._get_stats(url)
            stats.total_requests += 1
            stats.failures += 1
            stats.consecutive_failures += 1
            stats.last_failure = time.monotonic()
            if stats.consecutive_failures >= self._failure_threshold:
                logger.warning(
                    "Circuit OPEN for %s after %d consecutive failures: %s",
                    stats.url_pattern,
                    stats.consecutive_failures,
                    error,
                )

    def record_timeout(self, url: str) -> None:
        """Record a timeout."""
        with self._lock:
            stats = self._get_stats(url)
            stats.total_requests += 1
            stats.timeouts += 1
            stats.consecutive_failures += 1
            stats.last_failure = time.monotonic()

    def is_healthy(self, url: str) -> bool:
        """Check if an endpoint should be tried (circuit breaker check).

        Returns True if:
        - No stats (never tried, allow first attempt)
        - Consecutive failures below threshold (CLOSED)
        - Recovery timeout has elapsed (HALF-OPEN, allow probe)
        """
        with self._lock:
            key = self._pattern_key(url)
            if key not in self._stats:
                return True
            stats = self._stats[key]
            if stats.consecutive_failures < self._failure_threshold:
                return True
            # Circuit is OPEN — check if recovery timeout has elapsed
            if stats.last_failure is not None:
                elapsed = time.monotonic() - stats.last_failure
                if elapsed >= self._recovery_timeout:
                    return True  # HALF-OPEN: allow probe
            return False

    def get_all_stats(self) -> Dict[str, dict]:
        """Get stats for all tracked endpoints."""
        with self._lock:
            return {key: stats.to_dict() for key, stats in self._stats.items()}

    def reset(self) -> None:
        """Clear all tracking data."""
        with self._lock:
            self._stats.clear()


# Module-level singleton
_tracker: Optional[EndpointHealthTracker] = None


def get_endpoint_health_tracker() -> EndpointHealthTracker:
    """Get or create the global endpoint health tracker singleton."""
    global _tracker
    if _tracker is None:
        _tracker = EndpointHealthTracker()
    return _tracker
