"""Audit logging for VVP SIP Verify Service.

Sprint 44: Ring buffer based audit logging with summary statistics.
"""

import logging
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .config import VVP_AUDIT_BUFFER_SIZE

log = logging.getLogger(__name__)


@dataclass
class AuditEvent:
    """Single audit log event."""

    timestamp: float
    call_id: str
    from_tn: str
    to_tn: str
    vvp_status: str
    brand_name: Optional[str] = None
    error_code: Optional[str] = None
    processing_time_ms: float = 0.0
    source_ip: str = ""


@dataclass
class AuditBuffer:
    """Ring buffer for audit events with summary statistics."""

    events: deque = field(default_factory=lambda: deque(maxlen=VVP_AUDIT_BUFFER_SIZE))

    # Status counters
    valid_count: int = 0
    invalid_count: int = 0
    indeterminate_count: int = 0
    error_count: int = 0

    # Timing statistics
    total_processing_time_ms: float = 0.0
    request_count: int = 0

    def add_event(self, event: AuditEvent) -> None:
        """Add an audit event to the buffer."""
        self.events.append(event)
        self.request_count += 1
        self.total_processing_time_ms += event.processing_time_ms

        # Update status counters
        status = event.vvp_status.upper() if event.vvp_status else "UNKNOWN"
        if status == "VALID":
            self.valid_count += 1
        elif status == "INVALID":
            self.invalid_count += 1
        elif status == "INDETERMINATE":
            self.indeterminate_count += 1
        else:
            self.error_count += 1

        log.debug(
            f"Audit: call_id={event.call_id}, from={event.from_tn}, "
            f"to={event.to_tn}, status={event.vvp_status}, "
            f"time_ms={event.processing_time_ms:.1f}"
        )

    def get_recent_events(self, limit: int = 100) -> List[AuditEvent]:
        """Get most recent events."""
        return list(self.events)[-limit:]

    def get_summary(self, window_seconds: int = 600) -> Dict:
        """Get summary statistics for recent time window."""
        now = time.time()
        cutoff = now - window_seconds

        recent = [e for e in self.events if e.timestamp >= cutoff]

        recent_valid = sum(1 for e in recent if e.vvp_status == "VALID")
        recent_invalid = sum(1 for e in recent if e.vvp_status == "INVALID")
        recent_indeterminate = sum(1 for e in recent if e.vvp_status == "INDETERMINATE")

        total_time = sum(e.processing_time_ms for e in recent)
        avg_time = total_time / len(recent) if recent else 0.0

        return {
            "window_seconds": window_seconds,
            "total_requests": len(recent),
            "valid_count": recent_valid,
            "invalid_count": recent_invalid,
            "indeterminate_count": recent_indeterminate,
            "avg_processing_time_ms": round(avg_time, 2),
            "all_time": {
                "total_requests": self.request_count,
                "valid_count": self.valid_count,
                "invalid_count": self.invalid_count,
                "indeterminate_count": self.indeterminate_count,
                "error_count": self.error_count,
            },
        }


# Global audit buffer
_audit_buffer: Optional[AuditBuffer] = None


def get_audit_buffer() -> AuditBuffer:
    """Get or create the global audit buffer."""
    global _audit_buffer
    if _audit_buffer is None:
        _audit_buffer = AuditBuffer()
    return _audit_buffer


def log_verification(
    call_id: str,
    from_tn: str,
    to_tn: str,
    vvp_status: str,
    brand_name: Optional[str] = None,
    error_code: Optional[str] = None,
    processing_time_ms: float = 0.0,
    source_ip: str = "",
) -> None:
    """Log a verification event."""
    event = AuditEvent(
        timestamp=time.time(),
        call_id=call_id,
        from_tn=from_tn,
        to_tn=to_tn,
        vvp_status=vvp_status,
        brand_name=brand_name,
        error_code=error_code,
        processing_time_ms=processing_time_ms,
        source_ip=source_ip,
    )
    get_audit_buffer().add_event(event)
