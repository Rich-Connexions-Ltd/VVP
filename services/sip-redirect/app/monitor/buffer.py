"""SIP Event Buffer for monitoring dashboard.

Sprint 47: Circular buffer for capturing SIP INVITE events for
real-time visualization in the monitoring dashboard.

Sprint 48: Added subscriber mechanism for real-time WebSocket push.
"""

import asyncio
import logging
from collections import deque
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Optional

from app.config import MONITOR_BUFFER_SIZE

log = logging.getLogger(__name__)


@dataclass
class SIPEvent:
    """Captured SIP request/response event for monitoring.

    Stores all relevant data from a SIP INVITE transaction for
    visualization in the monitoring dashboard.
    """

    id: int  # Auto-incrementing event ID
    timestamp: str  # ISO 8601 timestamp
    service: str  # Service name (SIGNING, VERIFICATION)
    source_addr: str  # IP:port of sender
    method: str  # SIP method (INVITE, etc.)
    request_uri: str  # SIP Request-URI
    call_id: str  # SIP Call-ID
    from_tn: Optional[str]  # Originating telephone number
    to_tn: Optional[str]  # Destination telephone number
    api_key_prefix: Optional[str]  # First 8 chars of API key
    headers: dict  # All SIP headers
    vvp_headers: dict  # VVP-specific headers (X-VVP-*, Identity)
    response_code: int  # Response sent (302, 401, etc.)
    vvp_status: str  # VVP status (VALID, INVALID, INDETERMINATE)
    response_vvp_headers: dict  # VVP headers from SIP response (Sprint 48)
    redirect_uri: Optional[str]  # Contact URI from 302 response
    error: Optional[str]  # Error message if any
    raw_request: Optional[str] = None  # Raw SIP request message (Sprint 48)
    raw_response: Optional[str] = None  # Raw SIP response message (Sprint 48)


class SIPEventBuffer:
    """Thread-safe circular buffer for SIP events.

    Uses asyncio.Lock for thread safety. Events are stored with
    auto-incrementing IDs for efficient polling.
    """

    def __init__(self, max_size: int = 100):
        """Initialize buffer.

        Args:
            max_size: Maximum number of events to retain
        """
        self._buffer: deque = deque(maxlen=max_size)
        self._lock = asyncio.Lock()
        self._next_id: int = 1
        self._subscribers: set[asyncio.Queue] = set()
        self._sub_lock = asyncio.Lock()

    async def add(self, event_data: dict) -> int:
        """Add an event to the buffer and notify subscribers.

        Args:
            event_data: Dict with event fields (id will be auto-assigned)

        Returns:
            The assigned event ID
        """
        async with self._lock:
            event_id = self._next_id
            self._next_id += 1

            # Default response_vvp_headers if not provided (backward compat)
            event_data.setdefault("response_vvp_headers", {})

            event = SIPEvent(
                id=event_id,
                timestamp=datetime.now(timezone.utc).isoformat(),
                **event_data,
            )
            self._buffer.append(event)

        # Notify after releasing buffer lock to avoid holding it during I/O
        await self._notify_subscribers(event)
        return event_id

    async def get_all(self) -> list[dict]:
        """Get all events in buffer (newest first).

        Returns:
            List of event dicts
        """
        async with self._lock:
            return [asdict(e) for e in reversed(self._buffer)]

    async def get_since(self, last_id: int) -> list[dict]:
        """Get events newer than the given ID.

        Args:
            last_id: Only return events with ID > last_id

        Returns:
            List of event dicts (oldest first for append order)
        """
        async with self._lock:
            return [asdict(e) for e in self._buffer if e.id > last_id]

    async def clear(self) -> int:
        """Clear all events from buffer.

        Returns:
            Number of events cleared
        """
        async with self._lock:
            count = len(self._buffer)
            self._buffer.clear()
            return count

    async def subscribe(self) -> asyncio.Queue:
        """Create a subscriber queue for real-time events.

        Returns:
            asyncio.Queue that receives SIPEvent dicts as they are added.
        """
        queue: asyncio.Queue = asyncio.Queue(maxsize=100)
        async with self._sub_lock:
            self._subscribers.add(queue)
        return queue

    async def unsubscribe(self, queue: asyncio.Queue) -> None:
        """Remove a subscriber queue and drain pending items."""
        async with self._sub_lock:
            self._subscribers.discard(queue)
        # Drain pending items to avoid orphaned references
        while not queue.empty():
            try:
                queue.get_nowait()
            except asyncio.QueueEmpty:
                break

    async def _notify_subscribers(self, event: SIPEvent) -> None:
        """Push event dict to all subscribers (non-blocking).

        Uses copy-on-iterate to avoid RuntimeError from concurrent
        subscribe/unsubscribe during iteration.
        """
        event_dict = asdict(event)
        dead_queues = []

        async with self._sub_lock:
            subscribers = list(self._subscribers)

        for queue in subscribers:
            try:
                queue.put_nowait(event_dict)
            except asyncio.QueueFull:
                log.warning("Subscriber queue full, removing stale client")
                dead_queues.append(queue)

        if dead_queues:
            async with self._sub_lock:
                for q in dead_queues:
                    self._subscribers.discard(q)

    @property
    def subscriber_count(self) -> int:
        """Number of active subscribers."""
        return len(self._subscribers)

    @property
    def count(self) -> int:
        """Number of events in buffer."""
        return len(self._buffer)

    @property
    def max_size(self) -> int:
        """Maximum buffer size."""
        return self._buffer.maxlen or 0


# Global event buffer instance
_event_buffer: Optional[SIPEventBuffer] = None


def get_event_buffer() -> SIPEventBuffer:
    """Get the global event buffer instance.

    Returns:
        SIPEventBuffer singleton
    """
    global _event_buffer
    if _event_buffer is None:
        _event_buffer = SIPEventBuffer(max_size=MONITOR_BUFFER_SIZE)
    return _event_buffer
