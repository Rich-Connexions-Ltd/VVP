"""Tests for Sprint 48: WebSocket real-time events and buffer subscribers.

Tests cover:
- SIPEventBuffer subscriber mechanism (subscribe, unsubscribe, notify)
- WebSocketManager connection tracking and limits
"""

import asyncio

import pytest

from app.monitor.buffer import SIPEventBuffer
from app.monitor.server import WebSocketManager


# =============================================================================
# BUFFER SUBSCRIBER TESTS
# =============================================================================


def _make_event_data(**overrides):
    """Create minimal event data dict for testing."""
    defaults = {
        "source_addr": "10.0.0.1:5060",
        "method": "INVITE",
        "request_uri": "sip:1006@pbx.rcnx.io",
        "call_id": "test-call-123",
        "from_tn": "1001",
        "to_tn": "1006",
        "api_key_prefix": "test1234",
        "headers": {"Via": "SIP/2.0/UDP 10.0.0.1"},
        "vvp_headers": {},
        "response_code": 302,
        "vvp_status": "VALID",
        "redirect_uri": "sip:1006@10.0.0.2",
        "error": None,
    }
    defaults.update(overrides)
    return defaults


class TestBufferSubscribe:
    """Test SIPEventBuffer subscriber mechanism."""

    async def test_subscribe_receives_events(self):
        """Subscriber queue receives events after add()."""
        buffer = SIPEventBuffer(max_size=10)
        queue = await buffer.subscribe()

        await buffer.add(_make_event_data(from_tn="1001"))

        assert not queue.empty()
        event = queue.get_nowait()
        assert event["from_tn"] == "1001"
        assert event["id"] == 1

    async def test_unsubscribe_stops_events(self):
        """No events received after unsubscribe."""
        buffer = SIPEventBuffer(max_size=10)
        queue = await buffer.subscribe()

        await buffer.unsubscribe(queue)
        await buffer.add(_make_event_data())

        assert queue.empty()

    async def test_unsubscribe_drains_queue(self):
        """Pending items drained on unsubscribe."""
        buffer = SIPEventBuffer(max_size=10)
        queue = await buffer.subscribe()

        # Add events before unsubscribing
        await buffer.add(_make_event_data())
        await buffer.add(_make_event_data())
        assert not queue.empty()

        await buffer.unsubscribe(queue)
        assert queue.empty()

    async def test_full_queue_discarded(self):
        """Full subscriber queue is auto-removed."""
        buffer = SIPEventBuffer(max_size=200)
        queue = await buffer.subscribe()

        # Fill the queue (maxsize=100)
        for i in range(100):
            await buffer.add(_make_event_data(from_tn=str(i)))

        assert buffer.subscriber_count == 1

        # Next event should overflow and trigger discard
        await buffer.add(_make_event_data(from_tn="overflow"))
        assert buffer.subscriber_count == 0

    async def test_multiple_subscribers(self):
        """All subscribers receive the same event."""
        buffer = SIPEventBuffer(max_size=10)
        q1 = await buffer.subscribe()
        q2 = await buffer.subscribe()
        q3 = await buffer.subscribe()

        await buffer.add(_make_event_data(call_id="multi-test"))

        for q in [q1, q2, q3]:
            event = q.get_nowait()
            assert event["call_id"] == "multi-test"

    async def test_concurrent_subscribe_notify(self):
        """No RuntimeError from concurrent subscribe/notify."""
        buffer = SIPEventBuffer(max_size=100)
        queues = []

        async def add_events():
            for i in range(20):
                await buffer.add(_make_event_data(from_tn=str(i)))
                await asyncio.sleep(0)

        async def subscribe_unsubscribe():
            for _ in range(20):
                q = await buffer.subscribe()
                queues.append(q)
                await asyncio.sleep(0)
                await buffer.unsubscribe(q)

        # Run concurrently - should not raise RuntimeError
        await asyncio.gather(add_events(), subscribe_unsubscribe())

    async def test_subscriber_count(self):
        """subscriber_count property tracks active subscribers."""
        buffer = SIPEventBuffer(max_size=10)
        assert buffer.subscriber_count == 0

        q1 = await buffer.subscribe()
        assert buffer.subscriber_count == 1

        q2 = await buffer.subscribe()
        assert buffer.subscriber_count == 2

        await buffer.unsubscribe(q1)
        assert buffer.subscriber_count == 1

        await buffer.unsubscribe(q2)
        assert buffer.subscriber_count == 0


# =============================================================================
# WEBSOCKET MANAGER TESTS
# =============================================================================


class TestWebSocketManager:
    """Test WebSocketManager connection tracking."""

    def test_can_connect_initial(self):
        """New IP can connect."""
        mgr = WebSocketManager(max_per_ip=10, max_global=50)
        assert mgr.can_connect("10.0.0.1") is True

    def test_per_ip_limit(self):
        """Reject at per-IP limit."""
        mgr = WebSocketManager(max_per_ip=3, max_global=50)

        for _ in range(3):
            mgr.add("10.0.0.1")

        assert mgr.can_connect("10.0.0.1") is False
        # Different IP still works
        assert mgr.can_connect("10.0.0.2") is True

    def test_global_limit(self):
        """Reject at global cap."""
        mgr = WebSocketManager(max_per_ip=10, max_global=5)

        for i in range(5):
            mgr.add(f"10.0.0.{i}")

        assert mgr.total == 5
        # Even new IP is rejected
        assert mgr.can_connect("10.0.0.99") is False

    def test_remove_frees_slot(self):
        """Removing connection allows new one."""
        mgr = WebSocketManager(max_per_ip=2, max_global=50)

        mgr.add("10.0.0.1")
        mgr.add("10.0.0.1")
        assert mgr.can_connect("10.0.0.1") is False

        mgr.remove("10.0.0.1")
        assert mgr.can_connect("10.0.0.1") is True

    def test_remove_cleans_up_zero(self):
        """IP entry removed when count drops to zero."""
        mgr = WebSocketManager(max_per_ip=10, max_global=50)

        mgr.add("10.0.0.1")
        mgr.remove("10.0.0.1")

        assert mgr.total == 0
        assert "10.0.0.1" not in mgr._connections

    def test_total_across_ips(self):
        """Total counts all IPs."""
        mgr = WebSocketManager(max_per_ip=10, max_global=50)

        mgr.add("10.0.0.1")
        mgr.add("10.0.0.1")
        mgr.add("10.0.0.2")
        mgr.add("10.0.0.3")

        assert mgr.total == 4
