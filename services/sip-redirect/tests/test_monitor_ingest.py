"""Tests for Sprint 48: Event ingestion endpoint.

Tests cover:
- POST /api/events/ingest with valid event data
- Missing required fields → 400
- Optional fields filled with defaults
- Event appears in buffer after ingest
- response_vvp_headers populated and retrievable
- Non-loopback peer rejection → 403
"""

import json
from unittest.mock import MagicMock

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from app.monitor.buffer import SIPEventBuffer, get_event_buffer
from app.monitor.server import create_web_app, handle_event_ingest


def _make_ingest_payload(**overrides):
    """Create valid ingest payload."""
    defaults = {
        "service": "VERIFICATION",
        "method": "INVITE",
        "request_uri": "sip:1006@pbx.rcnx.io",
        "call_id": "verify-call-456",
        "response_code": 302,
        "source_addr": "127.0.0.1:5071",
        "from_tn": "1001",
        "to_tn": "1006",
        "headers": {"Via": "SIP/2.0/UDP 10.0.0.1", "Identity": "jwt;info=<url>"},
        "vvp_headers": {"Identity": "jwt;info=<url>", "P-VVP-Identity": "base64data"},
        "vvp_status": "VALID",
        "response_vvp_headers": {
            "X-VVP-Status": "VALID",
            "X-VVP-Brand-Name": "Test Corp",
            "X-VVP-Brand-Logo": "https://example.com/logo.png",
        },
        "redirect_uri": "sip:1006@10.0.0.2",
    }
    defaults.update(overrides)
    return defaults


@pytest.fixture
async def client():
    """Create aiohttp test client."""
    app = create_web_app()
    async with TestClient(TestServer(app)) as client:
        yield client


class TestEventIngest:
    """Test POST /api/events/ingest endpoint."""

    async def test_valid_ingest(self, client):
        """Valid event data returns 200 with event_id."""
        payload = _make_ingest_payload()
        resp = await client.post("/api/events/ingest", json=payload)

        assert resp.status == 200
        data = await resp.json()
        assert data["ok"] is True
        assert "event_id" in data
        assert data["event_id"] >= 1

    async def test_event_appears_in_buffer(self, client):
        """Ingested event is retrievable from the buffer."""
        payload = _make_ingest_payload(
            service="VERIFICATION",
            vvp_status="VALID",
            response_vvp_headers={"X-VVP-Status": "VALID", "X-VVP-Brand-Name": "Acme"},
        )
        resp = await client.post("/api/events/ingest", json=payload)
        assert resp.status == 200

        buffer = get_event_buffer()
        events = await buffer.get_all()
        assert len(events) >= 1

        last = events[0]
        assert last["service"] == "VERIFICATION"
        assert last["response_vvp_headers"]["X-VVP-Brand-Name"] == "Acme"

    async def test_missing_required_fields(self, client):
        """Missing required fields returns 400."""
        payload = {
            "request_uri": "sip:1006@pbx",
            "call_id": "test-123",
            "response_code": 302,
        }
        resp = await client.post("/api/events/ingest", json=payload)

        assert resp.status == 400
        data = await resp.json()
        assert "Missing required fields" in data["error"]
        assert "method" in data["error"]
        assert "service" in data["error"]

    async def test_optional_fields_defaulted(self, client):
        """Optional fields get defaults when not provided."""
        payload = {
            "service": "VERIFICATION",
            "method": "INVITE",
            "request_uri": "sip:1006@pbx",
            "call_id": "test-minimal",
            "response_code": 302,
        }
        resp = await client.post("/api/events/ingest", json=payload)
        assert resp.status == 200

        buffer = get_event_buffer()
        events = await buffer.get_all()
        event = next(e for e in events if e["call_id"] == "test-minimal")

        assert event["source_addr"] == "unknown"
        assert event["from_tn"] is None
        assert event["to_tn"] is None
        assert event["headers"] == {}
        assert event["vvp_headers"] == {}
        assert event["vvp_status"] == "INDETERMINATE"
        assert event["response_vvp_headers"] == {}
        assert event["error"] is None

    async def test_invalid_json(self, client):
        """Non-JSON body returns 400."""
        resp = await client.post(
            "/api/events/ingest",
            data="not json",
            headers={"Content-Type": "application/json"},
        )

        assert resp.status == 400
        data = await resp.json()
        assert "Invalid JSON" in data["error"]

    async def test_response_vvp_headers_populated(self, client):
        """response_vvp_headers are stored and retrievable."""
        response_headers = {
            "X-VVP-Status": "VALID",
            "X-VVP-Brand-Name": "Test Corp",
            "X-VVP-Brand-Logo": "https://example.com/logo.png",
            "X-VVP-Caller-ID": "+15551234567",
        }
        payload = _make_ingest_payload(response_vvp_headers=response_headers)
        resp = await client.post("/api/events/ingest", json=payload)
        assert resp.status == 200

        event_id = (await resp.json())["event_id"]

        buffer = get_event_buffer()
        events = await buffer.get_since(event_id - 1)
        event = next(e for e in events if e["id"] == event_id)

        assert event["response_vvp_headers"] == response_headers

    async def test_non_loopback_rejected(self):
        """Non-loopback peer IP returns 403."""
        # Create a mock aiohttp request with non-loopback peername
        mock_transport = MagicMock()
        mock_transport.get_extra_info.return_value = ("10.0.0.5", 12345)

        mock_request = MagicMock()
        mock_request.transport = mock_transport

        resp = await handle_event_ingest(mock_request)
        assert resp.status == 403
        body = json.loads(resp.body)
        assert body["error"] == "Forbidden"
