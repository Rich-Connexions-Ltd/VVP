"""Tests for Sprint 48: Verification handler event capture.

Tests cover:
- _capture_event extracts correct headers from request/response
- HTTP POST is scheduled as background task (fire-and-forget)
- Failure handling (monitor unreachable)
- Event capture disabled when VVP_MONITOR_ENABLED=false
"""

import asyncio
import json
import base64
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from common.vvp.sip import SIPRequest, SIPResponse

from app.verify.handler import _capture_event


def _make_request(**overrides):
    """Create a sample SIP request."""
    defaults = dict(
        method="INVITE",
        request_uri="sip:+14155551234@pbx.example.com",
        sip_version="SIP/2.0",
        via=["SIP/2.0/UDP carrier.com:5060;branch=z9hG4bK123"],
        from_header="<sip:+15551234567@carrier.com>;tag=abc123",
        to_header="<sip:+14155551234@pbx.example.com>",
        call_id="xyz789@carrier.com",
        cseq="1 INVITE",
        from_tn="+15551234567",
        to_tn="+14155551234",
        headers={
            "Via": "SIP/2.0/UDP carrier.com:5060",
            "Identity": "jwt.token;info=<url>;alg=EdDSA",
            "P-VVP-Identity": "base64data",
            "P-VVP-Passport": "jwt.passport",
        },
        source_addr="10.0.0.1:5060",
    )
    defaults.update(overrides)
    return SIPRequest(**defaults)


def _make_response(**overrides):
    """Create a sample SIP response."""
    defaults = dict(
        status_code=302,
        reason_phrase="Moved Temporarily",
        vvp_identity="base64data",
        vvp_passport="jwt.passport",
        vvp_status="VALID",
        brand_name="Test Corp",
        brand_logo_url="https://example.com/logo.png",
        caller_id="+15551234567",
        contact="<sip:+14155551234@pbx.example.com>",
    )
    defaults.update(overrides)
    return SIPResponse(**defaults)


class TestCaptureEvent:
    """Test _capture_event function."""

    @patch("app.verify.handler.VVP_MONITOR_ENABLED", True)
    @patch("app.verify.handler._get_monitor_session")
    async def test_extracts_request_vvp_headers(self, mock_get_session):
        """Request VVP headers are extracted correctly."""
        mock_resp = AsyncMock()
        mock_resp.status_code = 200

        mock_session = AsyncMock()
        mock_session.post.return_value = mock_resp
        mock_get_session.return_value = mock_session

        request = _make_request()
        response = _make_response()

        await _capture_event(request, response, 302, "VALID")
        # Let background task run
        await asyncio.sleep(0)

        mock_session.post.assert_called_once()
        call_kwargs = mock_session.post.call_args
        posted_data = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json")

        assert posted_data["service"] == "VERIFICATION"
        assert posted_data["vvp_headers"]["Identity"] == "jwt.token;info=<url>;alg=EdDSA"
        assert posted_data["vvp_headers"]["P-VVP-Identity"] == "base64data"

    @patch("app.verify.handler.VVP_MONITOR_ENABLED", True)
    @patch("app.verify.handler._get_monitor_session")
    async def test_extracts_response_vvp_headers(self, mock_get_session):
        """Response VVP headers are extracted from SIPResponse."""
        mock_resp = AsyncMock()
        mock_resp.status_code = 200

        mock_session = AsyncMock()
        mock_session.post.return_value = mock_resp
        mock_get_session.return_value = mock_session

        request = _make_request()
        response = _make_response(
            vvp_status="VALID",
            brand_name="Acme Inc",
            brand_logo_url="https://example.com/acme.png",
            caller_id="+15551234567",
        )

        await _capture_event(request, response, 302, "VALID")
        await asyncio.sleep(0)

        posted_data = mock_session.post.call_args.kwargs.get("json") or mock_session.post.call_args[1].get("json")
        rvh = posted_data["response_vvp_headers"]

        assert rvh["X-VVP-Status"] == "VALID"
        assert rvh["X-VVP-Brand-Name"] == "Acme Inc"
        assert rvh["X-VVP-Brand-Logo"] == "https://example.com/acme.png"
        assert rvh["X-VVP-Caller-ID"] == "+15551234567"

    @patch("app.verify.handler.VVP_MONITOR_ENABLED", True)
    @patch("app.verify.handler._get_monitor_session")
    async def test_monitor_failure_silent(self, mock_get_session):
        """Monitor HTTP failure does not propagate (fire-and-forget)."""
        mock_session = AsyncMock()
        mock_session.post.side_effect = Exception("Connection refused")
        mock_get_session.return_value = mock_session

        request = _make_request()
        response = _make_response()

        # Should not raise — error is caught inside background task
        await _capture_event(request, response, 302, "VALID")
        await asyncio.sleep(0)

    @patch("app.verify.handler.VVP_MONITOR_ENABLED", False)
    async def test_disabled_skips_capture(self):
        """No HTTP call when monitor is disabled."""
        request = _make_request()
        response = _make_response()

        # Should return immediately without scheduling a task
        await _capture_event(request, response, 302, "VALID")

    @patch("app.verify.handler.VVP_MONITOR_ENABLED", True)
    @patch("app.verify.handler._get_monitor_session")
    async def test_no_response_empty_response_headers(self, mock_get_session):
        """When response is None, response_vvp_headers is empty."""
        mock_resp = AsyncMock()
        mock_resp.status_code = 200

        mock_session = AsyncMock()
        mock_session.post.return_value = mock_resp
        mock_get_session.return_value = mock_session

        request = _make_request()

        await _capture_event(request, None, 400, "INDETERMINATE", error="Bad request")
        await asyncio.sleep(0)

        posted_data = mock_session.post.call_args.kwargs.get("json") or mock_session.post.call_args[1].get("json")
        assert posted_data["response_vvp_headers"] == {}
        assert posted_data["error"] == "Bad request"
