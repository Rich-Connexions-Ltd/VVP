# Copyright (c) Rich Connexions Ltd. All rights reserved.
# Licensed under the MIT License. See LICENSE for details.
"""Tests for the SIP message parser and builder (app.sip).

Covers SIP INVITE parsing, malformed message handling, 302 redirect
building, error response building, and round-trip serialization.

References:
    - RFC 3261 §7  — SIP message format
    - RFC 3261 §8.2.6 — Response construction rules
    - app.sip.parser.parse_request
    - app.sip.builder.build_302_redirect, build_error_response
"""

from __future__ import annotations

import pytest

from app.sip.parser import parse_request, parse_response, SIPParseError
from app.sip.builder import build_302_redirect, build_error_response
from app.sip.models import SIPRequest, SIPResponse


# =========================================================================
# Sample SIP Messages
# =========================================================================

VALID_INVITE = (
    b"INVITE sip:alice@example.com SIP/2.0\r\n"
    b"Via: SIP/2.0/UDP client.example.com;branch=z9hG4bK776asdhds\r\n"
    b"From: \"Bob\" <sip:bob@example.com>;tag=1928301774\r\n"
    b"To: <sip:alice@example.com>\r\n"
    b"Call-ID: a84b4c76e66710@client.example.com\r\n"
    b"CSeq: 314159 INVITE\r\n"
    b"Contact: <sip:bob@client.example.com>\r\n"
    b"Content-Length: 0\r\n"
    b"\r\n"
)


class TestParseInvite:
    """Test parsing of valid SIP INVITE requests."""

    def test_parse_invite(self):
        """A well-formed SIP INVITE should parse correctly."""
        req = parse_request(VALID_INVITE)

        assert req.method == "INVITE"
        assert req.uri == "sip:alice@example.com"
        assert req.version == "SIP/2.0"
        assert req.call_id == "a84b4c76e66710@client.example.com"
        assert req.cseq == "314159 INVITE"
        assert "Bob" in req.from_header

    def test_parse_invite_headers(self):
        """All standard dialog headers should be present after parsing."""
        req = parse_request(VALID_INVITE)

        assert req.via is not None
        assert req.from_header is not None
        assert req.to_header is not None
        assert req.contact is not None

    def test_parse_invite_body_empty(self):
        """An INVITE with no SDP body should have an empty body string."""
        req = parse_request(VALID_INVITE)
        assert req.body == ""


class TestParseMalformed:
    """Test handling of malformed SIP messages."""

    def test_parse_malformed_incomplete(self):
        """An incomplete SIP message should raise SIPParseError."""
        with pytest.raises(SIPParseError):
            parse_request(b"INVITE")

    def test_parse_empty(self):
        """Empty bytes should raise SIPParseError."""
        with pytest.raises(SIPParseError):
            parse_request(b"")

    def test_parse_no_sip_version(self):
        """A request line without SIP/ version should raise SIPParseError."""
        data = (
            b"INVITE sip:alice@example.com HTTP/1.1\r\n"
            b"From: <sip:bob@example.com>\r\n"
            b"\r\n"
        )
        with pytest.raises(SIPParseError):
            parse_request(data)


class TestBuild302:
    """Test SIP 302 redirect response building."""

    def test_build_302(self):
        """A 302 redirect should have correct status, contact, and dialog headers."""
        req = parse_request(VALID_INVITE)
        resp = build_302_redirect(req, contact_uri="sip:alice@proxy.example.com")

        assert resp.status_code == 302
        assert resp.reason == "Moved Temporarily"
        assert resp.headers["Contact"] == "<sip:alice@proxy.example.com>"
        # Dialog headers must be copied from request
        assert resp.headers.get("Call-ID") == req.call_id
        assert resp.headers.get("CSeq") == req.cseq

    def test_build_302_extra_headers(self):
        """Extra headers (e.g. X-VVP-*) should be included in the response."""
        req = parse_request(VALID_INVITE)
        extra = {"X-VVP-Status": "VALID", "X-VVP-Brand-Name": "Acme Corp"}
        resp = build_302_redirect(req, contact_uri="sip:alice@proxy.example.com", extra_headers=extra)

        assert resp.headers["X-VVP-Status"] == "VALID"
        assert resp.headers["X-VVP-Brand-Name"] == "Acme Corp"


class TestBuildError:
    """Test SIP error response building."""

    def test_build_error_400(self):
        """A 400 error response should have correct status and reason."""
        req = parse_request(VALID_INVITE)
        resp = build_error_response(req, status_code=400, reason="Bad Request")

        assert resp.status_code == 400
        assert resp.reason == "Bad Request"
        assert resp.headers.get("Call-ID") == req.call_id

    def test_build_error_500(self):
        """A 500 error response should have the correct status code."""
        req = parse_request(VALID_INVITE)
        resp = build_error_response(req, status_code=500, reason="Server Internal Error")

        assert resp.status_code == 500
        assert resp.reason == "Server Internal Error"


class TestSIPRoundtrip:
    """Test serialization and re-parsing roundtrip."""

    def test_sip_roundtrip_request(self):
        """A parsed request should survive to_bytes → parse_request."""
        req = parse_request(VALID_INVITE)
        raw = req.to_bytes()
        req2 = parse_request(raw)

        assert req2.method == req.method
        assert req2.uri == req.uri
        assert req2.call_id == req.call_id
        assert req2.cseq == req.cseq

    def test_sip_roundtrip_response(self):
        """A built response should survive to_bytes → parse_response."""
        req = parse_request(VALID_INVITE)
        resp = build_302_redirect(req, contact_uri="sip:alice@proxy.example.com")
        raw = resp.to_bytes()
        resp2 = parse_response(raw)

        assert resp2.status_code == 302
        assert resp2.reason == "Moved Temporarily"
        assert resp2.headers.get("Call-ID") == req.call_id


# =========================================================================
# SIP Handler Tests
# =========================================================================

class TestHandleInvite:
    """Tests for SIP INVITE handler wiring (app.sip.handler)."""

    @pytest.mark.asyncio
    async def test_non_invite_returns_none(self):
        """Non-INVITE methods should be silently ignored."""
        from app.sip.handler import handle_invite

        req = SIPRequest(
            method="OPTIONS",
            uri="sip:alice@example.com",
            version="SIP/2.0",
            headers={"Via": "SIP/2.0/UDP test", "Call-ID": "test123", "CSeq": "1 OPTIONS"},
            body=b"",
        )
        result = await handle_invite(req, ("127.0.0.1", 5060))
        assert result is None

    @pytest.mark.asyncio
    async def test_invite_missing_identity_returns_400(self):
        """INVITE without Identity/P-VVP-Passport header should return 400."""
        from app.sip.handler import handle_invite

        req = SIPRequest(
            method="INVITE",
            uri="sip:alice@example.com",
            version="SIP/2.0",
            headers={
                "Via": "SIP/2.0/UDP test;branch=z9hG4bK123",
                "Call-ID": "test456",
                "CSeq": "1 INVITE",
                "From": "<sip:bob@example.com>;tag=abc",
                "To": "<sip:alice@example.com>",
            },
            body=b"",
        )
        result = await handle_invite(req, ("127.0.0.1", 5060))
        assert result is not None
        assert result.status_code == 400

    @pytest.mark.asyncio
    async def test_invite_accepts_p_vvp_passport_fallback(self):
        """INVITE with P-VVP-Passport (no Identity) should not return 400 for missing PASSporT."""
        from app.sip.handler import handle_invite

        req = SIPRequest(
            method="INVITE",
            uri="sip:alice@example.com",
            version="SIP/2.0",
            headers={
                "Via": "SIP/2.0/UDP test;branch=z9hG4bK789",
                "Call-ID": "test789",
                "CSeq": "1 INVITE",
                "From": "<sip:bob@example.com>;tag=xyz",
                "To": "<sip:alice@example.com>",
                "P-VVP-Passport": "eyJhbGciOiJFZERTQSJ9.test.sig",
                "P-VVP-Identity": "eyJwcHQiOiJ2dnAiLCJraWQiOiJodHRwOi8vZXhhbXBsZS5jb20iLCJldmQiOiJodHRwOi8vZXhhbXBsZS5jb20vZG9zc2llciJ9",
            },
            body=b"",
        )
        result = await handle_invite(req, ("127.0.0.1", 5060))
        # Should NOT return 400 for missing Identity — P-VVP-Passport is accepted.
        assert result is None or result.status_code != 400
