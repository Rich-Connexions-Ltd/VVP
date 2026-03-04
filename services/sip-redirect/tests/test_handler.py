"""Tests for handle_invite — the SIP INVITE processing entry point.

Sprint 77: Added create_vvp_from_tn combined endpoint path. These tests
exercise the three primary response paths through handle_invite:
  - 302 success (TN mapped, VVP headers returned)
  - 404 TN not found (issuer returns 404)
  - 500 server error (issuer returns non-404 failure)
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from app.redirect.client import VVPCreateResult
from app.redirect.handler import handle_invite
from app.sip.models import SIPRequest


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def invite_request():
    """Minimal valid SIP INVITE request."""
    return SIPRequest(
        method="INVITE",
        request_uri="sip:+442071234567@carrier.example.com",
        sip_version="SIP/2.0",
        via=["SIP/2.0/UDP 192.168.1.100:5060;branch=z9hG4bK-test"],
        from_header="<sip:+441923311000@enterprise.example.com>;tag=abc123",
        to_header="<sip:+442071234567@carrier.example.com>",
        call_id="test-call-id@enterprise.example.com",
        cseq="1 INVITE",
        from_tn="+441923311000",
        to_tn="+442071234567",
        vvp_api_key="test-api-key-12345678",
    )


@pytest.fixture
def mock_client():
    """Mock IssuerClient with create_vvp_from_tn async method."""
    client = MagicMock()
    client.create_vvp_from_tn = AsyncMock()
    return client


# ---------------------------------------------------------------------------
# Success path: 302
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestHandleInviteSuccess:
    """handle_invite returns 302 when VVP headers are created successfully."""

    async def test_302_redirect_on_success(self, invite_request, mock_client):
        """Success path: create_vvp_from_tn returns success → 302."""
        mock_client.create_vvp_from_tn.return_value = VVPCreateResult(
            success=True,
            identity_header="eyJhbGciOiJFZERTQSIsInR5cCI6InBhc3Nwb3J0In0.test.sig",
            vvp_identity="vvp-identity-header-value",
            vvp_passport="vvp-passport-jwt-value",
        )

        with patch("app.redirect.handler.get_issuer_client", new_callable=AsyncMock, return_value=mock_client):
            response = await handle_invite(invite_request)

        assert response.status_code == 302

    async def test_302_response_contains_vvp_identity(self, invite_request, mock_client):
        """Success path: 302 response carries VVP identity header."""
        mock_client.create_vvp_from_tn.return_value = VVPCreateResult(
            success=True,
            identity_header="test-identity",
            vvp_identity="vvp-identity-value",
            vvp_passport="vvp-passport-value",
        )

        with patch("app.redirect.handler.get_issuer_client", new_callable=AsyncMock, return_value=mock_client):
            response = await handle_invite(invite_request)

        assert response.status_code == 302
        assert response.vvp_identity == "vvp-identity-value"

    async def test_create_vvp_called_with_correct_args(self, invite_request, mock_client):
        """Success path: create_vvp_from_tn is called with the request TNs and call_id."""
        mock_client.create_vvp_from_tn.return_value = VVPCreateResult(
            success=True,
            vvp_identity="vvp-identity",
            vvp_passport="vvp-passport",
        )

        with patch("app.redirect.handler.get_issuer_client", new_callable=AsyncMock, return_value=mock_client):
            await handle_invite(invite_request)

        mock_client.create_vvp_from_tn.assert_called_once()
        call_kwargs = mock_client.create_vvp_from_tn.call_args
        assert call_kwargs.kwargs["orig_tn"] == "+441923311000"
        assert call_kwargs.kwargs["dest_tn"] == "+442071234567"
        assert call_kwargs.kwargs["api_key"] == "test-api-key-12345678"
        assert call_kwargs.kwargs["call_id"] == "test-call-id@enterprise.example.com"


# ---------------------------------------------------------------------------
# Client error path: 404 TN not found
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestHandleInviteTNNotFound:
    """handle_invite returns 404 when issuer reports TN not found."""

    async def test_404_when_tn_not_found(self, invite_request, mock_client):
        """TN not found: create_vvp_from_tn returns http_status=404 → 404 SIP response."""
        mock_client.create_vvp_from_tn.return_value = VVPCreateResult(
            success=False,
            error="No mapping for +441923311000",
            http_status=404,
        )

        with patch("app.redirect.handler.get_issuer_client", new_callable=AsyncMock, return_value=mock_client):
            response = await handle_invite(invite_request)

        assert response.status_code == 404

    async def test_404_response_code_not_403(self, invite_request, mock_client):
        """TN not found: response is 404 (not 403 or 500)."""
        mock_client.create_vvp_from_tn.return_value = VVPCreateResult(
            success=False,
            error="TN +441923311000 has no dossier mapping",
            http_status=404,
        )

        with patch("app.redirect.handler.get_issuer_client", new_callable=AsyncMock, return_value=mock_client):
            response = await handle_invite(invite_request)

        # 404 SIP response — not a server error
        assert response.status_code == 404


# ---------------------------------------------------------------------------
# Server error path: 500
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestHandleInviteServerError:
    """handle_invite returns 500 when issuer returns a non-404 failure."""

    async def test_500_on_issuer_server_error(self, invite_request, mock_client):
        """Issuer returns 500: handle_invite returns 500 SIP response."""
        mock_client.create_vvp_from_tn.return_value = VVPCreateResult(
            success=False,
            error="Internal issuer error",
            http_status=500,
        )

        with patch("app.redirect.handler.get_issuer_client", new_callable=AsyncMock, return_value=mock_client):
            response = await handle_invite(invite_request)

        assert response.status_code == 500

    async def test_500_on_issuer_403(self, invite_request, mock_client):
        """Issuer returns 403 (bad API key): handle_invite returns 500 SIP response."""
        mock_client.create_vvp_from_tn.return_value = VVPCreateResult(
            success=False,
            error="Unauthorized",
            http_status=403,
        )

        with patch("app.redirect.handler.get_issuer_client", new_callable=AsyncMock, return_value=mock_client):
            response = await handle_invite(invite_request)

        # Non-404 failures → 500 (not 403, which would expose auth details)
        assert response.status_code == 500

    async def test_500_on_exception(self, invite_request, mock_client):
        """Exception in create_vvp_from_tn: handle_invite returns 500 SIP response."""
        mock_client.create_vvp_from_tn.side_effect = RuntimeError("Network timeout")

        with patch("app.redirect.handler.get_issuer_client", new_callable=AsyncMock, return_value=mock_client):
            response = await handle_invite(invite_request)

        assert response.status_code == 500


# ---------------------------------------------------------------------------
# Pre-condition checks (no API key, wrong method)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestHandleInvitePreConditions:
    """handle_invite validates pre-conditions before calling the issuer."""

    async def test_401_when_no_api_key(self):
        """Missing X-VVP-API-Key: handle_invite returns 401."""
        request = SIPRequest(
            method="INVITE",
            request_uri="sip:+442071234567@carrier.example.com",
            sip_version="SIP/2.0",
            via=["SIP/2.0/UDP 192.168.1.100:5060;branch=z9hG4bK-test"],
            from_header="<sip:+441923311000@enterprise.example.com>;tag=abc",
            to_header="<sip:+442071234567@carrier.example.com>",
            call_id="no-key-test@enterprise.com",
            cseq="1 INVITE",
            from_tn="+441923311000",
            to_tn="+442071234567",
        )

        response = await handle_invite(request)
        assert response.status_code == 401

    async def test_403_when_non_invite_method(self):
        """Non-INVITE method: handle_invite returns 403."""
        request = SIPRequest(
            method="REGISTER",
            request_uri="sip:pbx.example.com",
            sip_version="SIP/2.0",
            via=["SIP/2.0/UDP 192.168.1.100:5060;branch=z9hG4bK-test"],
            from_header="<sip:user@enterprise.example.com>;tag=abc",
            to_header="<sip:pbx.example.com>",
            call_id="register-test@enterprise.com",
            cseq="1 REGISTER",
            vvp_api_key="test-api-key",
        )

        response = await handle_invite(request)
        assert response.status_code == 403
