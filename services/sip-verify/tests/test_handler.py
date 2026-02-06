"""Tests for SIP INVITE verification handler.

Sprint 44: Tests for handle_verify_invite function.
"""

import base64
import json
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from common.vvp.sip import SIPRequest

from app.verify.handler import handle_verify_invite
from app.verify.client import VerifyResult


def _encode_vvp_identity(kid: str, evd: str, iat: int = 1704067200) -> str:
    """Encode VVP-Identity header."""
    data = {"ppt": "vvp", "kid": kid, "evd": evd, "iat": iat}
    json_str = json.dumps(data)
    return base64.urlsafe_b64encode(json_str.encode()).decode().rstrip("=")


def _encode_passport(passport: str) -> str:
    """Encode PASSporT for Identity header."""
    return base64.urlsafe_b64encode(passport.encode()).decode().rstrip("=")


@pytest.fixture
def sample_request():
    """Create a sample SIP request with VVP headers."""
    passport = "eyJhbGciOiJFZERTQSJ9.eyJpYXQiOjE3MDQwNjcyMDB9.signature"
    encoded_passport = _encode_passport(passport)
    kid = "https://witness.example.com/oobi/EAbc/witness"
    evd = "https://dossier.example.com/dossiers/SAbc"

    return SIPRequest(
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
        identity_header=f"<{encoded_passport}>;info={kid};alg=EdDSA;ppt=vvp",
        p_vvp_identity=_encode_vvp_identity(kid, evd),
        p_vvp_passport=passport,
    )


@pytest.fixture
def mock_verify_result():
    """Create a mock verification result."""
    return VerifyResult(
        status="VALID",
        brand_name="ACME Corporation",
        brand_logo_url="https://cdn.acme.com/logo.png",
        caller_id="+15551234567",
        request_id="test-request-id",
    )


class TestHandleVerifyInvite:
    """Tests for handle_verify_invite function."""

    @pytest.mark.asyncio
    async def test_successful_verification(self, sample_request, mock_verify_result):
        """Successful verification returns 302 with VVP headers."""
        with patch("app.verify.handler.get_verifier_client") as mock_get_client:
            mock_client = MagicMock()
            mock_client.verify_callee = AsyncMock(return_value=mock_verify_result)
            mock_get_client.return_value = mock_client

            response = await handle_verify_invite(sample_request)

            assert response.status_code == 302
            assert response.vvp_status == "VALID"
            assert response.brand_name == "ACME Corporation"
            assert response.brand_logo_url == "https://cdn.acme.com/logo.png"

    @pytest.mark.asyncio
    async def test_missing_headers_returns_400(self):
        """Request without VVP headers returns 400 Bad Request (Sprint 44)."""
        request = SIPRequest(
            method="INVITE",
            request_uri="sip:+14155551234@pbx.example.com",
            sip_version="SIP/2.0",
            via=["SIP/2.0/UDP carrier.com:5060;branch=z9hG4bK123"],
            from_header="<sip:+15551234567@carrier.com>;tag=abc123",
            to_header="<sip:+14155551234@pbx.example.com>",
            call_id="xyz789@carrier.com",
            cseq="1 INVITE",
        )

        response = await handle_verify_invite(request)

        assert response.status_code == 400
        assert "Missing VVP verification headers" in (response.error_reason or "")

    @pytest.mark.asyncio
    async def test_invalid_identity_returns_400(self, sample_request):
        """Invalid Identity header returns 400."""
        sample_request.identity_header = "<invalid!!!>;info=bad"

        response = await handle_verify_invite(sample_request)

        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_invalid_vvp_identity_returns_400(self, sample_request):
        """Invalid P-VVP-Identity header returns 400."""
        sample_request.p_vvp_identity = "invalid!!!"

        response = await handle_verify_invite(sample_request)

        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_verification_failure_returns_302_with_invalid(
        self, sample_request
    ):
        """Verification failure returns 302 with INVALID status."""
        error_result = VerifyResult(
            status="INVALID",
            error_code="SIGNATURE_INVALID",
            error_message="PASSporT signature invalid",
        )

        with patch("app.verify.handler.get_verifier_client") as mock_get_client:
            mock_client = MagicMock()
            mock_client.verify_callee = AsyncMock(return_value=error_result)
            mock_get_client.return_value = mock_client

            response = await handle_verify_invite(sample_request)

            assert response.status_code == 302
            assert response.vvp_status == "INVALID"
            assert response.error_code == "SIGNATURE_INVALID"

    @pytest.mark.asyncio
    async def test_verifier_timeout_returns_indeterminate(self, sample_request):
        """Verifier timeout returns 302 with INDETERMINATE."""
        timeout_result = VerifyResult(
            status="INDETERMINATE",
            error_code="VERIFIER_TIMEOUT",
            error_message="Verifier request timed out",
        )

        with patch("app.verify.handler.get_verifier_client") as mock_get_client:
            mock_client = MagicMock()
            mock_client.verify_callee = AsyncMock(return_value=timeout_result)
            mock_get_client.return_value = mock_client

            response = await handle_verify_invite(sample_request)

            assert response.status_code == 302
            assert response.vvp_status == "INDETERMINATE"

    @pytest.mark.asyncio
    async def test_response_copies_transaction_headers(
        self, sample_request, mock_verify_result
    ):
        """302 response copies transaction headers from request."""
        with patch("app.verify.handler.get_verifier_client") as mock_get_client:
            mock_client = MagicMock()
            mock_client.verify_callee = AsyncMock(return_value=mock_verify_result)
            mock_get_client.return_value = mock_client

            response = await handle_verify_invite(sample_request)

            assert response.via == sample_request.via
            assert response.from_header == sample_request.from_header
            assert response.call_id == sample_request.call_id
            assert response.cseq == sample_request.cseq
