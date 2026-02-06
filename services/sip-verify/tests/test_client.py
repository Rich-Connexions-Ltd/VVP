"""Tests for Verifier API client.

Sprint 44: Tests for VerifierClient and VVP-Identity header construction.
"""

import base64
import json
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from app.verify.client import VerifierClient, VerifyResult, get_verifier_client


class TestBuildVVPIdentityHeader:
    """Tests for VVP-Identity header construction."""

    def test_includes_required_fields(self):
        """Header includes ppt, kid, evd, and iat."""
        client = VerifierClient(base_url="http://test.local")

        header = client._build_vvp_identity_header(
            kid="https://witness.example.com/oobi/EAbc/witness",
            evd="https://dossier.example.com/dossiers/SAbc",
            iat=1704067200,
        )

        # Decode and verify
        decoded = base64.urlsafe_b64decode(header + "==")
        data = json.loads(decoded)

        assert data["ppt"] == "vvp"
        assert data["kid"] == "https://witness.example.com/oobi/EAbc/witness"
        assert data["evd"] == "https://dossier.example.com/dossiers/SAbc"
        assert data["iat"] == 1704067200

    def test_includes_exp_when_provided(self):
        """Header includes exp when provided."""
        client = VerifierClient(base_url="http://test.local")

        header = client._build_vvp_identity_header(
            kid="https://witness.example.com/oobi/EAbc/witness",
            evd="https://dossier.example.com/dossiers/SAbc",
            iat=1704067200,
            exp=1704153600,
        )

        decoded = base64.urlsafe_b64decode(header + "==")
        data = json.loads(decoded)

        assert data["exp"] == 1704153600

    def test_excludes_exp_when_none(self):
        """Header excludes exp when not provided."""
        client = VerifierClient(base_url="http://test.local")

        header = client._build_vvp_identity_header(
            kid="https://witness.example.com/oobi/EAbc/witness",
            evd="https://dossier.example.com/dossiers/SAbc",
            iat=1704067200,
            exp=None,
        )

        decoded = base64.urlsafe_b64decode(header + "==")
        data = json.loads(decoded)

        assert "exp" not in data

    def test_is_base64url_encoded(self):
        """Header is valid base64url (no padding)."""
        client = VerifierClient(base_url="http://test.local")

        header = client._build_vvp_identity_header(
            kid="https://witness.example.com/oobi/EAbc/witness",
            evd="https://dossier.example.com/dossiers/SAbc",
            iat=1704067200,
        )

        # Should not have padding
        assert "=" not in header

        # Should be decodable with padding added
        decoded = base64.urlsafe_b64decode(header + "==")
        assert json.loads(decoded)["ppt"] == "vvp"


class TestParseResponse:
    """Tests for response parsing."""

    def test_parse_valid_response(self):
        """Parses successful verification response."""
        client = VerifierClient(base_url="http://test.local")

        data = {
            "overall_status": "VALID",
            "brand_name": "ACME Corporation",
            "brand_logo_url": "https://cdn.acme.com/logo.png",
            "request_id": "req-123",
            "claims": [],
            "errors": [],
        }

        result = client._parse_response(data)

        assert result.status == "VALID"
        assert result.brand_name == "ACME Corporation"
        assert result.brand_logo_url == "https://cdn.acme.com/logo.png"
        assert result.request_id == "req-123"
        assert result.error_code is None

    def test_parse_invalid_response(self):
        """Parses INVALID verification response with error."""
        client = VerifierClient(base_url="http://test.local")

        data = {
            "overall_status": "INVALID",
            "request_id": "req-456",
            "claims": [],
            "errors": [
                {"code": "SIGNATURE_INVALID", "message": "PASSporT signature invalid"}
            ],
        }

        result = client._parse_response(data)

        assert result.status == "INVALID"
        assert result.error_code == "SIGNATURE_INVALID"
        assert result.error_message == "PASSporT signature invalid"

    def test_parse_indeterminate_response(self):
        """Parses INDETERMINATE verification response."""
        client = VerifierClient(base_url="http://test.local")

        data = {
            "overall_status": "INDETERMINATE",
            "request_id": "req-789",
            "claims": [],
            "errors": [],
        }

        result = client._parse_response(data)

        assert result.status == "INDETERMINATE"
        assert result.error_code is None

    def test_parse_extracts_caller_id_from_claims(self):
        """Extracts caller ID from claims evidence."""
        client = VerifierClient(base_url="http://test.local")

        data = {
            "overall_status": "VALID",
            "claims": [
                {
                    "name": "orig_tn_authorized",
                    "evidence": ["orig_tn:+15551234567", "status:authorized"],
                }
            ],
            "errors": [],
        }

        result = client._parse_response(data)

        assert result.caller_id == "+15551234567"


class TestVerifyCallee:
    """Tests for verify_callee method."""

    @pytest.mark.asyncio
    async def test_verify_callee_includes_iat_in_header(self):
        """verify_callee sends VVP-Identity with iat."""
        client = VerifierClient(
            base_url="http://test.local",
            timeout=5.0,
            api_key="",
        )

        with patch("aiohttp.ClientSession") as mock_session_class:
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(
                return_value={
                    "overall_status": "VALID",
                    "claims": [],
                    "errors": [],
                }
            )

            mock_session = MagicMock()
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)
            mock_session.post = MagicMock()
            mock_session.post.return_value.__aenter__ = AsyncMock(
                return_value=mock_response
            )
            mock_session.post.return_value.__aexit__ = AsyncMock(return_value=None)
            mock_session_class.return_value = mock_session

            result = await client.verify_callee(
                passport_jwt="eyJ...",
                call_id="call-123",
                from_uri="sip:+15551234567@carrier.com",
                to_uri="sip:+14155551234@pbx.example.com",
                invite_time="2024-01-01T00:00:00Z",
                cseq=1,
                kid="https://witness.example.com/oobi/EAbc",
                evd="https://dossier.example.com/dossiers/SAbc",
                iat=1704067200,
            )

            # Verify the VVP-Identity header was included
            call_args = mock_session.post.call_args
            headers = call_args.kwargs.get("headers", {})
            assert "VVP-Identity" in headers

            # Decode and verify iat is present
            vvp_identity = headers["VVP-Identity"]
            decoded = base64.urlsafe_b64decode(vvp_identity + "==")
            data = json.loads(decoded)
            assert data["iat"] == 1704067200

            assert result.status == "VALID"
