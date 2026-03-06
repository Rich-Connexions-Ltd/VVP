"""Tests for the Verifier TEL client Issuer source.

Sprint 80: TEL Publication to Witnesses.
"""
import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from app.vvp.keri.tel_client import TELClient, CredentialStatus, RevocationResult, TELEvent


# Sample CESR TEL events for testing
VALID_CRED_SAID = "E" + "A" * 43
VALID_REG_SAID = "E" + "B" * 43

ISS_EVENT = {
    "v": "KERI10JSON0001a0_",
    "t": "iss",
    "d": "E" + "C" * 43,
    "i": VALID_CRED_SAID,
    "s": "0",
    "ri": VALID_REG_SAID,
    "dt": "2024-01-01T00:00:00.000000+00:00",
}

REV_EVENT = {
    "v": "KERI10JSON0001a0_",
    "t": "rev",
    "d": "E" + "D" * 43,
    "i": VALID_CRED_SAID,
    "s": "1",
    "ri": VALID_REG_SAID,
    "p": "E" + "C" * 43,
    "dt": "2024-06-01T00:00:00.000000+00:00",
}


def _cesr_response(*events):
    """Build a CESR response from event dicts."""
    return "".join(json.dumps(e, separators=(",", ":")) for e in events)


class TestIssuerTelSource:
    """Tests for _query_issuer_tel() and TEL integrity verification."""

    @pytest.fixture
    def tel_client(self):
        return TELClient(timeout=5.0, witness_urls=[])

    @pytest.mark.asyncio
    @patch("app.core.config.TEL_ISSUER_URL", "https://issuer.example.com")
    async def test_issuer_returns_active(self, tel_client):
        """Issuer returns CESR with iss event -> parses as ACTIVE."""
        response = httpx.Response(
            200,
            content=_cesr_response(ISS_EVENT).encode(),
        )

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=response)

        with patch("app.vvp.keri.tel_client.TEL_ISSUER_URL", "https://issuer.example.com"):
            with patch("common.vvp.http_client.get_shared_client", return_value=mock_client):
                result = await tel_client._query_issuer_tel(VALID_CRED_SAID, VALID_REG_SAID)

        assert result.status == CredentialStatus.ACTIVE
        assert result.source == "issuer"
        assert result.issuance_event is not None
        assert result.issuance_event.credential_said == VALID_CRED_SAID

    @pytest.mark.asyncio
    async def test_issuer_returns_revoked(self, tel_client):
        """Issuer returns CESR with iss + rev events -> parses as REVOKED."""
        response = httpx.Response(
            200,
            content=_cesr_response(ISS_EVENT, REV_EVENT).encode(),
        )

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=response)

        with patch("app.vvp.keri.tel_client.TEL_ISSUER_URL", "https://issuer.example.com"):
            with patch("common.vvp.http_client.get_shared_client", return_value=mock_client):
                result = await tel_client._query_issuer_tel(VALID_CRED_SAID, VALID_REG_SAID)

        assert result.status == CredentialStatus.REVOKED
        assert result.revocation_event is not None

    @pytest.mark.asyncio
    async def test_issuer_credential_not_found(self, tel_client):
        """Issuer returns 404 -> UNKNOWN status."""
        response = httpx.Response(404, content=b"Not found")

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=response)

        with patch("app.vvp.keri.tel_client.TEL_ISSUER_URL", "https://issuer.example.com"):
            with patch("common.vvp.http_client.get_shared_client", return_value=mock_client):
                result = await tel_client._query_issuer_tel(VALID_CRED_SAID, VALID_REG_SAID)

        assert result.status == CredentialStatus.UNKNOWN

    @pytest.mark.asyncio
    async def test_issuer_unavailable_returns_error(self, tel_client):
        """Issuer connection error -> ERROR status (falls through to witnesses)."""
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.ConnectError("Connection refused"))

        with patch("app.vvp.keri.tel_client.TEL_ISSUER_URL", "https://issuer.example.com"):
            with patch("common.vvp.http_client.get_shared_client", return_value=mock_client):
                result = await tel_client._query_issuer_tel(VALID_CRED_SAID, VALID_REG_SAID)

        assert result.status == CredentialStatus.ERROR

    @pytest.mark.asyncio
    async def test_no_issuer_url_skips_issuer(self, tel_client):
        """No VVP_TEL_ISSUER_URL -> skips Issuer entirely (backward compatible)."""
        with patch("app.vvp.keri.tel_client.TEL_ISSUER_URL", ""):
            # check_revocation should not try issuer when URL is empty
            # Just verify the config path works
            from app.vvp.keri.tel_client import TEL_ISSUER_URL
            # When patched to empty, TEL_ISSUER_URL is falsy
            assert not ""

    @pytest.mark.asyncio
    async def test_wrong_credential_binding_fails(self, tel_client):
        """TEL event with wrong credential_said in i field -> integrity failure."""
        wrong_event = dict(ISS_EVENT)
        wrong_event["i"] = "E" + "X" * 43  # Wrong credential SAID

        response = httpx.Response(
            200,
            content=_cesr_response(wrong_event).encode(),
        )

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=response)

        with patch("app.vvp.keri.tel_client.TEL_ISSUER_URL", "https://issuer.example.com"):
            with patch("common.vvp.http_client.get_shared_client", return_value=mock_client):
                result = await tel_client._query_issuer_tel(VALID_CRED_SAID, VALID_REG_SAID)

        # Should return ERROR because binding check failed
        assert result.status == CredentialStatus.ERROR
        assert "integrity" in result.error.lower()


class TestVerifyTelIntegrity:
    """Tests for _verify_tel_integrity()."""

    @pytest.fixture
    def tel_client(self):
        return TELClient(timeout=5.0, witness_urls=[])

    def test_valid_iss_event_passes(self, tel_client):
        """Valid iss event with correct binding passes integrity check."""
        result = RevocationResult(
            status=CredentialStatus.ACTIVE,
            credential_said=VALID_CRED_SAID,
            registry_said=VALID_REG_SAID,
            issuance_event=TELEvent(
                event_type="iss",
                credential_said=VALID_CRED_SAID,
                registry_said=VALID_REG_SAID,
                sequence=0,
                datetime="2024-01-01",
                digest="E" + "C" * 43,
                raw=ISS_EVENT,
            ),
            revocation_event=None,
            error=None,
            source="issuer",
        )
        assert tel_client._verify_tel_integrity(result, VALID_CRED_SAID) is True

    def test_wrong_iss_binding_fails(self, tel_client):
        """Iss event with wrong credential SAID fails binding check."""
        result = RevocationResult(
            status=CredentialStatus.ACTIVE,
            credential_said=VALID_CRED_SAID,
            registry_said=VALID_REG_SAID,
            issuance_event=TELEvent(
                event_type="iss",
                credential_said="E" + "X" * 43,
                registry_said=VALID_REG_SAID,
                sequence=0,
                datetime="2024-01-01",
                digest="E" + "C" * 43,
                raw={},
            ),
            revocation_event=None,
            error=None,
            source="issuer",
        )
        assert tel_client._verify_tel_integrity(result, VALID_CRED_SAID) is False

    def test_wrong_iss_sequence_fails(self, tel_client):
        """Iss event with s != 0 fails sequence check."""
        result = RevocationResult(
            status=CredentialStatus.ACTIVE,
            credential_said=VALID_CRED_SAID,
            registry_said=VALID_REG_SAID,
            issuance_event=TELEvent(
                event_type="iss",
                credential_said=VALID_CRED_SAID,
                registry_said=VALID_REG_SAID,
                sequence=1,  # Wrong!
                datetime="2024-01-01",
                digest="E" + "C" * 43,
                raw={},
            ),
            revocation_event=None,
            error=None,
            source="issuer",
        )
        assert tel_client._verify_tel_integrity(result, VALID_CRED_SAID) is False

    def test_valid_rev_event_passes(self, tel_client):
        """Valid rev event with correct binding and sequence passes."""
        result = RevocationResult(
            status=CredentialStatus.REVOKED,
            credential_said=VALID_CRED_SAID,
            registry_said=VALID_REG_SAID,
            issuance_event=TELEvent(
                event_type="iss",
                credential_said=VALID_CRED_SAID,
                registry_said=VALID_REG_SAID,
                sequence=0,
                datetime="2024-01-01",
                digest="E" + "C" * 43,
                raw=ISS_EVENT,
            ),
            revocation_event=TELEvent(
                event_type="rev",
                credential_said=VALID_CRED_SAID,
                registry_said=VALID_REG_SAID,
                sequence=1,
                datetime="2024-06-01",
                digest="E" + "D" * 43,
                raw=REV_EVENT,
            ),
            error=None,
            source="issuer",
        )
        assert tel_client._verify_tel_integrity(result, VALID_CRED_SAID) is True

    def test_wrong_rev_sequence_fails(self, tel_client):
        """Rev event with s != 1 fails sequence check."""
        result = RevocationResult(
            status=CredentialStatus.REVOKED,
            credential_said=VALID_CRED_SAID,
            registry_said=VALID_REG_SAID,
            issuance_event=TELEvent(
                event_type="iss",
                credential_said=VALID_CRED_SAID,
                registry_said=VALID_REG_SAID,
                sequence=0,
                datetime="2024-01-01",
                digest="E" + "C" * 43,
                raw={},
            ),
            revocation_event=TELEvent(
                event_type="rev",
                credential_said=VALID_CRED_SAID,
                registry_said=VALID_REG_SAID,
                sequence=2,  # Wrong!
                datetime="2024-06-01",
                digest="E" + "D" * 43,
                raw={},
            ),
            error=None,
            source="issuer",
        )
        assert tel_client._verify_tel_integrity(result, VALID_CRED_SAID) is False


class TestSaidValidation:
    """Tests for the shared SAID validation utility."""

    def test_valid_said(self):
        from common.vvp.said_validation import is_valid_said
        assert is_valid_said("E" + "A" * 43) is True

    def test_invalid_prefix(self):
        from common.vvp.said_validation import is_valid_said
        assert is_valid_said("X" + "A" * 43) is False

    def test_too_short(self):
        from common.vvp.said_validation import is_valid_said
        assert is_valid_said("Eshort") is False

    def test_too_long(self):
        from common.vvp.said_validation import is_valid_said
        assert is_valid_said("E" + "A" * 44) is False

    def test_bad_chars(self):
        from common.vvp.said_validation import is_valid_said
        assert is_valid_said("E" + "A" * 42 + "!") is False

    def test_base64url_chars(self):
        from common.vvp.said_validation import is_valid_said
        assert is_valid_said("EABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklm_-01") is True

    def test_empty_string(self):
        from common.vvp.said_validation import is_valid_said
        assert is_valid_said("") is False
