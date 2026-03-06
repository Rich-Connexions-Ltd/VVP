"""Tests for the Issuer TEL facade endpoint.

Sprint 80: TEL Publication to Witnesses.
"""
from unittest.mock import AsyncMock, patch, MagicMock

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient


@pytest.fixture
def mock_keri_client():
    """Mock the KERI Agent client singleton."""
    client = AsyncMock()
    with patch("app.api.tel.get_keri_client", return_value=client):
        yield client


@pytest.fixture
def client(mock_keri_client):
    """Create test client with mocked KERI Agent client."""
    from app.api.tel import router
    from fastapi import FastAPI

    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


class TestIssuerTelProxy:
    """Tests for GET /tels/credential/{credential_said}."""

    def test_proxy_returns_cesr_unchanged(self, client, mock_keri_client):
        """Proxy returns CESR bytes from KERI Agent unchanged."""
        cesr_bytes = b'{"v":"KERI10JSON","t":"iss","s":"0","d":"ETEST","i":"ECRED","ri":"EREG"}'
        mock_keri_client.get_credential_tel_cesr = AsyncMock(return_value=cesr_bytes)

        said = "E" + "A" * 43
        resp = client.get(f"/tels/credential/{said}")

        assert resp.status_code == 200
        assert resp.content == cesr_bytes

    def test_content_type_is_cesr(self, client, mock_keri_client):
        """Content-Type is application/cesr."""
        mock_keri_client.get_credential_tel_cesr = AsyncMock(return_value=b"cesr-data")

        said = "E" + "A" * 43
        resp = client.get(f"/tels/credential/{said}")

        assert resp.headers["content-type"] == "application/cesr"

    def test_cache_control_no_store(self, client, mock_keri_client):
        """Cache-Control: no-store header present."""
        mock_keri_client.get_credential_tel_cesr = AsyncMock(return_value=b"cesr-data")

        said = "E" + "A" * 43
        resp = client.get(f"/tels/credential/{said}")

        assert resp.headers["cache-control"] == "no-store"

    def test_keri_agent_unavailable_returns_503(self, client, mock_keri_client):
        """KERI Agent unavailable returns 503 with Retry-After header."""
        from app.keri_client import KeriAgentUnavailableError
        mock_keri_client.get_credential_tel_cesr = AsyncMock(
            side_effect=KeriAgentUnavailableError("Agent down")
        )

        said = "E" + "A" * 43
        resp = client.get(f"/tels/credential/{said}")

        assert resp.status_code == 503
        assert resp.headers.get("retry-after") == "30"

    def test_credential_not_found_returns_404(self, client, mock_keri_client):
        """Credential not found returns 404."""
        mock_keri_client.get_credential_tel_cesr = AsyncMock(return_value=None)

        said = "E" + "A" * 43
        resp = client.get(f"/tels/credential/{said}")

        assert resp.status_code == 404

    def test_invalid_said_returns_400(self, client, mock_keri_client):
        """Invalid SAID format returns 400 (validated before proxy call)."""
        resp = client.get("/tels/credential/invalid-said")
        assert resp.status_code == 400
        # Ensure the KERI Agent was NOT called
        mock_keri_client.get_credential_tel_cesr.assert_not_called()

    def test_cors_no_access_control_header(self, client, mock_keri_client):
        """Request with Origin header does NOT get Access-Control-Allow-Origin."""
        mock_keri_client.get_credential_tel_cesr = AsyncMock(return_value=b"cesr-data")

        said = "E" + "A" * 43
        resp = client.get(
            f"/tels/credential/{said}",
            headers={"Origin": "https://evil.com"},
        )

        assert "access-control-allow-origin" not in resp.headers
