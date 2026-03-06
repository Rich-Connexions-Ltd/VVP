"""Tests for the KERI Agent TEL query endpoint.

Sprint 80: TEL Publication to Witnesses.
"""
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def mock_credential_issuer():
    """Mock the credential issuer singleton."""
    issuer = AsyncMock()
    with patch("app.api.tel.get_credential_issuer", return_value=issuer):
        yield issuer


@pytest.fixture
def mock_registry_manager():
    """Mock the registry manager singleton."""
    mgr = AsyncMock()
    mgr.regery = MagicMock()
    mgr.regery.reger = MagicMock()
    with patch("app.api.tel.get_registry_manager", return_value=mgr):
        yield mgr


@pytest.fixture
def client(mock_credential_issuer, mock_registry_manager):
    """Create test client with mocked dependencies."""
    # Import after mocks are in place
    from app.api.tel import router
    from fastapi import FastAPI

    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


class TestGetCredentialTel:
    """Tests for GET /tels/credential/{credential_said}."""

    def test_valid_said_returns_cesr(self, client, mock_registry_manager):
        """Query credential TEL for issued credential returns CESR with iss event."""
        iss_bytes = b'{"v":"KERI10JSON0001a0_","t":"iss","d":"ESAID","i":"ECRED","s":"0","ri":"EREG","dt":"2024-01-01T00:00:00.000000+00:00"}'
        reger = mock_registry_manager.regery.reger
        reger.cloneTvtAt = MagicMock(side_effect=lambda said, sn: iss_bytes if sn == 0 else None)

        said = "E" + "A" * 43
        resp = client.get(f"/tels/credential/{said}")

        assert resp.status_code == 200
        assert resp.headers["content-type"] == "application/cesr"
        assert resp.headers["cache-control"] == "no-store"
        assert resp.content == iss_bytes

    def test_revoked_credential_returns_iss_plus_rev(self, client, mock_registry_manager):
        """Query credential TEL for revoked credential returns iss + rev events."""
        iss_bytes = b'{"v":"KERI10JSON","t":"iss","s":"0"}'
        rev_bytes = b'{"v":"KERI10JSON","t":"rev","s":"1"}'
        reger = mock_registry_manager.regery.reger
        reger.cloneTvtAt = MagicMock(side_effect=lambda said, sn: iss_bytes if sn == 0 else rev_bytes)

        said = "E" + "A" * 43
        resp = client.get(f"/tels/credential/{said}")

        assert resp.status_code == 200
        assert resp.content == iss_bytes + rev_bytes

    def test_unknown_said_returns_404(self, client, mock_registry_manager):
        """Query for unknown SAID returns 404."""
        reger = mock_registry_manager.regery.reger
        reger.cloneTvtAt = MagicMock(return_value=None)

        said = "E" + "B" * 43
        resp = client.get(f"/tels/credential/{said}")

        assert resp.status_code == 404

    def test_invalid_said_short(self, client):
        """Invalid SAID format (too short) returns 400."""
        resp = client.get("/tels/credential/Eshort")
        assert resp.status_code == 400

    def test_invalid_said_bad_prefix(self, client):
        """Invalid SAID format (wrong prefix) returns 400."""
        said = "X" + "A" * 43
        resp = client.get(f"/tels/credential/{said}")
        assert resp.status_code == 400

    def test_invalid_said_bad_chars(self, client):
        """Invalid SAID format (bad characters) returns 400."""
        said = "E" + "A" * 42 + "!"
        resp = client.get(f"/tels/credential/{said}")
        assert resp.status_code == 400

    def test_invalid_said_with_slash(self, client):
        """SAID with path traversal characters returns 400."""
        resp = client.get("/tels/credential/E" + "A" * 20 + "/" + "A" * 22)
        # FastAPI routing may handle this differently, but the SAID won't match
        assert resp.status_code in (400, 404, 422)
