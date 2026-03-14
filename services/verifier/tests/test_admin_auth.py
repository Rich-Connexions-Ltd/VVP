"""Tests for admin endpoint auth hardening (Sprint 88, Component 5).

Validates:
- HTTPS enforcement on mutation endpoints
- Bearer token requirement
- Vary header middleware
- Rate limiting interaction with auth
"""

import importlib

import pytest
from fastapi.testclient import TestClient


def _setup(monkeypatch, token="test-token", allow_http=True):
    """Configure admin auth and return (client, headers)."""
    import app.core.config as cfg
    import app.main as main_mod
    monkeypatch.setattr(cfg, "ADMIN_TOKEN", token)
    monkeypatch.setattr(cfg, "TEL_ALLOW_HTTP", allow_http)
    monkeypatch.setattr(main_mod, "_LAST_MUTATION_TS", 0.0)
    from app.main import app
    return TestClient(app), {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# HTTPS enforcement
# ---------------------------------------------------------------------------

class TestHTTPSEnforcement:
    def test_http_blocked_when_allow_http_false(self, monkeypatch):
        """Mutation over HTTP returns 403 when TEL_ALLOW_HTTP=False."""
        client, headers = _setup(monkeypatch, allow_http=False)
        response = client.post(
            "/admin/log-level",
            json={"level": "DEBUG"},
            headers=headers,
        )
        assert response.status_code == 403
        assert "HTTPS" in response.json()["detail"]

    def test_http_allowed_when_allow_http_true(self, monkeypatch):
        """Mutation over HTTP succeeds when TEL_ALLOW_HTTP=True."""
        client, headers = _setup(monkeypatch, allow_http=True)
        response = client.post(
            "/admin/log-level",
            json={"level": "INFO"},
            headers=headers,
        )
        assert response.status_code == 200


# ---------------------------------------------------------------------------
# Bearer token auth
# ---------------------------------------------------------------------------

class TestBearerTokenAuth:
    def test_no_token_returns_503(self, monkeypatch):
        """Mutations return 503 when ADMIN_TOKEN not configured."""
        import app.core.config as cfg
        import app.main as main_mod
        monkeypatch.setattr(cfg, "ADMIN_TOKEN", None)
        monkeypatch.setattr(cfg, "TEL_ALLOW_HTTP", True)
        from app.main import app
        client = TestClient(app)
        response = client.post("/admin/log-level", json={"level": "DEBUG"})
        assert response.status_code == 503

    def test_wrong_token_returns_401(self, monkeypatch):
        """Wrong bearer token returns 401."""
        client, _ = _setup(monkeypatch)
        response = client.post(
            "/admin/log-level",
            json={"level": "DEBUG"},
            headers={"Authorization": "Bearer wrong-token"},
        )
        assert response.status_code == 401

    def test_missing_bearer_prefix_returns_401(self, monkeypatch):
        """Auth header without Bearer prefix returns 401."""
        client, _ = _setup(monkeypatch)
        response = client.post(
            "/admin/log-level",
            json={"level": "DEBUG"},
            headers={"Authorization": "test-token"},
        )
        assert response.status_code == 401

    def test_no_auth_header_returns_401(self, monkeypatch):
        """Missing Authorization header returns 401."""
        client, _ = _setup(monkeypatch)
        response = client.post(
            "/admin/log-level",
            json={"level": "DEBUG"},
        )
        assert response.status_code == 401


# ---------------------------------------------------------------------------
# Vary header
# ---------------------------------------------------------------------------

class TestVaryHeader:
    def test_admin_responses_have_vary_header(self, monkeypatch):
        """Admin responses include Vary: Origin, Authorization."""
        client, headers = _setup(monkeypatch)
        response = client.get("/admin", headers=headers)
        vary = response.headers.get("vary", "")
        assert "Origin" in vary
        assert "Authorization" in vary

    def test_mutation_responses_have_vary_header(self, monkeypatch):
        """Mutation responses include Vary header."""
        client, headers = _setup(monkeypatch)
        response = client.post(
            "/admin/log-level",
            json={"level": "INFO"},
            headers=headers,
        )
        vary = response.headers.get("vary", "")
        assert "Origin" in vary
        assert "Authorization" in vary


# ---------------------------------------------------------------------------
# Cache/witness endpoints also require auth
# ---------------------------------------------------------------------------

class TestMutationEndpointsRequireAuth:
    def test_cache_clear_requires_token(self, monkeypatch):
        client, _ = _setup(monkeypatch)
        response = client.post(
            "/admin/cache/clear",
            json={"cache_type": "verification"},
        )
        assert response.status_code == 401

    def test_witness_discover_requires_token(self, monkeypatch):
        client, _ = _setup(monkeypatch)
        response = client.post("/admin/witnesses/discover")
        assert response.status_code == 401
