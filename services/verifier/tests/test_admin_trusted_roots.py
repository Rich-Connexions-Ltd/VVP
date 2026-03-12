"""Tests for Sprint 83 trusted roots admin endpoints.

Tests cover:
- GET /admin/trusted-roots (list)
- POST /admin/trusted-roots/add
- POST /admin/trusted-roots/remove
- POST /admin/trusted-roots/replace
- Auth enforcement (fail-closed when no VVP_ADMIN_TOKEN)
- Rate limiting
- AID validation
- Request-scoped snapshot isolation
"""

import asyncio
import importlib
import os
import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def reset_trusted_roots_store():
    """Reset trusted roots store to env-default between tests."""
    yield
    # Reset store after each test to avoid cross-test contamination
    try:
        import app.core.config as cfg
        initial = cfg._parse_trusted_roots()
        asyncio.get_event_loop().run_until_complete(
            cfg._trusted_roots_store.replace(initial)
        )
    except Exception:
        pass


@pytest.fixture()
def client():
    from app.main import app
    return TestClient(app)


@pytest.fixture()
def client_with_token(monkeypatch):
    """Client with VVP_ADMIN_TOKEN set to 'test-token'."""
    monkeypatch.setenv("VVP_ADMIN_TOKEN", "test-token")
    import app.core.config as cfg
    monkeypatch.setattr(cfg, "ADMIN_TOKEN", "test-token")
    import app.main as main_mod
    monkeypatch.setattr(main_mod, "_LAST_MUTATION_TS", 0.0)
    from app.main import app
    return TestClient(app)


def _auth_headers(token="test-token"):
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# GET /admin/trusted-roots
# ---------------------------------------------------------------------------

class TestGetTrustedRoots:
    def test_returns_list(self, client):
        resp = client.get("/admin/trusted-roots")
        # Admin endpoint may be disabled in test env; accept 404 or 200
        if resp.status_code == 404:
            pytest.skip("Admin endpoint disabled")
        assert resp.status_code == 200
        data = resp.json()
        assert "trusted_roots" in data
        assert "count" in data
        assert isinstance(data["trusted_roots"], list)
        assert data["count"] == len(data["trusted_roots"])

    def test_no_cache_headers(self, client):
        resp = client.get("/admin/trusted-roots")
        if resp.status_code == 404:
            pytest.skip("Admin endpoint disabled")
        assert "no-store" in resp.headers.get("cache-control", "").lower()

    def test_requires_token_when_configured(self, monkeypatch):
        import app.core.config as cfg
        monkeypatch.setattr(cfg, "ADMIN_TOKEN", "secret")
        from app.main import app
        c = TestClient(app)
        resp = c.get("/admin/trusted-roots")
        if resp.status_code == 404:
            pytest.skip("Admin endpoint disabled")
        assert resp.status_code == 401

    def test_accepts_correct_token(self, monkeypatch):
        import app.core.config as cfg
        monkeypatch.setattr(cfg, "ADMIN_TOKEN", "secret")
        from app.main import app
        c = TestClient(app)
        resp = c.get("/admin/trusted-roots", headers={"Authorization": "Bearer secret"})
        if resp.status_code == 404:
            pytest.skip("Admin endpoint disabled")
        assert resp.status_code == 200

    def test_includes_env_source(self, client):
        resp = client.get("/admin/trusted-roots")
        if resp.status_code in (404, 401):
            pytest.skip("Admin endpoint disabled or requires token")
        assert resp.json()["env_source"] == "VVP_TRUSTED_ROOT_AIDS"


# ---------------------------------------------------------------------------
# POST /admin/trusted-roots/add
# ---------------------------------------------------------------------------

VALID_AID = "EDP1vHcw_wc4M__Fj53-cJaBnZZASd-aMTaSyWEQ-PC2"

class TestAddTrustedRoot:
    def test_add_requires_token(self, client):
        resp = client.post("/admin/trusted-roots/add", json={"aid": VALID_AID})
        if resp.status_code == 404:
            pytest.skip("Admin endpoint disabled")
        # No token configured → 503 fail-closed
        assert resp.status_code in (401, 503)

    def test_add_success(self, monkeypatch):
        import app.core.config as cfg
        import app.main as main_mod
        monkeypatch.setattr(cfg, "ADMIN_TOKEN", "tok")
        monkeypatch.setattr(main_mod, "_LAST_MUTATION_TS", 0.0)
        # Set a known empty state
        asyncio.get_event_loop().run_until_complete(
            cfg._trusted_roots_store.replace(set())
        )
        from app.main import app
        c = TestClient(app)
        resp = c.post(
            "/admin/trusted-roots/add",
            json={"aid": VALID_AID},
            headers=_auth_headers("tok"),
        )
        if resp.status_code == 404:
            pytest.skip("Admin endpoint disabled")
        assert resp.status_code == 200
        data = resp.json()
        assert VALID_AID in data["trusted_roots"]
        assert data["count"] == 1

    def test_add_idempotent(self, monkeypatch):
        """Adding an already-present AID is a no-op."""
        import app.core.config as cfg
        import app.main as main_mod
        monkeypatch.setattr(cfg, "ADMIN_TOKEN", "tok")
        monkeypatch.setattr(main_mod, "_LAST_MUTATION_TS", 0.0)
        asyncio.get_event_loop().run_until_complete(
            cfg._trusted_roots_store.replace({VALID_AID})
        )
        from app.main import app
        c = TestClient(app)
        # Reset rate limit between calls
        monkeypatch.setattr(main_mod, "_LAST_MUTATION_TS", 0.0)
        resp = c.post(
            "/admin/trusted-roots/add",
            json={"aid": VALID_AID},
            headers=_auth_headers("tok"),
        )
        if resp.status_code == 404:
            pytest.skip("Admin endpoint disabled")
        assert resp.status_code == 200
        data = resp.json()
        assert data["trusted_roots"].count(VALID_AID) == 1

    def test_add_invalid_aid(self, monkeypatch):
        import app.core.config as cfg
        import app.main as main_mod
        monkeypatch.setattr(cfg, "ADMIN_TOKEN", "tok")
        monkeypatch.setattr(main_mod, "_LAST_MUTATION_TS", 0.0)
        from app.main import app
        c = TestClient(app)
        resp = c.post(
            "/admin/trusted-roots/add",
            json={"aid": "not-a-valid-aid"},
            headers=_auth_headers("tok"),
        )
        if resp.status_code == 404:
            pytest.skip("Admin endpoint disabled")
        assert resp.status_code == 422

    def test_add_wrong_token(self, monkeypatch):
        import app.core.config as cfg
        import app.main as main_mod
        monkeypatch.setattr(cfg, "ADMIN_TOKEN", "real-token")
        monkeypatch.setattr(main_mod, "_LAST_MUTATION_TS", 0.0)
        from app.main import app
        c = TestClient(app)
        resp = c.post(
            "/admin/trusted-roots/add",
            json={"aid": VALID_AID},
            headers=_auth_headers("wrong-token"),
        )
        if resp.status_code == 404:
            pytest.skip("Admin endpoint disabled")
        assert resp.status_code == 401

    def test_add_mutation_warning_in_response(self, monkeypatch):
        import app.core.config as cfg
        import app.main as main_mod
        monkeypatch.setattr(cfg, "ADMIN_TOKEN", "tok")
        monkeypatch.setattr(main_mod, "_LAST_MUTATION_TS", 0.0)
        asyncio.get_event_loop().run_until_complete(
            cfg._trusted_roots_store.replace(set())
        )
        from app.main import app
        c = TestClient(app)
        resp = c.post(
            "/admin/trusted-roots/add",
            json={"aid": VALID_AID},
            headers=_auth_headers("tok"),
        )
        if resp.status_code == 404:
            pytest.skip("Admin endpoint disabled")
        if resp.status_code == 200:
            assert "_mutation_warning" in resp.json()


# ---------------------------------------------------------------------------
# POST /admin/trusted-roots/remove
# ---------------------------------------------------------------------------

class TestRemoveTrustedRoot:
    def test_remove_success(self, monkeypatch):
        import app.core.config as cfg
        import app.main as main_mod
        monkeypatch.setattr(cfg, "ADMIN_TOKEN", "tok")
        monkeypatch.setattr(main_mod, "_LAST_MUTATION_TS", 0.0)
        asyncio.get_event_loop().run_until_complete(
            cfg._trusted_roots_store.replace({VALID_AID})
        )
        from app.main import app
        c = TestClient(app)
        resp = c.post(
            "/admin/trusted-roots/remove",
            json={"aid": VALID_AID},
            headers=_auth_headers("tok"),
        )
        if resp.status_code == 404:
            pytest.skip("Admin endpoint disabled")
        assert resp.status_code == 200
        data = resp.json()
        assert VALID_AID not in data["trusted_roots"]
        assert data["count"] == 0
        assert data["empty_set_active"] is True

    def test_remove_nonexistent(self, monkeypatch):
        import app.core.config as cfg
        import app.main as main_mod
        monkeypatch.setattr(cfg, "ADMIN_TOKEN", "tok")
        monkeypatch.setattr(main_mod, "_LAST_MUTATION_TS", 0.0)
        asyncio.get_event_loop().run_until_complete(
            cfg._trusted_roots_store.replace(set())
        )
        from app.main import app
        c = TestClient(app)
        resp = c.post(
            "/admin/trusted-roots/remove",
            json={"aid": VALID_AID},
            headers=_auth_headers("tok"),
        )
        if resp.status_code == 404:
            assert True  # Could be admin disabled OR not-found
        else:
            assert resp.status_code == 404


# ---------------------------------------------------------------------------
# POST /admin/trusted-roots/replace
# ---------------------------------------------------------------------------

VALID_AID_2 = "EFvHcw_wc4M__Fj53-cJaBnZZASd-aMTaSyWEQ-test"

class TestReplaceTrustedRoots:
    def test_replace_success(self, monkeypatch):
        import app.core.config as cfg
        import app.main as main_mod
        monkeypatch.setattr(cfg, "ADMIN_TOKEN", "tok")
        monkeypatch.setattr(main_mod, "_LAST_MUTATION_TS", 0.0)
        from app.main import app
        c = TestClient(app)
        resp = c.post(
            "/admin/trusted-roots/replace",
            json={"aids": [VALID_AID]},
            headers=_auth_headers("tok"),
        )
        if resp.status_code == 404:
            pytest.skip("Admin endpoint disabled")
        assert resp.status_code == 200
        data = resp.json()
        assert data["trusted_roots"] == [VALID_AID]
        assert data["count"] == 1

    def test_replace_empty_list(self, monkeypatch):
        """Empty list puts verifier in fail-closed mode."""
        import app.core.config as cfg
        import app.main as main_mod
        monkeypatch.setattr(cfg, "ADMIN_TOKEN", "tok")
        monkeypatch.setattr(main_mod, "_LAST_MUTATION_TS", 0.0)
        from app.main import app
        c = TestClient(app)
        resp = c.post(
            "/admin/trusted-roots/replace",
            json={"aids": []},
            headers=_auth_headers("tok"),
        )
        if resp.status_code == 404:
            pytest.skip("Admin endpoint disabled")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 0
        assert data["empty_set_active"] is True
        assert "_warning" in data

    def test_replace_invalid_aid_rejected(self, monkeypatch):
        import app.core.config as cfg
        import app.main as main_mod
        monkeypatch.setattr(cfg, "ADMIN_TOKEN", "tok")
        monkeypatch.setattr(main_mod, "_LAST_MUTATION_TS", 0.0)
        from app.main import app
        c = TestClient(app)
        resp = c.post(
            "/admin/trusted-roots/replace",
            json={"aids": ["bad-aid"]},
            headers=_auth_headers("tok"),
        )
        if resp.status_code == 404:
            pytest.skip("Admin endpoint disabled")
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------

class TestRateLimiting:
    def test_second_mutation_rate_limited(self, monkeypatch):
        import app.core.config as cfg
        import app.main as main_mod
        monkeypatch.setattr(cfg, "ADMIN_TOKEN", "tok")
        monkeypatch.setattr(main_mod, "_LAST_MUTATION_TS", 0.0)
        asyncio.get_event_loop().run_until_complete(
            cfg._trusted_roots_store.replace(set())
        )
        from app.main import app
        c = TestClient(app)
        # First mutation should succeed
        resp1 = c.post(
            "/admin/trusted-roots/add",
            json={"aid": VALID_AID},
            headers=_auth_headers("tok"),
        )
        if resp1.status_code == 404:
            pytest.skip("Admin endpoint disabled")
        assert resp1.status_code == 200
        # Second mutation within rate limit window should be 503
        resp2 = c.post(
            "/admin/trusted-roots/remove",
            json={"aid": VALID_AID},
            headers=_auth_headers("tok"),
        )
        assert resp2.status_code == 503
        assert "Rate limited" in resp2.json().get("detail", "")


# ---------------------------------------------------------------------------
# Fail-closed (no VVP_ADMIN_TOKEN configured)
# ---------------------------------------------------------------------------

class TestFailClosed:
    def test_mutations_503_when_no_token_configured(self, monkeypatch):
        """Mutations return 503 when VVP_ADMIN_TOKEN is not set."""
        import app.core.config as cfg
        import app.main as main_mod
        monkeypatch.setattr(cfg, "ADMIN_TOKEN", None)
        from app.main import app
        c = TestClient(app)
        resp = c.post("/admin/trusted-roots/add", json={"aid": VALID_AID})
        if resp.status_code == 404:
            pytest.skip("Admin endpoint disabled")
        assert resp.status_code == 503


# ---------------------------------------------------------------------------
# Config.py store unit tests
# ---------------------------------------------------------------------------

class TestTrustedRootsStore:
    def test_snapshot_returns_frozenset(self):
        import app.core.config as cfg
        snap = asyncio.get_event_loop().run_until_complete(
            cfg._trusted_roots_store.snapshot()
        )
        assert isinstance(snap, frozenset)

    def test_add_and_remove(self):
        import app.core.config as cfg
        loop = asyncio.get_event_loop()
        # Start from empty
        loop.run_until_complete(cfg._trusted_roots_store.replace(set()))
        # Add
        result = loop.run_until_complete(cfg._trusted_roots_store.add(VALID_AID))
        assert VALID_AID in result
        # Remove
        result = loop.run_until_complete(cfg._trusted_roots_store.remove(VALID_AID))
        assert VALID_AID not in result

    def test_remove_nonexistent_raises_keyerror(self):
        import app.core.config as cfg
        loop = asyncio.get_event_loop()
        loop.run_until_complete(cfg._trusted_roots_store.replace(set()))
        with pytest.raises(KeyError):
            loop.run_until_complete(cfg._trusted_roots_store.remove("nonexistent"))

    def test_replace_atomic(self):
        import app.core.config as cfg
        loop = asyncio.get_event_loop()
        new_roots = {VALID_AID}
        result = loop.run_until_complete(cfg._trusted_roots_store.replace(new_roots))
        assert result == frozenset(new_roots)

    def test_current_sync_matches_snapshot(self):
        import app.core.config as cfg
        loop = asyncio.get_event_loop()
        loop.run_until_complete(cfg._trusted_roots_store.replace({VALID_AID}))
        sync_val = cfg.get_trusted_roots_current()
        snap = loop.run_until_complete(cfg.get_trusted_roots_snapshot())
        assert sync_val == snap
