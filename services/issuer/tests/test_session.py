"""Tests for session-based authentication in VVP Issuer.

Tests cover:
- Session store operations (create, get, delete, cleanup)
- Rate limiter for login protection
- Auth API endpoints (login, logout, status)
- CSRF protection for cookie-authenticated requests
- Dual-mode authentication (session cookie vs API key)
"""

import asyncio
import json
import os
import time
from datetime import datetime, timedelta, timezone

import pytest
from httpx import AsyncClient

from app.auth.api_key import Principal, reset_api_key_store
from app.auth.session import (
    Session,
    InMemorySessionStore,
    LoginRateLimiter,
    get_session_store,
    get_rate_limiter,
    reset_session_store,
    reset_rate_limiter,
)
from tests.conftest import (
    TEST_ADMIN_KEY,
    TEST_OPERATOR_KEY,
    TEST_READONLY_KEY,
    TEST_REVOKED_KEY,
    get_test_api_keys_config,
)


# =============================================================================
# Session Store Tests
# =============================================================================


class TestInMemorySessionStore:
    """Tests for InMemorySessionStore."""

    @pytest.fixture(autouse=True)
    def setup_api_key_store(self):
        """Set up API key store for session tests (needed for key revocation checks)."""
        import importlib
        from app.auth.api_key import get_api_key_store

        # Set up test API keys in environment
        original_api_keys = os.environ.get("VVP_API_KEYS")
        os.environ["VVP_API_KEYS"] = json.dumps(get_test_api_keys_config())

        # Reset stores first
        reset_api_key_store()
        reset_session_store()

        # Reload the config module to pick up the new env var
        import app.config as config_module
        importlib.reload(config_module)

        # Now initialize the API key store (it will use the reloaded config)
        api_key_store = get_api_key_store()

        yield

        # Cleanup
        reset_api_key_store()
        reset_session_store()
        if original_api_keys is not None:
            os.environ["VVP_API_KEYS"] = original_api_keys
        elif "VVP_API_KEYS" in os.environ:
            del os.environ["VVP_API_KEYS"]

        # Reload config to restore original state
        importlib.reload(config_module)

    @pytest.fixture
    def store(self) -> InMemorySessionStore:
        """Create a fresh session store."""
        return InMemorySessionStore()

    @pytest.fixture
    def principal(self) -> Principal:
        """Create a test principal using a key ID that exists in test config."""
        return Principal(
            key_id="test-admin",  # Must match a key in get_test_api_keys_config()
            name="Test User",
            roles={"issuer:admin", "issuer:operator", "issuer:readonly"},
        )

    @pytest.mark.asyncio
    async def test_create_session(self, store: InMemorySessionStore, principal: Principal):
        """Test session creation returns valid Session."""
        session = await store.create(principal, ttl_seconds=3600)

        assert session is not None
        assert session.session_id is not None
        assert len(session.session_id) > 20  # Cryptographically random
        assert session.key_id == "test-admin"
        assert session.principal.key_id == "test-admin"
        assert session.principal.name == "Test User"
        assert not session.is_expired
        assert session.ttl_seconds > 0

    @pytest.mark.asyncio
    async def test_get_valid_session(self, store: InMemorySessionStore, principal: Principal):
        """Test retrieving a valid session."""
        session = await store.create(principal, ttl_seconds=3600)

        retrieved = await store.get(session.session_id)

        assert retrieved is not None
        assert retrieved.session_id == session.session_id
        assert retrieved.key_id == session.key_id

    @pytest.mark.asyncio
    async def test_get_nonexistent_session(self, store: InMemorySessionStore):
        """Test retrieving a nonexistent session returns None."""
        result = await store.get("nonexistent-session-id")
        assert result is None

    @pytest.mark.asyncio
    async def test_get_expired_session(self, store: InMemorySessionStore, principal: Principal):
        """Test that expired sessions return None and are deleted."""
        # Create session with very short TTL
        session = await store.create(principal, ttl_seconds=1)

        # Wait for expiry
        await asyncio.sleep(1.1)

        # Session should be None and deleted
        result = await store.get(session.session_id)
        assert result is None
        assert store.session_count == 0

    @pytest.mark.asyncio
    async def test_delete_session(self, store: InMemorySessionStore, principal: Principal):
        """Test session deletion."""
        session = await store.create(principal, ttl_seconds=3600)

        result = await store.delete(session.session_id)
        assert result is True

        # Session should no longer exist
        retrieved = await store.get(session.session_id)
        assert retrieved is None

    @pytest.mark.asyncio
    async def test_delete_nonexistent_session(self, store: InMemorySessionStore):
        """Test deleting a nonexistent session returns False."""
        result = await store.delete("nonexistent-session-id")
        assert result is False

    @pytest.mark.asyncio
    async def test_delete_by_key_id(self, store: InMemorySessionStore, principal: Principal):
        """Test deleting all sessions for a key."""
        # Create multiple sessions for the same key (test-admin)
        await store.create(principal, ttl_seconds=3600)
        await store.create(principal, ttl_seconds=3600)
        await store.create(principal, ttl_seconds=3600)

        # Create session for different key (test-operator exists in test config)
        other_principal = Principal(key_id="test-operator", name="Other", roles=set())
        await store.create(other_principal, ttl_seconds=3600)

        assert store.session_count == 4

        # Delete sessions for first key (test-admin)
        count = await store.delete_by_key_id("test-admin")
        assert count == 3
        assert store.session_count == 1

    @pytest.mark.asyncio
    async def test_cleanup_expired(self, store: InMemorySessionStore, principal: Principal):
        """Test cleanup removes only expired sessions."""
        # Create session that will expire
        await store.create(principal, ttl_seconds=1)

        # Create session that won't expire
        long_session = await store.create(principal, ttl_seconds=3600)

        # Wait for first to expire
        await asyncio.sleep(1.1)

        # Cleanup
        count = await store.cleanup_expired()
        assert count == 1
        assert store.session_count == 1

        # Long session should still exist
        retrieved = await store.get(long_session.session_id)
        assert retrieved is not None


# =============================================================================
# Rate Limiter Tests
# =============================================================================


class TestLoginRateLimiter:
    """Tests for LoginRateLimiter."""

    @pytest.fixture
    def limiter(self) -> LoginRateLimiter:
        """Create a rate limiter with low thresholds for testing."""
        return LoginRateLimiter(max_attempts=3, window_seconds=5)

    @pytest.mark.asyncio
    async def test_first_attempt_allowed(self, limiter: LoginRateLimiter):
        """Test first login attempt is allowed."""
        result = await limiter.check_rate_limit("192.168.1.1")
        assert result is True

    @pytest.mark.asyncio
    async def test_under_threshold_allowed(self, limiter: LoginRateLimiter):
        """Test attempts under threshold are allowed."""
        ip = "192.168.1.2"

        # Record 2 failed attempts (threshold is 3)
        await limiter.record_attempt(ip, success=False)
        await limiter.record_attempt(ip, success=False)

        # Third should still be allowed (at threshold)
        result = await limiter.check_rate_limit(ip)
        assert result is True

    @pytest.mark.asyncio
    async def test_lockout_after_threshold(self, limiter: LoginRateLimiter):
        """Test lockout after exceeding threshold."""
        ip = "192.168.1.3"

        # Record 3 failed attempts (at threshold, triggers lockout)
        await limiter.record_attempt(ip, success=False)
        await limiter.record_attempt(ip, success=False)
        await limiter.record_attempt(ip, success=False)

        # Should be locked out
        result = await limiter.check_rate_limit(ip)
        assert result is False

        is_locked = await limiter.is_locked_out(ip)
        assert is_locked is True

    @pytest.mark.asyncio
    async def test_lockout_expires(self, limiter: LoginRateLimiter):
        """Test lockout expires after window."""
        ip = "192.168.1.4"

        # Trigger lockout
        for _ in range(3):
            await limiter.record_attempt(ip, success=False)

        assert await limiter.is_locked_out(ip) is True

        # Wait for window to expire
        await asyncio.sleep(5.1)

        # Should be allowed again
        result = await limiter.check_rate_limit(ip)
        assert result is True

    @pytest.mark.asyncio
    async def test_successful_login_resets_counter(self, limiter: LoginRateLimiter):
        """Test successful login clears rate limit counter."""
        ip = "192.168.1.5"

        # Record 2 failed attempts
        await limiter.record_attempt(ip, success=False)
        await limiter.record_attempt(ip, success=False)

        # Successful login should reset
        await limiter.record_attempt(ip, success=True)

        # Should be able to fail again without hitting lockout immediately
        await limiter.record_attempt(ip, success=False)
        await limiter.record_attempt(ip, success=False)

        result = await limiter.check_rate_limit(ip)
        assert result is True  # Still allowed (only 2 failures after reset)

    @pytest.mark.asyncio
    async def test_get_lockout_remaining(self, limiter: LoginRateLimiter):
        """Test getting remaining lockout time."""
        ip = "192.168.1.6"

        # Trigger lockout
        for _ in range(3):
            await limiter.record_attempt(ip, success=False)

        remaining = await limiter.get_lockout_remaining(ip)
        assert remaining > 0
        assert remaining <= 5


# =============================================================================
# Auth API Endpoint Tests
# =============================================================================


class TestAuthLogin:
    """Tests for POST /auth/login endpoint."""

    @pytest.mark.asyncio
    async def test_login_valid_key(self, client_with_auth: AsyncClient):
        """Test login with valid API key succeeds."""
        response = await client_with_auth.post(
            "/auth/login",
            json={"api_key": TEST_ADMIN_KEY},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["key_id"] == "test-admin"
        assert data["name"] == "Test Admin"
        assert "issuer:admin" in data["roles"]
        assert data["expires_at"] is not None

        # Check cookie is set
        assert "vvp_session" in response.cookies

    @pytest.mark.asyncio
    async def test_login_invalid_key(self, client_with_auth: AsyncClient):
        """Test login with invalid API key fails."""
        response = await client_with_auth.post(
            "/auth/login",
            json={"api_key": "invalid-key-that-does-not-exist"},
        )

        assert response.status_code == 401
        data = response.json()
        assert data["success"] is False

        # No cookie should be set
        assert "vvp_session" not in response.cookies

    @pytest.mark.asyncio
    async def test_login_revoked_key(self, client_with_auth: AsyncClient):
        """Test login with revoked API key fails."""
        response = await client_with_auth.post(
            "/auth/login",
            json={"api_key": TEST_REVOKED_KEY},
        )

        assert response.status_code == 401
        data = response.json()
        assert data["success"] is False

    @pytest.mark.asyncio
    async def test_login_rate_limited(self, client_with_auth: AsyncClient):
        """Test login rate limiting after multiple failures."""
        # Exhaust rate limit (5 attempts by default)
        for _ in range(5):
            await client_with_auth.post(
                "/auth/login",
                json={"api_key": "wrong-key"},
            )

        # Next attempt should be rate limited
        response = await client_with_auth.post(
            "/auth/login",
            json={"api_key": TEST_ADMIN_KEY},  # Even valid key should fail
        )

        assert response.status_code == 429
        data = response.json()
        assert "error" in data
        assert "retry_after" in data or "Retry-After" in response.headers


class TestAuthLogout:
    """Tests for POST /auth/logout endpoint."""

    @pytest.mark.asyncio
    async def test_logout_clears_session(self, client_with_auth: AsyncClient):
        """Test logout clears session and cookie."""
        # First login
        login_response = await client_with_auth.post(
            "/auth/login",
            json={"api_key": TEST_ADMIN_KEY},
        )
        assert login_response.status_code == 200
        session_cookie = login_response.cookies.get("vvp_session")
        assert session_cookie is not None

        # Now logout
        logout_response = await client_with_auth.post(
            "/auth/logout",
            cookies={"vvp_session": session_cookie},
        )

        assert logout_response.status_code == 200
        data = logout_response.json()
        assert data["success"] is True

        # Check session is no longer valid
        status_response = await client_with_auth.get(
            "/auth/status",
            cookies={"vvp_session": session_cookie},
        )
        data = status_response.json()
        assert data["authenticated"] is False

    @pytest.mark.asyncio
    async def test_logout_without_session(self, client_with_auth: AsyncClient):
        """Test logout without session still succeeds."""
        response = await client_with_auth.post("/auth/logout")

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True


class TestAuthStatus:
    """Tests for GET /auth/status endpoint."""

    @pytest.mark.asyncio
    async def test_status_unauthenticated(self, client_with_auth: AsyncClient):
        """Test status when not authenticated."""
        response = await client_with_auth.get("/auth/status")

        assert response.status_code == 200
        data = response.json()
        assert data["authenticated"] is False
        assert data["method"] is None

    @pytest.mark.asyncio
    async def test_status_with_session(self, client_with_auth: AsyncClient):
        """Test status with valid session."""
        # Login first
        login_response = await client_with_auth.post(
            "/auth/login",
            json={"api_key": TEST_ADMIN_KEY},
        )
        session_cookie = login_response.cookies.get("vvp_session")

        # Check status
        response = await client_with_auth.get(
            "/auth/status",
            cookies={"vvp_session": session_cookie},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["authenticated"] is True
        assert data["method"] == "session"
        assert data["key_id"] == "test-admin"
        assert data["expires_at"] is not None

    @pytest.mark.asyncio
    async def test_status_with_api_key(self, client_with_auth: AsyncClient, admin_headers: dict):
        """Test status with API key header."""
        response = await client_with_auth.get(
            "/auth/status",
            headers=admin_headers,
        )

        assert response.status_code == 200
        data = response.json()
        assert data["authenticated"] is True
        assert data["method"] == "api_key"
        assert data["key_id"] == "test-admin"
        assert data["expires_at"] is None  # API keys don't have per-request expiry


# =============================================================================
# CSRF Protection Tests
# =============================================================================


class TestCSRFProtection:
    """Tests for CSRF protection on cookie-authenticated requests."""

    @pytest.mark.asyncio
    async def test_csrf_required_for_cookie_auth_post(self, client_with_auth: AsyncClient):
        """Test CSRF header required for cookie-authenticated POST."""
        # Login to get session
        login_response = await client_with_auth.post(
            "/auth/login",
            json={"api_key": TEST_ADMIN_KEY},
        )
        session_cookie = login_response.cookies.get("vvp_session")

        # Try POST without CSRF header - should fail
        response = await client_with_auth.post(
            "/identity",
            json={"name": "test", "publish_to_witnesses": False},
            cookies={"vvp_session": session_cookie},
            # No X-Requested-With header
        )

        assert response.status_code == 401
        assert "CSRF" in response.text

    @pytest.mark.asyncio
    async def test_csrf_header_allows_cookie_auth_post(self, client_with_auth: AsyncClient):
        """Test CSRF header allows cookie-authenticated POST."""
        # Login to get session
        login_response = await client_with_auth.post(
            "/auth/login",
            json={"api_key": TEST_ADMIN_KEY},
        )
        session_cookie = login_response.cookies.get("vvp_session")

        # POST with CSRF header - should succeed
        response = await client_with_auth.post(
            "/identity",
            json={"name": "test-csrf", "publish_to_witnesses": False},
            cookies={"vvp_session": session_cookie},
            headers={"X-Requested-With": "XMLHttpRequest"},
        )

        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_api_key_auth_no_csrf_required(
        self, client_with_auth: AsyncClient, admin_headers: dict
    ):
        """Test API key auth doesn't require CSRF header."""
        response = await client_with_auth.post(
            "/identity",
            json={"name": "test-no-csrf", "publish_to_witnesses": False},
            headers=admin_headers,
            # No X-Requested-With header, but using API key
        )

        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_get_request_no_csrf_required(self, client_with_auth: AsyncClient):
        """Test GET requests don't require CSRF header."""
        # Login to get session
        login_response = await client_with_auth.post(
            "/auth/login",
            json={"api_key": TEST_ADMIN_KEY},
        )
        session_cookie = login_response.cookies.get("vvp_session")

        # GET request without CSRF header - should succeed
        response = await client_with_auth.get(
            "/identity",
            cookies={"vvp_session": session_cookie},
            # No X-Requested-With header
        )

        assert response.status_code == 200


# =============================================================================
# Dual-Mode Authentication Tests
# =============================================================================


class TestDualModeAuth:
    """Tests for dual-mode authentication (session vs API key)."""

    @pytest.mark.asyncio
    async def test_session_cookie_authenticates(self, client_with_auth: AsyncClient):
        """Test session cookie provides authentication."""
        # Login
        login_response = await client_with_auth.post(
            "/auth/login",
            json={"api_key": TEST_OPERATOR_KEY},
        )
        session_cookie = login_response.cookies.get("vvp_session")

        # Use session for protected endpoint
        response = await client_with_auth.get(
            "/identity",
            cookies={"vvp_session": session_cookie},
        )

        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_api_key_still_works(
        self, client_with_auth: AsyncClient, operator_headers: dict
    ):
        """Test API key header still works for authentication."""
        response = await client_with_auth.get(
            "/identity",
            headers=operator_headers,
        )

        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_session_inherits_roles(self, client_with_auth: AsyncClient):
        """Test session inherits roles from API key."""
        # Login with operator key (no admin role)
        login_response = await client_with_auth.post(
            "/auth/login",
            json={"api_key": TEST_OPERATOR_KEY},
        )
        session_cookie = login_response.cookies.get("vvp_session")

        # Try admin-only endpoint - should fail with 403
        response = await client_with_auth.post(
            "/admin/auth/reload",
            json={},
            cookies={"vvp_session": session_cookie},
            headers={"X-Requested-With": "XMLHttpRequest"},
        )

        # Should be 403 (forbidden) not 401 (unauthenticated)
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_readonly_session_cannot_write(self, client_with_auth: AsyncClient):
        """Test readonly session cannot perform write operations."""
        # Login with readonly key
        login_response = await client_with_auth.post(
            "/auth/login",
            json={"api_key": TEST_READONLY_KEY},
        )
        session_cookie = login_response.cookies.get("vvp_session")

        # Try to create identity (requires operator) - should fail
        response = await client_with_auth.post(
            "/identity",
            json={"name": "should-fail", "publish_to_witnesses": False},
            cookies={"vvp_session": session_cookie},
            headers={"X-Requested-With": "XMLHttpRequest"},
        )

        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_expired_session_falls_through_to_api_key(
        self, client_with_auth: AsyncClient, admin_headers: dict
    ):
        """Test expired/invalid session falls through to check API key."""
        # With invalid session but valid API key, should still authenticate
        response = await client_with_auth.get(
            "/identity",
            cookies={"vvp_session": "invalid-session-id"},
            headers=admin_headers,
        )

        # Should succeed because API key is valid
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_invalid_session_no_api_key_returns_401(
        self, client_with_auth: AsyncClient
    ):
        """Test invalid session with no API key returns 401 for protected endpoints."""
        # Try to POST (requires auth) with invalid session and no API key
        response = await client_with_auth.post(
            "/identity",
            json={"name": "test", "publish_to_witnesses": False},
            cookies={"vvp_session": "invalid-session-id"},
            headers={"X-Requested-With": "XMLHttpRequest"},  # CSRF header
        )

        # Should get 401 (no valid auth)
        assert response.status_code == 401
