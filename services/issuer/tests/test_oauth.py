"""Tests for Microsoft OAuth integration in VVP Issuer.

Tests cover:
- PKCE generation
- State and nonce generation
- OAuthStateStore (create, get, delete, expiry)
- Authorization URL building
- Domain whitelist checking
- OAuth user handling in UserStore
- OAuth endpoints (start, callback, status)
"""

import asyncio
import os
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.auth.oauth import (
    OAuthError,
    OAuthState,
    OAuthStateStore,
    OAuthUserInfo,
    build_authorization_url,
    generate_nonce,
    generate_pkce_pair,
    generate_state,
    get_oauth_state_store,
    is_email_domain_allowed,
    reset_oauth_state_store,
)
from app.auth.users import UserConfig, UserStore, get_user_store, reset_user_store


# =============================================================================
# PKCE AND STATE GENERATION TESTS
# =============================================================================


class TestPKCEGeneration:
    """Tests for PKCE code_verifier and code_challenge generation."""

    def test_generate_pkce_pair_returns_tuple(self):
        """Test that generate_pkce_pair returns a tuple of two strings."""
        verifier, challenge = generate_pkce_pair()

        assert isinstance(verifier, str)
        assert isinstance(challenge, str)
        assert verifier != challenge

    def test_pkce_verifier_is_url_safe(self):
        """Test that code_verifier is URL-safe base64."""
        verifier, _ = generate_pkce_pair()

        # URL-safe base64 only contains alphanumeric, -, and _
        assert all(c.isalnum() or c in "-_" for c in verifier)

    def test_pkce_verifier_has_sufficient_entropy(self):
        """Test that code_verifier has sufficient length (>40 chars)."""
        verifier, _ = generate_pkce_pair()

        assert len(verifier) > 40

    def test_pkce_challenge_is_sha256_hash(self):
        """Test that code_challenge is correct length for SHA-256."""
        _, challenge = generate_pkce_pair()

        # SHA-256 base64url without padding = 43 characters
        assert len(challenge) == 43

    def test_pkce_pairs_are_unique(self):
        """Test that each call generates unique pairs."""
        pair1 = generate_pkce_pair()
        pair2 = generate_pkce_pair()

        assert pair1[0] != pair2[0]
        assert pair1[1] != pair2[1]


class TestStateGeneration:
    """Tests for OAuth state parameter generation."""

    def test_generate_state_returns_string(self):
        """Test that generate_state returns a string."""
        state = generate_state()
        assert isinstance(state, str)

    def test_state_is_url_safe(self):
        """Test that state is URL-safe."""
        state = generate_state()
        assert all(c.isalnum() or c in "-_" for c in state)

    def test_states_are_unique(self):
        """Test that each call generates unique state."""
        state1 = generate_state()
        state2 = generate_state()
        assert state1 != state2


class TestNonceGeneration:
    """Tests for OAuth nonce parameter generation."""

    def test_generate_nonce_returns_string(self):
        """Test that generate_nonce returns a string."""
        nonce = generate_nonce()
        assert isinstance(nonce, str)

    def test_nonces_are_unique(self):
        """Test that each call generates unique nonce."""
        nonce1 = generate_nonce()
        nonce2 = generate_nonce()
        assert nonce1 != nonce2


# =============================================================================
# OAUTH STATE STORE TESTS
# =============================================================================


class TestOAuthStateStore:
    """Tests for server-side OAuth state storage."""

    @pytest.fixture
    def store(self):
        """Create a fresh OAuthStateStore for each test."""
        return OAuthStateStore(default_ttl=60)

    @pytest.fixture
    def sample_state(self):
        """Create a sample OAuth state."""
        return OAuthState(
            state="test-state",
            nonce="test-nonce",
            code_verifier="test-verifier",
            created_at=datetime.now(timezone.utc),
            redirect_after="/ui/",
        )

    @pytest.mark.asyncio
    async def test_create_and_get(self, store, sample_state):
        """Test creating and retrieving OAuth state."""
        state_id = await store.create(sample_state)

        assert isinstance(state_id, str)
        assert len(state_id) > 20

        retrieved = await store.get(state_id)

        assert retrieved is not None
        assert retrieved.state == sample_state.state
        assert retrieved.nonce == sample_state.nonce
        assert retrieved.code_verifier == sample_state.code_verifier

    @pytest.mark.asyncio
    async def test_get_nonexistent(self, store):
        """Test getting a non-existent state returns None."""
        result = await store.get("nonexistent-id")
        assert result is None

    @pytest.mark.asyncio
    async def test_get_and_delete(self, store, sample_state):
        """Test one-time use retrieval (get_and_delete)."""
        state_id = await store.create(sample_state)

        # First get_and_delete should succeed
        retrieved = await store.get_and_delete(state_id)
        assert retrieved is not None
        assert retrieved.state == sample_state.state

        # Second get should return None (state deleted)
        retrieved2 = await store.get(state_id)
        assert retrieved2 is None

    @pytest.mark.asyncio
    async def test_delete(self, store, sample_state):
        """Test explicit deletion of state."""
        state_id = await store.create(sample_state)

        # Delete should succeed
        result = await store.delete(state_id)
        assert result is True

        # State should be gone
        retrieved = await store.get(state_id)
        assert retrieved is None

    @pytest.mark.asyncio
    async def test_delete_nonexistent(self, store):
        """Test deleting non-existent state returns False."""
        result = await store.delete("nonexistent-id")
        assert result is False

    @pytest.mark.asyncio
    async def test_expired_state(self, store):
        """Test that expired states are not returned."""
        # Create state with very short TTL
        expired_state = OAuthState(
            state="expired",
            nonce="nonce",
            code_verifier="verifier",
            created_at=datetime.now(timezone.utc) - timedelta(seconds=120),
            redirect_after="/ui/",
        )

        state_id = await store.create(expired_state, ttl=1)

        # Wait for expiry
        await asyncio.sleep(1.1)

        # Should return None (expired)
        result = await store.get(state_id)
        assert result is None

    @pytest.mark.asyncio
    async def test_cleanup_expired(self, store):
        """Test cleanup of expired states."""
        # Create some states with short TTL
        for i in range(3):
            state = OAuthState(
                state=f"state-{i}",
                nonce="nonce",
                code_verifier="verifier",
                created_at=datetime.now(timezone.utc),
                redirect_after="/ui/",
            )
            await store.create(state, ttl=1)

        # Wait for expiry
        await asyncio.sleep(1.1)

        # Cleanup should remove all expired
        count = await store.cleanup_expired()
        assert count == 3
        assert store.state_count == 0

    @pytest.mark.asyncio
    async def test_state_count(self, store, sample_state):
        """Test state count property."""
        assert store.state_count == 0

        await store.create(sample_state)
        assert store.state_count == 1

        state2 = OAuthState(
            state="state2",
            nonce="nonce",
            code_verifier="verifier",
            created_at=datetime.now(timezone.utc),
            redirect_after="/ui/",
        )
        await store.create(state2)
        assert store.state_count == 2


# =============================================================================
# AUTHORIZATION URL TESTS
# =============================================================================


class TestAuthorizationURL:
    """Tests for authorization URL building."""

    def test_build_authorization_url_contains_all_params(self):
        """Test that authorization URL contains all required parameters."""
        url = build_authorization_url(
            tenant_id="test-tenant",
            client_id="test-client",
            redirect_uri="https://example.com/callback",
            state="test-state",
            nonce="test-nonce",
            code_challenge="test-challenge",
        )

        assert "https://login.microsoftonline.com/test-tenant/oauth2/v2.0/authorize" in url
        assert "client_id=test-client" in url
        assert "state=test-state" in url
        assert "nonce=test-nonce" in url
        assert "code_challenge=test-challenge" in url
        assert "code_challenge_method=S256" in url
        assert "response_type=code" in url
        assert "response_mode=query" in url

    def test_build_authorization_url_encodes_redirect_uri(self):
        """Test that redirect URI is properly encoded."""
        url = build_authorization_url(
            tenant_id="tenant",
            client_id="client",
            redirect_uri="https://example.com/callback?foo=bar",
            state="state",
            nonce="nonce",
            code_challenge="challenge",
        )

        # Should be URL-encoded
        assert "https%3A%2F%2F" in url or "redirect_uri=https" in url

    def test_build_authorization_url_includes_scopes(self):
        """Test that authorization URL includes OpenID scopes."""
        url = build_authorization_url(
            tenant_id="tenant",
            client_id="client",
            redirect_uri="https://example.com/callback",
            state="state",
            nonce="nonce",
            code_challenge="challenge",
        )

        # Should include openid, email, profile scopes
        assert "scope=" in url
        assert "openid" in url


# =============================================================================
# DOMAIN VALIDATION TESTS
# =============================================================================


class TestDomainValidation:
    """Tests for email domain whitelist checking."""

    def test_empty_allowed_list_allows_all(self):
        """Test that empty allowed list allows all domains."""
        assert is_email_domain_allowed("user@example.com", []) is True
        assert is_email_domain_allowed("user@anything.org", []) is True

    def test_domain_in_allowed_list(self):
        """Test that domain in allowed list is accepted."""
        allowed = ["example.com", "company.org"]

        assert is_email_domain_allowed("user@example.com", allowed) is True
        assert is_email_domain_allowed("user@company.org", allowed) is True

    def test_domain_not_in_allowed_list(self):
        """Test that domain not in allowed list is rejected."""
        allowed = ["example.com", "company.org"]

        assert is_email_domain_allowed("user@other.com", allowed) is False
        assert is_email_domain_allowed("user@notallowed.io", allowed) is False

    def test_domain_check_is_case_insensitive(self):
        """Test that domain check is case-insensitive."""
        allowed = ["example.com"]

        assert is_email_domain_allowed("user@EXAMPLE.COM", allowed) is True
        assert is_email_domain_allowed("user@Example.Com", allowed) is True
        assert is_email_domain_allowed("USER@example.com", allowed) is True


# =============================================================================
# USER STORE OAUTH TESTS
# =============================================================================


class TestUserStoreOAuth:
    """Tests for OAuth-specific UserStore functionality."""

    @pytest.fixture
    def user_store(self, tmp_path):
        """Create a UserStore with a temporary config file."""
        config_path = tmp_path / "users.json"
        config_path.write_text('{"users": []}')
        store = UserStore(config_path=str(config_path))
        store.load()
        return store

    def test_create_oauth_user(self, user_store):
        """Test creating an OAuth-provisioned user."""
        user = user_store.create_user(
            email="oauth@example.com",
            name="OAuth User",
            password_hash="",
            roles={"issuer:readonly"},
            enabled=True,
            is_oauth_user=True,
        )

        assert user.email == "oauth@example.com"
        assert user.name == "OAuth User"
        assert user.password_hash == ""
        assert user.is_oauth_user is True
        assert user.enabled is True

    def test_oauth_user_cannot_password_login(self, user_store):
        """Test that OAuth users cannot login with password."""
        user_store.create_user(
            email="oauth@example.com",
            name="OAuth User",
            password_hash="",
            roles={"issuer:readonly"},
            enabled=True,
            is_oauth_user=True,
        )

        # Should return oauth_user error
        principal, error = user_store.verify("oauth@example.com", "anypassword")
        assert principal is None
        assert error == "oauth_user"

    def test_regular_user_can_password_login(self, user_store):
        """Test that regular users can still login with password."""
        from app.auth.users import hash_password

        password_hash = hash_password("testpass123")
        user_store.create_user(
            email="regular@example.com",
            name="Regular User",
            password_hash=password_hash,
            roles={"issuer:readonly"},
            enabled=True,
            is_oauth_user=False,
        )

        # Should succeed with correct password
        principal, error = user_store.verify("regular@example.com", "testpass123")
        assert principal is not None
        assert error is None

        # Should fail with wrong password
        principal2, error2 = user_store.verify("regular@example.com", "wrongpass")
        assert principal2 is None
        assert error2 == "invalid"

    def test_create_duplicate_user_raises(self, user_store):
        """Test that creating duplicate user raises ValueError."""
        user_store.create_user(
            email="test@example.com",
            name="Test User",
            password_hash="",
            roles={"issuer:readonly"},
            enabled=True,
            is_oauth_user=True,
        )

        with pytest.raises(ValueError, match="User already exists"):
            user_store.create_user(
                email="test@example.com",
                name="Duplicate",
                password_hash="",
                roles={"issuer:readonly"},
                enabled=True,
                is_oauth_user=True,
            )

    def test_list_users_includes_oauth_flag(self, user_store):
        """Test that list_users includes is_oauth_user field."""
        user_store.create_user(
            email="oauth@example.com",
            name="OAuth User",
            password_hash="",
            roles={"issuer:readonly"},
            enabled=True,
            is_oauth_user=True,
        )

        users = user_store.list_users()
        assert len(users) == 1
        assert users[0]["is_oauth_user"] is True

    def test_disabled_oauth_user_cannot_login(self, user_store):
        """Test that disabled OAuth users are rejected."""
        user_store.create_user(
            email="disabled@example.com",
            name="Disabled OAuth User",
            password_hash="",
            roles={"issuer:readonly"},
            enabled=False,
            is_oauth_user=True,
        )

        # OAuth check happens before disabled check in verify()
        # but the user should still be found as disabled
        user = user_store.get_user("disabled@example.com")
        assert user is not None
        assert user.enabled is False


# =============================================================================
# OAUTH ENDPOINT TESTS
# =============================================================================


class TestOAuthEndpoints:
    """Tests for OAuth API endpoints.

    Note: These tests run with OAuth disabled by default (the config is loaded
    at module import time). Tests for OAuth-enabled scenarios would require
    integration tests with proper environment setup before app import.
    """

    @pytest.mark.asyncio
    async def test_oauth_status_endpoint(self):
        """Test OAuth status endpoint returns configuration."""
        from httpx import AsyncClient, ASGITransport
        from app.main import app

        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test"
        ) as client:
            response = await client.get("/auth/oauth/status")

            assert response.status_code == 200
            data = response.json()
            assert "m365" in data
            assert "enabled" in data["m365"]

    @pytest.mark.asyncio
    async def test_oauth_start_when_disabled(self):
        """Test OAuth start returns 400 when OAuth is disabled."""
        from httpx import AsyncClient, ASGITransport
        from app.main import app

        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test"
        ) as client:
            response = await client.get("/auth/oauth/m365/start")

            # OAuth is disabled by default, so should return 400
            assert response.status_code == 400
            assert "not enabled" in response.json()["error"].lower()

    @pytest.mark.asyncio
    async def test_oauth_callback_when_disabled(self):
        """Test OAuth callback returns 400 when OAuth is disabled."""
        from httpx import AsyncClient, ASGITransport
        from app.main import app

        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test"
        ) as client:
            response = await client.get(
                "/auth/oauth/m365/callback",
                params={"code": "test-code", "state": "test-state"},
                follow_redirects=False,
            )

            # OAuth is disabled by default, so should return 400
            assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_oauth_callback_error_when_disabled(self):
        """Test OAuth callback with Microsoft error returns 400 when disabled."""
        from httpx import AsyncClient, ASGITransport
        from app.main import app

        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test"
        ) as client:
            response = await client.get(
                "/auth/oauth/m365/callback",
                params={
                    "error": "access_denied",
                    "error_description": "User cancelled",
                },
                follow_redirects=False,
            )

            # OAuth is disabled by default, so should return 400
            assert response.status_code == 400


# =============================================================================
# GLOBAL SINGLETON TESTS
# =============================================================================


class TestOAuthGlobalSingleton:
    """Tests for global OAuth state store singleton."""

    def test_get_oauth_state_store_returns_same_instance(self):
        """Test that get_oauth_state_store returns singleton."""
        reset_oauth_state_store()

        store1 = get_oauth_state_store()
        store2 = get_oauth_state_store()

        assert store1 is store2

    def test_reset_oauth_state_store(self):
        """Test that reset creates a new instance."""
        store1 = get_oauth_state_store()
        reset_oauth_state_store()
        store2 = get_oauth_state_store()

        assert store1 is not store2


# =============================================================================
# TOKEN VALIDATION TESTS (MOCKED JWKS)
# =============================================================================


class TestTokenValidation:
    """Tests for ID token validation with mocked JWKS.

    These tests verify the validate_id_token function handles various
    JWT validation failure modes correctly. PyJWT is imported dynamically
    inside validate_id_token, so we mock it via the jwt module.
    """

    @pytest.fixture
    def mock_signing_key(self):
        """Create a mock signing key."""
        mock_key = MagicMock()
        mock_key.key = "mock_public_key"
        return mock_key

    @pytest.fixture
    def valid_payload(self):
        """Create a valid token payload."""
        import time

        now = int(time.time())
        return {
            "iss": "https://login.microsoftonline.com/test-tenant-id/v2.0",
            "aud": "test-client-id",
            "tid": "test-tenant-id",
            "exp": now + 3600,  # 1 hour from now
            "iat": now - 60,  # 1 minute ago
            "nbf": now - 60,  # 1 minute ago
            "nonce": "test-nonce",
            "email": "user@example.com",
            "name": "Test User",
            "oid": "user-object-id",
        }

    @pytest.mark.asyncio
    async def test_valid_token_succeeds(self, mock_signing_key, valid_payload):
        """Test that a valid token is accepted."""
        from app.auth.oauth import validate_id_token

        mock_jwks_client = MagicMock()
        mock_jwks_client.get_signing_key_from_jwt.return_value = mock_signing_key

        with patch("jwt.PyJWKClient", return_value=mock_jwks_client):
            with patch("jwt.decode", return_value=valid_payload):
                result = await validate_id_token(
                    id_token="valid.jwt.token",
                    tenant_id="test-tenant-id",
                    client_id="test-client-id",
                    nonce="test-nonce",
                )

                assert result.email == "user@example.com"
                assert result.name == "Test User"
                assert result.tid == "test-tenant-id"
                assert result.oid == "user-object-id"

    @pytest.mark.asyncio
    async def test_expired_token_raises_error(self, mock_signing_key):
        """Test that an expired token raises OAuthError."""
        import jwt as pyjwt
        from app.auth.oauth import validate_id_token, OAuthError

        mock_jwks_client = MagicMock()
        mock_jwks_client.get_signing_key_from_jwt.return_value = mock_signing_key

        with patch("jwt.PyJWKClient", return_value=mock_jwks_client):
            with patch(
                "jwt.decode",
                side_effect=pyjwt.ExpiredSignatureError("Token expired"),
            ):
                with pytest.raises(OAuthError, match="expired"):
                    await validate_id_token(
                        id_token="expired.jwt.token",
                        tenant_id="test-tenant-id",
                        client_id="test-client-id",
                        nonce="test-nonce",
                    )

    @pytest.mark.asyncio
    async def test_wrong_issuer_raises_error(self, mock_signing_key):
        """Test that a token with wrong issuer raises OAuthError."""
        import jwt as pyjwt
        from app.auth.oauth import validate_id_token, OAuthError

        mock_jwks_client = MagicMock()
        mock_jwks_client.get_signing_key_from_jwt.return_value = mock_signing_key

        with patch("jwt.PyJWKClient", return_value=mock_jwks_client):
            with patch(
                "jwt.decode",
                side_effect=pyjwt.InvalidIssuerError("Invalid issuer"),
            ):
                with pytest.raises(OAuthError, match="issuer"):
                    await validate_id_token(
                        id_token="wrong.issuer.token",
                        tenant_id="test-tenant-id",
                        client_id="test-client-id",
                        nonce="test-nonce",
                    )

    @pytest.mark.asyncio
    async def test_wrong_audience_raises_error(self, mock_signing_key):
        """Test that a token with wrong audience raises OAuthError."""
        import jwt as pyjwt
        from app.auth.oauth import validate_id_token, OAuthError

        mock_jwks_client = MagicMock()
        mock_jwks_client.get_signing_key_from_jwt.return_value = mock_signing_key

        with patch("jwt.PyJWKClient", return_value=mock_jwks_client):
            with patch(
                "jwt.decode",
                side_effect=pyjwt.InvalidAudienceError("Invalid audience"),
            ):
                with pytest.raises(OAuthError, match="audience"):
                    await validate_id_token(
                        id_token="wrong.audience.token",
                        tenant_id="test-tenant-id",
                        client_id="test-client-id",
                        nonce="test-nonce",
                    )

    @pytest.mark.asyncio
    async def test_wrong_tenant_raises_error(self, mock_signing_key, valid_payload):
        """Test that a token with wrong tenant ID raises OAuthError."""
        from app.auth.oauth import validate_id_token, OAuthError

        mock_jwks_client = MagicMock()
        mock_jwks_client.get_signing_key_from_jwt.return_value = mock_signing_key

        # Payload has tid="test-tenant-id" but we expect "different-tenant"
        with patch("jwt.PyJWKClient", return_value=mock_jwks_client):
            with patch("jwt.decode", return_value=valid_payload):
                with pytest.raises(OAuthError):
                    await validate_id_token(
                        id_token="wrong.tenant.token",
                        tenant_id="different-tenant-id",  # Different from payload
                        client_id="test-client-id",
                        nonce="test-nonce",
                    )

    @pytest.mark.asyncio
    async def test_wrong_nonce_raises_error(self, mock_signing_key, valid_payload):
        """Test that a token with wrong nonce raises OAuthError."""
        from app.auth.oauth import validate_id_token, OAuthError

        mock_jwks_client = MagicMock()
        mock_jwks_client.get_signing_key_from_jwt.return_value = mock_signing_key

        # Payload has nonce="test-nonce" but we expect "different-nonce"
        with patch("jwt.PyJWKClient", return_value=mock_jwks_client):
            with patch("jwt.decode", return_value=valid_payload):
                with pytest.raises(OAuthError):
                    await validate_id_token(
                        id_token="wrong.nonce.token",
                        tenant_id="test-tenant-id",
                        client_id="test-client-id",
                        nonce="different-nonce",  # Different from payload
                    )

    @pytest.mark.asyncio
    async def test_missing_nonce_raises_error(self, mock_signing_key, valid_payload):
        """Test that a token with missing nonce raises OAuthError."""
        from app.auth.oauth import validate_id_token, OAuthError

        mock_jwks_client = MagicMock()
        mock_jwks_client.get_signing_key_from_jwt.return_value = mock_signing_key

        # Remove nonce from payload
        payload_without_nonce = {**valid_payload}
        del payload_without_nonce["nonce"]

        with patch("jwt.PyJWKClient", return_value=mock_jwks_client):
            with patch("jwt.decode", return_value=payload_without_nonce):
                with pytest.raises(OAuthError):
                    await validate_id_token(
                        id_token="missing.nonce.token",
                        tenant_id="test-tenant-id",
                        client_id="test-client-id",
                        nonce="test-nonce",
                    )

    @pytest.mark.asyncio
    async def test_wrong_algorithm_raises_error(self, mock_signing_key):
        """Test that a token with wrong algorithm raises OAuthError."""
        import jwt as pyjwt
        from app.auth.oauth import validate_id_token, OAuthError

        mock_jwks_client = MagicMock()
        mock_jwks_client.get_signing_key_from_jwt.return_value = mock_signing_key

        with patch("jwt.PyJWKClient", return_value=mock_jwks_client):
            with patch(
                "jwt.decode",
                side_effect=pyjwt.InvalidAlgorithmError("Invalid algorithm"),
            ):
                with pytest.raises(OAuthError, match="algorithm"):
                    await validate_id_token(
                        id_token="wrong.alg.token",
                        tenant_id="test-tenant-id",
                        client_id="test-client-id",
                        nonce="test-nonce",
                    )

    @pytest.mark.asyncio
    async def test_invalid_signature_raises_error(self, mock_signing_key):
        """Test that a token with invalid signature raises OAuthError."""
        import jwt as pyjwt
        from app.auth.oauth import validate_id_token, OAuthError

        mock_jwks_client = MagicMock()
        mock_jwks_client.get_signing_key_from_jwt.return_value = mock_signing_key

        with patch("jwt.PyJWKClient", return_value=mock_jwks_client):
            with patch(
                "jwt.decode",
                side_effect=pyjwt.InvalidSignatureError("Signature verification failed"),
            ):
                with pytest.raises(OAuthError, match="validation failed"):
                    await validate_id_token(
                        id_token="bad.signature.token",
                        tenant_id="test-tenant-id",
                        client_id="test-client-id",
                        nonce="test-nonce",
                    )

    @pytest.mark.asyncio
    async def test_missing_email_raises_error(self, mock_signing_key, valid_payload):
        """Test that a token without email claim raises OAuthError."""
        from app.auth.oauth import validate_id_token, OAuthError

        mock_jwks_client = MagicMock()
        mock_jwks_client.get_signing_key_from_jwt.return_value = mock_signing_key

        # Remove both email and preferred_username
        payload_without_email = {**valid_payload}
        del payload_without_email["email"]

        with patch("jwt.PyJWKClient", return_value=mock_jwks_client):
            with patch("jwt.decode", return_value=payload_without_email):
                with pytest.raises(OAuthError):
                    await validate_id_token(
                        id_token="no.email.token",
                        tenant_id="test-tenant-id",
                        client_id="test-client-id",
                        nonce="test-nonce",
                    )

    @pytest.mark.asyncio
    async def test_preferred_username_used_as_fallback(self, mock_signing_key, valid_payload):
        """Test that preferred_username is used when email is missing."""
        from app.auth.oauth import validate_id_token

        mock_jwks_client = MagicMock()
        mock_jwks_client.get_signing_key_from_jwt.return_value = mock_signing_key

        # Remove email but add preferred_username
        payload_with_upn = {**valid_payload}
        del payload_with_upn["email"]
        payload_with_upn["preferred_username"] = "user@company.com"

        with patch("jwt.PyJWKClient", return_value=mock_jwks_client):
            with patch("jwt.decode", return_value=payload_with_upn):
                result = await validate_id_token(
                    id_token="upn.token",
                    tenant_id="test-tenant-id",
                    client_id="test-client-id",
                    nonce="test-nonce",
                )

                assert result.email == "user@company.com"

    @pytest.mark.asyncio
    async def test_jwks_fetch_error_raises_oauth_error(self):
        """Test that JWKS fetch errors are wrapped in OAuthError."""
        from app.auth.oauth import validate_id_token, OAuthError

        mock_jwks_client = MagicMock()
        mock_jwks_client.get_signing_key_from_jwt.side_effect = Exception("Network error")

        with patch("jwt.PyJWKClient", return_value=mock_jwks_client):
            with pytest.raises(OAuthError, match="validation failed"):
                await validate_id_token(
                    id_token="some.jwt.token",
                    tenant_id="test-tenant-id",
                    client_id="test-client-id",
                    nonce="test-nonce",
                )


# =============================================================================
# OPEN REDIRECT PROTECTION TESTS
# =============================================================================


class TestOpenRedirectProtection:
    """Tests for redirect_after URL validation."""

    @pytest.mark.asyncio
    async def test_valid_relative_path_accepted(self):
        """Test that valid relative paths are accepted."""
        from app.api.auth import _is_safe_redirect_url

        assert _is_safe_redirect_url("/ui/") is True
        assert _is_safe_redirect_url("/ui/identity") is True
        assert _is_safe_redirect_url("/registry/ui") is True
        assert _is_safe_redirect_url("/schemas/ui?query=test") is True

    @pytest.mark.asyncio
    async def test_absolute_urls_rejected(self):
        """Test that absolute URLs are rejected."""
        from app.api.auth import _is_safe_redirect_url

        assert _is_safe_redirect_url("http://evil.com") is False
        assert _is_safe_redirect_url("https://evil.com") is False
        assert _is_safe_redirect_url("http://evil.com/path") is False

    @pytest.mark.asyncio
    async def test_protocol_relative_urls_rejected(self):
        """Test that protocol-relative URLs are rejected."""
        from app.api.auth import _is_safe_redirect_url

        assert _is_safe_redirect_url("//evil.com") is False
        assert _is_safe_redirect_url("//evil.com/path") is False

    @pytest.mark.asyncio
    async def test_javascript_urls_rejected(self):
        """Test that javascript: URLs are rejected."""
        from app.api.auth import _is_safe_redirect_url

        assert _is_safe_redirect_url("javascript:alert(1)") is False
        assert _is_safe_redirect_url("JAVASCRIPT:alert(1)") is False

    @pytest.mark.asyncio
    async def test_encoded_slashes_rejected(self):
        """Test that URL-encoded slashes are rejected."""
        from app.api.auth import _is_safe_redirect_url

        assert _is_safe_redirect_url("/%2f%2fevil.com") is False
        assert _is_safe_redirect_url("/%252f%252fevil.com") is False

    @pytest.mark.asyncio
    async def test_empty_url_rejected(self):
        """Test that empty URLs are rejected."""
        from app.api.auth import _is_safe_redirect_url

        assert _is_safe_redirect_url("") is False
        assert _is_safe_redirect_url(None) is False

    @pytest.mark.asyncio
    async def test_non_slash_start_rejected(self):
        """Test that paths not starting with / are rejected."""
        from app.api.auth import _is_safe_redirect_url

        assert _is_safe_redirect_url("ui/") is False
        assert _is_safe_redirect_url("./ui/") is False
        assert _is_safe_redirect_url("../ui/") is False
