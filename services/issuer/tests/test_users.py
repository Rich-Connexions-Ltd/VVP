"""Tests for user authentication in VVP Issuer.

Tests cover:
- UserStore operations (load, verify, get_user, list_users)
- Email/password login via /auth/login endpoint
- User management endpoints (/admin/users CRUD)
- Session handling for user-authenticated sessions
"""

import asyncio
import json
import os
import tempfile
from pathlib import Path

import pytest
from httpx import AsyncClient

from app.auth.api_key import Principal, reset_api_key_store
from app.auth.users import (
    UserStore,
    UserConfig,
    hash_password,
    get_user_store,
    reset_user_store,
)
from app.auth.session import reset_session_store, reset_rate_limiter
from tests.conftest import (
    TEST_ADMIN_KEY,
    get_test_api_keys_config,
)


# =============================================================================
# Test fixtures
# =============================================================================


def get_test_users_config():
    """Generate test users configuration."""
    return {
        "users": [
            {
                "email": "admin@test.com",
                "name": "Admin User",
                "password_hash": hash_password("adminpass"),
                "roles": ["issuer:admin", "issuer:operator", "issuer:readonly"],
                "enabled": True,
            },
            {
                "email": "readonly@test.com",
                "name": "Readonly User",
                "password_hash": hash_password("readonlypass"),
                "roles": ["issuer:readonly"],
                "enabled": True,
            },
            {
                "email": "disabled@test.com",
                "name": "Disabled User",
                "password_hash": hash_password("disabledpass"),
                "roles": ["issuer:readonly"],
                "enabled": False,
            },
        ]
    }


@pytest.fixture
def users_config_file():
    """Create a temporary users config file."""
    config = get_test_users_config()

    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(config, f)
        f.flush()
        yield f.name

    # Cleanup
    Path(f.name).unlink(missing_ok=True)


@pytest.fixture
def user_store(users_config_file) -> UserStore:
    """Create a user store with test configuration."""
    store = UserStore(config_path=users_config_file)
    store.load()
    return store


# =============================================================================
# UserStore Tests
# =============================================================================


class TestUserStore:
    """Tests for UserStore."""

    def test_load_users_from_file(self, user_store: UserStore):
        """Test loading users from config file."""
        assert user_store.user_count == 3

    def test_verify_valid_credentials(self, user_store: UserStore):
        """Test verifying valid email/password."""
        principal, error = user_store.verify("admin@test.com", "adminpass")

        assert principal is not None
        assert error is None
        assert principal.key_id == "user:admin@test.com"
        assert principal.name == "Admin User"
        assert "issuer:admin" in principal.roles

    def test_verify_invalid_password(self, user_store: UserStore):
        """Test verifying with wrong password returns None."""
        principal, error = user_store.verify("admin@test.com", "wrongpass")

        assert principal is None
        assert error == "invalid"

    def test_verify_invalid_email(self, user_store: UserStore):
        """Test verifying with unknown email returns None."""
        principal, error = user_store.verify("unknown@test.com", "somepass")

        assert principal is None
        assert error == "invalid"

    def test_verify_disabled_user(self, user_store: UserStore):
        """Test verifying disabled user returns None with 'disabled' error."""
        principal, error = user_store.verify("disabled@test.com", "disabledpass")

        assert principal is None
        assert error == "disabled"

    def test_verify_case_insensitive_email(self, user_store: UserStore):
        """Test email verification is case-insensitive."""
        principal, error = user_store.verify("ADMIN@TEST.COM", "adminpass")

        assert principal is not None
        assert principal.key_id == "user:admin@test.com"

    def test_get_user(self, user_store: UserStore):
        """Test getting user by email."""
        user = user_store.get_user("admin@test.com")

        assert user is not None
        assert user.email == "admin@test.com"
        assert user.name == "Admin User"

    def test_get_user_not_found(self, user_store: UserStore):
        """Test getting non-existent user returns None."""
        user = user_store.get_user("nonexistent@test.com")
        assert user is None

    def test_list_users(self, user_store: UserStore):
        """Test listing all users."""
        users = user_store.list_users()

        assert len(users) == 3
        # Verify password hashes are not included
        for user in users:
            assert "password_hash" not in user
            assert "email" in user
            assert "name" in user
            assert "roles" in user
            assert "enabled" in user

    def test_load_from_inline_json(self):
        """Test loading users from inline JSON config."""
        config = json.dumps(get_test_users_config())
        store = UserStore(config_json=config)
        store.load()

        assert store.user_count == 3

    def test_reload_users(self, users_config_file):
        """Test reloading users from file."""
        store = UserStore(config_path=users_config_file)
        store.load()
        assert store.user_count == 3

        # Reload should succeed
        success = store.reload()
        assert success is True
        assert store.user_count == 3


class TestHashPassword:
    """Tests for password hashing."""

    def test_hash_password_returns_bcrypt(self):
        """Test that hash_password returns a bcrypt hash."""
        password_hash = hash_password("testpassword")

        # bcrypt hashes start with $2b$
        assert password_hash.startswith("$2b$")
        # bcrypt hashes are typically 60 characters
        assert len(password_hash) == 60

    def test_hash_password_different_each_time(self):
        """Test that hashing same password gives different hashes (due to salt)."""
        hash1 = hash_password("testpassword")
        hash2 = hash_password("testpassword")

        assert hash1 != hash2


# =============================================================================
# User Login Endpoint Tests
# =============================================================================


class TestUserLoginEndpoint:
    """Tests for email/password login via /auth/login."""

    @pytest.fixture(autouse=True)
    def setup_stores(self, users_config_file):
        """Set up API key and user stores for tests."""
        import importlib

        # Set up test API keys
        original_api_keys = os.environ.get("VVP_API_KEYS")
        os.environ["VVP_API_KEYS"] = json.dumps(get_test_api_keys_config())

        # Set up test users
        original_users = os.environ.get("VVP_USERS")
        os.environ["VVP_USERS"] = json.dumps(get_test_users_config())

        # Reset all stores
        reset_api_key_store()
        reset_user_store()
        reset_session_store()
        reset_rate_limiter()

        # Reload config module
        import app.config as config_module
        importlib.reload(config_module)

        yield

        # Cleanup
        reset_api_key_store()
        reset_user_store()
        reset_session_store()
        reset_rate_limiter()

        if original_api_keys is not None:
            os.environ["VVP_API_KEYS"] = original_api_keys
        elif "VVP_API_KEYS" in os.environ:
            del os.environ["VVP_API_KEYS"]

        if original_users is not None:
            os.environ["VVP_USERS"] = original_users
        elif "VVP_USERS" in os.environ:
            del os.environ["VVP_USERS"]

        importlib.reload(config_module)

    @pytest.mark.asyncio
    async def test_login_with_valid_credentials(self, client_with_auth: AsyncClient):
        """Test login with valid email/password returns 200 and session cookie."""
        response = await client_with_auth.post(
            "/auth/login",
            json={"email": "admin@test.com", "password": "adminpass"},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["key_id"] == "user:admin@test.com"
        assert data["name"] == "Admin User"
        assert "issuer:admin" in data["roles"]
        assert "vvp_session" in response.cookies

    @pytest.mark.asyncio
    async def test_login_with_invalid_password(self, client_with_auth: AsyncClient):
        """Test login with wrong password returns 401."""
        response = await client_with_auth.post(
            "/auth/login",
            json={"email": "admin@test.com", "password": "wrongpass"},
        )

        assert response.status_code == 401
        data = response.json()
        assert data["success"] is False

    @pytest.mark.asyncio
    async def test_login_with_disabled_user(self, client_with_auth: AsyncClient):
        """Test login with disabled user returns 401."""
        response = await client_with_auth.post(
            "/auth/login",
            json={"email": "disabled@test.com", "password": "disabledpass"},
        )

        assert response.status_code == 401
        data = response.json()
        assert data["success"] is False

    @pytest.mark.asyncio
    async def test_login_missing_credentials(self, client_with_auth: AsyncClient):
        """Test login without credentials returns 400."""
        response = await client_with_auth.post(
            "/auth/login",
            json={},
        )

        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_login_with_api_key_still_works(self, client_with_auth: AsyncClient):
        """Test that API key login still works alongside user login."""
        response = await client_with_auth.post(
            "/auth/login",
            json={"api_key": TEST_ADMIN_KEY},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["key_id"] == "test-admin"


# =============================================================================
# User Session Tests
# =============================================================================


class TestUserSession:
    """Tests for user-authenticated sessions."""

    @pytest.fixture(autouse=True)
    def setup_stores(self):
        """Set up stores for tests."""
        import importlib

        # Set up test config
        original_api_keys = os.environ.get("VVP_API_KEYS")
        os.environ["VVP_API_KEYS"] = json.dumps(get_test_api_keys_config())

        original_users = os.environ.get("VVP_USERS")
        os.environ["VVP_USERS"] = json.dumps(get_test_users_config())

        reset_api_key_store()
        reset_user_store()
        reset_session_store()
        reset_rate_limiter()

        import app.config as config_module
        importlib.reload(config_module)

        yield

        reset_api_key_store()
        reset_user_store()
        reset_session_store()
        reset_rate_limiter()

        if original_api_keys is not None:
            os.environ["VVP_API_KEYS"] = original_api_keys
        elif "VVP_API_KEYS" in os.environ:
            del os.environ["VVP_API_KEYS"]

        if original_users is not None:
            os.environ["VVP_USERS"] = original_users
        elif "VVP_USERS" in os.environ:
            del os.environ["VVP_USERS"]

        importlib.reload(config_module)

    @pytest.mark.asyncio
    async def test_user_session_invalidated_when_disabled(self, client_with_auth: AsyncClient):
        """Test that user session is invalidated when user is disabled."""
        # Login first
        login_response = await client_with_auth.post(
            "/auth/login",
            json={"email": "admin@test.com", "password": "adminpass"},
        )
        assert login_response.status_code == 200

        # Session should work
        client_with_auth.cookies.set("vvp_session", login_response.cookies.get("vvp_session"))

        status_response = await client_with_auth.get("/auth/status")
        assert status_response.status_code == 200
        data = status_response.json()
        assert data["authenticated"] is True

        # Now disable the user in the store
        user_store = get_user_store()
        user = user_store.get_user("admin@test.com")
        user.enabled = False

        # Session should be invalidated on next request
        # The auth status endpoint shows the session is no longer valid
        status_response = await client_with_auth.get("/auth/status")
        data = status_response.json()
        # The session should have been invalidated
        assert data["authenticated"] is False


# =============================================================================
# User Management Endpoint Tests
# =============================================================================


class TestUserManagementEndpoints:
    """Tests for /admin/users endpoints."""

    @pytest.fixture(autouse=True)
    def setup_stores(self, tmp_path):
        """Set up stores for tests."""
        import importlib

        # Create temp config files
        self.users_file = tmp_path / "users.json"
        self.users_file.write_text(json.dumps(get_test_users_config()))

        original_api_keys = os.environ.get("VVP_API_KEYS")
        os.environ["VVP_API_KEYS"] = json.dumps(get_test_api_keys_config())

        original_users_file = os.environ.get("VVP_USERS_FILE")
        os.environ["VVP_USERS_FILE"] = str(self.users_file)

        # Clear inline JSON override
        original_users_json = os.environ.get("VVP_USERS")
        if "VVP_USERS" in os.environ:
            del os.environ["VVP_USERS"]

        reset_api_key_store()
        reset_user_store()
        reset_session_store()
        reset_rate_limiter()

        import app.config as config_module
        importlib.reload(config_module)

        yield

        reset_api_key_store()
        reset_user_store()
        reset_session_store()
        reset_rate_limiter()

        if original_api_keys is not None:
            os.environ["VVP_API_KEYS"] = original_api_keys
        elif "VVP_API_KEYS" in os.environ:
            del os.environ["VVP_API_KEYS"]

        if original_users_file is not None:
            os.environ["VVP_USERS_FILE"] = original_users_file
        elif "VVP_USERS_FILE" in os.environ:
            del os.environ["VVP_USERS_FILE"]

        if original_users_json is not None:
            os.environ["VVP_USERS"] = original_users_json

        importlib.reload(config_module)

    @pytest.mark.asyncio
    async def test_list_users_requires_admin(self, client_with_auth: AsyncClient, readonly_headers: dict):
        """Test that listing users requires admin role."""
        response = await client_with_auth.get(
            "/admin/users",
            headers=readonly_headers,
        )

        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_list_users_as_admin(self, client_with_auth: AsyncClient, admin_headers: dict):
        """Test listing users as admin."""
        response = await client_with_auth.get(
            "/admin/users",
            headers=admin_headers,
        )

        assert response.status_code == 200
        data = response.json()
        assert data["count"] == 3
        assert len(data["users"]) == 3

    @pytest.mark.asyncio
    async def test_create_user(self, client_with_auth: AsyncClient, admin_headers: dict):
        """Test creating a new user."""
        response = await client_with_auth.post(
            "/admin/users",
            json={
                "email": "newuser@test.com",
                "name": "New User",
                "password": "newpass",
                "roles": ["issuer:readonly"],
            },
            headers=admin_headers,
        )

        assert response.status_code == 200
        data = response.json()
        assert data["email"] == "newuser@test.com"
        assert data["name"] == "New User"
        assert data["enabled"] is True

    @pytest.mark.asyncio
    async def test_create_duplicate_user_fails(self, client_with_auth: AsyncClient, admin_headers: dict):
        """Test creating a duplicate user fails."""
        response = await client_with_auth.post(
            "/admin/users",
            json={
                "email": "admin@test.com",  # Already exists
                "name": "Duplicate",
                "password": "somepass",
            },
            headers=admin_headers,
        )

        assert response.status_code == 409

    @pytest.mark.asyncio
    async def test_update_user(self, client_with_auth: AsyncClient, admin_headers: dict):
        """Test updating a user."""
        response = await client_with_auth.patch(
            "/admin/users/readonly@test.com",
            json={
                "name": "Updated Name",
                "enabled": False,
            },
            headers=admin_headers,
        )

        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "Updated Name"
        assert data["enabled"] is False

    @pytest.mark.asyncio
    async def test_delete_user(self, client_with_auth: AsyncClient, admin_headers: dict):
        """Test deleting a user."""
        response = await client_with_auth.delete(
            "/admin/users/readonly@test.com",
            headers=admin_headers,
        )

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True

    @pytest.mark.asyncio
    async def test_delete_nonexistent_user(self, client_with_auth: AsyncClient, admin_headers: dict):
        """Test deleting a non-existent user fails."""
        response = await client_with_auth.delete(
            "/admin/users/nonexistent@test.com",
            headers=admin_headers,
        )

        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_reload_users(self, client_with_auth: AsyncClient, admin_headers: dict):
        """Test reloading users from config file."""
        response = await client_with_auth.post(
            "/admin/users/reload",
            headers=admin_headers,
        )

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["user_count"] >= 0
