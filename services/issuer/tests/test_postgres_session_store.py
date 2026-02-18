"""Tests for PostgreSQL-backed session and OAuth state stores.

Sprint 73: Validates that PostgresSessionStore and PostgresOAuthStateStore
correctly persist sessions to the database, handle expiry, revocation,
org switching, and cleanup.

Uses SQLite in-memory for test isolation (same SQLAlchemy models).
"""

import asyncio
import json
import os
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.auth.api_key import Principal, reset_api_key_store
from app.auth.session import (
    PostgresSessionStore,
    reset_session_store,
)
from app.auth.oauth import (
    OAuthState,
    PostgresOAuthStateStore,
    reset_oauth_state_store,
)
from app.db.models import Base, DBSession, DBOAuthState
from tests.conftest import get_test_api_keys_config


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def test_engine():
    """Create an in-memory SQLite engine with all tables."""
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}
    )
    Base.metadata.create_all(bind=engine)
    return engine


@pytest.fixture
def test_session_factory(test_engine):
    """Create a session factory for the test database."""
    return sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


@pytest.fixture
def mock_db_session(test_session_factory):
    """Patch get_db_session to use the test database."""
    from contextlib import contextmanager

    @contextmanager
    def _get_db_session():
        db = test_session_factory()
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    with patch("app.db.session.get_db_session", _get_db_session):
        yield _get_db_session


@pytest.fixture
def principal():
    """Create a test principal."""
    return Principal(
        key_id="test-admin",
        name="Test User",
        roles={"issuer:admin", "issuer:operator"},
        organization_id="org-123",
    )


@pytest.fixture(autouse=True)
def setup_api_key_store():
    """Set up API key store for revocation checks during session.get()."""
    import importlib

    original_api_keys = os.environ.get("VVP_API_KEYS")
    os.environ["VVP_API_KEYS"] = json.dumps(get_test_api_keys_config())

    reset_api_key_store()
    reset_session_store()

    import app.config as config_module
    importlib.reload(config_module)

    from app.auth.api_key import get_api_key_store
    get_api_key_store()

    yield

    reset_api_key_store()
    reset_session_store()
    if original_api_keys is not None:
        os.environ["VVP_API_KEYS"] = original_api_keys
    elif "VVP_API_KEYS" in os.environ:
        del os.environ["VVP_API_KEYS"]
    importlib.reload(config_module)


# =============================================================================
# PostgresSessionStore Tests
# =============================================================================


class TestPostgresSessionStore:
    """Tests for PostgresSessionStore."""

    @pytest.fixture
    def store(self, mock_db_session):
        """Create a PostgresSessionStore with test DB."""
        return PostgresSessionStore()

    @pytest.mark.asyncio
    async def test_create_session(self, store, principal):
        """Test session creation persists to DB."""
        session = await store.create(principal, ttl_seconds=3600)

        assert session is not None
        assert session.session_id is not None
        assert len(session.session_id) > 20
        assert session.key_id == "test-admin"
        assert session.principal.key_id == "test-admin"
        assert session.principal.name == "Test User"
        assert session.principal.organization_id == "org-123"
        assert session.home_org_id == "org-123"
        assert not session.is_expired
        assert session.ttl_seconds > 0

    @pytest.mark.asyncio
    async def test_get_valid_session(self, store, principal):
        """Test retrieving a valid session from DB."""
        session = await store.create(principal, ttl_seconds=3600)
        retrieved = await store.get(session.session_id)

        assert retrieved is not None
        assert retrieved.session_id == session.session_id
        assert retrieved.key_id == "test-admin"
        assert retrieved.principal.name == "Test User"
        assert retrieved.principal.roles == {"issuer:admin", "issuer:operator"}

    @pytest.mark.asyncio
    async def test_get_nonexistent_session(self, store):
        """Test retrieving a nonexistent session returns None."""
        result = await store.get("nonexistent-session-id")
        assert result is None

    @pytest.mark.asyncio
    async def test_get_expired_session(self, store, principal):
        """Test that expired sessions return None and are cleaned up."""
        session = await store.create(principal, ttl_seconds=1)
        await asyncio.sleep(1.1)

        result = await store.get(session.session_id)
        assert result is None

    @pytest.mark.asyncio
    async def test_delete_session(self, store, principal):
        """Test session deletion."""
        session = await store.create(principal, ttl_seconds=3600)
        result = await store.delete(session.session_id)
        assert result is True

        retrieved = await store.get(session.session_id)
        assert retrieved is None

    @pytest.mark.asyncio
    async def test_delete_nonexistent_session(self, store):
        """Test deleting a nonexistent session returns False."""
        result = await store.delete("nonexistent-session-id")
        assert result is False

    @pytest.mark.asyncio
    async def test_delete_by_key_id(self, store, principal):
        """Test deleting all sessions for a key."""
        await store.create(principal, ttl_seconds=3600)
        await store.create(principal, ttl_seconds=3600)
        await store.create(principal, ttl_seconds=3600)

        other = Principal(key_id="test-operator", name="Other", roles=set())
        await store.create(other, ttl_seconds=3600)

        assert store.session_count == 4

        count = await store.delete_by_key_id("test-admin")
        assert count == 3
        assert store.session_count == 1

    @pytest.mark.asyncio
    async def test_cleanup_expired(self, store, principal):
        """Test cleanup removes only expired sessions."""
        await store.create(principal, ttl_seconds=1)
        long_session = await store.create(principal, ttl_seconds=3600)

        await asyncio.sleep(1.1)

        count = await store.cleanup_expired()
        assert count == 1
        assert store.session_count == 1

        retrieved = await store.get(long_session.session_id)
        assert retrieved is not None

    @pytest.mark.asyncio
    async def test_set_active_org(self, store, principal):
        """Test org context switching persists to DB."""
        session = await store.create(principal, ttl_seconds=3600)

        result = await store.set_active_org(session.session_id, "other-org-456")
        assert result is True

        retrieved = await store.get(session.session_id)
        assert retrieved is not None
        assert retrieved.active_org_id == "other-org-456"
        # Principal's org_id should be overridden
        assert retrieved.principal.organization_id == "other-org-456"

    @pytest.mark.asyncio
    async def test_set_active_org_revert(self, store, principal):
        """Test reverting org context switch."""
        session = await store.create(principal, ttl_seconds=3600)

        await store.set_active_org(session.session_id, "other-org-456")
        await store.set_active_org(session.session_id, None)

        retrieved = await store.get(session.session_id)
        assert retrieved is not None
        assert retrieved.active_org_id is None
        assert retrieved.principal.organization_id == "org-123"

    @pytest.mark.asyncio
    async def test_set_active_org_nonexistent(self, store):
        """Test setting active org on nonexistent session returns False."""
        result = await store.set_active_org("nonexistent", "org-123")
        assert result is False

    @pytest.mark.asyncio
    async def test_session_count(self, store, principal):
        """Test session_count property."""
        assert store.session_count == 0

        await store.create(principal, ttl_seconds=3600)
        assert store.session_count == 1

        await store.create(principal, ttl_seconds=3600)
        assert store.session_count == 2

    @pytest.mark.asyncio
    async def test_principal_roles_roundtrip(self, store):
        """Test that complex role sets survive serialization roundtrip."""
        principal = Principal(
            key_id="test-admin",
            name="Complex Roles User",
            roles={"issuer:admin", "issuer:operator", "issuer:readonly", "org:administrator"},
        )
        session = await store.create(principal, ttl_seconds=3600)
        retrieved = await store.get(session.session_id)

        assert retrieved is not None
        assert retrieved.principal.roles == {
            "issuer:admin", "issuer:operator", "issuer:readonly", "org:administrator"
        }

    @pytest.mark.asyncio
    async def test_empty_roles_roundtrip(self, store):
        """Test that empty roles survive serialization roundtrip."""
        principal = Principal(
            key_id="test-operator",
            name="No Roles",
            roles=set(),
        )
        session = await store.create(principal, ttl_seconds=3600)
        retrieved = await store.get(session.session_id)

        assert retrieved is not None
        assert retrieved.principal.roles == set()


# =============================================================================
# PostgresOAuthStateStore Tests
# =============================================================================


class TestPostgresOAuthStateStore:
    """Tests for PostgresOAuthStateStore."""

    @pytest.fixture
    def store(self, mock_db_session):
        """Create a PostgresOAuthStateStore with test DB."""
        return PostgresOAuthStateStore(default_ttl=600)

    @pytest.fixture
    def oauth_state(self):
        """Create a test OAuth state."""
        return OAuthState(
            state="test-csrf-state",
            nonce="test-nonce",
            code_verifier="test-code-verifier-string",
            created_at=datetime.now(timezone.utc),
            redirect_after="/ui/dashboard",
        )

    @pytest.mark.asyncio
    async def test_create_state(self, store, oauth_state):
        """Test OAuth state creation."""
        state_id = await store.create(oauth_state)

        assert state_id is not None
        assert len(state_id) > 20

    @pytest.mark.asyncio
    async def test_get_state(self, store, oauth_state):
        """Test retrieving OAuth state."""
        state_id = await store.create(oauth_state)
        retrieved = await store.get(state_id)

        assert retrieved is not None
        assert retrieved.state == "test-csrf-state"
        assert retrieved.nonce == "test-nonce"
        assert retrieved.code_verifier == "test-code-verifier-string"
        assert retrieved.redirect_after == "/ui/dashboard"

    @pytest.mark.asyncio
    async def test_get_nonexistent_state(self, store):
        """Test retrieving nonexistent state returns None."""
        result = await store.get("nonexistent-state-id")
        assert result is None

    @pytest.mark.asyncio
    async def test_get_and_delete(self, store, oauth_state):
        """Test one-time retrieval deletes state."""
        state_id = await store.create(oauth_state)
        retrieved = await store.get_and_delete(state_id)

        assert retrieved is not None
        assert retrieved.state == "test-csrf-state"

        # Second retrieval should return None
        second = await store.get(state_id)
        assert second is None

    @pytest.mark.asyncio
    async def test_get_and_delete_nonexistent(self, store):
        """Test get_and_delete on nonexistent state returns None."""
        result = await store.get_and_delete("nonexistent")
        assert result is None

    @pytest.mark.asyncio
    async def test_expired_state(self, store, oauth_state):
        """Test that expired states return None."""
        state_id = await store.create(oauth_state, ttl=1)
        await asyncio.sleep(1.1)

        result = await store.get(state_id)
        assert result is None

    @pytest.mark.asyncio
    async def test_expired_state_get_and_delete(self, store, oauth_state):
        """Test that get_and_delete returns None for expired state."""
        state_id = await store.create(oauth_state, ttl=1)
        await asyncio.sleep(1.1)

        result = await store.get_and_delete(state_id)
        assert result is None

    @pytest.mark.asyncio
    async def test_delete_state(self, store, oauth_state):
        """Test explicit state deletion."""
        state_id = await store.create(oauth_state)
        result = await store.delete(state_id)
        assert result is True

        retrieved = await store.get(state_id)
        assert retrieved is None

    @pytest.mark.asyncio
    async def test_delete_nonexistent_state(self, store):
        """Test deleting nonexistent state returns False."""
        result = await store.delete("nonexistent")
        assert result is False

    @pytest.mark.asyncio
    async def test_cleanup_expired(self, store, oauth_state):
        """Test cleanup removes only expired states."""
        # Create one that will expire
        await store.create(oauth_state, ttl=1)

        # Create one that won't expire
        long_state_id = await store.create(oauth_state, ttl=3600)

        await asyncio.sleep(1.1)

        count = await store.cleanup_expired()
        assert count == 1
        assert store.state_count == 1

        # Long-lived state should still exist
        retrieved = await store.get(long_state_id)
        assert retrieved is not None

    @pytest.mark.asyncio
    async def test_state_count(self, store, oauth_state):
        """Test state_count property."""
        assert store.state_count == 0

        await store.create(oauth_state)
        assert store.state_count == 1

        await store.create(oauth_state)
        assert store.state_count == 2
