"""Pytest fixtures for VVP Issuer tests."""
import asyncio
import importlib
import json
import os
import tempfile
from pathlib import Path
from typing import AsyncGenerator

import bcrypt
import pytest
from httpx import AsyncClient, ASGITransport

from app.auth.api_key import reset_api_key_store
from app.audit.logger import reset_audit_logger
from app.keri.identity import (
    reset_identity_manager,
    close_identity_manager,
    IssuerIdentityManager,
)
from app.keri.issuer import reset_credential_issuer, close_credential_issuer
from app.keri.persistence import reset_persistence_manager, PersistenceManager
from app.keri.registry import (
    reset_registry_manager,
    close_registry_manager,
)
from app.keri.witness import reset_witness_publisher
from app.dossier.builder import reset_dossier_builder


# =============================================================================
# Test API Keys (pre-generated for consistent testing)
# =============================================================================

# Raw keys for use in test headers
TEST_ADMIN_KEY = "test-admin-key-12345"
TEST_OPERATOR_KEY = "test-operator-key-12345"
TEST_READONLY_KEY = "test-readonly-key-12345"
TEST_REVOKED_KEY = "test-revoked-key-12345"

# Pre-computed bcrypt hashes (cost factor 4 for fast tests)
TEST_ADMIN_HASH = bcrypt.hashpw(TEST_ADMIN_KEY.encode(), bcrypt.gensalt(rounds=4)).decode()
TEST_OPERATOR_HASH = bcrypt.hashpw(TEST_OPERATOR_KEY.encode(), bcrypt.gensalt(rounds=4)).decode()
TEST_READONLY_HASH = bcrypt.hashpw(TEST_READONLY_KEY.encode(), bcrypt.gensalt(rounds=4)).decode()
TEST_REVOKED_HASH = bcrypt.hashpw(TEST_REVOKED_KEY.encode(), bcrypt.gensalt(rounds=4)).decode()


def get_test_api_keys_config() -> dict:
    """Get test API keys configuration."""
    return {
        "keys": [
            {
                "id": "test-admin",
                "name": "Test Admin",
                "hash": TEST_ADMIN_HASH,
                "roles": ["issuer:admin", "issuer:operator", "issuer:readonly"],
                "revoked": False,
            },
            {
                "id": "test-operator",
                "name": "Test Operator",
                "hash": TEST_OPERATOR_HASH,
                "roles": ["issuer:operator", "issuer:readonly"],
                "revoked": False,
            },
            {
                "id": "test-readonly",
                "name": "Test Readonly",
                "hash": TEST_READONLY_HASH,
                "roles": ["issuer:readonly"],
                "revoked": False,
            },
            {
                "id": "test-revoked",
                "name": "Test Revoked",
                "hash": TEST_REVOKED_HASH,
                "roles": ["issuer:admin"],
                "revoked": True,
            },
        ],
        "version": 1,
    }


@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


# =============================================================================
# Auth Header Fixtures
# =============================================================================

@pytest.fixture
def admin_headers() -> dict:
    """Headers with admin API key."""
    return {"X-API-Key": TEST_ADMIN_KEY}


@pytest.fixture
def operator_headers() -> dict:
    """Headers with operator API key."""
    return {"X-API-Key": TEST_OPERATOR_KEY}


@pytest.fixture
def readonly_headers() -> dict:
    """Headers with readonly API key."""
    return {"X-API-Key": TEST_READONLY_KEY}


@pytest.fixture
def revoked_headers() -> dict:
    """Headers with revoked API key."""
    return {"X-API-Key": TEST_REVOKED_KEY}


@pytest.fixture
def invalid_headers() -> dict:
    """Headers with invalid API key."""
    return {"X-API-Key": "invalid-key-that-does-not-exist"}


@pytest.fixture
def temp_dir():
    """Create temporary directory for test data."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
async def temp_persistence(temp_dir: Path) -> PersistenceManager:
    """Create persistence manager with temporary directory."""
    reset_persistence_manager()
    manager = PersistenceManager(base_dir=temp_dir)
    manager.initialize()
    yield manager
    reset_persistence_manager()


@pytest.fixture
async def temp_identity_manager(temp_dir: Path) -> AsyncGenerator[IssuerIdentityManager, None]:
    """Create identity manager with temporary storage."""
    reset_identity_manager()
    manager = IssuerIdentityManager(
        name="test-issuer",
        base_dir=temp_dir,
        temp=True,  # Use temp mode for faster cleanup
    )
    await manager.initialize()
    yield manager
    await manager.close()
    reset_identity_manager()


@pytest.fixture
async def identity_with_registry(
    client: AsyncClient,
) -> AsyncGenerator[dict, None]:
    """Create an identity for registry tests.

    Uses the client fixture to ensure proper singleton initialization,
    then creates an identity that can be used for registry creation.
    """
    # Create a test identity via API
    response = await client.post(
        "/identity",
        json={"name": "test-issuer-for-registry", "publish_to_witnesses": False},
    )
    assert response.status_code == 200, f"Failed to create identity: {response.text}"
    identity_data = response.json()
    yield identity_data["identity"]


@pytest.fixture
async def client(temp_dir: Path) -> AsyncGenerator[AsyncClient, None]:
    """Create test client for API testing with isolated temp storage.

    Sets VVP_ISSUER_DATA_DIR to a temp directory so tests don't pollute
    the user's home directory or leak state between test runs.

    NOTE: Auth is DISABLED by default to avoid breaking existing tests.
    Use client_with_auth fixture for testing authentication.
    """
    # Set environment variable BEFORE importing the app
    # so config.py picks up the temp directory
    original_data_dir = os.environ.get("VVP_ISSUER_DATA_DIR")
    original_auth_enabled = os.environ.get("VVP_AUTH_ENABLED")

    os.environ["VVP_ISSUER_DATA_DIR"] = str(temp_dir)
    os.environ["VVP_AUTH_ENABLED"] = "false"  # Disable auth for backward compatibility

    # Reset singletons to pick up new config
    reset_identity_manager()
    reset_registry_manager()
    reset_credential_issuer()
    reset_persistence_manager()
    reset_witness_publisher()
    reset_api_key_store()
    reset_audit_logger()
    reset_dossier_builder()

    # Import and reload config module to pick up the new env var
    import app.config as config_module
    importlib.reload(config_module)

    # Reload main to pick up new config
    import app.main as main_module
    importlib.reload(main_module)

    async with AsyncClient(
        transport=ASGITransport(app=main_module.app),
        base_url="http://test",
    ) as async_client:
        yield async_client

    # Close managers to release LMDB locks
    await close_credential_issuer()
    await close_registry_manager()
    await close_identity_manager()

    # Cleanup after test
    reset_identity_manager()
    reset_registry_manager()
    reset_credential_issuer()
    reset_persistence_manager()
    reset_witness_publisher()
    reset_api_key_store()
    reset_audit_logger()
    reset_dossier_builder()

    # Restore original environment
    if original_data_dir is not None:
        os.environ["VVP_ISSUER_DATA_DIR"] = original_data_dir
    elif "VVP_ISSUER_DATA_DIR" in os.environ:
        del os.environ["VVP_ISSUER_DATA_DIR"]

    if original_auth_enabled is not None:
        os.environ["VVP_AUTH_ENABLED"] = original_auth_enabled
    elif "VVP_AUTH_ENABLED" in os.environ:
        del os.environ["VVP_AUTH_ENABLED"]

    # Reload config to restore original values for other tests
    importlib.reload(config_module)


@pytest.fixture
async def client_with_auth(temp_dir: Path) -> AsyncGenerator[AsyncClient, None]:
    """Create test client with authentication ENABLED.

    Uses test API keys config for authentication testing.
    """
    # Save original environment
    original_data_dir = os.environ.get("VVP_ISSUER_DATA_DIR")
    original_auth_enabled = os.environ.get("VVP_AUTH_ENABLED")
    original_api_keys = os.environ.get("VVP_API_KEYS")

    # Set up test environment with auth enabled
    os.environ["VVP_ISSUER_DATA_DIR"] = str(temp_dir)
    os.environ["VVP_AUTH_ENABLED"] = "true"
    os.environ["VVP_API_KEYS"] = json.dumps(get_test_api_keys_config())

    # Reset singletons
    reset_identity_manager()
    reset_registry_manager()
    reset_credential_issuer()
    reset_persistence_manager()
    reset_witness_publisher()
    reset_api_key_store()
    reset_audit_logger()

    # Reload config and main
    import app.config as config_module
    importlib.reload(config_module)

    import app.main as main_module
    importlib.reload(main_module)

    async with AsyncClient(
        transport=ASGITransport(app=main_module.app),
        base_url="http://test",
    ) as async_client:
        yield async_client

    # Cleanup
    await close_credential_issuer()
    await close_registry_manager()
    await close_identity_manager()

    reset_identity_manager()
    reset_registry_manager()
    reset_credential_issuer()
    reset_persistence_manager()
    reset_witness_publisher()
    reset_api_key_store()
    reset_audit_logger()

    # Restore environment
    if original_data_dir is not None:
        os.environ["VVP_ISSUER_DATA_DIR"] = original_data_dir
    elif "VVP_ISSUER_DATA_DIR" in os.environ:
        del os.environ["VVP_ISSUER_DATA_DIR"]

    if original_auth_enabled is not None:
        os.environ["VVP_AUTH_ENABLED"] = original_auth_enabled
    elif "VVP_AUTH_ENABLED" in os.environ:
        del os.environ["VVP_AUTH_ENABLED"]

    if original_api_keys is not None:
        os.environ["VVP_API_KEYS"] = original_api_keys
    elif "VVP_API_KEYS" in os.environ:
        del os.environ["VVP_API_KEYS"]

    importlib.reload(config_module)
