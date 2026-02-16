"""Pytest fixtures for VVP KERI Agent tests.

Sprint 68: KERI Agent Service Extraction.
"""
import asyncio
import importlib
import os
import tempfile
from pathlib import Path
from typing import AsyncGenerator

import pytest
from httpx import AsyncClient, ASGITransport

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
from app.keri.seed_store import reset_seed_store
from app.dossier.builder import reset_dossier_builder
from app.mock_vlei import reset_mock_vlei_manager


@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


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
    # Sprint 69: Set up seed DB for identity manager initialization
    original_db_url = os.environ.get("VVP_KERI_AGENT_DATABASE_URL")
    os.environ["VVP_KERI_AGENT_DATABASE_URL"] = f"sqlite:///{temp_dir}/keri_seeds.db"
    import app.config as config_module
    importlib.reload(config_module)
    import app.db.session as db_session_module
    importlib.reload(db_session_module)
    db_session_module.init_database()

    reset_identity_manager()
    reset_seed_store()
    manager = IssuerIdentityManager(
        name="test-issuer",
        base_dir=temp_dir,
        temp=True,
    )
    await manager.initialize()
    yield manager
    await manager.close()
    reset_identity_manager()
    reset_seed_store()

    _restore_env("VVP_KERI_AGENT_DATABASE_URL", original_db_url)
    importlib.reload(config_module)


def _reset_all_singletons():
    """Reset all KERI Agent singletons to prevent state leakage between tests."""
    reset_identity_manager()
    reset_registry_manager()
    reset_credential_issuer()
    reset_persistence_manager()
    reset_witness_publisher()
    reset_seed_store()
    reset_dossier_builder()
    reset_mock_vlei_manager()


@pytest.fixture
async def client(temp_dir: Path) -> AsyncGenerator[AsyncClient, None]:
    """Create test client for API testing with isolated temp storage.

    Sets VVP_KERI_AGENT_DATA_DIR to a temp directory so tests don't pollute
    the user's home directory or leak state between test runs.

    Bearer token auth is DISABLED by default (empty token = auth disabled).
    Sprint 69: Also sets VVP_KERI_AGENT_DATABASE_URL to in-memory SQLite.
    """
    original_data_dir = os.environ.get("VVP_KERI_AGENT_DATA_DIR")
    original_auth_token = os.environ.get("VVP_KERI_AGENT_AUTH_TOKEN")
    original_mock_vlei = os.environ.get("VVP_MOCK_VLEI_ENABLED")
    original_db_url = os.environ.get("VVP_KERI_AGENT_DATABASE_URL")

    os.environ["VVP_KERI_AGENT_DATA_DIR"] = str(temp_dir)
    os.environ["VVP_KERI_AGENT_AUTH_TOKEN"] = ""  # Disable auth for tests
    os.environ["VVP_MOCK_VLEI_ENABLED"] = "false"  # Don't auto-init mock vLEI
    os.environ["VVP_KERI_AGENT_DATABASE_URL"] = f"sqlite:///{temp_dir}/keri_seeds.db"

    _reset_all_singletons()

    # Reload config, db session, and main to pick up new env vars
    import app.config as config_module
    importlib.reload(config_module)

    import app.db.session as db_session_module
    importlib.reload(db_session_module)
    db_session_module.init_database()

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

    _reset_all_singletons()

    # Restore original environment
    _restore_env("VVP_KERI_AGENT_DATA_DIR", original_data_dir)
    _restore_env("VVP_KERI_AGENT_AUTH_TOKEN", original_auth_token)
    _restore_env("VVP_MOCK_VLEI_ENABLED", original_mock_vlei)
    _restore_env("VVP_KERI_AGENT_DATABASE_URL", original_db_url)

    importlib.reload(config_module)


@pytest.fixture
async def client_with_auth(temp_dir: Path) -> AsyncGenerator[AsyncClient, None]:
    """Create test client with bearer token authentication ENABLED."""
    original_data_dir = os.environ.get("VVP_KERI_AGENT_DATA_DIR")
    original_auth_token = os.environ.get("VVP_KERI_AGENT_AUTH_TOKEN")
    original_mock_vlei = os.environ.get("VVP_MOCK_VLEI_ENABLED")
    original_db_url = os.environ.get("VVP_KERI_AGENT_DATABASE_URL")

    os.environ["VVP_KERI_AGENT_DATA_DIR"] = str(temp_dir)
    os.environ["VVP_KERI_AGENT_AUTH_TOKEN"] = "test-bearer-token-secret"
    os.environ["VVP_MOCK_VLEI_ENABLED"] = "false"
    os.environ["VVP_KERI_AGENT_DATABASE_URL"] = f"sqlite:///{temp_dir}/keri_seeds.db"

    _reset_all_singletons()

    import app.config as config_module
    importlib.reload(config_module)

    import app.db.session as db_session_module
    importlib.reload(db_session_module)
    db_session_module.init_database()

    import app.main as main_module
    importlib.reload(main_module)

    async with AsyncClient(
        transport=ASGITransport(app=main_module.app),
        base_url="http://test",
    ) as async_client:
        yield async_client

    await close_credential_issuer()
    await close_registry_manager()
    await close_identity_manager()

    _reset_all_singletons()

    _restore_env("VVP_KERI_AGENT_DATA_DIR", original_data_dir)
    _restore_env("VVP_KERI_AGENT_AUTH_TOKEN", original_auth_token)
    _restore_env("VVP_MOCK_VLEI_ENABLED", original_mock_vlei)
    _restore_env("VVP_KERI_AGENT_DATABASE_URL", original_db_url)

    importlib.reload(config_module)


@pytest.fixture
def auth_headers() -> dict:
    """Headers with valid bearer token (matches client_with_auth fixture)."""
    return {"Authorization": "Bearer test-bearer-token-secret"}


def _restore_env(key: str, original: str | None) -> None:
    """Restore an environment variable to its original value."""
    if original is not None:
        os.environ[key] = original
    elif key in os.environ:
        del os.environ[key]
