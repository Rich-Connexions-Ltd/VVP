"""Root conftest for all tests - provides shared fixtures."""

import os

import pytest


def pytest_addoption(parser):
    """Add --run-local-witnesses option to pytest."""
    parser.addoption(
        "--run-local-witnesses",
        action="store_true",
        default=False,
        help="Run tests that require local witnesses (docker-compose)",
    )


def pytest_configure(config):
    """Register the local_witnesses marker."""
    config.addinivalue_line(
        "markers", "local_witnesses: mark test as requiring local witnesses"
    )


def pytest_collection_modifyitems(config, items):
    """Skip local_witnesses tests unless --run-local-witnesses is provided."""
    if config.getoption("--run-local-witnesses"):
        return

    skip_marker = pytest.mark.skip(reason="Need --run-local-witnesses to run")
    for item in items:
        if "local_witnesses" in item.keywords:
            item.add_marker(skip_marker)


@pytest.fixture
def witness_base_url():
    """Get witness base URL from environment or use default localhost."""
    return os.getenv("VVP_LOCAL_WITNESS_HOST", "http://127.0.0.1")


@pytest.fixture(autouse=True)
def reset_caches():
    """Reset all caches before each test to ensure isolation.

    This prevents cache hits from previous tests affecting subsequent tests.
    """
    from app.vvp.dossier.cache import reset_dossier_cache

    reset_dossier_cache()
    yield
    reset_dossier_cache()
