"""Root conftest for all tests - provides shared fixtures."""

import pytest


@pytest.fixture(autouse=True)
def reset_caches():
    """Reset all caches before each test to ensure isolation.

    This prevents cache hits from previous tests affecting subsequent tests.
    """
    from app.vvp.dossier.cache import reset_dossier_cache

    reset_dossier_cache()
    yield
    reset_dossier_cache()
