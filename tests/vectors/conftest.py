"""Pytest fixtures and configuration for test vectors."""

import json
from pathlib import Path
from typing import List

import pytest

from .schema import VectorCase

VECTORS_DIR = Path(__file__).parent / "data"


@pytest.fixture(autouse=True)
def reset_caches():
    """Reset all caches before each test vector to ensure isolation."""
    from app.vvp.dossier.cache import reset_dossier_cache
    reset_dossier_cache()
    yield
    reset_dossier_cache()


def load_all_vectors() -> List[VectorCase]:
    """Load all test vectors from JSON files."""
    vectors = []
    for path in sorted(VECTORS_DIR.glob("v*.json")):
        with open(path) as f:
            vectors.append(VectorCase(**json.load(f)))
    return vectors


def pytest_generate_tests(metafunc):
    """Parametrize test_vector fixture with all vectors."""
    if "test_vector" in metafunc.fixturenames:
        vectors = load_all_vectors()
        metafunc.parametrize("test_vector", vectors, ids=[v.id for v in vectors])
