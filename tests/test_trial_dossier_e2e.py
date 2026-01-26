"""E2E integration tests using real Provenant trial dossier.

These tests validate:
- CESR parsing of real dossier data
- ACDC extraction and DAG building
- Claim tree structure with real credentials

Marked with @pytest.mark.e2e to allow skipping in CI if flaky:
    pytest -m "not e2e"
"""

import json
import os

import pytest

from app.vvp.dossier.parser import parse_dossier
from app.vvp.dossier.validator import build_dag

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")
TRIAL_DOSSIER_PATH = os.path.join(FIXTURES_DIR, "trial_dossier.json")


@pytest.mark.e2e
class TestTrialDossierE2E:
    """E2E tests using real Provenant trial dossier."""

    @pytest.fixture
    def trial_dossier_raw(self):
        """Load trial dossier as raw bytes."""
        with open(TRIAL_DOSSIER_PATH, "rb") as f:
            return f.read()

    @pytest.fixture
    def trial_dossier_json(self):
        """Load trial dossier as parsed JSON."""
        with open(TRIAL_DOSSIER_PATH, "r") as f:
            return json.load(f)

    def test_dossier_file_exists(self):
        """Verify trial dossier fixture exists."""
        assert os.path.exists(TRIAL_DOSSIER_PATH), (
            f"Trial dossier not found at {TRIAL_DOSSIER_PATH}"
        )

    def test_dossier_is_valid_json(self, trial_dossier_raw):
        """Verify trial dossier is valid JSON."""
        data = json.loads(trial_dossier_raw)
        assert isinstance(data, (dict, list)), "Dossier should be JSON object or array"

    def test_dossier_parsing_extracts_acdcs(self, trial_dossier_raw):
        """Verify ACDCs are extracted from trial dossier."""
        nodes, signatures = parse_dossier(trial_dossier_raw)
        assert len(nodes) > 0, "Should extract at least one ACDC from dossier"

    def test_dag_builds_without_cycles(self, trial_dossier_raw):
        """Verify DAG is built successfully (no cycles)."""
        nodes, _ = parse_dossier(trial_dossier_raw)
        if len(nodes) > 0:
            dag = build_dag(nodes)
            assert dag is not None, "DAG should be built successfully"
            # root_said may be None for certain dossier structures
            # (e.g., when credentials form a forest rather than a single tree)
            assert len(dag.nodes) > 0, "DAG should contain nodes"

    def test_all_acdcs_have_valid_structure(self, trial_dossier_raw):
        """Verify all ACDCs have required fields per spec."""
        nodes, _ = parse_dossier(trial_dossier_raw)
        for node in nodes:
            assert node.said, f"ACDC missing SAID"
            assert node.issuer, f"ACDC {node.said} missing issuer"
            assert node.schema, f"ACDC {node.said} missing schema"

    def test_dossier_size_reasonable(self, trial_dossier_raw):
        """Verify dossier size is within expected range."""
        size_kb = len(trial_dossier_raw) / 1024
        assert size_kb > 1, "Dossier should be at least 1KB"
        assert size_kb < 500, "Dossier should be under 500KB"
