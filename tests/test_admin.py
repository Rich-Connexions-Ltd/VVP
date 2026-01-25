"""Tests for /admin endpoint.

Phase 9.3: Configuration visibility for operators.
"""

import os
import pytest
from fastapi.testclient import TestClient


class TestAdminEndpoint:
    """Tests for /admin configuration endpoint."""

    def test_admin_returns_all_config_categories(self):
        """Admin endpoint returns all configuration categories."""
        # Import here to avoid pysodium issues at module level
        from app.main import app
        client = TestClient(app)

        response = client.get("/admin")
        assert response.status_code == 200

        data = response.json()

        # Check all expected categories exist
        assert "normative" in data
        assert "configurable" in data
        assert "policy" in data
        assert "features" in data
        assert "witnesses" in data
        assert "environment" in data

    def test_admin_normative_config(self):
        """Admin endpoint returns normative configuration."""
        from app.main import app
        client = TestClient(app)

        response = client.get("/admin")
        data = response.json()

        normative = data["normative"]
        assert "max_iat_drift_seconds" in normative
        assert normative["max_iat_drift_seconds"] == 5
        assert "allowed_algorithms" in normative
        assert "EdDSA" in normative["allowed_algorithms"]

    def test_admin_configurable_config(self):
        """Admin endpoint returns configurable defaults."""
        from app.main import app
        client = TestClient(app)

        response = client.get("/admin")
        data = response.json()

        configurable = data["configurable"]
        assert "clock_skew_seconds" in configurable
        assert "max_token_age_seconds" in configurable
        assert "max_passport_validity_seconds" in configurable
        assert "allow_passport_exp_omission" in configurable

    def test_admin_policy_config(self):
        """Admin endpoint returns policy configuration."""
        from app.main import app
        client = TestClient(app)

        response = client.get("/admin")
        data = response.json()

        policy = data["policy"]
        assert "dossier_fetch_timeout_seconds" in policy
        assert "dossier_max_size_bytes" in policy
        assert "dossier_max_redirects" in policy

    def test_admin_features_config(self):
        """Admin endpoint returns feature flags."""
        from app.main import app
        client = TestClient(app)

        response = client.get("/admin")
        data = response.json()

        features = data["features"]
        assert "tier2_kel_resolution_enabled" in features
        assert "admin_endpoint_enabled" in features
        assert features["admin_endpoint_enabled"] is True

    def test_admin_witnesses_config(self):
        """Admin endpoint returns witness URLs."""
        from app.main import app
        client = TestClient(app)

        response = client.get("/admin")
        data = response.json()

        witnesses = data["witnesses"]
        assert "default_witness_urls" in witnesses
        assert isinstance(witnesses["default_witness_urls"], list)
        assert len(witnesses["default_witness_urls"]) > 0

    def test_admin_environment_config(self):
        """Admin endpoint returns environment variables."""
        from app.main import app
        client = TestClient(app)

        response = client.get("/admin")
        data = response.json()

        environment = data["environment"]
        assert "log_level" in environment

    def test_admin_config_types(self):
        """Configuration values have expected types."""
        from app.main import app
        client = TestClient(app)

        response = client.get("/admin")
        data = response.json()

        # Normative
        assert isinstance(data["normative"]["max_iat_drift_seconds"], int)
        assert isinstance(data["normative"]["allowed_algorithms"], list)

        # Configurable
        assert isinstance(data["configurable"]["clock_skew_seconds"], int)
        assert isinstance(data["configurable"]["allow_passport_exp_omission"], bool)

        # Policy
        assert isinstance(data["policy"]["dossier_max_size_bytes"], int)

        # Features
        assert isinstance(data["features"]["tier2_kel_resolution_enabled"], bool)


class TestAdminEndpointDisabled:
    """Tests for admin endpoint when disabled."""

    def test_admin_disabled_returns_404(self, monkeypatch):
        """Admin endpoint returns 404 when ADMIN_ENDPOINT_ENABLED=false."""
        # Set environment variable before importing
        monkeypatch.setenv("ADMIN_ENDPOINT_ENABLED", "false")

        # Need to reload the config module to pick up the new env var
        import importlib
        import app.core.config
        importlib.reload(app.core.config)

        # Re-import main to pick up the reloaded config
        import app.main
        importlib.reload(app.main)

        client = TestClient(app.main.app)
        response = client.get("/admin")

        assert response.status_code == 404
        assert "disabled" in response.json()["detail"].lower()

        # Restore default
        monkeypatch.setenv("ADMIN_ENDPOINT_ENABLED", "true")
        importlib.reload(app.core.config)
        importlib.reload(app.main)


class TestLogLevelEndpoint:
    """Tests for POST /admin/log-level endpoint."""

    def test_set_log_level_debug(self):
        """Can set log level to DEBUG."""
        from app.main import app
        client = TestClient(app)

        response = client.post("/admin/log-level", json={"level": "DEBUG"})
        assert response.status_code == 200

        data = response.json()
        assert data["success"] is True
        assert data["log_level"] == "DEBUG"

    def test_set_log_level_info(self):
        """Can set log level to INFO."""
        from app.main import app
        client = TestClient(app)

        response = client.post("/admin/log-level", json={"level": "info"})
        assert response.status_code == 200

        data = response.json()
        assert data["success"] is True
        assert data["log_level"] == "INFO"

    def test_set_log_level_warning(self):
        """Can set log level to WARNING."""
        from app.main import app
        client = TestClient(app)

        response = client.post("/admin/log-level", json={"level": "WARNING"})
        assert response.status_code == 200

        data = response.json()
        assert data["log_level"] == "WARNING"

    def test_set_log_level_error(self):
        """Can set log level to ERROR."""
        from app.main import app
        client = TestClient(app)

        response = client.post("/admin/log-level", json={"level": "error"})
        assert response.status_code == 200

        data = response.json()
        assert data["log_level"] == "ERROR"

    def test_set_log_level_invalid_returns_400(self):
        """Invalid log level returns 400."""
        from app.main import app
        client = TestClient(app)

        response = client.post("/admin/log-level", json={"level": "INVALID"})
        assert response.status_code == 400
        assert "Invalid log level" in response.json()["detail"]

    def test_log_level_reflected_in_admin(self):
        """Changed log level is reflected in /admin response."""
        from app.main import app
        client = TestClient(app)

        # Set to DEBUG
        client.post("/admin/log-level", json={"level": "DEBUG"})

        # Check /admin shows DEBUG
        response = client.get("/admin")
        data = response.json()
        assert data["environment"]["log_level_name"] == "DEBUG"

        # Reset to INFO
        client.post("/admin/log-level", json={"level": "INFO"})
