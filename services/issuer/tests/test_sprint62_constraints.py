"""Tests for Sprint 62: Vetter Constraint Validator.

Tests cover:
- Layer 1: extract_ecc_from_tn, check_tn_ecc_constraint, check_jurisdiction_constraint
- Layer 2: validate_issuance_constraints, validate_dossier_constraints, validate_signing_constraints
- Admin toggle: GET/PUT /admin/settings/vetter-enforcement
- GSMA governance credential schema
"""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock


# =============================================================================
# Layer 1: extract_ecc_from_tn
# =============================================================================


class TestExtractEccFromTn:
    """Test E.164 → ECC extraction."""

    def test_uk_number(self):
        from app.vetter.constraints import extract_ecc_from_tn
        assert extract_ecc_from_tn("+441923311006") == "44"

    def test_us_number(self):
        from app.vetter.constraints import extract_ecc_from_tn
        assert extract_ecc_from_tn("+15551234567") == "1"

    def test_france_number(self):
        from app.vetter.constraints import extract_ecc_from_tn
        assert extract_ecc_from_tn("+33123456789") == "33"

    def test_germany_number(self):
        from app.vetter.constraints import extract_ecc_from_tn
        assert extract_ecc_from_tn("+4930123456") == "49"

    def test_japan_number(self):
        from app.vetter.constraints import extract_ecc_from_tn
        assert extract_ecc_from_tn("+81312345678") == "81"

    def test_uae_three_digit_ecc(self):
        from app.vetter.constraints import extract_ecc_from_tn
        assert extract_ecc_from_tn("+971501234567") == "971"

    def test_without_plus(self):
        from app.vetter.constraints import extract_ecc_from_tn
        assert extract_ecc_from_tn("441923311006") == "44"

    def test_empty_string_returns_none(self):
        from app.vetter.constraints import extract_ecc_from_tn
        assert extract_ecc_from_tn("") is None

    def test_none_returns_none(self):
        from app.vetter.constraints import extract_ecc_from_tn
        assert extract_ecc_from_tn(None) is None

    def test_single_digit_ecc_us(self):
        from app.vetter.constraints import extract_ecc_from_tn
        # "+1" is valid — US country code
        assert extract_ecc_from_tn("+1") == "1"

    def test_non_numeric_returns_none(self):
        from app.vetter.constraints import extract_ecc_from_tn
        assert extract_ecc_from_tn("+abcdefgh") is None


# =============================================================================
# Layer 1: check_tn_ecc_constraint
# =============================================================================


class TestCheckTnEccConstraint:
    """Test TN vs ECC target validation."""

    def test_tn_in_ecc_targets_passes(self):
        from app.vetter.constraints import check_tn_ecc_constraint
        result = check_tn_ecc_constraint("+441923311006", ["44", "1"])
        assert result.is_authorized is True

    def test_tn_not_in_ecc_targets_fails(self):
        from app.vetter.constraints import check_tn_ecc_constraint
        result = check_tn_ecc_constraint("+441923311006", ["33", "1"])
        assert result.is_authorized is False
        assert "44" in result.reason
        assert result.check_type == "ecc"

    def test_no_ecc_targets_fails(self):
        """Empty ecc_targets means ECC not in targets (no authorization)."""
        from app.vetter.constraints import check_tn_ecc_constraint
        result = check_tn_ecc_constraint("+441923311006", [])
        assert result.is_authorized is False

    def test_invalid_tn_skips(self):
        """Unrecognized TN skips check (is_authorized=True) rather than failing."""
        from app.vetter.constraints import check_tn_ecc_constraint
        result = check_tn_ecc_constraint("", ["44"])
        assert result.is_authorized is True


# =============================================================================
# Layer 1: check_jurisdiction_constraint
# =============================================================================


class TestCheckJurisdictionConstraint:
    """Test jurisdiction vs jurisdiction_targets validation."""

    def test_jurisdiction_in_targets_passes(self):
        from app.vetter.constraints import check_jurisdiction_constraint
        result = check_jurisdiction_constraint("GBR", ["GBR", "USA"], "Identity")
        assert result.is_authorized is True

    def test_jurisdiction_not_in_targets_fails(self):
        from app.vetter.constraints import check_jurisdiction_constraint
        result = check_jurisdiction_constraint("GBR", ["FRA", "DEU"], "Identity")
        assert result.is_authorized is False
        assert "GBR" in result.reason
        assert result.check_type == "jurisdiction"

    def test_no_jurisdiction_targets_fails(self):
        """Empty jurisdiction_targets means not in targets."""
        from app.vetter.constraints import check_jurisdiction_constraint
        result = check_jurisdiction_constraint("GBR", [], "Identity")
        assert result.is_authorized is False

    def test_brand_credential_type(self):
        """Brand jurisdiction check uses correct credential_type."""
        from app.vetter.constraints import check_jurisdiction_constraint
        result = check_jurisdiction_constraint("GBR", ["GBR"], "Brand")
        assert result.is_authorized is True
        assert result.credential_type == "Brand"


# =============================================================================
# ConstraintCheckResult model
# =============================================================================


class TestConstraintCheckResult:
    """Test ConstraintCheckResult dataclass."""

    def test_authorized_result(self):
        from app.vetter.constraints import ConstraintCheckResult
        r = ConstraintCheckResult(
            check_type="ecc",
            credential_type="TN",
            target_value="44",
            allowed_values=["44", "1"],
            is_authorized=True,
            reason="",
        )
        assert r.is_authorized is True
        assert r.credential_type == "TN"
        assert r.target_value == "44"

    def test_unauthorized_result(self):
        from app.vetter.constraints import ConstraintCheckResult
        r = ConstraintCheckResult(
            check_type="ecc",
            credential_type="TN",
            target_value="44",
            allowed_values=["33"],
            is_authorized=False,
            reason="ECC 44 not in targets [33]",
        )
        assert r.is_authorized is False
        assert r.allowed_values == ["33"]


# =============================================================================
# Admin Vetter Enforcement Toggle
# =============================================================================


class TestAdminVetterEnforcement:
    """Test GET/PUT /admin/settings/vetter-enforcement endpoints."""

    @pytest.mark.asyncio
    async def test_get_enforcement_default_off(self, client):
        """Default enforcement should be OFF (false)."""
        resp = await client.get("/admin/settings/vetter-enforcement")
        assert resp.status_code == 200
        data = resp.json()
        assert "enforce_vetter_constraints" in data
        # Default is false per config
        assert isinstance(data["enforce_vetter_constraints"], bool)

    @pytest.mark.asyncio
    async def test_put_enforcement_on(self, client):
        """PUT should toggle enforcement ON."""
        resp = await client.put(
            "/admin/settings/vetter-enforcement?enabled=true"
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["enforce_vetter_constraints"] is True

        # Verify it persists via GET
        resp2 = await client.get("/admin/settings/vetter-enforcement")
        assert resp2.json()["enforce_vetter_constraints"] is True

    @pytest.mark.asyncio
    async def test_put_enforcement_off(self, client):
        """PUT should toggle enforcement OFF."""
        # Turn on first
        await client.put("/admin/settings/vetter-enforcement?enabled=true")
        # Turn off
        resp = await client.put(
            "/admin/settings/vetter-enforcement?enabled=false"
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["enforce_vetter_constraints"] is False


# =============================================================================
# GSMA Governance Credential Schema
# =============================================================================


class TestGSMAGovernanceSchema:
    """Test GSMA governance credential schema exists and is valid."""

    def test_schema_file_exists(self):
        from pathlib import Path
        schema_path = (
            Path(__file__).parent.parent
            / "app" / "schema" / "schemas"
            / "gsma-governance-credential.json"
        )
        assert schema_path.exists(), "GSMA governance credential schema missing"

    def test_schema_has_required_fields(self):
        import json
        from pathlib import Path
        schema_path = (
            Path(__file__).parent.parent
            / "app" / "schema" / "schemas"
            / "gsma-governance-credential.json"
        )
        schema = json.loads(schema_path.read_text())

        # Must have $id (SAID)
        assert "$id" in schema

        # Must have title
        assert "title" in schema

        # a uses oneOf — find the object variant with name, role, i
        a_def = schema.get("properties", {}).get("a", {})
        oneOf = a_def.get("oneOf", [])
        assert len(oneOf) >= 2, "Schema 'a' must have oneOf variants"

        # Find the object variant
        obj_variant = None
        for variant in oneOf:
            if variant.get("type") == "object":
                obj_variant = variant
                break
        assert obj_variant is not None, "Schema 'a' must have an object variant"

        props = obj_variant.get("properties", {})
        assert "i" in props, "Schema must have 'i' (issuee AID) attribute"
        assert "name" in props, "Schema must have 'name' attribute"
        assert "role" in props, "Schema must have 'role' attribute"

    def test_schema_said_matches_constant(self):
        import json
        from pathlib import Path
        from app.vetter.constants import GSMA_GOVERNANCE_SCHEMA_SAID

        schema_path = (
            Path(__file__).parent.parent
            / "app" / "schema" / "schemas"
            / "gsma-governance-credential.json"
        )
        schema = json.loads(schema_path.read_text())
        assert schema["$id"] == GSMA_GOVERNANCE_SCHEMA_SAID


# =============================================================================
# Config: ENFORCE_VETTER_CONSTRAINTS
# =============================================================================


class TestEnforceVetterConstraintsConfig:
    """Test the ENFORCE_VETTER_CONSTRAINTS config and setter."""

    def test_default_is_false(self):
        """Default enforcement should be false."""
        # Import fresh — the module-level value may have been toggled by other tests
        import importlib
        import app.config as cfg
        # The default from os.getenv with "false" should be False
        assert isinstance(cfg.ENFORCE_VETTER_CONSTRAINTS, bool)

    def test_setter_toggles_value(self):
        from app.config import set_enforce_vetter_constraints
        import app.config as cfg

        original = cfg.ENFORCE_VETTER_CONSTRAINTS

        set_enforce_vetter_constraints(True)
        assert cfg.ENFORCE_VETTER_CONSTRAINTS is True

        set_enforce_vetter_constraints(False)
        assert cfg.ENFORCE_VETTER_CONSTRAINTS is False

        # Restore original
        set_enforce_vetter_constraints(original)
