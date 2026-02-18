"""Tests for PBX management: config, dialplan generation, and deploy.

Sprint 71: PBX Management UI
"""

import json
from unittest.mock import MagicMock, patch
from xml.etree import ElementTree

import pytest


def _init_app_db():
    """Ensure database tables exist for test methods that use the DB."""
    from app.db.session import init_database
    init_database()


# =============================================================================
# Dialplan Generation Tests
# =============================================================================


class TestDialplanGeneration:
    """Test FreeSWITCH dialplan XML generation."""

    def test_generate_with_no_extensions(self):
        """Dialplan with no extensions configured produces valid XML."""
        from app.pbx.dialplan import generate_dialplan

        xml = generate_dialplan(
            api_key_value="test-key-123",
            extensions_json="[]",
        )

        assert "<?xml version" in xml
        assert "No extensions configured" in xml
        # Should still have the 3 contexts
        assert '<context name="public">' in xml
        assert '<context name="redirected">' in xml
        assert '<context name="verified">' in xml
        # Valid XML
        ElementTree.fromstring(xml.split("?>", 1)[1].strip())

    def test_generate_with_two_extensions(self):
        """Dialplan with two extensions generates inbound blocks for each."""
        from app.pbx.dialplan import generate_dialplan

        extensions = json.dumps([
            {"ext": 1001, "cli": "+441923311001", "enabled": True, "description": "Primary"},
            {"ext": 1006, "cli": "+441923311006", "enabled": True, "description": "Secondary"},
        ])

        xml = generate_dialplan(
            api_key_value="test-key-123",
            extensions_json=extensions,
        )

        assert "vvp-inbound-1001" in xml
        assert "vvp-inbound-1006" in xml
        assert "Primary" in xml
        assert "Secondary" in xml

    def test_generate_api_key_injection(self):
        """API key appears in the VVP loopback outbound section."""
        from app.pbx.dialplan import generate_dialplan

        xml = generate_dialplan(
            api_key_value="my-secret-key-abc",
            extensions_json="[]",
        )

        assert "X-VVP-API-Key=my-secret-key-abc" in xml

    def test_generate_no_api_key(self):
        """When api_key_value is None, no API key line appears."""
        from app.pbx.dialplan import generate_dialplan

        xml = generate_dialplan(
            api_key_value=None,
            extensions_json="[]",
        )

        assert "X-VVP-API-Key" not in xml
        assert "API Key: NOT SET" in xml

    def test_generate_default_caller_id(self):
        """Default caller ID appears in loopback and outbound sections."""
        from app.pbx.dialplan import generate_dialplan

        xml = generate_dialplan(
            api_key_value="key",
            extensions_json="[]",
            default_caller_id="+441923311005",
        )

        assert "+441923311005" in xml

    def test_generate_catch_all_extension(self):
        """Last enabled extension becomes the catch-all default for external inbound."""
        from app.pbx.dialplan import generate_dialplan

        extensions = json.dumps([
            {"ext": 1001, "cli": "+441923311001", "enabled": True, "description": "A"},
            {"ext": 1006, "cli": "+441923311006", "enabled": True, "description": "B"},
        ])

        xml = generate_dialplan(api_key_value="key", extensions_json=extensions)

        # The last extension (1006) should be the catch-all (single condition: ^external$)
        # First extension (1001) should have specific TN match
        assert '4419233110' in xml  # TN pattern present

    def test_generate_disabled_extensions_excluded(self):
        """Disabled extensions are not included in the dialplan."""
        from app.pbx.dialplan import generate_dialplan

        extensions = json.dumps([
            {"ext": 1001, "cli": "+441923311001", "enabled": True, "description": "Active"},
            {"ext": 1002, "cli": "+441923311002", "enabled": False, "description": "Inactive"},
        ])

        xml = generate_dialplan(api_key_value="key", extensions_json=extensions)

        assert "vvp-inbound-1001" in xml
        assert "vvp-inbound-1002" not in xml

    def test_generate_preserves_redirected_context(self):
        """Redirected context is included with verification routing."""
        from app.pbx.dialplan import generate_dialplan

        xml = generate_dialplan(api_key_value="key", extensions_json="[]")

        assert "vvp-redirect-to-verify" in xml
        assert "127.0.0.1:5071" in xml

    def test_generate_preserves_verified_context(self):
        """Verified context is included with brand header delivery."""
        from app.pbx.dialplan import generate_dialplan

        xml = generate_dialplan(api_key_value="key", extensions_json="[]")

        assert "vvp-deliver" in xml
        assert "X-VVP-Brand-Name" in xml

    def test_generate_xml_escapes_special_chars(self):
        """Special XML characters in API key are escaped."""
        from app.pbx.dialplan import generate_dialplan

        xml = generate_dialplan(
            api_key_value="key<>&test",
            extensions_json="[]",
        )

        assert "key&lt;&gt;&amp;test" in xml

    def test_generate_invalid_json_returns_empty_extensions(self):
        """Invalid extensions JSON is handled gracefully."""
        from app.pbx.dialplan import generate_dialplan

        xml = generate_dialplan(
            api_key_value="key",
            extensions_json="not valid json",
        )

        # Should still generate valid XML with no inbound blocks
        assert "<?xml version" in xml
        assert "none configured" in xml


# =============================================================================
# PBX Config API Tests (auth disabled)
# =============================================================================


class TestPBXConfigAPI:
    """Test PBX config API endpoints."""

    async def test_get_config_creates_default(self, client):
        """GET /pbx/config creates singleton with defaults on first call."""
        _init_app_db()
        # Clean any pre-existing config from previous test runs
        from app.db.session import SessionLocal
        from app.db.models import PBXConfig
        db = SessionLocal()
        db.query(PBXConfig).delete()
        db.commit()
        db.close()

        resp = await client.get("/pbx/config")
        assert resp.status_code == 200
        data = resp.json()
        assert data["default_caller_id"] == "+441923311000"
        assert data["extensions"] == []
        assert data["api_key_org_id"] is None
        assert data["last_deployed_at"] is None

    async def test_update_config_extensions(self, client):
        """PUT /pbx/config updates extension configuration."""
        _init_app_db()
        # First GET to ensure singleton exists
        await client.get("/pbx/config")

        resp = await client.put("/pbx/config", json={
            "extensions": [
                {"ext": 1001, "cli": "+441923311001", "enabled": True, "description": "Test"},
                {"ext": 1006, "cli": "+441923311006", "enabled": True, "description": "Test 2"},
            ]
        })
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["extensions"]) == 2
        assert data["extensions"][0]["ext"] == 1001
        assert data["extensions"][1]["ext"] == 1006

    async def test_update_config_caller_id(self, client):
        """PUT /pbx/config updates default caller ID."""
        _init_app_db()
        await client.get("/pbx/config")

        resp = await client.put("/pbx/config", json={
            "default_caller_id": "+441923311005",
        })
        assert resp.status_code == 200
        assert resp.json()["default_caller_id"] == "+441923311005"

    async def test_update_config_api_key_value(self, client):
        """PUT /pbx/config stores API key value and returns preview."""
        _init_app_db()
        await client.get("/pbx/config")

        resp = await client.put("/pbx/config", json={
            "api_key_value": "abcdefgh12345678",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["api_key_preview"] == "abcdefgh"

    async def test_update_config_rejects_invalid_caller_id(self, client):
        """PUT /pbx/config rejects invalid E.164 caller ID."""
        _init_app_db()
        await client.get("/pbx/config")

        resp = await client.put("/pbx/config", json={
            "default_caller_id": "not-e164",
        })
        assert resp.status_code == 422

    async def test_update_config_rejects_duplicate_extensions(self, client):
        """PUT /pbx/config rejects duplicate extension numbers."""
        _init_app_db()
        await client.get("/pbx/config")

        resp = await client.put("/pbx/config", json={
            "extensions": [
                {"ext": 1001, "cli": "+441923311001", "enabled": True, "description": "A"},
                {"ext": 1001, "cli": "+441923311002", "enabled": True, "description": "B"},
            ]
        })
        assert resp.status_code == 422

    async def test_update_config_rejects_ext_out_of_range(self, client):
        """PUT /pbx/config rejects extension numbers outside 1000-1009."""
        _init_app_db()
        await client.get("/pbx/config")

        resp = await client.put("/pbx/config", json={
            "extensions": [
                {"ext": 999, "cli": "+441923311001", "enabled": True, "description": "X"},
            ]
        })
        assert resp.status_code == 422

        resp = await client.put("/pbx/config", json={
            "extensions": [
                {"ext": 1010, "cli": "+441923311001", "enabled": True, "description": "X"},
            ]
        })
        assert resp.status_code == 422

    async def test_deploy_dry_run(self, client):
        """POST /pbx/deploy with dry_run returns XML without deploying."""
        _init_app_db()
        # Setup config first
        await client.put("/pbx/config", json={
            "api_key_value": "test-key-123",
            "extensions": [
                {"ext": 1001, "cli": "+441923311001", "enabled": True, "description": "Test"},
            ],
        })

        resp = await client.post("/pbx/deploy", json={"dry_run": True})
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["dialplan_xml"] is not None
        assert "test-key-123" in data["dialplan_xml"]
        assert "vvp-inbound-1001" in data["dialplan_xml"]
        assert data["dialplan_size_bytes"] > 0
        assert "Dry run" in data["message"]

    async def test_dialplan_preview(self, client):
        """GET /pbx/dialplan-preview returns XML content."""
        _init_app_db()
        await client.put("/pbx/config", json={
            "api_key_value": "preview-key",
        })

        resp = await client.get("/pbx/dialplan-preview")
        assert resp.status_code == 200
        assert "application/xml" in resp.headers["content-type"]
        assert "preview-key" in resp.text

    async def test_get_config_persists_across_requests(self, client):
        """Config updates persist across GET requests."""
        _init_app_db()
        await client.put("/pbx/config", json={
            "api_key_value": "persistent-key",
            "default_caller_id": "+441923311009",
        })

        resp = await client.get("/pbx/config")
        data = resp.json()
        assert data["api_key_preview"] == "persiste"
        assert data["default_caller_id"] == "+441923311009"


# =============================================================================
# PBX Config Auth Tests
# =============================================================================


class TestPBXConfigAuth:
    """Test PBX config endpoints require admin role."""

    async def test_get_config_requires_admin(self, client_with_auth, readonly_headers):
        """GET /pbx/config requires issuer:admin role."""
        _init_app_db()
        resp = await client_with_auth.get("/pbx/config", headers=readonly_headers)
        assert resp.status_code == 403

    async def test_update_config_requires_admin(self, client_with_auth, readonly_headers):
        """PUT /pbx/config requires issuer:admin role."""
        _init_app_db()
        resp = await client_with_auth.put(
            "/pbx/config",
            json={"default_caller_id": "+441923311005"},
            headers=readonly_headers,
        )
        assert resp.status_code == 403

    async def test_deploy_requires_admin(self, client_with_auth, readonly_headers):
        """POST /pbx/deploy requires issuer:admin role."""
        _init_app_db()
        resp = await client_with_auth.post(
            "/pbx/deploy",
            json={"dry_run": True},
            headers=readonly_headers,
        )
        assert resp.status_code == 403

    async def test_admin_can_access(self, client_with_auth, admin_headers):
        """Admin can access PBX config endpoints."""
        _init_app_db()
        resp = await client_with_auth.get("/pbx/config", headers=admin_headers)
        assert resp.status_code == 200


# =============================================================================
# Deploy Service Tests (mocked Azure SDK)
# =============================================================================


class TestDeployService:
    """Test PBX deploy service with mocked Azure SDK."""

    def test_deploy_azure_unavailable(self):
        """Deploy raises 503 when AZURE_SUBSCRIPTION_ID not configured."""
        from app.pbx.deploy import deploy_dialplan_to_pbx

        with patch("app.pbx.deploy.AZURE_SUBSCRIPTION_ID", None):
            with pytest.raises(Exception) as exc_info:
                deploy_dialplan_to_pbx("<xml/>")
            assert "503" in str(exc_info.value.status_code)

    def test_deploy_success(self):
        """Deploy calls Azure VM run-command and returns success."""
        from app.pbx.deploy import deploy_dialplan_to_pbx

        mock_result = MagicMock()
        mock_result.value = [MagicMock(message="Dialplan deployed and reloaded successfully", code=None)]

        mock_poller = MagicMock()
        mock_poller.result.return_value = mock_result

        mock_vm = MagicMock()
        mock_vm.begin_run_command.return_value = mock_poller

        mock_client = MagicMock()
        mock_client.virtual_machines = mock_vm

        mock_rci = MagicMock()

        with patch("app.pbx.deploy.AZURE_SUBSCRIPTION_ID", "test-sub"):
            with patch("app.pbx.deploy._get_compute_client", return_value=(mock_client, mock_rci)):
                success, output = deploy_dialplan_to_pbx("<include/>")

        assert success is True
        assert "successfully" in output.lower()
        mock_vm.begin_run_command.assert_called_once()

    def test_deploy_vm_command_failure(self):
        """Deploy handles VM command execution failure."""
        from app.pbx.deploy import deploy_dialplan_to_pbx

        mock_client = MagicMock()
        mock_client.virtual_machines.begin_run_command.side_effect = Exception("VM unreachable")

        mock_rci = MagicMock()

        with patch("app.pbx.deploy.AZURE_SUBSCRIPTION_ID", "test-sub"):
            with patch("app.pbx.deploy._get_compute_client", return_value=(mock_client, mock_rci)):
                success, output = deploy_dialplan_to_pbx("<include/>")

        assert success is False
        assert "VM unreachable" in output


# =============================================================================
# Pydantic Model Validation Tests
# =============================================================================


class TestPBXModels:
    """Test PBX Pydantic model validation."""

    def test_pbx_extension_valid(self):
        """Valid extension model."""
        from app.api.models import PBXExtension

        ext = PBXExtension(ext=1005, cli="+441923311005", enabled=True, description="Test")
        assert ext.ext == 1005
        assert ext.cli == "+441923311005"

    def test_pbx_extension_invalid_range(self):
        """Extension number outside 1000-1009 is rejected."""
        from app.api.models import PBXExtension

        with pytest.raises(Exception):
            PBXExtension(ext=1010, cli="+441923311010", enabled=True, description="")

        with pytest.raises(Exception):
            PBXExtension(ext=999, cli="+441923310999", enabled=True, description="")

    def test_pbx_extension_invalid_cli(self):
        """Invalid E.164 format is rejected."""
        from app.api.models import PBXExtension

        with pytest.raises(Exception):
            PBXExtension(ext=1001, cli="not-a-number", enabled=True, description="")

    def test_update_request_no_duplicates(self):
        """UpdatePBXConfigRequest rejects duplicate extension numbers."""
        from app.api.models import UpdatePBXConfigRequest, PBXExtension

        with pytest.raises(Exception):
            UpdatePBXConfigRequest(extensions=[
                PBXExtension(ext=1001, cli="+441923311001", enabled=True, description="A"),
                PBXExtension(ext=1001, cli="+441923311002", enabled=True, description="B"),
            ])

    def test_update_request_valid(self):
        """Valid UpdatePBXConfigRequest with extensions."""
        from app.api.models import UpdatePBXConfigRequest, PBXExtension

        req = UpdatePBXConfigRequest(extensions=[
            PBXExtension(ext=1001, cli="+441923311001", enabled=True, description="A"),
            PBXExtension(ext=1002, cli="+441923311002", enabled=False, description="B"),
        ])
        assert len(req.extensions) == 2
