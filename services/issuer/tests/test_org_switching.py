"""Tests for Sprint 67 Phase 3: Org Context Switching.

Tests cover:
- POST /session/switch-org (admin only)
- Non-admin cannot switch (403)
- Switching to null reverts to home org
- Switching to non-existent org returns 404
- Switching to disabled org returns 400
- Principal resolution: active_org_id overrides organization_id
- Auth status reflects switched org context
- Session isolation: two sessions can have different active orgs
"""

import importlib
import json
import os
import uuid

import pytest
from httpx import AsyncClient

from app.auth.api_key import Principal, reset_api_key_store
from app.auth.session import InMemorySessionStore, get_session_store, reset_session_store
from app.db.models import Organization
from tests.conftest import TEST_ADMIN_KEY, TEST_READONLY_KEY, get_test_api_keys_config


# =============================================================================
# Helpers
# =============================================================================


def _create_test_org(*, org_type="regular", enabled=True, name=None):
    """Create a test org in the DB. Returns org_id."""
    from app.db.session import init_database, SessionLocal

    init_database()
    org_id = str(uuid.uuid4())
    db = SessionLocal()
    try:
        org = Organization(
            id=org_id,
            name=name or f"switch-test-{uuid.uuid4().hex[:8]}",
            pseudo_lei=f"54930{uuid.uuid4().hex[:15]}",
            aid=f"E{uuid.uuid4().hex[:43]}",
            org_type=org_type,
            enabled=enabled,
        )
        db.add(org)
        db.commit()
        return org_id
    finally:
        db.close()


async def _login_as_admin(client: AsyncClient) -> dict:
    """Login with admin API key and return cookies."""
    response = await client.post(
        "/auth/login",
        json={"api_key": TEST_ADMIN_KEY},
        headers={"X-Requested-With": "XMLHttpRequest"},
    )
    assert response.status_code == 200, f"Login failed: {response.text}"
    data = response.json()
    assert data["success"] is True
    return dict(response.cookies)


async def _login_as_readonly(client: AsyncClient) -> dict:
    """Login with readonly API key and return cookies."""
    response = await client.post(
        "/auth/login",
        json={"api_key": TEST_READONLY_KEY},
        headers={"X-Requested-With": "XMLHttpRequest"},
    )
    assert response.status_code == 200, f"Login failed: {response.text}"
    data = response.json()
    assert data["success"] is True
    return dict(response.cookies)


# =============================================================================
# Session Store: home_org_id and active_org_id
# =============================================================================


class TestSessionOrgFields:
    """Tests for session home_org_id and active_org_id fields."""

    @pytest.fixture(autouse=True)
    def setup_api_key_store(self):
        """Set up API key store so session.get() key validation passes."""
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

    @pytest.mark.asyncio
    async def test_create_session_sets_home_org_id(self):
        """Session creation sets home_org_id from principal.organization_id."""
        store = InMemorySessionStore()
        principal = Principal(
            key_id="test-admin",
            name="Test Admin",
            roles={"issuer:admin"},
            organization_id="org-123",
        )
        session = await store.create(principal, ttl_seconds=3600)

        assert session.home_org_id == "org-123"
        assert session.active_org_id is None

    @pytest.mark.asyncio
    async def test_create_session_no_org(self):
        """Session without org has null home_org_id."""
        store = InMemorySessionStore()
        principal = Principal(
            key_id="test-admin",
            name="Test Admin",
            roles={"issuer:admin"},
        )
        session = await store.create(principal, ttl_seconds=3600)

        assert session.home_org_id is None
        assert session.active_org_id is None

    @pytest.mark.asyncio
    async def test_active_org_overrides_principal(self):
        """When active_org_id is set, principal.organization_id is overridden."""
        store = InMemorySessionStore()
        principal = Principal(
            key_id="test-admin",
            name="Test Admin",
            roles={"issuer:admin"},
            organization_id="home-org",
        )
        session = await store.create(principal, ttl_seconds=3600)

        # Manually set active_org_id (simulates switch-org)
        session.active_org_id = "switched-org"

        # Retrieve session — principal should have overridden org
        retrieved = await store.get(session.session_id)
        assert retrieved is not None
        assert retrieved.principal.organization_id == "switched-org"
        assert retrieved.home_org_id == "home-org"  # Immutable

    @pytest.mark.asyncio
    async def test_session_isolation(self):
        """Two sessions can have different active_org_id values."""
        store = InMemorySessionStore()
        principal = Principal(
            key_id="test-admin",
            name="Test Admin",
            roles={"issuer:admin"},
            organization_id="home-org",
        )

        session1 = await store.create(principal, ttl_seconds=3600)
        session2 = await store.create(principal, ttl_seconds=3600)

        session1.active_org_id = "org-a"
        session2.active_org_id = "org-b"

        r1 = await store.get(session1.session_id)
        r2 = await store.get(session2.session_id)

        assert r1.principal.organization_id == "org-a"
        assert r2.principal.organization_id == "org-b"


# =============================================================================
# POST /session/switch-org endpoint
# =============================================================================


class TestSwitchOrgEndpoint:
    """Tests for POST /session/switch-org."""

    @pytest.mark.asyncio
    async def test_admin_can_switch_org(self, client_with_auth: AsyncClient):
        """Admin can switch to another org."""
        target_org_id = _create_test_org(org_type="vetter_authority")
        cookies = await _login_as_admin(client_with_auth)

        response = await client_with_auth.post(
            "/session/switch-org",
            json={"organization_id": target_org_id},
            cookies=cookies,
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        assert response.status_code == 200, f"Switch failed: {response.text}"
        data = response.json()
        assert data["active_org_id"] == target_org_id
        assert data["active_org_type"] == "vetter_authority"

    @pytest.mark.asyncio
    async def test_non_admin_cannot_switch(self, client_with_auth: AsyncClient):
        """Non-admin user gets 403 when trying to switch org."""
        target_org_id = _create_test_org()
        cookies = await _login_as_readonly(client_with_auth)

        response = await client_with_auth.post(
            "/session/switch-org",
            json={"organization_id": target_org_id},
            cookies=cookies,
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_switch_to_null_reverts(self, client_with_auth: AsyncClient):
        """Switching to null reverts to home org."""
        target_org_id = _create_test_org()
        cookies = await _login_as_admin(client_with_auth)

        # Switch to target
        await client_with_auth.post(
            "/session/switch-org",
            json={"organization_id": target_org_id},
            cookies=cookies,
            headers={"X-Requested-With": "XMLHttpRequest"},
        )

        # Revert
        response = await client_with_auth.post(
            "/session/switch-org",
            json={"organization_id": None},
            cookies=cookies,
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["active_org_id"] is None

    @pytest.mark.asyncio
    async def test_switch_to_nonexistent_org(self, client_with_auth: AsyncClient):
        """Switching to non-existent org returns 404."""
        cookies = await _login_as_admin(client_with_auth)
        fake_id = str(uuid.uuid4())

        response = await client_with_auth.post(
            "/session/switch-org",
            json={"organization_id": fake_id},
            cookies=cookies,
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_switch_to_disabled_org(self, client_with_auth: AsyncClient):
        """Switching to disabled org returns 400."""
        disabled_org_id = _create_test_org(enabled=False)
        cookies = await _login_as_admin(client_with_auth)

        response = await client_with_auth.post(
            "/session/switch-org",
            json={"organization_id": disabled_org_id},
            cookies=cookies,
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_no_session_returns_400(self, client_with_auth: AsyncClient):
        """Request without session cookie returns 400."""
        response = await client_with_auth.post(
            "/session/switch-org",
            json={"organization_id": str(uuid.uuid4())},
            headers={
                "X-API-Key": TEST_ADMIN_KEY,
                "X-Requested-With": "XMLHttpRequest",
            },
        )
        assert response.status_code == 400


# =============================================================================
# Auth status reflects switched org
# =============================================================================


class TestAuthStatusOrgSwitching:
    """Tests for GET /auth/status with org switching."""

    @pytest.mark.asyncio
    async def test_status_shows_home_org(self, client_with_auth: AsyncClient):
        """Auth status shows home org when not switched."""
        cookies = await _login_as_admin(client_with_auth)

        response = await client_with_auth.get("/auth/status", cookies=cookies)
        assert response.status_code == 200
        data = response.json()
        assert data["authenticated"] is True
        # Admin key has no org — home fields should be null
        assert data["home_org_id"] is None
        assert data["active_org_id"] is None

    @pytest.mark.asyncio
    async def test_status_after_switch(self, client_with_auth: AsyncClient):
        """Auth status shows both home and active org after switch."""
        target_org_id = _create_test_org(org_type="root_authority", name=f"gleif-test-{uuid.uuid4().hex[:8]}")
        cookies = await _login_as_admin(client_with_auth)

        # Switch org
        switch_response = await client_with_auth.post(
            "/session/switch-org",
            json={"organization_id": target_org_id},
            cookies=cookies,
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        assert switch_response.status_code == 200

        # Check status
        response = await client_with_auth.get("/auth/status", cookies=cookies)
        assert response.status_code == 200
        data = response.json()

        assert data["active_org_id"] == target_org_id
        assert data["active_org_type"] == "root_authority"
        # organization_id should be the effective org (active)
        assert data["organization_id"] == target_org_id

    @pytest.mark.asyncio
    async def test_status_after_revert(self, client_with_auth: AsyncClient):
        """Auth status clears active org after revert."""
        target_org_id = _create_test_org()
        cookies = await _login_as_admin(client_with_auth)

        # Switch then revert
        await client_with_auth.post(
            "/session/switch-org",
            json={"organization_id": target_org_id},
            cookies=cookies,
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        await client_with_auth.post(
            "/session/switch-org",
            json={"organization_id": None},
            cookies=cookies,
            headers={"X-Requested-With": "XMLHttpRequest"},
        )

        response = await client_with_auth.get("/auth/status", cookies=cookies)
        assert response.status_code == 200
        data = response.json()
        assert data["active_org_id"] is None
        assert data["active_org_type"] is None

    @pytest.mark.asyncio
    async def test_switch_revert_uses_home_org(self, client_with_auth: AsyncClient):
        """After switch->revert, authorized operations use home org context."""
        target_org_id = _create_test_org(org_type="root_authority")
        cookies = await _login_as_admin(client_with_auth)

        # Switch to target org
        switch_resp = await client_with_auth.post(
            "/session/switch-org",
            json={"organization_id": target_org_id},
            cookies=cookies,
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        assert switch_resp.status_code == 200
        assert switch_resp.json()["active_org_id"] == target_org_id

        # Revert
        revert_resp = await client_with_auth.post(
            "/session/switch-org",
            json={"organization_id": None},
            cookies=cookies,
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        assert revert_resp.status_code == 200
        assert revert_resp.json()["active_org_id"] is None

        # Verify: auth/status reflects home org, not the switched org
        status_resp = await client_with_auth.get("/auth/status", cookies=cookies)
        assert status_resp.status_code == 200
        status = status_resp.json()
        assert status["active_org_id"] is None
        assert status["active_org_type"] is None
        # organization_id should be the home org (admin key has no org → null)
        assert status["organization_id"] != target_org_id


# =============================================================================
# Regression: Mismatched registry/org issuance returns 403
# =============================================================================


class TestIssuerBinding:
    """Tests for Sprint 67 issuer-binding check in credential issuance."""

    @pytest.mark.asyncio
    async def test_mismatched_registry_org_returns_403(self, client_with_auth: AsyncClient):
        """Credential issuance with registry not owned by resolved org returns 403."""
        from unittest.mock import patch, AsyncMock, MagicMock
        from common.vvp.models.keri_agent import RegistryResponse

        # Create an org with a specific AID
        org_aid = f"E{uuid.uuid4().hex[:43]}"
        org_id = _create_test_org(org_type="regular")

        # Update the org to have a specific AID and registry_key
        from app.db.session import SessionLocal
        db = SessionLocal()
        try:
            org = db.query(Organization).filter(Organization.id == org_id).first()
            org.aid = org_aid
            org.registry_key = f"E{uuid.uuid4().hex[:43]}"
            db.commit()
        finally:
            db.close()

        cookies = await _login_as_admin(client_with_auth)

        # Switch to the org so it's the resolved org context
        await client_with_auth.post(
            "/session/switch-org",
            json={"organization_id": org_id},
            cookies=cookies,
            headers={"X-Requested-With": "XMLHttpRequest"},
        )

        # Sprint 68b: Mock keri_client to return a registry with a DIFFERENT issuer AID
        different_aid = f"E{uuid.uuid4().hex[:43]}"
        mock_registry = RegistryResponse(
            registry_key=f"E{uuid.uuid4().hex[:43]}",
            name="mismatched-registry",
            identity_aid=different_aid,  # Different from org_aid
            identity_name="other-identity",
            credential_count=0,
        )

        mock_client = MagicMock()
        mock_client.get_registry = AsyncMock(return_value=mock_registry)

        # Mock schema auth to allow the issuance
        with patch("app.api.credential.get_keri_client", return_value=mock_client), \
             patch("app.auth.schema_auth.is_schema_authorized", return_value=True):
            response = await client_with_auth.post(
                "/credential/issue",
                json={
                    "schema_said": "EFake_Schema_SAID_For_Test_123456789012345",
                    "registry_name": "mismatched-registry",
                    "attributes": {"key": "value"},
                    "organization_id": org_id,
                },
                cookies=cookies,
                headers={"X-Requested-With": "XMLHttpRequest"},
            )

        assert response.status_code == 403, f"Expected 403, got {response.status_code}: {response.text}"
        assert "does not belong to" in response.json()["detail"]


# =============================================================================
# Audit event tests for switch-org
# =============================================================================


class TestSwitchOrgAudit:
    """Tests that POST /session/switch-org emits correct audit events."""

    @staticmethod
    def _find_switch_audit_events():
        """Get all session.switch_org audit events from the logger."""
        from app.audit import get_audit_logger
        audit = get_audit_logger()
        return [
            e for e in audit.get_recent_events(limit=50)
            if e.get("action") == "session.switch_org"
        ]

    @pytest.mark.asyncio
    async def test_switch_success_audit(self, client_with_auth: AsyncClient):
        """Successful switch emits audit with action_type=switch, outcome=success."""
        target_org_id = _create_test_org()
        cookies = await _login_as_admin(client_with_auth)

        resp = await client_with_auth.post(
            "/session/switch-org",
            json={"organization_id": target_org_id},
            cookies=cookies,
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        assert resp.status_code == 200

        events = self._find_switch_audit_events()
        assert len(events) >= 1
        latest = events[-1]
        assert latest["details"]["action_type"] == "switch"
        assert latest["details"]["outcome"] == "success"
        assert latest["details"]["to_org"] == target_org_id

    @pytest.mark.asyncio
    async def test_revert_success_audit(self, client_with_auth: AsyncClient):
        """Revert emits audit with action_type=revert, to_org='home'."""
        target_org_id = _create_test_org()
        cookies = await _login_as_admin(client_with_auth)

        # Switch then revert
        await client_with_auth.post(
            "/session/switch-org",
            json={"organization_id": target_org_id},
            cookies=cookies,
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        resp = await client_with_auth.post(
            "/session/switch-org",
            json={"organization_id": None},
            cookies=cookies,
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        assert resp.status_code == 200

        events = self._find_switch_audit_events()
        revert_events = [e for e in events if e["details"].get("action_type") == "revert"]
        assert len(revert_events) >= 1
        latest = revert_events[-1]
        assert latest["details"]["to_org"] == "home"
        assert latest["details"]["outcome"] == "success"

    @pytest.mark.asyncio
    async def test_denied_nonexistent_org_audit(self, client_with_auth: AsyncClient):
        """Switch to nonexistent org emits audit with outcome=denied."""
        cookies = await _login_as_admin(client_with_auth)
        fake_id = str(uuid.uuid4())

        resp = await client_with_auth.post(
            "/session/switch-org",
            json={"organization_id": fake_id},
            cookies=cookies,
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        assert resp.status_code == 404

        events = self._find_switch_audit_events()
        denied_events = [e for e in events if e["details"].get("outcome") == "denied"]
        assert len(denied_events) >= 1
        latest = denied_events[-1]
        assert latest["details"]["reason"] == "org_not_found"
        assert latest["details"]["to_org"] == fake_id

    @pytest.mark.asyncio
    async def test_denied_disabled_org_audit(self, client_with_auth: AsyncClient):
        """Switch to disabled org emits audit with outcome=denied."""
        disabled_org_id = _create_test_org(enabled=False)
        cookies = await _login_as_admin(client_with_auth)

        resp = await client_with_auth.post(
            "/session/switch-org",
            json={"organization_id": disabled_org_id},
            cookies=cookies,
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        assert resp.status_code == 400

        events = self._find_switch_audit_events()
        denied_events = [e for e in events if e["details"].get("outcome") == "denied"]
        assert len(denied_events) >= 1
        latest = denied_events[-1]
        assert latest["details"]["reason"] == "org_disabled"
