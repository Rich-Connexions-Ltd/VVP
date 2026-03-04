"""Tests for PBX facade endpoints (Sprint 77).

Facade endpoints proxy /pbx/ → /organizations/* so the PBX portal's
CORS policy only needs to allow the /pbx/* prefix — no exceptions for
/organizations/* paths.

Sprint 77: Covers access-control branching for pbx_organization_api_keys:
  - issuer:admin can access any org
  - org:administrator can access their own org but NOT other orgs (cross-org 403)
  - any key without issuer:admin and without org:administrator gets 403
  - unknown org_id returns 404 (even for admin)
"""

import pytest
from httpx import AsyncClient

from tests.conftest import TEST_ADMIN_KEY, TEST_OPERATOR_KEY


def _init_db():
    from app.db.session import init_database
    init_database()


@pytest.mark.asyncio
class TestPBXOrganizationNames:
    """GET /pbx/organizations/names — facade for org listing."""

    async def test_admin_can_list_organizations(self, client: AsyncClient):
        """issuer:admin (auth disabled dummy principal) can list organizations."""
        _init_db()
        resp = await client.get("/pbx/organizations/names")
        assert resp.status_code == 200
        data = resp.json()
        assert "count" in data
        assert "organizations" in data
        assert isinstance(data["organizations"], list)

    async def test_response_count_matches_list_length(self, client: AsyncClient):
        """Response count field equals the length of the organizations list."""
        _init_db()
        resp = await client.get("/pbx/organizations/names")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == len(data["organizations"])

    async def test_response_fields_are_id_and_name_only(self, client: AsyncClient):
        """Each organization in the response has only id and name fields."""
        _init_db()
        from app.db.session import SessionLocal
        from app.db.models import Organization

        # Create a test org so the response is non-empty
        db = SessionLocal()
        try:
            # Clean up any residual test data from previous runs
            db.query(Organization).filter(Organization.id == "test-org-names-facade").delete()
            db.commit()
            org = Organization(
                id="test-org-names-facade",
                name="Names Facade Test Org",
                pseudo_lei="XNAMES0001",
                enabled=True,
            )
            db.add(org)
            db.commit()
        finally:
            db.close()

        resp = await client.get("/pbx/organizations/names")
        assert resp.status_code == 200
        data = resp.json()
        for org in data["organizations"]:
            assert set(org.keys()) == {"id", "name"}

    async def test_non_admin_returns_403(self, client_with_auth: AsyncClient):
        """Key without issuer:admin returns 403."""
        _init_db()
        resp = await client_with_auth.get(
            "/pbx/organizations/names",
            headers={"X-API-Key": TEST_OPERATOR_KEY},
        )
        assert resp.status_code == 403

    async def test_unauthenticated_returns_401(self, client_with_auth: AsyncClient):
        """No API key returns 401."""
        _init_db()
        resp = await client_with_auth.get("/pbx/organizations/names")
        assert resp.status_code == 401

    async def test_admin_authenticated_returns_200(self, client_with_auth: AsyncClient):
        """issuer:admin key can access the organizations/names facade."""
        _init_db()
        resp = await client_with_auth.get(
            "/pbx/organizations/names",
            headers={"X-API-Key": TEST_ADMIN_KEY},
        )
        assert resp.status_code == 200


@pytest.mark.asyncio
class TestPBXOrganizationAPIKeys:
    """GET /pbx/organizations/{org_id}/api-keys — facade with org-scoping."""

    async def test_unknown_org_returns_404(self, client: AsyncClient):
        """Unknown org_id returns 404 (admin bypass → DB check → 404)."""
        _init_db()
        resp = await client.get("/pbx/organizations/nonexistent-org-id/api-keys")
        assert resp.status_code == 404
        assert "not found" in resp.json()["detail"].lower()

    async def test_operator_cross_org_returns_403(self, client_with_auth: AsyncClient):
        """Key without issuer:admin or org:administrator gets 403 on existing org."""
        _init_db()
        from app.db.session import SessionLocal
        from app.db.models import Organization
        db = SessionLocal()
        try:
            db.query(Organization).filter(Organization.id == "test-operator-target-org").delete()
            db.commit()
            db.add(Organization(
                id="test-operator-target-org",
                name="Operator Target Org",
                pseudo_lei="XOPRTGT001",
                enabled=True,
            ))
            db.commit()
        finally:
            db.close()
        resp = await client_with_auth.get(
            "/pbx/organizations/test-operator-target-org/api-keys",
            headers={"X-API-Key": TEST_OPERATOR_KEY},
        )
        assert resp.status_code == 403

    async def test_org_admin_cross_org_returns_403(self, client: AsyncClient):
        """org:administrator for org-A is rejected when accessing org-B.

        Tests the `principal.organization_id != org_id` check specifically:
        a principal with org:administrator and organization_id="test-cross-org-a"
        must not access "/pbx/organizations/test-cross-org-b/api-keys".

        Both orgs are created in the DB so _check_org_admin_access reaches
        the authorization check (not the 404 branch).
        """
        _init_db()
        from app.db.session import SessionLocal
        from app.db.models import Organization
        import app.main as main_module
        from app.auth.api_key import Principal
        from app.auth.roles import require_auth

        db = SessionLocal()
        try:
            for org_id in ("test-cross-org-a", "test-cross-org-b"):
                db.query(Organization).filter(Organization.id == org_id).delete()
            db.commit()
            db.add(Organization(id="test-cross-org-a", name="Org A", pseudo_lei="XCORGA001", enabled=True))
            db.add(Organization(id="test-cross-org-b", name="Org B", pseudo_lei="XCORGB001", enabled=True))
            db.commit()
        finally:
            db.close()

        async def org_admin_for_org_a():
            return Principal(
                key_id="test-org-a-admin",
                name="Org A Admin",
                roles=["org:administrator"],
                organization_id="test-cross-org-a",
            )

        # Override require_auth to inject an org:administrator principal for
        # org-A attempting to access org-B.
        main_module.app.dependency_overrides[require_auth.dependency] = org_admin_for_org_a
        try:
            resp = await client.get("/pbx/organizations/test-cross-org-b/api-keys")
            assert resp.status_code == 403
        finally:
            main_module.app.dependency_overrides.pop(require_auth.dependency, None)

    async def test_org_admin_same_org_returns_200(self, client: AsyncClient):
        """org:administrator for org-A can access org-A's own API keys.

        Tests the same-org success path through _check_org_admin_access:
        a principal with org:administrator and organization_id="test-same-org-access"
        must be permitted to access "/pbx/organizations/test-same-org-access/api-keys".
        """
        _init_db()
        from app.db.session import SessionLocal
        from app.db.models import Organization
        import app.main as main_module
        from app.auth.api_key import Principal
        from app.auth.roles import require_auth

        org_id = "test-same-org-access"
        db = SessionLocal()
        try:
            db.query(Organization).filter(Organization.id == org_id).delete()
            db.commit()
            db.add(Organization(id=org_id, name="Same Org Access", pseudo_lei="XSAMEORG1", enabled=True))
            db.commit()
        finally:
            db.close()

        async def org_admin_for_own_org():
            return Principal(
                key_id="test-same-org-admin",
                name="Same Org Admin",
                roles=["org:administrator"],
                organization_id=org_id,
            )

        main_module.app.dependency_overrides[require_auth.dependency] = org_admin_for_own_org
        try:
            resp = await client.get(f"/pbx/organizations/{org_id}/api-keys")
            assert resp.status_code == 200
            data = resp.json()
            assert "api_keys" in data
            assert data["count"] == 0  # Org exists but has no keys
        finally:
            main_module.app.dependency_overrides.pop(require_auth.dependency, None)

    async def test_admin_bypasses_org_scope_check(self, client_with_auth: AsyncClient):
        """issuer:admin is not rejected by org-scoping — gets 404 from DB, not 403."""
        _init_db()
        resp = await client_with_auth.get(
            "/pbx/organizations/any-org-id/api-keys",
            headers={"X-API-Key": TEST_ADMIN_KEY},
        )
        # 404 from DB (org not found) — RBAC check was bypassed, DB check ran
        assert resp.status_code == 404

    async def test_response_excludes_roles(self, client: AsyncClient):
        """API key listing returns id and name only — roles excluded."""
        _init_db()
        from app.db.session import SessionLocal
        from app.db.models import Organization, OrgAPIKey
        import uuid

        db = SessionLocal()
        try:
            org_id = "test-org-keys-facade"
            # Clean up any residual test data from previous runs
            db.query(OrgAPIKey).filter(OrgAPIKey.organization_id == org_id).delete()
            db.query(Organization).filter(Organization.id == org_id).delete()
            db.commit()
            org = Organization(
                id=org_id,
                name="Keys Facade Test Org",
                pseudo_lei="XKEYS0001",
                enabled=True,
            )
            db.add(org)
            db.flush()

            key = OrgAPIKey(
                id=str(uuid.uuid4()),
                name="Test Key",
                organization_id=org_id,
                key_hash="dummy-hash",
                revoked=False,
            )
            db.add(key)
            db.commit()
        finally:
            db.close()

        resp = await client.get(f"/pbx/organizations/{org_id}/api-keys")
        assert resp.status_code == 200
        data = resp.json()
        assert "api_keys" in data
        assert "count" in data
        assert data["count"] == 1
        for api_key in data["api_keys"]:
            # Exact set check: catches any new field added (roles, key_hash, etc.)
            assert set(api_key.keys()) == {"id", "name"}

    async def test_revoked_keys_excluded_from_response(self, client: AsyncClient):
        """Revoked API keys must NOT appear in the facade listing."""
        _init_db()
        from app.db.session import SessionLocal
        from app.db.models import Organization, OrgAPIKey
        import uuid

        db = SessionLocal()
        try:
            org_id = "test-org-revoked-facade"
            db.query(OrgAPIKey).filter(OrgAPIKey.organization_id == org_id).delete()
            db.query(Organization).filter(Organization.id == org_id).delete()
            db.commit()
            db.add(Organization(
                id=org_id,
                name="Revoked Keys Test Org",
                pseudo_lei="XREVOK0001",
                enabled=True,
            ))
            db.flush()
            # One active key, one revoked key
            active_key_id = str(uuid.uuid4())
            db.add(OrgAPIKey(
                id=active_key_id,
                name="Active Key",
                organization_id=org_id,
                key_hash="hash-active",
                revoked=False,
            ))
            db.add(OrgAPIKey(
                id=str(uuid.uuid4()),
                name="Revoked Key",
                organization_id=org_id,
                key_hash="hash-revoked",
                revoked=True,
            ))
            db.commit()
        finally:
            db.close()

        resp = await client.get(f"/pbx/organizations/{org_id}/api-keys")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 1
        assert len(data["api_keys"]) == 1
        assert data["api_keys"][0]["id"] == active_key_id
