"""Tests for issuer bulk cleanup and cascade delete.

Sprint 73: Credential & Identity Cleanup — Cascade Delete and Bulk Purge.
"""
import uuid

import pytest
from httpx import AsyncClient

TN_ALLOCATION_SCHEMA = "EFvnoHDY7I-kaBBeKlbDbkjG4BaI0nKLGadxBdjMGgSQ"


def _create_test_org(org_type: str = "regular") -> str:
    """Create a test org in DB. Returns org_id."""
    from app.db.session import init_database, SessionLocal
    from app.db.models import Organization

    init_database()
    org_id = str(uuid.uuid4())
    db = SessionLocal()
    try:
        org = Organization(
            id=org_id,
            name=f"cleanup-test-{uuid.uuid4().hex[:8]}",
            pseudo_lei=f"54930{uuid.uuid4().hex[:15]}",
            aid=f"E{uuid.uuid4().hex[:43]}",
            registry_key=f"E{uuid.uuid4().hex[:43]}",
            org_type=org_type,
            enabled=True,
        )
        db.add(org)
        db.commit()
        return org_id
    finally:
        db.close()


async def _create_identity(client: AsyncClient, name: str = None) -> dict:
    """Helper to create a test identity."""
    name = name or f"cleanup-id-{uuid.uuid4().hex[:8]}"
    response = await client.post(
        "/identity",
        json={"name": name, "publish_to_witnesses": False},
    )
    assert response.status_code == 200, f"Failed to create identity: {response.text}"
    return response.json()["identity"]


async def _create_registry(client: AsyncClient, identity_name: str) -> dict:
    """Helper to create a test registry."""
    name = f"cleanup-reg-{uuid.uuid4().hex[:8]}"
    response = await client.post(
        "/registry",
        json={
            "name": name,
            "identity_name": identity_name,
            "publish_to_witnesses": False,
        },
    )
    assert response.status_code == 200, f"Failed to create registry: {response.text}"
    return response.json()["registry"]


async def setup_identity_and_registry(client: AsyncClient):
    """Helper to create identity, registry, and org for testing."""
    identity = await _create_identity(client)
    registry = await _create_registry(client, identity["name"])
    org_id = _create_test_org("regular")

    # Sync org AID and registry_key with real KERI identity/registry
    from app.db.session import SessionLocal
    from app.db.models import Organization
    db = SessionLocal()
    try:
        org = db.query(Organization).filter(Organization.id == org_id).first()
        org.aid = identity["aid"]
        org.registry_key = registry["registry_key"]
        db.commit()
    finally:
        db.close()

    return identity, registry, org_id


async def _issue_credential(client: AsyncClient, registry_name: str, org_id: str, tn: str = "+12025559999"):
    """Helper to issue a TN Allocation credential."""
    resp = await client.post("/credential/issue", json={
        "registry_name": registry_name,
        "schema_said": TN_ALLOCATION_SCHEMA,
        "attributes": {
            "numbers": {"tn": [tn]},
            "channel": "voice",
            "doNotOriginate": False,
        },
        "publish_to_witnesses": False,
        "organization_id": org_id,
    })
    assert resp.status_code == 200, f"Credential issuance failed: {resp.text}"
    return resp.json()["credential"]["said"]


# ============================================================================
# Credential Delete Cascade to managed_credentials
# ============================================================================


class TestCredentialDeleteCascade:
    """Test that DELETE /credential/{said} cleans up managed_credentials."""

    @pytest.mark.asyncio
    async def test_delete_credential_removes_managed_credential(self, client: AsyncClient):
        """Deleting a credential should also remove its managed_credentials row."""
        identity, registry, org_id = await setup_identity_and_registry(client)

        cred_said = await _issue_credential(client, registry["name"], org_id)

        # Verify credential is in the list
        list_resp = await client.get(f"/credential?organization_id={org_id}")
        assert list_resp.status_code == 200
        saids_before = [c["said"] for c in list_resp.json()["credentials"]]
        assert cred_said in saids_before

        # Delete the credential
        delete_resp = await client.delete(f"/credential/{cred_said}")
        assert delete_resp.status_code == 200
        assert delete_resp.json()["deleted"] is True

        # Verify it's gone from the list (managed_credentials cleaned up)
        list_resp = await client.get(f"/credential?organization_id={org_id}")
        assert list_resp.status_code == 200
        saids_after = [c["said"] for c in list_resp.json()["credentials"]]
        assert cred_said not in saids_after


# ============================================================================
# Bulk Cleanup Credentials
# ============================================================================


class TestBulkCleanupCredentials:
    """Tests for POST /admin/cleanup/credentials."""

    @pytest.mark.asyncio
    async def test_empty_cleanup(self, client: AsyncClient):
        """Cleanup with no matching credentials returns 0."""
        resp = await client.post("/admin/cleanup/credentials", json={
            "organization_id": "nonexistent-org-id",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["deleted_count"] == 0

    @pytest.mark.asyncio
    async def test_dry_run(self, client: AsyncClient):
        """Dry run reports matching credentials without deleting."""
        identity, registry, org_id = await setup_identity_and_registry(client)

        cred_said = await _issue_credential(client, registry["name"], org_id, "+12025558888")

        # Dry run
        resp = await client.post("/admin/cleanup/credentials", json={
            "organization_id": org_id,
            "dry_run": True,
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["dry_run"] is True
        assert data["deleted_count"] >= 1
        assert cred_said in data["deleted_saids"]

        # Credential should still exist
        list_resp = await client.get(f"/credential?organization_id={org_id}")
        assert cred_said in [c["said"] for c in list_resp.json()["credentials"]]

    @pytest.mark.asyncio
    async def test_bulk_delete_by_org(self, client: AsyncClient):
        """Bulk delete all credentials for an organization."""
        identity, registry, org_id = await setup_identity_and_registry(client)

        # Issue two credentials
        saids = []
        for i in range(2):
            said = await _issue_credential(client, registry["name"], org_id, f"+1202555{7700 + i}")
            saids.append(said)

        # Bulk delete
        resp = await client.post("/admin/cleanup/credentials", json={
            "organization_id": org_id,
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["deleted_count"] == 2
        assert data["dry_run"] is False

        # Verify credentials are gone from managed list
        list_resp = await client.get(f"/credential?organization_id={org_id}")
        remaining_saids = [c["said"] for c in list_resp.json()["credentials"]]
        for said in saids:
            assert said not in remaining_saids


# ============================================================================
# Bulk Cleanup Identities
# ============================================================================


class TestBulkCleanupIdentities:
    """Tests for POST /admin/cleanup/identities."""

    @pytest.mark.asyncio
    async def test_empty_cleanup(self, client: AsyncClient):
        """Cleanup with no matching identities returns 0."""
        resp = await client.post("/admin/cleanup/identities", json={
            "name_pattern": "nonexistent-*",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["deleted_count"] == 0

    @pytest.mark.asyncio
    async def test_dry_run(self, client: AsyncClient):
        """Dry run reports what would be deleted."""
        resp = await client.post("/admin/cleanup/identities", json={
            "name_pattern": "test-*",
            "dry_run": True,
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["dry_run"] is True


# ============================================================================
# Admin auth required
# ============================================================================


class TestCleanupAuth:
    """Tests that cleanup endpoints require admin auth."""

    @pytest.mark.asyncio
    async def test_cleanup_credentials_requires_admin(
        self, client_with_auth: AsyncClient, operator_headers: dict,
    ):
        """Non-admin users cannot use cleanup endpoints."""
        resp = await client_with_auth.post(
            "/admin/cleanup/credentials",
            json={},
            headers=operator_headers,
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_cleanup_identities_requires_admin(
        self, client_with_auth: AsyncClient, operator_headers: dict,
    ):
        """Non-admin users cannot use cleanup endpoints."""
        resp = await client_with_auth.post(
            "/admin/cleanup/identities",
            json={},
            headers=operator_headers,
        )
        assert resp.status_code == 403
