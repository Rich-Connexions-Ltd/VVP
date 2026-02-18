"""Tests for KERI Agent bulk cleanup admin endpoints.

Sprint 73: Credential & Identity Cleanup — Cascade Delete and Bulk Purge.
"""
import json

import pytest
from httpx import AsyncClient

TN_ALLOCATION_SCHEMA = "EFvnoHDY7I-kaBBeKlbDbkjG4BaI0nKLGadxBdjMGgSQ"


async def _issue_credential(client: AsyncClient, identity_name: str, registry_name: str, tn: str = "+12025551234"):
    """Helper to issue a TN Allocation credential via KERI Agent API."""
    resp = await client.post("/credentials/issue", json={
        "identity_name": identity_name,
        "registry_name": registry_name,
        "schema_said": TN_ALLOCATION_SCHEMA,
        "attributes": {
            "numbers": {"tn": [tn]},
            "channel": "voice",
            "doNotOriginate": False,
        },
        "publish": False,
    })
    assert resp.status_code == 201, f"Credential issuance failed: {resp.text}"
    return resp.json()["said"]


# ============================================================================
# Credential Bulk Cleanup
# ============================================================================


class TestBulkCleanupCredentials:
    """Tests for POST /admin/cleanup/credentials."""

    @pytest.mark.asyncio
    async def test_empty_cleanup(self, client: AsyncClient):
        """Cleanup with no matching credentials returns 0."""
        resp = await client.post("/admin/cleanup/credentials", json={
            "schema_said": "ENONEXISTENT",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["deleted_count"] == 0
        assert data["deleted_saids"] == []

    @pytest.mark.asyncio
    async def test_dry_run_does_not_delete(self, client: AsyncClient):
        """Dry run returns what would be deleted without actually deleting."""
        # Create an identity and credential first
        resp = await client.post("/identities", json={
            "name": "cleanup-test-issuer",
            "transferable": True,
        })
        assert resp.status_code == 201

        resp = await client.post("/registries", json={
            "name": "cleanup-test-registry",
            "identity_name": "cleanup-test-issuer",
        })
        assert resp.status_code == 201

        cred_said = await _issue_credential(client, "cleanup-test-issuer", "cleanup-test-registry")

        # Dry run
        resp = await client.post("/admin/cleanup/credentials", json={
            "saids": [cred_said],
            "dry_run": True,
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["dry_run"] is True
        assert data["deleted_count"] == 1
        assert cred_said in data["deleted_saids"]

        # Verify credential still exists
        resp = await client.get(f"/credentials/{cred_said}")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_delete_by_said_list(self, client: AsyncClient):
        """Delete specific credentials by SAID list."""
        # Create infrastructure
        await client.post("/identities", json={
            "name": "bulk-issuer",
            "transferable": True,
        })
        await client.post("/registries", json={
            "name": "bulk-registry",
            "identity_name": "bulk-issuer",
        })

        # Issue two credentials
        saids = []
        for i in range(2):
            said = await _issue_credential(client, "bulk-issuer", "bulk-registry", f"+1202555000{i}")
            saids.append(said)

        # Delete first credential
        resp = await client.post("/admin/cleanup/credentials", json={
            "saids": [saids[0]],
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["deleted_count"] == 1
        assert saids[0] in data["deleted_saids"]
        assert data["dry_run"] is False

        # First credential gone
        resp = await client.get(f"/credentials/{saids[0]}")
        assert resp.status_code == 404

        # Second credential still exists
        resp = await client.get(f"/credentials/{saids[1]}")
        assert resp.status_code == 200


# ============================================================================
# Identity Bulk Cleanup
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
        await client.post("/identities", json={
            "name": "dry-run-test",
            "transferable": True,
        })

        resp = await client.post("/admin/cleanup/identities", json={
            "names": ["dry-run-test"],
            "dry_run": True,
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["dry_run"] is True
        assert data["deleted_count"] == 1
        assert "dry-run-test" in data["deleted_names"]

        # Verify identity still exists
        resp = await client.get("/identities")
        names = [i["name"] for i in resp.json()]
        assert "dry-run-test" in names

    @pytest.mark.asyncio
    async def test_delete_by_name_pattern(self, client: AsyncClient):
        """Delete identities matching a glob pattern."""
        for i in range(3):
            await client.post("/identities", json={
                "name": f"test-cleanup-{i}",
                "transferable": True,
            })
        await client.post("/identities", json={
            "name": "keep-this-one",
            "transferable": True,
        })

        resp = await client.post("/admin/cleanup/identities", json={
            "name_pattern": "test-cleanup-*",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["deleted_count"] == 3

        # Verify only keep-this-one remains
        resp = await client.get("/identities")
        names = [i["name"] for i in resp.json()]
        assert "keep-this-one" in names
        assert all(f"test-cleanup-{i}" not in names for i in range(3))

    @pytest.mark.asyncio
    async def test_blocks_identity_with_credentials(self, client: AsyncClient):
        """By default, refuses to delete identities that have issued credentials."""
        # Create identity + registry + credential
        await client.post("/identities", json={
            "name": "has-creds",
            "transferable": True,
        })
        await client.post("/registries", json={
            "name": "has-creds-registry",
            "identity_name": "has-creds",
        })
        await _issue_credential(client, "has-creds", "has-creds-registry")

        # Try to delete — should be blocked
        resp = await client.post("/admin/cleanup/identities", json={
            "names": ["has-creds"],
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["deleted_count"] == 0
        assert len(data["blocked_names"]) == 1
        assert data["blocked_names"][0]["name"] == "has-creds"

    @pytest.mark.asyncio
    async def test_cascade_credentials_deletes_both(self, client: AsyncClient):
        """cascade_credentials=true deletes identity AND its credentials."""
        await client.post("/identities", json={
            "name": "cascade-me",
            "transferable": True,
        })
        await client.post("/registries", json={
            "name": "cascade-registry",
            "identity_name": "cascade-me",
        })
        cred_said = await _issue_credential(client, "cascade-me", "cascade-registry")

        # Delete with cascade
        resp = await client.post("/admin/cleanup/identities", json={
            "names": ["cascade-me"],
            "cascade_credentials": True,
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["deleted_count"] == 1
        assert data["cascaded_credential_count"] == 1

        # Credential should be gone
        resp = await client.get(f"/credentials/{cred_said}")
        assert resp.status_code == 404


# ============================================================================
# Cascade Delete (single item endpoints)
# ============================================================================


class TestCascadeDelete:
    """Tests that single DELETE endpoints remove items from LMDB.

    Seed store cascade is verified via unit tests in test_seed_store_delete.py.
    These tests verify the API-level wiring works end-to-end.
    """

    @pytest.mark.asyncio
    async def test_delete_credential_removes_from_lmdb(self, client: AsyncClient):
        """DELETE /credentials/{said} removes credential from LMDB."""
        await client.post("/identities", json={
            "name": "cascade-cred-issuer",
            "transferable": True,
        })
        await client.post("/registries", json={
            "name": "cascade-cred-registry",
            "identity_name": "cascade-cred-issuer",
        })
        cred_said = await _issue_credential(client, "cascade-cred-issuer", "cascade-cred-registry")

        # Credential exists
        resp = await client.get(f"/credentials/{cred_said}")
        assert resp.status_code == 200

        # Delete it
        resp = await client.delete(f"/credentials/{cred_said}")
        assert resp.status_code == 204

        # Gone
        resp = await client.get(f"/credentials/{cred_said}")
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_delete_identity_removes_from_lmdb(self, client: AsyncClient):
        """DELETE /identities/{name} removes identity from LMDB."""
        resp = await client.post("/identities", json={
            "name": "cascade-del-id",
            "transferable": True,
        })
        assert resp.status_code == 201

        # Identity exists
        resp = await client.get("/identities")
        names = [i["name"] for i in resp.json()]
        assert "cascade-del-id" in names

        # Delete it
        resp = await client.delete("/identities/cascade-del-id")
        assert resp.status_code == 204

        # Gone
        resp = await client.get("/identities")
        names = [i["name"] for i in resp.json()]
        assert "cascade-del-id" not in names
