"""Tests for KERI Agent bulk identity cleanup filter safety and metadata filtering.

Sprint 74: KERI Identity Stability — verifies:
- Safety guard rejects cleanup with no filter criteria (HTTP 400)
- metadata_type filter correctly selects/skips identities by metadata type
"""
import pytest
from httpx import AsyncClient


async def _create_identity(client: AsyncClient, name: str, metadata: dict | None = None) -> dict:
    """Create an identity, optionally with metadata."""
    payload = {"name": name, "transferable": True}
    if metadata is not None:
        payload["metadata"] = metadata
    resp = await client.post("/identities", json=payload)
    assert resp.status_code == 201, f"Failed to create identity {name!r}: {resp.text}"
    return resp.json()


class TestCleanupFilterSafetyGuard:
    """HTTP 400 is raised when no filter criterion is provided."""

    @pytest.mark.asyncio
    async def test_cleanup_requires_filter_criterion(self, client: AsyncClient):
        """No filter criteria → 400 Bad Request.

        Prevents accidental "delete all" when callers send an empty or
        partially-formed cleanup request.
        """
        resp = await client.post("/admin/cleanup/identities", json={
            "cascade_credentials": True,
            "force": True,
        })
        assert resp.status_code == 400
        detail = resp.json().get("detail", "")
        assert "filter criterion" in detail.lower() or "filter" in detail.lower()

    @pytest.mark.asyncio
    async def test_cleanup_with_name_pattern_bypasses_guard(self, client: AsyncClient):
        """name_pattern is a valid filter criterion — should not raise 400."""
        resp = await client.post("/admin/cleanup/identities", json={
            "name_pattern": "nonexistent-pattern-xyz-*",
        })
        # 200 with 0 matches (pattern doesn't match anything) is the expected response
        assert resp.status_code == 200
        assert resp.json()["deleted_count"] == 0

    @pytest.mark.asyncio
    async def test_cleanup_with_names_bypasses_guard(self, client: AsyncClient):
        """Explicit names list is a valid filter criterion — should not raise 400."""
        resp = await client.post("/admin/cleanup/identities", json={
            "names": ["nonexistent-identity-xyz"],
        })
        assert resp.status_code == 200
        assert resp.json()["deleted_count"] == 0

    @pytest.mark.asyncio
    async def test_cleanup_with_metadata_type_bypasses_guard(self, client: AsyncClient):
        """metadata_type is a valid filter criterion — should not raise 400."""
        resp = await client.post("/admin/cleanup/identities", json={
            "metadata_type": "test",
        })
        assert resp.status_code == 200
        assert resp.json()["deleted_count"] == 0


class TestCleanupMetadataTypeFilter:
    """metadata_type filter correctly selects identities."""

    @pytest.mark.asyncio
    async def test_metadata_type_test_deletes_test_identity(self, client: AsyncClient):
        """Identity with metadata type=test IS deleted when metadata_type=test."""
        await _create_identity(client, "filter-test-identity", metadata={"type": "test"})

        resp = await client.post("/admin/cleanup/identities", json={
            "metadata_type": "test",
            "force": True,
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "filter-test-identity" in data["deleted_names"]

    @pytest.mark.asyncio
    async def test_metadata_type_test_skips_org_identity(self, client: AsyncClient):
        """Identity with metadata type=org is NOT deleted when metadata_type=test."""
        await _create_identity(client, "filter-org-identity", metadata={"type": "org", "org_id": "test-org-id"})

        resp = await client.post("/admin/cleanup/identities", json={
            "metadata_type": "test",
            "force": True,
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "filter-org-identity" not in data["deleted_names"]

        # Verify the org identity still exists
        list_resp = await client.get("/identities")
        assert list_resp.status_code == 200
        names = [i["name"] for i in list_resp.json()]
        assert "filter-org-identity" in names

    @pytest.mark.asyncio
    async def test_metadata_type_test_skips_mock_gleif(self, client: AsyncClient):
        """Identity with metadata type=mock_gleif is NOT deleted when metadata_type=test."""
        await _create_identity(client, "filter-mock-gleif", metadata={"type": "mock_gleif"})

        resp = await client.post("/admin/cleanup/identities", json={
            "metadata_type": "test",
            "force": True,
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "filter-mock-gleif" not in data["deleted_names"]

        list_resp = await client.get("/identities")
        assert list_resp.status_code == 200
        names = [i["name"] for i in list_resp.json()]
        assert "filter-mock-gleif" in names

    @pytest.mark.asyncio
    async def test_metadata_type_selects_only_matching_type(self, client: AsyncClient):
        """With mixed identity types, only type=test identities are deleted."""
        await _create_identity(client, "mixed-test-1", metadata={"type": "test"})
        await _create_identity(client, "mixed-test-2", metadata={"type": "test"})
        await _create_identity(client, "mixed-org-1", metadata={"type": "org", "org_id": "org-abc"})
        await _create_identity(client, "mixed-gleif-1", metadata={"type": "mock_gleif"})

        resp = await client.post("/admin/cleanup/identities", json={
            "metadata_type": "test",
            "force": True,
        })
        assert resp.status_code == 200
        data = resp.json()

        deleted = set(data["deleted_names"])
        assert "mixed-test-1" in deleted
        assert "mixed-test-2" in deleted
        assert "mixed-org-1" not in deleted
        assert "mixed-gleif-1" not in deleted

    @pytest.mark.asyncio
    async def test_metadata_type_dry_run_reports_correctly(self, client: AsyncClient):
        """Dry run with metadata_type filter reports correct targets without deleting."""
        await _create_identity(client, "dryrun-test-id", metadata={"type": "test"})
        await _create_identity(client, "dryrun-org-id", metadata={"type": "org", "org_id": "org-xyz"})

        resp = await client.post("/admin/cleanup/identities", json={
            "metadata_type": "test",
            "dry_run": True,
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["dry_run"] is True
        assert "dryrun-test-id" in data["deleted_names"]
        assert "dryrun-org-id" not in data["deleted_names"]

        # Nothing actually deleted
        list_resp = await client.get("/identities")
        names = [i["name"] for i in list_resp.json()]
        assert "dryrun-test-id" in names
        assert "dryrun-org-id" in names
