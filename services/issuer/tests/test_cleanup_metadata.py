"""Tests for issuer bulk identity cleanup metadata_type passthrough.

Sprint 74: KERI Identity Stability — verifies that metadata_type is
forwarded from the issuer cleanup endpoint to the KERI Agent.
"""
import pytest
from unittest.mock import AsyncMock, patch
from httpx import AsyncClient


class TestBulkCleanupMetadataType:
    """Tests for metadata_type passthrough in POST /admin/cleanup/identities."""

    @pytest.mark.asyncio
    async def test_metadata_type_forwarded_to_agent(self, client: AsyncClient):
        """metadata_type in request body is forwarded to KERI Agent.

        When the issuer receives a cleanup request with metadata_type,
        it must include metadata_type in the body sent to the KERI Agent.
        """
        captured = {}

        async def mock_bulk_cleanup(body: dict):
            captured["body"] = body
            return {
                "deleted_count": 0,
                "deleted_names": [],
                "failed": [],
                "blocked_names": [],
                "cascaded_credential_count": 0,
                "dry_run": False,
            }

        import app.keri_client as kc_module
        mock_client = AsyncMock()
        mock_client.bulk_cleanup_identities.side_effect = mock_bulk_cleanup

        with patch.object(kc_module, "get_keri_client", return_value=mock_client):
            resp = await client.post(
                "/admin/cleanup/identities",
                json={
                    "metadata_type": "test",
                    "cascade_credentials": True,
                    "force": True,
                },
                headers={"X-API-Key": "test-admin-key-12345"},
            )

        assert resp.status_code == 200, resp.text
        assert "body" in captured, "KERI Agent was not called"
        assert captured["body"].get("metadata_type") == "test"

    @pytest.mark.asyncio
    async def test_metadata_type_absent_not_forwarded(self, client: AsyncClient):
        """Omitting metadata_type does not inject it into KERI Agent body.

        When the issuer receives a cleanup request without metadata_type,
        the field must not appear in the KERI Agent request body (it is
        optional — the KERI Agent's filter guard requires at least one other
        criterion, so we supply name_pattern to satisfy it).
        """
        captured = {}

        async def mock_bulk_cleanup(body: dict):
            captured["body"] = body
            return {
                "deleted_count": 0,
                "deleted_names": [],
                "failed": [],
                "blocked_names": [],
                "cascaded_credential_count": 0,
                "dry_run": True,
            }

        import app.keri_client as kc_module
        mock_client = AsyncMock()
        mock_client.bulk_cleanup_identities.side_effect = mock_bulk_cleanup

        with patch.object(kc_module, "get_keri_client", return_value=mock_client):
            resp = await client.post(
                "/admin/cleanup/identities",
                json={
                    "name_pattern": "test-*",
                    "dry_run": True,
                },
                headers={"X-API-Key": "test-admin-key-12345"},
            )

        assert resp.status_code == 200, resp.text
        assert "body" in captured, "KERI Agent was not called"
        assert "metadata_type" not in captured["body"]
