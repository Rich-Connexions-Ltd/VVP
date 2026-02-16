"""Tests for KERI agent outage → HTTP 503 mapping and migration regressions.

Sprint 68b: Verifies that router endpoints return HTTP 503 (Service Unavailable)
when the KERI agent is unreachable, for operations that require agent availability.

Also includes regression tests for R5 findings:
- mock_vlei.issue_le_credential reads state from TrustAnchorManager (not self._state)
- POST /vvp/create returns 404 (not 500) for unknown identity_name

All endpoints (read and mutation) return HTTP 503 when the KERI agent is
unavailable, per the approved plan's error-mapping contract.
"""

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import AsyncClient

import app.keri_client as keri_client_module
from app.keri_client import KeriAgentUnavailableError


def _get_installed_mock():
    """Get the MockKeriAgentClient installed by the client fixture."""
    return keri_client_module._client


# =============================================================================
# Identity endpoint 503
# =============================================================================


class TestIdentityOutage:
    """Identity creation returns 503 when agent is unavailable."""

    @pytest.mark.asyncio
    async def test_create_identity_returns_503(
        self, client_with_auth: AsyncClient, admin_headers: dict
    ):
        """POST /identity returns 503 when agent is down."""
        mock = _get_installed_mock()
        mock.create_identity.side_effect = KeriAgentUnavailableError("agent down")

        response = await client_with_auth.post(
            "/identity",
            json={"name": "test-identity", "transferable": True},
            headers=admin_headers,
        )

        assert response.status_code == 503


# =============================================================================
# Registry endpoint 503
# =============================================================================


class TestRegistryOutage:
    """Registry creation returns 503 when agent is unavailable."""

    @pytest.mark.asyncio
    async def test_create_registry_returns_503(
        self, client_with_auth: AsyncClient, admin_headers: dict
    ):
        """POST /registry returns 503 when agent is down.

        The registry endpoint resolves the identity first via get_identity(),
        so the outage may occur on that call before create_registry is reached.
        """
        mock = _get_installed_mock()
        mock.get_identity.side_effect = KeriAgentUnavailableError("agent down")

        response = await client_with_auth.post(
            "/registry",
            json={"name": "test-registry", "identity_name": "test-identity"},
            headers=admin_headers,
        )

        assert response.status_code == 503


# =============================================================================
# Organization endpoint 503
# =============================================================================


class TestOrganizationOutage:
    """Organization creation returns 503 when agent is unavailable."""

    @pytest.mark.asyncio
    async def test_create_org_returns_503(
        self, client_with_auth: AsyncClient, admin_headers: dict
    ):
        """POST /organizations returns 503 when KERI agent is down during org creation."""
        # Org endpoint queries DB before KERI calls (duplicate name check),
        # so ensure tables exist when running this test in isolation.
        from app.db.session import init_database
        init_database()

        mock = _get_installed_mock()
        mock.create_identity.side_effect = KeriAgentUnavailableError("agent down")

        response = await client_with_auth.post(
            "/organizations",
            json={"name": "Outage Test Org"},
            headers=admin_headers,
        )

        assert response.status_code == 503


# =============================================================================
# VVP endpoint 503
# =============================================================================


class TestVVPOutage:
    """VVP attestation endpoint returns 503 when agent is unavailable."""

    @pytest.mark.asyncio
    async def test_create_vvp_returns_503(
        self, client_with_auth: AsyncClient, admin_headers: dict
    ):
        """POST /vvp/create returns 503 when KERI agent is down."""
        mock = _get_installed_mock()
        mock.get_identity.side_effect = KeriAgentUnavailableError("agent down")

        response = await client_with_auth.post(
            "/vvp/create",
            json={
                "identity_name": "test-identity",
                "dossier_said": "EDOSSIERSAID",
                "orig_tn": "+14155551234",
                "dest_tn": ["+14155559999"],
            },
            headers=admin_headers,
        )

        assert response.status_code == 503


# =============================================================================
# R5 Regression: mock_vlei state access
# =============================================================================


class TestMockVLEIStateRegression:
    """Regression: issue_le_credential reads state from TrustAnchorManager."""

    @pytest.mark.asyncio
    async def test_issue_le_reads_from_trust_anchor_manager(self):
        """issue_le_credential works when self._state is None but TAM has state.

        Sprint 68b regression: mock_vlei.initialize() was removed from startup.
        issue_le_credential must read state via get_mock_vlei_state()
        (TrustAnchorManager, DB-backed) instead of self._state.
        """
        from app.org.mock_vlei import MockVLEIManager, MockVLEIState

        mgr = MockVLEIManager()
        assert mgr._state is None  # Not initialized

        mock_state = MockVLEIState(
            gleif_aid=f"E{uuid.uuid4().hex[:43]}",
            gleif_registry_key=f"E{uuid.uuid4().hex[:43]}",
            qvi_aid=f"E{uuid.uuid4().hex[:43]}",
            qvi_credential_said=f"E{uuid.uuid4().hex[:43]}",
            qvi_registry_key=f"E{uuid.uuid4().hex[:43]}",
        )

        # Mock get_mock_vlei_state to return state from TrustAnchorManager
        # and mock get_credential_issuer to avoid needing keripy LMDB
        mock_issuer = MagicMock()
        mock_cred_info = MagicMock()
        mock_cred_info.said = f"E{uuid.uuid4().hex[:43]}"
        mock_issuer.issue_credential = AsyncMock(
            return_value=(mock_cred_info, None)
        )

        with patch.object(mgr, "get_mock_vlei_state", return_value=mock_state), \
             patch(
                 "app.keri.issuer.get_credential_issuer",
                 new_callable=AsyncMock,
                 return_value=mock_issuer,
             ):
            said = await mgr.issue_le_credential(
                org_name="Test Org",
                org_aid=f"E{uuid.uuid4().hex[:43]}",
                pseudo_lei="549300TESTLEI000001",
            )

        assert said == mock_cred_info.said
        # Verify the edge used qvi_credential_said from mock_state
        call_kwargs = mock_issuer.issue_credential.call_args
        edges = call_kwargs.kwargs.get("edges") or call_kwargs[1].get("edges")
        assert edges["qvi"]["n"] == mock_state.qvi_credential_said

    @pytest.mark.asyncio
    async def test_issue_le_fails_when_no_state_anywhere(self):
        """issue_le_credential raises RuntimeError when no state is available."""
        from app.org.mock_vlei import MockVLEIManager

        mgr = MockVLEIManager()
        assert mgr._state is None

        with patch.object(mgr, "get_mock_vlei_state", return_value=None):
            with pytest.raises(RuntimeError, match="not initialized"):
                await mgr.issue_le_credential(
                    org_name="Test Org",
                    org_aid=f"E{uuid.uuid4().hex[:43]}",
                    pseudo_lei="549300TESTLEI000001",
                )


# =============================================================================
# R5 Regression: VVP 404 pass-through
# =============================================================================


class TestVVPHttpExceptionPassthrough:
    """Regression: POST /vvp/create preserves intentional HTTPException status codes."""

    @pytest.mark.asyncio
    async def test_vvp_unknown_identity_returns_404(
        self, client_with_auth: AsyncClient, admin_headers: dict
    ):
        """POST /vvp/create with unknown identity_name returns 404, not 500.

        Sprint 68b regression: broad except Exception handler was swallowing
        HTTPException(404) from identity-not-found and returning 500.
        """
        mock = _get_installed_mock()
        # get_identity returns None for unknown names (not an error)
        mock.get_identity.return_value = None

        response = await client_with_auth.post(
            "/vvp/create",
            json={
                "identity_name": "nonexistent-identity",
                "dossier_said": "EDOSSIERSAID",
                "orig_tn": "+14155551234",
                "dest_tn": ["+14155559999"],
            },
            headers=admin_headers,
        )

        assert response.status_code == 404
        assert "not found" in response.json()["detail"].lower()
