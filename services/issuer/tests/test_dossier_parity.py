"""Dossier service parity tests: verify agent outage propagation.

Sprint 68c: Tests that dossier_service and TN lookup correctly propagate
KeriAgentUnavailableError instead of masking it as TRUSTED/False.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from app.keri_client import KeriAgentUnavailableError
from common.vvp.dossier.trust import TrustDecision


class TestDossierRevocationOutagePropagation:
    """Verify KeriAgentUnavailableError propagates through revocation checks."""

    @pytest.mark.asyncio
    async def test_agent_outage_during_chain_resolution_propagates(self):
        """Agent outage in _build_cache_entry must not be masked as TRUSTED."""
        from app.vvp.dossier_service import check_dossier_revocation, reset_issuer_dossier_cache

        # Reset cache to force cache miss → chain resolution
        reset_issuer_dossier_cache()

        with patch(
            "app.vvp.dossier_service._build_cache_entry",
            new_callable=AsyncMock,
            side_effect=KeriAgentUnavailableError("agent down"),
        ):
            with pytest.raises(KeriAgentUnavailableError):
                await check_dossier_revocation(
                    dossier_url="https://issuer.example.com/dossier/Etest",
                    dossier_said="Etest1234",
                )

    @pytest.mark.asyncio
    async def test_non_agent_error_during_chain_resolution_returns_trusted(self):
        """Non-agent errors during chain resolution should degrade to TRUSTED."""
        from app.vvp.dossier_service import check_dossier_revocation, reset_issuer_dossier_cache

        reset_issuer_dossier_cache()

        with patch(
            "app.vvp.dossier_service._build_cache_entry",
            new_callable=AsyncMock,
            side_effect=ValueError("some other error"),
        ):
            trust, warning = await check_dossier_revocation(
                dossier_url="https://issuer.example.com/dossier/Enon-agent",
                dossier_said="Enon-agent",
            )
            assert trust == TrustDecision.TRUSTED
            assert warning is not None
            assert "Chain resolution failed" in warning


class TestTNLookupOutagePropagation:
    """Verify KeriAgentUnavailableError propagates through TN ownership validation."""

    @pytest.mark.asyncio
    async def test_agent_outage_during_tn_validation_propagates(self):
        """Agent outage in validate_tn_ownership must raise, not return False."""
        from app.tn.lookup import validate_tn_ownership

        mock_cred = MagicMock()
        mock_cred.said = "Etest_cred_said_1234567890"
        mock_cred.organization_id = "org-1"
        mock_cred.schema_said = "EFvnoHDY7I-kaBBeKlbDbkjG4BaI0nKLGadxBdjMGgSQ"

        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.all.return_value = [mock_cred]

        mock_client = MagicMock()
        mock_client.get_credential = AsyncMock(
            side_effect=KeriAgentUnavailableError("agent down")
        )

        with patch("app.keri_client.get_keri_client", return_value=mock_client):
            with pytest.raises(KeriAgentUnavailableError):
                await validate_tn_ownership(mock_db, "org-1", "+14155551234")

    @pytest.mark.asyncio
    async def test_non_agent_error_during_tn_validation_returns_false(self):
        """Non-agent errors should be caught and validation continues."""
        from app.tn.lookup import validate_tn_ownership

        mock_cred = MagicMock()
        mock_cred.said = "Etest_cred_said_1234567890"
        mock_cred.organization_id = "org-1"
        mock_cred.schema_said = "EFvnoHDY7I-kaBBeKlbDbkjG4BaI0nKLGadxBdjMGgSQ"

        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.all.return_value = [mock_cred]

        mock_client = MagicMock()
        mock_client.get_credential = AsyncMock(
            side_effect=RuntimeError("unexpected error")
        )

        with patch("app.keri_client.get_keri_client", return_value=mock_client):
            result = await validate_tn_ownership(mock_db, "org-1", "+14155551234")
            assert result is False  # Graceful degradation for non-agent errors
