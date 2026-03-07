"""Dossier service parity tests: verify outage handling and non-blocking revocation.

Sprint 68c: Tests that dossier_service and TN lookup correctly handle
KeriAgentUnavailableError.

Revocation cache miss is non-blocking — chain resolution runs as a background
task. The caller always receives TRUSTED on cache miss; errors are logged in
the background, never propagated to the signing path.
"""

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from app.keri_client import KeriAgentUnavailableError
from common.vvp.dossier.trust import TrustDecision


class TestDossierRevocationCacheMiss:
    """Verify non-blocking revocation on cache miss."""

    @pytest.mark.asyncio
    async def test_cache_miss_returns_trusted_immediately(self):
        """Cache miss returns TRUSTED without waiting for chain resolution."""
        from app.vvp.dossier_service import check_dossier_revocation, reset_issuer_dossier_cache

        reset_issuer_dossier_cache()

        with patch(
            "app.vvp.dossier_service._build_cache_entry",
            new_callable=AsyncMock,
            side_effect=KeriAgentUnavailableError("agent down"),
        ):
            trust, warning = await check_dossier_revocation(
                dossier_url="https://issuer.example.com/dossier/Etest",
                dossier_said="Etest1234",
            )
            assert trust == TrustDecision.TRUSTED
            assert "background" in warning.lower()

        # Let the background task run and complete (it will log the error)
        await asyncio.sleep(0.05)

    @pytest.mark.asyncio
    async def test_cache_miss_fires_background_resolution(self):
        """Cache miss starts a background task to populate the cache."""
        from app.vvp.dossier_service import check_dossier_revocation, reset_issuer_dossier_cache

        reset_issuer_dossier_cache()

        build_called = asyncio.Event()

        async def mock_build(said):
            build_called.set()
            raise ValueError("test error")

        with patch(
            "app.vvp.dossier_service._build_cache_entry",
            new_callable=AsyncMock,
            side_effect=mock_build,
        ):
            trust, _ = await check_dossier_revocation(
                dossier_url="https://issuer.example.com/dossier/Ebg",
                dossier_said="Ebg1234",
            )
            assert trust == TrustDecision.TRUSTED

            # Background task should run
            await asyncio.wait_for(build_called.wait(), timeout=1.0)
            assert build_called.is_set()


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
