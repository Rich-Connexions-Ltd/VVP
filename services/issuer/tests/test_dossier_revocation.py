"""Tests for issuer dossier revocation checking.

Verifies the revocation gate in the VVP creation flow:
- Cache miss → TRUSTED with warning, cache populated, background check started
- Cache hit with ACTIVE chain → TRUSTED
- Cache hit with REVOKED chain → UNTRUSTED
- Cache hit with pending check → TRUSTED with warning
- Chain resolution failure → TRUSTED (graceful degradation)
"""

import asyncio
from dataclasses import dataclass, field
from typing import Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from common.vvp.dossier.cache import CachedDossier, DossierCache
from common.vvp.dossier.trust import TrustDecision
from common.vvp.keri.tel_client import (
    ChainExtractionResult,
    ChainRevocationResult,
    CredentialStatus,
)
from common.vvp.models.dossier import ACDCNode, DossierDAG


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

DOSSIER_URL = "http://localhost:8001/dossier/EAbcdef1234567890"
DOSSIER_SAID = "EAbcdef1234567890abcdef1234567890abcdef12"


@dataclass
class FakeCredentialInfo:
    """Minimal stand-in for KeriAgentClient credential response."""

    said: str
    issuer_aid: str = "EIssuerAID000000000000000000000000000000000"
    recipient_aid: Optional[str] = None
    registry_key: str = "ERegistryKey0000000000000000000000000000000"
    schema_said: str = "ESchemaSAID00000000000000000000000000000000"
    issuance_dt: str = "2025-01-01T00:00:00Z"
    status: str = "issued"
    revocation_dt: Optional[str] = None
    attributes: dict = field(default_factory=dict)
    edges: Optional[dict] = None
    rules: Optional[dict] = None


@dataclass
class FakeDossierContent:
    """Minimal stand-in for app.dossier.builder.DossierContent."""

    root_said: str
    root_saids: list = field(default_factory=list)
    credential_saids: list = field(default_factory=list)
    is_aggregate: bool = False
    credentials: dict = field(default_factory=dict)
    credentials_json: dict = field(default_factory=dict)
    tel_events: dict = field(default_factory=dict)
    warnings: list = field(default_factory=list)


@pytest.fixture(autouse=True)
def _reset_cache():
    """Reset the issuer dossier cache before each test."""
    from app.vvp.dossier_service import reset_issuer_dossier_cache

    reset_issuer_dossier_cache()
    yield
    reset_issuer_dossier_cache()


def _make_fake_builder(credential_saids=None):
    """Create a mock DossierBuilder that returns a fake DossierContent."""
    saids = credential_saids or [DOSSIER_SAID]
    content = FakeDossierContent(
        root_said=DOSSIER_SAID,
        root_saids=[DOSSIER_SAID],
        credential_saids=saids,
    )
    builder = AsyncMock()
    builder.build = AsyncMock(return_value=content)
    return builder


def _make_fake_client(credential_saids=None):
    """Create a mock KeriAgentClient that returns FakeCredentialInfo."""
    saids = credential_saids or [DOSSIER_SAID]
    cred_map = {s: FakeCredentialInfo(said=s) for s in saids}
    issuer = AsyncMock()
    issuer.get_credential = AsyncMock(side_effect=lambda s: cred_map.get(s))
    return issuer


# ---------------------------------------------------------------------------
# Tests: check_dossier_revocation
# ---------------------------------------------------------------------------


class TestCacheMiss:
    """Cache miss populates cache and starts background revocation."""

    @pytest.mark.asyncio
    async def test_first_call_returns_trusted_with_warning(self):
        """First call for a dossier should return TRUSTED and populate cache."""
        from app.vvp.dossier_service import check_dossier_revocation

        with (
            patch(
                "app.dossier.builder.get_dossier_builder",
                new_callable=AsyncMock,
                return_value=_make_fake_builder(),
            ),
            patch(
                "app.keri_client.get_keri_client",
                return_value=_make_fake_client(),
            ),
        ):
            trust, warning = await check_dossier_revocation(
                dossier_url=DOSSIER_URL,
                dossier_said=DOSSIER_SAID,
            )

        assert trust == TrustDecision.TRUSTED
        assert warning is not None
        assert "background" in warning.lower()

    @pytest.mark.asyncio
    async def test_cache_populated_after_first_call(self):
        """After first call, cache should contain the dossier entry."""
        from app.vvp.dossier_service import (
            check_dossier_revocation,
            get_issuer_dossier_cache,
        )

        with (
            patch(
                "app.dossier.builder.get_dossier_builder",
                new_callable=AsyncMock,
                return_value=_make_fake_builder(),
            ),
            patch(
                "app.keri_client.get_keri_client",
                return_value=_make_fake_client(),
            ),
        ):
            await check_dossier_revocation(
                dossier_url=DOSSIER_URL,
                dossier_said=DOSSIER_SAID,
            )

        cache = get_issuer_dossier_cache()
        cached = await cache.get(DOSSIER_URL)
        assert cached is not None
        assert DOSSIER_SAID in cached.contained_saids

    @pytest.mark.asyncio
    async def test_chain_with_multiple_credentials(self):
        """Chain with 3 credentials should populate cache with all SAIDs."""
        from app.vvp.dossier_service import (
            check_dossier_revocation,
            get_issuer_dossier_cache,
        )

        saids = ["ESAID_leaf", "ESAID_mid", "ESAID_root"]

        with (
            patch(
                "app.dossier.builder.get_dossier_builder",
                new_callable=AsyncMock,
                return_value=_make_fake_builder(saids),
            ),
            patch(
                "app.keri_client.get_keri_client",
                return_value=_make_fake_client(saids),
            ),
        ):
            trust, _ = await check_dossier_revocation(
                dossier_url=DOSSIER_URL,
                dossier_said="ESAID_root",
            )

        assert trust == TrustDecision.TRUSTED
        cache = get_issuer_dossier_cache()
        cached = await cache.get(DOSSIER_URL)
        assert cached is not None
        assert cached.contained_saids == set(saids)


class TestCacheHit:
    """Cache hit returns trust decision based on cached revocation result."""

    @pytest.mark.asyncio
    async def test_active_chain_returns_trusted(self):
        """Cache entry with ACTIVE chain should return TRUSTED."""
        from app.vvp.dossier_service import (
            check_dossier_revocation,
            get_issuer_dossier_cache,
        )

        # Pre-populate cache with ACTIVE result
        cache = get_issuer_dossier_cache()
        dag = DossierDAG(root_said=DOSSIER_SAID)
        cached = CachedDossier(
            dag=dag,
            raw_content=b"",
            fetch_timestamp=1000.0,
            content_type="application/cesr",
            contained_saids={DOSSIER_SAID},
            chain_revocation=ChainRevocationResult(
                chain_status=CredentialStatus.ACTIVE,
                chain_saids=[DOSSIER_SAID],
                check_complete=True,
                checked_at="2025-01-01T00:00:00Z",
            ),
        )
        await cache.put(url=DOSSIER_URL, dossier=cached)

        trust, warning = await check_dossier_revocation(
            dossier_url=DOSSIER_URL,
            dossier_said=DOSSIER_SAID,
        )

        assert trust == TrustDecision.TRUSTED
        assert warning is None

    @pytest.mark.asyncio
    async def test_revoked_chain_returns_untrusted(self):
        """Cache entry with REVOKED chain should return UNTRUSTED."""
        from app.vvp.dossier_service import (
            check_dossier_revocation,
            get_issuer_dossier_cache,
        )

        # Pre-populate cache with REVOKED result
        cache = get_issuer_dossier_cache()
        dag = DossierDAG(root_said=DOSSIER_SAID)
        cached = CachedDossier(
            dag=dag,
            raw_content=b"",
            fetch_timestamp=1000.0,
            content_type="application/cesr",
            contained_saids={DOSSIER_SAID},
            chain_revocation=ChainRevocationResult(
                chain_status=CredentialStatus.REVOKED,
                chain_saids=[DOSSIER_SAID],
                revoked_credentials=[DOSSIER_SAID],
                check_complete=True,
                checked_at="2025-01-01T00:00:00Z",
            ),
        )
        await cache.put(url=DOSSIER_URL, dossier=cached)

        trust, warning = await check_dossier_revocation(
            dossier_url=DOSSIER_URL,
            dossier_said=DOSSIER_SAID,
        )

        assert trust == TrustDecision.UNTRUSTED
        assert "revoked" in warning.lower()

    @pytest.mark.asyncio
    async def test_pending_check_returns_trusted_with_warning(self):
        """Cache entry with no revocation result (pending) returns TRUSTED."""
        from app.vvp.dossier_service import (
            check_dossier_revocation,
            get_issuer_dossier_cache,
        )

        # Pre-populate cache without revocation result (check pending)
        cache = get_issuer_dossier_cache()
        dag = DossierDAG(root_said=DOSSIER_SAID)
        cached = CachedDossier(
            dag=dag,
            raw_content=b"",
            fetch_timestamp=1000.0,
            content_type="application/cesr",
            contained_saids={DOSSIER_SAID},
            chain_revocation=None,  # No result yet
        )
        await cache.put(url=DOSSIER_URL, dossier=cached)

        trust, warning = await check_dossier_revocation(
            dossier_url=DOSSIER_URL,
            dossier_said=DOSSIER_SAID,
        )

        assert trust == TrustDecision.TRUSTED
        assert warning is not None
        assert "pending" in warning.lower()


class TestChainResolutionFailure:
    """Chain resolution failures degrade gracefully to TRUSTED."""

    @pytest.mark.asyncio
    async def test_builder_error_returns_trusted(self):
        """If DossierBuilder raises, should return TRUSTED with warning."""
        from app.vvp.dossier_service import check_dossier_revocation

        failing_builder = AsyncMock()
        failing_builder.build = AsyncMock(side_effect=Exception("Credential not found"))

        with (
            patch(
                "app.dossier.builder.get_dossier_builder",
                new_callable=AsyncMock,
                return_value=failing_builder,
            ),
            patch(
                "app.keri_client.get_keri_client",
                return_value=_make_fake_client(),
            ),
        ):
            trust, warning = await check_dossier_revocation(
                dossier_url=DOSSIER_URL,
                dossier_said=DOSSIER_SAID,
            )

        assert trust == TrustDecision.TRUSTED
        assert warning is not None
        assert "failed" in warning.lower()


class TestBuildCacheEntry:
    """Tests for _build_cache_entry internal function."""

    @pytest.mark.asyncio
    async def test_builds_dag_with_correct_fields(self):
        """DAG nodes should use ACDCNode with correct field mappings."""
        from app.vvp.dossier_service import _build_cache_entry

        with (
            patch(
                "app.dossier.builder.get_dossier_builder",
                new_callable=AsyncMock,
                return_value=_make_fake_builder(),
            ),
            patch(
                "app.keri_client.get_keri_client",
                return_value=_make_fake_client(),
            ),
        ):
            cached_dossier, chain_info = await _build_cache_entry(DOSSIER_SAID)

        # Verify DAG structure
        assert cached_dossier.dag.root_said == DOSSIER_SAID
        assert DOSSIER_SAID in cached_dossier.dag.nodes
        node = cached_dossier.dag.nodes[DOSSIER_SAID]
        assert node.issuer == "EIssuerAID000000000000000000000000000000000"
        assert node.schema == "ESchemaSAID00000000000000000000000000000000"

        # Verify chain info
        assert chain_info.chain_saids == [DOSSIER_SAID]
        assert chain_info.complete is True
        assert DOSSIER_SAID in chain_info.registry_saids

    @pytest.mark.asyncio
    async def test_chain_info_maps_registry_saids(self):
        """ChainExtractionResult should map each credential to its registry."""
        from app.vvp.dossier_service import _build_cache_entry

        saids = ["ESAID1", "ESAID2"]

        with (
            patch(
                "app.dossier.builder.get_dossier_builder",
                new_callable=AsyncMock,
                return_value=_make_fake_builder(saids),
            ),
            patch(
                "app.keri_client.get_keri_client",
                return_value=_make_fake_client(saids),
            ),
        ):
            _, chain_info = await _build_cache_entry("ESAID2")

        assert len(chain_info.registry_saids) == 2
        for said in saids:
            assert said in chain_info.registry_saids
