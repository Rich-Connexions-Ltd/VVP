"""Unit tests for BackgroundRevocationChecker — Sprint 51.

Tests enqueue/dedup, start/stop, revocation detection, and staleness.
"""

import asyncio
import time

import pytest

from app.vvp.api_models import ClaimNode, ClaimStatus
from app.vvp.verification_cache import (
    CACHE_VERSION,
    CachedDossierVerification,
    RevocationStatus,
    VerificationResultCache,
    compute_config_fingerprint,
)
from app.vvp.revocation_checker import BackgroundRevocationChecker


# =============================================================================
# Helpers
# =============================================================================


def _make_cache_entry(
    dossier_url: str = "https://example.com/dossier.cesr",
    passport_kid: str = "kid-A",
) -> CachedDossierVerification:
    return CachedDossierVerification(
        dossier_url=dossier_url,
        passport_kid=passport_kid,
        dag=object(),
        raw_dossier=b"test",
        dossier_acdcs={},
        chain_claim=ClaimNode(
            name="chain_verified",
            status=ClaimStatus.VALID,
            reasons=[],
            evidence=[],
        ),
        chain_errors=[],
        acdc_signatures_verified=True,
        has_variant_limitations=False,
        dossier_claim_evidence=[],
        contained_saids=frozenset({"SAID1"}),
        credential_revocation_status={"SAID1": RevocationStatus.UNREVOKED},
        revocation_last_checked=time.time(),
        created_at=time.time(),
        cache_version=CACHE_VERSION,
        config_fingerprint=compute_config_fingerprint(),
    )


# =============================================================================
# Tests
# =============================================================================


class TestBackgroundRevocationChecker:
    @pytest.mark.asyncio
    async def test_enqueue_deduplicates(self):
        """Enqueue deduplicates by dossier URL."""
        cache = VerificationResultCache(max_entries=10)
        checker = BackgroundRevocationChecker(cache=cache, recheck_interval=300.0)

        await checker.enqueue("https://example.com/a")
        await checker.enqueue("https://example.com/a")  # duplicate

        assert checker._queue.qsize() == 1

    @pytest.mark.asyncio
    async def test_enqueue_different_urls(self):
        """Different URLs are not deduplicated."""
        cache = VerificationResultCache(max_entries=10)
        checker = BackgroundRevocationChecker(cache=cache, recheck_interval=300.0)

        await checker.enqueue("https://example.com/a")
        await checker.enqueue("https://example.com/b")

        assert checker._queue.qsize() == 2

    @pytest.mark.asyncio
    async def test_needs_recheck_none_timestamp(self):
        """None revocation_last_checked → needs recheck."""
        cache = VerificationResultCache(max_entries=10)
        checker = BackgroundRevocationChecker(cache=cache, recheck_interval=300.0)

        assert checker.needs_recheck(None) is True

    @pytest.mark.asyncio
    async def test_needs_recheck_fresh(self):
        """Recent timestamp → no recheck needed."""
        cache = VerificationResultCache(max_entries=10)
        checker = BackgroundRevocationChecker(cache=cache, recheck_interval=300.0)

        assert checker.needs_recheck(time.time()) is False

    @pytest.mark.asyncio
    async def test_needs_recheck_stale(self):
        """Old timestamp → needs recheck."""
        cache = VerificationResultCache(max_entries=10)
        checker = BackgroundRevocationChecker(cache=cache, recheck_interval=300.0)

        assert checker.needs_recheck(time.time() - 600.0) is True

    @pytest.mark.asyncio
    async def test_start_stop(self):
        """Checker starts and stops cleanly."""
        cache = VerificationResultCache(max_entries=10)
        checker = BackgroundRevocationChecker(cache=cache, recheck_interval=300.0)

        await checker.start()
        assert checker._running is True
        assert checker._task is not None

        await checker.stop()
        assert checker._running is False
        assert checker._task is None

    @pytest.mark.asyncio
    async def test_start_idempotent(self):
        """Starting twice is idempotent."""
        cache = VerificationResultCache(max_entries=10)
        checker = BackgroundRevocationChecker(cache=cache, recheck_interval=300.0)

        await checker.start()
        task1 = checker._task
        await checker.start()  # Should be no-op
        assert checker._task is task1

        await checker.stop()

    @pytest.mark.asyncio
    async def test_worker_processes_queue(self):
        """Worker task consumes items from the queue."""
        cache = VerificationResultCache(max_entries=10)
        entry = _make_cache_entry()
        await cache.put(entry)

        checker = BackgroundRevocationChecker(cache=cache, recheck_interval=300.0)
        await checker.start()

        await checker.enqueue(entry.dossier_url)
        # Give worker time to process
        await asyncio.sleep(0.5)

        # Queue should be empty after processing
        assert checker._queue.qsize() == 0
        # Pending set should be cleared
        assert entry.dossier_url not in checker._pending

        await checker.stop()
