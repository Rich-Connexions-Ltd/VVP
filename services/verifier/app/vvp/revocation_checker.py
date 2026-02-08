"""
Background Revocation Checker — Sprint 51.

Single background task that periodically re-checks revocation status for
cached verification results. Operates on the VerificationResultCache,
updating ALL kid variants for a given dossier URL on each check.
"""

import asyncio
import logging
import time
from typing import Optional, Set

from app.vvp.verification_cache import (
    RevocationStatus,
    VerificationResultCache,
)

log = logging.getLogger("vvp.revocation_checker")


class BackgroundRevocationChecker:
    """Asynchronous background worker for revocation re-checking.

    Deduplicates by dossier URL (not compound key) because revocation
    is a per-credential property independent of which PASSporT kid
    presented the dossier. Updates all kid variants atomically.
    """

    def __init__(
        self,
        cache: VerificationResultCache,
        recheck_interval: float = 300.0,
        concurrency: int = 1,
    ):
        self._cache = cache
        self._recheck_interval = recheck_interval
        self._queue: asyncio.Queue[str] = asyncio.Queue()
        self._pending: Set[str] = set()
        self._semaphore = asyncio.Semaphore(concurrency)
        self._running = False
        self._task: Optional[asyncio.Task] = None

    async def enqueue(self, dossier_url: str) -> None:
        """Enqueue dossier URL for revocation checking (deduplicates by URL)."""
        if dossier_url in self._pending:
            return
        self._pending.add(dossier_url)
        await self._queue.put(dossier_url)
        log.debug(f"Enqueued revocation check for {dossier_url[:50]}...")

    def needs_recheck(self, revocation_last_checked: Optional[float]) -> bool:
        """Check if revocation data is stale and needs re-checking."""
        if revocation_last_checked is None:
            return True
        age = time.time() - revocation_last_checked
        return age > self._recheck_interval

    async def start(self) -> None:
        """Start the background worker task."""
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._worker())
        log.info("Background revocation checker started")

    async def stop(self) -> None:
        """Gracefully stop the worker."""
        self._running = False
        if self._task is not None:
            # Put a sentinel to unblock the queue.get()
            await self._queue.put("")
            try:
                await asyncio.wait_for(self._task, timeout=5.0)
            except asyncio.TimeoutError:
                self._task.cancel()
                try:
                    await self._task
                except asyncio.CancelledError:
                    pass
            self._task = None
        log.info("Background revocation checker stopped")

    async def _worker(self) -> None:
        """Main worker loop: consume from queue, check revocations."""
        while self._running:
            try:
                dossier_url = await asyncio.wait_for(
                    self._queue.get(), timeout=10.0
                )
            except asyncio.TimeoutError:
                continue

            # Sentinel check for shutdown
            if not dossier_url:
                continue

            self._pending.discard(dossier_url)

            async with self._semaphore:
                try:
                    await self._check_revocations(dossier_url)
                except Exception:
                    log.exception(
                        f"Background revocation check failed for {dossier_url[:50]}..."
                    )

    async def _check_revocations(self, dossier_url: str) -> None:
        """Perform revocation check for a dossier URL.

        Checks all credential SAIDs in the cached entry against TEL
        using the TELClient.check_revocation() API. Updates all kid
        variants atomically.
        """
        # Get a cached entry to find credential SAIDs and passport kid
        cache = self._cache
        entry = None

        # Find any cached entry for this URL
        async with cache._lock:
            for key, cached in cache._cache.items():
                if key[0] == dossier_url:
                    entry = cached
                    break

        if entry is None:
            log.debug(f"No cached entry for {dossier_url[:50]}... skipping revocation check")
            return

        cache._metrics.revocation_checks += 1

        # Check revocation for each credential SAID using TELClient
        from app.vvp.keri.tel_client import get_tel_client, CredentialStatus

        tel_client = get_tel_client()

        # Extract registry SAIDs from the cached DAG for OOBI derivation
        dag = entry.dag

        for said in entry.contained_saids:
            try:
                # Get registry SAID from DAG node if available
                registry_said = None
                if dag and hasattr(dag, "nodes"):
                    node = dag.nodes.get(said)
                    if node and hasattr(node, "raw") and isinstance(node.raw, dict):
                        registry_said = node.raw.get("ri")

                result = await tel_client.check_revocation(
                    credential_said=said,
                    registry_said=registry_said,
                    oobi_url=entry.passport_kid,
                )
                if result.status == CredentialStatus.REVOKED:
                    await cache.update_revocation_all_for_url(
                        dossier_url, said, RevocationStatus.REVOKED
                    )
                elif result.status == CredentialStatus.ACTIVE:
                    await cache.update_revocation_all_for_url(
                        dossier_url, said, RevocationStatus.UNREVOKED
                    )
                # UNKNOWN/ERROR: keep existing status (don't downgrade UNREVOKED)
            except Exception:
                log.exception(f"Revocation check failed for SAID {said[:20]}...")
                # Keep existing status on failure

        # Update timestamp for all variants even if individual checks failed
        await cache.update_revocation_timestamp_all_for_url(dossier_url)

        log.debug(f"Revocation check complete for {dossier_url[:50]}...")


# =============================================================================
# Module-level singleton
# =============================================================================

_revocation_checker: Optional[BackgroundRevocationChecker] = None


def get_revocation_checker() -> BackgroundRevocationChecker:
    """Get the module-level revocation checker singleton."""
    global _revocation_checker
    if _revocation_checker is None:
        from app.core.config import (
            VVP_REVOCATION_RECHECK_INTERVAL,
            VVP_REVOCATION_CHECK_CONCURRENCY,
        )
        from app.vvp.verification_cache import get_verification_cache

        _revocation_checker = BackgroundRevocationChecker(
            cache=get_verification_cache(),
            recheck_interval=VVP_REVOCATION_RECHECK_INTERVAL,
            concurrency=VVP_REVOCATION_CHECK_CONCURRENCY,
        )
    return _revocation_checker


def reset_revocation_checker() -> None:
    """Reset the module-level revocation checker singleton (for testing)."""
    global _revocation_checker
    _revocation_checker = None
