"""URL-keyed dossier cache with SAID index for revocation invalidation.

Per spec §5.1.1-2.7: "Dossier Cache Check" - verifier MAY cache parsed dossiers.
Per spec §5C.2: Freshness policy for cached data.

Design decisions:
- Primary key: URL (available pre-fetch from VVP-Identity evd field)
- Secondary index: credential SAID → set of URLs (for revocation invalidation)
- TTL: Default 300s aligned with §5C.2 key state freshness
- LRU eviction when at capacity
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Dict, Optional, Set

from .models import DossierDAG

if TYPE_CHECKING:
    from ..keri.tel_client import ChainRevocationResult, ChainExtractionResult

log = logging.getLogger(__name__)


@dataclass
class CacheMetrics:
    """Metrics for cache operations.

    Used for monitoring and debugging cache effectiveness.

    Attributes:
        hits: Number of cache hits.
        misses: Number of cache misses.
        evictions: Number of LRU evictions.
        invalidations: Number of invalidation operations.
    """

    hits: int = 0
    misses: int = 0
    evictions: int = 0
    invalidations: int = 0

    def hit_rate(self) -> float:
        """Calculate cache hit rate.

        Returns:
            Hit rate as float (0.0 to 1.0), or 0.0 if no requests.
        """
        total = self.hits + self.misses
        return self.hits / total if total > 0 else 0.0

    def to_dict(self) -> Dict[str, any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "hits": self.hits,
            "misses": self.misses,
            "evictions": self.evictions,
            "invalidations": self.invalidations,
            "hit_rate": round(self.hit_rate(), 4),
        }

    def reset(self) -> None:
        """Reset all metrics to zero."""
        self.hits = 0
        self.misses = 0
        self.evictions = 0
        self.invalidations = 0


@dataclass
class CachedDossier:
    """Cached dossier entry with metadata.

    Attributes:
        dag: Parsed DossierDAG.
        raw_content: Original raw bytes (for signature verification).
        fetch_timestamp: Unix timestamp when dossier was fetched.
        content_type: Content-Type from HTTP response.
        contained_saids: Set of all credential SAIDs in this dossier.
        chain_revocation: Result of chain-wide revocation check (if completed).
        chain_revocation_checked_at: Unix timestamp of last revocation check.
        chain_revocation_in_progress: True if background check is running.
    """

    dag: DossierDAG
    raw_content: bytes
    fetch_timestamp: float
    content_type: str
    contained_saids: Set[str] = field(default_factory=set)

    # Chain revocation state (populated by background task)
    chain_revocation: Optional["ChainRevocationResult"] = None
    chain_revocation_checked_at: Optional[float] = None
    chain_revocation_in_progress: bool = False


@dataclass
class _CacheEntry:
    """Internal cache entry with TTL tracking.

    Attributes:
        dossier: The cached dossier data.
        expires_at: Unix timestamp when this entry expires.
    """

    dossier: CachedDossier
    expires_at: float


class DossierCache:
    """Thread-safe URL-keyed dossier cache with SAID secondary index.

    Supports:
    - Lookup by URL (pre-fetch, from VVP-Identity evd field)
    - Invalidation by credential SAID (for revocation handling)
    - LRU eviction when at capacity
    - TTL-based expiration

    Thread-safety is provided via asyncio.Lock for concurrent access.
    """

    def __init__(
        self,
        ttl_seconds: float = 300.0,
        max_entries: int = 100,
    ):
        """Initialize cache with configuration.

        Args:
            ttl_seconds: Time-to-live for cache entries (default 300s per §5C.2).
            max_entries: Maximum entries before LRU eviction.
        """
        # Primary index: URL → _CacheEntry
        self._cache: Dict[str, _CacheEntry] = {}
        # Secondary index: credential SAID → set of URLs containing it
        self._said_to_urls: Dict[str, Set[str]] = {}
        # LRU tracking: most recently accessed at end
        self._access_order: list[str] = []
        # Configuration
        self._ttl = ttl_seconds
        self._max_entries = max_entries
        # Thread safety
        self._lock = asyncio.Lock()
        # Metrics
        self._metrics = CacheMetrics()
        # Background revocation task tracking (protected by _lock)
        self._revocation_tasks: Dict[str, asyncio.Task] = {}

    async def get(self, url: str) -> Optional[CachedDossier]:
        """Lookup cached dossier by URL.

        Args:
            url: Dossier URL (from VVP-Identity evd field).

        Returns:
            CachedDossier if found and not expired, None otherwise.
        """
        async with self._lock:
            entry = self._cache.get(url)

            if entry is None:
                self._metrics.misses += 1
                log.debug(f"Dossier cache miss: {url[:50]}...")
                return None

            # Check expiration
            now = time.time()
            if entry.expires_at < now:
                self._remove_entry(url)
                self._metrics.misses += 1
                log.debug(f"Dossier cache expired: {url[:50]}...")
                return None

            # Update LRU order
            self._update_access_order(url)
            self._metrics.hits += 1
            log.info(f"Dossier cache hit: {url[:50]}...")

            return entry.dossier

    async def put(
        self,
        url: str,
        dossier: CachedDossier,
        *,
        chain_info: Optional["ChainExtractionResult"] = None,
        dossier_data: Optional[str] = None,
        oobi_url: Optional[str] = None,
    ) -> None:
        """Store dossier in cache with optional auto-start revocation check.

        Builds secondary SAID index and enforces LRU eviction.
        If chain_info is provided, automatically starts a fire-and-forget
        background task to check revocation status for all credentials in chain.

        Args:
            url: Dossier URL (from VVP-Identity evd field).
            dossier: The cached dossier data.
            chain_info: Optional chain extraction result for revocation checking.
            dossier_data: Optional raw dossier CESR for inline TEL parsing.
            oobi_url: Optional OOBI URL for witness discovery.
        """
        async with self._lock:
            now = time.time()

            # Evict LRU if at capacity and this is a new entry
            if len(self._cache) >= self._max_entries and url not in self._cache:
                self._evict_lru()

            # If replacing existing entry, clean up old SAID index
            if url in self._cache:
                old_entry = self._cache[url]
                self._remove_from_said_index(url, old_entry.dossier.contained_saids)

            # Store in primary index
            entry = _CacheEntry(
                dossier=dossier,
                expires_at=now + self._ttl,
            )
            self._cache[url] = entry
            self._update_access_order(url)

            # Build secondary SAID index
            for said in dossier.contained_saids:
                if said not in self._said_to_urls:
                    self._said_to_urls[said] = set()
                self._said_to_urls[said].add(url)

            log.debug(
                f"Dossier cached: {url[:50]}... "
                f"(saids={len(dossier.contained_saids)}, size={len(self._cache)})"
            )

        # Auto-start background revocation check if chain_info provided
        if chain_info is not None:
            # Fire-and-forget (don't await) - uses its own locking internally
            asyncio.create_task(
                self.start_background_revocation_check(
                    url=url,
                    chain_info=chain_info,
                    dossier_data=dossier_data,
                    oobi_url=oobi_url,
                )
            )

    async def invalidate_by_said(self, said: str) -> int:
        """Invalidate all dossiers containing a specific credential SAID.

        Use when a credential is revoked to ensure affected dossiers are
        not served from cache.

        Args:
            said: Credential SAID that was revoked.

        Returns:
            Number of cache entries invalidated.
        """
        async with self._lock:
            urls = self._said_to_urls.get(said)
            if not urls:
                return 0

            # Copy set since we'll modify during iteration
            urls_to_invalidate = set(urls)
            count = len(urls_to_invalidate)

            for url in urls_to_invalidate:
                self._remove_entry(url)

            self._metrics.invalidations += count
            log.info(
                f"Dossier cache invalidated {count} entries for revoked SAID: {said[:20]}..."
            )
            return count

    async def invalidate_by_url(self, url: str) -> bool:
        """Invalidate a specific cached dossier by URL.

        Args:
            url: Dossier URL to invalidate.

        Returns:
            True if entry existed and was removed, False otherwise.
        """
        async with self._lock:
            if url not in self._cache:
                return False

            self._remove_entry(url)
            self._metrics.invalidations += 1
            log.debug(f"Dossier cache invalidated: {url[:50]}...")
            return True

    async def clear(self) -> None:
        """Clear all cache entries."""
        async with self._lock:
            self._cache.clear()
            self._said_to_urls.clear()
            self._access_order.clear()
            # Cancel any in-flight revocation tasks
            for task in self._revocation_tasks.values():
                task.cancel()
            self._revocation_tasks.clear()
            log.info("Dossier cache cleared")

    async def start_background_revocation_check(
        self,
        url: str,
        chain_info: "ChainExtractionResult",
        dossier_data: Optional[str] = None,
        oobi_url: Optional[str] = None,
    ) -> None:
        """Start fire-and-forget background revocation check.

        Thread-safe: All checks and updates under single lock.
        Safe to call multiple times - duplicate requests are ignored.

        Args:
            url: Dossier URL (cache key).
            chain_info: Chain extraction result with SAIDs to check.
            dossier_data: Raw dossier CESR content for inline TEL parsing.
            oobi_url: OOBI URL for witness discovery.
        """
        from ..keri.tel_client import ChainExtractionResult

        async with self._lock:
            # Check for duplicate task (under lock)
            if url in self._revocation_tasks:
                task = self._revocation_tasks[url]
                if not task.done():
                    log.debug(f"Revocation check already in progress for: {url[:50]}...")
                    return  # Task already running

            # Check if already checked recently
            if url in self._cache:
                entry = self._cache[url]
                if entry.dossier.chain_revocation is not None:
                    log.debug(f"Revocation already checked for: {url[:50]}...")
                    return  # Already have results
                if entry.dossier.chain_revocation_in_progress:
                    log.debug(f"Revocation check marked in progress for: {url[:50]}...")
                    return  # Already in progress

                # Mark in-progress (under same lock)
                entry.dossier.chain_revocation_in_progress = True

            # Start task (under lock to prevent race)
            task = asyncio.create_task(
                self._do_revocation_check(url, chain_info, dossier_data, oobi_url)
            )
            self._revocation_tasks[url] = task
            log.info(f"Started background revocation check for: {url[:50]}...")

        # Callback outside lock (cleanup is also locked)
        task.add_done_callback(
            lambda t: asyncio.create_task(self._cleanup_task(url))
        )

    async def _do_revocation_check(
        self,
        url: str,
        chain_info: "ChainExtractionResult",
        dossier_data: Optional[str],
        oobi_url: Optional[str],
    ) -> None:
        """Background task that checks chain revocation.

        Updates cache with results when complete. On error, stores error result
        so UI sees failure rather than perpetual "pending" state.
        """
        from ..keri.tel_client import (
            get_tel_client,
            ChainRevocationResult,
            CredentialStatus,
        )

        try:
            tel_client = get_tel_client()
            result = await tel_client.check_chain_revocation(
                chain_info=chain_info,
                dossier_data=dossier_data,
                oobi_url=oobi_url,
            )

            async with self._lock:
                if url in self._cache:
                    entry = self._cache[url]
                    entry.dossier.chain_revocation = result
                    entry.dossier.chain_revocation_checked_at = time.time()
                    entry.dossier.chain_revocation_in_progress = False
                    log.info(
                        f"Revocation check complete for {url[:50]}...: "
                        f"status={result.chain_status.value}"
                    )

            # If revocation found, invalidate OTHER dossiers containing revoked creds
            # (NOT the current dossier - preserve result for UI polling)
            if result.chain_status == CredentialStatus.REVOKED:
                for said in result.revoked_credentials:
                    await self._invalidate_others_by_said(url, said)

        except Exception as e:
            log.error(f"Background revocation check failed for {url[:50]}...: {e}")
            async with self._lock:
                if url in self._cache:
                    entry = self._cache[url]
                    entry.dossier.chain_revocation_in_progress = False
                    # Store error result so UI sees failure, not perpetual "pending"
                    entry.dossier.chain_revocation = ChainRevocationResult(
                        chain_status=CredentialStatus.UNKNOWN,
                        credential_results={},
                        revoked_credentials=[],
                        chain_saids=chain_info.chain_saids,
                        missing_chain_links=chain_info.missing_links,
                        check_complete=False,
                        errors=[str(e)],
                        checked_at=datetime.now(timezone.utc).isoformat(),
                    )

    async def _invalidate_others_by_said(self, exclude_url: str, said: str) -> int:
        """Invalidate dossiers containing SAID, except the one we're checking.

        This preserves the revocation result for the current dossier (for UI polling)
        while evicting other affected dossiers from cache.

        Args:
            exclude_url: URL to exclude from invalidation (the one being checked).
            said: Credential SAID that was revoked.

        Returns:
            Number of entries invalidated.
        """
        async with self._lock:
            urls_to_invalidate = []
            if said in self._said_to_urls:
                for url in self._said_to_urls[said]:
                    if url != exclude_url:
                        urls_to_invalidate.append(url)

            for url in urls_to_invalidate:
                self._remove_entry(url)

            if urls_to_invalidate:
                self._metrics.invalidations += len(urls_to_invalidate)
                log.info(
                    f"Invalidated {len(urls_to_invalidate)} other dossiers "
                    f"containing revoked SAID: {said[:20]}..."
                )

            return len(urls_to_invalidate)

    async def _cleanup_task(self, url: str) -> None:
        """Remove completed task from tracking dict (under lock)."""
        async with self._lock:
            self._revocation_tasks.pop(url, None)

    def _remove_entry(self, url: str) -> None:
        """Remove entry from all indexes (caller must hold lock)."""
        entry = self._cache.pop(url, None)
        if entry:
            # Remove from SAID index
            self._remove_from_said_index(url, entry.dossier.contained_saids)
            # Remove from access order
            if url in self._access_order:
                self._access_order.remove(url)

    def _remove_from_said_index(self, url: str, saids: Set[str]) -> None:
        """Remove URL from SAID index entries (caller must hold lock)."""
        for said in saids:
            if said in self._said_to_urls:
                self._said_to_urls[said].discard(url)
                # Clean up empty sets
                if not self._said_to_urls[said]:
                    del self._said_to_urls[said]

    def _update_access_order(self, url: str) -> None:
        """Move URL to end of access order (caller must hold lock)."""
        if url in self._access_order:
            self._access_order.remove(url)
        self._access_order.append(url)

    def _evict_lru(self) -> None:
        """Evict least recently used entry (caller must hold lock)."""
        if self._access_order:
            lru_url = self._access_order[0]
            self._remove_entry(lru_url)
            self._metrics.evictions += 1
            log.debug(f"Dossier cache LRU eviction: {lru_url[:50]}...")

    @property
    def size(self) -> int:
        """Current number of cached entries."""
        return len(self._cache)

    def metrics(self) -> CacheMetrics:
        """Get cache metrics.

        Returns:
            CacheMetrics instance with current statistics.
        """
        return self._metrics


# Module-level singleton
_dossier_cache: Optional[DossierCache] = None


def get_dossier_cache() -> DossierCache:
    """Get or create the dossier cache singleton.

    Configuration is read from app.core.config on first access.
    """
    global _dossier_cache
    if _dossier_cache is None:
        # Import here to avoid circular dependency
        from app.core.config import DOSSIER_CACHE_MAX_ENTRIES, DOSSIER_CACHE_TTL_SECONDS

        _dossier_cache = DossierCache(
            ttl_seconds=DOSSIER_CACHE_TTL_SECONDS,
            max_entries=DOSSIER_CACHE_MAX_ENTRIES,
        )
    return _dossier_cache


def reset_dossier_cache() -> None:
    """Reset the dossier cache singleton (for testing)."""
    global _dossier_cache
    _dossier_cache = None
