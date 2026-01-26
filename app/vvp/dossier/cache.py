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
from typing import Dict, Optional, Set

from .models import DossierDAG

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
    """

    dag: DossierDAG
    raw_content: bytes
    fetch_timestamp: float
    content_type: str
    contained_saids: Set[str] = field(default_factory=set)


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

    async def put(self, url: str, dossier: CachedDossier) -> None:
        """Store dossier in cache.

        Builds secondary SAID index and enforces LRU eviction.

        Args:
            url: Dossier URL (from VVP-Identity evd field).
            dossier: The cached dossier data.
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
            log.info("Dossier cache cleared")

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
