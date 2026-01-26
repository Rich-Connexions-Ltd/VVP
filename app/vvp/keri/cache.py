"""Key state cache for KERI resolution.

Per spec §5C.2: "Key state cache: AID + timestamp → Minutes (rotation-sensitive)"

The cache uses a two-level keying strategy:
- Primary key: (AID, establishment_event_digest) - stable across time queries
- Secondary index: (AID, reference_time) → establishment_digest for time-based lookups

This avoids timestamp rounding issues and ensures cache hits return the exact
key state that was valid at the queried time.
"""

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Dict, Optional, Tuple

if TYPE_CHECKING:
    from .kel_resolver import KeyState

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
class CacheConfig:
    """Configuration for key state cache.

    Attributes:
        ttl_seconds: Time-to-live for cache entries (default 5 minutes per spec).
        max_entries: Maximum entries before LRU eviction.
    """
    ttl_seconds: int = 300  # 5 minutes default per §5C.2
    max_entries: int = 1000


@dataclass
class _CacheEntry:
    """Internal cache entry with metadata.

    Attributes:
        key_state: The cached KeyState.
        expires_at: Timestamp when this entry expires.
        last_access: Timestamp of last access (for LRU).
    """
    key_state: "KeyState"
    expires_at: datetime
    last_access: datetime


class KeyStateCache:
    """Thread-safe cache for resolved key states.

    Supports lookup by:
    1. (AID, establishment_digest) - exact match for a specific key state
    2. (AID, reference_time) - find key state valid at a given time

    The cache is designed for async access patterns typical in verification
    workloads where multiple PASSporTs may reference the same AID.
    """

    def __init__(self, config: Optional[CacheConfig] = None):
        """Initialize cache with configuration.

        Args:
            config: Cache configuration (uses defaults if None).
        """
        self._config = config or CacheConfig()
        # Primary index: (aid, establishment_digest) → entry
        self._entries: Dict[Tuple[str, str], _CacheEntry] = {}
        # Secondary index: (aid, reference_time) → establishment_digest
        self._time_index: Dict[Tuple[str, datetime], str] = {}
        # Access order for LRU (most recent at end)
        self._access_order: list[Tuple[str, str]] = []
        # Lock for thread safety
        self._lock = asyncio.Lock()
        # Metrics tracking
        self._metrics = CacheMetrics()

    async def get(self, aid: str, establishment_digest: str) -> Optional["KeyState"]:
        """Get cached key state by AID and establishment event digest.

        Args:
            aid: The AID (Autonomic Identifier).
            establishment_digest: SAID of the establishment event.

        Returns:
            KeyState if found and not expired, None otherwise.
        """
        async with self._lock:
            key = (aid, establishment_digest)
            entry = self._entries.get(key)

            if entry is None:
                self._metrics.misses += 1
                log.debug(f"KeyState cache miss: {aid[:20]}...")
                return None

            # Check expiration
            now = datetime.now(timezone.utc)
            if entry.expires_at < now:
                self._remove_entry(key)
                self._metrics.misses += 1
                log.debug(f"KeyState cache expired: {aid[:20]}...")
                return None

            # Update access time for LRU
            entry.last_access = now
            self._touch_access_order(key)
            self._metrics.hits += 1
            log.debug(f"KeyState cache hit: {aid[:20]}...")

            return entry.key_state

    async def get_for_time(
        self,
        aid: str,
        reference_time: datetime
    ) -> Optional["KeyState"]:
        """Get cached key state valid at a specific reference time.

        This uses the secondary time index to find the establishment digest,
        then looks up the full key state.

        Args:
            aid: The AID (Autonomic Identifier).
            reference_time: The reference time (e.g., PASSporT iat).

        Returns:
            KeyState if a cached entry covers this time, None otherwise.
        """
        async with self._lock:
            time_key = (aid, reference_time)
            digest = self._time_index.get(time_key)

            if digest is None:
                return None

            # Delegate to primary lookup (will check expiration)
            # Release lock to avoid deadlock
            pass

        # Call get() outside of lock (it acquires its own lock)
        return await self.get(aid, digest)

    async def put(
        self,
        key_state: "KeyState",
        reference_time: Optional[datetime] = None
    ) -> None:
        """Store a resolved key state in the cache.

        The key state is indexed by:
        1. (aid, establishment_digest) - primary key
        2. (aid, valid_from) - secondary time index (if valid_from is set)
        3. (aid, reference_time) - additional time index (if provided)

        Args:
            key_state: The resolved KeyState to cache.
            reference_time: Optional reference time to also index by.
        """
        async with self._lock:
            now = datetime.now(timezone.utc)
            key = (key_state.aid, key_state.establishment_digest)

            # Create entry
            entry = _CacheEntry(
                key_state=key_state,
                expires_at=now + timedelta(seconds=self._config.ttl_seconds),
                last_access=now
            )

            # Check if we need to evict
            if len(self._entries) >= self._config.max_entries and key not in self._entries:
                self._evict_lru()

            # Store in primary index
            self._entries[key] = entry
            self._touch_access_order(key)

            # Store in secondary time index if valid_from is set
            if key_state.valid_from:
                time_key = (key_state.aid, key_state.valid_from)
                self._time_index[time_key] = key_state.establishment_digest

            # Also index by the query reference_time if provided
            if reference_time:
                ref_time_key = (key_state.aid, reference_time)
                self._time_index[ref_time_key] = key_state.establishment_digest

    async def invalidate(self, aid: str) -> int:
        """Invalidate all cached entries for an AID.

        Use when key state may have changed (e.g., rotation detected).

        Args:
            aid: The AID to invalidate.

        Returns:
            Number of entries invalidated.
        """
        async with self._lock:
            # Find all entries for this AID
            keys_to_remove = [
                key for key in self._entries.keys()
                if key[0] == aid
            ]

            count = len(keys_to_remove)
            for key in keys_to_remove:
                self._remove_entry(key)

            # Remove from time index
            time_keys_to_remove = [
                tkey for tkey in self._time_index.keys()
                if tkey[0] == aid
            ]
            for tkey in time_keys_to_remove:
                del self._time_index[tkey]

            if count > 0:
                self._metrics.invalidations += count
                log.info(f"KeyState cache invalidated {count} entries for AID: {aid[:20]}...")

            return count

    def _remove_entry(self, key: Tuple[str, str]) -> None:
        """Remove entry from all indexes (caller must hold lock)."""
        entry = self._entries.pop(key, None)
        if entry and key in self._access_order:
            self._access_order.remove(key)

        # Clean up time index entries pointing to this digest
        aid, digest = key
        time_keys_to_remove = [
            tkey for tkey, d in self._time_index.items()
            if tkey[0] == aid and d == digest
        ]
        for tkey in time_keys_to_remove:
            del self._time_index[tkey]

    def _touch_access_order(self, key: Tuple[str, str]) -> None:
        """Move key to end of access order (caller must hold lock)."""
        if key in self._access_order:
            self._access_order.remove(key)
        self._access_order.append(key)

    def _evict_lru(self) -> None:
        """Evict least recently used entry (caller must hold lock)."""
        if self._access_order:
            lru_key = self._access_order[0]
            self._remove_entry(lru_key)
            self._metrics.evictions += 1
            log.debug(f"KeyState cache LRU eviction: {lru_key[0][:20]}...")

    async def clear(self) -> None:
        """Clear all cache entries."""
        async with self._lock:
            self._entries.clear()
            self._time_index.clear()
            self._access_order.clear()

    @property
    def size(self) -> int:
        """Current number of cached entries."""
        return len(self._entries)

    def metrics(self) -> CacheMetrics:
        """Get cache metrics.

        Returns:
            CacheMetrics instance with current statistics.
        """
        return self._metrics
