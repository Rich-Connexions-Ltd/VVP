"""Range-based key state cache for KERI resolution.

Per spec §5C.2: "Key state cache: AID + timestamp → Minutes (rotation-sensitive)"

Sprint 78: Upgraded from exact-timestamp matching to range-based matching.
Each cached entry covers a validity window [valid_from, valid_until), where:
- valid_from: timestamp of this establishment event
- valid_until: timestamp of the next establishment event (None = most recent)

Lookup strategy:
1. Exact match via time index — O(1)
2. Range scan over entries for the AID — O(N) where N ≈ 1-2 per AID
3. Higher KEL sequence number wins when multiple entries cover the same time

Freshness guard: Entries with valid_until=None (most recent key state, no known
rotation) are served only while their immutable cached_at timestamp is within
the configurable freshness_window_seconds (default 120s). After expiry, an OOBI
re-fetch is forced to detect any rotations that occurred since caching.

Time-index cap: A secondary index maps (AID, reference_time) → digest for O(1)
repeat lookups. Capped at max_time_index_entries (default 10,000) with bulk
eviction of the oldest half when exceeded.
"""

import asyncio
import logging
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, Dict, Optional, Tuple

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

    def to_dict(self) -> Dict[str, Any]:
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
        freshness_window_seconds: Max age (seconds) for entries with valid_until=None
            before forcing a re-fetch. Uses cached_at (immutable creation time).
        max_time_index_entries: Max time index entries before bulk eviction.
    """
    ttl_seconds: int = 300  # 5 minutes default per §5C.2
    max_entries: int = 1000
    freshness_window_seconds: float = 120.0  # Sprint 78: freshness guard
    max_time_index_entries: int = 10_000  # Sprint 78: time-index cap


@dataclass
class _CacheEntry:
    """Internal cache entry with metadata.

    Attributes:
        key_state: The cached KeyState.
        expires_at: Timestamp when this entry expires.
        last_access: Timestamp of last access (for LRU).
        cached_at: Immutable creation timestamp (freshness guard uses this).
        valid_until: Timestamp of next establishment event (None = most recent).
        sequence: KEL sequence number for authoritative ordering.
    """
    key_state: "KeyState"
    expires_at: datetime
    last_access: datetime
    cached_at: datetime  # Set once at creation — NOT updated on access
    valid_until: Optional[datetime] = None
    sequence: int = 0


def _normalize_datetime(dt: datetime) -> datetime:
    """Normalize datetime to UTC for comparison."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _entry_covers_time(
    entry: _CacheEntry, rt: datetime, now: datetime, freshness_window_seconds: float
) -> bool:
    """Check if entry's validity window covers reference_time.

    Module-level pure function — no access to cache state.
    Takes freshness_window_seconds as explicit parameter.
    """
    ks = entry.key_state
    if ks.valid_from is None:
        return False
    vf = _normalize_datetime(ks.valid_from)
    if vf > rt:
        return False  # Key state starts AFTER reference_time

    if entry.valid_until is not None:
        vu = _normalize_datetime(entry.valid_until)
        if rt >= vu:
            return False  # Superseded by rotation
    else:
        # Freshness guard for unbounded entries (no subsequent rotation known).
        # Uses cached_at (immutable creation time), NOT last_access.
        entry_age = (now - entry.cached_at).total_seconds()
        if entry_age > freshness_window_seconds:
            return False  # Stale — force re-fetch

    return True


class KeyStateCache:
    """Thread-safe, range-based cache for resolved key states.

    Supports lookup by:
    1. (AID, establishment_digest) - exact match for a specific key state
    2. (AID, reference_time) - range-based: find key state whose validity
       window [valid_from, valid_until) covers the reference time

    Range matching uses _entry_covers_time() (module-level pure function)
    to check validity windows and freshness. Higher KEL sequence numbers
    win tie-breaks. Successful range matches are indexed in _time_index
    for O(1) repeat lookups.

    The time index is capped at max_time_index_entries to prevent unbounded
    memory growth from attacker-controlled timestamps.
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
        # Access order for LRU (most recent at end). O(1) move_to_end.
        self._access_order: OrderedDict[Tuple[str, str], None] = OrderedDict()
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

        Strategy:
        1. Exact match via time index — O(1)
        2. Range scan via _range_match_locked() — O(N) where N ≈ 1-2

        Args:
            aid: The AID (Autonomic Identifier).
            reference_time: The reference time (e.g., PASSporT iat).

        Returns:
            KeyState if a cached entry covers this time, None otherwise.
        """
        async with self._lock:
            now = datetime.now(timezone.utc)

            # 1. Exact match (existing O(1) path)
            result = self._exact_match_locked(aid, reference_time, now)
            if result is not None:
                return result

            # 2. Range scan
            result = self._range_match_locked(aid, reference_time, now)
            if result is not None:
                return result

            self._metrics.misses += 1
            return None

    def _exact_match_locked(
        self, aid: str, reference_time: datetime, now: datetime
    ) -> Optional["KeyState"]:
        """O(1) lookup in time index. Caller holds lock."""
        digest = self._time_index.get((aid, reference_time))
        if not digest:
            return None
        entry = self._entries.get((aid, digest))
        if entry and entry.expires_at >= now:
            self._touch_access_order((aid, digest))
            entry.last_access = now
            self._metrics.hits += 1
            return entry.key_state
        return None

    def _range_match_locked(
        self, aid: str, reference_time: datetime, now: datetime
    ) -> Optional["KeyState"]:
        """Scan entries for AID, find best match by validity window + sequence.

        Caller holds lock.
        """
        rt = _normalize_datetime(reference_time)
        best_entry = None
        best_key = None
        best_seq = -1

        for key, entry in self._entries.items():
            if key[0] != aid or entry.expires_at < now:
                continue
            if not _entry_covers_time(
                entry, rt, now, self._config.freshness_window_seconds
            ):
                continue
            if entry.sequence > best_seq:
                best_entry = entry
                best_key = key
                best_seq = entry.sequence

        if best_entry is None:
            return None

        self._touch_access_order(best_key)
        best_entry.last_access = now
        self._metrics.hits += 1

        # Enforce time-index cap before inserting
        self._enforce_time_index_cap()

        # Index for future O(1) lookups
        self._time_index[(aid, reference_time)] = best_key[1]
        return best_entry.key_state

    async def put(
        self,
        key_state: "KeyState",
        reference_time: Optional[datetime] = None,
        valid_until: Optional[datetime] = None,
        sequence: Optional[int] = None,
    ) -> None:
        """Store a resolved key state in the cache.

        The key state is indexed by:
        1. (aid, establishment_digest) - primary key
        2. (aid, valid_from) - secondary time index (if valid_from is set)
        3. (aid, reference_time) - additional time index (if provided)

        Args:
            key_state: The resolved KeyState to cache.
            reference_time: Optional reference time to also index by.
            valid_until: Timestamp of next establishment event (None = most recent).
            sequence: KEL sequence number for authoritative ordering.
        """
        async with self._lock:
            now = datetime.now(timezone.utc)
            key = (key_state.aid, key_state.establishment_digest)

            # Create entry with immutable cached_at
            entry = _CacheEntry(
                key_state=key_state,
                expires_at=now + timedelta(seconds=self._config.ttl_seconds),
                last_access=now,
                cached_at=now,
                valid_until=valid_until,
                sequence=sequence if sequence is not None else key_state.sequence,
            )

            # Check if we need to evict
            if len(self._entries) >= self._config.max_entries and key not in self._entries:
                self._evict_lru()

            # Store in primary index
            self._entries[key] = entry
            self._touch_access_order(key)

            # Enforce time-index cap before adding new entries
            self._enforce_time_index_cap()

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

    def _enforce_time_index_cap(self) -> None:
        """Evict oldest half of time index if at or over cap. Caller holds lock."""
        if len(self._time_index) >= self._config.max_time_index_entries:
            to_remove = list(self._time_index.keys())[
                : len(self._time_index) // 2
            ]
            for k in to_remove:
                del self._time_index[k]

    def _remove_entry(self, key: Tuple[str, str]) -> None:
        """Remove entry from all indexes (caller must hold lock)."""
        entry = self._entries.pop(key, None)
        self._access_order.pop(key, None)

        # Clean up time index entries pointing to this digest
        if entry:
            aid, digest = key
            time_keys_to_remove = [
                tkey for tkey, d in self._time_index.items()
                if tkey[0] == aid and d == digest
            ]
            for tkey in time_keys_to_remove:
                del self._time_index[tkey]

    def _touch_access_order(self, key: Tuple[str, str]) -> None:
        """Move key to end of access order (caller must hold lock). O(1)."""
        self._access_order[key] = None
        self._access_order.move_to_end(key)

    def _evict_lru(self) -> None:
        """Evict least recently used entry (caller must hold lock)."""
        if self._access_order:
            lru_key = next(iter(self._access_order))
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
