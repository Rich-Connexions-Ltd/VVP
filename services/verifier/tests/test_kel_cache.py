"""Tests for key state cache.

Tests cache behavior per PLAN.md:
- Primary key: (AID, establishment_digest)
- Secondary time index: (AID, reference_time) → establishment_digest
- LRU eviction
- TTL expiration
"""

import asyncio
from datetime import datetime, timedelta
import pytest

from app.vvp.keri.cache import CacheConfig, KeyStateCache, _CacheEntry


# Import KeyState from where it's defined
# We need to avoid circular imports, so we'll create a mock KeyState here
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class MockKeyState:
    """Mock KeyState for testing cache without full kel_resolver dependency."""
    aid: str
    signing_keys: List[bytes]
    sequence: int
    establishment_digest: str
    valid_from: Optional[datetime]
    witnesses: List[str]
    toad: int


# Monkey-patch the KeyStateCache to use our mock
import app.vvp.keri.cache as cache_module


@pytest.fixture
def cache():
    """Create a fresh cache for each test."""
    return KeyStateCache(CacheConfig(ttl_seconds=300, max_entries=10))


@pytest.fixture
def small_cache():
    """Create a cache with small max_entries for eviction tests."""
    return KeyStateCache(CacheConfig(ttl_seconds=300, max_entries=3))


@pytest.fixture
def short_ttl_cache():
    """Create a cache with short TTL for expiration tests."""
    return KeyStateCache(CacheConfig(ttl_seconds=1, max_entries=10))


def make_key_state(
    aid: str = "BAID123",
    seq: int = 0,
    digest: str = "EDIGEST",
    valid_from: Optional[datetime] = None
) -> MockKeyState:
    """Create a test KeyState."""
    return MockKeyState(
        aid=aid,
        signing_keys=[b"key" * 10],
        sequence=seq,
        establishment_digest=digest,
        valid_from=valid_from,
        witnesses=[],
        toad=0,
    )


class TestCacheBasicOperations:
    """Test basic cache get/put operations."""

    @pytest.mark.asyncio
    async def test_put_and_get(self, cache):
        """Store and retrieve a key state."""
        ks = make_key_state()

        await cache.put(ks)
        result = await cache.get(ks.aid, ks.establishment_digest)

        assert result is not None
        assert result.aid == ks.aid
        assert result.establishment_digest == ks.establishment_digest

    @pytest.mark.asyncio
    async def test_get_nonexistent_returns_none(self, cache):
        """Get non-existent entry returns None."""
        result = await cache.get("nonexistent", "digest")
        assert result is None

    @pytest.mark.asyncio
    async def test_put_updates_existing(self, cache):
        """Put with same key updates the entry."""
        ks1 = make_key_state(seq=0)
        ks2 = make_key_state(seq=1)  # Same AID/digest, different seq

        await cache.put(ks1)
        await cache.put(ks2)

        result = await cache.get(ks1.aid, ks1.establishment_digest)
        assert result.sequence == 1

    @pytest.mark.asyncio
    async def test_cache_size(self, cache):
        """Cache size reflects stored entries."""
        assert cache.size == 0

        await cache.put(make_key_state(digest="d1"))
        assert cache.size == 1

        await cache.put(make_key_state(digest="d2"))
        assert cache.size == 2


class TestCacheTimeIndex:
    """Test secondary time index operations."""

    @pytest.mark.asyncio
    async def test_get_for_time_with_valid_from(self, cache):
        """Get by time uses secondary index."""
        ts = datetime(2024, 1, 1, 12, 0, 0)
        ks = make_key_state(valid_from=ts)

        await cache.put(ks)
        result = await cache.get_for_time(ks.aid, ts)

        assert result is not None
        assert result.establishment_digest == ks.establishment_digest

    @pytest.mark.asyncio
    async def test_get_for_time_without_valid_from(self, cache):
        """Get by time returns None if valid_from not set."""
        ks = make_key_state(valid_from=None)

        await cache.put(ks)
        result = await cache.get_for_time(ks.aid, datetime.now())

        # Should return None because no time index was created
        assert result is None

    @pytest.mark.asyncio
    async def test_get_for_time_range_match(self, cache):
        """Range match: query at ts2 hits entry with valid_from=ts1 (no rotation).

        Verifies that the range scan path (_range_match_locked) is exercised,
        not just the exact match path — ts2 is NOT in the time index.
        """
        ts1 = datetime(2024, 1, 1, 12, 0, 0)
        ts2 = datetime(2024, 1, 2, 12, 0, 0)  # Different from valid_from → range scan
        ks = make_key_state(valid_from=ts1)

        await cache.put(ks)

        # Confirm ts2 is not in time index (only ts1/valid_from is indexed by put())
        assert (ks.aid, ts2) not in cache._time_index

        result = await cache.get_for_time(ks.aid, ts2)

        # Sprint 78: range-based cache — entry covers ts2 since no valid_until
        # and entry was just cached (within freshness_window)
        assert result is not None
        assert result.establishment_digest == ks.establishment_digest

        # After range match, ts2 is now indexed for future O(1) lookups
        assert (ks.aid, ts2) in cache._time_index

    @pytest.mark.asyncio
    async def test_get_for_time_before_valid_from_misses(self, cache):
        """Query BEFORE valid_from misses — key wasn't established yet."""
        ts1 = datetime(2024, 1, 2, 12, 0, 0)
        ts_before = datetime(2024, 1, 1, 12, 0, 0)
        ks = make_key_state(valid_from=ts1)

        await cache.put(ks)
        result = await cache.get_for_time(ks.aid, ts_before)

        assert result is None


class TestCacheInvalidation:
    """Test cache invalidation."""

    @pytest.mark.asyncio
    async def test_invalidate_removes_all_for_aid(self, cache):
        """Invalidate removes all entries for an AID."""
        aid = "BAID_TO_INVALIDATE"
        ks1 = make_key_state(aid=aid, digest="d1")
        ks2 = make_key_state(aid=aid, digest="d2")
        ks3 = make_key_state(aid="BOTHER_AID", digest="d3")

        await cache.put(ks1)
        await cache.put(ks2)
        await cache.put(ks3)

        assert cache.size == 3

        await cache.invalidate(aid)

        assert cache.size == 1
        assert await cache.get(aid, "d1") is None
        assert await cache.get(aid, "d2") is None
        assert await cache.get("BOTHER_AID", "d3") is not None

    @pytest.mark.asyncio
    async def test_invalidate_nonexistent_aid(self, cache):
        """Invalidate non-existent AID is a no-op."""
        await cache.put(make_key_state())
        initial_size = cache.size

        await cache.invalidate("BNONEXISTENT")

        assert cache.size == initial_size


class TestCacheClear:
    """Test cache clearing."""

    @pytest.mark.asyncio
    async def test_clear_removes_all(self, cache):
        """Clear removes all entries."""
        await cache.put(make_key_state(digest="d1"))
        await cache.put(make_key_state(digest="d2"))

        assert cache.size == 2

        await cache.clear()

        assert cache.size == 0


class TestCacheLRUEviction:
    """Test LRU eviction behavior."""

    @pytest.mark.asyncio
    async def test_eviction_when_full(self, small_cache):
        """Evict LRU entry when cache is full."""
        # Fill cache to capacity
        await small_cache.put(make_key_state(digest="d1"))
        await small_cache.put(make_key_state(digest="d2"))
        await small_cache.put(make_key_state(digest="d3"))

        assert small_cache.size == 3

        # Add one more - should evict d1 (oldest)
        await small_cache.put(make_key_state(digest="d4"))

        assert small_cache.size == 3
        assert await small_cache.get("BAID123", "d1") is None  # Evicted
        assert await small_cache.get("BAID123", "d4") is not None  # New entry

    @pytest.mark.asyncio
    async def test_access_updates_lru_order(self, small_cache):
        """Accessing an entry updates its LRU position."""
        await small_cache.put(make_key_state(digest="d1"))
        await small_cache.put(make_key_state(digest="d2"))
        await small_cache.put(make_key_state(digest="d3"))

        # Access d1, making it most recently used
        await small_cache.get("BAID123", "d1")

        # Add new entry - should evict d2 (now oldest)
        await small_cache.put(make_key_state(digest="d4"))

        assert await small_cache.get("BAID123", "d1") is not None  # Still present
        assert await small_cache.get("BAID123", "d2") is None  # Evicted
        assert await small_cache.get("BAID123", "d4") is not None


class TestCacheTTL:
    """Test TTL expiration behavior."""

    @pytest.mark.asyncio
    async def test_expired_entry_returns_none(self, short_ttl_cache):
        """Expired entries return None."""
        ks = make_key_state()

        await short_ttl_cache.put(ks)

        # Entry should be present immediately
        assert await short_ttl_cache.get(ks.aid, ks.establishment_digest) is not None

        # Wait for TTL to expire
        await asyncio.sleep(1.5)

        # Entry should now be expired
        result = await short_ttl_cache.get(ks.aid, ks.establishment_digest)
        assert result is None

    @pytest.mark.asyncio
    async def test_expired_entry_removed_on_access(self, short_ttl_cache):
        """Expired entry is removed when accessed."""
        ks = make_key_state()

        await short_ttl_cache.put(ks)
        initial_size = short_ttl_cache.size

        await asyncio.sleep(1.5)

        # Access triggers cleanup
        await short_ttl_cache.get(ks.aid, ks.establishment_digest)

        assert short_ttl_cache.size == 0


class TestCacheConcurrency:
    """Test thread-safety under concurrent access."""

    @pytest.mark.asyncio
    async def test_concurrent_puts(self, cache):
        """Concurrent puts don't corrupt cache."""
        async def put_entry(i: int):
            ks = make_key_state(digest=f"d{i}")
            await cache.put(ks)

        # Run many puts concurrently
        await asyncio.gather(*[put_entry(i) for i in range(20)])

        # Should have 10 entries (max_entries = 10)
        assert cache.size <= 10

    @pytest.mark.asyncio
    async def test_concurrent_get_put(self, cache):
        """Concurrent gets and puts don't deadlock."""
        ks = make_key_state()
        await cache.put(ks)

        async def get_entry():
            for _ in range(10):
                await cache.get(ks.aid, ks.establishment_digest)
                await asyncio.sleep(0.001)

        async def put_entry():
            for i in range(10):
                await cache.put(make_key_state(digest=f"d{i}"))
                await asyncio.sleep(0.001)

        # Run concurrently
        await asyncio.gather(get_entry(), put_entry())

        # Should complete without deadlock


class TestCacheConfig:
    """Test cache configuration."""

    def test_default_config(self):
        """Default config has reasonable values."""
        config = CacheConfig()
        assert config.ttl_seconds == 300
        assert config.max_entries == 1000

    def test_custom_config(self):
        """Custom config is applied."""
        config = CacheConfig(ttl_seconds=60, max_entries=100)
        cache = KeyStateCache(config)

        assert cache._config.ttl_seconds == 60
        assert cache._config.max_entries == 100
