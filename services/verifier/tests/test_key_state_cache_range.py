"""Tests for Sprint 78: Range-based KeyStateCache.

Tests the new range-based matching logic:
- _entry_covers_time() pure function
- Range scan matching for different reference times
- Freshness guard for unbounded entries
- valid_until boundary enforcement
- Sequence-based tie-breaking
- Time-index eviction cap
"""

import asyncio
from datetime import datetime, timedelta, timezone
import pytest

from app.vvp.keri.cache import (
    CacheConfig,
    KeyStateCache,
    _CacheEntry,
    _entry_covers_time,
    _normalize_datetime,
)


from dataclasses import dataclass
from typing import List, Optional


@dataclass
class MockKeyState:
    """Mock KeyState for cache tests."""
    aid: str
    signing_keys: List[bytes]
    sequence: int
    establishment_digest: str
    valid_from: Optional[datetime]
    witnesses: List[str]
    toad: int


def make_ks(
    aid: str = "BAID_TEST",
    seq: int = 0,
    digest: str = "EDIGEST",
    valid_from: Optional[datetime] = None,
) -> MockKeyState:
    return MockKeyState(
        aid=aid,
        signing_keys=[b"key" * 10],
        sequence=seq,
        establishment_digest=digest,
        valid_from=valid_from,
        witnesses=[],
        toad=0,
    )


# =============================================================================
# _entry_covers_time pure function tests
# =============================================================================

class TestEntryCoversPureFunction:
    """Test _entry_covers_time as a pure function."""

    def _make_entry(
        self,
        valid_from: datetime,
        valid_until: Optional[datetime] = None,
        cached_at: Optional[datetime] = None,
        sequence: int = 0,
    ) -> _CacheEntry:
        now = datetime.now(timezone.utc)
        ks = make_ks(valid_from=valid_from, seq=sequence)
        return _CacheEntry(
            key_state=ks,
            expires_at=now + timedelta(seconds=300),
            last_access=now,
            cached_at=cached_at or now,
            valid_until=valid_until,
            sequence=sequence,
        )

    def test_covers_exact_valid_from(self):
        """Entry at valid_from covers that exact time."""
        vf = datetime(2024, 1, 1, tzinfo=timezone.utc)
        entry = self._make_entry(valid_from=vf)
        now = datetime.now(timezone.utc)
        assert _entry_covers_time(entry, vf, now, 120.0) is True

    def test_covers_time_after_valid_from(self):
        """Entry covers times after valid_from (no rotation)."""
        vf = datetime(2024, 1, 1, tzinfo=timezone.utc)
        rt = datetime(2024, 6, 1, tzinfo=timezone.utc)
        entry = self._make_entry(valid_from=vf)
        now = datetime.now(timezone.utc)
        assert _entry_covers_time(entry, rt, now, 120.0) is True

    def test_rejects_before_valid_from(self):
        """Entry doesn't cover times before valid_from."""
        vf = datetime(2024, 6, 1, tzinfo=timezone.utc)
        rt = datetime(2024, 1, 1, tzinfo=timezone.utc)
        entry = self._make_entry(valid_from=vf)
        now = datetime.now(timezone.utc)
        assert _entry_covers_time(entry, rt, now, 120.0) is False

    def test_rejects_after_valid_until(self):
        """Entry doesn't cover times at or after valid_until."""
        vf = datetime(2024, 1, 1, tzinfo=timezone.utc)
        vu = datetime(2024, 3, 1, tzinfo=timezone.utc)
        rt = datetime(2024, 4, 1, tzinfo=timezone.utc)
        entry = self._make_entry(valid_from=vf, valid_until=vu)
        now = datetime.now(timezone.utc)
        assert _entry_covers_time(entry, rt, now, 120.0) is False

    def test_covers_within_valid_until_window(self):
        """Entry covers times between valid_from and valid_until."""
        vf = datetime(2024, 1, 1, tzinfo=timezone.utc)
        vu = datetime(2024, 6, 1, tzinfo=timezone.utc)
        rt = datetime(2024, 3, 1, tzinfo=timezone.utc)
        entry = self._make_entry(valid_from=vf, valid_until=vu)
        now = datetime.now(timezone.utc)
        assert _entry_covers_time(entry, rt, now, 120.0) is True

    def test_valid_until_boundary_exclusive(self):
        """Exactly at valid_until is NOT covered (exclusive)."""
        vf = datetime(2024, 1, 1, tzinfo=timezone.utc)
        vu = datetime(2024, 3, 1, tzinfo=timezone.utc)
        entry = self._make_entry(valid_from=vf, valid_until=vu)
        now = datetime.now(timezone.utc)
        assert _entry_covers_time(entry, vu, now, 120.0) is False

    def test_freshness_guard_rejects_stale_unbounded(self):
        """Freshness guard rejects unbounded entries older than window."""
        vf = datetime(2024, 1, 1, tzinfo=timezone.utc)
        old_cached_at = datetime.now(timezone.utc) - timedelta(seconds=200)
        entry = self._make_entry(valid_from=vf, cached_at=old_cached_at)
        now = datetime.now(timezone.utc)
        rt = datetime(2024, 6, 1, tzinfo=timezone.utc)
        # 120s window, but entry is 200s old
        assert _entry_covers_time(entry, rt, now, 120.0) is False

    def test_freshness_guard_accepts_fresh_unbounded(self):
        """Freshness guard accepts fresh unbounded entries."""
        vf = datetime(2024, 1, 1, tzinfo=timezone.utc)
        fresh_cached_at = datetime.now(timezone.utc) - timedelta(seconds=10)
        entry = self._make_entry(valid_from=vf, cached_at=fresh_cached_at)
        now = datetime.now(timezone.utc)
        rt = datetime(2024, 6, 1, tzinfo=timezone.utc)
        assert _entry_covers_time(entry, rt, now, 120.0) is True

    def test_valid_until_ignores_freshness(self):
        """Entries with valid_until are NOT subject to freshness guard."""
        vf = datetime(2024, 1, 1, tzinfo=timezone.utc)
        vu = datetime(2025, 1, 1, tzinfo=timezone.utc)
        old_cached_at = datetime.now(timezone.utc) - timedelta(seconds=999)
        entry = self._make_entry(valid_from=vf, valid_until=vu, cached_at=old_cached_at)
        now = datetime.now(timezone.utc)
        rt = datetime(2024, 6, 1, tzinfo=timezone.utc)
        # Entry is very old but has valid_until — freshness doesn't apply
        assert _entry_covers_time(entry, rt, now, 120.0) is True

    def test_none_valid_from_rejected(self):
        """Entry with None valid_from always rejected."""
        ks = make_ks(valid_from=None)
        entry = _CacheEntry(
            key_state=ks,
            expires_at=datetime.now(timezone.utc) + timedelta(300),
            last_access=datetime.now(timezone.utc),
            cached_at=datetime.now(timezone.utc),
        )
        now = datetime.now(timezone.utc)
        rt = datetime(2024, 6, 1, tzinfo=timezone.utc)
        assert _entry_covers_time(entry, rt, now, 120.0) is False


# =============================================================================
# Range-based cache integration tests
# =============================================================================

class TestRangeBasedCache:
    """Test range-based get_for_time behavior."""

    @pytest.fixture
    def cache(self):
        return KeyStateCache(CacheConfig(
            ttl_seconds=300,
            max_entries=100,
            freshness_window_seconds=120.0,
        ))

    @pytest.mark.asyncio
    async def test_range_match_single_entry(self, cache):
        """Single entry covers any time after valid_from."""
        vf = datetime(2024, 1, 1, 12, 0, 0)
        ks = make_ks(valid_from=vf)
        await cache.put(ks)

        # Query at 3 different times after valid_from
        for day in [2, 10, 30]:
            rt = datetime(2024, 1, day, 12, 0, 0)
            result = await cache.get_for_time(ks.aid, rt)
            assert result is not None, f"Should match at day {day}"

    @pytest.mark.asyncio
    async def test_range_match_respects_valid_until(self, cache):
        """Range match stops at valid_until boundary."""
        vf = datetime(2024, 1, 1, tzinfo=timezone.utc)
        vu = datetime(2024, 3, 1, tzinfo=timezone.utc)
        ks = make_ks(valid_from=vf)

        await cache.put(ks, valid_until=vu)

        # Within range — should match
        rt_in = datetime(2024, 2, 1, tzinfo=timezone.utc)
        assert await cache.get_for_time(ks.aid, rt_in) is not None

        # After valid_until — should NOT match
        rt_out = datetime(2024, 4, 1, tzinfo=timezone.utc)
        assert await cache.get_for_time(ks.aid, rt_out) is None

    @pytest.mark.asyncio
    async def test_sequence_tiebreak(self, cache):
        """Higher sequence number wins when multiple entries cover same time."""
        vf = datetime(2024, 1, 1, tzinfo=timezone.utc)
        vu = datetime(2024, 12, 1, tzinfo=timezone.utc)

        ks_old = make_ks(seq=0, digest="D_OLD", valid_from=vf)
        ks_new = make_ks(seq=1, digest="D_NEW", valid_from=vf)

        await cache.put(ks_old, valid_until=vu, sequence=0)
        await cache.put(ks_new, valid_until=vu, sequence=1)

        rt = datetime(2024, 6, 1, tzinfo=timezone.utc)
        result = await cache.get_for_time(ks_old.aid, rt)
        assert result is not None
        assert result.sequence == 1  # Higher sequence wins

    @pytest.mark.asyncio
    async def test_exact_match_faster_than_range(self, cache):
        """Exact match via time index is used when available (O(1) path)."""
        vf = datetime(2024, 1, 1)
        ks = make_ks(valid_from=vf)
        await cache.put(ks)

        # First call uses exact match (valid_from == query time)
        result = await cache.get_for_time(ks.aid, vf)
        assert result is not None
        assert cache.metrics().hits == 1

    @pytest.mark.asyncio
    async def test_range_match_indexes_for_future(self, cache):
        """After range match, the result is indexed for O(1) next time."""
        vf = datetime(2024, 1, 1)
        rt = datetime(2024, 1, 15)
        ks = make_ks(valid_from=vf)
        await cache.put(ks)

        # First call: range match (miss on exact, then range scan)
        result1 = await cache.get_for_time(ks.aid, rt)
        assert result1 is not None

        # Second call: should be exact match (indexed from first call)
        result2 = await cache.get_for_time(ks.aid, rt)
        assert result2 is not None
        assert cache.metrics().hits == 2


# =============================================================================
# Time-index eviction tests
# =============================================================================

class TestTimeIndexEviction:
    """Test time-index cap enforcement."""

    @pytest.mark.asyncio
    async def test_time_index_eviction_at_cap(self):
        """Time index bulk evicts when reaching cap."""
        cache = KeyStateCache(CacheConfig(
            ttl_seconds=300,
            max_entries=100,
            freshness_window_seconds=3600.0,  # Long window so everything passes freshness
            max_time_index_entries=10,  # Small cap for testing
        ))

        vf = datetime(2024, 1, 1)
        ks = make_ks(valid_from=vf)
        await cache.put(ks)

        # Fill time index with range matches
        for i in range(15):
            rt = datetime(2024, 1, 1 + i, 12, 0, 0)
            await cache.get_for_time(ks.aid, rt)

        # Cache should still work (entries evicted but new ones added)
        result = await cache.get_for_time(ks.aid, datetime(2024, 1, 20))
        assert result is not None


# =============================================================================
# Freshness window config tests
# =============================================================================

class TestFreshnessConfig:
    """Test freshness window configuration."""

    @pytest.mark.asyncio
    async def test_custom_freshness_window(self):
        """Custom freshness window is respected."""
        cache = KeyStateCache(CacheConfig(
            freshness_window_seconds=5.0,  # Very short
        ))

        vf = datetime(2024, 1, 1)
        ks = make_ks(valid_from=vf)
        await cache.put(ks)

        # Should match immediately
        result = await cache.get_for_time(ks.aid, datetime(2024, 6, 1))
        assert result is not None

        # Wait for freshness to expire
        await asyncio.sleep(6)

        # Query a DIFFERENT time (not previously indexed) to trigger range scan,
        # which checks freshness. The previously-indexed time would hit exact match.
        result = await cache.get_for_time(ks.aid, datetime(2024, 7, 1))
        assert result is None


class TestNormalizeDatetime:
    """Test _normalize_datetime helper."""

    def test_naive_gets_utc(self):
        """Naive datetime gets UTC timezone."""
        naive = datetime(2024, 1, 1)
        result = _normalize_datetime(naive)
        assert result.tzinfo == timezone.utc

    def test_aware_unchanged(self):
        """Timezone-aware datetime is unchanged."""
        aware = datetime(2024, 1, 1, tzinfo=timezone.utc)
        result = _normalize_datetime(aware)
        assert result is aware
