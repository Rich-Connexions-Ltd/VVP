"""Tests for credential cache module."""

import asyncio
import pytest
import time
from unittest.mock import MagicMock

from app.vvp.keri.credential_cache import (
    CredentialCache,
    CredentialCacheConfig,
    CredentialCacheMetrics,
    CachedCredential,
    get_credential_cache,
    reset_credential_cache,
)


@pytest.fixture
def mock_acdc():
    """Create a mock ACDC for testing."""
    acdc = MagicMock()
    acdc.said = "EABC123456789012345678901234567890123"
    acdc.issuer_aid = "EIssuer1234567890123456789012345678"
    return acdc


@pytest.fixture
def cache():
    """Create a fresh cache for each test."""
    return CredentialCache(CredentialCacheConfig(ttl_seconds=60, max_entries=10))


@pytest.fixture(autouse=True)
def reset_singleton():
    """Reset singleton before each test."""
    reset_credential_cache()
    yield
    reset_credential_cache()


class TestCredentialCacheMetrics:
    """Tests for CredentialCacheMetrics."""

    def test_hit_rate_empty(self):
        """Test hit rate with no requests."""
        metrics = CredentialCacheMetrics()
        assert metrics.hit_rate() == 0.0

    def test_hit_rate_all_hits(self):
        """Test hit rate when all are hits."""
        metrics = CredentialCacheMetrics(hits=10, misses=0)
        assert metrics.hit_rate() == 1.0

    def test_hit_rate_all_misses(self):
        """Test hit rate when all are misses."""
        metrics = CredentialCacheMetrics(hits=0, misses=10)
        assert metrics.hit_rate() == 0.0

    def test_hit_rate_mixed(self):
        """Test hit rate with mixed hits/misses."""
        metrics = CredentialCacheMetrics(hits=7, misses=3)
        assert metrics.hit_rate() == 0.7

    def test_to_dict(self):
        """Test dictionary conversion."""
        metrics = CredentialCacheMetrics(hits=5, misses=5, evictions=2, expirations=1)
        d = metrics.to_dict()
        assert d["hits"] == 5
        assert d["misses"] == 5
        assert d["evictions"] == 2
        assert d["expirations"] == 1
        assert d["hit_rate"] == 0.5

    def test_reset(self):
        """Test metrics reset."""
        metrics = CredentialCacheMetrics(hits=5, misses=5, evictions=2, expirations=1)
        metrics.reset()
        assert metrics.hits == 0
        assert metrics.misses == 0
        assert metrics.evictions == 0
        assert metrics.expirations == 0


class TestCredentialCache:
    """Tests for CredentialCache."""

    @pytest.mark.asyncio
    async def test_put_and_get(self, cache, mock_acdc):
        """Test basic put and get operations."""
        said = mock_acdc.said

        await cache.put(said, mock_acdc, "http://witness.example.com")

        result = await cache.get(said)
        assert result is mock_acdc

    @pytest.mark.asyncio
    async def test_get_nonexistent(self, cache):
        """Test getting a non-existent entry."""
        result = await cache.get("nonexistent-said")
        assert result is None
        assert cache.metrics.misses == 1

    @pytest.mark.asyncio
    async def test_cache_hit_increments_metrics(self, cache, mock_acdc):
        """Test that cache hits increment metrics."""
        await cache.put(mock_acdc.said, mock_acdc, "http://witness.example.com")

        await cache.get(mock_acdc.said)
        assert cache.metrics.hits == 1

        await cache.get(mock_acdc.said)
        assert cache.metrics.hits == 2

    @pytest.mark.asyncio
    async def test_cache_miss_increments_metrics(self, cache):
        """Test that cache misses increment metrics."""
        await cache.get("nonexistent1")
        await cache.get("nonexistent2")
        assert cache.metrics.misses == 2

    @pytest.mark.asyncio
    async def test_ttl_expiration(self, mock_acdc):
        """Test that entries expire after TTL."""
        # Create cache with 1 second TTL
        cache = CredentialCache(CredentialCacheConfig(ttl_seconds=1, max_entries=10))

        await cache.put(mock_acdc.said, mock_acdc, "http://witness.example.com")

        # Should be present initially
        result = await cache.get(mock_acdc.said)
        assert result is mock_acdc

        # Wait for expiration
        await asyncio.sleep(1.1)

        # Should be expired now
        result = await cache.get(mock_acdc.said)
        assert result is None
        assert cache.metrics.expirations == 1

    @pytest.mark.asyncio
    async def test_lru_eviction(self, mock_acdc):
        """Test LRU eviction when max_entries is exceeded."""
        cache = CredentialCache(CredentialCacheConfig(ttl_seconds=60, max_entries=3))

        # Add 3 entries with distinct SAIDs
        saids = ["ESAID_ENTRY_0_12345678901234567890",
                 "ESAID_ENTRY_1_12345678901234567890",
                 "ESAID_ENTRY_2_12345678901234567890"]

        for i, said in enumerate(saids):
            acdc = MagicMock()
            acdc.said = said
            await cache.put(said, acdc, f"http://witness{i}.example.com")

        # All should be present
        assert await cache.size() == 3

        # Access first entry to make it most recently used
        await cache.get(saids[0])

        # Add a new entry, should evict ESAID1 (least recently used)
        new_acdc = MagicMock()
        new_acdc.said = "ESAID_NEW_ENTRY_123456789012345678"
        await cache.put(new_acdc.said, new_acdc, "http://witness-new.example.com")

        # Should still have 3 entries (max)
        assert await cache.size() == 3
        assert cache.metrics.evictions >= 1

        # First entry should still be present (was accessed, so not LRU)
        result = await cache.get(saids[0])
        assert result is not None

    @pytest.mark.asyncio
    async def test_invalidate_existing(self, cache, mock_acdc):
        """Test invalidating an existing entry."""
        await cache.put(mock_acdc.said, mock_acdc, "http://witness.example.com")

        result = await cache.invalidate(mock_acdc.said)
        assert result is True

        # Should be gone
        result = await cache.get(mock_acdc.said)
        assert result is None

    @pytest.mark.asyncio
    async def test_invalidate_nonexistent(self, cache):
        """Test invalidating a non-existent entry."""
        result = await cache.invalidate("nonexistent-said")
        assert result is False

    @pytest.mark.asyncio
    async def test_clear(self, cache, mock_acdc):
        """Test clearing all entries."""
        # Add some entries
        for i in range(5):
            acdc = MagicMock()
            acdc.said = f"ESAID{i:037d}"
            await cache.put(acdc.said, acdc, f"http://witness{i}.example.com")

        assert await cache.size() == 5

        count = await cache.clear()
        assert count == 5
        assert await cache.size() == 0

    @pytest.mark.asyncio
    async def test_get_entry_returns_metadata(self, cache, mock_acdc):
        """Test that get_entry returns full cache entry with metadata."""
        await cache.put(
            mock_acdc.said,
            mock_acdc,
            "http://witness.example.com",
            signature=b"test_signature",
        )

        entry = await cache.get_entry(mock_acdc.said)
        assert entry is not None
        assert entry.acdc is mock_acdc
        assert entry.source_url == "http://witness.example.com"
        assert entry.signature == b"test_signature"
        assert entry.cached_at > 0
        assert entry.expires_at > entry.cached_at

    @pytest.mark.asyncio
    async def test_get_entry_nonexistent(self, cache):
        """Test get_entry for non-existent entry."""
        entry = await cache.get_entry("nonexistent-said")
        assert entry is None

    @pytest.mark.asyncio
    async def test_put_updates_existing(self, cache, mock_acdc):
        """Test that put overwrites existing entry."""
        await cache.put(mock_acdc.said, mock_acdc, "http://witness1.example.com")

        # Update with different source
        await cache.put(mock_acdc.said, mock_acdc, "http://witness2.example.com")

        entry = await cache.get_entry(mock_acdc.said)
        assert entry.source_url == "http://witness2.example.com"


class TestCredentialCacheSingleton:
    """Tests for credential cache singleton."""

    @pytest.mark.asyncio
    async def test_singleton_returns_same_instance(self):
        """Test that singleton returns the same instance."""
        cache1 = await get_credential_cache()
        cache2 = await get_credential_cache()
        assert cache1 is cache2

    @pytest.mark.asyncio
    async def test_reset_clears_singleton(self):
        """Test that reset clears the singleton."""
        cache1 = await get_credential_cache()
        reset_credential_cache()
        cache2 = await get_credential_cache()
        assert cache1 is not cache2

    @pytest.mark.asyncio
    async def test_config_only_used_on_creation(self):
        """Test that config is only used when creating new instance."""
        config1 = CredentialCacheConfig(ttl_seconds=100, max_entries=50)
        cache1 = await get_credential_cache(config1)

        # This config should be ignored
        config2 = CredentialCacheConfig(ttl_seconds=200, max_entries=100)
        cache2 = await get_credential_cache(config2)

        assert cache1 is cache2
        # Original config should be in effect
        assert cache1._config.ttl_seconds == 100
