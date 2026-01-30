"""Tests for SchemaCache with LRU eviction and TTL expiration."""

import asyncio
import time

import pytest

from app.vvp.acdc.schema_cache import (
    CachedSchema,
    SchemaCache,
    SchemaCacheConfig,
    SchemaCacheMetrics,
    get_schema_cache,
    reset_schema_cache,
)


@pytest.fixture
def sample_schema():
    """Sample JSON Schema document for testing."""
    return {
        "$id": "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao",
        "$schema": "http://json-schema.org/draft-07/schema#",
        "title": "Test Schema",
        "type": "object",
        "properties": {
            "name": {"type": "string"},
            "value": {"type": "integer"},
        },
    }


@pytest.fixture
def cache_config():
    """Short TTL config for testing."""
    return SchemaCacheConfig(ttl_seconds=1, max_entries=3)


@pytest.fixture
async def cache(cache_config):
    """Fresh cache instance for testing."""
    reset_schema_cache()
    return SchemaCache(cache_config)


class TestSchemaCacheConfig:
    """Tests for SchemaCacheConfig defaults."""

    def test_default_values(self):
        """Default TTL is 1 hour, max entries is 200."""
        config = SchemaCacheConfig()
        assert config.ttl_seconds == 3600
        assert config.max_entries == 200

    def test_custom_values(self):
        """Custom values are respected."""
        config = SchemaCacheConfig(ttl_seconds=60, max_entries=10)
        assert config.ttl_seconds == 60
        assert config.max_entries == 10


class TestSchemaCacheMetrics:
    """Tests for SchemaCacheMetrics."""

    def test_hit_rate_calculation(self):
        """Hit rate is computed correctly."""
        metrics = SchemaCacheMetrics(hits=3, misses=1)
        assert metrics.hit_rate() == 0.75

    def test_hit_rate_zero_requests(self):
        """Hit rate is 0.0 when no requests."""
        metrics = SchemaCacheMetrics()
        assert metrics.hit_rate() == 0.0

    def test_to_dict(self):
        """Metrics can be serialized to dict."""
        metrics = SchemaCacheMetrics(hits=10, misses=5, evictions=2, expirations=1)
        d = metrics.to_dict()
        assert d["hits"] == 10
        assert d["misses"] == 5
        assert d["evictions"] == 2
        assert d["expirations"] == 1
        assert d["hit_rate"] == pytest.approx(0.6667, rel=0.01)

    def test_reset(self):
        """Reset clears all metrics."""
        metrics = SchemaCacheMetrics(hits=10, misses=5)
        metrics.reset()
        assert metrics.hits == 0
        assert metrics.misses == 0


class TestSchemaCache:
    """Core cache tests."""

    @pytest.mark.asyncio
    async def test_cache_miss(self, cache):
        """Cache miss returns None and increments counter."""
        result = await cache.get("nonexistent-said")
        assert result is None
        assert cache.metrics.misses == 1

    @pytest.mark.asyncio
    async def test_cache_hit(self, cache, sample_schema):
        """Cache hit returns schema and increments counter."""
        said = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao"
        await cache.put(said, sample_schema, "https://test.registry/", "registry")

        result = await cache.get(said)
        assert result == sample_schema
        assert cache.metrics.hits == 1

    @pytest.mark.asyncio
    async def test_cache_expiration(self, cache, sample_schema):
        """Expired entries are removed on access."""
        said = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao"
        await cache.put(said, sample_schema, "https://test.registry/", "registry")

        # Wait for TTL to expire (config has 1 second TTL)
        await asyncio.sleep(1.5)

        result = await cache.get(said)
        assert result is None
        assert cache.metrics.expirations == 1

    @pytest.mark.asyncio
    async def test_cache_lru_eviction(self, cache, sample_schema):
        """LRU eviction when at capacity."""
        # Cache has max_entries=3
        schemas = [
            {"$id": f"said-{i}", "title": f"Schema {i}"}
            for i in range(4)
        ]

        # Put 4 schemas, first should be evicted
        for i, schema in enumerate(schemas):
            await cache.put(f"said-{i}", schema, "https://test/", "registry")

        # First should be evicted (LRU)
        assert await cache.get("said-0") is None
        # Others should still exist
        assert await cache.get("said-1") is not None
        assert await cache.get("said-2") is not None
        assert await cache.get("said-3") is not None
        assert cache.metrics.evictions == 1

    @pytest.mark.asyncio
    async def test_cache_get_entry(self, cache, sample_schema):
        """get_entry returns full CachedSchema with metadata."""
        said = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao"
        await cache.put(said, sample_schema, "https://test.registry/", "registry")

        entry = await cache.get_entry(said)
        assert entry is not None
        assert isinstance(entry, CachedSchema)
        assert entry.schema_doc == sample_schema
        assert entry.verified_said == said
        assert entry.source == "https://test.registry/"
        assert entry.source_type == "registry"
        assert entry.cached_at > 0
        assert entry.expires_at > entry.cached_at

    @pytest.mark.asyncio
    async def test_cache_invalidate(self, cache, sample_schema):
        """Invalidate removes entry from cache."""
        said = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao"
        await cache.put(said, sample_schema, "https://test/", "registry")

        removed = await cache.invalidate(said)
        assert removed is True
        assert await cache.get(said) is None

        # Invalidating again returns False
        removed = await cache.invalidate(said)
        assert removed is False

    @pytest.mark.asyncio
    async def test_cache_clear(self, cache, sample_schema):
        """Clear removes all entries."""
        for i in range(3):
            await cache.put(f"said-{i}", sample_schema, "https://test/", "registry")

        count = await cache.clear()
        assert count == 3
        assert await cache.size() == 0

    @pytest.mark.asyncio
    async def test_cache_size(self, cache, sample_schema):
        """Size returns current entry count."""
        assert await cache.size() == 0

        await cache.put("said-1", sample_schema, "https://test/", "registry")
        assert await cache.size() == 1

        await cache.put("said-2", sample_schema, "https://test/", "registry")
        assert await cache.size() == 2

    @pytest.mark.asyncio
    async def test_cache_lru_access_updates_order(self, cache, sample_schema):
        """Accessing an entry moves it to most-recently-used."""
        # Put 3 entries (at capacity)
        for i in range(3):
            await cache.put(f"said-{i}", {"$id": f"said-{i}"}, "https://test/", "registry")

        # Access said-0 to make it most recently used
        await cache.get("said-0")

        # Put a 4th entry - should evict said-1 (now LRU)
        await cache.put("said-3", {"$id": "said-3"}, "https://test/", "registry")

        # said-0 should still exist (was accessed)
        assert await cache.get("said-0") is not None
        # said-1 should be evicted
        assert await cache.get("said-1") is None


class TestSchemaCacheSingleton:
    """Tests for singleton access."""

    @pytest.mark.asyncio
    async def test_singleton_creation(self):
        """get_schema_cache creates singleton."""
        reset_schema_cache()
        cache1 = await get_schema_cache()
        cache2 = await get_schema_cache()
        assert cache1 is cache2

    @pytest.mark.asyncio
    async def test_singleton_reset(self):
        """reset_schema_cache clears singleton."""
        cache1 = await get_schema_cache()
        reset_schema_cache()
        cache2 = await get_schema_cache()
        assert cache1 is not cache2


class TestCacheInvariant:
    """Tests for cache invariant: only stores verified schemas."""

    @pytest.mark.asyncio
    async def test_cache_stores_with_verified_said(self, cache, sample_schema):
        """Cache entry includes verified_said field."""
        said = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao"
        await cache.put(said, sample_schema, "https://test/", "registry")

        entry = await cache.get_entry(said)
        assert entry.verified_said == said

    @pytest.mark.asyncio
    async def test_cache_key_is_said(self, cache, sample_schema):
        """Cache key is the SAID, ensuring verified content."""
        said = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao"
        await cache.put(said, sample_schema, "https://test/", "registry")

        # Can only retrieve by exact SAID
        assert await cache.get(said) is not None
        assert await cache.get("different-said") is None
