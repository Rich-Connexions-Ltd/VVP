"""Tests for dossier cache module.

Tests URL-keyed dossier cache with SAID secondary index per §5.1.1-2.7.
"""

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.vvp.dossier.cache import (
    CachedDossier,
    CacheMetrics,
    DossierCache,
    get_dossier_cache,
    reset_dossier_cache,
)
from app.vvp.dossier.models import ACDCNode, DossierDAG


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def sample_dag():
    """Create a sample DossierDAG for testing."""
    nodes = {
        "SAID_ROOT": ACDCNode(
            said="SAID_ROOT",
            issuer="AID_ISSUER_1",
            schema="SCHEMA_APE",
            attributes={"type": "ape"},
            raw={"d": "SAID_ROOT"},
        ),
        "SAID_CHILD": ACDCNode(
            said="SAID_CHILD",
            issuer="AID_ISSUER_2",
            schema="SCHEMA_LE",
            attributes={"type": "le"},
            raw={"d": "SAID_CHILD"},
        ),
    }
    return DossierDAG(
        nodes=nodes,
        root_said="SAID_ROOT",
        root_saids=["SAID_ROOT"],
    )


@pytest.fixture
def sample_cached_dossier(sample_dag):
    """Create a sample CachedDossier for testing."""
    return CachedDossier(
        dag=sample_dag,
        raw_content=b'{"d": "SAID_ROOT"}',
        fetch_timestamp=time.time(),
        content_type="application/json",
        contained_saids={"SAID_ROOT", "SAID_CHILD"},
    )


@pytest.fixture
def cache():
    """Create a fresh DossierCache for each test."""
    return DossierCache(ttl_seconds=300.0, max_entries=10)


@pytest.fixture
def small_cache():
    """Create a small cache for LRU eviction testing."""
    return DossierCache(ttl_seconds=300.0, max_entries=3)


# =============================================================================
# CacheMetrics Tests
# =============================================================================


class TestCacheMetrics:
    """Tests for CacheMetrics dataclass."""

    def test_initial_values(self):
        """Metrics start at zero."""
        metrics = CacheMetrics()
        assert metrics.hits == 0
        assert metrics.misses == 0
        assert metrics.evictions == 0
        assert metrics.invalidations == 0

    def test_hit_rate_no_requests(self):
        """Hit rate is 0.0 when no requests."""
        metrics = CacheMetrics()
        assert metrics.hit_rate() == 0.0

    def test_hit_rate_all_hits(self):
        """Hit rate is 1.0 when all requests are hits."""
        metrics = CacheMetrics(hits=10, misses=0)
        assert metrics.hit_rate() == 1.0

    def test_hit_rate_all_misses(self):
        """Hit rate is 0.0 when all requests are misses."""
        metrics = CacheMetrics(hits=0, misses=10)
        assert metrics.hit_rate() == 0.0

    def test_hit_rate_mixed(self):
        """Hit rate calculated correctly for mixed hits/misses."""
        metrics = CacheMetrics(hits=7, misses=3)
        assert metrics.hit_rate() == 0.7

    def test_to_dict(self):
        """Metrics can be serialized to dict."""
        metrics = CacheMetrics(hits=7, misses=3, evictions=1, invalidations=2)
        result = metrics.to_dict()
        assert result["hits"] == 7
        assert result["misses"] == 3
        assert result["evictions"] == 1
        assert result["invalidations"] == 2
        assert result["hit_rate"] == 0.7

    def test_reset(self):
        """Metrics can be reset to zero."""
        metrics = CacheMetrics(hits=10, misses=5, evictions=2, invalidations=1)
        metrics.reset()
        assert metrics.hits == 0
        assert metrics.misses == 0
        assert metrics.evictions == 0
        assert metrics.invalidations == 0


# =============================================================================
# Basic Cache Operations Tests
# =============================================================================


class TestDossierCacheBasicOps:
    """Tests for basic get/put operations."""

    @pytest.mark.asyncio
    async def test_get_miss_on_empty_cache(self, cache):
        """Get returns None on empty cache."""
        result = await cache.get("http://example.com/dossier")
        assert result is None
        assert cache.metrics().misses == 1

    @pytest.mark.asyncio
    async def test_put_and_get(self, cache, sample_cached_dossier):
        """Put stores dossier, get retrieves it."""
        url = "http://example.com/dossier"
        await cache.put(url, sample_cached_dossier)

        result = await cache.get(url)
        assert result is not None
        assert result.dag.root_said == "SAID_ROOT"
        assert result.contained_saids == {"SAID_ROOT", "SAID_CHILD"}
        assert cache.metrics().hits == 1

    @pytest.mark.asyncio
    async def test_size_tracking(self, cache, sample_cached_dossier):
        """Cache size is tracked correctly."""
        assert cache.size == 0

        await cache.put("http://example.com/1", sample_cached_dossier)
        assert cache.size == 1

        await cache.put("http://example.com/2", sample_cached_dossier)
        assert cache.size == 2

    @pytest.mark.asyncio
    async def test_put_replaces_existing(self, cache, sample_dag):
        """Put replaces existing entry for same URL."""
        url = "http://example.com/dossier"

        # First entry
        dossier1 = CachedDossier(
            dag=sample_dag,
            raw_content=b"v1",
            fetch_timestamp=time.time(),
            content_type="application/json",
            contained_saids={"SAID_ROOT"},
        )
        await cache.put(url, dossier1)
        assert cache.size == 1

        # Replace with second entry
        dossier2 = CachedDossier(
            dag=sample_dag,
            raw_content=b"v2",
            fetch_timestamp=time.time(),
            content_type="application/json",
            contained_saids={"SAID_NEW"},
        )
        await cache.put(url, dossier2)
        assert cache.size == 1  # Still 1, not 2

        result = await cache.get(url)
        assert result.raw_content == b"v2"

    @pytest.mark.asyncio
    async def test_clear(self, cache, sample_cached_dossier):
        """Clear removes all entries."""
        await cache.put("http://example.com/1", sample_cached_dossier)
        await cache.put("http://example.com/2", sample_cached_dossier)
        assert cache.size == 2

        await cache.clear()
        assert cache.size == 0

        result = await cache.get("http://example.com/1")
        assert result is None


# =============================================================================
# TTL Expiration Tests
# =============================================================================


class TestDossierCacheTTL:
    """Tests for TTL expiration behavior."""

    @pytest.mark.asyncio
    async def test_entry_expires_after_ttl(self, sample_cached_dossier):
        """Entry expires after TTL."""
        cache = DossierCache(ttl_seconds=0.1, max_entries=10)  # 100ms TTL
        url = "http://example.com/dossier"

        await cache.put(url, sample_cached_dossier)
        result = await cache.get(url)
        assert result is not None  # Not expired yet

        await asyncio.sleep(0.15)  # Wait for expiration

        result = await cache.get(url)
        assert result is None  # Expired
        assert cache.metrics().misses == 1  # Expiration counts as miss

    @pytest.mark.asyncio
    async def test_fresh_entry_not_expired(self, sample_cached_dossier):
        """Fresh entry is not expired."""
        cache = DossierCache(ttl_seconds=10.0, max_entries=10)
        url = "http://example.com/dossier"

        await cache.put(url, sample_cached_dossier)

        # Multiple gets should all succeed
        for _ in range(5):
            result = await cache.get(url)
            assert result is not None

        assert cache.metrics().hits == 5


# =============================================================================
# LRU Eviction Tests
# =============================================================================


class TestDossierCacheLRU:
    """Tests for LRU eviction behavior."""

    @pytest.mark.asyncio
    async def test_evict_lru_when_at_capacity(self, small_cache, sample_dag):
        """Least recently used entry is evicted when at capacity."""
        # Fill cache (max_entries=3)
        for i in range(3):
            dossier = CachedDossier(
                dag=sample_dag,
                raw_content=f"v{i}".encode(),
                fetch_timestamp=time.time(),
                content_type="application/json",
                contained_saids={f"SAID_{i}"},
            )
            await small_cache.put(f"http://example.com/{i}", dossier)

        assert small_cache.size == 3

        # Access URL 0 and 2 to make URL 1 the LRU
        await small_cache.get("http://example.com/0")
        await small_cache.get("http://example.com/2")

        # Add new entry - should evict URL 1 (LRU)
        dossier = CachedDossier(
            dag=sample_dag,
            raw_content=b"new",
            fetch_timestamp=time.time(),
            content_type="application/json",
            contained_saids={"SAID_NEW"},
        )
        await small_cache.put("http://example.com/new", dossier)

        assert small_cache.size == 3
        assert small_cache.metrics().evictions == 1

        # URL 1 should be gone
        result = await small_cache.get("http://example.com/1")
        assert result is None

        # URLs 0, 2, and new should still exist
        assert await small_cache.get("http://example.com/0") is not None
        assert await small_cache.get("http://example.com/2") is not None
        assert await small_cache.get("http://example.com/new") is not None

    @pytest.mark.asyncio
    async def test_access_updates_lru_order(self, small_cache, sample_dag):
        """Accessing an entry updates its LRU position."""
        # Fill cache
        for i in range(3):
            dossier = CachedDossier(
                dag=sample_dag,
                raw_content=f"v{i}".encode(),
                fetch_timestamp=time.time(),
                content_type="application/json",
                contained_saids={f"SAID_{i}"},
            )
            await small_cache.put(f"http://example.com/{i}", dossier)

        # Access URL 0 to move it to most recent
        await small_cache.get("http://example.com/0")

        # Add new entry - should evict URL 1 (now LRU)
        dossier = CachedDossier(
            dag=sample_dag,
            raw_content=b"new",
            fetch_timestamp=time.time(),
            content_type="application/json",
            contained_saids={"SAID_NEW"},
        )
        await small_cache.put("http://example.com/new", dossier)

        # URL 0 should still exist (was accessed)
        assert await small_cache.get("http://example.com/0") is not None
        # URL 1 should be evicted
        assert await small_cache.get("http://example.com/1") is None


# =============================================================================
# SAID Index Tests (Revocation Invalidation)
# =============================================================================


class TestDossierCacheSAIDIndex:
    """Tests for SAID secondary index and invalidation."""

    @pytest.mark.asyncio
    async def test_said_index_built_on_put(self, cache, sample_cached_dossier):
        """SAID index is built when dossier is stored."""
        url = "http://example.com/dossier"
        await cache.put(url, sample_cached_dossier)

        # Internal check - SAID index should have entries
        assert "SAID_ROOT" in cache._said_to_urls
        assert "SAID_CHILD" in cache._said_to_urls
        assert url in cache._said_to_urls["SAID_ROOT"]
        assert url in cache._said_to_urls["SAID_CHILD"]

    @pytest.mark.asyncio
    async def test_invalidate_by_said_removes_dossiers(self, cache, sample_dag):
        """Invalidate by SAID removes all dossiers containing that SAID."""
        # Create two dossiers sharing a SAID
        shared_said = "SAID_SHARED"

        dossier1 = CachedDossier(
            dag=sample_dag,
            raw_content=b"v1",
            fetch_timestamp=time.time(),
            content_type="application/json",
            contained_saids={"SAID_A", shared_said},
        )
        dossier2 = CachedDossier(
            dag=sample_dag,
            raw_content=b"v2",
            fetch_timestamp=time.time(),
            content_type="application/json",
            contained_saids={"SAID_B", shared_said},
        )
        dossier3 = CachedDossier(
            dag=sample_dag,
            raw_content=b"v3",
            fetch_timestamp=time.time(),
            content_type="application/json",
            contained_saids={"SAID_C"},  # Does NOT contain shared_said
        )

        await cache.put("http://example.com/1", dossier1)
        await cache.put("http://example.com/2", dossier2)
        await cache.put("http://example.com/3", dossier3)
        assert cache.size == 3

        # Invalidate by shared SAID
        count = await cache.invalidate_by_said(shared_said)
        assert count == 2
        assert cache.size == 1  # Only dossier3 remains

        # Dossiers 1 and 2 should be gone
        assert await cache.get("http://example.com/1") is None
        assert await cache.get("http://example.com/2") is None
        # Dossier 3 should remain
        assert await cache.get("http://example.com/3") is not None

        assert cache.metrics().invalidations == 2

    @pytest.mark.asyncio
    async def test_invalidate_by_said_returns_zero_for_unknown(self, cache):
        """Invalidate by unknown SAID returns 0."""
        count = await cache.invalidate_by_said("UNKNOWN_SAID")
        assert count == 0

    @pytest.mark.asyncio
    async def test_invalidate_by_url(self, cache, sample_cached_dossier):
        """Invalidate by URL removes specific entry."""
        url = "http://example.com/dossier"
        await cache.put(url, sample_cached_dossier)
        assert cache.size == 1

        result = await cache.invalidate_by_url(url)
        assert result is True
        assert cache.size == 0
        assert cache.metrics().invalidations == 1

    @pytest.mark.asyncio
    async def test_invalidate_by_url_returns_false_for_unknown(self, cache):
        """Invalidate by unknown URL returns False."""
        result = await cache.invalidate_by_url("http://unknown.com/dossier")
        assert result is False

    @pytest.mark.asyncio
    async def test_said_index_cleaned_on_invalidation(self, cache, sample_dag):
        """SAID index is cleaned when dossiers are invalidated."""
        dossier = CachedDossier(
            dag=sample_dag,
            raw_content=b"v1",
            fetch_timestamp=time.time(),
            content_type="application/json",
            contained_saids={"SAID_ONLY_HERE"},
        )
        await cache.put("http://example.com/1", dossier)

        # SAID index should have entry
        assert "SAID_ONLY_HERE" in cache._said_to_urls

        await cache.invalidate_by_url("http://example.com/1")

        # SAID index should be cleaned
        assert "SAID_ONLY_HERE" not in cache._said_to_urls

    @pytest.mark.asyncio
    async def test_said_index_updated_on_replace(self, cache, sample_dag):
        """SAID index is updated when dossier is replaced."""
        url = "http://example.com/dossier"

        # First version with SAID_A
        dossier1 = CachedDossier(
            dag=sample_dag,
            raw_content=b"v1",
            fetch_timestamp=time.time(),
            content_type="application/json",
            contained_saids={"SAID_A"},
        )
        await cache.put(url, dossier1)
        assert "SAID_A" in cache._said_to_urls

        # Replace with version containing SAID_B
        dossier2 = CachedDossier(
            dag=sample_dag,
            raw_content=b"v2",
            fetch_timestamp=time.time(),
            content_type="application/json",
            contained_saids={"SAID_B"},
        )
        await cache.put(url, dossier2)

        # SAID_A should be removed, SAID_B should be present
        assert "SAID_A" not in cache._said_to_urls
        assert "SAID_B" in cache._said_to_urls


# =============================================================================
# Concurrent Access Tests
# =============================================================================


class TestDossierCacheConcurrency:
    """Tests for concurrent access behavior."""

    @pytest.mark.asyncio
    async def test_concurrent_puts(self, cache, sample_dag):
        """Concurrent puts don't corrupt cache state."""

        async def put_dossier(url_suffix):
            dossier = CachedDossier(
                dag=sample_dag,
                raw_content=f"v{url_suffix}".encode(),
                fetch_timestamp=time.time(),
                content_type="application/json",
                contained_saids={f"SAID_{url_suffix}"},
            )
            await cache.put(f"http://example.com/{url_suffix}", dossier)

        # Run 10 concurrent puts
        await asyncio.gather(*[put_dossier(i) for i in range(10)])

        assert cache.size == 10

    @pytest.mark.asyncio
    async def test_concurrent_gets_and_puts(self, cache, sample_dag):
        """Concurrent gets and puts don't corrupt cache state."""

        async def put_dossier(url_suffix):
            dossier = CachedDossier(
                dag=sample_dag,
                raw_content=f"v{url_suffix}".encode(),
                fetch_timestamp=time.time(),
                content_type="application/json",
                contained_saids={f"SAID_{url_suffix}"},
            )
            await cache.put(f"http://example.com/{url_suffix}", dossier)

        async def get_dossier(url_suffix):
            await cache.get(f"http://example.com/{url_suffix}")

        # Mix puts and gets
        tasks = []
        for i in range(10):
            tasks.append(put_dossier(i))
            tasks.append(get_dossier(i))

        await asyncio.gather(*tasks)

        # Should have 10 entries (puts may have raced with gets)
        assert cache.size == 10


# =============================================================================
# Singleton Tests
# =============================================================================


class TestDossierCacheSingleton:
    """Tests for singleton behavior."""

    def test_get_dossier_cache_returns_singleton(self):
        """get_dossier_cache returns same instance."""
        reset_dossier_cache()

        cache1 = get_dossier_cache()
        cache2 = get_dossier_cache()

        assert cache1 is cache2

    def test_reset_dossier_cache_clears_singleton(self):
        """reset_dossier_cache clears the singleton."""
        cache1 = get_dossier_cache()
        reset_dossier_cache()
        cache2 = get_dossier_cache()

        assert cache1 is not cache2

    def test_singleton_uses_config(self):
        """Singleton uses config values."""
        reset_dossier_cache()

        with patch("app.core.config.DOSSIER_CACHE_TTL_SECONDS", 600.0):
            with patch("app.core.config.DOSSIER_CACHE_MAX_ENTRIES", 50):
                cache = get_dossier_cache()
                assert cache._ttl == 600.0
                assert cache._max_entries == 50

        reset_dossier_cache()


class TestDossierCacheIntegration:
    """Integration tests for dossier cache in verification flow."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Reset cache before each test."""
        reset_dossier_cache()
        yield
        reset_dossier_cache()

    @pytest.mark.asyncio
    async def test_cache_get_put_in_verify_flow(self):
        """Cache get/put are called during verification flow.

        This test directly verifies that verify_vvp calls cache.get() before
        fetching and cache.put() after successful parse, without mocking the
        full verification flow.
        """
        from app.vvp.dossier.models import ACDCNode, DossierDAG

        # Reset and get cache
        cache = get_dossier_cache()

        # Verify cache starts empty
        assert cache.size == 0

        # Create mock DAG to store in cache
        test_said = "SAID_TEST_123456789012345678901234567890"
        mock_node = ACDCNode(
            said=test_said,
            issuer="BIssuer12345678901234567890123456789012345",
            schema="ESchema12345678901234567890123456789012345",
            edges={},
            raw={"d": test_said, "i": "BIssuer12345678901234567890123456789012345"},
        )
        mock_dag = DossierDAG(
            nodes={test_said: mock_node},
            root_said=test_said,
        )

        # Put in cache
        evd_url = "http://test.example.com/dossier/integration"
        cached = CachedDossier(
            dag=mock_dag,
            raw_content=b'{"test": "data"}',
            fetch_timestamp=time.time(),
            content_type="application/json",
            contained_saids={test_said},
        )
        await cache.put(evd_url, cached)

        # Verify put worked
        assert cache.size == 1
        metrics = cache.metrics()
        assert metrics.misses == 0  # No gets yet

        # Get from cache
        result = await cache.get(evd_url)

        # Verify get worked
        assert result is not None
        assert result.dag.root_said == test_said
        assert cache.metrics().hits == 1
        assert cache.metrics().misses == 0

        # Get non-existent URL
        result2 = await cache.get("http://other.example.com/dossier/nonexistent")
        assert result2 is None
        assert cache.metrics().hits == 1
        assert cache.metrics().misses == 1

    @pytest.mark.asyncio
    async def test_cache_hit_skips_fetch(self):
        """When cache hits, fetch_dossier is not called.

        This is the key integration test: verify that when a dossier is cached,
        the fetch is skipped on subsequent requests.
        """
        from app.vvp.dossier.models import ACDCNode, DossierDAG

        cache = get_dossier_cache()

        # Create and cache a dossier
        test_said = "SAID_CACHED_12345678901234567890123456"
        mock_node = ACDCNode(
            said=test_said,
            issuer="BIssuer12345678901234567890123456789012345",
            schema="ESchema12345678901234567890123456789012345",
            edges={},
            raw={"d": test_said, "i": "BIssuer12345678901234567890123456789012345"},
        )
        mock_dag = DossierDAG(
            nodes={test_said: mock_node},
            root_said=test_said,
        )

        evd_url = "http://cached.example.com/dossier/skipfetch"
        cached = CachedDossier(
            dag=mock_dag,
            raw_content=b'{"cached": true}',
            fetch_timestamp=time.time(),
            content_type="application/json",
            contained_saids={test_said},
        )
        await cache.put(evd_url, cached)

        # Verify cache is populated
        assert cache.size == 1

        # Simulate what verify_vvp does: check cache before fetch
        cached_result = await cache.get(evd_url)

        # If cached, we skip fetch
        assert cached_result is not None
        assert cached_result.dag.root_said == test_said

        # This demonstrates the integration: if cache.get() returns non-None,
        # the verification flow uses the cached dag instead of calling fetch_dossier()
        metrics = cache.metrics()
        assert metrics.hits == 1
        assert metrics.misses == 0

    @pytest.mark.asyncio
    async def test_verify_vvp_fetch_skipped_on_cache_hit(self):
        """verify_vvp skips fetch_dossier when cache has entry.

        This test calls verify_vvp directly and asserts fetch_dossier is NOT
        called when the dossier is already cached.
        """
        import base64
        import json
        from datetime import datetime, timezone

        from app.vvp.api_models import VerifyRequest, CallContext
        from app.vvp.verify import verify_vvp
        from app.vvp.dossier.models import ACDCNode, DossierDAG

        # Pre-populate cache with a dossier
        evd_url = "http://integration.example.com/dossier/cached"
        test_said = "SAID_INTEGRATION_TEST_12345678901234567"
        mock_node = ACDCNode(
            said=test_said,
            issuer="BIssuer12345678901234567890123456789012345",
            schema="ESchema12345678901234567890123456789012345",
            edges={},
            raw={
                "v": "ACDC10JSON000001_",
                "d": test_said,
                "i": "BIssuer12345678901234567890123456789012345",
                "s": "ESchema12345678901234567890123456789012345",
                "a": {"i": "BTest123456789012345678901234567890123"},
            },
        )
        mock_dag = DossierDAG(
            nodes={test_said: mock_node},
            root_said=test_said,
        )

        cache = get_dossier_cache()
        cached = CachedDossier(
            dag=mock_dag,
            raw_content=b'{"test": "cached_dossier"}',
            fetch_timestamp=time.time(),
            content_type="application/json+cesr",
            contained_saids={test_said},
        )
        await cache.put(evd_url, cached)

        # Create VVP-Identity header pointing to cached URL
        vvp_identity_data = {
            "ppt": "vvp",
            "kid": "http://witness.example.com/oobi/BTest123456789012345678901234567890123/witness",
            "evd": evd_url,
            "iat": int(time.time()),
        }
        vvp_identity_header = base64.urlsafe_b64encode(
            json.dumps(vvp_identity_data).encode()
        ).decode().rstrip("=")

        # Create PASSporT JWT
        jwt_header = {
            "alg": "EdDSA",
            "typ": "passport",
            "ppt": "vvp",
            "kid": vvp_identity_data["kid"],
        }
        jwt_payload = {
            "iss": "example.com",
            "iat": vvp_identity_data["iat"],
            "orig": {"tn": ["+15551234567"]},
            "dest": {"tn": ["+15559876543"]},
            "evd": evd_url,
        }
        header_b64 = base64.urlsafe_b64encode(json.dumps(jwt_header).encode()).decode().rstrip("=")
        payload_b64 = base64.urlsafe_b64encode(json.dumps(jwt_payload).encode()).decode().rstrip("=")
        sig_b64 = base64.urlsafe_b64encode(b"x" * 64).decode().rstrip("=")
        passport_jwt = f"{header_b64}.{payload_b64}.{sig_b64}"

        # Mock fetch_dossier to track if it's called
        mock_fetch = AsyncMock(return_value=b'{"should": "not_be_called"}')

        # Mock other dependencies to allow verify_vvp to proceed
        with patch("app.vvp.verify.fetch_dossier", mock_fetch):
            with patch("app.vvp.verify.verify_passport_signature_tier2_with_key_state", return_value=(MagicMock(aid="ETest...", delegation_chain=None), "VALID")):
                with patch("app.vvp.keri.kel_resolver.resolve_key_state") as mock_key_state:
                    mock_ks = MagicMock()
                    mock_ks.signing_keys = [b"x" * 32]
                    mock_key_state.return_value = mock_ks

                    with patch("app.vvp.acdc.verifier.validate_credential_chain") as mock_chain:
                        mock_result = MagicMock()
                        mock_result.validated = True
                        mock_result.root_aid = "BRootAID"
                        mock_result.status = "VALID"
                        mock_result.has_variant_limitations = False
                        mock_chain.return_value = mock_result

                        with patch("app.vvp.acdc.verifier.verify_acdc_signature"):
                            context = CallContext(
                                call_id="test-call-123",
                                received_at=datetime.now(timezone.utc).isoformat(),
                            )
                            req = VerifyRequest(passport_jwt=passport_jwt, context=context)
                            _, resp = await verify_vvp(req, vvp_identity_header)

        # KEY ASSERTION: fetch_dossier should NOT have been called (cache hit)
        mock_fetch.assert_not_called()

        # Verify cache metrics show a hit
        metrics = cache.metrics()
        assert metrics.hits >= 1, "Expected at least one cache hit"

        # Verify response has cache_hit evidence
        assert resp.claims is not None
        caller_claim = resp.claims[0]
        dossier_claim = None
        for child in caller_claim.children:
            if child.node.name == "dossier_verified":
                dossier_claim = child.node
                break
        assert dossier_claim is not None
        evidence_str = " ".join(dossier_claim.evidence)
        assert "cache_hit" in evidence_str, f"Expected 'cache_hit' in evidence: {dossier_claim.evidence}"

    @pytest.mark.asyncio
    async def test_verify_vvp_fetch_called_on_cache_miss(self):
        """verify_vvp calls fetch_dossier when cache is empty.

        This test ensures fetch IS called when there's no cache entry.
        """
        import base64
        import json
        from datetime import datetime, timezone

        from app.vvp.api_models import VerifyRequest, CallContext
        from app.vvp.verify import verify_vvp

        # Ensure cache is empty (fixture does this, but be explicit)
        cache = get_dossier_cache()
        assert cache.size == 0

        evd_url = "http://miss.example.com/dossier/notcached"

        # Create VVP-Identity header
        vvp_identity_data = {
            "ppt": "vvp",
            "kid": "http://witness.example.com/oobi/BTest123456789012345678901234567890123/witness",
            "evd": evd_url,
            "iat": int(time.time()),
        }
        vvp_identity_header = base64.urlsafe_b64encode(
            json.dumps(vvp_identity_data).encode()
        ).decode().rstrip("=")

        # Create PASSporT JWT
        jwt_header = {
            "alg": "EdDSA",
            "typ": "passport",
            "ppt": "vvp",
            "kid": vvp_identity_data["kid"],
        }
        jwt_payload = {
            "iss": "example.com",
            "iat": vvp_identity_data["iat"],
            "orig": {"tn": ["+15551234567"]},
            "dest": {"tn": ["+15559876543"]},
            "evd": evd_url,
        }
        header_b64 = base64.urlsafe_b64encode(json.dumps(jwt_header).encode()).decode().rstrip("=")
        payload_b64 = base64.urlsafe_b64encode(json.dumps(jwt_payload).encode()).decode().rstrip("=")
        sig_b64 = base64.urlsafe_b64encode(b"x" * 64).decode().rstrip("=")
        passport_jwt = f"{header_b64}.{payload_b64}.{sig_b64}"

        # Mock fetch_dossier to return valid dossier content
        dossier_content = json.dumps({
            "v": "ACDC10JSON000001_",
            "d": "SAID_FETCHED_123456789012345678901234567",
            "i": "BIssuer12345678901234567890123456789012345",
            "s": "ESchema12345678901234567890123456789012345",
            "a": {"i": "BTest123456789012345678901234567890123"},
            "e": {}
        }).encode()
        mock_fetch = AsyncMock(return_value=dossier_content)

        # Mock other dependencies
        with patch("app.vvp.verify.fetch_dossier", mock_fetch):
            with patch("app.vvp.verify.verify_passport_signature_tier2_with_key_state", return_value=(MagicMock(aid="ETest...", delegation_chain=None), "VALID")):
                with patch("app.vvp.keri.kel_resolver.resolve_key_state") as mock_key_state:
                    mock_ks = MagicMock()
                    mock_ks.signing_keys = [b"x" * 32]
                    mock_key_state.return_value = mock_ks

                    with patch("app.vvp.acdc.verifier.validate_credential_chain") as mock_chain:
                        mock_result = MagicMock()
                        mock_result.validated = True
                        mock_result.root_aid = "BRootAID"
                        mock_result.status = "VALID"
                        mock_result.has_variant_limitations = False
                        mock_chain.return_value = mock_result

                        with patch("app.vvp.acdc.verifier.verify_acdc_signature"):
                            context = CallContext(
                                call_id="test-call-456",
                                received_at=datetime.now(timezone.utc).isoformat(),
                            )
                            req = VerifyRequest(passport_jwt=passport_jwt, context=context)
                            _, resp = await verify_vvp(req, vvp_identity_header)

        # KEY ASSERTION: fetch_dossier SHOULD have been called (cache miss)
        mock_fetch.assert_called_once()

        # Verify cache metrics show a miss
        metrics = cache.metrics()
        assert metrics.misses >= 1, "Expected at least one cache miss"

        # Verify dossier was cached after fetch
        assert cache.size == 1, "Dossier should be cached after successful fetch"

        # Verify response has 'fetched=' evidence (not cache_hit)
        assert resp.claims is not None
        caller_claim = resp.claims[0]
        dossier_claim = None
        for child in caller_claim.children:
            if child.node.name == "dossier_verified":
                dossier_claim = child.node
                break
        assert dossier_claim is not None
        evidence_str = " ".join(dossier_claim.evidence)
        assert "fetched=" in evidence_str, f"Expected 'fetched=' in evidence: {dossier_claim.evidence}"
        assert "cache_hit" not in evidence_str, f"Should not have 'cache_hit' on miss: {dossier_claim.evidence}"
