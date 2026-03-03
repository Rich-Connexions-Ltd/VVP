"""Tests for VVP attestation intermediate result cache.

Sprint 76: Tests cache hit/miss, TTL expiry, LRU eviction, and
invalidation by dossier SAID and identity name.
"""

import time
from unittest.mock import patch

import pytest

from app.vvp.attestation_cache import (
    AttestationCache,
    AttestationCacheEntry,
    get_attestation_cache,
    reset_attestation_cache,
)


@pytest.fixture
def cache():
    """Create a fresh attestation cache for testing."""
    return AttestationCache(ttl=10.0, max_entries=5)


def _put_entry(cache, identity="org-test", dossier="ESAID1234", aid="EAbc123", card=None):
    """Helper to put an entry in the cache."""
    cache.put(
        identity_name=identity,
        dossier_said=dossier,
        identity_aid=aid,
        issuer_oobi=f"http://witness.example/{aid}/oobi",
        dossier_url=f"http://issuer.example/dossier/{dossier}",
        card=card,
    )


class TestAttestationCacheBasic:
    """Basic cache operations: get, put, miss, hit."""

    def test_miss_on_empty_cache(self, cache):
        result = cache.get("org-test", "ESAID1234")
        assert result is None
        assert cache.metrics.misses == 1
        assert cache.metrics.hits == 0

    def test_put_then_hit(self, cache):
        _put_entry(cache, identity="org-a", dossier="ESAID1")
        result = cache.get("org-a", "ESAID1")
        assert result is not None
        assert result.identity_aid == "EAbc123"
        assert result.issuer_oobi == "http://witness.example/EAbc123/oobi"
        assert cache.metrics.hits == 1
        assert cache.metrics.misses == 0

    def test_miss_wrong_key(self, cache):
        _put_entry(cache, identity="org-a", dossier="ESAID1")
        result = cache.get("org-a", "ESAID-different")
        assert result is None
        assert cache.metrics.misses == 1

    def test_card_stored(self, cache):
        card = [{"fn": "ACME Inc"}]
        _put_entry(cache, card=card)
        result = cache.get("org-test", "ESAID1234")
        assert result.card == [{"fn": "ACME Inc"}]

    def test_size(self, cache):
        assert cache.size() == 0
        _put_entry(cache, identity="a", dossier="1")
        assert cache.size() == 1
        _put_entry(cache, identity="b", dossier="2")
        assert cache.size() == 2

    def test_clear(self, cache):
        _put_entry(cache, identity="a", dossier="1")
        _put_entry(cache, identity="b", dossier="2")
        cache.clear()
        assert cache.size() == 0
        assert cache.get("a", "1") is None


class TestAttestationCacheTTL:
    """TTL expiration behavior."""

    def test_expired_entry_returns_none(self, cache):
        _put_entry(cache)
        # Fast-forward the entry's created_at to simulate expiry
        key = ("org-test", "ESAID1234")
        cache._cache[key].created_at = time.monotonic() - 11.0  # TTL=10s
        result = cache.get("org-test", "ESAID1234")
        assert result is None
        assert cache.metrics.misses == 1
        assert cache.size() == 0  # Expired entry removed

    def test_fresh_entry_returns_data(self, cache):
        _put_entry(cache)
        result = cache.get("org-test", "ESAID1234")
        assert result is not None
        assert cache.metrics.hits == 1


class TestAttestationCacheLRU:
    """LRU eviction when at capacity."""

    def test_eviction_at_capacity(self, cache):
        """Fill cache beyond max_entries (5), oldest should be evicted."""
        for i in range(6):
            _put_entry(cache, identity=f"org-{i}", dossier=f"SAID-{i}")

        # Cache should have exactly max_entries
        assert cache.size() == 5
        assert cache.metrics.evictions == 1

        # First entry should be evicted (org-0)
        assert cache.get("org-0", "SAID-0") is None
        # Last entry should still be there
        assert cache.get("org-5", "SAID-5") is not None

    def test_access_promotes_entry(self, cache):
        """Accessing an entry should move it to end (LRU promotion)."""
        for i in range(5):
            _put_entry(cache, identity=f"org-{i}", dossier=f"SAID-{i}")

        # Access org-0 to promote it
        cache.get("org-0", "SAID-0")

        # Now add a new entry — org-1 should be evicted (it's now the LRU)
        _put_entry(cache, identity="org-new", dossier="SAID-new")

        assert cache.get("org-0", "SAID-0") is not None  # Still here (promoted)
        assert cache.get("org-1", "SAID-1") is None  # Evicted (was LRU)


class TestAttestationCacheInvalidation:
    """Cache invalidation by dossier SAID and identity name."""

    def test_invalidate_by_dossier_said(self, cache):
        _put_entry(cache, identity="org-a", dossier="SAID-X")
        _put_entry(cache, identity="org-b", dossier="SAID-X")
        _put_entry(cache, identity="org-c", dossier="SAID-Y")

        count = cache.invalidate_by_dossier_said("SAID-X")
        assert count == 2
        assert cache.get("org-a", "SAID-X") is None
        assert cache.get("org-b", "SAID-X") is None
        assert cache.get("org-c", "SAID-Y") is not None
        assert cache.metrics.invalidations == 2

    def test_invalidate_by_identity(self, cache):
        _put_entry(cache, identity="org-a", dossier="SAID-1")
        _put_entry(cache, identity="org-a", dossier="SAID-2")
        _put_entry(cache, identity="org-b", dossier="SAID-3")

        count = cache.invalidate_by_identity("org-a")
        assert count == 2
        assert cache.get("org-a", "SAID-1") is None
        assert cache.get("org-a", "SAID-2") is None
        assert cache.get("org-b", "SAID-3") is not None

    def test_invalidate_nonexistent_said(self, cache):
        count = cache.invalidate_by_dossier_said("NONEXISTENT")
        assert count == 0

    def test_invalidate_nonexistent_identity(self, cache):
        count = cache.invalidate_by_identity("nonexistent")
        assert count == 0


class TestAttestationCacheMetrics:
    """Cache metrics tracking."""

    def test_metrics_hit_rate(self, cache):
        _put_entry(cache)
        cache.get("org-test", "ESAID1234")  # hit
        cache.get("org-test", "ESAID1234")  # hit
        cache.get("org-missing", "SAID-none")  # miss

        metrics = cache.metrics.to_dict()
        assert metrics["hits"] == 2
        assert metrics["misses"] == 1
        assert metrics["hit_rate_pct"] == pytest.approx(66.7, abs=0.1)


class TestAttestationCacheSingleton:
    """Singleton management."""

    def test_singleton_returns_same_instance(self):
        reset_attestation_cache()
        c1 = get_attestation_cache()
        c2 = get_attestation_cache()
        assert c1 is c2
        reset_attestation_cache()

    def test_reset_creates_new_instance(self):
        reset_attestation_cache()
        c1 = get_attestation_cache()
        reset_attestation_cache()
        c2 = get_attestation_cache()
        assert c1 is not c2
        reset_attestation_cache()
