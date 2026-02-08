"""Unit tests for VerificationResultCache — Sprint 51.

Tests cache get/put/eviction, compound key behavior, deep-copy safety,
config fingerprint, cache versioning, and metrics.
"""

import asyncio
import copy
import time
from typing import Dict, FrozenSet

import pytest

from app.vvp.api_models import ClaimNode, ClaimStatus, ErrorDetail
from app.vvp.verification_cache import (
    CACHE_VERSION,
    CachedDossierVerification,
    RevocationStatus,
    VerificationCacheMetrics,
    VerificationResultCache,
    compute_config_fingerprint,
)


# =============================================================================
# Helpers
# =============================================================================


def _make_entry(
    dossier_url: str = "https://example.com/dossier.cesr",
    passport_kid: str = "http://witness.example.com/oobi/EABC123/witness",
    chain_status: ClaimStatus = ClaimStatus.VALID,
    revocation: Dict[str, RevocationStatus] | None = None,
    created_at: float | None = None,
) -> CachedDossierVerification:
    """Create a test CachedDossierVerification entry."""
    return CachedDossierVerification(
        dossier_url=dossier_url,
        passport_kid=passport_kid,
        dag=object(),  # Placeholder
        raw_dossier=b"test-dossier-bytes",
        dossier_acdcs={"SAID1": object()},
        chain_claim=ClaimNode(
            name="chain_verified",
            status=chain_status,
            reasons=[],
            evidence=["chain_valid:SAID1...,root=EROOT..."],
        ),
        chain_errors=[],
        acdc_signatures_verified=True,
        has_variant_limitations=False,
        dossier_claim_evidence=["fetched=https://example.com/..."],
        contained_saids=frozenset({"SAID1", "SAID2"}),
        credential_revocation_status=revocation or {
            "SAID1": RevocationStatus.UNREVOKED,
            "SAID2": RevocationStatus.UNREVOKED,
        },
        revocation_last_checked=time.time(),
        created_at=created_at or time.time(),
        cache_version=CACHE_VERSION,
        config_fingerprint=compute_config_fingerprint(),
    )


# =============================================================================
# RevocationStatus
# =============================================================================


class TestRevocationStatus:
    def test_enum_values(self):
        assert RevocationStatus.UNDEFINED.value == "UNDEFINED"
        assert RevocationStatus.UNREVOKED.value == "UNREVOKED"
        assert RevocationStatus.REVOKED.value == "REVOKED"

    def test_enum_count(self):
        assert len(RevocationStatus) == 3


# =============================================================================
# CachedDossierVerification
# =============================================================================


class TestCachedDossierVerification:
    def test_construction(self):
        entry = _make_entry()
        assert entry.dossier_url == "https://example.com/dossier.cesr"
        assert entry.passport_kid == "http://witness.example.com/oobi/EABC123/witness"
        assert entry.acdc_signatures_verified is True
        assert entry.has_variant_limitations is False
        assert isinstance(entry.contained_saids, frozenset)

    def test_default_revocation_last_checked_is_set(self):
        entry = _make_entry()
        assert entry.revocation_last_checked is not None
        assert entry.revocation_last_checked <= time.time()


# =============================================================================
# VerificationResultCache — get/put basics
# =============================================================================


class TestCacheBasics:
    @pytest.mark.asyncio
    async def test_put_and_get(self):
        cache = VerificationResultCache(max_entries=10)
        entry = _make_entry()
        await cache.put(entry)

        result = await cache.get(entry.dossier_url, entry.passport_kid)
        assert result is not None
        assert result.dossier_url == entry.dossier_url
        assert result.passport_kid == entry.passport_kid
        assert result.chain_claim.status == ClaimStatus.VALID

    @pytest.mark.asyncio
    async def test_get_miss(self):
        cache = VerificationResultCache(max_entries=10)
        result = await cache.get("missing-url", "missing-kid")
        assert result is None

    @pytest.mark.asyncio
    async def test_metrics_hit_miss(self):
        cache = VerificationResultCache(max_entries=10)
        entry = _make_entry()
        await cache.put(entry)

        await cache.get("missing", "missing")  # miss
        await cache.get(entry.dossier_url, entry.passport_kid)  # hit

        m = cache.metrics()
        assert m.hits == 1
        assert m.misses == 1

    @pytest.mark.asyncio
    async def test_clear(self):
        cache = VerificationResultCache(max_entries=10)
        await cache.put(_make_entry())
        await cache.clear()

        result = await cache.get(
            "https://example.com/dossier.cesr",
            "http://witness.example.com/oobi/EABC123/witness",
        )
        assert result is None


# =============================================================================
# Compound Key Behavior
# =============================================================================


class TestCompoundKey:
    @pytest.mark.asyncio
    async def test_different_kid_separate_entries(self):
        """Same dossier URL with different kids → separate cache entries."""
        cache = VerificationResultCache(max_entries=10)

        entry1 = _make_entry(passport_kid="kid-A")
        entry2 = _make_entry(passport_kid="kid-B")
        await cache.put(entry1)
        await cache.put(entry2)

        r1 = await cache.get(entry1.dossier_url, "kid-A")
        r2 = await cache.get(entry1.dossier_url, "kid-B")
        assert r1 is not None
        assert r2 is not None
        assert r1.passport_kid == "kid-A"
        assert r2.passport_kid == "kid-B"

    @pytest.mark.asyncio
    async def test_same_kid_cache_hit(self):
        """Same dossier URL + same kid → cache hit."""
        cache = VerificationResultCache(max_entries=10)
        entry = _make_entry()
        await cache.put(entry)

        result = await cache.get(entry.dossier_url, entry.passport_kid)
        assert result is not None

    @pytest.mark.asyncio
    async def test_invalidate_all_for_url(self):
        """invalidate_all_for_url evicts all kid variants."""
        cache = VerificationResultCache(max_entries=10)
        url = "https://example.com/dossier.cesr"

        await cache.put(_make_entry(dossier_url=url, passport_kid="kid-A"))
        await cache.put(_make_entry(dossier_url=url, passport_kid="kid-B"))

        await cache.invalidate_all_for_url(url)

        assert await cache.get(url, "kid-A") is None
        assert await cache.get(url, "kid-B") is None


# =============================================================================
# Deep-Copy Safety
# =============================================================================


class TestDeepCopySafety:
    @pytest.mark.asyncio
    async def test_chain_claim_mutation_isolation(self):
        """Mutating returned chain_claim does not affect cached entry."""
        cache = VerificationResultCache(max_entries=10)
        entry = _make_entry()
        await cache.put(entry)

        r1 = await cache.get(entry.dossier_url, entry.passport_kid)
        r1.chain_claim.status = ClaimStatus.INVALID
        r1.chain_claim.evidence.append("mutated")

        r2 = await cache.get(entry.dossier_url, entry.passport_kid)
        assert r2.chain_claim.status == ClaimStatus.VALID
        assert "mutated" not in r2.chain_claim.evidence

    @pytest.mark.asyncio
    async def test_chain_errors_mutation_isolation(self):
        """Mutating returned chain_errors does not affect cached entry."""
        cache = VerificationResultCache(max_entries=10)
        entry = _make_entry()
        entry.chain_errors = [
            ErrorDetail(code="TEST", message="test", recoverable=False)
        ]
        await cache.put(entry)

        r1 = await cache.get(entry.dossier_url, entry.passport_kid)
        r1.chain_errors.append(
            ErrorDetail(code="EXTRA", message="extra", recoverable=True)
        )

        r2 = await cache.get(entry.dossier_url, entry.passport_kid)
        assert len(r2.chain_errors) == 1

    @pytest.mark.asyncio
    async def test_revocation_status_mutation_isolation(self):
        """Mutating returned revocation status does not affect cached entry."""
        cache = VerificationResultCache(max_entries=10)
        entry = _make_entry()
        await cache.put(entry)

        r1 = await cache.get(entry.dossier_url, entry.passport_kid)
        r1.credential_revocation_status["SAID1"] = RevocationStatus.REVOKED

        r2 = await cache.get(entry.dossier_url, entry.passport_kid)
        assert r2.credential_revocation_status["SAID1"] == RevocationStatus.UNREVOKED

    @pytest.mark.asyncio
    async def test_dossier_claim_evidence_mutation_isolation(self):
        """Mutating returned dossier_claim_evidence does not affect cached entry."""
        cache = VerificationResultCache(max_entries=10)
        entry = _make_entry()
        await cache.put(entry)

        r1 = await cache.get(entry.dossier_url, entry.passport_kid)
        r1.dossier_claim_evidence.append("cache_hit:extra")

        r2 = await cache.get(entry.dossier_url, entry.passport_kid)
        assert "cache_hit:extra" not in r2.dossier_claim_evidence

    @pytest.mark.asyncio
    async def test_concurrent_gets_return_independent_objects(self):
        """Two concurrent get() calls return independent deep copies."""
        cache = VerificationResultCache(max_entries=10)
        entry = _make_entry()
        await cache.put(entry)

        r1, r2 = await asyncio.gather(
            cache.get(entry.dossier_url, entry.passport_kid),
            cache.get(entry.dossier_url, entry.passport_kid),
        )
        assert r1 is not r2
        assert r1.chain_claim is not r2.chain_claim


# =============================================================================
# TTL and Eviction
# =============================================================================


class TestTTLAndEviction:
    @pytest.mark.asyncio
    async def test_ttl_expired_entry_is_miss(self):
        """Entry past TTL is evicted on get()."""
        cache = VerificationResultCache(max_entries=10, ttl_seconds=1.0)
        entry = _make_entry(created_at=time.time() - 10.0)
        await cache.put(entry)

        result = await cache.get(entry.dossier_url, entry.passport_kid)
        assert result is None
        assert cache.metrics().misses == 1

    @pytest.mark.asyncio
    async def test_lru_eviction(self):
        """LRU eviction when at capacity."""
        cache = VerificationResultCache(max_entries=2)

        e1 = _make_entry(passport_kid="kid-1")
        e2 = _make_entry(passport_kid="kid-2")
        e3 = _make_entry(passport_kid="kid-3")

        await cache.put(e1)
        await cache.put(e2)
        await cache.put(e3)  # Should evict e1 (LRU)

        assert await cache.get(e1.dossier_url, "kid-1") is None
        assert await cache.get(e2.dossier_url, "kid-2") is not None
        assert await cache.get(e3.dossier_url, "kid-3") is not None


# =============================================================================
# Cache Version and Config Fingerprint
# =============================================================================


class TestCacheVersioning:
    @pytest.mark.asyncio
    async def test_version_mismatch_is_miss(self):
        """Entry with old cache_version is treated as miss."""
        cache = VerificationResultCache(max_entries=10)
        entry = _make_entry()
        entry.cache_version = 0  # Old version
        # Manually insert to bypass put()'s version setting
        key = (entry.dossier_url, entry.passport_kid)
        async with cache._lock:
            cache._cache[key] = entry
            cache._access_order.append(key)

        result = await cache.get(entry.dossier_url, entry.passport_kid)
        assert result is None
        assert cache.metrics().version_mismatches == 1

    @pytest.mark.asyncio
    async def test_config_fingerprint_mismatch_is_miss(self):
        """Entry with stale config fingerprint is treated as miss."""
        cache = VerificationResultCache(max_entries=10)
        entry = _make_entry()
        entry.config_fingerprint = "stale-fingerprint"
        key = (entry.dossier_url, entry.passport_kid)
        async with cache._lock:
            cache._cache[key] = entry
            cache._access_order.append(key)

        result = await cache.get(entry.dossier_url, entry.passport_kid)
        assert result is None
        assert cache.metrics().config_mismatches == 1


# =============================================================================
# Revocation Update Methods
# =============================================================================


class TestRevocationUpdates:
    @pytest.mark.asyncio
    async def test_update_revocation_single_entry(self):
        """update_revocation updates a specific (url, kid) entry."""
        cache = VerificationResultCache(max_entries=10)
        entry = _make_entry()
        await cache.put(entry)

        await cache.update_revocation(
            entry.dossier_url, entry.passport_kid, "SAID1", RevocationStatus.REVOKED
        )

        # Read directly from internal cache (update_revocation modifies in place)
        key = (entry.dossier_url, entry.passport_kid)
        async with cache._lock:
            stored = cache._cache[key]
            assert stored.credential_revocation_status["SAID1"] == RevocationStatus.REVOKED

    @pytest.mark.asyncio
    async def test_update_revocation_all_for_url(self):
        """update_revocation_all_for_url updates all kid variants atomically."""
        cache = VerificationResultCache(max_entries=10)
        url = "https://example.com/dossier.cesr"

        e1 = _make_entry(dossier_url=url, passport_kid="kid-A")
        e2 = _make_entry(dossier_url=url, passport_kid="kid-B")
        await cache.put(e1)
        await cache.put(e2)

        before = time.time()
        await cache.update_revocation_all_for_url(url, "SAID1", RevocationStatus.REVOKED)

        # Both entries should be updated
        async with cache._lock:
            for key, stored in cache._cache.items():
                assert stored.credential_revocation_status["SAID1"] == RevocationStatus.REVOKED
                assert stored.revocation_last_checked >= before

    @pytest.mark.asyncio
    async def test_update_revocation_timestamp_all_for_url(self):
        """update_revocation_timestamp_all_for_url updates timestamps."""
        cache = VerificationResultCache(max_entries=10)
        url = "https://example.com/dossier.cesr"

        e1 = _make_entry(dossier_url=url, passport_kid="kid-A")
        e1.revocation_last_checked = 0  # Very old
        await cache.put(e1)

        before = time.time()
        await cache.update_revocation_timestamp_all_for_url(url)

        async with cache._lock:
            stored = cache._cache[(url, "kid-A")]
            assert stored.revocation_last_checked >= before

    @pytest.mark.asyncio
    async def test_revocation_found_metric(self):
        """Revocation detection increments revocations_found metric."""
        cache = VerificationResultCache(max_entries=10)
        entry = _make_entry()
        await cache.put(entry)

        await cache.update_revocation(
            entry.dossier_url, entry.passport_kid, "SAID1", RevocationStatus.REVOKED
        )
        assert cache.metrics().revocations_found == 1

        # Duplicate revocation for same SAID should not increment
        await cache.update_revocation(
            entry.dossier_url, entry.passport_kid, "SAID1", RevocationStatus.REVOKED
        )
        assert cache.metrics().revocations_found == 1


# =============================================================================
# Config Fingerprint
# =============================================================================


class TestConfigFingerprint:
    def test_fingerprint_is_deterministic(self):
        """Same config → same fingerprint."""
        fp1 = compute_config_fingerprint()
        fp2 = compute_config_fingerprint()
        assert fp1 == fp2

    def test_fingerprint_is_string(self):
        fp = compute_config_fingerprint()
        assert isinstance(fp, str)
        assert len(fp) == 16  # SHA256 truncated to 16 hex chars


# =============================================================================
# Metrics
# =============================================================================


class TestMetrics:
    def test_metrics_to_dict(self):
        m = VerificationCacheMetrics()
        d = m.to_dict()
        assert "hits" in d
        assert "misses" in d
        assert "evictions" in d
        assert "version_mismatches" in d
        assert "config_mismatches" in d
        assert "revocation_checks" in d
        assert "revocations_found" in d
