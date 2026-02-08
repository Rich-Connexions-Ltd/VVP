"""
Verification Result Cache — Sprint 51.

Caches dossier-derived verification artifacts (chain validation, ACDC signatures,
revocation status) keyed by (dossier_url, passport_kid). On cache hit, expensive
Phases 5, 5.5, and 9 are skipped while per-request phases always re-evaluate.

Only VALID chain results are cached. INVALID and INDETERMINATE results are not
cached to avoid sticky failures from transient conditions.
"""

import copy
import hashlib
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

import asyncio

from app.vvp.api_models import ClaimNode, ClaimStatus, ErrorDetail

log = logging.getLogger("vvp.verification_cache")

# Bump when cached data format or verification logic changes
CACHE_VERSION = 1


# =============================================================================
# RevocationStatus Enum
# =============================================================================

class RevocationStatus(Enum):
    """Three-state revocation status for each credential in a cached result."""
    UNDEFINED = "UNDEFINED"
    UNREVOKED = "UNREVOKED"
    REVOKED = "REVOKED"


# =============================================================================
# CachedDossierVerification
# =============================================================================

@dataclass
class CachedDossierVerification:
    """Stores immutable dossier-derived verification artifacts.

    Cache key: (dossier_url, passport_kid)
    """
    # Compound key parts
    dossier_url: str
    passport_kid: str

    # Dossier artifacts
    dag: object  # DossierDAG — returned by reference (read-only)
    raw_dossier: bytes  # Immutable bytes
    dossier_acdcs: Dict  # Dict[str, ACDC] — deep-copied on read
    chain_claim: ClaimNode  # Immutable chain_verified claim — deep-copied on read
    chain_errors: List[ErrorDetail]  # Chain errors — deep-copied on read
    acdc_signatures_verified: bool
    has_variant_limitations: bool
    dossier_claim_evidence: List[str]  # Evidence strings — deep-copied on read
    contained_saids: FrozenSet[str]  # Immutable

    # Revocation state
    credential_revocation_status: Dict[str, RevocationStatus]  # deep-copied on read
    revocation_last_checked: Optional[float] = None

    # Cache metadata
    created_at: float = field(default_factory=time.time)
    cache_version: int = CACHE_VERSION
    config_fingerprint: str = ""


# =============================================================================
# Config Fingerprint
# =============================================================================

def compute_config_fingerprint() -> str:
    """Compute a deterministic hash of all validation-affecting config values.

    Included configs:
    - TRUSTED_ROOT_AIDS
    - OPERATOR_VIOLATION_SEVERITY
    - EXTERNAL_SAID_RESOLUTION_ENABLED
    - SCHEMA_VALIDATION_STRICT
    - TIER2_KEL_RESOLUTION_ENABLED
    - EXTERNAL_SAID_MAX_DEPTH
    """
    from app.core.config import (
        TRUSTED_ROOT_AIDS,
        VVP_OPERATOR_VIOLATION_SEVERITY,
        EXTERNAL_SAID_RESOLUTION_ENABLED,
        SCHEMA_VALIDATION_STRICT,
        TIER2_KEL_RESOLUTION_ENABLED,
        EXTERNAL_SAID_MAX_DEPTH,
    )

    parts = [
        f"roots={','.join(sorted(TRUSTED_ROOT_AIDS))}",
        f"operator_severity={VVP_OPERATOR_VIOLATION_SEVERITY}",
        f"external_said={EXTERNAL_SAID_RESOLUTION_ENABLED}",
        f"schema_strict={SCHEMA_VALIDATION_STRICT}",
        f"tier2_kel={TIER2_KEL_RESOLUTION_ENABLED}",
        f"said_max_depth={EXTERNAL_SAID_MAX_DEPTH}",
    ]
    fingerprint_str = "|".join(parts)
    return hashlib.sha256(fingerprint_str.encode()).hexdigest()[:16]


# =============================================================================
# Cache Metrics
# =============================================================================

@dataclass
class VerificationCacheMetrics:
    hits: int = 0
    misses: int = 0
    evictions: int = 0
    version_mismatches: int = 0
    config_mismatches: int = 0
    revocation_checks: int = 0
    revocations_found: int = 0

    def to_dict(self) -> dict:
        return {
            "hits": self.hits,
            "misses": self.misses,
            "evictions": self.evictions,
            "version_mismatches": self.version_mismatches,
            "config_mismatches": self.config_mismatches,
            "revocation_checks": self.revocation_checks,
            "revocations_found": self.revocations_found,
        }


# =============================================================================
# VerificationResultCache
# =============================================================================

# Type alias for compound key
CacheKey = Tuple[str, str]  # (dossier_url, passport_kid)


class VerificationResultCache:
    """In-memory LRU cache of dossier-derived verification artifacts.

    Keyed by (dossier_url, passport_kid). Deep-copies mutable fields on read
    to prevent cross-request mutation. Checks cache_version and config_fingerprint
    on read to handle code upgrades and config changes.
    """

    def __init__(self, max_entries: int = 200, ttl_seconds: float = 3600.0):
        self._max_entries = max_entries
        self._ttl_seconds = ttl_seconds
        self._cache: Dict[CacheKey, CachedDossierVerification] = {}
        self._access_order: List[CacheKey] = []  # LRU tracking
        self._lock = asyncio.Lock()
        self._metrics = VerificationCacheMetrics()

    async def get(
        self, dossier_url: str, passport_kid: str
    ) -> Optional[CachedDossierVerification]:
        """Retrieve cached verification result. Returns deep-copied mutable fields."""
        key: CacheKey = (dossier_url, passport_kid)

        async with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                self._metrics.misses += 1
                return None

            # Version check
            if entry.cache_version != CACHE_VERSION:
                log.info(
                    f"Cache version mismatch for {dossier_url[:50]}... "
                    f"(cached={entry.cache_version}, current={CACHE_VERSION})"
                )
                self._metrics.version_mismatches += 1
                self._evict_locked(key)
                self._metrics.misses += 1
                return None

            # Config fingerprint check
            current_fp = compute_config_fingerprint()
            if entry.config_fingerprint != current_fp:
                log.info(
                    f"Config fingerprint mismatch for {dossier_url[:50]}... "
                    f"(cached={entry.config_fingerprint}, current={current_fp})"
                )
                self._metrics.config_mismatches += 1
                self._evict_locked(key)
                self._metrics.misses += 1
                return None

            # TTL check
            age = time.time() - entry.created_at
            if age > self._ttl_seconds:
                log.debug(f"Cache TTL expired for {dossier_url[:50]}... (age={age:.0f}s)")
                self._evict_locked(key)
                self._metrics.misses += 1
                return None

            # Cache hit — deep-copy mutable fields
            self._metrics.hits += 1
            self._touch_locked(key)

            # Create a shallow copy of the entry, then deep-copy mutable fields
            result = CachedDossierVerification(
                dossier_url=entry.dossier_url,
                passport_kid=entry.passport_kid,
                # Returned by reference (immutable or read-only)
                dag=entry.dag,
                raw_dossier=entry.raw_dossier,
                contained_saids=entry.contained_saids,
                # Deep-copied mutable fields
                chain_claim=copy.deepcopy(entry.chain_claim),
                chain_errors=copy.deepcopy(entry.chain_errors),
                dossier_acdcs=copy.deepcopy(entry.dossier_acdcs),
                credential_revocation_status=copy.deepcopy(entry.credential_revocation_status),
                dossier_claim_evidence=copy.deepcopy(entry.dossier_claim_evidence),
                # Scalar/immutable fields
                acdc_signatures_verified=entry.acdc_signatures_verified,
                has_variant_limitations=entry.has_variant_limitations,
                revocation_last_checked=entry.revocation_last_checked,
                created_at=entry.created_at,
                cache_version=entry.cache_version,
                config_fingerprint=entry.config_fingerprint,
            )
            return result

    async def put(self, result: CachedDossierVerification) -> None:
        """Store verification result. Key derived from result fields."""
        key: CacheKey = (result.dossier_url, result.passport_kid)

        # Set config fingerprint at put time
        result.config_fingerprint = compute_config_fingerprint()
        result.cache_version = CACHE_VERSION

        async with self._lock:
            # Evict LRU if at capacity
            while len(self._cache) >= self._max_entries and key not in self._cache:
                self._evict_lru_locked()

            self._cache[key] = result
            self._touch_locked(key)
            log.debug(
                f"Cached verification result for {result.dossier_url[:50]}... "
                f"kid={result.passport_kid[:30]}..."
            )

    async def update_revocation(
        self,
        dossier_url: str,
        passport_kid: str,
        credential_said: str,
        status: RevocationStatus,
    ) -> None:
        """Update revocation status for a specific credential in a specific entry."""
        key: CacheKey = (dossier_url, passport_kid)
        async with self._lock:
            entry = self._cache.get(key)
            if entry is not None:
                old = entry.credential_revocation_status.get(credential_said)
                entry.credential_revocation_status[credential_said] = status
                if status == RevocationStatus.REVOKED and old != RevocationStatus.REVOKED:
                    self._metrics.revocations_found += 1
                    log.warning(
                        f"Revocation detected: {credential_said} in {dossier_url[:50]}..."
                    )

    async def update_revocation_all_for_url(
        self,
        dossier_url: str,
        credential_said: str,
        status: RevocationStatus,
    ) -> None:
        """Update revocation status for a credential across ALL kid variants.

        Also atomically updates revocation_last_checked for all variants.
        """
        now = time.time()
        async with self._lock:
            for key, entry in self._cache.items():
                if key[0] == dossier_url:
                    old = entry.credential_revocation_status.get(credential_said)
                    entry.credential_revocation_status[credential_said] = status
                    entry.revocation_last_checked = now
                    if status == RevocationStatus.REVOKED and old != RevocationStatus.REVOKED:
                        self._metrics.revocations_found += 1
                        log.warning(
                            f"Revocation detected: {credential_said} in {dossier_url[:50]}... "
                            f"kid={key[1][:30]}..."
                        )

    async def update_revocation_timestamp_all_for_url(
        self, dossier_url: str
    ) -> None:
        """Update revocation_last_checked for all kid variants of a URL."""
        now = time.time()
        async with self._lock:
            for key, entry in self._cache.items():
                if key[0] == dossier_url:
                    entry.revocation_last_checked = now

    async def invalidate(self, dossier_url: str, passport_kid: str) -> None:
        """Evict a specific entry."""
        key: CacheKey = (dossier_url, passport_kid)
        async with self._lock:
            self._evict_locked(key)

    async def invalidate_all_for_url(self, dossier_url: str) -> None:
        """Evict all entries for a given dossier URL (across all kids)."""
        async with self._lock:
            keys_to_evict = [k for k in self._cache if k[0] == dossier_url]
            for key in keys_to_evict:
                self._evict_locked(key)

    def metrics(self) -> VerificationCacheMetrics:
        return self._metrics

    async def clear(self) -> None:
        """Clear entire cache."""
        async with self._lock:
            self._cache.clear()
            self._access_order.clear()

    # ---- Internal helpers (must be called with lock held) ----

    def _touch_locked(self, key: CacheKey) -> None:
        """Move key to end of access order (most recently used)."""
        if key in self._access_order:
            self._access_order.remove(key)
        self._access_order.append(key)

    def _evict_locked(self, key: CacheKey) -> None:
        """Remove a specific entry."""
        if key in self._cache:
            del self._cache[key]
            self._metrics.evictions += 1
        if key in self._access_order:
            self._access_order.remove(key)

    def _evict_lru_locked(self) -> None:
        """Evict the least recently used entry."""
        if self._access_order:
            lru_key = self._access_order[0]
            self._evict_locked(lru_key)


# =============================================================================
# Module-level singleton
# =============================================================================

_verification_cache: Optional[VerificationResultCache] = None


def get_verification_cache() -> VerificationResultCache:
    """Get the module-level verification cache singleton."""
    global _verification_cache
    if _verification_cache is None:
        from app.core.config import (
            VVP_VERIFICATION_CACHE_MAX_ENTRIES,
            VVP_VERIFICATION_CACHE_TTL,
        )
        _verification_cache = VerificationResultCache(
            max_entries=VVP_VERIFICATION_CACHE_MAX_ENTRIES,
            ttl_seconds=VVP_VERIFICATION_CACHE_TTL,
        )
    return _verification_cache


def reset_verification_cache() -> None:
    """Reset the module-level verification cache singleton (for testing)."""
    global _verification_cache
    _verification_cache = None
