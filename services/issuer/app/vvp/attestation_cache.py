"""VVP attestation intermediate result cache.

Sprint 76: Caches identity/brand/URL data that is identical across calls
for the same (identity_name, dossier_said) pair. Only the PASSporT signing
call remains uncached (unique per call due to iat/call_id/cseq).

Invalidation triggers:
1. DossierCache revocation callback → invalidate_by_dossier_said()
2. Admin API / identity change → invalidate_by_identity()
3. TTL expiry (300s hard ceiling)
"""

import logging
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Optional, Tuple

log = logging.getLogger(__name__)

# Default TTL matches dossier cache and spec §5C.2
DEFAULT_TTL_SECONDS = 300.0
DEFAULT_MAX_ENTRIES = 100


@dataclass
class AttestationCacheEntry:
    """Cached intermediate results for VVP attestation."""

    identity_aid: str
    issuer_oobi: str
    dossier_url: str
    card: Optional[Any]  # vCard claim dict or None
    created_at: float

    def is_expired(self, ttl: float) -> bool:
        return (time.monotonic() - self.created_at) > ttl


@dataclass
class AttestationCacheMetrics:
    """Cache performance metrics."""

    hits: int = 0
    misses: int = 0
    evictions: int = 0
    invalidations: int = 0

    def to_dict(self) -> dict:
        total = self.hits + self.misses
        hit_rate = (self.hits / total * 100) if total > 0 else 0.0
        return {
            "hits": self.hits,
            "misses": self.misses,
            "evictions": self.evictions,
            "invalidations": self.invalidations,
            "hit_rate_pct": round(hit_rate, 1),
        }


class AttestationCache:
    """LRU cache for VVP attestation intermediate results.

    Keyed by (identity_name, dossier_said). Thread-safety: NOT thread-safe.
    Each uvicorn worker gets its own instance (module-level singleton).
    """

    def __init__(
        self,
        ttl: float = DEFAULT_TTL_SECONDS,
        max_entries: int = DEFAULT_MAX_ENTRIES,
    ):
        self._cache: OrderedDict[Tuple[str, str], AttestationCacheEntry] = OrderedDict()
        self._ttl = ttl
        self._max_entries = max_entries
        self._metrics = AttestationCacheMetrics()

    @property
    def metrics(self) -> AttestationCacheMetrics:
        return self._metrics

    def get(
        self, identity_name: str, dossier_said: str
    ) -> Optional[AttestationCacheEntry]:
        """Look up cached attestation data.

        Returns None on miss or expired entry. Moves entry to end on hit (LRU).
        """
        key = (identity_name, dossier_said)
        entry = self._cache.get(key)

        if entry is None:
            self._metrics.misses += 1
            return None

        if entry.is_expired(self._ttl):
            del self._cache[key]
            self._metrics.misses += 1
            log.debug(f"Attestation cache expired: {identity_name}/{dossier_said[:16]}...")
            return None

        # Move to end (most recently used)
        self._cache.move_to_end(key)
        self._metrics.hits += 1
        return entry

    def put(
        self,
        identity_name: str,
        dossier_said: str,
        identity_aid: str,
        issuer_oobi: str,
        dossier_url: str,
        card: Optional[Any],
    ) -> None:
        """Store attestation data in cache."""
        key = (identity_name, dossier_said)

        entry = AttestationCacheEntry(
            identity_aid=identity_aid,
            issuer_oobi=issuer_oobi,
            dossier_url=dossier_url,
            card=card,
            created_at=time.monotonic(),
        )

        # Remove old entry if exists (to reset position)
        if key in self._cache:
            del self._cache[key]

        self._cache[key] = entry

        # LRU eviction
        while len(self._cache) > self._max_entries:
            evicted_key, _ = self._cache.popitem(last=False)
            self._metrics.evictions += 1
            log.debug(f"Attestation cache LRU eviction: {evicted_key[0]}/{evicted_key[1][:16]}...")

    def invalidate_by_dossier_said(self, dossier_said: str) -> int:
        """Remove all entries for a given dossier SAID.

        Called by DossierCache revocation callback when a credential
        in the dossier chain is revoked.

        Args:
            dossier_said: Dossier SAID to invalidate.

        Returns:
            Number of entries removed.
        """
        keys_to_remove = [k for k in self._cache if k[1] == dossier_said]
        for key in keys_to_remove:
            del self._cache[key]
        if keys_to_remove:
            self._metrics.invalidations += len(keys_to_remove)
            log.info(
                f"Attestation cache invalidated {len(keys_to_remove)} entries "
                f"for dossier SAID: {dossier_said[:20]}..."
            )
        return len(keys_to_remove)

    def invalidate_by_identity(self, identity_name: str) -> int:
        """Remove all entries for a given identity.

        Called when identity changes (AID rotation, witness change).

        Args:
            identity_name: Identity name to invalidate.

        Returns:
            Number of entries removed.
        """
        keys_to_remove = [k for k in self._cache if k[0] == identity_name]
        for key in keys_to_remove:
            del self._cache[key]
        if keys_to_remove:
            self._metrics.invalidations += len(keys_to_remove)
            log.info(
                f"Attestation cache invalidated {len(keys_to_remove)} entries "
                f"for identity: {identity_name}"
            )
        return len(keys_to_remove)

    def clear(self) -> None:
        """Clear all cache entries."""
        self._cache.clear()

    def size(self) -> int:
        """Return number of entries in cache."""
        return len(self._cache)


# Module-level singleton
_cache: Optional[AttestationCache] = None


def get_attestation_cache() -> AttestationCache:
    """Get or create the attestation cache singleton."""
    global _cache
    if _cache is None:
        _cache = AttestationCache()
    return _cache


def reset_attestation_cache() -> None:
    """Reset the attestation cache singleton (for testing)."""
    global _cache
    _cache = None
