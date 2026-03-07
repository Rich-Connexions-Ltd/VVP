"""Signing constraint result cache.

Caches vetter constraint validation results by (dossier_said, ecc_code).
Constraint results are deterministic for a given dossier + calling country
code — the VetterCert targets and credential chain don't change between calls.

Invalidation triggers:
1. Enforcement toggle via admin API → clear()
2. Dossier revocation → invalidate_by_dossier_said()
3. TTL expiry (300s)
"""

import logging
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Optional

log = logging.getLogger(__name__)

DEFAULT_TTL_SECONDS = 300.0
DEFAULT_MAX_ENTRIES = 200


@dataclass
class ConstraintCacheEntry:
    """Cached constraint check results for a (dossier, ecc) pair."""

    violations: list  # list[ConstraintCheckResult]
    created_at: float

    def is_expired(self, ttl: float) -> bool:
        return (time.monotonic() - self.created_at) > ttl


class ConstraintCache:
    """LRU cache for signing constraint results.

    Keyed by (dossier_said, ecc_code). Per-worker singleton (not thread-safe).
    """

    def __init__(
        self,
        ttl: float = DEFAULT_TTL_SECONDS,
        max_entries: int = DEFAULT_MAX_ENTRIES,
    ):
        self._cache: OrderedDict[tuple[str, str], ConstraintCacheEntry] = OrderedDict()
        self._ttl = ttl
        self._max_entries = max_entries
        self._hits = 0
        self._misses = 0

    def get(self, dossier_said: str, ecc_code: str) -> Optional[list]:
        """Look up cached constraint results. Returns None on miss."""
        key = (dossier_said, ecc_code)
        entry = self._cache.get(key)

        if entry is None:
            self._misses += 1
            return None

        if entry.is_expired(self._ttl):
            del self._cache[key]
            self._misses += 1
            return None

        self._cache.move_to_end(key)
        self._hits += 1
        return entry.violations

    def put(self, dossier_said: str, ecc_code: str, violations: list) -> None:
        """Store constraint results."""
        key = (dossier_said, ecc_code)
        if key in self._cache:
            del self._cache[key]

        self._cache[key] = ConstraintCacheEntry(
            violations=violations,
            created_at=time.monotonic(),
        )

        while len(self._cache) > self._max_entries:
            self._cache.popitem(last=False)

    def invalidate_by_dossier_said(self, dossier_said: str) -> int:
        """Remove all entries for a dossier SAID (e.g. on revocation)."""
        keys = [k for k in self._cache if k[0] == dossier_said]
        for key in keys:
            del self._cache[key]
        if keys:
            log.info(f"Constraint cache invalidated {len(keys)} entries for {dossier_said[:20]}...")
        return len(keys)

    def clear(self) -> None:
        """Clear all entries (e.g. on enforcement toggle)."""
        count = len(self._cache)
        self._cache.clear()
        if count:
            log.info(f"Constraint cache cleared ({count} entries)")

    def size(self) -> int:
        return len(self._cache)

    def metrics(self) -> dict:
        total = self._hits + self._misses
        return {
            "hits": self._hits,
            "misses": self._misses,
            "size": len(self._cache),
            "hit_rate_pct": round(self._hits / total * 100, 1) if total else 0.0,
        }


# Module-level singleton
_cache: Optional[ConstraintCache] = None


def get_constraint_cache() -> ConstraintCache:
    """Get or create the constraint cache singleton."""
    global _cache
    if _cache is None:
        _cache = ConstraintCache()
    return _cache


def reset_constraint_cache() -> None:
    """Reset the singleton (for testing)."""
    global _cache
    _cache = None
