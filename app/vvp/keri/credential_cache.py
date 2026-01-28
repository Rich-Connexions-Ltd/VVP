"""Credential cache for externally resolved ACDCs.

Per spec §5C.2: Cache freshness policy aligns with key state cache.

This cache stores ACDC credentials fetched from KERI witnesses during
external SAID resolution. It uses LRU eviction and TTL expiration.
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Dict, List, Optional

if TYPE_CHECKING:
    from ..acdc.models import ACDC

log = logging.getLogger(__name__)


@dataclass
class CachedCredential:
    """Cached credential with metadata.

    Attributes:
        acdc: The resolved ACDC credential.
        source_url: The witness URL that provided this credential.
        signature: Optional signature bytes from the credential.
        cached_at: Unix timestamp when the entry was cached.
        expires_at: Unix timestamp when this entry expires.
        last_access: Unix timestamp of last access (for LRU).
    """

    acdc: "ACDC"
    source_url: str
    signature: Optional[bytes] = None
    cached_at: float = field(default_factory=time.time)
    expires_at: float = 0.0
    last_access: float = field(default_factory=time.time)


@dataclass
class CredentialCacheConfig:
    """Configuration for credential cache.

    Attributes:
        ttl_seconds: Time-to-live for cache entries (default 5 minutes per §5C.2).
        max_entries: Maximum entries before LRU eviction.
    """

    ttl_seconds: int = 300  # 5 minutes default per §5C.2
    max_entries: int = 500


@dataclass
class CredentialCacheMetrics:
    """Metrics for cache operations.

    Attributes:
        hits: Number of cache hits.
        misses: Number of cache misses.
        evictions: Number of LRU evictions.
        expirations: Number of TTL expirations.
    """

    hits: int = 0
    misses: int = 0
    evictions: int = 0
    expirations: int = 0

    def hit_rate(self) -> float:
        """Calculate cache hit rate.

        Returns:
            Hit rate as float (0.0 to 1.0), or 0.0 if no requests.
        """
        total = self.hits + self.misses
        return self.hits / total if total > 0 else 0.0

    def to_dict(self) -> Dict[str, any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "hits": self.hits,
            "misses": self.misses,
            "evictions": self.evictions,
            "expirations": self.expirations,
            "hit_rate": round(self.hit_rate(), 4),
        }

    def reset(self) -> None:
        """Reset all metrics to zero."""
        self.hits = 0
        self.misses = 0
        self.evictions = 0
        self.expirations = 0


class CredentialCache:
    """Thread-safe cache for resolved ACDC credentials.

    Supports lookup by SAID (self-addressing identifier).
    Uses LRU eviction when max_entries is exceeded and TTL expiration.

    Thread-safety is provided via asyncio.Lock for async contexts.
    """

    def __init__(self, config: Optional[CredentialCacheConfig] = None):
        """Initialize the cache.

        Args:
            config: Optional configuration. Uses defaults if not provided.
        """
        self._config = config or CredentialCacheConfig()
        self._entries: Dict[str, CachedCredential] = {}
        self._access_order: List[str] = []  # LRU tracking
        self._lock = asyncio.Lock()
        self._metrics = CredentialCacheMetrics()

    @property
    def metrics(self) -> CredentialCacheMetrics:
        """Get cache metrics."""
        return self._metrics

    async def get(self, said: str) -> Optional["ACDC"]:
        """Retrieve a credential from cache by SAID.

        Args:
            said: The SAID of the credential to retrieve.

        Returns:
            The cached ACDC if found and not expired, None otherwise.
        """
        async with self._lock:
            entry = self._entries.get(said)

            if entry is None:
                self._metrics.misses += 1
                return None

            # Check expiration
            now = time.time()
            if now >= entry.expires_at:
                # Entry expired, remove it
                del self._entries[said]
                if said in self._access_order:
                    self._access_order.remove(said)
                self._metrics.expirations += 1
                self._metrics.misses += 1
                log.debug(f"Credential {said[:20]}... expired in cache")
                return None

            # Update access time and order for LRU
            entry.last_access = now
            if said in self._access_order:
                self._access_order.remove(said)
            self._access_order.append(said)

            self._metrics.hits += 1
            log.debug(f"Credential cache hit for {said[:20]}...")
            return entry.acdc

    async def put(
        self,
        said: str,
        acdc: "ACDC",
        source_url: str,
        signature: Optional[bytes] = None,
    ) -> None:
        """Store a credential in the cache.

        Args:
            said: The SAID of the credential.
            acdc: The ACDC credential to cache.
            source_url: The witness URL that provided this credential.
            signature: Optional signature bytes.
        """
        async with self._lock:
            now = time.time()

            # Evict if at capacity
            while len(self._entries) >= self._config.max_entries:
                if not self._access_order:
                    break
                # Evict least recently used
                lru_said = self._access_order.pop(0)
                if lru_said in self._entries:
                    del self._entries[lru_said]
                    self._metrics.evictions += 1
                    log.debug(f"Evicted LRU credential {lru_said[:20]}...")

            # Create new entry
            entry = CachedCredential(
                acdc=acdc,
                source_url=source_url,
                signature=signature,
                cached_at=now,
                expires_at=now + self._config.ttl_seconds,
                last_access=now,
            )

            self._entries[said] = entry

            # Update access order
            if said in self._access_order:
                self._access_order.remove(said)
            self._access_order.append(said)

            log.debug(f"Cached credential {said[:20]}... from {source_url}")

    async def get_entry(self, said: str) -> Optional[CachedCredential]:
        """Retrieve full cache entry by SAID.

        Unlike get(), this returns the full CachedCredential with metadata.

        Args:
            said: The SAID of the credential to retrieve.

        Returns:
            The cached entry if found and not expired, None otherwise.
        """
        async with self._lock:
            entry = self._entries.get(said)

            if entry is None:
                return None

            # Check expiration
            now = time.time()
            if now >= entry.expires_at:
                del self._entries[said]
                if said in self._access_order:
                    self._access_order.remove(said)
                self._metrics.expirations += 1
                return None

            # Update access time and order for LRU
            entry.last_access = now
            if said in self._access_order:
                self._access_order.remove(said)
            self._access_order.append(said)

            return entry

    async def invalidate(self, said: str) -> bool:
        """Remove a credential from the cache.

        Args:
            said: The SAID of the credential to remove.

        Returns:
            True if the credential was in cache, False otherwise.
        """
        async with self._lock:
            if said in self._entries:
                del self._entries[said]
                if said in self._access_order:
                    self._access_order.remove(said)
                log.debug(f"Invalidated credential {said[:20]}...")
                return True
            return False

    async def clear(self) -> int:
        """Clear all entries from the cache.

        Returns:
            Number of entries cleared.
        """
        async with self._lock:
            count = len(self._entries)
            self._entries.clear()
            self._access_order.clear()
            log.debug(f"Cleared {count} entries from credential cache")
            return count

    async def size(self) -> int:
        """Get the current number of entries in the cache.

        Returns:
            Number of cached entries.
        """
        async with self._lock:
            return len(self._entries)


# Singleton instance
_credential_cache: Optional[CredentialCache] = None
_cache_lock = asyncio.Lock()


async def get_credential_cache(
    config: Optional[CredentialCacheConfig] = None,
) -> CredentialCache:
    """Get or create the singleton credential cache instance.

    Args:
        config: Optional configuration for cache creation.
                Ignored if cache already exists.

    Returns:
        The credential cache singleton.
    """
    global _credential_cache

    async with _cache_lock:
        if _credential_cache is None:
            _credential_cache = CredentialCache(config)
            log.info("Created credential cache singleton")
        return _credential_cache


def reset_credential_cache() -> None:
    """Reset the singleton cache instance.

    Used primarily for testing to ensure clean state between tests.
    """
    global _credential_cache
    _credential_cache = None
