"""Schema cache with LRU eviction and TTL expiration.

Caches SAID-verified schema documents for ACDC validation.
Schemas are immutable (content-addressed via SAID), so longer TTL is safe.

INVARIANT: Only schemas that have passed SAID verification are stored.
The cache key is the verified SAID, guaranteeing cache hits return
cryptographically verified content.
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

log = logging.getLogger(__name__)


@dataclass
class CachedSchema:
    """Cached schema entry with metadata.

    Attributes:
        schema_doc: The verified JSON Schema document.
        verified_said: The SAID that was verified (cache key).
        source: The URL or identifier that provided this schema.
        source_type: Type of source ("registry", "oobi", "embedded").
        cached_at: Unix timestamp when the entry was cached.
        expires_at: Unix timestamp when this entry expires.
        last_access: Unix timestamp of last access (for LRU).
    """

    schema_doc: Dict[str, Any]
    verified_said: str
    source: str
    source_type: str
    cached_at: float = field(default_factory=time.time)
    expires_at: float = 0.0
    last_access: float = field(default_factory=time.time)


@dataclass
class SchemaCacheConfig:
    """Configuration for schema cache.

    Attributes:
        ttl_seconds: Time-to-live for cache entries.
            Default 1 hour - schemas are immutable so longer TTL is safe.
        max_entries: Maximum entries before LRU eviction.
    """

    ttl_seconds: int = 3600  # 1 hour - schemas are immutable
    max_entries: int = 200


@dataclass
class SchemaCacheMetrics:
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

    def to_dict(self) -> Dict[str, Any]:
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


class SchemaCache:
    """Thread-safe LRU cache for SAID-verified schema documents.

    INVARIANT: Only schemas that have passed SAID verification are stored.
    The cache key is the verified SAID, guaranteeing cache hits return
    cryptographically verified content.

    Thread-safety is provided via asyncio.Lock for async contexts.
    """

    def __init__(self, config: Optional[SchemaCacheConfig] = None):
        """Initialize the cache.

        Args:
            config: Optional configuration. Uses defaults if not provided.
        """
        self._config = config or SchemaCacheConfig()
        self._entries: Dict[str, CachedSchema] = {}
        self._access_order: List[str] = []  # LRU tracking
        self._lock = asyncio.Lock()
        self._metrics = SchemaCacheMetrics()

    @property
    def config(self) -> SchemaCacheConfig:
        """Get cache configuration."""
        return self._config

    @property
    def metrics(self) -> SchemaCacheMetrics:
        """Get cache metrics."""
        return self._metrics

    async def get(self, said: str) -> Optional[Dict[str, Any]]:
        """Retrieve a schema document from cache by SAID.

        Args:
            said: The SAID of the schema to retrieve.

        Returns:
            The cached schema document if found and not expired, None otherwise.
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
                log.debug(f"Schema {said[:20]}... expired in cache")
                return None

            # Update access time and order for LRU
            entry.last_access = now
            if said in self._access_order:
                self._access_order.remove(said)
            self._access_order.append(said)

            self._metrics.hits += 1
            log.debug(f"Schema cache hit for {said[:20]}...")
            return entry.schema_doc

    async def put(
        self,
        said: str,
        schema_doc: Dict[str, Any],
        source: str,
        source_type: str,
    ) -> None:
        """Store a SAID-verified schema in the cache.

        PRECONDITION: The schema_doc MUST have already passed SAID verification.
        This method does NOT verify the SAID - that is the caller's responsibility.

        Args:
            said: The verified SAID of the schema (cache key).
            schema_doc: The verified JSON Schema document.
            source: The URL or identifier that provided this schema.
            source_type: Type of source ("registry", "oobi", "embedded").
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
                    log.debug(f"Evicted LRU schema {lru_said[:20]}...")

            # Create new entry
            entry = CachedSchema(
                schema_doc=schema_doc,
                verified_said=said,
                source=source,
                source_type=source_type,
                cached_at=now,
                expires_at=now + self._config.ttl_seconds,
                last_access=now,
            )

            self._entries[said] = entry

            # Update access order
            if said in self._access_order:
                self._access_order.remove(said)
            self._access_order.append(said)

            log.debug(f"Cached schema {said[:20]}... from {source} ({source_type})")

    async def get_entry(self, said: str) -> Optional[CachedSchema]:
        """Retrieve full cache entry by SAID.

        Unlike get(), this returns the full CachedSchema with metadata.

        Args:
            said: The SAID of the schema to retrieve.

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
        """Remove a schema from the cache.

        Args:
            said: The SAID of the schema to remove.

        Returns:
            True if the schema was in cache, False otherwise.
        """
        async with self._lock:
            if said in self._entries:
                del self._entries[said]
                if said in self._access_order:
                    self._access_order.remove(said)
                log.debug(f"Invalidated schema {said[:20]}...")
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
            log.debug(f"Cleared {count} entries from schema cache")
            return count

    async def size(self) -> int:
        """Get the current number of entries in the cache.

        Returns:
            Number of cached entries.
        """
        async with self._lock:
            return len(self._entries)


# Singleton instance
_schema_cache: Optional[SchemaCache] = None
_cache_lock = asyncio.Lock()


async def get_schema_cache(
    config: Optional[SchemaCacheConfig] = None,
) -> SchemaCache:
    """Get or create the singleton schema cache instance.

    Args:
        config: Optional configuration for cache creation.
                Ignored if cache already exists.

    Returns:
        The schema cache singleton.
    """
    global _schema_cache

    async with _cache_lock:
        if _schema_cache is None:
            _schema_cache = SchemaCache(config)
            log.info("Created schema cache singleton")
        return _schema_cache


def reset_schema_cache() -> None:
    """Reset the singleton cache instance.

    Used primarily for testing to ensure clean state between tests.
    """
    global _schema_cache
    _schema_cache = None
