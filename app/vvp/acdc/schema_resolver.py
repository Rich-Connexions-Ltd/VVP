"""SAID-first schema resolution for ACDC credentials.

Resolves schema documents from multiple sources with mandatory SAID verification.
Mirrors the CredentialResolver pattern from keri/credential_resolver.py.

Per ACDC spec, schemas are content-addressed via SAID:
- SAID verification is MANDATORY before caching or returning
- Mismatch is INVALID (not INDETERMINATE)
- Missing $id field is INVALID (cannot compute SAID)

Per VVP §2.2, unavailable schemas (network failure) result in INDETERMINATE.
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

import httpx

from .exceptions import ACDCChainInvalid
from .schema_cache import (
    SchemaCache,
    SchemaCacheConfig,
    get_schema_cache,
    reset_schema_cache,
)

log = logging.getLogger(__name__)


class SchemaResolutionError(Exception):
    """Base exception for schema resolution errors."""

    pass


class SchemaNotFoundError(SchemaResolutionError):
    """Schema not found at any source."""

    pass


class SchemaSAIDMismatchError(SchemaResolutionError):
    """Fetched schema SAID doesn't match requested SAID."""

    pass


class SchemaMissingSAIDError(SchemaResolutionError):
    """Schema document missing $id field required for SAID computation."""

    pass


@dataclass
class SchemaResolverConfig:
    """Configuration for schema resolver.

    Attributes:
        enabled: Whether external resolution is enabled.
        timeout_seconds: HTTP request timeout per source.
        cache_ttl_seconds: TTL for cached schemas (longer than credentials).
        cache_max_entries: Maximum cache entries before LRU eviction.
        registry_urls: Ordered list of schema registry URLs to try.
        oobi_resolution_enabled: Whether to try OOBI/witness resolution.
    """

    enabled: bool = True
    timeout_seconds: float = 5.0
    cache_ttl_seconds: int = 3600  # 1 hour - schemas are immutable
    cache_max_entries: int = 200
    registry_urls: List[str] = field(
        default_factory=lambda: [
            "https://schema.gleif.org/",
            "https://schema.provenant.net/",
        ]
    )
    oobi_resolution_enabled: bool = False  # Feature flag - off by default


@dataclass
class ResolvedSchema:
    """Result of schema resolution.

    Attributes:
        schema_doc: The resolved and SAID-verified JSON Schema document.
        said: The verified schema SAID.
        source: The URL or identifier that provided this schema.
        source_type: Type of source ("cache", "registry", "oobi").
        fetch_time_ms: Time taken to fetch in milliseconds.
    """

    schema_doc: Dict[str, Any]
    said: str
    source: str
    source_type: str
    fetch_time_ms: float = 0.0


@dataclass
class SchemaResolverMetrics:
    """Metrics for schema resolution operations.

    Attributes:
        attempts: Number of resolution attempts.
        successes: Number of successful resolutions.
        failures: Number of failed resolutions (all sources failed).
        cache_hits: Number of cache hits.
        said_mismatches: Number of SAID verification failures.
        missing_said_field: Number of schemas without $id field.
        registry_hits: Number of successful registry fetches.
        oobi_hits: Number of successful OOBI fetches.
    """

    attempts: int = 0
    successes: int = 0
    failures: int = 0
    cache_hits: int = 0
    said_mismatches: int = 0
    missing_said_field: int = 0
    registry_hits: int = 0
    oobi_hits: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "attempts": self.attempts,
            "successes": self.successes,
            "failures": self.failures,
            "cache_hits": self.cache_hits,
            "said_mismatches": self.said_mismatches,
            "missing_said_field": self.missing_said_field,
            "registry_hits": self.registry_hits,
            "oobi_hits": self.oobi_hits,
            "success_rate": (
                round(self.successes / self.attempts, 4)
                if self.attempts > 0
                else 0.0
            ),
        }

    def reset(self) -> None:
        """Reset all metrics to zero."""
        self.attempts = 0
        self.successes = 0
        self.failures = 0
        self.cache_hits = 0
        self.said_mismatches = 0
        self.missing_said_field = 0
        self.registry_hits = 0
        self.oobi_hits = 0


class SchemaResolver:
    """SAID-first schema resolver with multi-source lookup.

    Resolves schema documents from cache, registries, and optionally OOBI
    endpoints, with MANDATORY SAID verification before caching or returning.

    Resolution order:
    1. Cache lookup (stores only verified schemas)
    2. HTTP registry fetch (with SAID verification)
    3. OOBI/witness fetch (feature-flagged, off by default)

    Thread-safety is provided via asyncio patterns.
    """

    def __init__(
        self,
        config: Optional[SchemaResolverConfig] = None,
        cache: Optional[SchemaCache] = None,
    ):
        """Initialize the resolver.

        Args:
            config: Optional configuration. Uses defaults if not provided.
            cache: Optional cache. Uses singleton if not provided.
        """
        self._config = config or SchemaResolverConfig()
        self._cache = cache
        self._in_flight: Set[str] = set()  # Prevent duplicate fetches
        self._metrics = SchemaResolverMetrics()

    @property
    def metrics(self) -> SchemaResolverMetrics:
        """Get resolver metrics."""
        return self._metrics

    @property
    def config(self) -> SchemaResolverConfig:
        """Get resolver configuration."""
        return self._config

    async def _get_cache(self) -> SchemaCache:
        """Get or create the cache instance."""
        if self._cache is None:
            self._cache = await get_schema_cache(
                SchemaCacheConfig(
                    ttl_seconds=self._config.cache_ttl_seconds,
                    max_entries=self._config.cache_max_entries,
                )
            )
        return self._cache

    def _has_said_field(self, schema_doc: Dict[str, Any]) -> bool:
        """Check if schema has $id field required for SAID computation.

        Args:
            schema_doc: The schema document to check.

        Returns:
            True if $id field exists and is non-empty.
        """
        return "$id" in schema_doc and bool(schema_doc["$id"])

    def _verify_schema_said(
        self,
        schema_doc: Dict[str, Any],
        expected_said: str,
    ) -> bool:
        """Verify schema document matches expected SAID.

        Delegates to schema_fetcher.verify_schema_said() to ensure
        single source of truth for SAID verification logic.

        Args:
            schema_doc: The schema document to verify.
            expected_said: The expected SAID.

        Returns:
            True if computed SAID matches expected.
        """
        from .schema_fetcher import verify_schema_said

        return verify_schema_said(schema_doc, expected_said)

    async def resolve(
        self,
        schema_said: str,
        witness_urls: Optional[List[str]] = None,
    ) -> Optional[ResolvedSchema]:
        """Resolve a schema by SAID with mandatory verification.

        Resolution order:
        1. Cache lookup (stores only verified schemas)
        2. HTTP registry fetch (with SAID verification)
        3. OOBI/witness fetch (if enabled)

        SAID verification is MANDATORY:
        - Mismatch raises ACDCChainInvalid (INVALID, not INDETERMINATE)
        - Missing $id field raises ACDCChainInvalid (INVALID)
        - Network failures return None (INDETERMINATE)

        Args:
            schema_said: The SAID of the schema to resolve.
            witness_urls: Optional witness URLs for OOBI resolution.

        Returns:
            ResolvedSchema if found and verified, None if unavailable.

        Raises:
            ACDCChainInvalid: If schema found but SAID doesn't match or
                missing $id field (these are INVALID, not INDETERMINATE).
        """
        if not self._config.enabled:
            log.debug(f"Schema resolution disabled, skipping {schema_said[:20]}...")
            return None

        self._metrics.attempts += 1
        start_time = time.time()

        # Check embedded schema store first (instant lookup, no network)
        from .schema_store import get_embedded_schema
        embedded = get_embedded_schema(schema_said)
        if embedded:
            log.debug(f"Embedded store hit for schema {schema_said[:20]}...")
            self._metrics.successes += 1
            return ResolvedSchema(
                schema_doc=embedded,
                said=schema_said,
                source="embedded",
                source_type="embedded",
                fetch_time_ms=0.0,
            )

        # Check in-flight to prevent duplicate concurrent fetches
        if schema_said in self._in_flight:
            log.debug(f"Schema {schema_said[:20]}... already being resolved")
            # Wait briefly and check cache
            await asyncio.sleep(0.1)

        # Check cache (stores only verified schemas)
        cache = await self._get_cache()
        cached_entry = await cache.get_entry(schema_said)
        if cached_entry:
            self._metrics.cache_hits += 1
            self._metrics.successes += 1
            log.debug(f"Cache hit for schema {schema_said[:20]}...")
            return ResolvedSchema(
                schema_doc=cached_entry.schema_doc,
                said=cached_entry.verified_said,
                source=cached_entry.source,
                source_type="cache",
                fetch_time_ms=0.0,
            )

        # Mark as in-flight
        self._in_flight.add(schema_said)
        try:
            # Try registries
            result = await self._fetch_from_registries(schema_said)
            if result:
                elapsed_ms = (time.time() - start_time) * 1000
                result.fetch_time_ms = elapsed_ms
                # Cache the verified result
                await cache.put(
                    said=schema_said,
                    schema_doc=result.schema_doc,
                    source=result.source,
                    source_type=result.source_type,
                )
                self._metrics.successes += 1
                return result

            # Try OOBI if enabled
            if self._config.oobi_resolution_enabled and witness_urls:
                result = await self._fetch_from_oobi(schema_said, witness_urls)
                if result:
                    elapsed_ms = (time.time() - start_time) * 1000
                    result.fetch_time_ms = elapsed_ms
                    # Cache the verified result
                    await cache.put(
                        said=schema_said,
                        schema_doc=result.schema_doc,
                        source=result.source,
                        source_type=result.source_type,
                    )
                    self._metrics.successes += 1
                    return result

            # All sources failed
            self._metrics.failures += 1
            log.warning(f"Failed to resolve schema {schema_said[:20]}... from any source")
            return None

        finally:
            self._in_flight.discard(schema_said)

    async def _fetch_from_registries(
        self,
        schema_said: str,
    ) -> Optional[ResolvedSchema]:
        """Fetch schema from configured registries with SAID verification.

        Tries each registry in order until successful.

        Args:
            schema_said: The SAID of the schema to fetch.

        Returns:
            ResolvedSchema if found and verified, None otherwise.

        Raises:
            ACDCChainInvalid: If schema found but SAID doesn't match.
        """
        if not self._config.registry_urls:
            log.debug("No registry URLs configured")
            return None

        for registry_url in self._config.registry_urls:
            try:
                result = await self._fetch_from_single_registry(
                    schema_said, registry_url
                )
                if result:
                    self._metrics.registry_hits += 1
                    return result
            except ACDCChainInvalid:
                # SAID mismatch - propagate as INVALID
                raise
            except Exception as e:
                log.debug(f"Failed to fetch schema from {registry_url}: {e}")
                continue

        return None

    async def _fetch_from_single_registry(
        self,
        schema_said: str,
        registry_url: str,
    ) -> Optional[ResolvedSchema]:
        """Fetch schema from a single registry with SAID verification.

        Args:
            schema_said: The SAID of the schema to fetch.
            registry_url: The registry base URL.

        Returns:
            ResolvedSchema if found and verified, None if not found.

        Raises:
            ACDCChainInvalid: If schema found but SAID doesn't match or
                missing $id field.
        """
        url = f"{registry_url.rstrip('/')}/{schema_said}"
        log.debug(f"Fetching schema {schema_said[:20]}... from {url}")

        try:
            async with httpx.AsyncClient(
                timeout=self._config.timeout_seconds,
                follow_redirects=True,
            ) as client:
                response = await client.get(url)

                if response.status_code == 404:
                    log.debug(f"Schema {schema_said[:20]}... not found at {registry_url}")
                    return None

                if response.status_code != 200:
                    log.warning(
                        f"Unexpected status {response.status_code} fetching "
                        f"schema {schema_said[:20]}... from {registry_url}"
                    )
                    return None

                # Parse JSON
                try:
                    schema_doc = response.json()
                except Exception as e:
                    log.warning(f"Invalid JSON from {registry_url}: {e}")
                    return None

                # MANDATORY: Check for $id field
                if not self._has_said_field(schema_doc):
                    self._metrics.missing_said_field += 1
                    raise ACDCChainInvalid(
                        f"Schema from {registry_url} missing $id field - "
                        f"cannot verify SAID"
                    )

                # MANDATORY: Verify SAID
                if not self._verify_schema_said(schema_doc, schema_said):
                    self._metrics.said_mismatches += 1
                    raise ACDCChainInvalid(
                        f"Schema SAID mismatch: requested {schema_said[:20]}... "
                        f"but fetched document doesn't match (from {registry_url})"
                    )

                log.info(f"Fetched and verified schema {schema_said[:20]}... from {registry_url}")
                return ResolvedSchema(
                    schema_doc=schema_doc,
                    said=schema_said,
                    source=registry_url,
                    source_type="registry",
                )

        except httpx.TimeoutException:
            log.warning(f"Timeout fetching schema from {registry_url}")
            return None
        except httpx.RequestError as e:
            log.warning(f"Network error fetching schema from {registry_url}: {e}")
            return None
        except ACDCChainInvalid:
            # Re-raise SAID/structure errors
            raise

    async def _fetch_from_oobi(
        self,
        schema_said: str,
        witness_urls: List[str],
    ) -> Optional[ResolvedSchema]:
        """Fetch schema from OOBI/witness endpoints with SAID verification.

        NOTE: This is experimental. Current KERI witnesses typically serve
        KEL data, not schemas. Enable with SCHEMA_OOBI_RESOLUTION_ENABLED=true.

        Args:
            schema_said: The SAID of the schema to fetch.
            witness_urls: Base URLs of witnesses to query.

        Returns:
            ResolvedSchema if found and verified, None otherwise.

        Raises:
            ACDCChainInvalid: If schema found but SAID doesn't match or
                missing $id field.
        """
        if not witness_urls:
            log.debug("No witness URLs provided for OOBI resolution")
            return None

        # Try first 3 witnesses
        urls_to_try = witness_urls[:3]

        async def fetch_one(base_url: str) -> Optional[ResolvedSchema]:
            # Standard endpoint pattern for schemas
            url = f"{base_url.rstrip('/')}/schemas/{schema_said}"
            try:
                async with httpx.AsyncClient(
                    timeout=self._config.timeout_seconds,
                ) as client:
                    response = await client.get(url)
                    if response.status_code != 200:
                        return None

                    schema_doc = response.json()

                    # MANDATORY: Check for $id field - raises INVALID per invariants
                    if not self._has_said_field(schema_doc):
                        self._metrics.missing_said_field += 1
                        raise ACDCChainInvalid(
                            f"Schema from {base_url} missing $id field - "
                            f"cannot verify SAID"
                        )

                    # MANDATORY: Verify SAID - raises INVALID per invariants
                    if not self._verify_schema_said(schema_doc, schema_said):
                        self._metrics.said_mismatches += 1
                        raise ACDCChainInvalid(
                            f"Schema SAID mismatch: requested {schema_said[:20]}... "
                            f"but fetched document doesn't match (from {base_url})"
                        )

                    return ResolvedSchema(
                        schema_doc=schema_doc,
                        said=schema_said,
                        source=base_url,
                        source_type="oobi",
                    )
            except ACDCChainInvalid:
                # Re-raise SAID/structure errors - these are INVALID, not network failures
                raise
            except Exception as e:
                log.debug(f"OOBI fetch failed from {base_url}: {e}")
                return None

        # Run queries in parallel
        tasks = [fetch_one(url) for url in urls_to_try]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Check results: propagate ACDCChainInvalid, return first success
        for result in results:
            # Propagate SAID verification failures as INVALID
            if isinstance(result, ACDCChainInvalid):
                raise result
            if isinstance(result, ResolvedSchema):
                self._metrics.oobi_hits += 1
                return result

        return None


# Singleton resolver
_schema_resolver: Optional[SchemaResolver] = None


def _config_from_env() -> SchemaResolverConfig:
    """Create SchemaResolverConfig from environment variables.

    Reads configuration from app.core.config module which parses
    environment variables at import time.

    Returns:
        SchemaResolverConfig with values from environment.
    """
    from app.core import config as app_config

    return SchemaResolverConfig(
        enabled=app_config.SCHEMA_RESOLVER_ENABLED,
        timeout_seconds=app_config.SCHEMA_RESOLVER_TIMEOUT_SECONDS,
        cache_ttl_seconds=app_config.SCHEMA_RESOLVER_CACHE_TTL_SECONDS,
        cache_max_entries=app_config.SCHEMA_RESOLVER_CACHE_MAX_ENTRIES,
        registry_urls=app_config.SCHEMA_REGISTRY_URLS,
        oobi_resolution_enabled=app_config.SCHEMA_OOBI_RESOLUTION_ENABLED,
    )


def get_schema_resolver(
    config: Optional[SchemaResolverConfig] = None,
) -> SchemaResolver:
    """Get or create the singleton schema resolver instance.

    If no config is provided, creates one from environment variables
    via app.core.config.

    Args:
        config: Optional configuration for resolver creation.
                If None, uses environment configuration.
                Ignored if resolver already exists.

    Returns:
        The schema resolver singleton.
    """
    global _schema_resolver

    if _schema_resolver is None:
        # Use provided config or create from environment
        resolver_config = config if config is not None else _config_from_env()
        _schema_resolver = SchemaResolver(resolver_config)
        log.info(
            f"Created schema resolver singleton "
            f"(registries={len(resolver_config.registry_urls)}, "
            f"oobi={'enabled' if resolver_config.oobi_resolution_enabled else 'disabled'})"
        )

    return _schema_resolver


def reset_schema_resolver() -> None:
    """Reset the singleton resolver instance.

    Used primarily for testing to ensure clean state between tests.
    Also resets the schema cache.
    """
    global _schema_resolver
    _schema_resolver = None
    reset_schema_cache()
