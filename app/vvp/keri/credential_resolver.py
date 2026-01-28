"""External SAID resolution for ACDC credentials.

When compact ACDCs have edge references to credentials not in the dossier,
this module attempts to fetch those credentials from KERI witnesses.

Per VVP §2.2: If resolution fails, we fall back to INDETERMINATE rather than
INVALID, since the credential may exist but simply be unreachable.
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Dict, List, Optional, Set

import httpx

from .credential_cache import (
    CredentialCache,
    CredentialCacheConfig,
    get_credential_cache,
)

if TYPE_CHECKING:
    from ..acdc.models import ACDC

log = logging.getLogger(__name__)


class CredentialResolutionError(Exception):
    """Base exception for credential resolution errors."""

    pass


class CredentialNotFoundError(CredentialResolutionError):
    """Credential not found at any witness."""

    pass


class CredentialParseError(CredentialResolutionError):
    """Failed to parse credential from witness response."""

    pass


class SAIDMismatchError(CredentialResolutionError):
    """Fetched credential SAID doesn't match requested SAID."""

    pass


@dataclass
class CredentialResolverConfig:
    """Configuration for credential resolver.

    Attributes:
        enabled: Whether external resolution is enabled.
        timeout_seconds: HTTP request timeout.
        max_recursion_depth: Maximum depth for resolving chained external refs.
        cache_ttl_seconds: TTL for cached credentials.
        cache_max_entries: Maximum cache entries before LRU eviction.
    """

    enabled: bool = True
    timeout_seconds: float = 5.0
    max_recursion_depth: int = 3
    cache_ttl_seconds: int = 300
    cache_max_entries: int = 500


@dataclass
class ResolvedCredential:
    """Result of credential resolution.

    Attributes:
        acdc: The resolved ACDC credential.
        source_url: The witness URL that provided this credential.
        signature: Optional signature bytes from the credential.
        fetch_time_ms: Time taken to fetch in milliseconds.
    """

    acdc: "ACDC"
    source_url: str
    signature: Optional[bytes] = None
    fetch_time_ms: float = 0.0


@dataclass
class ResolverMetrics:
    """Metrics for credential resolution operations.

    Attributes:
        attempts: Number of resolution attempts.
        successes: Number of successful resolutions.
        failures: Number of failed resolutions.
        cache_hits: Number of cache hits.
        recursion_limits: Number of times recursion limit was reached.
    """

    attempts: int = 0
    successes: int = 0
    failures: int = 0
    cache_hits: int = 0
    recursion_limits: int = 0

    def to_dict(self) -> Dict[str, any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "attempts": self.attempts,
            "successes": self.successes,
            "failures": self.failures,
            "cache_hits": self.cache_hits,
            "recursion_limits": self.recursion_limits,
            "success_rate": (
                round(self.successes / self.attempts, 4)
                if self.attempts > 0
                else 0.0
            ),
        }


class CredentialResolver:
    """Resolves external ACDC credentials from KERI witnesses.

    When a compact ACDC references credentials not in the dossier,
    this resolver attempts to fetch them from witness endpoints.

    Thread-safety is provided via the in_flight set and async patterns.
    """

    def __init__(
        self,
        config: Optional[CredentialResolverConfig] = None,
        cache: Optional[CredentialCache] = None,
    ):
        """Initialize the resolver.

        Args:
            config: Optional configuration. Uses defaults if not provided.
            cache: Optional cache. Uses singleton if not provided.
        """
        self._config = config or CredentialResolverConfig()
        self._cache = cache
        self._in_flight: Set[str] = set()  # Recursion guard
        self._metrics = ResolverMetrics()

    @property
    def metrics(self) -> ResolverMetrics:
        """Get resolver metrics."""
        return self._metrics

    @property
    def config(self) -> CredentialResolverConfig:
        """Get resolver configuration."""
        return self._config

    async def _get_cache(self) -> CredentialCache:
        """Get or create the cache instance."""
        if self._cache is None:
            self._cache = await get_credential_cache(
                CredentialCacheConfig(
                    ttl_seconds=self._config.cache_ttl_seconds,
                    max_entries=self._config.cache_max_entries,
                )
            )
        return self._cache

    async def resolve(
        self,
        said: str,
        witness_base_urls: List[str],
        current_depth: int = 0,
    ) -> Optional[ResolvedCredential]:
        """Attempt to resolve a credential SAID from witnesses.

        Args:
            said: The SAID of the credential to resolve.
            witness_base_urls: Base URLs of witnesses to query.
            current_depth: Current recursion depth (for nested external refs).

        Returns:
            ResolvedCredential if found and valid, None otherwise.
        """
        if not self._config.enabled:
            log.debug(f"External SAID resolution disabled, skipping {said[:20]}...")
            return None

        self._metrics.attempts += 1

        # Check recursion limit
        if current_depth >= self._config.max_recursion_depth:
            log.warning(
                f"Recursion limit ({self._config.max_recursion_depth}) reached "
                f"for credential {said[:20]}..."
            )
            self._metrics.recursion_limits += 1
            return None

        # Check in-flight to prevent loops
        if said in self._in_flight:
            log.warning(f"Credential {said[:20]}... already being resolved (loop?)")
            return None

        # Check cache first
        cache = await self._get_cache()
        cached_entry = await cache.get_entry(said)
        if cached_entry:
            self._metrics.cache_hits += 1
            log.debug(f"Cache hit for credential {said[:20]}...")
            return ResolvedCredential(
                acdc=cached_entry.acdc,
                source_url=cached_entry.source_url,
                signature=cached_entry.signature,
            )

        # Mark as in-flight
        self._in_flight.add(said)
        try:
            result = await self._fetch_from_witnesses(said, witness_base_urls)
            if result:
                # Cache successful resolution
                await cache.put(
                    said=said,
                    acdc=result.acdc,
                    source_url=result.source_url,
                    signature=result.signature,
                )
                self._metrics.successes += 1
                return result
            else:
                self._metrics.failures += 1
                return None
        finally:
            self._in_flight.discard(said)

    async def _fetch_from_witnesses(
        self,
        said: str,
        witness_base_urls: List[str],
    ) -> Optional[ResolvedCredential]:
        """Fetch credential from witnesses in parallel.

        Queries up to 3 witnesses in parallel and returns the first
        successful response.

        Args:
            said: The SAID of the credential to fetch.
            witness_base_urls: Base URLs of witnesses to query.

        Returns:
            ResolvedCredential if found, None otherwise.
        """
        if not witness_base_urls:
            log.warning(f"No witness URLs provided for credential {said[:20]}...")
            return None

        # Query up to 3 witnesses in parallel
        urls_to_try = witness_base_urls[:3]
        start_time = time.time()

        async def fetch_one(base_url: str) -> Optional[ResolvedCredential]:
            try:
                return await self._fetch_from_single_witness(said, base_url)
            except Exception as e:
                log.debug(f"Failed to fetch {said[:20]}... from {base_url}: {e}")
                return None

        # Run queries in parallel
        tasks = [fetch_one(url) for url in urls_to_try]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        elapsed_ms = (time.time() - start_time) * 1000

        # Return first successful result
        for result in results:
            if isinstance(result, ResolvedCredential):
                result.fetch_time_ms = elapsed_ms
                return result

        log.warning(
            f"Failed to resolve credential {said[:20]}... from any witness "
            f"({len(urls_to_try)} tried)"
        )
        return None

    async def _fetch_from_single_witness(
        self,
        said: str,
        witness_base_url: str,
    ) -> Optional[ResolvedCredential]:
        """Fetch credential from a single witness.

        Args:
            said: The SAID of the credential to fetch.
            witness_base_url: Base URL of the witness.

        Returns:
            ResolvedCredential if found and valid, None otherwise.
        """
        # Standard KERI credential endpoint
        url = f"{witness_base_url.rstrip('/')}/credentials/{said}"

        log.debug(f"Fetching credential {said[:20]}... from {url}")

        try:
            async with httpx.AsyncClient(
                timeout=self._config.timeout_seconds,
                follow_redirects=True,
            ) as client:
                response = await client.get(url)

                if response.status_code == 404:
                    log.debug(f"Credential {said[:20]}... not found at {witness_base_url}")
                    return None

                if response.status_code != 200:
                    log.warning(
                        f"Unexpected status {response.status_code} fetching "
                        f"credential {said[:20]}... from {witness_base_url}"
                    )
                    return None

                # Parse the response
                return await self._parse_credential_response(
                    said, response.content, witness_base_url
                )

        except httpx.TimeoutException:
            log.warning(
                f"Timeout fetching credential {said[:20]}... from {witness_base_url}"
            )
            return None
        except httpx.RequestError as e:
            log.warning(
                f"Network error fetching credential {said[:20]}... from "
                f"{witness_base_url}: {e}"
            )
            return None

    async def _parse_credential_response(
        self,
        requested_said: str,
        content: bytes,
        source_url: str,
    ) -> Optional[ResolvedCredential]:
        """Parse credential from witness response.

        Witness responses may be:
        - Raw JSON ACDC
        - CESR stream with ACDC + signatures
        - JSON-wrapped ACDC

        Args:
            requested_said: The SAID we requested.
            content: Raw response content.
            source_url: The witness URL for logging.

        Returns:
            ResolvedCredential if parsing succeeds and SAID matches.
        """
        # Import here to avoid circular imports
        from ..acdc.parser import parse_acdc
        from ..acdc.models import ACDC
        from .cesr import parse_cesr_stream, CESRMessage

        signature: Optional[bytes] = None
        data: Optional[dict] = None

        try:
            # First try parsing as CESR stream (most complete format)
            # This handles JSON with attachments properly
            try:
                messages = parse_cesr_stream(content)
                if messages:
                    # Use first message with valid ACDC structure
                    for msg in messages:
                        if isinstance(msg.event_dict, dict) and (
                            "d" in msg.event_dict or "v" in msg.event_dict
                        ):
                            data = msg.event_dict
                            # Extract controller signature if present
                            if msg.controller_sigs:
                                signature = msg.controller_sigs[0]
                                log.debug(
                                    f"Extracted signature from CESR for {requested_said[:20]}..."
                                )
                            break
            except Exception as cesr_err:
                log.debug(f"CESR parsing failed for {source_url}: {cesr_err}")

            # If CESR didn't work, try plain JSON
            if data is None:
                import json

                try:
                    data = json.loads(content)
                except json.JSONDecodeError:
                    log.warning(f"Failed to parse response from {source_url}")
                    return None

            # Handle wrapped responses
            if isinstance(data, dict):
                # Check for credential wrapper
                if "credential" in data:
                    data = data["credential"]
                elif "acdc" in data:
                    data = data["acdc"]

            # Parse as ACDC
            acdc = parse_acdc(data)

            # Validate SAID matches
            if acdc.said != requested_said:
                log.warning(
                    f"SAID mismatch: requested {requested_said[:20]}..., "
                    f"got {acdc.said[:20]}... from {source_url}"
                )
                return None

            log.info(
                f"Successfully resolved credential {requested_said[:20]}... "
                f"from {source_url} (signature={'present' if signature else 'absent'})"
            )
            return ResolvedCredential(
                acdc=acdc,
                source_url=source_url,
                signature=signature,
            )

        except Exception as e:
            log.warning(f"Failed to parse credential from {source_url}: {e}")
            return None


# Singleton resolver
_credential_resolver: Optional[CredentialResolver] = None


def get_credential_resolver(
    config: Optional[CredentialResolverConfig] = None,
) -> CredentialResolver:
    """Get or create the singleton credential resolver instance.

    Args:
        config: Optional configuration for resolver creation.
                Ignored if resolver already exists.

    Returns:
        The credential resolver singleton.
    """
    global _credential_resolver

    if _credential_resolver is None:
        _credential_resolver = CredentialResolver(config)
        log.info("Created credential resolver singleton")

    return _credential_resolver


def reset_credential_resolver() -> None:
    """Reset the singleton resolver instance.

    Used primarily for testing to ensure clean state between tests.
    """
    global _credential_resolver
    _credential_resolver = None
