"""Issuer API client.

Sprint 42: httpx-based async client for issuer service.
Sprint 50: Added TN lookup cache to reduce latency on repeat calls.
"""

import logging
import time
from dataclasses import dataclass, field
from typing import Optional

import httpx

from app.config import ISSUER_URL, ISSUER_TIMEOUT, TN_CACHE_TTL, TN_CACHE_MAX_ENTRIES

log = logging.getLogger(__name__)


@dataclass
class TNLookupResult:
    """Result from TN lookup API call."""

    found: bool
    tn: Optional[str] = None
    organization_id: Optional[str] = None
    organization_name: Optional[str] = None
    dossier_said: Optional[str] = None
    identity_name: Optional[str] = None
    brand_name: Optional[str] = None
    brand_logo_url: Optional[str] = None
    error: Optional[str] = None


@dataclass
class VVPCreateResult:
    """Result from VVP create API call."""

    success: bool
    vvp_identity: Optional[str] = None
    vvp_passport: Optional[str] = None
    error: Optional[str] = None


@dataclass
class _CachedTN:
    """Cached TN lookup result with expiry."""

    result: TNLookupResult
    expires_at: float


class TNLookupCache:
    """Cache for TN lookup results to avoid repeated issuer API calls.

    TN-to-dossier mappings change infrequently, so caching them for
    a few minutes dramatically reduces call setup latency.
    """

    def __init__(self, ttl: int = TN_CACHE_TTL, max_entries: int = TN_CACHE_MAX_ENTRIES):
        self._ttl = ttl
        self._max_entries = max_entries
        self._cache: dict[str, _CachedTN] = {}

    def get(self, tn: str) -> Optional[TNLookupResult]:
        """Get cached lookup result. Returns None if expired or missing."""
        entry = self._cache.get(tn)
        if entry is None:
            return None
        if time.monotonic() > entry.expires_at:
            del self._cache[tn]
            return None
        return entry.result

    def put(self, tn: str, result: TNLookupResult) -> None:
        """Cache a successful lookup result."""
        if not result.found:
            return  # Don't cache failures
        # Evict oldest if full
        if len(self._cache) >= self._max_entries:
            oldest_key = next(iter(self._cache))
            del self._cache[oldest_key]
        self._cache[tn] = _CachedTN(
            result=result,
            expires_at=time.monotonic() + self._ttl,
        )
        log.debug(f"Cached TN lookup for {tn} (TTL={self._ttl}s, entries={len(self._cache)})")

    def invalidate(self, tn: str) -> None:
        """Remove a specific TN from cache."""
        self._cache.pop(tn, None)

    @property
    def size(self) -> int:
        return len(self._cache)


class IssuerClient:
    """Async HTTP client for VVP Issuer API.

    Provides methods for TN lookup and VVP header creation.
    TN lookups are cached to reduce call setup latency.
    """

    def __init__(self, base_url: str = ISSUER_URL, timeout: float = ISSUER_TIMEOUT):
        """Initialize client.

        Args:
            base_url: Issuer service base URL
            timeout: Request timeout in seconds
        """
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._client: Optional[httpx.AsyncClient] = None
        self._tn_cache = TNLookupCache()

    async def __aenter__(self) -> "IssuerClient":
        """Async context manager entry."""
        self._client = httpx.AsyncClient(
            base_url=self._base_url,
            timeout=self._timeout,
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit."""
        if self._client:
            await self._client.aclose()
            self._client = None

    async def lookup_tn(self, tn: str, api_key: str) -> TNLookupResult:
        """Look up TN mapping from issuer.

        Results are cached for TN_CACHE_TTL seconds to reduce call setup
        latency on repeated calls for the same number.

        Args:
            tn: E.164 telephone number
            api_key: VVP API key for authentication

        Returns:
            TNLookupResult with mapping data or error
        """
        # Check cache first
        cached = self._tn_cache.get(tn)
        if cached is not None:
            log.info(f"TN cache hit for {tn} (cache size={self._tn_cache.size})")
            return cached

        if not self._client:
            log.error(f"TN lookup for {tn}: client not initialized")
            return TNLookupResult(found=False, error="Client not initialized")

        t0 = time.monotonic()
        url = f"{self._base_url}/tn/lookup"
        log.info(f"TN lookup START: tn={tn}, url={url}, timeout={self._timeout}s")

        try:
            response = await self._client.post(
                "/tn/lookup",
                json={"tn": tn, "api_key": api_key},
            )
            elapsed = (time.monotonic() - t0) * 1000

            if response.status_code == 200:
                data = response.json()
                result = TNLookupResult(
                    found=data.get("found", False),
                    tn=data.get("tn"),
                    organization_id=data.get("organization_id"),
                    organization_name=data.get("organization_name"),
                    dossier_said=data.get("dossier_said"),
                    identity_name=data.get("identity_name"),
                    brand_name=data.get("brand_name"),
                    brand_logo_url=data.get("brand_logo_url"),
                    error=data.get("error"),
                )
                log.info(f"TN lookup OK: tn={tn}, found={result.found}, brand={result.brand_name}, elapsed={elapsed:.0f}ms")
                # Cache successful lookups
                self._tn_cache.put(tn, result)
                return result
            else:
                try:
                    data = response.json()
                    error = data.get("error") or data.get("detail") or f"HTTP {response.status_code}"
                except Exception:
                    error = f"HTTP {response.status_code}"
                log.warning(f"TN lookup FAILED: tn={tn}, status={response.status_code}, error={error}, elapsed={elapsed:.0f}ms")
                return TNLookupResult(found=False, error=error)

        except httpx.TimeoutException:
            elapsed = (time.monotonic() - t0) * 1000
            log.error(f"TN lookup TIMEOUT: tn={tn}, elapsed={elapsed:.0f}ms, timeout={self._timeout}s, url={url}")
            return TNLookupResult(found=False, error="Timeout")
        except httpx.ConnectError as e:
            elapsed = (time.monotonic() - t0) * 1000
            log.error(f"TN lookup CONNECT_ERROR: tn={tn}, elapsed={elapsed:.0f}ms, url={url}, error={e}")
            return TNLookupResult(found=False, error=f"Connect error: {e}")
        except Exception as e:
            elapsed = (time.monotonic() - t0) * 1000
            log.error(f"TN lookup ERROR: tn={tn}, elapsed={elapsed:.0f}ms, error={type(e).__name__}: {e}")
            return TNLookupResult(found=False, error=str(e))

    async def create_vvp(
        self,
        api_key: str,
        identity_name: str,
        dossier_said: str,
        orig_tn: str,
        dest_tn: str,
    ) -> VVPCreateResult:
        """Create VVP headers via issuer API.

        Args:
            api_key: Org API key for authentication (dossier_manager role)
            identity_name: KERI identity name for signing
            dossier_said: Root credential SAID for dossier
            orig_tn: Originating telephone number
            dest_tn: Destination telephone number

        Returns:
            VVPCreateResult with VVP headers or error
        """
        if not self._client:
            log.error("VVP create: client not initialized")
            return VVPCreateResult(success=False, error="Client not initialized")

        if not api_key:
            log.error("VVP create: no API key provided")
            return VVPCreateResult(success=False, error="API key required")

        t0 = time.monotonic()
        log.info(f"VVP create START: identity={identity_name}, dossier={dossier_said[:16]}..., orig={orig_tn}, dest={dest_tn}")

        try:
            response = await self._client.post(
                "/vvp/create",
                json={
                    "identity_name": identity_name,
                    "dossier_said": dossier_said,
                    "orig_tn": orig_tn,
                    "dest_tn": [dest_tn],  # API expects list of TNs
                },
                headers={"X-API-Key": api_key},
            )
            elapsed = (time.monotonic() - t0) * 1000

            if response.status_code == 200:
                data = response.json()
                log.info(f"VVP create OK: orig={orig_tn}, elapsed={elapsed:.0f}ms")
                return VVPCreateResult(
                    success=True,
                    vvp_identity=data.get("vvp_identity_header"),
                    vvp_passport=data.get("passport_jwt"),
                )
            else:
                try:
                    data = response.json()
                    error = data.get("error") or data.get("detail") or f"HTTP {response.status_code}"
                except Exception:
                    error = f"HTTP {response.status_code}"
                log.warning(f"VVP create FAILED: status={response.status_code}, error={error}, elapsed={elapsed:.0f}ms")
                return VVPCreateResult(success=False, error=error)

        except httpx.TimeoutException:
            elapsed = (time.monotonic() - t0) * 1000
            log.error(f"VVP create TIMEOUT: elapsed={elapsed:.0f}ms, timeout={self._timeout}s")
            return VVPCreateResult(success=False, error="Timeout")
        except httpx.ConnectError as e:
            elapsed = (time.monotonic() - t0) * 1000
            log.error(f"VVP create CONNECT_ERROR: elapsed={elapsed:.0f}ms, error={e}")
            return VVPCreateResult(success=False, error=f"Connect error: {e}")
        except Exception as e:
            elapsed = (time.monotonic() - t0) * 1000
            log.error(f"VVP create ERROR: elapsed={elapsed:.0f}ms, error={type(e).__name__}: {e}")
            return VVPCreateResult(success=False, error=str(e))


# Global client instance
_client: Optional[IssuerClient] = None


async def get_issuer_client() -> IssuerClient:
    """Get or create the global issuer client."""
    global _client
    if _client is None:
        _client = IssuerClient()
        await _client.__aenter__()
    return _client


async def close_issuer_client() -> None:
    """Close the global issuer client."""
    global _client
    if _client is not None:
        await _client.__aexit__(None, None, None)
        _client = None
