"""Issuer API client.

Sprint 42: httpx-based async client for issuer service.
"""

import logging
from dataclasses import dataclass
from typing import Optional

import httpx

from app.config import ISSUER_URL, ISSUER_TIMEOUT

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


class IssuerClient:
    """Async HTTP client for VVP Issuer API.

    Provides methods for TN lookup and VVP header creation.
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

        Args:
            tn: E.164 telephone number
            api_key: VVP API key for authentication

        Returns:
            TNLookupResult with mapping data or error
        """
        if not self._client:
            return TNLookupResult(found=False, error="Client not initialized")

        try:
            response = await self._client.post(
                "/tn/lookup",
                json={"tn": tn, "api_key": api_key},
            )

            if response.status_code == 200:
                data = response.json()
                return TNLookupResult(
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
            else:
                log.warning(f"TN lookup failed: {response.status_code}")
                try:
                    data = response.json()
                    error = data.get("error") or data.get("detail") or f"HTTP {response.status_code}"
                except Exception:
                    error = f"HTTP {response.status_code}"
                return TNLookupResult(found=False, error=error)

        except httpx.TimeoutException:
            log.error("TN lookup timeout")
            return TNLookupResult(found=False, error="Timeout")
        except Exception as e:
            log.error(f"TN lookup error: {e}")
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
            return VVPCreateResult(success=False, error="Client not initialized")

        if not api_key:
            log.error("No API key provided")
            return VVPCreateResult(success=False, error="API key required")

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

            if response.status_code == 200:
                data = response.json()
                return VVPCreateResult(
                    success=True,
                    vvp_identity=data.get("vvp_identity"),
                    vvp_passport=data.get("passport"),
                )
            else:
                log.warning(f"VVP create failed: {response.status_code}")
                try:
                    data = response.json()
                    error = data.get("error") or data.get("detail") or f"HTTP {response.status_code}"
                except Exception:
                    error = f"HTTP {response.status_code}"
                return VVPCreateResult(success=False, error=error)

        except httpx.TimeoutException:
            log.error("VVP create timeout")
            return VVPCreateResult(success=False, error="Timeout")
        except Exception as e:
            log.error(f"VVP create error: {e}")
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
