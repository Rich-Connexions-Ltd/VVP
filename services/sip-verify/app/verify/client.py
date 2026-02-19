"""Verifier API client for VVP SIP Verify Service.

Sprint 44: HTTP client for calling the VVP Verifier /verify-callee endpoint.
Sprint 50: Persistent session for connection reuse (avoids TCP/TLS per call).
"""

import asyncio
import base64
import json
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

import aiohttp

from ..config import VVP_VERIFIER_URL, VVP_VERIFIER_TIMEOUT, VVP_VERIFIER_API_KEY

log = logging.getLogger(__name__)


@dataclass
class VerifyResult:
    """Result from Verifier API call.

    Attributes:
        status: VVP verification status (VALID/INVALID/INDETERMINATE).
        brand_name: Brand name from verified PASSporT card.
        brand_logo_url: Brand logo URL from verified PASSporT card.
        caller_id: Caller ID from PASSporT orig.tn.
        error_code: Error code if status is INVALID.
        error_message: Error message if status is INVALID/INDETERMINATE.
        request_id: Verifier request ID for tracing.
    """

    status: str
    brand_name: Optional[str] = None
    brand_logo_url: Optional[str] = None
    caller_id: Optional[str] = None
    error_code: Optional[str] = None
    error_message: Optional[str] = None
    request_id: Optional[str] = None
    vetter_status: Optional[str] = None  # Sprint 62: PASS/FAIL-ECC/FAIL-JURISDICTION/...
    warning_reason: Optional[str] = None  # Sprint 75: vetter_not_authorised_for_jurisdiction when status=WARNING


@dataclass
class _CachedBrand:
    """Cached brand info from a recent verification."""

    brand_name: Optional[str]
    brand_logo_url: Optional[str]
    expires_at: float


class VerifierClient:
    """HTTP client for VVP Verifier API.

    Uses a persistent aiohttp session for connection reuse,
    avoiding TCP/TLS handshake overhead on each verification call.
    """

    def __init__(
        self,
        base_url: str = VVP_VERIFIER_URL,
        timeout: float = VVP_VERIFIER_TIMEOUT,
        api_key: str = VVP_VERIFIER_API_KEY,
    ):
        """Initialize Verifier client.

        Args:
            base_url: Base URL of the Verifier API.
            timeout: Request timeout in seconds.
            api_key: Optional API key for authentication.
        """
        self.base_url = base_url.rstrip("/")
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.api_key = api_key
        self._session: Optional[aiohttp.ClientSession] = None
        # Cache brand info by evd URL (dossier doesn't change frequently)
        self._brand_cache: dict[str, _CachedBrand] = {}
        self._brand_cache_ttl = 300  # 5 minutes

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create the persistent HTTP session."""
        if self._session is None or self._session.closed:
            connector = aiohttp.TCPConnector(
                limit=10,  # Max connections
                keepalive_timeout=60,  # Keep alive for 60s
            )
            self._session = aiohttp.ClientSession(
                timeout=self.timeout,
                connector=connector,
            )
        return self._session

    async def close(self) -> None:
        """Close the persistent session."""
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None

    def _get_cached_brand(self, evd: str) -> Optional[_CachedBrand]:
        """Get cached brand info for a dossier URL."""
        entry = self._brand_cache.get(evd)
        if entry and time.monotonic() < entry.expires_at:
            return entry
        if entry:
            del self._brand_cache[evd]
        return None

    def _cache_brand(self, evd: str, brand_name: Optional[str], brand_logo_url: Optional[str]) -> None:
        """Cache brand info from a successful verification."""
        if brand_name:
            self._brand_cache[evd] = _CachedBrand(
                brand_name=brand_name,
                brand_logo_url=brand_logo_url,
                expires_at=time.monotonic() + self._brand_cache_ttl,
            )

    def _build_vvp_identity_header(
        self,
        kid: str,
        evd: str,
        iat: int,
        exp: Optional[int] = None,
    ) -> str:
        """Build VVP-Identity header value.

        Args:
            kid: OOBI URL for key resolution.
            evd: Dossier evidence URL.
            iat: Issued-at timestamp (Unix epoch seconds). Required by verifier.
            exp: Optional expiration timestamp (Unix epoch seconds).

        Returns:
            Base64url-encoded VVP-Identity JSON.
        """
        identity = {
            "ppt": "vvp",
            "kid": kid,
            "evd": evd,
            "iat": iat,
        }
        if exp is not None:
            identity["exp"] = exp
        json_str = json.dumps(identity, separators=(",", ":"))
        encoded = base64.urlsafe_b64encode(json_str.encode()).decode()
        # Remove padding
        return encoded.rstrip("=")

    async def verify_callee(
        self,
        passport_jwt: str,
        call_id: str,
        from_uri: str,
        to_uri: str,
        invite_time: str,
        cseq: int,
        kid: str,
        evd: str,
        iat: int,
        exp: Optional[int] = None,
        caller_passport_jwt: Optional[str] = None,
    ) -> VerifyResult:
        """Call the /verify-callee endpoint.

        Args:
            passport_jwt: Callee's PASSporT JWT.
            call_id: SIP Call-ID.
            from_uri: SIP From URI.
            to_uri: SIP To URI.
            invite_time: RFC3339 timestamp of SIP INVITE.
            cseq: SIP CSeq number.
            kid: OOBI URL for key resolution.
            evd: Dossier evidence URL.
            iat: Issued-at timestamp from P-VVP-Identity (required by verifier).
            exp: Optional expiration timestamp from P-VVP-Identity.
            caller_passport_jwt: Optional caller's PASSporT for goal overlap.

        Returns:
            VerifyResult with verification outcome.
        """
        url = f"{self.base_url}/verify-callee"

        # Build request body
        request_body = {
            "passport_jwt": passport_jwt,
            "context": {
                "call_id": call_id,
                "received_at": datetime.now(timezone.utc).isoformat(),
                "sip": {
                    "from_uri": from_uri,
                    "to_uri": to_uri,
                    "invite_time": invite_time,
                    "cseq": cseq,
                },
            },
        }

        if caller_passport_jwt:
            request_body["caller_passport_jwt"] = caller_passport_jwt

        # Build headers
        headers = {
            "Content-Type": "application/json",
            "VVP-Identity": self._build_vvp_identity_header(kid, evd, iat, exp),
        }

        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        log.debug(f"Calling {url} for call_id={call_id}")

        try:
            session = await self._get_session()
            async with session.post(url, json=request_body, headers=headers) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    log.info(f"Verifier response for call_id={call_id}: status={data.get('overall_status')}, errors={data.get('errors', [])}, brand={data.get('brand_name')}, cache_hit={data.get('cache_hit')}")
                    if data.get("overall_status") != "VALID":
                        # Log claim tree for debugging
                        import json
                        claims = data.get("claims", [])
                        for claim in claims:
                            log.info(f"  claim: {claim.get('name')}={claim.get('status')}, reasons={claim.get('reasons', [])}")
                            for child in claim.get("children", []):
                                c = child.get("node", {})
                                log.info(f"    child: {c.get('name')}={c.get('status')}, reasons={c.get('reasons', [])}")
                    result = self._parse_response(data)
                    # Cache brand info from VALID and WARNING verifications
                    # WARNING = valid but vetter not authorised for jurisdiction — brand still deliverable
                    if result.status in ("VALID", "WARNING") and evd:
                        self._cache_brand(evd, result.brand_name, result.brand_logo_url)
                    return result
                else:
                    text = await resp.text()
                    log.warning(f"Verifier returned {resp.status}: {text[:200]}")
                    # On timeout/error, use cached brand if available
                    cached_brand = self._get_cached_brand(evd) if evd else None
                    if cached_brand:
                        log.info(f"Using cached brand for {evd[:50]}... (verifier returned {resp.status})")
                        return VerifyResult(
                            status="INDETERMINATE",
                            brand_name=cached_brand.brand_name,
                            brand_logo_url=cached_brand.brand_logo_url,
                            error_code="VERIFIER_ERROR",
                            error_message=f"Verifier returned HTTP {resp.status}",
                        )
                    return VerifyResult(
                        status="INDETERMINATE",
                        error_code="VERIFIER_ERROR",
                        error_message=f"Verifier returned HTTP {resp.status}",
                    )
        except asyncio.TimeoutError:
            log.warning(f"Verifier timeout for call_id={call_id}")
            # Use cached brand on timeout
            cached_brand = self._get_cached_brand(evd) if evd else None
            if cached_brand:
                log.info(f"Using cached brand for {evd[:50]}... (timeout)")
                return VerifyResult(
                    status="INDETERMINATE",
                    brand_name=cached_brand.brand_name,
                    brand_logo_url=cached_brand.brand_logo_url,
                    error_code="VERIFIER_TIMEOUT",
                    error_message="Verifier request timed out",
                )
            return VerifyResult(
                status="INDETERMINATE",
                error_code="VERIFIER_TIMEOUT",
                error_message="Verifier request timed out",
            )
        except aiohttp.ClientError as e:
            log.warning(f"Verifier connection error for call_id={call_id}: {e}")
            return VerifyResult(
                status="INDETERMINATE",
                error_code="VERIFIER_UNREACHABLE",
                error_message=str(e),
            )

    @staticmethod
    def _derive_vetter_status(constraints) -> Optional[str]:
        """Derive a single X-VVP-Vetter-Status from vetter_constraints.

        The verifier returns vetter_constraints as Dict[str, VetterConstraintInfo]
        keyed by credential SAID.  Each value has constraint_type ("ecc" or
        "jurisdiction") and is_authorized (bool).

        Deterministic precedence (FAIL > INDETERMINATE > PASS):
        - If any hard failure (cert found but unauthorized): FAIL-ECC / FAIL-JURISDICTION / FAIL-ECC-JURISDICTION
        - If any soft failure (cert missing, vetter_certification_said=None): INDETERMINATE
        - If all constraints authorized → PASS
        - If no constraints present → None (omit header)
        """
        if not constraints:
            return None

        # Accept both dict (real verifier) and list (legacy/test) shapes
        if isinstance(constraints, dict):
            entries = constraints.values()
        elif isinstance(constraints, list):
            entries = constraints
        else:
            return None

        has_ecc_fail = False
        has_jurisdiction_fail = False
        has_missing_cert = False

        for c in entries:
            if not isinstance(c, dict):
                continue
            if c.get("is_authorized"):
                continue
            # Unauthorized — distinguish missing cert from hard failure
            if c.get("vetter_certification_said") is None:
                has_missing_cert = True
            else:
                ct = c.get("constraint_type", c.get("check_type", ""))
                if "ecc" in ct.lower():
                    has_ecc_fail = True
                if "jurisdiction" in ct.lower():
                    has_jurisdiction_fail = True

        # Hard failures take precedence
        if has_ecc_fail and has_jurisdiction_fail:
            return "FAIL-ECC-JURISDICTION"
        if has_ecc_fail:
            return "FAIL-ECC"
        if has_jurisdiction_fail:
            return "FAIL-JURISDICTION"
        # Soft failure: cert missing but not a hard authorization violation
        if has_missing_cert:
            return "INDETERMINATE"
        return "PASS"

    def _parse_response(self, data: dict) -> VerifyResult:
        """Parse Verifier API response.

        Args:
            data: JSON response from Verifier.

        Returns:
            VerifyResult with extracted fields.
        """
        status = data.get("overall_status", "INDETERMINATE")
        brand_name = data.get("brand_name")
        brand_logo_url = data.get("brand_logo_url")
        request_id = data.get("request_id")

        # Extract error info
        error_code = None
        error_message = None
        errors = data.get("errors", [])
        if errors:
            first_error = errors[0]
            error_code = first_error.get("code")
            error_message = first_error.get("message")

        # Extract caller ID from claims if available
        caller_id = None
        claims = data.get("claims", [])
        if claims:
            # Look for orig.tn in evidence
            for claim in claims:
                for ev in claim.get("evidence", []):
                    if "orig_tn" in ev or "caller_tn" in ev:
                        # Parse "orig_tn:+15551234567" format
                        if ":" in ev:
                            caller_id = ev.split(":", 1)[1]
                            break

        # Sprint 62: Map vetter_constraints dict → single status string
        vetter_status = self._derive_vetter_status(data.get("vetter_constraints"))

        # Sprint 75: Extract warning reason for WARNING status
        warning_reason = data.get("vetter_warning_reason") if status == "WARNING" else None

        return VerifyResult(
            status=status,
            brand_name=brand_name,
            brand_logo_url=brand_logo_url,
            caller_id=caller_id,
            error_code=error_code,
            error_message=error_message,
            request_id=request_id,
            vetter_status=vetter_status,
            warning_reason=warning_reason,
        )


# Global client instance
_client: Optional[VerifierClient] = None


def get_verifier_client() -> VerifierClient:
    """Get or create the global Verifier client."""
    global _client
    if _client is None:
        _client = VerifierClient()
    return _client
