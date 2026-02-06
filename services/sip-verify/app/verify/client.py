"""Verifier API client for VVP SIP Verify Service.

Sprint 44: HTTP client for calling the VVP Verifier /verify-callee endpoint.
"""

import asyncio
import base64
import json
import logging
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


class VerifierClient:
    """HTTP client for VVP Verifier API."""

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
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.post(url, json=request_body, headers=headers) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return self._parse_response(data)
                    else:
                        text = await resp.text()
                        log.warning(f"Verifier returned {resp.status}: {text[:200]}")
                        return VerifyResult(
                            status="INDETERMINATE",
                            error_code="VERIFIER_ERROR",
                            error_message=f"Verifier returned HTTP {resp.status}",
                        )
        except asyncio.TimeoutError:
            log.warning(f"Verifier timeout for call_id={call_id}")
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

        return VerifyResult(
            status=status,
            brand_name=brand_name,
            brand_logo_url=brand_logo_url,
            caller_id=caller_id,
            error_code=error_code,
            error_message=error_message,
            request_id=request_id,
        )


# Global client instance
_client: Optional[VerifierClient] = None


def get_verifier_client() -> VerifierClient:
    """Get or create the global Verifier client."""
    global _client
    if _client is None:
        _client = VerifierClient()
    return _client
