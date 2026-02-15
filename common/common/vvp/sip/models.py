"""SIP protocol data models.

Sprint 44: Shared dataclasses for SIP requests and responses.
Supports both signing (X-VVP-API-Key) and verification (Identity, P-VVP-*) headers.
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class SIPRequest:
    """Parsed SIP INVITE request.

    Extracts the essential information needed for VVP redirect:
    - Telephone numbers from From/To URIs
    - Authentication via X-VVP-API-Key header (signing)
    - VVP verification headers (Identity, P-VVP-*)
    - Transaction headers for response (Via, From, To, Call-ID, CSeq)
    """

    method: str
    request_uri: str
    sip_version: str = "SIP/2.0"

    # Required transaction headers (RFC 3261)
    via: list[str] = field(default_factory=list)
    from_header: str = ""
    to_header: str = ""
    call_id: str = ""
    cseq: str = ""

    # Extracted telephone numbers (E.164 normalized)
    from_tn: Optional[str] = None
    to_tn: Optional[str] = None

    # VVP Signing header (Sprint 42)
    vvp_api_key: Optional[str] = None

    # VVP Verification headers (Sprint 44)
    identity_header: Optional[str] = None      # RFC 8224 Identity header
    p_vvp_identity: Optional[str] = None       # P-VVP-Identity (base64url JSON)
    p_vvp_passport: Optional[str] = None       # P-VVP-Passport (JWT)

    # Optional headers
    contact: Optional[str] = None
    content_length: int = 0

    # All headers dict (Sprint 48: for monitoring dashboard event capture)
    headers: dict = field(default_factory=dict)

    # Source address (Sprint 48: for monitoring dashboard event capture)
    source_addr: Optional[str] = None

    # Raw message for debugging
    raw: bytes = b""

    @property
    def is_invite(self) -> bool:
        """Check if this is an INVITE request."""
        return self.method.upper() == "INVITE"

    @property
    def has_verification_headers(self) -> bool:
        """Check if this request has VVP verification headers.

        Used to route between signing and verification handlers.
        A request has verification headers if any of the following are present:
        - Identity header (RFC 8224)
        - P-VVP-Identity header
        - P-VVP-Passport header
        """
        return (
            self.identity_header is not None
            or self.p_vvp_identity is not None
            or self.p_vvp_passport is not None
        )

    @property
    def has_signing_headers(self) -> bool:
        """Check if this request has VVP signing headers."""
        return self.vvp_api_key is not None


@dataclass
class SIPResponse:
    """SIP response for redirect.

    RFC 3261 requires copying these headers from request:
    - Via (all headers, in order)
    - From (exactly as received)
    - To (with tag added if not present)
    - Call-ID (exactly as received)
    - CSeq (exactly as received)
    """

    status_code: int
    reason_phrase: str
    sip_version: str = "SIP/2.0"

    # Required headers (copied from request)
    via: list[str] = field(default_factory=list)
    from_header: str = ""
    to_header: str = ""
    call_id: str = ""
    cseq: str = ""

    # Response-specific headers
    contact: Optional[str] = None

    # RFC 8224 Identity header (Sprint 57: STIR compliance)
    identity: Optional[str] = None

    # VVP headers for 302 redirect
    vvp_identity: Optional[str] = None
    vvp_passport: Optional[str] = None
    vvp_status: str = "INDETERMINATE"  # VALID | INVALID | INDETERMINATE
    brand_name: Optional[str] = None
    brand_logo_url: Optional[str] = None
    caller_id: Optional[str] = None  # Sprint 44: X-VVP-Caller-ID

    # Sprint 62: Vetter constraint status
    vetter_status: Optional[str] = None  # PASS | FAIL-ECC | FAIL-JURISDICTION | FAIL-ECC-JURISDICTION | INDETERMINATE

    # Error info (for non-2xx responses)
    error_reason: Optional[str] = None
    error_code: Optional[str] = None  # Sprint 44: X-VVP-Error code

    def to_bytes(self) -> bytes:
        """Serialize response to SIP message bytes."""
        lines = []

        # Status line
        lines.append(f"{self.sip_version} {self.status_code} {self.reason_phrase}")

        # Required headers (copied from request per RFC 3261)
        for via in self.via:
            lines.append(f"Via: {via}")
        lines.append(f"From: {self.from_header}")
        lines.append(f"To: {self.to_header}")
        lines.append(f"Call-ID: {self.call_id}")
        lines.append(f"CSeq: {self.cseq}")

        # Response-specific headers
        if self.contact:
            lines.append(f"Contact: {self.contact}")

        # RFC 8224 Identity header (Sprint 57)
        if self.identity:
            lines.append(f"Identity: {self.identity}")

        # VVP headers for 302 redirect
        if self.vvp_identity:
            lines.append(f"P-VVP-Identity: {self.vvp_identity}")
        if self.vvp_passport:
            lines.append(f"P-VVP-Passport: {self.vvp_passport}")
        if self.brand_name:
            lines.append(f"X-VVP-Brand-Name: {self.brand_name}")
        if self.brand_logo_url:
            lines.append(f"X-VVP-Brand-Logo: {self.brand_logo_url}")
        if self.caller_id:
            lines.append(f"X-VVP-Caller-ID: {self.caller_id}")

        # Always include VVP status
        lines.append(f"X-VVP-Status: {self.vvp_status}")

        # Sprint 62: Vetter constraint status
        if self.vetter_status:
            lines.append(f"X-VVP-Vetter-Status: {self.vetter_status}")

        # Error code for INVALID status (Sprint 44)
        if self.error_code:
            lines.append(f"X-VVP-Error: {self.error_code}")

        # Content-Length (always 0 for redirects)
        lines.append("Content-Length: 0")

        # End headers
        lines.append("")
        lines.append("")

        return "\r\n".join(lines).encode("utf-8")
