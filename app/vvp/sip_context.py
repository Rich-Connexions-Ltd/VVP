"""SIP Contextual Alignment per spec §5A Step 2.

This module validates that PASSporT claims align with SIP INVITE metadata:
- orig.tn matches SIP From URI
- dest.tn contains SIP To URI
- iat aligns with SIP INVITE timing (within tolerance)

Per §4.4, SIP context is optional. When absent, context_aligned is INDETERMINATE.
When provided, mismatches result in INVALID with CONTEXT_MISMATCH error.
"""

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional, Tuple
from urllib.parse import urlparse, unquote

from .api_models import ClaimStatus, ErrorCode

log = logging.getLogger(__name__)


@dataclass
class ClaimBuilder:
    """Accumulates evidence and failures for a single claim.

    Mirrors the ClaimBuilder in verify.py for consistency.
    """

    name: str
    status: ClaimStatus = ClaimStatus.VALID
    reasons: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)

    def fail(self, status: ClaimStatus, reason: str) -> None:
        """Record a failure. INVALID always wins over INDETERMINATE."""
        if status == ClaimStatus.INVALID:
            self.status = ClaimStatus.INVALID
        elif status == ClaimStatus.INDETERMINATE and self.status == ClaimStatus.VALID:
            self.status = ClaimStatus.INDETERMINATE
        self.reasons.append(reason)

    def add_evidence(self, ev: str) -> None:
        """Add evidence string."""
        self.evidence.append(ev)


# Pattern to extract phone number from various formats
# Matches: +15551234567, 15551234567, +1-555-123-4567, etc.
PHONE_PATTERN = re.compile(r"^\+?[\d\-\.\s\(\)]+$")

# E.164 normalization: keep only digits and leading +
E164_CHARS = set("0123456789+")


def _normalize_to_e164(phone: str) -> str:
    """Normalize phone number to E.164 format.

    Strips visual separators (-, spaces, parens, dots) and ensures
    the result contains only digits with optional leading +.

    Args:
        phone: Phone number in various formats

    Returns:
        Normalized E.164 format (e.g., "+15551234567")
    """
    # Keep only digits and +
    normalized = "".join(c for c in phone if c in E164_CHARS)

    # Ensure leading + if it looks like an international number
    if normalized and not normalized.startswith("+") and len(normalized) >= 10:
        # Assume it needs a + prefix for E.164
        normalized = "+" + normalized

    return normalized


def extract_tn_from_sip_uri(uri: str) -> Optional[str]:
    """Extract phone number from SIP or TEL URI.

    Supports formats per RFC 3261 and RFC 3966:
    - sip:+15551234567@domain.com
    - sip:15551234567@domain.com;user=phone
    - tel:+15551234567
    - tel:+1-555-123-4567 (with visual separators)

    Args:
        uri: SIP or TEL URI string

    Returns:
        Normalized E.164 phone number, or None if extraction fails
    """
    if not uri:
        return None

    uri = uri.strip()

    # Handle tel: URI (RFC 3966)
    if uri.lower().startswith("tel:"):
        # tel:+1-555-123-4567;param=value
        phone_part = uri[4:]  # Remove "tel:"
        # Strip URI parameters (after ;)
        if ";" in phone_part:
            phone_part = phone_part.split(";")[0]
        phone_part = unquote(phone_part)
        return _normalize_to_e164(phone_part)

    # Handle sip: or sips: URI (RFC 3261)
    if uri.lower().startswith(("sip:", "sips:")):
        try:
            parsed = urlparse(uri)
            user_part = parsed.username or parsed.path.split("@")[0]

            # URL decode the user part
            user_part = unquote(user_part)

            # Strip any URI parameters from user part
            if ";" in user_part:
                user_part = user_part.split(";")[0]

            # Check if it looks like a phone number
            if PHONE_PATTERN.match(user_part):
                return _normalize_to_e164(user_part)

            # If no username, try extracting from path
            if not user_part and "@" in parsed.path:
                user_part = parsed.path.split("@")[0]
                user_part = unquote(user_part)
                if PHONE_PATTERN.match(user_part):
                    return _normalize_to_e164(user_part)

        except Exception as e:
            log.debug(f"Failed to parse SIP URI '{uri[:50]}...': {e}")
            return None

    # Fallback: if it looks like a phone number directly
    if PHONE_PATTERN.match(uri):
        return _normalize_to_e164(uri)

    return None


def validate_orig_alignment(
    passport_orig_tn: str, sip_from_uri: str
) -> Tuple[bool, str]:
    """Validate PASSporT orig.tn matches SIP From URI.

    Per §5.1.1-2.2: MUST confirm orig claim matches SIP From URI.

    Args:
        passport_orig_tn: Phone number from PASSporT orig.tn
        sip_from_uri: SIP From URI

    Returns:
        Tuple of (is_valid, evidence_or_reason)
    """
    from_tn = extract_tn_from_sip_uri(sip_from_uri)

    if from_tn is None:
        return False, f"Could not extract phone from SIP From URI: {sip_from_uri[:50]}"

    # Normalize both for comparison
    orig_normalized = _normalize_to_e164(passport_orig_tn)

    if orig_normalized == from_tn:
        return True, f"orig_aligned:{orig_normalized}"
    else:
        return False, f"orig.tn '{orig_normalized}' != From URI '{from_tn}'"


def validate_dest_alignment(
    passport_dest_tns: List[str], sip_to_uri: str
) -> Tuple[bool, str]:
    """Validate SIP To URI is contained in PASSporT dest.tn array.

    Per §5.1.1-2.2: MUST confirm dest claim matches SIP To URI.

    Args:
        passport_dest_tns: Array of phone numbers from PASSporT dest.tn
        sip_to_uri: SIP To URI

    Returns:
        Tuple of (is_valid, evidence_or_reason)
    """
    to_tn = extract_tn_from_sip_uri(sip_to_uri)

    if to_tn is None:
        return False, f"Could not extract phone from SIP To URI: {sip_to_uri[:50]}"

    # Normalize all dest TNs for comparison
    normalized_dests = [_normalize_to_e164(tn) for tn in passport_dest_tns]

    if to_tn in normalized_dests:
        return True, f"dest_aligned:{to_tn}"
    else:
        return False, f"To URI '{to_tn}' not in dest.tn {normalized_dests}"


def validate_timing_alignment(
    passport_iat: int, invite_time: datetime, tolerance_seconds: int = 30
) -> Tuple[bool, str]:
    """Validate PASSporT iat aligns with SIP INVITE timing.

    Per §5.1.1-2.2: MUST confirm iat aligns with SIP INVITE timing.

    Args:
        passport_iat: PASSporT issuance time (Unix timestamp)
        invite_time: SIP INVITE timestamp
        tolerance_seconds: Maximum allowed drift (default 30s)

    Returns:
        Tuple of (is_valid, evidence_or_reason)
    """
    # Convert invite_time to Unix timestamp
    invite_ts = int(invite_time.timestamp())
    drift = abs(passport_iat - invite_ts)

    if drift <= tolerance_seconds:
        return True, f"timing_aligned:drift={drift}s"
    else:
        return (
            False,
            f"iat drift {drift}s exceeds {tolerance_seconds}s tolerance",
        )


def _parse_rfc3339(timestamp: str) -> Optional[datetime]:
    """Parse RFC3339 timestamp string to datetime.

    Args:
        timestamp: RFC3339 formatted timestamp string

    Returns:
        datetime object or None if parsing fails
    """
    try:
        # Handle various RFC3339 formats
        # Python 3.11+ supports fromisoformat with Z
        if timestamp.endswith("Z"):
            timestamp = timestamp[:-1] + "+00:00"
        return datetime.fromisoformat(timestamp)
    except (ValueError, TypeError) as e:
        log.debug(f"Failed to parse timestamp '{timestamp}': {e}")
        return None


def verify_sip_context_alignment(
    passport,  # Passport type from passport.py
    sip_context,  # Optional[SipContext]
    timing_tolerance: int = 30,
    context_required: bool = False,
) -> ClaimBuilder:
    """Verify SIP contextual alignment per §5A Step 2.

    Args:
        passport: Parsed PASSporT object
        sip_context: Optional SIP context from request
        timing_tolerance: Timing tolerance in seconds (default 30)
        context_required: If True, missing context is INVALID (from config)

    Returns:
        ClaimBuilder for `context_aligned` claim
    """
    claim = ClaimBuilder("context_aligned")

    # If SIP context not provided, check policy per §4.4
    if sip_context is None:
        if context_required:
            # Per Sprint 18 fix A1: CONTEXT_ALIGNMENT_REQUIRED=True means missing context is INVALID
            claim.fail(ClaimStatus.INVALID, "SIP context required but not provided")
        else:
            claim.fail(ClaimStatus.INDETERMINATE, "SIP context not provided")
        claim.add_evidence("sip_context:absent")
        return claim

    claim.add_evidence("sip_context:present")

    # Extract orig.tn from passport (array with single element per §4.2)
    orig_tn = None
    if passport.payload.orig and isinstance(passport.payload.orig, dict):
        tn_array = passport.payload.orig.get("tn")
        if isinstance(tn_array, list) and len(tn_array) == 1:
            orig_tn = tn_array[0]

    # Extract dest.tn from passport
    dest_tns = []
    if passport.payload.dest and isinstance(passport.payload.dest, dict):
        dest_value = passport.payload.dest.get("tn")
        if isinstance(dest_value, list):
            dest_tns = dest_value
        elif isinstance(dest_value, str):
            dest_tns = [dest_value]

    # Validate orig alignment
    if orig_tn:
        valid, evidence = validate_orig_alignment(orig_tn, sip_context.from_uri)
        if valid:
            claim.add_evidence(evidence)
        else:
            claim.fail(ClaimStatus.INVALID, evidence)
            return claim  # Early exit on first mismatch
    else:
        claim.fail(ClaimStatus.INVALID, "PASSporT missing orig.tn")
        return claim

    # Validate dest alignment
    if dest_tns:
        valid, evidence = validate_dest_alignment(dest_tns, sip_context.to_uri)
        if valid:
            claim.add_evidence(evidence)
        else:
            claim.fail(ClaimStatus.INVALID, evidence)
            return claim
    else:
        claim.fail(ClaimStatus.INVALID, "PASSporT missing dest.tn")
        return claim

    # Validate timing alignment
    invite_time = _parse_rfc3339(sip_context.invite_time)
    if invite_time is None:
        claim.fail(
            ClaimStatus.INDETERMINATE,
            f"Could not parse invite_time: {sip_context.invite_time}",
        )
        return claim

    valid, evidence = validate_timing_alignment(
        passport.payload.iat, invite_time, timing_tolerance
    )
    if valid:
        claim.add_evidence(evidence)
    else:
        claim.fail(ClaimStatus.INVALID, evidence)
        return claim

    return claim
