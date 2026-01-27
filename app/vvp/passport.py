"""
PASSporT JWT parser and validator per spec §5.0-§5.4.

Parses and validates VVP PASSporT JWTs. Signature verification is deferred
to Phase 4 (requires KERI key state).

Sprint 12: Added E.164 phone validation (§4.2), orig.tn/dest.tn validation,
typ header validation (RFC8225).
"""

import base64
import json
import re
import time
from dataclasses import dataclass
from typing import Any, List, Optional

# E.164 phone number format: +[1-9][0-9]{1,14}
# Per ITU-T E.164: 1-15 digits total, must start with non-zero
E164_PATTERN = re.compile(r"^\+[1-9]\d{1,14}$")

from app.core.config import (
    ALLOW_PASSPORT_EXP_OMISSION,
    ALLOWED_ALGORITHMS,
    CLOCK_SKEW_SECONDS,
    FORBIDDEN_ALGORITHMS,
    MAX_IAT_DRIFT_SECONDS,
    MAX_PASSPORT_VALIDITY_SECONDS,
    MAX_TOKEN_AGE_SECONDS,
)
from app.vvp.exceptions import PassportError
from app.vvp.header import VVPIdentity


@dataclass(frozen=True)
class PassportHeader:
    """Decoded PASSporT JWT header."""
    alg: str
    ppt: str
    kid: str
    typ: Optional[str] = None  # Not validated per v1.4


@dataclass(frozen=True)
class PassportPayload:
    """Decoded PASSporT JWT payload."""
    iat: int
    orig: Optional[dict] = None    # Required by local policy
    dest: Optional[dict] = None    # Required by local policy
    evd: Optional[str] = None      # Required by local policy
    iss: Optional[str] = None
    exp: Optional[int] = None
    card: Optional[dict] = None
    goal: Optional[str] = None
    call_reason: Optional[str] = None  # Mapped from "call-reason"
    origid: Optional[str] = None


@dataclass(frozen=True)
class Passport:
    """Parsed VVP PASSporT."""
    header: PassportHeader
    payload: PassportPayload
    signature: bytes
    raw_header: str      # Base64url-encoded header (for signature verification)
    raw_payload: str     # Base64url-encoded payload (for signature verification)
    warnings: tuple[str, ...] = ()  # Validation warnings (e.g., non-E.164 phone numbers)


def parse_passport(jwt: Optional[str]) -> Passport:
    """Parse and validate a VVP PASSporT JWT.

    Args:
        jwt: The PASSporT JWT string (header.payload.signature).

    Returns:
        Passport dataclass with parsed header, payload, and signature.

    Raises:
        PassportError: With appropriate error code on failure.

    Note:
        Signature verification is NOT performed here (deferred to Phase 4).
        This function validates structure, algorithm, and required field presence.
    """
    # Step 1: Check for missing/empty JWT
    if not jwt or not jwt.strip():
        raise PassportError.missing()

    jwt = jwt.strip()

    # Step 2: Split into parts
    parts = jwt.split(".")
    if len(parts) != 3:
        raise PassportError.parse_failed(
            f"JWT must have 3 parts (header.payload.signature), got {len(parts)}"
        )

    raw_header, raw_payload, raw_signature = parts

    # Step 3: Decode and parse header
    header_data = _decode_jwt_part(raw_header, "header")
    header = _parse_header(header_data)

    # Step 4: Validate algorithm
    _validate_algorithm(header.alg)

    # Step 5: Validate ppt is "vvp"
    if header.ppt != "vvp":
        raise PassportError.parse_failed(
            f"ppt must be 'vvp' for VVP PASSporTs, got '{header.ppt}'"
        )

    # Step 6: Decode and parse payload
    payload_data = _decode_jwt_part(raw_payload, "payload")
    payload, warnings = _parse_payload(payload_data)

    # Step 7: Decode signature (keep as bytes for Phase 4)
    signature = _decode_signature(raw_signature)

    return Passport(
        header=header,
        payload=payload,
        signature=signature,
        raw_header=raw_header,
        raw_payload=raw_payload,
        warnings=tuple(warnings),
    )


def validate_passport_binding(
    passport: Passport,
    vvp_identity: VVPIdentity,
    now: Optional[int] = None
) -> None:
    """Validate binding between PASSporT and VVP-Identity per §5.2.

    Args:
        passport: Parsed PASSporT.
        vvp_identity: Parsed VVP-Identity header.
        now: Current timestamp (defaults to time.time()).

    Raises:
        PassportError: If binding validation fails.

    Validates (Normative per spec):
        - ppt in PASSporT matches VVP-Identity ppt (§5.2)
        - kid in PASSporT matches VVP-Identity kid (§5.2) - strict equality
        - iat drift ≤ 5 seconds (§5.2A) - binding violation
        - exp consistency (§5.2A) - binding violation
        - PASSporT not expired (§5.2B) - expiry policy
    """
    if now is None:
        now = int(time.time())

    # §5.2: ppt binding
    if passport.header.ppt != vvp_identity.ppt:
        raise PassportError.parse_failed(
            f"ppt mismatch: PASSporT has '{passport.header.ppt}', "
            f"VVP-Identity has '{vvp_identity.ppt}'"
        )

    # §5.2: kid binding (strict equality in Phase 3)
    if passport.header.kid != vvp_identity.kid:
        raise PassportError.parse_failed(
            f"kid mismatch: PASSporT has '{passport.header.kid}', "
            f"VVP-Identity has '{vvp_identity.kid}'"
        )

    # §5.2A: iat drift
    iat_drift = abs(passport.payload.iat - vvp_identity.iat)
    if iat_drift > MAX_IAT_DRIFT_SECONDS:
        raise PassportError.parse_failed(
            f"iat drift exceeds {MAX_IAT_DRIFT_SECONDS}s: "
            f"PASSporT iat={passport.payload.iat}, VVP-Identity iat={vvp_identity.iat}, "
            f"drift={iat_drift}s"
        )

    # §5.2A: exp > iat (if exp present)
    if passport.payload.exp is not None:
        if passport.payload.exp <= passport.payload.iat:
            raise PassportError.parse_failed(
                f"exp must be greater than iat: exp={passport.payload.exp}, "
                f"iat={passport.payload.iat}"
            )

    # §5.2A: exp consistency between PASSporT and VVP-Identity
    passport_exp = passport.payload.exp
    # VVP-Identity exp is always present (computed if absent in Phase 2)
    identity_exp = vvp_identity.exp

    if passport_exp is not None:
        # Both have exp: check drift
        exp_drift = abs(passport_exp - identity_exp)
        if exp_drift > MAX_IAT_DRIFT_SECONDS:
            raise PassportError.parse_failed(
                f"exp drift exceeds {MAX_IAT_DRIFT_SECONDS}s: "
                f"PASSporT exp={passport_exp}, VVP-Identity exp={identity_exp}, "
                f"drift={exp_drift}s"
            )
    else:
        # PASSporT exp absent - check if VVP-Identity had explicit exp
        # §5.2A: "If VVP-Identity exp is present but PASSporT exp is absent,
        # the verifier MUST treat the PASSporT as expired unless explicitly
        # configured to allow exp omission (default: reject)."
        if vvp_identity.exp_provided and not ALLOW_PASSPORT_EXP_OMISSION:
            raise PassportError.expired(
                f"PASSporT exp absent but VVP-Identity exp explicitly provided "
                f"(VVP-Identity exp={identity_exp}); configure ALLOW_PASSPORT_EXP_OMISSION "
                f"to permit this"
            )

    # §5.2B: Expiry policy
    _validate_expiry(passport, now)


def _decode_jwt_part(encoded: str, part_name: str) -> dict[str, Any]:
    """Decode a base64url-encoded JWT part to a dictionary."""
    try:
        # Add padding if needed
        padded = encoded + "=" * (-len(encoded) % 4)
        decoded_bytes = base64.urlsafe_b64decode(padded)
    except Exception as e:
        raise PassportError.parse_failed(f"{part_name} base64url decode failed: {e}")

    try:
        parsed = json.loads(decoded_bytes)
        if not isinstance(parsed, dict):
            raise PassportError.parse_failed(f"{part_name} JSON root must be an object")
        return parsed
    except json.JSONDecodeError as e:
        raise PassportError.parse_failed(f"{part_name} JSON parse failed: {e}")
    except UnicodeDecodeError as e:
        raise PassportError.parse_failed(f"{part_name} invalid UTF-8: {e}")


def _decode_signature(encoded: str) -> bytes:
    """Decode a PASSporT signature to bytes.

    VVP PASSporT signatures may use either:
    1. CESR encoding with derivation code prefix (88 chars for Ed25519)
    2. Standard JWS base64url encoding

    Per VVP §6.3.1, PSS (PASSporT-Specific Signatures) use CESR format.
    This function auto-detects the format based on length and prefix.

    Args:
        encoded: Signature string (CESR or base64url).

    Returns:
        Raw signature bytes.

    Raises:
        PassportError: If decoding fails.
    """
    from app.vvp.keri.cesr import decode_pss_signature
    from app.vvp.keri.exceptions import ResolutionFailedError

    # Check for CESR-encoded PSS signature (88 chars with valid code prefix)
    cesr_codes = ("0A", "0B", "0C", "0D", "AA")
    if len(encoded) == 88 and encoded[:2] in cesr_codes:
        try:
            return decode_pss_signature(encoded)
        except ResolutionFailedError as e:
            raise PassportError.parse_failed(f"CESR signature decode failed: {e}")

    # Standard JWS base64url encoding
    try:
        padded = encoded + "=" * (-len(encoded) % 4)
        return base64.urlsafe_b64decode(padded)
    except Exception as e:
        raise PassportError.parse_failed(f"signature base64url decode failed: {e}")


def _parse_header(data: dict[str, Any]) -> PassportHeader:
    """Parse and validate JWT header fields."""
    # Required fields
    alg = _require_string(data, "alg", "header")
    ppt = _require_string(data, "ppt", "header")
    kid = _require_string(data, "kid", "header")

    # Optional field - typ validation per RFC8225
    typ = data.get("typ")
    if typ is not None and not isinstance(typ, str):
        typ = None  # Ignore non-string typ

    # Validate typ if present (must be "passport" per RFC8225)
    _validate_typ_header(typ)

    return PassportHeader(alg=alg, ppt=ppt, kid=kid, typ=typ)


def _parse_payload(data: dict[str, Any]) -> tuple[PassportPayload, list[str]]:
    """Parse and validate JWT payload fields.

    Returns:
        Tuple of (PassportPayload, list of warning messages).
    """
    warnings = []

    # Required by spec §5.2A
    iat = _require_integer(data, "iat", "payload")

    # Required by local policy (VVP-draft)
    orig = _require_dict(data, "orig", "payload")
    dest = _require_dict(data, "dest", "payload")

    # Evidence URL: support both formats
    # 1. Top-level "evd" field (simple format)
    # 2. "attest.creds[0]" with "evd:" prefix (VVP 1.0 format)
    evd = data.get("evd")
    if evd is None:
        # Try attest.creds format
        attest = data.get("attest")
        if isinstance(attest, dict):
            creds = attest.get("creds")
            if isinstance(creds, list) and len(creds) > 0:
                cred = creds[0]
                if isinstance(cred, str) and cred.startswith("evd:"):
                    evd = cred[4:]  # Strip "evd:" prefix
    if evd is None or not isinstance(evd, str) or evd == "":
        raise PassportError.parse_failed("payload missing required field: evd (or attest.creds)")

    # Validate phone number fields per VVP §4.2
    warnings.extend(_validate_orig_tn_field(orig))
    warnings.extend(_validate_dest_tn_field(dest))

    # Optional fields
    iss = data.get("iss")
    if iss is not None and not isinstance(iss, str):
        iss = None

    exp = _get_optional_integer(data, "exp", "payload")
    card = data.get("card") if isinstance(data.get("card"), dict) else None
    goal = data.get("goal") if isinstance(data.get("goal"), str) else None

    # Map "call-reason" to call_reason
    call_reason = data.get("call-reason")
    if call_reason is not None and not isinstance(call_reason, str):
        call_reason = None

    origid = data.get("origid")
    if origid is not None and not isinstance(origid, str):
        origid = None

    payload = PassportPayload(
        iat=iat,
        orig=orig,
        dest=dest,
        evd=evd,
        iss=iss,
        exp=exp,
        card=card,
        goal=goal,
        call_reason=call_reason,
        origid=origid,
    )
    return payload, warnings


def _validate_algorithm(alg: str) -> None:
    """Validate algorithm per §5.0, §5.1."""
    # Check forbidden algorithms
    if alg in FORBIDDEN_ALGORITHMS or alg == "none":
        raise PassportError.forbidden_alg(alg)

    # Check allowed algorithms
    if alg not in ALLOWED_ALGORITHMS:
        raise PassportError.forbidden_alg(alg)


def _validate_typ_header(typ: Optional[str]) -> None:
    """Validate typ header per RFC8225 and VVP §4.2.

    Per RFC8225: typ MUST be "passport" when present.
    Per VVP §4.2: PASSporTs MUST comply with RFC8225.

    Args:
        typ: The typ header value (may be None).

    Raises:
        PassportError: If typ is present but not "passport".
    """
    if typ is not None and typ != "passport":
        raise PassportError.parse_failed(
            f"typ must be 'passport' when present, got '{typ}'"
        )


def _validate_phone_format(phone: str) -> bool:
    """Validate E.164 phone number format per VVP §4.2.

    E.164 format: +[1-9][0-9]{1,14}
    - Starts with +
    - First digit after + must be 1-9 (no leading zeros)
    - Total 1-15 digits (excluding +)

    Args:
        phone: Phone number string to validate.

    Returns:
        True if valid E.164 format.
    """
    return bool(E164_PATTERN.match(phone))


def _validate_orig_tn_field(orig: dict) -> list[str]:
    """Validate orig.tn field per VVP §4.2.

    Per spec:
    - orig.tn MUST be an array containing exactly one phone number
    - The single phone number SHOULD be in E.164 format (warning if not)

    Args:
        orig: The orig claim object.

    Returns:
        List of warning messages (empty if fully compliant).

    Raises:
        PassportError: If orig.tn is missing, not a single-element array,
                       or element is not a string.
    """
    warnings = []

    if "tn" not in orig:
        raise PassportError.parse_failed("payload orig.tn is required")

    tn = orig["tn"]

    # orig.tn MUST be an array
    if not isinstance(tn, list):
        raise PassportError.parse_failed(
            f"orig.tn must be an array, got {type(tn).__name__}"
        )

    # orig.tn array MUST contain exactly one element
    if len(tn) != 1:
        raise PassportError.parse_failed(
            f"orig.tn must contain exactly one phone number, got {len(tn)}"
        )

    phone = tn[0]
    if not isinstance(phone, str):
        raise PassportError.parse_failed(
            f"orig.tn[0] must be a string, got {type(phone).__name__}"
        )

    # E.164 format is recommended but not required - warn if not compliant
    if not _validate_phone_format(phone):
        warnings.append(
            f"orig.tn[0] is not E.164 format (+[1-9][0-9]{{1,14}}): '{phone}'"
        )

    return warnings


def _validate_dest_tn_field(dest: dict) -> list[str]:
    """Validate dest.tn field per RFC8225.

    Per RFC8225:
    - dest.tn MUST be an array of phone numbers
    - Each phone number SHOULD be in E.164 format (warning if not)
    - Array must not be empty

    Args:
        dest: The dest claim object.

    Returns:
        List of warning messages (empty if fully compliant).

    Raises:
        PassportError: If dest.tn is missing, not an array, empty,
                       or contains non-string elements.
    """
    warnings = []

    if "tn" not in dest:
        raise PassportError.parse_failed("payload dest.tn is required")

    tn = dest["tn"]

    # dest.tn MUST be an array
    if not isinstance(tn, list):
        raise PassportError.parse_failed(
            f"dest.tn must be an array, got {type(tn).__name__}"
        )

    if len(tn) == 0:
        raise PassportError.parse_failed("dest.tn array must not be empty")

    # Validate each phone number
    for i, phone in enumerate(tn):
        if not isinstance(phone, str):
            raise PassportError.parse_failed(
                f"dest.tn[{i}] must be a string, got {type(phone).__name__}"
            )
        # E.164 format is recommended but not required - warn if not compliant
        if not _validate_phone_format(phone):
            warnings.append(
                f"dest.tn[{i}] is not E.164 format: '{phone}'"
            )

    return warnings


def _validate_expiry(passport: Passport, now: int) -> None:
    """Validate expiry per §5.2B."""
    iat = passport.payload.iat
    exp = passport.payload.exp

    if exp is not None:
        # §5.2B: exp - iat must be ≤ MAX_PASSPORT_VALIDITY_SECONDS
        validity_window = exp - iat
        if validity_window > MAX_PASSPORT_VALIDITY_SECONDS:
            raise PassportError.expired(
                f"validity window exceeds {MAX_PASSPORT_VALIDITY_SECONDS}s: "
                f"exp - iat = {validity_window}s"
            )

        # §5.2B: now > exp + CLOCK_SKEW_SECONDS means expired
        if now > exp + CLOCK_SKEW_SECONDS:
            raise PassportError.expired(
                f"token expired: now={now}, exp={exp}, clock_skew={CLOCK_SKEW_SECONDS}"
            )
    else:
        # §5.2B: exp absent, check max-age policy
        max_age_deadline = iat + MAX_TOKEN_AGE_SECONDS + CLOCK_SKEW_SECONDS
        if now > max_age_deadline:
            raise PassportError.expired(
                f"max-age exceeded: now={now}, iat={iat}, "
                f"max_age={MAX_TOKEN_AGE_SECONDS}, clock_skew={CLOCK_SKEW_SECONDS}"
            )


def _require_string(data: dict[str, Any], field: str, part: str) -> str:
    """Require a non-empty string field."""
    if field not in data:
        raise PassportError.parse_failed(f"{part} missing required field: {field}")
    value = data[field]
    if not isinstance(value, str):
        raise PassportError.parse_failed(f"{part} field {field} must be a string")
    if not value.strip():
        raise PassportError.parse_failed(f"{part} field {field} must not be empty")
    return value


def _require_integer(data: dict[str, Any], field: str, part: str) -> int:
    """Require an integer field."""
    if field not in data:
        raise PassportError.parse_failed(f"{part} missing required field: {field}")
    value = data[field]
    if isinstance(value, bool):
        raise PassportError.parse_failed(f"{part} field {field} must be an integer")
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    raise PassportError.parse_failed(f"{part} field {field} must be an integer")


def _require_dict(data: dict[str, Any], field: str, part: str) -> dict:
    """Require a dict field (local policy)."""
    if field not in data:
        raise PassportError.parse_failed(f"{part} missing required field: {field}")
    value = data[field]
    if not isinstance(value, dict):
        raise PassportError.parse_failed(f"{part} field {field} must be an object")
    return value


def _get_optional_integer(data: dict[str, Any], field: str, part: str) -> Optional[int]:
    """Get an optional integer field."""
    if field not in data:
        return None
    value = data[field]
    if isinstance(value, bool):
        raise PassportError.parse_failed(f"{part} field {field} must be an integer")
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    raise PassportError.parse_failed(f"{part} field {field} must be an integer")
