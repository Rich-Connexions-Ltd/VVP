"""PASSporT JWT creation per spec §5.0-§5.4.

Creates signed PASSporT JWTs with Ed25519 signatures in PSS CESR format.
This is the inverse of services/verifier/app/vvp/passport.py (parsing).
"""

import base64
import json
import re
import logging
from dataclasses import dataclass
from typing import Optional

from app.keri.identity import get_identity_manager
from app.vvp.exceptions import (
    IdentityNotAvailableError,
    InvalidPhoneNumberError,
    VVPCreationError,
)

log = logging.getLogger(__name__)

# E.164 phone number pattern per spec §4.2
E164_PATTERN = re.compile(r"^\+[1-9]\d{1,14}$")


@dataclass(frozen=True)
class PASSporT:
    """Created PASSporT JWT with metadata.

    Attributes:
        jwt: The complete JWT string (header.payload.signature)
        header: Decoded JWT header dictionary
        payload: Decoded JWT payload dictionary
        signature_cesr: The PSS CESR-encoded signature (88 chars)
    """

    jwt: str
    header: dict
    payload: dict
    signature_cesr: str


def encode_pss_signature(sig_bytes: bytes, index: int = 1) -> str:
    """Encode Ed25519 signature in PSS CESR format per §6.3.1.

    PASSporT signatures use CESR encoding with derivation codes.
    The format is: <2-char derivation code><86-char base64url signature>

    Derivation codes:
    - 0A: Ed25519 indexed signature (index 0)
    - 0B: Ed25519 indexed signature (index 1) - most common
    - 0C: Ed25519 indexed signature (index 2)
    - 0D: Ed25519 indexed signature (index 3)

    Args:
        sig_bytes: Raw 64-byte Ed25519 signature
        index: Signature index (0-3, default 1)

    Returns:
        88-char PSS CESR signature string

    Raises:
        ValueError: If signature is not 64 bytes or index out of range
    """
    if len(sig_bytes) != 64:
        raise ValueError(f"Ed25519 signature must be 64 bytes, got {len(sig_bytes)}")

    if index < 0 or index > 3:
        raise ValueError(f"Signature index must be 0-3, got {index}")

    # Derivation code: 0A=index 0, 0B=index 1, 0C=index 2, 0D=index 3
    code = f"0{chr(ord('A') + index)}"

    # Base64url encode without padding
    sig_b64 = base64.urlsafe_b64encode(sig_bytes).decode("ascii").rstrip("=")

    # Result should be 2 + 86 = 88 chars
    result = code + sig_b64
    if len(result) != 88:
        raise ValueError(f"PSS CESR signature should be 88 chars, got {len(result)}")

    return result


def _base64url_encode(data: bytes) -> str:
    """Encode bytes as base64url without padding."""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _validate_e164(phone: str, field_name: str) -> None:
    """Validate E.164 phone number format."""
    if not E164_PATTERN.match(phone):
        raise InvalidPhoneNumberError(
            f"Invalid E.164 phone number for {field_name}: {phone}. "
            f"Expected format: +[1-9][0-9]{{1,14}}"
        )


async def create_passport(
    identity_name: str,
    issuer_oobi: str,
    orig_tn: str,
    dest_tn: list[str],
    dossier_url: str,
    iat: int,
    exp: int,
    card: Optional[list[str]] = None,
    call_id: Optional[str] = None,
    cseq: Optional[int] = None,
) -> PASSporT:
    """Create a signed PASSporT JWT per §5.0-§5.4.

    The PASSporT is signed with the issuer's Ed25519 key and the signature
    is encoded in PSS CESR format (88 chars with derivation code prefix).

    Args:
        identity_name: Name of issuer identity for signing
        issuer_oobi: Full OOBI URL for kid field (MUST match VVP-Identity kid)
        orig_tn: Originating phone number in E.164 format
        dest_tn: List of destination phone numbers in E.164 format
        dossier_url: Evidence URL (MUST match VVP-Identity evd)
        iat: Issued-at timestamp (MUST match VVP-Identity iat)
        exp: Expiry timestamp (MUST match VVP-Identity exp)
        card: Optional vCard dict for brand identity (Sprint 58)
        call_id: SIP Call-ID for dialog binding (callee PASSporT §5.2)
        cseq: SIP CSeq number for dialog binding (callee PASSporT §5.2)

    Returns:
        PASSporT with JWT string and component metadata

    Raises:
        IdentityNotAvailableError: If identity not found
        InvalidPhoneNumberError: If phone numbers are not E.164 format
        VVPCreationError: If signing fails
    """
    # Validate phone numbers
    _validate_e164(orig_tn, "orig_tn")
    for i, tn in enumerate(dest_tn):
        _validate_e164(tn, f"dest_tn[{i}]")

    if not dest_tn:
        raise InvalidPhoneNumberError("dest_tn must have at least one phone number")

    # Get issuer identity
    identity_mgr = await get_identity_manager()
    hab = identity_mgr.hby.habByName(identity_name)
    if hab is None:
        raise IdentityNotAvailableError(f"Identity not found: {identity_name}")

    # Build JWT header per §5.0
    # CRITICAL: alg MUST be "EdDSA" (JOSE value), NOT "Ed25519"
    jwt_header = {
        "alg": "EdDSA",
        "ppt": "vvp",
        "kid": issuer_oobi,
        "typ": "passport",
    }

    # Build JWT payload per §5.2
    # CRITICAL: evd MUST be included and match VVP-Identity evd
    jwt_payload = {
        "iat": iat,
        "exp": exp,
        "orig": {"tn": [orig_tn]},
        "dest": {"tn": dest_tn},
        "evd": dossier_url,
    }

    # Sprint 58: Include vCard card claim if brand data is available
    if card:
        jwt_payload["card"] = card

    # Callee PASSporT dialog binding claims (§5.2)
    if call_id is not None:
        jwt_payload["call-id"] = call_id
    if cseq is not None:
        jwt_payload["cseq"] = cseq

    # Encode header and payload
    header_b64 = _base64url_encode(json.dumps(jwt_header, separators=(",", ":")).encode("utf-8"))
    payload_b64 = _base64url_encode(json.dumps(jwt_payload, separators=(",", ":")).encode("utf-8"))

    # Create signing input per JWT spec: header.payload as ASCII bytes
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")

    # Sign with issuer's Ed25519 key
    try:
        # hab.sign() returns a Cigar (non-indexed signature) by default
        # We need the raw 64-byte signature
        cigars = hab.sign(ser=signing_input, indexed=False)
        if not cigars:
            raise VVPCreationError("Signing returned no signatures")

        # Get the first signature (raw bytes)
        cigar = cigars[0]
        sig_bytes = cigar.raw  # 64-byte Ed25519 signature

    except Exception as e:
        log.error(f"Failed to sign PASSporT: {e}")
        raise VVPCreationError(f"Signing failed: {e}") from e

    # Encode signature in PSS CESR format
    sig_cesr = encode_pss_signature(sig_bytes, index=1)

    # Assemble complete JWT
    jwt = f"{header_b64}.{payload_b64}.{sig_cesr}"

    log.info(f"Created PASSporT for identity={identity_name}, orig={orig_tn}")

    return PASSporT(
        jwt=jwt,
        header=jwt_header,
        payload=jwt_payload,
        signature_cesr=sig_cesr,
    )
