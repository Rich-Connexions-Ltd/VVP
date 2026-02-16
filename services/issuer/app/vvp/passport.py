"""PASSporT JWT utilities per spec §5.0-§5.4.

Utility functions for PASSporT JWT construction. The actual signing is
delegated to the KERI Agent via KeriAgentClient.create_vvp_attestation().

Sprint 68c: Removed create_passport() (signing now delegated to KERI Agent).
Retained: encode_pss_signature, validate_e164, PASSporT dataclass.
"""

import base64
import re
import logging
from dataclasses import dataclass
from typing import Optional

from app.vvp.exceptions import (
    InvalidPhoneNumberError,
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


def validate_e164(phone: str, field_name: str) -> None:
    """Validate E.164 phone number format.

    Args:
        phone: Phone number string to validate
        field_name: Field name for error messages

    Raises:
        InvalidPhoneNumberError: If the phone number doesn't match E.164 format
    """
    if not E164_PATTERN.match(phone):
        raise InvalidPhoneNumberError(
            f"Invalid E.164 phone number for {field_name}: {phone}. "
            f"Expected format: +[1-9][0-9]{{1,14}}"
        )
