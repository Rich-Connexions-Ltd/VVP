"""Parse KERI identifiers to extract verification keys.

KERI AIDs (Autonomic Identifiers) encode the public key in the identifier
itself. The first character is a derivation code indicating the algorithm,
followed by the base64url-encoded public key.

Tier 1 supports only Ed25519 keys (B and D prefix codes).
"""

import base64
from dataclasses import dataclass

from .exceptions import ResolutionFailedError


# KERI derivation codes for Ed25519 (from keripy MtrDex)
# B = Ed25519 transferable (can rotate)
# D = Ed25519 non-transferable (cannot rotate)
ED25519_CODES = frozenset({"B", "D"})


@dataclass(frozen=True)
class VerificationKey:
    """Extracted verification key from kid field.

    Attributes:
        raw: 32-byte Ed25519 public key
        aid: Original AID string (for logging)
        code: KERI derivation code (e.g., "B" for Ed25519 transferable)
    """
    raw: bytes
    aid: str
    code: str


def parse_kid_to_verkey(kid: str) -> VerificationKey:
    """Parse kid (KERI AID) to extract Ed25519 public key.

    KERI AID format: <code><base64url_key>
    - "B" prefix = Ed25519 transferable (43 chars key)
    - "D" prefix = Ed25519 non-transferable (43 chars key)

    Args:
        kid: KERI AID string from PASSporT header kid field.

    Returns:
        VerificationKey with extracted public key bytes.

    Raises:
        ResolutionFailedError: If format invalid or unsupported algorithm.
            This is a recoverable error (→ INDETERMINATE).
    """
    if not kid or len(kid) < 2:
        raise ResolutionFailedError(f"Invalid kid format: too short (len={len(kid) if kid else 0})")

    code = kid[0]
    if code not in ED25519_CODES:
        raise ResolutionFailedError(
            f"Unsupported derivation code '{code}', expected Ed25519 (B or D)"
        )

    key_b64 = kid[1:]
    try:
        # Add padding and decode (base64url may omit trailing =)
        padded = key_b64 + "=" * (-len(key_b64) % 4)
        raw = base64.urlsafe_b64decode(padded)
    except Exception as e:
        raise ResolutionFailedError(f"Failed to decode kid base64: {e}")

    if len(raw) != 32:
        raise ResolutionFailedError(
            f"Invalid key length: {len(raw)} bytes, expected 32 for Ed25519"
        )

    return VerificationKey(raw=raw, aid=kid, code=code)
