"""Ed25519 signature verification for VVP PASSporTs.

Tier 1 implementation: Direct verification using public key embedded in KERI AID.
Full KERI integration (Tier 2) would involve KEL lookup and historical key state.
"""

import pysodium

from app.vvp.passport import Passport
from .key_parser import parse_kid_to_verkey
from .exceptions import SignatureInvalidError


def verify_passport_signature(passport: Passport) -> None:
    """Verify PASSporT signature using Ed25519.

    The signing input for JWT is: base64url(header).base64url(payload)
    The signature is verified against this input using the public key
    extracted from the kid field.

    Args:
        passport: Parsed Passport with raw_header, raw_payload, signature.

    Raises:
        SignatureInvalidError: Signature cryptographically invalid (→ INVALID).
        ResolutionFailedError: Could not resolve/parse kid to key (→ INDETERMINATE).

    Note:
        Tier 1 does not validate key state at time T (iat).
        It assumes the key embedded in the AID is currently valid.
    """
    # Step 1: Parse kid to get verification key
    # This may raise ResolutionFailedError (recoverable → INDETERMINATE)
    verkey = parse_kid_to_verkey(passport.header.kid)

    # Step 2: Reconstruct JWT signing input: header.payload (ASCII bytes)
    # Per JWT spec, the signature covers the exact base64url-encoded strings
    signing_input = f"{passport.raw_header}.{passport.raw_payload}".encode("ascii")

    # Step 3: Verify signature using pysodium (libsodium)
    try:
        # pysodium.crypto_sign_verify_detached raises ValueError if invalid
        pysodium.crypto_sign_verify_detached(
            passport.signature,
            signing_input,
            verkey.raw
        )
    except Exception:
        # Any verification failure is a cryptographic failure → INVALID
        raise SignatureInvalidError(
            f"Ed25519 signature verification failed for kid={passport.header.kid[:20]}..."
        )
