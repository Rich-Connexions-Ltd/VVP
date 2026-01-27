"""Helper functions for generating test vector artifacts.

Ported from tests/test_signature.py with additional utilities for
VVP-Identity headers and forbidden algorithm JWTs.
"""

import base64
import json
from typing import Tuple

import pysodium


def generate_test_keypair() -> Tuple[bytes, bytes, bytes]:
    """Generate Ed25519 keypair for testing.

    Returns:
        Tuple of (seed, verkey, sigkey) where:
        - seed: 32-byte seed
        - verkey: 32-byte public key
        - sigkey: 64-byte secret key (seed + verkey)
    """
    seed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    verkey, sigkey = pysodium.crypto_sign_seed_keypair(seed)
    return seed, verkey, sigkey


def make_keri_aid(verkey: bytes, transferable: bool = True) -> str:
    """Create a KERI AID from a public key.

    Args:
        verkey: 32-byte Ed25519 public key
        transferable: If True, use B prefix; if False, use D prefix

    Returns:
        KERI AID string (e.g., "BIKKuv...")
    """
    code = "B" if transferable else "D"
    key_b64 = base64.urlsafe_b64encode(verkey).rstrip(b"=").decode()
    return code + key_b64


def create_vvp_identity(kid: str, evd_url: str, iat: int) -> str:
    """Create base64url-encoded VVP-Identity header.

    Args:
        kid: KERI AID for the caller
        evd_url: Evidence OOBI URL
        iat: Issued-at timestamp

    Returns:
        Base64url-encoded JSON string (no padding)
    """
    data = {
        "ppt": "vvp",
        "kid": kid,
        "evd": evd_url,
        "iat": iat,
    }
    return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()


def create_signed_passport(
    seed: bytes, verkey: bytes, iat: int, evd_url: str
) -> str:
    """Create a properly signed VVP PASSporT JWT.

    Args:
        seed: 32-byte seed for signing
        verkey: 32-byte public key (embedded in kid)
        iat: Issued-at timestamp
        evd_url: Evidence OOBI URL

    Returns:
        JWT string (header.payload.signature)
    """
    kid = make_keri_aid(verkey)
    header = {"alg": "EdDSA", "ppt": "vvp", "kid": kid}
    payload = {
        "iat": iat,
        "orig": {"tn": ["+12025551234"]},
        "dest": {"tn": ["+12025555678"]},
        "evd": evd_url,
    }

    h_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    p_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()

    # Sign with Ed25519 (seed + verkey = 64-byte secret key)
    signing_input = f"{h_b64}.{p_b64}".encode("ascii")
    sig = pysodium.crypto_sign_detached(signing_input, seed + verkey)
    sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()

    return f"{h_b64}.{p_b64}.{sig_b64}"


def create_passport_with_algorithm(
    alg: str, kid: str, iat: int, evd_url: str
) -> str:
    """Create PASSporT with specified algorithm (for testing rejection).

    Args:
        alg: Algorithm to use (e.g., "ES256" for forbidden)
        kid: KERI AID
        iat: Issued-at timestamp
        evd_url: Evidence OOBI URL

    Returns:
        JWT string with fake signature (algorithm will be rejected before verification)
    """
    header = {"alg": alg, "ppt": "vvp", "kid": kid}
    payload = {
        "iat": iat,
        "orig": {"tn": ["+12025551234"]},
        "dest": {"tn": ["+12025555678"]},
        "evd": evd_url,
    }

    h_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    p_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()

    # Fake signature (will be rejected before verification for forbidden alg)
    sig_b64 = base64.urlsafe_b64encode(b"x" * 64).rstrip(b"=").decode()

    return f"{h_b64}.{p_b64}.{sig_b64}"


def create_corrupted_signature_passport(
    seed: bytes, verkey: bytes, iat: int, evd_url: str
) -> str:
    """Create PASSporT with valid structure but corrupted signature.

    Args:
        seed: 32-byte seed for signing
        verkey: 32-byte public key
        iat: Issued-at timestamp
        evd_url: Evidence OOBI URL

    Returns:
        JWT string with corrupted signature
    """
    kid = make_keri_aid(verkey)
    header = {"alg": "EdDSA", "ppt": "vvp", "kid": kid}
    payload = {
        "iat": iat,
        "orig": {"tn": ["+12025551234"]},
        "dest": {"tn": ["+12025555678"]},
        "evd": evd_url,
    }

    h_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    p_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()

    # Create valid signature then corrupt it
    signing_input = f"{h_b64}.{p_b64}".encode("ascii")
    sig = pysodium.crypto_sign_detached(signing_input, seed + verkey)

    # Corrupt the signature by flipping bits
    corrupted_sig = bytes([b ^ 0xFF for b in sig[:8]]) + sig[8:]
    sig_b64 = base64.urlsafe_b64encode(corrupted_sig).rstrip(b"=").decode()

    return f"{h_b64}.{p_b64}.{sig_b64}"
