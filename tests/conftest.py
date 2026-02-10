# Copyright (c) Rich Connexions Ltd. All rights reserved.
# Licensed under the MIT License. See LICENSE for details.
"""Shared test fixtures for the VVP standalone verifier test suite.

Provides reusable fixtures for generating Ed25519 keypairs, signed
PASSporT JWTs, and base64url-encoded VVP-Identity headers.  All
fixtures use real Ed25519 key material via pysodium when available.
"""

from __future__ import annotations

import base64
import json
import time
from typing import Callable, Optional, Tuple

import pytest

try:
    import pysodium
except ImportError:
    pysodium = None


# =========================================================================
# Ed25519 Keypair
# =========================================================================

@pytest.fixture
def ed25519_keypair() -> Tuple[bytes, bytes]:
    """Generate a fresh Ed25519 keypair for testing.

    Returns:
        Tuple of (public_key, secret_key), each 32 and 64 bytes respectively.

    Skips:
        If pysodium is not installed.
    """
    if pysodium is None:
        pytest.skip("pysodium not available")
    pk, sk = pysodium.crypto_sign_keypair()
    return pk, sk


# =========================================================================
# AID Construction
# =========================================================================

@pytest.fixture
def make_aid(ed25519_keypair: Tuple[bytes, bytes]) -> Tuple[str, bytes, bytes]:
    """Create a non-transferable Ed25519 AID (B-prefix).

    Derives a KERI-compatible AID from the Ed25519 public key.  The
    B-prefix indicates a non-transferable identifier with the public
    key material embedded directly in the identifier.

    Returns:
        Tuple of (aid_string, public_key_bytes, secret_key_bytes).
    """
    pk, sk = ed25519_keypair
    # B-prefix AID: base64url encode the raw 32-byte public key,
    # strip padding, and prepend 'B' to produce a 44-char identifier.
    encoded = base64.urlsafe_b64encode(pk).decode().rstrip("=")
    aid = "B" + encoded[:43]
    return aid, pk, sk


# =========================================================================
# PASSporT JWT Factory
# =========================================================================

@pytest.fixture
def make_passport_jwt(
    make_aid: Tuple[str, bytes, bytes],
) -> Callable[..., Tuple[str, str]]:
    """Factory fixture: create a signed PASSporT JWT.

    Returns a callable that produces (jwt_string, aid_string) tuples.
    The JWT is signed with the Ed25519 secret key from the keypair fixture,
    producing a real verifiable signature.

    Keyword arguments control header/payload fields; defaults produce a
    spec-compliant VVP PASSporT.
    """
    aid, pk, sk = make_aid

    def _make(
        orig_tn: str = "+15551234567",
        dest_tn: str = "+15559876543",
        evd: str = "https://example.com/dossier.cesr",
        iat: Optional[int] = None,
        exp: Optional[int] = None,
        extra_header: Optional[dict] = None,
        extra_payload: Optional[dict] = None,
    ) -> Tuple[str, str]:
        if iat is None:
            iat = int(time.time())

        header = {"alg": "EdDSA", "ppt": "vvp", "kid": aid, "typ": "passport"}
        if extra_header:
            header.update(extra_header)

        payload: dict = {
            "iat": iat,
            "orig": {"tn": [orig_tn]},
            "dest": {"tn": [dest_tn]},
            "evd": evd,
        }
        if exp is not None:
            payload["exp"] = exp
        if extra_payload:
            payload.update(extra_payload)

        h = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        p = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        signing_input = f"{h}.{p}".encode("ascii")
        sig = pysodium.crypto_sign_detached(signing_input, sk)
        s = base64.urlsafe_b64encode(sig).decode().rstrip("=")
        return f"{h}.{p}.{s}", aid

    return _make


# =========================================================================
# VVP-Identity Header Factory
# =========================================================================

@pytest.fixture
def make_vvp_identity() -> Callable[..., str]:
    """Factory fixture: create a base64url-encoded VVP-Identity header.

    Returns a callable that produces a base64url-encoded JSON string
    suitable for passing to ``parse_vvp_identity()``.
    """

    def _make(
        ppt: str = "vvp",
        kid: str = "Btest_kid_000000000000000000000000000000000",
        evd: str = "https://example.com/dossier.cesr",
        iat: Optional[int] = None,
        exp: Optional[int] = None,
    ) -> str:
        if iat is None:
            iat = int(time.time())
        data: dict = {"ppt": ppt, "kid": kid, "evd": evd, "iat": iat}
        if exp is not None:
            data["exp"] = exp
        return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")

    return _make
