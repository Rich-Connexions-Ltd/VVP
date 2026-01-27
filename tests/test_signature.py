"""
Unit tests for Phase 4 signature verification.

Covers:
- Key parser (parse_kid_to_verkey)
- Ed25519 signature verification (verify_passport_signature)
- Error handling (SignatureInvalidError, ResolutionFailedError)
"""

import base64
import json

import pysodium
import pytest

from app.vvp.api_models import ErrorCode
from app.vvp.keri.exceptions import ResolutionFailedError, SignatureInvalidError
from app.vvp.keri.key_parser import parse_kid_to_verkey, VerificationKey
from app.vvp.keri.signature import verify_passport_signature
from app.vvp.passport import parse_passport


# =============================================================================
# Test Helpers
# =============================================================================


def generate_test_keypair():
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


def create_signed_jwt(seed: bytes, verkey: bytes, iat: int = 1700000000) -> str:
    """Create a properly signed VVP PASSporT JWT.

    Args:
        seed: 32-byte seed for signing
        verkey: 32-byte public key (embedded in kid)
        iat: Issued-at timestamp

    Returns:
        JWT string (header.payload.signature)
    """
    kid = make_keri_aid(verkey)
    header = {"alg": "EdDSA", "ppt": "vvp", "kid": kid}
    payload = {
        "iat": iat,
        "orig": {"tn": ["+12025551234"]},
        "dest": {"tn": ["+12025555678"]},
        "evd": "oobi:http://example.com/oobi",
    }

    h_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    p_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()

    # Sign with Ed25519 (seed + verkey = 64-byte secret key)
    signing_input = f"{h_b64}.{p_b64}".encode("ascii")
    sig = pysodium.crypto_sign_detached(signing_input, seed + verkey)
    sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()

    return f"{h_b64}.{p_b64}.{sig_b64}"


# =============================================================================
# Key Parser Tests
# =============================================================================


class TestKeyParser:
    """Tests for parse_kid_to_verkey."""

    def test_parse_ed25519_transferable(self):
        """Parse Ed25519 AID with B prefix (transferable)."""
        _, verkey, _ = generate_test_keypair()
        kid = make_keri_aid(verkey, transferable=True)
        result = parse_kid_to_verkey(kid)

        assert isinstance(result, VerificationKey)
        assert result.raw == verkey
        assert result.code == "B"
        assert result.aid == kid

    def test_parse_ed25519_non_transferable(self):
        """Parse Ed25519 AID with D prefix (non-transferable)."""
        _, verkey, _ = generate_test_keypair()
        kid = make_keri_aid(verkey, transferable=False)
        result = parse_kid_to_verkey(kid)

        assert result.raw == verkey
        assert result.code == "D"

    def test_empty_kid_raises(self):
        """Empty kid raises ResolutionFailedError."""
        with pytest.raises(ResolutionFailedError) as exc:
            parse_kid_to_verkey("")
        assert exc.value.code == ErrorCode.KERI_RESOLUTION_FAILED
        assert "too short" in exc.value.message

    def test_none_kid_raises(self):
        """None kid raises ResolutionFailedError."""
        with pytest.raises(ResolutionFailedError) as exc:
            parse_kid_to_verkey(None)
        assert exc.value.code == ErrorCode.KERI_RESOLUTION_FAILED

    def test_single_char_kid_raises(self):
        """Single character kid raises ResolutionFailedError."""
        with pytest.raises(ResolutionFailedError) as exc:
            parse_kid_to_verkey("B")
        assert exc.value.code == ErrorCode.KERI_RESOLUTION_FAILED
        assert "too short" in exc.value.message

    def test_unsupported_code_raises(self):
        """Non-Ed25519 derivation code raises ResolutionFailedError."""
        # '0' is not a supported Ed25519 code
        kid = "0" + "A" * 43
        with pytest.raises(ResolutionFailedError) as exc:
            parse_kid_to_verkey(kid)
        assert exc.value.code == ErrorCode.KERI_RESOLUTION_FAILED
        assert "Unsupported derivation code" in exc.value.message

    def test_invalid_base64_raises(self):
        """Invalid base64 in key portion raises ResolutionFailedError."""
        # B prefix with invalid base64 characters
        kid = "B" + "!!invalid!!"
        with pytest.raises(ResolutionFailedError) as exc:
            parse_kid_to_verkey(kid)
        assert exc.value.code == ErrorCode.KERI_RESOLUTION_FAILED

    def test_wrong_key_length_raises(self):
        """Key not 32 bytes after decoding raises ResolutionFailedError."""
        # Create a valid base64 string that decodes to wrong length
        short_key = base64.urlsafe_b64encode(b"short").rstrip(b"=").decode()
        kid = "B" + short_key
        with pytest.raises(ResolutionFailedError) as exc:
            parse_kid_to_verkey(kid)
        assert exc.value.code == ErrorCode.KERI_RESOLUTION_FAILED
        assert "Invalid key length" in exc.value.message


# =============================================================================
# Signature Verification Tests
# =============================================================================


class TestSignatureVerification:
    """Tests for verify_passport_signature."""

    def test_valid_signature_passes(self):
        """Valid Ed25519 signature passes verification."""
        seed, verkey, _ = generate_test_keypair()
        jwt = create_signed_jwt(seed, verkey)
        passport = parse_passport(jwt)

        # Should not raise
        verify_passport_signature(passport)

    def test_valid_signature_non_transferable(self):
        """Valid signature with D prefix (non-transferable) passes."""
        seed, verkey, _ = generate_test_keypair()

        # Create JWT with D prefix kid
        kid = make_keri_aid(verkey, transferable=False)
        header = {"alg": "EdDSA", "ppt": "vvp", "kid": kid}
        payload = {"iat": 1700000000, "orig": {"tn": ["+12025551234"]}, "dest": {"tn": ["+12025555678"]}, "evd": "x"}

        h_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
        p_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
        signing_input = f"{h_b64}.{p_b64}".encode("ascii")
        sig = pysodium.crypto_sign_detached(signing_input, seed + verkey)
        sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
        jwt = f"{h_b64}.{p_b64}.{sig_b64}"

        passport = parse_passport(jwt)
        verify_passport_signature(passport)  # Should not raise

    def test_corrupted_signature_raises(self):
        """Corrupted signature raises SignatureInvalidError."""
        seed, verkey, _ = generate_test_keypair()
        jwt = create_signed_jwt(seed, verkey)

        # Corrupt the signature by changing some bytes
        parts = jwt.split(".")
        sig_bytes = base64.urlsafe_b64decode(parts[2] + "==")
        corrupted_sig = bytes([b ^ 0xFF for b in sig_bytes[:8]]) + sig_bytes[8:]
        parts[2] = base64.urlsafe_b64encode(corrupted_sig).rstrip(b"=").decode()

        passport = parse_passport(".".join(parts))
        with pytest.raises(SignatureInvalidError) as exc:
            verify_passport_signature(passport)
        assert exc.value.code == ErrorCode.PASSPORT_SIG_INVALID

    def test_wrong_key_raises(self):
        """Signature verified against wrong key raises SignatureInvalidError."""
        seed1, verkey1, _ = generate_test_keypair()
        _, verkey2, _ = generate_test_keypair()

        # Sign with key1 but embed key2 in header
        jwt = create_signed_jwt(seed1, verkey1)
        parts = jwt.split(".")

        # Replace kid with different key
        header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
        header["kid"] = make_keri_aid(verkey2)
        parts[0] = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()

        passport = parse_passport(".".join(parts))
        with pytest.raises(SignatureInvalidError) as exc:
            verify_passport_signature(passport)
        assert exc.value.code == ErrorCode.PASSPORT_SIG_INVALID

    def test_modified_header_raises(self):
        """Modified header after signing raises SignatureInvalidError."""
        seed, verkey, _ = generate_test_keypair()
        jwt = create_signed_jwt(seed, verkey)
        parts = jwt.split(".")

        # Modify header by adding a new field (doesn't affect parsing but breaks signature)
        header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
        header["x-modified"] = "true"  # Add field that won't affect parsing
        parts[0] = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()

        passport = parse_passport(".".join(parts))
        with pytest.raises(SignatureInvalidError):
            verify_passport_signature(passport)

    def test_modified_payload_raises(self):
        """Modified payload after signing raises SignatureInvalidError."""
        seed, verkey, _ = generate_test_keypair()
        jwt = create_signed_jwt(seed, verkey)
        parts = jwt.split(".")

        # Modify payload (change iat)
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
        payload["iat"] = 9999999999
        parts[1] = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()

        passport = parse_passport(".".join(parts))
        with pytest.raises(SignatureInvalidError):
            verify_passport_signature(passport)

    def test_empty_signature_raises(self):
        """Empty signature raises SignatureInvalidError."""
        seed, verkey, _ = generate_test_keypair()
        jwt = create_signed_jwt(seed, verkey)
        parts = jwt.split(".")

        # Replace signature with minimal valid base64 that decodes to empty/short
        parts[2] = "AA"  # Decodes to single byte

        passport = parse_passport(".".join(parts))
        with pytest.raises(SignatureInvalidError):
            verify_passport_signature(passport)

    def test_invalid_kid_raises_resolution_error(self):
        """Invalid kid format raises ResolutionFailedError (not SignatureInvalidError)."""
        seed, verkey, _ = generate_test_keypair()
        jwt = create_signed_jwt(seed, verkey)
        parts = jwt.split(".")

        # Replace kid with invalid format
        header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
        header["kid"] = "invalid-kid-format"
        parts[0] = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()

        passport = parse_passport(".".join(parts))
        with pytest.raises(ResolutionFailedError) as exc:
            verify_passport_signature(passport)
        # Resolution failure is recoverable
        assert exc.value.code == ErrorCode.KERI_RESOLUTION_FAILED


# =============================================================================
# Error Code Tests
# =============================================================================


class TestErrorCodes:
    """Tests for correct error code assignment."""

    def test_signature_invalid_is_non_recoverable(self):
        """PASSPORT_SIG_INVALID has correct code."""
        err = SignatureInvalidError("test")
        assert err.code == ErrorCode.PASSPORT_SIG_INVALID
        assert err.message == "test"

    def test_resolution_failed_is_recoverable(self):
        """KERI_RESOLUTION_FAILED has correct code."""
        err = ResolutionFailedError("test")
        assert err.code == ErrorCode.KERI_RESOLUTION_FAILED


# =============================================================================
# Edge Cases
# =============================================================================


class TestEdgeCases:
    """Edge case tests."""

    def test_deterministic_verification(self):
        """Same JWT always produces same verification result."""
        seed, verkey, _ = generate_test_keypair()
        jwt = create_signed_jwt(seed, verkey)
        passport = parse_passport(jwt)

        # Verify multiple times
        for _ in range(10):
            verify_passport_signature(passport)  # Should always pass

    def test_different_keys_produce_different_signatures(self):
        """Different keys produce different (invalid) signatures."""
        seed1, verkey1, _ = generate_test_keypair()
        seed2, verkey2, _ = generate_test_keypair()

        jwt1 = create_signed_jwt(seed1, verkey1)
        jwt2 = create_signed_jwt(seed2, verkey2)

        passport1 = parse_passport(jwt1)
        passport2 = parse_passport(jwt2)

        # Each verifies with its own key
        verify_passport_signature(passport1)
        verify_passport_signature(passport2)

        # But cross-verification fails
        # Swap signatures
        parts1 = jwt1.split(".")
        parts2 = jwt2.split(".")
        swapped1 = f"{parts1[0]}.{parts1[1]}.{parts2[2]}"

        passport_swapped = parse_passport(swapped1)
        with pytest.raises(SignatureInvalidError):
            verify_passport_signature(passport_swapped)
