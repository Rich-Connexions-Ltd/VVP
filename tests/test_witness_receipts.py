"""Tests for witness receipt validation.

Per VVP §7.3 - witness receipts must be cryptographically validated.
"""

import pytest
import pysodium

from app.vvp.keri.kel_parser import (
    KELEvent,
    EventType,
    WitnessReceipt,
    validate_witness_receipts,
    _compute_signing_input,
)
from app.vvp.keri.exceptions import KELChainInvalidError


def create_test_keypair():
    """Create a test Ed25519 keypair."""
    pk, sk = pysodium.crypto_sign_keypair()
    return pk, sk


def create_witness_aid(public_key: bytes) -> str:
    """Create a B-prefix witness AID from public key using proper CESR encoding.

    CESR B-prefix (Ed25519N) encoding prepends a lead byte (0x04) to the
    32-byte public key, then base64url encodes the 33-byte result.
    """
    import base64
    # Prepend CESR lead byte for B-prefix (Ed25519N non-transferable)
    cesr_lead_byte = bytes([0x04])
    full_bytes = cesr_lead_byte + public_key
    return base64.urlsafe_b64encode(full_bytes).decode().rstrip("=")


def sign_message(message: bytes, secret_key: bytes) -> bytes:
    """Sign a message with Ed25519."""
    return pysodium.crypto_sign_detached(message, secret_key)


class TestValidateWitnessReceipts:
    """Tests for validate_witness_receipts function."""

    def test_no_receipts_no_threshold(self):
        """Test that no receipts with no threshold returns empty list."""
        event = KELEvent(
            event_type=EventType.ICP,
            sequence=0,
            prior_digest="",
            digest="E" + "A" * 43,
            signing_keys=[],
            next_keys_digest=None,
            toad=0,
            witnesses=[],
            witness_receipts=[],
            raw={"t": "icp", "s": "0"}
        )

        result = validate_witness_receipts(event, b"test message", min_threshold=0)

        assert result == []

    def test_no_receipts_with_threshold_raises(self):
        """Test that no receipts with threshold requirement raises."""
        event = KELEvent(
            event_type=EventType.ICP,
            sequence=0,
            prior_digest="",
            digest="E" + "A" * 43,
            signing_keys=[],
            next_keys_digest=None,
            toad=2,
            witnesses=["Bwitness1", "Bwitness2"],
            witness_receipts=[],
            raw={"t": "icp", "s": "0"}
        )

        with pytest.raises(KELChainInvalidError, match="No witness receipts"):
            validate_witness_receipts(event, b"test message")

    def test_valid_single_witness(self):
        """Test validation with single valid witness receipt."""
        # Create witness keypair
        pk, sk = create_test_keypair()
        witness_aid = create_witness_aid(pk)

        # Create message and signature
        message = b"test event bytes"
        signature = sign_message(message, sk)

        event = KELEvent(
            event_type=EventType.ICP,
            sequence=0,
            prior_digest="",
            digest="E" + "A" * 43,
            signing_keys=[],
            next_keys_digest=None,
            toad=1,
            witnesses=[witness_aid],
            witness_receipts=[
                WitnessReceipt(witness_aid=witness_aid, signature=signature)
            ],
            raw={"t": "icp", "s": "0"}
        )

        result = validate_witness_receipts(event, message, min_threshold=1)

        assert len(result) == 1
        assert result[0] == witness_aid

    def test_threshold_from_toad(self):
        """Test that threshold uses event.toad when min_threshold=0."""
        pk1, sk1 = create_test_keypair()
        pk2, sk2 = create_test_keypair()
        witness1 = create_witness_aid(pk1)
        witness2 = create_witness_aid(pk2)

        message = b"test event bytes"
        sig1 = sign_message(message, sk1)
        sig2 = sign_message(message, sk2)

        event = KELEvent(
            event_type=EventType.ICP,
            sequence=0,
            prior_digest="",
            digest="E" + "A" * 43,
            signing_keys=[],
            next_keys_digest=None,
            toad=2,  # Requires 2 valid witnesses
            witnesses=[witness1, witness2],
            witness_receipts=[
                WitnessReceipt(witness_aid=witness1, signature=sig1),
                WitnessReceipt(witness_aid=witness2, signature=sig2),
            ],
            raw={"t": "icp", "s": "0"}
        )

        result = validate_witness_receipts(event, message, min_threshold=0)

        assert len(result) == 2

    def test_majority_threshold_default(self):
        """Test that default threshold is majority when toad=0."""
        pk1, sk1 = create_test_keypair()
        pk2, sk2 = create_test_keypair()
        pk3, _ = create_test_keypair()  # Third witness, no valid sig
        witness1 = create_witness_aid(pk1)
        witness2 = create_witness_aid(pk2)
        witness3 = create_witness_aid(pk3)

        message = b"test event bytes"
        sig1 = sign_message(message, sk1)
        sig2 = sign_message(message, sk2)

        event = KELEvent(
            event_type=EventType.ICP,
            sequence=0,
            prior_digest="",
            digest="E" + "A" * 43,
            signing_keys=[],
            next_keys_digest=None,
            toad=0,  # No explicit threshold
            witnesses=[witness1, witness2, witness3],
            witness_receipts=[
                WitnessReceipt(witness_aid=witness1, signature=sig1),
                WitnessReceipt(witness_aid=witness2, signature=sig2),
            ],
            raw={"t": "icp", "s": "0"}
        )

        # Majority of 3 = ceil(3/2) = 2
        result = validate_witness_receipts(event, message, min_threshold=0)

        assert len(result) == 2

    def test_invalid_signature_not_counted(self):
        """Test that invalid signatures are not counted."""
        pk, sk = create_test_keypair()
        witness_aid = create_witness_aid(pk)

        message = b"test event bytes"
        wrong_sig = b"\x00" * 64  # Invalid signature

        event = KELEvent(
            event_type=EventType.ICP,
            sequence=0,
            prior_digest="",
            digest="E" + "A" * 43,
            signing_keys=[],
            next_keys_digest=None,
            toad=1,
            witnesses=[witness_aid],
            witness_receipts=[
                WitnessReceipt(witness_aid=witness_aid, signature=wrong_sig)
            ],
            raw={"t": "icp", "s": "0"}
        )

        with pytest.raises(KELChainInvalidError, match="Insufficient valid witness signatures"):
            validate_witness_receipts(event, message, min_threshold=1)

    def test_witness_not_in_list_ignored(self):
        """Test that receipts from unknown witnesses are ignored."""
        pk, sk = create_test_keypair()
        witness_aid = create_witness_aid(pk)

        message = b"test event bytes"
        sig = sign_message(message, sk)

        event = KELEvent(
            event_type=EventType.ICP,
            sequence=0,
            prior_digest="",
            digest="E" + "A" * 43,
            signing_keys=[],
            next_keys_digest=None,
            toad=1,
            witnesses=["Bother_witness"],  # Different witness
            witness_receipts=[
                WitnessReceipt(witness_aid=witness_aid, signature=sig)
            ],
            raw={"t": "icp", "s": "0"}
        )

        with pytest.raises(KELChainInvalidError, match="not in event's witness list"):
            validate_witness_receipts(event, message, min_threshold=1)

    def test_empty_witness_aid_skipped(self):
        """Test that receipts with empty AID are skipped."""
        pk, sk = create_test_keypair()
        witness_aid = create_witness_aid(pk)

        message = b"test event bytes"
        sig = sign_message(message, sk)

        event = KELEvent(
            event_type=EventType.ICP,
            sequence=0,
            prior_digest="",
            digest="E" + "A" * 43,
            signing_keys=[],
            next_keys_digest=None,
            toad=1,
            witnesses=[witness_aid],
            witness_receipts=[
                WitnessReceipt(witness_aid="", signature=sig),  # Empty AID
                WitnessReceipt(witness_aid=witness_aid, signature=sig),
            ],
            raw={"t": "icp", "s": "0"}
        )

        result = validate_witness_receipts(event, message, min_threshold=1)

        assert len(result) == 1
        assert result[0] == witness_aid
