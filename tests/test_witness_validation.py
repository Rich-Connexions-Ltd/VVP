"""
Tests for witness receipt signature validation.

These tests verify that witness signatures are properly validated against
the canonical event bytes, including:
- Valid signatures pass validation
- Invalid signatures fail validation
- Threshold enforcement (toad)
- Witness AID parsing (B-prefix non-transferable)
"""

import base64
import json
from pathlib import Path

import pytest

# Check if pysodium/libsodium is available for actual signature verification
try:
    import pysodium
    PYSODIUM_AVAILABLE = True
except (ImportError, ValueError):
    PYSODIUM_AVAILABLE = False

requires_pysodium = pytest.mark.skipif(
    not PYSODIUM_AVAILABLE, reason="requires pysodium/libsodium for cryptographic verification"
)

from app.vvp.keri.exceptions import KELChainInvalidError, ResolutionFailedError
from app.vvp.keri.kel_parser import (
    KELEvent,
    EventType,
    WitnessReceipt,
    _decode_keri_key,
    _verify_signature,
    validate_witness_receipts,
    compute_signing_input_canonical,
)
from app.vvp.keri.keri_canonical import canonical_serialize


# Fixtures directory
FIXTURES_DIR = Path(__file__).parent / "fixtures" / "keri"


def load_fixture(name: str) -> dict:
    """Load a JSON fixture file."""
    path = FIXTURES_DIR / name
    with open(path) as f:
        return json.load(f)


class TestDecodeKeriKey:
    """Tests for _decode_keri_key function with witness AIDs."""

    def test_b_prefix_non_transferable(self):
        """B-prefix non-transferable AID decodes to correct public key."""
        fixture = load_fixture("witness_receipts_keripy.json")
        witness = fixture["witnesses"][0]

        public_key = _decode_keri_key(witness["aid"])

        expected = bytes.fromhex(witness["public_key_hex"])
        assert public_key == expected

    def test_all_witness_keys_decode(self):
        """All witness AIDs in fixture decode correctly."""
        fixture = load_fixture("witness_receipts_keripy.json")

        for witness in fixture["witnesses"]:
            public_key = _decode_keri_key(witness["aid"])
            expected = bytes.fromhex(witness["public_key_hex"])
            assert public_key == expected, f"Witness {witness['index']} key mismatch"

    def test_invalid_prefix_raises(self):
        """Unknown AID prefix raises ResolutionFailedError."""
        with pytest.raises(ResolutionFailedError):
            _decode_keri_key("XINVALIDPREFIX000000000000000000000000000")

    def test_empty_aid_raises(self):
        """Empty AID raises ResolutionFailedError."""
        with pytest.raises(ResolutionFailedError):
            _decode_keri_key("")

    def test_too_short_raises(self):
        """AID too short raises ResolutionFailedError."""
        with pytest.raises(ResolutionFailedError):
            _decode_keri_key("B")


class TestVerifyWitnessSignature:
    """Tests for witness signature verification."""

    @pytest.fixture
    def fixture(self):
        """Load witness receipts fixture."""
        return load_fixture("witness_receipts_keripy.json")

    @requires_pysodium
    def test_valid_signature_passes(self, fixture):
        """Valid witness signature verifies correctly."""
        event = fixture["event"]
        canonical_bytes = bytes.fromhex(fixture["canonical_bytes_hex"])
        receipt = fixture["valid_receipts"][0]

        public_key = _decode_keri_key(receipt["witness_aid"])
        signature = bytes.fromhex(receipt["signature_hex"])

        result = _verify_signature(canonical_bytes, signature, public_key)

        assert result is True

    @requires_pysodium
    def test_all_valid_signatures_pass(self, fixture):
        """All valid witness signatures verify correctly."""
        canonical_bytes = bytes.fromhex(fixture["canonical_bytes_hex"])

        for i, receipt in enumerate(fixture["valid_receipts"]):
            public_key = _decode_keri_key(receipt["witness_aid"])
            signature = bytes.fromhex(receipt["signature_hex"])

            result = _verify_signature(canonical_bytes, signature, public_key)
            assert result is True, f"Witness {i} signature should be valid"

    def test_invalid_signature_fails(self, fixture):
        """Invalid witness signature fails verification."""
        canonical_bytes = bytes.fromhex(fixture["canonical_bytes_hex"])
        invalid_receipt = fixture["invalid_receipt"]

        public_key = _decode_keri_key(invalid_receipt["witness_aid"])
        signature = bytes.fromhex(invalid_receipt["signature_hex"])

        result = _verify_signature(canonical_bytes, signature, public_key)

        assert result is False

    def test_wrong_message_fails(self, fixture):
        """Signature over different message fails verification."""
        receipt = fixture["valid_receipts"][0]
        public_key = _decode_keri_key(receipt["witness_aid"])
        signature = bytes.fromhex(receipt["signature_hex"])

        # Sign was over canonical_bytes, verify with different message
        wrong_message = b"this is not the canonical bytes"

        result = _verify_signature(wrong_message, signature, public_key)

        assert result is False


class TestValidateWitnessReceipts:
    """Tests for validate_witness_receipts function."""

    @pytest.fixture
    def fixture(self):
        """Load witness receipts fixture."""
        return load_fixture("witness_receipts_keripy.json")

    @pytest.fixture
    def event_with_receipts(self, fixture):
        """Create a KELEvent with valid witness receipts."""
        event_dict = fixture["event"]
        canonical_bytes = bytes.fromhex(fixture["canonical_bytes_hex"])

        # Create witness receipts
        receipts = []
        for r in fixture["valid_receipts"]:
            receipts.append(WitnessReceipt(
                witness_aid=r["witness_aid"],
                signature=bytes.fromhex(r["signature_hex"]),
            ))

        # Create KELEvent
        return KELEvent(
            event_type=EventType.ICP,
            sequence=0,
            prior_digest="",
            digest=event_dict["d"],
            signing_keys=[],
            next_keys_digest=None,
            toad=fixture["toad"],
            witnesses=[w["aid"] for w in fixture["witnesses"]],
            witness_receipts=receipts,
            raw=event_dict,
        ), canonical_bytes

    @requires_pysodium
    def test_valid_receipts_pass(self, event_with_receipts):
        """Event with sufficient valid receipts passes validation."""
        event, canonical_bytes = event_with_receipts

        # Should not raise - returns list of validated AIDs
        validated_aids = validate_witness_receipts(event, canonical_bytes, min_threshold=2)

        assert len(validated_aids) >= 2

    @requires_pysodium
    def test_exceeds_threshold(self, event_with_receipts):
        """3 valid receipts with threshold 2 passes."""
        event, canonical_bytes = event_with_receipts

        validated_aids = validate_witness_receipts(event, canonical_bytes, min_threshold=2)

        assert len(validated_aids) == 3  # All 3 receipts are valid

    @requires_pysodium
    def test_uses_event_toad_when_threshold_zero(self, event_with_receipts):
        """When min_threshold=0, uses event.toad."""
        event, canonical_bytes = event_with_receipts

        # min_threshold=0 means use event.toad (which is 2)
        validated_aids = validate_witness_receipts(event, canonical_bytes, min_threshold=0)

        assert len(validated_aids) >= event.toad

    def test_insufficient_valid_receipts_raises(self, event_with_receipts, fixture):
        """Insufficient valid receipts raises KELChainInvalidError."""
        event, canonical_bytes = event_with_receipts

        # Replace all receipts with invalid ones
        invalid_sig = bytes.fromhex(fixture["invalid_receipt"]["signature_hex"])
        event.witness_receipts = [
            WitnessReceipt(witness_aid=r["witness_aid"], signature=invalid_sig)
            for r in fixture["valid_receipts"][:2]  # Only 2 invalid receipts
        ]

        with pytest.raises(KELChainInvalidError) as exc:
            validate_witness_receipts(event, canonical_bytes, min_threshold=2)

        assert "Insufficient valid witness signatures" in str(exc.value)
        assert "0 < threshold 2" in str(exc.value)

    @requires_pysodium
    def test_partial_valid_receipts_below_threshold(self, event_with_receipts, fixture):
        """1 valid receipt with threshold 2 raises error."""
        event, canonical_bytes = event_with_receipts

        # Keep only 1 valid receipt and 1 invalid
        valid_receipt = event.witness_receipts[0]
        invalid_sig = bytes.fromhex(fixture["invalid_receipt"]["signature_hex"])
        invalid_receipt = WitnessReceipt(
            witness_aid=fixture["witnesses"][1]["aid"],
            signature=invalid_sig,
        )
        event.witness_receipts = [valid_receipt, invalid_receipt]

        with pytest.raises(KELChainInvalidError) as exc:
            validate_witness_receipts(event, canonical_bytes, min_threshold=2)

        assert "1 < threshold 2" in str(exc.value)

    def test_no_receipts_with_zero_threshold_passes(self, fixture):
        """Event with no receipts and threshold 0 passes."""
        event_dict = fixture["event"]

        event = KELEvent(
            event_type=EventType.ICP,
            sequence=0,
            prior_digest="",
            digest=event_dict["d"],
            signing_keys=[],
            next_keys_digest=None,
            toad=0,  # No witnesses required
            witnesses=[],
            witness_receipts=[],
            raw=event_dict,
        )

        canonical_bytes = bytes.fromhex(fixture["canonical_bytes_hex"])
        validated_aids = validate_witness_receipts(event, canonical_bytes, min_threshold=0)

        assert len(validated_aids) == 0

    def test_no_receipts_with_nonzero_threshold_raises(self, fixture):
        """Event with no receipts but threshold > 0 raises error."""
        event_dict = fixture["event"]

        event = KELEvent(
            event_type=EventType.ICP,
            sequence=0,
            prior_digest="",
            digest=event_dict["d"],
            signing_keys=[],
            next_keys_digest=None,
            toad=2,
            witnesses=[w["aid"] for w in fixture["witnesses"]],
            witness_receipts=[],
            raw=event_dict,
        )

        canonical_bytes = bytes.fromhex(fixture["canonical_bytes_hex"])

        with pytest.raises(KELChainInvalidError) as exc:
            validate_witness_receipts(event, canonical_bytes, min_threshold=2)

        assert "No witness receipts" in str(exc.value)

    @requires_pysodium
    def test_witness_not_in_list_skipped(self, event_with_receipts, fixture):
        """Receipt from witness not in event's list is skipped."""
        event, canonical_bytes = event_with_receipts

        # Create a receipt from an unknown witness
        unknown_witness_aid = "B" + "_" * 43  # Not in event's witness list
        unknown_receipt = WitnessReceipt(
            witness_aid=unknown_witness_aid,
            signature=bytes.fromhex(fixture["valid_receipts"][0]["signature_hex"]),
        )

        # Replace receipts: 2 valid + 1 unknown
        event.witness_receipts = event.witness_receipts[:2] + [unknown_receipt]

        # Should still pass with 2 valid (unknown is skipped)
        validated_aids = validate_witness_receipts(event, canonical_bytes, min_threshold=2)

        assert len(validated_aids) == 2


class TestComputeSigningInputCanonical:
    """Tests for compute_signing_input_canonical function."""

    @pytest.fixture
    def fixture(self):
        """Load witness receipts fixture."""
        return load_fixture("witness_receipts_keripy.json")

    def test_matches_canonical_bytes(self, fixture):
        """compute_signing_input_canonical matches canonical_serialize."""
        event = fixture["event"]
        expected = bytes.fromhex(fixture["canonical_bytes_hex"])

        result = compute_signing_input_canonical(event)

        assert result == expected

    def test_strips_attachment_fields(self, fixture):
        """compute_signing_input_canonical removes signature/receipt fields."""
        event = dict(fixture["event"])
        event["signatures"] = ["fake_sig"]
        event["-"] = ["attachment"]
        event["receipts"] = [{"i": "witness", "s": "sig"}]
        event["rcts"] = [{"i": "witness", "s": "sig"}]

        result = compute_signing_input_canonical(event)

        # Should match original (without attachment fields)
        expected = bytes.fromhex(fixture["canonical_bytes_hex"])
        assert result == expected


class TestIntegrationWithKeriPyFixtures:
    """Integration tests using keripy-generated fixtures."""

    def test_witness_receipts_fixture_has_valid_said(self):
        """Witness receipts fixture has valid SAID."""
        fixture = load_fixture("witness_receipts_keripy.json")
        event = fixture["event"]

        from app.vvp.keri.kel_parser import compute_said_canonical

        computed_said = compute_said_canonical(event)

        assert computed_said == event["d"]

    def test_witnesses_fixture_compatible(self):
        """Witness receipts fixture is compatible with icp_witnesses fixture."""
        witness_fixture = load_fixture("witness_receipts_keripy.json")
        icp_fixture = load_fixture("icp_witnesses_keripy.json")

        # Both should have same number of witnesses
        assert len(witness_fixture["witnesses"]) == len(icp_fixture["witnesses"])

        # Both should use toad=2
        assert witness_fixture["toad"] == icp_fixture["toad"]
