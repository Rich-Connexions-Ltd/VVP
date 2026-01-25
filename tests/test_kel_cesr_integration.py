"""
Integration tests for CESR KEL parsing and validation.

These tests verify the complete pipeline from raw CESR stream to
validated KEL events, including:
- CESR stream parsing
- Canonical SAID validation
- Controller signature verification
- Witness receipt validation
- Chain continuity validation
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

from app.vvp.keri.cesr import parse_cesr_stream, is_cesr_stream
from app.vvp.keri.exceptions import KELChainInvalidError, ResolutionFailedError
from app.vvp.keri.kel_parser import (
    parse_kel_stream,
    validate_kel_chain,
    compute_said_canonical,
    validate_event_said_canonical,
    validate_witness_receipts,
    compute_signing_input_canonical,
    CESR_CONTENT_TYPE,
    JSON_CONTENT_TYPE,
)
from app.vvp.keri.keri_canonical import canonical_serialize


# Fixtures directory
FIXTURES_DIR = Path(__file__).parent / "fixtures" / "keri"


def load_fixture(name: str) -> dict:
    """Load a JSON fixture file."""
    path = FIXTURES_DIR / name
    with open(path) as f:
        return json.load(f)


class TestCESRParsingIntegration:
    """Integration tests for CESR stream parsing."""

    def test_parse_icp_from_cesr_stream(self):
        """Parse ICP event from CESR-style JSON stream."""
        # Load ICP fixture
        fixture = load_fixture("icp_keripy.json")
        event = fixture["event"]

        # Create a JSON "stream" (single event)
        event_bytes = json.dumps(event).encode("utf-8")

        # Parse as KEL stream with JSON content type
        events = parse_kel_stream(event_bytes, content_type=JSON_CONTENT_TYPE, allow_json_only=True)

        assert len(events) == 1
        assert events[0].event_type.value == "icp"
        assert events[0].digest == fixture["said"]

    def test_parse_kel_stream_multiple_events(self):
        """Parse KEL stream with multiple events."""
        fixture = load_fixture("kel_stream_keripy.json")
        events_data = fixture["events"]

        # Create JSON stream
        stream_bytes = json.dumps(events_data).encode("utf-8")

        # Parse
        events = parse_kel_stream(stream_bytes, content_type=JSON_CONTENT_TYPE, allow_json_only=True)

        assert len(events) == len(events_data)
        assert events[0].event_type.value == "icp"
        assert events[0].sequence == 0

    def test_cesr_detection(self):
        """Detect CESR vs JSON streams correctly."""
        # JSON does not trigger CESR detection (no attachments)
        json_only = b'{"v":"KERI10JSON","t":"icp"}'
        assert not is_cesr_stream(json_only)

        # CESR version marker
        cesr_marker = b"-_AAAKERI10JSON000000_"
        assert is_cesr_stream(cesr_marker)

        # JSON with count code attachment
        json_with_attachment = b'{"v":"KERI10JSON"}-AAB'
        assert is_cesr_stream(json_with_attachment)


class TestCanonicalValidationIntegration:
    """Integration tests for canonical serialization and SAID validation."""

    def test_icp_canonical_roundtrip(self):
        """ICP event survives canonical serialize -> SAID compute roundtrip."""
        fixture = load_fixture("icp_keripy.json")
        event = fixture["event"]

        # Compute SAID
        computed_said = compute_said_canonical(event)

        # Should match fixture
        assert computed_said == fixture["said"]

    def test_rot_canonical_roundtrip(self):
        """ROT event survives canonical serialize -> SAID compute roundtrip."""
        fixture = load_fixture("rot_keripy.json")
        event = fixture["event"]

        computed_said = compute_said_canonical(event)

        assert computed_said == fixture["said"]

    def test_ixn_canonical_roundtrip(self):
        """IXN event survives canonical serialize -> SAID compute roundtrip."""
        fixture = load_fixture("ixn_keripy.json")
        event = fixture["event"]

        computed_said = compute_said_canonical(event)

        assert computed_said == fixture["said"]

    def test_validate_all_kel_stream_saids(self):
        """All events in KEL stream have valid SAIDs."""
        fixture = load_fixture("kel_stream_keripy.json")
        events = fixture["events"]

        for i, event in enumerate(events):
            # Should not raise
            validate_event_said_canonical(event)


class TestWitnessValidationIntegration:
    """Integration tests for witness receipt validation."""

    @requires_pysodium
    def test_witness_receipts_end_to_end(self):
        """Full witness validation from fixture."""
        fixture = load_fixture("witness_receipts_keripy.json")
        event = fixture["event"]
        canonical_bytes = bytes.fromhex(fixture["canonical_bytes_hex"])

        # Parse event
        from app.vvp.keri.kel_parser import _parse_event_dict, WitnessReceipt, KELEvent
        parsed_event = _parse_event_dict(event)

        # Add witness receipts
        for r in fixture["valid_receipts"]:
            parsed_event.witness_receipts.append(WitnessReceipt(
                witness_aid=r["witness_aid"],
                signature=bytes.fromhex(r["signature_hex"]),
            ))

        # Validate - returns list of validated AIDs
        validated_aids = validate_witness_receipts(
            parsed_event,
            canonical_bytes,
            min_threshold=fixture["toad"]
        )

        assert len(validated_aids) >= fixture["toad"]


class TestChainValidationIntegration:
    """Integration tests for full chain validation."""

    def test_kel_stream_chain_validation(self):
        """Full KEL stream passes chain validation."""
        fixture = load_fixture("kel_stream_keripy.json")
        events_data = fixture["events"]

        # Create JSON stream
        stream_bytes = json.dumps(events_data).encode("utf-8")

        # Parse
        events = parse_kel_stream(
            stream_bytes,
            content_type=JSON_CONTENT_TYPE,
            allow_json_only=True
        )

        # Validate chain (without signatures - fixture doesn't have them)
        # This tests chain continuity: sequence, prior_digest linking
        # Note: signature validation requires actual signatures in the fixture
        assert len(events) > 0
        assert events[0].event_type.value == "icp"
        assert events[0].sequence == 0

        # Verify chain linking
        for i, event in enumerate(events[1:], 1):
            assert event.sequence == i
            assert event.prior_digest == events[i-1].digest

    def test_chain_validation_with_canonical_said(self):
        """Chain validation works with canonical SAID computation."""
        fixture = load_fixture("kel_stream_keripy.json")

        for event_data in fixture["events"]:
            # Validate SAID using canonical serialization
            validate_event_said_canonical(event_data)


class TestContentTypeRouting:
    """Tests for content-type based routing."""

    def test_json_content_type_uses_json_parser(self):
        """JSON content-type routes to JSON parser."""
        fixture = load_fixture("icp_keripy.json")
        event_bytes = json.dumps(fixture["event"]).encode("utf-8")

        events = parse_kel_stream(
            event_bytes,
            content_type=JSON_CONTENT_TYPE,
            allow_json_only=True
        )

        assert len(events) == 1

    def test_cesr_content_type_with_json_data(self):
        """CESR content-type with JSON data still parses correctly."""
        fixture = load_fixture("icp_keripy.json")
        event_bytes = json.dumps(fixture["event"]).encode("utf-8")

        # Even with CESR content-type, JSON data should parse
        # because the CESR parser handles JSON events
        events = parse_kel_stream(
            event_bytes,
            content_type=CESR_CONTENT_TYPE,
            allow_json_only=False
        )

        assert len(events) == 1


class TestSigningInputComputation:
    """Tests for signing input computation."""

    def test_signing_input_matches_canonical_bytes(self):
        """Signing input matches canonical bytes from fixture."""
        fixture = load_fixture("witness_receipts_keripy.json")
        event = fixture["event"]
        expected = bytes.fromhex(fixture["canonical_bytes_hex"])

        result = compute_signing_input_canonical(event)

        assert result == expected

    def test_signing_input_for_all_event_types(self):
        """Signing input can be computed for all event types."""
        for fixture_name in ["icp_keripy.json", "rot_keripy.json", "ixn_keripy.json"]:
            fixture = load_fixture(fixture_name)
            event = fixture["event"]
            expected = base64.urlsafe_b64decode(fixture["canonical_bytes"] + "===")

            result = compute_signing_input_canonical(event)

            assert result == expected, f"Mismatch for {fixture_name}"


class TestKeriPyCompatibility:
    """Tests verifying compatibility with keripy fixtures."""

    def test_all_fixtures_have_valid_metadata(self):
        """All keripy fixtures include required metadata."""
        fixture_names = [
            "icp_keripy.json",
            "rot_keripy.json",
            "ixn_keripy.json",
            "kel_stream_keripy.json",
        ]

        for name in fixture_names:
            fixture = load_fixture(name)

            # Should have keripy version info
            if "keripy_version" in fixture:
                assert fixture["keripy_version"].startswith("2.")
                assert "keripy_commit" in fixture

    def test_field_orders_match_keripy(self):
        """Field orderings match keripy fixture."""
        fixture = load_fixture("field_orders_keripy.json")
        from app.vvp.keri.keri_canonical import FIELD_ORDER

        for event_type, expected_order in fixture["field_orders"].items():
            assert FIELD_ORDER.get(event_type) == expected_order, \
                f"Field order mismatch for {event_type}"
