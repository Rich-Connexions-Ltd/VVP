"""Tests for KEL (Key Event Log) parser.

Tests parsing of KERI events and validation of event structure.
"""

import base64
import json
import pytest

from app.vvp.keri.kel_parser import (
    EventType,
    KELEvent,
    WitnessReceipt,
    parse_kel_stream,
    _parse_event_dict,
    _decode_keri_key,
    _decode_signature,
    compute_said,
)
from app.vvp.keri.exceptions import (
    ResolutionFailedError,
)


# Test keys (valid Ed25519 32-byte keys encoded for KERI)
TEST_KEY_1 = "B" + base64.urlsafe_b64encode(b"A" * 32).decode().rstrip("=")
TEST_KEY_2 = "B" + base64.urlsafe_b64encode(b"B" * 32).decode().rstrip("=")
TEST_SIG = "0B" + base64.urlsafe_b64encode(b"S" * 64).decode().rstrip("=")


class TestEventTypeParsing:
    """Test event type enumeration."""

    def test_icp_event_type(self):
        """Parse inception event type."""
        assert EventType("icp") == EventType.ICP

    def test_rot_event_type(self):
        """Parse rotation event type."""
        assert EventType("rot") == EventType.ROT

    def test_ixn_event_type(self):
        """Parse interaction event type."""
        assert EventType("ixn") == EventType.IXN

    def test_dip_event_type(self):
        """Parse delegated inception event type."""
        assert EventType("dip") == EventType.DIP

    def test_drt_event_type(self):
        """Parse delegated rotation event type."""
        assert EventType("drt") == EventType.DRT

    def test_invalid_event_type(self):
        """Reject unknown event types."""
        with pytest.raises(ValueError):
            EventType("unknown")


class TestKeyDecoding:
    """Test KERI key decoding."""

    def test_decode_ed25519_transferable(self):
        """Decode Ed25519 transferable key (B prefix)."""
        key_bytes = b"A" * 32
        key_str = "B" + base64.urlsafe_b64encode(key_bytes).decode().rstrip("=")

        decoded = _decode_keri_key(key_str)
        assert decoded == key_bytes

    def test_decode_ed25519_nontransferable(self):
        """Decode Ed25519 non-transferable key (D prefix)."""
        key_bytes = b"B" * 32
        key_str = "D" + base64.urlsafe_b64encode(key_bytes).decode().rstrip("=")

        decoded = _decode_keri_key(key_str)
        assert decoded == key_bytes

    def test_decode_key_too_short(self):
        """Reject keys that are too short."""
        with pytest.raises(ResolutionFailedError, match="too short"):
            _decode_keri_key("B")

    def test_decode_key_empty(self):
        """Reject empty key string."""
        with pytest.raises(ResolutionFailedError, match="too short"):
            _decode_keri_key("")

    def test_decode_unsupported_code(self):
        """Reject unsupported derivation codes."""
        with pytest.raises(ResolutionFailedError, match="Unsupported key derivation"):
            _decode_keri_key("X" + "A" * 43)


class TestSignatureDecoding:
    """Test signature decoding."""

    def test_decode_indexed_signature(self):
        """Decode indexed controller signature (0B prefix)."""
        sig_bytes = b"S" * 64
        sig_str = "0B" + base64.urlsafe_b64encode(sig_bytes).decode().rstrip("=")

        decoded = _decode_signature(sig_str)
        assert decoded == sig_bytes

    def test_decode_empty_signature(self):
        """Empty signature returns empty bytes."""
        assert _decode_signature("") == b""


class TestParseEventDict:
    """Test parsing individual event dictionaries."""

    def test_parse_inception_event(self):
        """Parse a valid inception event."""
        event_dict = {
            "t": "icp",
            "s": "0",
            "d": "SAID_PLACEHOLDER",
            "k": [TEST_KEY_1],
            "n": ["NEXT_KEY_DIGEST"],
            "bt": "1",
            "b": ["witness1", "witness2"],
            "signatures": [TEST_SIG],
        }

        event = _parse_event_dict(event_dict)

        assert event.event_type == EventType.ICP
        assert event.sequence == 0
        assert event.digest == "SAID_PLACEHOLDER"
        assert len(event.signing_keys) == 1
        assert event.toad == 1
        assert len(event.witnesses) == 2

    def test_parse_rotation_event(self):
        """Parse a valid rotation event."""
        event_dict = {
            "t": "rot",
            "s": "1",
            "p": "PRIOR_DIGEST",
            "d": "SAID_PLACEHOLDER",
            "k": [TEST_KEY_2],
            "n": ["NEW_NEXT_KEY_DIGEST"],
            "bt": "2",
            "b": ["witness1", "witness2", "witness3"],
            "signatures": [TEST_SIG],
        }

        event = _parse_event_dict(event_dict)

        assert event.event_type == EventType.ROT
        assert event.sequence == 1
        assert event.prior_digest == "PRIOR_DIGEST"
        assert event.is_establishment

    def test_parse_interaction_event(self):
        """Parse an interaction event (non-establishment)."""
        event_dict = {
            "t": "ixn",
            "s": "2",
            "p": "PRIOR_DIGEST",
            "d": "SAID_PLACEHOLDER",
            "a": [{"type": "anchor"}],
            "signatures": [TEST_SIG],
        }

        event = _parse_event_dict(event_dict)

        assert event.event_type == EventType.IXN
        assert event.sequence == 2
        assert not event.is_establishment

    def test_parse_delegated_inception_with_di(self):
        """Delegated inception with di field parses successfully."""
        event_dict = {
            "t": "dip",
            "s": "0",
            "d": "SAID_PLACEHOLDER",
            "k": [TEST_KEY_1],
            "di": "EDelegatorAID00000000000000000000000000000",
        }

        event = _parse_event_dict(event_dict)
        assert event.event_type == EventType.DIP
        assert event.delegator_aid == "EDelegatorAID00000000000000000000000000000"
        assert event.is_delegated is True

    def test_parse_delegated_inception_missing_di_raises(self):
        """Delegated inception missing di field raises ResolutionFailedError."""
        event_dict = {
            "t": "dip",
            "s": "0",
            "d": "SAID_PLACEHOLDER",
            "k": [TEST_KEY_1],
            # Missing "di" field
        }

        with pytest.raises(ResolutionFailedError) as exc_info:
            _parse_event_dict(event_dict)
        assert "missing required 'di' field" in str(exc_info.value)

    def test_parse_delegated_rotation_with_di(self):
        """Delegated rotation with di field parses successfully."""
        event_dict = {
            "t": "drt",
            "s": "1",
            "p": "PRIOR_DIGEST",
            "d": "SAID_PLACEHOLDER",
            "k": [TEST_KEY_2],
            "di": "EDelegatorAID00000000000000000000000000000",
        }

        event = _parse_event_dict(event_dict)
        assert event.event_type == EventType.DRT
        assert event.delegator_aid == "EDelegatorAID00000000000000000000000000000"
        assert event.is_delegated is True

    def test_parse_delegated_rotation_missing_di_raises(self):
        """Delegated rotation missing di field raises ResolutionFailedError."""
        event_dict = {
            "t": "drt",
            "s": "1",
            "p": "PRIOR_DIGEST",
            "d": "SAID_PLACEHOLDER",
            "k": [TEST_KEY_2],
            # Missing "di" field
        }

        with pytest.raises(ResolutionFailedError) as exc_info:
            _parse_event_dict(event_dict)
        assert "missing required 'di' field" in str(exc_info.value)

    def test_parse_hex_sequence_number(self):
        """Parse sequence number in hex format."""
        event_dict = {
            "t": "icp",
            "s": "a",  # hex for 10
            "d": "SAID_PLACEHOLDER",
            "k": [TEST_KEY_1],
        }

        event = _parse_event_dict(event_dict)
        assert event.sequence == 10

    def test_parse_unknown_event_type(self):
        """Reject unknown event types."""
        event_dict = {
            "t": "unknown",
            "s": "0",
        }

        with pytest.raises(ResolutionFailedError, match="Unknown event type"):
            _parse_event_dict(event_dict)


class TestParseKelStream:
    """Test parsing complete KEL streams."""

    def test_parse_single_event_json(self):
        """Parse a single event in JSON format."""
        event_dict = {
            "t": "icp",
            "s": "0",
            "d": "SAID",
            "k": [TEST_KEY_1],
            "signatures": [TEST_SIG],
        }
        kel_data = json.dumps(event_dict).encode()

        events = parse_kel_stream(kel_data)

        assert len(events) == 1
        assert events[0].event_type == EventType.ICP

    def test_parse_multiple_events_json(self):
        """Parse multiple events in JSON array format."""
        events_list = [
            {
                "t": "icp",
                "s": "0",
                "d": "SAID_0",
                "k": [TEST_KEY_1],
                "signatures": [TEST_SIG],
            },
            {
                "t": "rot",
                "s": "1",
                "p": "SAID_0",
                "d": "SAID_1",
                "k": [TEST_KEY_2],
                "signatures": [TEST_SIG],
            },
        ]
        kel_data = json.dumps(events_list).encode()

        events = parse_kel_stream(kel_data)

        assert len(events) == 2
        assert events[0].sequence == 0
        assert events[1].sequence == 1

    def test_parse_unsorted_events_are_sorted(self):
        """Events are sorted by sequence number."""
        events_list = [
            {"t": "rot", "s": "1", "p": "SAID_0", "d": "SAID_1", "k": [TEST_KEY_2]},
            {"t": "icp", "s": "0", "d": "SAID_0", "k": [TEST_KEY_1]},
        ]
        kel_data = json.dumps(events_list).encode()

        events = parse_kel_stream(kel_data)

        assert events[0].sequence == 0
        assert events[1].sequence == 1

    def test_parse_invalid_json(self):
        """Reject invalid JSON."""
        kel_data = b"not valid json {"

        with pytest.raises(ResolutionFailedError):
            parse_kel_stream(kel_data)

    def test_parse_invalid_json_structure(self):
        """Reject JSON that's not a dict or list."""
        kel_data = b'"just a string"'

        with pytest.raises(ResolutionFailedError, match="Invalid JSON KEL format"):
            parse_kel_stream(kel_data)


class TestKELEventProperties:
    """Test KELEvent property methods."""

    def test_is_establishment_inception(self):
        """Inception is an establishment event."""
        event = KELEvent(
            event_type=EventType.ICP,
            sequence=0,
            prior_digest="",
            digest="SAID",
            signing_keys=[],
            next_keys_digest=None,
            toad=0,
            witnesses=[],
        )
        assert event.is_establishment
        assert event.is_inception

    def test_is_establishment_rotation(self):
        """Rotation is an establishment event."""
        event = KELEvent(
            event_type=EventType.ROT,
            sequence=1,
            prior_digest="PRIOR",
            digest="SAID",
            signing_keys=[],
            next_keys_digest=None,
            toad=0,
            witnesses=[],
        )
        assert event.is_establishment
        assert not event.is_inception

    def test_is_not_establishment_interaction(self):
        """Interaction is not an establishment event."""
        event = KELEvent(
            event_type=EventType.IXN,
            sequence=1,
            prior_digest="PRIOR",
            digest="SAID",
            signing_keys=[],
            next_keys_digest=None,
            toad=0,
            witnesses=[],
        )
        assert not event.is_establishment
        assert not event.is_inception


class TestComputeSAID:
    """Test SAID computation."""

    def test_compute_said_deterministic(self):
        """SAID computation is deterministic."""
        data = {"t": "icp", "s": "0", "k": [TEST_KEY_1]}

        said1 = compute_said(data)
        said2 = compute_said(data)

        assert said1 == said2
        assert said1.startswith("E")  # Blake3-256 derivation code

    def test_compute_said_different_for_different_data(self):
        """Different data produces different SAIDs."""
        data1 = {"t": "icp", "s": "0", "k": [TEST_KEY_1]}
        data2 = {"t": "icp", "s": "1", "k": [TEST_KEY_1]}

        said1 = compute_said(data1)
        said2 = compute_said(data2)

        assert said1 != said2
