"""
Tests for CESR stream parser.

These tests verify that the CESR parser correctly handles:
- JSON events with attached signatures
- Count codes for different attachment types
- Error handling for malformed streams
"""

import json
import base64
from pathlib import Path

import pytest

from app.vvp.keri.cesr import (
    CESRMessage,
    CountCode,
    WitnessReceipt,
    _b64_to_int,
    _parse_count_code,
    is_cesr_stream,
    parse_cesr_stream,
)
from app.vvp.keri.exceptions import ResolutionFailedError, CESRMalformedError


# Fixtures directory
FIXTURES_DIR = Path(__file__).parent / "fixtures" / "keri"


def load_fixture(name: str) -> dict:
    """Load a JSON fixture file."""
    path = FIXTURES_DIR / name
    with open(path) as f:
        return json.load(f)


class TestB64ToInt:
    """Tests for base64 to integer conversion."""

    def test_single_char(self):
        """Single character conversion."""
        assert _b64_to_int("A") == 0
        assert _b64_to_int("B") == 1
        assert _b64_to_int("Z") == 25
        assert _b64_to_int("a") == 26
        assert _b64_to_int("z") == 51
        assert _b64_to_int("0") == 52
        assert _b64_to_int("9") == 61
        assert _b64_to_int("-") == 62
        assert _b64_to_int("_") == 63

    def test_multi_char(self):
        """Multi-character conversion."""
        # "AA" = 0 * 64 + 0 = 0
        assert _b64_to_int("AA") == 0
        # "AB" = 0 * 64 + 1 = 1
        assert _b64_to_int("AB") == 1
        # "BA" = 1 * 64 + 0 = 64
        assert _b64_to_int("BA") == 64
        # "BB" = 1 * 64 + 1 = 65
        assert _b64_to_int("BB") == 65


class TestParseCountCode:
    """Tests for count code parsing."""

    def test_controller_sigs_code(self):
        """Parse -A count code."""
        data = b"-AAB"  # -A with count 1
        code, count, offset = _parse_count_code(data, 0)
        assert code == "-A"
        assert count == 1
        assert offset == 4

    def test_witness_sigs_code(self):
        """Parse -B count code."""
        data = b"-BAC"  # -B with count 2
        code, count, offset = _parse_count_code(data, 0)
        assert code == "-B"
        assert count == 2
        assert offset == 4

    def test_receipt_couples_code(self):
        """Parse -C count code."""
        data = b"-CAD"  # -C with count 3
        code, count, offset = _parse_count_code(data, 0)
        assert code == "-C"
        assert count == 3
        assert offset == 4

    def test_version_marker(self):
        """Parse CESR version marker."""
        data = b"-_AAAKERI10JSON000000_"
        code, count, offset = _parse_count_code(data, 0)
        assert code == "-_AAA"
        assert offset == 8

    def test_truncated_code(self):
        """Truncated count code raises error."""
        with pytest.raises(ResolutionFailedError):
            _parse_count_code(b"-A", 0)  # Missing count chars

    def test_unknown_code(self):
        """Unknown count code raises CESRMalformedError."""
        with pytest.raises(CESRMalformedError):
            _parse_count_code(b"-XAB", 0)


class TestIsCesrStream:
    """Tests for CESR detection."""

    def test_version_marker(self):
        """Detect CESR version marker."""
        assert is_cesr_stream(b"-_AAAKERI10")

    def test_count_code(self):
        """Detect count code."""
        assert is_cesr_stream(b"-AAB0A...")

    def test_json_only(self):
        """Plain JSON is not detected as CESR."""
        assert not is_cesr_stream(b'{"v":"KERI10JSON"}')

    def test_json_with_attachment(self):
        """JSON followed by count code is CESR."""
        data = b'{"v":"KERI10JSON","t":"icp"}-AAB'
        assert is_cesr_stream(data)

    def test_empty(self):
        """Empty data is not CESR."""
        assert not is_cesr_stream(b"")


class TestParseCesrStream:
    """Tests for CESR stream parsing."""

    def test_empty_stream(self):
        """Empty stream returns empty list."""
        result = parse_cesr_stream(b"")
        assert result == []

    def test_json_only(self):
        """Parse JSON without attachments."""
        event = {"v": "KERI10JSON000100_", "t": "icp", "d": "ESAID", "i": "DAID"}
        data = json.dumps(event).encode("utf-8")

        result = parse_cesr_stream(data)

        assert len(result) == 1
        assert result[0].event_dict == event
        assert result[0].controller_sigs == []
        assert result[0].witness_receipts == []

    def test_multiple_events(self):
        """Parse multiple JSON events."""
        event1 = {"v": "KERI10JSON000100_", "t": "icp", "d": "ESAID1", "i": "DAID"}
        event2 = {"v": "KERI10JSON000100_", "t": "rot", "d": "ESAID2", "i": "DAID"}
        data = json.dumps(event1).encode() + b"\n" + json.dumps(event2).encode()

        result = parse_cesr_stream(data)

        assert len(result) == 2
        assert result[0].event_dict["d"] == "ESAID1"
        assert result[1].event_dict["d"] == "ESAID2"

    def test_with_version_marker(self):
        """Parse stream with version marker."""
        event = {"v": "KERI10JSON000100_", "t": "icp", "d": "ESAID", "i": "DAID"}
        # Version marker is 8 chars total: -_AAA + 3 chars for version/count
        # After the 8-char version marker, JSON follows directly
        data = b"-_AAABAA" + json.dumps(event).encode()

        result = parse_cesr_stream(data)

        assert len(result) == 1
        assert result[0].event_dict == event

    def test_malformed_json(self):
        """Malformed JSON raises error."""
        with pytest.raises(ResolutionFailedError) as exc:
            parse_cesr_stream(b'{"v": "KERI", "t": ')

        assert "Invalid JSON" in str(exc.value) or "Unterminated" in str(exc.value)


class TestCESRMessageDataclass:
    """Tests for CESRMessage dataclass."""

    def test_default_values(self):
        """Default values are correct."""
        msg = CESRMessage(event_bytes=b"{}", event_dict={})
        assert msg.controller_sigs == []
        assert msg.witness_receipts == []
        assert msg.raw == b""

    def test_with_signatures(self):
        """Message with signatures."""
        msg = CESRMessage(
            event_bytes=b"{}",
            event_dict={},
            controller_sigs=[b"sig1", b"sig2"],
        )
        assert len(msg.controller_sigs) == 2

    def test_with_receipts(self):
        """Message with witness receipts."""
        receipt = WitnessReceipt(witness_aid="BWITNESS", signature=b"sig")
        msg = CESRMessage(
            event_bytes=b"{}",
            event_dict={},
            witness_receipts=[receipt],
        )
        assert len(msg.witness_receipts) == 1
        assert msg.witness_receipts[0].witness_aid == "BWITNESS"


class TestWitnessReceiptDataclass:
    """Tests for WitnessReceipt dataclass."""

    def test_creation(self):
        """Create a witness receipt."""
        receipt = WitnessReceipt(witness_aid="BWITNESS", signature=b"sig")
        assert receipt.witness_aid == "BWITNESS"
        assert receipt.signature == b"sig"


class TestWithKeriPyFixtures:
    """Integration tests using keripy-generated fixtures."""

    @pytest.fixture
    def icp_fixture(self):
        """Load ICP fixture."""
        return load_fixture("icp_keripy.json")

    def test_parse_icp_event_bytes(self, icp_fixture):
        """Parse ICP event from canonical bytes."""
        canonical_bytes = base64.urlsafe_b64decode(icp_fixture["canonical_bytes"])

        result = parse_cesr_stream(canonical_bytes)

        assert len(result) == 1
        msg = result[0]
        assert msg.event_dict["t"] == "icp"
        assert msg.event_dict["d"] == icp_fixture["said"]

    def test_parse_kel_stream(self):
        """Parse complete KEL stream from fixture."""
        kel_fixture = load_fixture("kel_stream_keripy.json")
        events = kel_fixture["events"]

        # Concatenate all events as JSON (without CESR attachments for this test)
        data = b"".join(json.dumps(e).encode() for e in events)

        result = parse_cesr_stream(data)

        assert len(result) == len(events)
        for i, msg in enumerate(result):
            assert msg.event_dict["t"] == events[i]["t"]
            assert msg.event_dict["d"] == events[i]["d"]


# =============================================================================
# Additional cesr.py coverage tests - Phase 5
# =============================================================================


class TestParseCountCodeCoverage:
    """Additional tests for _parse_count_code coverage."""

    def test_end_of_stream_raises(self):
        """Parsing at end of stream raises error."""
        data = b""
        with pytest.raises(ResolutionFailedError, match="Unexpected end"):
            _parse_count_code(data, 0)

    def test_end_of_stream_with_offset(self):
        """Parsing past end of stream raises error."""
        data = b"-AAA"
        with pytest.raises(ResolutionFailedError, match="Unexpected end"):
            _parse_count_code(data, 10)

    def test_truncated_version_string(self):
        """Truncated version string raises error."""
        data = b"-_AAA1"  # Only 6 chars, needs 8
        with pytest.raises(ResolutionFailedError, match="Truncated CESR version"):
            _parse_count_code(data, 0)

    def test_truncated_count_code(self):
        """Truncated count code (less than 2 chars) raises error."""
        data = b"-"  # Only 1 char
        with pytest.raises(ResolutionFailedError, match="Truncated count code"):
            _parse_count_code(data, 0)

    def test_big_count_code_parsing(self):
        """Big count codes (--V prefix) are parsed correctly."""
        # --V count code is 3-char hard + 3-char soft (6 chars total)
        # Build a valid --V code: --VAA (count of 0)
        # Actually --V requires 5 char soft code per COUNT_CODE_SIZES
        # Let's check what codes are supported
        from app.vvp.keri.cesr import COUNT_CODE_SIZES

        # Only test if --V is in COUNT_CODE_SIZES
        if "--V" in COUNT_CODE_SIZES:
            _, ss, fs = COUNT_CODE_SIZES["--V"]
            # Build valid code
            data = b"--V" + b"A" * ss
            code, count, offset = _parse_count_code(data, 0)
            assert code == "--V"
            assert offset == fs


class TestParseIndexedSignatureCoverage:
    """Additional tests for _parse_indexed_signature coverage."""

    def test_truncated_signature_at_start(self):
        """Truncated stream at start raises error."""
        from app.vvp.keri.cesr import _parse_indexed_signature

        data = b"0"  # Only 1 byte, needs at least 2
        with pytest.raises(ResolutionFailedError, match="Truncated signature"):
            _parse_indexed_signature(data, 0)

    def test_truncated_ed25519_signature(self):
        """Truncated Ed25519 signature raises error."""
        from app.vvp.keri.cesr import _parse_indexed_signature

        # 0A code but only partial signature
        data = b"0A" + b"A" * 30  # Only 32 bytes total, needs 88
        with pytest.raises(ResolutionFailedError, match="Truncated Ed25519"):
            _parse_indexed_signature(data, 0)

    def test_4char_code_truncated(self):
        """4-char derivation code with truncated signature raises error."""
        from app.vvp.keri.cesr import _parse_indexed_signature

        # 1AAA code but only partial signature
        data = b"1AAA" + b"A" * 30  # Only 34 bytes total, needs 88
        with pytest.raises(ResolutionFailedError, match="Truncated Ed25519 indexed"):
            _parse_indexed_signature(data, 0)

    def test_unknown_derivation_code(self):
        """Unknown derivation code raises error."""
        from app.vvp.keri.cesr import _parse_indexed_signature

        data = b"ZZ" + b"A" * 86  # Unknown code
        with pytest.raises(ResolutionFailedError, match="Unknown signature derivation"):
            _parse_indexed_signature(data, 0)


class TestFindJsonEndCoverage:
    """Additional tests for _find_json_end coverage."""

    def test_json_with_escaped_chars(self):
        """JSON with escaped characters is handled correctly."""
        from app.vvp.keri.cesr import _find_json_end

        data = b'{"key": "value with \\\\ backslash"}'
        end = _find_json_end(data, 0)
        assert end == len(data)

    def test_json_with_escaped_quote(self):
        """JSON with escaped quote is handled correctly."""
        from app.vvp.keri.cesr import _find_json_end

        data = b'{"key": "value with \\" quote"}'
        end = _find_json_end(data, 0)
        assert end == len(data)

    def test_unterminated_json(self):
        """Unterminated JSON raises error."""
        from app.vvp.keri.cesr import _find_json_end

        data = b'{"key": "value"'  # Missing closing brace
        with pytest.raises(ResolutionFailedError, match="Unterminated JSON"):
            _find_json_end(data, 0)


class TestParseCesrStreamCoverage:
    """Additional tests for parse_cesr_stream coverage."""

    def test_whitespace_skipping(self):
        """Whitespace between events is skipped."""
        event1 = b'{"t":"icp","d":"ESAID1"}'
        event2 = b'{"t":"rot","d":"ESAID2"}'
        data = event1 + b"   \n\r\t   " + event2  # Lots of whitespace

        result = parse_cesr_stream(data)
        assert len(result) == 2

    def test_json_parse_error(self):
        """Unterminated JSON raises error."""
        # Properly unterminated - has opening but no closing brace
        data = b'{"key": "value"'  # Missing closing brace
        with pytest.raises(ResolutionFailedError, match="Unterminated JSON"):
            parse_cesr_stream(data)

    def test_unknown_byte_raises(self):
        """Unknown byte in stream raises error."""
        # Start with something that's not { or -
        data = b"UNKNOWN"
        with pytest.raises(ResolutionFailedError, match="Unexpected byte"):
            parse_cesr_stream(data)

    def test_whitespace_only_after_json(self):
        """Whitespace only after JSON doesn't cause issues."""
        event = b'{"t":"icp","d":"ESAID"}'
        data = event + b"   \n\t  "  # Trailing whitespace

        result = parse_cesr_stream(data)
        assert len(result) == 1

    def test_attachment_group_passthrough(self):
        """Attachment group codes (-V, --V) are passed through."""
        # This test verifies that -V codes don't crash
        event = b'{"t":"icp","d":"ESAID"}'
        # -VAA is an attachment group count code (count=0)
        attachment = b"-VAA"
        data = event + attachment

        result = parse_cesr_stream(data)
        assert len(result) == 1


class TestIsCesrStreamCoverage:
    """Additional tests for is_cesr_stream coverage."""

    def test_json_without_attachments_false(self):
        """Plain JSON without CESR attachments returns False."""
        data = b'{"key": "value"}'
        assert is_cesr_stream(data) is False

    def test_json_with_trailing_count_code_true(self):
        """JSON followed by count code returns True."""
        data = b'{"key": "value"}-AAA'
        assert is_cesr_stream(data) is True

    def test_json_parse_error_returns_false(self):
        """Invalid JSON returns False (no crash)."""
        data = b'{"invalid'
        # Should not crash, just return False
        assert is_cesr_stream(data) is False


class TestDecodePssSignatureCoverage:
    """Additional tests for decode_pss_signature coverage."""

    def test_invalid_base64_encoding(self):
        """Invalid base64 in signature raises error."""
        from app.vvp.keri.cesr import decode_pss_signature

        # Valid code but bytes that will fail proper base64 decoding
        # Use non-printable chars that result in decode failure or wrong length
        invalid_sig = "0A" + "\xff" * 86  # 88 chars with non-base64 chars
        with pytest.raises(ResolutionFailedError):
            decode_pss_signature(invalid_sig)
