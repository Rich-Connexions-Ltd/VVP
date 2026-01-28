"""Tests for OOBI (Out-of-Band Introduction) dereferencing.

Coverage target: app/vvp/keri/oobi.py (21% → 75%)
"""

import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

import httpx

from app.vvp.keri.oobi import (
    dereference_oobi,
    fetch_kel_from_witnesses,
    validate_oobi_is_kel,
    _extract_aid_from_url,
    _extract_witnesses,
    OOBIResult,
    CESR_CONTENT_TYPE,
    JSON_CONTENT_TYPE,
)
from app.vvp.keri.exceptions import (
    OOBIContentInvalidError,
    ResolutionFailedError,
)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def sample_icp_event():
    """Sample inception event for testing."""
    return {
        "v": "KERI10JSON000000_",
        "t": "icp",
        "d": "EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UlsMlymgo0",
        "i": "EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UlsMlymgo0",
        "s": "0",
        "kt": "1",
        "k": ["DqI2cOZ06RwGNwCovYUWExmdKU983IasmUKMmZflvWdQ"],
        "nt": "1",
        "n": ["EFGH123"],
        "bt": "0",
        "b": ["BBfxWitness1", "BBfxWitness2"],
        "c": [],
        "a": [],
    }


@pytest.fixture
def sample_rot_event():
    """Sample rotation event for testing."""
    return {
        "v": "KERI10JSON000000_",
        "t": "rot",
        "d": "ESAID_ROT_EVENT",
        "i": "EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UlsMlymgo0",
        "s": "1",
        "p": "EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UlsMlymgo0",
        "kt": "1",
        "k": ["DNewKey123"],
        "nt": "1",
        "n": ["EIJK456"],
        "bt": "0",
        "b": ["BBfxWitness3"],
        "br": [],
        "ba": [],
        "a": [],
    }


@pytest.fixture
def mock_httpx_response():
    """Create a mock httpx response."""
    def _create(
        status_code: int = 200,
        content: bytes = b'{}',
        content_type: str = "application/json"
    ):
        response = MagicMock()
        response.status_code = status_code
        response.content = content
        response.headers = {"content-type": content_type}
        return response
    return _create


@pytest.fixture
def mock_httpx_client(mock_httpx_response):
    """Create a mock httpx.AsyncClient."""
    def _create(response=None, side_effect=None):
        mock_client = AsyncMock()
        if side_effect:
            mock_client.get = AsyncMock(side_effect=side_effect)
        else:
            mock_client.get = AsyncMock(return_value=response or mock_httpx_response())
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        return mock_client
    return _create


# =============================================================================
# TestDereferenceOOBI - Core OOBI dereferencing tests
# =============================================================================


class TestDereferenceOOBI:
    """Tests for main OOBI dereferencing function."""

    @pytest.mark.asyncio
    async def test_valid_json_response(self, mock_httpx_client, mock_httpx_response, sample_icp_event):
        """200 with application/json returns OOBIResult."""
        content = json.dumps(sample_icp_event).encode()
        response = mock_httpx_response(200, content, "application/json")
        mock_client = mock_httpx_client(response)

        with patch("app.vvp.keri.oobi.httpx.AsyncClient", return_value=mock_client):
            result = await dereference_oobi("http://example.com/oobi/EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UlsMlymgo0")

        assert isinstance(result, OOBIResult)
        assert result.content_type == JSON_CONTENT_TYPE
        assert result.kel_data == content
        assert result.aid == "EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UlsMlymgo0"

    @pytest.mark.asyncio
    async def test_valid_cesr_response(self, mock_httpx_client, mock_httpx_response):
        """200 with application/json+cesr detected correctly."""
        content = b'{"t":"icp","d":"ESAID"}'
        response = mock_httpx_response(200, content, "application/json+cesr")
        mock_client = mock_httpx_client(response)

        with patch("app.vvp.keri.oobi.httpx.AsyncClient", return_value=mock_client):
            result = await dereference_oobi("http://example.com/oobi/EAID123")

        assert result.content_type == CESR_CONTENT_TYPE

    @pytest.mark.asyncio
    async def test_octet_stream_cesr_detection_dash(self, mock_httpx_client, mock_httpx_response):
        """Detect CESR from octet-stream by '-' first byte marker."""
        # '-' (0x2D) is a CESR count code marker
        content = b'-VAi-HABEBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UlsMlymgo0'
        response = mock_httpx_response(200, content, "application/octet-stream")
        mock_client = mock_httpx_client(response)

        with patch("app.vvp.keri.oobi.httpx.AsyncClient", return_value=mock_client):
            result = await dereference_oobi("http://example.com/oobi/EAID123")

        assert result.content_type == CESR_CONTENT_TYPE

    @pytest.mark.asyncio
    async def test_octet_stream_cesr_detection_zero(self, mock_httpx_client, mock_httpx_response):
        """Detect CESR from octet-stream by '0' first byte marker."""
        content = b'0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
        response = mock_httpx_response(200, content, "application/octet-stream")
        mock_client = mock_httpx_client(response)

        with patch("app.vvp.keri.oobi.httpx.AsyncClient", return_value=mock_client):
            result = await dereference_oobi("http://example.com/oobi/EAID123")

        assert result.content_type == CESR_CONTENT_TYPE

    @pytest.mark.asyncio
    async def test_octet_stream_non_cesr_defaults_json(self, mock_httpx_client, mock_httpx_response):
        """Non-CESR octet-stream defaults to JSON content type."""
        content = b'{"regular": "json"}'
        response = mock_httpx_response(200, content, "application/octet-stream")
        mock_client = mock_httpx_client(response)

        with patch("app.vvp.keri.oobi.httpx.AsyncClient", return_value=mock_client):
            result = await dereference_oobi("http://example.com/oobi/EAID123")

        # First byte is '{' (0x7B), not a CESR marker
        assert result.content_type == JSON_CONTENT_TYPE

    @pytest.mark.asyncio
    async def test_invalid_url_no_scheme(self):
        """Malformed URL (no scheme) raises ResolutionFailedError."""
        with pytest.raises(ResolutionFailedError, match="Invalid OOBI URL"):
            await dereference_oobi("example.com/oobi/EAID")

    @pytest.mark.asyncio
    async def test_invalid_url_no_netloc(self):
        """Malformed URL (no netloc) raises ResolutionFailedError."""
        with pytest.raises(ResolutionFailedError, match="Invalid OOBI URL"):
            await dereference_oobi("http:///oobi/EAID")

    @pytest.mark.asyncio
    async def test_http_404_raises(self, mock_httpx_client, mock_httpx_response):
        """HTTP 404 raises ResolutionFailedError."""
        response = mock_httpx_response(404, b"Not Found")
        mock_client = mock_httpx_client(response)

        with patch("app.vvp.keri.oobi.httpx.AsyncClient", return_value=mock_client):
            with pytest.raises(ResolutionFailedError, match="HTTP 404"):
                await dereference_oobi("http://example.com/oobi/EAID123")

    @pytest.mark.asyncio
    async def test_http_500_raises(self, mock_httpx_client, mock_httpx_response):
        """HTTP 500 raises ResolutionFailedError."""
        response = mock_httpx_response(500, b"Server Error")
        mock_client = mock_httpx_client(response)

        with patch("app.vvp.keri.oobi.httpx.AsyncClient", return_value=mock_client):
            with pytest.raises(ResolutionFailedError, match="HTTP 500"):
                await dereference_oobi("http://example.com/oobi/EAID123")

    @pytest.mark.asyncio
    async def test_timeout_raises(self, mock_httpx_client):
        """httpx.TimeoutException raises ResolutionFailedError."""
        mock_client = mock_httpx_client(side_effect=httpx.TimeoutException("timeout"))

        with patch("app.vvp.keri.oobi.httpx.AsyncClient", return_value=mock_client):
            with pytest.raises(ResolutionFailedError, match="timeout"):
                await dereference_oobi("http://example.com/oobi/EAID123")

    @pytest.mark.asyncio
    async def test_network_error_raises(self, mock_httpx_client):
        """httpx.RequestError raises ResolutionFailedError."""
        mock_client = mock_httpx_client(
            side_effect=httpx.RequestError("Connection refused")
        )

        with patch("app.vvp.keri.oobi.httpx.AsyncClient", return_value=mock_client):
            with pytest.raises(ResolutionFailedError, match="network error"):
                await dereference_oobi("http://example.com/oobi/EAID123")

    @pytest.mark.asyncio
    async def test_empty_response_raises(self, mock_httpx_client, mock_httpx_response):
        """Empty response body raises ResolutionFailedError."""
        response = mock_httpx_response(200, b"", "application/json")
        mock_client = mock_httpx_client(response)

        with patch("app.vvp.keri.oobi.httpx.AsyncClient", return_value=mock_client):
            with pytest.raises(ResolutionFailedError, match="empty"):
                await dereference_oobi("http://example.com/oobi/EAID123")

    @pytest.mark.asyncio
    async def test_invalid_content_type_raises(self, mock_httpx_client, mock_httpx_response):
        """Invalid content-type raises OOBIContentInvalidError."""
        response = mock_httpx_response(200, b"data", "application/xml")
        mock_client = mock_httpx_client(response)

        with patch("app.vvp.keri.oobi.httpx.AsyncClient", return_value=mock_client):
            with pytest.raises(OOBIContentInvalidError, match="Invalid OOBI content type"):
                await dereference_oobi("http://example.com/oobi/EAID123")

    @pytest.mark.asyncio
    async def test_text_content_type_lenient(self, mock_httpx_client, mock_httpx_response):
        """text/* content-type is accepted (lenient mode)."""
        content = b'{"t":"icp"}'
        response = mock_httpx_response(200, content, "text/plain")
        mock_client = mock_httpx_client(response)

        with patch("app.vvp.keri.oobi.httpx.AsyncClient", return_value=mock_client):
            result = await dereference_oobi("http://example.com/oobi/EAID123")

        # text/plain is accepted leniently
        assert result.kel_data == content

    @pytest.mark.asyncio
    async def test_missing_content_type_lenient(self, mock_httpx_client):
        """Missing content-type header accepted with fallback to JSON."""
        response = MagicMock()
        response.status_code = 200
        response.content = b'{"t":"icp"}'
        response.headers = {}  # No content-type header
        mock_client = mock_httpx_client(response)

        with patch("app.vvp.keri.oobi.httpx.AsyncClient", return_value=mock_client):
            result = await dereference_oobi("http://example.com/oobi/EAID123")

        # Default to JSON when no content-type
        assert result.content_type == JSON_CONTENT_TYPE

    @pytest.mark.asyncio
    async def test_extracts_witnesses_from_json(self, mock_httpx_client, mock_httpx_response, sample_icp_event):
        """Witnesses are extracted from JSON KEL response."""
        content = json.dumps(sample_icp_event).encode()
        response = mock_httpx_response(200, content, "application/json")
        mock_client = mock_httpx_client(response)

        with patch("app.vvp.keri.oobi.httpx.AsyncClient", return_value=mock_client):
            result = await dereference_oobi("http://example.com/oobi/EAID123")

        assert "BBfxWitness1" in result.witnesses
        assert "BBfxWitness2" in result.witnesses

    @pytest.mark.asyncio
    async def test_generic_exception_wrapped(self, mock_httpx_client):
        """Generic exceptions are wrapped in ResolutionFailedError."""
        mock_client = mock_httpx_client(side_effect=RuntimeError("Unexpected"))

        with patch("app.vvp.keri.oobi.httpx.AsyncClient", return_value=mock_client):
            with pytest.raises(ResolutionFailedError, match="Unexpected"):
                await dereference_oobi("http://example.com/oobi/EAID123")


# =============================================================================
# TestExtractAidFromUrl - AID extraction tests
# =============================================================================


class TestExtractAidFromUrl:
    """Tests for _extract_aid_from_url helper."""

    def test_extract_from_oobi_path(self):
        """/oobi/{aid} format extracts AID."""
        url = "http://example.com/oobi/EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UlsMlymgo0"
        aid = _extract_aid_from_url(url)
        assert aid == "EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UlsMlymgo0"

    def test_extract_with_witness_suffix(self):
        """/oobi/{aid}/witness/{wit_aid} extracts main AID."""
        url = "http://example.com/oobi/EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UlsMlymgo0/witness/BBfxWitness"
        aid = _extract_aid_from_url(url)
        assert aid == "EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UlsMlymgo0"

    def test_extract_with_controller_suffix(self):
        """/oobi/{aid}/controller extracts main AID."""
        url = "http://example.com/oobi/DBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UlsMlymgo0/controller"
        aid = _extract_aid_from_url(url)
        assert aid == "DBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UlsMlymgo0"

    def test_case_insensitive_oobi(self):
        """OOBI path segment matching is case-insensitive."""
        url = "http://example.com/OOBI/EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UlsMlymgo0"
        aid = _extract_aid_from_url(url)
        assert aid == "EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UlsMlymgo0"

    def test_fallback_to_last_segment(self):
        """Use last path segment if no /oobi/ found and segment looks like AID."""
        # No /oobi/ segment, but last segment is >40 chars and starts with valid code
        url = "http://example.com/keri/aid/EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UlsMlymgo0"
        aid = _extract_aid_from_url(url)
        assert aid == "EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UlsMlymgo0"

    def test_reject_short_segment(self):
        """Segment <40 chars rejected in fallback."""
        url = "http://example.com/keri/EShortAID"
        aid = _extract_aid_from_url(url)
        assert aid == ""

    def test_return_empty_when_no_aid(self):
        """No valid AID returns empty string."""
        url = "http://example.com/api/v1/status"
        aid = _extract_aid_from_url(url)
        assert aid == ""

    def test_invalid_derivation_code_rejected(self):
        """Segment not starting with valid KERI code rejected."""
        # 'a' is not a valid KERI derivation code (must be uppercase)
        url = "http://example.com/oobi/abcdefghijklmnopqrstuvwxyz1234567890123456"
        aid = _extract_aid_from_url(url)
        assert aid == ""

    def test_various_valid_derivation_codes(self):
        """Various valid KERI derivation codes are accepted."""
        for code in "BDEFGHJKLMNOPQRSTUVWXYZ":
            aid_base = code + "Bfxc4RiVY6saIFmUfEtETs1FcqmktZW88UlsMlymgo0"
            url = f"http://example.com/oobi/{aid_base}"
            aid = _extract_aid_from_url(url)
            assert aid == aid_base, f"Failed for code {code}"


# =============================================================================
# TestExtractWitnesses - Witness extraction tests
# =============================================================================


class TestExtractWitnesses:
    """Tests for _extract_witnesses helper."""

    def test_single_event_with_witnesses(self, sample_icp_event):
        """Extract from single event dict with 'b' field."""
        kel_data = json.dumps(sample_icp_event).encode()
        witnesses = _extract_witnesses(kel_data, "EAID")
        assert "BBfxWitness1" in witnesses
        assert "BBfxWitness2" in witnesses

    def test_event_array_finds_last_establishment(self, sample_icp_event, sample_rot_event):
        """Array processing finds most recent establishment event."""
        # Rotation event is last and has BBfxWitness3
        events = [sample_icp_event, sample_rot_event]
        kel_data = json.dumps(events).encode()
        witnesses = _extract_witnesses(kel_data, "EAID")
        # Should find witnesses from rotation (most recent establishment)
        assert "BBfxWitness3" in witnesses

    def test_skip_non_establishment_events(self, sample_icp_event):
        """Skip ixn events to find icp/rot."""
        ixn_event = {
            "t": "ixn",
            "d": "ESAID_IXN",
            "i": "EAID",
            "s": "1",
            "p": sample_icp_event["d"],
            "a": [],
        }
        events = [sample_icp_event, ixn_event]
        kel_data = json.dumps(events).encode()
        witnesses = _extract_witnesses(kel_data, "EAID")
        # Should find witnesses from icp (ixn has no witnesses)
        assert "BBfxWitness1" in witnesses
        assert "BBfxWitness2" in witnesses

    def test_malformed_json_returns_empty(self):
        """Malformed JSON returns empty list gracefully."""
        witnesses = _extract_witnesses(b"not valid json", "EAID")
        assert witnesses == []

    def test_cesr_binary_returns_empty(self):
        """CESR binary data returns empty list gracefully."""
        # CESR binary data is not JSON parseable
        witnesses = _extract_witnesses(b"-VAi-HAB...", "EAID")
        assert witnesses == []

    def test_missing_b_field_returns_empty(self):
        """Event without 'b' field returns empty list."""
        event = {"t": "icp", "d": "ESAID", "i": "EAID", "s": "0"}
        kel_data = json.dumps(event).encode()
        witnesses = _extract_witnesses(kel_data, "EAID")
        assert witnesses == []

    def test_empty_witnesses_list(self, sample_icp_event):
        """Empty 'b' field returns empty list."""
        sample_icp_event["b"] = []
        kel_data = json.dumps(sample_icp_event).encode()
        witnesses = _extract_witnesses(kel_data, "EAID")
        assert witnesses == []

    def test_dip_event_witnesses(self):
        """Delegated inception (dip) event witnesses extracted."""
        dip_event = {
            "t": "dip",
            "d": "ESAID_DIP",
            "i": "EAID_DIP",
            "s": "0",
            "b": ["BDipWitness1"],
        }
        kel_data = json.dumps(dip_event).encode()
        witnesses = _extract_witnesses(kel_data, "EAID_DIP")
        assert "BDipWitness1" in witnesses

    def test_drt_event_witnesses(self):
        """Delegated rotation (drt) event witnesses extracted."""
        drt_event = {
            "t": "drt",
            "d": "ESAID_DRT",
            "i": "EAID",
            "s": "1",
            "b": ["BDrtWitness1"],
        }
        events = [{"t": "dip", "d": "ESAID_DIP", "b": []}, drt_event]
        kel_data = json.dumps(events).encode()
        witnesses = _extract_witnesses(kel_data, "EAID")
        assert "BDrtWitness1" in witnesses


# =============================================================================
# TestFetchKelFromWitnesses - Multi-witness fetching tests
# =============================================================================


class TestFetchKelFromWitnesses:
    """Tests for fetch_kel_from_witnesses function."""

    @pytest.mark.asyncio
    async def test_single_witness_success(self, mock_httpx_client, mock_httpx_response, sample_icp_event):
        """Single witness fetch succeeds."""
        content = json.dumps(sample_icp_event).encode()
        response = mock_httpx_response(200, content, "application/json")
        mock_client = mock_httpx_client(response)

        with patch("app.vvp.keri.oobi.httpx.AsyncClient", return_value=mock_client):
            result = await fetch_kel_from_witnesses(
                aid="EAID123",
                witnesses=["http://witness1.example.com/oobi/EAID123"]
            )

        assert isinstance(result, OOBIResult)
        assert result.kel_data == content

    @pytest.mark.asyncio
    async def test_multiple_witnesses_parallel(self, mock_httpx_client, mock_httpx_response, sample_icp_event):
        """Parallel fetch from multiple witnesses."""
        content = json.dumps(sample_icp_event).encode()
        response = mock_httpx_response(200, content, "application/json")
        mock_client = mock_httpx_client(response)

        with patch("app.vvp.keri.oobi.httpx.AsyncClient", return_value=mock_client):
            result = await fetch_kel_from_witnesses(
                aid="EAID123",
                witnesses=[
                    "http://witness1.example.com/oobi/EAID123",
                    "http://witness2.example.com/oobi/EAID123",
                    "http://witness3.example.com/oobi/EAID123",
                ]
            )

        assert isinstance(result, OOBIResult)

    @pytest.mark.asyncio
    async def test_no_witnesses_raises(self):
        """Empty witness list raises ResolutionFailedError."""
        with pytest.raises(ResolutionFailedError, match="No witnesses provided"):
            await fetch_kel_from_witnesses(aid="EAID123", witnesses=[])

    @pytest.mark.asyncio
    async def test_insufficient_responses_raises(self, mock_httpx_client):
        """Less than min_responses raises ResolutionFailedError."""
        # All witnesses fail
        mock_client = mock_httpx_client(
            side_effect=httpx.TimeoutException("timeout")
        )

        with patch("app.vvp.keri.oobi.httpx.AsyncClient", return_value=mock_client):
            with pytest.raises(ResolutionFailedError, match="Insufficient witness responses"):
                await fetch_kel_from_witnesses(
                    aid="EAID123",
                    witnesses=[
                        "http://witness1.example.com/oobi/EAID123",
                        "http://witness2.example.com/oobi/EAID123",
                    ],
                    min_responses=1
                )

    @pytest.mark.asyncio
    async def test_error_collection_in_message(self, mock_httpx_client):
        """Failed fetches collected in error message."""
        mock_client = mock_httpx_client(
            side_effect=httpx.TimeoutException("connection timeout")
        )

        with patch("app.vvp.keri.oobi.httpx.AsyncClient", return_value=mock_client):
            with pytest.raises(ResolutionFailedError) as exc_info:
                await fetch_kel_from_witnesses(
                    aid="EAID123",
                    witnesses=["http://witness1.example.com/oobi/EAID123"],
                    min_responses=1
                )

        # Error message should contain errors from failed witnesses
        assert "Errors:" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_partial_success_meets_min_responses(self, mock_httpx_client, mock_httpx_response, sample_icp_event):
        """Some witnesses fail but min_responses met."""
        content = json.dumps(sample_icp_event).encode()
        success_response = mock_httpx_response(200, content, "application/json")

        call_count = 0

        async def alternating_response(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count % 2 == 0:
                raise httpx.TimeoutException("timeout")
            return success_response

        mock_client = AsyncMock()
        mock_client.get = alternating_response
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)

        with patch("app.vvp.keri.oobi.httpx.AsyncClient", return_value=mock_client):
            result = await fetch_kel_from_witnesses(
                aid="EAID123",
                witnesses=[
                    "http://witness1.example.com/oobi/EAID123",  # succeeds
                    "http://witness2.example.com/oobi/EAID123",  # fails
                    "http://witness3.example.com/oobi/EAID123",  # succeeds
                ],
                min_responses=1
            )

        assert isinstance(result, OOBIResult)


# =============================================================================
# TestValidateOobiIsKel - Full validation pipeline tests
# =============================================================================


class TestValidateOobiIsKel:
    """Tests for validate_oobi_is_kel integration function.

    Note: parse_kel_stream, validate_kel_chain, and EventType are imported
    lazily inside validate_oobi_is_kel to avoid circular imports, so we must
    mock them at app.vvp.keri.kel_parser, not app.vvp.keri.oobi.
    """

    @pytest.mark.asyncio
    async def test_valid_kel_returns_key_state(self, mock_httpx_client, mock_httpx_response, sample_icp_event):
        """Valid KEL with ICP returns KeyState."""
        test_aid = "EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UlsMlymgo0"
        content = json.dumps(sample_icp_event).encode()
        response = mock_httpx_response(200, content, "application/json")
        mock_client = mock_httpx_client(response)

        # Mock the parser to return valid events
        mock_event = MagicMock()
        mock_event.event_type = MagicMock()
        mock_event.event_type.value = "icp"
        mock_event.is_establishment = True
        mock_event.digest = test_aid
        mock_event.signing_keys = ["DqI2cOZ06RwGNwCovYUWExmdKU983IasmUKMmZflvWdQ"]
        mock_event.sequence = 0
        mock_event.timestamp = None
        mock_event.witnesses = ["BBfxWitness1"]
        mock_event.toad = 0

        # Import the real EventType to match against
        from app.vvp.keri.kel_parser import EventType
        mock_event.event_type = EventType.ICP

        with patch("app.vvp.keri.oobi.httpx.AsyncClient", return_value=mock_client), \
             patch("app.vvp.keri.kel_parser.parse_kel_stream", return_value=[mock_event]) as mock_parse, \
             patch("app.vvp.keri.kel_parser.validate_kel_chain") as mock_validate:

            # Use full AID in URL so it's extracted correctly
            result = await validate_oobi_is_kel(f"http://example.com/oobi/{test_aid}")

            mock_parse.assert_called_once()
            mock_validate.assert_called_once()

            # Verify KeyState structure - AID comes from URL extraction
            assert result.aid == test_aid
            assert result.signing_keys == ["DqI2cOZ06RwGNwCovYUWExmdKU983IasmUKMmZflvWdQ"]
            assert result.sequence == 0

    @pytest.mark.asyncio
    async def test_empty_kel_data_raises(self, mock_httpx_client, mock_httpx_response):
        """Empty KEL data raises OOBIContentInvalidError."""
        response = mock_httpx_response(200, b"", "application/json")
        mock_client = mock_httpx_client(response)

        with patch("app.vvp.keri.oobi.httpx.AsyncClient", return_value=mock_client):
            # This should raise due to empty response
            with pytest.raises(ResolutionFailedError, match="empty"):
                await validate_oobi_is_kel("http://example.com/oobi/EAID")

    @pytest.mark.asyncio
    async def test_parse_failure_raises(self, mock_httpx_client, mock_httpx_response):
        """Parse failure raises OOBIContentInvalidError."""
        response = mock_httpx_response(200, b"invalid kel data", "application/json")
        mock_client = mock_httpx_client(response)

        with patch("app.vvp.keri.oobi.httpx.AsyncClient", return_value=mock_client), \
             patch("app.vvp.keri.kel_parser.parse_kel_stream", side_effect=ValueError("parse error")):

            with pytest.raises(OOBIContentInvalidError, match="Failed to parse KEL"):
                await validate_oobi_is_kel("http://example.com/oobi/EAID")

    @pytest.mark.asyncio
    async def test_no_events_raises(self, mock_httpx_client, mock_httpx_response):
        """Empty events list raises OOBIContentInvalidError."""
        response = mock_httpx_response(200, b"[]", "application/json")
        mock_client = mock_httpx_client(response)

        with patch("app.vvp.keri.oobi.httpx.AsyncClient", return_value=mock_client), \
             patch("app.vvp.keri.kel_parser.parse_kel_stream", return_value=[]):

            with pytest.raises(OOBIContentInvalidError, match="no events"):
                await validate_oobi_is_kel("http://example.com/oobi/EAID")

    @pytest.mark.asyncio
    async def test_requires_inception_event(self, mock_httpx_client, mock_httpx_response):
        """Missing ICP/DIP as first event raises OOBIContentInvalidError."""
        response = mock_httpx_response(200, b'{"t":"ixn"}', "application/json")
        mock_client = mock_httpx_client(response)

        # Mock an ixn event as first event
        from app.vvp.keri.kel_parser import EventType
        mock_event = MagicMock()
        mock_event.event_type = EventType.IXN

        with patch("app.vvp.keri.oobi.httpx.AsyncClient", return_value=mock_client), \
             patch("app.vvp.keri.kel_parser.parse_kel_stream", return_value=[mock_event]):

            with pytest.raises(OOBIContentInvalidError, match="must start with inception"):
                await validate_oobi_is_kel("http://example.com/oobi/EAID")

    @pytest.mark.asyncio
    async def test_chain_validation_failure_raises(self, mock_httpx_client, mock_httpx_response):
        """Chain validation failure raises OOBIContentInvalidError."""
        response = mock_httpx_response(200, b'{"t":"icp"}', "application/json")
        mock_client = mock_httpx_client(response)

        from app.vvp.keri.kel_parser import EventType
        mock_event = MagicMock()
        mock_event.event_type = EventType.ICP

        with patch("app.vvp.keri.oobi.httpx.AsyncClient", return_value=mock_client), \
             patch("app.vvp.keri.kel_parser.parse_kel_stream", return_value=[mock_event]), \
             patch("app.vvp.keri.kel_parser.validate_kel_chain", side_effect=ValueError("chain broken")):

            with pytest.raises(OOBIContentInvalidError, match="chain validation failed"):
                await validate_oobi_is_kel("http://example.com/oobi/EAID")

    @pytest.mark.asyncio
    async def test_no_establishment_event_raises(self, mock_httpx_client, mock_httpx_response):
        """No establishment event found raises OOBIContentInvalidError."""
        response = mock_httpx_response(200, b'{"t":"icp"}', "application/json")
        mock_client = mock_httpx_client(response)

        # Mock event that passes inception check but is_establishment is False
        from app.vvp.keri.kel_parser import EventType
        mock_event = MagicMock()
        mock_event.event_type = EventType.ICP
        mock_event.is_establishment = False

        with patch("app.vvp.keri.oobi.httpx.AsyncClient", return_value=mock_client), \
             patch("app.vvp.keri.kel_parser.parse_kel_stream", return_value=[mock_event]), \
             patch("app.vvp.keri.kel_parser.validate_kel_chain"):

            with pytest.raises(OOBIContentInvalidError, match="No establishment event"):
                await validate_oobi_is_kel("http://example.com/oobi/EAID")

    @pytest.mark.asyncio
    async def test_multiple_events_finds_terminal(self, mock_httpx_client, mock_httpx_response):
        """Multi-event KEL finds last establishment event."""
        response = mock_httpx_response(200, b'[{"t":"icp"},{"t":"rot"}]', "application/json")
        mock_client = mock_httpx_client(response)

        from app.vvp.keri.kel_parser import EventType

        # Mock events: icp then rot
        mock_icp = MagicMock()
        mock_icp.event_type = EventType.ICP
        mock_icp.is_establishment = True
        mock_icp.digest = "ESAID_ICP"
        mock_icp.signing_keys = ["DKey1"]
        mock_icp.sequence = 0
        mock_icp.timestamp = None
        mock_icp.witnesses = ["BWit1"]
        mock_icp.toad = 0

        mock_rot = MagicMock()
        mock_rot.event_type = EventType.ROT
        mock_rot.is_establishment = True
        mock_rot.digest = "ESAID_ROT"
        mock_rot.signing_keys = ["DKey2"]
        mock_rot.sequence = 1
        mock_rot.timestamp = None
        mock_rot.witnesses = ["BWit2"]
        mock_rot.toad = 1

        with patch("app.vvp.keri.oobi.httpx.AsyncClient", return_value=mock_client), \
             patch("app.vvp.keri.kel_parser.parse_kel_stream", return_value=[mock_icp, mock_rot]), \
             patch("app.vvp.keri.kel_parser.validate_kel_chain"):

            result = await validate_oobi_is_kel("http://example.com/oobi/EAID")

            # Should use rot (terminal) event's key state
            assert result.signing_keys == ["DKey2"]
            assert result.sequence == 1
            assert result.witnesses == ["BWit2"]

    @pytest.mark.asyncio
    async def test_delegated_inception_accepted(self, mock_httpx_client, mock_httpx_response):
        """Delegated inception (dip) is accepted as valid inception."""
        response = mock_httpx_response(200, b'{"t":"dip"}', "application/json")
        mock_client = mock_httpx_client(response)

        from app.vvp.keri.kel_parser import EventType

        mock_event = MagicMock()
        mock_event.event_type = EventType.DIP
        mock_event.is_establishment = True
        mock_event.digest = "ESAID_DIP"
        mock_event.signing_keys = ["DDelegatedKey"]
        mock_event.sequence = 0
        mock_event.timestamp = None
        mock_event.witnesses = []
        mock_event.toad = 0

        with patch("app.vvp.keri.oobi.httpx.AsyncClient", return_value=mock_client), \
             patch("app.vvp.keri.kel_parser.parse_kel_stream", return_value=[mock_event]), \
             patch("app.vvp.keri.kel_parser.validate_kel_chain"):

            result = await validate_oobi_is_kel("http://example.com/oobi/EAID")

            assert result.signing_keys == ["DDelegatedKey"]
