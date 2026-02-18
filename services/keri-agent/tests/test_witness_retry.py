"""Tests for WitnessPublisher retry logic.

Verifies exponential backoff retry on transient failures (HTTP 5xx,
timeout, connect error) and retry on HTTP 202 (escrowed). Confirms
no retry on HTTP 4xx (client error) or HTTP 200 (success).
"""
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock

import httpx
import pytest

from app.keri.witness import WitnessPublisher, WitnessResult, reset_witness_publisher


@pytest.fixture(autouse=True)
def _reset_publisher():
    """Reset singleton between tests."""
    reset_witness_publisher()
    yield
    reset_witness_publisher()


def _make_publisher(**kwargs) -> WitnessPublisher:
    """Create a publisher with fast backoff for tests."""
    defaults = dict(
        witness_urls=["https://w1.example.com", "https://w2.example.com"],
        timeout=5.0,
        threshold=1,
        max_attempts=3,
        backoff_base=0.01,  # 10ms backoff for fast tests
    )
    defaults.update(kwargs)
    return WitnessPublisher(**defaults)


def _mock_kel_bytes() -> bytes:
    """Create minimal fake KEL bytes for testing.

    We patch _try_publish so these bytes are never actually parsed.
    """
    return b'{"v":"KERI10JSON000000_","t":"icp","d":"EAID","i":"EAID","s":"0","b":["Bwit1"]}'


# =============================================================================
# Phase 1: _publish_to_witness retry tests
# =============================================================================


@pytest.mark.asyncio
async def test_retry_on_connect_error():
    """First attempt raises ConnectError, second succeeds with receipt."""
    publisher = _make_publisher()
    kel = _mock_kel_bytes()

    success_result = (
        WitnessResult(url="https://w1.example.com", success=True, response_time_ms=10),
        b"receipt_bytes",
    )
    connect_error_result = (
        WitnessResult(url="https://w1.example.com", success=False, error="ConnectError"),
        None,
    )

    call_count = 0

    async def mock_try_publish(client, url, aid, kel_bytes):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return connect_error_result
        return success_result

    with patch.object(publisher, "_try_publish", side_effect=mock_try_publish):
        async with httpx.AsyncClient() as client:
            result, receipt = await publisher._publish_to_witness(
                client, "https://w1.example.com", "EAID123", kel
            )

    assert call_count == 2
    assert result.success is True
    assert receipt == b"receipt_bytes"


@pytest.mark.asyncio
async def test_retry_on_timeout():
    """First attempt times out, second succeeds."""
    publisher = _make_publisher()
    kel = _mock_kel_bytes()

    success_result = (
        WitnessResult(url="https://w1.example.com", success=True, response_time_ms=10),
        b"receipt_bytes",
    )
    timeout_result = (
        WitnessResult(url="https://w1.example.com", success=False, error="Timeout"),
        None,
    )

    call_count = 0

    async def mock_try_publish(client, url, aid, kel_bytes):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return timeout_result
        return success_result

    with patch.object(publisher, "_try_publish", side_effect=mock_try_publish):
        async with httpx.AsyncClient() as client:
            result, receipt = await publisher._publish_to_witness(
                client, "https://w1.example.com", "EAID123", kel
            )

    assert call_count == 2
    assert result.success is True
    assert receipt == b"receipt_bytes"


@pytest.mark.asyncio
async def test_retry_on_5xx():
    """First attempt returns HTTP 500, second returns 200 with receipt."""
    publisher = _make_publisher()
    kel = _mock_kel_bytes()

    success_result = (
        WitnessResult(url="https://w1.example.com", success=True, response_time_ms=10),
        b"receipt_bytes",
    )
    error_result = (
        WitnessResult(url="https://w1.example.com", success=False, error="HTTP 500"),
        None,
    )

    call_count = 0

    async def mock_try_publish(client, url, aid, kel_bytes):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return error_result
        return success_result

    with patch.object(publisher, "_try_publish", side_effect=mock_try_publish):
        async with httpx.AsyncClient() as client:
            result, receipt = await publisher._publish_to_witness(
                client, "https://w1.example.com", "EAID123", kel
            )

    assert call_count == 2
    assert result.success is True
    assert receipt == b"receipt_bytes"


@pytest.mark.asyncio
async def test_retry_on_202_then_200():
    """First attempt returns 202 (escrowed), second returns 200 (receipt)."""
    publisher = _make_publisher()
    kel = _mock_kel_bytes()

    success_result = (
        WitnessResult(url="https://w1.example.com", success=True, response_time_ms=10),
        b"receipt_bytes",
    )
    escrowed_result = (
        WitnessResult(url="https://w1.example.com", success=True, response_time_ms=10),
        None,  # 202 returns no receipt
    )

    call_count = 0

    async def mock_try_publish(client, url, aid, kel_bytes):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return escrowed_result
        return success_result

    with patch.object(publisher, "_try_publish", side_effect=mock_try_publish):
        async with httpx.AsyncClient() as client:
            result, receipt = await publisher._publish_to_witness(
                client, "https://w1.example.com", "EAID123", kel
            )

    assert call_count == 2
    assert result.success is True
    assert receipt == b"receipt_bytes"


@pytest.mark.asyncio
async def test_no_retry_on_4xx():
    """HTTP 400/404 returns immediately without retry."""
    publisher = _make_publisher()
    kel = _mock_kel_bytes()

    error_result = (
        WitnessResult(url="https://w1.example.com", success=False, error="HTTP 400"),
        None,
    )

    call_count = 0

    async def mock_try_publish(client, url, aid, kel_bytes):
        nonlocal call_count
        call_count += 1
        return error_result

    with patch.object(publisher, "_try_publish", side_effect=mock_try_publish):
        async with httpx.AsyncClient() as client:
            result, receipt = await publisher._publish_to_witness(
                client, "https://w1.example.com", "EAID123", kel
            )

    assert call_count == 1  # No retry
    assert result.success is False
    assert result.error == "HTTP 400"


@pytest.mark.asyncio
async def test_no_retry_on_immediate_success():
    """HTTP 200 with receipt returns immediately without retry."""
    publisher = _make_publisher()
    kel = _mock_kel_bytes()

    success_result = (
        WitnessResult(url="https://w1.example.com", success=True, response_time_ms=10),
        b"receipt_bytes",
    )

    call_count = 0

    async def mock_try_publish(client, url, aid, kel_bytes):
        nonlocal call_count
        call_count += 1
        return success_result

    with patch.object(publisher, "_try_publish", side_effect=mock_try_publish):
        async with httpx.AsyncClient() as client:
            result, receipt = await publisher._publish_to_witness(
                client, "https://w1.example.com", "EAID123", kel
            )

    assert call_count == 1  # No retry needed
    assert result.success is True
    assert receipt == b"receipt_bytes"


@pytest.mark.asyncio
async def test_max_attempts_exhausted():
    """All attempts fail — returns last error after max_attempts."""
    publisher = _make_publisher(max_attempts=3)
    kel = _mock_kel_bytes()

    timeout_result = (
        WitnessResult(url="https://w1.example.com", success=False, error="Timeout"),
        None,
    )

    call_count = 0

    async def mock_try_publish(client, url, aid, kel_bytes):
        nonlocal call_count
        call_count += 1
        return timeout_result

    with patch.object(publisher, "_try_publish", side_effect=mock_try_publish):
        async with httpx.AsyncClient() as client:
            result, receipt = await publisher._publish_to_witness(
                client, "https://w1.example.com", "EAID123", kel
            )

    assert call_count == 3  # All attempts exhausted
    assert result.success is False
    assert result.error == "Timeout"
    assert receipt is None


@pytest.mark.asyncio
async def test_202_accepted_on_final_attempt():
    """All attempts return 202 — accepts escrowed on final attempt."""
    publisher = _make_publisher(max_attempts=3)
    kel = _mock_kel_bytes()

    escrowed_result = (
        WitnessResult(url="https://w1.example.com", success=True, response_time_ms=10),
        None,
    )

    call_count = 0

    async def mock_try_publish(client, url, aid, kel_bytes):
        nonlocal call_count
        call_count += 1
        return escrowed_result

    with patch.object(publisher, "_try_publish", side_effect=mock_try_publish):
        async with httpx.AsyncClient() as client:
            result, receipt = await publisher._publish_to_witness(
                client, "https://w1.example.com", "EAID123", kel
            )

    assert call_count == 3  # Retried all attempts
    assert result.success is True  # Accepted as escrowed
    assert receipt is None


# =============================================================================
# Phase 2: _distribute_receipt retry tests
# =============================================================================


@pytest.mark.asyncio
async def test_phase2_retry_on_5xx():
    """Phase 2 receipt distribution retries on HTTP 500."""
    publisher = _make_publisher()

    call_count = 0

    async def mock_post(url, content=None, headers=None):
        nonlocal call_count
        call_count += 1
        resp = MagicMock()
        resp.status_code = 500 if call_count == 1 else 200
        return resp

    client = AsyncMock()
    client.post = mock_post

    # Create minimal rct message bytes that can be parsed by SerderKERI
    # We need to patch the serder parsing to avoid needing real CESR bytes
    with patch("app.keri.witness.serdering.SerderKERI") as mock_serder_cls:
        mock_serder = MagicMock()
        mock_serder.raw = b'{"t":"rct"}'
        mock_serder.size = 11
        mock_serder_cls.return_value = mock_serder

        rct_msg = b'{"t":"rct"}attachments'
        await publisher._distribute_receipt(client, "https://w1.example.com", rct_msg)

    assert call_count == 2


@pytest.mark.asyncio
async def test_phase2_retry_on_timeout():
    """Phase 2 receipt distribution retries on timeout."""
    publisher = _make_publisher()

    call_count = 0

    async def mock_post(url, content=None, headers=None):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise httpx.TimeoutException("timed out")
        resp = MagicMock()
        resp.status_code = 200
        return resp

    client = AsyncMock()
    client.post = mock_post

    with patch("app.keri.witness.serdering.SerderKERI") as mock_serder_cls:
        mock_serder = MagicMock()
        mock_serder.raw = b'{"t":"rct"}'
        mock_serder.size = 11
        mock_serder_cls.return_value = mock_serder

        rct_msg = b'{"t":"rct"}attachments'
        await publisher._distribute_receipt(client, "https://w1.example.com", rct_msg)

    assert call_count == 2


@pytest.mark.asyncio
async def test_phase2_retry_on_connect_error():
    """Phase 2 receipt distribution retries on connect error."""
    publisher = _make_publisher()

    call_count = 0

    async def mock_post(url, content=None, headers=None):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise httpx.ConnectError("connection refused")
        resp = MagicMock()
        resp.status_code = 200
        return resp

    client = AsyncMock()
    client.post = mock_post

    with patch("app.keri.witness.serdering.SerderKERI") as mock_serder_cls:
        mock_serder = MagicMock()
        mock_serder.raw = b'{"t":"rct"}'
        mock_serder.size = 11
        mock_serder_cls.return_value = mock_serder

        rct_msg = b'{"t":"rct"}attachments'
        await publisher._distribute_receipt(client, "https://w1.example.com", rct_msg)

    assert call_count == 2


@pytest.mark.asyncio
async def test_phase2_no_retry_on_4xx():
    """Phase 2 receipt distribution does not retry on HTTP 400."""
    publisher = _make_publisher()

    call_count = 0

    async def mock_post(url, content=None, headers=None):
        nonlocal call_count
        call_count += 1
        resp = MagicMock()
        resp.status_code = 400
        return resp

    client = AsyncMock()
    client.post = mock_post

    with patch("app.keri.witness.serdering.SerderKERI") as mock_serder_cls:
        mock_serder = MagicMock()
        mock_serder.raw = b'{"t":"rct"}'
        mock_serder.size = 11
        mock_serder_cls.return_value = mock_serder

        rct_msg = b'{"t":"rct"}attachments'
        await publisher._distribute_receipt(client, "https://w1.example.com", rct_msg)

    assert call_count == 1  # No retry


# =============================================================================
# _is_retryable_error tests
# =============================================================================


def test_retryable_error_5xx():
    assert WitnessPublisher._is_retryable_error("HTTP 500") is True
    assert WitnessPublisher._is_retryable_error("HTTP 502") is True
    assert WitnessPublisher._is_retryable_error("HTTP 503: Service Unavailable") is True


def test_retryable_error_network():
    assert WitnessPublisher._is_retryable_error("Timeout") is True
    assert WitnessPublisher._is_retryable_error("ConnectError") is True


def test_non_retryable_error():
    assert WitnessPublisher._is_retryable_error("HTTP 400") is False
    assert WitnessPublisher._is_retryable_error("HTTP 404") is False
    assert WitnessPublisher._is_retryable_error(None) is False
    assert WitnessPublisher._is_retryable_error("") is False
    assert WitnessPublisher._is_retryable_error("Some random error") is False


# =============================================================================
# Backoff timing test
# =============================================================================


@pytest.mark.asyncio
async def test_backoff_timing():
    """Verify exponential backoff delays increase correctly."""
    publisher = _make_publisher(max_attempts=4, backoff_base=0.05)
    kel = _mock_kel_bytes()

    timeout_result = (
        WitnessResult(url="https://w1.example.com", success=False, error="Timeout"),
        None,
    )

    sleep_times = []
    original_sleep = asyncio.sleep

    async def mock_sleep(duration):
        sleep_times.append(duration)
        # Don't actually sleep in tests

    call_count = 0

    async def mock_try_publish(client, url, aid, kel_bytes):
        nonlocal call_count
        call_count += 1
        return timeout_result

    with patch.object(publisher, "_try_publish", side_effect=mock_try_publish), \
         patch("app.keri.witness.asyncio.sleep", side_effect=mock_sleep):
        async with httpx.AsyncClient() as client:
            await publisher._publish_to_witness(
                client, "https://w1.example.com", "EAID123", kel
            )

    assert call_count == 4  # All attempts used
    assert len(sleep_times) == 3  # 3 sleeps between 4 attempts
    # Exponential: 0.05 * 2^0, 0.05 * 2^1, 0.05 * 2^2
    assert abs(sleep_times[0] - 0.05) < 0.001
    assert abs(sleep_times[1] - 0.10) < 0.001
    assert abs(sleep_times[2] - 0.20) < 0.001
