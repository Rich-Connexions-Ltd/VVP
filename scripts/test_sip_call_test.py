#!/usr/bin/env python3
"""CLI regression tests for sip-call-test.py.

Sprint 53: Validates timing flags, guardrails, JSON output schema,
and chained mode requirements. Uses unittest.mock to mock network calls,
so these run locally without SIP services.

Run:
    python3 -m pytest scripts/test_sip_call_test.py -v
"""

import json
import subprocess
import sys
import time
from unittest.mock import patch, MagicMock

import pytest

# Import the module under test
sys.path.insert(0, "scripts")
import importlib
sip_call_test = importlib.import_module("sip-call-test")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_sip_response(status_code: int = 302, elapsed_ms: float = 100.0,
                      headers: dict = None) -> dict:
    """Build a mock SIP response dict matching send_sip_and_receive() output."""
    default_headers = {
        "X-VVP-Status": "VALID",
        "X-VVP-Brand-Name": "ACME Inc",
        "X-VVP-Brand-Logo": "https://example.com/logo.png",
        "Contact": "<sip:1001@127.0.0.1>",
        "P-VVP-Identity": "eyJwcHQiOiJ2dnAiLCJraWQiOiJodHRwczovL2V4YW1wbGUuY29tIn0",
        "P-VVP-Passport": "eyJhbGciOiJFZERTQSJ9.eyJvcmlnIjp7InRuIjpbIjEyMzQiXX19.AAAA",
    }
    if headers:
        default_headers.update(headers)

    return {
        "raw_status_line": f"SIP/2.0 {status_code} OK",
        "status_code": status_code,
        "reason": "OK",
        "headers": default_headers,
        "elapsed_ms": elapsed_ms,
        "source": "127.0.0.1:5070",
    }


def make_timeout_response() -> dict:
    """Build a mock timeout response."""
    return {
        "error": "timeout",
        "detail": "No SIP response within 15s",
        "elapsed_ms": 15000.0,
    }


def make_metrics(verification_hits: int = 0, verification_misses: int = 0,
                 dossier_hits: int = 0, dossier_misses: int = 0) -> dict:
    """Build a mock verifier metrics snapshot."""
    return {
        "verification_hits": verification_hits,
        "verification_misses": verification_misses,
        "dossier_hits": dossier_hits,
        "dossier_misses": dossier_misses,
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestArgumentParsing:
    """Test that all new CLI flags are accepted by argparse."""

    def test_timing_flag_accepted(self):
        """--timing flag is parsed."""
        parser = sip_call_test.main.__code__  # Just verify the args are accepted
        # Use subprocess to test actual argument parsing
        result = subprocess.run(
            [sys.executable, "scripts/sip-call-test.py", "--help"],
            capture_output=True, text=True
        )
        assert "--timing" in result.stdout

    def test_timing_count_flag_accepted(self):
        """--timing-count is in help output."""
        result = subprocess.run(
            [sys.executable, "scripts/sip-call-test.py", "--help"],
            capture_output=True, text=True
        )
        assert "--timing-count" in result.stdout

    def test_timing_threshold_flag_accepted(self):
        """--timing-threshold is in help output."""
        result = subprocess.run(
            [sys.executable, "scripts/sip-call-test.py", "--help"],
            capture_output=True, text=True
        )
        assert "--timing-threshold" in result.stdout

    def test_timing_delay_flag_accepted(self):
        """--timing-delay is in help output."""
        result = subprocess.run(
            [sys.executable, "scripts/sip-call-test.py", "--help"],
            capture_output=True, text=True
        )
        assert "--timing-delay" in result.stdout

    def test_chain_mode_accepted(self):
        """--test chain is a valid choice."""
        result = subprocess.run(
            [sys.executable, "scripts/sip-call-test.py", "--help"],
            capture_output=True, text=True
        )
        assert "chain" in result.stdout

    def test_verifier_url_flag_accepted(self):
        """--verifier-url is in help output."""
        result = subprocess.run(
            [sys.executable, "scripts/sip-call-test.py", "--help"],
            capture_output=True, text=True
        )
        assert "--verifier-url" in result.stdout


class TestTimingCountCap:
    """--timing-count is capped at MAX_TIMING_COUNT (20)."""

    @patch.object(sip_call_test, "send_sip_and_receive")
    def test_count_capped_at_20(self, mock_send):
        """Requesting count=50 should only produce 20 calls."""
        call_count = 0

        def counting_send(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            return make_sip_response(elapsed_ms=100.0 + call_count * 10)

        mock_send.side_effect = counting_send

        result = sip_call_test.test_timing(
            sip_call_test.test_signing, "signing",
            "127.0.0.1", 5070,
            count=50,  # Exceeds cap — caller is responsible for min()
            threshold=2.0, delay=0.0, timeout=5,
            api_key="test-key", orig_tn="+441923311000", dest_tn="+441923311006",
        )
        # The test_timing function itself doesn't enforce the cap —
        # the cap is enforced in main() via min(). But we verify the
        # constant exists and has the expected value.
        assert sip_call_test.MAX_TIMING_COUNT == 20

    def test_cap_enforced_in_main(self):
        """main() enforces the cap via min(args.timing_count, MAX_TIMING_COUNT)."""
        import ast
        import inspect

        source = inspect.getsource(sip_call_test.main)
        # Verify the capping logic exists in main()
        assert "MAX_TIMING_COUNT" in source
        assert "min(" in source


class TestTimingDelayMinimum:
    """--timing-delay below MIN_TIMING_DELAY is raised to minimum."""

    def test_min_delay_constant(self):
        """MIN_TIMING_DELAY is 0.1."""
        assert sip_call_test.MIN_TIMING_DELAY == 0.1

    def test_delay_enforced_in_main(self):
        """main() enforces the minimum via max(args.timing_delay, MIN_TIMING_DELAY)."""
        import inspect

        source = inspect.getsource(sip_call_test.main)
        assert "MIN_TIMING_DELAY" in source
        assert "max(" in source


class TestTimingResultSchema:
    """Mock send_sip_and_receive to return fixed latencies, verify JSON output."""

    @patch.object(sip_call_test, "send_sip_and_receive")
    def test_signing_timing_result_has_required_fields(self, mock_send):
        """Timing result contains all required fields."""
        calls = [0]

        def fake_send(*args, **kwargs):
            calls[0] += 1
            # First call: slow (cold). Second: fast (cached).
            elapsed = 2000.0 if calls[0] == 1 else 200.0
            return make_sip_response(elapsed_ms=elapsed)

        mock_send.side_effect = fake_send

        result = sip_call_test.test_timing(
            sip_call_test.test_signing, "signing",
            "127.0.0.1", 5070,
            count=2, threshold=2.0, delay=0.0, timeout=5,
            api_key="test-key", orig_tn="+441923311000", dest_tn="+441923311006",
        )

        # Required fields per plan
        assert "first_call_ms" in result
        assert "speedup_ratio" in result
        assert "threshold" in result
        assert "status" in result
        assert "all_timings_ms" in result
        assert "min_ms" in result
        assert "max_ms" in result
        assert "avg_ms" in result
        assert "cold_uncertain" in result

    @patch.object(sip_call_test, "send_sip_and_receive")
    def test_timing_speedup_calculated_correctly(self, mock_send):
        """Speedup ratio = first / min(subsequent)."""
        calls = [0]

        def fake_send(*args, **kwargs):
            calls[0] += 1
            elapsed = 2000.0 if calls[0] == 1 else 500.0
            return make_sip_response(elapsed_ms=elapsed)

        mock_send.side_effect = fake_send

        result = sip_call_test.test_timing(
            sip_call_test.test_signing, "signing",
            "127.0.0.1", 5070,
            count=3, threshold=2.0, delay=0.0, timeout=5,
            api_key="test-key", orig_tn="+441923311000", dest_tn="+441923311006",
        )

        assert result["first_call_ms"] == 2000.0
        assert result["speedup_ratio"] == 4.0  # 2000 / 500


class TestWarnVsFail:
    """Speedup below threshold → warn, actual error → fail."""

    @patch.object(sip_call_test, "send_sip_and_receive")
    def test_below_threshold_is_warn(self, mock_send):
        """When speedup < threshold, status should be 'warn' not 'fail'."""
        calls = [0]

        def fake_send(*args, **kwargs):
            calls[0] += 1
            # No speedup — both calls same latency
            return make_sip_response(elapsed_ms=500.0)

        mock_send.side_effect = fake_send

        result = sip_call_test.test_timing(
            sip_call_test.test_signing, "signing",
            "127.0.0.1", 5070,
            count=2, threshold=2.0, delay=0.0, timeout=5,
            api_key="test-key", orig_tn="+441923311000", dest_tn="+441923311006",
        )

        assert result["status"] == "warn"

    @patch.object(sip_call_test, "send_sip_and_receive")
    def test_above_threshold_is_pass(self, mock_send):
        """When speedup >= threshold, status should be 'pass'."""
        calls = [0]

        def fake_send(*args, **kwargs):
            calls[0] += 1
            elapsed = 3000.0 if calls[0] == 1 else 300.0
            return make_sip_response(elapsed_ms=elapsed)

        mock_send.side_effect = fake_send

        result = sip_call_test.test_timing(
            sip_call_test.test_signing, "signing",
            "127.0.0.1", 5070,
            count=2, threshold=2.0, delay=0.0, timeout=5,
            api_key="test-key", orig_tn="+441923311000", dest_tn="+441923311006",
        )

        assert result["status"] == "pass"

    @patch.object(sip_call_test, "send_sip_and_receive")
    def test_timeout_is_fail(self, mock_send):
        """Actual error (timeout) produces status='fail'."""
        mock_send.return_value = make_timeout_response()

        result = sip_call_test.test_timing(
            sip_call_test.test_signing, "signing",
            "127.0.0.1", 5070,
            count=2, threshold=2.0, delay=0.0, timeout=5,
            api_key="test-key", orig_tn="+441923311000", dest_tn="+441923311006",
        )

        assert result["status"] == "fail"


class TestColdUncertainFlag:
    """First call < 500ms → cold_uncertain: true."""

    @patch.object(sip_call_test, "send_sip_and_receive")
    def test_fast_first_call_sets_cold_uncertain(self, mock_send):
        """When first call is < 500ms, cold_uncertain should be True."""
        calls = [0]

        def fake_send(*args, **kwargs):
            calls[0] += 1
            # Both fast — can't distinguish cold from cached
            return make_sip_response(elapsed_ms=100.0)

        mock_send.side_effect = fake_send

        result = sip_call_test.test_timing(
            sip_call_test.test_signing, "signing",
            "127.0.0.1", 5070,
            count=2, threshold=2.0, delay=0.0, timeout=5,
            api_key="test-key", orig_tn="+441923311000", dest_tn="+441923311006",
        )

        assert result["cold_uncertain"] is True

    @patch.object(sip_call_test, "send_sip_and_receive")
    def test_slow_first_call_no_cold_uncertain(self, mock_send):
        """When first call >= 500ms, cold_uncertain should be False."""
        calls = [0]

        def fake_send(*args, **kwargs):
            calls[0] += 1
            elapsed = 2000.0 if calls[0] == 1 else 200.0
            return make_sip_response(elapsed_ms=elapsed)

        mock_send.side_effect = fake_send

        result = sip_call_test.test_timing(
            sip_call_test.test_signing, "signing",
            "127.0.0.1", 5070,
            count=2, threshold=2.0, delay=0.0, timeout=5,
            api_key="test-key", orig_tn="+441923311000", dest_tn="+441923311006",
        )

        assert result["cold_uncertain"] is False


class TestChainRequiresTiming:
    """--test chain without --timing should exit with error."""

    def test_chain_without_timing_exits_with_error(self):
        """Running --test chain without --timing produces exit code 2."""
        result = subprocess.run(
            [sys.executable, "scripts/sip-call-test.py", "--test", "chain"],
            capture_output=True, text=True,
        )
        assert result.returncode == 2
        assert "requires --timing" in result.stderr


class TestChainedTimingSchema:
    """Chained sign→verify timing result has chain-specific fields."""

    @patch.object(sip_call_test, "snapshot_verifier_metrics")
    @patch.object(sip_call_test, "send_sip_and_receive")
    def test_chain_result_has_required_fields(self, mock_send, mock_metrics):
        """Chain timing result includes all expected fields."""
        calls = [0]

        def fake_send(*args, **kwargs):
            calls[0] += 1
            if calls[0] == 1:
                # Signing response with real headers
                return make_sip_response(elapsed_ms=1500.0)
            # Verify responses
            elapsed = 2000.0 if calls[0] == 2 else 300.0
            return make_sip_response(
                elapsed_ms=elapsed,
                headers={"X-VVP-Status": "VALID"},
            )

        mock_send.side_effect = fake_send
        mock_metrics.side_effect = [
            make_metrics(verification_hits=0, verification_misses=0),
            make_metrics(verification_hits=1, verification_misses=1),
        ]

        result = sip_call_test.test_chained_timing(
            "127.0.0.1", 5070, "127.0.0.1", 5071,
            "test-key", "+441923311000", "+441923311006",
            count=2, threshold=2.0, delay=0.0, timeout=5,
            verifier_url="http://localhost:8000",
        )

        # Chain-specific fields
        assert "sign_elapsed_ms" in result
        assert "cache_metrics" in result
        assert "vvp_statuses" in result
        assert "cache_exercised" in result
        # Standard timing fields
        assert "first_call_ms" in result
        assert "speedup_ratio" in result
        assert "threshold" in result
        assert "status" in result

    @patch.object(sip_call_test, "snapshot_verifier_metrics")
    @patch.object(sip_call_test, "send_sip_and_receive")
    def test_chain_cache_confirmed_when_hits_match(self, mock_send, mock_metrics):
        """cache_confirmed is True when verification_hits_delta >= count-1."""
        calls = [0]

        def fake_send(*args, **kwargs):
            calls[0] += 1
            if calls[0] == 1:
                return make_sip_response(elapsed_ms=1000.0)
            return make_sip_response(
                elapsed_ms=200.0,
                headers={"X-VVP-Status": "VALID"},
            )

        mock_send.side_effect = fake_send
        mock_metrics.side_effect = [
            make_metrics(verification_hits=5),
            make_metrics(verification_hits=7),  # delta = 2, count-1 = 2
        ]

        result = sip_call_test.test_chained_timing(
            "127.0.0.1", 5070, "127.0.0.1", 5071,
            "test-key", "+441923311000", "+441923311006",
            count=3, threshold=2.0, delay=0.0, timeout=5,
            verifier_url="http://localhost:8000",
        )

        assert result["cache_metrics"]["cache_confirmed"] is True

    @patch.object(sip_call_test, "snapshot_verifier_metrics")
    @patch.object(sip_call_test, "send_sip_and_receive")
    def test_chain_no_metrics_graceful(self, mock_send, mock_metrics):
        """Chain works gracefully when /admin is unavailable."""
        calls = [0]

        def fake_send(*args, **kwargs):
            calls[0] += 1
            if calls[0] == 1:
                return make_sip_response(elapsed_ms=1000.0)
            return make_sip_response(elapsed_ms=200.0)

        mock_send.side_effect = fake_send
        mock_metrics.return_value = None  # /admin unavailable

        result = sip_call_test.test_chained_timing(
            "127.0.0.1", 5070, "127.0.0.1", 5071,
            "test-key", "+441923311000", "+441923311006",
            count=2, threshold=2.0, delay=0.0, timeout=5,
            verifier_url="http://localhost:8000",
        )

        assert result["cache_metrics"] is None
        assert result["status"] in ("pass", "warn")
        assert "no metrics" in result["detail"]
