"""Tests for Sprint 78: Connection pooling and SSRF validation.

Tests the shared HTTP client module and URL validation module:
- get_shared_client() lifecycle and concurrency safety
- validate_url_target() SSRF prevention (IPv4, IPv6, cloud metadata)
- Integration with dossier fetch and OOBI
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from common.vvp.http_client import (
    get_shared_client,
    close_shared_client,
    reset_shared_client,
)
from common.vvp.url_validation import URLValidationError, validate_url_target


# =============================================================================
# Shared HTTP client tests
# =============================================================================


class TestSharedClient:
    """Test shared httpx.AsyncClient lifecycle."""

    @pytest.mark.asyncio
    async def test_get_returns_client(self):
        """get_shared_client returns an AsyncClient."""
        client = await get_shared_client()
        assert isinstance(client, httpx.AsyncClient)
        assert not client.is_closed

    @pytest.mark.asyncio
    async def test_get_returns_same_instance(self):
        """Subsequent calls return the same client instance."""
        client1 = await get_shared_client()
        client2 = await get_shared_client()
        assert client1 is client2

    @pytest.mark.asyncio
    async def test_close_and_recreate(self):
        """After close, get creates a new client."""
        client1 = await get_shared_client()
        await close_shared_client()

        client2 = await get_shared_client()
        assert client2 is not client1
        assert not client2.is_closed

    @pytest.mark.asyncio
    async def test_no_redirects(self):
        """Shared client has follow_redirects=False."""
        client = await get_shared_client()
        assert client.follow_redirects is False

    @pytest.mark.asyncio
    async def test_reset_for_tests(self):
        """reset_shared_client clears the singleton."""
        client1 = await get_shared_client()
        await reset_shared_client()

        client2 = await get_shared_client()
        assert client2 is not client1

    @pytest.mark.asyncio
    async def test_concurrent_get_safe(self):
        """Concurrent get_shared_client calls under real contention create only one client.

        Uses asyncio.Event to hold all coroutines at the same point,
        then releases them simultaneously to create genuine contention
        for the asyncio.Lock inside get_shared_client().
        """
        await reset_shared_client()

        creation_count = 0
        original_init = httpx.AsyncClient.__init__

        def counting_init(self_client, *args, **kwargs):
            nonlocal creation_count
            creation_count += 1
            original_init(self_client, *args, **kwargs)

        # Gate: all coroutines wait until released
        gate = asyncio.Event()
        n_tasks = 20

        async def get_after_gate():
            await gate.wait()
            return await get_shared_client()

        with patch.object(httpx.AsyncClient, "__init__", counting_init):
            tasks = [asyncio.create_task(get_after_gate()) for _ in range(n_tasks)]
            await asyncio.sleep(0)  # Let all tasks reach the gate
            gate.set()  # Release all at once
            results = await asyncio.gather(*tasks)

        # All should be the same instance
        first = results[0]
        for r in results[1:]:
            assert r is first

        # Only one client should have been created (lock prevents duplicates)
        assert creation_count == 1

    @pytest.mark.asyncio
    async def test_reset_sync_safety_guard(self):
        """reset_shared_client_sync() raises AssertionError outside pytest."""
        from common.vvp.http_client import reset_shared_client_sync
        import sys

        # In test context, pytest is in sys.modules — should work
        reset_shared_client_sync()

        # Simulate non-test context by temporarily hiding pytest
        original = sys.modules.get("pytest")
        del sys.modules["pytest"]
        try:
            with pytest.raises(AssertionError, match="test use only"):
                reset_shared_client_sync()
        finally:
            sys.modules["pytest"] = original

    @pytest.mark.asyncio
    async def test_reset_sync_clears_client(self):
        """reset_shared_client_sync() sets the singleton to None."""
        from common.vvp.http_client import reset_shared_client_sync

        client1 = await get_shared_client()
        assert client1 is not None

        reset_shared_client_sync()

        client2 = await get_shared_client()
        assert client2 is not client1


# =============================================================================
# URL validation tests
# =============================================================================


def _mock_dns(ip_address: str, family: int = 2):
    """Helper to mock DNS resolution to return a specific IP."""
    mock_asyncio = MagicMock()
    mock_loop = AsyncMock()
    mock_loop.getaddrinfo = AsyncMock(return_value=[
        (family, 1, 6, '', (ip_address, 0)),
    ])
    mock_asyncio.get_running_loop.return_value = mock_loop
    return patch("common.vvp.url_validation.asyncio", mock_asyncio)


class TestUrlValidation:
    """Test SSRF prevention in validate_url_target."""

    @pytest.mark.asyncio
    async def test_https_accepted(self):
        """HTTPS URLs with public IPs are accepted."""
        with _mock_dns('93.184.216.34'):
            await validate_url_target("https://example.com/path")

    @pytest.mark.asyncio
    async def test_http_rejected_by_default(self):
        """HTTP URLs rejected when allow_http=False (default)."""
        with pytest.raises(URLValidationError, match="Invalid URL scheme"):
            await validate_url_target("http://example.com/path")

    @pytest.mark.asyncio
    async def test_http_allowed_when_specified(self):
        """HTTP URLs accepted when allow_http=True."""
        with _mock_dns('93.184.216.34'):
            await validate_url_target("http://example.com/path", allow_http=True)

    @pytest.mark.asyncio
    async def test_private_ip_rejected(self):
        """Private IPs rejected (10.x, 172.16.x, 192.168.x)."""
        with _mock_dns('192.168.1.1'):
            with pytest.raises(URLValidationError, match="non-routable"):
                await validate_url_target("https://evil.com/path")

    @pytest.mark.asyncio
    async def test_loopback_ipv4_rejected(self):
        """IPv4 loopback (127.0.0.1) rejected."""
        with _mock_dns('127.0.0.1'):
            with pytest.raises(URLValidationError, match="non-routable"):
                await validate_url_target("https://localhost/path")

    @pytest.mark.asyncio
    async def test_loopback_ipv6_rejected(self):
        """IPv6 loopback (::1) rejected."""
        with _mock_dns('::1', family=10):
            with pytest.raises(URLValidationError, match="non-routable"):
                await validate_url_target("https://localhost/path")

    @pytest.mark.asyncio
    async def test_cloud_metadata_rejected(self):
        """Cloud metadata endpoint (169.254.169.254) rejected.

        This is the AWS/Azure/GCP metadata service endpoint.
        Must be blocked to prevent SSRF credential theft.
        """
        with _mock_dns('169.254.169.254'):
            with pytest.raises(URLValidationError, match="non-routable"):
                await validate_url_target("https://metadata.google.internal/path")

    @pytest.mark.asyncio
    async def test_link_local_rejected(self):
        """Link-local addresses (169.254.x.x) rejected."""
        with _mock_dns('169.254.1.1'):
            with pytest.raises(URLValidationError, match="non-routable"):
                await validate_url_target("https://evil.com/path")

    @pytest.mark.asyncio
    async def test_missing_host_rejected(self):
        """URL without host is rejected."""
        with pytest.raises(URLValidationError, match="missing host"):
            await validate_url_target("https:///path")

    @pytest.mark.asyncio
    async def test_ftp_scheme_rejected(self):
        """Non-HTTP schemes rejected."""
        with pytest.raises(URLValidationError, match="Invalid URL scheme"):
            await validate_url_target("ftp://example.com/path")

    @pytest.mark.asyncio
    async def test_dns_failure_raises(self):
        """DNS resolution failure raises URLValidationError."""
        import socket
        with patch("common.vvp.url_validation.asyncio") as mock_asyncio:
            mock_loop = AsyncMock()
            mock_loop.getaddrinfo = AsyncMock(
                side_effect=socket.gaierror("Name or service not known")
            )
            mock_asyncio.get_running_loop.return_value = mock_loop
            with pytest.raises(URLValidationError, match="DNS resolution failed"):
                await validate_url_target("https://nonexistent.example.com/path")


# =============================================================================
# Integration: dossier fetch uses shared client
# =============================================================================


class TestDossierFetchIntegration:
    """Test that dossier fetch uses the shared client."""

    @pytest.mark.asyncio
    async def test_fetch_uses_shared_client(self):
        """fetch_dossier uses get_shared_client, not per-request client."""
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.headers = {"content-type": "application/json"}
        mock_response.content = b'[{"d": "ESAID"}]'

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)

        async def _noop_validate(*a, **kw):
            pass

        with patch("common.vvp.url_validation.validate_url_target", new=_noop_validate), \
             patch("common.vvp.http_client.get_shared_client",
                   new=AsyncMock(return_value=mock_client)):

            from common.vvp.dossier.fetch import fetch_dossier
            content = await fetch_dossier("https://example.com/dossier")

            assert content == b'[{"d": "ESAID"}]'
            mock_client.get.assert_called_once()

    @pytest.mark.asyncio
    async def test_fetch_ssrf_blocked_propagates_as_fetch_error(self):
        """URL validation failure in fetch_dossier raises FetchError (not URLValidationError)."""
        from common.vvp.dossier.exceptions import FetchError
        from common.vvp.dossier.fetch import fetch_dossier

        with _mock_dns('127.0.0.1'):
            with pytest.raises(FetchError, match="non-routable"):
                await fetch_dossier("https://evil.com/dossier")


# =============================================================================
# URL validation policy assertion tests (R4 finding #73)
# =============================================================================


class TestUrlValidationPolicy:
    """Assert that callers pass the correct allow_http policy to validate_url_target.

    Prevents security regressions where allow_http=True is accidentally used
    for untrusted dossier URLs, or allow_http=False blocks local witness OOBIs.
    """

    @pytest.mark.asyncio
    async def test_dossier_fetch_rejects_http(self):
        """fetch_dossier calls validate_url_target with allow_http=False (https only)."""
        from common.vvp.dossier.fetch import fetch_dossier

        captured_kwargs = {}

        async def spy_validate(url, *, allow_http=False):
            captured_kwargs["allow_http"] = allow_http
            # Let it pass through to the HTTP client (which we'll mock)

        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.headers = {"content-type": "application/json"}
        mock_response.content = b'{"d": "ESAID"}'

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)

        # validate_url_target is imported inside fetch_dossier via deferred import;
        # patch at the source module where it's defined
        with patch("common.vvp.url_validation.validate_url_target", new=spy_validate), \
             patch("common.vvp.http_client.get_shared_client",
                   new=AsyncMock(return_value=mock_client)):
            await fetch_dossier("https://example.com/dossier")

        assert captured_kwargs["allow_http"] is False, \
            "fetch_dossier must call validate_url_target with allow_http=False"

    @pytest.mark.asyncio
    async def test_oobi_allows_http(self):
        """dereference_oobi calls validate_url_target with allow_http=True."""
        from app.vvp.keri.oobi import dereference_oobi

        captured_kwargs = {}

        async def spy_validate(url, *, allow_http=False):
            captured_kwargs["allow_http"] = allow_http

        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.headers = {"content-type": "application/json"}
        mock_response.content = b'{"t": "icp", "i": "EAID123", "b": []}'

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)

        with patch("common.vvp.url_validation.validate_url_target", new=spy_validate), \
             patch("common.vvp.http_client.get_shared_client",
                   new=AsyncMock(return_value=mock_client)):
            await dereference_oobi("http://witness.local:5642/oobi/EAID123/witness")

        assert captured_kwargs["allow_http"] is True, \
            "dereference_oobi must call validate_url_target with allow_http=True"


# =============================================================================
# E2E cached second-call regression test (R4 finding #68)
# =============================================================================


class TestCachedSecondCallRegression:
    """Verify the Sprint 78 goal: a second verification call with cached key state
    avoids OOBI network fetches, proving the range-based cache eliminates redundant
    lookups for different iat values against the same AID.
    """

    @pytest.mark.asyncio
    async def test_second_call_uses_cache_no_refetch(self):
        """Second resolve_key_state call with different reference_time uses cache,
        does NOT re-fetch OOBI — proving the Sprint 78 performance goal.
        """
        from datetime import datetime, timezone
        from app.vvp.keri.kel_resolver import resolve_key_state, get_cache, reset_cache
        from app.vvp.keri.cache import CacheConfig

        reset_cache()

        # Build a cache with a generous freshness window
        cache = get_cache(CacheConfig(
            ttl_seconds=300, max_entries=100,
            freshness_window_seconds=300.0,
        ))

        # Mock OOBI fetch to return valid KEL data
        from app.vvp.keri.kel_parser import KELEvent, EventType
        from app.vvp.keri.oobi import OOBIResult

        aid = "ETestAID12345678901234567890123456789012"
        iat1 = datetime(2024, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        iat2 = datetime(2024, 6, 1, 12, 0, 5, tzinfo=timezone.utc)  # 5s later

        mock_icp = KELEvent(
            event_type=EventType.ICP,
            sequence=0,
            prior_digest="",
            digest="ESAID_ICP_0001",
            signing_keys=[b"\x01" * 32],
            next_keys_digest=None,
            witnesses=["BWITNESS1"],
            toad=1,
            timestamp=datetime(2024, 1, 1, tzinfo=timezone.utc),
        )

        mock_oobi_result = OOBIResult(
            aid=aid,
            kel_data=b'[{"t":"icp"}]',
            witnesses=["BWITNESS1"],
            content_type="application/json",
        )

        oobi_fetch_count = 0

        async def mock_fetch_and_validate(oobi_url, aid_, strict_validation=True):
            nonlocal oobi_fetch_count
            oobi_fetch_count += 1
            return mock_oobi_result, [mock_icp]

        # First call: should fetch OOBI
        with patch("app.vvp.keri.kel_resolver._fetch_and_validate_oobi",
                    new=mock_fetch_and_validate), \
             patch("app.core.config.TIER2_KEL_RESOLUTION_ENABLED", True):
            ks1 = await resolve_key_state(
                aid, iat1,
                oobi_url=f"http://witness.local/oobi/{aid}/witness",
                _allow_test_mode=True,
            )

        assert oobi_fetch_count == 1, "First call should fetch OOBI"
        assert ks1.aid == aid

        # Second call with different iat: should use cache, NOT re-fetch
        with patch("app.vvp.keri.kel_resolver._fetch_and_validate_oobi",
                    new=mock_fetch_and_validate), \
             patch("app.core.config.TIER2_KEL_RESOLUTION_ENABLED", True):
            ks2 = await resolve_key_state(
                aid, iat2,
                oobi_url=f"http://witness.local/oobi/{aid}/witness",
                _allow_test_mode=True,
            )

        # CRITICAL ASSERTION: OOBI fetch count did NOT increase
        assert oobi_fetch_count == 1, \
            "Second call with different iat must use range-based cache — " \
            "OOBI fetch count should remain 1 (Sprint 78 goal)"
        assert ks2.aid == aid
        assert ks2.signing_keys == ks1.signing_keys

        # Verify cache metrics confirm the hit
        assert cache.metrics().hits >= 1, "Cache should record at least one hit"

        reset_cache()


# =============================================================================
# Redirect handling regression test (R6 finding #86)
# =============================================================================


class TestRedirectHandling:
    """Assert that the shared HTTP client does NOT follow redirects.

    Sprint 78 hardened redirect handling: follow_redirects=False on the shared
    client means 3xx responses are returned as-is (not followed). Callers treat
    these as errors. This prevents redirect-based SSRF bypass.
    """

    @pytest.mark.asyncio
    async def test_shared_client_returns_redirect_as_is(self):
        """Shared client returns 3xx response without following the redirect."""
        client = await get_shared_client()
        assert client.follow_redirects is False, \
            "Shared client must have follow_redirects=False"

    @pytest.mark.asyncio
    async def test_dossier_fetch_rejects_redirect(self):
        """fetch_dossier treats a 3xx response as an HTTP error, not a redirect to follow."""
        from common.vvp.dossier.exceptions import FetchError
        from common.vvp.dossier.fetch import fetch_dossier

        mock_response = AsyncMock()
        mock_response.status_code = 302
        mock_response.headers = {"location": "http://evil.internal/steal"}
        mock_response.raise_for_status = MagicMock(
            side_effect=httpx.HTTPStatusError(
                "302 redirect", request=MagicMock(), response=mock_response
            )
        )

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)

        async def _noop_validate(*a, **kw):
            pass

        with patch("common.vvp.url_validation.validate_url_target", new=_noop_validate), \
             patch("common.vvp.http_client.get_shared_client",
                   new=AsyncMock(return_value=mock_client)):
            with pytest.raises(FetchError):
                await fetch_dossier("https://example.com/dossier")
