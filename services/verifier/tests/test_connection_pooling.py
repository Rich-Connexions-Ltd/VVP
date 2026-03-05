"""Tests for Sprint 78: Connection pooling and SSRF validation.

Tests the shared HTTP client module and URL validation module:
- get_shared_client() lifecycle
- validate_url_target() SSRF prevention
- Integration with dossier fetch and OOBI
"""

import asyncio
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from common.vvp.http_client import (
    get_shared_client,
    close_shared_client,
    reset_shared_client,
)
from common.vvp.url_validation import validate_url_target
from common.vvp.dossier.exceptions import FetchError


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
        """Concurrent get_shared_client calls don't create multiple clients."""
        await reset_shared_client()

        # Launch many concurrent get calls
        results = await asyncio.gather(*[get_shared_client() for _ in range(20)])

        # All should be the same instance
        first = results[0]
        for r in results[1:]:
            assert r is first


# =============================================================================
# URL validation tests
# =============================================================================


class TestUrlValidation:
    """Test SSRF prevention in validate_url_target."""

    @pytest.mark.asyncio
    async def test_https_accepted(self):
        """HTTPS URLs are accepted."""
        # Mock DNS to return a public IP
        with patch("common.vvp.url_validation.asyncio") as mock_asyncio:
            mock_loop = AsyncMock()
            mock_loop.getaddrinfo = AsyncMock(return_value=[
                (2, 1, 6, '', ('93.184.216.34', 0)),  # example.com public IP
            ])
            mock_asyncio.get_running_loop.return_value = mock_loop
            await validate_url_target("https://example.com/path")

    @pytest.mark.asyncio
    async def test_http_rejected_by_default(self):
        """HTTP URLs rejected when allow_http=False (default)."""
        with pytest.raises(FetchError, match="Invalid URL scheme"):
            await validate_url_target("http://example.com/path")

    @pytest.mark.asyncio
    async def test_http_allowed_when_specified(self):
        """HTTP URLs accepted when allow_http=True."""
        with patch("common.vvp.url_validation.asyncio") as mock_asyncio:
            mock_loop = AsyncMock()
            mock_loop.getaddrinfo = AsyncMock(return_value=[
                (2, 1, 6, '', ('93.184.216.34', 0)),
            ])
            mock_asyncio.get_running_loop.return_value = mock_loop
            await validate_url_target("http://example.com/path", allow_http=True)

    @pytest.mark.asyncio
    async def test_private_ip_rejected(self):
        """Private IPs rejected (SSRF prevention)."""
        with patch("common.vvp.url_validation.asyncio") as mock_asyncio:
            mock_loop = AsyncMock()
            mock_loop.getaddrinfo = AsyncMock(return_value=[
                (2, 1, 6, '', ('192.168.1.1', 0)),  # Private IP
            ])
            mock_asyncio.get_running_loop.return_value = mock_loop
            with pytest.raises(FetchError, match="non-routable"):
                await validate_url_target("https://evil.com/path")

    @pytest.mark.asyncio
    async def test_loopback_rejected(self):
        """Loopback addresses rejected."""
        with patch("common.vvp.url_validation.asyncio") as mock_asyncio:
            mock_loop = AsyncMock()
            mock_loop.getaddrinfo = AsyncMock(return_value=[
                (2, 1, 6, '', ('127.0.0.1', 0)),
            ])
            mock_asyncio.get_running_loop.return_value = mock_loop
            with pytest.raises(FetchError, match="non-routable"):
                await validate_url_target("https://localhost/path")

    @pytest.mark.asyncio
    async def test_missing_host_rejected(self):
        """URL without host is rejected."""
        with pytest.raises(FetchError, match="missing host"):
            await validate_url_target("https:///path")

    @pytest.mark.asyncio
    async def test_ftp_scheme_rejected(self):
        """Non-HTTP schemes rejected."""
        with pytest.raises(FetchError, match="Invalid URL scheme"):
            await validate_url_target("ftp://example.com/path")

    @pytest.mark.asyncio
    async def test_dns_failure_raises(self):
        """DNS resolution failure raises FetchError."""
        import socket
        with patch("common.vvp.url_validation.asyncio") as mock_asyncio:
            mock_loop = AsyncMock()
            mock_loop.getaddrinfo = AsyncMock(
                side_effect=socket.gaierror("Name or service not known")
            )
            mock_asyncio.get_running_loop.return_value = mock_loop
            with pytest.raises(FetchError, match="DNS resolution failed"):
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
