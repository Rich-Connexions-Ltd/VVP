"""Shared httpx.AsyncClient for connection pooling.

Single responsibility: client lifecycle (create, get, close, test-reset).
URL validation lives in common.vvp.url_validation.

Thread/async safety: asyncio.Lock guards lazy initialization to prevent
race conditions where concurrent coroutines could create multiple clients.

Sprint 78: Moved from services/verifier to common for shared use.
"""

import asyncio
import logging
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

_DEFAULT_POOL_LIMITS = httpx.Limits(
    max_connections=100,
    max_keepalive_connections=20,
    keepalive_expiry=30.0,
)

_shared_client: Optional[httpx.AsyncClient] = None
_init_lock = asyncio.Lock()


async def get_shared_client() -> httpx.AsyncClient:
    """Get or create the shared httpx.AsyncClient.

    The client has follow_redirects=False to prevent SSRF bypass via
    redirects to private IPs. Callers must handle 3xx responses as errors.

    Uses asyncio.Lock to prevent race condition where concurrent
    coroutines could create multiple clients.
    """
    global _shared_client
    if _shared_client is not None and not _shared_client.is_closed:
        return _shared_client
    async with _init_lock:
        if _shared_client is not None and not _shared_client.is_closed:
            return _shared_client
        _shared_client = httpx.AsyncClient(
            limits=_DEFAULT_POOL_LIMITS,
            follow_redirects=False,  # SSRF: no redirects — prevents DNS rebinding bypass
            http2=False,
        )
        logger.info("Created shared httpx.AsyncClient with connection pooling")
        return _shared_client


async def close_shared_client() -> None:
    """Close the shared client. Call on application shutdown."""
    global _shared_client
    if _shared_client is not None and not _shared_client.is_closed:
        await _shared_client.aclose()
        logger.info("Closed shared httpx.AsyncClient")
    _shared_client = None


async def reset_shared_client() -> None:
    """Reset shared client for testing. Properly closes any open client.

    Guarded: only callable within a pytest session.
    """
    import sys
    assert "pytest" in sys.modules, "reset_shared_client() is for test use only"
    global _shared_client
    if _shared_client is not None and not _shared_client.is_closed:
        await _shared_client.aclose()
    _shared_client = None
