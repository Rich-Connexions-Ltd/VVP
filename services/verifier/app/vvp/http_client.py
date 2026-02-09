"""Shared httpx.AsyncClient for connection pooling across external calls.

Instead of creating a new httpx.AsyncClient per HTTP call (which means
new TCP connections, TLS handshakes, etc.), this module provides a shared
client with connection pooling and keepalive.

Usage:
    from app.vvp.http_client import get_shared_client

    client = get_shared_client()
    response = await client.get(url, timeout=5.0)
"""

import logging
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

# Pool limits: max 20 connections per host, 100 total
_DEFAULT_POOL_LIMITS = httpx.Limits(
    max_connections=100,
    max_keepalive_connections=20,
    keepalive_expiry=30.0,
)

_shared_client: Optional[httpx.AsyncClient] = None


def get_shared_client() -> httpx.AsyncClient:
    """Get or create the shared httpx.AsyncClient.

    The client is created lazily on first use and reused for all subsequent
    calls. Connection pooling is enabled with reasonable defaults.
    """
    global _shared_client
    if _shared_client is None or _shared_client.is_closed:
        _shared_client = httpx.AsyncClient(
            limits=_DEFAULT_POOL_LIMITS,
            follow_redirects=True,
            http2=False,  # HTTP/2 adds complexity; HTTP/1.1 is fine for our use case
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


def reset_shared_client() -> None:
    """Reset the shared client (for testing). Does NOT close it."""
    global _shared_client
    _shared_client = None
