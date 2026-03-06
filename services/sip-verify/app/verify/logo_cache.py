"""Logo fetch, hash verification, and disk cache.

Sprint 79: Fetches brand logos, verifies Blake3-256 hash against credential,
caches on disk, and serves via local HTTP endpoint. Per-SAID async locks
prevent thundering herd.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from common.vvp.logo_hash import (
    LogoFetchError,
    LogoHashMismatchError,
    fetch_validate_hash,
    validate_said_format,
)

logger = logging.getLogger(__name__)

# Default config
DEFAULT_CACHE_DIR = "/tmp/vvp-logo-cache"
DEFAULT_MAX_MB = 100
DEFAULT_TTL_HOURS = 24
DEFAULT_BASE_URL = "http://127.0.0.1:8080"

# Extension mapping from content-type
_EXT_MAP = {
    "image/png": "png",
    "image/jpeg": "jpg",
    "image/webp": "webp",
    "image/gif": "gif",
}


@dataclass
class LogoCacheResult:
    """Result from logo cache lookup or fetch."""
    local_url: str
    verified: bool
    from_cache: bool
    original_url: str


@dataclass
class _LockEntry:
    lock: asyncio.Lock
    refcount: int = 0
    last_used: float = 0.0


@dataclass
class _IndexEntry:
    said: str
    ext: str
    size: int
    last_access: float


class LogoCache:
    """Fetches, verifies, and caches brand logos with hash integrity."""

    def __init__(
        self,
        cache_dir: str = DEFAULT_CACHE_DIR,
        max_mb: int = DEFAULT_MAX_MB,
        ttl_hours: int = DEFAULT_TTL_HOURS,
        base_url: str = DEFAULT_BASE_URL,
    ):
        self._cache_dir = Path(cache_dir)
        self._max_bytes = max_mb * 1024 * 1024
        self._ttl_seconds = ttl_hours * 3600
        self._base_url = base_url.rstrip("/")

        self._cache_dir.mkdir(parents=True, exist_ok=True)

        # In-memory index: said -> _IndexEntry
        self._index: dict[str, _IndexEntry] = {}
        self._index_lock = asyncio.Lock()
        self._total_size = 0

        # Per-SAID locks with refcounting
        self._locks: dict[str, _LockEntry] = {}
        self._locks_mutex = asyncio.Lock()
        self._max_locks = 1000

    @property
    def unknown_url(self) -> str:
        """URL for the unknown/placeholder brand logo."""
        return f"{self._base_url}/logo/unknown"

    async def get_or_fetch(
        self,
        logo_url: str,
        expected_said: Optional[str] = None,
        http_client=None,
    ) -> LogoCacheResult:
        """Get cached logo or fetch, verify, and cache.

        Args:
            logo_url: URL to fetch the logo from.
            expected_said: Blake3 SAID to verify against (new schema).
                If None (legacy), logo is cached by content hash.
            http_client: httpx.AsyncClient to use for fetching.
        """
        if http_client is None:
            from common.vvp.http_client import get_shared_client
            http_client = await get_shared_client()

        # For legacy logos without hash, we'll compute the hash after fetch
        cache_key = expected_said

        # Check cache if we have a key
        if cache_key and validate_said_format(cache_key):
            cached = await self._check_cache(cache_key)
            if cached:
                return LogoCacheResult(
                    local_url=f"{self._base_url}/logo/{cache_key}",
                    verified=True,
                    from_cache=True,
                    original_url=logo_url,
                )

        # Acquire per-SAID lock
        lock_key = cache_key or logo_url
        lock = await self._acquire_lock(lock_key)
        try:
            async with lock:
                # Double-check cache after acquiring lock
                if cache_key and validate_said_format(cache_key):
                    cached = await self._check_cache(cache_key)
                    if cached:
                        return LogoCacheResult(
                            local_url=f"{self._base_url}/logo/{cache_key}",
                            verified=True,
                            from_cache=True,
                            original_url=logo_url,
                        )

                # Fetch and verify
                try:
                    image_bytes, computed_said = await fetch_validate_hash(
                        logo_url, http_client, expected_said=expected_said
                    )
                except LogoHashMismatchError as e:
                    logger.warning("Logo hash mismatch for %s: %s", logo_url[:80], e)
                    return LogoCacheResult(
                        local_url=self.unknown_url,
                        verified=False,
                        from_cache=False,
                        original_url=logo_url,
                    )
                except LogoFetchError as e:
                    logger.warning("Logo fetch failed for %s: %s", logo_url[:80], e)
                    return LogoCacheResult(
                        local_url=self.unknown_url,
                        verified=False,
                        from_cache=False,
                        original_url=logo_url,
                    )

                # Determine file extension from content (default png)
                ext = _detect_extension(image_bytes)
                said_key = expected_said or computed_said

                # Write to disk
                await self._write_cache(said_key, ext, image_bytes)

                verified = expected_said is not None
                return LogoCacheResult(
                    local_url=f"{self._base_url}/logo/{said_key}",
                    verified=verified,
                    from_cache=False,
                    original_url=logo_url,
                )
        finally:
            await self._release_lock(lock_key)

    async def _check_cache(self, said: str) -> bool:
        """Check if logo is in cache and not expired."""
        async with self._index_lock:
            entry = self._index.get(said)
            if entry is None:
                return False
            if time.monotonic() - entry.last_access > self._ttl_seconds:
                # Expired — remove
                await self._remove_entry(said)
                return False
            entry.last_access = time.monotonic()
            return True

    async def _write_cache(self, said: str, ext: str, data: bytes) -> None:
        """Write logo to cache directory."""
        filepath = self._cache_dir / f"{said}.{ext}"

        # Validate path doesn't escape cache dir
        real_cache = os.path.realpath(self._cache_dir)
        real_file = os.path.realpath(filepath)
        if not real_file.startswith(real_cache):
            logger.error("Path traversal attempt: %s", filepath)
            return

        await asyncio.to_thread(filepath.write_bytes, data)

        async with self._index_lock:
            # Remove old entry if exists
            if said in self._index:
                self._total_size -= self._index[said].size

            self._index[said] = _IndexEntry(
                said=said, ext=ext, size=len(data), last_access=time.monotonic()
            )
            self._total_size += len(data)

            # Evict if over limit
            await self._evict_if_needed()

    async def _remove_entry(self, said: str) -> None:
        """Remove entry from cache (caller must hold index_lock)."""
        entry = self._index.pop(said, None)
        if entry:
            self._total_size -= entry.size
            filepath = self._cache_dir / f"{said}.{entry.ext}"
            try:
                await asyncio.to_thread(filepath.unlink, True)
            except Exception:
                pass

    async def _evict_if_needed(self) -> None:
        """Evict LRU entries if total size exceeds max (caller must hold index_lock)."""
        if self._total_size <= self._max_bytes:
            return

        # Sort by last_access, evict oldest
        sorted_entries = sorted(self._index.values(), key=lambda e: e.last_access)
        evicted = 0
        for entry in sorted_entries:
            if self._total_size <= self._max_bytes * 0.8:  # Evict to 80%
                break
            await self._remove_entry(entry.said)
            evicted += 1

        if evicted:
            logger.info("Evicted %d logo cache entries", evicted)

    async def _acquire_lock(self, key: str) -> asyncio.Lock:
        """Get or create per-SAID lock with refcounting."""
        async with self._locks_mutex:
            if key not in self._locks:
                # Evict idle locks if at capacity
                if len(self._locks) >= self._max_locks:
                    idle = [
                        k for k, v in self._locks.items()
                        if v.refcount == 0
                    ]
                    # Sort by last_used, remove oldest
                    idle.sort(key=lambda k: self._locks[k].last_used)
                    for k in idle[:100]:  # Remove batch
                        del self._locks[k]

                self._locks[key] = _LockEntry(lock=asyncio.Lock())

            entry = self._locks[key]
            entry.refcount += 1
            entry.last_used = time.monotonic()
            return entry.lock

    async def _release_lock(self, key: str) -> None:
        """Decrement refcount for per-SAID lock."""
        async with self._locks_mutex:
            entry = self._locks.get(key)
            if entry:
                entry.refcount = max(0, entry.refcount - 1)

    def get_file_path(self, said: str) -> Optional[Path]:
        """Get the file path for a cached logo by SAID.

        Returns None if not in cache. Used by the serving endpoint.
        """
        entry = self._index.get(said)
        if entry is None:
            return None

        filepath = self._cache_dir / f"{said}.{entry.ext}"
        # Path traversal protection
        real_cache = os.path.realpath(self._cache_dir)
        real_file = os.path.realpath(filepath)
        if not real_file.startswith(real_cache):
            return None

        if not filepath.exists():
            return None

        # Update access time
        entry.last_access = time.monotonic()
        return filepath

    def get_content_type(self, said: str) -> str:
        """Get content-type for a cached logo."""
        entry = self._index.get(said)
        if entry is None:
            return "application/octet-stream"
        return {
            "png": "image/png",
            "jpg": "image/jpeg",
            "webp": "image/webp",
            "gif": "image/gif",
        }.get(entry.ext, "application/octet-stream")


def _detect_extension(data: bytes) -> str:
    """Detect image type from magic bytes."""
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "png"
    if data[:2] == b"\xff\xd8":
        return "jpg"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp"
    if data[:6] in (b"GIF87a", b"GIF89a"):
        return "gif"
    return "png"  # Default
