"""Tests for logo cache (Sprint 79)."""

import asyncio
import os
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.verify.logo_cache import LogoCache, LogoCacheResult, _detect_extension


# PNG magic bytes
PNG_BYTES = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100

# JPEG magic bytes
JPEG_BYTES = b"\xff\xd8\xff\xe0" + b"\x00" * 100


class TestDetectExtension:
    def test_png(self):
        assert _detect_extension(PNG_BYTES) == "png"

    def test_jpeg(self):
        assert _detect_extension(JPEG_BYTES) == "jpg"

    def test_gif(self):
        assert _detect_extension(b"GIF89a" + b"\x00" * 100) == "gif"

    def test_webp(self):
        assert _detect_extension(b"RIFF\x00\x00\x00\x00WEBP" + b"\x00" * 100) == "webp"

    def test_unknown_defaults_to_png(self):
        assert _detect_extension(b"\x00\x00\x00\x00") == "png"


class TestLogoCacheResult:
    def test_verified_result(self):
        result = LogoCacheResult(
            local_url="http://127.0.0.1:8080/logo/Eaaa",
            verified=True,
            from_cache=False,
            original_url="https://cdn.example.com/logo.png",
        )
        assert result.verified is True
        assert result.from_cache is False

    def test_unverified_result(self):
        result = LogoCacheResult(
            local_url="http://127.0.0.1:8080/logo/unknown",
            verified=False,
            from_cache=False,
            original_url="https://cdn.example.com/logo.png",
        )
        assert result.verified is False


@pytest.fixture
def cache(tmp_path):
    """Create a LogoCache with a temp directory."""
    return LogoCache(
        cache_dir=str(tmp_path),
        max_mb=10,
        ttl_hours=24,
        base_url="http://127.0.0.1:8080",
    )


class TestLogoCacheGetOrFetch:
    @pytest.mark.asyncio
    async def test_fetch_and_cache(self, cache, tmp_path):
        """First fetch stores logo in cache and returns local URL."""
        said = "E" + "a" * 43
        mock_client = AsyncMock()

        with patch("app.verify.logo_cache.fetch_validate_hash") as mock_fetch:
            mock_fetch.return_value = (PNG_BYTES, said)

            result = await cache.get_or_fetch(
                logo_url="https://cdn.example.com/logo.png",
                expected_said=said,
                http_client=mock_client,
            )

        assert result.verified is True
        assert result.from_cache is False
        assert said in result.local_url
        # File should exist on disk
        assert (tmp_path / f"{said}.png").exists()

    @pytest.mark.asyncio
    async def test_cache_hit(self, cache, tmp_path):
        """Second fetch for same SAID returns from cache."""
        said = "E" + "a" * 43
        mock_client = AsyncMock()

        with patch("app.verify.logo_cache.fetch_validate_hash") as mock_fetch:
            mock_fetch.return_value = (PNG_BYTES, said)

            # First fetch
            await cache.get_or_fetch(
                logo_url="https://cdn.example.com/logo.png",
                expected_said=said,
                http_client=mock_client,
            )

            # Second fetch — should hit cache
            result = await cache.get_or_fetch(
                logo_url="https://cdn.example.com/logo.png",
                expected_said=said,
                http_client=mock_client,
            )

        assert result.from_cache is True
        assert result.verified is True
        assert mock_fetch.call_count == 1  # Only one fetch

    @pytest.mark.asyncio
    async def test_hash_mismatch_returns_unknown(self, cache):
        """Hash mismatch returns unknown-brand URL."""
        from common.vvp.logo_hash import LogoHashMismatchError

        said = "E" + "a" * 43
        mock_client = AsyncMock()

        with patch("app.verify.logo_cache.fetch_validate_hash") as mock_fetch:
            mock_fetch.side_effect = LogoHashMismatchError(said, "E" + "b" * 43)

            result = await cache.get_or_fetch(
                logo_url="https://cdn.example.com/logo.png",
                expected_said=said,
                http_client=mock_client,
            )

        assert result.verified is False
        assert "unknown" in result.local_url

    @pytest.mark.asyncio
    async def test_fetch_error_returns_unknown(self, cache):
        """Fetch failure returns unknown-brand URL."""
        from common.vvp.logo_hash import LogoFetchError

        said = "E" + "a" * 43
        mock_client = AsyncMock()

        with patch("app.verify.logo_cache.fetch_validate_hash") as mock_fetch:
            mock_fetch.side_effect = LogoFetchError("Timeout")

            result = await cache.get_or_fetch(
                logo_url="https://cdn.example.com/logo.png",
                expected_said=said,
                http_client=mock_client,
            )

        assert result.verified is False
        assert "unknown" in result.local_url

    @pytest.mark.asyncio
    async def test_legacy_no_hash(self, cache):
        """Legacy logo (no expected_said) cached by computed hash."""
        computed_said = "E" + "b" * 43
        mock_client = AsyncMock()

        with patch("app.verify.logo_cache.fetch_validate_hash") as mock_fetch:
            mock_fetch.return_value = (PNG_BYTES, computed_said)

            result = await cache.get_or_fetch(
                logo_url="https://cdn.example.com/logo.png",
                expected_said=None,
                http_client=mock_client,
            )

        assert result.verified is False  # No expected hash = unverified
        assert computed_said in result.local_url


class TestLogoCacheGetFilePath:
    @pytest.mark.asyncio
    async def test_get_cached_file(self, cache, tmp_path):
        """get_file_path returns path for cached logo."""
        said = "E" + "a" * 43
        mock_client = AsyncMock()

        with patch("app.verify.logo_cache.fetch_validate_hash") as mock_fetch:
            mock_fetch.return_value = (PNG_BYTES, said)
            await cache.get_or_fetch(
                logo_url="https://cdn.example.com/logo.png",
                expected_said=said,
                http_client=mock_client,
            )

        path = cache.get_file_path(said)
        assert path is not None
        assert path.exists()

    def test_get_missing_file(self, cache):
        """get_file_path returns None for uncached SAID."""
        assert cache.get_file_path("E" + "x" * 43) is None

    def test_get_content_type(self, cache):
        """get_content_type returns correct MIME type."""
        assert cache.get_content_type("nonexistent") == "application/octet-stream"


class TestLogoCacheSaidValidation:
    @pytest.mark.asyncio
    async def test_invalid_said_format_bypasses_cache(self, cache):
        """Invalid SAID format doesn't try cache lookup, proceeds to fetch."""
        mock_client = AsyncMock()
        computed = "E" + "c" * 43

        with patch("app.verify.logo_cache.fetch_validate_hash") as mock_fetch:
            mock_fetch.return_value = (PNG_BYTES, computed)

            result = await cache.get_or_fetch(
                logo_url="https://cdn.example.com/logo.png",
                expected_said="not-a-valid-said",
                http_client=mock_client,
            )

        # Should still return a result (fetch proceeds)
        assert result is not None
