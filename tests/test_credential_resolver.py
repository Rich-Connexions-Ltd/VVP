"""Tests for credential resolver module."""

import asyncio
import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from app.vvp.keri.credential_resolver import (
    CredentialResolver,
    CredentialResolverConfig,
    ResolvedCredential,
    ResolverMetrics,
    get_credential_resolver,
    reset_credential_resolver,
)
from app.vvp.keri.credential_cache import (
    CredentialCache,
    CredentialCacheConfig,
    reset_credential_cache,
)


@pytest.fixture
def mock_acdc():
    """Create a mock ACDC for testing."""
    acdc = MagicMock()
    acdc.said = "EABC123456789012345678901234567890123"
    acdc.issuer_aid = "EIssuer1234567890123456789012345678"
    return acdc


@pytest.fixture
def resolver():
    """Create a fresh resolver for each test."""
    cache = CredentialCache(CredentialCacheConfig(ttl_seconds=60, max_entries=10))
    return CredentialResolver(
        config=CredentialResolverConfig(
            enabled=True,
            timeout_seconds=1.0,
            max_recursion_depth=3,
        ),
        cache=cache,
    )


@pytest.fixture(autouse=True)
def reset_singletons():
    """Reset singletons before each test."""
    reset_credential_resolver()
    reset_credential_cache()
    yield
    reset_credential_resolver()
    reset_credential_cache()


class TestResolverMetrics:
    """Tests for ResolverMetrics."""

    def test_to_dict(self):
        """Test dictionary conversion."""
        metrics = ResolverMetrics(
            attempts=10, successes=7, failures=3, cache_hits=2, recursion_limits=1
        )
        d = metrics.to_dict()
        assert d["attempts"] == 10
        assert d["successes"] == 7
        assert d["failures"] == 3
        assert d["cache_hits"] == 2
        assert d["recursion_limits"] == 1
        assert d["success_rate"] == 0.7

    def test_success_rate_zero_attempts(self):
        """Test success rate with zero attempts."""
        metrics = ResolverMetrics()
        assert metrics.to_dict()["success_rate"] == 0.0


class TestCredentialResolverConfig:
    """Tests for CredentialResolverConfig."""

    def test_default_values(self):
        """Test default configuration values."""
        config = CredentialResolverConfig()
        assert config.enabled is True
        assert config.timeout_seconds == 5.0
        assert config.max_recursion_depth == 3
        assert config.cache_ttl_seconds == 300
        assert config.cache_max_entries == 500


class TestCredentialResolver:
    """Tests for CredentialResolver."""

    @pytest.mark.asyncio
    async def test_resolve_disabled_returns_none(self, mock_acdc):
        """Test that resolution returns None when disabled."""
        config = CredentialResolverConfig(enabled=False)
        resolver = CredentialResolver(config=config)

        result = await resolver.resolve(
            said="ESAID_123456789012345678901234567890",
            witness_base_urls=["http://witness.example.com"],
        )

        assert result is None

    @pytest.mark.asyncio
    async def test_resolve_recursion_limit(self, resolver):
        """Test that recursion limit is enforced."""
        result = await resolver.resolve(
            said="ESAID_123456789012345678901234567890",
            witness_base_urls=["http://witness.example.com"],
            current_depth=10,  # Exceeds max_recursion_depth=3
        )

        assert result is None
        assert resolver.metrics.recursion_limits == 1

    @pytest.mark.asyncio
    async def test_resolve_no_witnesses_returns_none(self, resolver):
        """Test that empty witness list returns None."""
        result = await resolver.resolve(
            said="ESAID_123456789012345678901234567890",
            witness_base_urls=[],
        )

        assert result is None
        assert resolver.metrics.failures == 1

    @pytest.mark.asyncio
    async def test_resolve_cache_hit(self, resolver, mock_acdc):
        """Test that cache hits return cached credentials."""
        # Pre-populate cache
        cache = await resolver._get_cache()
        await cache.put(
            said=mock_acdc.said,
            acdc=mock_acdc,
            source_url="http://cached.example.com",
        )

        result = await resolver.resolve(
            said=mock_acdc.said,
            witness_base_urls=["http://witness.example.com"],
        )

        assert result is not None
        assert result.acdc is mock_acdc
        assert result.source_url == "http://cached.example.com"
        assert resolver.metrics.cache_hits == 1

    @pytest.mark.asyncio
    async def test_resolve_prevents_loops(self, resolver):
        """Test that in-flight tracking prevents loops."""
        said = "ESAID_123456789012345678901234567890"

        # Simulate an in-flight request
        resolver._in_flight.add(said)

        result = await resolver.resolve(
            said=said,
            witness_base_urls=["http://witness.example.com"],
        )

        assert result is None

    @pytest.mark.asyncio
    async def test_fetch_successful_resolution(self, resolver):
        """Test successful credential resolution from witness."""
        said = "EABC123456789012345678901234567890123"
        acdc_json = {
            "v": "ACDC10JSON000000_",
            "d": said,
            "i": "EIssuer1234567890123456789012345678",
            "s": "ESchema123456789012345678901234567890",
            "a": {"name": "Test"},
        }

        with patch("httpx.AsyncClient") as mock_client:
            # Setup mock response
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.content = json.dumps(acdc_json).encode()

            mock_instance = AsyncMock()
            mock_instance.get = AsyncMock(return_value=mock_response)
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=None)
            mock_client.return_value = mock_instance

            result = await resolver.resolve(
                said=said,
                witness_base_urls=["http://witness.example.com"],
            )

            assert result is not None
            assert result.acdc.said == said
            assert result.source_url == "http://witness.example.com"
            assert resolver.metrics.successes == 1

    @pytest.mark.asyncio
    async def test_fetch_404_returns_none(self, resolver):
        """Test that 404 response returns None."""
        said = "ESAID_123456789012345678901234567890"

        with patch("httpx.AsyncClient") as mock_client:
            mock_response = MagicMock()
            mock_response.status_code = 404

            mock_instance = AsyncMock()
            mock_instance.get = AsyncMock(return_value=mock_response)
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=None)
            mock_client.return_value = mock_instance

            result = await resolver.resolve(
                said=said,
                witness_base_urls=["http://witness.example.com"],
            )

            assert result is None
            assert resolver.metrics.failures == 1

    @pytest.mark.asyncio
    async def test_fetch_timeout_returns_none(self, resolver):
        """Test that timeout returns None."""
        import httpx

        said = "ESAID_123456789012345678901234567890"

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_instance.get = AsyncMock(side_effect=httpx.TimeoutException("timeout"))
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=None)
            mock_client.return_value = mock_instance

            result = await resolver.resolve(
                said=said,
                witness_base_urls=["http://witness.example.com"],
            )

            assert result is None

    @pytest.mark.asyncio
    async def test_fetch_network_error_returns_none(self, resolver):
        """Test that network error returns None."""
        import httpx

        said = "ESAID_123456789012345678901234567890"

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_instance.get = AsyncMock(
                side_effect=httpx.RequestError("connection refused")
            )
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=None)
            mock_client.return_value = mock_instance

            result = await resolver.resolve(
                said=said,
                witness_base_urls=["http://witness.example.com"],
            )

            assert result is None

    @pytest.mark.asyncio
    async def test_fetch_said_mismatch_returns_none(self, resolver):
        """Test that SAID mismatch returns None."""
        requested_said = "ESAID_REQUEST_123456789012345678901"
        returned_said = "ESAID_DIFFERENT_12345678901234567890"

        acdc_json = {
            "v": "ACDC10JSON000000_",
            "d": returned_said,  # Different SAID
            "i": "EIssuer1234567890123456789012345678",
            "s": "ESchema123456789012345678901234567890",
        }

        with patch("httpx.AsyncClient") as mock_client:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.content = json.dumps(acdc_json).encode()

            mock_instance = AsyncMock()
            mock_instance.get = AsyncMock(return_value=mock_response)
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=None)
            mock_client.return_value = mock_instance

            result = await resolver.resolve(
                said=requested_said,
                witness_base_urls=["http://witness.example.com"],
            )

            assert result is None

    @pytest.mark.asyncio
    async def test_fetch_wrapped_credential(self, resolver):
        """Test parsing wrapped credential response."""
        said = "EABC123456789012345678901234567890123"
        acdc_json = {
            "credential": {  # Wrapped in "credential" key
                "v": "ACDC10JSON000000_",
                "d": said,
                "i": "EIssuer1234567890123456789012345678",
                "s": "ESchema123456789012345678901234567890",
            }
        }

        with patch("httpx.AsyncClient") as mock_client:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.content = json.dumps(acdc_json).encode()

            mock_instance = AsyncMock()
            mock_instance.get = AsyncMock(return_value=mock_response)
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=None)
            mock_client.return_value = mock_instance

            result = await resolver.resolve(
                said=said,
                witness_base_urls=["http://witness.example.com"],
            )

            assert result is not None
            assert result.acdc.said == said

    @pytest.mark.asyncio
    async def test_fetch_parallel_witnesses(self, resolver):
        """Test that multiple witnesses are queried in parallel."""
        said = "EABC123456789012345678901234567890123"
        acdc_json = {
            "v": "ACDC10JSON000000_",
            "d": said,
            "i": "EIssuer1234567890123456789012345678",
            "s": "ESchema123456789012345678901234567890",
        }

        call_count = 0

        async def mock_get(url):
            nonlocal call_count
            call_count += 1
            response = MagicMock()
            response.status_code = 200
            response.content = json.dumps(acdc_json).encode()
            return response

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_instance.get = mock_get
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=None)
            mock_client.return_value = mock_instance

            result = await resolver.resolve(
                said=said,
                witness_base_urls=[
                    "http://witness1.example.com",
                    "http://witness2.example.com",
                    "http://witness3.example.com",
                ],
            )

            assert result is not None
            # All 3 witnesses should be queried in parallel
            assert call_count == 3

    @pytest.mark.asyncio
    async def test_fetch_max_three_witnesses(self, resolver):
        """Test that at most 3 witnesses are queried."""
        said = "EABC123456789012345678901234567890123"
        acdc_json = {
            "v": "ACDC10JSON000000_",
            "d": said,
            "i": "EIssuer1234567890123456789012345678",
            "s": "ESchema123456789012345678901234567890",
        }

        call_count = 0

        async def mock_get(url):
            nonlocal call_count
            call_count += 1
            response = MagicMock()
            response.status_code = 200
            response.content = json.dumps(acdc_json).encode()
            return response

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_instance.get = mock_get
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=None)
            mock_client.return_value = mock_instance

            result = await resolver.resolve(
                said=said,
                witness_base_urls=[
                    "http://witness1.example.com",
                    "http://witness2.example.com",
                    "http://witness3.example.com",
                    "http://witness4.example.com",
                    "http://witness5.example.com",
                ],
            )

            assert result is not None
            # Only first 3 witnesses should be queried
            assert call_count == 3


class TestCESRResponseParsing:
    """Tests for CESR response parsing with attachments."""

    @pytest.fixture
    def resolver(self):
        """Create a fresh resolver for each test."""
        cache = CredentialCache(CredentialCacheConfig(ttl_seconds=60, max_entries=10))
        return CredentialResolver(
            config=CredentialResolverConfig(
                enabled=True,
                timeout_seconds=1.0,
                max_recursion_depth=3,
            ),
            cache=cache,
        )

    @pytest.mark.asyncio
    async def test_parse_cesr_response_with_signature(self, resolver):
        """Test parsing CESR response with controller signature attachment.

        Per review: CESR responses with -A attachments should extract signatures.
        """
        said = "EABC123456789012345678901234567890123"

        # Build a CESR message: JSON event + -A controller signature
        # This mimics what a real witness would return
        acdc_json = {
            "v": "ACDC10JSON000000_",
            "d": said,
            "i": "EIssuer1234567890123456789012345678",
            "s": "ESchema123456789012345678901234567890",
            "a": {"name": "Test"},
        }
        json_bytes = json.dumps(acdc_json).encode()

        # Create a real CESR stream with -AAB attachment (1 indexed signature)
        # Format: JSON + count code (-AAB = 1 signature) + indexed signature primitive
        # Indexed signature primitive is 88 qb64 chars starting with derivation code
        # Using 0A derivation code (Ed25519 indexed signature, index 0)
        # The full primitive is: derivation code (2 chars) + index (2 chars) + sig data (84 chars) = 88 chars
        fake_signature_qb64 = "0AAA" + "A" * 84  # 88 chars total for indexed sig
        cesr_content = json_bytes + b"-AAB" + fake_signature_qb64.encode()

        with patch("httpx.AsyncClient") as mock_client:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.content = cesr_content

            mock_instance = AsyncMock()
            mock_instance.get = AsyncMock(return_value=mock_response)
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=None)
            mock_client.return_value = mock_instance

            result = await resolver.resolve(
                said=said,
                witness_base_urls=["http://witness.example.com"],
            )

            # Should successfully parse and extract signature
            assert result is not None
            assert result.acdc.said == said
            # Signature should be extracted from the -AAB attachment
            assert result.signature is not None
            # Ed25519 signature is 64 bytes (the raw signature after stripping lead bytes)
            assert len(result.signature) == 64

    @pytest.mark.asyncio
    async def test_parse_json_response_no_signature(self, resolver):
        """Test that plain JSON response returns None signature."""
        said = "EABC123456789012345678901234567890123"
        acdc_json = {
            "v": "ACDC10JSON000000_",
            "d": said,
            "i": "EIssuer1234567890123456789012345678",
            "s": "ESchema123456789012345678901234567890",
            "a": {"name": "Test"},
        }

        with patch("httpx.AsyncClient") as mock_client:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.content = json.dumps(acdc_json).encode()

            mock_instance = AsyncMock()
            mock_instance.get = AsyncMock(return_value=mock_response)
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=None)
            mock_client.return_value = mock_instance

            result = await resolver.resolve(
                said=said,
                witness_base_urls=["http://witness.example.com"],
            )

            assert result is not None
            assert result.acdc.said == said
            # Plain JSON has no signature
            assert result.signature is None


class TestCredentialResolverSingleton:
    """Tests for credential resolver singleton."""

    def test_singleton_returns_same_instance(self):
        """Test that singleton returns the same instance."""
        resolver1 = get_credential_resolver()
        resolver2 = get_credential_resolver()
        assert resolver1 is resolver2

    def test_reset_clears_singleton(self):
        """Test that reset clears the singleton."""
        resolver1 = get_credential_resolver()
        reset_credential_resolver()
        resolver2 = get_credential_resolver()
        assert resolver1 is not resolver2

    def test_config_only_used_on_creation(self):
        """Test that config is only used when creating new instance."""
        config1 = CredentialResolverConfig(timeout_seconds=10.0)
        resolver1 = get_credential_resolver(config1)

        # This config should be ignored
        config2 = CredentialResolverConfig(timeout_seconds=20.0)
        resolver2 = get_credential_resolver(config2)

        assert resolver1 is resolver2
        # Original config should be in effect
        assert resolver1.config.timeout_seconds == 10.0
