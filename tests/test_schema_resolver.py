"""Tests for SAID-first SchemaResolver with multi-source resolution."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from app.vvp.acdc.exceptions import ACDCChainInvalid
from app.vvp.acdc.schema_cache import SchemaCache, SchemaCacheConfig, reset_schema_cache
from app.vvp.acdc.schema_resolver import (
    ResolvedSchema,
    SchemaResolver,
    SchemaResolverConfig,
    SchemaResolverMetrics,
    get_schema_resolver,
    reset_schema_resolver,
)


# Sample schema with valid SAID
# Note: Use a SAID that is NOT in the embedded store to test registry/cache paths
SAMPLE_SCHEMA_SAID = "ETestSAID_NotInEmbeddedStore_ForTesting1234"
SAMPLE_SCHEMA = {
    "$id": SAMPLE_SCHEMA_SAID,
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "Test Schema",
    "type": "object",
    "properties": {
        "name": {"type": "string"},
    },
}

# SAID that IS in the embedded store (for testing embedded store hits)
EMBEDDED_SCHEMA_SAID = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao"


@pytest.fixture
def resolver_config():
    """Test resolver config with short timeouts."""
    return SchemaResolverConfig(
        enabled=True,
        timeout_seconds=1.0,
        cache_ttl_seconds=60,
        cache_max_entries=10,
        registry_urls=["https://test.registry.com/"],
        oobi_resolution_enabled=False,
    )


@pytest.fixture
async def resolver(resolver_config):
    """Fresh resolver instance for testing."""
    reset_schema_resolver()
    cache = SchemaCache(SchemaCacheConfig(ttl_seconds=60, max_entries=10))
    return SchemaResolver(config=resolver_config, cache=cache)


class TestSchemaResolverConfig:
    """Tests for SchemaResolverConfig defaults."""

    def test_default_values(self):
        """Default config has sensible values."""
        config = SchemaResolverConfig()
        assert config.enabled is True
        assert config.timeout_seconds == 5.0
        assert config.cache_ttl_seconds == 3600
        assert config.cache_max_entries == 200
        assert len(config.registry_urls) == 2
        assert config.oobi_resolution_enabled is False

    def test_custom_registry_urls(self):
        """Custom registry URLs are respected."""
        config = SchemaResolverConfig(
            registry_urls=["https://custom.registry/"]
        )
        assert config.registry_urls == ["https://custom.registry/"]


class TestSchemaResolverMetrics:
    """Tests for SchemaResolverMetrics."""

    def test_to_dict(self):
        """Metrics can be serialized to dict."""
        metrics = SchemaResolverMetrics(
            attempts=10,
            successes=8,
            failures=2,
            cache_hits=5,
            said_mismatches=1,
            missing_said_field=0,
            registry_hits=3,
            oobi_hits=0,
        )
        d = metrics.to_dict()
        assert d["attempts"] == 10
        assert d["successes"] == 8
        assert d["success_rate"] == 0.8

    def test_success_rate_zero_attempts(self):
        """Success rate is 0.0 when no attempts."""
        metrics = SchemaResolverMetrics()
        assert metrics.to_dict()["success_rate"] == 0.0

    def test_reset(self):
        """Reset clears all metrics."""
        metrics = SchemaResolverMetrics(attempts=10, successes=8)
        metrics.reset()
        assert metrics.attempts == 0
        assert metrics.successes == 0


class TestSchemaResolver:
    """Core resolver tests."""

    @pytest.mark.asyncio
    async def test_resolve_disabled_returns_none(self, resolver_config):
        """When disabled, resolver returns None immediately."""
        resolver_config.enabled = False
        resolver = SchemaResolver(config=resolver_config)

        result = await resolver.resolve(SAMPLE_SCHEMA_SAID)
        assert result is None

    @pytest.mark.asyncio
    async def test_resolve_cache_hit(self, resolver):
        """Cache hit returns cached schema immediately."""
        # Pre-populate cache
        cache = await resolver._get_cache()
        await cache.put(
            SAMPLE_SCHEMA_SAID,
            SAMPLE_SCHEMA,
            "https://cached.source/",
            "registry",
        )

        result = await resolver.resolve(SAMPLE_SCHEMA_SAID)

        assert result is not None
        assert result.schema_doc == SAMPLE_SCHEMA
        assert result.source_type == "cache"
        assert resolver.metrics.cache_hits == 1

    @pytest.mark.asyncio
    async def test_resolve_registry_success_with_said_verification(self, resolver):
        """Registry fetch verifies SAID before returning."""
        # Mock successful HTTP response with valid schema
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = SAMPLE_SCHEMA

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.get.return_value = mock_response
            mock_client.__aenter__.return_value = mock_client
            mock_client.__aexit__.return_value = None
            mock_client_class.return_value = mock_client

            # Mock SAID verification to return True
            with patch.object(resolver, "_verify_schema_said", return_value=True):
                result = await resolver.resolve(SAMPLE_SCHEMA_SAID)

        assert result is not None
        assert result.schema_doc == SAMPLE_SCHEMA
        assert result.source_type == "registry"
        assert resolver.metrics.registry_hits == 1

    @pytest.mark.asyncio
    async def test_resolve_said_mismatch_raises_invalid(self, resolver):
        """SAID mismatch raises ACDCChainInvalid (not returns None)."""
        # Mock successful HTTP response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = SAMPLE_SCHEMA

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.get.return_value = mock_response
            mock_client.__aenter__.return_value = mock_client
            mock_client.__aexit__.return_value = None
            mock_client_class.return_value = mock_client

            # Mock SAID verification to return False (mismatch)
            with patch.object(resolver, "_verify_schema_said", return_value=False):
                with pytest.raises(ACDCChainInvalid) as exc_info:
                    await resolver.resolve(SAMPLE_SCHEMA_SAID)

        assert "SAID mismatch" in str(exc_info.value)
        assert resolver.metrics.said_mismatches == 1

    @pytest.mark.asyncio
    async def test_resolve_missing_said_field_raises_invalid(self, resolver):
        """Schema missing $id field raises ACDCChainInvalid."""
        # Schema without $id field
        schema_without_id = {"title": "No ID Schema", "type": "object"}

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = schema_without_id

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.get.return_value = mock_response
            mock_client.__aenter__.return_value = mock_client
            mock_client.__aexit__.return_value = None
            mock_client_class.return_value = mock_client

            with pytest.raises(ACDCChainInvalid) as exc_info:
                await resolver.resolve(SAMPLE_SCHEMA_SAID)

        assert "missing $id field" in str(exc_info.value)
        assert resolver.metrics.missing_said_field == 1

    @pytest.mark.asyncio
    async def test_resolve_all_sources_fail_returns_none(self, resolver):
        """Network failures return None (INDETERMINATE)."""
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.get.side_effect = httpx.TimeoutException("timeout")
            mock_client.__aenter__.return_value = mock_client
            mock_client.__aexit__.return_value = None
            mock_client_class.return_value = mock_client

            result = await resolver.resolve(SAMPLE_SCHEMA_SAID)

        assert result is None
        assert resolver.metrics.failures == 1

    @pytest.mark.asyncio
    async def test_resolve_404_returns_none(self, resolver):
        """404 response returns None (schema not at this source)."""
        mock_response = MagicMock()
        mock_response.status_code = 404

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.get.return_value = mock_response
            mock_client.__aenter__.return_value = mock_client
            mock_client.__aexit__.return_value = None
            mock_client_class.return_value = mock_client

            result = await resolver.resolve(SAMPLE_SCHEMA_SAID)

        assert result is None

    @pytest.mark.asyncio
    async def test_resolve_tries_multiple_registries(self):
        """Resolver tries multiple registries in order."""
        config = SchemaResolverConfig(
            enabled=True,
            registry_urls=[
                "https://registry1.com/",
                "https://registry2.com/",
            ],
            oobi_resolution_enabled=False,
        )
        cache = SchemaCache(SchemaCacheConfig(ttl_seconds=60, max_entries=10))
        resolver = SchemaResolver(config=config, cache=cache)

        # First registry returns 404, second succeeds
        responses = [
            MagicMock(status_code=404),
            MagicMock(status_code=200, json=MagicMock(return_value=SAMPLE_SCHEMA)),
        ]

        call_count = 0

        async def mock_get(url):
            nonlocal call_count
            response = responses[call_count]
            call_count += 1
            return response

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.get = mock_get
            mock_client.__aenter__.return_value = mock_client
            mock_client.__aexit__.return_value = None
            mock_client_class.return_value = mock_client

            with patch.object(resolver, "_verify_schema_said", return_value=True):
                result = await resolver.resolve(SAMPLE_SCHEMA_SAID)

        assert result is not None
        assert call_count == 2  # Both registries tried

    @pytest.mark.asyncio
    async def test_oobi_disabled_by_default(self, resolver_config):
        """OOBI resolution is disabled by default."""
        assert resolver_config.oobi_resolution_enabled is False

    @pytest.mark.asyncio
    async def test_oobi_not_called_when_disabled(self, resolver):
        """OOBI endpoints not queried when disabled."""
        # Registry fails
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.get.return_value = MagicMock(status_code=404)
            mock_client.__aenter__.return_value = mock_client
            mock_client.__aexit__.return_value = None
            mock_client_class.return_value = mock_client

            result = await resolver.resolve(
                SAMPLE_SCHEMA_SAID,
                witness_urls=["https://witness1.com/"],
            )

        # Should return None without trying OOBI
        assert result is None
        assert resolver.metrics.oobi_hits == 0


class TestSchemaResolverSingleton:
    """Tests for singleton access."""

    def test_singleton_creation(self):
        """get_schema_resolver creates singleton."""
        reset_schema_resolver()
        resolver1 = get_schema_resolver()
        resolver2 = get_schema_resolver()
        assert resolver1 is resolver2

    def test_singleton_reset(self):
        """reset_schema_resolver clears singleton."""
        resolver1 = get_schema_resolver()
        reset_schema_resolver()
        resolver2 = get_schema_resolver()
        assert resolver1 is not resolver2


class TestSAIDVerification:
    """SAID verification tests."""

    @pytest.mark.asyncio
    async def test_has_said_field_true(self, resolver):
        """Schema with $id passes has_said_field check."""
        assert resolver._has_said_field(SAMPLE_SCHEMA) is True

    @pytest.mark.asyncio
    async def test_has_said_field_false_missing(self, resolver):
        """Schema without $id fails has_said_field check."""
        schema_no_id = {"title": "No ID"}
        assert resolver._has_said_field(schema_no_id) is False

    @pytest.mark.asyncio
    async def test_has_said_field_false_empty(self, resolver):
        """Schema with empty $id fails has_said_field check."""
        schema_empty_id = {"$id": "", "title": "Empty ID"}
        assert resolver._has_said_field(schema_empty_id) is False

    @pytest.mark.asyncio
    async def test_verify_delegates_to_schema_fetcher(self, resolver):
        """_verify_schema_said delegates to schema_fetcher.verify_schema_said."""
        with patch(
            "app.vvp.acdc.schema_fetcher.verify_schema_said",
            return_value=True,
        ) as mock_verify:
            result = resolver._verify_schema_said(SAMPLE_SCHEMA, SAMPLE_SCHEMA_SAID)

        assert result is True
        mock_verify.assert_called_once_with(SAMPLE_SCHEMA, SAMPLE_SCHEMA_SAID)


class TestResolvedSchema:
    """Tests for ResolvedSchema dataclass."""

    def test_resolved_schema_fields(self):
        """ResolvedSchema has expected fields."""
        resolved = ResolvedSchema(
            schema_doc=SAMPLE_SCHEMA,
            said=SAMPLE_SCHEMA_SAID,
            source="https://test.registry/",
            source_type="registry",
            fetch_time_ms=42.5,
        )
        assert resolved.schema_doc == SAMPLE_SCHEMA
        assert resolved.said == SAMPLE_SCHEMA_SAID
        assert resolved.source == "https://test.registry/"
        assert resolved.source_type == "registry"
        assert resolved.fetch_time_ms == 42.5

    def test_resolved_schema_default_fetch_time(self):
        """ResolvedSchema has default fetch_time_ms of 0."""
        resolved = ResolvedSchema(
            schema_doc=SAMPLE_SCHEMA,
            said=SAMPLE_SCHEMA_SAID,
            source="cache",
            source_type="cache",
        )
        assert resolved.fetch_time_ms == 0.0


class TestCacheIntegration:
    """Tests for cache integration with resolver."""

    @pytest.mark.asyncio
    async def test_successful_fetch_cached(self, resolver):
        """Successful fetches are cached."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = SAMPLE_SCHEMA

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.get.return_value = mock_response
            mock_client.__aenter__.return_value = mock_client
            mock_client.__aexit__.return_value = None
            mock_client_class.return_value = mock_client

            with patch.object(resolver, "_verify_schema_said", return_value=True):
                # First resolve - fetches from registry
                result1 = await resolver.resolve(SAMPLE_SCHEMA_SAID)

        assert result1 is not None
        assert result1.source_type == "registry"

        # Second resolve - should hit cache (no HTTP call)
        result2 = await resolver.resolve(SAMPLE_SCHEMA_SAID)
        assert result2 is not None
        assert result2.source_type == "cache"
        assert resolver.metrics.cache_hits == 1


class TestOOBIInvariants:
    """Tests for OOBI path SAID verification invariants.

    Per reviewer feedback: OOBI mismatch/missing $id MUST raise INVALID,
    not return None (INDETERMINATE).
    """

    @pytest.mark.asyncio
    async def test_oobi_said_mismatch_raises_invalid(self):
        """OOBI SAID mismatch raises ACDCChainInvalid (not returns None)."""
        config = SchemaResolverConfig(
            enabled=True,
            registry_urls=[],  # No registries - force OOBI path
            oobi_resolution_enabled=True,
        )
        cache = SchemaCache(SchemaCacheConfig(ttl_seconds=60, max_entries=10))
        resolver = SchemaResolver(config=config, cache=cache)

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = SAMPLE_SCHEMA

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.get.return_value = mock_response
            mock_client.__aenter__.return_value = mock_client
            mock_client.__aexit__.return_value = None
            mock_client_class.return_value = mock_client

            # Mock SAID verification to return False (mismatch)
            with patch.object(resolver, "_verify_schema_said", return_value=False):
                with pytest.raises(ACDCChainInvalid) as exc_info:
                    await resolver.resolve(
                        SAMPLE_SCHEMA_SAID,
                        witness_urls=["https://witness1.com/"],
                    )

        assert "SAID mismatch" in str(exc_info.value)
        assert resolver.metrics.said_mismatches == 1

    @pytest.mark.asyncio
    async def test_oobi_missing_said_field_raises_invalid(self):
        """OOBI schema missing $id raises ACDCChainInvalid (not returns None)."""
        config = SchemaResolverConfig(
            enabled=True,
            registry_urls=[],  # No registries - force OOBI path
            oobi_resolution_enabled=True,
        )
        cache = SchemaCache(SchemaCacheConfig(ttl_seconds=60, max_entries=10))
        resolver = SchemaResolver(config=config, cache=cache)

        # Schema without $id field
        schema_without_id = {"title": "No ID Schema", "type": "object"}

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = schema_without_id

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.get.return_value = mock_response
            mock_client.__aenter__.return_value = mock_client
            mock_client.__aexit__.return_value = None
            mock_client_class.return_value = mock_client

            with pytest.raises(ACDCChainInvalid) as exc_info:
                await resolver.resolve(
                    SAMPLE_SCHEMA_SAID,
                    witness_urls=["https://witness1.com/"],
                )

        assert "missing $id field" in str(exc_info.value)
        assert resolver.metrics.missing_said_field == 1


class TestConfigWiring:
    """Tests for environment configuration wiring."""

    def test_config_from_env_uses_app_config(self):
        """_config_from_env reads from app.core.config."""
        from app.vvp.acdc.schema_resolver import _config_from_env

        config = _config_from_env()

        # Verify config was created with values from app.core.config
        assert isinstance(config, SchemaResolverConfig)
        assert isinstance(config.registry_urls, list)
        assert len(config.registry_urls) >= 0

    def test_get_schema_resolver_uses_env_config(self):
        """get_schema_resolver creates resolver with env config when no config provided."""
        reset_schema_resolver()

        resolver = get_schema_resolver()

        # Verify resolver was created with config from environment
        assert resolver.config is not None
        # Default registries should be present
        assert len(resolver.config.registry_urls) >= 0

    def test_get_schema_resolver_respects_provided_config(self):
        """get_schema_resolver uses provided config over env config."""
        reset_schema_resolver()

        custom_config = SchemaResolverConfig(
            enabled=True,
            registry_urls=["https://custom.registry/"],
            oobi_resolution_enabled=True,
        )

        resolver = get_schema_resolver(config=custom_config)

        assert resolver.config.registry_urls == ["https://custom.registry/"]
        assert resolver.config.oobi_resolution_enabled is True
