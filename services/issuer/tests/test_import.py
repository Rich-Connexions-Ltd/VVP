"""Tests for schema import service."""

import json
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from app.schema.importer import (
    SchemaImporter,
    SchemaImportError,
    get_schema_importer,
    reset_schema_importer,
)
from app.schema.said import SAIDVerificationError


class TestSchemaImporter:
    """Tests for SchemaImporter class."""

    @pytest.fixture
    def importer(self):
        """Create a fresh importer instance."""
        return SchemaImporter(ref="test-branch")

    def test_init_default_ref(self):
        """Importer should use default ref."""
        importer = SchemaImporter()
        assert importer.ref == "main"

    def test_init_custom_ref(self):
        """Importer should accept custom ref."""
        importer = SchemaImporter(ref="v1.0.0")
        assert importer.ref == "v1.0.0"

    def test_base_url(self, importer):
        """Base URL should include ref."""
        assert "test-branch" in importer.base_url

    @pytest.mark.asyncio
    async def test_fetch_registry_success(self, importer):
        """fetch_registry should parse JSON response."""
        mock_registry = {"schemas": [{"id": "E123", "title": "Test"}]}

        # Create a mock response with synchronous json() method
        from unittest.mock import MagicMock
        mock_response = MagicMock()
        mock_response.json.return_value = mock_registry
        mock_response.raise_for_status.return_value = None

        # Create async mock client that returns the sync response
        mock_client = AsyncMock()
        mock_client.get.return_value = mock_response

        with patch.object(importer, "_get_client", return_value=mock_client):
            result = await importer.fetch_registry()

            assert result == mock_registry
            assert importer._registry_cache == mock_registry

    @pytest.mark.asyncio
    async def test_fetch_registry_uses_cache(self, importer):
        """fetch_registry should return cached registry."""
        cached = {"schemas": [{"id": "cached", "title": "Cached"}]}
        importer._registry_cache = cached

        result = await importer.fetch_registry(use_cache=True)

        assert result == cached

    @pytest.mark.asyncio
    async def test_fetch_registry_bypass_cache(self, importer):
        """fetch_registry should bypass cache when requested."""
        from unittest.mock import MagicMock
        cached = {"schemas": [{"id": "cached", "title": "Cached"}]}
        fresh = {"schemas": [{"id": "fresh", "title": "Fresh"}]}
        importer._registry_cache = cached

        mock_response = MagicMock()
        mock_response.json.return_value = fresh
        mock_response.raise_for_status.return_value = None

        mock_client = AsyncMock()
        mock_client.get.return_value = mock_response

        with patch.object(importer, "_get_client", return_value=mock_client):
            result = await importer.fetch_registry(use_cache=False)

            assert result == fresh

    @pytest.mark.asyncio
    async def test_fetch_registry_http_error(self, importer):
        """fetch_registry should raise on HTTP error."""
        mock_request = httpx.Request("GET", "https://example.com")
        mock_response = httpx.Response(404, request=mock_request)

        mock_client = AsyncMock()
        mock_client.get.return_value = mock_response

        with patch.object(importer, "_get_client", return_value=mock_client):
            with pytest.raises(SchemaImportError, match="HTTP 404"):
                await importer.fetch_registry()

    @pytest.mark.asyncio
    async def test_list_available_schemas(self, importer):
        """list_available_schemas should return schema list."""
        registry = {"schemas": [
            {"id": "E1", "title": "Schema 1"},
            {"id": "E2", "title": "Schema 2"},
        ]}
        importer._registry_cache = registry

        result = await importer.list_available_schemas()

        assert len(result) == 2
        assert result[0]["id"] == "E1"

    @pytest.mark.asyncio
    async def test_import_schema_not_found(self, importer):
        """import_schema should raise for unknown schema ID."""
        registry = {"schemas": [{"id": "E1", "title": "Schema 1"}]}
        importer._registry_cache = registry

        with pytest.raises(SchemaImportError, match="not found"):
            await importer.import_schema("E999")

    @pytest.mark.asyncio
    async def test_fetch_schema_by_path_success(self, importer):
        """fetch_schema_by_path should return schema."""
        from unittest.mock import MagicMock
        schema = {
            "$id": "ETestSAIDthatisexactly44characterslong1234",
            "title": "Test Schema",
        }

        mock_response = MagicMock()
        mock_response.json.return_value = schema
        mock_response.raise_for_status.return_value = None

        mock_client = AsyncMock()
        mock_client.get.return_value = mock_response

        with patch.object(importer, "_get_client", return_value=mock_client):
            # Skip SAID verification for this test
            result = await importer.fetch_schema_by_path(
                "test.json",
                verify_said=False
            )

            assert result["$id"] == schema["$id"]
            assert result["title"] == "Test Schema"

    @pytest.mark.asyncio
    async def test_fetch_schema_missing_id(self, importer):
        """fetch_schema_by_path should raise for missing $id."""
        from unittest.mock import MagicMock
        schema = {"title": "No ID Schema"}

        mock_response = MagicMock()
        mock_response.json.return_value = schema
        mock_response.raise_for_status.return_value = None

        mock_client = AsyncMock()
        mock_client.get.return_value = mock_response

        with patch.object(importer, "_get_client", return_value=mock_client):
            with pytest.raises(SchemaImportError, match="missing required"):
                await importer.fetch_schema_by_path("test.json")

    def test_clear_cache(self, importer):
        """clear_cache should reset registry cache."""
        importer._registry_cache = {"schemas": []}
        importer.clear_cache()
        assert importer._registry_cache is None


class TestGlobalImporter:
    """Tests for global importer functions."""

    def test_get_schema_importer_singleton(self):
        """get_schema_importer should return same instance."""
        reset_schema_importer()
        imp1 = get_schema_importer()
        imp2 = get_schema_importer()
        assert imp1 is imp2

    def test_reset_schema_importer(self):
        """reset_schema_importer should clear instance."""
        reset_schema_importer()
        imp1 = get_schema_importer()
        reset_schema_importer()
        imp2 = get_schema_importer()
        assert imp1 is not imp2


class TestSchemaImporterClientLifecycle:
    """Tests for HTTP client lifecycle."""

    @pytest.mark.asyncio
    async def test_close_client(self):
        """close() should close the HTTP client."""
        importer = SchemaImporter()

        # Force client creation
        client = await importer._get_client()
        assert importer._client is not None

        # Close it
        await importer.close()
        assert importer._client is None

    @pytest.mark.asyncio
    async def test_get_client_reuses_instance(self):
        """_get_client should return same instance."""
        importer = SchemaImporter()

        client1 = await importer._get_client()
        client2 = await importer._get_client()

        assert client1 is client2

        await importer.close()


class TestSchemaImporterErrorHandling:
    """Tests for error handling paths."""

    @pytest.mark.asyncio
    async def test_fetch_registry_request_error(self):
        """fetch_registry should handle network errors."""
        importer = SchemaImporter()

        mock_client = AsyncMock()
        mock_client.get.side_effect = httpx.RequestError("Connection failed")

        with patch.object(importer, "_get_client", return_value=mock_client):
            with pytest.raises(SchemaImportError, match="Network error"):
                await importer.fetch_registry()

    @pytest.mark.asyncio
    async def test_fetch_registry_json_decode_error(self):
        """fetch_registry should handle invalid JSON."""
        from unittest.mock import MagicMock
        importer = SchemaImporter()

        mock_response = MagicMock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.side_effect = json.JSONDecodeError("Invalid", "", 0)

        mock_client = AsyncMock()
        mock_client.get.return_value = mock_response

        with patch.object(importer, "_get_client", return_value=mock_client):
            with pytest.raises(SchemaImportError, match="Invalid JSON"):
                await importer.fetch_registry()

    @pytest.mark.asyncio
    async def test_fetch_schema_by_path_request_error(self):
        """fetch_schema_by_path should handle network errors."""
        importer = SchemaImporter()

        mock_client = AsyncMock()
        mock_client.get.side_effect = httpx.RequestError("Connection failed")

        with patch.object(importer, "_get_client", return_value=mock_client):
            with pytest.raises(SchemaImportError, match="Network error"):
                await importer.fetch_schema_by_path("test.json")

    @pytest.mark.asyncio
    async def test_fetch_schema_by_path_json_error(self):
        """fetch_schema_by_path should handle invalid JSON."""
        from unittest.mock import MagicMock
        importer = SchemaImporter()

        mock_response = MagicMock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.side_effect = json.JSONDecodeError("Invalid", "", 0)

        mock_client = AsyncMock()
        mock_client.get.return_value = mock_response

        with patch.object(importer, "_get_client", return_value=mock_client):
            with pytest.raises(SchemaImportError, match="Invalid JSON"):
                await importer.fetch_schema_by_path("test.json")


class TestImportSchemaFilePath:
    """Tests for import_schema file path handling."""

    @pytest.mark.asyncio
    async def test_import_schema_no_file_path(self):
        """import_schema should raise when schema has no file path."""
        importer = SchemaImporter()

        # Registry with schema missing file path
        registry = {"schemas": [{"id": "E123", "title": "No File"}]}
        importer._registry_cache = registry

        with pytest.raises(SchemaImportError, match="no file path"):
            await importer.import_schema("E123")


class TestImportAll:
    """Tests for import_all method."""

    @pytest.mark.asyncio
    async def test_import_all_success(self):
        """import_all should import all schemas from registry."""
        from unittest.mock import MagicMock
        importer = SchemaImporter()

        # Set up registry with two schemas
        registry = {"schemas": [
            {"id": "E1", "title": "Schema 1", "file": "schema1.json"},
            {"id": "E2", "title": "Schema 2", "file": "schema2.json"},
        ]}
        importer._registry_cache = registry

        schema1 = {"$id": "E1", "title": "Schema 1"}
        schema2 = {"$id": "E2", "title": "Schema 2"}

        mock_response1 = MagicMock()
        mock_response1.json.return_value = schema1
        mock_response1.raise_for_status.return_value = None

        mock_response2 = MagicMock()
        mock_response2.json.return_value = schema2
        mock_response2.raise_for_status.return_value = None

        mock_client = AsyncMock()
        mock_client.get.side_effect = [mock_response1, mock_response2]

        with patch.object(importer, "_get_client", return_value=mock_client):
            result = await importer.import_all(verify_said=False)

        assert len(result) == 2

    @pytest.mark.asyncio
    async def test_import_all_partial_failure(self):
        """import_all should continue after individual failures."""
        from unittest.mock import MagicMock
        importer = SchemaImporter()

        # Set up registry with two schemas
        registry = {"schemas": [
            {"id": "E1", "title": "Schema 1", "file": "schema1.json"},
            {"id": "E2", "title": "Schema 2", "file": "schema2.json"},
        ]}
        importer._registry_cache = registry

        schema2 = {"$id": "E2", "title": "Schema 2"}

        # First request fails, second succeeds
        mock_response_fail = MagicMock()
        mock_response_fail.raise_for_status.side_effect = httpx.HTTPStatusError(
            "Not found",
            request=httpx.Request("GET", "https://example.com"),
            response=httpx.Response(404),
        )

        mock_response_ok = MagicMock()
        mock_response_ok.json.return_value = schema2
        mock_response_ok.raise_for_status.return_value = None

        mock_client = AsyncMock()
        mock_client.get.side_effect = [mock_response_fail, mock_response_ok]

        with patch.object(importer, "_get_client", return_value=mock_client):
            result = await importer.import_all(verify_said=False)

        # Should have 1 success despite 1 failure
        assert len(result) == 1
        assert result[0]["$id"] == "E2"


class TestFetchSchemaFromUrl:
    """Tests for fetch_schema_from_url method."""

    @pytest.mark.asyncio
    async def test_fetch_schema_from_url_success(self):
        """fetch_schema_from_url should fetch and return schema."""
        from unittest.mock import MagicMock
        importer = SchemaImporter()

        schema = {"$id": "ETestFromUrl123456789012345678901234567890", "title": "URL Schema"}

        mock_response = MagicMock()
        mock_response.json.return_value = schema
        mock_response.raise_for_status.return_value = None

        mock_client = AsyncMock()
        mock_client.get.return_value = mock_response

        with patch.object(importer, "_get_client", return_value=mock_client):
            result = await importer.fetch_schema_from_url(
                "https://example.com/schema.json",
                verify_said=False
            )

        assert result["$id"] == schema["$id"]

    @pytest.mark.asyncio
    async def test_fetch_schema_from_url_http_error(self):
        """fetch_schema_from_url should handle HTTP errors."""
        importer = SchemaImporter()

        mock_request = httpx.Request("GET", "https://example.com")
        mock_response = httpx.Response(404, request=mock_request)

        mock_client = AsyncMock()
        mock_client.get.return_value = mock_response

        with patch.object(importer, "_get_client", return_value=mock_client):
            with pytest.raises(SchemaImportError, match="HTTP 404"):
                await importer.fetch_schema_from_url("https://example.com/schema.json")

    @pytest.mark.asyncio
    async def test_fetch_schema_from_url_missing_id(self):
        """fetch_schema_from_url should raise for missing $id."""
        from unittest.mock import MagicMock
        importer = SchemaImporter()

        schema = {"title": "No ID"}

        mock_response = MagicMock()
        mock_response.json.return_value = schema
        mock_response.raise_for_status.return_value = None

        mock_client = AsyncMock()
        mock_client.get.return_value = mock_response

        with patch.object(importer, "_get_client", return_value=mock_client):
            with pytest.raises(SchemaImportError, match="missing required"):
                await importer.fetch_schema_from_url("https://example.com/schema.json")

    @pytest.mark.asyncio
    async def test_fetch_schema_from_url_request_error(self):
        """fetch_schema_from_url should handle network errors."""
        importer = SchemaImporter()

        mock_client = AsyncMock()
        mock_client.get.side_effect = httpx.RequestError("Connection failed")

        with patch.object(importer, "_get_client", return_value=mock_client):
            with pytest.raises(SchemaImportError, match="Network error"):
                await importer.fetch_schema_from_url("https://example.com/schema.json")


class TestSchemaImporterIntegration:
    """Integration tests that may hit real endpoints."""

    @pytest.mark.asyncio
    @pytest.mark.skip(reason="Requires network access")
    async def test_fetch_real_registry(self):
        """Fetch real WebOfTrust registry (skipped by default)."""
        importer = SchemaImporter()
        try:
            registry = await importer.fetch_registry()
            assert "schemas" in registry
            assert len(registry["schemas"]) > 0
        finally:
            await importer.close()
