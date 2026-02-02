"""Tests for schema endpoints."""
import pytest
from httpx import AsyncClient


# Known schema SAIDs from the embedded schema files
KNOWN_EMBEDDED_SAID = "ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY"  # Legal Entity vLEI

# Known schema SAIDs from governance registry
KNOWN_LE_SAID = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao"
KNOWN_DE_SAID = "EL7irIKYJL9Io0hhKSGWI4OznhwC7qgJG5Qf4aEs6j0o"


@pytest.mark.asyncio
async def test_list_schemas(client: AsyncClient):
    """Test listing all available schemas."""
    response = await client.get("/schema")
    assert response.status_code == 200
    data = response.json()

    assert "schemas" in data
    assert "count" in data
    assert data["count"] >= 1

    # Each schema should have at least said and title
    for schema in data["schemas"]:
        assert "said" in schema
        assert "title" in schema


@pytest.mark.asyncio
async def test_get_schema_by_said(client: AsyncClient):
    """Test getting a specific schema by SAID."""
    response = await client.get(f"/schema/{KNOWN_EMBEDDED_SAID}")
    assert response.status_code == 200
    data = response.json()

    assert data["said"] == KNOWN_EMBEDDED_SAID
    assert "title" in data
    assert data["title"] == "Legal Entity vLEI Credential"
    # Full schema document should be included
    assert "schema_document" in data
    assert data["schema_document"] is not None
    assert data["schema_document"]["$id"] == KNOWN_EMBEDDED_SAID


@pytest.mark.asyncio
async def test_schema_not_found(client: AsyncClient):
    """Test 404 for unknown schema SAID."""
    response = await client.get("/schema/Eunknown123456789012345678901234567890123")
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_validate_schema_known_le(client: AsyncClient):
    """Test validating a known LE schema SAID."""
    response = await client.post(
        "/schema/validate",
        json={
            "said": KNOWN_LE_SAID,
            "credential_type": "LE",
        },
    )
    assert response.status_code == 200
    data = response.json()

    assert data["said"] == KNOWN_LE_SAID
    assert data["valid"] is True
    assert data["credential_type"] == "LE"


@pytest.mark.asyncio
async def test_validate_schema_known_de(client: AsyncClient):
    """Test validating a known DE schema SAID."""
    response = await client.post(
        "/schema/validate",
        json={
            "said": KNOWN_DE_SAID,
            "credential_type": "DE",
        },
    )
    assert response.status_code == 200
    data = response.json()

    assert data["said"] == KNOWN_DE_SAID
    assert data["valid"] is True


@pytest.mark.asyncio
async def test_validate_schema_unknown(client: AsyncClient):
    """Test validating an unknown schema SAID."""
    response = await client.post(
        "/schema/validate",
        json={
            "said": "Eunknown123456789012345678901234567890123",
            "credential_type": "LE",
        },
    )
    assert response.status_code == 200
    data = response.json()

    # Unknown SAID for LE type should return invalid
    assert data["valid"] is False


@pytest.mark.asyncio
async def test_validate_schema_no_credential_type(client: AsyncClient):
    """Test validating a schema SAID without credential type."""
    response = await client.post(
        "/schema/validate",
        json={
            "said": KNOWN_LE_SAID,
        },
    )
    assert response.status_code == 200
    data = response.json()

    assert data["said"] == KNOWN_LE_SAID
    assert data["valid"] is True
    assert data["credential_type"] is None


@pytest.mark.asyncio
async def test_validate_schema_pending_governance(client: AsyncClient):
    """Test validating schema for type with pending governance.

    APE and TNAlloc have no known schemas, so any SAID should be valid.
    """
    response = await client.post(
        "/schema/validate",
        json={
            "said": "EanySchemaForPendingType123456789012345678",
            "credential_type": "APE",
        },
    )
    assert response.status_code == 200
    data = response.json()

    # APE has no known schemas, so any is valid
    assert data["valid"] is True


@pytest.mark.asyncio
async def test_list_schemas_contains_known(client: AsyncClient):
    """Test that list includes our known embedded schemas."""
    response = await client.get("/schema")
    assert response.status_code == 200
    data = response.json()

    saids = [s["said"] for s in data["schemas"]]
    assert KNOWN_EMBEDDED_SAID in saids


@pytest.mark.asyncio
async def test_schema_has_description(client: AsyncClient):
    """Test that schema response includes description."""
    response = await client.get(f"/schema/{KNOWN_EMBEDDED_SAID}")
    assert response.status_code == 200
    data = response.json()

    assert "description" in data
    # Legal Entity vLEI Credential has a description
    assert data["description"] is not None
    assert len(data["description"]) > 0


@pytest.mark.asyncio
async def test_verify_embedded_schema_said(client: AsyncClient):
    """Test verifying SAID of an embedded schema."""
    response = await client.get(f"/schema/{KNOWN_EMBEDDED_SAID}/verify")
    assert response.status_code == 200
    data = response.json()

    assert data["said"] == KNOWN_EMBEDDED_SAID
    assert data["valid"] is True
    assert data["computed_said"] is None  # None when valid


class TestSchemaStoreMetadata:
    """Tests for schema store metadata handling."""

    def test_get_schema_strips_metadata(self):
        """get_schema should strip _source metadata by default."""
        from app.schema.store import (
            add_schema,
            get_schema,
            remove_schema,
            reload_all_schemas,
        )
        from app.schema.said import inject_said

        # Force reload to clear cache
        reload_all_schemas()

        # Create a test schema with SAID
        template = {
            "$id": "",
            "$schema": "http://json-schema.org/draft-07/schema#",
            "title": "Test Metadata Schema",
            "type": "object",
        }
        schema = inject_said(template)
        said = schema["$id"]

        try:
            # Add it (this injects _source metadata)
            add_schema(schema, source="test")

            # Get it back - should NOT have _source
            retrieved = get_schema(said)
            assert retrieved is not None
            assert "_source" not in retrieved
            assert retrieved["$id"] == said

            # Get with metadata - SHOULD have _source
            retrieved_with_meta = get_schema(said, include_metadata=True)
            assert retrieved_with_meta is not None
            assert "_source" in retrieved_with_meta
            assert retrieved_with_meta["_source"] == "test"
        finally:
            # Clean up
            remove_schema(said)
            reload_all_schemas()

    def test_user_schema_verifies_correctly(self):
        """User schemas should verify correctly after stripping metadata."""
        from app.schema.store import (
            add_schema,
            get_schema,
            remove_schema,
            reload_all_schemas,
        )
        from app.schema.said import inject_said, verify_schema_said

        # Force reload to clear cache
        reload_all_schemas()

        # Create a test schema with SAID
        template = {
            "$id": "",
            "$schema": "http://json-schema.org/draft-07/schema#",
            "title": "Test Verify Schema",
            "type": "object",
        }
        schema = inject_said(template)
        said = schema["$id"]

        try:
            # Add it as imported (this injects _source metadata)
            add_schema(schema, source="imported")

            # Get the schema (metadata stripped)
            retrieved = get_schema(said)
            assert retrieved is not None

            # Verify the SAID - should work because _source is stripped
            assert verify_schema_said(retrieved) is True
        finally:
            # Clean up
            remove_schema(said)
            reload_all_schemas()


# =============================================================================
# Schema Create Tests
# =============================================================================


@pytest.mark.asyncio
async def test_create_schema_success(client: AsyncClient):
    """Test creating a custom schema with auto-generated SAID."""
    from app.schema.store import remove_schema, reload_all_schemas

    response = await client.post(
        "/schema/create",
        json={
            "title": "Test Custom Schema",
            "description": "A test schema for coverage",
            "credential_type": "TestCred",
            "properties": {
                "testField": {"type": "string", "description": "A test field"},
            },
        },
    )
    assert response.status_code == 200
    data = response.json()

    assert "said" in data
    assert data["said"].startswith("E")
    assert data["title"] == "Test Custom Schema"
    assert "schema_document" in data
    assert data["schema_document"]["$id"] == data["said"]

    # Clean up
    try:
        remove_schema(data["said"])
        reload_all_schemas()
    except Exception:
        pass


@pytest.mark.asyncio
async def test_create_schema_minimal(client: AsyncClient):
    """Test creating a schema with minimal fields."""
    from app.schema.store import remove_schema, reload_all_schemas

    response = await client.post(
        "/schema/create",
        json={
            "title": "Minimal Schema",
            "credential_type": "MinCred",
            "properties": {},
        },
    )
    assert response.status_code == 200
    data = response.json()

    assert data["title"] == "Minimal Schema"

    # Clean up
    try:
        remove_schema(data["said"])
        reload_all_schemas()
    except Exception:
        pass


# =============================================================================
# Schema Delete Tests
# =============================================================================


@pytest.mark.asyncio
async def test_delete_schema_custom_success(client: AsyncClient):
    """Test deleting a custom (user-created) schema."""
    from app.schema.store import reload_all_schemas

    # First create a schema
    create_response = await client.post(
        "/schema/create",
        json={
            "title": "Schema To Delete",
            "credential_type": "DeleteTest",
            "properties": {},
        },
    )
    assert create_response.status_code == 200
    said = create_response.json()["said"]

    # Delete it
    delete_response = await client.delete(f"/schema/{said}")
    assert delete_response.status_code == 200
    data = delete_response.json()

    assert data["deleted"] == said

    # Verify it's gone
    get_response = await client.get(f"/schema/{said}")
    assert get_response.status_code == 404

    reload_all_schemas()


@pytest.mark.asyncio
async def test_delete_schema_not_found(client: AsyncClient):
    """Test 404 when deleting non-existent schema."""
    response = await client.delete("/schema/Enonexistent12345678901234567890123456789012")
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_delete_embedded_schema_rejected(client: AsyncClient):
    """Test that embedded schemas cannot be deleted."""
    # Try to delete a known embedded schema
    response = await client.delete(f"/schema/{KNOWN_EMBEDDED_SAID}")
    assert response.status_code == 400
    assert "embedded" in response.json()["detail"].lower()


# =============================================================================
# Schema Import Tests (mocked)
# =============================================================================


@pytest.mark.asyncio
async def test_import_schema_weboftrust_missing_id(client: AsyncClient):
    """Test import fails without schema_id for weboftrust source."""
    response = await client.post(
        "/schema/import",
        json={
            "source": "weboftrust",
            # Missing schema_id
        },
    )
    assert response.status_code == 400
    assert "schema_id required" in response.json()["detail"]


@pytest.mark.asyncio
async def test_import_schema_url_missing_url(client: AsyncClient):
    """Test import fails without url for URL source."""
    response = await client.post(
        "/schema/import",
        json={
            "source": "url",
            # Missing url
        },
    )
    assert response.status_code == 400
    assert "url required" in response.json()["detail"]


@pytest.mark.asyncio
async def test_import_schema_unknown_source(client: AsyncClient):
    """Test import fails with unknown source."""
    response = await client.post(
        "/schema/import",
        json={
            "source": "unknown",
        },
    )
    assert response.status_code == 400
    assert "unknown import source" in response.json()["detail"].lower()


# =============================================================================
# WebOfTrust Registry Tests (mocked)
# =============================================================================


@pytest.mark.asyncio
async def test_list_weboftrust_schemas_error(client: AsyncClient, monkeypatch):
    """Test weboftrust registry endpoint handles errors."""
    from unittest.mock import AsyncMock, patch
    from app.schema import importer
    from app.api import schema as schema_api

    mock_importer = AsyncMock()
    mock_importer.list_available_schemas.side_effect = importer.SchemaImportError("Network error")
    mock_importer.ref = "main"

    # Patch at the API module level where it's used
    with patch.object(schema_api, "get_schema_importer", return_value=mock_importer):
        response = await client.get("/schema/weboftrust/registry")

    assert response.status_code == 502
    assert "failed to fetch" in response.json()["detail"].lower()
