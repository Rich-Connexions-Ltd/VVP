"""Schema management endpoints."""
import logging
from typing import Any

from fastapi import APIRouter, HTTPException, Request

from app.api.models import (
    SchemaResponse,
    SchemaListResponse,
    SchemaValidationRequest,
    SchemaValidationResponse,
    SchemaImportRequest,
    SchemaImportResponse,
    SchemaCreateRequest,
    SchemaCreateResponse,
    SchemaVerifyResponse,
    WebOfTrustRegistryResponse,
)
from app.auth.api_key import Principal
from app.auth.roles import require_readonly, require_admin
from app.audit import get_audit_logger
from common.vvp.schema.registry import (
    is_known_schema,
    KNOWN_SCHEMA_SAIDS,
)

log = logging.getLogger(__name__)
router = APIRouter(prefix="/schema", tags=["schema"])


# Import schema store and SAID functions
from app.schema.store import (
    get_schema as store_get_schema,
    get_schema_source,
    has_schema,
    list_all_schemas,
    add_schema,
    remove_schema,
    SCHEMA_SOURCE_EMBEDDED,
    SCHEMA_SOURCE_IMPORTED,
    SCHEMA_SOURCE_CUSTOM,
)
from app.schema.said import (
    compute_schema_said,
    inject_said,
    verify_schema_said,
    create_schema_template,
    SAIDComputationError,
    SAIDVerificationError,
)
from app.schema.importer import (
    get_schema_importer,
    SchemaImportError,
)


@router.get("", response_model=SchemaListResponse)
async def list_schemas() -> SchemaListResponse:
    """List all available schemas.

    Returns schemas from both embedded and user-added stores.

    This endpoint is public (no auth required) for UI access.
    """
    all_schemas = list_all_schemas()

    schemas = [
        SchemaResponse(
            said=s["said"],
            title=s["title"],
            description=s.get("description"),
            source=s["source"],
            schema_document=None,
        )
        for s in all_schemas
    ]

    return SchemaListResponse(
        schemas=schemas,
        count=len(schemas),
    )


@router.get("/weboftrust/registry", response_model=WebOfTrustRegistryResponse)
async def list_weboftrust_schemas() -> WebOfTrustRegistryResponse:
    """List schemas available in WebOfTrust registry.

    Fetches the registry.json from WebOfTrust/schema repository.

    This endpoint is public (no auth required) for UI access.
    """
    importer = get_schema_importer()
    try:
        available = await importer.list_available_schemas()
        return WebOfTrustRegistryResponse(
            schemas=available,
            count=len(available),
            ref=importer.ref,
        )
    except SchemaImportError as e:
        raise HTTPException(status_code=502, detail=f"Failed to fetch registry: {e}")


@router.get("/{said}", response_model=SchemaResponse)
async def get_schema(said: str) -> SchemaResponse:
    """Get a schema by SAID.

    Args:
        said: The schema's self-addressing identifier ($id field)

    Returns:
        Schema with full document if found

    This endpoint is public (no auth required) for UI access.
    """
    schema_doc = store_get_schema(said)

    if schema_doc is None:
        raise HTTPException(status_code=404, detail=f"Schema not found: {said}")

    source = get_schema_source(said)

    return SchemaResponse(
        said=said,
        title=schema_doc.get("title", "Untitled"),
        description=schema_doc.get("description"),
        source=source,
        schema_document=schema_doc,
    )


@router.get("/{said}/verify", response_model=SchemaVerifyResponse)
async def verify_schema(said: str) -> SchemaVerifyResponse:
    """Verify a schema's SAID is correct.

    Computes the SAID from the schema content and compares
    with the stored $id value.

    Args:
        said: The schema's stored SAID

    Returns:
        Verification result

    This endpoint is public (no auth required) for UI access.
    """
    schema_doc = store_get_schema(said)

    if schema_doc is None:
        raise HTTPException(status_code=404, detail=f"Schema not found: {said}")

    try:
        is_valid = verify_schema_said(schema_doc)
        computed = None if is_valid else compute_schema_said(schema_doc)
        return SchemaVerifyResponse(
            said=said,
            valid=is_valid,
            computed_said=computed,
        )
    except (SAIDComputationError, SAIDVerificationError) as e:
        raise HTTPException(status_code=500, detail=f"Verification failed: {e}")


@router.post("/validate", response_model=SchemaValidationResponse)
async def validate_schema(
    request: SchemaValidationRequest,
    principal: Principal = require_readonly,
) -> SchemaValidationResponse:
    """Validate a schema SAID is recognized for issuance.

    Checks if the SAID is in the known schema registry. If a credential_type
    is specified, validates against that specific type's known schemas.

    Args:
        request: Schema validation request with SAID and optional credential type

    Returns:
        Validation result indicating if the schema is recognized

    Requires: issuer:readonly role
    """
    if request.credential_type:
        # Check against specific credential type
        valid = is_known_schema(request.credential_type, request.said)
    else:
        # Check if SAID exists in any type
        valid = any(
            request.said in saids
            for saids in KNOWN_SCHEMA_SAIDS.values()
            if saids  # Skip empty frozensets
        )
        # Also check all stored schemas
        if not valid:
            valid = has_schema(request.said)

    return SchemaValidationResponse(
        said=request.said,
        valid=valid,
        credential_type=request.credential_type,
    )


@router.post("/import", response_model=SchemaImportResponse)
async def import_schema(
    request: SchemaImportRequest,
    http_request: Request,
    principal: Principal = require_admin,
) -> SchemaImportResponse:
    """Import a schema from WebOfTrust repository or URL.

    Fetches the schema, verifies the SAID (optional), and stores it.

    Args:
        request: Import request specifying source and identifier

    Returns:
        Import result with schema SAID

    Requires: issuer:admin role
    """
    audit = get_audit_logger()
    importer = get_schema_importer()

    try:
        if request.source == "weboftrust":
            if not request.schema_id:
                raise HTTPException(
                    status_code=400,
                    detail="schema_id required for weboftrust import"
                )
            schema = await importer.import_schema(
                request.schema_id,
                verify_said=request.verify_said
            )
        elif request.source == "url":
            if not request.url:
                raise HTTPException(
                    status_code=400,
                    detail="url required for URL import"
                )
            schema = await importer.fetch_schema_from_url(
                request.url,
                verify_said=request.verify_said
            )
        else:
            raise HTTPException(
                status_code=400,
                detail=f"Unknown import source: {request.source}"
            )

        # Store the schema
        said = add_schema(schema, source=SCHEMA_SOURCE_IMPORTED)

        audit.log_access(
            action="schema.import",
            principal_id=principal.key_id,
            resource=said,
            details={"source": request.source},
            request=http_request,
        )

        return SchemaImportResponse(
            said=said,
            title=schema.get("title", "Untitled"),
            source=request.source,
            verified=request.verify_said,
        )

    except SchemaImportError as e:
        raise HTTPException(status_code=502, detail=f"Import failed: {e}")
    except SAIDVerificationError as e:
        raise HTTPException(status_code=400, detail=f"SAID verification failed: {e}")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/create", response_model=SchemaCreateResponse)
async def create_schema(
    request: SchemaCreateRequest,
    http_request: Request,
    principal: Principal = require_admin,
) -> SchemaCreateResponse:
    """Create a new schema with auto-generated SAID.

    Creates a JSON Schema template and computes the SAID.

    Args:
        request: Schema creation request

    Returns:
        Created schema with SAID

    Requires: issuer:admin role
    """
    audit = get_audit_logger()

    try:
        # Create schema template
        template = create_schema_template(
            title=request.title,
            description=request.description or "",
            credential_type=request.credential_type,
            properties=request.properties,
        )

        # Inject SAID
        schema = inject_said(template)
        said = schema["$id"]

        # Store the schema
        add_schema(schema, source=SCHEMA_SOURCE_CUSTOM)

        audit.log_access(
            action="schema.create",
            principal_id=principal.key_id,
            resource=said,
            details={"title": request.title},
            request=http_request,
        )

        return SchemaCreateResponse(
            said=said,
            title=request.title,
            schema_document=schema,
        )

    except SAIDComputationError as e:
        raise HTTPException(status_code=500, detail=f"SAID computation failed: {e}")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.delete("/{said}")
async def delete_schema(
    said: str,
    http_request: Request,
    principal: Principal = require_admin,
) -> dict:
    """Delete a user-added schema.

    Only user-added (imported or custom) schemas can be deleted.
    Embedded schemas cannot be removed.

    Args:
        said: The schema's SAID

    Returns:
        Deletion confirmation

    Requires: issuer:admin role
    """
    audit = get_audit_logger()

    source = get_schema_source(said)

    if source is None:
        raise HTTPException(status_code=404, detail=f"Schema not found: {said}")

    if source == SCHEMA_SOURCE_EMBEDDED:
        raise HTTPException(
            status_code=400,
            detail="Cannot delete embedded schema"
        )

    try:
        removed = remove_schema(said)
        if not removed:
            raise HTTPException(status_code=404, detail=f"Schema not found: {said}")

        audit.log_access(
            action="schema.delete",
            principal_id=principal.key_id,
            resource=said,
            request=http_request,
        )

        return {"deleted": said, "source": source}

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
