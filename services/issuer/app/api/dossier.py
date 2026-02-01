"""Dossier API endpoints for VVP Issuer.

Provides endpoints to build dossiers from credential chains.
"""

import logging

from fastapi import APIRouter, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse

from app.api.models import (
    BuildDossierRequest,
    BuildDossierResponse,
    DossierInfoResponse,
    ErrorResponse,
)
from app.auth.api_key import Principal
from app.auth.roles import require_operator, require_readonly
from app.dossier import DossierBuildError, DossierFormat, get_dossier_builder, serialize_dossier

log = logging.getLogger(__name__)

router = APIRouter(prefix="/dossier", tags=["dossier"])


@router.post(
    "/build",
    responses={
        200: {"description": "Dossier built successfully"},
        400: {"model": ErrorResponse, "description": "Invalid request"},
        404: {"model": ErrorResponse, "description": "Credential not found"},
    },
)
async def build_dossier(
    body: BuildDossierRequest,
    principal: Principal = require_operator,
) -> Response:
    """Build a dossier from a credential chain.

    Walks edge references to collect all credentials in the chain,
    then serializes in the requested format.

    **Authentication:** Requires `issuer:operator` role or higher.

    **Formats:**
    - `cesr`: CESR stream with signature attachments (application/cesr)
    - `json`: JSON array of ACDC objects (application/json)

    **Note:** TEL events are only included in CESR format. JSON format
    contains credentials only; the verifier resolves TEL separately.
    """
    # Validate format
    try:
        dossier_format = DossierFormat(body.format.lower())
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid format: {body.format}. Use 'cesr' or 'json'.",
        )

    try:
        builder = await get_dossier_builder()

        # Build aggregate or single dossier
        if body.root_saids and len(body.root_saids) > 1:
            content = await builder.build_aggregate(
                root_saids=body.root_saids,
                include_tel=body.include_tel,
            )
        else:
            root_said = body.root_said
            if body.root_saids and len(body.root_saids) == 1:
                root_said = body.root_saids[0]

            content = await builder.build(
                root_said=root_said,
                include_tel=body.include_tel,
            )

        # Serialize to requested format
        data, content_type = serialize_dossier(content, dossier_format)

        log.info(
            f"Built dossier: root={content.root_said[:16]}..., "
            f"format={dossier_format.value}, size={len(data)}"
        )

        return Response(
            content=data,
            media_type=content_type,
            headers={
                "X-Dossier-Root-Said": content.root_said,
                "X-Dossier-Credential-Count": str(len(content.credential_saids)),
                "X-Dossier-Is-Aggregate": str(content.is_aggregate).lower(),
            },
        )

    except DossierBuildError as e:
        log.warning(f"Dossier build failed: {e}")
        status_code = 404 if "not found" in str(e).lower() else 400
        raise HTTPException(status_code=status_code, detail=str(e))
    except Exception as e:
        log.exception(f"Unexpected error building dossier: {e}")
        raise HTTPException(status_code=500, detail=f"Internal error: {e}")


@router.post(
    "/build/info",
    response_model=BuildDossierResponse,
    responses={
        400: {"model": ErrorResponse, "description": "Invalid request"},
        404: {"model": ErrorResponse, "description": "Credential not found"},
    },
)
async def build_dossier_info(
    body: BuildDossierRequest,
    principal: Principal = require_operator,
) -> BuildDossierResponse:
    """Build a dossier and return metadata (no content).

    Same as `/dossier/build` but returns JSON metadata about the dossier
    instead of the raw content. Useful for previewing what a dossier
    would contain without downloading the full content.

    **Authentication:** Requires `issuer:operator` role or higher.
    """
    try:
        dossier_format = DossierFormat(body.format.lower())
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid format: {body.format}. Use 'cesr' or 'json'.",
        )

    try:
        builder = await get_dossier_builder()

        if body.root_saids and len(body.root_saids) > 1:
            content = await builder.build_aggregate(
                root_saids=body.root_saids,
                include_tel=body.include_tel,
            )
        else:
            root_said = body.root_said
            if body.root_saids and len(body.root_saids) == 1:
                root_said = body.root_saids[0]

            content = await builder.build(
                root_said=root_said,
                include_tel=body.include_tel,
            )

        # Serialize to get size
        data, content_type = serialize_dossier(content, dossier_format)

        return BuildDossierResponse(
            dossier=DossierInfoResponse(
                root_said=content.root_said,
                root_saids=content.root_saids,
                credential_count=len(content.credential_saids),
                is_aggregate=content.is_aggregate,
                format=dossier_format.value,
                content_type=content_type,
                size_bytes=len(data),
                warnings=content.warnings,
            )
        )

    except DossierBuildError as e:
        log.warning(f"Dossier build failed: {e}")
        status_code = 404 if "not found" in str(e).lower() else 400
        raise HTTPException(status_code=status_code, detail=str(e))
    except Exception as e:
        log.exception(f"Unexpected error building dossier: {e}")
        raise HTTPException(status_code=500, detail=f"Internal error: {e}")


@router.get(
    "/{said}",
    responses={
        200: {"description": "Dossier content"},
        404: {"model": ErrorResponse, "description": "Credential not found"},
    },
)
async def get_dossier(
    said: str,
    format: str = Query("cesr", description="Output format: cesr or json"),
    include_tel: bool = Query(True, description="Include TEL events (CESR only)"),
    principal: Principal = require_readonly,
) -> Response:
    """Get a dossier by root credential SAID.

    Builds the dossier on-demand from the credential chain.

    **Authentication:** Requires `issuer:readonly` role or higher.
    """
    try:
        dossier_format = DossierFormat(format.lower())
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid format: {format}. Use 'cesr' or 'json'.",
        )

    try:
        builder = await get_dossier_builder()
        content = await builder.build(root_said=said, include_tel=include_tel)
        data, content_type = serialize_dossier(content, dossier_format)

        return Response(
            content=data,
            media_type=content_type,
            headers={
                "X-Dossier-Root-Said": content.root_said,
                "X-Dossier-Credential-Count": str(len(content.credential_saids)),
            },
        )

    except DossierBuildError as e:
        log.warning(f"Dossier get failed: {e}")
        status_code = 404 if "not found" in str(e).lower() else 400
        raise HTTPException(status_code=status_code, detail=str(e))
    except Exception as e:
        log.exception(f"Unexpected error getting dossier: {e}")
        raise HTTPException(status_code=500, detail=f"Internal error: {e}")
