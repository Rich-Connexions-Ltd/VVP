"""Dossier API endpoints for VVP Issuer.

Sprint 41: Updated with organization scoping for multi-tenant isolation.
Provides endpoints to build dossiers from credential chains.
"""

import logging

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.api.models import (
    BuildDossierRequest,
    BuildDossierResponse,
    DossierInfoResponse,
    ErrorResponse,
)
from app.auth.api_key import Principal
from app.auth.roles import (
    require_auth,
    check_credential_access_role,
    check_credential_write_role,
)
from app.auth.scoping import can_access_credential, filter_credentials_by_org, validate_dossier_chain_access
from app.db.session import get_db
from app.dossier import DossierBuildError, DossierFormat, get_dossier_builder, serialize_dossier

log = logging.getLogger(__name__)

router = APIRouter(prefix="/dossier", tags=["dossier"])


@router.post(
    "/build",
    responses={
        200: {"description": "Dossier built successfully"},
        400: {"model": ErrorResponse, "description": "Invalid request"},
        403: {"model": ErrorResponse, "description": "Access denied to credential"},
        404: {"model": ErrorResponse, "description": "Credential not found"},
    },
)
async def build_dossier(
    body: BuildDossierRequest,
    principal: Principal = require_auth,
    db: Session = Depends(get_db),
) -> Response:
    """Build a dossier from a credential chain.

    Walks edge references to collect all credentials in the chain,
    then serializes in the requested format.

    **Sprint 41:** Non-admin users can only build dossiers from credentials
    owned by their organization.

    **Authentication:** Requires `issuer:operator+` OR `org:dossier_manager+` role.

    **Formats:**
    - `cesr`: CESR stream with signature attachments (application/cesr)
    - `json`: JSON array of ACDC objects (application/json)

    **Note:** TEL events are only included in CESR format. JSON format
    contains credentials only; the verifier resolves TEL separately.
    """
    # Sprint 41: Check role access (system operator+ OR org dossier_manager+)
    check_credential_write_role(principal)

    # Validate format
    try:
        dossier_format = DossierFormat(body.format.lower())
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid format: {body.format}. Use 'cesr' or 'json'.",
        )

    # Sprint 41: Check access to root credential(s)
    root_saids = body.root_saids if body.root_saids else ([body.root_said] if body.root_said else [])
    for root_said in root_saids:
        if not can_access_credential(db, principal, root_said):
            raise HTTPException(
                status_code=403,
                detail=f"Access denied to credential {root_said[:16]}...",
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

        # Sprint 41: Validate access to FULL chain, not just root credentials
        # This prevents cross-tenant leakage via edge references
        inaccessible = validate_dossier_chain_access(db, principal, content.credential_saids)
        if inaccessible:
            log.warning(
                f"Dossier build blocked: {len(inaccessible)} inaccessible credentials in chain "
                f"for principal {principal.key_id}"
            )
            raise HTTPException(
                status_code=403,
                detail=f"Access denied to {len(inaccessible)} credential(s) in chain: "
                f"{', '.join(said[:16] + '...' for said in inaccessible[:3])}"
                + (f" and {len(inaccessible) - 3} more" if len(inaccessible) > 3 else ""),
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
        403: {"model": ErrorResponse, "description": "Access denied to credential"},
        404: {"model": ErrorResponse, "description": "Credential not found"},
    },
)
async def build_dossier_info(
    body: BuildDossierRequest,
    principal: Principal = require_auth,
    db: Session = Depends(get_db),
) -> BuildDossierResponse:
    """Build a dossier and return metadata (no content).

    Same as `/dossier/build` but returns JSON metadata about the dossier
    instead of the raw content. Useful for previewing what a dossier
    would contain without downloading the full content.

    **Sprint 41:** Non-admin users can only preview dossiers from credentials
    owned by their organization.

    **Authentication:** Requires `issuer:operator+` OR `org:dossier_manager+` role.
    """
    # Sprint 41: Check role access (system operator+ OR org dossier_manager+)
    check_credential_write_role(principal)

    try:
        dossier_format = DossierFormat(body.format.lower())
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid format: {body.format}. Use 'cesr' or 'json'.",
        )

    # Sprint 41: Check access to root credential(s)
    root_saids = body.root_saids if body.root_saids else ([body.root_said] if body.root_said else [])
    for root_said in root_saids:
        if not can_access_credential(db, principal, root_said):
            raise HTTPException(
                status_code=403,
                detail=f"Access denied to credential {root_said[:16]}...",
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

        # Sprint 41: Validate access to FULL chain, not just root credentials
        inaccessible = validate_dossier_chain_access(db, principal, content.credential_saids)
        if inaccessible:
            log.warning(
                f"Dossier info blocked: {len(inaccessible)} inaccessible credentials in chain "
                f"for principal {principal.key_id}"
            )
            raise HTTPException(
                status_code=403,
                detail=f"Access denied to {len(inaccessible)} credential(s) in chain: "
                f"{', '.join(said[:16] + '...' for said in inaccessible[:3])}"
                + (f" and {len(inaccessible) - 3} more" if len(inaccessible) > 3 else ""),
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


async def _optional_principal(request: Request) -> Optional[Principal]:
    """Return authenticated principal if available, None if unauthenticated.

    Sprint 59: Allows dossier GET to work both authenticated (dashboard) and
    unauthenticated (verifier fetching via evd URL).
    """
    try:
        user = request.user
    except (AttributeError, AssertionError):
        return None
    if user is not None and getattr(user, "is_authenticated", False):
        return user
    return None


@router.get(
    "/{said}",
    responses={
        200: {"description": "Dossier content"},
        403: {"model": ErrorResponse, "description": "Access denied to credential"},
        404: {"model": ErrorResponse, "description": "Credential not found"},
    },
)
async def get_dossier(
    said: str,
    format: str = Query("cesr", description="Output format: cesr or json"),
    include_tel: bool = Query(True, description="Include TEL events (CESR only)"),
    principal: Optional[Principal] = Depends(_optional_principal),
    db: Session = Depends(get_db),
) -> Response:
    """Get a dossier by root credential SAID.

    Builds the dossier on-demand from the credential chain.

    **Sprint 59:** Public access for verifier dossier fetching (evd URL).
    Dossiers are content-addressed by SAID and meant to be publicly readable
    per VVP spec §6.1B.  When authenticated, Sprint 41 org-scoping still applies.

    **Authentication:** Optional. If authenticated, requires `issuer:readonly+`
    OR `org:dossier_manager+` role.
    """
    # If authenticated, enforce role and org scoping (Sprint 41)
    if principal is not None:
        check_credential_access_role(principal)

        if not can_access_credential(db, principal, said):
            raise HTTPException(
                status_code=403,
                detail=f"Access denied to credential {said[:16]}...",
            )

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

        # If authenticated, validate chain access (Sprint 41)
        if principal is not None:
            inaccessible = validate_dossier_chain_access(db, principal, content.credential_saids)
            if inaccessible:
                log.warning(
                    f"Dossier get blocked: {len(inaccessible)} inaccessible credentials in chain "
                    f"for principal {principal.key_id}"
                )
                raise HTTPException(
                    status_code=403,
                    detail=f"Access denied to {len(inaccessible)} credential(s) in chain: "
                    f"{', '.join(said[:16] + '...' for said in inaccessible[:3])}"
                    + (f" and {len(inaccessible) - 3} more" if len(inaccessible) > 3 else ""),
                )

        data, content_type = serialize_dossier(content, dossier_format)

        # Return with caching headers per VVP spec
        # Dossiers are immutable and content-addressed by SAID
        return Response(
            content=data,
            media_type=content_type,
            headers={
                "X-Dossier-Root-Said": content.root_said,
                "X-Dossier-Credential-Count": str(len(content.credential_saids)),
                "ETag": f'"{said}"',
                "Cache-Control": "public, max-age=31536000, immutable",
            },
        )

    except DossierBuildError as e:
        log.warning(f"Dossier get failed: {e}")
        status_code = 404 if "not found" in str(e).lower() else 400
        raise HTTPException(status_code=status_code, detail=str(e))
    except Exception as e:
        log.exception(f"Unexpected error getting dossier: {e}")
        raise HTTPException(status_code=500, detail=f"Internal error: {e}")
