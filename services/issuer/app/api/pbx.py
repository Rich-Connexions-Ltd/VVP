"""PBX Management API endpoints.

Sprint 71: Configure PBX extensions, API key, and deploy dialplan.
"""

import json
import logging
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response
from sqlalchemy.orm import Session

from app.api.models import (
    PBXConfigResponse,
    PBXExtension,
    UpdatePBXConfigRequest,
    PBXDeployRequest,
    PBXDeployResponse,
)
from app.auth.api_key import Principal
from app.auth.roles import require_admin
from app.audit import get_audit_logger
from app.db.session import get_db
from app.db.models import Organization, OrgAPIKey, PBXConfig

log = logging.getLogger(__name__)
router = APIRouter(prefix="/pbx", tags=["pbx"])


def _get_or_create_config(db: Session) -> PBXConfig:
    """Get the singleton PBX config, creating it with defaults if absent."""
    config = db.query(PBXConfig).filter(PBXConfig.id == 1).first()
    if not config:
        config = PBXConfig(id=1)
        db.add(config)
        db.flush()
    return config


def _config_to_response(config: PBXConfig, db: Session) -> PBXConfigResponse:
    """Convert PBXConfig model to API response."""
    org_name = None
    key_name = None

    if config.api_key_org_id:
        org = db.query(Organization).filter(
            Organization.id == config.api_key_org_id
        ).first()
        if org:
            org_name = org.name

    if config.api_key_id:
        key = db.query(OrgAPIKey).filter(
            OrgAPIKey.id == config.api_key_id
        ).first()
        if key:
            key_name = key.name

    # Parse extensions JSON
    try:
        ext_list = json.loads(config.extensions_json or "[]")
        extensions = [PBXExtension(**e) for e in ext_list]
    except (json.JSONDecodeError, TypeError, ValueError):
        extensions = []

    return PBXConfigResponse(
        api_key_org_id=config.api_key_org_id,
        api_key_org_name=org_name,
        api_key_id=config.api_key_id,
        api_key_name=key_name,
        api_key_preview=config.api_key_value[:8] if config.api_key_value else None,
        extensions=extensions,
        default_caller_id=config.default_caller_id or "+441923311000",
        last_deployed_at=config.last_deployed_at.isoformat() if config.last_deployed_at else None,
        last_deployed_by=config.last_deployed_by,
    )


@router.get("/config", response_model=PBXConfigResponse)
async def get_pbx_config(
    db: Session = Depends(get_db),
    principal: Principal = require_admin,
) -> PBXConfigResponse:
    """Get current PBX configuration.

    Returns the singleton PBX config including API key reference,
    extension definitions, and last deployment info.

    Requires: issuer:admin role
    """
    config = _get_or_create_config(db)
    db.commit()
    return _config_to_response(config, db)


@router.put("/config", response_model=PBXConfigResponse)
async def update_pbx_config(
    body: UpdatePBXConfigRequest,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = require_admin,
) -> PBXConfigResponse:
    """Update PBX configuration.

    Updates the API key, extensions, and/or default caller ID.
    All fields are optional — only provided fields are updated.

    Requires: issuer:admin role
    """
    config = _get_or_create_config(db)
    audit = get_audit_logger()
    changes = []

    if body.api_key_org_id is not None:
        # Validate org exists
        org = db.query(Organization).filter(
            Organization.id == body.api_key_org_id
        ).first()
        if not org:
            raise HTTPException(status_code=404, detail="Organization not found")
        config.api_key_org_id = body.api_key_org_id
        changes.append("api_key_org_id")

    if body.api_key_id is not None:
        # Validate key exists and is not revoked
        key = db.query(OrgAPIKey).filter(
            OrgAPIKey.id == body.api_key_id,
            OrgAPIKey.revoked == False,
        ).first()
        if not key:
            raise HTTPException(status_code=404, detail="API key not found or revoked")
        config.api_key_id = body.api_key_id
        changes.append("api_key_id")

    if body.api_key_value is not None:
        config.api_key_value = body.api_key_value
        changes.append("api_key_value")

    if body.extensions is not None:
        config.extensions_json = json.dumps(
            [e.model_dump() for e in body.extensions]
        )
        changes.append(f"extensions ({len(body.extensions)} configured)")

    if body.default_caller_id is not None:
        config.default_caller_id = body.default_caller_id
        changes.append("default_caller_id")

    db.commit()

    audit.log(
        action="pbx.config.update",
        principal=principal.key_id,
        resource_type="pbx_config",
        resource_id="singleton",
        details={"changes": changes},
    )
    log.info(f"PBX config updated by {principal.key_id}: {', '.join(changes)}")

    return _config_to_response(config, db)


@router.post("/deploy", response_model=PBXDeployResponse)
async def deploy_pbx(
    body: PBXDeployRequest,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = require_admin,
) -> PBXDeployResponse:
    """Deploy dialplan to PBX VM.

    Generates FreeSWITCH dialplan XML from current configuration and
    deploys it to the PBX VM via Azure SDK. If dry_run=true, returns
    the generated XML without deploying.

    Requires: issuer:admin role
    """
    from app.pbx.dialplan import generate_dialplan

    config = _get_or_create_config(db)

    dialplan_xml = generate_dialplan(
        api_key_value=config.api_key_value,
        extensions_json=config.extensions_json or "[]",
        default_caller_id=config.default_caller_id or "+441923311000",
    )

    if body.dry_run:
        return PBXDeployResponse(
            success=True,
            dialplan_xml=dialplan_xml,
            dialplan_size_bytes=len(dialplan_xml.encode()),
            message="Dry run — XML generated but not deployed",
        )

    # Deploy to PBX
    from app.pbx.deploy import deploy_dialplan_to_pbx

    success, output = deploy_dialplan_to_pbx(dialplan_xml)

    if success:
        config.last_deployed_at = datetime.utcnow()
        config.last_deployed_by = principal.key_id
        db.commit()

        audit = get_audit_logger()
        audit.log(
            action="pbx.deploy",
            principal=principal.key_id,
            resource_type="pbx_dialplan",
            resource_id="vvp-pbx",
            details={
                "size_bytes": len(dialplan_xml.encode()),
                "output": output[:500],
            },
        )

    return PBXDeployResponse(
        success=success,
        dialplan_size_bytes=len(dialplan_xml.encode()),
        message=output,
        deployed_at=datetime.utcnow().isoformat() if success else None,
    )


@router.get("/dialplan-preview")
async def preview_dialplan(
    db: Session = Depends(get_db),
    principal: Principal = require_admin,
) -> Response:
    """Preview generated dialplan XML.

    Returns the complete FreeSWITCH dialplan XML that would be deployed,
    based on current configuration.

    Requires: issuer:admin role
    """
    from app.pbx.dialplan import generate_dialplan

    config = _get_or_create_config(db)
    db.commit()

    dialplan_xml = generate_dialplan(
        api_key_value=config.api_key_value,
        extensions_json=config.extensions_json or "[]",
        default_caller_id=config.default_caller_id or "+441923311000",
    )

    return Response(content=dialplan_xml, media_type="application/xml")
