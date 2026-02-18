"""Credential management endpoints.

Sprint 41: Updated with organization scoping for multi-tenant isolation.
Sprint 68b: Migrated from direct app.keri.* imports to KeriAgentClient.
All KERI operations are delegated to the KERI Agent service.
"""
import logging
import time
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from app.api.models import (
    DeleteResponse,
    IssueCredentialRequest,
    IssueCredentialResponse,
    CredentialResponse,
    CredentialDetailResponse,
    CredentialListResponse,
    RevokeCredentialRequest,
    RevokeCredentialResponse,
)
from app.auth.api_key import Principal
from app.auth.roles import (
    require_auth,
    check_credential_access_role,
    check_credential_write_role,
    check_credential_admin_role,
)
from app.auth.scoping import (
    can_access_credential,
    get_org_aid,
    get_org_credentials,
    get_user_organization,
    register_credential,
)
from app.db.models import ManagedCredential, Organization
from app.audit import get_audit_logger
from app.db.session import get_db
from app.keri_client import get_keri_client, KeriAgentUnavailableError
from common.vvp.models.keri_agent import (
    IssueCredentialRequest as AgentIssueCredentialRequest,
)

log = logging.getLogger(__name__)
router = APIRouter(prefix="/credential", tags=["credential"])


def _agent_to_issuer_credential(agent_cred, **extra) -> CredentialResponse:
    """Map agent CredentialResponse DTO to issuer CredentialResponse model."""
    return CredentialResponse(
        said=agent_cred.said,
        issuer_aid=agent_cred.issuer_aid,
        recipient_aid=agent_cred.recipient_aid,
        registry_key=agent_cred.registry_key,
        schema_said=agent_cred.schema_said,
        issuance_dt=agent_cred.issuance_dt,
        status=agent_cred.status,
        revocation_dt=agent_cred.revocation_dt,
        **extra,
    )


def schema_requires_certification_edge(schema_said: str) -> bool:
    """Check if a schema requires a ``certification`` edge.

    Schema-driven detection using the e.oneOf object-variant pattern
    (same as Sprint 65's parse_schema_edges).
    """
    from app.schema.store import get_schema
    from app.vetter.constants import KNOWN_EXTENDED_SCHEMA_SAIDS

    schema_doc = get_schema(schema_said)
    if schema_doc is None:
        if schema_said in KNOWN_EXTENDED_SCHEMA_SAIDS:
            raise RuntimeError(
                f"Schema {schema_said} is a known extended schema but could not "
                f"be loaded. Cannot enforce certification edge requirement."
            )
        return False

    edges_one_of = schema_doc.get("properties", {}).get("e", {}).get("oneOf")
    if not edges_one_of:
        return False
    edges_obj = next((v for v in edges_one_of if v.get("type") == "object"), None)
    if not edges_obj:
        return False
    return "certification" in edges_obj.get("properties", {})


async def _inject_certification_edge(
    schema_said: str,
    edges: Optional[dict],
    org: Optional[Organization],
) -> Optional[dict]:
    """Inject certification edge for extended schemas.

    Returns updated edges dict, or original edges if not an extended schema.
    """
    if not schema_requires_certification_edge(schema_said):
        return edges

    if org is None:
        raise HTTPException(
            status_code=400,
            detail="Extended schemas require organization context. "
                   "Provide organization_id in the request.",
        )

    from app.vetter.service import resolve_active_vetter_cert
    from app.vetter.constants import VETTER_CERT_SCHEMA_SAID

    cert_info = await resolve_active_vetter_cert(org)
    if cert_info is None:
        raise HTTPException(
            status_code=400,
            detail="Organization has no valid active VetterCertification. "
                   "Issue a VetterCertification before using extended schemas.",
        )

    cert_edge = {
        "n": cert_info.said,
        "s": VETTER_CERT_SCHEMA_SAID,
    }

    edges = dict(edges) if edges else {}

    if "certification" in edges:
        caller_edge = edges["certification"]
        if not isinstance(caller_edge, dict) or "n" not in caller_edge:
            raise HTTPException(
                status_code=400,
                detail="Malformed certification edge. Expected dict with 'n' key.",
            )
        if caller_edge.get("n") != cert_info.said:
            raise HTTPException(
                status_code=400,
                detail="Provided certification edge SAID does not match "
                       "org's active VetterCertification.",
            )
        if caller_edge.get("s") != VETTER_CERT_SCHEMA_SAID:
            raise HTTPException(
                status_code=400,
                detail="Provided certification edge schema does not match "
                       f"VetterCertification schema ({VETTER_CERT_SCHEMA_SAID}).",
            )
    else:
        edges["certification"] = cert_edge

    return edges


@router.post("/issue", response_model=IssueCredentialResponse)
async def issue_credential(
    request: IssueCredentialRequest,
    http_request: Request,
    principal: Principal = require_auth,
    db: Session = Depends(get_db),
) -> IssueCredentialResponse:
    """Issue a new ACDC credential.

    Creates a credential via the KERI Agent and registers it with the
    organization.

    **Sprint 41:** If the principal has an organization, the credential is
    registered as managed by that organization. System admins issuing without
    an organization create unmanaged credentials.

    Requires: issuer:operator+ OR org:dossier_manager+ role
    """
    # Sprint 41: Check role access (system operator+ OR org dossier_manager+)
    check_credential_write_role(principal)

    # Sprint 61: Block VetterCertification via generic endpoint
    from app.vetter.constants import VETTER_CERT_SCHEMA_SAID
    if request.schema_said == VETTER_CERT_SCHEMA_SAID:
        raise HTTPException(
            status_code=400,
            detail="VetterCertification credentials must be issued via "
                   "POST /vetter-certifications, not the generic issuance endpoint.",
        )

    # Sprint 61: Resolve org context for edge injection
    resolved_org = None
    resolved_org_id = None
    if request.organization_id:
        # Admin cross-org: explicit org_id in request
        if not principal.is_system_admin:
            if request.organization_id != principal.organization_id:
                raise HTTPException(
                    status_code=403,
                    detail="Only system admins can specify a different organization_id.",
                )
        resolved_org = db.query(Organization).filter(
            Organization.id == request.organization_id
        ).first()
        if resolved_org is None:
            raise HTTPException(
                status_code=404,
                detail=f"Organization not found: {request.organization_id}",
            )
        resolved_org_id = request.organization_id
    elif principal.organization_id:
        resolved_org = db.query(Organization).filter(
            Organization.id == principal.organization_id
        ).first()
        resolved_org_id = principal.organization_id

    # Sprint 67: Org context is MANDATORY for credential issuance
    if resolved_org is None:
        raise HTTPException(
            status_code=403,
            detail="Organization context required for credential issuance. "
                   "Authenticate as an org member or specify organization_id.",
        )

    # Sprint 67: Schema authorization check
    from app.auth.schema_auth import is_schema_authorized
    if not is_schema_authorized(resolved_org.org_type or "regular", request.schema_said):
        raise HTTPException(
            status_code=403,
            detail=f"Organization type '{resolved_org.org_type}' is not authorized "
                   f"to issue schema {request.schema_said}.",
        )

    # Sprint 67: Issuer-binding — fail-closed validation
    # Org MUST have issuer identity (AID) and registry to issue credentials
    if not resolved_org.aid or not resolved_org.registry_key:
        raise HTTPException(
            status_code=403,
            detail=f"Organization '{resolved_org.name}' has incomplete issuer identity "
                   f"(missing AID or registry). Cannot issue credentials.",
        )

    # Sprint 68b: Resolve registry name via KERI Agent if explicit registry_name
    registry_name = request.registry_name
    if registry_name:
        try:
            client = get_keri_client()
            reg_info = await client.get_registry(registry_name)
        except KeriAgentUnavailableError as e:
            raise HTTPException(status_code=503, detail=str(e))
        if not reg_info:
            raise HTTPException(
                status_code=400,
                detail=f"Registry '{registry_name}' not found.",
            )
        # Registry issuer AID must match the org's AID
        if reg_info.identity_aid and reg_info.identity_aid != resolved_org.aid:
            raise HTTPException(
                status_code=403,
                detail=f"Registry '{registry_name}' does not belong to "
                       f"organization '{resolved_org.name}'. Use the org's own registry.",
            )

    # Sprint 61: Inject certification edge for extended schemas
    edges = request.edges
    edges = await _inject_certification_edge(request.schema_said, edges, resolved_org)

    # Sprint 62: Pre-issuance vetter constraint validation
    if schema_requires_certification_edge(request.schema_said) and resolved_org:
        from app.vetter.constraints import validate_issuance_constraints
        from app.config import ENFORCE_VETTER_CONSTRAINTS

        violations = await validate_issuance_constraints(
            schema_said=request.schema_said,
            attributes=request.attributes,
            org=resolved_org,
        )
        failed = [v for v in violations if not v.is_authorized]
        if failed:
            detail = "; ".join(
                f"{v.credential_type} {v.check_type}: {v.reason}" for v in failed
            )
            if ENFORCE_VETTER_CONSTRAINTS:
                raise HTTPException(
                    status_code=403,
                    detail=f"Vetter constraint violation: {detail}",
                )
            else:
                log.warning(f"Vetter constraint warning (soft): {detail}")

    audit = get_audit_logger()
    t_issuer_start = time.perf_counter()

    try:
        client = get_keri_client()

        # Sprint 68b: Resolve identity name from org's AID
        identity = await client.get_identity_by_aid(resolved_org.aid)
        if identity is None:
            raise HTTPException(
                status_code=503,
                detail=f"Could not find identity for org AID {resolved_org.aid}. "
                       "KERI Agent may not have this identity.",
            )

        t_identity_resolved = time.perf_counter()

        # Auto-resolve registry name from identity if not explicitly provided
        effective_registry = registry_name or f"{identity.name}-registry"

        # Issue credential via KERI Agent
        agent_cred = await client.issue_credential(AgentIssueCredentialRequest(
            identity_name=identity.name,
            registry_name=effective_registry,
            schema_said=request.schema_said,
            attributes=request.attributes,
            recipient_aid=request.recipient_aid,
            edges=edges,
            rules=request.rules,
            publish=True,
        ))

        t_agent_returned = time.perf_counter()

        # Sprint 41/61: Register credential with organization
        managed = False
        reg_org_id = resolved_org_id or principal.organization_id
        if reg_org_id:
            register_credential(
                db=db,
                credential_said=agent_cred.said,
                organization_id=reg_org_id,
                schema_said=request.schema_said,
                issuer_aid=agent_cred.issuer_aid,
            )
            managed = True
            log.info(
                f"Credential {agent_cred.said[:16]}... registered to org {reg_org_id[:8]}..."
            )

        t_registered = time.perf_counter()

        # Audit log the issuance
        audit_details = {
            "registry_name": registry_name,
            "schema_said": request.schema_said,
            "recipient_aid": request.recipient_aid,
            "organization_id": reg_org_id or principal.organization_id,
            "managed": managed,
        }
        # Sprint 61: Record cross-org context when admin issues for a different org
        if resolved_org_id and resolved_org_id != principal.organization_id:
            audit_details["caller_organization_id"] = principal.organization_id
            audit_details["target_organization_id"] = resolved_org_id
        audit.log_access(
            action="credential.issue",
            principal_id=principal.key_id,
            resource=agent_cred.said,
            details=audit_details,
            request=http_request,
        )

        t_end = time.perf_counter()
        log.info(
            f"PERF issuer_issue {agent_cred.said[:12]}... "
            f"total={t_end - t_issuer_start:.3f}s "
            f"identity_resolve={t_identity_resolved - t_issuer_start:.3f}s "
            f"keri_agent_call={t_agent_returned - t_identity_resolved:.3f}s "
            f"db_register={t_registered - t_agent_returned:.3f}s"
        )

        return IssueCredentialResponse(
            credential=_agent_to_issuer_credential(agent_cred),
            publish_results=None,  # Agent handles publishing internally
        )

    except KeriAgentUnavailableError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except HTTPException:
        raise
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        log.exception(f"Failed to issue credential: {e}")
        raise HTTPException(status_code=500, detail="Internal error issuing credential")


@router.get("", response_model=CredentialListResponse)
async def list_credentials(
    registry_key: Optional[str] = None,
    status: Optional[str] = None,
    schema_said: Optional[str] = None,
    org_id: Optional[str] = None,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    principal: Principal = require_auth,
    db: Session = Depends(get_db),
) -> CredentialListResponse:
    """List issued credentials with optional filtering and pagination.

    **Sprint 41:** Non-admin users only see credentials owned by their organization.
    System admins can see all credentials.

    **Sprint 63:** Added ``schema_said`` and ``org_id`` query filters.
    ``org_id`` is admin-only and returns credentials visible to the specified org
    (issued by or targeted to that org).

    **Sprint 72:** Added ``limit`` (default 50, max 200) and ``offset`` (default 0)
    for server-side pagination. Response includes ``total`` count alongside the
    paginated ``credentials`` array.

    Requires: issuer:readonly+ OR org:dossier_manager+ role
    """
    # Sprint 41: Check role access (system readonly+ OR org dossier_manager+)
    check_credential_access_role(principal)

    # Sprint 63: Validate org_id parameter
    if org_id is not None:
        if not principal.is_system_admin:
            raise HTTPException(
                status_code=403,
                detail="org_id filter requires admin role",
            )
        # Validate org_id format and existence
        import re
        if not re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', org_id, re.I):
            raise HTTPException(status_code=400, detail="Invalid org_id format")
        target_org = db.query(Organization).filter(Organization.id == org_id).first()
        if not target_org:
            raise HTTPException(status_code=404, detail="Organization not found")

    try:
        client = get_keri_client()

        # Get all credentials from KERI Agent
        all_credentials = await client.list_credentials(
            registry_key=registry_key,
            status=status,
        )

        # Filter by organization and determine relationship
        issued_saids: set[str] = set()
        org_aid: str | None = None

        if org_id and principal.is_system_admin:
            # Sprint 63: Admin filtering by specific org — show that org's universe
            target_org = db.query(Organization).filter(Organization.id == org_id).first()
            target_org_aid = target_org.aid if target_org else None

            # Filter to target org's managed credentials
            target_managed = [
                m for m in db.query(ManagedCredential)
                .filter(ManagedCredential.organization_id == org_id)
                .all()
            ]
            issued_saids = {m.said for m in target_managed}
            org_aid = target_org_aid

            # Dual-visibility: issued by OR targeted to the specified org
            credentials = [
                c for c in all_credentials
                if c.said in issued_saids
                or (org_aid and c.recipient_aid == org_aid)
            ]
        elif principal.is_system_admin and not org_id:
            credentials = all_credentials
        else:
            # Credentials the org ISSUED (via ManagedCredential)
            org_managed = get_org_credentials(db, principal)
            issued_saids = {m.said for m in org_managed}

            # Org's AID for subject matching
            org_aid = get_org_aid(db, principal)

            # Include issued OR subject credentials
            credentials = [
                c for c in all_credentials
                if c.said in issued_saids
                or (org_aid and c.recipient_aid == org_aid)
            ]

        # Sprint 63: Apply schema_said filter
        if schema_said:
            credentials = [c for c in credentials if c.schema_said == schema_said]

        # Batch AID-to-org-name lookup
        aids_to_resolve = set()
        for c in credentials:
            aids_to_resolve.add(c.issuer_aid)
            if c.recipient_aid:
                aids_to_resolve.add(c.recipient_aid)
        aid_to_name: dict[str, str] = {}
        if aids_to_resolve:
            try:
                orgs = db.query(Organization.aid, Organization.name).filter(
                    Organization.aid.in_(aids_to_resolve)
                ).all()
                aid_to_name = {o.aid: o.name for o in orgs if o.aid}
            except Exception:
                pass  # Organizations table may not exist in test environments

        # Build response with relationship tagging and org names
        # Sprint 63: When org_id is provided, tag from perspective of that org
        perspective_org_id = org_id if org_id else principal.organization_id
        perspective_issued_saids = issued_saids
        perspective_org_aid = org_aid

        result = []
        for c in credentials:
            relationship = None
            if perspective_org_id:
                if c.said in perspective_issued_saids:
                    relationship = "issued"
                elif perspective_org_aid and c.recipient_aid == perspective_org_aid:
                    relationship = "subject"

            result.append(_agent_to_issuer_credential(
                c,
                relationship=relationship,
                issuer_name=aid_to_name.get(c.issuer_aid),
                recipient_name=aid_to_name.get(c.recipient_aid) if c.recipient_aid else None,
            ))

        # Sprint 72: Server-side pagination (in-memory slicing).
        # Credentials are fetched from the KERI Agent HTTP API, not a SQL database,
        # so DB-level LIMIT/OFFSET is not applicable. In-memory pagination is the
        # correct approach here. For scale beyond ~10k credentials, push pagination
        # into the KERI Agent API itself.
        total = len(result)
        paginated = result[offset:offset + limit]

        return CredentialListResponse(
            credentials=paginated,
            count=len(paginated),
            total=total,
            limit=limit,
            offset=offset,
        )
    except KeriAgentUnavailableError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        log.exception(f"Failed to list credentials: {e}")
        raise HTTPException(status_code=500, detail="Internal error listing credentials")


@router.get("/{said}", response_model=CredentialDetailResponse)
async def get_credential(
    said: str,
    principal: Principal = require_auth,
    db: Session = Depends(get_db),
) -> CredentialDetailResponse:
    """Get credential details by SAID.

    **Sprint 41:** Non-admin users can only access credentials owned by their organization.

    Requires: issuer:readonly+ OR org:dossier_manager+ role
    """
    # Sprint 41: Check role access (system readonly+ OR org dossier_manager+)
    check_credential_access_role(principal)

    try:
        client = get_keri_client()
        agent_cred = await client.get_credential(said)

        if agent_cred is None:
            raise HTTPException(status_code=404, detail=f"Credential not found: {said}")

        # Sprint 41: Check organization access (issued or subject)
        if not can_access_credential(db, principal, said, recipient_aid=agent_cred.recipient_aid):
            raise HTTPException(
                status_code=403,
                detail="Access denied to this credential",
            )

        return CredentialDetailResponse(
            said=agent_cred.said,
            issuer_aid=agent_cred.issuer_aid,
            recipient_aid=agent_cred.recipient_aid,
            registry_key=agent_cred.registry_key,
            schema_said=agent_cred.schema_said,
            issuance_dt=agent_cred.issuance_dt,
            status=agent_cred.status,
            revocation_dt=agent_cred.revocation_dt,
            attributes=agent_cred.attributes,
            edges=agent_cred.edges,
            rules=agent_cred.rules,
        )
    except KeriAgentUnavailableError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        log.exception(f"Failed to get credential {said}: {e}")
        raise HTTPException(status_code=500, detail="Internal error getting credential")


@router.post("/{said}/revoke", response_model=RevokeCredentialResponse)
async def revoke_credential(
    said: str,
    request: RevokeCredentialRequest,
    http_request: Request,
    principal: Principal = require_auth,
    db: Session = Depends(get_db),
) -> RevokeCredentialResponse:
    """Revoke an issued credential.

    The KERI Agent handles TEL revocation event creation and witness publishing.

    **Sprint 41:** Non-admin users can only revoke credentials owned by their organization.

    Requires: issuer:admin OR org:administrator role
    """
    # Sprint 41: Check role access (system admin OR org administrator)
    check_credential_admin_role(principal)

    audit = get_audit_logger()

    # Sprint 41: Check organization access
    if not can_access_credential(db, principal, said):
        raise HTTPException(
            status_code=403,
            detail="Access denied to this credential",
        )

    try:
        client = get_keri_client()
        agent_cred = await client.revoke_credential(said)

        # Audit log the revocation
        audit.log_access(
            action="credential.revoke",
            principal_id=principal.key_id,
            resource=said,
            details={"reason": request.reason},
            request=http_request,
        )

        return RevokeCredentialResponse(
            credential=_agent_to_issuer_credential(agent_cred),
            publish_results=None,  # Agent handles publishing internally
        )

    except KeriAgentUnavailableError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except HTTPException:
        raise
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        log.exception(f"Failed to revoke credential {said}: {e}")
        raise HTTPException(status_code=500, detail="Internal error revoking credential")


@router.delete("/{said}", response_model=DeleteResponse)
async def delete_credential(
    said: str,
    http_request: Request,
    principal: Principal = require_auth,
    db: Session = Depends(get_db),
) -> DeleteResponse:
    """Delete a credential from local storage.

    Note: This only removes the credential from local storage. The credential
    and its TEL events still exist in the KERI ecosystem and cannot be
    truly deleted from the global state.

    **Sprint 41:** Non-admin users can only delete credentials owned by their organization.

    Requires: issuer:admin OR org:administrator role
    """
    # Sprint 41: Check role access (system admin OR org administrator)
    check_credential_admin_role(principal)

    audit = get_audit_logger()

    try:
        client = get_keri_client()

        # Verify credential exists before deletion
        agent_cred = await client.get_credential(said)
        if agent_cred is None:
            raise HTTPException(status_code=404, detail=f"Credential not found: {said}")

        # Sprint 41: Check organization access
        if not can_access_credential(db, principal, said):
            raise HTTPException(
                status_code=403,
                detail="Access denied to this credential",
            )

        # Delete via KERI Agent (also deletes seed in Sprint 73)
        await client.delete_credential(said)

        # Sprint 73: Clean up issuer metadata
        from app.db.models import ManagedCredential
        db.query(ManagedCredential).filter(ManagedCredential.said == said).delete()
        db.commit()

        # Audit log the deletion
        audit.log_access(
            action="credential.delete",
            principal_id=principal.key_id,
            resource=said,
            details={},
            request=http_request,
        )

        return DeleteResponse(
            deleted=True,
            resource_type="credential",
            resource_id=said,
            message="Credential removed from local storage and metadata. Note: The credential still exists in the KERI ecosystem.",
        )

    except KeriAgentUnavailableError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except HTTPException:
        raise
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        log.exception(f"Failed to delete credential {said}: {e}")
        raise HTTPException(status_code=500, detail="Internal error deleting credential")
