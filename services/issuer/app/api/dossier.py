"""Dossier API endpoints for VVP Issuer.

Sprint 41: Updated with organization scoping for multi-tenant isolation.
Sprint 63: Added dossier ACDC creation and OSP association endpoints.
"""

import logging

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from sqlalchemy.orm import Session

from app.api.models import (
    AssociatedDossierEntry,
    AssociatedDossierListResponse,
    BuildDossierRequest,
    BuildDossierResponse,
    CreateDossierRequest,
    CreateDossierResponse,
    DossierInfoResponse,
    DossierReadinessResponse,
    DossierSlotStatus,
    ErrorResponse,
)
from app.auth.api_key import Principal
from app.auth.roles import (
    require_auth,
    check_credential_access_role,
    check_credential_write_role,
)
from app.auth.scoping import can_access_credential, validate_dossier_chain_access
from app.audit import get_audit_logger
from app.config import VVP_ISSUER_BASE_URL
from app.db.models import DossierOspAssociation, ManagedCredential, Organization
from app.db.session import get_db
from app.dossier import DossierBuildError, DossierFormat, get_dossier_builder, serialize_dossier
from app.keri_client import get_keri_client, KeriAgentUnavailableError

log = logging.getLogger(__name__)

router = APIRouter(prefix="/dossier", tags=["dossier"])

# =============================================================================
# Sprint 63: Dossier Schema & Edge Constants
# =============================================================================

DOSSIER_SCHEMA_SAID = "EH1jN4U4LMYHmPVI4FYdZ10bIPR7YWKp8TDdZ9Y9Al-P"
GCD_SCHEMA_SAID = "EL7irIKYJL9Io0hhKSGWI4OznhwC7qgJG5Qf4aEs6j0o"
TNALLOC_SCHEMA_SAID = "EFvnoHDY7I-kaBBeKlbDbkjG4BaI0nKLGadxBdjMGgSQ"

DOSSIER_EDGE_DEFS = {
    "vetting": {"required": True, "schema": None, "operator": "NI2I", "i2i": False, "access": "ap_org"},
    "alloc": {"required": True, "schema": GCD_SCHEMA_SAID, "operator": "I2I", "i2i": True, "access": "ap_org"},
    "tnalloc": {"required": True, "schema": TNALLOC_SCHEMA_SAID, "operator": "I2I", "i2i": True, "access": "ap_org"},
    "delsig": {"required": True, "schema": GCD_SCHEMA_SAID, "operator": "NI2I", "i2i": False, "access": "ap_org"},
    "bownr": {"required": False, "schema": None, "operator": "NI2I", "i2i": False, "access": "ap_org"},
    "bproxy": {"required": False, "schema": None, "operator": None, "i2i": False, "access": "principal"},
}


# Human-readable labels for dossier edge slots
DOSSIER_EDGE_LABELS = {
    "vetting": "Vetting Credential",
    "alloc": "Service Provider Allocation",
    "tnalloc": "TN Allocation",
    "delsig": "Delegated Signer",
    "bownr": "Brand Ownership",
    "bproxy": "Brand Proxy",
}


# =============================================================================
# Sprint 65: Shared Edge Validation Helpers
# =============================================================================


def _check_edge_schema(cred_schema_said: str, edge_def: dict) -> bool:
    """Check if credential matches edge schema constraint."""
    if edge_def.get("schema") and cred_schema_said != edge_def["schema"]:
        return False
    return True


def _check_edge_i2i(cred_recipient_aid: str | None, org_aid: str | None, edge_def: dict) -> bool:
    """Check I2I: credential recipient_aid must match org AID."""
    if edge_def.get("i2i"):
        if not org_aid or cred_recipient_aid != org_aid:
            return False
    return True


def _check_edge_status(cred_status: str) -> bool:
    """Check credential is not revoked."""
    return cred_status != "revoked"


def _check_delsig_semantics(cred_issuer_aid: str, cred_recipient_aid: str | None, org_aid: str | None) -> bool:
    """Check delsig-specific rules: issuer must be AP, recipient (OP) must exist."""
    if not org_aid or cred_issuer_aid != org_aid:
        return False
    if not cred_recipient_aid:
        return False
    return True


# =============================================================================
# Sprint 63: Edge Validation Helper
# =============================================================================


async def _validate_dossier_edges(
    db: Session,
    principal: Principal,
    owner_org: Organization,
    edge_selections: dict[str, str],
) -> tuple[dict, str | None]:
    """Validate edge credentials and build the ACDC edges dict.

    Returns:
        (edges_dict, delsig_issuee_aid) — edges dict for issue_credential(),
        and the delsig issuee AID (OP) for bproxy enforcement.

    Raises:
        HTTPException: If validation fails.
    """
    edges = {"d": ""}
    delsig_issuee_aid: str | None = None

    # Fast-fail: check required edges and unknown names before KERI initialization
    for edge_name, edge_def in DOSSIER_EDGE_DEFS.items():
        if edge_def["required"] and edge_name not in edge_selections:
            raise HTTPException(
                status_code=400,
                detail=f"Required edge '{edge_name}' not provided",
            )
    for edge_name in edge_selections:
        if edge_name not in DOSSIER_EDGE_DEFS:
            raise HTTPException(
                status_code=400,
                detail=f"Unknown edge '{edge_name}'",
            )

    # Initialize KERI Agent client after all fast validation passes
    client = get_keri_client()

    # Validate each provided edge credential
    for edge_name, cred_said in edge_selections.items():
        edge_def = DOSSIER_EDGE_DEFS[edge_name]  # safe — unknown names rejected above

        # Get credential info
        cred_info = await client.get_credential(cred_said)
        if cred_info is None:
            raise HTTPException(
                status_code=404,
                detail=f"Credential {cred_said} not found",
            )

        # Check status (shared helper)
        if not _check_edge_status(cred_info.status):
            raise HTTPException(
                status_code=400,
                detail=f"Credential {cred_said} for edge '{edge_name}' is revoked",
            )

        # Access enforcement (per-edge policy)
        if edge_def["access"] == "ap_org":
            # Must be issued by or targeted to the AP org
            managed = db.query(ManagedCredential).filter(
                ManagedCredential.said == cred_said
            ).first()
            is_issued_by_org = managed and managed.organization_id == owner_org.id
            is_subject_of_org = owner_org.aid and cred_info.recipient_aid == owner_org.aid
            if not is_issued_by_org and not is_subject_of_org:
                raise HTTPException(
                    status_code=403,
                    detail=f"Access denied to credential {cred_said} for organization {owner_org.name}",
                )
        elif edge_def["access"] == "principal":
            # Must be accessible to the requesting principal
            if not can_access_credential(db, principal, cred_said, recipient_aid=cred_info.recipient_aid):
                raise HTTPException(
                    status_code=403,
                    detail=f"Access denied to credential {cred_said}",
                )

        # Schema constraint check (shared helper)
        if not _check_edge_schema(cred_info.schema_said, edge_def):
            raise HTTPException(
                status_code=400,
                detail=f"Edge '{edge_name}' requires schema {edge_def['schema']}, got {cred_info.schema_said}",
            )

        # I2I check (shared helper)
        if not _check_edge_i2i(cred_info.recipient_aid, owner_org.aid, edge_def):
            raise HTTPException(
                status_code=400,
                detail=f"I2I edge '{edge_name}': credential issuee does not match org AID",
            )

        # delsig-specific checks (shared helper)
        if edge_name == "delsig":
            if not _check_delsig_semantics(cred_info.issuer_aid, cred_info.recipient_aid, owner_org.aid):
                if not owner_org.aid or cred_info.issuer_aid != owner_org.aid:
                    raise HTTPException(
                        status_code=400,
                        detail="delsig credential issuer must be the Accountable Party",
                    )
                raise HTTPException(
                    status_code=400,
                    detail="delsig credential must have a recipient (OP AID) — §5.1 step 9",
                )
            delsig_issuee_aid = cred_info.recipient_aid

        # Build edge entry
        edge_entry: dict = {"n": cred_said, "s": cred_info.schema_said}
        if edge_def["operator"]:
            edge_entry["o"] = edge_def["operator"]
        edges[edge_name] = edge_entry

    # bproxy enforcement (§6.3.4): required when bownr present AND OP ≠ AP
    # delsig_issuee_aid is guaranteed non-None (validated above), so check is unconditional
    if "bownr" in edge_selections and delsig_issuee_aid:
        if delsig_issuee_aid != owner_org.aid and "bproxy" not in edge_selections:
            raise HTTPException(
                status_code=400,
                detail="bproxy is required when brand ownership (bownr) is present and OP differs from AP (§6.3.4)",
            )

    return edges, delsig_issuee_aid


# =============================================================================
# Sprint 63: Dossier Creation Endpoint
# =============================================================================


@router.post(
    "/create",
    response_model=CreateDossierResponse,
    responses={
        400: {"model": ErrorResponse, "description": "Validation error"},
        403: {"model": ErrorResponse, "description": "Access denied"},
        404: {"model": ErrorResponse, "description": "Organization or credential not found"},
    },
)
async def create_dossier(
    body: CreateDossierRequest,
    http_request: Request,
    principal: Principal = require_auth,
    db: Session = Depends(get_db),
) -> CreateDossierResponse:
    """Create a new dossier ACDC with edge validation and optional OSP association.

    Sprint 63: Guided dossier creation with schema-driven edge slots. Issues a
    dossier ACDC (CVD, no issuee) with validated edges, registers it as managed,
    and optionally associates it with an OSP organization.

    **Authentication:** Requires ``issuer:operator+`` OR ``org:dossier_manager+`` role.
    """
    check_credential_write_role(principal)
    audit = get_audit_logger()

    # Step 1: Resolve owner org
    owner_org = db.query(Organization).filter(Organization.id == body.owner_org_id).first()
    if not owner_org:
        raise HTTPException(status_code=404, detail="Organization not found")
    if not owner_org.enabled:
        raise HTTPException(status_code=400, detail="Organization is disabled")
    if not owner_org.aid:
        raise HTTPException(status_code=400, detail="Organization has no AID")
    if not owner_org.registry_key:
        raise HTTPException(status_code=400, detail="Organization has no credential registry")

    # Step 2: Cross-org access policy (admin-only)
    if not principal.is_system_admin:
        if principal.organization_id != body.owner_org_id:
            raise HTTPException(
                status_code=403,
                detail="Access denied: can only create dossiers for your own organization",
            )

    # Step 3: Validate edges
    try:
        edges, delsig_issuee_aid = await _validate_dossier_edges(
            db, principal, owner_org, body.edges
        )
    except KeriAgentUnavailableError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except HTTPException:
        raise

    # Sprint 62: Dossier-creation-time vetter constraint validation
    from app.vetter.constraints import validate_dossier_constraints
    from app.config import ENFORCE_VETTER_CONSTRAINTS

    all_cred_saids = list(body.edges.values())
    constraint_violations = await validate_dossier_constraints(
        credential_saids=all_cred_saids,
    )
    failed_constraints = [v for v in constraint_violations if not v.is_authorized]
    if failed_constraints:
        detail = "; ".join(
            f"{v.credential_type} {v.check_type}: {v.reason}" for v in failed_constraints
        )
        if ENFORCE_VETTER_CONSTRAINTS:
            raise HTTPException(
                status_code=403,
                detail=f"Dossier constraint violation: {detail}",
            )
        else:
            log.warning(f"Dossier constraint warning (soft): {detail}")

    # Step 4: Validate OSP org (BEFORE issuance — all 4xx errors must be side-effect free)
    osp_org_id_result: str | None = None
    if body.osp_org_id:
        osp_org = db.query(Organization).filter(Organization.id == body.osp_org_id).first()
        if not osp_org:
            raise HTTPException(status_code=404, detail="OSP organization not found")
        if not osp_org.enabled:
            raise HTTPException(status_code=400, detail="OSP organization is disabled")
        if not osp_org.aid:
            raise HTTPException(
                status_code=400,
                detail="OSP organization has no AID — cannot verify delegation target",
            )
        if delsig_issuee_aid and delsig_issuee_aid != osp_org.aid:
            raise HTTPException(
                status_code=400,
                detail="delsig issuee AID does not match OSP organization AID",
            )
        osp_org_id_result = body.osp_org_id

    # Step 5: Build attributes
    from datetime import datetime, timezone
    attributes = {"d": "", "dt": datetime.now(timezone.utc).isoformat()}
    if body.name:
        attributes["name"] = body.name

    # Step 6: Resolve registry and identity names from stored keys
    try:
        client = get_keri_client()
        registry_info = await client.get_registry_by_key(owner_org.registry_key)
        if not registry_info:
            log.error(f"Could not resolve registry for key {owner_org.registry_key[:16]}...")
            raise HTTPException(
                status_code=500,
                detail="Could not resolve credential registry for organization",
            )
        registry_name = registry_info.name

        # Resolve identity name from org AID (agent uses names, not AIDs)
        identity_info = await client.get_identity_by_aid(owner_org.aid)
        if not identity_info:
            log.error(f"Could not resolve identity for AID {owner_org.aid[:16]}...")
            raise HTTPException(
                status_code=500,
                detail="Could not resolve KERI identity for organization",
            )
    except KeriAgentUnavailableError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except HTTPException:
        raise

    # Step 7: Issue the dossier ACDC (after all validation — no orphaned credentials)
    from common.vvp.models.keri_agent import IssueCredentialRequest
    try:
        cred_info = await client.issue_credential(IssueCredentialRequest(
            identity_name=identity_info.name,
            registry_name=registry_name,
            schema_said=DOSSIER_SCHEMA_SAID,
            attributes=attributes,
            recipient_aid=None,  # CVD, no issuee
            edges=edges,
        ))
    except KeriAgentUnavailableError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        log.exception(f"Failed to issue dossier ACDC: {e}")
        raise HTTPException(status_code=500, detail="Failed to issue dossier credential")

    dossier_said = cred_info.said

    # Step 8: Stage SQL writes (no commit yet)
    managed_cred = ManagedCredential(
        said=dossier_said,
        organization_id=owner_org.id,
        schema_said=DOSSIER_SCHEMA_SAID,
        issuer_aid=cred_info.issuer_aid,
    )
    db.add(managed_cred)

    if body.osp_org_id:
        assoc = DossierOspAssociation(
            dossier_said=dossier_said,
            owner_org_id=owner_org.id,
            osp_org_id=body.osp_org_id,
        )
        db.add(assoc)

    # Step 9: Witness publishing handled by KERI Agent internally

    # Step 10: Commit SQL (atomic: ManagedCredential + optional DossierOspAssociation)
    try:
        db.commit()
    except Exception as e:
        db.rollback()
        log.error(f"SQL commit failed for dossier {dossier_said}: {e}. Orphaned KERI credential.")
        raise HTTPException(status_code=500, detail="Failed to register dossier")

    # Step 11: Audit logging
    audit.log_access(
        action="dossier.create",
        principal_id=principal.key_id,
        resource=dossier_said,
        details={
            "owner_org_id": body.owner_org_id,
            "osp_org_id": osp_org_id_result,
            "edge_count": len(body.edges),
            "name": body.name,
        },
        request=http_request,
    )
    if osp_org_id_result:
        audit.log_access(
            action="dossier.osp_associate",
            principal_id=principal.key_id,
            resource=dossier_said,
            details={"osp_org_id": osp_org_id_result},
            request=http_request,
        )

    # Build dossier URL
    base_url = VVP_ISSUER_BASE_URL.rstrip("/") if VVP_ISSUER_BASE_URL else ""
    dossier_url = f"{base_url}/api/dossier/{dossier_said}"

    log.info(
        f"Created dossier {dossier_said[:16]}... for org {owner_org.name} "
        f"(edges: {len(body.edges)}, osp: {osp_org_id_result or 'none'})"
    )

    return CreateDossierResponse(
        dossier_said=dossier_said,
        issuer_aid=cred_info.issuer_aid,
        schema_said=DOSSIER_SCHEMA_SAID,
        edge_count=len(body.edges),
        name=body.name,
        osp_org_id=osp_org_id_result,
        dossier_url=dossier_url,
        publish_results=None,  # Agent handles witness publishing internally
    )


# =============================================================================
# Sprint 63: Associated Dossiers Endpoint
# =============================================================================


@router.get("/associated", response_model=AssociatedDossierListResponse)
async def list_associated_dossiers(
    org_id: Optional[str] = Query(None, description="Filter by OSP org ID (admin only)"),
    principal: Principal = require_auth,
    db: Session = Depends(get_db),
) -> AssociatedDossierListResponse:
    """List dossier-OSP associations visible to the current principal.

    Sprint 63: OSP orgs can discover dossiers associated with them.

    - **System admins:** See all associations. Optional ``org_id`` filter.
    - **Org-scoped principals:** See associations where their org is the OSP.
    - **Principals without org:** Empty list.

    **Authentication:** Requires ``issuer:readonly+`` OR ``org:dossier_manager+`` role.
    """
    check_credential_access_role(principal)

    query = db.query(DossierOspAssociation)

    if principal.is_system_admin:
        if org_id:
            query = query.filter(DossierOspAssociation.osp_org_id == org_id)
    elif principal.organization_id:
        query = query.filter(
            DossierOspAssociation.osp_org_id == principal.organization_id
        )
    else:
        return AssociatedDossierListResponse(associations=[], count=0)

    associations = query.order_by(DossierOspAssociation.created_at.desc()).all()

    # Batch org name lookups
    org_ids_to_resolve = set()
    for a in associations:
        org_ids_to_resolve.add(a.owner_org_id)
        org_ids_to_resolve.add(a.osp_org_id)

    org_name_map: dict[str, str] = {}
    if org_ids_to_resolve:
        orgs = db.query(Organization.id, Organization.name).filter(
            Organization.id.in_(org_ids_to_resolve)
        ).all()
        org_name_map = {o.id: o.name for o in orgs}

    entries = [
        AssociatedDossierEntry(
            dossier_said=a.dossier_said,
            owner_org_id=a.owner_org_id,
            owner_org_name=org_name_map.get(a.owner_org_id),
            osp_org_id=a.osp_org_id,
            osp_org_name=org_name_map.get(a.osp_org_id),
            created_at=a.created_at.isoformat(),
        )
        for a in associations
    ]

    return AssociatedDossierListResponse(
        associations=entries,
        count=len(entries),
    )


# =============================================================================
# Sprint 65: Dossier Readiness Endpoint
# =============================================================================


@router.get(
    "/readiness",
    response_model=DossierReadinessResponse,
    responses={
        400: {"model": ErrorResponse, "description": "Organization disabled, no AID, or no registry"},
        403: {"model": ErrorResponse, "description": "Access denied"},
        404: {"model": ErrorResponse, "description": "Organization not found"},
    },
)
async def dossier_readiness(
    org_id: str = Query(..., description="Organization ID to check readiness for"),
    principal: Principal = require_auth,
    db: Session = Depends(get_db),
) -> DossierReadinessResponse:
    """Check dossier creation readiness for an organization.

    Sprint 65: Evaluates each dossier edge slot against the same validation
    constraints that POST /dossier/create would enforce. Returns per-slot
    status and overall readiness flag.

    **Authentication:** Requires ``issuer:readonly+`` OR ``org:dossier_manager+`` role.
    Non-admin users can only check their own organization.
    """
    check_credential_access_role(principal)

    # Access control: non-admin can only check own org
    if not principal.is_system_admin:
        if principal.organization_id != org_id:
            raise HTTPException(
                status_code=403,
                detail="Access denied: can only check readiness for your own organization",
            )

    # Resolve org (mirror /dossier/create preconditions)
    org = db.query(Organization).filter(Organization.id == org_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    if not org.enabled:
        raise HTTPException(status_code=400, detail="Organization is disabled")
    if not org.aid:
        raise HTTPException(status_code=400, detail="Organization has no AID")
    if not org.registry_key:
        raise HTTPException(status_code=400, detail="Organization has no credential registry")

    # Get all credentials visible to this org from KERI
    try:
        client = get_keri_client()
        all_credentials = await client.list_credentials()
    except KeriAgentUnavailableError as e:
        raise HTTPException(status_code=503, detail=str(e))

    # Build org credential universe: issued by org OR targeted to org
    managed = db.query(ManagedCredential).filter(
        ManagedCredential.organization_id == org_id
    ).all()
    issued_saids = {m.said for m in managed}

    org_credentials = [
        c for c in all_credentials
        if c.said in issued_saids or (org.aid and c.recipient_aid == org.aid)
    ]

    # For bproxy (principal-scoped): all credentials the principal can access
    principal_credentials = all_credentials if principal.is_system_admin else [
        c for c in all_credentials
        if can_access_credential(db, principal, c.said, recipient_aid=c.recipient_aid)
    ]

    # Evaluate each edge slot
    slots: list[DossierSlotStatus] = []

    for edge_name, edge_def in DOSSIER_EDGE_DEFS.items():
        # Select credential pool based on access policy
        if edge_def["access"] == "principal":
            pool = principal_credentials
        else:
            pool = org_credentials

        # Schema filter + exclude revoked (total_count: non-revoked schema matches)
        if edge_def["schema"]:
            schema_pool = [c for c in pool if c.schema_said == edge_def["schema"] and _check_edge_status(c.status)]
        else:
            schema_pool = [c for c in pool if _check_edge_status(c.status)]
        total_count = len(schema_pool)

        # Full validation (available_count: passes all checks)
        valid_candidates = []
        for cred in schema_pool:
            if not _check_edge_schema(cred.schema_said, edge_def):
                continue
            if not _check_edge_i2i(cred.recipient_aid, org.aid, edge_def):
                continue
            if edge_name == "delsig":
                if not _check_delsig_semantics(cred.issuer_aid, cred.recipient_aid, org.aid):
                    continue
            valid_candidates.append(cred)

        available_count = len(valid_candidates)

        # Determine status
        if available_count > 0:
            if not edge_def["required"] and edge_def["schema"] is None:
                # Unconstrained optional edge — candidates exist but suitability
                # can't be automatically assessed (any credential matches)
                status = "optional_unconstrained"
            else:
                status = "ready"
        elif total_count > 0:
            # Candidates exist but fail validation — invalid regardless of required/optional
            status = "invalid"
        elif not edge_def["required"]:
            status = "optional_missing"
        else:
            status = "missing"

        slots.append(DossierSlotStatus(
            edge=edge_name,
            label=DOSSIER_EDGE_LABELS.get(edge_name, edge_name),
            required=edge_def["required"],
            schema_constraint=edge_def.get("schema"),
            available_count=available_count,
            total_count=total_count,
            status=status,
        ))

    # Compute overall readiness
    blocking_reason: str | None = None
    ready = True

    # Check required slots
    for slot in slots:
        if slot.required and slot.status != "ready":
            ready = False
            blocking_reason = f"Required edge '{slot.edge}' is not satisfied"
            break

    # Note: bproxy conditional gate (§6.3.4) is NOT applied at readiness level.
    # bownr/bproxy are unconstrained optional edges (schema=None), so readiness
    # cannot reliably detect actual brand ownership/proxy credentials.
    # The actual enforcement happens at POST /dossier/create when the user
    # selects specific edges.

    return DossierReadinessResponse(
        org_id=org_id,
        org_name=org.name,
        ready=ready,
        slots=slots,
        blocking_reason=blocking_reason,
    )


# =============================================================================
# Existing Endpoints (Sprint 41)
# =============================================================================


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
    except KeriAgentUnavailableError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except HTTPException:
        raise
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
    except KeriAgentUnavailableError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except HTTPException:
        raise
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
    except KeriAgentUnavailableError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        log.exception(f"Unexpected error getting dossier: {e}")
        raise HTTPException(status_code=500, detail=f"Internal error: {e}")
