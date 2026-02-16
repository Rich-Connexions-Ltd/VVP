"""Vetter certification business logic.

Sprint 61: Issue, revoke, and query VetterCertification credentials.
Central resolve_active_vetter_cert() helper prevents semantic drift.

Sprint 68c: Migrated from direct app.keri.* access to KeriAgentClient.
"""

import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.db.models import ManagedCredential, Organization
from app.keri_client import get_keri_client
from app.vetter.constants import VETTER_CERT_SCHEMA_SAID

log = logging.getLogger(__name__)


class CredentialInfo:
    """Minimal credential info returned by resolve_active_vetter_cert."""

    def __init__(self, said: str, attributes: dict, issuer_aid: str, status: str):
        self.said = said
        self.attributes = attributes
        self.issuer_aid = issuer_aid
        self.status = status


async def resolve_active_vetter_cert(
    org: Organization,
) -> Optional[CredentialInfo]:
    """Resolve and validate the org's active VetterCertification.

    Performs full validation:
    1. org.vetter_certification_said is not None
    2. Credential exists in KERI store (via agent)
    3. Credential schema matches VETTER_CERT_SCHEMA_SAID
    4. Credential status is "issued" (not revoked)
    5. Credential issuer is mock GSMA
    6. Credential issuee AID matches org.aid
    7. If certificationExpiry is present, not expired

    Returns:
        CredentialInfo if valid, None otherwise.
    """
    if not org.vetter_certification_said:
        return None

    client = get_keri_client()
    said = org.vetter_certification_said

    # Look up credential via KERI Agent
    cred = await client.get_credential(said)
    if cred is None:
        log.warning(f"Stale pointer: credential {said[:16]}... not found in KERI store")
        return None

    # Check schema
    if cred.schema_said != VETTER_CERT_SCHEMA_SAID:
        log.warning(
            f"Stale pointer: credential {said[:16]}... has wrong schema "
            f"({cred.schema_said}, expected {VETTER_CERT_SCHEMA_SAID})"
        )
        return None

    # Check status (not revoked)
    if cred.status == "revoked":
        log.warning(f"Stale pointer: credential {said[:16]}... is revoked")
        return None

    # Check issuer (should be mock GSMA) — fail-closed
    from app.org.mock_vlei import get_mock_vlei_manager
    mock_vlei = get_mock_vlei_manager()
    if not mock_vlei.state or not mock_vlei.state.gsma_aid:
        log.warning(
            f"Cannot validate issuer for credential {said[:16]}...: "
            f"Mock GSMA state unavailable — treating cert as inactive"
        )
        return None
    if cred.issuer_aid != mock_vlei.state.gsma_aid:
        log.warning(
            f"Stale pointer: credential {said[:16]}... issued by {cred.issuer_aid[:16]}... "
            f"not mock GSMA {mock_vlei.state.gsma_aid[:16]}..."
        )
        return None

    # Check issuee binding
    attrib = cred.attributes
    if attrib.get("i") != org.aid:
        log.warning(
            f"Stale pointer: credential {said[:16]}... issuee {attrib.get('i', 'none')[:16]}... "
            f"doesn't match org AID {org.aid[:16] if org.aid else 'none'}..."
        )
        return None

    # Check expiry
    cert_expiry = attrib.get("certificationExpiry")
    if cert_expiry:
        try:
            expiry_dt = datetime.fromisoformat(cert_expiry)
            if expiry_dt.tzinfo is None:
                expiry_dt = expiry_dt.replace(tzinfo=timezone.utc)
            if expiry_dt < datetime.now(timezone.utc):
                log.warning(f"Stale pointer: credential {said[:16]}... is expired ({cert_expiry})")
                return None
        except (ValueError, TypeError):
            log.warning(f"Could not parse certificationExpiry: {cert_expiry}")

    return CredentialInfo(
        said=said,
        attributes=attrib,
        issuer_aid=cred.issuer_aid,
        status=cred.status,
    )


async def _resolve_cert_attributes(said: str) -> dict:
    """Read credential attributes and status from KERI Agent.

    Returns dict with ecc_targets, jurisdiction_targets, name,
    certification_expiry, and status. Defaults status to "unknown"
    if credential cannot be loaded (fail-closed, not "issued").

    Raises KeriAgentUnavailableError if the KERI Agent is unreachable,
    so callers can propagate 503 to the client.
    """
    from app.keri_client import KeriAgentUnavailableError

    result = {
        "ecc_targets": [],
        "jurisdiction_targets": [],
        "name": "",
        "certification_expiry": None,
        "status": "unknown",
    }
    try:
        client = get_keri_client()
        cred = await client.get_credential(said)
        if cred is not None:
            attrib = cred.attributes
            result["ecc_targets"] = attrib.get("ecc_targets", [])
            result["jurisdiction_targets"] = attrib.get("jurisdiction_targets", [])
            result["name"] = attrib.get("name", "")
            result["certification_expiry"] = attrib.get("certificationExpiry")
            result["status"] = cred.status
    except KeriAgentUnavailableError:
        raise  # Propagate agent outage as-is
    except Exception as e:
        log.warning(f"Could not resolve attributes for credential {said[:16]}...: {e}")

    return result


async def issue_vetter_certification(
    db: Session,
    organization_id: str,
    ecc_targets: list[str],
    jurisdiction_targets: list[str],
    name: str,
    certification_expiry: Optional[str] = None,
) -> dict:
    """Issue a VetterCertification ACDC and link to org.

    Returns:
        Dict with credential info for building the response.
    """
    from app.org.mock_vlei import get_mock_vlei_manager

    # 1. Validate org exists, has AID and registry
    org = (
        db.query(Organization)
        .with_for_update()
        .filter(Organization.id == organization_id)
        .first()
    )
    if org is None:
        raise HTTPException(status_code=404, detail="Organization not found")
    if not org.aid:
        raise HTTPException(
            status_code=400, detail="Organization has no KERI identity"
        )

    # 3. Check for existing active cert
    if org.vetter_certification_said:
        cert_info = await resolve_active_vetter_cert(org)
        if cert_info is not None:
            raise HTTPException(
                status_code=409,
                detail="Organization already has active VetterCertification. "
                       "Revoke it first.",
            )
        # Stale pointer — auto-clear
        log.warning(
            f"Cleared stale vetter cert pointer for org {organization_id[:8]}... "
            f"(was {org.vetter_certification_said[:16]}...)"
        )
        org.vetter_certification_said = None

    # 3b. Durable secondary guard
    active_managed = (
        db.query(ManagedCredential)
        .filter(
            ManagedCredential.organization_id == organization_id,
            ManagedCredential.schema_said == VETTER_CERT_SCHEMA_SAID,
        )
        .all()
    )
    for mc in active_managed:
        # Check if this managed credential is actually active in KERI
        temp_org = Organization(
            id=organization_id,
            name=org.name,
            aid=org.aid,
            vetter_certification_said=mc.said,
        )
        temp_info = await resolve_active_vetter_cert(temp_org)
        if temp_info is not None:
            log.warning(
                f"Durable guard: found active vetter cert {mc.said[:16]}... "
                f"for org {organization_id[:8]}... via ManagedCredential scan"
            )
            raise HTTPException(
                status_code=409,
                detail="Organization already has active VetterCertification. "
                       "Revoke it first.",
            )

    # 5. Issue credential via mock GSMA
    mock_vlei = get_mock_vlei_manager()
    if not mock_vlei.state or not mock_vlei.state.gsma_aid:
        raise HTTPException(
            status_code=500,
            detail="Mock GSMA infrastructure not available",
        )

    cred_said = await mock_vlei.issue_vetter_certification(
        org_aid=org.aid,
        ecc_targets=ecc_targets,
        jurisdiction_targets=jurisdiction_targets,
        name=name,
        certification_expiry=certification_expiry,
    )

    # 6-8. Register ManagedCredential + set pointer — single commit
    managed = ManagedCredential(
        said=cred_said,
        organization_id=organization_id,
        schema_said=VETTER_CERT_SCHEMA_SAID,
        issuer_aid=mock_vlei.state.gsma_aid,
    )
    db.add(managed)
    org.vetter_certification_said = cred_said
    db.commit()
    db.refresh(org)
    db.refresh(managed)

    # 9. Publish to witnesses (agent handles this internally on issue)

    return {
        "said": cred_said,
        "issuer_aid": mock_vlei.state.gsma_aid,
        "vetter_aid": org.aid,
        "organization_id": organization_id,
        "organization_name": org.name,
        "ecc_targets": ecc_targets,
        "jurisdiction_targets": jurisdiction_targets,
        "name": name,
        "certification_expiry": certification_expiry,
        "status": "issued",
        "created_at": managed.created_at.isoformat(),
    }


async def revoke_vetter_certification(
    db: Session,
    said: str,
) -> dict:
    """Revoke a VetterCertification and conditionally clear org link."""
    client = get_keri_client()

    # Find the managed credential
    managed = (
        db.query(ManagedCredential)
        .filter(
            ManagedCredential.said == said,
            ManagedCredential.schema_said == VETTER_CERT_SCHEMA_SAID,
        )
        .first()
    )
    if managed is None:
        raise HTTPException(status_code=404, detail="VetterCertification not found")

    org = db.query(Organization).filter(
        Organization.id == managed.organization_id
    ).first()

    # Revoke via KERI Agent (agent handles witness publishing internally)
    await client.revoke_credential(said)

    # Clear org pointer only if it points to this cert
    if org and org.vetter_certification_said == said:
        org.vetter_certification_said = None

    db.commit()

    # Resolve credential attributes from KERI Agent (status will be "revoked")
    attrs = await _resolve_cert_attributes(said)

    return {
        "said": said,
        "issuer_aid": managed.issuer_aid,
        "vetter_aid": org.aid if org else "",
        "organization_id": managed.organization_id,
        "organization_name": org.name if org else "",
        "ecc_targets": attrs["ecc_targets"],
        "jurisdiction_targets": attrs["jurisdiction_targets"],
        "name": attrs["name"],
        "certification_expiry": attrs["certification_expiry"],
        "status": "revoked",
        "created_at": managed.created_at.isoformat(),
    }


async def get_org_constraints(
    db: Session,
    organization_id: str,
) -> dict:
    """Get parsed constraints for an org.

    Uses resolve_active_vetter_cert() to validate the credential.
    Returns null constraints if no valid active cert.
    """
    org = db.query(Organization).filter(Organization.id == organization_id).first()
    if org is None:
        raise HTTPException(status_code=404, detail="Organization not found")

    result = {
        "organization_id": org.id,
        "organization_name": org.name,
        "vetter_certification_said": None,
        "ecc_targets": None,
        "jurisdiction_targets": None,
        "certification_status": None,
        "certification_expiry": None,
    }

    cert_info = await resolve_active_vetter_cert(org)
    if cert_info is None:
        return result

    result["vetter_certification_said"] = cert_info.said
    result["ecc_targets"] = cert_info.attributes.get("ecc_targets", [])
    result["jurisdiction_targets"] = cert_info.attributes.get("jurisdiction_targets", [])
    result["certification_status"] = cert_info.status
    result["certification_expiry"] = cert_info.attributes.get("certificationExpiry")

    return result
