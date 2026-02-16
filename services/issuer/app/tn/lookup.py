"""TN Lookup with Ownership Validation.

Sprint 42: Validates that TNs are covered by the organization's TN Allocation
credentials before allowing VVP attestation.
"""

import logging
from dataclasses import dataclass
from typing import Optional

from sqlalchemy.orm import Session

from common.vvp.utils.tn_utils import parse_tn_allocation, TNParseError

log = logging.getLogger(__name__)


# TN Allocation schema SAIDs (base and extended versions)
TN_ALLOCATION_SCHEMA_SAIDS = [
    "EFvnoHDY7I-kaBBeKlbDbkjG4BaI0nKLGadxBdjMGgSQ",  # Base TN Allocation
    "EGUh_fVLbjfkYFb5zAsY2Rqq0NqwnD3r5jsdKWLTpU8_",  # Extended with vetter cert edge
]


@dataclass
class TNLookupResult:
    """Result from TN lookup operation."""

    found: bool
    tn: Optional[str] = None
    organization_id: Optional[str] = None
    organization_name: Optional[str] = None
    dossier_said: Optional[str] = None
    identity_name: Optional[str] = None
    brand_name: Optional[str] = None
    brand_logo_url: Optional[str] = None
    error: Optional[str] = None


def tn_to_int(tn: str) -> int:
    """Convert E.164 TN to integer.

    Args:
        tn: E.164 format phone number (e.g., "+15551234567")

    Returns:
        Integer representation (e.g., 15551234567)
    """
    # Normalize: add + if missing, then strip it
    if not tn.startswith("+"):
        tn = f"+{tn}"
    return int(tn.replace("+", ""))


def tn_in_ranges(tn: str, ranges: list) -> bool:
    """Check if a TN falls within any of the given ranges.

    Args:
        tn: E.164 telephone number
        ranges: List of TNRange objects

    Returns:
        True if TN is covered by at least one range
    """
    try:
        tn_int = tn_to_int(tn)
        return any(r.contains(tn_int) for r in ranges)
    except (ValueError, AttributeError):
        return False


async def validate_tn_ownership(db: Session, org_id: str, tn: str) -> bool:
    """Validate TN is covered by org's TN Allocation credentials.

    Queries ManagedCredential for TN Allocation schema credentials
    owned by org, then checks if TN falls within any allocated range.

    Args:
        db: Database session
        org_id: Organization ID
        tn: E.164 telephone number to validate

    Returns:
        True if TN is covered by at least one TN Allocation credential
    """
    from app.db.models import ManagedCredential
    from app.keri_client import get_keri_client

    # Get org's TN allocation credentials
    tn_creds = (
        db.query(ManagedCredential)
        .filter(
            ManagedCredential.organization_id == org_id,
            ManagedCredential.schema_said.in_(TN_ALLOCATION_SCHEMA_SAIDS),
        )
        .all()
    )

    if not tn_creds:
        log.debug(f"No TN Allocation credentials found for org {org_id[:8]}...")
        return False

    # Check if TN falls within any allocation
    client = get_keri_client()
    for cred in tn_creds:
        try:
            cred_info = await client.get_credential(cred.said)
            if not cred_info:
                continue

            # Get the numbers field from attributes
            numbers = cred_info.attributes.get("numbers", {})
            if not numbers:
                continue

            # Parse the TN allocation
            ranges = parse_tn_allocation(numbers)
            if tn_in_ranges(tn, ranges):
                log.debug(f"TN {tn} validated by credential {cred.said[:16]}...")
                return True

        except TNParseError as e:
            log.warning(f"Failed to parse TN allocation from {cred.said[:16]}...: {e}")
            continue
        except Exception as e:
            log.error(f"Error validating TN against {cred.said[:16]}...: {e}")
            continue

    log.debug(f"TN {tn} not covered by any TN Allocation credentials for org {org_id[:8]}...")
    return False


def _lookup_via_osp_delegation(
    db: Session, tn: str, osp_org_id: str
) -> Optional["TNMapping"]:
    """Find a TN mapping via OSP delegation.

    When an OSP presents their own API key, the TN mapping belongs to the
    owner (accountable party) org. This function joins DossierOspAssociation
    with TNMapping to find mappings where the dossier has been delegated to
    the OSP's org.

    Args:
        db: Database session
        tn: E.164 telephone number
        osp_org_id: Organization ID of the OSP (from API key)

    Returns:
        TNMapping if found via delegation, None otherwise
    """
    from app.db.models import DossierOspAssociation, TNMapping

    result = (
        db.query(TNMapping)
        .join(
            DossierOspAssociation,
            DossierOspAssociation.dossier_said == TNMapping.dossier_said,
        )
        .filter(
            TNMapping.tn == tn,
            TNMapping.enabled == True,  # noqa: E712
            DossierOspAssociation.osp_org_id == osp_org_id,
        )
        .first()
    )

    return result


async def lookup_tn_with_validation(
    db: Session,
    tn: str,
    api_key: str,
    validate_ownership: bool = True,
) -> TNLookupResult:
    """Look up TN mapping with optional ownership validation.

    Steps:
    1. Authenticate API key -> get org_id
    2. Query TN mapping for (tn, org_id)
    3. Validate TN ownership against org's TN Allocation credentials (if enabled)
    4. Return mapping data or error

    Args:
        db: Database session
        tn: E.164 telephone number to lookup
        api_key: API key for authentication
        validate_ownership: Whether to check TN Allocation credentials

    Returns:
        TNLookupResult with mapping data or error
    """
    from app.auth.api_key import get_api_key_store, verify_org_api_key
    from app.db.models import Organization
    from app.tn.store import TNMappingStore

    # Normalize TN to E.164
    if not tn.startswith("+"):
        tn = f"+{tn}"

    # Authenticate API key (try system key first, then org key)
    store = get_api_key_store()
    principal, _ = store.verify(api_key)
    if not principal:
        principal, _ = verify_org_api_key(api_key)

    if not principal:
        return TNLookupResult(found=False, error="Invalid API key")

    # Get organization ID
    org_id = principal.organization_id
    if not org_id:
        return TNLookupResult(found=False, error="No organization associated with API key")

    # Look up mapping — first try direct (API key's own org), then OSP delegation
    store = TNMappingStore(db)
    mapping = store.get_by_tn(tn, org_id)
    owner_org_id = org_id  # For TN ownership validation

    if not mapping:
        # Fallback: check if API key's org is an OSP for a dossier with this TN
        mapping = _lookup_via_osp_delegation(db, tn, org_id)
        if mapping:
            # TN ownership belongs to the delegating (owner) org, not the OSP
            owner_org_id = mapping.organization_id
            log.info(
                f"TN {tn} resolved via OSP delegation "
                f"(osp={org_id[:8]}..., owner={owner_org_id[:8]}...)"
            )

    if not mapping:
        return TNLookupResult(found=False, tn=tn, error=f"No mapping found for TN {tn}")

    if not mapping.enabled:
        return TNLookupResult(found=False, tn=tn, error=f"TN mapping for {tn} is disabled")

    # Validate TN ownership (if enabled) — always against the owner org
    if validate_ownership:
        if not await validate_tn_ownership(db, owner_org_id, tn):
            return TNLookupResult(
                found=False,
                tn=tn,
                error=f"TN {tn} not covered by organization's TN Allocation credentials",
            )

    # Get organization name (of the owner org that holds the TN mapping)
    org = db.query(Organization).filter(Organization.id == mapping.organization_id).first()
    org_name = org.name if org else None

    return TNLookupResult(
        found=True,
        tn=mapping.tn,
        organization_id=mapping.organization_id,
        organization_name=org_name,
        dossier_said=mapping.dossier_said,
        identity_name=mapping.identity_name,
        brand_name=mapping.brand_name,
        brand_logo_url=mapping.brand_logo_url,
    )
