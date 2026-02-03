"""Issuer identity extraction module.

Extracts semantic identity (legal name, LEI) from credentials in a dossier.
This module is used by the core verification flow to populate issuer_identities
in the API response.

Per KERI design, an AID alone represents cryptographic control, not semantic
identity. Semantic identity is established via credentials (ACDCs) that assert
attributes about the AID holder.
"""

import json
import logging
import os
from dataclasses import dataclass
from typing import TYPE_CHECKING, Dict, List, Optional, Tuple

if TYPE_CHECKING:
    from .acdc.models import ACDC

log = logging.getLogger(__name__)


# =============================================================================
# IssuerIdentity Data Class
# =============================================================================


@dataclass
class IssuerIdentity:
    """Resolved identity for an AID.

    Attributes:
        aid: The AID this identity is about.
        legal_name: Legal name from LE credential or vCard ORG.
        lei: Legal Entity Identifier (ISO 17442) from LE credential.
        source_said: SAID of the LE credential this came from.
            None if from well-known registry (static fallback).
        role: How this identity was derived:
            - "issuee": AID is the issuee/subject of an LE credential
            - "issuer": AID issued a self-issued LE credential (no explicit issuee)
            - "wellknown": Identity from static well-known AIDs registry
    """

    aid: str
    legal_name: Optional[str] = None
    lei: Optional[str] = None
    source_said: Optional[str] = None
    role: Optional[str] = None


# =============================================================================
# Well-Known AIDs Registry
# =============================================================================

# Default well-known AIDs for root of trust organizations
# These provide fallback identity when LE credentials aren't in dossier
# Source: vLEI Governance Framework
#
# IMPORTANT: This registry contains ISSUER AIDs (autonomic identifiers derived
# from inception events), NOT schema SAIDs (content-addressed identifiers).
# Schema SAIDs belong in common/vvp/schema/registry.py.
#
# The production GLEIF GEDA (GLEIF External Delegated AID) used to issue QVI
# credentials is established through a multi-party ceremony. The GEDA is
# delegated from the GLEIF Root AID. Contact GLEIF for the current production
# GEDA value: https://www.gleif.org/en/about-lei/introducing-the-vlei
#
# Note: EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao is the QVI SCHEMA SAID,
# not an issuer AID. It should not appear in this registry.
_DEFAULT_WELLKNOWN_AIDS: Dict[str, Tuple[str, Optional[str]]] = {
    # Provenant Global QVI (multiple AIDs observed in production)
    "ELW1FqnJZgOBR43USMu1RfVE6U1BXl6UFecIDPmJnscQ": ("Provenant Global", None),
    "ELW1FqnJZgOBR43UqAXCCFF6Zyz_EXaunivemMEkhRLy": ("Provenant Global", None),
    # GLEIF Internal Issuer (observed in test/demo environments)
    "EPI6riUghhZcrzeRvP2w94LKmPYplMVUXgpj2m5sJOzL": ("GLEIF Internal Issuer", None),
    "EPI6riUghhZcrzeRrf4qxOSgMvqL97LKxMSaxcDUciub": ("GLEIF Internal Issuer", None),
    # Brand assure QVI (Provenant demo ecosystem)
    "EKudJXsXQNzMzEhBHjs5iqZXLSF5fg1Nxs1MD-IAXqDo": ("Brand assure", None),
    # Test roots (for development)
    "EDP1vHcw_wc4M__Fj53-cJaBnZZASd-aMTaSyWvOPUbo": ("Test QVI Root", None),
}


# =============================================================================
# Known GLEIF-Authorized QVIs (Qualified vLEI Issuers)
# =============================================================================
# These AIDs represent organizations that have been authorized by GLEIF to issue
# vLEI credentials. When a dossier's terminal issuer is a known QVI, the graph
# can show an implicit trust path to GLEIF even if the QVI credential is not
# explicitly included in the dossier's chain edges.
#
# Source: https://www.gleif.org/en/about-lei/introducing-the-vlei
# QVI list: https://keri.one/qvi-list (maintained by GLEIF/ToIP)

GLEIF_AUTHORIZED_QVIS: set[str] = {
    # Provenant Global - First commercial QVI
    "ELW1FqnJZgOBR43USMu1RfVE6U1BXl6UFecIDPmJnscQ",
    "ELW1FqnJZgOBR43UqAXCCFF6Zyz_EXaunivemMEkhRLy",
    # Brand assure - Demo/test QVI in Provenant ecosystem
    "EKudJXsXQNzMzEhBHjs5iqZXLSF5fg1Nxs1MD-IAXqDo",
}


def is_gleif_authorized_qvi(aid: str) -> bool:
    """Check if an AID is a known GLEIF-authorized QVI.

    Args:
        aid: The AID to check.

    Returns:
        True if this AID is a known GLEIF-authorized QVI.
    """
    return aid in GLEIF_AUTHORIZED_QVIS


def _load_wellknown_aids() -> Dict[str, Tuple[str, Optional[str]]]:
    """Load well-known AIDs from file or use defaults.

    If WELLKNOWN_AIDS_FILE environment variable is set, loads the registry
    from that JSON file. Otherwise, returns the built-in defaults.

    File format:
    {
        "AID1": ["Legal Name", "LEI or null"],
        "AID2": ["Legal Name", null]
    }

    Returns:
        Dict mapping AID strings to (name, lei) tuples.
    """
    aids_file = os.getenv("WELLKNOWN_AIDS_FILE")

    if not aids_file:
        return _DEFAULT_WELLKNOWN_AIDS.copy()

    try:
        with open(aids_file, "r") as f:
            data = json.load(f)

        result: Dict[str, Tuple[str, Optional[str]]] = {}
        for aid, values in data.items():
            if isinstance(values, list) and len(values) >= 2:
                result[aid] = (values[0], values[1])
            elif isinstance(values, list) and len(values) == 1:
                result[aid] = (values[0], None)
            elif isinstance(values, str):
                result[aid] = (values, None)

        log.info(f"Loaded {len(result)} well-known AIDs from {aids_file}")
        return result

    except FileNotFoundError:
        log.warning(f"Well-known AIDs file not found: {aids_file}, using defaults")
        return _DEFAULT_WELLKNOWN_AIDS.copy()
    except json.JSONDecodeError as e:
        log.warning(f"Invalid JSON in well-known AIDs file: {e}, using defaults")
        return _DEFAULT_WELLKNOWN_AIDS.copy()
    except Exception as e:
        log.warning(f"Error loading well-known AIDs file: {e}, using defaults")
        return _DEFAULT_WELLKNOWN_AIDS.copy()


# Global registry - loaded once at module import
WELLKNOWN_AIDS: Dict[str, Tuple[str, Optional[str]]] = _load_wellknown_aids()


# =============================================================================
# Identity Extraction Functions
# =============================================================================


def get_wellknown_identity(aid: str) -> Optional[IssuerIdentity]:
    """Get identity from well-known AIDs registry.

    Args:
        aid: The AID to look up.

    Returns:
        IssuerIdentity if AID is in registry, None otherwise.
    """
    if aid in WELLKNOWN_AIDS:
        name, lei = WELLKNOWN_AIDS[aid]
        return IssuerIdentity(
            aid=aid,
            legal_name=name,
            lei=lei,
            source_said=None,  # No credential source, from static registry
            role="wellknown",
        )
    return None


def build_issuer_identity_map(
    acdcs: List["ACDC"],
) -> Dict[str, IssuerIdentity]:
    """Build AID→identity mapping from LE credentials in a dossier.

    Scans all credentials for Legal Entity (LE) credentials which contain
    identity information (legalName, LEI) for their issuee AID. Also checks
    vCard data for organization name as fallback.

    Identity source is determined by whether source_said is set:
    - source_said present → "dossier" (from credential, including vCard)
    - source_said None → "wellknown" (from static registry)

    Args:
        acdcs: List of parsed ACDC credentials from a dossier.

    Returns:
        Dict mapping AID strings to IssuerIdentity objects.
    """
    identity_map: Dict[str, IssuerIdentity] = {}

    for acdc in acdcs:
        # LE credentials have legalName or LEI in attributes
        if not isinstance(acdc.attributes, dict):
            continue

        # Check if this is an LE credential with identity info
        legal_name = acdc.attributes.get("legalName")
        lei = acdc.attributes.get("LEI")

        # Also check 'lids' field (vLEI Legal Identity Data Source)
        # May contain LEI directly as string or as structured data
        lids = acdc.attributes.get("lids")
        if lids:
            # lids might be direct LEI string (20-character alphanumeric)
            if isinstance(lids, str):
                if len(lids) == 20 and lids.isalnum() and not lei:
                    lei = lids
            # lids might be a dict with nested identity fields
            elif isinstance(lids, dict):
                if not lei:
                    lei = lids.get("LEI") or lids.get("lei")
                if not legal_name:
                    legal_name = (
                        lids.get("legalName")
                        or lids.get("name")
                        or lids.get("legalname")
                    )
            # lids might be a list of identity sources
            elif isinstance(lids, list):
                for item in lids:
                    if isinstance(item, dict):
                        if not lei:
                            lei = item.get("LEI") or item.get("lei")
                        if not legal_name:
                            legal_name = (
                                item.get("legalName")
                                or item.get("name")
                                or item.get("legalname")
                            )
                        if lei or legal_name:
                            break

        # Also check vCard data for organization name and LEI
        vcard_data = acdc.attributes.get("vcard")
        if isinstance(vcard_data, list):
            for line in vcard_data:
                if isinstance(line, str):
                    line_upper = line.upper()
                    if line_upper.startswith("ORG:") and not legal_name:
                        legal_name = line[4:].strip()
                    elif line_upper.startswith("NOTE;LEI:") and not lei:
                        lei = line[9:].strip()

        if not legal_name and not lei:
            continue

        # The issuee (subject) of the LE credential is the AID being identified
        issuee = acdc.attributes.get("issuee") or acdc.attributes.get("i")

        if issuee:
            # Credential has explicit issuee - identity describes that AID
            identity_map[issuee] = IssuerIdentity(
                aid=issuee,
                legal_name=legal_name,
                lei=lei,
                source_said=acdc.said,
                role="issuee",
            )
            log.debug(
                f"Identity from dossier (issuee): {issuee[:16]}... = "
                f"{legal_name or 'LEI:' + str(lei)}"
            )
        else:
            # Self-issued credential - identity describes the issuer itself
            identity_map[acdc.issuer_aid] = IssuerIdentity(
                aid=acdc.issuer_aid,
                legal_name=legal_name,
                lei=lei,
                source_said=acdc.said,
                role="issuer",
            )
            log.debug(
                f"Identity from dossier (self-issued): {acdc.issuer_aid[:16]}... = "
                f"{legal_name or 'LEI:' + str(lei)}"
            )

    # Add well-known AIDs as fallback for issuers not found in dossier
    all_issuer_aids = {acdc.issuer_aid for acdc in acdcs}
    for aid in all_issuer_aids:
        if aid not in identity_map:
            wk = get_wellknown_identity(aid)
            if wk:
                identity_map[aid] = wk
                log.debug(f"Identity from well-known: {aid[:16]}... = {wk.legal_name}")

    # Also check edge targets for well-known AIDs
    # Edges may point to AIDs (not credential SAIDs) that should be resolved
    for acdc in acdcs:
        if not isinstance(acdc.edges, dict):
            continue
        for edge_key, edge_value in acdc.edges.items():
            if edge_key in ("d", "n"):
                continue
            # Extract edge target (could be string AID, dict with 'n', etc.)
            target = None
            if isinstance(edge_value, str):
                target = edge_value
            elif isinstance(edge_value, dict):
                target = edge_value.get("n") or edge_value.get("d")
            if target and target not in identity_map:
                wk = get_wellknown_identity(target)
                if wk:
                    identity_map[target] = wk
                    log.debug(f"Identity from well-known (edge): {target[:16]}... = {wk.legal_name}")

    return identity_map
