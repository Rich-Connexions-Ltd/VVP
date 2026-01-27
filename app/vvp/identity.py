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
    """

    aid: str
    legal_name: Optional[str] = None
    lei: Optional[str] = None
    source_said: Optional[str] = None


# =============================================================================
# Well-Known AIDs Registry
# =============================================================================

# Default well-known AIDs for root of trust organizations
# These provide fallback identity when LE credentials aren't in dossier
# Source: vLEI Governance Framework
_DEFAULT_WELLKNOWN_AIDS: Dict[str, Tuple[str, Optional[str]]] = {
    # GLEIF External (production vLEI root of trust)
    "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao": ("GLEIF", "5493001KJTIIGC8Y1R12"),
    # Provenant Global QVI (multiple AIDs observed)
    "ELW1FqnJZgOBR43USMu1RfVE6U1BXl6UFecIDPmJnscQ": ("Provenant Global", None),
    "ELW1FqnJZgOBR43UqAXCCFF6Zyz_EXaunivemMEkhRLy": ("Provenant Global", None),
    # GLEIF Internal Issuer (multiple AIDs observed)
    "EPI6riUghhZcrzeRvP2w94LKmPYplMVUXgpj2m5sJOzL": ("GLEIF Internal Issuer", None),
    "EPI6riUghhZcrzeRrf4qxOSgMvqL97LKxMSaxcDUciub": ("GLEIF Internal Issuer", None),
    # Test roots (for development)
    "EDP1vHcw_wc4M__Fj53-cJaBnZZASd-aMTaSyWvOPUbo": ("Test QVI Root", None),
}


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

        # Also check vCard data for organization name
        vcard_data = acdc.attributes.get("vcard")
        if isinstance(vcard_data, list) and not legal_name:
            for line in vcard_data:
                if isinstance(line, str) and line.upper().startswith("ORG:"):
                    legal_name = line[4:].strip()
                    break

        if not legal_name and not lei:
            continue

        # The issuee (subject) of the LE credential is the AID being identified
        issuee = acdc.attributes.get("issuee") or acdc.attributes.get("i")

        # If no explicit issuee, the credential identifies its own issuer
        # (self-issued LE credentials)
        if not issuee:
            issuee = acdc.issuer_aid

        if issuee:
            identity_map[issuee] = IssuerIdentity(
                aid=issuee,
                legal_name=legal_name,
                lei=lei,
                source_said=acdc.said,
            )
            log.debug(
                f"Identity from dossier: {issuee[:16]}... = "
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

    return identity_map
