"""Edge traversal to find Vetter Certification credentials.

This module provides functions to traverse credential edges and
locate the Vetter Certification credential that constrains a
given credential's issuer.
"""

import logging
from typing import Any, Optional

from app.vvp.vetter.certification import (
    VetterCertification,
    is_vetter_certification_schema,
    parse_vetter_certification,
)

log = logging.getLogger(__name__)

# Edge names that may reference a vetter certification
CERTIFICATION_EDGE_NAMES = ["certification", "vetter", "vetter_cert", "cert"]


def find_vetter_certification(
    credential: Any,
    dossier_acdcs: dict[str, Any],
) -> Optional[VetterCertification]:
    """Find the Vetter Certification for a credential.

    Traverses the credential's edges looking for a "certification" backlink
    that references a Vetter Certification credential.

    Per the VVP Multichannel Vetters spec: "Each of these credentials
    contains an edge, which is a backlink to CertificationB."

    Args:
        credential: The ACDC to find certification for (dict or object)
        dossier_acdcs: All ACDCs in the current dossier, keyed by SAID

    Returns:
        VetterCertification if found, None otherwise
    """
    # Extract edges from credential
    edges = _get_edges(credential)
    if not edges:
        log.debug(f"Credential has no edges, cannot find vetter certification")
        return None

    # Look for certification edge by known names
    for edge_name in CERTIFICATION_EDGE_NAMES:
        if edge_name not in edges:
            continue

        edge_ref = edges[edge_name]
        cert_said = _extract_edge_said(edge_ref)

        if not cert_said:
            log.debug(f"Edge '{edge_name}' has no SAID reference")
            continue

        # Try to find certification in dossier
        if cert_said in dossier_acdcs:
            cert_acdc = dossier_acdcs[cert_said]

            # Verify it's actually a vetter certification
            schema_said = _get_schema_said(cert_acdc)
            if schema_said and is_vetter_certification_schema(schema_said):
                parsed = parse_vetter_certification(cert_acdc)
                if parsed:
                    log.debug(
                        f"Found vetter certification {cert_said[:16]}... "
                        f"via edge '{edge_name}'"
                    )
                    return parsed
            else:
                # May still be a vetter certification with unknown schema
                # Try parsing anyway
                parsed = parse_vetter_certification(cert_acdc)
                if parsed and parsed.ecc_targets and parsed.jurisdiction_targets:
                    log.debug(
                        f"Found vetter certification {cert_said[:16]}... "
                        f"via edge '{edge_name}' (schema not in known list)"
                    )
                    return parsed

        log.debug(
            f"Certification SAID {cert_said[:16]}... "
            f"not found in dossier or not a valid certification"
        )

    # Check if any credential in dossier looks like a vetter certification
    # that issued this credential (fallback for legacy dossiers)
    issuer_aid = _get_issuer_aid(credential)
    if issuer_aid:
        for said, acdc in dossier_acdcs.items():
            schema_said = _get_schema_said(acdc)
            if schema_said and is_vetter_certification_schema(schema_said):
                parsed = parse_vetter_certification(acdc)
                if parsed and parsed.vetter_aid == issuer_aid:
                    log.debug(
                        f"Found vetter certification {said[:16]}... "
                        f"by matching issuer AID (fallback)"
                    )
                    return parsed

    log.debug("No vetter certification found for credential")
    return None


def _get_edges(credential: Any) -> Optional[dict[str, Any]]:
    """Extract edges dict from credential."""
    if isinstance(credential, dict):
        edges = credential.get("e")
    else:
        edges = getattr(credential, "edges", None)
        if edges is None:
            raw = getattr(credential, "raw", {})
            edges = raw.get("e") if raw else None

    if isinstance(edges, str):
        # Compact form - edges is a SAID, not a dict
        return None

    return edges if isinstance(edges, dict) else None


def _extract_edge_said(edge_ref: Any) -> Optional[str]:
    """Extract SAID from an edge reference.

    Handles both formats:
    - Dict format: {"n": "<SAID>", "s": "<schema_said>"}
    - String format: "<SAID>"
    """
    if isinstance(edge_ref, str):
        return edge_ref
    if isinstance(edge_ref, dict):
        return edge_ref.get("n")
    return None


def _get_schema_said(acdc: Any) -> Optional[str]:
    """Extract schema SAID from ACDC."""
    if isinstance(acdc, dict):
        return acdc.get("s")
    return getattr(acdc, "schema_said", None) or getattr(acdc, "schema", None)


def _get_issuer_aid(credential: Any) -> Optional[str]:
    """Extract issuer AID from credential."""
    if isinstance(credential, dict):
        return credential.get("i")
    return getattr(credential, "issuer_aid", None)


def get_certification_edge_said(credential: Any) -> Optional[str]:
    """Get the SAID of the certification edge from a credential.

    This is useful for checking if a credential has a certification
    edge without fully resolving it.

    Args:
        credential: The ACDC to check

    Returns:
        SAID of the certification edge target, or None if not present
    """
    edges = _get_edges(credential)
    if not edges:
        return None

    for edge_name in CERTIFICATION_EDGE_NAMES:
        if edge_name in edges:
            return _extract_edge_said(edges[edge_name])

    return None


def has_certification_edge(credential: Any) -> bool:
    """Check if a credential has a certification edge.

    Args:
        credential: The ACDC to check

    Returns:
        True if the credential has a certification edge
    """
    return get_certification_edge_said(credential) is not None
