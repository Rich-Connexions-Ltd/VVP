"""ACDC (Authentic Chained Data Container) verification package.

This package provides ACDC credential verification for VVP per §6.3.x.

Components:
- models: ACDC and ACDCChainResult dataclasses
- parser: ACDC parsing and SAID validation
- verifier: Signature verification and chain validation
- exceptions: ACDCError hierarchy

Usage:
    from app.vvp.acdc import (
        ACDC,
        ACDCChainResult,
        parse_acdc,
        validate_acdc_said,
        verify_acdc_signature,
        validate_credential_chain,
        ACDCError,
        ACDCSAIDMismatch,
        ACDCSignatureInvalid,
        ACDCChainInvalid,
    )
"""

from .exceptions import (
    ACDCError,
    ACDCChainInvalid,
    ACDCParseError,
    ACDCSAIDMismatch,
    ACDCSignatureInvalid,
)
from .models import ACDC, ACDCChainResult
from .parser import parse_acdc, parse_acdc_from_dossier, validate_acdc_said
from .verifier import (
    KNOWN_SCHEMA_SAIDS,
    resolve_issuer_key_state,
    validate_ape_credential,
    validate_credential_chain,
    validate_de_credential,
    validate_issuee_binding,
    validate_schema_said,
    validate_tnalloc_credential,
    verify_acdc_signature,
)
from .graph import (
    CredentialGraph,
    CredentialNode,
    CredentialEdge,
    CredentialStatus,
    ResolutionSource,
    build_credential_graph,
    credential_graph_to_dict,
)

__all__ = [
    # Models
    "ACDC",
    "ACDCChainResult",
    # Parsing
    "parse_acdc",
    "parse_acdc_from_dossier",
    "validate_acdc_said",
    # Verification
    "resolve_issuer_key_state",
    "verify_acdc_signature",
    "validate_credential_chain",
    "validate_ape_credential",
    "validate_de_credential",
    "validate_issuee_binding",
    "validate_tnalloc_credential",
    "validate_schema_said",
    "KNOWN_SCHEMA_SAIDS",
    # Graph visualization
    "CredentialGraph",
    "CredentialNode",
    "CredentialEdge",
    "CredentialStatus",
    "ResolutionSource",
    "build_credential_graph",
    "credential_graph_to_dict",
    # Exceptions
    "ACDCError",
    "ACDCParseError",
    "ACDCSAIDMismatch",
    "ACDCSignatureInvalid",
    "ACDCChainInvalid",
]
