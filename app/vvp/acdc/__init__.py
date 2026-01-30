"""ACDC (Authentic Chained Data Container) verification package.

This package provides ACDC credential verification for VVP per §6.3.x.

Components:
- models: ACDC and ACDCChainResult dataclasses
- parser: ACDC parsing and SAID validation
- verifier: Signature verification and chain validation
- schema_resolver: SAID-first schema resolution with multi-source lookup
- schema_cache: LRU+TTL cache for verified schemas
- schema_store: Embedded schema store for known vLEI schemas
- exceptions: ACDCError hierarchy

Usage:
    from app.vvp.acdc import (
        ACDC,
        ACDCChainResult,
        parse_acdc,
        validate_acdc_said,
        verify_acdc_signature,
        validate_credential_chain,
        SchemaResolver,
        get_schema_resolver,
        get_embedded_schema,
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
    validate_schema_document,
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
from .schema_resolver import (
    SchemaResolver,
    SchemaResolverConfig,
    SchemaResolverMetrics,
    ResolvedSchema,
    get_schema_resolver,
    reset_schema_resolver,
)
from .schema_cache import (
    SchemaCache,
    SchemaCacheConfig,
    SchemaCacheMetrics,
    CachedSchema,
    get_schema_cache,
    reset_schema_cache,
)
from .schema_store import (
    get_embedded_schema,
    has_embedded_schema,
    list_embedded_schemas,
    get_embedded_schema_count,
    reload_embedded_schemas,
    KNOWN_VLEI_SCHEMA_SAIDS,
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
    "validate_schema_document",
    "KNOWN_SCHEMA_SAIDS",
    # Schema resolution
    "SchemaResolver",
    "SchemaResolverConfig",
    "SchemaResolverMetrics",
    "ResolvedSchema",
    "get_schema_resolver",
    "reset_schema_resolver",
    # Schema cache
    "SchemaCache",
    "SchemaCacheConfig",
    "SchemaCacheMetrics",
    "CachedSchema",
    "get_schema_cache",
    "reset_schema_cache",
    # Embedded schema store
    "get_embedded_schema",
    "has_embedded_schema",
    "list_embedded_schemas",
    "get_embedded_schema_count",
    "reload_embedded_schemas",
    "KNOWN_VLEI_SCHEMA_SAIDS",
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
