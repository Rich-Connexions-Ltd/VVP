# VVP Schema - Schema registry, validation, and embedded schemas

from common.vvp.schema.registry import (
    SCHEMA_REGISTRY_VERSION,
    KNOWN_SCHEMA_SAIDS,
    SCHEMA_SOURCE,
    get_known_schemas,
    is_known_schema,
    has_governance_schemas,
)

__all__ = [
    "SCHEMA_REGISTRY_VERSION",
    "KNOWN_SCHEMA_SAIDS",
    "SCHEMA_SOURCE",
    "get_known_schemas",
    "is_known_schema",
    "has_governance_schemas",
]
