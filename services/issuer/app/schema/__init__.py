"""Schema store for VVP Issuer."""

from app.schema.importer import (
    SchemaImporter,
    SchemaImportError,
    get_schema_importer,
    reset_schema_importer,
)
from app.schema.said import (
    SAIDComputationError,
    SAIDVerificationError,
    compute_schema_said,
    create_schema_template,
    inject_said,
    verify_schema_said,
)
from app.schema.store import (
    get_embedded_schema,
    get_embedded_schema_count,
    has_embedded_schema,
    list_embedded_schemas,
    reload_embedded_schemas,
)

__all__ = [
    # SAID computation
    "SAIDComputationError",
    "SAIDVerificationError",
    "compute_schema_said",
    "inject_said",
    "verify_schema_said",
    "create_schema_template",
    # Schema import
    "SchemaImporter",
    "SchemaImportError",
    "get_schema_importer",
    "reset_schema_importer",
    # Embedded schemas
    "get_embedded_schema",
    "has_embedded_schema",
    "list_embedded_schemas",
    "get_embedded_schema_count",
    "reload_embedded_schemas",
]
