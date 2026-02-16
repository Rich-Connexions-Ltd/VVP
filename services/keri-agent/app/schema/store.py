"""Schema store for VVP KERI Agent.

Minimal schema store providing schema validation for credential issuance.
Loads embedded schema JSON files from the schemas/ directory.

Sprint 68: Extracted from services/issuer/app/schema/store.py.
"""

import json
import logging
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

# Directory containing embedded schema JSON files (read-only)
EMBEDDED_SCHEMAS_DIR = Path(__file__).parent / "schemas"

# Embedded schema cache: SAID -> schema document
_embedded_schemas: dict[str, dict[str, Any]] = {}
_embedded_loaded = False


def _load_embedded_schemas() -> None:
    """Load all embedded schema JSON files into memory."""
    global _embedded_loaded, _embedded_schemas

    if _embedded_loaded:
        return

    if not EMBEDDED_SCHEMAS_DIR.exists():
        log.warning(f"Embedded schemas directory not found: {EMBEDDED_SCHEMAS_DIR}")
        _embedded_loaded = True
        return

    loaded_count = 0
    for json_file in EMBEDDED_SCHEMAS_DIR.glob("*.json"):
        try:
            with open(json_file, "r", encoding="utf-8") as f:
                schema_doc = json.load(f)

            schema_said = schema_doc.get("$id")
            if schema_said:
                _embedded_schemas[schema_said] = schema_doc
                loaded_count += 1
            else:
                log.warning(f"Schema file missing $id: {json_file.name}")

        except json.JSONDecodeError as e:
            log.error(f"Invalid JSON in schema file {json_file.name}: {e}")

    _embedded_loaded = True
    log.info(f"Loaded {loaded_count} embedded schemas")


def has_embedded_schema(schema_said: str) -> bool:
    """Check if a schema is available in the embedded store."""
    _load_embedded_schemas()
    return schema_said in _embedded_schemas


def get_embedded_schema(schema_said: str) -> dict[str, Any] | None:
    """Get an embedded schema by SAID."""
    _load_embedded_schemas()
    return _embedded_schemas.get(schema_said)


def list_embedded_schemas() -> list[dict[str, Any]]:
    """List all embedded schemas."""
    _load_embedded_schemas()
    return list(_embedded_schemas.values())
