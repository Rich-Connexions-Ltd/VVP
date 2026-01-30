"""Embedded schema store for known vLEI schemas.

This module provides an embedded store of known vLEI schema documents,
eliminating the need to fetch them from external registries. Schemas are
loaded from JSON files in the schemas/ subdirectory.

Per VVP §6.3.x, credentials must use recognized schema SAIDs. This store
provides instant lookup for official vLEI governance schemas.

Schema Sources:
- GLEIF-IT/vLEI-schema: https://github.com/GLEIF-IT/vLEI-schema
- WebOfTrust/vLEI: https://github.com/WebOfTrust/vLEI
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, Optional

log = logging.getLogger(__name__)

# Directory containing embedded schema JSON files
SCHEMAS_DIR = Path(__file__).parent / "schemas"

# Embedded schema cache: SAID -> schema document
_embedded_schemas: Dict[str, Dict[str, Any]] = {}

# Flag to track if schemas have been loaded
_schemas_loaded = False


def _load_embedded_schemas() -> None:
    """Load all embedded schema JSON files into memory.

    Scans the schemas/ directory for .json files, loads each one,
    and indexes by the $id field (SAID).
    """
    global _schemas_loaded, _embedded_schemas

    if _schemas_loaded:
        return

    if not SCHEMAS_DIR.exists():
        log.warning(f"Schemas directory not found: {SCHEMAS_DIR}")
        _schemas_loaded = True
        return

    loaded_count = 0
    for json_file in SCHEMAS_DIR.glob("*.json"):
        try:
            with open(json_file, "r", encoding="utf-8") as f:
                schema_doc = json.load(f)

            # Index by $id (SAID)
            schema_said = schema_doc.get("$id")
            if schema_said:
                _embedded_schemas[schema_said] = schema_doc
                loaded_count += 1
                log.debug(f"Loaded embedded schema: {schema_said[:20]}... from {json_file.name}")
            else:
                log.warning(f"Schema file missing $id: {json_file.name}")

        except json.JSONDecodeError as e:
            log.error(f"Invalid JSON in schema file {json_file.name}: {e}")
        except Exception as e:
            log.error(f"Error loading schema file {json_file.name}: {e}")

    _schemas_loaded = True
    log.info(f"Loaded {loaded_count} embedded schemas from {SCHEMAS_DIR}")


def get_embedded_schema(schema_said: str) -> Optional[Dict[str, Any]]:
    """Get an embedded schema by SAID.

    Args:
        schema_said: The schema's self-addressing identifier ($id field).

    Returns:
        The schema document dict if found, None otherwise.
    """
    _load_embedded_schemas()
    return _embedded_schemas.get(schema_said)


def has_embedded_schema(schema_said: str) -> bool:
    """Check if a schema is available in the embedded store.

    Args:
        schema_said: The schema's self-addressing identifier.

    Returns:
        True if schema is embedded, False otherwise.
    """
    _load_embedded_schemas()
    return schema_said in _embedded_schemas


def list_embedded_schemas() -> Dict[str, str]:
    """List all embedded schemas with their titles.

    Returns:
        Dict mapping SAID to schema title.
    """
    _load_embedded_schemas()
    return {
        said: schema.get("title", "Untitled")
        for said, schema in _embedded_schemas.items()
    }


def get_embedded_schema_count() -> int:
    """Get the number of embedded schemas.

    Returns:
        Count of loaded schemas.
    """
    _load_embedded_schemas()
    return len(_embedded_schemas)


def reload_embedded_schemas() -> int:
    """Force reload of embedded schemas.

    Useful for testing or after adding new schema files.

    Returns:
        Count of loaded schemas.
    """
    global _schemas_loaded, _embedded_schemas
    _schemas_loaded = False
    _embedded_schemas = {}
    _load_embedded_schemas()
    return len(_embedded_schemas)


# Known schema SAIDs for quick reference
# These are the official vLEI governance framework schemas
KNOWN_VLEI_SCHEMA_SAIDS = {
    # === Official GLEIF vLEI Governance Schemas ===
    # QVI - Qualified vLEI Issuer credential
    "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao": "Qualified vLEI Issuer Credential",
    # LE - Legal Entity credential
    "ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY": "Legal Entity vLEI Credential",
    # ECR - Engagement Context Role
    "EEy9PkikFcANV1l7EHukCeXqrzT1hNZjGlUk7wuMO5jw": "Legal Entity Engagement Context Role Credential",
    # OOR - Official Organizational Role
    "EBNaNu-M9P5cgrnfl2Fvymy4E_jvxxyjb70PRtiANlJy": "Legal Entity Official Organizational Role Credential",
    # ECR Auth
    "EH6ekLjSr8V32WyFbGe1zXjTzFs9PkTYmupJ9H65O14g": "ECR Authorization Credential",
    # OOR Auth
    "EKA57bKBKxr_kN7iN5i7lMUxpMG-s19dRcmov1iDxz-E": "OOR Authorization Credential",
    # === Provenant VVP Schemas (from provenant-dev/public-schema) ===
    # VVP Dossier - assembles evidence per Verifiable Voice Protocol
    "EH1jN4U4LMYHmPVI4FYdZ10bIPR7YWKp8TDdZ9Y9Al-P": "Verifiable Voice Dossier Credential",
    # TN Allocation - proves right to use telephone numbers
    "EFvnoHDY7I-kaBBeKlbDbkjG4BaI0nKLGadxBdjMGgSQ": "TN Allocation Credential",
    # GCD - Generalized Cooperative Delegation credential
    "EL7irIKYJL9Io0hhKSGWI4OznhwC7qgJG5Qf4aEs6j0o": "Generalized Cooperative Delegation Credential",
}
