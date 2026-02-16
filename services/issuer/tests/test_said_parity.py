"""SAID parity tests: verify pure-Python SAID matches known keripy-computed values.

Sprint 68c: Ensures the pure-Python compute_schema_said() produces identical
results to keripy's Saider.saidify() for all embedded schemas.
"""

import json
from pathlib import Path

import pytest

from app.schema.said import compute_schema_said, verify_schema_said

# Embedded schema directory
SCHEMA_DIR = Path(__file__).parent.parent / "app" / "schema" / "schemas"

# Schemas whose content was modified after initial SAIDification.
# These SAIDs are well-known and referenced across the codebase, so they
# cannot be recomputed without a coordinated migration. The SAID→content
# mismatch predates Sprint 68c.
KNOWN_DIVERGENT_SAIDS = {
    "EK7kPhs5YkPsq9mZgUfPYfU-zq5iSlU8XVYJWqrVPk6g",  # extended-brand-credential
}


def _load_embedded_schemas() -> list[tuple[str, dict]]:
    """Load all embedded schema JSON files."""
    schemas = []
    if not SCHEMA_DIR.exists():
        return schemas
    for f in sorted(SCHEMA_DIR.glob("*.json")):
        try:
            data = json.loads(f.read_text())
            if "$id" in data and data["$id"]:
                schemas.append((f.name, data))
        except (json.JSONDecodeError, KeyError):
            continue
    return schemas


def _load_verifiable_schemas() -> list[tuple[str, dict]]:
    """Load embedded schemas excluding known-divergent ones."""
    return [
        (name, schema)
        for name, schema in _load_embedded_schemas()
        if schema["$id"] not in KNOWN_DIVERGENT_SAIDS
    ]


class TestSAIDParity:
    """Verify pure-Python SAID computation matches keripy for embedded schemas."""

    @pytest.mark.parametrize(
        "filename,schema",
        _load_verifiable_schemas(),
        ids=[name for name, _ in _load_verifiable_schemas()],
    )
    def test_embedded_schema_said_matches(self, filename, schema):
        """Computed SAID must match the stored $id for each embedded schema."""
        stored_said = schema["$id"]
        computed_said = compute_schema_said(schema)
        assert computed_said == stored_said, (
            f"SAID mismatch for {filename}: "
            f"stored={stored_said}, computed={computed_said}"
        )

    @pytest.mark.parametrize(
        "filename,schema",
        _load_verifiable_schemas(),
        ids=[name for name, _ in _load_verifiable_schemas()],
    )
    def test_embedded_schema_said_verifies(self, filename, schema):
        """verify_schema_said() must return True for each embedded schema."""
        assert verify_schema_said(schema) is True, (
            f"SAID verification failed for {filename}"
        )

    def test_at_least_one_embedded_schema_exists(self):
        """Sanity: at least one embedded schema must exist for parity testing."""
        schemas = _load_verifiable_schemas()
        assert len(schemas) > 0, (
            f"No verifiable embedded schemas found in {SCHEMA_DIR}. "
            "SAID parity tests are vacuously passing."
        )

    def test_known_divergent_schema_is_tracked(self):
        """Ensure known-divergent schemas actually exist and are divergent."""
        all_schemas = {schema["$id"]: schema for _, schema in _load_embedded_schemas()}
        for said in KNOWN_DIVERGENT_SAIDS:
            assert said in all_schemas, f"Divergent schema {said} not found in embedded schemas"
            computed = compute_schema_said(all_schemas[said])
            assert computed != said, (
                f"Schema {said} is no longer divergent — remove from KNOWN_DIVERGENT_SAIDS"
            )
