"""Add key_prefix column to org_api_keys for O(1) API key lookup.

Without key_prefix, API key verification requires O(n) bcrypt operations
against ALL org API keys. With key_prefix (first 8 chars of the raw key
stored as plaintext), the lookup filters to at most 1 key before bcrypt.

Existing keys without a prefix are backfilled on first successful use.

This migration is idempotent — safe to run multiple times.
"""

import logging
from sqlalchemy import text
from sqlalchemy.engine import Engine

log = logging.getLogger(__name__)


def _run_postgresql(engine: Engine) -> None:
    """Run migration for PostgreSQL."""
    migration_sql = text("""
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_name = 'org_api_keys'
                AND column_name = 'key_prefix'
            ) THEN
                ALTER TABLE org_api_keys
                ADD COLUMN key_prefix VARCHAR(8);

                CREATE INDEX IF NOT EXISTS ix_org_api_keys_key_prefix
                ON org_api_keys (key_prefix);
            END IF;
        END $$;
    """)
    with engine.connect() as conn:
        conn.execute(migration_sql)
        conn.commit()
    log.info("API key prefix PostgreSQL migration complete")


def _run_sqlite(engine: Engine) -> None:
    """Run migration for SQLite."""
    with engine.connect() as conn:
        result = conn.execute(
            text("SELECT name FROM sqlite_master WHERE type='table' AND name='org_api_keys'")
        )
        if result.fetchone() is None:
            log.debug("API key prefix SQLite migration skipped: table not yet created")
            return

        # Check if column already exists
        result = conn.execute(text("PRAGMA table_info(org_api_keys)"))
        cols = {row[1] for row in result}
        if "key_prefix" not in cols:
            conn.execute(text(
                "ALTER TABLE org_api_keys ADD COLUMN key_prefix VARCHAR(8)"
            ))
            log.info("Added org_api_keys.key_prefix column")

        conn.commit()
    log.info("API key prefix SQLite migration complete")


def run_migrations(engine: Engine) -> None:
    """Run API key prefix migration.

    Adds key_prefix column to org_api_keys table for O(1) lookup.
    Safe to call multiple times (idempotent).

    Args:
        engine: SQLAlchemy engine instance
    """
    backend = engine.url.get_backend_name()
    log.info(f"Running API key prefix migration (dialect: {backend})")

    if backend == "postgresql":
        _run_postgresql(engine)
    elif backend == "sqlite":
        _run_sqlite(engine)
    else:
        log.warning(f"API key prefix migration: unsupported dialect {backend}, skipping")
