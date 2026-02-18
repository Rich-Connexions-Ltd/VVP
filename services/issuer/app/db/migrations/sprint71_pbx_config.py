"""Sprint 71: PBX Config table for dialplan management.

The pbx_config table is created by Base.metadata.create_all() from the
PBXConfig model definition. This migration file exists for the registry
pattern in session.py and for future column additions.

This migration is idempotent — safe to run multiple times.
"""

import logging
from sqlalchemy.engine import Engine

log = logging.getLogger(__name__)


def run_migrations(engine: Engine) -> None:
    """Run Sprint 71 migrations.

    The pbx_config table is created by create_all(). This placeholder
    ensures the migration is registered in init_database() and provides
    a location for future schema changes.

    Args:
        engine: SQLAlchemy engine instance
    """
    backend = engine.url.get_backend_name()
    log.debug(f"Sprint 71 migration check (dialect: {backend}) — table created by create_all")
