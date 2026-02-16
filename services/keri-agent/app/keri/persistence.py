"""Persistence management for VVP KERI Agent data.

Manages storage paths for KERI identity data including keystores and databases.
Ensures directory structure exists and provides path accessors.
"""
import logging
from pathlib import Path
from typing import Optional

from app import config

log = logging.getLogger(__name__)


class PersistenceManager:
    """Manages storage paths for KERI identity data.

    Ensures directory structure exists and provides path accessors
    for keystores and databases.
    """

    def __init__(self, base_dir: Optional[Path] = None):
        """Initialize persistence manager.

        Args:
            base_dir: Override base directory (for testing)
        """
        self._base_dir = base_dir or config.DATA_DIR
        self._initialized = False

    def initialize(self) -> None:
        """Create required directories if they don't exist."""
        if self._initialized:
            return

        self.keystore_dir.mkdir(parents=True, exist_ok=True)
        self.database_dir.mkdir(parents=True, exist_ok=True)
        self._initialized = True
        log.info(f"Persistence initialized at {self._base_dir}")

    @property
    def base_dir(self) -> Path:
        """Base directory for all agent data."""
        return self._base_dir

    @property
    def keystore_dir(self) -> Path:
        """Directory for KERI keystores."""
        return self._base_dir / "keystores"

    @property
    def database_dir(self) -> Path:
        """Directory for KERI databases."""
        return self._base_dir / "databases"

    def identity_path(self, name: str) -> Path:
        """Get path for a specific identity's data."""
        return self._base_dir / "identities" / name


# Module-level singleton
_persistence_manager: Optional[PersistenceManager] = None


def get_persistence_manager() -> PersistenceManager:
    """Get or create the persistence manager singleton."""
    global _persistence_manager
    if _persistence_manager is None:
        _persistence_manager = PersistenceManager()
        _persistence_manager.initialize()
    return _persistence_manager


def reset_persistence_manager() -> None:
    """Reset the singleton (for testing)."""
    global _persistence_manager
    _persistence_manager = None
