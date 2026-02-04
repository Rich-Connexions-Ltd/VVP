"""VVP CLI Tools - Chainable command-line utilities for KERI/ACDC/VVP parsing.

This package provides a unified `vvp` command with subcommands for parsing
and managing JWTs, SAIDs, ACDCs, CESR streams, and dossiers.

Usage:
    vvp --help              # Show all available commands
    vvp jwt parse <token>   # Parse a JWT/PASSporT
    vvp said compute -      # Compute SAID from stdin
    vvp dossier parse -     # Parse dossier from stdin

Installation:
    pip install -e services/verifier && pip install -e 'common[cli]'
"""

from common.vvp.cli.main import app

__all__ = ["app"]
