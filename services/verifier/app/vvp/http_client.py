"""Shared HTTP client — re-exported from common package.

Canonical implementation lives in common/common/vvp/http_client.py.
This module re-exports for backwards compatibility with existing verifier imports.

Sprint 78: Moved implementation to common; verifier re-exports.
"""
from common.vvp.http_client import (
    get_shared_client,
    close_shared_client,
    reset_shared_client,
)

__all__ = ["get_shared_client", "close_shared_client", "reset_shared_client"]
