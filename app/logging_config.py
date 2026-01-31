"""Logging Configuration.

COMPATIBILITY SHIM: This module re-exports from common.vvp.core.logging.
The actual implementation has been moved to the shared common/ package.

For new code, import directly from common.vvp.core:
    from common.vvp.core import configure_logging, JsonFormatter
"""

# Re-export from common package
from common.vvp.core.logging import (
    JsonFormatter,
    configure_logging,
)

__all__ = [
    "JsonFormatter",
    "configure_logging",
]
