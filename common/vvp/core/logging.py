"""Shared logging configuration.

Provides JSON-formatted logging for VVP services.

This module is shared between verifier and issuer services.
"""

import json
import logging
import os
import sys
from datetime import datetime, timezone


class JsonFormatter(logging.Formatter):
    """JSON log formatter for structured logging."""

    def format(self, record):
        payload = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for k in ("request_id", "route", "remote_addr"):
            if hasattr(record, k):
                payload[k] = getattr(record, k)
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def configure_logging(
    log_file: str = None,
    log_level: str = None,
):
    """Configure logging with JSON formatter.

    Args:
        log_file: Path to log file. Defaults to VVP_LOG_FILE env var or 'vvp_debug.log'.
        log_level: Log level. Defaults to VVP_LOG_LEVEL env var or 'INFO'.
    """
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(JsonFormatter())

    # File handler for debugging (always append)
    log_file = log_file or os.getenv("VVP_LOG_FILE", "vvp_debug.log")
    file_handler = logging.FileHandler(log_file, mode='a')
    file_handler.setFormatter(JsonFormatter())

    root = logging.getLogger()
    # Allow DEBUG level via environment variable (default: INFO)
    log_level = log_level or os.getenv("VVP_LOG_LEVEL", "INFO").upper()
    root.setLevel(getattr(logging, log_level, logging.INFO))
    root.handlers = [console_handler, file_handler]
