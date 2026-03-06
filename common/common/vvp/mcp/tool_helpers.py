"""Input resolution and error formatting helpers for MCP tools.

Translates MCP tool parameters into formats the adapter layer expects.
MCP tools receive string parameters; these helpers resolve them to the
appropriate Python types (file contents, decoded bytes, parsed JSON).
"""

import base64
import json
from pathlib import Path
from typing import Any


def resolve_text_input(value: str) -> str:
    """Resolve a text input that may be a file path or literal string.

    If the value is an absolute path to an existing file, read and return
    its contents. Otherwise return the value as-is (JWT string, header, etc.).
    """
    if value.startswith("/"):
        path = Path(value)
        if path.exists() and path.is_file():
            return path.read_text(encoding="utf-8")
    return value


def resolve_binary_input(value: str) -> bytes:
    """Resolve binary input that may be a file path, base64, or UTF-8 text.

    Strategy:
    1. If it's an absolute path to an existing file, read bytes from disk
    2. If it doesn't look like JSON, try base64 decoding
    3. Fall back to UTF-8 encoding (for JSON dossiers passed as strings)
    """
    # Check file path first
    if value.startswith("/"):
        path = Path(value)
        if path.exists() and path.is_file():
            return path.read_bytes()

    # Try base64 decode (skip if it looks like JSON)
    stripped = value.strip()
    if not stripped.startswith(("{", "[")):
        try:
            decoded = base64.b64decode(stripped, validate=True)
            if len(decoded) > 0:
                return decoded
        except Exception:
            pass

    return value.encode("utf-8")


def parse_json_param(value: str) -> dict[str, Any]:
    """Parse a JSON string parameter, with file path fallback.

    Resolves the input as text first (checking for file paths),
    then parses the result as JSON.
    """
    resolved = resolve_text_input(value)
    return json.loads(resolved)


def error_result(
    code: str,
    message: str,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Create a standardized error result dict for MCP tool responses."""
    result: dict[str, Any] = {
        "error": True,
        "code": code,
        "message": message,
    }
    if details:
        result["details"] = details
    return result
