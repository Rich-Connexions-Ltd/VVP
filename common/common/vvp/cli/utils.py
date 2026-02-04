"""Shared utilities for VVP CLI tools.

This module provides common functionality for:
- Reading input from stdin, files, or arguments
- Running async functions from sync CLI context
- Error handling and exit codes
"""

import asyncio
import json
import sys
from pathlib import Path
from typing import Any, Coroutine, Optional, TypeVar, Union

import typer

# Exit codes
EXIT_SUCCESS = 0
EXIT_VALIDATION_FAILURE = 1
EXIT_PARSE_ERROR = 2
EXIT_IO_ERROR = 3

T = TypeVar("T")


def run_async(coro: Coroutine[Any, Any, T]) -> T:
    """Run async function from sync CLI context.

    Args:
        coro: Coroutine to execute

    Returns:
        Result of the coroutine
    """
    return asyncio.run(coro)


def read_input(
    source: str,
    binary: bool = False,
    encoding: str = "utf-8",
) -> Union[str, bytes]:
    """Read input from stdin, file, or argument.

    Args:
        source: Input source - "-" for stdin, file path, or literal value
        binary: If True, read as bytes (for CESR streams)
        encoding: Text encoding (ignored if binary=True)

    Returns:
        Content as string or bytes depending on binary flag

    Raises:
        typer.Exit: On I/O errors with appropriate exit code
    """
    try:
        if source == "-":
            # Read from stdin
            if binary:
                return sys.stdin.buffer.read()
            return sys.stdin.read()

        path = Path(source)
        if path.exists() and path.is_file():
            # Read from file
            if binary:
                return path.read_bytes()
            return path.read_text(encoding=encoding)

        # Treat as literal value (for JWT strings, etc.)
        if binary:
            return source.encode(encoding)
        return source

    except IOError as e:
        typer.echo(f"Error reading input: {e}", err=True)
        raise typer.Exit(EXIT_IO_ERROR) from e


def read_json_input(source: str) -> dict[str, Any]:
    """Read JSON input from stdin, file, or argument.

    Args:
        source: Input source - "-" for stdin, file path, or JSON string

    Returns:
        Parsed JSON as dictionary

    Raises:
        typer.Exit: On I/O or parse errors
    """
    content = read_input(source, binary=False)

    try:
        return json.loads(content)
    except json.JSONDecodeError as e:
        typer.echo(f"Invalid JSON: {e}", err=True)
        raise typer.Exit(EXIT_PARSE_ERROR) from e


def is_json_string(value: str) -> bool:
    """Check if a string appears to be JSON (starts with { or [).

    Args:
        value: String to check

    Returns:
        True if the string looks like JSON
    """
    stripped = value.strip()
    return stripped.startswith("{") or stripped.startswith("[")


def detect_input_type(source: str) -> str:
    """Detect the type of input (json, jwt, base64, cesr, file).

    Args:
        source: Input source string

    Returns:
        One of: "stdin", "file", "json", "jwt", "base64", "unknown"
    """
    if source == "-":
        return "stdin"

    path = Path(source)
    if path.exists() and path.is_file():
        return "file"

    stripped = source.strip()

    # JSON detection
    if stripped.startswith("{") or stripped.startswith("["):
        return "json"

    # JWT detection (3 base64url parts separated by dots)
    if stripped.count(".") == 2:
        parts = stripped.split(".")
        if all(len(p) > 0 for p in parts):
            return "jwt"

    # Base64url detection (used for VVP-Identity headers)
    if len(stripped) > 10 and all(c.isalnum() or c in "-_=" for c in stripped):
        return "base64"

    return "unknown"


def error_response(
    code: str,
    message: str,
    details: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Create a standardized error response.

    Args:
        code: Error code (e.g., "PASSPORT_PARSE_FAILED")
        message: Human-readable error message
        details: Optional additional details

    Returns:
        Error response dictionary
    """
    response: dict[str, Any] = {
        "error": True,
        "code": code,
        "message": message,
    }
    if details:
        response["details"] = details
    return response


def dataclass_to_dict(obj: Any) -> dict[str, Any]:
    """Convert a dataclass to a dictionary, handling nested dataclasses.

    Args:
        obj: Dataclass instance or any object

    Returns:
        Dictionary representation
    """
    from dataclasses import asdict, is_dataclass

    if is_dataclass(obj) and not isinstance(obj, type):
        return asdict(obj)
    if isinstance(obj, dict):
        return {k: dataclass_to_dict(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [dataclass_to_dict(item) for item in obj]  # type: ignore
    if isinstance(obj, bytes):
        return obj.hex()
    return obj
