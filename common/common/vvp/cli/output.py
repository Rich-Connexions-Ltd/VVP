"""Output formatting utilities for VVP CLI tools.

Supports three output formats:
- json: Machine-readable JSON (default, for piping)
- pretty: Indented JSON for human reading
- table: Rich tables for list data
"""

import json
import sys
from enum import Enum
from typing import Any, Optional, Sequence

import typer

# Try to import rich for table output
try:
    from rich.console import Console
    from rich.table import Table

    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


class OutputFormat(str, Enum):
    """Output format options."""

    json = "json"
    pretty = "pretty"
    table = "table"


def output_json(data: Any, pretty: bool = False) -> None:
    """Output data as JSON to stdout.

    Args:
        data: Data to output (must be JSON-serializable)
        pretty: If True, output with indentation
    """
    indent = 2 if pretty else None
    try:
        print(json.dumps(data, indent=indent, default=str))
    except TypeError as e:
        typer.echo(f"Error serializing output: {e}", err=True)
        raise typer.Exit(2) from e


def output_table(
    data: Sequence[dict[str, Any]],
    columns: Optional[list[str]] = None,
    title: Optional[str] = None,
) -> None:
    """Output data as a rich table.

    Args:
        data: List of dictionaries to display
        columns: Column names to display (defaults to all keys from first row)
        title: Optional table title

    Falls back to JSON if rich is not available.
    """
    if not RICH_AVAILABLE:
        typer.echo("Table output requires 'rich' package. Falling back to JSON.", err=True)
        output_json(list(data), pretty=True)
        return

    if not data:
        typer.echo("No data to display.", err=True)
        return

    # Determine columns
    if columns is None:
        columns = list(data[0].keys())

    # Create table
    console = Console()
    table = Table(title=title, show_header=True, header_style="bold")

    for col in columns:
        table.add_column(col)

    for row in data:
        values = [str(row.get(col, "")) for col in columns]
        table.add_row(*values)

    console.print(table)


def output(
    data: Any,
    format: OutputFormat = OutputFormat.json,
    table_columns: Optional[list[str]] = None,
    table_title: Optional[str] = None,
) -> None:
    """Output data in the specified format.

    Args:
        data: Data to output
        format: Output format (json, pretty, or table)
        table_columns: Columns to display for table format
        table_title: Title for table format
    """
    if format == OutputFormat.json:
        output_json(data, pretty=False)
    elif format == OutputFormat.pretty:
        output_json(data, pretty=True)
    elif format == OutputFormat.table:
        # Table format requires list data
        if isinstance(data, list):
            output_table(data, columns=table_columns, title=table_title)
        elif isinstance(data, dict):
            # Convert single dict to list of key-value pairs
            items = [{"key": k, "value": str(v)} for k, v in data.items()]
            output_table(items, columns=["key", "value"], title=table_title)
        else:
            typer.echo("Table format requires list or dict data. Falling back to JSON.", err=True)
            output_json(data, pretty=True)


def output_error(
    code: str,
    message: str,
    details: Optional[dict[str, Any]] = None,
    exit_code: int = 1,
) -> None:
    """Output an error and exit.

    Args:
        code: Error code
        message: Error message
        details: Optional error details
        exit_code: Exit code to use
    """
    error_data: dict[str, Any] = {
        "error": True,
        "code": code,
        "message": message,
    }
    if details:
        error_data["details"] = details

    # Always output errors as JSON to stderr
    print(json.dumps(error_data), file=sys.stderr)
    raise typer.Exit(exit_code)
