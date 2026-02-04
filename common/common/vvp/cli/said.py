"""SAID computation and validation commands.

Commands:
    vvp said compute <input>   Compute SAID for a structure
    vvp said validate <input>  Validate existing SAID
    vvp said inject <input>    Inject computed SAID into structure
"""

import json
from enum import Enum
from typing import Any

import typer

from common.vvp.cli.output import OutputFormat, output, output_error
from common.vvp.cli.utils import (
    EXIT_PARSE_ERROR,
    EXIT_VALIDATION_FAILURE,
    read_json_input,
)

app = typer.Typer(
    name="said",
    help="Compute and validate SAIDs (Self-Addressing Identifiers).",
    no_args_is_help=True,
)


class SAIDType(str, Enum):
    """SAID computation type."""

    acdc = "acdc"
    kel = "kel"
    schema = "schema"
    auto = "auto"


def _detect_type(data: dict[str, Any]) -> SAIDType:
    """Auto-detect the type of structure for SAID computation.

    Args:
        data: JSON structure

    Returns:
        Detected SAIDType
    """
    # ACDC: has version string starting with ACDC
    if "v" in data and isinstance(data.get("v"), str) and data["v"].startswith("ACDC"):
        return SAIDType.acdc

    # Schema: has $schema or $id fields
    if "$schema" in data or "$id" in data:
        return SAIDType.schema

    # KEL: has event type field 't'
    if "t" in data and data.get("t") in ("icp", "rot", "ixn", "dip", "drt", "vcp", "vrt", "iss", "rev"):
        return SAIDType.kel

    # Default to ACDC for generic JSON with 'd' field
    if "d" in data:
        return SAIDType.acdc

    return SAIDType.acdc


@app.command("compute")
def compute_cmd(
    source: str = typer.Argument(
        ...,
        help="JSON file path or '-' for stdin",
    ),
    type: SAIDType = typer.Option(
        SAIDType.auto,
        "--type",
        "-t",
        help="Structure type for canonicalization (auto-detect if not specified)",
    ),
    field: str = typer.Option(
        "d",
        "--field",
        help="SAID field name (default: 'd', schema uses '$id')",
    ),
    format: OutputFormat = typer.Option(
        OutputFormat.json,
        "--format",
        "-f",
        help="Output format",
    ),
) -> None:
    """Compute SAID for a JSON structure.

    Different structure types use different canonicalization rules:
    - acdc: ACDC field order (v, d, i, s, a, e, r)
    - kel: KERI event field order (v, t, d, i, s, ...)
    - schema: JSON Schema SAID computation

    Examples:
        cat acdc.json | vvp said compute - --type acdc
        vvp said compute event.json --type kel
        vvp said compute schema.json --type schema --field '$id'
    """
    # Read JSON input
    data = read_json_input(source)

    # Auto-detect type if needed
    actual_type = type if type != SAIDType.auto else _detect_type(data)

    # Override field for schema type
    if actual_type == SAIDType.schema and field == "d":
        field = "$id"

    # Compute SAID based on type
    try:
        if actual_type == SAIDType.acdc:
            from common.vvp.cli.adapters import compute_acdc_said

            said = compute_acdc_said(data, said_field=field)
        elif actual_type == SAIDType.kel:
            from common.vvp.cli.adapters import compute_kel_event_said

            said = compute_kel_event_said(data)
        elif actual_type == SAIDType.schema:
            from common.vvp.cli.adapters import compute_schema_said

            said = compute_schema_said(data)
        else:
            output_error(
                code="SAID_COMPUTE_FAILED",
                message=f"Unknown SAID type: {actual_type}",
                exit_code=EXIT_PARSE_ERROR,
            )
            return
    except Exception as e:
        output_error(
            code="SAID_COMPUTE_FAILED",
            message=str(e),
            exit_code=EXIT_PARSE_ERROR,
        )
        return

    result: dict[str, Any] = {
        "said": said,
        "algorithm": "blake3-256",
        "type": actual_type.value,
        "field": field,
    }

    output(result, format)


@app.command("validate")
def validate_cmd(
    source: str = typer.Argument(
        ...,
        help="JSON file path or '-' for stdin",
    ),
    type: SAIDType = typer.Option(
        SAIDType.auto,
        "--type",
        "-t",
        help="Structure type for canonicalization",
    ),
    field: str = typer.Option(
        "d",
        "--field",
        help="SAID field name to validate",
    ),
    format: OutputFormat = typer.Option(
        OutputFormat.json,
        "--format",
        "-f",
        help="Output format",
    ),
) -> None:
    """Validate that a structure's SAID field matches computed SAID.

    Examples:
        cat acdc.json | vvp said validate - --type acdc
        vvp said validate event.json --type kel
    """
    # Read JSON input
    data = read_json_input(source)

    # Auto-detect type if needed
    actual_type = type if type != SAIDType.auto else _detect_type(data)

    # Override field for schema type
    if actual_type == SAIDType.schema and field == "d":
        field = "$id"

    # Get expected SAID from data
    expected = data.get(field)
    if not expected:
        output_error(
            code="SAID_VALIDATE_FAILED",
            message=f"No '{field}' field found in input",
            exit_code=EXIT_VALIDATION_FAILURE,
        )
        return

    # Compute SAID
    try:
        if actual_type == SAIDType.acdc:
            from common.vvp.cli.adapters import compute_acdc_said

            computed = compute_acdc_said(data, said_field=field)
        elif actual_type == SAIDType.kel:
            from common.vvp.cli.adapters import compute_kel_event_said

            computed = compute_kel_event_said(data)
        elif actual_type == SAIDType.schema:
            from common.vvp.cli.adapters import compute_schema_said

            computed = compute_schema_said(data)
        else:
            output_error(
                code="SAID_VALIDATE_FAILED",
                message=f"Unknown SAID type: {actual_type}",
                exit_code=EXIT_PARSE_ERROR,
            )
            return
    except Exception as e:
        output_error(
            code="SAID_COMPUTE_FAILED",
            message=str(e),
            exit_code=EXIT_PARSE_ERROR,
        )
        return

    is_valid = expected == computed

    result: dict[str, Any] = {
        "valid": is_valid,
        "expected": expected,
        "computed": computed,
        "type": actual_type.value,
        "field": field,
    }

    output(result, format)

    if not is_valid:
        raise typer.Exit(EXIT_VALIDATION_FAILURE)


@app.command("inject")
def inject_cmd(
    source: str = typer.Argument(
        ...,
        help="JSON file path or '-' for stdin",
    ),
    type: SAIDType = typer.Option(
        SAIDType.auto,
        "--type",
        "-t",
        help="Structure type for canonicalization",
    ),
    field: str = typer.Option(
        "d",
        "--field",
        help="SAID field name to inject",
    ),
) -> None:
    """Compute SAID and inject it into the structure.

    Outputs the modified JSON with the computed SAID in the specified field.

    Examples:
        cat schema.json | vvp said inject - --type schema > schema-with-said.json
        vvp said inject draft-acdc.json --type acdc
    """
    # Read JSON input
    data = read_json_input(source)

    # Auto-detect type if needed
    actual_type = type if type != SAIDType.auto else _detect_type(data)

    # Override field for schema type
    if actual_type == SAIDType.schema and field == "d":
        field = "$id"

    # Set placeholder for SAID computation
    placeholder = "#" * 44  # 44 chars for Blake3-256 SAID
    data[field] = placeholder

    # Compute SAID
    try:
        if actual_type == SAIDType.acdc:
            from common.vvp.cli.adapters import compute_acdc_said

            said = compute_acdc_said(data, said_field=field)
        elif actual_type == SAIDType.kel:
            from common.vvp.cli.adapters import compute_kel_event_said

            said = compute_kel_event_said(data)
        elif actual_type == SAIDType.schema:
            from common.vvp.cli.adapters import compute_schema_said

            said = compute_schema_said(data)
        else:
            output_error(
                code="SAID_INJECT_FAILED",
                message=f"Unknown SAID type: {actual_type}",
                exit_code=EXIT_PARSE_ERROR,
            )
            return
    except Exception as e:
        output_error(
            code="SAID_INJECT_FAILED",
            message=str(e),
            exit_code=EXIT_PARSE_ERROR,
        )
        return

    # Inject computed SAID
    data[field] = said

    # Output modified JSON (always as JSON for piping)
    print(json.dumps(data, indent=2))


if __name__ == "__main__":
    app()
