"""ACDC credential parsing commands.

Commands:
    vvp acdc parse <input>  Parse ACDC credential
    vvp acdc type <input>   Detect credential type
"""

from typing import Any

import typer

from common.vvp.cli.output import OutputFormat, output, output_error
from common.vvp.cli.utils import (
    EXIT_PARSE_ERROR,
    dataclass_to_dict,
    read_json_input,
)

app = typer.Typer(
    name="acdc",
    help="Parse ACDC credentials.",
    no_args_is_help=True,
)


@app.command("parse")
def parse_cmd(
    source: str = typer.Argument(
        ...,
        help="JSON file path or '-' for stdin",
    ),
    format: OutputFormat = typer.Option(
        OutputFormat.json,
        "--format",
        "-f",
        help="Output format",
    ),
    validate_said: bool = typer.Option(
        False,
        "--validate-said",
        help="Compute and validate SAID",
    ),
    show_raw: bool = typer.Option(
        False,
        "--show-raw",
        help="Include raw parsed dictionary in output",
    ),
) -> None:
    """Parse an ACDC credential and display its structure.

    ACDCs (Authentic Chained Data Containers) are verifiable credentials
    in the KERI ecosystem. This command parses and displays their contents.

    Supports all ACDC variants:
    - full: Complete ACDC with expanded attributes
    - compact: Minimal ACDC with SAID references
    - partial: ACDC with selective disclosure

    Examples:
        cat credential.json | vvp acdc parse -
        vvp acdc parse le_credential.json --validate-said
        vvp acdc parse - --format pretty < acdc.json
    """
    from common.vvp.cli.adapters import ACDC, compute_acdc_said, detect_acdc_variant, parse_acdc

    # Read JSON input
    data = read_json_input(source)

    # Parse the ACDC
    try:
        acdc: ACDC = parse_acdc(data)
    except Exception as e:
        output_error(
            code="ACDC_PARSE_FAILED",
            message=str(e),
            exit_code=EXIT_PARSE_ERROR,
        )
        return

    # Build output
    result: dict[str, Any] = {
        "said": acdc.said,
        "issuer_aid": acdc.issuer_aid,
        "schema_said": acdc.schema_said,
        "credential_type": acdc.credential_type,
        "variant": acdc.variant,
        "is_root_credential": acdc.is_root_credential,
    }

    # Include attributes based on variant
    if acdc.attributes is not None:
        if isinstance(acdc.attributes, dict):
            result["attributes"] = acdc.attributes
        else:
            result["attributes_said"] = acdc.attributes

    # Include edges if present
    if acdc.edges:
        result["edges"] = acdc.edges

    # Include rules if present
    if acdc.rules:
        result["rules"] = acdc.rules

    # Validate SAID if requested
    if validate_said:
        try:
            computed_said = compute_acdc_said(data)
            result["said_validation"] = {
                "valid": acdc.said == computed_said,
                "expected": acdc.said,
                "computed": computed_said,
            }
        except Exception as e:
            result["said_validation"] = {
                "valid": False,
                "error": str(e),
            }

    if show_raw:
        result["raw"] = acdc.raw

    output(result, format)


@app.command("type")
def type_cmd(
    source: str = typer.Argument(
        ...,
        help="JSON file path or '-' for stdin",
    ),
    format: OutputFormat = typer.Option(
        OutputFormat.json,
        "--format",
        "-f",
        help="Output format",
    ),
) -> None:
    """Detect credential type from schema, edges, or attributes.

    Attempts to determine the credential type (LE, APE, DE, TNAlloc,
    OOR, QVI, etc.) based on schema SAID, edge structure, or attributes.

    Examples:
        cat credential.json | vvp acdc type -
        vvp acdc type unknown_cred.json
    """
    from common.vvp.cli.adapters import ACDC, detect_acdc_variant, parse_acdc

    # Read JSON input
    data = read_json_input(source)

    # Parse the ACDC
    try:
        acdc: ACDC = parse_acdc(data)
    except Exception as e:
        output_error(
            code="ACDC_PARSE_FAILED",
            message=str(e),
            exit_code=EXIT_PARSE_ERROR,
        )
        return

    # Get variant
    variant = detect_acdc_variant(data)

    # Determine confidence based on how type was inferred
    confidence = "high" if acdc.schema_said else "medium"
    source = "schema_said"

    # Check if type came from schema registry
    try:
        from common.vvp.schema.registry import is_known_schema

        if acdc.schema_said and is_known_schema(acdc.credential_type, acdc.schema_said):
            source = "schema_registry"
            confidence = "high"
    except ImportError:
        pass

    result: dict[str, Any] = {
        "type": acdc.credential_type,
        "confidence": confidence,
        "source": source,
        "variant": variant,
        "schema_said": acdc.schema_said,
    }

    # Include type hints from structure
    hints: list[str] = []
    if acdc.edges:
        if "qvi" in acdc.edges:
            hints.append("has_qvi_edge (suggests LE)")
        if "le" in acdc.edges:
            hints.append("has_le_edge (suggests APE/DE/TNAlloc)")
        if "auth" in acdc.edges:
            hints.append("has_auth_edge (suggests OOR/ECR)")
    if acdc.attributes and isinstance(acdc.attributes, dict):
        if "LEI" in acdc.attributes:
            hints.append("has_LEI_attribute (suggests LE)")
        if "AID" in acdc.attributes:
            hints.append("has_AID_attribute (suggests APE/DE)")
        if "tn" in acdc.attributes or "TN" in acdc.attributes:
            hints.append("has_TN_attribute (suggests TNAlloc)")

    if hints:
        result["hints"] = hints

    output(result, format)


if __name__ == "__main__":
    app()
