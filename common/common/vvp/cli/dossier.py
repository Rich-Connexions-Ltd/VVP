"""Dossier parsing and analysis commands.

Commands:
    vvp dossier parse <input>     Parse dossier to ACDCs
    vvp dossier validate <input>  Validate DAG structure
    vvp dossier fetch <url>       Fetch and parse from URL
"""

from typing import Any, Optional

import typer

from common.vvp.cli.output import OutputFormat, output, output_error
from common.vvp.cli.utils import (
    EXIT_IO_ERROR,
    EXIT_PARSE_ERROR,
    EXIT_VALIDATION_FAILURE,
    dataclass_to_dict,
    read_input,
    run_async,
)

app = typer.Typer(
    name="dossier",
    help="Parse and analyze dossiers (credential bundles).",
    no_args_is_help=True,
)


@app.command("parse")
def parse_cmd(
    source: str = typer.Argument(
        ...,
        help="Dossier file path (JSON or CESR) or '-' for stdin",
    ),
    format: OutputFormat = typer.Option(
        OutputFormat.json,
        "--format",
        "-f",
        help="Output format",
    ),
) -> None:
    """Parse a dossier into individual ACDCs.

    Supports multiple dossier formats:
    - Single ACDC object: {...}
    - Array of ACDC objects: [{...}, {...}]
    - CESR stream with attachments: {...}-A##<sig>...
    - Provenant wrapper format: {"details": "...CESR content..."}

    Examples:
        cat dossier.cesr | vvp dossier parse -
        vvp dossier parse credentials.json
        vvp dossier parse - --format table < dossier.json
    """
    from common.vvp.cli.adapters import ACDCNode, parse_dossier

    # Read binary input (to handle CESR)
    data = read_input(source, binary=True)
    if isinstance(data, str):
        data = data.encode("utf-8")

    # Parse the dossier
    try:
        nodes, signatures = parse_dossier(data)
    except Exception as e:
        output_error(
            code="DOSSIER_PARSE_FAILED",
            message=str(e),
            exit_code=EXIT_PARSE_ERROR,
        )
        return

    # Build output
    credentials: list[dict[str, Any]] = []
    for node in nodes:
        cred_data: dict[str, Any] = {
            "said": node.said,
            "issuer": node.issuer,
            "schema": node.schema,
        }
        if node.attributes:
            cred_data["attributes"] = node.attributes
        if node.edges:
            cred_data["edges"] = node.edges

        # Check if we have a signature for this credential
        if node.said in signatures:
            cred_data["has_signature"] = True
            cred_data["signature_bytes"] = len(signatures[node.said])

        credentials.append(cred_data)

    # Detect format
    detected_format = "json"
    if data.startswith(b"{") and b"-A" in data:
        detected_format = "cesr"
    elif data.strip().startswith(b"["):
        detected_format = "json_array"

    result: dict[str, Any] = {
        "credentials": credentials,
        "credential_count": len(credentials),
        "format": detected_format,
        "signatures_extracted": len(signatures),
    }

    output(result, format)


@app.command("validate")
def validate_cmd(
    source: str = typer.Argument(
        ...,
        help="Dossier file path or '-' for stdin",
    ),
    format: OutputFormat = typer.Option(
        OutputFormat.json,
        "--format",
        "-f",
        help="Output format",
    ),
    allow_aggregate: bool = typer.Option(
        False,
        "--allow-aggregate",
        help="Allow multiple root credentials (aggregate dossiers)",
    ),
) -> None:
    """Validate dossier DAG structure.

    Checks:
    - No cycles in credential chain
    - Exactly one root node (or multiple for aggregate dossiers)
    - ToIP spec compliance (warnings)

    Examples:
        cat dossier.json | vvp dossier validate -
        vvp dossier validate credentials.cesr --allow-aggregate
    """
    from common.vvp.cli.adapters import (
        DossierWarning,
        build_dag,
        detect_cycle,
        find_roots,
        parse_dossier,
        validate_dag,
    )

    # Read binary input
    data = read_input(source, binary=True)
    if isinstance(data, str):
        data = data.encode("utf-8")

    # Parse the dossier
    try:
        nodes, _ = parse_dossier(data)
    except Exception as e:
        output_error(
            code="DOSSIER_PARSE_FAILED",
            message=str(e),
            exit_code=EXIT_PARSE_ERROR,
        )
        return

    # Build DAG
    try:
        dag = build_dag(nodes)
    except Exception as e:
        output_error(
            code="DOSSIER_DAG_FAILED",
            message=str(e),
            exit_code=EXIT_PARSE_ERROR,
        )
        return

    # Validate DAG
    errors: list[str] = []
    try:
        validate_dag(dag, allow_aggregate=allow_aggregate)
    except Exception as e:
        errors.append(str(e))

    # Check for cycles
    cycle = detect_cycle(dag)
    if cycle:
        errors.append(f"Cycle detected: {' -> '.join(cycle)}")

    # Find roots
    roots = find_roots(dag, allow_multiple=allow_aggregate)

    # Collect warnings
    warnings: list[dict[str, Any]] = []
    if dag.warnings:
        for w in dag.warnings:
            warnings.append({
                "code": w.code.value if hasattr(w.code, "value") else str(w.code),
                "message": w.message,
                "credential_said": w.credential_said,
            })

    is_valid = len(errors) == 0

    result: dict[str, Any] = {
        "valid": is_valid,
        "root_saids": roots,
        "is_aggregate": len(roots) > 1,
        "node_count": len(dag.nodes),
        "cycle_detected": cycle is not None,
        "errors": errors,
        "warnings": warnings,
    }

    output(result, format)

    if not is_valid:
        raise typer.Exit(EXIT_VALIDATION_FAILURE)


@app.command("fetch")
def fetch_cmd(
    url: str = typer.Argument(
        ...,
        help="Dossier URL to fetch",
    ),
    format: OutputFormat = typer.Option(
        OutputFormat.json,
        "--format",
        "-f",
        help="Output format",
    ),
) -> None:
    """Fetch a dossier from URL and parse it.

    Fetches the dossier and parses it like the 'parse' command.

    Examples:
        vvp dossier fetch "https://evd.example.com/dossier/ENPXp1vQ..."
        vvp jwt parse token.jwt | jq -r '.payload.evd' | xargs vvp dossier fetch
    """
    from common.vvp.cli.adapters import fetch_dossier, parse_dossier

    # Fetch the dossier
    try:
        data = run_async(fetch_dossier(url))
    except Exception as e:
        output_error(
            code="DOSSIER_FETCH_FAILED",
            message=str(e),
            details={"url": url},
            exit_code=EXIT_IO_ERROR,
        )
        return

    # Parse the dossier
    try:
        nodes, signatures = parse_dossier(data)
    except Exception as e:
        output_error(
            code="DOSSIER_PARSE_FAILED",
            message=str(e),
            exit_code=EXIT_PARSE_ERROR,
        )
        return

    # Build output (same as parse command)
    credentials: list[dict[str, Any]] = []
    for node in nodes:
        cred_data: dict[str, Any] = {
            "said": node.said,
            "issuer": node.issuer,
            "schema": node.schema,
        }
        if node.attributes:
            cred_data["attributes"] = node.attributes
        if node.edges:
            cred_data["edges"] = node.edges
        if node.said in signatures:
            cred_data["has_signature"] = True

        credentials.append(cred_data)

    result: dict[str, Any] = {
        "credentials": credentials,
        "credential_count": len(credentials),
        "signatures_extracted": len(signatures),
        "source_url": url,
    }

    output(result, format)


if __name__ == "__main__":
    app()
