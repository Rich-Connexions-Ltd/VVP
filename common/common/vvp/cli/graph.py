"""Credential graph building commands.

Commands:
    vvp graph build <input>  Build credential graph from dossier
"""

from typing import Any, Optional

import typer

from common.vvp.cli.output import OutputFormat, output, output_error
from common.vvp.cli.utils import (
    EXIT_PARSE_ERROR,
    read_input,
)

app = typer.Typer(
    name="graph",
    help="Build credential graphs from dossiers.",
    no_args_is_help=True,
)


@app.command("build")
def build_cmd(
    source: str = typer.Argument(
        ...,
        help="Dossier file path or '-' for stdin",
    ),
    trusted_roots: Optional[str] = typer.Option(
        None,
        "--trusted-roots",
        "-r",
        help="Comma-separated trusted root AIDs",
    ),
    format: OutputFormat = typer.Option(
        OutputFormat.json,
        "--format",
        "-f",
        help="Output format",
    ),
) -> None:
    """Build a credential graph from a dossier.

    Creates a graph structure suitable for visualization, with nodes
    representing credentials and edges representing chain relationships.

    The graph includes:
    - Credential nodes with type, status, and attributes
    - Chain edges between credentials
    - Trust path validation against trusted roots
    - Hierarchical layers (root -> leaf)

    Examples:
        cat dossier.json | vvp graph build -
        vvp graph build dossier.cesr --trusted-roots "DER2Rc...,DFG4Xy..."
    """
    from common.vvp.cli.adapters import (
        ACDC,
        build_credential_graph,
        credential_graph_to_dict,
        parse_acdc,
        parse_dossier,
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

    # Convert ACDCNodes to ACDCs for the graph builder
    dossier_acdcs: dict[str, ACDC] = {}
    for node in nodes:
        try:
            acdc = parse_acdc(node.raw)
            dossier_acdcs[acdc.said] = acdc
        except Exception:
            # Skip nodes that fail to parse as full ACDCs
            pass

    # Parse trusted roots
    roots: set[str] = set()
    if trusted_roots:
        roots = {r.strip() for r in trusted_roots.split(",") if r.strip()}

    # Build graph
    try:
        graph = build_credential_graph(
            dossier_acdcs=dossier_acdcs,
            trusted_roots=roots,
        )
    except Exception as e:
        output_error(
            code="GRAPH_BUILD_FAILED",
            message=str(e),
            exit_code=EXIT_PARSE_ERROR,
        )
        return

    # Convert to dict for output
    result = credential_graph_to_dict(graph)

    output(result, format)


if __name__ == "__main__":
    app()
