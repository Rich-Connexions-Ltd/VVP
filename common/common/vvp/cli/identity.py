"""VVP-Identity header parsing commands.

Commands:
    vvp identity parse <header>  Parse VVP-Identity header
"""

from typing import Any

import typer

from common.vvp.cli.output import OutputFormat, output, output_error
from common.vvp.cli.utils import (
    EXIT_PARSE_ERROR,
    dataclass_to_dict,
    read_input,
)

app = typer.Typer(
    name="identity",
    help="Parse VVP-Identity headers.",
    no_args_is_help=True,
)


@app.command("parse")
def parse_cmd(
    source: str = typer.Argument(
        ...,
        help="Base64url-encoded VVP-Identity header, file path, or '-' for stdin",
    ),
    format: OutputFormat = typer.Option(
        OutputFormat.json,
        "--format",
        "-f",
        help="Output format",
    ),
) -> None:
    """Parse a VVP-Identity header and display its contents.

    The header is a base64url-encoded JSON object containing:
    - ppt: PASSporT type (must be "vvp")
    - kid: Key identifier (AID or OOBI URL)
    - evd: Evidence URL (dossier location)
    - iat: Issued-at timestamp
    - exp: Expiration timestamp (optional)

    Examples:
        vvp identity parse "eyJwcHQiOiJ2dnAi..."
        vvp identity parse header.txt
        cat header.txt | vvp identity parse -
    """
    from common.vvp.cli.adapters import parse_vvp_identity

    # Read input
    header_string = read_input(source, binary=False)
    header_string = header_string.strip()

    # Parse the header
    try:
        identity = parse_vvp_identity(header_string)
    except Exception as e:
        output_error(
            code="IDENTITY_PARSE_FAILED",
            message=str(e),
            exit_code=EXIT_PARSE_ERROR,
        )
        return

    # Build output
    result: dict[str, Any] = dataclass_to_dict(identity)

    output(result, format)


if __name__ == "__main__":
    app()
