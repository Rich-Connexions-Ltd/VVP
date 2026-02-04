"""JWT/PASSporT parsing commands.

Commands:
    vvp jwt parse <token>     Parse JWT structure
    vvp jwt validate <token>  Validate JWT with optional binding
"""

from typing import Any, Optional

import typer

from common.vvp.cli.output import OutputFormat, output, output_error
from common.vvp.cli.utils import (
    EXIT_PARSE_ERROR,
    EXIT_VALIDATION_FAILURE,
    dataclass_to_dict,
    read_input,
)

app = typer.Typer(
    name="jwt",
    help="Parse and validate JWT/PASSporT tokens.",
    no_args_is_help=True,
)


@app.command("parse")
def parse_cmd(
    source: str = typer.Argument(
        ...,
        help="JWT token, file path, or '-' for stdin",
    ),
    format: OutputFormat = typer.Option(
        OutputFormat.json,
        "--format",
        "-f",
        help="Output format",
    ),
    show_raw: bool = typer.Option(
        False,
        "--show-raw",
        help="Include raw base64 parts in output",
    ),
    no_validate: bool = typer.Option(
        False,
        "--no-validate",
        help="Skip validation, parse structure only",
    ),
) -> None:
    """Parse a JWT/PASSporT token and display its structure.

    The token can be provided as:
    - A literal JWT string (header.payload.signature)
    - A file path containing the JWT
    - '-' to read from stdin

    Examples:
        vvp jwt parse "eyJhbGciOiJFZERTQSI..."
        vvp jwt parse token.jwt
        cat token.jwt | vvp jwt parse -
    """
    from common.vvp.cli.adapters import Passport, parse_passport

    # Read input
    jwt_string = read_input(source, binary=False)
    jwt_string = jwt_string.strip()

    # Parse the JWT
    try:
        passport: Passport = parse_passport(jwt_string)
    except Exception as e:
        output_error(
            code="PASSPORT_PARSE_FAILED",
            message=str(e),
            exit_code=EXIT_PARSE_ERROR,
        )
        return  # unreachable, but helps type checker

    # Build output
    result: dict[str, Any] = {
        "header": dataclass_to_dict(passport.header),
        "payload": dataclass_to_dict(passport.payload),
        "signature": {
            "bytes": passport.signature.hex() if passport.signature else None,
            "length": len(passport.signature) if passport.signature else 0,
        },
        "warnings": list(passport.warnings) if passport.warnings else [],
    }

    if show_raw:
        result["raw"] = {
            "header": passport.raw_header,
            "payload": passport.raw_payload,
        }

    output(result, format)


@app.command("validate")
def validate_cmd(
    source: str = typer.Argument(
        ...,
        help="JWT token, file path, or '-' for stdin",
    ),
    identity_header: Optional[str] = typer.Option(
        None,
        "--identity",
        "-i",
        help="VVP-Identity header for binding validation",
    ),
    now: Optional[int] = typer.Option(
        None,
        "--now",
        help="Override current time (Unix timestamp) for testing",
    ),
    format: OutputFormat = typer.Option(
        OutputFormat.json,
        "--format",
        "-f",
        help="Output format",
    ),
    strict: bool = typer.Option(
        False,
        "--strict",
        help="Fail on any warnings",
    ),
) -> None:
    """Validate a JWT/PASSporT token.

    Performs structural validation and optionally validates binding
    against a VVP-Identity header.

    Examples:
        vvp jwt validate token.jwt
        vvp jwt validate token.jwt --identity "eyJwcHQi..."
        cat token.jwt | vvp jwt validate - --strict
    """
    from common.vvp.cli.adapters import parse_passport, parse_vvp_identity

    # Read input
    jwt_string = read_input(source, binary=False)
    jwt_string = jwt_string.strip()

    errors: list[str] = []
    warnings: list[str] = []

    # Parse the JWT
    try:
        passport = parse_passport(jwt_string)
        warnings.extend(passport.warnings)
    except Exception as e:
        output_error(
            code="PASSPORT_PARSE_FAILED",
            message=str(e),
            exit_code=EXIT_PARSE_ERROR,
        )
        return

    # Parse VVP-Identity if provided
    vvp_identity = None
    if identity_header:
        try:
            vvp_identity = parse_vvp_identity(identity_header)
        except Exception as e:
            errors.append(f"VVP-Identity parse failed: {e}")

    # Validate binding if we have both
    if vvp_identity and passport:
        try:
            from common.vvp.cli.adapters import validate_passport_binding

            validate_passport_binding(passport, vvp_identity, now=now)
        except Exception as e:
            errors.append(f"Binding validation failed: {e}")

    # Determine validity
    is_valid = len(errors) == 0 and (not strict or len(warnings) == 0)

    result: dict[str, Any] = {
        "valid": is_valid,
        "errors": errors,
        "warnings": warnings,
    }

    output(result, format)

    if not is_valid:
        raise typer.Exit(EXIT_VALIDATION_FAILURE)


if __name__ == "__main__":
    app()
