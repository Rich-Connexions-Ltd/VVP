"""VVP CLI - Main entry point with subcommand registration.

This module defines the main typer app and registers all subcommands.
"""

import typer

# Main app
app = typer.Typer(
    name="vvp",
    help="VVP CLI Tools - Chainable utilities for KERI/ACDC/VVP parsing.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)


def version_callback(value: bool) -> None:
    """Show version and exit."""
    if value:
        typer.echo("vvp version 0.1.0")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        None,
        "--version",
        "-V",
        callback=version_callback,
        is_eager=True,
        help="Show version and exit.",
    ),
) -> None:
    """VVP CLI Tools - Chainable utilities for KERI/ACDC/VVP parsing.

    All commands support reading from stdin using '-' as the input argument.
    Output is JSON by default for easy piping between commands.

    Examples:
        vvp jwt parse token.jwt
        cat dossier.cesr | vvp dossier parse -
        vvp jwt parse - | jq '.payload.evd' | xargs vvp dossier fetch
    """
    pass


# Import and register subcommand modules
# Each module defines a typer.Typer() app that gets added here


def _register_subcommands() -> None:
    """Register all subcommand modules.

    This function imports subcommand modules lazily to avoid import
    errors if the verifier package is not installed. The import error
    will be raised when the user actually tries to use a command.
    """
    try:
        from common.vvp.cli import jwt

        app.add_typer(jwt.app, name="jwt", help="Parse and validate JWT/PASSporT tokens")
    except ImportError:
        pass

    try:
        from common.vvp.cli import identity

        app.add_typer(identity.app, name="identity", help="Parse VVP-Identity headers")
    except ImportError:
        pass

    try:
        from common.vvp.cli import cesr

        app.add_typer(cesr.app, name="cesr", help="Parse CESR streams")
    except ImportError:
        pass

    try:
        from common.vvp.cli import said

        app.add_typer(said.app, name="said", help="Compute and validate SAIDs")
    except ImportError:
        pass

    try:
        from common.vvp.cli import acdc

        app.add_typer(acdc.app, name="acdc", help="Parse ACDC credentials")
    except ImportError:
        pass

    try:
        from common.vvp.cli import dossier

        app.add_typer(dossier.app, name="dossier", help="Parse and analyze dossiers")
    except ImportError:
        pass

    try:
        from common.vvp.cli import graph

        app.add_typer(graph.app, name="graph", help="Build credential graphs")
    except ImportError:
        pass

    try:
        from common.vvp.cli import kel

        app.add_typer(kel.app, name="kel", help="Parse and validate KELs")
    except ImportError:
        pass


# Register subcommands on module load
_register_subcommands()


if __name__ == "__main__":
    app()
