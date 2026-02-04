"""KEL (Key Event Log) parsing commands.

Commands:
    vvp kel parse <input>     Parse KEL events
    vvp kel validate <input>  Validate KEL chain
"""

from typing import Any

import typer

from common.vvp.cli.output import OutputFormat, output, output_error
from common.vvp.cli.utils import (
    EXIT_PARSE_ERROR,
    EXIT_VALIDATION_FAILURE,
    read_input,
)

app = typer.Typer(
    name="kel",
    help="Parse and validate Key Event Logs.",
    no_args_is_help=True,
)


# Event type descriptions
EVENT_TYPES = {
    "icp": "Inception (create new identifier)",
    "rot": "Rotation (change keys/witnesses)",
    "ixn": "Interaction (anchor data)",
    "dip": "Delegated inception",
    "drt": "Delegated rotation",
    "vcp": "Verifiable credential registry inception",
    "vrt": "Verifiable credential registry rotation",
    "iss": "Credential issuance",
    "rev": "Credential revocation",
    "bis": "Backed credential issuance",
    "brv": "Backed credential revocation",
}


@app.command("parse")
def parse_cmd(
    source: str = typer.Argument(
        ...,
        help="CESR-encoded KEL file or '-' for stdin",
    ),
    format: OutputFormat = typer.Option(
        OutputFormat.json,
        "--format",
        "-f",
        help="Output format",
    ),
    show_keys: bool = typer.Option(
        False,
        "--show-keys",
        help="Include full key lists in output",
    ),
) -> None:
    """Parse a Key Event Log and display its events.

    KELs contain the cryptographic history of KERI identifiers,
    including inception, rotation, and interaction events.

    Examples:
        curl -s $WITNESS/kel/DER2Rc... | vvp kel parse -
        vvp kel parse identifier.cesr --format table
    """
    from common.vvp.cli.adapters import parse_cesr_stream

    # Read binary input
    data = read_input(source, binary=True)
    if isinstance(data, str):
        data = data.encode("utf-8")

    # Parse the CESR stream
    try:
        messages = parse_cesr_stream(data)
    except Exception as e:
        output_error(
            code="KEL_PARSE_FAILED",
            message=str(e),
            exit_code=EXIT_PARSE_ERROR,
        )
        return

    # Extract events
    events: list[dict[str, Any]] = []
    current_key: str | None = None
    current_sequence = 0

    for msg in messages:
        event = msg.event_dict
        event_type = event.get("t", "unknown")

        event_data: dict[str, Any] = {
            "type": event_type,
            "type_description": EVENT_TYPES.get(event_type, "Unknown event type"),
            "sequence": event.get("s", 0),
            "digest": event.get("d", ""),
            "identifier": event.get("i", ""),
            "prior_digest": event.get("p", None),
            "controller_sigs": len(msg.controller_sigs),
            "witness_receipts": len(msg.witness_receipts),
        }

        # Track key state
        if event_type in ("icp", "dip"):
            # Inception - extract initial key
            keys = event.get("k", [])
            if keys:
                current_key = keys[0] if isinstance(keys, list) else keys
            current_sequence = 0
        elif event_type in ("rot", "drt"):
            # Rotation - extract new key
            keys = event.get("k", [])
            if keys:
                current_key = keys[0] if isinstance(keys, list) else keys
            current_sequence = int(event.get("s", 0))

        if show_keys:
            event_data["signing_keys"] = event.get("k", [])
            event_data["next_keys_digest"] = event.get("n", [])
            event_data["witnesses"] = event.get("b", [])
            event_data["witness_threshold"] = event.get("bt", 0)

        events.append(event_data)

    result: dict[str, Any] = {
        "events": events,
        "event_count": len(events),
        "current_key": current_key,
        "key_state_sequence": current_sequence,
    }

    # Identify the AID from first inception event
    for ev in events:
        if ev["type"] in ("icp", "dip"):
            result["aid"] = ev["identifier"]
            break

    output(result, format)


@app.command("validate")
def validate_cmd(
    source: str = typer.Argument(
        ...,
        help="CESR-encoded KEL file or '-' for stdin",
    ),
    format: OutputFormat = typer.Option(
        OutputFormat.json,
        "--format",
        "-f",
        help="Output format",
    ),
    validate_saids: bool = typer.Option(
        True,
        "--validate-saids/--no-validate-saids",
        help="Validate event SAIDs",
    ),
    validate_witnesses: bool = typer.Option(
        False,
        "--validate-witnesses",
        help="Validate witness signatures (requires receipts)",
    ),
) -> None:
    """Validate KEL chain continuity and integrity.

    Checks:
    - Event sequence continuity
    - Prior event digest links
    - SAID validity (optional)
    - Witness receipt thresholds (optional)

    Examples:
        vvp kel validate identifier.cesr
        vvp kel validate - --validate-witnesses < kel.cesr
    """
    from common.vvp.cli.adapters import (
        compute_kel_event_said,
        parse_cesr_stream,
        validate_event_said_canonical,
    )

    # Read binary input
    data = read_input(source, binary=True)
    if isinstance(data, str):
        data = data.encode("utf-8")

    # Parse the CESR stream
    try:
        messages = parse_cesr_stream(data)
    except Exception as e:
        output_error(
            code="KEL_PARSE_FAILED",
            message=str(e),
            exit_code=EXIT_PARSE_ERROR,
        )
        return

    errors: list[str] = []
    warnings: list[str] = []

    # Validate chain
    prev_digest: str | None = None
    prev_sequence = -1

    for i, msg in enumerate(messages):
        event = msg.event_dict
        event_type = event.get("t", "unknown")
        sequence = int(event.get("s", 0))
        digest = event.get("d", "")
        prior = event.get("p")

        # Check sequence continuity
        if event_type in ("icp", "dip"):
            if sequence != 0:
                errors.append(f"Event {i}: Inception sequence must be 0, got {sequence}")
        else:
            if sequence != prev_sequence + 1:
                errors.append(
                    f"Event {i}: Sequence discontinuity. Expected {prev_sequence + 1}, got {sequence}"
                )

        # Check prior digest link
        if event_type not in ("icp", "dip"):
            if prior != prev_digest:
                errors.append(
                    f"Event {i}: Prior digest mismatch. Expected {prev_digest}, got {prior}"
                )

        # Validate SAID
        if validate_saids:
            try:
                validate_event_said_canonical(event)
            except Exception as e:
                errors.append(f"Event {i}: SAID validation failed: {e}")

        # Check witness receipts
        if validate_witnesses:
            toad = int(event.get("bt", 0))
            receipts = len(msg.witness_receipts)
            if receipts < toad:
                warnings.append(
                    f"Event {i}: Insufficient witness receipts. Need {toad}, have {receipts}"
                )

        prev_digest = digest
        prev_sequence = sequence

    is_valid = len(errors) == 0

    result: dict[str, Any] = {
        "valid": is_valid,
        "event_count": len(messages),
        "final_sequence": prev_sequence,
        "errors": errors,
        "warnings": warnings,
    }

    output(result, format)

    if not is_valid:
        raise typer.Exit(EXIT_VALIDATION_FAILURE)


if __name__ == "__main__":
    app()
