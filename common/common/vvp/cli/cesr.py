"""CESR stream parsing commands.

Commands:
    vvp cesr parse <input>   Parse CESR stream to events
    vvp cesr detect <input>  Check if input is CESR-encoded
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
    name="cesr",
    help="Parse CESR streams.",
    no_args_is_help=True,
)


@app.command("parse")
def parse_cmd(
    source: str = typer.Argument(
        ...,
        help="CESR stream file path or '-' for stdin",
    ),
    format: OutputFormat = typer.Option(
        OutputFormat.json,
        "--format",
        "-f",
        help="Output format",
    ),
    extract_events: bool = typer.Option(
        False,
        "--extract-events",
        help="Output only event dictionaries (without attachments)",
    ),
    show_raw: bool = typer.Option(
        False,
        "--show-raw",
        help="Include raw bytes as hex in output",
    ),
) -> None:
    """Parse a CESR stream into events and attachments.

    CESR (Composable Event Streaming Representation) is the binary
    format used by KERI for events and signatures. This command
    parses CESR streams and extracts the embedded events.

    Examples:
        cat kel.cesr | vvp cesr parse -
        vvp cesr parse witness_response.cesr
        vvp cesr parse - --extract-events < stream.cesr
    """
    from common.vvp.cli.adapters import CESRMessage, parse_cesr_stream

    # Read binary input
    data = read_input(source, binary=True)
    if isinstance(data, str):
        data = data.encode("utf-8")

    # Parse the CESR stream
    try:
        messages: list[CESRMessage] = parse_cesr_stream(data)
    except Exception as e:
        output_error(
            code="CESR_PARSE_FAILED",
            message=str(e),
            exit_code=EXIT_PARSE_ERROR,
        )
        return

    if extract_events:
        # Output only event dictionaries
        events = [msg.event_dict for msg in messages]
        output(events, format)
        return

    # Build full output with attachment summaries
    result: dict[str, Any] = {
        "messages": [],
        "attachment_summary": {
            "total_messages": len(messages),
            "total_controller_sigs": 0,
            "total_witness_receipts": 0,
        },
    }

    for msg in messages:
        msg_data: dict[str, Any] = {
            "event_type": msg.event_dict.get("t", "unknown"),
            "sequence": msg.event_dict.get("s", 0),
            "digest": msg.event_dict.get("d", ""),
            "controller_sigs": len(msg.controller_sigs),
            "witness_receipts": len(msg.witness_receipts),
            "event": msg.event_dict,
        }

        if show_raw:
            msg_data["raw_event_bytes"] = msg.event_bytes.hex()
            msg_data["raw_bytes"] = msg.raw.hex() if msg.raw else None

        result["messages"].append(msg_data)
        result["attachment_summary"]["total_controller_sigs"] += len(msg.controller_sigs)
        result["attachment_summary"]["total_witness_receipts"] += len(msg.witness_receipts)

    output(result, format)


@app.command("detect")
def detect_cmd(
    source: str = typer.Argument(
        ...,
        help="Input file path or '-' for stdin",
    ),
    format: OutputFormat = typer.Option(
        OutputFormat.json,
        "--format",
        "-f",
        help="Output format",
    ),
) -> None:
    """Check if input appears to be CESR-encoded.

    Detects CESR version strings or count codes in the input.

    Examples:
        cat data | vvp cesr detect -
        vvp cesr detect unknown_file.bin
    """
    from common.vvp.cli.adapters import is_cesr_stream, parse_version_string

    # Read binary input
    data = read_input(source, binary=True)
    if isinstance(data, str):
        data = data.encode("utf-8")

    # Check if it's CESR
    is_cesr = is_cesr_stream(data)

    result: dict[str, Any] = {
        "is_cesr": is_cesr,
        "size_bytes": len(data),
    }

    # Try to extract version info if CESR
    if is_cesr and len(data) >= 17:
        try:
            version, _ = parse_version_string(data)
            result["version"] = {
                "protocol": version.protocol,
                "major": version.major,
                "minor": version.minor,
                "kind": version.kind,
                "declared_size": version.size,
            }
        except Exception:
            # Version parsing failed, but stream may still be CESR
            pass

    output(result, format)


if __name__ == "__main__":
    app()
