"""VVP MCP Server — Exposes VVP CLI tools as MCP protocol tools.

Provides 17 tools for parsing and validating KERI/ACDC/VVP protocol data:
- JWT/PASSporT parsing and validation
- VVP-Identity header parsing
- CESR stream parsing and detection
- SAID computation, validation, and injection
- ACDC credential parsing and type detection
- Dossier parsing, validation, and fetching
- Credential graph building
- KEL parsing and validation
- Full verification chain (composite)

Run: python -m common.vvp.mcp.server
Or via wrapper: ./scripts/run-mcp-server.sh
"""

import importlib
import json
from typing import Annotated, Any, Optional

from fastmcp import FastMCP

from common.vvp.mcp.tool_helpers import (
    error_result,
    parse_json_param,
    resolve_binary_input,
    resolve_text_input,
)

mcp = FastMCP(
    name="vvp",
    version="0.1.0",
)

# Lazy adapter import with clear error message
_adapters = None


def _get_adapters():
    """Lazy-load adapters to defer heavy imports until first tool call."""
    global _adapters
    if _adapters is None:
        try:
            from common.vvp.cli import adapters

            _adapters = adapters
        except ImportError as e:
            raise RuntimeError(
                "VVP MCP server requires the verifier package. Install with:\n"
                "  pip install -e services/verifier && pip install -e 'common[mcp]'\n"
                f"Original error: {e}"
            ) from e
    return _adapters


@mcp.tool()
def vvp_reload() -> dict[str, Any]:
    """Reload the VVP schema registry and adapter modules to pick up source file changes.

    Call this after editing registry.py or other common modules to avoid restarting Claude Code.
    """
    global _adapters
    reloaded: list[str] = []

    # Reload the schema registry (most common change target)
    import common.vvp.schema.registry as registry_mod
    importlib.reload(registry_mod)
    reloaded.append("common.vvp.schema.registry")

    # Clear cached adapters so next tool call re-imports
    _adapters = None
    reloaded.append("adapters cache cleared")

    # Verify the reload by reading current state
    from common.vvp.schema.registry import KNOWN_SCHEMA_SAIDS, SCHEMA_REGISTRY_VERSION
    schema_counts = {k: len(v) for k, v in KNOWN_SCHEMA_SAIDS.items()}

    return {
        "reloaded": reloaded,
        "registry_version": SCHEMA_REGISTRY_VERSION,
        "schema_counts": schema_counts,
    }


def _dataclass_to_dict(obj: Any) -> Any:
    """Convert dataclasses to dicts, handling nesting and bytes."""
    from common.vvp.cli.utils import dataclass_to_dict

    return dataclass_to_dict(obj)


# ─── JWT Tools ──────────────────────────────────────


@mcp.tool(annotations={"readOnlyHint": True})
def vvp_jwt_parse(
    jwt_token: Annotated[str, "JWT/PASSporT token string (header.payload.signature format)"],
    show_raw: Annotated[bool, "Include raw base64 parts in output"] = False,
) -> dict[str, Any]:
    """Parse a JWT/PASSporT token and return its structure (header, payload, signature).

    Accepts the raw JWT string directly or an absolute file path containing the token.
    """
    adapters = _get_adapters()
    token = resolve_text_input(jwt_token).strip()

    try:
        passport = adapters.parse_passport(token)
    except Exception as e:
        return error_result("PASSPORT_PARSE_FAILED", str(e))

    result: dict[str, Any] = {
        "header": _dataclass_to_dict(passport.header),
        "payload": _dataclass_to_dict(passport.payload),
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

    return result


@mcp.tool(annotations={"readOnlyHint": True})
def vvp_jwt_validate(
    jwt_token: Annotated[str, "JWT/PASSporT token string"],
    identity_header: Annotated[
        Optional[str], "Base64url VVP-Identity header for binding validation"
    ] = None,
    now: Annotated[Optional[int], "Override current time (Unix timestamp) for testing"] = None,
    strict: Annotated[bool, "Fail on any warnings"] = False,
) -> dict[str, Any]:
    """Validate a JWT/PASSporT token with optional VVP-Identity binding check.

    Returns validation result with errors and warnings.
    """
    adapters = _get_adapters()
    token = resolve_text_input(jwt_token).strip()

    errors: list[str] = []
    warnings: list[str] = []

    # Parse the JWT
    try:
        passport = adapters.parse_passport(token)
        warnings.extend(passport.warnings)
    except Exception as e:
        return error_result("PASSPORT_PARSE_FAILED", str(e))

    # Parse VVP-Identity if provided
    vvp_identity = None
    if identity_header:
        try:
            vvp_identity = adapters.parse_vvp_identity(identity_header.strip())
        except Exception as e:
            errors.append(f"VVP-Identity parse failed: {e}")

    # Validate binding if we have both
    if vvp_identity and passport:
        try:
            adapters.validate_passport_binding(passport, vvp_identity, now=now)
        except Exception as e:
            errors.append(f"Binding validation failed: {e}")

    is_valid = len(errors) == 0 and (not strict or len(warnings) == 0)

    result: dict[str, Any] = {
        "valid": is_valid,
        "errors": errors,
        "warnings": warnings,
    }

    if now is not None:
        result["validation_time"] = now

    return result


# ─── Identity Tools ────────────────────────────────


@mcp.tool(annotations={"readOnlyHint": True})
def vvp_identity_parse(
    header: Annotated[str, "Base64url-encoded VVP-Identity header string"],
) -> dict[str, Any]:
    """Parse a VVP-Identity header and return its fields (ppt, kid, evd, iat, exp).

    The header is a base64url-encoded JSON object from SIP headers.
    """
    adapters = _get_adapters()
    header_str = resolve_text_input(header).strip()

    try:
        identity = adapters.parse_vvp_identity(header_str)
    except Exception as e:
        return error_result("IDENTITY_PARSE_FAILED", str(e))

    return _dataclass_to_dict(identity)


# ─── CESR Tools ─────────────────────────────────────


@mcp.tool(annotations={"readOnlyHint": True})
def vvp_cesr_parse(
    data: Annotated[str, "CESR stream as base64-encoded string or absolute path to a CESR file"],
    extract_events: Annotated[
        bool, "Return only event dictionaries without attachment info"
    ] = False,
    show_raw: Annotated[bool, "Include raw bytes as hex in output"] = False,
) -> dict[str, Any] | list[dict[str, Any]]:
    """Parse a CESR (Composable Event Streaming Representation) stream into events and attachments."""
    adapters = _get_adapters()
    raw_bytes = resolve_binary_input(data)

    try:
        messages = adapters.parse_cesr_stream(raw_bytes)
    except Exception as e:
        return error_result("CESR_PARSE_FAILED", str(e))

    if extract_events:
        return [msg.event_dict for msg in messages]

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

    return result


@mcp.tool(annotations={"readOnlyHint": True})
def vvp_cesr_detect(
    data: Annotated[str, "Data as base64-encoded string or absolute path to a file to check"],
) -> dict[str, Any]:
    """Check if input appears to be CESR-encoded. Returns is_cesr boolean and version info if detected."""
    adapters = _get_adapters()
    raw_bytes = resolve_binary_input(data)

    is_cesr = adapters.is_cesr_stream(raw_bytes)

    result: dict[str, Any] = {
        "is_cesr": is_cesr,
        "size_bytes": len(raw_bytes),
    }

    if is_cesr and len(raw_bytes) >= 17:
        try:
            version, _ = adapters.parse_version_string(raw_bytes)
            result["version"] = {
                "protocol": version.protocol,
                "major": version.major,
                "minor": version.minor,
                "kind": version.kind,
                "declared_size": version.size,
            }
        except Exception:
            pass

    return result


# ─── SAID Tools ──────────────────────────────────────


def _detect_said_type(data: dict[str, Any]) -> str:
    """Auto-detect the type of structure for SAID computation."""
    if "v" in data and isinstance(data.get("v"), str) and data["v"].startswith("ACDC"):
        return "acdc"
    if "$schema" in data or "$id" in data:
        return "schema"
    if "t" in data and data.get("t") in (
        "icp", "rot", "ixn", "dip", "drt", "vcp", "vrt", "iss", "rev",
    ):
        return "kel"
    if "d" in data:
        return "acdc"
    return "acdc"


def _compute_said(adapters: Any, data: dict[str, Any], structure_type: str, field: str) -> str:
    """Compute SAID using the appropriate adapter function."""
    if structure_type == "acdc":
        return adapters.compute_acdc_said(data, said_field=field)
    elif structure_type == "kel":
        return adapters.compute_kel_event_said(data)
    elif structure_type == "schema":
        return adapters.compute_schema_said(data)
    else:
        raise ValueError(f"Unknown SAID type: {structure_type}")


@mcp.tool(annotations={"readOnlyHint": True})
def vvp_said_compute(
    json_data: Annotated[str, "JSON string of the structure to compute SAID for, or absolute file path"],
    structure_type: Annotated[
        str, "Type: 'acdc', 'kel', 'schema', or 'auto' (auto-detect)"
    ] = "auto",
    field: Annotated[str, "SAID field name (default 'd', schema uses '$id')"] = "d",
) -> dict[str, Any]:
    """Compute the SAID (Self-Addressing Identifier) for a JSON structure using Blake3-256."""
    adapters = _get_adapters()

    try:
        data = parse_json_param(json_data)
    except (json.JSONDecodeError, ValueError) as e:
        return error_result("SAID_PARSE_FAILED", f"Invalid JSON: {e}")

    actual_type = structure_type if structure_type != "auto" else _detect_said_type(data)
    if actual_type == "schema" and field == "d":
        field = "$id"

    try:
        said = _compute_said(adapters, data, actual_type, field)
    except Exception as e:
        return error_result("SAID_COMPUTE_FAILED", str(e))

    return {
        "said": said,
        "algorithm": "blake3-256",
        "type": actual_type,
        "field": field,
    }


@mcp.tool(annotations={"readOnlyHint": True})
def vvp_said_validate(
    json_data: Annotated[str, "JSON string containing a SAID field to validate, or absolute file path"],
    structure_type: Annotated[str, "Type: 'acdc', 'kel', 'schema', or 'auto'"] = "auto",
    field: Annotated[str, "SAID field name to validate"] = "d",
) -> dict[str, Any]:
    """Validate that a structure's SAID field matches its computed SAID."""
    adapters = _get_adapters()

    try:
        data = parse_json_param(json_data)
    except (json.JSONDecodeError, ValueError) as e:
        return error_result("SAID_PARSE_FAILED", f"Invalid JSON: {e}")

    actual_type = structure_type if structure_type != "auto" else _detect_said_type(data)
    if actual_type == "schema" and field == "d":
        field = "$id"

    expected = data.get(field)
    if not expected:
        return error_result("SAID_VALIDATE_FAILED", f"No '{field}' field found in input")

    try:
        computed = _compute_said(adapters, data, actual_type, field)
    except Exception as e:
        return error_result("SAID_COMPUTE_FAILED", str(e))

    return {
        "valid": expected == computed,
        "expected": expected,
        "computed": computed,
        "type": actual_type,
        "field": field,
    }


@mcp.tool()
def vvp_said_inject(
    json_data: Annotated[str, "JSON string of the structure to inject SAID into, or absolute file path"],
    structure_type: Annotated[str, "Type: 'acdc', 'kel', 'schema', or 'auto'"] = "auto",
    field: Annotated[str, "SAID field name to inject"] = "d",
) -> dict[str, Any]:
    """Compute SAID and inject it into the structure's SAID field. Returns the modified JSON."""
    adapters = _get_adapters()

    try:
        data = parse_json_param(json_data)
    except (json.JSONDecodeError, ValueError) as e:
        return error_result("SAID_PARSE_FAILED", f"Invalid JSON: {e}")

    actual_type = structure_type if structure_type != "auto" else _detect_said_type(data)
    if actual_type == "schema" and field == "d":
        field = "$id"

    # Set placeholder for SAID computation
    data[field] = "#" * 44

    try:
        said = _compute_said(adapters, data, actual_type, field)
    except Exception as e:
        return error_result("SAID_INJECT_FAILED", str(e))

    data[field] = said
    return data


# ─── ACDC Tools ──────────────────────────────────────


@mcp.tool(annotations={"readOnlyHint": True})
def vvp_acdc_parse(
    json_data: Annotated[str, "JSON string of the ACDC credential, or absolute file path"],
    validate_said: Annotated[bool, "Compute and validate the credential's SAID"] = False,
) -> dict[str, Any]:
    """Parse an ACDC (Authentic Chained Data Container) credential and return its structure.

    Supports all ACDC variants: full, compact, partial.
    """
    adapters = _get_adapters()

    try:
        data = parse_json_param(json_data)
    except (json.JSONDecodeError, ValueError) as e:
        return error_result("ACDC_PARSE_FAILED", f"Invalid JSON: {e}")

    try:
        acdc = adapters.parse_acdc(data)
    except Exception as e:
        return error_result("ACDC_PARSE_FAILED", str(e))

    result: dict[str, Any] = {
        "said": acdc.said,
        "issuer_aid": acdc.issuer_aid,
        "schema_said": acdc.schema_said,
        "credential_type": acdc.credential_type,
        "variant": acdc.variant,
        "is_root_credential": acdc.is_root_credential,
    }

    if acdc.attributes is not None:
        if isinstance(acdc.attributes, dict):
            result["attributes"] = acdc.attributes
        else:
            result["attributes_said"] = acdc.attributes

    if acdc.edges:
        result["edges"] = acdc.edges
    if acdc.rules:
        result["rules"] = acdc.rules

    if validate_said:
        try:
            computed_said = adapters.compute_acdc_said(data)
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

    return result


@mcp.tool(annotations={"readOnlyHint": True})
def vvp_acdc_type(
    json_data: Annotated[str, "JSON string of the ACDC credential, or absolute file path"],
) -> dict[str, Any]:
    """Detect credential type (LE, QVI, APE, DE, TNAlloc, OOR, etc.) from schema, edges, or attributes.

    Returns type with confidence level (high/medium) and structural hints.
    """
    adapters = _get_adapters()

    try:
        data = parse_json_param(json_data)
    except (json.JSONDecodeError, ValueError) as e:
        return error_result("ACDC_PARSE_FAILED", f"Invalid JSON: {e}")

    try:
        acdc = adapters.parse_acdc(data)
    except Exception as e:
        return error_result("ACDC_PARSE_FAILED", str(e))

    variant = adapters.detect_acdc_variant(data)

    confidence = "high" if acdc.schema_said else "medium"
    source = "schema_said"

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

    return result


# ─── Dossier Tools ───────────────────────────────────


def _build_credential_list(
    nodes: list, signatures: dict,
) -> list[dict[str, Any]]:
    """Build credential list from parsed dossier nodes."""
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
            cred_data["signature_bytes"] = len(signatures[node.said])
        credentials.append(cred_data)
    return credentials


@mcp.tool(annotations={"readOnlyHint": True})
def vvp_dossier_parse(
    data: Annotated[
        str,
        "Dossier content as JSON string, base64-encoded CESR, or absolute file path",
    ],
) -> dict[str, Any]:
    """Parse a dossier (credential bundle) into individual ACDCs with signatures.

    Supports: single ACDC JSON, JSON array, CESR stream, Provenant wrapper.
    """
    adapters = _get_adapters()
    raw_bytes = resolve_binary_input(data)

    try:
        nodes, signatures = adapters.parse_dossier(raw_bytes)
    except Exception as e:
        return error_result("DOSSIER_PARSE_FAILED", str(e))

    # Detect format
    detected_format = "json"
    if raw_bytes.startswith(b"{") and b"-A" in raw_bytes:
        detected_format = "cesr"
    elif raw_bytes.strip().startswith(b"["):
        detected_format = "json_array"

    credentials = _build_credential_list(nodes, signatures)

    return {
        "credentials": credentials,
        "credential_count": len(credentials),
        "format": detected_format,
        "signatures_extracted": len(signatures),
    }


@mcp.tool(annotations={"readOnlyHint": True})
def vvp_dossier_validate(
    data: Annotated[
        str,
        "Dossier content as JSON string, base64-encoded CESR, or absolute file path",
    ],
    allow_aggregate: Annotated[
        bool, "Allow multiple root credentials (aggregate dossiers)"
    ] = False,
) -> dict[str, Any]:
    """Validate dossier DAG structure: no cycles, proper roots, ToIP compliance."""
    adapters = _get_adapters()
    raw_bytes = resolve_binary_input(data)

    try:
        nodes, _ = adapters.parse_dossier(raw_bytes)
    except Exception as e:
        return error_result("DOSSIER_PARSE_FAILED", str(e))

    try:
        dag = adapters.build_dag(nodes)
    except Exception as e:
        return error_result("DOSSIER_DAG_FAILED", str(e))

    errors: list[str] = []
    try:
        adapters.validate_dag(dag, allow_aggregate=allow_aggregate)
    except Exception as e:
        errors.append(str(e))

    cycle = adapters.detect_cycle(dag)
    if cycle:
        errors.append(f"Cycle detected: {' -> '.join(cycle)}")

    roots = adapters.find_roots(dag, allow_multiple=allow_aggregate)

    warnings: list[dict[str, Any]] = []
    if dag.warnings:
        for w in dag.warnings:
            warnings.append({
                "code": w.code.value if hasattr(w.code, "value") else str(w.code),
                "message": w.message,
                "credential_said": w.credential_said,
            })

    return {
        "valid": len(errors) == 0,
        "root_saids": roots,
        "is_aggregate": len(roots) > 1,
        "node_count": len(dag.nodes),
        "cycle_detected": cycle is not None,
        "errors": errors,
        "warnings": warnings,
    }


@mcp.tool(annotations={"readOnlyHint": True, "openWorldHint": True})
async def vvp_dossier_fetch(
    url: Annotated[str, "URL to fetch the dossier from (typically from PASSporT evd claim)"],
) -> dict[str, Any]:
    """Fetch a dossier from a URL and parse it into credentials."""
    adapters = _get_adapters()

    try:
        data = await adapters.fetch_dossier(url)
    except Exception as e:
        return error_result("DOSSIER_FETCH_FAILED", str(e), details={"url": url})

    try:
        nodes, signatures = adapters.parse_dossier(data)
    except Exception as e:
        return error_result("DOSSIER_PARSE_FAILED", str(e))

    credentials = _build_credential_list(nodes, signatures)

    return {
        "credentials": credentials,
        "credential_count": len(credentials),
        "signatures_extracted": len(signatures),
        "source_url": url,
    }


# ─── Graph Tools ─────────────────────────────────────


@mcp.tool(annotations={"readOnlyHint": True})
def vvp_graph_build(
    data: Annotated[
        str,
        "Dossier content as JSON string, base64-encoded CESR, or absolute file path",
    ],
    trusted_roots: Annotated[
        Optional[str], "Comma-separated trusted root AIDs for trust path validation"
    ] = None,
) -> dict[str, Any]:
    """Build a credential graph from a dossier, showing chain relationships and trust paths.

    The graph includes nodes (credentials with type/status), edges (chain relationships),
    and trust path validation against specified root AIDs.
    """
    adapters = _get_adapters()
    raw_bytes = resolve_binary_input(data)

    try:
        nodes, _ = adapters.parse_dossier(raw_bytes)
    except Exception as e:
        return error_result("DOSSIER_PARSE_FAILED", str(e))

    # Convert ACDCNodes to ACDCs for the graph builder
    dossier_acdcs: dict[str, Any] = {}
    for node in nodes:
        try:
            acdc = adapters.parse_acdc(node.raw)
            dossier_acdcs[acdc.said] = acdc
        except Exception:
            pass

    # Parse trusted roots
    roots: set[str] = set()
    if trusted_roots:
        roots = {r.strip() for r in trusted_roots.split(",") if r.strip()}

    try:
        graph = adapters.build_credential_graph(
            dossier_acdcs=dossier_acdcs,
            trusted_roots=roots,
        )
    except Exception as e:
        return error_result("GRAPH_BUILD_FAILED", str(e))

    return adapters.credential_graph_to_dict(graph)


# ─── KEL Tools ───────────────────────────────────────

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


@mcp.tool(annotations={"readOnlyHint": True})
def vvp_kel_parse(
    data: Annotated[str, "CESR-encoded KEL as base64 string or absolute path to a CESR file"],
    show_keys: Annotated[bool, "Include full key lists and witness info"] = False,
) -> dict[str, Any]:
    """Parse a Key Event Log and display its events (inception, rotation, interaction).

    Tracks key state across the event sequence and identifies the AID.
    """
    adapters = _get_adapters()
    raw_bytes = resolve_binary_input(data)

    try:
        messages = adapters.parse_cesr_stream(raw_bytes)
    except Exception as e:
        return error_result("KEL_PARSE_FAILED", str(e))

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

        if event_type in ("icp", "dip"):
            keys = event.get("k", [])
            if keys:
                current_key = keys[0] if isinstance(keys, list) else keys
            current_sequence = 0
        elif event_type in ("rot", "drt"):
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

    for ev in events:
        if ev["type"] in ("icp", "dip"):
            result["aid"] = ev["identifier"]
            break

    return result


@mcp.tool(annotations={"readOnlyHint": True})
def vvp_kel_validate(
    data: Annotated[str, "CESR-encoded KEL as base64 string or absolute path to a CESR file"],
    validate_saids: Annotated[bool, "Validate event SAIDs"] = True,
    validate_witnesses: Annotated[bool, "Validate witness receipt thresholds"] = False,
) -> dict[str, Any]:
    """Validate KEL chain continuity and integrity.

    Checks sequence continuity, prior digest links, SAID validity, and witness receipt thresholds.
    """
    adapters = _get_adapters()
    raw_bytes = resolve_binary_input(data)

    try:
        messages = adapters.parse_cesr_stream(raw_bytes)
    except Exception as e:
        return error_result("KEL_PARSE_FAILED", str(e))

    errors: list[str] = []
    warnings: list[str] = []

    prev_digest: str | None = None
    prev_sequence = -1

    for i, msg in enumerate(messages):
        event = msg.event_dict
        event_type = event.get("t", "unknown")
        sequence = int(event.get("s", 0))
        digest = event.get("d", "")
        prior = event.get("p")

        if event_type in ("icp", "dip"):
            if sequence != 0:
                errors.append(f"Event {i}: Inception sequence must be 0, got {sequence}")
        else:
            if sequence != prev_sequence + 1:
                errors.append(
                    f"Event {i}: Sequence discontinuity. Expected {prev_sequence + 1}, got {sequence}"
                )

        if event_type not in ("icp", "dip"):
            if prior != prev_digest:
                errors.append(
                    f"Event {i}: Prior digest mismatch. Expected {prev_digest}, got {prior}"
                )

        if validate_saids:
            try:
                adapters.validate_event_said_canonical(event)
            except Exception as e:
                errors.append(f"Event {i}: SAID validation failed: {e}")

        if validate_witnesses:
            toad = int(event.get("bt", 0))
            receipts = len(msg.witness_receipts)
            if receipts < toad:
                warnings.append(
                    f"Event {i}: Insufficient witness receipts. Need {toad}, have {receipts}"
                )

        prev_digest = digest
        prev_sequence = sequence

    return {
        "valid": len(errors) == 0,
        "event_count": len(messages),
        "final_sequence": prev_sequence,
        "errors": errors,
        "warnings": warnings,
    }


# ─── Composite Tool ──────────────────────────────────


@mcp.tool(annotations={"readOnlyHint": True, "openWorldHint": True})
async def vvp_verify_chain(
    jwt_token: Annotated[str, "JWT/PASSporT token to trace the full verification chain for"],
    trusted_roots: Annotated[
        Optional[str], "Comma-separated trusted root AIDs"
    ] = None,
) -> dict[str, Any]:
    """Full verification chain: parse JWT, extract evd URL, fetch dossier, validate DAG, build graph.

    This composite operation mirrors the CLI pipe chain:
      vvp jwt parse | extract evd | vvp dossier fetch | vvp dossier validate | vvp graph build
    """
    adapters = _get_adapters()
    token = resolve_text_input(jwt_token).strip()

    # Step 1: Parse JWT
    try:
        passport = adapters.parse_passport(token)
    except Exception as e:
        return error_result("PASSPORT_PARSE_FAILED", str(e))

    jwt_info = {
        "header": _dataclass_to_dict(passport.header),
        "payload": _dataclass_to_dict(passport.payload),
    }

    # Step 2: Extract identity header and evd URL
    identity_info = None
    evd_url = None

    # Try to get evd from identity header in JWT payload
    payload_dict = _dataclass_to_dict(passport.payload)
    if isinstance(payload_dict, dict):
        evd_url = payload_dict.get("evd")
        # Also check for kid which may contain identity info
        kid = payload_dict.get("kid")
        if kid:
            try:
                identity = adapters.parse_vvp_identity(kid)
                identity_info = _dataclass_to_dict(identity)
                evd_url = evd_url or identity_info.get("evd")
            except Exception:
                pass

    if not evd_url:
        return error_result(
            "VERIFY_CHAIN_FAILED",
            "Could not extract evidence URL (evd) from JWT payload",
            details={"jwt": jwt_info},
        )

    # Step 3: Fetch dossier
    try:
        dossier_data = await adapters.fetch_dossier(evd_url)
    except Exception as e:
        return error_result(
            "DOSSIER_FETCH_FAILED",
            str(e),
            details={"url": evd_url, "jwt": jwt_info},
        )

    # Step 4: Parse dossier
    try:
        nodes, signatures = adapters.parse_dossier(dossier_data)
    except Exception as e:
        return error_result("DOSSIER_PARSE_FAILED", str(e))

    credentials = _build_credential_list(nodes, signatures)

    # Step 5: Validate DAG
    dag_validation: dict[str, Any] = {}
    try:
        dag = adapters.build_dag(nodes)
        dag_errors: list[str] = []
        try:
            adapters.validate_dag(dag)
        except Exception as e:
            dag_errors.append(str(e))

        cycle = adapters.detect_cycle(dag)
        if cycle:
            dag_errors.append(f"Cycle detected: {' -> '.join(cycle)}")

        roots = adapters.find_roots(dag, allow_multiple=False)

        dag_validation = {
            "valid": len(dag_errors) == 0,
            "root_saids": roots,
            "node_count": len(dag.nodes),
            "errors": dag_errors,
        }
    except Exception as e:
        dag_validation = {"valid": False, "errors": [str(e)]}

    # Step 6: Build graph
    graph_data: dict[str, Any] | None = None
    dossier_acdcs: dict[str, Any] = {}
    for node in nodes:
        try:
            acdc = adapters.parse_acdc(node.raw)
            dossier_acdcs[acdc.said] = acdc
        except Exception:
            pass

    roots_set: set[str] = set()
    if trusted_roots:
        roots_set = {r.strip() for r in trusted_roots.split(",") if r.strip()}

    try:
        graph = adapters.build_credential_graph(
            dossier_acdcs=dossier_acdcs,
            trusted_roots=roots_set,
        )
        graph_data = adapters.credential_graph_to_dict(graph)
    except Exception as e:
        graph_data = {"error": str(e)}

    return {
        "jwt": jwt_info,
        "identity": identity_info,
        "evidence_url": evd_url,
        "dossier": {
            "credentials": credentials,
            "credential_count": len(credentials),
            "signatures_extracted": len(signatures),
        },
        "dag_validation": dag_validation,
        "credential_graph": graph_data,
    }


# ── Issuer Management Tools ──────────────────────────────────────────
# These tools call the issuer HTTP API (not the adapter layer).
# They require a running issuer instance.

from common.vvp.mcp.issuer_tools import register_issuer_tools

register_issuer_tools(mcp)


def main():
    """Entry point for the VVP MCP server."""
    mcp.run()


if __name__ == "__main__":
    main()
