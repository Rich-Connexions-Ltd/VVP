# VVP CLI Tools User Guide

Chainable command-line utilities for parsing and analyzing JWTs, ACDCs, CESR streams, dossiers, and KERI structures.

## Installation

```bash
# Install from the VVP repository root
cd VVP
pip install -e services/verifier && pip install -e 'common[cli]'

# Verify installation
vvp --help
```

## Quick Reference

| Command | Purpose |
|---------|---------|
| `vvp jwt parse` | Parse JWT/PASSporT structure |
| `vvp jwt validate` | Validate JWT with optional identity binding |
| `vvp identity parse` | Parse VVP-Identity header |
| `vvp cesr parse` | Parse CESR-encoded stream |
| `vvp cesr detect` | Check if input is CESR-encoded |
| `vvp said compute` | Compute SAID for JSON structure |
| `vvp said validate` | Validate existing SAID |
| `vvp said inject` | Inject computed SAID into structure |
| `vvp acdc parse` | Parse ACDC credential |
| `vvp acdc type` | Detect ACDC credential type |
| `vvp dossier parse` | Parse dossier to ACDCs |
| `vvp dossier validate` | Validate dossier DAG structure |
| `vvp dossier fetch` | Fetch dossier from URL |
| `vvp graph build` | Build credential graph |
| `vvp kel parse` | Parse Key Event Log |
| `vvp kel validate` | Validate KEL chain |

## Common Options

All commands support:
- `-f, --format [json|pretty|table]` - Output format (default: json)
- `--help` - Show help for the command
- `-` as input - Read from stdin

## Commands

### JWT Commands

#### `vvp jwt parse`

Parse a JWT/PASSporT token and display its structure.

```bash
# Parse from literal string
vvp jwt parse "eyJhbGciOiJFZERTQSIsInBwdCI6InNoYWtlbiIsInR5cCI6InBhc3Nwb3J0In0.eyJkZXN0Ijp7InRuIjpbIisxNTU1MTIzNDU2NyJdfSwiaWF0IjoxNzA0MDY3MjAwLCJvcmlnIjp7InRuIjoiKzE1NTUxMjM0NTY3In19.SIGNATURE"

# Parse from file
vvp jwt parse token.jwt

# Parse from stdin
cat token.jwt | vvp jwt parse -

# Include raw base64 parts
vvp jwt parse token.jwt --show-raw

# Pretty-printed output
vvp jwt parse token.jwt -f pretty
```

**Output:**
```json
{
  "header": {
    "alg": "EdDSA",
    "ppt": "shaken",
    "typ": "passport"
  },
  "payload": {
    "dest": {"tn": ["+15551234567"]},
    "iat": 1704067200,
    "orig": {"tn": "+15551234567"}
  },
  "signature": {
    "bytes": "...",
    "length": 64
  },
  "warnings": []
}
```

#### `vvp jwt validate`

Validate a JWT/PASSporT token with optional VVP-Identity binding.

```bash
# Basic validation
vvp jwt validate token.jwt

# Validate with VVP-Identity binding
vvp jwt validate token.jwt --identity "eyJwcHQiOiJzaGFrZW4iLCJraWQiOiIuLi4ifQ=="

# Strict mode (fail on warnings)
vvp jwt validate token.jwt --strict

# Override current time for testing
vvp jwt validate token.jwt --now 1704067200
```

### Identity Commands

#### `vvp identity parse`

Parse a VVP-Identity header (base64url-encoded JSON).

```bash
# Parse from string
vvp identity parse "eyJwcHQiOiJzaGFrZW4iLCJraWQiOiJFTlBYcDF2US4uLiIsImV2ZCI6Imh0dHBzOi8vLi4uIn0="

# Parse from stdin
echo "eyJwcHQiOi..." | vvp identity parse -
```

**Output:**
```json
{
  "ppt": "shaken",
  "kid": "ENPXp1vQ...",
  "evd": "https://example.com/dossier/...",
  "iat": 1704067200,
  "exp": 1704067500
}
```

### CESR Commands

#### `vvp cesr parse`

Parse a CESR-encoded stream into events.

```bash
# Parse from file
vvp cesr parse stream.cesr

# Parse from stdin
curl -s "$WITNESS/kel/$AID" | vvp cesr parse -

# Detailed output
vvp cesr parse stream.cesr --detailed
```

**Output:**
```json
{
  "messages": [
    {
      "type": "icp",
      "said": "ENPXp1vQ...",
      "sequence": 0,
      "controller_sigs": 1,
      "witness_receipts": 3
    }
  ],
  "message_count": 1,
  "has_attachments": true
}
```

#### `vvp cesr detect`

Check if input is CESR-encoded.

```bash
# Detect from file
vvp cesr detect maybe-cesr.bin

# Detect from stdin
cat data.bin | vvp cesr detect -
```

**Output:**
```json
{
  "is_cesr": true,
  "version": "KERI10JSON",
  "first_event_type": "icp"
}
```

### SAID Commands

#### `vvp said compute`

Compute the SAID (Self-Addressing Identifier) for a JSON structure.

```bash
# Auto-detect type and compute
echo '{"d":"","i":"DER2Rc...","s":"EBfdlu..."}' | vvp said compute -

# Specify type explicitly
echo '{"v":"KERI10JSON...","t":"icp",...}' | vvp said compute - --type kel

# Compute for schema
cat schema.json | vvp said compute - --type schema
```

**Output:**
```json
{
  "said": "ENPXp1vQklP5gKsVaV9_7vHdqfMU-VbLmn8sSzjCE0_c",
  "algorithm": "blake3-256",
  "type_detected": "acdc"
}
```

#### `vvp said validate`

Validate that a structure's SAID matches its content.

```bash
# Validate ACDC SAID
cat credential.json | vvp said validate -

# Validate with specific type
cat event.json | vvp said validate - --type kel
```

**Output:**
```json
{
  "valid": true,
  "expected": "ENPXp1vQ...",
  "computed": "ENPXp1vQ..."
}
```

#### `vvp said inject`

Inject a computed SAID into a structure's `d` field.

```bash
# Inject SAID into ACDC
echo '{"d":"","i":"DER2Rc..."}' | vvp said inject -

# Output is the complete structure with SAID filled in
```

### ACDC Commands

#### `vvp acdc parse`

Parse an ACDC credential and display its structure.

```bash
# Parse from file
vvp acdc parse credential.json

# Parse from stdin
cat credential.json | vvp acdc parse -

# Show full attributes
vvp acdc parse credential.json --show-attributes
```

**Output:**
```json
{
  "said": "ENPXp1vQ...",
  "issuer_aid": "DER2Rc...",
  "schema_said": "EBfdlu...",
  "type": "QualifiedvLEIIssuervLEICredential",
  "variant": "targeted",
  "issuee_aid": "DFG4Xy...",
  "edge_count": 1
}
```

#### `vvp acdc type`

Detect the type of an ACDC credential.

```bash
cat credential.json | vvp acdc type -
```

**Output:**
```json
{
  "type": "LegalEntityvLEICredential",
  "schema_said": "EBfdlu...",
  "confidence": "high",
  "source": "schema_registry"
}
```

### Dossier Commands

#### `vvp dossier parse`

Parse a dossier (credential bundle) into individual ACDCs.

```bash
# Parse JSON array dossier
vvp dossier parse credentials.json

# Parse CESR-encoded dossier
vvp dossier parse dossier.cesr

# Parse from stdin
cat dossier.json | vvp dossier parse -
```

**Output:**
```json
{
  "credentials": [
    {
      "said": "ENPXp1vQ...",
      "issuer": "DER2Rc...",
      "schema": "EBfdlu...",
      "has_signature": true
    }
  ],
  "credential_count": 3,
  "format": "json_array",
  "signatures_extracted": 3
}
```

#### `vvp dossier validate`

Validate dossier DAG structure (no cycles, proper roots).

```bash
# Basic validation
cat dossier.json | vvp dossier validate -

# Allow multiple roots (aggregate dossiers)
cat aggregate.json | vvp dossier validate - --allow-aggregate
```

**Output:**
```json
{
  "valid": true,
  "root_saids": ["ENPXp1vQ..."],
  "is_aggregate": false,
  "node_count": 4,
  "cycle_detected": false,
  "errors": [],
  "warnings": []
}
```

#### `vvp dossier fetch`

Fetch a dossier from a URL and parse it.

```bash
# Fetch and parse
vvp dossier fetch "https://evd.example.com/dossier/ENPXp1vQ..."

# Chain with validation
vvp dossier fetch "$URL" | vvp dossier validate -
```

### Graph Commands

#### `vvp graph build`

Build a credential graph from a dossier.

```bash
# Build graph from dossier
cat dossier.json | vvp graph build -

# With trusted roots for validation
vvp graph build dossier.cesr --trusted-roots "DER2Rc...,DFG4Xy..."

# Pretty-printed for visualization
cat dossier.json | vvp graph build - -f pretty
```

**Output:**
```json
{
  "nodes": [
    {
      "said": "ENPXp1vQ...",
      "type": "QVI",
      "status": "valid",
      "layer": 1
    }
  ],
  "edges": [
    {
      "from_said": "EFG5Yz...",
      "to_said": "ENPXp1vQ...",
      "edge_type": "chain"
    }
  ],
  "root_aids": ["DER2Rc..."],
  "trust_paths_valid": true
}
```

### KEL Commands

#### `vvp kel parse`

Parse a Key Event Log and display its events.

```bash
# Parse from file
vvp kel parse identifier.cesr

# Parse from witness
curl -s "$WITNESS/kel/$AID" | vvp kel parse -

# Include full key lists
vvp kel parse identifier.cesr --show-keys
```

**Output:**
```json
{
  "events": [
    {
      "type": "icp",
      "type_description": "Inception (create new identifier)",
      "sequence": 0,
      "digest": "ENPXp1vQ...",
      "identifier": "DER2Rc...",
      "controller_sigs": 1,
      "witness_receipts": 3
    },
    {
      "type": "ixn",
      "type_description": "Interaction (anchor data)",
      "sequence": 1,
      "digest": "EFG5Yz...",
      "identifier": "DER2Rc...",
      "prior_digest": "ENPXp1vQ..."
    }
  ],
  "event_count": 2,
  "current_key": "DO8ej...",
  "key_state_sequence": 0,
  "aid": "DER2Rc..."
}
```

#### `vvp kel validate`

Validate KEL chain continuity and integrity.

```bash
# Basic validation
vvp kel validate identifier.cesr

# Include SAID validation
vvp kel validate identifier.cesr --validate-saids

# Include witness receipt validation
vvp kel validate identifier.cesr --validate-witnesses
```

**Output:**
```json
{
  "valid": true,
  "event_count": 5,
  "final_sequence": 4,
  "errors": [],
  "warnings": []
}
```

## Chaining Examples

The VVP CLI tools are designed to chain together using Unix pipes.

### Full Verification Chain

Parse a JWT, extract the evidence URL, fetch the dossier, validate it, and build a graph:

```bash
vvp jwt parse token.jwt | \
  jq -r '.payload.evd' | \
  xargs vvp dossier fetch | \
  vvp dossier validate - | \
  vvp graph build - --trusted-roots "$TRUSTED_ROOTS"
```

### Validate All SAIDs in a Dossier

```bash
cat dossier.json | vvp dossier parse - | \
  jq -c '.credentials[]' | \
  while read cred; do
    echo "$cred" | vvp said validate -
  done
```

### Extract Credential Chain from JWT

```bash
# Get the complete verification context
JWT=$(cat token.jwt)
IDENTITY=$(echo "$JWT" | vvp jwt parse - | jq -r '.header.x5u // empty')

# Fetch and analyze the dossier
EVD_URL=$(echo "$JWT" | vvp jwt parse - | jq -r '.payload.evd')
vvp dossier fetch "$EVD_URL" | vvp graph build - -f pretty
```

### Analyze KEL from Witness

```bash
# Fetch and analyze an identifier's key history
curl -s "http://localhost:5642/kel/$AID" | vvp kel parse - | jq '.events[] | {type, sequence}'
```

### Debug Credential Structure

```bash
# Analyze a credential step by step
cat credential.json | vvp acdc parse - -f pretty
cat credential.json | vvp said validate -
cat credential.json | vvp acdc type -
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Validation failure (invalid input) |
| 2 | Parse error (malformed input) |
| 3 | I/O error (file not found, network) |

## Troubleshooting

### Import Errors

If you see import errors, ensure the verifier package is installed:

```bash
pip install -e services/verifier
pip install -e 'common[cli]'
```

### libsodium Errors

On macOS, if you see libsodium errors:

```bash
brew install libsodium
export DYLD_LIBRARY_PATH="/opt/homebrew/lib:$DYLD_LIBRARY_PATH"
```

### Empty Output

If a command produces empty output, check:
1. Input format is correct (JSON, CESR, JWT)
2. Use `-f pretty` to see formatted output
3. Check stderr for error messages

## See Also

- [VVP Verifier Specification](VVP_Verifier_Specification_v1.5.md)
- [KERI Specification](https://github.com/WebOfTrust/ietf-keri)
- [ACDC Specification](https://github.com/WebOfTrust/ietf-acdc)
