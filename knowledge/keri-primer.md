# KERI/ACDC/CESR Primer for VVP

This document explains KERI ecosystem concepts as they apply to this codebase. For authoritative KERI documentation, use the MCP knowledge base at `https://www.vlei.wiki/mcp` (tools: `keri_search`, `keri_explain`, `keri_get_document`, `keri_find_related`).

---

## KERI (Key Event Receipt Infrastructure)

KERI provides decentralized identity without X.509 certificates or blockchain. Authority is established via **verifiable key state** recorded in append-only event logs.

### Core Concepts Used in VVP

| Concept | What It Is | Where Used in VVP |
|---------|-----------|-------------------|
| **AID** | Autonomic Identifier - a self-certifying identifier derived from public key(s) | PASSporT signer identity, credential issuers, trusted roots |
| **KEL** | Key Event Log - ordered events (inception, rotation, delegation) defining key state | Resolved via OOBI to verify PASSporT signatures |
| **OOBI** | Out-of-Band Introduction - a URL that resolves to KERI resources | `kid` and `evd` fields in VVP-Identity header |
| **Witness** | Infrastructure node that receipts events for availability | Queried during KEL resolution and TEL lookups |
| **TEL** | Transaction Event Log - records credential issuance/revocation | Used for revocation checking in `tel_client.py` |
| **Registry** | TEL-backed structure governing credential lifecycle | Contains `iss`/`rev`/`bis`/`brv` events |

### Key State Resolution Flow (Tier 2 Verification)
```
PASSporT.kid (OOBI URL)
  → HTTP GET to witness endpoint
  → Returns KEL stream (CESR-encoded events)
  → Parse inception event → extract public key
  → Verify PASSporT signature against key at call time
```

**Code**: `services/verifier/app/vvp/keri/kel_resolver.py`

---

## ACDC (Authentic Chained Data Containers)

ACDCs are self-describing, cryptographically bound credentials. A **dossier** is a DAG of ACDCs that proves a caller's rights.

### ACDC Structure
```json
{
  "v": "ACDC10JSON...",     // Version string
  "d": "SAID",              // Self-Addressing Identifier (content hash)
  "i": "AID of issuer",     // Who issued this credential
  "ri": "Registry SAID",    // Which registry tracks its status
  "s": "Schema SAID",       // What type of credential this is
  "a": {                    // Attributes block
    "d": "SAID",
    "i": "AID of issuee",   // Who this credential is about
    "dt": "ISO8601",        // Issuance datetime
    ...                     // Type-specific attributes
  },
  "e": {                    // Edges block (links to other ACDCs)
    "d": "SAID",
    "edgename": {
      "n": "SAID of target ACDC",
      "s": "Schema SAID of target"
    }
  }
}
```

### Credential Types in VVP

| Type | Schema Purpose | Edge Rules | Code Reference |
|------|---------------|------------|----------------|
| **LE** (Legal Entity) | Identifies a legal entity vetted by a QVI | Root of vetting chain | `acdc/verifier.py` |
| **QVI** (Qualified vLEI Issuer) | Identifies a QVI authorized by GLEIF | Trusted intermediate | `acdc/verifier.py` |
| **APE** (Auth Phone Entity) | Authorizes an entity for phone calls | Must have `vetting` edge → LE | `authorization.py` |
| **DE** (Delegate Entity) | Delegates authority to a sub-entity | Must have `delegation`/`issuer` edge | `authorization.py` |
| **TNAlloc** (TN Allocation) | Allocates telephone numbers to an entity | Must have `jl` edge (jurisdiction) | `authorization.py` |
| **Brand** | Associates brand info with an entity | Optional, for display purposes | `authorization.py` |

### ACDC Variants
ACDCs can appear in three forms (VVP §1.4):
- **Full**: All attributes expanded inline
- **Compact**: Attributes replaced by SAID references (hash pointers)
- **Partial**: Some attributes expanded, others compacted

**Critical**: If a compact ACDC references an external SAID not in the dossier, status becomes **INDETERMINATE** (not INVALID). This is the "Explicit Uncertainty" principle.

### Credential Chain Validation Algorithm
```
walk_chain(credential, visited, depth):
  1. Check depth limit (prevent infinite recursion)
  2. Check visited set (detect cycles)
  3. Identify credential type from schema SAID
  4. Apply type-specific edge rules:
     - APE → must have vetting edge → LE credential
     - DE → must have delegation edge → parent APE/DE
     - TNAlloc → must have jl edge → parent allocator
  5. Check if issuer AID is a trusted root → SUCCESS
  6. Resolve parent credential from edges
  7. Recurse: walk_chain(parent, visited + current, depth + 1)
```

**Code**: `services/verifier/app/vvp/acdc/verifier.py:validate_credential_chain()`

---

## CESR (Composable Event Streaming Representation)

CESR is a binary-to-text encoding that allows events and signatures to be streamed together efficiently.

### How VVP Uses CESR
Dossiers can arrive as CESR streams containing multiple ACDCs with their cryptographic proofs (signatures, receipts).

### CESR Stream Parsing Algorithm
```
1. Detect format: check for version marker (-_AAA) or count code prefix (-)
2. Iterate through stream:
   a. If byte is '{' → JSON event (ACDC), find matching '}'
   b. If byte is '-' → Count code, read hard code (2 bytes)
      - Look up in COUNT_CODE_SIZES table
      - Read soft code to get count
      - Slice binary attachment data
   c. Map attachments (signatures) to preceding JSON event
3. If strict parsing fails → fall back to permissive mode:
   - Scan for balanced {} braces
   - Extract JSON objects, discard binary attachments
   - Ensures forward compatibility with newer KERI versions
```

### Key Count Codes
| Code | Meaning | Used For |
|------|---------|----------|
| `-A` | Controller Indexed Signatures | ACDC signatures |
| `-C` | Witness Receipts (Non-transferable) | Witness endorsements |
| `-V` | Attachment Groups | Grouped attachments |

**Code**: `services/verifier/app/vvp/keri/cesr.py`, `common/vvp/canonical/cesr.py`

---

## SAID (Self-Addressing Identifier)

A SAID is a content-derived hash embedded within the data it identifies. It provides tamper-evident self-verification.

### SAID Computation
1. Replace the `d` field with a placeholder of the correct length
2. Serialize the data to its canonical form (ordered JSON)
3. Compute Blake3-256 hash
4. Encode as CESR-compatible Base64
5. The result is the SAID that goes in the `d` field

**Important**: SAIDs must be computed from the "most compact form" of the data, not the received representation. This affects validation when comparing SAIDs.

**Code**: `common/vvp/canonical/said.py`

---

## Trust Model

### Trust Chain (bottom to top)
```
PASSporT Signer (AID)
  ↑ signed by
APE/DE Credential (authorizes signer for phone calls)
  ↑ vetting edge
LE Credential (legal entity identity)
  ↑ issued by
QVI (Qualified vLEI Issuer)
  ↑ authorized by
GLEIF Root (trusted anchor)
```

### Trusted Root AIDs
Configured in `services/verifier/app/core/config.py:TRUSTED_ROOT_AIDS`. These are the GLEIF and QVI AIDs that serve as trust anchors. The verifier traces every credential chain back to one of these roots.

### Revocation Checking
For each credential in the chain:
1. **Inline TEL** (fast path): Check for TEL events embedded in the dossier stream
2. **Registry OOBI**: Use the credential's `ri` field to construct an OOBI URL
3. **Witness Query**: Query witnesses for the credential's TEL state
4. Status: `iss`/`bis` event = ACTIVE, `rev`/`brv` event = REVOKED, no events = UNKNOWN

**Code**: `services/verifier/app/vvp/keri/tel_client.py`

---

## MCP Knowledge Base

For deeper KERI/ACDC/vLEI research, use the MCP server at `https://www.vlei.wiki/mcp`:
- `keri_search` - Search KERI documents
- `keri_explain` - Explain KERI concepts
- `keri_get_document` - Get full document content
- `keri_find_related` - Find related documents
- `keri_concepts_graph` - Get concept relationships
- `keri_gleif_context` - Extract GLEIF vLEI training context
