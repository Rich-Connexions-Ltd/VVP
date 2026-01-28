# VVP Verifier System Internals

This document is a deep technical reference for the VVP Verifier. It is designed for experienced engineers who need to understand the comprehensive lifecycle of a VVP verification request, the specific algorithms used, and how to extend the codebase.

---

## 1. System Architecture

The VVP Verifier is a Python 3.12+ FastAPI application designed to verify cryptographic claims in Voice over IP (VoIP) calls. It implements the **Verifiable Voice Protocol (VVP)**, combining STIR/SHAKEN identity headers with KERI-based decentralized dossiers.

### Project Structure & Layering

The codebase follows a strict separation of concerns:

| Layer | Responsibility | Key Directory |
| :--- | :--- | :--- |
| **Interface** | HTTP handling, Request/Response models, Middleware | `app/main.py` |
| **Orchestration** | Wiring together phases (Passport -> Dossier -> Verification) | `app/vvp/verify.py` |
| **Domain (Dossier)** | Fetching, Parsing, caching, and DAG validation | `app/vvp/dossier/` |
| **Domain (ACDC)** | Credential chain verification and semantic rules | `app/vvp/acdc/` |
| **Core (KERI)** | Low-level CESR parsing, Signature verification | `app/vvp/keri/` |

---

## 2. Orchestration: The Life of a Request

**File:** `app/vvp/verify.py`
**Function:** `verify_vvp`

Every verification request flows through the `verify_vvp` function. It acts as the central nervous system, executing the VVP protocol phases sequentially.

```python
async def verify_vvp(req: VerifyRequest, ...):
    # Phase 2: Parse VVP-Identity header
    vvp_identity = parse_vvp_identity(...)

    # Phase 3: Parse and bind PASSporT
    passport = parse_passport(...)
    validate_passport_binding(passport, vvp_identity)

    # Phase 4: Verify Signature (Tier 2/3)
    # Resolves KeyState via OOBI if needed
    verify_passport_signature_tier2_with_key_state(...)

    # Phase 5: Fetch & Parse Dossier
    # This is the heavy lifting of gathering external evidence
    raw_dossier = await fetch_dossier(...)
    nodes, signatures = parse_dossier(raw_dossier)
    dag = build_dag(nodes)

    # Phase 6 & 9: Verification
    # Revocation checking and Claim Tree construction
    check_dossier_revocations(dag, ...)
    ...
```

---

## 3. Deep Dive: Dossier Parsing & CESR

The system must handle dossiers that arrive as either simple JSON or complex KERI CESR (Composable Event Streaming Representation) streams.

### Format Detection
**File:** `app/vvp/dossier/parser.py`

The parser uses a fast heuristic `_is_cesr_stream` to switch modes:
1.  **Strict CESR Parsing**: If data starts with a version string (`-_AAA`) or count code (`-`), it's treated as a CESR stream.
2.  **JSON with CESR Attachments**: Handle mixed formats common in web APIs.

### The CESR Engine
**File:** `app/vvp/keri/cesr.py`

This module implements a subset of the CESR specification (v1.0) required for VVP. It parses streams by reading **Count Codes**.

#### Key Concept: Count Codes
In CESR, a "Count Code" tells the parser what comes next.
*   **`-A`**: Controller Indexed Signatures.
*   **`-C`**: Witness Receipts (Non-transferable).
*   **`-V`**: Attachment Groups.

**Algorithm: Count Code Parsing**
```python
def _parse_count_code(data, offset):
    # Reads 2 bytes (Hard Code) e.g., "-A"
    # Looks up size in table (Hard/Soft/Full sizes)
    # Decodes Base64 characters to an integer Count
    return code, count, new_offset
```
This is critical for correctly slicing the byte stream without incorrectly interpreting binary signature data as control characters.

### Resilience: Permissive Fallback
**File:** `app/vvp/dossier/parser.py` -> `_extract_json_events_permissive`

If strict CESR parsing fails (e.g., due to a new attachment type from a newer KERI version), the system falls back to **Permissive Extraction**.
*   **Why?** To ensure forward compatibility. We prioritize reading the *content* (the JSON credential) even if we can't verify the *attachment* (the new signature type).
*   **How?** It iterates through the byte stream counting `{` and `}` braces, handling string escaping, to isolate valid JSON objects.

---

## 4. Graph Construction & Validation

**File:** `app/vvp/dossier/validator.py`

Once ACDCs are parsed, they are assembled into a **DossierDAG** (Directed Acyclic Graph).

### Cycle Detection
Cycles are illegal in a dossier. The system checks using a classic **3-Color Depth-First Search (DFS)**.
*   **White**: Unvisited.
*   **Gray**: Visiting (in stack).
*   **Black**: Visited.
If DFS encounters a `Gray` node, a back-edge exists -> **Invalid**.

### Root Finding
A standard dossier must have exactly one root (no incoming edges).
*   Correctness is enforced by calculating `Roots = AllNodes - Set(AllEdgeTargets)`.
*   If `len(Roots) != 1`, the dossier structure is invalid (unless Aggregate mode is enabled).

---

## 5. Credential Verification (ACDC)

**File:** `app/vvp/acdc/verifier.py`

This is where the semantic meaning of the credentials is validated.

### Chain Validation
The function `validate_credential_chain` performs a recursive walk from a leaf credential up to a trusted root.

**Algorithm: Recursive Chain Walk**
1.  **Loop Detection**: Checks `current` against `visited` set.
2.  **Type Rules**: Applies semantic rules based on credential type:
    *   **APE**: Must have `vetting` edge to an LE credential.
    *   **DE**: Must have `delegate` edge; specific check for PSS signer matching.
    *   **TNAlloc**: Must have `jl` (jurisdiction link) to parent (unless root requlator).
3.  **Root Check**: If `issuer` is in `TRUSTED_ROOTS` (GLEIF/QVI), recursion success.
4.  **Edge Traversal**: Otherwise, resolve parent SAID from edges and recurse.

### Edge Semantics
Detailed edge validation ensures the graph implies the correct authority delegation.
*   **Compact Models**: A significant complexity is "Compact Variants" where edges are SAID strings (references) rather than embedded objects.
    *   If a compact credential references an external SAID (not in the dossier), the status becomes **INDETERMINATE** (per VVP §2.2) rather than INVALID. This "explicit uncertainty" is a key design principle.

---

## 6. Revocation Checking

**File:** `app/vvp/verify.py` -> `check_dossier_revocations`
**File:** `app/vvp/keri/tel_client.py`

Revocation is checked via the **Transaction Event Log (TEL)**.

### Strategy
1.  **Inline First**: The system first checks if TEL events are embedded directly in the dossier (common for self-contained proofs).
2.  **Registry Resolution (OOBI)**: If not inline, it uses the **Registry SAID (`ri` field)** to construct an OOBI URL.
3.  **Witness Query**: It queries the witnesses designated by that OOBI to get the authoritative state of the credential.

### Performance: The Dossier Cache
**File:** `app/vvp/dossier/cache.py`

To allow aggressive caching while supporting immediate revocation:
*   **Primary Index**: URL -> Dossier.
*   **Secondary Index**: SAID -> Set[URLs].
*   **Invalidation**: When a credential with SAID `X` is found to be revoked, *all* cached dossiers containing `X` are immediately invalidated via the secondary index.

---

## 7. Extending the Codebase

### Adding a New Credential Type
1.  **Define Rules**: Update `EDGE_RULES` in `app/vvp/acdc/verifier.py`.
2.  **Implement Validation**: Add a specialized validator function (e.g., `validate_newtype_credential`).
3.  **Hook into Walk**: Call it from `walk_chain` inside `validate_credential_chain`.

### Adding a new VVP Phase
1.  **Orchestrator**: Add the phase step in `app/vvp/verify.py`.
2.  **Model**: Update `VerifyResponse` in `app/vvp/api_models.py` if new claims are produced.
3.  **Logic**: Implement the domain logic in a new module under `app/vvp/`.
