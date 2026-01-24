# Current Plan

<!-- STATUS: IMPLEMENTED -->
<!-- RECONSTRUCTED: This plan was reconstructed from commit message and implementation code -->

## Phase 5: Dossier Fetching and Structural Validation (Tier 1)

### Overview

Implement dossier (ACDC credential bundle) fetching and structural validation per VVP Specification §6.1. This includes HTTP fetch with constraints, ACDC JSON parsing, and DAG validation. CESR parsing, SAID verification, and issuer signature verification are deferred to Tier 2.

### Spec References

- **§6.1** - Dossier Structure
- **§6.1A** - ACDC Node Structure (d, i, s, a, e, r fields)
- **§6.1B** - Dossier Fetch Constraints (timeout, size, redirects, content-type)
- **§4.2A** - Error codes: DOSSIER_FETCH_FAILED, DOSSIER_PARSE_FAILED, DOSSIER_GRAPH_INVALID

### Tier 1 Scope

**Implemented:**
- HTTP fetch with timeout, size limit, and redirect constraints
- ACDC JSON parsing with required field validation
- DAG construction from edge references
- Cycle detection
- Root node identification (node with no incoming edges)
- Error classification: recoverable (FetchError) vs non-recoverable (ParseError, GraphError)

**Deferred to Tier 2:**
- CESR parsing (application/json+cesr)
- SAID computation using "most compact form" rule
- SAID verification (Blake3-256)
- Issuer signature verification via KERI historical key state

### Files to Create/Modify

| File | Action | Description |
|------|--------|-------------|
| `app/vvp/dossier/__init__.py` | Create | Package init with exports |
| `app/vvp/dossier/exceptions.py` | Create | DossierError, FetchError, ParseError, GraphError |
| `app/vvp/dossier/models.py` | Create | ACDCNode, DossierDAG dataclasses |
| `app/vvp/dossier/fetch.py` | Create | Async HTTP fetch with httpx |
| `app/vvp/dossier/parser.py` | Create | ACDC JSON structure parsing |
| `app/vvp/dossier/validator.py` | Create | DAG cycle detection, root finding |
| `app/core/config.py` | Modify | Add dossier config constants |
| `pyproject.toml` | Modify | Add httpx dependency |
| `tests/test_dossier.py` | Create | Unit tests |

### Implementation Approach

#### 1. Exception Hierarchy

```python
class DossierError(Exception):
    """Base exception for dossier-related errors."""
    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message

class FetchError(DossierError):
    """Network/timeout errors → INDETERMINATE (recoverable)."""

class ParseError(DossierError):
    """JSON/structure errors → INVALID (non-recoverable)."""

class GraphError(DossierError):
    """DAG validation errors → INVALID (non-recoverable)."""
```

#### 2. Data Models

```python
@dataclass(frozen=True)
class ACDCNode:
    """ACDC credential node per spec §6.1A."""
    said: str                           # d field - Self-Addressing ID
    issuer: str                         # i field - Issuer AID
    schema: str                         # s field - Schema SAID
    attributes: Optional[Any] = None    # a field - may be SAID (compact)
    edges: Optional[Dict] = None        # e field - references to other ACDCs
    rules: Optional[Dict] = None        # r field - rules block
    raw: Dict = field(default_factory=dict)  # For SAID recomputation

@dataclass
class DossierDAG:
    """DAG of ACDC nodes per spec §6.1."""
    nodes: Dict[str, ACDCNode]
    root_said: Optional[str] = None
```

#### 3. HTTP Fetch

```python
async def fetch_dossier(url: str) -> bytes:
    """Fetch dossier from URL with constraints per §6.1B.

    Constraints:
    - Timeout: 5 seconds (configurable)
    - Max size: 1 MB (configurable)
    - Max redirects: 3 (configurable)
    - Content-Type: application/json or application/json+cesr

    Raises:
        FetchError: On network/timeout/size errors (recoverable)
    """
```

#### 4. ACDC Parser

```python
def parse_dossier(raw: bytes) -> List[ACDCNode]:
    """Parse dossier JSON into ACDC nodes.

    Expects either:
    - Single ACDC object: {"d": "...", "i": "...", ...}
    - Array of ACDCs: [{"d": ...}, {"d": ...}]

    Raises:
        ParseError: On JSON/structure errors (non-recoverable)
    """
```

#### 5. DAG Validator

```python
def build_dag(nodes: List[ACDCNode]) -> DossierDAG:
    """Build DAG from list of ACDC nodes."""

def validate_dag(dag: DossierDAG) -> None:
    """Validate DAG structure per §6.1.

    Checks:
    - No cycles (depth-first traversal)
    - Exactly one root node (no incoming edges)
    - All edge targets exist in DAG

    Raises:
        GraphError: On validation failure (non-recoverable)
    """
```

### Configuration Constants

```python
DOSSIER_FETCH_TIMEOUT_SECONDS = 5.0   # Per §6.1B
DOSSIER_MAX_SIZE_BYTES = 1_048_576    # 1 MB
DOSSIER_MAX_REDIRECTS = 3             # Per §6.1B
```

### Validation Rules

| Check | Action | Error Code |
|-------|--------|------------|
| Network timeout | Reject | DOSSIER_FETCH_FAILED (recoverable) |
| HTTP error (4xx/5xx) | Reject | DOSSIER_FETCH_FAILED (recoverable) |
| Too many redirects | Reject | DOSSIER_FETCH_FAILED (recoverable) |
| Response too large | Reject | DOSSIER_FETCH_FAILED (recoverable) |
| Invalid content-type | Reject | DOSSIER_FETCH_FAILED (recoverable) |
| Invalid JSON | Reject | DOSSIER_PARSE_FAILED (non-recoverable) |
| Missing required field (d, i, s) | Reject | DOSSIER_PARSE_FAILED (non-recoverable) |
| Cycle in DAG | Reject | DOSSIER_GRAPH_INVALID (non-recoverable) |
| No root node | Reject | DOSSIER_GRAPH_INVALID (non-recoverable) |
| Multiple root nodes | Reject | DOSSIER_GRAPH_INVALID (non-recoverable) |
| Edge target not in DAG | Reject | DOSSIER_GRAPH_INVALID (non-recoverable) |

### Test Strategy

| Test Case | Expected Result |
|-----------|-----------------|
| **Fetch** | |
| Valid URL, valid response | Returns bytes |
| Network timeout | DOSSIER_FETCH_FAILED |
| HTTP 404 | DOSSIER_FETCH_FAILED |
| HTTP 503 | DOSSIER_FETCH_FAILED |
| Too many redirects | DOSSIER_FETCH_FAILED |
| Response > 1MB | DOSSIER_FETCH_FAILED |
| Wrong content-type | DOSSIER_FETCH_FAILED |
| **Parsing** | |
| Valid single ACDC | Returns [ACDCNode] |
| Valid ACDC array | Returns [ACDCNode, ...] |
| Invalid JSON | DOSSIER_PARSE_FAILED |
| Missing d field | DOSSIER_PARSE_FAILED |
| Missing i field | DOSSIER_PARSE_FAILED |
| Missing s field | DOSSIER_PARSE_FAILED |
| **DAG Validation** | |
| Valid single-node DAG | Valid, node is root |
| Valid multi-node DAG | Valid, root identified |
| Cycle detected | DOSSIER_GRAPH_INVALID |
| No root (all have incoming) | DOSSIER_GRAPH_INVALID |
| Multiple roots | DOSSIER_GRAPH_INVALID |
| Edge to nonexistent node | DOSSIER_GRAPH_INVALID |

### Checklist Tasks Covered

- [x] 5.1 - Create fetch.py module
- [x] 5.2 - Create model.py module
- [x] 5.3 - Define ACDCNode dataclass
- [x] 5.4 - Define DossierGraph dataclass
- [x] 5.5 - Implement OOBI dereference for evd field
- [x] 5.6 - Validate response content-type
- [x] 5.7 - Enforce timeout (5 seconds)
- [x] 5.8 - Enforce redirect limits
- [x] 5.9 - Enforce size limit (1MB)
- [x] 5.12 - Implement DAG cycle detection
- [x] 5.13 - Validate explicit root node exists
- [x] 5.19 - Handle fetch failures → INDETERMINATE
- [x] 5.20 - Unit tests for dossier validation

### Deferred Tasks (Tier 2)

- [ ] 5.10 - Parse dossier using KERI/CESR parser
- [ ] 5.11 - Handle ACDC variants: compact, partial, aggregate
- [ ] 5.14 - Implement "most compact form" SAID computation
- [ ] 5.15 - Verify each ACDC SAID matches recomputed value
- [ ] 5.16 - Verify ACDC issuer signatures via KERI historical key state
- [ ] 5.17 - Verify ACDC proofs present where required
- [ ] 5.18 - Enforce freshness/expiry policy on credentials

### Test Results

```
222 passed (161 prior + 61 new)
```

---

**Status:** IMPLEMENTED
**Commit:** `98cffc5`
