# Current Plan

<!-- STATUS: IMPLEMENTED -->
<!-- RECONSTRUCTED: This plan was reconstructed from commit message and implementation code -->

## Phase 8: Test Vectors per VVP Spec §10

### Overview

Implement test vectors as specified in VVP Specification §10. Each vector includes input artifacts, verification context, and expected results. The test infrastructure supports time freezing, configuration patching, and HTTP mocking for deterministic testing.

### Spec References

- **§10** - Test Vectors
- **§10.2** - Required Test Cases
- **§10.3** - Test Vector Format

### Implementation

**8 Test Vectors:**
- 6 Tier 1 passing (fully tested)
- 2 Tier 2 skipped (require historical key state / SAID verification)

### Files to Create

| File | Action | Description |
|------|--------|-------------|
| `tests/vectors/__init__.py` | Create | Package init |
| `tests/vectors/conftest.py` | Create | Pytest fixtures |
| `tests/vectors/schema.py` | Create | Pydantic models for vector format |
| `tests/vectors/helpers.py` | Create | JWT/header generation utilities |
| `tests/vectors/runner.py` | Create | VectorRunner with mocking infrastructure |
| `tests/vectors/test_vectors.py` | Create | Parametrized test execution |
| `tests/vectors/data/v01_valid_happy_path.json` | Create | Vector: Valid request |
| `tests/vectors/data/v02_forbidden_algorithm.json` | Create | Vector: ES256 forbidden |
| `tests/vectors/data/v03_invalid_signature.json` | Create | Vector: Bad signature |
| `tests/vectors/data/v04_key_rotated.json` | Create | Vector: Key rotation (Tier 2) |
| `tests/vectors/data/v05_oobi_timeout.json` | Create | Vector: OOBI timeout |
| `tests/vectors/data/v06_dossier_unreachable.json` | Create | Vector: HTTP 503 |
| `tests/vectors/data/v07_said_mismatch.json` | Create | Vector: SAID mismatch (Tier 2) |
| `tests/vectors/data/v08_acdc_variants.json` | Create | Vector: ACDC DAG |

### Test Vector Format (§10.3)

```python
class VectorCase(BaseModel):
    id: str                              # e.g., "v01"
    name: str                            # e.g., "valid_happy_path"
    description: str                     # Human-readable description
    tier: int = 1                        # 1 = Tier 1, 2 = Tier 2
    skip_reason: Optional[str] = None   # Why vector is skipped
    input: VectorInput                   # VVP-Identity, PASSporT, context
    artifacts: VectorArtifacts           # Mock HTTP responses
    verification_context: VerificationContext  # Reference time, skew, etc.
    expected: ExpectedResult             # overall_status, claim tree, errors
```

### Test Vectors

| ID | Name | Tier | Status | Description |
|----|------|------|--------|-------------|
| v01 | valid_happy_path | 1 | ✓ | Valid VVP-Identity + EdDSA PASSporT + dossier → VALID |
| v02 | forbidden_algorithm | 1 | ✓ | PASSporT uses ES256 → INVALID |
| v03 | invalid_signature | 1 | ✓ | Ed25519 signature verification fails → INVALID |
| v04 | key_rotated | 2 | SKIP | Key rotated before T (requires historical state) |
| v05 | oobi_timeout | 1 | ✓ | Dossier fetch timeout → INDETERMINATE |
| v06 | dossier_unreachable | 1 | ✓ | Dossier HTTP 503 → INDETERMINATE |
| v07 | said_mismatch | 2 | SKIP | ACDC SAID doesn't match (requires SAID verification) |
| v08 | acdc_variants | 1 | ✓ | Valid multi-node ACDC DAG → VALID |

### Test Infrastructure

#### VectorRunner

```python
class VectorRunner:
    """Runs test vectors with deterministic mocking.

    Features:
    - Time freezing at reference_time_t
    - Configuration patching (clock_skew, max_token_age)
    - httpx.AsyncClient mocking for dossier fetch
    - Proper AsyncMock context manager support
    """

    async def run(self, vector: VectorCase) -> VerifyResponse:
        """Execute vector and return verification response."""

    def assert_result(
        self,
        response: VerifyResponse,
        expected: ExpectedResult
    ) -> None:
        """Assert response matches expected result.

        Checks:
        - overall_status matches
        - Claim tree structure matches (if specified)
        - Child count verification (Tier 1 structure guarantee)
        - Error codes present (if specified)
        """
```

#### Claim Tree Assertions

```python
class ExpectedClaimNode(BaseModel):
    name: str
    status: ExpectedStatus
    reasons_contain: Optional[List[str]] = None   # Substring match
    evidence_contain: Optional[List[str]] = None  # Substring match
    children: Optional[List[ExpectedChildLink]] = None

class ExpectedChildLink(BaseModel):
    required: bool
    node: ExpectedClaimNode
```

### Helper Utilities

```python
def make_vvp_identity_header(
    ppt: str = "vvp",
    kid: str = "...",
    evd: str = "...",
    iat: int = ...,
    exp: Optional[int] = None,
) -> str:
    """Generate base64url-encoded VVP-Identity header."""

def make_passport_jwt(
    header: dict,
    payload: dict,
    private_key: bytes,
) -> str:
    """Generate signed PASSporT JWT."""

def generate_ed25519_keypair() -> Tuple[bytes, bytes]:
    """Generate Ed25519 keypair for testing."""
```

### Checklist Tasks Covered

- [x] 8.1 - Create test vector directory structure
- [x] 8.2 - Valid VVP-Identity + valid EdDSA PASSporT + valid dossier → VALID
- [x] 8.3 - PASSporT uses forbidden algorithm (ES256) → INVALID
- [x] 8.4 - PASSporT signature invalid at reference time T → INVALID
- [x] 8.6 - OOBI/KERI resolution timeout → INDETERMINATE
- [x] 8.7 - Dossier unreachable → INDETERMINATE
- [x] 8.9 - Valid compact/partial/aggregate dossier variant → VALID
- [x] 8.10 - Each vector includes: input, artefacts, T, expected tree, errors
- [x] 8.11 - Implement test vector runner

### Deferred Tasks (Tier 2)

- [ ] 8.5 - Key rotated/revoked before T (historical) → INVALID
- [ ] 8.8 - SAID mismatch under most-compact-form rule → INVALID
- [ ] 8.12 - CI integration for test vectors

### Test Results

```
271 passed, 2 skipped
Skipped:
- v04_key_rotated: Requires Tier 2 historical key state
- v07_said_mismatch: Requires Tier 2 SAID verification
```

---

**Status:** IMPLEMENTED
**Commit:** `59b4942`
