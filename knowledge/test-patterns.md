# VVP Test Patterns

## Running Tests

**Always use the test runner script** - it handles libsodium library paths:

```bash
# From repo root:
./scripts/run-tests.sh                              # All tests
./scripts/run-tests.sh -v                            # Verbose
./scripts/run-tests.sh tests/test_signature.py       # Specific file
./scripts/run-tests.sh -k "test_format"              # Pattern match
./scripts/run-tests.sh --cov=app --cov-report=term-missing  # Coverage

# Or from service directory:
cd services/verifier && ./scripts/run-tests.sh -v
cd services/issuer && ./scripts/run-tests.sh -v
```

The script sets `LD_LIBRARY_PATH` (Linux) or `DYLD_LIBRARY_PATH` (macOS) for libsodium.

---

## Verifier Test Files (`services/verifier/tests/`)

### By Component

| Test File | What It Tests |
|-----------|--------------|
| **Core Pipeline** | |
| `test_header.py` | VVP-Identity header parsing |
| `test_passport.py` | PASSporT JWT parsing |
| `test_verify.py` | Main verification orchestrator |
| `test_verify_callee.py` | Callee verification (§5B) |
| `test_full_verification.py` | End-to-end verification flow |
| **KERI/Crypto** | |
| `test_signature.py` | Ed25519 signature verification |
| `test_cesr_parser.py` | CESR stream parsing |
| `test_cesr_negative.py` | CESR error handling |
| `test_cesr_pss.py` | CESR PSS (partial signature) |
| `test_kel_resolver.py` | KEL resolution via OOBI |
| `test_kel_parser.py` | KEL event parsing |
| `test_kel_chain.py` | KEL chain validation |
| `test_kel_cache.py` | KEL cache behavior |
| `test_kel_integration.py` | KEL integration tests |
| `test_kel_cesr_integration.py` | KEL+CESR integration |
| `test_witness_pool.py` | Witness pool management |
| `test_witness_validation.py` | Witness receipt validation |
| `test_witness_receipts.py` | Witness receipt parsing |
| `test_local_witnesses.py` | Local witness tests |
| **Credentials** | |
| `test_acdc.py` | ACDC model and parsing |
| `test_dossier.py` | Dossier parsing and DAG |
| `test_dossier_cache.py` | Dossier caching |
| `test_credential_graph.py` | Credential graph validation |
| `test_credential_resolver.py` | External credential resolution |
| `test_credential_cache.py` | Credential caching |
| `test_credential_viewmodel.py` | Credential display models |
| `test_revocation_checker.py` | TEL revocation checking |
| `test_chain_revocation.py` | Chain-wide revocation |
| **Authorization** | |
| `test_authorization.py` | Authorization chain validation |
| `test_delegation.py` | Delegation chain traversal |
| `test_delegation_ui.py` | Delegation UI display |
| `test_trusted_roots.py` | Trusted root AID validation |
| **Schema** | |
| `test_schema_validation.py` | Schema SAID validation |
| `test_schema_store.py` | Schema storage |
| `test_schema_resolver.py` | Schema resolution |
| `test_schema_cache.py` | Schema caching |
| **Features** | |
| `test_brand.py` | Brand credential verification |
| `test_goal.py` | Goal claim verification |
| `test_sip_context.py` | SIP contextual alignment |
| `test_vetter_constraints.py` | Vetter geographic constraints |
| `test_vetter_certification.py` | Vetter certification validation |
| `test_identity.py` | Identity resolution |
| `test_identity_resolver.py` | Identity resolver logic |
| **Infrastructure** | |
| `test_models.py` | Pydantic model validation |
| `test_admin.py` | Admin endpoints |
| `test_e2e_endpoints.py` | API endpoint integration |
| `test_ui_endpoints.py` | UI page rendering |
| `test_tn_utils.py` | Telephone number utilities |
| `test_said_canonical.py` | SAID canonicalization |
| `test_canonicalization.py` | JSON canonicalization |
| `test_oobi.py` | OOBI resolution |
| `test_gleif.py` | GLEIF witness discovery |
| `test_edge_operator.py` | Edge operator logic |
| **Integration** | |
| `test_trial_dossier_e2e.py` | Full flow with real dossier |
| `test_live_verification_e2e.py` | Live verification test |
| `test_keripy_integration.py` | Keripy library integration |
| **Test Vectors** | |
| `vectors/test_vectors.py` | Spec-defined test vectors |
| `vectors/runner.py` | Test vector runner framework |
| `vectors/schema.py` | Test vector schema definitions |
| `vectors/helpers.py` | Test vector helpers |

### Fixtures (`conftest.py`)
Key shared fixtures:
- `sample_jwt` - Valid PASSporT JWT for testing
- `sample_vvp_identity` - Valid VVP-Identity header
- `sample_dossier` - Parsed dossier DAG
- `mock_kel_resolver` - Mocked KEL resolver
- `mock_tel_client` - Mocked TEL client

---

## Issuer Test Files (`services/issuer/tests/`)

| Test File | What It Tests |
|-----------|--------------|
| `test_health.py` | Health endpoint |
| `test_identity.py` | KERI identity CRUD |
| `test_registry.py` | Registry CRUD |
| `test_credential.py` | Credential issuance/revocation |
| `test_dossier.py` | Dossier building |
| `test_dossier_revocation.py` | Dossier revocation handling |
| `test_tn_mapping.py` | TN mapping CRUD and lookup |
| `test_schema.py` | Schema operations |
| `test_auth.py` | Authentication (API key, session) |
| `test_session.py` | Session management |
| `test_oauth.py` | Microsoft OAuth integration |
| `test_users.py` | User management |
| `test_persistence.py` | Database persistence |
| `test_said.py` | SAID computation |
| `test_import.py` | Module import tests |
| `test_vvp_header.py` | VVP header generation |
| `test_vvp_passport.py` | PASSporT JWT generation |
| `test_sprint41_multitenancy.py` | Multi-tenancy features |
| `test_vetter_certification.py` | VetterCert API CRUD, access control, schema guard (22 tests, Sprint 61) |
| `test_vetter_constraints.py` | Pydantic validation, `resolve_active_vetter_cert()`, edge injection, constants (27 tests, Sprint 61) |
| `test_dossier_readiness.py` | Dossier readiness endpoint, per-slot status, I2I checks, bproxy gate (25 tests, Sprint 65) |
| `test_walkthrough.py` | Walkthrough page auth/access, route registration (Sprint 66) |
| `test_no_keripy.py` | AST-based import guard — ensures no keripy/lmdb/hio imports in issuer code (Sprint 68c) |
| `test_agent_contract.py` | 28 DTO contract tests — field presence, validation, round-trip serialization (Sprint 68c) |
| `test_said_parity.py` | 26 SAID parity tests — pure-Python blake3+CESR vs embedded schema SAIDs (Sprint 68c) |
| `test_passport_parity.py` | 13 attestation request/response shape and outage propagation tests (Sprint 68c) |
| `test_dossier_parity.py` | 4 outage propagation tests — KeriAgentUnavailableError through revocation/TN paths (Sprint 68c) |

---

## Test Conventions

1. **File naming**: `test_{module_name}.py` mirrors `app/{module_name}.py`
2. **Fixtures**: Shared in `conftest.py`, service-specific
3. **Mocking**: `MockKeriAgentClient` in conftest.py replaces all KERI operations (Sprint 68b). External services (witnesses, OOBI endpoints) are mocked
4. **Test vectors**: Formal vectors in `tests/vectors/` with schema validation
5. **libsodium**: Required for crypto tests - always use test runner script
6. **keripy exclusion**: `keripy/` directory excluded in `pytest.ini` to avoid conflicts

### Test Identity Conventions (Post-Sprint 73)

Integration tests that create identities on the live platform follow these conventions:

1. **Name prefix**: All test identities use a `test-` prefix (e.g., `test-api-rotate-a1b2c3d4`, `test-integ-e5f6g7h8`)
2. **Metadata tag**: All test identities are created with `metadata={"type": "test"}` so they can be filtered by the bulk cleanup API
3. **Three-layer cleanup**:
   - **Per-test**: `test_identity` fixture deletes its identity in teardown
   - **Session**: `cleanup_test_identities` autouse fixture sweeps leftover `test-*` identities after the test session
   - **CI**: `deploy.yml` "Cleanup test identities" step calls `POST /admin/cleanup/identities` with `metadata_type: "test"` after every post-deployment test run

Key files:
- `tests/integration/conftest.py` — `TEST_IDENTITY_PREFIXES` tuple, `cleanup_test_identities` fixture
- `tests/integration/helpers/issuer_client.py` — `create_identity(metadata=...)` parameter
- `.github/workflows/deploy.yml` — "Cleanup test identities" step

### Sprint 61 Test Patterns

**Direct DB org creation** (`_create_db_org()`): Creates organizations directly in the database via `SessionLocal()`, bypassing KERI infrastructure. Used when tests need an org with an AID but don't need real KERI identity management. Pattern:
```python
def _create_db_org(*, aid=None):
    _init_app_db()
    from app.db.session import SessionLocal
    db = SessionLocal()
    org = Organization(id=str(uuid.uuid4()), name=..., aid=aid or f"E{...}", ...)
    db.add(org); db.commit(); db.refresh(org)
    return org
```

**`_resolve_cert_attributes` mocking**: The vetter API tests mock `_resolve_cert_attributes` to avoid needing real KERI credential store access. Pattern:
```python
@patch("app.api.vetter_certification._resolve_cert_attributes", new_callable=AsyncMock)
async def test_list_certs(mock_resolve, ...):
    mock_resolve.return_value = {"ecc_targets": [...], "jurisdiction_targets": [...], ...}
```

**`resolve_active_vetter_cert` mocking**: The constraint tests mock the 7-point validation function. Returns `CredentialInfo(...)` for active cert or `None` for no cert:
```python
@patch("app.vetter.service.resolve_active_vetter_cert", new_callable=AsyncMock)
async def test_constraints(mock_resolve, ...):
    mock_resolve.return_value = CredentialInfo(said="E...", attributes={...}, ...)
```

**Schema JSON inspection**: `test_vetter_constraints.py` reads schema JSON files from disk to verify `schema_requires_certification_edge()` detects `oneOf` edge blocks correctly in extended schema definitions

### Sprint 65 Test Patterns

**In-memory SQLite with FK enforcement**: Readiness tests use an in-memory SQLite engine with `PRAGMA foreign_keys=ON` listener to enforce FK constraints during testing:
```python
@pytest.fixture
def in_memory_db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    @event.listens_for(engine, "connect")
    def _set_fk_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()
```

**`_full_cred_set()` helper**: Generates a complete set of `ManagedCredential` rows for all dossier edge slots (dossier, GCD, TNAlloc, LE). Used in readiness tests to simulate full credential availability:
```python
def _full_cred_set(org_id, org_aid):
    return [
        ManagedCredential(said="Edossier...", organization_id=org_id,
            schema_said=DOSSIER_SCHEMA_SAID, issuer_aid=org_aid),
        ManagedCredential(said="Egcd...", organization_id=org_id,
            schema_said=GCD_SCHEMA_SAID, issuer_aid=org_aid),
        ...
    ]
```

**Schema edge parsing mock**: Tests mock `_parse_schema_edges()` and `_check_edge_schema()` to test slot validation logic without loading real schema JSON files

### Sprint 68b Test Patterns

**`MockKeriAgentClient`**: All issuer tests use `MockKeriAgentClient` (conftest.py) instead of real KERI managers. The mock is installed as the `keri_client` singleton in the `client` and `client_with_auth` fixtures:
```python
keri_client_module._client = MockKeriAgentClient()
```

**Stateful tracking**: The mock tracks created identities, registries, and credentials in internal dicts (`_created_identities`, `_created_registries`, `_issued_credentials`). Operations like `create_identity`, `issue_credential`, and `delete_credential` update these dicts, so subsequent lookups (`get_credential`, `get_registry`) return consistent data.

**Patch target for `get_keri_client`**: Since `get_keri_client()` is a sync function (not async), patches must NOT use `new_callable=AsyncMock`:
```python
# Correct:
with patch("app.api.dossier.get_keri_client", return_value=mock_client):
# Wrong — will fail:
with patch("app.api.dossier.get_keri_client", new_callable=AsyncMock, return_value=mock_client):
```

**CESR mock includes SAID**: `get_credential_cesr(said)` returns bytes containing the credential SAID, enabling CESR format tests that check `said.encode() in content`:
```python
async def _get_credential_cesr(said):
    return f'{{"d":"{said}","v":"ACDC10JSON"}}'.encode()
```

### Sprint 68c Test Patterns

**Import guard test** (`test_no_keripy.py`): AST-based analysis ensures no issuer source file imports `keripy`, `lmdb`, or `hio`. Walks `app/` directory, parses each `.py` file, checks `Import` and `ImportFrom` AST nodes. Prevents accidental re-coupling:
```python
def test_no_keripy_imports():
    for py_file in Path("app").rglob("*.py"):
        tree = ast.parse(py_file.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert not alias.name.startswith(("keri.", "lmdb", "hio"))
```

**DTO contract tests** (`test_agent_contract.py`): Validates that issuer DTOs (`CreateVVPAttestationRequest`, `BootstrapStatusResponse`, `DossierBuildRequest`, etc.) match the agent's expected field names and types. Includes validation tests (missing required fields) and round-trip serialization (`.model_dump()` → `Model(**data)`).

**SAID parity tests** (`test_said_parity.py`): Tests pure-Python blake3+CESR SAID computation against known schema SAIDs embedded in `common/vvp/schema/schemas/*.json`. Verifies insertion-order JSON, `"#" * 44` placeholder, and CESR "E" prefix.

**Outage propagation tests** (`test_dossier_parity.py`, `test_passport_parity.py`): Verify that `KeriAgentUnavailableError` propagates through all code paths (TN lookup, dossier revocation, attestation) rather than being swallowed by broad `except Exception`. Key pattern: patch `_build_cache_entry` or `get_keri_client` at the source module (not the importing module) because functions are imported inside function bodies:
```python
# Correct: patch at source module (lazy import picks it up)
with patch("app.keri_client.get_keri_client", return_value=mock_client):
# Wrong: patch at consuming module (function imports inside body, bypasses patch)
with patch("app.tn.lookup.get_keri_client", return_value=mock_client):
```
