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

---

## Test Conventions

1. **File naming**: `test_{module_name}.py` mirrors `app/{module_name}.py`
2. **Fixtures**: Shared in `conftest.py`, service-specific
3. **Mocking**: External services (witnesses, OOBI endpoints) are mocked
4. **Test vectors**: Formal vectors in `tests/vectors/` with schema validation
5. **libsodium**: Required for crypto tests - always use test runner script
6. **keripy exclusion**: `keripy/` directory excluded in `pytest.ini` to avoid conflicts
