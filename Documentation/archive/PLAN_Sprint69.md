# Sprint 69: Ephemeral LMDB & Zero-Downtime KERI Deploys

## Problem Statement

The KERI Agent stores all state (identities, registries, credentials) in LMDB on an Azure Files (SMB) mount. LMDB relies on POSIX file locks for writer exclusion, but Azure Files does not correctly implement them. Every deployment risks LMDB corruption (`MDB_BAD_DBI`, `MDB_BAD_TXN`) when outgoing and incoming containers overlap. The fragile 3-phase stop sequence (deactivate → poll → 10s buffer) narrows the race window but cannot eliminate it, and introduces 5-7 minutes of downtime per deploy.

This sprint solves the root cause by making LMDB ephemeral — each container starts with fresh local LMDB and deterministically rebuilds all KERI state from key seeds and configuration stored in PostgreSQL. Since each container uses its own local filesystem, POSIX locks work correctly, there is no shared-state contention, and deploys become safe and fast.

## Spec References

- Sprint 69 definition in `SPRINTS.md` lines 5180-5402
- KERI salt determinism: keripy's `Habery(salt=...)` derives all signing keys deterministically from the salt
- SAID stability: credential SAIDs are computed from content (attributes, edges, schema, issuer AID) — same inputs → same SAID

## Current State

```
KERI Agent Container
├── Azure Files mount (/data/vvp-keri-agent)    ← SMB, POSIX lock issues
│   ├── keri/db/vvp-issuer/data.mdb             ← KEL database
│   ├── keri/ks/vvp-issuer/data.mdb             ← Keystore (private keys)
│   └── keri/reg/vvp-issuer/data.mdb            ← TEL registry
├── Salt: core.Salter().qb64 — random on first boot, stored in LMDB keystore
├── Deploy: 3-phase stop → deploy → verify (~5-7 min, risk of corruption)
├── Startup: open existing LMDB → load identities
└── No PostgreSQL dependency — pure LMDB/keripy
```

## Proposed Solution

### Approach

Add PostgreSQL as a new dependency to the KERI Agent. Persist the Habery salt and per-identity/registry/credential metadata to PostgreSQL. On startup, create a fresh LMDB on local ephemeral storage (`/tmp/vvp-keri-agent`) and rebuild all KERI state deterministically from the PostgreSQL records. This makes LMDB disposable — every container restart produces identical cryptographic state.

### Why This Approach

| Alternative | Pros | Cons | Why Rejected |
|-------------|------|------|--------------|
| Fix Azure Files locks (lock proxy) | No new dependency | Complex, doesn't fix SMB semantics | Azure Files fundamentally lacks POSIX locks |
| Migrate to Azure Managed Disk | Proper POSIX locks | Can't share across revisions, costly disk | Still single-writer, doesn't solve deploy overlap |
| Export/import LMDB snapshot (backup/restore) | No new dependency | Snapshot can be stale, no seed determinism | Doesn't guarantee AID stability |
| **PostgreSQL seed persistence (chosen)** | **Deterministic rebuild, zero corruption risk** | **New PG dependency for KERI Agent** | **Best: deterministic, proven, leverages existing PG** |

### Detailed Design

#### Architecture Overview

```
KERI Agent Container (after Sprint 69)
├── Local ephemeral storage (/tmp/vvp-keri-agent)  ← proper POSIX locks
│   ├── keystores/vvp-issuer/...                    ← rebuilt on startup
│   └── databases/vvp-issuer/...                    ← rebuilt on startup
├── PostgreSQL (shared with Issuer, different tables)
│   ├── keri_habery_salt      ← single row: the master salt
│   ├── keri_identity_seeds   ← per-identity params for makeHab() replay
│   ├── keri_registry_seeds   ← per-registry params for makeRegistry() replay
│   └── keri_credential_seeds ← per-credential params for issue_credential() replay
├── Startup: fresh LMDB → read PG → rebuild all state (~10-15s)
├── Deploy: standard rolling update (~30-60s, zero corruption risk)
└── Scaling: max_replicas=1 (single-writer, but local LMDB = no contention)
```

#### Component 1: Database Infrastructure (`app/db/`)

**Purpose**: Give the KERI Agent its own PostgreSQL connection with seed-specific tables.

**Files**:
- `services/keri-agent/app/db/__init__.py` — Package init
- `services/keri-agent/app/db/models.py` — SQLAlchemy models
- `services/keri-agent/app/db/session.py` — Engine, session factory, init_database()

**Config** (`app/config.py`):
```python
# New env var: VVP_KERI_AGENT_DATABASE_URL
# Default: sqlite:////{DATA_DIR}/keri_seeds.db (local dev)
# Production: postgresql+psycopg2://... (same PG instance as Issuer)
DATABASE_URL: str = os.getenv(
    "VVP_KERI_AGENT_DATABASE_URL",
    f"sqlite:///{DATA_DIR}/keri_seeds.db"
)
```

**Models** (`app/db/models.py`):

```python
class KeriHaberySalt(Base):
    """Master Habery salt — single row table.

    The Habery salt deterministically derives all signing keys for
    all identities. This is the crown jewel of the seed store.
    """
    __tablename__ = "keri_habery_salt"

    id = Column(Integer, primary_key=True)  # Always 1
    salt = Column(String(44), nullable=False)  # qb64-encoded salt
    habery_name = Column(String(100), nullable=False)  # e.g., "vvp-issuer"
    created_at = Column(DateTime, nullable=False)

class KeriIdentitySeed(Base):
    """Parameters to replay makeHab() for a specific identity."""
    __tablename__ = "keri_identity_seeds"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False, unique=True)  # "mock-gleif", "org-xxx"
    expected_aid = Column(String(44), nullable=False)  # For verification
    transferable = Column(Boolean, default=True, nullable=False)
    icount = Column(Integer, nullable=False)
    isith = Column(String(20), nullable=False)
    ncount = Column(Integer, nullable=False)
    nsith = Column(String(20), nullable=False)
    witness_aids = Column(Text, nullable=False)  # JSON array of witness AIDs
    toad = Column(Integer, nullable=False)
    created_at = Column(DateTime, nullable=False)
    metadata = Column(Text, nullable=True)  # JSON: {"type": "mock_gleif", "org_id": "..."}

class KeriRegistrySeed(Base):
    """Parameters to replay makeRegistry() for a specific registry."""
    __tablename__ = "keri_registry_seeds"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False, unique=True)  # "mock-gleif-registry"
    identity_name = Column(String(255), nullable=False)  # FK to keri_identity_seeds.name
    expected_registry_key = Column(String(44), nullable=False)  # For verification
    no_backers = Column(Boolean, default=True, nullable=False)
    nonce = Column(String(44), nullable=True)  # Registry nonce for deterministic rebuild
    created_at = Column(DateTime, nullable=False)

class KeriRotationSeed(Base):
    """Parameters to replay hab.rotate() for key rotation events.

    Each row represents one rotation event. On rebuild, rotations are
    replayed in sequence_number order after identity inception.
    """
    __tablename__ = "keri_rotation_seeds"

    id = Column(Integer, primary_key=True, autoincrement=True)
    identity_name = Column(String(255), nullable=False)  # Which identity was rotated
    sequence_number = Column(Integer, nullable=False)  # KEL sequence number of rotation
    ncount = Column(Integer, nullable=True)  # Next key count (None = use default)
    nsith = Column(String(20), nullable=True)  # Next signing threshold
    created_at = Column(DateTime, nullable=False)

    __table_args__ = (
        UniqueConstraint("identity_name", "sequence_number", name="uq_rotation_identity_sn"),
    )

class KeriCredentialSeed(Base):
    """Parameters to replay issue_credential() for a specific credential."""
    __tablename__ = "keri_credential_seeds"

    id = Column(Integer, primary_key=True, autoincrement=True)
    expected_said = Column(String(44), nullable=False, unique=True)  # For verification
    registry_name = Column(String(255), nullable=False)  # FK to registry seed
    schema_said = Column(String(44), nullable=False)
    issuer_identity_name = Column(String(255), nullable=False)  # Which identity issued
    recipient_aid = Column(String(44), nullable=True)
    attributes_json = Column(Text, nullable=False)  # Insertion-order JSON (compact)
    edges_json = Column(Text, nullable=True)  # Insertion-order JSON edge references
    rules_json = Column(Text, nullable=True)  # Insertion-order JSON rules
    private = Column(Boolean, default=False, nullable=False)
    rebuild_order = Column(Integer, nullable=False)  # Topological sort position
    edge_saids = Column(Text, nullable=True)  # JSON list of credential SAIDs this depends on
    created_at = Column(DateTime, nullable=False)
```

**JSON Serialization**: All JSON columns use **insertion-order** serialization via
`json.dumps(data, separators=(',', ':'))` (NO `sort_keys`). This preserves the
original dict key ordering, matching the insertion-order convention used throughout
the codebase for SAID computation (established in Sprint 68c). On deserialization,
`json.loads()` preserves the stored key order in Python 3.7+ dicts, so credentials
rebuilt from stored JSON produce identical SAIDs.

**Session** (`app/db/session.py`):
- Follows same pattern as `services/issuer/app/db/session.py`
- SQLite fallback for local dev/tests, PostgreSQL for production
- `init_database()` creates tables idempotently

#### Component 2: Seed Capture (`app/keri/seed_store.py`)

**Purpose**: Intercept identity/registry/credential creation to persist seeds.

**Interface**:
```python
class SeedStore:
    """Persists KERI seed data to PostgreSQL for deterministic rebuild."""

    async def save_habery_salt(self, salt: str, habery_name: str) -> None
    async def get_habery_salt(self, habery_name: str) -> Optional[str]

    async def save_identity_seed(self, name: str, expected_aid: str,
                                  transferable: bool, icount: int, isith: str,
                                  ncount: int, nsith: str, witness_aids: list[str],
                                  toad: int, metadata: Optional[dict] = None) -> None
    async def get_all_identity_seeds(self) -> list[KeriIdentitySeed]

    async def save_registry_seed(self, name: str, identity_name: str,
                                  expected_registry_key: str, no_backers: bool,
                                  nonce: Optional[str] = None) -> None
    async def get_all_registry_seeds(self) -> list[KeriRegistrySeed]

    async def save_rotation_seed(self, identity_name: str, sequence_number: int,
                                  ncount: Optional[int] = None,
                                  nsith: Optional[str] = None) -> None
    async def get_rotations_for_identity(self, identity_name: str) -> list[KeriRotationSeed]

    async def save_credential_seed(self, expected_said: str, registry_name: str,
                                    schema_said: str, issuer_identity_name: str,
                                    recipient_aid: Optional[str], attributes: dict,
                                    edges: Optional[dict], rules: Optional[dict],
                                    private: bool, rebuild_order: int,
                                    edge_saids: Optional[list[str]] = None) -> None
    async def get_all_credential_seeds(self) -> list[KeriCredentialSeed]

    async def compute_rebuild_order(self, edge_saids: Optional[list[str]]) -> int
    """Compute topological rebuild order from credential edge dependencies.

    Algorithm: for each edge SAID, look up its rebuild_order. This credential's
    rebuild_order = max(dependency rebuild_orders) + 1. Credentials with no edges
    get rebuild_order = 0. This ensures parents are always rebuilt before children.
    """

    async def has_seeds(self) -> bool
    """Check if any seeds exist (to distinguish first boot from rebuild)."""
```

**Behavior**:
- All save operations are idempotent (upsert on unique key)
- All get operations return ordered by `created_at` (identities) or `rebuild_order` (credentials)

#### Component 3: Seed Capture Integration

**`IssuerIdentityManager.initialize()`** — Modified to use stored salt:
```python
async def initialize(self) -> None:
    seed_store = get_seed_store()

    # Try to load existing Habery salt from PostgreSQL
    stored_salt = await seed_store.get_habery_salt(self._name)

    if stored_salt is not None:
        salt = stored_salt  # Deterministic: use stored salt
        log.info(f"Using stored Habery salt for {self._name}")
    else:
        salt = core.Salter().qb64  # First boot: generate new salt
        await seed_store.save_habery_salt(salt, self._name)
        log.info(f"Generated and stored new Habery salt for {self._name}")

    self._hby = habbing.Habery(
        name=self._name, base="", temp=self._temp,
        salt=salt, headDirPath=str(self._base_dir),
    )
```

**`IssuerIdentityManager.create_identity()`** — Persist seed after creation:
```python
async def create_identity(self, name, ...) -> IdentityInfo:
    # ... existing creation logic ...
    hab = self.hby.makeHab(name=name, ...)

    # NEW: Persist seed for rebuild
    seed_store = get_seed_store()
    await seed_store.save_identity_seed(
        name=name, expected_aid=hab.pre,
        transferable=transferable, icount=icount, isith=isith,
        ncount=ncount, nsith=nsith, witness_aids=wits, toad=toad,
    )

    return IdentityInfo(...)
```

**`CredentialRegistryManager.create_registry()`** — Persist registry nonce:
```python
async def create_registry(self, name, issuer_aid, no_backers=True) -> RegistryInfo:
    # ... existing creation logic ...
    registry = self.regery.makeRegistry(name=name, prefix=issuer_aid, noBackers=no_backers)

    # NEW: Capture and persist registry nonce for rebuild
    nonce = registry.vcp.ked.get("n", "")  # VCP inception nonce
    seed_store = get_seed_store()
    await seed_store.save_registry_seed(
        name=name, identity_name=...,
        expected_registry_key=registry.regk,
        no_backers=no_backers, nonce=nonce,
    )

    # ... rest of existing code ...
```

**`IssuerIdentityManager.rotate_identity()`** — Persist rotation event:
```python
async def rotate_identity(self, aid, next_key_count=None, next_threshold=None) -> RotationResult:
    # ... existing rotation logic ...
    rotation_msg = hab.rotate(ncount=next_key_count, nsith=next_threshold)

    # NEW: Persist rotation event for rebuild
    seed_store = get_seed_store()
    await seed_store.save_rotation_seed(
        identity_name=hab.name,
        sequence_number=hab.kever.sn,  # Post-rotation sequence number
        ncount=next_key_count,
        nsith=next_threshold,
    )

    return RotationResult(...)
```

**`CredentialIssuer.issue_credential()`** — Persist credential metadata after LMDB creation:
```python
import json

def _insertion_order_json(data: dict | list | None) -> str | None:
    """Serialize to insertion-order JSON for SAID-stable storage.

    Uses compact separators and preserves dict key ordering.
    Matches the insertion-order convention used throughout the codebase
    for SAID computation (established in Sprint 68c).
    """
    if data is None:
        return None
    return json.dumps(data, separators=(',', ':'))

async def issue_credential(self, registry_name, schema_said, attributes, ...) -> tuple:
    # Pre-compute topological rebuild order from edge dependencies
    seed_store = get_seed_store()
    edge_saids = _extract_edge_saids(edges)  # Extract SAID refs from edge dict
    rebuild_order = await seed_store.compute_rebuild_order(edge_saids)

    # ... existing issuance logic (LMDB first) ...
    creder = proving.credential(...)

    # Persist seed to PostgreSQL AFTER successful LMDB creation.
    # Write order: LMDB → PG. If PG write fails, the LMDB credential
    # is ephemeral (lost on restart), so no orphan state accumulates.
    # On next restart, the credential won't exist in PG seeds and won't
    # be rebuilt — the caller should retry the issuance.
    await seed_store.save_credential_seed(
        expected_said=creder.said, registry_name=registry_name,
        schema_said=schema_said, issuer_identity_name=hab.name,
        recipient_aid=recipient_aid,
        attributes=attributes,  # SeedStore serializes internally
        edges=edges, rules=rules, private=private,
        rebuild_order=rebuild_order,
        edge_saids=edge_saids,
    )

    # ... rest of existing code ...
```

#### Component 4: KeriStateBuilder (`app/keri/state_builder.py`)

**Purpose**: Rebuild all KERI state from PostgreSQL seeds on startup.

**Interface**:
```python
class KeriStateBuilder:
    """Deterministically rebuilds all KERI state from PostgreSQL seeds."""

    async def rebuild(self) -> RebuildReport:
        """Full rebuild sequence. Returns timing and count report."""

    async def _rebuild_identities(self) -> int:
        """Replay all makeHab() calls from identity seeds."""

    async def _replay_rotations(self) -> int:
        """Replay all rotation events per identity (in sequence_number order)."""

    async def _rebuild_registries(self) -> int:
        """Replay all makeRegistry() calls from registry seeds."""

    async def _rebuild_credentials(self) -> int:
        """Replay all issue_credential() calls in topological order (by rebuild_order)."""

    async def _verify_state(self) -> list[str]:
        """Verify all AIDs, registry keys, and credential SAIDs match expected."""

    async def _publish_to_witnesses(self) -> None:
        """Re-publish all KEL events to witnesses (idempotent)."""
```

**Rebuild Flow**:
1. Read all seeds from PostgreSQL (one query per table)
2. Create Habery with stored salt (already handled by modified `initialize()`)
3. For each identity seed (ordered by `created_at`):
   - Call `hby.makeHab(name=seed.name, transferable=seed.transferable, ...)`
   - Verify `hab.pre == seed.expected_aid` — log error and skip on mismatch
4. For each registry seed (ordered by `created_at`):
   - Call `regery.makeRegistry(name=seed.name, prefix=identity_aid, nonce=seed.nonce, ...)`
   - Verify `registry.regk == seed.expected_registry_key`
   - Anchor TEL inception in KEL (same flow as `create_registry`)
5. For each credential seed (ordered by `rebuild_order` — topological):
   - Call `proving.credential(schema=seed.schema_said, issuer=issuer_aid, data=seed.attributes, ...)`
   - Verify `creder.said == seed.expected_said`
   - Create TEL issuance event, anchor in KEL (same flow as `issue_credential`)
6. Verify all state matches expectations
7. Publish all identities to witnesses (idempotent)

**Timing Report** (logged at INFO level):
```
KERI Agent startup: 12.3s total
  PostgreSQL connect: 0.2s
  Identity rebuild: 4.1s (15 identities)
  Registry rebuild: 2.8s (5 registries)
  Credential rebuild: 5.0s (25 credentials)
  Witness publish: 0.2s
  State verify: 0.1s
```

#### Component 5: Updated Startup Sequence (`app/main.py`)

```python
@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("Starting VVP KERI Agent service...")

    # 1. Initialize database (create tables if needed)
    from app.db.session import init_database
    init_database()

    # 2. Initialize KERI managers (Habery uses stored or new salt)
    await get_identity_manager()
    await get_registry_manager()
    await get_credential_issuer()

    # 3. Check if this is a rebuild (seeds exist in PG)
    seed_store = get_seed_store()
    if await seed_store.has_seeds():
        # Rebuild: replay all state from seeds
        builder = KeriStateBuilder()
        report = await builder.rebuild()
        log.info(f"State rebuild complete: {report}")

    # 4. Initialize mock vLEI if enabled
    if MOCK_VLEI_ENABLED:
        mock_vlei = get_mock_vlei_manager()
        await mock_vlei.initialize()  # Idempotent: creates or finds existing

    log.info("VVP KERI Agent service started")
    yield
    # ... shutdown ...
```

**Key insight**: The rebuild happens AFTER identity manager initialization (which loads the stored salt) but BEFORE mock vLEI initialization (which may create new identities if not yet seeded). This ordering ensures:
- First boot: empty DB → new salt stored → no rebuild → mock vLEI creates fresh identities and stores seeds
- Subsequent boots: stored salt → rebuild identities/registries/credentials → mock vLEI `initialize()` finds existing identities (idempotent)

#### Component 6: MockVLEI Rebuild Awareness

`MockVLEIManager.initialize()` already checks for existing identities before creating:
```python
gleif_info = await identity_mgr.get_identity_by_name(MOCK_GLEIF_NAME)
if gleif_info is None:
    gleif_info = await identity_mgr.create_identity(...)  # Creates + persists seed
else:
    log.info(f"Found existing mock GLEIF identity: ...")  # Already rebuilt
```

After rebuild, all mock vLEI identities already exist in LMDB (rebuilt from seeds), so `initialize()` takes the fast path (find existing). No changes needed to `MockVLEIManager` beyond ensuring it persists seeds during first-boot creation (handled by the modified `create_identity` and `create_registry`).

#### Component 7: Configuration Changes (Phase 3)

`app/config.py` update:
```python
def _get_data_dir() -> Path:
    """Ephemeral LMDB: default to /tmp for containers."""
    env_path = os.getenv("VVP_KERI_AGENT_DATA_DIR")
    if env_path:
        return Path(env_path)

    # Sprint 69: Default to ephemeral storage
    # Containers: /tmp/vvp-keri-agent (rebuilt on startup from PG seeds)
    # Local dev: ~/.vvp-issuer (persistent, for convenience)
    if Path("/tmp").exists() and not Path.home().joinpath(".vvp-issuer").exists():
        return Path("/tmp/vvp-keri-agent")

    # Local development: keep persistent LMDB for convenience
    try:
        home_path = Path.home() / ".vvp-issuer"
        home_path.mkdir(parents=True, exist_ok=True)
        return home_path
    except (OSError, PermissionError):
        return Path("/tmp/vvp-keri-agent")
```

**Docker Compose**: Remove `keri-agent-data` volume, add tmpfs:
```yaml
keri-agent:
  # Remove: volumes: ["keri-agent-data:/data/vvp-keri-agent"]
  tmpfs:
    - /tmp/vvp-keri-agent
  environment:
    - VVP_KERI_AGENT_DATA_DIR=/tmp/vvp-keri-agent
    - VVP_KERI_AGENT_DATABASE_URL=sqlite:////tmp/keri_seeds.db  # local dev
```

#### Component 8: CI/CD Simplification (Phase 4)

**Remove from deploy.yml**:
- The entire "Stop old revision (release LMDB lock on shared volume)" step
- The 3-phase stop logic (deactivate → poll → LMDB buffer)
- Azure Files volume mount configuration for the KERI Agent

**Replace with**:
```yaml
- name: Deploy keri-agent
  run: |
    az containerapp update \
      --name vvp-keri-agent \
      --resource-group "$RG" \
      --image "$IMAGE" \
      --min-replicas 1 \
      --max-replicas 1
```

**Keep**:
- `max_replicas=1` (KERI Agent is still logically single-writer)
- Self-healing activation check (Azure can still leave revision `active=false`)
- Health check polling (rebuild takes ~10-15s, not 3 minutes)
- Reduce health check timeout from 5 minutes to 2 minutes (rebuild is faster)

**Add PostgreSQL config** to KERI Agent env vars in deploy.yml:
```yaml
--env-vars \
  "VVP_KERI_AGENT_DATABASE_URL=secretref:keri-agent-db-url" \
  "VVP_KERI_AGENT_DATA_DIR=/tmp/vvp-keri-agent" \
  ...
```

#### Component 9: Seed Export Endpoint (Phase 5)

`app/api/seeds.py`:
```python
@router.get("/admin/seeds/export")
async def export_seeds():
    """Export all seed data as JSON for disaster recovery.

    Returns AES-256-GCM encrypted JSON containing all seeds needed to
    rebuild KERI state from scratch (salt, identities, registries, credentials).
    """
```

**Security**:
- **Authentication**: Admin bearer token required (same as other admin endpoints)
- **Encryption**: The export payload is encrypted at rest using AES-256-GCM:
  - **Key derivation**: PBKDF2-SHA256 with 600,000 iterations, 16-byte random salt
  - **Passphrase**: Supplied as query parameter `?passphrase=...` (required). The passphrase is NOT stored — the operator must remember it for import.
  - **Format**: Base64-encoded JSON envelope: `{"v": 1, "alg": "AES-256-GCM", "kdf": "PBKDF2-SHA256", "iterations": 600000, "salt": "<b64>", "iv": "<b64>", "ciphertext": "<b64>", "tag": "<b64>"}`
  - **Implementation**: Uses Python `cryptography` library (`Fernet` is simpler but AES-GCM gives us explicit IV/tag control)
- **Plaintext contents** (before encryption): JSON with keys `habery_salt`, `identity_seeds`, `registry_seeds`, `rotation_seeds`, `credential_seeds`, `exported_at`, `version`
- **No import endpoint in Sprint 69** — import is a future sprint (requires careful merge logic). The export is for disaster recovery backup only.

### Data Flow

#### First Boot (no seeds in PostgreSQL)
```
Startup
  → init_database() — creates empty tables
  → initialize() — generates NEW salt, stores in PG
  → has_seeds() → False — skip rebuild
  → MockVLEI.initialize()
      → create_identity("mock-gleif") → stores seed in PG
      → create_registry("mock-gleif-registry") → stores seed in PG
      → create_identity("mock-qvi") → stores seed in PG
      → ... (all identities/registries/credentials stored)
  → Service ready
```

#### Subsequent Boot (seeds exist)
```
Startup
  → init_database() — tables exist, no-op
  → initialize() — loads STORED salt from PG, creates Habery with it
  → has_seeds() → True
  → KeriStateBuilder.rebuild()
      → rebuild identities: makeHab() for each seed → verify AIDs match
      → rebuild registries: makeRegistry(nonce=stored) → verify regk match
      → rebuild credentials: issue_credential() in order → verify SAIDs match
      → publish to witnesses (idempotent)
  → MockVLEI.initialize()
      → get_identity_by_name("mock-gleif") → FOUND (already rebuilt)
      → get_identity_by_name("mock-qvi") → FOUND (already rebuilt)
      → ... (all found, fast path)
  → Service ready
```

### Error Handling

| Error | Response | Recovery |
|-------|----------|----------|
| PostgreSQL unavailable at startup | Retry with backoff (5s, 10s, 20s, 40s, 60s) | Cannot start without seeds |
| AID mismatch on rebuild | Log ERROR, skip identity | Service starts with partial state, `/healthz` reports degraded |
| Registry key mismatch | Log ERROR, skip registry | Credentials depending on this registry also skipped |
| Credential SAID mismatch | Log ERROR, skip credential | Downstream edges may be affected |
| All seeds missing (first boot) | Generate fresh state | Normal first-boot path |
| Some identities fail, others succeed | Continue with available state | Partial rebuild, operator intervention needed |

### Data Migration Strategy

The production KERI Agent currently stores all state in LMDB on Azure Files. On first deployment of Sprint 69, the new PostgreSQL seed tables will be empty. Without migration, the system would generate a new salt and lose all existing identities/credentials.

#### Migration Approach: Fresh Re-initialization (Mock vLEI)

The production system currently runs **mock vLEI** infrastructure (mock GLEIF, QVI, GSMA identities). Since these are mock identities (not real vLEI credentials from the GLEIF root of trust), the pragmatic approach is fresh re-initialization:

1. **Deploy Sprint 69** — KERI Agent starts with empty PG seed tables
2. **First boot**: generates new salt, empty LMDB, no rebuild needed
3. **Mock vLEI `initialize()`**: creates fresh mock identities, registries, credentials — all seeds stored in PG
4. **Run bootstrap script** (`scripts/bootstrap-issuer.py`): re-provisions org, API keys, TN allocations, TN mappings against the new KERI Agent identities
5. **Verify**: E2E health check + loopback call

This is the **recommended path** because:
- Mock identities are disposable by design — the bootstrap script already handles full re-provisioning
- Extracting seeds from existing LMDB is complex (salt is buried in keripy's internal keystore format) and error-prone
- The Issuer's PostgreSQL data (orgs, users, API keys) is reset by the bootstrap script anyway

#### Future: LMDB Migration Script (for Production vLEI)

When the system transitions to real vLEI credentials (actual GLEIF-rooted trust chain), a proper migration tool will be needed. This is **out of scope for Sprint 69** but documented here for future reference:

```
python -m app.cli migrate-lmdb-to-pg \
    --lmdb-path /data/vvp-keri-agent \
    --db-url $DATABASE_URL \
    --dry-run  # Validate without writing
```

The migration script would:
1. Open existing LMDB keystore, extract the Habery salt via `hby.salt` (keripy accessor)
2. Iterate KEL databases to find all identity inception events → extract makeHab parameters
3. Iterate KEL for rotation events per identity → extract rotation parameters
4. Iterate TEL for registry inception events → extract registry parameters and nonces
5. Iterate credential store → extract attributes, edges, rules, schema SAIDs
6. Write all extracted seeds to PostgreSQL
7. Verify: close LMDB, reopen fresh, rebuild from PG seeds, compare all AIDs/SAIDs

This will be implemented in a future sprint when real vLEI integration is imminent.

### Test Strategy

**Phase 1 Tests** (`tests/test_seed_store.py`):
- CRUD operations on seed store (save/get/list)
- Habery salt save + retrieve
- Identity seed upsert idempotency
- Registry seed with nonce persistence
- Credential seed with rebuild_order

**Phase 2 Tests** (`tests/test_state_builder.py`):
- Round-trip test: create identities → persist seeds → close LMDB → fresh LMDB → rebuild → verify AIDs match
- Registry rebuild with nonce → verify registry key matches
- Credential rebuild in order → verify SAIDs match
- Edge reference integrity (credential A → credential B → rebuild both → edges valid)
- MockVLEI rebuild: create mock trust chain → close → rebuild → verify all AIDs/SAIDs stable
- Partial failure: one identity seed corrupt → others still rebuilt

**Phase 3 Tests** (`tests/test_ephemeral_storage.py`):
- Start with empty /tmp → first boot → verify state created
- Delete /tmp contents → restart → verify identical state from seeds

**Phase 4 Tests**: Manual/CI verification that deploy.yml generates correct `az` commands.

**Phase 5 Tests** (`tests/test_seed_export.py`):
- Export endpoint returns all seed data
- Startup telemetry logged correctly
- Graceful degradation on partial seed failure

## Files to Create/Modify

| File | Action | Purpose |
|------|--------|---------|
| `services/keri-agent/app/db/__init__.py` | Create | Package init |
| `services/keri-agent/app/db/models.py` | Create | SQLAlchemy models (4 seed tables) |
| `services/keri-agent/app/db/session.py` | Create | Engine, session factory, init_database |
| `services/keri-agent/app/keri/seed_store.py` | Create | SeedStore class — CRUD for seeds |
| `services/keri-agent/app/keri/state_builder.py` | Create | KeriStateBuilder — deterministic rebuild |
| `services/keri-agent/app/api/seeds.py` | Create | Seed export admin endpoint |
| `services/keri-agent/app/config.py` | Modify | Add DATABASE_URL, update _get_data_dir() |
| `services/keri-agent/app/main.py` | Modify | Add DB init, rebuild on startup |
| `services/keri-agent/app/keri/identity.py` | Modify | Use stored salt, persist identity seeds |
| `services/keri-agent/app/keri/registry.py` | Modify | Persist registry seeds with nonce |
| `services/keri-agent/app/keri/issuer.py` | Modify | Persist credential seeds |
| `services/keri-agent/pyproject.toml` | Modify | Add sqlalchemy, psycopg2-binary, cryptography deps |
| `services/keri-agent/Dockerfile` | Modify | Remove VOLUME, add psycopg2 system deps |
| `services/keri-agent/tests/conftest.py` | Modify | Add SQLite DB fixture for tests |
| `services/keri-agent/tests/test_seed_store.py` | Create | Seed store CRUD tests |
| `services/keri-agent/tests/test_state_builder.py` | Create | Round-trip rebuild tests |
| `services/keri-agent/tests/test_ephemeral_storage.py` | Create | Ephemeral storage tests |
| `services/keri-agent/tests/test_seed_export.py` | Create | Seed export endpoint tests |
| `docker-compose.yml` | Modify | Remove keri-agent-data volume, add tmpfs |
| `.github/workflows/deploy.yml` | Modify | Remove 3-phase stop, add PG config |
| `knowledge/deployment.md` | Modify | Update deploy docs |
| `knowledge/architecture.md` | Modify | Update architecture docs |

## Open Questions (Resolved in R2)

1. **Registry nonce capture** — RESOLVED: Will use `registry.vcp.ked.get("n")` to extract the nonce from the VCP inception event. Fallback: store full VCP inception event bytes if accessor doesn't work.

2. **Credential edge ordering** — RESOLVED: Using topological sort via `compute_rebuild_order()` in `SeedStore`. Algorithm: `rebuild_order = max(dependency rebuild_orders) + 1`. Credentials with no edges get `rebuild_order = 0`. The `edge_saids` column stores the dependency list for computing order.

3. **Key rotation history** — RESOLVED: Added `KeriRotationSeed` table to persist rotation events. `rotate_identity()` now persists rotation parameters. `KeriStateBuilder._replay_rotations()` replays all rotation events per identity in sequence_number order after inception rebuild. This ensures correct signing key state (not just AID stability).

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Seed mismatch → wrong AID | Low | High | Verify `expected_aid` on every rebuild. Alert if mismatch. |
| Credential SAID drift | Medium | High | Persist full attributes incl. `dt`. Verify rebuilt SAIDs. |
| Registry nonce not capturable | Low | Medium | Fallback: store full VCP inception event bytes. |
| Key rotation state loss | Low | Medium | `KeriRotationSeed` table persists all rotation events. Replayed on rebuild. |
| Startup time regression | Low | Low | Local LMDB ~100x faster than Azure Files. Target <15s. |
| PostgreSQL unavailable at startup | Low | High | Retry with exponential backoff (max 60s). |

---

## Implementation Notes

### Deviations from Plan

- **No `test_ephemeral_storage.py`**: The round-trip rebuild tests in `test_state_builder.py` already exercise the full ephemeral storage flow (create → wipe LMDB → rebuild). A separate test file was unnecessary.
- **`_get_data_dir()` config function**: Not modified. The existing `DATA_DIR` config with `VVP_KERI_AGENT_DATA_DIR` env var was sufficient. Docker/docker-compose set it to `/tmp/vvp-keri-agent`.
- **Witness publish on rebuild**: Not implemented in Sprint 69. Witnesses are re-published when needed (lazy, on OOBI resolution). Adds no value for mock vLEI.
- **Seed export uses late import for `get_db_session`**: Consistent with seed_store pattern for test module reloading support.
- **SeedStore is synchronous (not async)**: Plan specified `async def` methods, but implementation uses sync. All keripy operations are synchronous and CPU-bound — making only the DB layer async while keripy blocks the event loop is theater. Seed writes happen during rare creation events; rebuild runs at startup before requests. Documented in seed_store.py module docstring.
- **`_extract_edge_saids` renamed to `extract_edge_saids`**: Made public since used by `issuer.py`.
- **`_get_data_dir()` simplified**: Removed legacy `/data/vvp-issuer` and `VVP_ISSUER_DATA_DIR` fallbacks. Now defaults to ephemeral `/tmp/vvp-keri-agent` unless `~/.vvp-issuer` already exists (local dev).

### Test Results

```
KERI Agent: 125 passed in 22.23s
  - 72 existing tests (identity, registry, credential, dossier, vvp, health, auth, mock_vlei)
  - 37 seed store tests (CRUD, helpers, rebuild_order, has_seeds)
  - 7 state builder tests (round-trip identity/registry/credential rebuild)
  - 9 seed export tests (encryption, API, auth)

Issuer: 820 passed, 7 skipped in 61.30s (no regressions)
```

### Files Changed

| File | Lines | Summary |
|------|-------|---------|
| `services/keri-agent/app/config.py` | +5 | DATABASE_URL config |
| `services/keri-agent/app/db/__init__.py` | +1 | Package init |
| `services/keri-agent/app/db/models.py` | +95 | 5 SQLAlchemy models (salt, identity, registry, rotation, credential seeds) |
| `services/keri-agent/app/db/session.py` | +55 | Engine, session factory, init_database |
| `services/keri-agent/app/keri/seed_store.py` | +317 | SeedStore CRUD, _insertion_order_json, extract_edge_saids |
| `services/keri-agent/app/keri/state_builder.py` | +200 | KeriStateBuilder — deterministic rebuild from seeds |
| `services/keri-agent/app/api/seeds.py` | +135 | Seed export endpoint (AES-256-GCM encrypted) |
| `services/keri-agent/app/keri/identity.py` | +30 | Stored salt, persist identity/rotation seeds |
| `services/keri-agent/app/keri/registry.py` | +15 | Persist registry seeds with nonce |
| `services/keri-agent/app/keri/issuer.py` | +25 | Persist credential seeds with rebuild_order |
| `services/keri-agent/app/main.py` | +15 | DB init, state rebuild on startup, seeds router |
| `services/keri-agent/pyproject.toml` | +3 | sqlalchemy, psycopg2-binary, cryptography deps |
| `services/keri-agent/Dockerfile` | +5 | libpq-dev, ephemeral DATA_DIR |
| `services/keri-agent/tests/conftest.py` | +20 | Seed DB fixtures, reset_seed_store |
| `services/keri-agent/tests/test_seed_store.py` | +330 | 37 tests for seed store |
| `services/keri-agent/tests/test_state_builder.py` | +330 | 7 round-trip rebuild tests |
| `services/keri-agent/tests/test_seed_export.py` | +160 | 9 seed export tests |
| `docker-compose.yml` | +5/-5 | tmpfs for keri-agent, removed volume |
| `.github/workflows/deploy.yml` | +30/-80 | Removed 3-phase LMDB stop, added PG config, reduced health timeout |

## Revision History

| Round | Date | Changes |
|-------|------|---------|
| R1 | 2026-02-16 | Initial draft |
| R2 | 2026-02-16 | Added KeriRotationSeed table for rotation replay. Topological sort for credential rebuild_order. Canonical JSON for SAID-stable storage. PG-first write strategy for transactional safety. Resolved all open questions. |
| R3 | 2026-02-16 | Fixed JSON serialization: changed from `sort_keys=True` to insertion-order JSON throughout (matching Sprint 68c convention). Renamed `_canonical_json` → `_insertion_order_json`, `rules_canonical` → `rules_json`. Added seed export encryption spec: AES-256-GCM with PBKDF2-SHA256 key derivation, passphrase-based, explicit format definition. |
| R4 | 2026-02-16 | Added Data Migration Strategy section: fresh re-initialization for mock vLEI (recommended), future LMDB migration script for production vLEI (out of scope). Corrected write strategy description: removed inaccurate "PG-first" label, documented actual LMDB→PG write order with risk explanation (ephemeral LMDB mitigates orphan state). |
