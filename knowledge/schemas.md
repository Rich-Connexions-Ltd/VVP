# VVP Schema Registry

This document catalogs all credential schemas, their SAIDs, and governance rules used in the VVP system.

## Schema Registry Location
- **Verifier**: `services/verifier/app/vvp/acdc/schema_registry.py`
- **Common**: `common/vvp/schema/registry.py`
- **Schema JSON files**: `services/verifier/app/schema/schemas/`, `services/issuer/app/schema/schemas/`

---

## Credential Types and Schema SAIDs

### Official vLEI Governance Framework SAIDs

| Credential Type | Schema SAID | Description |
|----------------|-------------|-------------|
| **QVI** (Qualified vLEI Issuer) | `EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao` | Identifies a QVI authorized by GLEIF |
| **LE** (Legal Entity) | `EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao` | Identifies a legal entity vetted by a QVI |
| **LE** (Provenant demo) | `EJrcLKzq4d1PFtlnHLb9tl4zGwPAjO6v0dec4CiJMZk6` | Provenant-specific LE schema (workaround) |
| **APE** (Auth Phone Entity) | *(project-specific)* | Authorizes entity for phone operations |
| **DE** (Delegate Entity) | `EL7irIKYJL9Io0hhKSGWI4OznhwC7qgJG5Qf4aEs6j0o` | Delegates authority (Provenant demo) |
| **TNAlloc** (TN Allocation) | `EFvnoHDY7I-kaBBeKlbDbkjG4BaI0nKLGadxBdjMGgSQ` | Allocates telephone numbers |
| **Brand** (Brand Owner) | *(project-specific)* | Associates brand identity |

### Schema SAID Lookup
Credential type is determined primarily by schema SAID, with edge-name heuristic as fallback:

```python
# Primary: Schema SAID → credential type
SCHEMA_SAID_MAP = {
    "EBfdlu8R27Fbx-...": "LE",                # Official vLEI
    "EJrcLKzq4d1PF...": "LE",                 # Provenant demo
    "EL7irIKYJL9Io...": "DE",                 # Provenant demo
    "EFvnoHDY7I-kaBBe...": "TNAlloc",         # Base TN Allocation
    ...
}

# Fallback: Edge name → credential type (heuristic)
EDGE_NAME_MAP = {
    "vetting": "LE",
    "delegation": "DE", "delegate": "DE", "issuer": "DE",
    "alloc": "TNAlloc", "tnalloc": "TNAlloc",
    "bownr": "Brand",
}

# Tertiary fallback: Attribute inspection
# TNAlloc detected if attributes contain "phone", "tn", or "numbers"
```

---

## Schema JSON Files

### Verifier Schemas (`services/verifier/app/schema/schemas/`)

| File | Schema Type | Purpose |
|------|-------------|---------|
| `legal-entity-vLEI-credential.json` | LE | Legal Entity credential schema |
| `qualified-vLEI-issuer-vLEI-credential.json` | QVI | Qualified vLEI Issuer schema |
| `oor-authorization-vlei-credential.json` | OOR Auth | OOR authorization |
| `ecr-authorization-vlei-credential.json` | ECR Auth | ECR authorization |
| `legal-entity-official-organizational-role-vLEI-credential.json` | OOR | Official Organizational Role |
| `legal-entity-engagement-context-role-vLEI-credential.json` | ECR | Engagement Context Role |

### Issuer Schemas (`services/issuer/app/schema/schemas/`)
Contains the same set plus additional types for credential issuance.

---

## Credential Chain Structure

### Typical Dossier DAG
```
GLEIF Root (trusted anchor)
  └── QVI Credential
        └── LE Credential (Legal Entity)
              ├── APE Credential (Auth Phone Entity)
              │     └── DE Credential (delsig - delegation to signer)
              └── Brand Credential (dossier root)
                    ├── edge "le" → LE Credential
                    ├── edge "tnAlloc0" → TNAlloc Credential (range 1)
                    └── edge "tnAlloc1" → TNAlloc Credential (range 2)
```
**Note:** The Brand Credential is typically the dossier root SAID. The dossier builder
does a DFS edge walk from the root, so TNAlloc credentials must be linked as edges of
the brand credential to be included in the dossier.

### Edge Rules (Semantic Validation)

| Credential | Required Edge | Target Type | Rule |
|------------|--------------|-------------|------|
| APE | `vetting` | LE | APE must be vetted by a Legal Entity |
| DE | `delegation` / `issuer` | APE or DE | Authority must be delegated from above |
| TNAlloc | `jl` (jurisdiction link) | Parent allocator | Unless root regulator |
| Brand | *(varies)* | LE or APE | Links brand to authorized entity |

### Delegation Chain (Signer Authorization)
The PASSporT signer may not be directly referenced in the root credential. Authorization flows through delegation:

```
APE Credential (authorizes entity)
  → DE Credential "delsig" (delegates to signer AID)
    → PASSporT Signer (the AID that signed the JWT)
```

The signer AID appears as the `issuee` (`a.i`) of the delegation credential.

---

## Schema Governance

### Official vs Demo SAIDs
- **Official SAIDs**: From the vLEI Governance Framework, published by GLEIF
- **Demo SAIDs**: From Provenant demo environment (added as workarounds)
- See `Documentation/DOSSIER_WORKAROUNDS.md` for the full list of workaround SAIDs

### Schema Validation Rules
1. Every ACDC must have a `s` (schema) field with a valid SAID
2. The schema SAID must be in the registry for type determination
3. Unknown schema SAIDs → credential type is "unknown" → may cause `AUTHORIZATION_FAILED`
4. Schema content (JSON Schema) is validated against credential attributes

### Trusted Root AIDs
Configured in `services/verifier/app/core/config.py`:
- GLEIF root AID(s)
- QVI AID(s)
- These serve as trust anchors for chain validation

---

## Adding New Schemas

1. Add JSON schema file to `services/*/app/schema/schemas/`
2. Register the SAID in `schema_registry.py`
3. If new credential type, add edge rules in `acdc/verifier.py`
4. Update `knowledge/schemas.md` (this file)
