# VVP Schema Registry

This document catalogs all credential schemas, their SAIDs, and governance rules used in the VVP system.

## Schema Registry Location
- **Verifier**: `services/verifier/app/vvp/acdc/schema_registry.py`
- **Common**: `common/vvp/schema/registry.py`
- **Schema JSON files**: `services/verifier/app/schema/schemas/`, `services/issuer/app/schema/schemas/`

---

## Credential Types and Schema SAIDs

### All Schema SAIDs

| Credential Type | Schema SAID | Source |
|----------------|-------------|--------|
| **QVI** (Qualified vLEI Issuer) | `EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao` | vLEI Governance |
| **LE** (Legal Entity) | `ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY` | vLEI Governance |
| **LE** (Provenant demo) | `EJrcLKzq4d1PFtlnHLb9tl4zGwPAjO6v0dec4CiJMZk6` | Provenant workaround |
| **OOR Auth** | `EKA57bKBKxr_kN7iN5i7lMUxpMG-s19dRcmov1iDxz-E` | vLEI Governance |
| **OOR** (Official Org Role) | `EBNaNu-M9P5cgrnfl2Fvymy4E_jvxxyjb70PRtiANlJy` | vLEI Governance |
| **ECR Auth** | `EH6ekLjSr8V32WyFbGe1zXjTzFs9PkTYmupJ9H65O14g` | vLEI Governance |
| **ECR** (Engagement Context) | `EEy9PkikFcANV1l7EHukCeXqrzT1hNZjGlUk7wuMO5jw` | vLEI Governance |
| **APE** (Auth Phone Entity) | *(pending governance)* | Accept any |
| **DE / GCD** (Delegate / Cooperative Delegation) | `EL7irIKYJL9Io0hhKSGWI4OznhwC7qgJG5Qf4aEs6j0o` | VVP project |
| **TNAlloc** (TN Allocation) | `EFvnoHDY7I-kaBBeKlbDbkjG4BaI0nKLGadxBdjMGgSQ` | VVP project |
| **Brand** (Brand Owner) | *(pending governance)* | Accept any |
| **Dossier (CVD)** | `EH1jN4U4LMYHmPVI4FYdZ10bIPR7YWKp8TDdZ9Y9Al-P` | VVP project |
| **GSMA Governance** | `EIBowJmxx5hNWQlfXqGcbN0aP_RBuucMW6mle4tAN6TL` | VVP project (Sprint 62) |
| **VetterCertification** | `EOefmhWU2qTpMiEQhXohE6z3xRXkpLloZdhTYIenlD4H` | VVP project (Sprint 61) |
| **Extended LE** | `EPknTwPpSZi379molapnuN4V5AyhCxz_6TLYdiVNWvbV` | VVP project (Sprint 61) |
| **Extended Brand** | `EK7kPhs5YkPsq9mZgUfPYfU-zq5iSlU8XVYJWqrVPk6g` | VVP project (Sprint 61) |
| **Extended TNAlloc** | `EGUh_fVLbjfkYFb5zAsY2Rqq0NqwnD3r5jsdKWLTpU8_` | VVP project (Sprint 61) |

### Schema SAID Lookup
Credential type is determined primarily by schema SAID, with edge-name heuristic as fallback:

```python
# Primary: Schema SAID → credential type (KNOWN_SCHEMA_SAIDS in common/vvp/schema/registry.py)
KNOWN_SCHEMA_SAIDS = {
    "QVI": {"EBfdlu8R27Fbx-..."},
    "LE": {"ENPXp1vQzRF6Jw...", "EJrcLKzq4d1PF..."},  # Official + Provenant
    "OOR_AUTH": {"EKA57bKBKxr_kN..."},
    "OOR": {"EBNaNu-M9P5cgr..."},
    "ECR_AUTH": {"EH6ekLjSr8V32W..."},
    "ECR": {"EEy9PkikFcANV1..."},
    "APE": set(),                              # Pending governance — accept any
    "DE": {"EL7irIKYJL9Io..."},                # GCD (delsig, TN allocator)
    "TNAlloc": {"EFvnoHDY7I-kaBBe..."},
}

# Extended schemas — schemas with a `certification` edge to VetterCert (Sprint 61)
# Detected via oneOf edge block in schema JSON or via KNOWN_EXTENDED_SCHEMA_SAIDS fallback
KNOWN_EXTENDED_SCHEMA_SAIDS = {
    "EPknTwPpSZi379mo...": "Extended LE",
    "EK7kPhs5YkPsq9mZ...": "Extended Brand",
    "EGUh_fVLbjfkYFb5...": "Extended TNAlloc",
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

| File | SAID | Schema Type |
|------|------|-------------|
| `qualified-vLEI-issuer-vLEI-credential.json` | `EBfdlu8R27Fbx-...` | QVI |
| `legal-entity-vLEI-credential.json` | `ENPXp1vQzRF6Jw...` | LE |
| `EL7irIKYJL9Io0hhKSGWI4OznhwC7qgJG5Qf4aEs6j0o.json` | `EL7irIKYJL9Io...` | GCD (DE) |
| `EFvnoHDY7I-kaBBeKlbDbkjG4BaI0nKLGadxBdjMGgSQ.json` | `EFvnoHDY7I-ka...` | TNAlloc |
| `EH1jN4U4LMYHmPVI4FYdZ10bIPR7YWKp8TDdZ9Y9Al-P.json` | `EH1jN4U4LMYHm...` | Dossier (CVD) |
| `vetter-certification-credential.json` | `EOefmhWU2qTpMi...` | VetterCert |
| `gsma-governance-credential.json` | `EIBowJmxx5hNWQ...` | GSMA Governance |
| `extended-legal-entity-credential.json` | `EPknTwPpSZi379...` | Extended LE |
| `extended-brand-credential.json` | `EK7kPhs5YkPsq9...` | Extended Brand |
| `extended-tn-allocation-credential.json` | `EGUh_fVLbjfkYF...` | Extended TNAlloc |
| `oor-authorization-vlei-credential.json` | `EKA57bKBKxr_kN...` | OOR Auth |
| `ecr-authorization-vlei-credential.json` | `EH6ekLjSr8V32W...` | ECR Auth |
| `legal-entity-official-organizational-role-vLEI-credential.json` | `EBNaNu-M9P5cgr...` | OOR |
| `legal-entity-engagement-context-role-vLEI-credential.json` | `EEy9PkikFcANV1...` | ECR |

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

### VetterCertification Trust Chain (Sprint 61)
```
Mock GSMA (trust anchor, separate from QVI chain)
  └── VetterCertification (issued to org AID)
        ├── ecc_targets: ["44", "1"]        # Allowed E.164 country codes
        ├── jurisdiction_targets: ["GBR"]   # Allowed ISO 3166-1 alpha-3
        └── certificationExpiry: "..."      # Optional expiry
```
Extended schemas (Extended LE, Extended Brand, Extended TNAlloc) have a `certification`
edge that links to the org's VetterCertification. This edge is auto-injected by
`_inject_certification_edge()` during credential issuance when the schema has a
`oneOf` edge block containing a `certification` variant.

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

## Schema Authorization by Organization Type (Sprint 67)

The issuer enforces which schemas each organization type can issue. This mapping is hard-coded in `services/issuer/app/auth/schema_auth.py` because the trust chain structure is defined by the vLEI/VVP specification.

| Org Type | Authorized Schemas | Schema SAIDs |
|----------|-------------------|-------------|
| `root_authority` (GLEIF) | QVI | `EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao` |
| `qvi` (QVI) | LE, Extended LE | `ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY`, `EPknTwPpSZi379molapnuN4V5AyhCxz_6TLYdiVNWvbV` |
| `vetter_authority` (GSMA) | VetterCert, Governance | `EOefmhWU2qTpMiEQhXohE6z3xRXkpLloZdhTYIenlD4H`, `EIBowJmxx5hNWQlfXqGcbN0aP_RBuucMW6mle4tAN6TL` |
| `regular` (standard org) | Extended Brand, TNAlloc, Extended TNAlloc, DE/GCD | `EK7kPhs5YkPsq9mZgUfPYfU-zq5iSlU8XVYJWqrVPk6g`, `EFvnoHDY7I-kaBBeKlbDbkjG4BaI0nKLGadxBdjMGgSQ`, `EGUh_fVLbjfkYFb5zAsY2Rqq0NqwnD3r5jsdKWLTpU8_`, `EL7irIKYJL9Io0hhKSGWI4OznhwC7qgJG5Qf4aEs6j0o` |

**Enforcement points:**
- `POST /credential/issue` — rejects unauthorized schemas with 403
- `GET /schema/authorized` — returns only schemas the org type is allowed to issue
- Credential UI — filters schema dropdown based on `GET /schema/authorized`

**Helper functions** in `schema_auth.py`:
- `is_schema_authorized(org_type, schema_said) -> bool`
- `get_authorized_schemas(org_type) -> set[str]`

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
