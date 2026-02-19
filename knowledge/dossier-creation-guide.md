# Dossier Creation Guide

Step-by-step guide for creating VVP dossiers via the Issuer API.

---

## Prerequisites

1. **Organization** with AID and LE credential (auto-created on org creation when mock vLEI is enabled)
2. **KERI identity** for signing (`POST /identity`)
3. **Registry** for credential lifecycle (`POST /registry`)
4. **Credentials** for each dossier edge slot

---

## Model 1: Base Dossier (Without Vetter Certification)

### Step 1: Issue Credentials

Issue the required credentials in chain order:

```
POST /credential/issue
```

**a. GCD (Generalized Cooperative Delegation) — delsig**
```json
{
  "schema_said": "EL7irIKYJL9Io0hhKSGWI4OznhwC7qgJG5Qf4aEs6j0o",
  "issuer_aid": "<org AID>",
  "issuee_aid": "<signing identity AID>",
  "registry_key": "<registry key>",
  "attributes": {"dt": "2024-01-01T00:00:00Z"},
  "edges": {"le": {"n": "<LE credential SAID>", "s": "<LE schema SAID>"}}
}
```

**b. TN Allocation**
```json
{
  "schema_said": "EFvnoHDY7I-kaBBeKlbDbkjG4BaI0nKLGadxBdjMGgSQ",
  "issuer_aid": "<org AID>",
  "registry_key": "<registry key>",
  "attributes": {"numbers": ["+15551234567", "+15551234568"], "dt": "2024-01-01T00:00:00Z"}
}
```

### Step 2: Check Readiness

```
GET /dossier/readiness?org_id=<org_id>
```

Response shows per-slot status:
- `ready` — credential available and valid
- `missing` — required credential not found
- `invalid` — credential exists but fails I2I check
- `optional_missing` — optional slot, not blocking
- `optional_unconstrained` — optional slot with no schema constraint (e.g., bownr, bproxy)

### Step 3: Create Dossier

```
POST /dossier/create
```

```json
{
  "owner_org_id": "<org UUID>",
  "name": "My VVP Dossier",
  "edges": {
    "delsig": "<GCD credential SAID>",
    "alloc": "<TNAlloc credential SAID>"
  },
  "osp_org_id": "<optional OSP org UUID>"
}
```

The endpoint:
1. Validates each edge credential exists and belongs to the org
2. Issues a Dossier ACDC (CVD schema, no issuee) with the specified edges
3. Publishes to witnesses
4. Optionally creates a `DossierOspAssociation` record (enables TN lookup via OSP's API key)
5. Returns `dossier_said`, `dossier_url`, and publish results

### Step 4: Create TN Mapping

```
POST /tn/mappings
```

```json
{
  "telephone_number": "+15551234567",
  "dossier_id": "<dossier SAID>",
  "signing_identity_aid": "<signing identity AID>",
  "brand_name": "ACME Inc",
  "brand_logo_url": "https://example.com/logo.png"
}
```

---

## Model 2: Extended Dossier (With Vetter Certification)

### Additional Prerequisites

- **VetterCertification** credential issued to the org (via `POST /vetter-certifications`)
- **Extended schemas** used instead of base schemas

### Step 0: Issue Vetter Certification

```
POST /vetter-certifications
```

```json
{
  "organization_id": "<org UUID>",
  "ecc_targets": ["44", "1"],
  "jurisdiction_targets": ["GBR", "USA"],
  "name": "ACME Vetter",
  "certificationExpiry": "2025-12-31T23:59:59Z"
}
```

This issues a VetterCertification ACDC from the mock GSMA trust chain and stores the SAID on the organization.

### Step 1: Issue Extended Credentials

When issuing credentials with extended schemas, the `certification` edge is **auto-injected** — you do NOT need to supply it manually.

**Extended LE** (schema: `EPknTwPpSZi379molapnuN4V5AyhCxz_6TLYdiVNWvbV`)
- Auto-injects `certification` edge → org's active VetterCert

**Extended Brand** (schema: `EK7kPhs5YkPsq9mZgUfPYfU-zq5iSlU8XVYJWqrVPk6g`)
- Auto-injects `certification` edge → org's active VetterCert

**Extended TNAlloc** (schema: `EGUh_fVLbjfkYFb5zAsY2Rqq0NqwnD3r5jsdKWLTpU8_`)
- Auto-injects `certification` edge → org's active VetterCert

### Constraint Semantics

At issuance time, `validate_issuance_constraints()` checks:
- **ECC targets**: The TNAlloc's number ranges match the VetterCert's allowed country codes
- **Jurisdiction targets**: The credential's jurisdiction matches the VetterCert's allowed jurisdictions

Enforcement is controlled by `ENFORCE_VETTER_CONSTRAINTS` (default: `false` = soft warnings only).

At verification time (Verifier Phase 11b), the same constraints are checked from the other direction — the verifier walks the credential chain looking for VetterCertification backlinks and validates the calling TN's country code against `ecc_targets`.

### Steps 2-4: Same as Model 1

The readiness check, dossier creation, and TN mapping steps are identical.

---

## Dossier Edge Structure

The Dossier (CVD) credential has a flexible edge block parsed from the schema JSON's `properties.e.oneOf` structure. Typical edges:

| Edge Name | Target Type | Required | Description |
|-----------|-------------|----------|-------------|
| `delsig` | GCD | Yes | Delegation to signing identity |
| `alloc` | TNAlloc | Yes | TN allocation rights |
| `vetting` | LE | Varies | Legal entity vetting link |
| `bownr` | Brand | No | Brand owner credential |
| `bproxy` | Brand | No | Brand proxy credential |
| `tnalloc0..N` | TNAlloc | No | Additional TN allocations |
| `certification` | VetterCert | Auto | Auto-injected for extended schemas |

---

## Bootstrap Script

For development/recovery, `scripts/bootstrap-issuer.py` automates the full chain:

```bash
python3 scripts/bootstrap-issuer.py --url https://vvp-issuer.rcnx.io --admin-key <key>
```

Creates: mock vLEI infrastructure → test org → org API key → VetterCert → TN allocation credentials → brand credential (with `certification` + `vetterCert` edges) → TN mappings.

**Important — run after KERI Agent restarts:** The KERI Agent LMDB is ephemeral (`/tmp`). Any credentials (LE, VetterCert, TN Allocs, Brand) from a previous session are gone after container restart. Use `--skip-reinit` to skip the mock vLEI reinitialization and just recreate test credentials:

```bash
python3 scripts/bootstrap-issuer.py --url https://vvp-issuer.rcnx.io --admin-key <key> --skip-reinit
```

The bootstrap handles stale pointers automatically:
- **Stale LE credential**: `reissue-le` endpoint re-issues LE from current mock-QVI
- **Stale VetterCert**: The vetter service auto-clears stale pointers (KERI Agent 404) and issues a new one
- **Stale TN Allocs/Brand**: New credentials issued; TN mappings updated to new dossier root SAID

---

## TEL Events in Dossiers (Sprint 74)

VVP dossiers include inline TEL (Transaction Event Log) issuance events for all credentials the KERI Agent has issued. The verifier uses inline TEL to check revocation status without fetching the issuer's TEL registry separately.

**Why it matters:** Without inline TEL, the verifier cannot determine if credentials are revoked → it returns `INDETERMINATE` instead of `TRUSTED`. This applies to the brand credential, TN Allocation, and any other credential in the dossier chain where the issuer's TEL is accessible.

**Coverage:** Only credentials whose TEL the KERI Agent holds (credentials it issued) get inline TEL. Externally-issued credentials (e.g. LE credential issued by mock-QVI) do not have inline TEL in the dossier — the verifier handles these via KERI OOBI resolution of the issuer registry.

**Technical implementation:** KERI Agent exposes `GET /credentials/{said}/tel` returning the iss event bytes (CESR). The issuer's `DossierBuilder._get_tel_event()` calls this for each credential in the DFS walk.
