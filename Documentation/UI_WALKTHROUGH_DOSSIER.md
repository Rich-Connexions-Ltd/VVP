# Dossier Creation Walkthrough — UI Guide

**Issuer URL:** https://vvp-issuer.rcnx.io
**Target Org:** TEST Inc (AID: `EL5bHBXIjlpMhkhyT2As3EzLwGyLcqF9Q2zL48o7DY6h`)

This walkthrough creates a complete VVP dossier for TEST Inc using the simplified Sprint 72 UI. At each stage you **log out and log back in** as the admin for the organisation issuing that credential.

---

## Prerequisites

The following organisations and VetterCerts already exist:

| Organisation | Role | VetterCert |
|---|---|---|
| mock-gsma | Vetter Authority | n/a (issues VetterCerts) |
| Brand Assure | Vetter (brand) | ECC: 44, Jurisdiction: GBR |
| Deutsche Vetters | Vetter (TN) | ECC: 49+44, Jurisdiction: DEU+GBR |

If either vetter is missing a VetterCert, see [Step 1b](#step-1b-issue-vettercerts-only-if-missing) first.

---

## Step 1: Create TEST Inc organisation

> **Log in as:** System Admin (admin@testinc.com)

**Page:** [Organisations](https://vvp-issuer.rcnx.io/ui/organizations)

1. Log in to the issuer as `admin@testinc.com`
2. Navigate to **Organisations**
3. Click **Create Organisation**
4. Fill in:
   - **Name:** `TEST Inc`
   - **Pseudo-LEI:** Leave blank (auto-generated) or enter a 20-character LEI
   - **Org Type:** `regular`
5. Click **Create**

The system auto-provisions a mock vLEI chain (GLEIF → QVI → LE) and assigns an AID.

> **Note:** Record the **org ID** and **AID** shown after creation — you'll need them later. If the AID shown differs from `EL5bHBXIjlpMhkhyT2As3EzLwGyLcqF9Q2zL48o7DY6h`, use the one the system assigned.

**Log out** when done.

---

## Step 1b: Issue VetterCerts (only if missing)

> **Log in as:** mock-gsma admin

**Page:** [Vetter Certifications](https://vvp-issuer.rcnx.io/ui/vetter)

Skip this step if both vetters already have certifications.

1. Log in as the **mock-gsma** admin
2. Navigate to **Vetter Certifications**

### For Brand Assure:
3. Click **Issue VetterCert**
4. Select **Organisation:** Brand Assure
5. **ECC Targets:** Search and select `44` (UK)
6. **Jurisdiction Targets:** Search and select `GBR`
7. Click **Issue**

### For Deutsche Vetters:
8. Click **Issue VetterCert** again
9. Select **Organisation:** Deutsche Vetters
10. **ECC Targets:** Select `49` (Germany) and `44` (UK)
11. **Jurisdiction Targets:** Select `DEU` and `GBR`
12. Click **Issue**

**Log out** when done.

---

## Step 2: Issue Extended Brand credential (Brand Assure → TEST Inc)

> **Log in as:** Brand Assure admin

**Page:** [Credentials](https://vvp-issuer.rcnx.io/ui/credentials)

1. Log in as the **Brand Assure** admin
2. Navigate to **Credentials**
3. Click **Issue Credential**
4. **Schema:** Select `Extended Brand Credential` (`EK7kPhs5...`)
5. The form shows simplified fields:
   - **Brand Owner (required):** Select `TEST Inc` from the organisation dropdown (all orgs are listed)
     - The LEI field auto-populates from the selected org
   - **Brand Name:** `TEST Inc`
   - **Assertion Country:** Select `GBR` from the dropdown
6. **Edges:** The `issuer` edge should auto-populate with Brand Assure's LE credential. If not, select it manually.
7. Click **Issue**

> **Record the credential SAID** — this is the Brand credential for the dossier.

**Log out** when done.

---

## Step 3: Issue Extended TNAlloc credential (Deutsche Vetters → TEST Inc)

> **Log in as:** Deutsche Vetters admin

**Page:** [Credentials](https://vvp-issuer.rcnx.io/ui/credentials)

1. Log in as the **Deutsche Vetters** admin
2. Navigate to **Credentials**
3. Click **Issue Credential**
4. **Schema:** Select `TN Allocation` (`EFvnoHDY...`)
5. Fill in:
   - **Allocated Organization (required):** Select `TEST Inc` from the organisation dropdown
   - **Numbers:** Enter the phone numbers to allocate, e.g.:
     ```
     {"tn": ["+441923312000", "+441923312001", "+441923312002"]}
     ```
   - **Channel:** Select `voice`
   - **Do Not Originate:** Leave unchecked (false)
6. **Edges:** The `issuer` edge should auto-populate with Deutsche Vetters' LE credential.
7. Click **Issue**

> **Record the TNAlloc credential SAID** and the phone numbers you entered (you'll need one for the TN mapping in Step 8).

**Log out** when done.

---

## Step 4: Create signing identity for TEST Inc

> **Log in as:** TEST Inc admin (admin@testinc.com)

**Page:** [Identity](https://vvp-issuer.rcnx.io/ui/identity)

1. Log in as `admin@testinc.com`
2. Navigate to **Identity**
3. Click **Create Identity**
4. Fill in:
   - **Name:** `test-signing-key` (or any meaningful name)
   - **Allow key rotation:** Leave checked (default)
5. Click **Create**

> **Record the signing identity AID** shown after creation.

Stay logged in — the next two steps are also as TEST Inc.

---

## Step 5: Issue GCD — Delegate Signing (TEST Inc → signing key)

> **Logged in as:** TEST Inc admin (admin@testinc.com)

**Page:** [Credentials](https://vvp-issuer.rcnx.io/ui/credentials)

This credential delegates PASSporT signing authority to the signing key created in Step 4.

1. Navigate to **Credentials**
2. Click **Issue Credential**
3. **Schema:** Select `General Cooperative Delegation` (`EL7irIKY...`)
4. Fill in:
   - **Delegate Identity:** The identity picker dropdown shows only signing keys (org identities are filtered out) — select `test-signing-key`
   - **c_goal:** Enter `delsig`
   - **c_proto:** Pre-filled with `sip` (default)
   - **c_prove:** Pre-filled with `attestation` (default)
5. **Edges:** The `issuer` edge should auto-populate with TEST Inc's LE credential.
7. Click **Issue**

> **Record the GCD (delsig) credential SAID.**

---

## Step 6: Issue GCD — Service Provider Allocation (TEST Inc → TEST Inc)

> **Logged in as:** TEST Inc admin (admin@testinc.com)

**Page:** [Credentials](https://vvp-issuer.rcnx.io/ui/credentials)

This credential authorises TEST Inc as a service provider (self-issued).

1. Click **Issue Credential**
2. **Schema:** Select `General Cooperative Delegation` (`EL7irIKY...`)
3. Fill in:
   - **Recipient:** Select `TEST Inc` from the organisation dropdown (self-issued for service provider authorisation)
   - **c_goal:** Enter `alloc`
   - **c_proto:** Pre-filled with `sip` (default)
   - **c_prove:** Pre-filled with `attestation` (default)
4. **Edges:** The `issuer` edge should auto-populate.
5. Click **Issue**

> **Record the GCD (alloc) credential SAID.**

---

## Step 7: Create Dossier via Wizard

> **Logged in as:** TEST Inc admin (admin@testinc.com)

**Page:** [Dossier](https://vvp-issuer.rcnx.io/ui/dossier)

1. Navigate to **Dossier**
2. Click **Create Dossier**
3. **Step 1 — Name:** Enter `TEST Inc VVP Dossier`
4. **Step 2 — Select Edge Credentials:**

   The wizard shows four edge slots with user-friendly labels:

   | Edge Slot | Label | What to select |
   |---|---|---|
   | vetting | **Organisation Verification** | The Extended Brand from Step 2 (preview shows "TEST Inc") |
   | alloc | **Service Provider Authorisation** | The GCD (alloc) from Step 6 (preview shows "alloc") |
   | tnalloc | **Phone Number Allocation** | The TNAlloc from Step 3 (preview shows your phone numbers) |
   | delsig | **Signing Authorisation** | The GCD (delsig) from Step 5 (preview shows "delsig") |

   - If there's only one candidate for a slot, it **auto-selects**
   - Each credential shows a **preview** with key attributes (brand name, phone numbers, goal, etc.)
   - Select the correct credential for each slot

5. **Step 3 — Review:** Confirm all four edges are populated
6. Click **Create Dossier**

> **Record the dossier SAID.**

---

## Step 8: Create TN Mapping

> **Logged in as:** TEST Inc admin (admin@testinc.com)

**Page:** [TN Mappings](https://vvp-issuer.rcnx.io/ui/tn-mappings)

1. Navigate to **TN Mappings**
2. Click **Create Mapping**
3. Fill in:
   - **Telephone Number:** One of the TNs from Step 3, e.g. `+441923312000`
   - **Dossier:** Select the dossier from Step 7 from the dropdown
   - **Signing Identity:** Select `test-signing-key`
4. Click **Create**

Repeat for additional TNs as needed.

---

## What you've built

```
                        ┌─────────────────────┐
                        │  mock-gleif (Root)   │
                        └──────────┬──────────┘
                                   │
                        ┌──────────▼──────────┐
                        │   mock-qvi (QVI)    │
                        └──────────┬──────────┘
                                   │
                        ┌──────────▼──────────┐
                        │    TEST Inc (LE)     │
                        └──────────┬──────────┘
                                   │
          ┌────────────────────────┼────────────────────────┐
          │                        │                        │
 Brand Assure              Deutsche Vetters           TEST Inc
 issues Brand              issues TNAlloc          issues 2x GCD
 to TEST Inc               to TEST Inc         (alloc + delsig)
          │                        │                        │
          └────────────┬───────────┘              ┌─────────┘
                       │                          │
              ┌────────▼──────────────────────────▼────────┐
              │               CVD Dossier                  │
              │  vetting:  Extended Brand                  │
              │  tnalloc:  TN Allocation                   │
              │  alloc:    GCD (alloc)                     │
              │  delsig:   GCD (delsig) → test-signing-key │
              └───────────────────┬────────────────────────┘
                                  │
                      ┌───────────▼───────────┐
                      │     TN Mapping        │
                      │  +441923312000        │
                      │  → dossier            │
                      │  → test-signing-key   │
                      └───────────────────────┘
```

---

## Login summary

| Step | Log in as | Organisation | Action |
|------|-----------|-------------|--------|
| 1 | admin@testinc.com | (System admin) | Create TEST Inc org |
| 1b | mock-gsma admin | mock-gsma | Issue VetterCerts (if needed) |
| 2 | Brand Assure admin | Brand Assure | Issue Extended Brand → TEST Inc |
| 3 | Deutsche Vetters admin | Deutsche Vetters | Issue TNAlloc → TEST Inc |
| 4 | admin@testinc.com | TEST Inc | Create signing identity |
| 5 | admin@testinc.com | TEST Inc | Issue GCD (delsig) → signing key |
| 6 | admin@testinc.com | TEST Inc | Issue GCD (alloc) → TEST Inc |
| 7 | admin@testinc.com | TEST Inc | Create dossier (4 edges) |
| 8 | admin@testinc.com | TEST Inc | Create TN mapping |

---

## Verification

### In the UI
1. On the **Dossier** page, your new dossier should appear in the list
2. Click it to view edge credentials and download the CESR bundle
3. On the **TN Mappings** page, your mapping should show the dossier and signing identity

### Via API (optional)
```bash
curl -s -X POST -H "Content-Type: application/json" \
  "https://vvp-issuer.rcnx.io/tn/lookup" \
  -d '{"tn": "+441923312000", "api_key": "<TEST_INC_ORG_API_KEY>"}' \
  | python3 -m json.tool
```

---

## Troubleshooting

| Problem | Cause | Fix |
|---|---|---|
| Can't see Credentials page | Not logged in as correct org admin | Log out, log in as the right admin |
| No schemas in dropdown | Org type not authorised for that schema | Check org type is `regular` |
| Recipient AID not accepted | AID doesn't exist in KERI Agent | Verify AID, or create identity first |
| Issuer edge not auto-populated | Org has no LE credential | Re-create org (mock vLEI provisioning may have failed) |
| Dossier wizard shows 0 candidates for a slot | Credential was issued by wrong org or to wrong AID | Verify the credential's issuer and recipient match expectations |
| TN mapping fails "already mapped" | TN already has a mapping in this org | Use a different TN or delete the existing mapping first |
| TN mapping fails "not allocated" | TN not in any TNAlloc credential for this org | Check the TNAlloc from Step 3 contains this exact TN |
