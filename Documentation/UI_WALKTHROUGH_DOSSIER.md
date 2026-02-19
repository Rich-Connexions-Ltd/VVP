# Dossier Creation Walkthrough — UI Guide

**Issuer URL:** https://vvp-issuer.rcnx.io

This walkthrough creates a complete VVP dossier for a new organisation ("TEST Inc") using the VVP Issuer UI. At each stage you **log out and log back in** as the admin for the organisation issuing that credential.

---

## Prerequisites

The following organisations and VetterCerts already exist:

| Organisation | Org Type | Role | VetterCert |
|---|---|---|---|
| mock-gsma | `vetter_authority` | Issues VetterCerts | n/a |
| Brand Assure | `vetter_authority` | Vetter (brand) | ECC: 44, Jurisdiction: GBR |
| Deutsche Vetters | `vetter_authority` | Vetter (TN) | ECC: 49+44, Jurisdiction: DEU+GBR |

If either vetter is missing a VetterCert, see [Step 1b](#step-1b-issue-vettercerts-only-if-missing) first.

---

## Step 1: Create TEST Inc organisation

> **Log in as:** System Admin

### Login Page

1. Go to https://vvp-issuer.rcnx.io
2. You'll see the **Sign In** page with:
   - A "Sign in with Microsoft" button (if OAuth is enabled)
   - Two tabs: **Email/Password** (default) and **API Key**
3. Use the **Email/Password** tab — enter your system admin credentials
4. Click **Sign In**

### Organisation Management Page

**Navigation:** The top nav bar shows: Identities | Schemas | Credentials | Dossiers | VVP Headers | TN Mappings | PBX | Help | Admin. (Organisations and Users links are visible only to system admins.)

5. Navigate to **Organisations** (visible in nav for admins)
6. The page heading reads **"Organization Management"**
7. Click the **Create Organization** button (top-right of page)
8. A modal dialog appears with:
   - **Organization Name** — enter `TEST Inc`
   - **Admin Email** — enter an email (e.g. `admin@testinc.com`)
   - **Password** — auto-generated 16-character password (click **Regenerate** to get a new one)
9. Click **Create Organization**

The system auto-provisions a mock vLEI chain (GLEIF → QVI → LE) and assigns an AID. After creation, the org appears as a card in the grid showing:
- Name, type badge (`Organization` in gray), status badge (`Active` in green)
- **LEI** (auto-generated pseudo-LEI)
- **AID** (the KERI identifier — record this)
- **LE Credential** SAID

> **Note:** Record the admin email/password shown in the confirmation modal — you'll need them in Steps 4–8. Copy the password immediately; it's shown only once.

**Log out** when done.

---

## Step 1b: Issue VetterCerts (only if missing)

> **Log in as:** mock-gsma admin

**Page:** Vetter Certifications (`/ui/vetter` — no nav link; access via the info banner on the Credentials page or direct URL)

Skip this step if both vetters already have certifications.

1. Log in as the **mock-gsma** admin
2. Navigate to the **Vetter Certifications** page
3. The page heading reads **"Vetter Certification"** with a blue info box explaining what VetterCerts authorise
4. An orange warning box notes this is for testing/development purposes

### For Brand Assure:

5. In the **"Issue Vetter Certification"** form:
   - **Vetter Organization (recipient):** Select `Brand Assure` from the dropdown
   - **ECC Targets:** The searchable multi-select shows country codes with a search bar, "All" and "Clear" buttons. Type `44` or scroll to find `+44 United Kingdom`. Click the checkbox to select it. A blue chip `+44` appears above the list.
   - **Jurisdiction Targets:** Similarly, search for `GBR` and select it. A green chip `GBR` appears.
   - **Certification Expiry:** Leave blank (optional)
6. Click **Issue Vetter Certification**
7. A green success box shows the issued credential SAID

### For Deutsche Vetters:

8. In the same form:
   - **Vetter Organization:** Select `Deutsche Vetters`
   - **ECC Targets:** Select `+49 Germany` and `+44 United Kingdom` (two blue chips)
   - **Jurisdiction Targets:** Select `DEU` and `GBR` (two green chips)
9. Click **Issue Vetter Certification**

Both certifications now appear in the **"Existing Vetter Certifications"** list below the form, each showing SAID, org name, status, date, and coloured target badges.

> **Note:** The Vetter Certifications page does not currently have a revocation function. To revoke a VetterCert, use the admin cleanup API (`POST /admin/cleanup/credentials`).

**Log out** when done.

---

## Step 2: Issue Extended Brand credential (Brand Assure → TEST Inc)

> **Log in as:** Brand Assure admin

**Page:** Credentials (nav: **Credentials**)

1. Log in as the **Brand Assure** admin
2. Navigate to **Credentials**
3. The page heading reads **"Credential Management"**

### Issue form

4. At the top of the form, three **credential type cards** are shown: **TN Allocation** (Phone number allocation) | **Delegated Signer** (Delegation credential) | **Brand Credential** (Brand ownership). Click **Brand Credential** — it highlights with a blue border.

   > The "Legal Entity" and "Vetter Cert" card types are filtered out for `vetter_authority` orgs. Legal Entity is for QVIs; Vetter Certs are issued from the dedicated Vetter Certifications page.

5. **Schema:** The dropdown (filtered for Brand Assure's `vetter_authority` org type) auto-selects **Extended Brand Credential** when you click the card.

6. **Brand Owner:** Immediately below the schema selection, the recipient field label changes from "Recipient AID" to **"Brand Owner"** (context-aware label for Brand schemas). Use the **"Or pick org..."** dropdown on the right to select `TEST Inc` — this auto-populates the Brand Owner AID field.

7. The form dynamically generates attribute fields based on the schema. In **Form Mode** (default tab):
   - **LEI:** Auto-populates from the selected organisation's stored LEI (set when TEST Inc was created)
   - **brandName:** Enter `TEST Inc` (required)
   - **brandDisplayName:** Enter `TEST Inc` (optional — used for caller ID display)
   - **Advanced Constraints** (collapsible section — click to expand if needed):
     - **assertionCountry:** Select `GBR` from the dropdown

8. **Credential Edges (from schema definition):** Below the attributes, a collapsible edge section appears. The **`le`** (Legal Entity) edge slot is shown but has **no candidates in the dropdown** — this is normal for cross-org issuance (the `le` edge links to the brand owner's LE credential, which Brand Assure doesn't hold). Leave it empty.

   Below that, an **"Additional Edges (Advanced)"** section allows manually adding edge types: `certification`, `vetting`, `delegation`, `jl`, `le`, or `custom`. You do not need to add any — the `certification` edge is **automatically injected** by the server.

9. Click **Issue Credential**

A success toast appears and the credential details are shown. The **credential SAID** is `EC7XJUOe1HgQI8l5FWgd01OwZRQq9SPcND4jOCAFr1IU`. Record this.

The credential also appears in the **"Issued by Your Organization"** table below, showing SAID, schema, status (`issued` in green), and date.

**Log out** when done.

---

## Step 3: Issue TN Allocation credential (Deutsche Vetters → TEST Inc)

> **Log in as:** Deutsche Vetters admin

**Page:** Credentials (nav: **Credentials**)

1. Log in as the **Deutsche Vetters** admin
2. Navigate to **Credentials**

### Issue form

3. Click the **TN Allocation** type card (blue highlight)

4. **Schema:** Auto-selects **Extended TN Allocation** when you click the card.

5. **Allocated Organization:** The recipient label changes to **"Allocated Organization"** (context-aware label for TNAlloc schemas). Use the **"Or pick org..."** dropdown to select `TEST Inc` — this auto-populates the Allocated Organization AID field.

6. Schema-driven attribute fields appear in **Form Mode** (default):
   - **numbers:** Switch to the **Advanced (JSON)** tab and enter:
     ```json
     {"tn": ["+441923312000", "+441923312001", "+441923312002"]}
     ```
     Or in **Form Mode**, use the array "Add item" buttons to enter each number
   - **channel:** Select `voice` from the dropdown
   - **doNotOriginate:** Leave unchecked (false)

7. **Credential Edges (from schema definition):** Two edge slots appear:
   - **`tnalloc`** (Required, I2I) — For a first allocation this will show no candidates. Leave empty — it's used for chaining allocations from a regulator.
   - **`issuer`** (Optional, NI2I) — Shows **all credentials** visible to the Deutsche Vetters admin (unfiltered). Scroll through the list to find Deutsche Vetters' **Legal Entity** credential and select it via its radio button.

   > **UX note:** The `issuer` edge currently has no schema filter, so all credential types appear (including TNAllocs). Look for the credential with schema type "Legal Entity" to select the correct one. The `certification` edge is **automatically injected** by the server.

8. Click **Issue Credential**

The **TNAlloc credential SAID** is `EGu649N_St6w74WAF9vU_6-IX01wVIpt62BwqRteFwR4`. Record this and the phone numbers you entered — you'll need one for the TN mapping in Step 8.

**Log out** when done.

---

## Step 4: Create signing identity for TEST Inc

> **Log in as:** TEST Inc admin (the credentials you recorded in Step 1)

**Page:** Identities (nav: **Identities**)

1. Log in with the TEST Inc admin email and password from Step 1
2. Navigate to **Identities**
3. The page heading reads **"Identity Management"**

### Create New Identity form

4. In the **"Create New Identity"** card:
   - **Identity Name:** Enter `test-signing-key`
   - **Allow key rotation:** Leave checked (default, recommended)
5. Click **Create Identity**

A green success box appears showing:
- **Identity Name:** `test-signing-key`
- **AID:** The newly created KERI identifier
- **Transferable:** Yes
- **Witnesses:** count
- **OOBI URLs** card with copyable URLs
- **Publish results** showing per-witness success/failure

The identity also appears in the **"Existing Identities"** list below with a green `Transferable` badge, the AID, and action buttons (View OOBI URLs, Rotate Keys, Delete).

> Record the **signing identity AID** shown after creation.

Stay logged in — the next two steps are also as TEST Inc.

---

## Step 5: Issue GCD — Delegate Signing (TEST Inc → signing key)

> **Logged in as:** TEST Inc admin

**Page:** Credentials (nav: **Credentials**)

This credential delegates PASSporT signing authority to the signing key created in Step 4.

1. Navigate to **Credentials**
2. From the **Schema** dropdown, select **Generalized Cooperative Delegation Credential** — this auto-selects the **Delegated Signer** type card (blue highlight).

3. **Delegate Identity:** The recipient label changes to **"Delegate Identity"** (context-aware label for GCD schemas). A **"Pick identity..."** dropdown appears listing identities.

   > **Known issue:** The identity picker currently shows **all identities in the system**, not just those belonging to your org. Select `test-signing-key` (the one you created in Step 4). Ignore other identities.

4. Schema-driven attribute fields appear (all blank by default — they are **not** pre-filled):
   - **c_goal:** Add an array item with value `delsig` (required for VVP dossier matching)
   - **c_proto:** Leave **empty** (optional; if entered, format must be `protocol: roles`, e.g., `sip: originator`)
   - **c_prove:** Leave **empty** (optional)

5. **Credential Edges:** The **`issuer`** edge slot (Required, I2I) shows candidates but does **not** auto-populate with the LE credential.

   > **Known issue:** The LE credential from mock vLEI provisioning doesn't appear in the edge candidates because it was created as a database placeholder, not issued through the KERI Agent. The candidates list shows Brand and TN Allocation credentials issued to your org — these are **not** the right type. Leave the issuer edge **empty** and submit.

6. Click **Issue Credential**

> Record the **GCD (delsig) credential SAID**.

---

## Step 6: Issue GCD — Service Provider Allocation (TEST Inc → TEST Inc)

> **Logged in as:** TEST Inc admin

**Page:** Credentials (nav: **Credentials**)

This credential authorises TEST Inc as a service provider (self-issued).

1. From the **Schema** dropdown, select **Generalized Cooperative Delegation Credential** (if not already selected). The **Delegated Signer** card stays highlighted.

2. **Delegate Identity:** Use the **"Or pick org..."** dropdown and select `TEST Inc` (self-issued — the org delegates to itself).

3. Schema-driven attribute fields (all blank by default):
   - **c_goal:** Add an array item with value `alloc`
   - **c_proto:** Leave **empty**
   - **c_prove:** Leave **empty**

4. **Credential Edges:** Leave the **`issuer`** edge **empty** (same LE credential issue as Step 5).

5. Click **Issue Credential**

> Record the **GCD (alloc) credential SAID**.

---

## Step 7: Create Dossier via Wizard

> **Logged in as:** TEST Inc admin

**Page:** Dossiers (nav: **Dossiers**)

1. Navigate to **Dossiers**
2. The page shows a **4-step wizard** with numbered step indicators (1–4) connected by lines

### Step 1 — Select Accountable Party Organisation

3. **Select AP Organization:** If you only belong to one org, TEST Inc is **auto-selected** and the dropdown is disabled. Otherwise, select `TEST Inc` from the dropdown.
4. Click **Next →**

### Step 2 — Select Edge Credentials

5. The wizard shows **six edge slots** as collapsible cards, each with a label, description, and Required/Optional badge:

   | Edge Slot | Label | Badge | What to select |
   |---|---|---|---|
   | `vetting` | **Organisation Verification** | Required | The Extended Brand from Step 2 |
   | `alloc` | **Service Provider Authorisation** | Required | The GCD (alloc) from Step 6 |
   | `tnalloc` | **Phone Number Allocation** | Required | The TNAlloc from Step 3 |
   | `delsig` | **Signing Authorisation** | Required | The GCD (delsig) from Step 5 |
   | `bownr` | **Brand Ownership** | Optional | Skip (not needed for basic dossier) |
   | `bproxy` | **Brand Proxy** | Optional | Skip (not needed for basic dossier) |

6. Click each edge card header to expand it. Inside each:
   - A table of candidate credentials appears with columns: radio button, SAID (truncated), Type, Preview, Issued date
   - The **Preview** column shows key attributes (brand name, phone numbers, goal value, etc.)
   - If there's **only one candidate**, it **auto-selects** (green checkmark appears on the header)
   - Click the radio button to select a credential; the row highlights in blue

7. Ensure all four required edges show a green **✓** checkmark on their headers
8. Click **Next →** (disabled until all required edges are selected)

### Step 3 — Dossier Metadata

9. Optional fields:
   - **Dossier Name:** Enter `TEST Inc VVP Dossier` (or leave blank)
   - **OSP Organization:** Leave as "None" (optional)
10. A summary shows all selected edges with checkmarks
11. Click **Next →**

### Step 4 — Review & Create

12. The review panel shows:
    - **AP Organization:** TEST Inc
    - **Dossier Name** (if entered)
    - **Edge Credentials:** One row per selected edge with label, SAID prefix, and schema type
13. Click **Create Dossier**

A green **"Dossier Created Successfully"** banner appears showing:
- **Dossier SAID** (monospace code block)
- **Issuer AID**
- **Dossier URL** (clickable)
- **Edge Count**
- **Witness Publish** results

Two action buttons appear:
- **"Create TN Mapping →"** — navigates directly to TN Mappings with the dossier pre-selected
- **"Create Another"** — resets the wizard

> Record the **dossier SAID**, or click **"Create TN Mapping →"** to proceed directly to Step 8.

---

## Step 8: Create TN Mapping

> **Logged in as:** TEST Inc admin

**Page:** TN Mappings (nav: **TN Mappings**)

If you clicked "Create TN Mapping →" from the dossier wizard, the create modal **opens automatically** with the dossier pre-selected.

Otherwise:

1. Navigate to **TN Mappings**
2. Click the **Create TN Mapping** button (top-right)
3. A modal dialog appears with:
   - **Telephone Number:** Enter one of the TNs from Step 3 in E.164 format, e.g. `+441923312000`
   - **Dossier:** Select the dossier from Step 7 from the dropdown (shows dossier name or root SAID)
   - **Signing Identity:** Select `test-signing-key` from the dropdown
4. Click **Create Mapping**

A toast notification confirms "TN mapping created successfully". The mapping appears in the table showing:
- Telephone number (monospace, bold)
- Brand name and logo (if available)
- Identity name
- Dossier SAID (truncated)
- Status badge (`Active` in green)
- Created date
- Action buttons: **Test** | **Edit** | **Delete**

5. Click the **Test** button to verify — a modal shows either:
   - **"TN Lookup Successful"** (green) with TN, organisation, dossier SAID, identity, and brand details
   - **"TN Lookup Failed"** (red) with the error message

Repeat for additional TNs as needed.

---

## What you've built

```
                        +---------------------+
                        |  mock-gleif (Root)   |
                        +----------+----------+
                                   |
                        +----------v----------+
                        |   mock-qvi (QVI)    |
                        +----------+----------+
                                   |
                        +----------v----------+
                        |    TEST Inc (LE)     |
                        +----------+----------+
                                   |
          +------------------------+------------------------+
          |                        |                        |
 Brand Assure              Deutsche Vetters           TEST Inc
 issues Brand              issues TNAlloc          issues 2x GCD
 to TEST Inc               to TEST Inc         (alloc + delsig)
          |                        |                        |
          +------------+-----------+              +---------+
                       |                          |
              +--------v--------------------------v--------+
              |               CVD Dossier                  |
              |  vetting:  Extended Brand                  |
              |  tnalloc:  TN Allocation                   |
              |  alloc:    GCD (alloc)                     |
              |  delsig:   GCD (delsig) -> test-signing-key|
              +-------------------+------------------------+
                                  |
                      +-----------v-----------+
                      |     TN Mapping        |
                      |  +441923312000        |
                      |  -> dossier           |
                      |  -> test-signing-key  |
                      +-------------------  --+
```

---

## Login summary

| Step | Log in as | Organisation | Action |
|------|-----------|-------------|--------|
| 1 | System admin | (System admin) | Create TEST Inc org + admin user |
| 1b | mock-gsma admin | mock-gsma | Issue VetterCerts (if needed) |
| 2 | Brand Assure admin | Brand Assure | Issue Extended Brand → TEST Inc |
| 3 | Deutsche Vetters admin | Deutsche Vetters | Issue TNAlloc → TEST Inc |
| 4 | TEST Inc admin | TEST Inc | Create signing identity |
| 5 | TEST Inc admin | TEST Inc | Issue GCD (delsig) → signing key |
| 6 | TEST Inc admin | TEST Inc | Issue GCD (alloc) → TEST Inc |
| 7 | TEST Inc admin | TEST Inc | Create dossier (4 required edges) |
| 8 | TEST Inc admin | TEST Inc | Create TN mapping |

---

## Navigation reference

The top navigation bar is consistent across all pages:

| Nav Link | Page | Used in Steps |
|----------|------|---------------|
| Identities | `/ui/identity` — Create/manage KERI identities | Step 4 |
| Schemas | `/ui/schemas` — Browse available credential schemas | (reference) |
| Credentials | `/ui/credentials` — Issue and list credentials | Steps 2, 3, 5, 6 |
| Dossiers | `/ui/dossier` — Dossier wizard and readiness check | Step 7 |
| TN Mappings | `/ui/tn-mappings` — Map phone numbers to dossiers | Step 8 |
| Admin | `/ui/admin` — System administration | (admin only) |
| Organizations | `/organizations/ui` — Org management | Step 1 (admin only) |

---

## Verification

### In the UI

1. On the **Dossiers** page, your new dossier should appear in the list
2. The **"Build & Download Existing Dossier"** section (below the wizard) lets you select a credential and download its full dossier in CESR or JSON format
3. On the **TN Mappings** page, your mapping shows the dossier, signing identity, and status
4. Click the **Test** button on any mapping to verify the full TN lookup chain

### Via API (optional)

```bash
curl -s -X POST -H "Content-Type: application/json" \
  "https://vvp-issuer.rcnx.io/tn/lookup" \
  -d '{"tn": "+441923312000", "api_key": "<TEST_INC_ORG_API_KEY>"}' \
  | python3 -m json.tool
```

### Dossier Readiness Check

The Dossiers page also includes a **Dossier Readiness** tool below the wizard:
1. Select an organisation from the dropdown
2. Click **Check Readiness**
3. Each edge slot shows a coloured status card:
   - **Green** (ready) — credential available
   - **Red** (missing) — required credential not found, with a "Create credential →" link
   - **Orange** (invalid) — credential present but has issues
   - **Gray** (optional) — optional credential not present
4. A summary banner shows whether the organisation is ready to create a dossier

---

## Troubleshooting

| Problem | Cause | Fix |
|---|---|---|
| Login page shows only "Sign in with Microsoft" | OAuth is the only enabled method | Use OAuth, or ask admin to enable email/password auth |
| Can't see Organisations link in nav | Not logged in as system admin | System admin role required for org management |
| No schemas in dropdown | Org type not authorised for that schema | `regular` orgs can issue Brand/TNAlloc/GCD; `vetter_authority` orgs use the dedicated Vetter page |
| "Use POST /vetter-certifications" error | Tried to issue VetterCert via Credentials page | VetterCerts must be issued from the **Vetter Certifications** page |
| Brand Owner / Delegate Identity / Allocated Org not found | AID doesn't exist in KERI Agent | Create the identity first (Step 4), or verify the AID |
| Issuer edge shows no candidates | Org has no LE credential | Re-create org (mock vLEI provisioning may have failed) |
| Dossier wizard shows 0 candidates for a slot | Credential was issued by wrong org or to wrong AID | For I2I edges (alloc, tnalloc, delsig), the credential must be issued **to** the AP org |
| "Next" button disabled in wizard Step 2 | Not all required edges selected | Expand each required edge slot and select a credential |
| TN mapping fails "already mapped" | TN already has a mapping in this org | Delete the existing mapping first, or use a different TN |
| TN mapping fails "not allocated" | TN not in any TNAlloc credential for this org | Check the TNAlloc from Step 3 contains this exact TN |
| Credential issuance returns 503 | KERI Agent is unavailable | Wait a moment and retry; check system health via Admin page |
| c_proto rejects "sip" with "Match the requested format" | Schema pattern requires `protocol: roles` format | Enter `sip: originator` or leave empty (optional field) |
| Issuer edge shows Brand/TNAlloc instead of LE | LE credential is a mock vLEI placeholder (not in KERI Agent) | Leave issuer edge empty — credential issuance works without it |
| Verifier returns `dossier_verified=INDETERMINATE` | TEL events missing — credentials issued before Sprint 74, or in a previous KERI Agent session | Re-issue credentials to get fresh TEL in current KERI Agent LMDB. For the test org use `scripts/bootstrap-issuer.py --skip-reinit` |
| Verifier returns `vetter_constraints_valid=INDETERMINATE` | VetterCert not reachable from dossier root (DFS edge walk) | Ensure issuing org has an active VetterCert **before** issuing Brand/TNAlloc/GCD — the `certification` edge is auto-injected server-side for Extended schemas |
| All credentials gone after KERI Agent restart | KERI Agent LMDB is ephemeral (`/tmp`) — cleared on container restart | Re-issue credentials. The bootstrap script handles stale LE and VetterCert pointers automatically with `--skip-reinit` |

---

## Known UI Issues

Issues discovered during walkthrough testing that should be fixed in a future sprint:

| Issue | Location | Impact | Suggested Fix |
|-------|----------|--------|---------------|
| Identity picker shows ALL system identities | `GET /identity` is unfiltered, public endpoint | Users see signing keys from other orgs | Filter by org on server-side or frontend |
| c_goal/c_proto/c_prove not pre-filled | GCD form fields are blank | Users must know VVP-specific values | Pre-fill c_goal with `delsig` or `alloc` based on context |
| c_proto validation message unhelpful | HTML5 pattern validation: `^[^:]+: *.+$` | "Match the requested format" doesn't explain the format | Add placeholder text showing example: `sip: originator` |
| LE credential missing from issuer edge candidates | Mock vLEI provisioning creates DB-only placeholder | Auto-populate fails silently, users can't find LE cred | Either issue real KERI credential or inject DB-stored SAID into candidates |
| Issuer edge shows all credential types (TNAlloc) | NI2I/no schema constraint on `issuer` edge in TNAlloc schema | Users must manually identify correct credential | Add schema filtering hint or auto-select LE credential |
| Vetter Certifications page has no revocation UI | `/ui/vetter` only supports issuance | Must use admin cleanup API to revoke | Add revoke button to existing certifications list |
| No nav link to Vetter Certifications page | `/ui/vetter` not in NAV_LINKS | Users must know the direct URL or find the info banner | Add nav link (conditionally for vetter_authority orgs) |
