# Dossier Creation Walkthrough — UI Guide

**Issuer URL:** https://vvp-issuer.rcnx.io

This walkthrough creates **three VVP dossiers** covering the three key verification scenarios. Each dossier belongs to a different accountable party organisation and is issued by a different vetter configuration. By the end you have three live TN mappings and a PBX configured to make test calls that exercise each scenario.

---

## Scenario Overview

| Phase | AP Organisation | Caller TN | Brand issuer | VetterCert ECC | Expected `X-VVP-Vetter-Status` |
|-------|----------------|-----------|--------------|----------------|-------------------------------|
| **1** | TEST Phase 1 | +441923312001 | Self-issued (no vetter) | *(none)* | *(not set)* |
| **2a** | TEST Phase 2a | +441923312002 | Brand Assure (ECC: UK) | `["44"]` | `PASS` |
| **2b** | TEST Phase 2b | +441923312003 | US Vetters (ECC: US only) | `["1"]` | `FAIL-JURISDICTION` |

All three organisations use Deutsche Vetters for TN Allocation credentials. Extension 1006 (`+441923311006`) is the callee TN in all loopback tests — it must be included in each org's TNAlloc.

---

## Part A: Shared Infrastructure

These steps are done **once**. If the vetter organisations already exist with valid VetterCerts, skip to [Part B](#part-b-per-organisation-dossier-setup).

---

### Step 1: Create the four supporting organisations

> **Log in as:** System Admin

**Page:** Organisation Management (`/organizations/ui`)

1. Go to https://vvp-issuer.rcnx.io, sign in with system admin credentials.
2. Navigate to **Organisations** (visible in nav for admins).
3. Click **Create Organization** for each of the following. Record the admin email and password shown in the confirmation modal — they are shown only once.

| Organisation | Type | Purpose |
|---|---|---|
| `Brand Assure` | `vetter_authority` | Issues Extended Brand credentials to Phase 2a org |
| `US Vetters` | `vetter_authority` | Issues Extended Brand credentials to Phase 2b org |
| `Deutsche Vetters` | `vetter_authority` | Issues TNAlloc credentials to all three AP orgs |

For each:
- **Organization Name** — as above
- **Admin Email** — e.g. `admin@brandassure.example`
- **Password** — auto-generated; click **Regenerate** if needed, copy immediately

The system auto-provisions a mock vLEI chain (GLEIF → QVI → LE) for each org and assigns an AID.

**Log out** when all four are created.

---

### Step 1b: Issue VetterCerts

> **Log in as:** mock-gsma admin

**Page:** Vetter Certifications (`/ui/vetter` — no nav link; access via the info banner on the Credentials page or direct URL)

Issue one VetterCert to each of the three vetter organisations:

#### Brand Assure (UK brand vetter)

1. Log in as the **mock-gsma** admin.
2. Navigate to the **Vetter Certifications** page.
3. In the **"Issue Vetter Certification"** form:
   - **Vetter Organization:** Select `Brand Assure`
   - **ECC Targets:** Type `44` in the search box, select `+44 United Kingdom`. A blue chip `+44` appears.
   - **Jurisdiction Targets:** Search `GBR`, select it. A green chip `GBR` appears.
4. Click **Issue Vetter Certification**. Record the SAID.

#### US Vetters (US brand vetter)

5. In the same form:
   - **Vetter Organization:** Select `US Vetters`
   - **ECC Targets:** Search `1`, select `+1 United States`. Chip `+1` appears.
   - **Jurisdiction Targets:** Search `USA`, select it. Chip `USA` appears.
6. Click **Issue Vetter Certification**. Record the SAID.

#### Deutsche Vetters (TN vetter, covers +44 and +49)

7. In the same form:
   - **Vetter Organization:** Select `Deutsche Vetters`
   - **ECC Targets:** Select `+44 United Kingdom` and `+49 Germany` (two chips).
   - **Jurisdiction Targets:** Select `GBR` and `DEU` (two chips).
8. Click **Issue Vetter Certification**. Record the SAID.

All three certifications appear in the **"Existing Vetter Certifications"** list below the form.

**Log out** when done.

---

## Part B: Per-Organisation Dossier Setup

Repeat Steps 2–8 **three times** — once for each AP organisation. A summary table at each step shows what changes per scenario.

---

### Step 2: Create the three AP organisations

> **Log in as:** System Admin

**Page:** Organisation Management (`/organizations/ui`)

Create each of the three accountable party organisations. Record the admin email and password for each.

| Organisation | Admin Email (example) |
|---|---|
| `TEST Phase 1` | `admin@phase1.example` |
| `TEST Phase 2a` | `admin@phase2a.example` |
| `TEST Phase 2b` | `admin@phase2b.example` |

For each:
1. Click **Create Organization**.
2. Enter the Organisation Name and an Admin Email.
3. Copy the auto-generated password immediately.
4. Click **Create Organization**.

**Log out** when all three are created.

---

### Step 3: Issue Brand credentials

Each organisation's Brand credential is issued by a different vetter (or self-issued for Phase 1). Perform each sub-step as the indicated org.

---

#### 3a: Phase 1 — Self-issued Brand (no vetter)

> **Log in as:** TEST Phase 1 admin

**Page:** Credentials (nav: **Credentials**)

TEST Phase 1 issues its own Brand credential — no external vetter is involved, so there is no vetter certification edge in the dossier.

1. Log in as `TEST Phase 1` admin.
2. Navigate to **Credentials**.
3. Click the **Brand Credential** type card (blue highlight). The schema auto-selects **Brand Credential** (not Extended).
4. **Brand Owner:** Use **"Or pick org..."** to select `TEST Phase 1` (self-issued).
5. Fill in attributes:
   - **brandName:** `TEST Phase 1`
   - **brandDisplayName:** `TEST Phase 1` (shown as caller ID)
   - **assertionCountry:** `GBR` (or leave blank)
6. Leave all edge slots empty.
7. Click **Issue Credential**. Record the Brand SAID.

**Log out** when done.

---

#### 3b: Phase 2a — Extended Brand issued by Brand Assure

> **Log in as:** Brand Assure admin

**Page:** Credentials (nav: **Credentials**)

Brand Assure (ECC: `["44"]`, Jurisdiction: `GBR`) issues an Extended Brand credential to TEST Phase 2a. The server auto-injects a `certification` edge linking this credential to Brand Assure's VetterCert.

1. Log in as `Brand Assure` admin.
2. Navigate to **Credentials**.
3. Click the **Brand Credential** type card. The schema dropdown shows **Extended Brand Credential** for vetter_authority orgs — select it.
4. **Brand Owner:** Use **"Or pick org..."** to select `TEST Phase 2a`.
5. Fill in attributes:
   - **brandName:** `TEST Phase 2a`
   - **brandDisplayName:** `TEST Phase 2a`
   - **assertionCountry:** `GBR`
6. Leave all edge slots empty (the `certification` edge is auto-injected by the server).
7. Click **Issue Credential**. Record the Brand SAID.

**Log out** when done.

---

#### 3c: Phase 2b — Extended Brand issued by US Vetters

> **Log in as:** US Vetters admin

**Page:** Credentials (nav: **Credentials**)

US Vetters (ECC: `["1"]`, Jurisdiction: `USA`) issues an Extended Brand credential to TEST Phase 2b. Because US Vetters' ECC covers only US country code (+1), UK calls from this org's TNs will yield `FAIL-JURISDICTION` at verification time.

1. Log in as `US Vetters` admin.
2. Navigate to **Credentials**.
3. Click the **Brand Credential** type card. Select **Extended Brand Credential**.
4. **Brand Owner:** Use **"Or pick org..."** to select `TEST Phase 2b`.
5. Fill in attributes:
   - **brandName:** `TEST Phase 2b`
   - **brandDisplayName:** `TEST Phase 2b`
   - **assertionCountry:** `USA`
6. Leave all edge slots empty (`certification` edge auto-injected).
7. Click **Issue Credential**. Record the Brand SAID.

**Log out** when done.

---

### Step 4: Issue TN Allocation credentials

> **Log in as:** Deutsche Vetters admin

**Page:** Credentials (nav: **Credentials**)

Deutsche Vetters issues a separate TNAlloc to each of the three AP organisations. Each TNAlloc must include **both** the org's originating TN **and** the callee TN (`+441923311006`) — the verifier's `/verify-callee` endpoint checks that the caller's TNAlloc covers the destination TN.

Repeat for each org:

| Organisation | TN numbers to include |
|---|---|
| TEST Phase 1 | `+441923312001`, `+441923311006` |
| TEST Phase 2a | `+441923312002`, `+441923311006` |
| TEST Phase 2b | `+441923312003`, `+441923311006` |

For each allocation:

1. Log in as `Deutsche Vetters` admin.
2. Navigate to **Credentials**.
3. Click the **TN Allocation** type card. Select **Extended TN Allocation**.
4. **Allocated Organization:** Use **"Or pick org..."** to select the target org.
5. Switch to the **Advanced (JSON)** tab for the `numbers` attribute and enter:
   ```json
   {"tn": ["+441923312001", "+441923311006"]}
   ```
   (substitute the correct origin TN for each org)
6. **channel:** `voice`
7. **Credential Edges:** Leave the `tnalloc` edge empty. For the `issuer` edge, find Deutsche Vetters' Legal Entity credential in the list and select it.
8. Click **Issue Credential**. Record the TNAlloc SAID.

**Log out** after issuing all three TNAllocs.

---

### Step 5: Create signing identities

> **Log in as:** each AP org admin in turn

**Page:** Identities (nav: **Identities**)

Each org needs its own signing identity. Create one signing identity per org.

For each of `TEST Phase 1`, `TEST Phase 2a`, `TEST Phase 2b`:

1. Log in as that org's admin.
2. Navigate to **Identities**.
3. In the **"Create New Identity"** card:
   - **Identity Name:** e.g. `phase1-signing-key` (or `phase2a-signing-key`, etc.)
   - **Allow key rotation:** Leave checked (recommended)
4. Click **Create Identity**.

A green success box shows the **AID** and **OOBI URLs**. The identity appears in the **"Existing Identities"** list.

> Record the **signing identity AID** for each org — you will need it in Step 8.

**Log out** after creating each identity.

---

### Step 6: Issue GCD — Delegate Signing (delsig)

> **Log in as:** each AP org admin in turn

**Page:** Credentials (nav: **Credentials**)

Each org must issue a GCD (delsig) credential delegating PASSporT signing authority to its signing identity from Step 5.

For each of `TEST Phase 1`, `TEST Phase 2a`, `TEST Phase 2b`:

1. Log in as that org's admin.
2. Navigate to **Credentials**.
3. From the **Schema** dropdown, select **Generalized Cooperative Delegation Credential** — this auto-selects the **Delegated Signer** type card.
4. **Delegate Identity:** Use the **"Pick identity..."** dropdown and select the signing identity created in Step 5 for this org.
5. Schema-driven attributes:
   - **c_goal:** Add an array item with value `delsig`
   - **c_proto:** Leave empty
   - **c_prove:** Leave empty
6. **Credential Edges:** Leave the `issuer` edge empty (LE credential is a mock vLEI placeholder — see Known Issues).
7. Click **Issue Credential**. Record the GCD (delsig) SAID.

**Log out** after issuing each.

---

### Step 7: Issue GCD — Service Provider Allocation (alloc)

> **Log in as:** each AP org admin in turn

**Page:** Credentials (nav: **Credentials**)

Each org must also issue a GCD (alloc) credential authorising itself as a service provider (self-issued).

For each of `TEST Phase 1`, `TEST Phase 2a`, `TEST Phase 2b`:

1. Log in as that org's admin.
2. Navigate to **Credentials**.
3. From the **Schema** dropdown, select **Generalized Cooperative Delegation Credential**.
4. **Delegate Identity:** Use **"Or pick org..."** and select the same org (self-issued).
5. Schema-driven attributes:
   - **c_goal:** Add an array item with value `alloc`
   - **c_proto:** Leave empty
   - **c_prove:** Leave empty
6. Leave the `issuer` edge empty.
7. Click **Issue Credential**. Record the GCD (alloc) SAID.

**Log out** after issuing each.

---

### Step 8: Create Dossiers via Wizard

> **Log in as:** each AP org admin in turn

**Page:** Dossiers (nav: **Dossiers**)

Create one dossier per organisation using the 4-step wizard. The only difference between phases is which credential fills the `vetting` edge slot.

For each of `TEST Phase 1`, `TEST Phase 2a`, `TEST Phase 2b`:

1. Log in as that org's admin.
2. Navigate to **Dossiers**.

#### Wizard Step 1 — Select AP Organisation

3. The org auto-selects if you only belong to one org. Click **Next →**.

#### Wizard Step 2 — Select Edge Credentials

4. Six edge slots appear as collapsible cards:

| Edge Slot | Label | Badge | What to select |
|---|---|---|---|
| `vetting` | **Organisation Verification** | Required | The Brand credential from Step 3 (issued to this org) |
| `alloc` | **Service Provider Authorisation** | Required | The GCD (alloc) from Step 7 |
| `tnalloc` | **Phone Number Allocation** | Required | The TNAlloc from Step 4 (issued to this org) |
| `delsig` | **Signing Authorisation** | Required | The GCD (delsig) from Step 6 |
| `bownr` | **Brand Ownership** | Optional | Skip |
| `bproxy` | **Brand Proxy** | Optional | Skip |

Expand each card and select the appropriate credential. If there is only one candidate it auto-selects (green checkmark).

> **Phase 1 note:** The `vetting` edge will show the self-issued Brand credential. This is correct — the dossier has no external vetter certification in the chain.

5. When all four required edges show a green **✓**, click **Next →**.

#### Wizard Step 3 — Dossier Metadata

6. **Dossier Name:** e.g. `TEST Phase 1 Dossier` (optional).
7. **OSP Organization:** Leave as "None".
8. Click **Next →**.

#### Wizard Step 4 — Review & Create

9. Review the selected edges. Click **Create Dossier**.

A green **"Dossier Created Successfully"** banner shows the **Dossier SAID**. Record it.

10. Click **"Create TN Mapping →"** to proceed directly to Step 9 with the dossier pre-selected.

---

### Step 9: Create TN Mappings

> **Log in as:** each AP org admin in turn

**Page:** TN Mappings (nav: **TN Mappings**)

Create one TN mapping per organisation. If you clicked "Create TN Mapping →" from the dossier wizard, the modal opens automatically with the dossier pre-selected.

| Organisation | Telephone Number | Signing Identity |
|---|---|---|
| TEST Phase 1 | `+441923312001` | `phase1-signing-key` |
| TEST Phase 2a | `+441923312002` | `phase2a-signing-key` |
| TEST Phase 2b | `+441923312003` | `phase2b-signing-key` |

For each mapping:

1. Log in as that org's admin (if not already).
2. Navigate to **TN Mappings** → click **Create TN Mapping** (or use the wizard link from Step 8).
3. In the modal:
   - **Telephone Number:** Enter the org's TN (E.164 format, from table above)
   - **Dossier:** Select the dossier from Step 8 for this org
   - **Signing Identity:** Select the signing identity created in Step 5
4. Click **Create Mapping**.

A toast confirms "TN mapping created successfully". The mapping appears in the table.

5. Click the **Test** button to verify:
   - **"TN Lookup Successful"** (green) — TN, org, dossier SAID, identity, and brand details shown
   - **"TN Lookup Failed"** (red) — error message shown; check TNAlloc covers this TN

**Log out** after creating each mapping.

---

## Part C: PBX Configuration

### Step 10: Configure and Deploy PBX

> **Log in as:** System admin (or any org admin with a valid API key)

**Page:** PBX Management (nav: **PBX**)
**URL:** `https://vvp-issuer.rcnx.io/ui/pbx`

This step configures the PBX to use your organisation's API key for the VVP signing service, maps extensions to E.164 numbers, and deploys the generated dialplan XML to the live FreeSWITCH PBX.

---

#### Card 1: Signing API Key

The API key is embedded as `X-VVP-API-Key` in every SIP INVITE the PBX sends to the signing service.

1. **Organization** — Select the org whose API key will be used (any of the three works; typically one org is designated for PBX use).
2. **API Key** — Select the key from the dropdown (populated once org is selected).
3. **Raw API Key Value** — Paste the plaintext key. Keys are stored hashed; the PBX needs the raw value.
   > Hint: *"This value goes into the X-VVP-API-Key SIP header."*
4. **Default Caller ID** — E.164 fallback caller ID for test calls (each extension's CLI overrides this for real calls).
5. Click **Save API Key Config**. A badge shows the current key prefix.

---

#### Card 2: Extension CLI Configuration

Map each extension to its E.164 calling line identity — this is the TN the signing service looks up to find the dossier and signing key.

Configure the three extensions for the three scenarios:

| Ext | CLI (E.164) | Enabled | Description |
|-----|-------------|---------|-------------|
| 1001 | `+441923312001` | ✅ | TEST Phase 1 — no vetter |
| 1002 | `+441923312002` | ✅ | TEST Phase 2a — UK vetter (PASS expected) |
| 1003 | `+441923312003` | ✅ | TEST Phase 2b — US vetter (FAIL-JURISDICTION expected) |
| 1004–1009 | *(leave blank)* | — | Not used in this walkthrough |

> Each CLI must appear in a TNAlloc credential held by an org with a TN mapping (Step 9).

Click **Save Extensions** when done.

---

#### Card 3: Deploy to PBX

1. Click **Preview Dialplan XML** to review the generated FreeSWITCH XML before deploying. A modal shows the full dialplan covering all three contexts (`public`, `redirected`, `verified`).
2. Click **Deploy to PBX**.
   - The Issuer generates dialplan XML from the saved extension config, uploads it to the PBX VM via Azure Run Command, and reloads FreeSWITCH (`fs_cli -x 'reloadxml'`).
   - A success toast: *"Dialplan deployed successfully"*
   - The **Last deployed** timestamp updates.

---

## Part D: Test Calls

### Step 11: Make a Test Call

The VVP loopback prefix `7` + extension triggers the full signing → verification → delivery flow. Extension 1006 rings with VVP headers.

```
Extension 100x dials 71006
    │
    ▼  FreeSWITCH public context
       Routes 7xxxx to signing service (sip-redirect, port 5070)
    │
    ▼  sip-redirect
       1. Sends 100 Trying immediately (resets SIP Timer B)
       2. Looks up caller TN → finds dossier + signing key
       3. Creates PASSporT JWT + VVP-Identity header
       4. Returns 302 redirect
    │
    ▼  FreeSWITCH redirected context
       Routes to verification service (vvp-sip-verify, port 5071)
    │
    ▼  vvp-sip-verify
       Verifies PASSporT + dossier, returns 302 with VVP headers
    │
    ▼  FreeSWITCH verified context
       Captures VVP headers, exports to B-leg, delivers to ext 1006
    │
    ▼  Extension 1006 rings — VVP headers available to callee application
```

**Prerequisites:** Extensions 1001, 1002, 1003, and 1006 registered in FreeSWITCH (WebRTC at `wss://pbx.rcnx.io:7443`).

---

#### Scenario 1 — Phase 1: No VetterCert

Dial `71006` from extension **1001** (CLI: `+441923312001`).

| Header | Expected |
|--------|----------|
| `X-VVP-Status` | `VALID` |
| `X-VVP-Brand-Name` | `TEST Phase 1` |
| `X-VVP-Vetter-Status` | *(not set — no vetter in chain)* |

FreeSWITCH log: `[VVP] Delivering: brand=TEST Phase 1, status=VALID, vetter=, warning=`

**Result:** Brand delivered, no vetter check. ✅

---

#### Scenario 2 — Phase 2a: VetterCert with Correct UK Rights

Dial `71006` from extension **1002** (CLI: `+441923312002`).

| Header | Expected |
|--------|----------|
| `X-VVP-Status` | `VALID` |
| `X-VVP-Brand-Name` | `TEST Phase 2a` |
| `X-VVP-Vetter-Status` | `PASS` |

FreeSWITCH log: `[VVP] Delivering: brand=TEST Phase 2a, status=VALID, vetter=PASS, warning=`

> **If `INDETERMINATE` appears instead of `PASS`:** This is a test environment issue — the verifier's in-memory TEL revocation cache stores `UNKNOWN` from empty witness responses. The first call after a verifier restart is always authoritative. Restart the verifier container and retry.

**Result:** Brand delivered, vetter authorised. ✅

---

#### Scenario 3 — Phase 2b: VetterCert with Wrong Rights (US only)

Dial `71006` from extension **1003** (CLI: `+441923312003`).

| Header | Expected |
|--------|----------|
| `X-VVP-Status` | `VALID` |
| `X-VVP-Brand-Name` | `TEST Phase 2b` |
| `X-VVP-Vetter-Status` | `FAIL-JURISDICTION` |

FreeSWITCH log: `[VVP] Delivering: brand=TEST Phase 2b, status=VALID, vetter=FAIL-JURISDICTION, warning=`

> **Why VALID with FAIL-JURISDICTION?** The verifier config flag `ENFORCE_VETTER_CONSTRAINTS` is `False`. Vetter failures are informational — the call proceeds as VALID but the header signals the violation. A receiving application can inspect this header to display a warning or apply its own policy.

**Result:** Brand delivered, vetter constraint failure correctly signalled. ✅

---

#### Summary

| Phase | Extension | Caller TN | `X-VVP-Status` | `X-VVP-Vetter-Status` |
|-------|-----------|-----------|----------------|----------------------|
| 1 — no vetter | 1001 | +441923312001 | `VALID` | *(not set)* |
| 2a — UK vetter | 1002 | +441923312002 | `VALID` | `PASS` |
| 2b — US vetter (wrong rights) | 1003 | +441923312003 | `VALID` | `FAIL-JURISDICTION` |

---

## What you've built

```
               mock-gsma
                   │ issues VetterCerts to
         ┌─────────┼─────────────┐
         ▼         ▼             ▼
    Brand Assure  US Vetters  Deutsche Vetters
    ECC: ["44"]   ECC: ["1"]  ECC: ["44","49"]

         │              │            │ TNAlloc to each AP org
         │ Brand cred   │ Brand cred │
         ▼              ▼            │
    TEST Phase 2a  TEST Phase 2b   ├──> TEST Phase 1 (+441923312001)
         │              │           ├──> TEST Phase 2a (+441923312002)
         │         TEST Phase 1     └──> TEST Phase 2b (+441923312003)
         │         (self-issued brand)
         │
         └───────────────────────────────────────────────────┐
                                                             │
         Each AP org also has:                              │
         - Signing identity (KERI AID)                      │
         - GCD delsig → signing identity                     │
         - GCD alloc → self                                  │
         - Dossier (vetting + tnalloc + alloc + delsig)     │
         - TN Mapping (TN → dossier + signing identity)     │
                                                             │
    PBX Extension CLIs ─────────────────────────────────────┘
    1001 → +441923312001 (Phase 1)
    1002 → +441923312002 (Phase 2a)
    1003 → +441923312003 (Phase 2b)
```

---

## Login summary

| Step | Log in as | Action |
|------|-----------|--------|
| 1 | System admin | Create Brand Assure, US Vetters, Deutsche Vetters |
| 1b | mock-gsma admin | Issue VetterCerts to all three vetter orgs |
| 2 | System admin | Create TEST Phase 1, TEST Phase 2a, TEST Phase 2b |
| 3a | TEST Phase 1 admin | Issue own Brand credential (self-issued) |
| 3b | Brand Assure admin | Issue Extended Brand → TEST Phase 2a |
| 3c | US Vetters admin | Issue Extended Brand → TEST Phase 2b |
| 4 | Deutsche Vetters admin | Issue TNAlloc to each of the three AP orgs (×3) |
| 5 | Each AP org admin | Create signing identity (×3) |
| 6 | Each AP org admin | Issue GCD delsig → signing identity (×3) |
| 7 | Each AP org admin | Issue GCD alloc → self (×3) |
| 8 | Each AP org admin | Create dossier via wizard (×3) |
| 9 | Each AP org admin | Create TN mapping (×3) |
| 10 | System admin or org admin | Configure PBX (extensions + API key) and deploy |
| 11 | — (SIP phone/WebRTC) | Make loopback test calls from extensions 1001, 1002, 1003 |

---

## Navigation reference

| Nav Link | Page | Used in Steps |
|----------|------|---------------|
| Identities | `/ui/identity` — Create/manage KERI identities | Step 5 |
| Schemas | `/ui/schemas` — Browse available credential schemas | (reference) |
| Credentials | `/ui/credentials` — Issue and list credentials | Steps 3, 4, 6, 7 |
| Dossiers | `/ui/dossier` — Dossier wizard and readiness check | Step 8 |
| TN Mappings | `/ui/tn-mappings` — Map phone numbers to dossiers | Step 9 |
| PBX | `/ui/pbx` — Configure extensions, API key, deploy dialplan | Step 10 |
| Admin | `/ui/admin` — System administration | (admin only) |
| Organizations | `/organizations/ui` — Org management | Steps 1, 2 (admin only) |

---

## Verification

### In the UI

1. On the **Dossiers** page, all three dossiers should appear in the list.
2. On the **TN Mappings** page, all three mappings show the dossier, signing identity, and `Active` status.
3. Click the **Test** button on each mapping to verify the full TN lookup chain.

### Via API (optional)

```bash
# Test each org's TN lookup
curl -s -X POST -H "Content-Type: application/json" \
  "https://vvp-issuer.rcnx.io/tn/lookup" \
  -d '{"tn": "+441923312001", "api_key": "<PHASE1_API_KEY>"}' \
  | python3 -m json.tool
```

### Dossier Readiness Check

The Dossiers page includes a **Dossier Readiness** tool below the wizard:
1. Select an organisation from the dropdown.
2. Click **Check Readiness**.
3. Each edge slot shows a coloured status card:
   - **Green** (ready) — credential available
   - **Red** (missing) — required credential not found, with a "Create credential →" link
   - **Orange** (invalid) — credential present but has issues
   - **Gray** (optional) — optional credential not present
4. A summary banner shows whether the organisation is ready to create a dossier.

---

## Troubleshooting

| Problem | Cause | Fix |
|---|---|---|
| Login page shows only "Sign in with Microsoft" | OAuth is the only enabled method | Use OAuth, or ask admin to enable email/password auth |
| Can't see Organisations link in nav | Not logged in as system admin | System admin role required for org management |
| No schemas in dropdown | Org type not authorised for that schema | `regular` orgs issue Brand/TNAlloc/GCD; `vetter_authority` orgs see Extended schemas and use the dedicated Vetter page |
| "Use POST /vetter-certifications" error | Tried to issue VetterCert via Credentials page | VetterCerts must be issued from the **Vetter Certifications** page |
| Brand Owner / Delegate Identity / Allocated Org not found | AID doesn't exist in KERI Agent | Create the identity first (Step 5), or verify the AID |
| Issuer edge shows no candidates | Org has no LE credential | Re-create org (mock vLEI provisioning may have failed) |
| Dossier wizard shows 0 candidates for a slot | Credential was issued by wrong org or to wrong AID | For I2I edges (alloc, tnalloc, delsig), the credential must be issued **to** the AP org |
| "Next" button disabled in wizard Step 2 | Not all required edges selected | Expand each required edge slot and select a credential |
| TN mapping fails "already mapped" | TN already has a mapping in this org | Delete the existing mapping first, or use a different TN |
| TN mapping fails "not allocated" | TN not in any TNAlloc credential for this org | Check the TNAlloc from Step 4 contains this exact TN and `+441923311006` |
| Credential issuance returns 503 | KERI Agent is unavailable | Wait a moment and retry; check system health via Admin page |
| c_proto rejects "sip" with "Match the requested format" | Schema pattern requires `protocol: roles` format | Enter `sip: originator` or leave empty (optional field) |
| Issuer edge shows Brand/TNAlloc instead of LE | LE credential is a mock vLEI placeholder (not in KERI Agent) | Leave issuer edge empty — credential issuance works without it |
| Verifier returns `dossier_verified=INDETERMINATE` | TEL events missing — credentials issued in a previous KERI Agent session | Re-issue credentials. For the test org use `scripts/bootstrap-issuer.py --skip-reinit` |
| Verifier returns `vetter_constraints_valid=INDETERMINATE` | VetterCert not reachable from dossier root (DFS edge walk) | Ensure issuing org has an active VetterCert **before** issuing Brand/TNAlloc/GCD |
| All credentials gone after KERI Agent restart | KERI Agent LMDB is ephemeral (`/tmp`) — cleared on container restart | Re-issue credentials. The bootstrap script handles stale LE and VetterCert pointers automatically with `--skip-reinit` |
| PBX deploy fails | KERI Agent or Issuer unavailable, or Azure VM not running | Check Admin health page; verify `vvp-pbx` VM is running in Azure portal |
| Call fails with 401 "Missing API key" | API key not in PBX dialplan, or wrong key value in Step 10 | Re-enter the raw API key value in the PBX page and redeploy |
| Call fails with 403 "Invalid API key" | Key prefix doesn't match stored hash, or key was regenerated | Copy the key value exactly — no leading/trailing whitespace; regenerate if lost |
| Call completes but no VVP headers | Extension CLI not mapped, or TN mapping missing | Verify extension CLI in Step 10 matches a TN mapping from Step 9 |
| `X-VVP-Vetter-Status` not set | No VetterCert in dossier chain (Phase 1 scenario) | Expected — Phase 1 self-issued brand dossiers don't set this header |
| `X-VVP-Vetter-Status: INDETERMINATE` on second call | Verifier in-memory TEL cache stores UNKNOWN from empty witness responses | Restart the verifier container to flush the cache; first call is always authoritative |
| `X-VVP-Status: INVALID` with "No TNAlloc covers callee TN" | Caller's TNAlloc does not include the destination TN (`+441923311006`) | Re-issue TNAlloc to include both origin TN and callee TN in the `numbers` array |
| Loopback channel torn down before 302 arrives | SIP Timer B (32s) expired; signing service took >32s cold | Ensure `VVP_ISSUER_TIMEOUT=30` is set on PBX sip-redirect service; 100 Trying is sent automatically by current sip-redirect version |

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
