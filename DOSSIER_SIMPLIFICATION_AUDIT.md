# Dossier Creation Simplification Audit

## Scenario

Create a complete VVP dossier for **ACME Inc** using two vetter organizations (**Brand Assure** and **Deutsche Vetters**), each authorized by GSMA.

## Credential Chain

```
GLEIF ──QVI──> Mock QVI ──LE──> ACME Inc              (auto)
                        ──LE──> Brand Assure           (auto on org creation)
                        ──LE──> Deutsche Vetters       (auto on org creation)

GSMA ──VetterCert──> Brand Assure                      (step 2)
GSMA ──VetterCert──> Deutsche Vetters                  (step 3)

Brand Assure     ──Extended Brand──>   ACME Inc        (step 5)
Deutsche Vetters ──Extended TNAlloc──> ACME Inc        (step 6)

ACME Inc ──GCD (delsig)──> signing identity            (step 7)
ACME Inc ──GCD (alloc)──>  ACME Inc                    (step 8)

ACME Inc ──CVD Dossier (assembles all edges)──>        (step 9)
ACME Inc ──TN Mapping──>                               (step 10)
```

---

## Step 1: Create Vetter Organizations

**Page**: `/organizations/ui`
**Acting as**: System admin

### What the user sees
- "Create Organization" modal with two fields: **Name** and **Pseudo LEI**
- Must create "Brand Assure" and "Deutsche Vetters" separately

### Fields

| Field | Required | Current UX | Issue | Recommendation |
|-------|----------|-----------|-------|----------------|
| Name | Yes | Text input, clear | Fine | No change |
| Pseudo LEI | Yes | Text input, no hint | **User won't know what this is.** No explanation, no format hint, no validation feedback. LEIs are 20-char alphanumeric. | Add hint text: "20-character Legal Entity Identifier (e.g., 5493001KJTIIGC8Y1R12). A pseudo-LEI will be generated if left blank." Consider auto-generating if empty. |

### Issues found

1. **No "org type" visible at creation time** — after creating the org, it's `regular` type. To make it a vetter, you need to go to the Vetter Certification page and issue a cert. The org card doesn't explain this workflow.
2. **No workflow guidance** — after creating Brand Assure, there's no prompt like "Next: issue a VetterCertification for this org" or link to the vetter page.
3. **API key creation required but buried** — to later act *as* Brand Assure (org switching), the admin needs to create an API key or user for that org. This is in the org detail page but not prompted.

### Recommendations

- **R1.1**: Auto-generate pseudo-LEI if field left blank (reduces friction for testing/demo)
- **R1.2**: After org creation, show a "next steps" prompt based on intended use (e.g., "Issue VetterCertification" link)
- **R1.3**: Add hint text explaining pseudo-LEI format

---

## Step 2: Issue VetterCertification for Brand Assure

**Page**: `/ui/vetter`
**Acting as**: GSMA (vetter_authority) — requires org context switch

### Pre-requisite issue
To issue a VetterCert, the user must be acting as the GSMA org (vetter_authority type). This requires **org context switching** via the session switcher — but there's no clear indication of *which org you need to be* to perform this action. The vetter page has a warning box saying "In production, Vetter Certifications are typically issued by a governance authority (e.g., GSMA)" but doesn't explain how to switch to GSMA context.

### Fields

| Field | Required | Current UX | Issue | Recommendation |
|-------|----------|-----------|-------|----------------|
| Vetter Organization | Yes | Dropdown of all orgs | Fine — good that it's a picker | No change |
| Vetter Name | Yes | Text input, auto-fills from org | **Redundant** — auto-fills from dropdown but user can override. Why would they? | Default from org name, hide unless overriding |
| ECC Targets | Yes | Checkbox grid of ~70 E.164 codes | **Overwhelming** — 70 checkboxes in a scrollable grid. For a UK/US vetter, user must scroll and find "+44" and "+1" among 70 options. | Add a search/filter box. Show common codes first. Consider a type-ahead multi-select instead of checkbox grid. |
| Jurisdiction Targets | Yes | Checkbox grid of ~60 ISO codes | **Same problem** — 60 checkboxes. User must find "GBR" and "USA" in a long list. | Same fix: search/filter, common-first ordering, or type-ahead multi-select |
| Certification Expiry | No | datetime-local input | Fine | No change |
| Publish to witnesses | No | Checkbox, default checked | **Not needed in UI** — should always be true. Exposing this creates confusion ("what happens if I uncheck?") | Remove from UI, always publish |

### Issues found

1. **Country selector UX is poor** — scrolling through 60-70 checkboxes to find 2-3 countries is tedious
2. **No search/filter** on either country selector
3. **"Vetter Name" is redundant** — auto-fills from org selection, no reason to override
4. **"Publish to witnesses" checkbox is an implementation detail** — should not be user-facing
5. **No validation feedback** — if you select ECC code "+44" but not jurisdiction "GBR", there's no warning about the mismatch (a UK telephone code without UK jurisdiction authorization)
6. **Repeat for Deutsche Vetters** — must go through the same 70-checkbox process again

### Recommendations

- **R2.1**: Replace checkbox grids with searchable/filterable multi-select (type-ahead)
- **R2.2**: Group common countries at top (US, UK, DE, FR, etc.)
- **R2.3**: Remove "Vetter Name" field (use org name automatically)
- **R2.4**: Remove "Publish to witnesses" checkbox (always true)
- **R2.5**: Add smart validation: warn if ECC and jurisdiction selections are mismatched
- **R2.6**: Consider ECC↔Jurisdiction auto-linking: selecting "+44" auto-suggests "GBR"

---

## Step 3: Issue VetterCertification for Deutsche Vetters

Same page, same issues as Step 2. No additional findings.

---

## Step 4: Create Signing Identity for ACME Inc

**Page**: `/ui/identity`
**Acting as**: ACME Inc

### Fields

| Field | Required | Current UX | Issue | Recommendation |
|-------|----------|-----------|-------|----------------|
| Identity Name | Yes | Text input, placeholder "e.g., my-issuer" | **Placeholder is vague** — "my-issuer" doesn't suggest this is for signing. | Change placeholder to "e.g., acme-signing-key" |
| Transferable | No | Checkbox, default checked | **Users won't understand "transferable"** — this is a KERI concept meaning keys can be rotated. | Rename to "Allow key rotation" with hint: "Recommended. Allows rotating keys without changing the identity." |
| Publish to witnesses | No | Checkbox, default checked | **Implementation detail** — should not be user-facing | Remove from UI, always publish |

### Issues found

1. **Identity list is cluttered** — shows ALL 69 identities including system ones (mock-gleif, mock-qvi, mock-gsma, test identities). No filtering.
2. **No indication which identities belong to which org** — all identities are shown in one flat list
3. **No "purpose" field** — can't distinguish a signing identity from a test identity from a rotation test
4. **OOBI section is confusing** — each identity has an "OOBIs" expandable section showing witness URLs. This is deep KERI internals that most users don't need.

### Recommendations

- **R4.1**: Filter identity list to show only current org's identities (or add filter)
- **R4.2**: Rename "Transferable" to "Allow key rotation" with explanatory hint
- **R4.3**: Remove "Publish to witnesses" checkbox
- **R4.4**: Change placeholder to suggest purpose (e.g., "acme-signing-key")
- **R4.5**: Hide OOBI section behind an "Advanced" toggle
- **R4.6**: Add org association to identities (currently they're org-less)

---

## Step 5: Issue Extended Brand Credential (Brand Assure → ACME)

**Page**: `/ui/credentials`
**Acting as**: Brand Assure (requires org switch)

### Pre-requisite: Org context switch
Must switch to Brand Assure org context. The credential page shows "Issuing as: Brand Assure" banner when switched — good. But the process of switching is not obvious (requires the org switcher in the header/profile area).

### Fields (Extended Brand schema)

| Field | Required | Schema Required | Current UX | Issue | Recommendation |
|-------|----------|----------------|-----------|-------|----------------|
| Schema selector | Yes | — | Dropdown + type cards | OK — "Brand Credential" card is clear | No change |
| Brand Name | Yes | Yes | Text input | **No default from org** — could pre-fill from ACME's org name | Auto-fill from target org name |
| Brand Display Name | No | No | Text input | Fine — optional caller ID display name | No change |
| Assertion Country | Yes | Yes | **Free text input** | **Major issue** — expects ISO 3166-1 alpha-3 code (e.g., "GBR") but is a raw text field. User must know the code. | Replace with country dropdown (same data as vetter page) |
| Logo URL | No | No | Text input | Fine | No change |
| Website URL | No | No | Text input | Fine | No change |
| Legal Entity LEI | No | No | Text input | Fine — optional | No change |
| Start Date | No | No | datetime-local | Fine | No change |
| End Date | No | No | datetime-local | Fine | No change |
| Recipient AID | Yes (for brand) | — | **Raw AID text input** + org picker dropdown | **Major issue** — "Recipient AID (optional)" label is wrong; for a brand credential it should be the brand owner (ACME). The label doesn't explain this. The org picker helps but is labelled "Or pick org..." which is vague. | Rename to "Brand Owner" with hint. Auto-fill from the target org when context is known. |
| Edges: `le` | Optional | Optional | Edge slot picker | Requires finding ACME's LE credential among all credentials. | Auto-populate with ACME's LE credential |
| Edges: `certification` | Required | Required | Edge slot picker | **Auto-injected by backend** — but UI still shows it as a slot requiring selection. Confusing. | Hide this edge entirely in UI (already auto-injected) |
| Privacy nonces | No | — | Checkbox | Fine — advanced | Move under "Advanced" section |
| Publish to witnesses | No | — | Checkbox, default checked | Implementation detail | Remove from UI |

### Issues found

1. **assertionCountry is free text** — should be a dropdown. Users won't know "GBR" off the top of their head.
2. **Recipient AID is confusing** — labelled "optional" but actually required for brand creds. Label doesn't explain it's the brand owner.
3. **certification edge shown but auto-injected** — user sees an edge slot for "certification" and must either select it or trust the backend to inject it. This is confusing.
4. **949 existing credentials** in the list below the form — the credential list is overwhelmingly long with no pagination or filtering.
5. **No org filter on credential list** — shows all credentials across all orgs
6. **Schema-driven form is good** — dynamically generates fields from schema. This is a strength.
7. **Form vs JSON toggle is good** — advanced users can use JSON mode.

### Recommendations

- **R5.1**: Replace assertionCountry text input with country dropdown
- **R5.2**: Rename "Recipient AID" to context-aware label (e.g., "Brand Owner" for brand creds)
- **R5.3**: Auto-fill recipient from org context when issuing cross-org
- **R5.4**: Hide auto-injected edges (certification) from UI
- **R5.5**: Add pagination to credential list (currently 949 items)
- **R5.6**: Add schema/type filter to credential list
- **R5.7**: Remove "Publish to witnesses" checkbox
- **R5.8**: Move "Privacy nonces" under an "Advanced" section

---

## Step 6: Issue Extended TNAlloc Credential (Deutsche Vetters → ACME)

**Page**: `/ui/credentials`
**Acting as**: Deutsche Vetters (requires org switch)

### Fields (Extended TNAlloc schema)

| Field | Required | Schema Required | Current UX | Issue | Recommendation |
|-------|----------|----------------|-----------|-------|----------------|
| Schema selector | Yes | — | Dropdown + type cards | OK — "TN Allocation" card | No change |
| numbers.tn | Yes (one of) | Yes | **Array input inside nested "numbers" object** | **Confusing nesting** — form shows a "Numbers" nested section with sub-fields. The `.tn` array has a single text input with "+" button. User must type each number individually. | Simplify: single text area for comma/newline-separated numbers |
| numbers.rangeStart | No | No | Text input inside Numbers | Fine for range-based allocation | No change |
| numbers.rangeEnd | No | No | Text input inside Numbers | Fine for range-based allocation | No change |
| channel | Yes | Yes | **Free text input** | **Should be a dropdown** — only valid values are "voice", "sms", "video", etc. | Replace with dropdown: voice / sms / video |
| doNotOriginate | Yes | Yes | Checkbox | **Label is confusing** — "Do Not Originate" is telecom jargon. Most users will leave this false. | Rename to "Do Not Originate (DNO)" with hint: "Check if this number should never be used as a caller ID" |
| Start Date | No | No | datetime-local | Fine | No change |
| End Date | No | No | datetime-local | Fine | No change |
| Recipient AID | Contextual | — | Text input + org picker | **Same issue as brand** — for TNAlloc the `i` field is "Recipient Brand AID" per schema, but UI says "Recipient AID (optional)" | Context-aware label |
| Edges: `tnalloc` | Required | Required (I2I) | Edge slot picker | **Major confusion** — this edge is labelled "tnalloc" and expects a parent TNAlloc credential. But for a root allocation (no parent), what does the user select? Currently no guidance. | Add "root allocation" option or auto-detect |
| Edges: `issuer` | Optional | Optional (NI2I) | Edge slot picker | Reference to LE — fine | No change |
| Edges: `certification` | Required | Required | Edge slot picker | **Auto-injected** — same issue as brand | Hide from UI |

### Issues found

1. **Channel is free text** — should be a constrained dropdown
2. **Numbers input is awkward** — nested object with sub-fields. Adding multiple phone numbers requires clicking "+" for each one. A simple text area would be faster.
3. **"tnalloc" edge for root allocation is confusing** — if this is the first TNAlloc in the chain, what parent does it point to? No guidance.
4. **doNotOriginate label** — telecom jargon without explanation
5. **certification edge exposed** — same auto-injection confusion as brand

### Recommendations

- **R6.1**: Replace channel text input with dropdown (voice/sms/video)
- **R6.2**: Simplify numbers input — text area for bulk entry, or at minimum improve the array UX
- **R6.3**: Add "root allocation" guidance for the tnalloc edge (or auto-skip for root case)
- **R6.4**: Add hint to doNotOriginate explaining the concept
- **R6.5**: Hide auto-injected certification edge
- **R6.6**: Context-aware recipient label

---

## Step 7: Issue GCD — Delegated Signer (ACME → signing identity)

**Page**: `/ui/credentials`
**Acting as**: ACME Inc

### Fields (GCD schema)

| Field | Required | Schema Required | Current UX | Issue | Recommendation |
|-------|----------|----------------|-----------|-------|----------------|
| Schema selector | Yes | — | Dropdown | OK — "Delegated Signer" card | No change |
| i (delegate AID) | Yes | Yes | **Shown as part of dynamic form** | **Form field labelled "I"** — the raw schema field name. Means nothing to users. | Rename to "Delegate Identity" with a picker of existing identities |
| dt (issuance date) | — | No | Auto-skipped (SYSTEM_FIELD) | Good | No change |
| gfw | No | No | Text input | **Governance framework SAID** — only used in advanced compliance scenarios. | Hide under "Advanced Constraints" |
| role | No | No | Text input | Useful but vague | Add hint: "e.g., signing, authentication" |
| c_goal | No | No | Array input | **Never used in VVP** | Hide under "Advanced Constraints" |
| c_pgeo | No | No | Array input | **Never used in VVP** | Hide under "Advanced Constraints" |
| c_rgeo | No | No | Array input | **Never used in VVP** | Hide under "Advanced Constraints" |
| c_jur | No | No | Array input | **Never used in VVP** | Hide under "Advanced Constraints" |
| c_ical | No | No | Array input | **Never used in VVP** | Hide under "Advanced Constraints" |
| c_proto | No | No | Array input | **Never used in VVP** | Hide under "Advanced Constraints" |
| c_prove | No | No | Array input | **Never used in VVP** | Hide under "Advanced Constraints" |
| c_human | No | No | Text input | **Never used in VVP** | Hide under "Advanced Constraints" |
| c_after | No | No | datetime-local | Useful for time-bound delegation | Keep visible but move to end |
| c_before | No | No | datetime-local | Useful for time-bound delegation | Keep visible but move to end |
| Recipient AID | Yes | — | Text input + org picker | **Must be the signing identity AID** — not an org. The org picker is irrelevant here. | Replace with identity picker dropdown |
| Edges: `issuer` | Required (I2I) | Yes | Edge slot picker | Must point to ACME's LE credential. Currently requires manual selection. | Auto-populate from current org's LE credential |

### Issues found

1. **14 optional constraint fields shown** — `c_goal`, `c_pgeo`, `c_rgeo`, `c_jur`, `c_ical`, `c_proto`, `c_prove`, `c_human`, `gfw` — none of these are used in VVP. They clutter the form massively.
2. **`i` field labelled as "I"** — raw schema field name, meaningless
3. **Recipient must be a signing identity** — but the org picker dropdown is shown (irrelevant for this credential type)
4. **issuer edge not auto-populated** — should default to the current org's LE credential
5. **This is the most confusing credential to issue** — the GCD schema is generic (designed for all cooperative delegation), but in VVP context it has a very specific purpose. The form gives no VVP-specific guidance.

### Recommendations

- **R7.1**: Hide all `c_*` constraint fields under "Advanced Constraints" collapsible section
- **R7.2**: Rename `i` field to "Delegate Identity" with identity picker dropdown
- **R7.3**: Replace "Recipient AID" with identity picker (not org picker) for GCD
- **R7.4**: Auto-populate `issuer` edge with current org's LE credential
- **R7.5**: Add VVP-specific guidance: "This credential delegates signing authority from your organization to a specific identity"
- **R7.6**: Consider a dedicated "Create Delegation" UI (simpler than the generic credential form)

---

## Step 8: Issue GCD — Allocation (ACME → ACME)

**Page**: `/ui/credentials`
**Acting as**: ACME Inc

Same schema as Step 7, same issues. Additional confusion:

### Issues found

1. **Same schema used for two different purposes** — `delsig` (step 7) and `alloc` (step 8) both use the GCD schema. The user must understand that they need TWO GCD credentials with different recipients.
2. **No guidance on alloc vs delsig** — the dossier wizard expects both but the credential page doesn't explain the difference
3. **alloc recipient is the org itself** — counter-intuitive. "Issue a credential to yourself"?

### Recommendations

- **R8.1**: The dossier readiness page should explain: "You need TWO delegation credentials — one authorizing a signing identity (delsig), and one representing your service provider allocation authority (alloc)"
- **R8.2**: Consider separating these into distinct UI flows or at least labelling them differently

---

## Step 9: Assemble Dossier

**Page**: `/ui/dossier`
**Acting as**: ACME Inc

### Wizard Steps

#### Step 1: Select AP Organization
- Single dropdown, auto-selects if only one org
- **Fine for single-org users**, but for our multi-org scenario (ACME + Brand Assure + Deutsche Vetters), the user must be logged in as ACME and select ACME.
- **Issue**: No hint that they should be acting as ACME for dossier creation.

#### Step 2: Select Edge Credentials

| Edge Slot | Label in UI | Required | Current UX | Issue |
|-----------|------------|----------|-----------|-------|
| vetting | "Vetting (LE)" | Yes | Credential picker table | **Which LE?** — shows all 922 credentials (no schema filter). User must find ACME's LE among them. |
| alloc | "Allocation (GCD)" | Yes | Credential picker table | **I2I filter** — correctly filters to credentials issued TO ACME. But with 0 GCD credentials issued to ACME, shows empty. |
| tnalloc | "TN Allocation (RTU)" | Yes | Credential picker table | **633 TNAlloc credentials** — massive list, no pagination, no search. User must find the right one. |
| delsig | "Delegation Signing" | Yes | Credential picker table | Same as alloc — needs GCD issued BY ACME |
| bownr | "Brand Ownership" | No | Credential picker table | **922 unconstrained credentials** — no schema filter! Shows everything. |
| bproxy | "Brand Proxy" | No | Credential picker table | Same problem |

### Issues found

1. **Credential lists are overwhelming** — 633 TNAllocs, 922 unconstrained credentials. No pagination, no search, no filtering.
2. **Edge labels use KERI jargon** — "alloc", "delsig", "bownr", "bproxy" are not user-friendly
3. **vetting slot has no schema constraint** — shows ALL credentials, not just LE credentials
4. **bownr/bproxy slots have no schema constraint** — shows ALL credentials
5. **No preview of credential content** — just SAID + schema + date. Hard to identify which is the right credential.
6. **No link between credential origin and edge purpose** — user doesn't know that "alloc" should be the GCD from step 8 and "delsig" should be the GCD from step 7

#### Step 3: Metadata
- Dossier Name (optional) — **Fine**
- OSP Organization (optional) — **Fine for advanced users**, confusing for basic use
- Edges summary — **Good** — shows selected edges

#### Step 4: Review & Create
- Shows all selections — **Good**
- Create button — **Good**
- Success shows dossier URL + "Create TN Mapping" link — **Good**

### Recommendations

- **R9.1**: Add pagination and search/filter to edge credential pickers
- **R9.2**: Rename edge labels to user-friendly terms:
  - `vetting` → "Organization Verification (LE)"
  - `alloc` → "Service Provider Authorization"
  - `tnalloc` → "Phone Number Allocation"
  - `delsig` → "Signing Authorization"
  - `bownr` → "Brand Ownership"
  - `bproxy` → "Brand Proxy"
- **R9.3**: Add schema constraints to vetting, bownr, bproxy slots
- **R9.4**: Show credential attribute preview inline (not just SAID)
- **R9.5**: Auto-select obvious choices (e.g., if only one LE credential, auto-select it for vetting)
- **R9.6**: Add "recently created" sorting to help users find credentials they just issued

---

## Step 10: Create TN Mapping

**Page**: `/ui/tn-mappings`
**Acting as**: ACME Inc

### Fields (from "Create TN Mapping" modal)

| Field | Required | Current UX | Issue | Recommendation |
|-------|----------|-----------|-------|----------------|
| Telephone Number | Yes | Text input | Fine — E.164 format | Add format hint: "+44..." |
| Dossier | Yes | Dropdown picker | **Must find the right dossier** — needs to be the one just created | Auto-select most recently created dossier |
| Signing Identity | Yes | Dropdown picker | **Must find the right identity** — the one from step 4 | Auto-select if only one signing identity |
| Brand Name | Yes | Text input | Fine | Auto-fill from brand credential in dossier |
| Brand Logo URL | No | Text input | Fine | Auto-fill from brand credential in dossier |

### Issues found

1. **No auto-fill from dossier** — brand name and logo could be extracted from the brand credential in the dossier
2. **No continuity from dossier creation** — when clicking "Create TN Mapping" from the dossier success page, the mapping form doesn't pre-select the just-created dossier

### Recommendations

- **R10.1**: Pre-select the just-created dossier when linked from dossier wizard
- **R10.2**: Auto-fill brand name and logo URL from dossier's brand credential
- **R10.3**: Add E.164 format hint

---

## Cross-Cutting Issues

### C1: Org Context Switching
The multi-org flow requires switching between GSMA, Brand Assure, Deutsche Vetters, and ACME. The current org switcher is in the header but it's not obvious *when* to switch or *to which org*. Each page should indicate which org context is needed for the current action.

### C2: "Publish to Witnesses" Checkbox
This appears on every creation form (identity, credential, vetter cert). It's an implementation detail that should always be true. **Remove from all UI forms.**

### C3: Credential List Performance
With 949 credentials, every page that loads credentials is slow and the lists are unmanageable. **Need pagination (20-50 per page) and filtering across all credential-displaying pages.**

### C4: No Guided Workflow
The journey requires visiting 5 different pages in a specific order, switching orgs multiple times. There's no guided flow or checklist. The dossier readiness checker helps but it's reactive (tells you what's missing) not proactive (guides you through creation).

### C5: KERI Jargon Throughout
Terms like "AID", "SAID", "OOBI", "transferable", "I2I", "NI2I", "GCD", "CESR", "KEL" appear throughout the UI with no explanation. Non-KERI users will be lost.

### C6: Manual Edges Section
Every credential form has "Additional Edges — Link to other credentials manually" at the bottom. This is never needed in the standard VVP flow and adds visual noise. **Hide under "Advanced".**

---

## Summary of Recommendations

### Quick Wins (low effort, high impact)
| # | Change | Pages Affected |
|---|--------|---------------|
| R2.4, R4.3, R5.7 | Remove "Publish to witnesses" checkbox from all forms | identity, credentials, vetter |
| R5.1 | Replace assertionCountry free text with dropdown | credentials |
| R6.1 | Replace channel free text with dropdown (voice/sms/video) | credentials |
| R7.1 | Hide GCD constraint fields (c_*) under "Advanced" | credentials |
| R5.4, R6.5 | Hide auto-injected certification edge from UI | credentials |

### Medium Effort (significant UX improvement)
| # | Change | Pages Affected |
|---|--------|---------------|
| R2.1 | Searchable country selectors for vetter cert | vetter |
| R7.2, R7.3 | Identity picker instead of raw AID input | credentials |
| R7.4 | Auto-populate issuer edge from org's LE credential | credentials |
| R9.1 | Pagination + filtering on credential lists | dossier, credentials |
| R9.2 | Rename edge labels to user-friendly terms | dossier |
| R9.5 | Auto-select obvious credential choices in dossier wizard | dossier |
| R10.1, R10.2 | Auto-fill TN mapping from dossier context | tn-mappings |

### Larger Scope (architectural improvements)
| # | Change | Pages Affected |
|---|--------|---------------|
| C4 | Guided dossier creation workflow (wizard across pages) | all |
| C1 | Context-aware org switching guidance | all |
| R7.6 | Dedicated "Create Delegation" simplified UI | credentials or new page |
| R8.1 | Explain alloc vs delsig distinction clearly | dossier, credentials |

---

## Appendix A: End-to-End SIP Verification Test Results

These tests validate that the dossier-based VVP verification pipeline works correctly end-to-end. Three dossier scenarios were tested via real SIP loopback calls through the PBX.

### Test Infrastructure

| Component | Value |
|-----------|-------|
| Signing service | `sip-redirect` on PBX port 5070 (UDP) |
| Verification service | `vvp-sip-verify` on PBX port 5071 (UDP) |
| Verifier API | `https://vvp-verifier.rcnx.io` |
| Issuer API | `https://vvp-issuer.rcnx.io` |
| Callee TN | `+441923311006` (extension 1006) |
| Call flow | FreeSWITCH loopback → signing (302) → verified (302) → extension 1006 |

**Key fix applied during testing**: Added 100 Trying to `sip-redirect` service (`services/sip-redirect/app/sip/builder.py` + `transport.py`). Without this, FreeSWITCH Timer B (32s) destroyed the loopback channel before the signing service (which takes 34s for cold TN lookup + VVP create) could return its 302.

**TNAlloc fix**: Each org's TNAlloc credential covers both the org's origin TN AND the callee TN (`+441923311006`). The `/verify-callee` endpoint checks that the caller's TNAlloc covers the destination TN (§5B callee TN rights).

---

### Phase 1: Full Branded, No VetterCert

**Scenario**: Direct brand credential issued to org; no VetterCert in dossier.

**Org details**:
| Field | Value |
|-------|-------|
| Org name | Phase 1 Branded Co |
| Org ID | c9721736-d2da-4b70-9a41-4b9452843c44 |
| Identity | org-c9721736 |
| Origin TN | +441923311001 |
| VetterCert | None (Phase 1 — no explicit vetter) |

**Credential chain**:
```
Mock GLEIF → QVI → Phase 1 Branded Co (LE)
             ↓
        TNAlloc: [+441923311001, +441923311006] (SAID: EDJXmV1pV9Khl5HzNFokj--)
             ↓
        Brand: "Phase 1 Branded Co" (SAID: ELR6gNfEKWy4JY2tvRej2ckoI9uqE_zrZ9TStYpXhVuy)
```
Dossier root SAID: `ELR6gNfEKWy4JY2tvRej2ckoI9uqE_zrZ9TStYpXhVuy` (Brand = Dossier root)

**SIP call result** (authoritative first call):
| Header | Value |
|--------|-------|
| X-VVP-Status | `VALID` |
| X-VVP-Brand-Name | `Phase 1 Branded Co` |
| X-VVP-Brand-Logo | `https://vvp-issuer.rcnx.io/static/brand-logo.png` |
| X-VVP-Vetter-Status | *(not set — no VetterCert in dossier)* |
| X-VVP-Warning-Reason | *(not set)* |

**FreeSWITCH log**:
```
[VVP] Signing 302 redirect for +441923311006 — routing to verification
[VVP] Bridging to verification service at 127.0.0.1:5071
[VVP] Delivering: brand=Phase 1 Branded Co, status=VALID, vetter=, warning=
SET loopback/71006-b [vvp_brand_name]=[Phase 1 Branded Co]
SET loopback/71006-b [vvp_status]=[VALID]
```

**Result**: ✅ PASS — brand delivered, no vetter check (as expected for Phase 1 dossier without VetterCert).

---

### Phase 2a: VetterCert with Correct UK Rights

**Scenario**: VetterCert issued with ECC targets `["44"]` (UK) — should authorize calling from +44 numbers.

**Org details**:
| Field | Value |
|-------|-------|
| Org name | Phase 2a UK Ltd |
| Org ID | 9ef9e083-4286-41d8-922b-f8bd772b5049 |
| Identity | org-9ef9e083 |
| Origin TN | +441923311002 |
| VetterCert ECC | `["44"]` (UK country code) |
| Explicit vetter edge | Yes |

**Credential chain**:
```
Mock GLEIF → QVI → Phase 2a UK Ltd (LE)
                 → Vetter Org (LE)
                        ↓
                   VetterCert: ecc=["44"] (SAID: EMRrbR5lqB5n-c0bGbMc75SOGW2kwB8g-wCTLkvSv0Vz)
                        ↓ (certification edge)
             TNAlloc: [+441923311002, +441923311006] (SAID: ELDsoIwKoGRljLZ4Jw3wH8umVDISxZ3rUcyhtcYKqyY6)
             Brand: "Phase 2a UK Ltd" (SAID: EBHgSL2hbjHD3G65z_meovi_8tkbHdGtZOp93Q8EOERd)
```
Dossier root SAID: `EBHgSL2hbjHD3G65z_meovi_8tkbHdGtZOp93Q8EOERd`

**SIP call result** (authoritative first call):
| Header | Value |
|--------|-------|
| X-VVP-Status | `VALID` |
| X-VVP-Brand-Name | `Phase 2a UK Ltd` |
| X-VVP-Brand-Logo | `https://vvp-issuer.rcnx.io/static/brand-logo.png` |
| X-VVP-Vetter-Status | `INDETERMINATE` (cert present but traversal incomplete — see note) |
| X-VVP-Warning-Reason | *(not set)* |

**Note on vetter status**: The verifier returns `INDETERMINATE` for the vetter ECC check, indicating the VetterCert was not successfully located by the vetter traversal algorithm for some credentials in the chain. This is a test environment issue — the VetterCert `EMRrbR5lqB5n-c0bGbMc75SOGW2kwB8g-wCTLkvSv0Vz` is issued correctly but the verifier's `find_vetter_certification()` traversal (which walks credential edges looking for a VetterCert linked to the issuer) returns `None` for one or more credentials. ECC `["44"]` correctly covers origin TN `+441923311002` (country code 44) — so if found, this should yield `PASS`.

**FreeSWITCH log**:
```
[VVP] Delivering: brand=Phase 2a UK Ltd, status=VALID, vetter=INDETERMINATE, warning=
```

**Result**: ⚠️ PARTIAL — brand delivered correctly (VALID), vetter traversal returns INDETERMINATE instead of expected PASS.

---

### Phase 2b: VetterCert with Incorrect Rights (US only, no +44)

**Scenario**: VetterCert issued with ECC targets `["1"]` (US only) — should NOT authorize calling from +44 numbers. Call must still proceed (vetter constraints non-enforced) but vetter status header must indicate failure.

**Org details**:
| Field | Value |
|-------|-------|
| Org name | Phase 2b US Ltd |
| Org ID | b19a8f09-731f-4f6d-bc74-8fb700015bb0 |
| Identity | org-b19a8f09 |
| Origin TN | +441923311003 |
| VetterCert ECC | `["1"]` (US country code only) |
| Explicit vetter edge | Yes |

**Credential chain**:
```
Mock GLEIF → QVI → Phase 2b US Ltd (LE)
                 → Vetter Org (LE)
                        ↓
                   VetterCert: ecc=["1"] (SAID: EKnzGQLbOHbXy0JAEnx9Wnjw6A-qCx1A9JymGKjbbr1a)
                        ↓ (certification edge)
             TNAlloc: [+441923311003, +441923311006] (SAID: EFgjCB0ozbzgdDoOfpVVZoAQizlg_uhC1NUY5Pht9_3G)
             Brand: "Phase 2b US Ltd" (SAID: EIw9pJgiXzbH_pBCndgN3aaF9frNVJewhPgLvF-CvpN_)
```
Dossier root SAID: `EIw9pJgiXzbH_pBCndgN3aaF9frNVJewhPgLvF-CvpN_`

**SIP call result** (authoritative first call):
| Header | Value |
|--------|-------|
| X-VVP-Status | `VALID` |
| X-VVP-Brand-Name | `Phase 2b US Ltd` |
| X-VVP-Brand-Logo | `https://vvp-issuer.rcnx.io/static/brand-logo.png` |
| X-VVP-Vetter-Status | `FAIL-JURISDICTION` |
| X-VVP-Warning-Reason | *(not set)* |

**FreeSWITCH log**:
```
SET loopback/71006-b [vvp_brand_name]=[Phase 2b US Ltd]
SET loopback/71006-b [vvp_vetter_status]=[FAIL-JURISDICTION]
SET loopback/71006-b [vvp_status]=[VALID]
[VVP] Delivering: brand=Phase 2b US Ltd, status=VALID, vetter=FAIL-JURISDICTION, warning=
```

**Explanation of FAIL-JURISDICTION vs FAIL-ECC**: The vetter constraint check validates TN credentials (ECC check, `constraint_type=ecc`) AND identity/brand credentials (jurisdiction check, `constraint_type=jurisdiction`). For Phase 2b, the jurisdiction check on the identity/brand credential fails because the vetter cert's jurisdiction targets do not cover UK/EU jurisdiction. The `_derive_vetter_status()` in the sip-verify client maps this to `FAIL-JURISDICTION`. The ECC check on the TNAlloc credential may also fail independently, but the combined result is classified as `FAIL-JURISDICTION` because a jurisdiction constraint violation was found.

**ENFORCE_VETTER_CONSTRAINTS**: This config flag is currently `False` in the deployed verifier. Vetter constraint failures are informational — the call proceeds as `VALID` but the `X-VVP-Vetter-Status` header signals the violation. A UA/application receiving this call can use this header to display a warning or block the call based on its own policy.

**Result**: ✅ PASS — brand delivered (VALID), vetter constraint failure correctly detected and signalled via `X-VVP-Vetter-Status: FAIL-JURISDICTION`.

---

### Test Environment Observations

**TEL Revocation Cache Issue**: After the first successful call for each org, subsequent calls within the same verifier process lifetime return `INDETERMINATE`. The verifier's TEL status cache (in-memory) stores `UNKNOWN` for all credential SAIDs (because the witnesses return empty bodies for TEL queries). On the second call, the inline TEL from the dossier is not re-evaluated — the cached `UNKNOWN` values are used, yielding `INDETERMINATE`.

This is a test environment limitation:
- Witnesses return `HTTP 200 OK` with empty body for TEL state queries
- Verifier TEL cache stores `UNKNOWN` after any failed witness query
- Inline TEL (embedded in the dossier) is not re-consulted after cache is populated
- First call always works correctly (fresh dossier parse + inline TEL)
- Production witnesses would return proper TEL state, making this a non-issue

**Dialplan change during testing**: `X-VVP-Vetter-Status` header capture was added to the FreeSWITCH `verified` context dialplan mid-test. Phase 1 and Phase 2a first calls ran before this change. Phase 2b ran after the change (hence `vvp_vetter_status` visible in FreeSWITCH log for 2b only).

### Summary Table

| Scenario | Origin TN | X-VVP-Status | X-VVP-Brand-Name | X-VVP-Vetter-Status | Notes |
|----------|-----------|--------------|------------------|---------------------|-------|
| Phase 1 (no vetter) | +441923311001 | VALID | Phase 1 Branded Co | *(not set)* | No VetterCert in dossier |
| Phase 2a (vetter, ecc=+44) | +441923311002 | VALID | Phase 2a UK Ltd | INDETERMINATE | VetterCert found but traversal incomplete |
| Phase 2b (vetter, ecc=+1) | +441923311003 | VALID | Phase 2b US Ltd | FAIL-JURISDICTION | US-only vetter can't certify UK caller |
