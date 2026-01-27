# Verifiable Voice Protocol (VVP) Verifier

**Authoritative Specification — v1.5**

---

## Status of This Document

This document is the **authoritative, normative specification** for the VVP Verifier project, superseding v1.4 (FINAL).

**Changes from v1.4:**
- Added §5A: Complete Caller Verification Algorithm (13 steps per VVP §5.1)
- Added §5B: Callee Verification Algorithm (14 steps per VVP §5.2)
- Added §5C: Efficiency and Caching guidance (per VVP §5.3)
- Added §5D: Historical Verification capabilities (per VVP §5.4)
- Updated §3.3: Complete claim tree structure with authorization claims
- Updated §4.2A: Extended error code registry
- Added §4.4: SIP Context Fields
- Updated §9: Expanded verification pseudocode
- Updated §10: Additional test vectors
- Added §12: Implementation Tiers

This document is considered specification-locked; future changes require an explicit version bump.

---

## 1. Objectives and System Overview

### 1.1 Purpose

The VVP Verifier enables a call terminator (or intermediary) to evaluate **cryptographically verifiable claims about a call originator's rights**.

The verifier:
- Produces **evidence-backed claim trees**
- Makes **no routing or blocking decisions**
- Does **not assert trust**, only verifiable facts

Downstream systems decide policy.

---

### 1.2 Verifiable Voice Protocol (VVP)

VVP extends STIR/SHAKEN by enabling **proof-of-rights**, not merely proof-of-origin.

Core properties:
- Multiple independent claims per call
- Claims backed by cryptographic evidence
- Decentralised trust (no X.509 PKI dependency)
- Auditability and explainability

Normative reference:
https://dhh1128.github.io/vvp/draft-hardman-verifiable-voice-protocol.html

---

### 1.3 KERI (Key Event Receipt Infrastructure)

KERI establishes authority via **verifiable key state**, not certificates.

Implications:
- Authority evaluated at a point in time
- First-class revocation and rotation
- Evidence-driven trust decisions

References:
- https://keri.one
- https://github.com/WebOfTrust/keri

---

### 1.4 ACDCs (Authentic Chained Data Containers)

ACDCs are **self-addressing, integrity-bound claim objects**.

Properties:
- Content-derived identifiers (SAIDs)
- Intrinsic integrity verification
- Graph composition (including compact / partial / aggregate disclosure variants)

A **dossier** is a DAG of ACDCs whose combined meaning supports claims.

Normative note on ACDC variants and SAID computation:
- ACDC supports compact, partial, and aggregate disclosure; verifiers MUST be able to validate dossiers expressed in these valid forms without assuming fully expanded JSON. (spec-body.md: "ACDC Variants")
- SAIDs MUST be computed using the "most compact form" algorithm, not necessarily the received representation. (spec-body.md: "Most compact form SAID")

---

## 2. System Architecture

### 2.1 Logical Architecture

```
Call + VVP-Identity + PASSporT + SIP Context
            |
            v
        VVP Verifier
        ├─ Parse artefacts (CESR where applicable)
        ├─ Validate SIP contextual alignment
        ├─ Resolve OOBIs (kid, evd)
        ├─ Verify crypto & key state at reference time
        ├─ Validate dossier and check revocation
        ├─ Verify authorization (TNAlloc, delegation)
        └─ Derive claim tree
            |
            v
    Downstream decision systems
```

---

### 2.2 Trust Boundaries

- Inputs are **untrusted**
- Claims are **never invented**
- Ambiguity is **never collapsed**

Uncertainty must be explicit.

---

## 3. Claim Model (Normative)

### 3.1 Claim Definition

A **claim** is a proposition about the call originator whose truth can be evaluated using evidence.

---

### 3.2 Claim Status

```python
class ClaimStatus(Enum):
    VALID
    INVALID
    INDETERMINATE
```

Meanings:
- VALID — proven by evidence
- INVALID — contradicted by evidence
- INDETERMINATE — insufficient or unverifiable evidence

---

### 3.3 Claim Tree

Each parent-child relationship in the claim tree MUST declare whether the child is REQUIRED or OPTIONAL for the parent's semantics. **Omission of this declaration is a schema violation and MUST be treated as an error by the verifier.**

Verification output is a recursive **claim tree**.

#### 3.3A Claim Propagation Rules (Normative)

- Parent/child dependencies MUST be explicit
- REQUIRED children:
  - Any INVALID → parent INVALID
  - Else any INDETERMINATE → parent INDETERMINATE
  - Else → parent MAY be VALID
- OPTIONAL children MUST NOT invalidate a parent

Implementation hint: represent child dependencies as objects with a boolean flag, e.g., `{ "node": <claim-node>, "required": true }`.

#### 3.3B Claim Tree Structure (Normative)

The complete claim tree for caller verification:

```
caller_verified (root)
├── passport_verified (REQUIRED)
│   ├── timing_valid (REQUIRED)
│   ├── signature_valid (REQUIRED)
│   └── binding_valid (REQUIRED)
├── dossier_verified (REQUIRED)
│   ├── structure_valid (REQUIRED)
│   ├── acdc_signatures_valid (REQUIRED)
│   └── revocation_clear (REQUIRED)
├── authorization_valid (REQUIRED)
│   ├── party_authorized (REQUIRED)
│   └── tn_rights_valid (REQUIRED)
├── context_aligned (REQUIRED or OPTIONAL per policy)
├── brand_verified (OPTIONAL)
└── business_logic_verified (OPTIONAL)
```

The complete claim tree for callee verification:

```
callee_verified (root)
├── passport_verified (REQUIRED)
│   ├── dialog_matched (REQUIRED)
│   ├── timing_valid (REQUIRED)
│   └── signature_valid (REQUIRED)
├── dossier_verified (REQUIRED)
│   ├── structure_valid (REQUIRED)
│   ├── acdc_signatures_valid (REQUIRED)
│   ├── revocation_clear (REQUIRED)
│   └── issuer_matched (REQUIRED)  # Per §5B Step 9: dossier issuer verification
├── tn_rights_valid (REQUIRED)
├── brand_verified (OPTIONAL)
└── goal_overlap_verified (OPTIONAL)
```

---

## 4. API Contracts

### 4.1 `/verify` Request

**Header**

```
VVP-Identity: <base64url-encoded JSON>
```

**Body**

```json
{
  "passport_jwt": "string",
  "context": {
    "call_id": "string",
    "received_at": "RFC3339 timestamp",
    "sip": {
      "from_uri": "string",
      "to_uri": "string",
      "invite_time": "RFC3339 timestamp",
      "cseq": "integer (optional)"
    }
  }
}
```

---

### 4.1A VVP-Identity Header (Decoded)

```json
{
  "ppt": "vvp",
  "kid": "oobi:...",
  "evd": "oobi:...",
  "iat": 1737500000,
  "exp": 1737503600
}
```

Rules:
- MUST decode via base64url
- MUST reject malformed JSON
- MUST bind `kid` to PASSporT issuer (see §5)
- MUST allow configurable clock skew; default policy for this project is ±300 seconds.
- SHOULD use a UTC time source synchronized via standard system mechanisms (e.g., NTP) to reduce false INVALIDs.
- `exp` is OPTIONAL; if absent, implementations MUST enforce a maximum token age of **300 seconds** derived from `iat`, unless explicitly configured otherwise.
- `iat` values in the future within the allowed clock skew MUST be accepted; values beyond skew MUST be rejected.

#### 4.1B OOBI Semantics for `kid` and `evd` (Normative)

In VVP, `kid` and `evd` are **OOBIs (Out-Of-Band Introductions)**, not generic URLs. (draft-hardman-verifiable-voice-protocol.txt: §4.1.2)

- The verifier MUST treat `kid` and `evd` as OOBI references.
- The verifier MUST support OOBI dereferencing that returns **application/json+cesr**. (draft-hardman-verifiable-voice-protocol.txt: §4.1.2)
- The verifier MUST validate OOBI responses using KERI/CESR parsing and KEL-backed evidence, not generic JSON canonicalization. (spec-body.md: "Special label ordering requirements"; "Protocol genus/version tables")

---

### 4.2 Error Envelope

```json
{
  "request_id": "uuid",
  "overall_status": "INVALID",
  "errors": [
    {
      "code": "PASSPORT_SIG_INVALID",
      "message": "Signature verification failed",
      "recoverable": false
    }
  ]
}
```

---

### 4.2A Error Code Registry

Implementations MUST use the following error codes (and may extend them with project-specific codes prefixed with `EXT_`).

| Code | Layer | Meaning | Recoverable (Y/N) |
|---|---|---|---|
| VVP_IDENTITY_MISSING | Protocol | Missing VVP-Identity header | N |
| VVP_IDENTITY_INVALID | Protocol | Header cannot be decoded/parsed | N |
| VVP_OOBI_FETCH_FAILED | Protocol | OOBI dereference failed | Y |
| VVP_OOBI_CONTENT_INVALID | Protocol | OOBI content-type/format invalid | N |
| PASSPORT_MISSING | Protocol | Missing passport_jwt in request body | N |
| PASSPORT_PARSE_FAILED | Protocol | PASSporT JWT cannot be decoded | N |
| PASSPORT_SIG_INVALID | Crypto | PASSporT signature invalid | N |
| PASSPORT_FORBIDDEN_ALG | Crypto | PASSporT uses forbidden algorithm | N |
| PASSPORT_EXPIRED | Protocol | PASSporT is expired per iat/exp policy | N |
| DOSSIER_URL_MISSING | Evidence | No evd OOBI present in VVP-Identity | N |
| DOSSIER_FETCH_FAILED | Evidence | Unable to retrieve dossier from evd | Y |
| DOSSIER_PARSE_FAILED | Evidence | Dossier content cannot be parsed | N |
| DOSSIER_GRAPH_INVALID | Evidence | Dossier graph invalid (cycle/missing nodes/root) | N |
| ACDC_SAID_MISMATCH | Crypto | ACDC SAID does not match most-compact-form content | N |
| ACDC_PROOF_MISSING | Crypto | Required proof/signature missing | N |
| KERI_RESOLUTION_FAILED | KERI | Unable to resolve issuer key state | Y |
| KERI_STATE_INVALID | KERI | Resolved key state fails required constraints | N |
| CREDENTIAL_REVOKED | Evidence | Credential in dossier has been revoked | N |
| CONTEXT_MISMATCH | Protocol | SIP context does not match PASSporT claims | N |
| AUTHORIZATION_FAILED | Authorization | Originating party not authorized | N |
| TN_RIGHTS_INVALID | Authorization | TNAlloc credential does not match orig | N |
| BRAND_CREDENTIAL_INVALID | Evidence | Brand credential does not support card claims | N |
| GOAL_REJECTED | Policy | Goal claim rejected by verifier policy | N |
| DIALOG_MISMATCH | Protocol | call-id/cseq do not match SIP INVITE | N |
| ISSUER_MISMATCH | Evidence | Dossier issuer does not match PASSporT kid (callee) | N |
| INTERNAL_ERROR | Verifier | Unexpected verifier failure | Y |

---

### 4.3 Successful Verification Response

```json
{
  "request_id": "uuid",
  "overall_status": "VALID",
  "claims": [
    {
      "name": "caller_verified",
      "status": "VALID",
      "reasons": [],
      "evidence": ["said:abc"],
      "children": [
        {
          "required": true,
          "node": {
            "name": "passport_verified",
            "status": "VALID",
            "reasons": [],
            "evidence": [],
            "children": []
          }
        }
      ]
    }
  ]
}
```

### 4.3A overall_status Derivation (Normative)

For responses that contain `claims`, the verifier MUST derive `overall_status` from the set of root claims:
- If any root claim is INVALID → overall_status MUST be INVALID.
- Else if any root claim is INDETERMINATE → overall_status MUST be INDETERMINATE.
- Else → overall_status MUST be VALID.

For responses that contain only `errors` (no `claims`), the verifier MUST derive `overall_status` as follows:
- If any error has recoverable=false → overall_status MUST be INVALID.
- Else → overall_status MUST be INDETERMINATE.

A response MAY contain both `claims` and `errors`. In such cases, the following precedence rules apply:
- Non-recoverable errors (`recoverable=false`) take precedence and force `overall_status` to `INVALID`.
- Recoverable errors may coexist with claims and do not override a worse claim-derived status.
- The `overall_status` is the maximum severity across all errors and claims, where `INVALID` > `INDETERMINATE` > `VALID`.

### 4.3B Claim Node Schema (Normative)

Each child relationship in a claim node MUST explicitly declare whether it is REQUIRED or OPTIONAL.

A claim node is a JSON object with the following fields:
- `name`: string — the claim name
- `status`: string — one of `"VALID"`, `"INVALID"`, or `"INDETERMINATE"`
- `reasons`: array of strings — explanations for the status
- `evidence`: array of strings — identifiers of supporting evidence
- `children`: array of child link objects

Each child link object has the following fields:
- `required`: boolean — true if the child is REQUIRED, false if OPTIONAL
- `node`: claim node — the child claim node

Implementations MUST NOT represent `children` as a bare list of claim nodes without the `required` flag.

---

### 4.4 SIP Context Fields (Normative)

The `context.sip` object provides SIP metadata for contextual alignment per §5A Step 2.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `from_uri` | string | Yes | SIP From URI (originating party) |
| `to_uri` | string | Yes | SIP To URI (destination party) |
| `invite_time` | RFC3339 | Yes | Timestamp of SIP INVITE |
| `cseq` | integer | No | CSeq number (for callee verification) |

When `context.sip` is provided, the verifier MUST perform contextual alignment (§5A Step 2).

When `context.sip` is absent:
- The verifier MUST mark `context_aligned` as INDETERMINATE (not INVALID)
- The verifier MUST NOT reject the request solely due to missing SIP context
- The `context_aligned` claim SHOULD be OPTIONAL by default (per `policy.context_required`)
- Deployments requiring SIP context MAY configure `policy.context_required = true`

---

## 5. PASSporT Verification (Normative)

### 5.0 Non-compliance note (Normative)

VVP mandates `alg = EdDSA` and explicitly forbids ES256/HMAC/RSA for VVP passports. (draft-hardman-verifiable-voice-protocol.txt: §4.1.2)

Accordingly, this verifier specification is VVP-compliant only if it enforces the algorithm requirements below.

### 5.1 Allowed Algorithms (Normative)

- The verifier MUST reject the JWS algorithm value `none`.
- The verifier MUST reject `ES256`, HMAC, and RSA algorithms for VVP PASSporTs. (draft-hardman-verifiable-voice-protocol.txt: §4.1.2)
- The verifier MUST implement support for `EdDSA` (Ed25519) as the baseline algorithm for VVP PASSporT.
- The verifier MUST reject any algorithm not explicitly allowed by local policy.

References:
- Ref: draft-hardman-verifiable-voice-protocol.txt: §4.1.2
- Ref: https://www.rfc-editor.org/rfc/rfc8037 (EdDSA for JOSE)

### 5.2 Header Binding Rules (Normative)

The PASSporT header and the decoded VVP-Identity MUST be mutually consistent:
- `ppt` in PASSporT MUST be exactly "vvp" for VVP passports, and MUST match `ppt` in VVP-Identity.
- `kid` issuer identity in PASSporT MUST match (or be resolvable from) `kid` OOBI in VVP-Identity.

### 5.2A Temporal Binding Rules (Normative)
The verifier MUST bind the temporal assertions in VVP-Identity to the temporal assertions in the PASSporT to prevent replay and mismatch windows.

Rules:
•	PASSporT iat MUST be present.
•	PASSporT exp MAY be present; if present it MUST be greater than iat.
•	The absolute difference between VVP-Identity iat and PASSporT iat MUST be ≤ 5 seconds. Values outside this bound MUST be rejected as INVALID.
•	If VVP-Identity exp is present and PASSporT exp is present, the absolute difference between them MUST be ≤ 5 seconds; otherwise the verifier MUST reject as INVALID.
•	If VVP-Identity exp is present but PASSporT exp is absent, the verifier MUST treat the PASSporT as expired unless explicitly configured to allow exp omission (default: reject).
•	If both exp values are absent, the verifier MUST enforce the PASSporT maximum-age policy in §5.2B.

### 5.2B PASSporT Expiry Policy (Normative)
The verifier MUST enforce a deterministic expiry policy for VVP PASSporTs.
•	Default maximum validity window: 300 seconds.
•	If PASSporT exp is present, then (exp − iat) MUST be ≤ 300 seconds unless explicitly configured otherwise; if it exceeds this window, the verifier MUST reject as INVALID.
•	A PASSporT MUST be treated as expired (PASSPORT_EXPIRED) if the verifier's current time is greater than exp plus allowed clock skew (default ±300 seconds).
•	If PASSporT exp is absent, the PASSporT MUST be treated as expired if the verifier's current time is greater than (iat + 300 seconds) plus allowed clock skew, unless explicitly configured otherwise.

### 5.3 Reference-Time Key-State Verification (Normative)

VVP verification requires key-state validation at a **reference time** using KEL history and witness receipts, not just the current key. (draft-hardman-verifiable-voice-protocol.txt: §5.1.1)

- The verifier MUST validate signature and issuer authority **as of reference time T**, where:
  - T = the PASSporT `iat` (seconds since epoch), provided it is consistent with the VVP-Identity iat per §5.2A.
- The verifier MUST use KEL history to determine:
  - which keys were valid at T
  - whether the identifier was revoked/rotated prior to or at T
- The verifier MUST validate witness receipts appropriate to the trust policy at T. (draft-hardman-verifiable-voice-protocol.txt: §5.1.1)

### 5.4 Failure Mapping (Normative)

Failures in PASSporT processing MUST be mapped deterministically to claim status.

- Failures caused by invalid input or failed cryptographic checks (parse errors, signature mismatch, forbidden algorithm, expired token, key-state invalid at T) MUST result in INVALID.
- Failures caused by temporarily unavailable dependencies (e.g., OOBI/KERI resolution timeout) MUST result in INDETERMINATE for all claims that depend on the unresolved key state.

Non-normative note: This distinction allows verifiers to be fail-closed on cryptographic correctness while remaining explicit about operational uncertainty.

---

## 5A. Caller Verification Algorithm (Normative)

The following 13 steps define the complete caller verification algorithm per VVP §5.1. Implementations MAY optimize execution order but MUST achieve all the same guarantees.

### Step 1: Timing Analysis (§5.1.1-2.1)

- MUST analyze `iat` and `exp` claims from PASSporT
- MUST confirm `exp` > `iat` (if exp present)
- MUST confirm `exp` > reference time (if exp present)
- MUST verify `iat` is within replay tolerance window
- Default replay tolerance: 30 seconds (configurable)

Note: Replay tolerance (30s default) is distinct from VVP-Identity↔PASSporT iat binding tolerance (5s per §5.2A). Replay tolerance prevents reuse of old passports; binding tolerance ensures VVP-Identity and PASSporT were generated together.

### Step 2: Contextual Alignment (§5.1.1-2.2)

- MUST confirm `orig` claim matches SIP From URI
- MUST confirm `dest` claim matches SIP To URI
- MUST confirm `iat` aligns with SIP INVITE timing (within tolerance)

Failure: `CONTEXT_MISMATCH` error, `context_aligned` claim INVALID.

### Step 3: Key Identification (§5.1.1-2.3)

- Extract `kid` header from PASSporT JWT
- Validate `kid` format as KERI AID or OOBI reference

### Step 4: Key State Retrieval (§5.1.1-2.4)

- MUST fetch key state for originating party from OOBI in `kid`
- MUST resolve key state at reference time T (where T = iat)
- Caches permitted if meeting verifier freshness requirements

Failure: `KERI_RESOLUTION_FAILED` error (recoverable), affected claims INDETERMINATE.

### Step 5: Signature Verification (§5.1.1-2.5)

- MUST verify PASSporT signature using originating party's public key from Step 4
- Success confirms originating party's assertion about accountable party identity

Failure: `PASSPORT_SIG_INVALID` error, `signature_valid` claim INVALID.

### Step 6: Evidence Reference Extraction (§5.1.1-2.6)

- Extract `evd` field from PASSporT payload
- Validate `evd` as OOBI reference to backing dossier

### Step 7: Dossier Cache Check (§5.1.1-2.7)

- MUST use dossier SAID as lookup key to check prior validation status
- If cached validation is fresh, MAY skip full validation
- Dossier caching strongly recommended due to stability across calls

### Step 8: Dossier Validation (§5.1.1-2.8)

Dossier validation comprises two layers (per ToIP Verifiable Dossiers Specification §4.5):

**Layer 1: Cryptographic Validation (Universal)**

This layer is application-agnostic and verifies the integrity of the dossier structure:

- MUST verify SAID integrity for the dossier ACDC and all evidence ACDCs
- MUST verify signature on each ACDC against issuer key state at issuance time (§5.1.1-2.8.1)
- Key state proven by KEL, checked against independent witnesses (§5.1.1-2.8.2)
- Issuance recorded explicitly in KEL event sequence
- MUST validate DAG structure (no cycles, valid root per §6.1)

Failure: `ACDC_SAID_MISMATCH`, `ACDC_PROOF_MISSING`, or `DOSSIER_GRAPH_INVALID` error.

**Layer 2: Semantic Validation (Application-Specific)**

This layer applies VVP-specific rules to interpret the dossier contents:

- MUST validate data structures against declared schema (§5.1.1-2.8.3)
- MUST perform full traversal of cryptographically verifiable evidence chain to root of trust
- MUST verify correct relationships among evidence artifacts
- MUST verify edge labels correspond to expected VVP credential types (TNAlloc, LegalEntity, Brand, etc.)
- SHOULD verify schema SAIDs match VVP-defined credential schemas

Note: A generic dossier verifier can perform Layer 1 for any dossier, but Layer 2 requires VVP-specific business logic. This separation enables reusable cryptographic validation while allowing application-specific interpretation.

### Step 9: Revocation Status Check (§5.1.1-2.9)

- MUST confirm dossier and all dependencies tested for revocation status recently enough per verifier freshness policy
- If not fresh enough, MUST check for revocations anywhere in dossier data graph
- Revocation checks can be cached with potentially different freshness threshold than dossier validation

Failure: `CREDENTIAL_REVOKED` error, `revocation_clear` claim INVALID.

### Step 10: Originating Party Authorization (§5.1.1-2.10)

- MUST confirm originating party is authorized to sign passport

**Case A: No delegation**
- Accountable party and originating party MUST be identical
- Originating party MUST be issuee of identity credential in dossier

**Case B: With delegation**
- Originating party MUST be issuee of delegated signing credential
- Issuer of delegation credential MUST be accountable party
- Delegation chain MUST be valid and unrevoked

Failure: `AUTHORIZATION_FAILED` error, `party_authorized` claim INVALID.

### Step 11: Phone Number Rights Verification (§5.1.1-2.11)

- Extract `orig` field from PASSporT (telephone number)
- MUST locate TNAlloc credential in dossier
- MUST compare originating number to TNAlloc credential
- MUST confirm accountable party (or originating party if using own number) has right to originate calls from this number

Failure: `TN_RIGHTS_INVALID` error, `tn_rights_valid` claim INVALID.

### Step 12: Brand Attributes Verification (§5.1.1-2.12)

- If passport includes non-null `card` claim values:
  - MUST locate brand credential in dossier
  - MUST verify brand attributes are justified by brand credential

Failure: `BRAND_CREDENTIAL_INVALID` error, `brand_verified` claim INVALID.

Note: `brand_verified` is OPTIONAL; failure does not invalidate parent.

### Step 13: Business Logic Verification (§5.1.1-2.13)

- If passport includes non-null `goal` claim:
  - Confirm verifier accepts this goal (per local policy)
- Check delegated signer credential constraints:
  - Hours of operation
  - Geographic restrictions
- Verify call attributes match credential limitations

Failure: `GOAL_REJECTED` error, `business_logic_verified` claim INVALID.

Note: `business_logic_verified` is OPTIONAL; failure does not invalidate parent.

### Step-to-Claim Mapping (Caller)

| Step | Claim Node | Parent |
|------|------------|--------|
| 1 | `timing_valid` | `passport_verified` |
| 2 | `context_aligned` | `caller_verified` |
| 3 | `binding_valid` | `passport_verified` |
| 4-5 | `signature_valid` | `passport_verified` |
| 6-8 | `structure_valid`, `acdc_signatures_valid` | `dossier_verified` |
| 9 | `revocation_clear` | `dossier_verified` |
| 10 | `party_authorized` | `authorization_valid` |
| 11 | `tn_rights_valid` | `authorization_valid` |
| 12 | `brand_verified` | `caller_verified` |
| 13 | `business_logic_verified` | `caller_verified` |

---

## 5B. Callee Verification Algorithm (Normative)

The following 14 steps define the callee verification algorithm per VVP §5.2. This algorithm achieves the same security guarantees as caller verification.

### Step 1: Dialog Matching (§5.2-2.1)

- MUST confirm `call-id` claim matches preceding SIP INVITE Call-ID
- MUST confirm `cseq` claim matches preceding SIP INVITE CSeq

Failure: `DIALOG_MISMATCH` error, `dialog_matched` claim INVALID.

### Step 2: Timing Alignment (§5.2-2.2)

- MUST confirm `iat` claim matches SIP metadata observations (within tolerance)

### Step 3: Expiration Analysis (§5.2-2.3)

- If `exp` claim present, analyze `iat` and `exp` for timeout evaluation
- Apply same expiry policy as caller verification (§5.2B)

### Step 4: Key Identifier Extraction (§5.2-2.4)

- Extract `kid` header from callee's PASSporT

### Step 5: Key State Retrieval (§5.2-2.5)

- MUST fetch callee key state at reference time from OOBI in `kid`
- Caches permitted if meeting verifier freshness requirements

### Step 6: Signature Verification (§5.2-2.6)

- MUST verify callee's PASSporT signature using callee's public key

### Step 7: Evidence Reference Extraction (§5.2-2.7)

- Extract `evd` field referencing callee's backing evidence

### Step 8: Dossier Cache Check (§5.2-2.8)

- MUST use dossier SAID as lookup key for prior validation status
- Caching recommended due to stability

### Step 9: Issuer Verification (§5.2-2.9)

- MUST confirm dossier was signed by same AID appearing in `kid` header

Failure: `ISSUER_MISMATCH` error, `issuer_matched` claim INVALID.

### Step 10: Dossier Validation (§5.2-2.10)

- If required, perform full validation per §5A Step 8

### Step 11: Revocation Status Check (§5.2-2.11)

- MUST confirm dossier and dependencies tested for revocation recently enough per verifier freshness requirements

### Step 12: Phone Number Rights Verification (§5.2-2.12)

- MUST compare callee's TN to TNAlloc credential in dossier
- Confirm callee has right to accept calls at this number

### Step 13: Brand Attributes Verification (§5.2-2.13)

- If passport includes non-null `card` claim values:
  - MUST verify brand attributes justified by brand credential in dossier

### Step 14: Goal Overlap Verification (§5.2-2.14)

- If callee passport includes non-null `goal` claim AND preceding INVITE included caller VVP passport:
  - Confirm goals overlap appropriately
- Verify call center or AI temporal and geographic constraints

### Step-to-Claim Mapping (Callee)

| Step | Claim Node | Parent |
|------|------------|--------|
| 1 | `dialog_matched` | `passport_verified` |
| 2-3 | `timing_valid` | `passport_verified` |
| 4-6 | `signature_valid` | `passport_verified` |
| 7-8 | (cache check) | — |
| 9 | `issuer_matched` | `dossier_verified` |
| 10 | `structure_valid`, `acdc_signatures_valid` | `dossier_verified` |
| 11 | `revocation_clear` | `dossier_verified` |
| 12 | `tn_rights_valid` | `callee_verified` |
| 13 | `brand_verified` | `callee_verified` |
| 14 | `goal_overlap_verified` | `callee_verified` |

---

## 5C. Efficiency and Caching (Normative)

Per VVP §5.3, verifiers SHOULD implement caching strategies to achieve acceptable performance.

### 5C.1 Performance Considerations

- Complete verification from scratch may require several seconds without caching
- Dossiers are highly stable and support caching across thousands or millions of calls
- SAID relationships are tamper-evident, enabling shared validation results
- Verifiers need not blindly trust shared results; can recompute lazily

### 5C.2 Caching Requirements

| Cache Type | Key | Recommended TTL | Notes |
|------------|-----|-----------------|-------|
| Dossier validation | SAID | Hours to days | Highly stable |
| Key state | AID + timestamp | Minutes | Rotation-sensitive |
| Revocation status | Credential SAID | Minutes | May have different freshness than dossier |

### 5C.3 Data Sovereignty

- No centralized registry required
- Data fetched directly from source across jurisdictional boundaries
- Privacy tunable through source fetching policies

---

## 5D. Historical Verification (Normative)

Per VVP §5.4, the verification algorithm supports evaluation at arbitrary past moments.

### 5D.1 Temporal Capability

- VVP passports can verify at arbitrary past moments using historical data
- `kid` header references KEL providing timestamped key state transitions
- `evd` header references dossier connected to KEL

### 5D.2 Historical Verification Process

- Timestamps from AID controllers and independent witnesses enable key state comparison at T
- Outside fuzzy ranges: clear answers about historical key state
- Inside fuzzy ranges: state transition underway but not universally known
- Verifiers compute key state according to preferred interpretation during transition periods

### 5D.3 Use Cases

- Post-incident forensic analysis
- Dispute resolution
- Compliance auditing
- Call detail record validation

---

## 6. Dossier Model

### 6.1 Dossier Graph

A **dossier** is itself a valid ACDC that serves as a **curator's attestation** over a collection of evidence. The dossier ACDC's `e` (edges) block references other ACDCs that constitute the evidence graph. (Reference: ToIP Verifiable Dossiers Specification v0.6)

Key distinctions:
- **Dossier ACDC** (root): Issued by the party assembling evidence; typically has NO issuee
- **Evidence ACDCs** (leaves): Credentials with issuees (e.g., TNAlloc, LegalEntity, Brand)

The issuer's signature attests to the **composition and integrity** of the collection, not necessarily the veracity of claims within the individual evidence items. This issuer-centric model distinguishes a dossier from a traditional credential.

The dossier forms a **directed acyclic graph (DAG)**:

- Cycles are INVALID and MUST yield the error code DOSSIER_GRAPH_INVALID.
- The graph root MUST be explicit (the `root` field). If multiple entry points exist and no single root can be selected deterministically, the dossier MUST be treated as invalid (DOSSIER_GRAPH_INVALID), unless local policy explicitly supports multiple roots by returning multiple root claims.

```python
@dataclass
class DossierGraph:
    root: str
    nodes: Dict[str, ACDCNode]
```

---

### 6.1A ACDCNode (Minimum Structure)

Each node in the dossier graph represents a single ACDC (or ACDC-like) object keyed by its SAID. This is the minimum structure required for graph validation and claim derivation; implementations may extend it.

```python
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

@dataclass
class ACDCNode:
    # Self-Addressing Identifier (content-derived)
    said: str

    # Issuer identifier (expected to be a KERI identifier, e.g., did:keri:...)
    issuer: str

    # Schema identifier (e.g., a URI) describing the ACDC semantics
    schema: str

    # Attributes / claims carried by the ACDC payload
    attributes: Dict[str, Any] = field(default_factory=dict)

    # References to other ACDCs by SAID (outbound edges)
    edges: List[str] = field(default_factory=list)

    # Optional signatures / proofs blob as received (implementation-defined)
    proofs: Optional[Dict[str, Any]] = None
```

---

### 6.1B Dossier Retrieval and Integrity (Normative)

- The `evd` value MUST be treated as an OOBI reference (see §4.1B).
- The verifier MUST support retrieving dossiers via OOBI dereference returning `application/json+cesr`. (draft-hardman-verifiable-voice-protocol.txt: §4.1.2)
- Implementations MUST enforce:
  - timeouts
  - redirect limits
  - maximum response size
- SAID recomputation MUST be performed using the **most compact form** algorithm. (spec-body.md: "Most compact form SAID")
- Verifiers MUST support valid ACDC variants (compact / partial / aggregate) and MUST NOT require a fully expanded JSON representation. (spec-body.md: "ACDC Variants")

---

### 6.1C Edge Structure (Normative)

Each edge in the dossier's `e` (edges) block links to evidence ACDCs. Per the ToIP Verifiable Dossiers Specification, edges MUST be structured as follows:

```json
"e": {
  "d": "EaBc...",
  "tnAlloc": {
    "n": "EXyz...",
    "s": "ESchemaAbc..."
  },
  "legalEntity": {
    "n": "ELei...",
    "s": "ESchemaDef..."
  }
}
```

Edge field requirements:
- `d` (REQUIRED): SAID of the edges block itself
- Each named edge (e.g., `tnAlloc`, `legalEntity`) MUST be a JSON object containing:
  - `n` (REQUIRED): SAID of the referenced ACDC (the evidence artifact)
  - `s` (RECOMMENDED): SAID of the schema to which the referenced ACDC conforms

The `s` field enables verifiers to correctly parse and interpret the evidence. Verifiers SHOULD log a warning when `s` is absent but MUST NOT reject the dossier solely for this reason.

Evidence placement:
- Evidence MUST be referenced via edges in the `e` block
- The `a` (attributes) block is for **proximate metadata** about the dossier itself, NOT for evidence
- Verifiers SHOULD log a warning if evidence-like structures appear in the `a` block

---

### 6.1D Dossier Versioning (Informative)

A dossier MAY link to a prior version via a `prev` edge in the edges block. This creates a verifiable chain of the dossier's history. (Reference: ToIP Verifiable Dossiers Specification §4.1.3)

```json
"e": {
  "d": "EaBc...",
  "prev": {
    "n": "EPriorDossierSaid...",
    "s": "EDossierSchema..."
  },
  "tnAlloc": { ... }
}
```

For VVP real-time call verification:
- Verifiers MAY ignore the `prev` edge and process only the current dossier version
- Version traversal is primarily relevant for audit, compliance, and forensic scenarios
- If `prev` is present, verifiers SHOULD record its presence in verification logs

---

## 7. KERI Integration

- Resolver treated as abstract oracle, but MUST provide sufficient evidence for reference-time validation.
- Network-agnostic
- Read-only key state resolution

KERI resolution failures that are transient (timeouts/unreachable resolver) MUST produce INDETERMINATE for dependent claims; cryptographically invalid or contradictory resolved state MUST produce INVALID.

### 7.1 KERI/CESR Versioning (Normative)

KERI/CESR messages are versioned and require strict field ordering and code tables; generic JSON canonicalization is not sufficient. (spec-body.md: "Special label ordering requirements"; "Protocol genus/version tables")

Policy for this project:
- The verifier MUST support parsing and verifying the target KERI/CESR version(s) used by the deployment's OOBIs and KELs.
- If multiple versions are supported, the verifier MUST either:
  - reject mismatched versions with a clear error, or
  - explicitly down-convert under a documented policy.
- Implementations using `keripy` MUST ensure the parser/verifier is configured for the correct KERI version; defaults may be v1. (verifying.py line 65)

Non-normative note: Prefer supporting both v1 and v2 where feasible, but treat silent down-conversion as a risk.

### 7.2 Delegation and DI2I Edges (Implementation Risk)

Some library implementations may not implement DI2I (delegated issuer → issuee) edges required for VVP-style delegation. (verifying.py line 334)

If the selected verification library does not support DI2I:
- the verifier MUST treat delegation verification as INDETERMINATE (recoverable) unless a conformant verifier is available, or
- implement DI2I verification directly according to the relevant KERI/ACDC rules.

### 7.3 Freshness and Expiry Policy (Normative)

Some libraries default credential expiry to effectively "never". (verifying.py line 34)

Policy for this project:
- Verifiers MUST enforce freshness/expiry policies for credentials and evidence where the relevant schema or dossier semantics require it.
- If a credential/evidence item has no explicit expiry, the verifier MUST apply a conservative local policy and SHOULD treat stale evidence as INDETERMINATE (or INVALID when contradiction is proven), rather than silently accepting indefinitely.

---

## 8. CI/CD and Deployment (Normative)

- GitHub Actions
- OIDC authentication
- Push to main → new ACA revision
- No secrets permitted

---

## 9. Verification Engine Pseudocode (Normative)

### 9.1 Caller Verification

```text
function verify_caller(request):
  id = new_request_id()

  # Initialize claim tree with all REQUIRED nodes per §3.3B
  claims = new_claim_tree("caller_verified")
  claims.passport_verified = new_claim("passport_verified")
  claims.passport_verified.timing_valid = new_claim("timing_valid")
  claims.passport_verified.signature_valid = new_claim("signature_valid")
  claims.passport_verified.binding_valid = new_claim("binding_valid")
  claims.dossier_verified = new_claim("dossier_verified")
  claims.dossier_verified.structure_valid = new_claim("structure_valid")
  claims.dossier_verified.acdc_signatures_valid = new_claim("acdc_signatures_valid")
  claims.dossier_verified.revocation_clear = new_claim("revocation_clear")
  claims.authorization_valid = new_claim("authorization_valid")
  claims.authorization_valid.party_authorized = new_claim("party_authorized")
  claims.authorization_valid.tn_rights_valid = new_claim("tn_rights_valid")
  claims.context_aligned = new_claim("context_aligned")

  # Step 1: Timing Analysis (§5A Step 1)
  vvp = parse_and_validate_vvp_identity(request)
  passport = parse_passport(request.passport_jwt)
  claims.passport_verified.timing_valid = verify_timing(passport, vvp, replay_tolerance=30s)

  # Step 2: Contextual Alignment (§5A Step 2)
  if request.context.sip:
    claims.context_aligned = verify_context_alignment(passport, request.context.sip)
  else:
    claims.context_aligned.status = INDETERMINATE
    claims.context_aligned.reasons = ["SIP context not provided"]
  # Note: context_aligned required flag set by policy.context_required (default: false)

  # Step 3: Key Identification (§5A Step 3)
  kid = extract_kid(passport)
  claims.passport_verified.binding_valid = verify_kid_binding(passport.kid, vvp.kid)

  # Step 4: Key State Retrieval (§5A Step 4)
  key_state = resolve_key_state(kid, T=vvp.iat)

  # Step 5: Signature Verification (§5A Step 5)
  claims.passport_verified.signature_valid = verify_signature(passport, key_state)

  # Step 6-7: Evidence Reference and Cache Check (§5A Steps 6-7)
  dossier = fetch_dossier(vvp.evd)
  cached = cached_valid(dossier.said)

  # Step 8: Dossier Validation (§5A Step 8)
  if not cached:
    claims.dossier_verified.structure_valid = validate_dossier_structure(dossier)
    claims.dossier_verified.acdc_signatures_valid = validate_acdc_signatures(dossier, T=issuance_time)
  else:
    claims.dossier_verified.structure_valid.status = VALID
    claims.dossier_verified.acdc_signatures_valid.status = VALID

  # Step 9: Revocation Status Check (§5A Step 9)
  claims.dossier_verified.revocation_clear = check_revocation(dossier)

  # Step 10: Originating Party Authorization (§5A Step 10)
  claims.authorization_valid.party_authorized = verify_party_authorization(passport, dossier)

  # Step 11: Phone Number Rights Verification (§5A Step 11)
  claims.authorization_valid.tn_rights_valid = verify_tn_rights(passport.orig, dossier)

  # Step 12: Brand Attributes Verification (§5A Step 12) - OPTIONAL
  if passport.card:
    claims.brand_verified = verify_brand(passport.card, dossier)

  # Step 13: Business Logic Verification (§5A Step 13) - OPTIONAL
  if passport.goal:
    claims.business_logic_verified = verify_goal(passport.goal, policy)

  # Propagate claim statuses per §3.3A
  propagate_claims(claims)
  return response(id, claims)
```

### 9.2 Callee Verification

```text
function verify_callee(request, caller_passport):
  id = new_request_id()

  # Initialize claim tree with all REQUIRED nodes per §3.3B
  claims = new_claim_tree("callee_verified")
  claims.passport_verified = new_claim("passport_verified")
  claims.passport_verified.dialog_matched = new_claim("dialog_matched")
  claims.passport_verified.timing_valid = new_claim("timing_valid")
  claims.passport_verified.signature_valid = new_claim("signature_valid")
  claims.dossier_verified = new_claim("dossier_verified")
  claims.dossier_verified.structure_valid = new_claim("structure_valid")
  claims.dossier_verified.acdc_signatures_valid = new_claim("acdc_signatures_valid")
  claims.dossier_verified.revocation_clear = new_claim("revocation_clear")
  claims.dossier_verified.issuer_matched = new_claim("issuer_matched")  # Per §5B Step 9
  claims.tn_rights_valid = new_claim("tn_rights_valid")

  # Step 1: Dialog Matching (§5B Step 1)
  claims.passport_verified.dialog_matched = verify_dialog(request.passport, request.context.sip)

  # Step 2-3: Timing Alignment and Expiration (§5B Steps 2-3)
  passport = parse_passport(request.passport_jwt)
  claims.passport_verified.timing_valid = verify_timing(passport, request.context, replay_tolerance=30s)

  # Step 4: Key Identifier Extraction (§5B Step 4)
  kid = extract_kid(passport)

  # Step 5: Key State Retrieval (§5B Step 5)
  key_state = resolve_key_state(kid, T=passport.iat)

  # Step 6: Signature Verification (§5B Step 6)
  claims.passport_verified.signature_valid = verify_signature(passport, key_state)

  # Step 7-8: Evidence Reference and Cache Check (§5B Steps 7-8)
  dossier = fetch_dossier(passport.evd)
  cached = cached_valid(dossier.said)

  # Step 9: Issuer Verification (§5B Step 9) - under dossier_verified per algorithm
  claims.dossier_verified.issuer_matched = verify_issuer_match(dossier, passport.kid)

  # Step 10: Dossier Validation (§5B Step 10)
  if not cached:
    claims.dossier_verified.structure_valid = validate_dossier_structure(dossier)
    claims.dossier_verified.acdc_signatures_valid = validate_acdc_signatures(dossier, T=issuance_time)
  else:
    claims.dossier_verified.structure_valid.status = VALID
    claims.dossier_verified.acdc_signatures_valid.status = VALID

  # Step 11: Revocation Status Check (§5B Step 11)
  claims.dossier_verified.revocation_clear = check_revocation(dossier)

  # Step 12: Phone Number Rights Verification (§5B Step 12)
  claims.tn_rights_valid = verify_tn_rights(passport.dest, dossier)

  # Step 13: Brand Attributes Verification (§5B Step 13) - OPTIONAL
  if passport.card:
    claims.brand_verified = verify_brand(passport.card, dossier)

  # Step 14: Goal Overlap Verification (§5B Step 14) - OPTIONAL
  if passport.goal and caller_passport:
    claims.goal_overlap_verified = verify_goal_overlap(passport.goal, caller_passport.goal)

  # Propagate claim statuses per §3.3A
  propagate_claims(claims)
  return response(id, claims)
```

Implementations MAY short-circuit claim derivation on fatal PASSporT failures, returning an error-only response. For recoverable failures (e.g., OOBI/KERI resolution timeout), implementations SHOULD return a partial claim tree with affected claims marked INDETERMINATE. This behavior aligns with the overall_status derivation rules in §4.3A.

---

## 10. Test Vectors (Normative)

### 10.1 Purpose

Test vectors define **expected behaviour** for interoperable implementations.

### 10.2 Minimum Required Vectors

Vectors are tiered to align with implementation phases. Tier 1 vectors are required for basic compliance; Tier 2/3 vectors become required when those capabilities are implemented.

#### 10.2.1 Tier 1 Vectors (Direct Verification)

| Scenario | Expected Result |
|---|---|
| Valid VVP-Identity + valid EdDSA PASSporT + valid dossier | VALID |
| PASSporT uses forbidden algorithm (e.g., ES256) | INVALID |
| PASSporT signature invalid | INVALID |
| VVP-Identity iat/exp binding violation (>5s drift) | INVALID |
| Dossier unreachable | INDETERMINATE |
| SAID mismatch under most-compact-form rule | INVALID |
| Dossier graph invalid (cycle/missing root) | INVALID |
| Valid compact/partial/aggregate dossier variant | VALID (if proofs/SAIDs validate) |

#### 10.2.2 Tier 2 Vectors (Full KERI)

| Scenario | Expected Result |
|---|---|
| PASSporT signature invalid at reference time T | INVALID |
| Key rotated/revoked before T (historical) | INVALID |
| OOBI/KERI resolution timeout | INDETERMINATE |
| Credential in dossier revoked | INVALID |
| ACDC signature invalid against issuer key state | INVALID |

#### 10.2.3 Tier 3 Vectors (Authorization and Rich Call Data)

| Scenario | Expected Result |
|---|---|
| SIP context mismatch (orig != From URI) | INVALID or INDETERMINATE (policy) |
| TNAlloc credential does not match orig | INVALID |
| Delegation chain invalid | INVALID |
| Brand claim without supporting credential | INVALID (brand_verified only) |
| Goal rejected by verifier policy | INVALID (business_logic_verified only) |
| Callee call-id/cseq mismatch | INVALID |
| Callee dossier issuer != kid | INVALID |

### 10.3 Vector Structure

Each vector MUST include:
- Input request (headers + body + SIP context)
- External artefacts (PASSporT, OOBI responses, dossier)
- Reference time T and any skew policy used
- Expected claim tree (with all claim statuses)
- Expected error codes (if any)

---

## 11. Coding Agent Instructions

- Follow this specification exactly
- Do not invent semantics
- Fail closed
- Log every decision
- Map code to spec sections

---

## 12. Implementation Tiers

Implementation may proceed in tiers:

### Tier 1: Direct Verification (Complete)
- Parse VVP-Identity and PASSporT
- Validate structure and binding
- Verify signature using embedded key from AID
- Fetch and validate dossier structure (DAG)
- Basic claim tree with passport_verified and dossier_verified

### Tier 2: Full KERI Verification
- KEL resolution from OOBI
- Historical key state at reference time T
- Witness receipt validation
- ACDC signature verification
- Revocation checking via TEL
- Dossier caching

### Tier 3: Authorization and Rich Call Data
- Originating party authorization
- TNAlloc credential matching
- Delegation chain verification
- Brand credential verification
- Business logic and goal verification
- Callee verification flow
- SIP contextual alignment

---

## 13. Next Steps

- Implement Tier 2: KEL resolution and ACDC signature verification
- Implement Tier 2: Revocation checking via TEL
- Implement Tier 3: Authorization and TNAlloc verification
- Add comprehensive test vectors per §10.2
- Performance and abuse testing

---

## Appendix A: Spec §5 Traceability Matrix

| VVP Spec Section | This Spec Section | Implementation Phase |
|------------------|-------------------|---------------------|
| §5.1.1-2.1 (Timing) | §5A Step 1 | Phase 2, 3 |
| §5.1.1-2.2 (Context) | §5A Step 2 | Phase 13 |
| §5.1.1-2.3 (Key ID) | §5A Step 3 | Phase 4 |
| §5.1.1-2.4 (Key State) | §5A Step 4 | Phase 7 |
| §5.1.1-2.5 (Signature) | §5A Step 5 | Phase 4 |
| §5.1.1-2.6 (Evidence) | §5A Step 6 | Phase 5 |
| §5.1.1-2.7 (Cache) | §5A Step 7, §5C | Phase 14 |
| §5.1.1-2.8 (Dossier) | §5A Step 8 | Phase 5, 8 |
| §5.1.1-2.9 (Revocation) | §5A Step 9 | Phase 9 |
| §5.1.1-2.10 (Auth) | §5A Step 10 | Phase 10 |
| §5.1.1-2.11 (TN Rights) | §5A Step 11 | Phase 10 |
| §5.1.1-2.12 (Brand) | §5A Step 12 | Phase 11 |
| §5.1.1-2.13 (Business) | §5A Step 13 | Phase 11 |
| §5.2 (Callee) | §5B | Phase 12 |
| §5.3 (Efficiency) | §5C | Phase 14 |
| §5.4 (Historical) | §5D | Phase 7 |

---

**End of Specification — v1.5**
