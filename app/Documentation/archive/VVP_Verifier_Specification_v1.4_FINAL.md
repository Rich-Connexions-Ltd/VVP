# Verifiable Voice Protocol (VVP) Verifier

**Authoritative Specification — v1.4 (FINAL)**

---

## Status of This Document

This document is the **authoritative, normative specification** for the VVP Verifier project, superseding v1.3 (FINAL).

It defines:
- Protocol semantics (what is being verified)
- Verification rules (how truth is determined)
- Output structures (how results are expressed)
- Constraints for implementations and coding agents

Non-normative guidance is explicitly marked.  
This document is considered specification-locked; future changes require an explicit version bump.

---

## 1. Objectives and System Overview

### 1.1 Purpose

The VVP Verifier enables a call terminator (or intermediary) to evaluate **cryptographically verifiable claims about a call originator’s rights**.

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
- ACDC supports compact, partial, and aggregate disclosure; verifiers MUST be able to validate dossiers expressed in these valid forms without assuming fully expanded JSON. (spec-body.md: “ACDC Variants”)
- SAIDs MUST be computed using the “most compact form” algorithm, not necessarily the received representation. (spec-body.md: “Most compact form SAID”)

---

## 2. System Architecture

### 2.1 Logical Architecture

```
Call + VVP-Identity + PASSporT
            |
            v
        VVP Verifier
        ├─ Parse artefacts (CESR where applicable)
        ├─ Resolve OOBIs (kid, evd)
        ├─ Verify crypto & key state at reference time
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

Each parent-child relationship in the claim tree MUST declare whether the child is REQUIRED or OPTIONAL for the parent’s semantics. **Omission of this declaration is a schema violation and MUST be treated as an error by the verifier.**

Verification output is a recursive **claim tree**.

#### 3.3A Claim Propagation Rules (Normative)

- Parent/child dependencies MUST be explicit
- REQUIRED children:
  - Any INVALID → parent INVALID
  - Else any INDETERMINATE → parent INDETERMINATE
  - Else → parent MAY be VALID
- OPTIONAL children MUST NOT invalidate a parent

Implementation hint: represent child dependencies as objects with a boolean flag, e.g., `{ "node": <claim-node>, "required": true }`.

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
    "received_at": "RFC3339 timestamp"
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
- The verifier MUST validate OOBI responses using KERI/CESR parsing and KEL-backed evidence, not generic JSON canonicalization. (spec-body.md: “Special label ordering requirements”; “Protocol genus/version tables”)

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

### 4.2A Error Code Registry (Initial)

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
| INTERNAL_ERROR | Verifier | Unexpected verifier failure | Y |

---

### 4.3 Successful Verification Response

```json
{
  "request_id": "uuid",
  "overall_status": "VALID",
  "claims": [
    {
      "name": "caller_authorised",
      "status": "VALID",
      "reasons": [],
      "evidence": ["said:abc"],
      "children": [
        {
          "required": true,
          "node": {
            "name": "example_child_claim",
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
•	A PASSporT MUST be treated as expired (PASSPORT_EXPIRED) if the verifier’s current time is greater than exp plus allowed clock skew (default ±300 seconds).
•	If PASSporT exp is absent, the PASSporT MUST be treated as expired if the verifier’s current time is greater than (iat + 300 seconds) plus allowed clock skew, unless explicitly configured otherwise.

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

## 6. Dossier Model

### 6.1 Dossier Graph

The dossier is a **directed acyclic graph (DAG)**.

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
- SAID recomputation MUST be performed using the **most compact form** algorithm. (spec-body.md: “Most compact form SAID”)
- Verifiers MUST support valid ACDC variants (compact / partial / aggregate) and MUST NOT require a fully expanded JSON representation. (spec-body.md: “ACDC Variants”)

---

## 7. KERI Integration

- Resolver treated as abstract oracle, but MUST provide sufficient evidence for reference-time validation.
- Network-agnostic
- Read-only key state resolution

KERI resolution failures that are transient (timeouts/unreachable resolver) MUST produce INDETERMINATE for dependent claims; cryptographically invalid or contradictory resolved state MUST produce INVALID.

### 7.1 KERI/CESR Versioning (Normative)

KERI/CESR messages are versioned and require strict field ordering and code tables; generic JSON canonicalization is not sufficient. (spec-body.md: “Special label ordering requirements”; “Protocol genus/version tables”)

Policy for this project:
- The verifier MUST support parsing and verifying the target KERI/CESR version(s) used by the deployment’s OOBIs and KELs.
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

Some libraries default credential expiry to effectively “never”. (verifying.py line 34)

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

```text
function verify(request):
  id = new_request_id()

  vvp = parse_and_validate_vvp_identity(request)         # §4.1A/§4.1B (OOBI semantics + temporal rules)
  passport = verify_passport_at_time(request.passport, vvp, T=vvp.iat)  # §5.3 reference-time validation

  dossier = fetch_and_validate_dossier_oobi(vvp.evd)     # §6.1B (application/json+cesr + SAID rules + variants)

  claims = derive_claims(passport, dossier)              # maps evidence → claim nodes (§3)
  propagate_claims(claims)                               # §3.3A
  return response(id, claims)
```

Implementations MAY short-circuit claim derivation on fatal PASSporT failures, returning an error-only response. For recoverable failures (e.g., OOBI/KERI resolution timeout), implementations SHOULD return a partial claim tree with affected claims marked INDETERMINATE. This behavior aligns with the overall_status derivation rules in §4.3A.

---

## 10. Test Vectors (Normative)

### 10.1 Purpose

Test vectors define **expected behaviour** for interoperable implementations.

### 10.2 Minimum Required Vectors

| Scenario | Expected Result |
|---|---|
| Valid VVP-Identity + valid EdDSA PASSporT + valid dossier | VALID |
| PASSporT uses forbidden algorithm (e.g., ES256) | INVALID |
| PASSporT signature invalid at reference time T | INVALID |
| Key rotated/revoked before T (historical) | INVALID |
| OOBI/KERI resolution timeout | INDETERMINATE |
| Dossier unreachable | INDETERMINATE |
| SAID mismatch under most-compact-form rule | INVALID |
| Valid compact/partial/aggregate dossier variant | VALID (if proofs/SAIDs validate) |

### 10.3 Vector Structure

Each vector MUST include:
- Input request (headers + body)
- External artefacts (PASSporT, OOBI responses, dossier)
- Reference time T and any skew policy used
- Expected claim tree
- Expected error codes (if any)

---

## 11. Coding Agent Instructions

- Follow this specification exactly
- Do not invent semantics
- Fail closed
- Log every decision
- Map code to spec sections

---

## 12. Next Steps

- Implement verifier skeleton against §9
- Add golden test vectors per §10
- Integrate KERI resolver with reference-time key state validation
- Performance and abuse testing

---

**End of Specification — v1.4 (FINAL)**
