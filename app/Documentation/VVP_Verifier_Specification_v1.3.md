# Verifiable Voice Protocol (VVP) Verifier

**Authoritative Specification --- v1.3**

------------------------------------------------------------------------

## Status of This Document

This document is the **authoritative, normative specification** for the
VVP Verifier project, superseding v1.2.

It defines: - Protocol semantics (what is being verified) - Verification
rules (how truth is determined) - Output structures (how results are
expressed) - Constraints for implementations and coding agents

Non‑normative guidance is explicitly marked.

------------------------------------------------------------------------

## 1. Objectives and System Overview

### 1.1 Purpose

The VVP Verifier enables a call terminator (or intermediary) to evaluate
**cryptographically verifiable claims about a call originator's
rights**.

The verifier: - Produces **evidence‑backed claim trees** - Makes **no
routing or blocking decisions** - Does **not assert trust**, only
verifiable facts

Downstream systems decide policy.

------------------------------------------------------------------------

### 1.2 Verifiable Voice Protocol (VVP)

VVP extends STIR/SHAKEN by enabling **proof‑of‑rights**, not merely
proof‑of‑origin.

Core properties: - Multiple independent claims per call - Claims backed
by cryptographic evidence - Decentralised trust (no X.509 PKI
dependency) - Auditability and explainability

Normative reference:\
https://dhh1128.github.io/vvp/draft-hardman-verifiable-voice-protocol.html

------------------------------------------------------------------------

### 1.3 KERI (Key Event Receipt Infrastructure)

KERI establishes authority via **verifiable key state**, not
certificates.

Implications: - Authority evaluated at a point in time - First‑class
revocation and rotation - Evidence‑driven trust decisions

References: - https://keri.one\
- https://github.com/WebOfTrust/keri

------------------------------------------------------------------------

### 1.4 ACDCs (Authentic Chained Data Containers)

ACDCs are **self‑addressing, integrity‑bound claim objects**.

Properties: - Content‑derived identifiers (SAIDs) - Intrinsic integrity
verification - Graph composition

A **dossier** is a DAG of ACDCs whose combined meaning supports claims.

------------------------------------------------------------------------

## 2. System Architecture

### 2.1 Logical Architecture

    Call + VVP‑Identity + PASSporT
                |
                v
            VVP Verifier
            ├─ Parse artefacts
            ├─ Fetch dossier
            ├─ Verify crypto & authority
            └─ Derive claim tree
                |
                v
        Downstream decision systems

------------------------------------------------------------------------

### 2.2 Trust Boundaries

-   Inputs are **untrusted**
-   Claims are **never invented**
-   Ambiguity is **never collapsed**

Uncertainty must be explicit.

------------------------------------------------------------------------

## 3. Claim Model (Normative)

### 3.1 Claim Definition

A **claim** is a proposition about the call originator whose truth can
be evaluated using evidence.

------------------------------------------------------------------------

### 3.2 Claim Status

``` python
class ClaimStatus(Enum):
    VALID
    INVALID
    INDETERMINATE
```

Meanings: - VALID --- proven by evidence - INVALID --- contradicted by
evidence - INDETERMINATE --- insufficient or unverifiable evidence

------------------------------------------------------------------------

### 3.3 Claim Tree

Each parent-child relationship in the claim tree MUST declare whether the child is REQUIRED or OPTIONAL for the parent’s semantics. If not declared, the child relationship MUST be treated as REQUIRED (conservative default).

Verification output is a recursive **claim tree**.

#### 3.3A Claim Propagation Rules (Normative)

-   Parent/child dependencies MUST be explicit
-   REQUIRED children:
    -   Any INVALID → parent INVALID
    -   Else any INDETERMINATE → parent INDETERMINATE
    -   Else → parent MAY be VALID
-   OPTIONAL children MUST NOT invalidate a parent

Non-normative note: REQUIRED vs OPTIONAL is a schema-level decision. Early prototypes MAY treat all children as REQUIRED to be conservative.
Implementation hint: represent child dependencies as objects with a boolean flag, e.g., { "node": <claim-node>, "required": true }.

------------------------------------------------------------------------

## 4. API Contracts

### 4.1 `/verify` Request

**Header**

    VVP‑Identity: <base64url‑encoded JSON>

**Body**

``` json
{
  "passport_jwt": "string",
  "context": {
    "call_id": "string",
    "received_at": "RFC3339 timestamp"
  }
}
```

------------------------------------------------------------------------

### 4.1A VVP‑Identity Header (Decoded)

``` json
{
  "ppt": "shaken",
  "kid": "did:keri:...",
  "evd": "https://example.com/dossier.json",
  "iat": 1737500000,
  "exp": 1737503600
}
```

Rules: - MUST decode via base64url - MUST enforce iat/exp - MUST reject
malformed JSON - MUST bind kid to PASSporT issuer
- MUST allow configurable clock skew; default policy for this project is ±300 seconds.
- SHOULD use a UTC time source synchronized via standard system mechanisms (e.g., NTP) to reduce false INVALIDs.

------------------------------------------------------------------------

### 4.2 Error Envelope

``` json
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

------------------------------------------------------------------------

### 4.2A Error Code Registry (Initial)

  Code                     Layer      Recoverable
  ------------------------ ---------- -------------
  VVP_IDENTITY_INVALID     Protocol   N
  PASSPORT_PARSE_FAILED    Protocol   N
  PASSPORT_SIG_INVALID     Crypto     N
  PASSPORT_EXPIRED         Protocol   N
  DOSSIER_FETCH_FAILED     Evidence   Y
  DOSSIER_GRAPH_INVALID    Evidence   N
  ACDC_SAID_MISMATCH       Crypto     N
  KERI_RESOLUTION_FAILED   KERI       Y
  INTERNAL_ERROR           Verifier   Y

------------------------------------------------------------------------

### 4.3 Successful Verification Response

``` json
{
  "request_id": "uuid",
  "overall_status": "VALID",
  "claims": [
    {
      "name": "caller_authorised",
      "status": "VALID",
      "reasons": [],
      "evidence": ["said:abc"],
      "children": []
    }
  ]
}
```

------------------------------------------------------------------------

### 4.3A overall_status Derivation (Normative)

For responses that contain `claims`, the verifier MUST derive `overall_status` from the set of root claims:
- If any root claim is INVALID → overall_status MUST be INVALID.
- Else if any root claim is INDETERMINATE → overall_status MUST be INDETERMINATE.
- Else → overall_status MUST be VALID.
For responses that contain only `errors` (no `claims`), the verifier MUST derive `overall_status` as follows:
- If any error has recoverable=false → overall_status MUST be INVALID.
- Else → overall_status MUST be INDETERMINATE.

------------------------------------------------------------------------

## 5. PASSporT Verification (Normative)

Implementations MUST:

-   Reject alg=none
-   Accept only approved asymmetric algorithms
-   Verify signature using issuer key state (KERI)
-   Enforce temporal validity
-   Bind PASSporT issuer to VVP‑Identity kid

Failures in PASSporT processing MUST be mapped deterministically to claim status. Failures caused by invalid input or failed cryptographic checks (e.g., parse errors, signature mismatch, forbidden algorithm, expired token) MUST result in INVALID. Failures caused by temporarily unavailable dependencies (e.g., KERI resolution timeout) MUST result in INDETERMINATE for all claims that depend on the unresolved key state.

Non-normative note: This distinction allows verifiers to be fail-closed on cryptographic correctness while remaining explicit about operational uncertainty.

### 5.1 Allowed Algorithms (Normative)

The verifier MUST reject the JWS algorithm value `none`. The verifier MUST implement support for `ES256` (ECDSA P-256 with SHA-256) as the baseline algorithm for PASSporT, and MUST reject any algorithm not explicitly allowed by local policy.  
Default policy for this project (unless explicitly configured otherwise): allow only `ES256`.  
Reference registries and definitions: RFC 7518 (JSON Web Algorithms) defines `ES256`; RFC 8225 defines PASSporT header processing and references JOSE.  

Ref: https://www.rfc-editor.org/rfc/rfc7518  
Ref: https://www.rfc-editor.org/rfc/rfc8225

------------------------------------------------------------------------

## 6. Dossier Model

### 6.1 Dossier Graph

The dossier is a **directed acyclic graph (DAG)**.

- Cycles are INVALID and MUST yield the error code DOSSIER_GRAPH_INVALID.  
- The graph root MUST be explicit (the `root` field). If multiple entry points exist and no single root can be selected deterministically, the dossier MUST be treated as invalid (DOSSIER_GRAPH_INVALID), unless local policy explicitly supports multiple roots by returning multiple root claims.

``` python
@dataclass
class DossierGraph:
    root: str
    nodes: Dict[str, ACDCNode]
```

------------------------------------------------------------------------

### 6.1A ACDCNode

``` python
@dataclass
class ACDCNode:
    said: str
    issuer: str
    schema: str
    attributes: Dict[str, Any]
    edges: List[str]
    proofs: Optional[Dict[str, Any]]
```

------------------------------------------------------------------------

### 6.1B Dossier Retrieval Rules

-   HTTP(S) MUST be supported
-   Timeouts and size limits MUST be enforced
-   SAID recomputation is mandatory
-   TLS is RECOMMENDED but not relied upon

------------------------------------------------------------------------

## 7. KERI Integration

-   Resolver treated as abstract oracle
-   Network‑agnostic
-   Read‑only key state resolution
-   KERI resolution failures that are transient (timeouts/unreachable resolver) MUST produce INDETERMINATE for dependent claims; cryptographically invalid or contradictory resolved state MUST produce INVALID.

------------------------------------------------------------------------

## 8. CI/CD and Deployment (Normative)

-   GitHub Actions
-   OIDC authentication
-   Push to main → new ACA revision
-   No secrets permitted

------------------------------------------------------------------------

## 9. Verification Engine Pseudocode (Normative)

``` text
function verify(request):
  id = new_request_id()
  header = parse_vvp_identity(request)
  passport = verify_passport(request.passport_jwt, header.kid)
  dossier = fetch_and_validate_dossier(header.evd)
  claims = derive_claims(passport, dossier)
  propagate_claims(claims)
  return response(id, claims)
```

All failures must surface explicit error codes.

------------------------------------------------------------------------

## 10. Test Vectors (Normative)

### 10.1 Purpose

Test vectors define **expected behaviour** for interoperable
implementations.

------------------------------------------------------------------------

### 10.2 Minimum Required Vectors

  Scenario                         Expected Result
  -------------------------------- -----------------
  Valid PASSporT + valid dossier   VALID
  PASSporT signature invalid       INVALID
  Dossier unreachable              INDETERMINATE
  SAID mismatch                    INVALID
  Expired PASSporT                 INVALID
  KERI resolution timeout          INDETERMINATE

------------------------------------------------------------------------

### 10.3 Vector Structure

Each vector MUST include: - Input request (headers + body) - External
artefacts (PASSporT, dossier) - Expected claim tree - Expected error
codes (if any)

------------------------------------------------------------------------

## 11. Coding Agent Instructions

-   Follow this specification exactly
-   Do not invent semantics
-   Fail closed
-   Log every decision
-   Map code to spec sections

------------------------------------------------------------------------

## 12. Next Steps

-   Implement verifier skeleton
-   Add golden test vectors
-   Integrate KERI resolver
-   Performance and abuse testing

------------------------------------------------------------------------

**End of Specification --- v1.3**
