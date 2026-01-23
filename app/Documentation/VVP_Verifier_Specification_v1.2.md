# Verifiable Voice Protocol (VVP) Verifier

**Authoritative Specification -- v1.2**

------------------------------------------------------------------------

## Status of This Document

This document is the **authoritative, normative specification** for the
VVP Verifier project.

It is intended to: - Define *what* is being verified (protocol
semantics) - Define *how* verification results must be expressed -
Constrain implementation choices for both humans and coding agents -
Serve as onboarding material with minimal assumed prior knowledge

Non-normative notes are explicitly marked.

------------------------------------------------------------------------

## 1. Objectives and System Overview

### 1.1 Purpose

The VVP Verifier exists to allow a call terminator (or an intermediary
acting on its behalf) to evaluate **cryptographically verifiable claims
about a call originator's rights**.

The verifier does **not**: - make routing decisions - block or allow
calls - assert trust on behalf of the terminator

Instead, it produces an **explainable claim tree** that downstream
systems may consume.

------------------------------------------------------------------------

### 1.2 Verifiable Voice Protocol (VVP)

The Verifiable Voice Protocol extends STIR/SHAKEN by allowing
**proof-of-rights**, not merely proof-of-origin, to be conveyed
alongside calls.

VVP enables: - Multiple, independent claims per call - Claims backed by
cryptographic evidence - Verification without reliance on X.509 PKI or
certificate authorities

VVP is intentionally: - Evidence-driven - Decentralised - Auditable

**Normative reference:**\
https://dhh1128.github.io/vvp/draft-hardman-verifiable-voice-protocol.html

------------------------------------------------------------------------

### 1.3 KERI (Key Event Receipt Infrastructure)

KERI replaces static certificates with **key state** derived from
ordered event logs.

Key implications for VVP: - Authority is evaluated *at a point in
time* - Revocation and rotation are first-class - Trust decisions are
evidence-based

The verifier never asks: \> "Is this certificate trusted?"

It instead asks: \> "What does the cryptographic history of this
identifier prove?"

References: - https://keri.one\
- https://github.com/WebOfTrust/keri

------------------------------------------------------------------------

### 1.4 ACDCs (Authentic Chained Data Containers)

ACDCs are self-addressing, cryptographically bound data objects used to
express claims.

Properties: - Each ACDC has a **SAID** (self-addressing identifier) -
Content integrity is intrinsic - Objects may reference other ACDCs,
forming a graph

In VVP, a **dossier** is a graph of ACDCs whose combined meaning
supports one or more claims.

------------------------------------------------------------------------

## 2. System Architecture

### 2.1 Logical Architecture

    Call + VVP Header + PASSporT
              |
              v
       VVP Verifier
       ├─ Parse protocol artefacts
       ├─ Retrieve dossier
       ├─ Verify cryptographic evidence
       └─ Produce claim tree
              |
              v
       Downstream decision system

------------------------------------------------------------------------

### 2.2 Trust Boundaries

-   The verifier **does not trust input**
-   The verifier **does not invent claims**
-   The verifier **does not collapse ambiguity**

All uncertainty must be surfaced explicitly.

------------------------------------------------------------------------

## 3. Claim Model (Normative)

### 3.1 Claim Definition

A **claim** is a proposition asserted about the call originator, whose
truth value may be evaluated using evidence.

Examples: - "The caller is authorised to use this number" - "The caller
represents brand X" - "The call purpose matches its declared intent"

------------------------------------------------------------------------

### 3.2 Claim Status

Every claim MUST be assigned exactly one status:

``` python
class ClaimStatus(Enum):
    VALID
    INVALID
    INDETERMINATE
```

Meanings:

-   **VALID** -- Evidence proves the claim
-   **INVALID** -- Evidence contradicts the claim
-   **INDETERMINATE** -- Evidence is missing, incomplete, or
    unverifiable

The verifier MUST NOT guess.

------------------------------------------------------------------------

### 3.3 Claim Tree

Verification output is a **tree of claims**, where: - Parent claims
depend on child claims - Failure propagates upward only when logically
required

### 3.3A Claim Propagation Rules (Normative)

- A parent claim MAY depend on one or more child claims.
- The dependency relationship MUST be explicit in code (no implicit guessing).
- If any REQUIRED child claim is INVALID, the parent claim MUST be INVALID.
- If no REQUIRED child claim is INVALID but at least one REQUIRED child claim is INDETERMINATE, the parent claim MUST be INDETERMINATE.
- If all REQUIRED child claims are VALID, the parent claim MAY be VALID (subject to any additional evidence checks at the parent level).
- OPTIONAL child claims MUST NOT cause the parent to become INVALID; they MAY cause INDETERMINATE if the parent’s semantics explicitly require them.

*Note: “REQUIRED vs OPTIONAL” is a schema-level decision. Early prototypes may treat all children as REQUIRED to be conservative.*

Propagation pseudocode:
```text
function propagate(parent):
  required = parent.required_children
  if any(child.status == INVALID for child in required): parent.status = INVALID
  else if any(child.status == INDETERMINATE for child in required): parent.status = INDETERMINATE
  else: parent.status = VALID  # unless parent has additional checks
```
------------------------------------------------------------------------

## 4. API Contracts

### 4.1 `/verify` Request

**Headers**

    VVP-Identity: <base64url-encoded JSON>

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

### 4.1A VVP-Identity Header (Decoded)

Decoded form:

``` json
{
  "ppt": "shaken",
  "kid": "did:keri:...",
  "evd": "https://example.com/dossier.json",
  "iat": 1737500000,
  "exp": 1737503600
}
```

  Field   Meaning
  ------- ----------------------
  ppt     PASSporT profile
  kid     Issuer identifier
  evd     Evidence dossier URL
  iat     Issued-at
  exp     Optional expiry

------------------------------------------------------------------------

### 4.2 Error Envelope

``` json
{
  "request_id": "uuid",
  "overall_status": "INVALID",
  "errors": [
    {
      "code": "DOSSIER_FETCH_FAILED",
      "message": "Unable to retrieve dossier",
      "recoverable": true
    }
  ]
}
```

### 4.2A Error Code Registry (Initial)

Implementations MUST use the following error codes (and may extend them with project-specific codes prefixed with `EXT_`).

| Code                    | Layer     | Meaning                                              | Recoverable |
|-------------------------|-----------|------------------------------------------------------|-------------|
| VVP_IDENTITY_MISSING    | Protocol  | Missing VVP-Identity header                          | N           |
| VVP_IDENTITY_INVALID    | Protocol  | Header cannot be decoded/parsed                      | N           |
| PASSPORT_MISSING        | Protocol  | Missing passport_jwt in request body                 | N           |
| PASSPORT_PARSE_FAILED   | Protocol  | PASSporT JWT cannot be decoded                       | N           |
| PASSPORT_SIG_INVALID    | Crypto    | PASSporT signature invalid                           | N           |
| PASSPORT_EXPIRED        | Protocol  | PASSporT is expired per iat/exp policy               | N           |
| DOSSIER_URL_MISSING     | Evidence  | No evd URL present in VVP-Identity                   | N           |
| DOSSIER_FETCH_FAILED    | Evidence  | Unable to retrieve dossier from evd                  | Y           |
| DOSSIER_PARSE_FAILED    | Evidence  | Dossier content cannot be parsed                     | N           |
| DOSSIER_GRAPH_INVALID   | Evidence  | Dossier graph invalid (cycle/missing nodes)          | N           |
| ACDC_SAID_MISMATCH      | Crypto    | ACDC SAID does not match content                     | N           |
| ACDC_PROOF_MISSING      | Crypto    | Required proof/signature missing                     | N           |
| KERI_RESOLUTION_FAILED  | KERI      | Unable to resolve issuer key state                   | Y           |
| KERI_STATE_INVALID      | KERI      | Resolved key state does not validate required constraints | N      |
| INTERNAL_ERROR          | Verifier  | Unexpected verifier failure                          | Y           |
------------------------------------------------------------------------

### 4.3 Successful Verification Response

``` json
{
  "request_id": "uuid",
  "overall_status": "VALID",
  "claims": {
    "name": "call_authorisation",
    "status": "VALID",
    "reasons": [],
    "evidence": ["said:abc..."],
    "children": []
  }
}
```

------------------------------------------------------------------------

## 5. PASSporT JWT Expectations

Minimum expected claims per RFC 8225:

``` json
{
  "iss": "string",
  "iat": 1737500000,
  "orig": { "tn": "string" },
  "dest": { "tn": ["string"] },
  "attest": "A|B|C",
  "origid": "uuid"
}
```

------------------------------------------------------------------------

## 6. Dossier Model

### 6.1 Dossier Graph

The dossier is a **directed acyclic graph (DAG)** of ACDCs.

Cycles are INVALID.

``` python
@dataclass
class DossierGraph:
    root: str
    nodes: Dict[str, ACDCNode]
```

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

------------------------------------------------------------------------

## 7. KERI Integration

### 7.1 Resolver Interface

``` python
class KeriResolver:
    def resolve(self, identifier: str) -> dict:
        ...
```

### 7.2 Infrastructure Assumptions

-   Network-agnostic
-   Public or private witnesses permitted
-   Resolver treated as abstract oracle

------------------------------------------------------------------------

## 8. CI/CD and Deployment (Normative)

-   GitHub Actions
-   OIDC authentication
-   Push to main → build → ACR → Container App revision
-   No secrets permitted

------------------------------------------------------------------------

## 9. Coding Agent Instructions

### Scope Rules

-   Do not modify infrastructure unless instructed
-   Do not introduce secrets
-   Do not invent protocol semantics

### Verification Rules

-   Never silently downgrade
-   Always return explicit claim status
-   Log all decisions

### Security Rules

-   Assume hostile input
-   Fail closed

------------------------------------------------------------------------

## 10. Next Implementation Phases

1.  Version endpoint
2.  Request correlation
3.  Header parsing
4.  PASSporT verification
5.  Dossier validation
6.  KERI resolution
7.  Claim derivation
8.  Test vectors

------------------------------------------------------------------------

**End of Specification**
