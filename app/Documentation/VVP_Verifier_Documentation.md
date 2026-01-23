# Verifiable Voice Protocol (VVP) Verifier -- Documentation Pack

## 1. Objectives and Background

### 1.1 Verifiable Voice Protocol (VVP)

The Verifiable Voice Protocol (VVP) is a proposed mechanism for enabling
cryptographically verifiable assertions about the legitimacy and
authority of a call originator, conveyed alongside real-time voice
communications. VVP is designed to complement (not replace) STIR/SHAKEN
by allowing richer, machine-verifiable claims to be conveyed from the
call originator to the call terminator.

Key objectives of VVP: - Provide **proof of rights**, not just proof of
identity - Support **multi-claim assertions** (e.g. authority to use a
number, brand affiliation, call purpose) - Enable **end-to-end
verification** without reliance on central certificate authorities - Be
compatible with existing telephony infrastructure

Primary reference: - VVP draft specification (Daniel Hardman):
https://dhh1128.github.io/vvp/draft-hardman-verifiable-voice-protocol.html

------------------------------------------------------------------------

### 1.2 KERI (Key Event Receipt Infrastructure)

KERI is a decentralized key management and trust framework based on
**event logs** rather than static certificates. Instead of asking "is
this key valid?", KERI allows verifiers to ask "what is the current
state of this identifier?".

Core KERI concepts: - **Self-certifying identifiers** (SCIDs) - **Key
Event Logs (KELs)** describing inception, rotation, delegation, and
revocation - **Receipts** that provide non-repudiation and witness
confirmation - No dependency on traditional PKI or Certificate
Authorities

Why KERI matters for VVP: - Allows cryptographic verification of issuer
authority over time - Supports revocation and key rotation without CRLs
or OCSP - Aligns with regulatory needs for demonstrable evidence

Primary references: - KERI overview: https://keri.one - Reference
implementation: https://github.com/WebOfTrust/keri

------------------------------------------------------------------------

### 1.3 ACDCs (Authentic Chained Data Containers)

ACDCs are structured, cryptographically verifiable data objects designed
to express claims, credentials, and assertions that can be chained
together and independently verified.

Key properties: - **Self-addressing identifiers (SAIDs)** derived from
content - Strong integrity guarantees - Explicit issuer binding (often
via KERI identifiers) - Suitable for building verifiable dossiers of
evidence

Role in VVP: - A VVP "dossier" is expected to be a graph of ACDCs - Each
ACDC supports one or more claims (e.g. "this entity is authorised to
place this call") - The verifier evaluates the dossier to produce a
claim-status tree

Primary references: - Web of Trust specifications and examples:
https://github.com/WebOfTrust

------------------------------------------------------------------------

## 2. Known Secrets, IDs, and Configuration Values

The following table captures all currently known identifiers and
configuration values. **No long-lived secrets are used**; authentication
relies on managed identity and OIDC.

  ---------------------------------------------------------------------------------------------------------------------
  Category            Name             Value                                                           Notes
  ------------------- ---------------- --------------------------------------------------------------- ----------------
  Azure Subscription  Subscription ID  83c40054-5d1d-408a-b771-e4aae662e6e4                            RichConnexions

  Azure Tenant        Tenant ID        cffbeae9-2c9d-4b23-922b-033cc9d9a652                            Entra ID tenant

  Resource Group      Name             VVP                                                             All resources

  Azure Container     Name             rcnxvvpacr                                                      SKU: Basic
  Registry                                                                                             

  ACR Login Server    URL              rcnxvvpacr.azurecr.io                                           Used in CI/CD

  Container Apps      Name             vvp-env                                                         UK South
  Environment                                                                                          

  Container App       Name             vvp-verifier                                                    FastAPI service

  Public FQDN         URL              vvp-verifier.wittytree-2a937ccd.uksouth.azurecontainerapps.io   Stable endpoint

  GitHub Repo         Owner/Repo       andrewbalercnx/vvp-verifier                                     Source of truth

  GitHub Branch       Deployment       main                                                            Triggers CI/CD
                      Branch                                                                           

  CI/CD Auth          Method           GitHub OIDC                                                     No secrets

  Env Var             GIT_SHA          injected at deploy                                              Exposed via
                                                                                                       /version
  ---------------------------------------------------------------------------------------------------------------------

------------------------------------------------------------------------

## 3. Verification Engine Skeleton (Design + Pseudocode)

This section defines the **intended structure** of the VVP verification
engine. All verdicts should initially be returned as `INDETERMINATE`
until cryptographic verification is fully implemented.

### 3.1 High-level flow

1.  Receive `/verify` request
2.  Generate `request_id`
3.  Parse VVP Identity header
4.  Parse PASSporT JWT
5.  Fetch dossier from `evd` URL
6.  Validate dossier graph structure
7.  Verify issuer key state via KERI
8.  Derive claim tree with statuses
9.  Return structured result

------------------------------------------------------------------------

### 3.2 Proposed module layout

    app/
      main.py
      api/
        routes.py
      core/
        logging.py
        config.py
        request_id.py
      vvp/
        header.py
        passport.py
        dossier/
          fetch.py
          model.py
        keri/
          resolver.py
        verify/
          engine.py
          claimtree.py

------------------------------------------------------------------------

### 3.3 Claim status model

``` python
from enum import Enum

class ClaimStatus(str, Enum):
    VALID = "VALID"
    INVALID = "INVALID"
    INDETERMINATE = "INDETERMINATE"
```

------------------------------------------------------------------------

### 3.4 Verification engine skeleton

``` python
# app/vvp/verify/engine.py

from app.vvp.verify.claimtree import ClaimNode, ClaimStatus

def verify_vvp_request(vvp_header: str, passport_jwt: str) -> ClaimNode:
    # Root of the claim tree
    root = ClaimNode(
        name="vvp_verification",
        status=ClaimStatus.INDETERMINATE,
        reasons=[],
        evidence=[]
    )

    # Step 1: Parse header
    root.add_child(ClaimNode(
        name="vvp_header_parsed",
        status=ClaimStatus.INDETERMINATE
    ))

    # Step 2: PASSporT parsing
    root.add_child(ClaimNode(
        name="passport_parsed",
        status=ClaimStatus.INDETERMINATE
    ))

    # Step 3: Dossier retrieval
    root.add_child(ClaimNode(
        name="dossier_retrieved",
        status=ClaimStatus.INDETERMINATE
    ))

    # Step 4: KERI verification
    root.add_child(ClaimNode(
        name="issuer_key_state_verified",
        status=ClaimStatus.INDETERMINATE
    ))

    return root
```

------------------------------------------------------------------------

### 3.5 Claim tree data structure

``` python
# app/vvp/verify/claimtree.py

from dataclasses import dataclass, field
from typing import List

@dataclass
class ClaimNode:
    name: str
    status: str
    reasons: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)
    children: List["ClaimNode"] = field(default_factory=list)

    def add_child(self, node: "ClaimNode"):
        self.children.append(node)
```

------------------------------------------------------------------------

## 4. Intended Next Steps

1.  Implement `/version` endpoint and deploy (testbed complete)
2.  Add request correlation middleware
3.  Implement VVP header parser
4.  Implement PASSporT JWT parsing and signature verification
5.  Define dossier schema and parsing rules
6.  Integrate KERI key state resolution
7.  Produce full claim tree with reasons and evidence
8.  Add golden test vectors and CI tests

------------------------------------------------------------------------

## 5. Guiding Principles for Contributors and Coding Agents

-   Assume hostile input
-   Never silently fail verification steps
-   Always return explicit claim statuses
-   Log every verification decision with `request_id`
-   Prefer explainability over brevity

------------------------------------------------------------------------

**Document version:** 1.0\
**Status:** Living document -- update as verification logic evolves
