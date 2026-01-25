# VVP & KERI Glossary

This project relies heavily on terminology from the Verifiable Voice Protocol (VVP) and Key Event Receipt Infrastructure (KERI). This glossary defines these terms in the context of this codebase.

## Core VVP Terms

### VVP (Verifiable Voice Protocol)
A protocol extending STIR/SHAKEN to provide proof-of-rights for call origination. It uses a claim tree model backed by cryptographic evidence.

### PASSporT (Personal Assertion Token)
A JWT used in STIR/SHAKEN. VVP uses a specific profile (`ppt=vvp`) where the `kid` (Key ID) is a KERI OOBI and the payload cites a Dossier.

### Dossier
A Directed Acyclic Graph (DAG) of **ACDCs** that provides the backing evidence for a call. It proves the caller's identity, phone number rights, and brand attributes.

### Claim Tree
The recursive output of the VVP Verifier. It represents the hierarchical validation status of the call, where parent claims depend on the status of child claims (e.g., `caller_verified` depends on `passport_verified`).

## KERI / Crypto Terms

### AID (Autonomic Identifier)
A decentralized identifier derived from a public key (or set of keys). Unlike X.509 certificates, AIDs support key rotation without changing the identifier.
*   **Prefixes:** `B` (Basic/Non-transferable), `D` (Digest/Transferable), `E` (Pre-rotated).

### KEL (Key Event Log)
An append-only log of events (Inception, Rotation, Interaction) signed by the AID controller. It proves the authoritative key state of an AID at any given point in time.

### OOBI (Out-of-Band Introduction)
A URL used to discover KERI resources. In VVP, the `kid` header in a PASSporT is an OOBI that points to the caller's KEL.

### CESR (Composable Event Streaming Representation)
A binary-to-text encoding format used for KERI events and signatures. It supports pipelining and is more compact than standard JSON.
*   **Note:** VVP signatures use a specific CESR encoding (prefixed with `0B`) inside the JWT, which differs from standard JWS signatures.

### ACDC (Authentic Chained Data Container)
A verifiable data format used for credentials in the Dossier. ACDCs are bound to the issuer's KEL and use **SAIDs** for tamper-evident linking.

### SAID (Self-Addressing Identifier)
A content-derived identifier (hash) embedded within the data it identifies. Validating a SAID requires re-computing the hash of the data (in its canonical form) and ensuring it matches the identifier field.

### TEL (Transaction Event Log)
A log used to track the revocation status of credentials (ACDCs).

## Implementation Terms

### Tier 1 (Direct Verification)
Verification logic that checks the syntax and cryptographic integrity of the PASSporT and Dossier structure, but assumes the keys in the AID are valid without checking history.

### Tier 2 (Full KERI Verification)
Verification logic that resolves the full **KEL** to prove the keys were valid at the specific timestamp (`iat`) of the call, and checks for revocation via **TEL**.

### Tier 3 (Authorization)
High-level verification of business logic, such as checking if the caller has the right to use a specific phone number (**TNAlloc**) or brand.