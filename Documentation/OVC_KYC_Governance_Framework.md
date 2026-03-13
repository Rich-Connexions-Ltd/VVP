# Open Verifiable Communications: Telecoms KYC Governance Framework

**Document type:** Governance Specification — Version 0.1 (Draft for Community Review)
**Date:** March 2026
**Prepared by:** Open Verifiable Communications Community
**Status:** Working Draft

---

## Abstract

This document defines a governance framework for a telecoms-specific Know Your Customer (KYC) process that operates across territorial boundaries. It establishes the concept of an Authorised Vetter — an entity accredited to perform originator vetting on behalf of communications providers — and defines the trust hierarchy, vetting process requirements, and attestation model that together constitute the OVC KYC framework. The framework is explicitly designed to satisfy the existing obligations of communications providers under US, EU, and UK regulation without prescribing the method those providers must use to meet those obligations. It uses the GSMA as the global root of trust, reflecting the GSMA's existing role in cross-border identity assurance for mobile and messaging services.

---

## 1. Problem Statement

### 1.1 The regulatory obligation is clear; the method is not

Every major telecommunications regulatory jurisdiction has established that a communications provider must know its customers — that is, must verify the identity of a business entity seeking to originate communications, and must confirm that entity's entitlement to use the identifiers (telephone numbers, Sender IDs, brand names) it claims. This obligation is stated in 47 CFR § 64.1200(n)(4) (US), EECC Article 100 (EU), and the Ofcom General Conditions GC B1 and GC C6 (UK), as well as in the GSMA FASG KYC Guidelines and national frameworks including India's TRAI TCCCPR and Singapore's IMDA SSIR.

What none of these instruments specifies is *how* the verification must be performed, *who* may perform it, or *how* the results of verification may be relied upon downstream. The NANC Call Authentication Trust Anchor Working Group (CATA-WG) document — the most detailed industry guidance on STIR/SHAKEN subscriber vetting — explicitly recognises this gap. It endorses the use of "third-party vetting services" and notes that for indirect subscriber relationships (resellers, VASPs, enterprise customers), "there needs to be new and additional mechanisms in place so the VSP can be sufficiently confident the caller identity or telephone number used for the call merits full attestation." The CATA-WG further identifies international origination as the domain where "industry consensus has not yet coalesced" and where the GSMA VINES Working Group is developing cross-border solutions.

The OVC framework fills exactly this gap: it specifies the governance structure, the vetting process requirements, and the attestation format that allow third-party vetting to be conducted, certified, and relied upon in a manner that satisfies the regulatory obligations of carrying networks across multiple jurisdictions.

### 1.2 The chain-of-custody problem

Business communications do not travel through a single provider. An enterprise originator may engage a CPaaS reseller, which connects to a Tier-1 aggregator, which connects to an originating carrier, which passes the call through transit providers to a terminating carrier. Each link in this chain has a potential obligation to know its immediate upstream customer. Without a shared vetting credential, every link must repeat the verification process independently, or accept that upstream vetting has been performed without being able to verify it.

The TRAI TCCCPR (India) has solved this through a national blockchain registry (DLT) on which every Principal Entity and Telemarketer is registered; every link can query the same authoritative ledger. This approach works within a single national jurisdiction. It does not work across borders.

The OVC framework solves this through verifiable credentials: a vetting result, once issued as a credential by an Authorised Vetter, can be presented to any downstream carrier in any jurisdiction and verified cryptographically without requiring the carrying network to trust or contact the vetter directly.

### 1.3 The international origination gap

Every national framework reviewed in the OVC KYC research programme addresses domestic originator accountability. None has successfully attributed positive identity to international business originators before their traffic enters a national network. This is the dominant fraud vector identified in enforcement actions across all primary jurisdictions: communications injected from foreign networks using spoofed domestic identifiers.

The OVC framework is specifically designed to operate internationally. A business originator in any jurisdiction can obtain an OVC vetting credential from an Authorised Vetter operating in that jurisdiction. That credential is expressed in a standard format and signed under the GSMA trust hierarchy, making it verifiable by any carrying network regardless of where the originator or the vetter is located.

---

## 2. Scope

This document establishes:

1. A set of **definitions** for the key concepts in telecoms KYC, aligned to the regulatory vocabulary of the primary jurisdictions
2. A **governance hierarchy** using the GSMA as the global root of trust
3. The **Authorised Vetter** model — the role, accreditation requirements, and obligations of entities authorised to perform OVC vetting
4. **Vetting process requirements** — the minimum obligations that constitute a valid OVC vetting exercise
5. The **OVC Vetting Credential** — the format and content of the attestation issued following successful vetting
6. **Regulatory alignment** — how the framework maps to existing obligations in primary jurisdictions
7. **Open questions** requiring further specification

This document does not define the technical credential format (that is addressed in the OVC Protocol Specification). It does not define the OVC transport layer. It does not address consumer (non-business) identity verification.

---

## 3. Core Definitions

The following definitions are established as the authoritative vocabulary of the OVC KYC framework. They are designed to be compatible with the regulatory terminology of the primary jurisdictions; the mapping is set out in Section 7.

| Term | Definition |
|---|---|
| **Business Originator** | A legal entity — incorporated company, partnership, sole trader, or equivalent — that contracts with a communications provider to send voice or data communications to consumers or other businesses. Excludes natural persons originating personal communications. |
| **Communications Provider (CP)** | An entity that provides communications services (voice, SMS, RCS, OTT) to Business Originators. Includes CPaaS platforms, aggregators, SIP trunk providers, messaging APIs, and wholesale voice carriers. |
| **Originating Carrier** | The network operator whose infrastructure first places a communication onto the PSTN, mobile network, or internet backbone on behalf of a Business Originator or CP. |
| **KYC (Know Your Customer)** | The process of verifying the identity of a Business Originator, confirming its entitlement to use claimed communications identifiers, and maintaining ongoing awareness of its communications behaviour. Distinct from financial AML KYC: telecoms KYC does not require verification of beneficial ownership except where the Authorised Vetter's risk assessment indicates it. |
| **KYT (Know Your Traffic)** | The ongoing obligation to monitor, characterise, and act on the traffic patterns generated by a vetted Business Originator, to detect divergence from declared use and patterns associated with fraud or abuse. KYT is the temporal extension of KYC — not a one-time event but a continuous obligation. |
| **RTU (Right to Use)** | The entitlement of a Business Originator to present a specific identifier — telephone number, SMS Sender ID, RCS Agent ID, or display name — as the origin of its communications. RTU verification is a distinct step within the KYC process and must be re-confirmed whenever a new identifier is claimed or assigned. |
| **Authorised Vetter (AV)** | An entity accredited by the GSMA (or by a GSMA-recognised National Accreditation Body) to perform OVC vetting on behalf of communications providers. An AV conducts the KYC process, confirms RTU, and issues OVC Vetting Credentials to Business Originators who have successfully completed vetting. |
| **OVC Vetting Credential (OVC-VC)** | A digitally signed verifiable credential, issued by an Authorised Vetter, attesting that a named Business Originator has been vetted to a specified Vetting Level, has the right to use specific communications identifiers, and is subject to ongoing KYT monitoring at a defined frequency. |
| **Vetting Level** | The depth of verification performed, as defined in Section 5. Three levels are defined: Entity Verified (L1), Authorised Originator (L2), and Audited Originator (L3). |
| **Relying Carrier** | An Originating Carrier or CP that accepts an OVC-VC as evidence of a Business Originator's vetting status and relies on it when making decisions about STIR/SHAKEN attestation level, A2P message acceptance, or service provision. |

---

## 4. Governance Hierarchy

### 4.1 GSMA as Root of Trust

The GSMA is designated as the global root of trust for the OVC KYC framework. This designation reflects:

- **Existing mandate**: The GSMA Fraud and Security Group (FASG) is the recognised international body for telecoms fraud and identity assurance standards. Its membership encompasses mobile network operators in over 220 countries.
- **Existing infrastructure**: The GSMA operates the GSMA Open Gateway / Network APIs infrastructure, including Number Verification and SIM Swap APIs, which provide technically authoritative identity signals that complement OVC vetting.
- **International recognition**: The GSMA holds formal observer or participant status in the regulatory proceedings of all primary jurisdictions and engages directly with the ITU, BEREC, FCC, and Ofcom. GSMA standards are cited in regulatory instruments in all three primary jurisdictions.
- **Existing activity**: The GSMA VINES (Validating INtegrity of End-to-End Signaling) Working Group is already developing recommendations for cross-border signalling fraud prevention, specifically including mechanisms to interwork with STIR/SHAKEN. OVC's governance framework is designed to be complementary to, and extendable from, VINES outputs.
- **RCS governance**: The GSMA governs the RCS Business Messaging (RBM) specification, including the Verified Sender mechanism, which constitutes the closest existing analogue to OVC vetting for the messaging modality.

The GSMA's role as root of trust means:
1. The GSMA issues and manages the root cryptographic keys from which OVC signing keys derive
2. The GSMA accredits Authorised Vetters directly, or recognises National Accreditation Bodies which may accredit Vetters in their territories
3. The GSMA maintains the OVC Vetter Registry — the authoritative list of active, accredited Authorised Vetters
4. The GSMA defines the minimum standards for Authorised Vetter accreditation (building on the framework in this document)
5. The GSMA may revoke Authorised Vetter status and, correspondingly, invalidate that Vetter's credentials

### 4.2 National Accreditation Bodies (NABs)

In jurisdictions where a national regulatory authority or industry body is better positioned to assess Vetter accreditation, the GSMA may recognise a National Accreditation Body (NAB). A NAB operates under GSMA standards but is responsible for accrediting Vetters within its territory and for primary oversight of their compliance.

Candidate NABs by jurisdiction:
- **United States**: STI-GA (Secure Telephone Identity Governance Authority, operated by iconectiv under ATIS governance) — already governs STIR/SHAKEN certificate issuance; natural extension to vetter accreditation
- **United Kingdom**: Ofcom, or a body designated by Ofcom under the Communications Act 2003 — consistent with Ofcom's role in certifying compliance with General Conditions
- **European Union**: ENISA or a BEREC-coordinated body — consistent with BEREC's harmonisation role
- **India**: TRAI or a TRAI-designated body — consistent with TRAI's role in DLT platform governance
- **Singapore**: IMDA — consistent with IMDA's role in SSIR governance

Where a NAB has been recognised, Vetters accredited by that NAB are automatically recognised across the OVC framework as Authorised Vetters, with the GSMA as the ultimate arbiter of cross-border disputes.

### 4.3 Authorised Vetters

An Authorised Vetter is an entity accredited under the governance hierarchy to perform OVC vetting. An AV may be:

- A communications provider who has obtained accreditation to vet its own customers (self-vetting model — analogous to how large carriers implement 10DLC brand registration)
- A third-party specialist vetting service (commercial vetting bureau — the model endorsed by the NANC CATA-WG as "third-party vetting services")
- An industry body or trust service provider operating a shared vetting service for smaller carriers who cannot economically conduct independent vetting

An AV must:
- Maintain a documented vetting procedure that meets the minimum standards in Section 5
- Be subject to annual audit by the GSMA or its NAB
- Carry liability insurance or financial surety appropriate to the volume and nature of credentials issued
- Operate a credential revocation mechanism and respond to revocation requests within defined SLAs
- Maintain auditable records of vetting activities for a minimum of 5 years
- Not delegate vetting responsibilities to sub-contractors without GSMA/NAB approval

### 4.4 The Vetter Registry

The GSMA maintains the OVC Vetter Registry — a public, machine-readable list of:
- All active Authorised Vetters, with their jurisdictional scope
- The cryptographic public keys under which each AV signs credentials
- The date of their most recent accreditation audit
- Any restrictions on their accreditation scope (modality, jurisdiction, vetting level)

Any Relying Carrier can query the Vetter Registry to confirm that a credential was issued by an active, accredited Authorised Vetter at the time of issuance.

---

## 5. Vetting Process Requirements

### 5.1 Overview

OVC vetting has three defined levels, each building on the previous. The level assigned to an OVC-VC determines what reliance Relying Carriers may place on it and what STIR/SHAKEN attestation level (or equivalent) is supported.

| Level | Name | Supports | Analogues |
|---|---|---|---|
| **L1** | Entity Verified | STIR/SHAKEN B-level; service provision | India DLT PE basic registration; CTIA 10DLC Brand registration |
| **L2** | Authorised Originator | STIR/SHAKEN A-level (Full attestation); full service with verified identifiers | India DLT PE with registered Headers/Templates; Singapore SSIR |
| **L3** | Audited Originator | STIR/SHAKEN A-level with ongoing KYT confirmation; financial liability frameworks | Proposed UK Fraud Charter commitment; Singapore SRF telco qualification |

Higher levels subsume lower levels. A Business Originator holding an L3 credential implicitly holds L2 and L1.

### 5.2 Level 1 — Entity Verified

**Purpose**: Establish that the Business Originator is a real, identifiable legal entity.

**Minimum information to be collected and verified:**

| Element | Verification method |
|---|---|
| Legal entity name | Document verification — certificate of incorporation, company register entry, or equivalent |
| Registered address / principal place of business | Document verification — official incorporation record or utility/tax document |
| Jurisdiction of incorporation | Cross-referenced against national company register |
| Tax identification number (or equivalent) | Cross-referenced against national tax authority database where available (e.g., EIN in US, Companies House number in UK, UEN in Singapore, GSTIN in India) |
| Authorised representative name and role | Document verification — appointment letter, board resolution, or equivalent |
| Contact details for authorised representative | Verified by independent contact (email confirmation + call or video verification) |
| Nature of business / intended communications use | Declaration — not independently verified at L1 |

**Method**: The AV must verify documentation independently. Self-declaration without independent verification is insufficient for L1. Acceptable verification includes: electronic registry lookup (Companies House API, EIN lookup, ACRA BizFile, MCA21, etc.); certified document review; or confirmation via a regulated professional (solicitor, notary, CPA) that has itself performed document verification.

**Output**: L1 credential confirms identity of the Business Originator. It does not confirm entitlement to any specific identifier.

### 5.3 Level 2 — Authorised Originator

**Purpose**: Confirm that the verified entity is entitled to originate communications using the specific identifiers it claims, and that its declared communications use is plausible and consistent with its legal nature.

**Prerequisite**: L1 verification completed.

**Additional requirements:**

| Element | Verification method |
|---|---|
| Telephone number(s) to be originated | TN assignment confirmation — carrier assignment letter, number portability record, or equivalent. For each claimed number, the AV must confirm either that the number is assigned to the Business Originator by a TNSP, or that the Business Originator holds a documented authorisation from the number holder |
| SMS Sender ID / alphanumeric identifier (where claimed) | Registration confirmation against applicable Sender ID registry (SSIR for Singapore; CNMC registry for Spain from June 2026; 10DLC TCR for US; MEF SSID for other markets); or, where no registry exists, trademark/brand documentation and carrier assignment evidence |
| RCS Agent ID / OTT display name (where claimed) | GSMA RCS Verified Sender verification; WhatsApp Business API verification documentation; or equivalent platform-level brand verification |
| Communications use case declaration | Reviewed for consistency with entity type — a residential property management firm declaring outbound appointment reminders is consistent; a newly incorporated entity declaring outbound financial services calls at scale is higher risk and triggers enhanced review |
| Enhanced review triggers (any of the following mandate escalation): | High volume outbound voice; financial services impersonation risk sectors; recently incorporated entity (<12 months); overseas entity originating to domestic consumers; significant prior complaints |

**Output**: L2 credential confirms entity identity AND right-to-use of each listed identifier. The credential lists identifiers in scope; identifiers not listed are not covered.

**Identifier scope management**: When a Business Originator acquires a new number, Sender ID, or brand identifier after initial L2 vetting, it must obtain an updated or supplementary credential from the AV confirming the new identifier. The AV must perform TN Validation for each new identifier.

### 5.4 Level 3 — Audited Originator

**Purpose**: Provide ongoing KYT monitoring and periodic re-vetting, supporting reliance by Relying Carriers in regulatory environments that impose ongoing monitoring obligations and for use in financial liability frameworks (e.g., Singapore SRF, emerging UK telecoms fraud accountability regimes).

**Prerequisite**: L2 verification completed; minimum 6 months operating history with the AV.

**Additional requirements:**

| Element | Requirement |
|---|---|
| Traffic monitoring | AV must receive call/message volume reports from the Relying Carrier or CP at a frequency no less than monthly. Reports must include: total origination volume by identifier; complaint rate; flag rate from network analytics; any traceback requests received |
| Anomaly response | AV must establish a threshold system: if a Business Originator's complaint or flag rate exceeds defined thresholds, the AV must investigate within 5 business days and report findings to the Relying Carrier within 10 business days |
| Annual re-vetting | Full L2 re-verification annually, including refresh of all documentation and re-confirmation of identifier entitlements |
| Credential validity | L3 credential is valid for 12 months from date of issue; automatically expires unless renewed |
| Revocation capability | AV must be capable of revoking the L3 credential within 4 hours of a verified complaint indicating the Business Originator is conducting fraudulent origination |

**Output**: L3 credential is a time-bounded, monitored attestation that the Business Originator is an identified, authorised, and behaviourally-compliant originator as of the credential issuance date.

---

## 6. The OVC Vetting Credential

### 6.1 Credential structure

An OVC Vetting Credential is a Verifiable Credential in W3C VC 2.0 format, signed using the AV's cryptographic key (itself derived from the GSMA root). The credential contains:

| Field | Content |
|---|---|
| `credentialSubject.legalName` | The verified legal name of the Business Originator |
| `credentialSubject.jurisdiction` | The jurisdiction of incorporation |
| `credentialSubject.identifiers` | Array of identifier objects, each containing: type (TN / SenderID / RCSAgent / DisplayName), value, and confirmedRTU flag |
| `credentialSubject.vettingLevel` | L1, L2, or L3 |
| `credentialSubject.useCase` | Declared communications use case category |
| `issuer` | DID of the Authorised Vetter |
| `issuanceDate` | Date of credential issuance |
| `expirationDate` | Expiry date (L1/L2: 24 months; L3: 12 months) |
| `evidence` | Reference to the vetting evidence type used (not the evidence itself) |
| `credentialStatus` | Link to AV's revocation registry |

The OVC technical specification defines the full JSON-LD schema, signing algorithm (Ed25519 / EdDSA per OVC's KERI/ACDC underpinning), and the DID method used for both Vetter and Originator identifiers.

### 6.2 Credential presentation

A Business Originator presents its OVC-VC to a Relying Carrier at the point of service provisioning, or at the point of each communication origination (e.g., embedded in SIP signalling or as a PASSporT extension). The Relying Carrier:

1. Verifies the credential signature against the Vetter's public key from the OVC Vetter Registry
2. Confirms the Vetter is listed as active in the Vetter Registry
3. Confirms the credential has not expired and is not revoked (via the `credentialStatus` endpoint)
4. Confirms the originating identifier (CLI, Sender ID, etc.) is listed in the credential's `identifiers` array

If all four checks pass, the Relying Carrier has received sufficient assurance to:
- Assign Full (A-level) STIR/SHAKEN attestation to the call (for L2 or L3 credentials)
- Accept the A2P message for onward delivery without independent re-vetting
- Document its reliance on the OVC-VC in its Robocall Mitigation Program (for US compliance)

### 6.3 Reliance scope and limitations

An OVC-VC constitutes evidence that the Authorised Vetter performed the vetting obligations described in Section 5. It does not:
- Guarantee that the Business Originator will not subsequently conduct fraudulent origination
- Constitute a representation by the GSMA or any regulatory authority that the carrying network is compliant with any specific regulation
- Transfer liability from the Relying Carrier to the AV for traffic originating from a vetted Business Originator, except where the AV's vetting was negligently performed

A Relying Carrier that relies on an OVC-VC in good faith, verifies its authenticity against the Vetter Registry, and takes prompt action on revocation notifications has satisfied its "reasonable steps" obligation under FCC rules (47 CFR § 64.1200(n)(4)), Ofcom's Good Practice Guide standard, and EECC Article 100 RTU obligations. This reliance position requires regulatory confirmation in each primary jurisdiction (see Section 8.5).

---

## 7. Regulatory Alignment

### 7.1 United States

| OVC Framework Element | US Regulatory Obligation | Alignment |
|---|---|---|
| L1/L2 vetting | 47 CFR § 64.1200(n)(4): "affirmative, effective measures to... know its customers" | An OVC-VC from an accredited AV constitutes documented compliance with this obligation. The Robocall Mitigation Program must reference OVC-VC reliance and the AV's accreditation. |
| L2 TN/identifier confirmation | STIR/SHAKEN Full (A-level) attestation: carrier must confirm End-User's right-to-use the TN | OVC L2 credential lists confirmed TNs. Relying Carrier may rely on L2/L3 OVC-VC to support A-level attestation for calls from listed TNs, satisfying the ATIS-1000088 conditions for A-level signing. |
| L3 ongoing monitoring | 47 CFR § 64.6305(b): Robocall Mitigation Plan must describe "call analytics systems used to identify and block illegal calls" | AV's KYT monitoring under L3 constitutes a documented analytics programme. Monthly traffic reports to AV satisfy the substance of this obligation for the originator-specific component. |
| Third-party reliance | NANC CATA-WG endorses "third-party vetting services"; ATIS-1000088 contemplates "Delegate Certificates" and "Letters of Authorization" for indirect relationships | OVC-VC is the formal expression of third-party vetting and TN validation for indirect subscriber scenarios endorsed by CATA-WG. |
| Gateway provider obligations | FCC 23-18: gateway providers must "know their upstream providers" | OVC-VC held by a CP or reseller confirms that the Business Originator above them has been vetted; gateway may rely on OVC-VC for upstream providers in the chain. |

### 7.2 European Union

| OVC Framework Element | EU Regulatory Obligation | Alignment |
|---|---|---|
| L1/L2 entity and RTU verification | EECC Article 100: providers may only assign numbers to subscribers with a right to use them | OVC L2 credential provides documented evidence of RTU verification for the listed identifiers, satisfying the Article 100 obligation. |
| L2 TN/Sender ID verification | National implementations (France MAN, Spain CNMC registry, Ireland ComReg) require carrier confirmation of originator authorisation | OVC L2 credential is compatible with the evidence requirements of national implementations; specific recognition by national NRAs will be sought. |
| L3 ongoing monitoring | No EU-level KYT obligation currently; BEREC identifies this as an emerging area | OVC L3 positions operators ahead of likely future harmonised KYT obligations. |
| Cross-border recognition | BEREC BoR (25) 129 identifies lack of harmonisation as key gap; recommends stronger cross-border cooperation | OVC provides the cross-border credential mechanism that BEREC has identified as missing. |

### 7.3 United Kingdom

| OVC Framework Element | UK Regulatory Obligation | Alignment |
|---|---|---|
| L1/L2 entity verification | Ofcom Good Practice Guide Area 1: "robust due diligence checks before sub-allocating or assigning numbers" | OVC L2 vetting directly fulfils the substance of Area 1 obligations. An Ofcom-accredited AV performing OVC vetting constitutes the documented due diligence process. |
| L2 risk-based approach | Ofcom Good Practice Guide Area 2: "risk-based approach to higher-risk customers" | OVC L2 requires enhanced review for higher-risk Business Originators (high volume, financial sector, recently incorporated). This mirrors Ofcom's Area 2 expectations. |
| L2 TN/identifier confirmation | GC C6: originating provider must require customers to only use numbers they have the right to use | OVC L2 TN confirmation is the documented mechanism by which a Relying Carrier satisfies its GC C6 contractual obligation. |
| L3 ongoing monitoring | Ofcom Good Practice Guide Areas 3-5: contractual controls, ongoing monitoring, misuse response | OVC L3's monthly traffic monitoring, anomaly response, and revocation capability directly implements Areas 3-5 of the Ofcom Good Practice Guide. |
| SMS/messaging | Ofcom October 2025 consultation on mobile messaging scams (decision expected summer 2026) | OVC L2 Sender ID verification is designed to be compatible with the forthcoming mandatory Ofcom guidance on business messaging KYC. |

### 7.4 Secondary Jurisdictions

| Jurisdiction | Analogue | OVC Compatibility |
|---|---|---|
| India | TRAI TCCCPR DLT registration (PE/TM) | OVC L2 is functionally equivalent to a DLT-registered PE with confirmed headers. OVC-VC cross-recognition by TRAI is a target for bilateral engagement. |
| Singapore | IMDA SSIR + SRF | OVC L2 Sender ID verification is directly comparable to SSIR UEN-based registration. GSMA-IMDA relationship supports recognition pathway. |
| Australia | ACMA Reducing Scam Calls Code | OVC L2/L3 satisfies the "know your customer" and ongoing monitoring elements of the Code. |
| Canada | CRTC / CSTGA | OVC operates within the same STIR/SHAKEN framework as CSTGA; credential format is interoperable. |

---

## 8. Where OVC KYC Sits Within the Regulatory Landscape

### 8.1 What OVC KYC is not

The OVC KYC framework is not:
- A regulatory requirement in any jurisdiction. It is a voluntary framework that enables communications providers to satisfy their regulatory requirements in a documented, portable, and cross-territorial manner.
- A substitute for national regulatory compliance. A Relying Carrier in the US still operates under FCC rules; an OVC-VC provides evidence that it has met those rules' KYC requirements, it does not replace the FCC as the compliance authority.
- A financial AML KYC framework. It does not require beneficial ownership disclosure except where risk-based assessment warrants it. It is not a Suspicious Activity Report (SAR) mechanism. It does not create AML/CFT obligations.
- A content regulation mechanism. It does not address the content of communications, only the identity of the originating entity and its entitlement to use claimed identifiers.

### 8.2 What OVC KYC adds

The OVC KYC framework adds to the existing regulatory landscape:

1. **A portable credential**: A vetting result that can travel with a Business Originator across carriers, CPaaS layers, and jurisdictions, avoiding duplication of the vetting process at every link in the chain.

2. **A third-party vetting ecosystem**: A structure within which specialist vetting bureaus can operate, be accredited, and have their work relied upon — filling the gap that the NANC CATA-WG identified but did not specify.

3. **A cross-border identity solution**: The mechanism that the GSMA VINES Working Group is seeking to develop — a way for an international business originator to establish verifiable identity before its communications enter a national network, without requiring the receiving network to have a direct relationship with the originator or its domestic carrier.

4. **A common language**: A consistent vocabulary (Business Originator, Authorised Vetter, L1/L2/L3, OVC-VC) that can be used by carriers, regulators, law enforcement, and end users without translation across jurisdictional terminology.

5. **A liability anchor**: In jurisdictions moving toward financial liability for fraud-enabling networks (Singapore SRF, UK PSR commercial pressure, Australia SPF), the OVC-VC provides documented evidence that a carrying network exercised reasonable care in accepting traffic from an identified, vetted originator.

### 8.3 Relationship to STIR/SHAKEN

OVC KYC and STIR/SHAKEN are complementary, not competing. STIR/SHAKEN is a cryptographic call authentication framework — it attests that a carrier has a verified relationship with the calling party and that the calling number has not been altered in transit. OVC KYC provides the identity substrate that underpins STIR/SHAKEN attestation decisions:

| STIR/SHAKEN Question | OVC KYC Answer |
|---|---|
| Can the carrier issue A-level attestation? | Yes, if the Business Originator holds an OVC L2 or L3 credential with the originating TN listed |
| What does A-level attestation mean? | That the carrier has OVC-VC-verified evidence that the caller is a known entity with confirmed right-to-use that TN |
| How does a carrier know its indirect customer (reseller/VASP)? | The reseller/VASP presents its own OVC-VC confirming its identity and, in turn, evidence that its customers are OVC-vetted |
| How can an international call receive A-level attestation? | The international Business Originator holds an OVC L2 credential from an AV in its own jurisdiction; that credential is presented to the domestic gateway provider |

The "enhanced international attestation" model described in the NANC CATA-WG document — where international providers enter voluntary commercial arrangements with domestic carriers to convey attestation information — is implemented via OVC credentials.

### 8.4 Relationship to messaging frameworks

OVC KYC addresses the voice/messaging convergence gap that no single existing framework closes:

| Framework | Voice | A2P SMS | RCS | OTT |
|---|---|---|---|---|
| STIR/SHAKEN | ✓ | ✗ | ✗ | ✗ |
| CTIA 10DLC | ✗ | ✓ | ✗ | ✗ |
| GSMA RCS Verified Sender | ✗ | ✗ | ✓ | ✗ |
| Platform KYC (WhatsApp etc.) | ✗ | ✗ | ✗ | Partial |
| **OVC KYC (L2 with identifier scope)** | **✓** | **✓** | **✓** | **✓** |

OVC KYC uses the same entity verification and credential infrastructure for all modalities. The `identifiers` array in the OVC-VC may list TNs (for voice), Sender IDs (for SMS/RCS), RCS Agent IDs, and OTT display names — all confirmed by the same Authorised Vetter against the same legal entity.

### 8.5 Regulatory recognition pathway

For the OVC framework to deliver its full compliance value, regulatory bodies in each primary jurisdiction should formally recognise OVC credentials as satisfying the KYC obligations within their frameworks. The target positions are:

- **FCC**: Formal guidance that a voice service provider relying on an OVC-VC from a GSMA-accredited AV has satisfied its obligation under 47 CFR § 64.1200(n)(4); and that such reliance constitutes a "reasonable steps" defence in enforcement proceedings.
- **Ofcom**: Formal guidance that OVC vetting by an accredited AV constitutes compliance with Ofcom's Good Practice Guide on Sub-Allocated Numbers for the due diligence and RTU confirmation requirements.
- **BEREC/NRAs**: Recognition of OVC credentials as an acceptable cross-border verification mechanism under EECC Article 100, subject to national implementation.

This regulatory engagement is a community priority and requires coordination between the OVC community, GSMA, and the relevant regulatory bodies.

---

## 9. Open Questions for Community Resolution

The following questions are not resolved by this version of the framework and require community decisions before Version 1.0 is finalised:

**Q1 — Minimum identity evidence equivalence**
OVC L1 lists accepted verification methods for each jurisdiction (EIN, Companies House number, UEN). What is the equivalence table for jurisdictions not yet listed? Who maintains and updates this table as new jurisdictions are added?

**Q2 — Risk-based enhanced vetting triggers**
Section 5.3 lists enhanced review triggers (high volume, financial sector, recently incorporated, etc.). The community must specify the thresholds: what constitutes "high volume", what sectors are "financial impersonation risk", how long is "recently incorporated"?

**Q3 — Credential granularity vs. identifier scope**
Should an OVC-VC cover all of a Business Originator's identifiers in a single credential, or should separate credentials be issued per identifier? The single-credential model is simpler for relying carriers; the per-identifier model offers finer-grained revocation.

**Q4 — Revocation SLA obligations on Relying Carriers**
The framework requires AVs to revoke credentials within 4 hours for confirmed fraud. What is the obligation on Relying Carriers to check and act on revocation? STIR/SHAKEN does not specify a blocklist check SLA; OVC should.

**Q5 — AV liability**
Section 6.3 notes that reliance on a negligently-issued OVC-VC does not transfer liability from the carrier. The community must define what constitutes "negligent vetting" for AV liability purposes and whether a compensation mechanism is needed for carriers who suffer enforcement action as a result of relying on a fraudulently or negligently issued credential.

**Q6 — SME / sole trader vetting**
The framework currently contemplates legal entities. Sole traders and micro-businesses in some jurisdictions (especially in LATAM and MEA) may not have formal incorporation documents. What constitutes adequate verification for unincorporated but legitimate business originators?

**Q7 — GSMA governance commitment**
This framework designates the GSMA as root of trust. This designation requires the GSMA to accept the governance role and establish the Vetter Registry. The OVC community should initiate formal engagement with the GSMA FASG to confirm willingness and define terms.

---

## 10. Summary

The OVC KYC Governance Framework provides:

1. A **common vocabulary** for telecoms KYC, aligned to and compatible with the regulatory terminology of all primary jurisdictions
2. A **three-level vetting system** (Entity Verified / Authorised Originator / Audited Originator) that maps to regulatory obligations and STIR/SHAKEN attestation levels
3. An **Authorised Vetter model** that enables third-party vetting bureaus to operate under GSMA oversight, with credentials that can be relied upon by any carrying network
4. A **GSMA-anchored trust hierarchy** that provides global recognition without dependence on any single national regulatory infrastructure
5. A **regulatory alignment table** showing how OVC credentials satisfy existing obligations in the US, EU, and UK
6. A **cross-modal framework** that covers voice, A2P SMS, RCS, and OTT messaging with a single entity verification and credential architecture

The framework is designed to fill the gap that the NANC CATA-WG explicitly identified but could not close: a portable, third-party verifiable, internationally recognised mechanism for establishing that a business originator of communications is who it says it is and has the right to originate what it claims to originate.

---

*This document is a working draft for community review. It does not represent the position of the GSMA, FCC, Ofcom, BEREC, or any regulatory authority. Regulatory alignment statements reflect the authors' interpretation of existing obligations and are subject to confirmation by the relevant authorities.*

*Version history: v0.1 — March 2026 — Initial draft*
