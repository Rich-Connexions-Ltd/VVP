# Know Your Customer in Telecommunications: A Cross-Territorial Regulatory Reference for the Open Verifiable Communications Community

**Report date:** March 2026
**Prepared for:** Open Verifiable Communications (OVC) Community
**Primary jurisdictions:** United States, European Union, United Kingdom
**Secondary jurisdictions:** Australia, Canada, India, Singapore, Japan, South Korea, Brazil, UAE

---

## TABLE OF CONTENTS

**TIER 1: EXECUTIVE SUMMARY**
1. Purpose and Scope
2. Key Findings
3. Jurisdictional Comparison Snapshot
4. OVC Framework Implications
5. Open Questions for OVC Specification

**TIER 2: TECHNICAL REPORT**
- Part 1: Conceptual Framework
- Part 2: Regulatory Landscape — United States
- Part 3: Regulatory Landscape — European Union
- Part 4: Regulatory Landscape — United Kingdom
- Part 5: Regulatory Landscape — Secondary Jurisdictions
- Part 6: Enforcement Actions
- Part 7: Industry Self-Regulation
- Part 8: OVC Framework Implications

**Appendices**
- Appendix A: Regulatory Mapping Matrix
- Appendix B: Enforcement Action Catalogue
- Appendix C: Terminology Glossary

---

---

# TIER 1: EXECUTIVE SUMMARY

---

## 1. Purpose and Scope

This report surveys the regulatory obligations that apply to business originators of communications — and to the providers who carry their traffic — across the primary telecommunications jurisdictions relevant to the Open Verifiable Communications (OVC) community. The community is designing a consistent vetting framework for business originators that can operate across multiple territories; this report provides the authoritative regulatory baseline for that work.

The analysis covers three primary jurisdictions (United States, European Union, United Kingdom) and six secondary or comparative jurisdictions (Australia, Canada, India, Singapore, Japan, South Korea, Brazil, UAE). It addresses voice (PSTN, VoIP), A2P SMS and MMS, RCS Business Messaging, and OTT business messaging. It examines obligations at each layer of the communications provider chain: originating carriers, CPaaS resellers and sub-aggregators, transit providers, and terminating providers.

Three conceptual frameworks overlap in this space and are distinguished throughout: Know Your Customer (KYC) obligations (identity verification of the business originator), Know Your Traffic (KYT) obligations (ongoing monitoring of traffic patterns), and Right to Use (RTU) obligations (verification that an originator is authorised to use a specific number, sender ID, or brand identity). These are related but distinct, and most regulatory frameworks address all three simultaneously without explicitly separating them.

The report draws on primary regulatory instruments, enforcement records, and documented industry self-regulatory frameworks. Factual uncertainties not confirmed by primary sources are marked **[UNCERTAIN]**. Items with direct OVC design implications are flagged **[OVC NOTE]**.

---

## 2. Key Findings

**Finding 1: KYC in telecoms has a different structure from financial AML KYC, but is converging toward similar outcomes.**
Financial-sector KYC is principally concerned with individual customer identity and anti-money laundering. Telecommunications KYC is principally concerned with the right to originate communications in a given name, from a given number, with given content. Regulatory instruments in all primary jurisdictions define KYC obligations by reference to the purpose of fraud prevention and consumer protection, not anti-money laundering. However, the substantive verification steps — confirming legal entity identity, authorisation to use claimed identifiers, and ongoing monitoring of behaviour — increasingly parallel AML obligations in sophistication if not in legal basis.

**Finding 2: The United States has the most developed regulatory KYC framework for voice, but it is non-prescriptive as to method.**
Under 47 CFR § 64.1200(n)(4), all US voice service providers must take "affirmative, effective measures" to know their customers and prevent illegal origination. STIR/SHAKEN attestation levels (Full/Partial/Gateway) create a direct regulatory linkage between KYC adequacy and cryptographic identity claims. The FCC's Robocall Mitigation Database requires public filing of KYC procedures. However, the FCC has not specified a verification methodology, creating wide variance in practice and, correspondingly, in enforcement exposure. The Lingo Telecom (2024) and Telnyx (2025) cases define the floor: assigning Full attestation without having verified the subscriber's RTU to the number is itself a violation.

**Finding 3: The EU has no harmonised KYC or CLI authentication mandate — obligations exist at national level with significant variation.**
The EECC Directive creates an RTU obligation through Article 100 (providers may only assign numbers to those with a right to use them) but does not mandate specific KYC methodology. BEREC documents consistently identify lack of harmonisation as the primary gap in the European response. Eleven of fifteen EU countries surveyed by BEREC in 2025 had implemented anti-spoofing measures, most in 2024. France has the most advanced implementation (MAN/STIR/SHAKEN); Spain is introducing the EU's most advanced sender ID registration regime from June 2026.

**Finding 4: The UK has a comprehensive RTU/KYC framework for voice through GC B1 and GC C6, but has explicitly decided not to mandate STIR/SHAKEN.**
Ofcom's Good Practice Guide (2022) constitutes a detailed de facto KYC standard: due diligence before sub-allocating numbers, risk-based approach to high-risk customers, contractual controls, ongoing monitoring, and misuse response. Ofcom has opened an active enforcement programme (since February 2024) testing whether providers comply with these obligations. The decision on STIR/SHAKEN is that international gateway presentation-number blocking is a sufficient near-term approach; cryptographic authentication will be reconsidered if the threat landscape changes.

**Finding 5: India's TRAI TCCCPR is the global gold standard for prescriptive originator vetting — but it is SMS-focused and not directly portable.**
India's Distributed Ledger Technology (DLT) blockchain platform requires Principal Entity KYC (PAN, incorporation documents), header (Sender ID) registration, message template pre-approval, consent recording, and end-to-end traceability before any commercial message can be delivered. The system demonstrates what full-chain originator accountability can achieve at national scale. However, it is architecturally optimised for India's telecom market structure and would require substantial adaptation for a cross-territorial framework. The enforcement disruption during rollout (40% of SMS traffic dropped; bank OTP failures exceeding 25%) is a significant OVC design risk to manage.

**Finding 6: Singapore's SSIR demonstrates that mandatory sender ID registration with aggregator KYC can produce rapid, measurable fraud reduction.**
Singapore achieved a 70% reduction in scam SMS within three months of mandatory implementation of its SMS Sender ID Registry. The regime is notable for its clarity of obligation (aggregators must perform KYC on all senders; non-registered IDs are automatically labelled "Likely-SCAM"), its proportionality (clear fee structure, UEN-based entity verification), and its commercial consequence (Singapore is the first jurisdiction to impose telco financial liability in a scam reimbursement waterfall under the Shared Responsibility Framework). The SSIR is the closest existing analogue to an OVC originator registry for the messaging modality.

**Finding 7: Voice call originator vetting at enterprise (end-user) level is consistently weaker than messaging originator vetting in all jurisdictions.**
STIR/SHAKEN addresses origination at the carrier level — it attests that a carrier has a verified relationship with the calling party, not that the calling party's identity has been disclosed to downstream parties. No jurisdiction requires the calling business enterprise to register with a public originator registry analogous to India DLT or Singapore SSIR. This asymmetry between voice and messaging is the primary design gap for the OVC framework.

**Finding 8: Enforcement in primary jurisdictions is moving from civil penalty focus to network exclusion and criminal prosecution.**
The FCC's mass RMD removal sweeps (1,200+ providers in late 2024), network-wide blocking orders, and the first criminal indictment of a VoIP infrastructure provider (E Sampark, 2020) represent a qualitative shift. The FTC's "knowing facilitation" theory under TSR § 310.3(b) creates liability for CPaaS platforms and aggregators that continue serving known bad actors. In the UK, Ofcom's enforcement programme (opened 2024) has investigated Tismi and Primo Dialler under GC B1/C6. Commercial-contractual KYC pressure from the financial sector is creating an additional compliance driver not anchored in telecoms regulation.

**Finding 9: Industry self-regulation has raised baseline standards but consistently fails to close determined bad actor access.**
CTIA 10DLC (US A2P SMS) demonstrates that industry-managed registration with EIN verification, campaign pre-approval, and carrier filtering can materially reduce unwanted SMS at scale. However, the introduction of Authentication+ in October 2024 — requiring individual verification of brand representatives — was a direct response to fraudsters gaming the initial system by registering fake brands using legitimate EINs from public records. The GSMA's RCS Verified Sender programme and MEF's SMS SenderID Protection Registry provide analogous frameworks at international and regional scales. All self-regulatory frameworks share a common limitation: enforcement depends on commercial incentives rather than regulatory mandate.

**Finding 10: No jurisdiction has closed the international originator gap — cross-border CLI spoofing and sender ID forgery remain the dominant attack vector.**
Every enforcement action reviewed involves calls or messages injected from foreign networks using spoofed domestic identifiers. STIR/SHAKEN attests calls only within national IP networks; gateway providers receive calls from international sources with no cryptographic attestation history. EU anti-spoofing measures (Ireland, France, Germany) are network-level blocking approaches that reduce impact but do not establish positive originator identity. The OVC framework addresses precisely this gap and will need to specify how cross-border identity attestation can be achieved without depending on any single national regulatory mechanism.

---

## 3. Jurisdictional Comparison Snapshot

The following table maps primary obligation types across the primary jurisdictions. "Partial" indicates the obligation exists in some jurisdictions/modalities but not universally.

| Obligation Type | United States | European Union | United Kingdom |
|---|---|---|---|
| Statutory KYC obligation for voice providers | **Yes** (47 CFR § 64.1200(n)(4)) | **Partial** (EECC Art. 100 RTU; national implementations vary) | **Yes** (GC B1, GC C6; Ofcom GPG) |
| Mandatory STIR/SHAKEN implementation | **Yes** (all IP voice providers) | **Partial** (France MAN from Oct 2024; others none) | **No** (presentation blocking chosen over S/S) |
| CLI attestation levels with KYC linkage | **Yes** (A/B/C levels; Full requires RTU verification) | **No** (national blocking measures, not attestation) | **No** |
| Mandatory originator registry — A2P SMS | **Partial** (CTIA 10DLC — industry-mandated, not regulatory) | **Partial** (Spain from June 2026; others no) | **No** (Ofcom consulting; decision 2026) |
| KYC obligation for SMS aggregators/CSPs | **Partial** (10DLC EIN + campaign registry) | **Partial** (Spain) | **Partial** (Ofcom SMS guidance consulting) |
| Sender ID registration / brand protection | **Partial** (10DLC brand registration) | **Partial** (Spain; MEF in UK/IE market) | **Partial** (MEF SSID Registry; no mandate) |
| RTU verification obligation | **Yes** (STIR/SHAKEN Full attestation; RMD) | **Yes** (EECC Art. 100; national rules) | **Yes** (GC B1, GC C6) |
| Public filing / certification of KYC practices | **Yes** (FCC RMD — public database) | **No** | **No** (Ofcom enforcement against non-compliers) |
| Traceback cooperation obligation | **Yes** (24-hour obligation; ITG traceback) | **Partial** (BEREC recommends; limited national) | **Partial** (Ofcom GC C6; no ITG equivalent) |
| Network exclusion for non-compliant providers | **Yes** (RMD removal; blocking orders) | **Partial** (Ireland, France, Germany blocking) | **Yes** (GC C6 blocking; Ofcom enforcement) |
| Telco financial liability for scam losses | **No** | **No** | **Partial** (commercial PSR pressure; not regulatory) |
| Criminal exposure for carrier facilitation | **Yes** (wire fraud; conspiracy post-E Sampark) | **[UNCERTAIN]** | **[UNCERTAIN]** |
| RCS Business Messaging registration | **No** (industry GSMA/Google only) | **No** | **No** |
| OTT messaging business verification | **No** | **Partial** (DSA for large platforms) | **Partial** (Online Safety Act — platforms only) |

---

## 4. OVC Framework Implications

**Implication 1: The framework must satisfy minimum compliance baselines in all three primary jurisdictions simultaneously — but those baselines are non-prescriptive.**
No primary jurisdiction mandates a specific verification methodology. The US FCC requires "affirmative, effective measures"; Ofcom requires "robust due diligence"; the EECC requires RTU confirmation. An OVC originator vetting framework that can demonstrate documented identity verification, authorisation-chain confirmation, and ongoing monitoring will satisfy the substantive requirements of all three without needing to mirror any single regime's technical architecture. [OVC NOTE: The framework's documented vetting procedures should explicitly address each of the FCC best-practice elements (subscriber identity, RTU, ongoing monitoring) to ensure US compliance, which is the most demanding on process documentation.]

**Implication 2: The attestation model is the correct technical architecture for cross-territorial use.**
STIR/SHAKEN's most valuable contribution is not the US-specific implementation but the conceptual model: a carrier makes a cryptographic attestation about the verified identity relationship it holds with a calling party, at the point of origination, in a way that persists through the call chain. This model — attestation with explicit levels reflecting depth of KYC performed — is directly applicable to OVC's identity assertion layer. [OVC NOTE: OVC should define attestation levels analogous to STIR/SHAKEN A/B/C but applicable to enterprise business originators rather than carrier-to-carrier relationships, and covering all modalities (voice, SMS, RCS, OTT).]

**Implication 3: The framework needs an RTU model that covers both number-based and non-number-based identifiers.**
Every jurisdiction's RTU obligation addresses telephone number authorisation. A2P SMS frameworks (India, Singapore, US 10DLC) additionally address Sender ID / Alphanumeric ID authorisation. OVC's framework must handle voice CLI (E.164 numbers), SMS Sender IDs (alphanumeric), RCS agent IDs, and OTT display names — four distinct identifier types with different regulatory treatment in different jurisdictions. [OVC NOTE: The framework specification should define RTU verification as identifier-type-agnostic: the principle (the originator must be authorised to use the claimed identifier) applies universally; the verification method depends on identifier type.]

**Implication 4: The chain-of-custody model is essential — single-layer KYC is insufficient.**
India's DLT model requires every link (PE → TM → operator) to be registered and bound. US 10DLC requires brand, CSP, and reseller identification. UK's Ofcom Good Practice Guide explicitly addresses sub-allocation chains. A cross-territorial framework that performs KYC only at one layer (e.g., only the originating CPaaS) will not satisfy the chain-of-custody requirements of the most demanding jurisdictions. [OVC NOTE: The framework must specify KYC obligations at each layer: the business originator (equivalent to India's PE), the CPaaS/aggregator (equivalent to India's TM), and the carrying network. Obligations at each layer must be distinct and documented.]

**Implication 5: The framework should be designed to accommodate mandatory telco financial liability — an emerging global trend.**
Singapore's Shared Responsibility Framework (December 2024) is the first jurisdiction to impose mandatory reimbursement liability on telcos for scam losses attributable to network-level failures. Australia's Scams Prevention Framework (2025) creates analogous systemic duties with regulatory penalties. The UK's PSR APP fraud reimbursement regime (October 2024) is creating commercial contractual KYC pressure on telecoms aggregators via bank counterparties. These are independent data points of the same regulatory trajectory. [OVC NOTE: An OVC originator vetting certification should be designed to constitute evidence that the carrying network met its duty of care under these emerging liability regimes — i.e., the OVC certificate should be defensible in financial reimbursement dispute proceedings.]

**Implication 6: The framework must address the international originator gap that no national regulatory regime has yet closed.**
Every national framework reviewed addresses domestic originator accountability. None has successfully attributed identity to international business originators before their traffic enters a national network. This is the core problem OVC exists to solve. The framework must specify: (a) what identity evidence is required from a business originator regardless of jurisdiction; (b) how that evidence is attested and by whom; (c) how the attestation is transmitted with the communication; and (d) how a receiving network or party can verify the attestation without depending on any single national infrastructure. [OVC NOTE: This is the central design question. The answer must be infrastructure-independent, legally defensible in multiple jurisdictions, and not require any national authority to participate in real-time verification.]

---

## 5. Open Questions for OVC Specification

The following questions are not answered by the regulatory research and require OVC community decisions as definitional or design choices:

**Q1: What is the minimum identity evidence standard for OVC originator certification?**
The research shows that different jurisdictions use different anchors: EIN/tax ID (US 10DLC), PAN/incorporation documents (India DLT), UEN (Singapore SSIR), Companies House registration (UK). The OVC framework must specify: what legal entity identification evidence is sufficient; how it is verified; and how it is translated across jurisdictions (e.g., an entity incorporated in India seeking OVC certification for use in the US and EU). This is a definitional gap.

**Q2: How should the framework handle alphanumeric Sender IDs, display names, and non-number-based brand identifiers?**
Telephone number RTU has clear jurisdictional anchors. Brand/display name verification is inconsistent: India uses registered headers; Singapore uses UEN-tied Sender IDs; US 10DLC uses brand names associated with EINs. No jurisdiction provides a cross-territorial brand identity registry. The OVC framework must decide whether to create one or to federate across existing registries.

**Q3: What is the attestation lifetime and renewal model?**
STIR/SHAKEN attestation is per-call. India DLT registration is persistent until revoked. Singapore SSIR uses annual renewal. UK sub-allocation review is risk-based and ongoing. The OVC framework must specify how long an attestation remains valid, what triggers re-vetting, and what constitutes a lapse.

**Q4: How should the framework handle tiered originator categories (enterprise vs. SMB vs. individual)?**
India's PE/TM model applies identical KYC to a multinational bank and a small trader. US 10DLC distinguishes Sole Proprietors (reduced vetting, lower throughput limits). The regulatory research provides no clear consensus. OVC must decide whether to adopt tiered KYC depth based on originator scale, traffic volume, or content category.

**Q5: What liability does an OVC certification confer or extinguish?**
An OVC certificate that establishes that a business originator has been vetted to a defined standard should, in principle, provide evidentiary support for the carrying network's "reasonable steps" defence under FCC rules and Ofcom's Good Practice Guide. However, no jurisdiction has formally recognised a private certification standard as satisfying regulatory compliance. The OVC community will need to engage with regulators in primary jurisdictions — particularly the FCC and Ofcom — to determine whether and how OVC certifications will be recognised.

---

---

# TIER 2: TECHNICAL REPORT

---

## PART 1: CONCEPTUAL FRAMEWORK

### 1.1 The KYC Obligation in Telecommunications: Origins, Scope, and Divergence from Financial AML KYC

The phrase "Know Your Customer" in telecommunications derives from the financial services context, where it denotes the obligation to verify the identity of customers and assess their risk of involvement in money laundering or terrorist financing. The regulatory architecture for financial KYC — identity documents, beneficial ownership registers, transaction monitoring — is established in the EU's Anti-Money Laundering Directives (AMLD), the US Bank Secrecy Act and FATF Recommendations, and their national equivalents.

Telecommunications KYC is structurally different. The obligation in telecommunications arises from the need to: (a) ensure that a business originator of communications has a legitimate right to use the identifier it claims (the RTU obligation); (b) prevent fraudulent, spoofed, or illegal communications from being introduced into a public network; and (c) enable attribution of illegal communications to the responsible party (the traceback obligation). None of these purposes is anti-money laundering. The regulatory basis in the US is the Telephone Consumer Protection Act and TRACED Act; in the EU, the EECC; in the UK, the General Conditions of Entitlement. None of these instruments cross-reference financial KYC frameworks.

Nevertheless, the practical effect of telecommunications KYC obligations increasingly resembles financial KYC in two respects. First, the depth of identity verification required has grown substantially — from simple name-and-address collection to EIN verification (US), PAN and incorporation document verification (India), and UEN confirmation (Singapore). Second, the scope of ongoing monitoring obligations has expanded beyond identity at onboarding to include behavioural monitoring (traffic pattern analysis), whistleblowing obligations (traceback responses), and chain-of-custody documentation (who authorised whom to send on whose behalf). The terminology is different; the substantive requirements are converging.

A key structural difference remains: financial KYC is subject to prescriptive international standards (FATF Recommendations), harmonised EU-level law (AMLD6), and specific regulatory guidance from financial supervisors. Telecommunications KYC is, in all primary jurisdictions, a conduct-based obligation expressed at a high level of generality ("affirmative effective measures"; "robust due diligence"; "right to use"), leaving providers to determine their own verification methodology. This creates compliance uncertainty and the primary enforcement risk: that a provider's chosen methodology will be judged inadequate in retrospect by a regulator applying an objective reasonableness standard.

### 1.2 Know Your Traffic (KYT): A Distinct but Related Obligation

Know Your Traffic refers to the obligation to monitor, analyse, and act on traffic patterns as an ongoing operational matter, distinct from the identity verification conducted at customer onboarding. KYT obligations arise from:

- **FCC rules (US):** Robocall Mitigation Programs must describe "call analytics systems used to identify and block illegal calls"; the gateway provider must take "reasonable and effective steps" to ensure its upstream provider is not transmitting high volumes of illegal traffic on an ongoing basis; providers must respond within 24 hours to traceback requests.
- **Ofcom Good Practice Guide (UK):** Providers must conduct "ongoing monitoring of call volumes and patterns" and maintain a "misuse response process" for complaints received from Ofcom, other providers, Action Fraud, or affected organisations.
- **Australia's Reducing Scam Calls Code (2022) and Scams Prevention Framework (2025):** Telcos must monitor networks for scam call/SMS traffic, share information about identified scam traffic with other participating telcos, and report blocked scam traffic to ACMA.
- **India's TCCCPR:** The complaint threshold (5 complaints in 10 days by 2024) creates a near-real-time KYT feedback loop that triggers automatic suspension of sender registrations.

KYT differs from KYC in that it applies continuously, after onboarding, and addresses the behavioural patterns of traffic rather than the identity of the originator. For OVC purposes, KYT represents the ongoing monitoring component of the framework — the mechanism by which a certified originator's continued compliance is validated.

### 1.3 Right to Use (RTU): Number Assignment, Subscriber Authorisation, Brand Identity

The RTU concept in telecommunications has three distinct applications:

**RTU for telephone numbers:** The foundational obligation that a provider may only assign or authorise the use of a telephone number to an entity that is legally entitled to originate calls from that number. In the US, this flows from STIR/SHAKEN Level A attestation requirements: a carrier attesting Full attestation is asserting that it has verified the calling party's authorisation to use the specific CLI number. In the EU, EECC Article 100 requires that numbers may only be assigned to subscribers with a right to use them. In the UK, GC B1 and GC C6 impose analogous obligations.

**RTU for Sender IDs (alphanumeric identifiers):** The obligation that an aggregator or CPaaS may only transmit messages using a Sender ID that has been registered to and authorised by the named brand. India's TCCCPR enforces this through the Header registry. Singapore's SSIR enforces it through the UEN-tied Sender ID registry. US 10DLC enforces it through brand/campaign registration. Spain's forthcoming regime (June 2026) will enforce it through a CNMC-managed national registry.

**RTU for brand identity and display name:** The most complex dimension, where the claimed identifier is a brand name or display name rather than a number or registered ID. This is primarily relevant to RCS Business Messaging and OTT messaging for business. The GSMA's RCS Verified Sender programme addresses this by requiring that the entity submitting an RCS agent profile has authority from the named brand to do so. No regulatory regime has yet formalised brand identity RTU in the same way as number or Sender ID RTU.

### 1.4 The Relationship Between KYC, KYT, and RTU

The three obligations operate at different stages of the originator's relationship with the communications network:

| Stage | Obligation | Key question |
|---|---|---|
| Onboarding | KYC | Who is this entity? Are they a legitimate business? |
| Provisioning | RTU | Are they authorised to use the identifier they claim? |
| Operation | KYT | Are their traffic patterns consistent with declared use? |
| Post-incident | KYT + KYC | When a violation occurs, who is accountable? |

A fully compliant originator vetting framework must address all three stages. Most current regulatory frameworks address at least two of the three, but none address all three for all modalities in all primary jurisdictions simultaneously. The OVC framework's contribution is to provide that comprehensive, cross-territorial, multi-modality coverage.

### 1.5 The Communications Provider Chain and Where Obligations Sit

The following layers exist in a typical commercial communications deployment:

```
Business Originator (Brand/Enterprise)
    ↓
CPaaS / Communications Platform (e.g., Twilio, Bandwidth, Vonage)
    ↓
Sub-aggregator / Reseller
    ↓
Originating Carrier / Voice Service Provider
    ↓
Transit Provider(s)
    ↓
Terminating Carrier
    ↓
End Consumer
```

Regulatory KYC obligations attach at different layers in different jurisdictions:

- **US:** KYC obligations attach to all voice service providers (47 CFR § 64.1200(n)(4)) and specifically to gateway providers (FCC 23-18). 10DLC attaches at CPaaS and sub-aggregator levels for A2P SMS.
- **UK:** GC B1 and GC C6 attach to "Communications Providers" — which includes all entities in the chain. Ofcom's Good Practice Guide specifically addresses sub-allocation chains.
- **EU:** EECC obligations attach to providers of electronic communications services; specific national implementations vary in their chain coverage.
- **India:** TCCCPR DLT registration is required at PE (originator), TM (aggregator), and operator levels — all three must be present in the blockchain record.

[OVC NOTE: The OVC framework must specify obligations for each layer independently. A framework that only certifies business originators, without addressing aggregator obligations, will not satisfy India TCCCPR chain-of-custody requirements or Ofcom's sub-allocation Good Practice Guide.]

### 1.6 Definitional Mapping Across Jurisdictions

| Working Term | US | EU | UK | India | Singapore |
|---|---|---|---|---|---|
| Business originator | "Customer" / "Subscriber" | "End-user" | "Customer" / "Subscriber" | "Principal Entity (PE)" | "Registered Organisation" |
| Aggregator/CPaaS | "Voice Service Provider" / "Intermediate Provider" | "Provider of electronic communications services" | "Communications Provider" | "Registered Telemarketer (TM)" | "Participating Aggregator" |
| Carrier | "Voice Service Provider" / "Originating Carrier" | "Provider of publicly available telephone services" | "Communications Provider" | "Access Service Provider" | "Operator / Service Provider" |
| KYC | "Know Your Customer" (FCC) | "Right to Use verification" (EECC) | "Due diligence" (Ofcom GPG) | "KYC / Registration on DLT" | "KYC on UEN" |
| Number right-to-use | "Right to Use" (RTU) / STIR/SHAKEN Level A | "Right to Use numbers" (Art. 100) | "Right to Use" (GC B1) | "Header ownership" | "Sender ID ownership" |
| Traffic monitoring | "Call Analytics" / "Robocall Mitigation" | "Fraud prevention measures" | "Ongoing monitoring" (GPG) | "Scrubbing / DLT tracing" | "Anti-spoofing measures" |
| Identifier | CLI / Caller ID | CLI | CLI / Presentation Number | Header / Sender ID | Sender ID |

---

## PART 2: REGULATORY LANDSCAPE — UNITED STATES

### 2.1 TRACED Act and the Originator Vetting Mandate

The Telephone Robocall Abuse Criminal Enforcement and Deterrence Act (TRACED Act, Pub. L. 116-105, enacted 30 December 2019) is the principal legislative foundation for US telecommunications KYC. Its core KYC/originator vetting obligations flow through FCC implementing rules.

The TRACED Act directed the FCC to require providers to take "affirmative, effective measures" to prevent customers from using their networks to originate illegal calls; to issue rules on subscriber vetting (implemented via 47 CFR § 64.1200(n)(4)); to establish a Robocall Mitigation Database; and to establish best practices for subscriber identity verification.

**The operative rule — 47 CFR § 64.1200(n)(4):** Voice service providers must "take affirmative, effective measures to prevent new and renewing customers from using its network to originate illegal calls, including knowing its customers and exercising due diligence in ensuring that its services are not used to originate illegal traffic." Providers must establish analogous "know your upstream provider" policies for intermediate and wholesale arrangements. (Source: TRACED Act, 47 CFR Part 64)

**FCC-adopted subscriber vetting best practices (non-prescriptive):** Vet subscriber identity at the time of application, provisioning, contracting, or granting of RTU to telephone numbers; confirm the end user's RTU to the numbers they will originate calls from; for international call originators using NANP numbers, validate that the calling party is authorised to use the telephone number. The FCC has explicitly not mandated specific verification methods, creating wide variance in industry practice.

### 2.2 STIR/SHAKEN: Attestation Levels and KYC Implications

STIR/SHAKEN (Secure Telephone Identity Revisited / Signature-based Handling of Asserted information using toKENs) is a cryptographic caller ID authentication framework standardised by ATIS and mandated by the FCC under 47 CFR Part 64, Subpart HH. (Source: 47 CFR § 64.6305; ATIS-1000080)

The three attestation levels create a direct regulatory linkage between KYC adequacy and the identity claim transmitted with each call:

| Level | Name | What the originating carrier attests | KYC implication |
|---|---|---|---|
| A | Full Attestation | Carrier has a direct authenticated relationship with the customer AND has verified the customer is authorised to use the specific CLI number being transmitted | Both KYC and RTU must have been performed |
| B | Partial Attestation | Carrier has a direct authenticated relationship with the customer BUT has not established the customer's authorisation to use the specific CLI | KYC confirmed; RTU not confirmed |
| C | Gateway Attestation | Carrier has no direct authenticated relationship with the entity that originated the call | Neither KYC nor RTU confirmed; typically applied to calls from international networks |

To assign Level A attestation, a provider must have conducted KYC sufficient to establish a "direct authenticated relationship" with the customer and separately verified the RTU to the telephone number. Assigning Level A without adequate KYC is itself an FCC rule violation — this was the central allegation in the Lingo Telecom case (2024). (Source: FCC File No. EB-TCD-24-00037144)

Certificate issuance for STIR/SHAKEN is governed by the ATIS SHAKEN Governance Authority (STI-GA), which requires providers to be registered in the FCC's Robocall Mitigation Database as a prerequisite. The STI-PA (operated by Iconectiv) validates provider eligibility before issuing credentials. This creates a regulatory identity gate at the carrier level.

**ATIS-1000094 Branded Calling:** For Rich Call Data (caller name and logo display), the standard requires that all identity information be based on "vetted information" — providers cannot present calling identity data that has not been verified. This extends the KYC obligation into the display layer.

**Third-party authentication (FCC Eighth Report and Order, 2024):** When a provider uses a third-party vendor to perform STIR/SHAKEN signing, the call must be signed using the provider's own STI certificate — not the vendor's — preventing accountability gaps in the signing chain.

### 2.3 FCC Gateway Provider Rules

The FCC's Fifth Report and Order (2022) and Sixth Report and Order (FCC 23-18, 2023) extended robocall mitigation obligations specifically to gateway providers — US-based voice service providers that receive calls directly from foreign originating networks and introduce them into the US telecommunications network. (Source: FCC 23-18)

Gateway providers must: (1) maintain a Know-Your-Upstream-Provider programme (47 CFR § 64.1200(n)(4)), taking "reasonable and effective steps" to ensure upstream foreign providers are not transmitting high volumes of illegal traffic; (2) implement STIR/SHAKEN on all IP portions of their networks; (3) file in the Robocall Mitigation Database; (4) respond within 24 hours to all traceback requests from the FCC, law enforcement, or the Industry Traceback Group (ITG); and (5) block traffic from providers identified as transmitting illegal robocalls upon FCC or ITG direction.

From April 2023 onwards, other US providers are prohibited from accepting traffic from gateway providers not listed in the RMD — creating a network-exclusion mechanism for non-compliant gateways.

### 2.4 FCC Robocall Mitigation Database: KYC as Filed Practice

Every voice service provider and gateway provider must file a public certification and Robocall Mitigation Plan (RMP) in the FCC's Robocall Mitigation Database. The filing must include a description of the provider's KYC procedures, its call analytics systems, its responses to traceback requests, and any prior enforcement actions. (Source: 47 CFR § 64.6305)

The RMD performs two functions for OVC purposes: it creates a public record of each provider's stated KYC methodology (enabling comparison and gap analysis), and it creates a certification that the FCC can hold providers to in enforcement proceedings. A Robocall Mitigation Plan that is filed but not followed is worse than no plan — it establishes bad faith.

The mass RMD removal sweeps of 2024–2025 (185 providers removed in August 2024; 1,200+ in December 2024/January 2025) represent the FCC's most aggressive use of network exclusion as an enforcement tool. Removal from the RMD triggers mandatory blocking by all other US providers within a specified window, effectively terminating the removed provider's ability to route traffic on the US network.

### 2.5 CTIA 10DLC: A2P Messaging KYC

The 10DLC (10-Digit Long Code) framework governs Application-to-Person business SMS sent from standard 10-digit US numbers. It is an industry-managed framework implemented by wireless carriers (AT&T, T-Mobile, Verizon) with CTIA governance, administered through The Campaign Registry (TCR). It is not a formal FCC regulation but is the de facto mandatory standard for A2P messaging in the US. (Source: CTIA; The Campaign Registry)

**Brand registration (identity layer):** Legal business name, EIN verified against IRS/public records, business type and vertical, physical address, website URL (must display opt-in/opt-out and privacy policy), business email on company domain, phone number findable on company website, social media presence. Companies on the Russell 3000 list are pre-vetted; others require standard or enhanced vetting. TCR assigns a Trust Score (0–100) that directly controls maximum messaging throughput.

**Campaign registration (use-case layer):** Campaign/use case type, message content description, sample messages (2 required), opt-in/opt-out/help mechanisms, subscriber consent process description. Each distinct use case requires a separate campaign registration.

**Authentication+** (from 17 October 2024): A one-time brand-representative identity check requiring individual verification of the person submitting the brand registration. Introduced after fraudsters were found to register fake brand identities using legitimate EINs obtained from public records. Applies initially to public, for-profit brands.

**CSP and sub-aggregator obligations:** Campaign Service Providers (CSPs) — CPaaS platforms and SMS marketing platforms — are responsible for the accuracy of campaign registrations they submit. Sub-aggregators must include a Reseller ID during campaign registration (strictly enforced from 2025). CSPs are responsible for their resellers' compliance.

**Known limitations:** The 10DLC system has been gamed through fake brand registration, consent misrepresentation, and content-category misclassification. Authentication+ addresses one attack vector; it does not address consent quality verification or ongoing content monitoring.

### 2.6 Direction of Travel

The FCC's enforcement trajectory points to increased accountability at every layer of the call chain: the mass RMD removal sweeps, the first KYC-specific STIR/SHAKEN enforcement action (Lingo Telecom), and the 2024 NAL against Telnyx for onboarding failures establish increasingly specific standards for what constitutes adequate KYC. The FTC's "knowing facilitation" theory under TSR § 310.3(b) continues to expand through new case precedent. Criminal prosecution of VoIP infrastructure providers (E Sampark; USAO EDNY civil complaints) represents an escalating deterrent. For A2P SMS, carriers and CTIA will likely continue tightening 10DLC controls incrementally rather than moving to a formal regulatory framework in the near term.

---

## PART 3: REGULATORY LANDSCAPE — EUROPEAN UNION

### 3.1 EECC Framework: The RTU Obligation and Its Limits

The European Electronic Communications Code (Directive 2018/1972, the EECC) provides the framework for telecommunications regulation across the EU. It does not impose a prescriptive KYC methodology. Key provisions:

**Article 100 (number assignment):** "Member States shall ensure that undertakings provide telephone numbers only to subscribers who have a right to use them." This is the foundational RTU obligation — providers must ensure that the subscriber to whom a number is assigned or sub-allocated is legally entitled to use it. This is a member-state obligation to ensure (via national implementation), not a direct obligation on providers under EU law.

**Article 97 (fraud prevention):** National regulatory authorities (NRAs) may require providers to block access to numbers or services where fraud or misuse is justified. This is the basis for national CLI blocking mandates.

**Article 115 (CLI rights):** Users must be able to withhold or receive CLI. This is a user-rights provision, not an authentication mandate.

The EECC does not mandate any specific CLI authentication technology, does not require originator registration for any modality, and does not establish EU-level harmonised KYC standards for providers. This creates the primary gap in the European telecommunications regulatory landscape. (Source: EECC Directive 2018/1972)

### 3.2 BEREC and the Fragmented European Response

BEREC (Body of European Regulators for Electronic Communications) has produced two significant analytical documents on CLI spoofing and originator fraud:

**ECC Report 338 (CEPT, June 2022):** An authoritative survey of CLI spoofing in Europe, recommending mandatory CLI validation by originating service providers. Documents Norway (obligations since 2013) and Latvia as the earliest EU-area implementations. Notes STIR/SHAKEN as one technical approach but acknowledges limitations in non-SIP environments. (Source: ECC Report 338, June 2022)

**BEREC BoR (25) 129 (October 2025):** Examined 15 EU countries; found 11 had implemented measures against CLI spoofing, most adopted in 2024. Identified lack of harmonised legal frameworks as the key gap: "Without harmonisation, full potential cannot be realised." Noted that enforcement speed mismatch — regulators need months to act, criminals adapt in weeks — is a systemic problem. Assessed BEREC's 2013 "cross-border fraud process" guidelines as "largely untested" and too slow to be effective. (Source: BEREC BoR (25) 129, October 2025)

[UNCERTAIN: BEREC documents referenced as "GL 03/2020" and "GL 06/2021" on CLI authentication could not be confirmed as formal BEREC guideline instruments with binding force; BEREC's CLI work appears to be primarily advisory and workshop-based.]

The fundamental European regulatory problem is that CLI fraud is cross-border by design — calls spoofing Irish numbers originate from outside Ireland; calls spoofing French numbers come from outside France. BEREC's analysis is that national-level blocking measures reduce impact but cannot solve an inherently cross-border problem without harmonisation.

### 3.3 National Implementations

**France (ARCEP):** The most advanced EU CLI authentication implementation. ARCEP Decision 0881 (2019) requires CLI to be a dialable number with territorial verification for geographic/mobile numbers. The MAN (Mécanisme d'Authentification des Numéros) mechanism entered force July 2023; STIR/SHAKEN-based authentication for VoIP using national fixed numbers became mandatory from October 2024. From January 2026 (Decision 2025-2215), French mobile CLIs on incoming international calls where authentication cannot be confirmed will be masked. Chain-of-trust model between operators. (Source: ARCEP; Decision 2025-2215)

**Germany (BNetzA):** The TKG 2021 (effective 1 December 2022) requires blocking of calls falsely displaying emergency numbers (110/112), premium-rate numbers, or directory short codes; and blocking of calls from outside Germany displaying a German mobile CLI (except legitimate roaming). No prescriptive KYC methodology centrally mandated. (Source: TKG 2021; BNetzA)

**Ireland (ComReg):** ComReg Decision 24/24 (October 2024) imposes four mandatory blocking obligations: (1) international calls spoofing Irish geographic numbers; (2) international calls spoofing Irish mobile numbers; (3) calls using unallocated/unassigned numbers; (4) calls using Do Not Originate (DNO) registry numbers. Over 131 million scam calls blocked between February 2023 and October 2025. A fifth measure (ML voice firewall) is planned for H1 2026. (Source: ComReg Decision 24/24)

**Spain (Order TDF/149/2025):** The most advanced EU originator registration regime. From June 2025: companies may not use mobile numbers for marketing/customer service calls; operators must block spoofed/unauthorised CLIs. From June 2026: mandatory national alphanumeric sender ID registry managed by CNMC; SMS from unregistered or unvalidated aliases will be blocked. The sender ID registry is the closest EU analogue to Singapore's SSIR and India's TCCCPR header registry. (Source: Order TDF/149/2025, 12 February 2025; Law 11/2022)

**Other national measures:** Belgium (2024 Royal Decree) — block international calls using Belgian numbers. Czech Republic (CTU, July 2024) — block international calls presenting Czech CLI unless originating on national networks. Sweden (PTS, 2024) — block international calls presenting Swedish CLI. Netherlands (ACM) — voluntary cooperation approach; no mandatory CLI authentication as of 2024. (Source: BEREC BoR (25) 129)

### 3.4 The EU Sender ID Registration Gap

There is no EU-level harmonised mandatory registration or KYC requirement for A2P SMS aggregators, RCS Business Messaging providers, or OTT messaging operators. The gap is being filled at national level (Spain most advanced, with its June 2026 registry mandate), but no common framework exists. MEF's SMS SenderID Protection Registry operates as a voluntary industry solution in several EU markets (Ireland, Spain). The absence of EU-level harmonisation means that a business originator certified for A2P messaging in one EU jurisdiction may face entirely different verification requirements when seeking to send in another.

[OVC NOTE: This gap is a primary opportunity for the OVC framework — an EU-wide originator certification could satisfy the requirements of the most demanding member state (Spain from 2026) while establishing a consistent baseline across all member states.]

### 3.5 eIDAS 2.0: Limited Near-Term Relevance, Long-Term Potential

The eIDAS 2.0 Regulation (EU 2024/1183) creates the European Digital Identity (EUDI) Wallet as a harmonised framework for digital identity across EU member states. It does not impose direct obligations on telecommunications providers for CLI authentication or messaging KYC. No regulatory link between EUDI Wallet and originator identity verification in communications has been established. However, the EUDI Wallet provides a potential future technical substrate for verified identity in communications — if a business entity can prove its identity through a qualified electronic attestation of attributes (QEAA) from its national EUDI Wallet, that attestation could in principle be incorporated into an OVC originator verification process. This is long-term potential, not current regulatory requirement. (Source: Regulation EU 2024/1183)

### 3.6 Direction of Travel

The EU's direction is toward mandatory CLI authentication, harmonisation across member states, and eventually mandatory sender ID registration. BEREC BoR (25) 129 (2025) makes clear that 11 of 15 member states have now moved, and that the case for EU-level harmonisation is strong but not yet acted on by the Commission. France's advanced implementation creates a model that BEREC is likely to promote. Spain's sender ID registry creates an EU model for A2P originator registration. The EU has not yet initiated formal EECC reform to add CLI authentication or originator registration obligations, but the political and technical groundwork is being laid.

---

## PART 4: REGULATORY LANDSCAPE — UNITED KINGDOM

### 4.1 The General Conditions Framework (GC B1, GC C6)

Ofcom's General Conditions of Entitlement (GC) impose obligations on all communications providers (CPs) in the UK. Two conditions are directly relevant:

**GC B1 (Number Management):** Providers must ensure numbers are only sub-allocated or assigned to entities with a right to use them. This is the UK's primary RTU obligation. Providers must maintain records of number assignments and sub-allocations.

**GC C6 (Caller ID and Network Protection, as amended May 2023):** Providers must block calls with invalid, non-unique, or non-dialable CLI; must use Ofcom's numbering allocation data and Do Not Originate (DNO) list; must block international calls with invalid CLI; and originating providers must contractually require customers to only use numbers they have the right to use. (Source: Ofcom General Conditions; GC C6 May 2023)

### 4.2 The Right-to-Use Obligation in UK Law

Under GC B1, a UK communications provider that sub-allocates numbers to another provider or to an end-user enterprise must document the basis on which the sub-allocation is made and ensure the recipient has a legitimate right to use those numbers. "Right to Use" is not defined prescriptively in the GC — it is judged contextually. In practice, for enterprise customers, RTU documentation means contractual records showing that the customer has been assigned specific numbers for outbound calling, that those numbers are in ranges allocated to the provider by Ofcom, and that the customer has agreed to use numbers only for legitimate purposes.

GC C6's contractual requirement — originating providers must require customers by contract to use only numbers they have the right to use — creates a direct chain-of-custody obligation flowing down to the business originator level.

### 4.3 Ofcom's Good Practice Guide: KYC and KYT as Regulatory Expectation

Ofcom's Good Practice Guide on Sub-Allocated Numbers (November 2022) is the primary source of KYC and KYT expectations for UK providers. It is not a legally binding instrument but sets out what Ofcom considers best practice, and in enforcement proceedings, deviation from it will be a factor in Ofcom's assessment of whether a provider has met its GC obligations. (Source: Ofcom Good Practice Guide, November 2022)

The Guide specifies five compliance areas:

1. **Robust due diligence before sub-allocating numbers:** Verify the identity of the customer; assess the customer's use case and business model; assess the risk of number misuse given the customer's sector, size, and call volume.

2. **Risk-based approach to high-risk customers:** Apply enhanced scrutiny to customers in higher-risk categories: financial services companies (impersonation risk), overseas-registered customers (reduced traceability), high-volume outbound diallers (robocall risk), call centre operators.

3. **Contractual controls:** Include suspension and termination rights in contracts; require customers to comply with Ofcom's numbering conditions; require customers to notify the provider of sub-sub-allocations.

4. **Ongoing monitoring:** Monitor call volumes and traffic patterns for anomalies consistent with number misuse; set thresholds for unusual activity that trigger investigation.

5. **Misuse response process:** Maintain a process for responding to complaints from Ofcom, other providers, Action Fraud, or affected organisations; be able to act quickly (including suspension) when misuse is identified.

[OVC NOTE: These five elements are directly analogous to the components of an OVC originator vetting framework: onboarding KYC, risk-based enhanced vetting, contractual controls, ongoing KYT monitoring, and incident response. The framework should map explicitly to each of these five elements to ensure UK compliance readiness.]

### 4.4 CLI Authentication: The Decision Not to Mandate STIR/SHAKEN

Ofcom's CLI Authentication Assessment (February 2024) examined the case for mandating STIR/SHAKEN in the UK and decided against it. Ofcom's approach is to rely on presentation-number blocking at the international gateway — blocking any international call that presents a UK telephone number as its CLI — rather than cryptographic attestation throughout the call chain. (Source: Ofcom CLI Authentication Assessment, February 2024)

The key considerations in Ofcom's decision: (1) STIR/SHAKEN addresses only IP-networked calls; a significant portion of UK voice traffic still transits TDM/PSTN segments where STIR/SHAKEN cannot be applied; (2) International gateway blocking is technically simpler and already delivering measurable results (Ofcom data show substantial blocking volumes); (3) STIR/SHAKEN would require significant infrastructure investment by providers, particularly smaller ones, for uncertain incremental benefit. Ofcom's roadmap is to monitor the situation, continue international gateway blocking, and revisit cryptographic CLI authentication if the threat landscape changes.

Ofcom's consultation on international mobile CLI blocking (July 2025, closes October 2025) suggests a decision likely in early 2026, potentially extending gateway blocking to mobile CLI. This would be Ofcom's next step on the CLI authentication trajectory.

### 4.5 The Online Safety Act and Messaging Platforms

The UK Online Safety Act 2023 applies to user-to-user messaging platforms (WhatsApp, iMessage, etc.) but explicitly excludes traditional SMS and voice calls (Schedule 1 exemption). The regulatory treatment of RCS Business Messaging under the Online Safety Act is uncertain — it depends on the technical implementation and whether RCS is characterised as a user-to-user service or a business-to-consumer service. OTT messaging platforms that are also regulated under the Online Safety Act (Meta Messenger, WhatsApp Business) face distinct obligations from traditional messaging originator KYC — the OSA focuses on harmful content and user safety, not on business originator identity. (Source: UK Online Safety Act 2023, Schedule 1)

### 4.6 The PSR APP Fraud Reimbursement Regime: Commercial KYC Pressure

The Payment Systems Regulator's APP (Authorised Push Payment) fraud reimbursement regime (PS23/4, PS24/7, effective October 2024) requires banks to reimburse victims of APP fraud up to £85,000 per claim, with the cost shared 50:50 between the sending and receiving payment service provider (PSP). The PSR has no jurisdiction over telecommunications providers. However, market commentary indicates that banks bearing reimbursement liability — where 16% of APP fraud is estimated to originate via telecommunications channels [UNCERTAIN — based on market commentary, not confirmed primary source] — are incorporating CLI verification and sender ID attestation requirements into commercial contracts with telecommunications aggregators. This creates a commercial-contractual KYC pressure that is not technically regulatory but has regulatory-equivalent effect on larger aggregators working with financial institution clients. (Source: PSR PS23/4; PS24/7)

### 4.7 Enforcement Programme and Direction of Travel

**Ofcom's enforcement programme** (opened 1 February 2024, extended October 2025): Active enforcement sweeps on GC B1/C6 compliance. Two formal investigations opened as of research date: Tismi (a Netherlands-based carrier) and Primo Dialler (VoIP/outbound dialling). No final enforcement decisions have been issued as of March 2026. Ofcom's maximum penalty for GC contravention is 10% of annual turnover. (Source: Ofcom)

**Direction of travel:**
- SMS sender ID guidance: Ofcom consultation October 2025, final decision expected summer 2026. The consultation will likely introduce mandatory KYC/KYT obligations for business messaging aggregators and potentially a formal Sender ID registration framework — analogous to MEF SSID Registry but regulatory rather than voluntary.
- RCS Business Messaging: under active regulatory consideration; regulatory treatment evolving but no specific consultation issued as of research date.
- International mobile CLI blocking: consultation July 2025; decision early 2026; likely mandatory 2026–2027.
- Telecoms Fraud Charter: voluntary commitments (November 2025) by MNOs, indicating industry willingness to move ahead of regulation.

---

## PART 5: REGULATORY LANDSCAPE — SECONDARY JURISDICTIONS

### 5.1 India — TRAI TCCCPR: The Prescriptive Originator Vetting Model

The Telecom Commercial Communications Customer Preference Regulations, 2018 (TCCCPR-2018), issued by TRAI under the Telecom Regulatory Authority of India Act 1997, with substantial amendments in 2021, 2023, 2024, and 2025, constitutes the world's most prescriptive and comprehensive regulatory originator vetting framework for A2P commercial communications. (Source: TRAI TCCCPR; TRAI amending Regulation 12 February 2025)

**Principal Entities (PEs)** are business originators: banks, e-commerce companies, financial services firms, government bodies, any enterprise sending commercial or transactional SMS. PEs must register on the DLT platform of one licensed operator (registration propagates to all via blockchain); provide KYC data including Business PAN and proof of incorporation; register all Headers (Sender IDs) they intend to use; register all Content Templates with pre-approved message formats; and bind with specific Registered Telemarketers (TMs) they authorise to send on their behalf.

**Registered Telemarketers (TMs)** are intermediaries — SMS aggregators, messaging platforms, CPaaS providers. They must register on the DLT platform, complete KYC with the operator, bind to the PEs they serve, and bind to the access providers through which they route traffic.

**The DLT (Distributed Ledger Technology) platform** is a blockchain-based ledger shared across all licensed telecom operators. Its key properties: immutable registration records; interoperability across operators; 100% message traceability (every message can be traced to the registered PE, header, and template); template-matching enforcement (messages not matching a registered template are blocked at the scrubbing layer); and consent registry (Digital Consent Acquisition, DCA).

**CTA Whitelisting (from September 2024):** URLs, phone numbers, and other calls-to-action embedded in SMS templates must be whitelisted on the DLT platform. Messages containing non-whitelisted CTAs are blocked. This closes the loophole of registered templates being used to embed malicious links.

**Message categorisation (from 2025):** Promotional messages are suffixed "-P"; Service messages are suffixed "-S", enabling consumers to identify message type.

**Enforcement results:** The tightened complaint threshold (5 complaints in 10 days) enables near-real-time enforcement. August 2024: TRAI issued comprehensive enforcement directions targeting unregistered telemarketers. The 2021 rollout caused major disruption (40% of SMS traffic initially dropped; some banks saw OTP failure rates exceeding 25%), demonstrating both the system's effectiveness and the operational risk of rapid implementation.

**Assessment for OVC:** India's DLT model is the most technically rigorous and comprehensive originator vetting framework in existence. Its blockchain traceability, template locking, and consent recording go substantially beyond any other jurisdiction's requirements. However, it is architecturally tightly coupled to India's specific market structure (limited number of licensed operators, mandatory DLT platform operated by those operators) and would require significant architectural adaptation for a cross-territorial framework.

### 5.2 Australia — Reducing Scam Calls Code and Scams Prevention Framework

Australia operates two complementary frameworks: the conduct-based Spam Act 2003 (consent, identification, unsubscribe obligations) and the network-level Reducing Scam Calls Code (ACMA-registered industry code, December 2020, amended 2022). No mandatory originator registration regime exists for voice or SMS as of research date. (Source: Spam Act 2003; Reducing Scam Calls Code; ACMA)

The **Scams Prevention Framework Act 2025** (passed 13 February 2025) creates a new co-regulatory architecture covering telecommunications providers, banks/financial institutions, and digital platforms. Six overarching principles apply: Governance (document policies, annual board-level certification), Prevent (reasonable steps to prevent scams), Detect (investigate suspicious activities), Report (provide ACCC with actionable scam intelligence), Disrupt (take reasonable steps to disrupt scam activities), and Respond (accessible complaints mechanism with timely resolution). (Source: Scams Prevention Framework Act 2025; Parliament of Australia)

**Enforcement example:** In December 2024, ACMA directed NetSIP to comply with the Reducing Scam Calls Code after finding it failed to share information about approximately 47,000 scam calls with other telcos and approximately 500,000 scam calls with ACMA. This is a concrete example of enforcement against inter-carrier information-sharing obligations. Total fines in 2022–23 exceeded AU$8 million across spam enforcement actions. (Source: ACMA, December 2024)

**Assessment:** Australia's framework is system-level (duties on the ecosystem as a whole) rather than prescriptive originator vetting. The SPF's duty model creates strong incentives for telcos to implement upstream originator controls but does not mandate a specific verification methodology.

### 5.3 Canada — CRTC and STIR/SHAKEN

Canada mandated STIR/SHAKEN implementation for all IP-based voice calls as a condition of service effective 30 November 2021 (CRTC 2021-123). The **Canadian Secure Token Governance Authority (CSTGA)** governs certificate access; eligibility is restricted to CRTC-registered telecommunications service providers. (Source: CRTC 2021-123; CSTGA)

Canada's CLI spoofing prohibition under the Unsolicited Telecommunications Rules (UTR) explicitly prohibits displaying fictitious, inaccurate, or misleading CLI. Companies are vicariously liable for violations by their agents or contractors. Penalties: individuals up to CAD$1,500 per call; corporations up to CAD$15,000 per call.

From October 2021 to April 2023, Canadian telcos processed 470 STIR/SHAKEN traceback requests; in 76% of cases the traceback identified either the Canadian source of the call or, for calls from outside Canada, the Canadian gateway carrier. (Source: CRTC Staff Letter, October 2023)

Canada's Anti-Spam Legislation (CASL) addresses commercial electronic messages (email, SMS) with consent, identification, and unsubscribe requirements. It does not impose originator registration or KYC on business senders. CASL enforcement: in 2022–23, the CRTC issued 5 enforcement notices and collected penalties; the CRTC's CASL annual report for 2022–23 reports ongoing investigations.

**Assessment:** Canada's STIR/SHAKEN implementation is strong and well-governed, with a clear governance authority and traceback statistics demonstrating effectiveness. A2P SMS and voice originator KYC at the enterprise level remains less developed than in India or Singapore.

### 5.4 Singapore — IMDA SMS Sender ID Registry

Singapore's SMS Sender ID Registry (SSIR), established by IMDA and operated by SGNIC, is mandatory since 31 January 2023. It is the most precise international comparator for an OVC-style business originator registry for messaging. (Source: IMDA; SGNIC SSIR)

**Registration requirements:** Organisations must hold a valid Singapore UEN; foreign businesses must register a local subsidiary or branch to obtain a UEN. Non-unique Sender IDs require additional supporting documentation. Registration fees: S$500 one-time + S$200 annual per Sender ID.

**Aggregator obligations:** Participating Aggregators (PAs) hold an IMDA Services-Based Operations licence. PAs must perform KYC on all organisations they onboard (verify UEN genuineness and bona fide nature of organisation), handle only registered Sender IDs, verify message origin from registered owners, implement access security controls, and route all SMS through the SGNIC whitelist coordination mechanism.

**Enforcement mechanism:** Non-registered Sender IDs are automatically labelled "Likely-SCAM". Messages from non-participating aggregators are blocked. Case-sensitive mismatch between registered and transmitted Sender ID triggers blocking.

**Results:** 70% reduction in scam SMS within three months of mandatory implementation. Over 1,200 organisations with 2,600+ Sender IDs registered within weeks of launch.

**Shared Responsibility Framework (SRF, effective 16 December 2024):** Singapore is the first jurisdiction globally to include telcos in a mandatory scam loss reimbursement waterfall. In the SRF's three-tier waterfall: if the bank breached its defined duties, the bank bears full reimbursement liability; if the bank met its duties but the telco failed its anti-spoofing obligations, the telco bears full liability; if both met their duties, the consumer bears the loss. (Source: MAS; IMDA SRF)

### 5.5 APAC: Japan and South Korea

**Japan (MIC):** Japan lacks a formal STIR/SHAKEN mandate or originator registration regime for voice or messaging as of research date. Japan's PSTN is undergoing transition from ISUP/TDM to SIP-based IP interconnection (target completion approximately 2025), which is a prerequisite for STIR/SHAKEN-type deployment. Japan's Telecommunications Business Act (amended 29 December 2023) requires large-scale communications providers to take technical and administrative measures to ensure network quality, but specific originator vetting requirements have not been documented in available English-language sources. [UNCERTAIN — Japanese-language primary sources may reflect more recent regulatory developments not covered by available English sources.] (Source: MIC; CEPT NaN Working Group Japan document, November 2023)

**South Korea (MSIT/KCC):** South Korea prohibits CLI spoofing and concealment under the Telecommunications Business Act and Network Act. Telemarketers must display valid callback numbers or numbers registered to the calling entity; auto-dialers require consumer consent. KISA (Korea Internet and Security Agency) operates a spam reporting centre. Korean carriers have deployed AI-based scam detection. No formal originator registration/KYC system analogous to India DLT or Singapore SSIR has been documented. [UNCERTAIN] (Source: KISA; MSIT)

### 5.6 LATAM and MEA: Brazil and UAE

**Brazil (ANATEL):** Brazil has the most active originator authentication development in LATAM. The "Verified Origin" (Origem Verificada) system is Brazil's domestically-developed STIR/SHAKEN-adjacent call origin authentication framework. ANATEL Act No. 12.712/2024 establishes that telecommunications providers and users must identify certain calls through codes assigned by nature of call. ANATEL has mandated that companies making more than 500,000 calls per month must adopt a call origin authentication system. The earlier mandatory 0303 prefix regime (June 2022) was reversed (Decision Order No. 103/2023) after industry progress toward Verified Origin adoption. A2P SMS requires Sender ID pre-registration and approval; Brazil's LGPD requires explicit consent before marketing SMS. [UNCERTAIN on precise implementation status of Verified Origin.] (Source: ANATEL; LGPD)

**UAE (TDRA):** Alphanumeric Sender IDs must be registered on all UAE networks through the Etisalat (e&) or du portals. Sender IDs dormant for more than 6 months are deactivated. SIM registration requires original Emirates ID biometric verification — up to 5 SIMs per operator for residents. The Hesabati initiative allows subscribers to view all numbers registered to their Emirates ID across all operators. Commercial entities must use licensed aggregators for bulk messaging. [UNCERTAIN on the specific penalty figure of AED 400,000 per non-compliant message — appears in commercial guidance; primary TDRA document not confirmed.] (Source: TDRA; IMDA comparative materials)

---

## PART 6: ENFORCEMENT ACTIONS

### 6.1 FCC Enforcement: Key Cases and Patterns

**Sumco Panama / Cox-Jones Auto Warranty (FCC 23-68, August 2023):** Over 5 billion robocalls in a three-month window. FCC imposed the largest robocall fine in history: $299,997,000 forfeiture order. Multiple US-registered shell VoIP entities were created specifically to introduce foreign-originating illegal traffic — the international gateway problem in its most acute form. Illustrated that FCC can issue network-wide blocking orders prior to formal forfeiture. [Collectability uncertain given offshore structure.] (Source: FCC Docket EB-TCD-21-00034958; FCC 23-68)

**Lingo Telecom (File No. EB-TCD-24-00037144, 2024):** The FCC's first enforcement action specifically targeting a voice service provider for violating KYC requirements under STIR/SHAKEN. Lingo applied Level A attestation to deepfake AI robocalls impersonating President Biden without adequate KYC. Proposed NAL $2,000,000; settled for $1,000,000 civil penalty plus compliance plan. Established that assigning Level A attestation without reasonable KYC verification is itself a violation, not merely a technical mislabelling. (Source: FCC File No. EB-TCD-24-00037144; Consent Decree, 21 August 2024)

**Telnyx LLC (NAL/Acct. No. 202432170009, February 2025):** Proposed $4,489,200 NAL for KYC/onboarding failures. FCC alleged Telnyx collected only name, email, address, and IP address — no telephone number — for accounts that placed fraudulent calls impersonating an FCC fraud team. No independent verification performed despite geographic anomalies (address in Canada, IP from UK). Established that collecting minimal identity data without corroboration, when anomalies are present, constitutes a KYC failure. [Matter pending as of March 2026.] (Source: FCC File No. EB-TCD-24-00037170)

**Avid Telecom / Michael D. Lansky LLC (2023):** Over 24.5 billion calls carried between December 2018 and January 2023, with over 90% lasting under 15 seconds. Avid received 329 ITG traceback complaints and did not terminate offending customer relationships. 49-state attorney general lawsuit (141 pages) filed May 2023; FCC cease-and-desist June 2023. Demonstrates that failure to act on repeated traceback complaints establishes the "knowledge" element for liability. (Source: FCC; 49-state AG coalition)

**Mass RMD Removal Sweeps (2024–2025):** August 2024: 185 providers removed for appearing in traceback records without adequate mitigation. December 2024/January 2025: 1,200+ additional providers removed for deficient certifications. This is the most significant mass enforcement action in the programme's history and represents a qualitative shift from targeted case-by-case enforcement to systemic network hygiene enforcement. (Source: FCC)

**Global UC Inc. (DA-22-1220, October 2022):** Removed from RMD for certification deficiency; all US providers directed to cease accepting traffic within two business days. First significant use of RMD removal as an enforcement tool targeting a gateway-adjacent provider. Later reinstated upon remediation — illustrating FCC preference for compliance-willing providers. (Source: FCC DA-22-1220)

### 6.2 FTC Enforcement: Knowing Facilitation Liability

The FTC's primary tool against telecom/VoIP facilitators is the Telemarketing Sales Rule (TSR), 16 CFR Part 310, specifically § 310.3(b): "It is a deceptive telemarketing act or practice... for a person to provide substantial assistance or support to any seller or telemarketer when that person knows or consciously avoids knowing that the seller or telemarketer is engaged in any act or practice that violates... this Rule." (Source: 16 CFR Part 310)

**Key liability standard elements:** "Substantial assistance" is broadly interpreted to include VoIP termination services, autodial software, server infrastructure, or payment processing. "Knows or consciously avoids knowing" requires knowledge or wilful blindness — not strict liability. After receiving a traceback complaint, cease-and-desist letter, or regulatory warning about a specific customer's conduct, continued service provision is treated as creating knowledge. Geographic and call-pattern anomalies that go uninvestigated can constitute "conscious avoidance."

**VoIP Terminator Inc. (April 2022):** Suspended civil penalty of more than $3 million; permanent ban on providing VoIP services without automated blocking procedures. Continued providing services to foreign-originated robocall operations after receiving FTC warning letters. (Source: FTC)

**Hello Hello Miami (July 2023, Operation Stop Scam Calls):** Gateway provider introduced over 37 million illegal robocalls from more than 11 foreign telemarketing clients; continued after receiving notice of illegal use. FTC established that a foreign-traffic gateway operator is a facilitator subject to TSR § 310.3(b) substantial assistance liability. (Source: FTC Operation Stop Scam Calls, July 2023)

**Stratics Networks / Netlatitude (2023):** Wholesale SIP termination and ringless voicemail services to clients it knew (or consciously avoided knowing) were placing illegal robocalls; continued after receiving FCC cease-and-desist letter (March 19, 2021). Archetype for "knowing facilitation" liability for wholesale VoIP providers.

**NetDotSolutions / TeraMESH (September 2018):** $1.35 million joint and several judgment; activities permanently enjoined. Licensed autodial software enabling over 1 billion illegal robocalls annually. Established that a software licensor can be liable for substantial assistance even if it is not the carrier or the caller.

**FTC enforcement statistics:** Over 151 enforcement actions against companies and telemarketers for DNC, robocall, spoofed caller ID, and assisting/facilitating violations through July 2023. Operation Stop Scam Calls (July 2023) involved 48 federal and 54 state agencies. (Source: FTC)

### 6.3 Criminal Prosecutions: DOJ/FBI Actions

**E Sampark / VG-Tech Serve Private Limited (USAO N.D. Georgia, indictment unsealed November 2020):** The first criminal indictment of a VoIP infrastructure provider for serving as the technical intermediary for foreign scam call centres. From May 2015 to June 2020, E Sampark operated wholesale VoIP infrastructure for India-based call centres running Social Security, IRS, and loan scams — approximately 60 Florida servers, 130,000+ recorded scam calls, victim losses over $20 million. Charges: wire fraud, conspiracy, Computer Fraud and Abuse Act. A federal court issued a consent permanent injunction against the Florida server farm. This case established that a non-calling VoIP company with knowledge of downstream criminal use can be criminally charged. [Conviction/plea status not confirmed as of March 2026.] (Source: DOJ press release, November 2020)

**India-Based Call Centre Network (Multiple districts, February 2022):** Six India-based call centres and directors charged with wire fraud, conspiracy, and money laundering for government impersonation, tech support, and lottery scams targeting US elderly consumers. Coordinated with civil FTC/FCC actions against US-based VoIP gateway providers routing the traffic.

**Operation Stop Scam Calls (USAO D. South Dakota, 2019):** DOJ obtained emergency TROs against telecom carriers facilitating fraudulent robocalls within days — a de facto blocking mechanism outside the FCC's administrative process. USAO EDNY filed related civil complaints against telecom carriers.

### 6.4 UK and EU Enforcement

**UK:** Ofcom's enforcement programme (opened 1 February 2024) has opened formal investigations against Tismi (Netherlands-based carrier) and Primo Dialler (VoIP/outbound dialling) under GC B1 and GC C6. No final enforcement decisions have been issued as of March 2026. Ofcom's maximum penalty is 10% of annual turnover. No UK enforcement actions specifically addressing STIR/SHAKEN were identified (UK has not mandated STIR/SHAKEN). Ofcom's enforcement programme is the first systematic UK enforcement sweep against carriers for number-use compliance failures, rather than individual consumer protection enforcement.

**EU:** No EU member state enforcement actions against specific telecom companies for CLI spoofing or originator fraud were identified in the research. National patterns are network-level blocking obligations and industry codes, not company-specific monetary enforcement.

**Australia:** ACMA enforcement actions documented above (NetSIP December 2024; AU$8M+ in spam enforcement in 2022–23). Notable for enforcement against inter-carrier information-sharing obligations under the Reducing Scam Calls Code, which is a distinct category not yet seen in European enforcement.

### 6.5 Commercial-Contractual KYC Pressure from Financial Regulation

Beyond direct regulatory enforcement against telcos, commercial pressure from financial services regulation is creating an additional KYC compliance driver:

**UK PSR APP fraud reimbursement:** As noted in Part 4, banks bearing 50% of APP fraud reimbursement costs (up to £85,000/claim) are reportedly incorporating CLI verification and sender ID attestation requirements into commercial contracts with telecommunications aggregators. This is not confirmed primary source information but is noted as market commentary reflecting an emerging pattern.

**Singapore SRF:** Singapore's Shared Responsibility Framework (December 2024) creates a formal regulatory mechanism for telco financial liability — if a telco fails its anti-spoofing duties and a consumer suffers a scam loss, the telco bears the reimbursement cost. This is the first jurisdiction to convert telco KYC/KYT failures into direct financial liability in a consumer protection context.

**Australia SPF:** Australia's Scams Prevention Framework (2025) creates analogous systemic duties on telcos with penalty exposure, creating incentives for upstream originator controls even without specific mandates.

### 6.6 Liability Regime Analysis: What Standard Applies and What Protects Providers

| Jurisdiction | Instrument | Liability Standard | Key Defence |
|---|---|---|---|
| US (FCC) | 47 CFR § 64.1200(n)(4); STIR/SHAKEN rules | Negligence-adjacent: failure to take "reasonable and effective measures" | Compliant RMD filing; documented KYC programme; good-faith call analytics |
| US (FTC) | TSR § 310.3(b) | Knowledge-based: "knows or consciously avoids knowing" | No confirmed successful merits defence in VoIP facilitator cases; settlement with ability-to-pay mitigation is the pattern |
| US (DOJ Criminal) | 18 U.S.C. §§ 1343, 371 | Specific intent; knowledge of illegal purpose | No direct facilitation; lack of knowledge; no participation in criminal scheme |
| UK | GC B1, GC C6; Ofcom GPG | Conduct-based: failure to comply with GC obligations as assessed against GPG best practice | Documented compliance with GPG five areas; evidence of risk-based monitoring |
| EU (national) | National implementations of EECC | Varies by member state; generally network-level blocking obligation, not company-level KYC enforcement | |
| Singapore | SRF | Strict liability against telco if defined anti-spoofing duties are not met | Demonstrating compliance with defined IMDA anti-spoofing obligations |
| Australia | SPF 2025 | Duty of care ("reasonable steps") | Evidence of governance, prevention, detection, reporting, disruption, and response measures |

**What a documented vetting framework provides:** In FCC and Ofcom contexts, a documented, systematically applied originator vetting programme provides evidentiary support for the "reasonable steps" or "robust due diligence" defence. It does not eliminate liability but reduces the risk of penalty and, in settlement contexts, is treated as a mitigating factor. In FTC contexts, a documented programme that includes response procedures for acting on traceback complaints helps counter the "consciously avoiding knowing" element. In Singapore SRF context, compliance with IMDA-defined obligations is a binary gate.

---

## PART 7: INDUSTRY SELF-REGULATION

### 7.1 GSMA Frameworks

**GSMA FASG (Fraud and Security Group):** Maintains guidance on network-level fraud detection (SMS firewalls, signalling anomalies, SIM swap). FASG documents are largely available only to GSMA members. No single comprehensive publicly available originator KYC guideline analogous to CTIA 10DLC rules was identified. GSMA's 2023 "Mobile Ecosystem Combatting Scams" initiative produced commitments from 28 carriers (via the Global Leaders' Forum and i3 Forum) to deploy SMS firewalls at increasing fidelity. [UNCERTAIN — significant FASG output is member-restricted; there may be FS-series documents directly addressing originator vetting not publicly accessible.] (Source: GSMA; FASG)

**GSMA RCS Business Messaging — Verified Sender:** Iconectiv is designated as the GSMA Verification Authority for RCS Rich Business Messaging. The vetting process verifies that the entity submitting an RCS agent profile has authority from the named brand to do so — it is authorization-chain verification focused on brand impersonation prevention. KYC data collected: legal entity identity, business registration number or EIN, named contact with management authority, website, use case, privacy policy, opt-in/opt-out procedures. Once approved, the agent receives a verified checkmark badge valid for all future Google-managed launches. The system is designed to prevent brand impersonation; it does not constitute regulatory-grade originator vetting. (Source: GSMA RCS Verified Sender Product Feature Implementation Guideline, March 2019)

**GSMA Open Gateway — KYC Match API:** Defines a standardised API allowing businesses (e.g., financial institutions) to query whether an end-user's name, address, and date of birth match the identity data held by their mobile operator. This is a B2B identity verification service, not an originator vetting mechanism, but it demonstrates GSMA's willingness to build network identity infrastructure as a commercial service.

### 7.2 CTIA 10DLC and Campaign Registry: Model, Gaps, and Lessons

As detailed in Part 2.5, CTIA 10DLC is the US industry-managed framework for A2P business SMS. Key lessons for OVC:

**What works:** EIN-based identity anchoring creates a verifiable legal entity tie; campaign pre-registration forces use-case disclosure before sending; carrier-enforced Trust Scores create material throttling consequences for low-vetting-quality senders; reseller ID requirements create chain-of-custody visibility.

**Persistent gaps:** Fraudsters game the EIN requirement by incorporating legitimate-looking entities and registering them before committing violations — the "brand squatting" attack. Content-category misclassification remains a common evasion technique. Authentication+ (October 2024) adds individual representative verification but is new and untested at scale.

**Lessons for OVC:** A registration-based system alone is insufficient; continuous monitoring (KYT) is required. The linkage between identity verification depth and throughput limits (Trust Score model) is an effective incentive structure. Reseller chain documentation is essential but must be technically enforced, not merely contractually required.

### 7.3 MEF Global Code of Conduct

The MEF Business SMS Code of Conduct / Trust in Enterprise Messaging (TEM) framework (launched 2018) is a 10-principle self-regulatory code covering originator disclosure, sender ID accuracy, consent management, opt-out mechanisms, content standards, and anti-fraud measures. Aggregators certified under TEM must perform KYC on brands they onboard and verify the legitimacy of sender IDs. The TEM badge is voluntary; no enforcement mechanism independent of commercial reputation and carrier relationships exists. (Source: MEF)

MEF's SMS SenderID Protection Registry maps sender IDs to legitimate brand owners and enables aggregators to block or flag messages using unregistered sender IDs. Deployed in UK (January 2022), Ireland (2021/2023), Spain (2023), and Singapore (2021 — now superseded by government-mandated SSIR). The Registry is a useful cross-border tool but depends on aggregator participation and has no regulatory mandate outside of where it has been endorsed by national authorities.

### 7.4 ATIS/STI-GA SHAKEN Governance: KYC for Certificate Issuance

ATIS created the SHAKEN technical specification (ATIS-1000080.v005, November 2025) and established the STI-GA as the US STIR/SHAKEN governance authority. Iconectiv operates as the STI-PA (Policy Administrator). (Source: ATIS-1000080; STI-GA)

KYC requirements to obtain an STI certificate: (1) FCC RMD registration — the primary identity gate, tying certificate access to regulatory registration; (2) STI-PA vetting — validation of the SP's registration status, secure credential issuance (username/password plus 2FA), Certificate Signing Request (CSR) plus STI-PA token; (3) STI-GA/ATIS-1000094 attestation level obligations — explicit standards linking attestation level to the depth of KYC performed. The STI-GA explicitly states that giving C-Level attestation "where the OSP is under an FCC know your customer requirement" is inconsistent with the SP's obligations — if you are required to know your customer, you cannot legitimately give only C-attestation.

This governance model — certificate access gated by regulatory registration, with attestation levels linked to KYC obligations — is the most developed existing analogue to an OVC originator certification system for the voice carrier layer.

### 7.5 i3 Forum and One Consortium: KYC/KYT for Wholesale Interconnect

The i3 Forum is the secretariat for the **One Consortium**, a not-for-profit designed for the international communications ecosystem to cooperate with national regulatory authorities to fight unwanted/fraudulent calls and messages from abroad. Work areas include international traceback coordination, trusted trunks (carrier-to-carrier traffic origin authentication), and KYC/KYT standards for wholesale interconnect. (Source: i3 Forum; One Consortium)

i3 Forum/One Consortium's work on "trusted trunks" and wholesale interconnect KYC/KYT is directly relevant to the international originator gap. Their standards are largely member-restricted, limiting external analysis. The concept of carrier-to-carrier trust relationships governing the acceptability of traffic is an important complement to enterprise-level originator certification. [UNCERTAIN — precise scope and current version of i3 Forum KYC/KYT standards not recoverable from publicly available sources.]

### 7.6 Alignment and Gaps vs. Formal Regulation

| Framework | Jurisdiction | Scope | Regulatory backing | Key gap |
|---|---|---|---|---|
| CTIA 10DLC | US | A2P SMS | Industry-mandatory (carrier enforcement) | Voice not covered; fraud gaming |
| GSMA RCS Verified Sender | International | RCS BM | GSMA governance | Not regulatory; brand-impersonation focus only |
| MEF TEM / SSID Registry | International | A2P SMS | Voluntary (some national endorsement) | No enforcement mechanism |
| ATIS STI-GA | US | Voice (STIR/SHAKEN certs) | FCC-backed | Carrier-layer only; not enterprise originator |
| i3 One Consortium | International | Wholesale voice | Voluntary | Member-restricted; not prescriptive |
| CSTGA | Canada | Voice (STIR/SHAKEN certs) | CRTC-backed | Carrier-layer only |

The OVC framework is positioned to fill the gap that none of the above address: enterprise-level, multi-modality, cross-territorial originator identity attestation with a documented vetting process.

---

## PART 8: OVC FRAMEWORK IMPLICATIONS

### 8.1 Minimum Compliance Baseline: What a Cross-Territorial Framework Must Satisfy

To be defensible across all three primary jurisdictions simultaneously, an OVC originator vetting framework must at minimum satisfy:

**US (FCC):**
- Vet subscriber identity at onboarding (name, address, EIN or equivalent)
- Confirm RTU to the numbers/identifiers claimed
- Maintain an ongoing monitoring process responsive to traceback complaints
- Document the KYC programme in a form that can be produced in enforcement proceedings
- If assigning STIR/SHAKEN attestation: ensure Level A is only assigned where RTU has been verified

**UK (Ofcom):**
- Conduct "robust due diligence" before sub-allocating numbers or onboarding business senders
- Apply a risk-based approach to high-risk customer categories
- Include suspension/termination rights in contractual arrangements
- Monitor call volumes and traffic patterns on an ongoing basis
- Maintain a misuse response process for regulatory and third-party complaints

**EU (representative of most demanding member states):**
- Confirm RTU under EECC Article 100 for number assignment
- For A2P SMS into Spain from June 2026: ensure Sender IDs are registered in the CNMC national registry
- For voice into France: ensure STIR/SHAKEN-equivalent authentication is present for traffic traversing French networks from October 2024

**India (if routing traffic into the Indian market):**
- Register as a Telemarketer (TM) on the DLT platform
- Bind to registered Principal Entities
- Only route messages with registered headers and templates

**Singapore (if routing A2P SMS into Singapore):**
- Hold an IMDA SBO(C) licence as a Participating Aggregator
- Perform KYC on all organisations onboarded (UEN verification)
- Only handle registered Sender IDs
- Implement the SGNIC whitelist coordination mechanism

### 8.2 Recommended Forward-Looking Baseline: Future-Proofing Against Direction of Travel

Beyond current minimum compliance, the following elements reflect the direction of regulatory travel across primary jurisdictions and should be incorporated into the framework design:

| Element | Regulatory driver | Timeline |
|---|---|---|
| Enterprise-level originator registration (A2P SMS) | Spain CNMC registry (June 2026); Ofcom SMS guidance (expected 2026) | 2026 |
| Mandatory sender ID registration for UK A2P | Ofcom SMS guidance consultation (October 2025; decision summer 2026) | 2026–2027 |
| International mobile CLI blocking (UK) | Ofcom consultation July 2025; decision early 2026 | 2026–2027 |
| Telco financial liability for scam losses | Singapore SRF (active); Australia SPF (2025); UK PSR commercial pressure | Active now |
| EU harmonised CLI authentication | BEREC direction; member state convergence | 2027+ |
| RCS Business Messaging regulatory oversight | UK and EU both under consideration | 2026–2028 |

### 8.3 Liability Protection: What a Documented Vetting Framework Provides

A structured, documented OVC originator vetting certification provides the following in enforcement and litigation contexts:

1. **FCC context:** Evidence that the provider took "affirmative, effective measures" and exercised "due diligence" — the statutory standard under 47 CFR § 64.1200(n)(4). A documented programme does not guarantee non-enforcement, but it supports the good-faith/mitigation argument that has produced settlement concessions in the Lingo Telecom case.

2. **FTC context:** Evidence that the provider did not "consciously avoid knowing" of illegal use — the TSR § 310.3(b) standard. A documented vetting programme with clear response procedures for traceback complaints directly rebuts the wilful blindness element.

3. **UK context:** Evidence of compliance with Ofcom's Good Practice Guide five areas — the benchmark against which GC B1/C6 compliance is assessed in enforcement proceedings.

4. **Singapore SRF context:** Compliance with IMDA-defined anti-spoofing and KYC obligations is a binary gate in the waterfall liability model. An OVC certification aligned to IMDA requirements would constitute evidence of compliance.

5. **Contractual context:** An OVC certification provides a commercially recognised standard that counterparties (financial institutions, enterprise customers) can reference in contractual KYC requirements, displacing the need for bespoke compliance questionnaires.

### 8.4 Definitional Gaps Requiring OVC Specification Work

The following items cannot be resolved by reference to existing regulatory frameworks and require OVC community specification:

1. **Minimum identity evidence standard across jurisdictions:** What documents constitute sufficient legal entity verification for an originator located in India seeking OVC certification for use in the US and EU? How are non-EIN identity anchors (PAN, UEN, Companies House number) equivalenced?

2. **Brand/display name RTU:** How is a business originator's right to use a brand name or display name (as distinct from a registered number or Sender ID) verified? What prevents brand impersonation through OVC certification?

3. **Attestation lifetime and renewal:** How long is an OVC certification valid? What events trigger re-vetting (change of control, new jurisdiction, new modality, traffic anomaly threshold)?

4. **Tiered KYC depth:** Does OVC apply uniform KYC requirements to all originator categories, or does it tier by volume, category, or risk profile? What are the threshold criteria?

5. **OVC certificate transmission mechanism:** How is an OVC attestation transmitted with a communication? For voice, this is analogous to PASSporT in STIR/SHAKEN. For SMS and RCS, no standardised attestation transmission mechanism currently exists.

6. **Regulatory recognition:** How does OVC engage with FCC, Ofcom, IMDA, and other regulators to seek formal recognition of OVC certifications as satisfying national KYC requirements? This is the long-term lever for commercial adoption.

### 8.5 Framework Design Considerations: Obligations by Layer, Modality, and Jurisdiction

The following matrix summarises the framework design requirements by layer:

| Layer | OVC obligation | Jurisdictional anchors |
|---|---|---|
| Business originator | Legal entity KYC; identifier RTU; use-case declaration; consent framework documentation | US (10DLC brand); India (PE DLT); Singapore (SSIR registration); UK (GC B1 sub-allocation) |
| CPaaS / Aggregator | KYC of business originators onboarded; monitoring of traffic patterns; contractual controls; incident response | US (RMD; CTIA CSP obligations); UK (Ofcom GPG); India (TM DLT registration); Singapore (PA licence) |
| Originating carrier | STIR/SHAKEN attestation level aligned to KYC depth; RMD filing; traceback response | US (47 CFR § 64.6305); Canada (CSTGA); France (MAN) |
| Transit provider | Know-your-upstream-provider due diligence; participate in traceback on request | US (FCC 23-18 gateway rules); UK (GC C6) |
| Terminating carrier | Receive and act on attestation; block non-compliant traffic; report anomalies | US (RMD); UK (GC C6 blocking obligations); Ireland/Germany/France blocking mandates |

---

## APPENDIX A: REGULATORY MAPPING MATRIX

Full matrix of obligation types × provider layers × jurisdictions:

| Obligation | US | EU | UK | India | Australia | Canada | Singapore |
|---|---|---|---|---|---|---|---|
| **Voice originator KYC** |
| Legal entity ID verification at onboarding | Required (47 CFR § 64.1200(n)(4)) | Required via RTU (EECC Art. 100) | Required (GC B1; GPG) | N/A (SMS-focused) | Not prescribed | Required (UTR) | Not prescribed for voice |
| RTU verification for CLI | Required (STIR/SHAKEN Level A) | Required (EECC Art. 100; national blocking rules) | Required (GC B1, GC C6) | N/A | Not prescribed | Required (STIR/SHAKEN; UTR) | Not prescribed |
| Originator registration registry (voice) | No | No | No | No | No | No | No |
| STIR/SHAKEN / CLI authentication | Mandatory | Partial (France MAN; others no) | Not mandated | No | No | Mandatory | No |
| **A2P SMS originator KYC** |
| Legal entity ID verification for SMS senders | Industry-mandatory (10DLC EIN) | Partial (Spain June 2026) | Consulting (2025) | Mandatory (DLT PAN) | Not prescribed | Not prescribed | Mandatory (SSIR UEN) |
| Sender ID registration | Industry-mandatory (10DLC brand) | Partial (Spain June 2026; MEF voluntary) | Voluntary (MEF) | Mandatory (DLT Header) | Not prescribed | Not prescribed | Mandatory (SSIR) |
| Message template pre-approval | No | No | No | Mandatory (DLT) | No | No | No |
| Aggregator KYC obligation | Industry-mandatory (10DLC CSP) | Partial (Spain) | Consulting | Mandatory (TM DLT) | Not prescribed | Not prescribed | Mandatory (PA licence) |
| Blocking of unregistered senders | Industry-mandatory (carrier filtering) | Partial (Spain from 2026) | No | Mandatory | No | No | Mandatory |
| **Cross-cutting** |
| Public filing/certification of KYC practices | Yes (FCC RMD) | No | No | Yes (DLT blockchain — immutable) | No (SPF reporting to ACCC) | Partial (CRTC reports) | Yes (PA licence; SGNIC) |
| Traceback obligation | Yes (24-hour; ITG) | Partial | Partial (GC C6) | Yes (DLT traceability) | Yes (code reporting) | Yes (CRTC traceback) | Yes |
| Ongoing traffic monitoring (KYT) | Required (RMD programme) | Not prescribed | Required (GPG) | Yes (complaint threshold) | Required (SPF Detect) | Partial | Required |
| Network exclusion for non-compliance | Yes (RMD removal) | Partial | Yes (Ofcom enforcement) | Yes (TM suspension) | Yes (directed compliance) | Partial | Yes (PA licence revocation) |
| Telco financial liability for scam losses | No | No | No (commercial pressure only) | No | Partial (SPF; penalties) | No | Yes (SRF waterfall) |
| **Messaging — RCS / OTT** |
| RCS Business Messaging registration | No (GSMA voluntary) | No | No | No | No | No | No |
| OTT business messaging regulation | No | Partial (DSA; large platforms only) | Partial (OSA; platforms only) | No | Partial (SPF covers platforms) | No | No |

---

## APPENDIX B: ENFORCEMENT ACTION CATALOGUE

| Case | Jurisdiction | Year | Parties | Amount/Outcome | Legal basis | Key principle |
|---|---|---|---|---|---|---|
| Sumco Panama / Cox-Jones | FCC | 2022–2023 | Roy Cox Jr., Aaron Michael Jones, Sumco Panama SA, multiple shell VoIP entities | $299,997,000 forfeiture (FCC 23-68) | Truth in Caller ID Act; TCPA; spoofing rules | International gateway shell company problem; network-wide blocking before forfeiture |
| Lingo Telecom | FCC | 2024 | Lingo Telecom LLC | $1,000,000 consent decree (from $2M NAL) | 47 CFR § 64.1200(n)(4); STIR/SHAKEN rules | First KYC-specific STIR/SHAKEN enforcement; Level A attestation without RTU verification is a violation |
| Telnyx LLC | FCC | 2025 (NAL pending) | Telnyx LLC | $4,489,200 proposed NAL | 47 CFR § 64.1200(n)(4) | Minimal identity data collection without corroboration = KYC failure; geographic anomalies must trigger enhanced review |
| Avid Telecom / Lansky | FCC + 49-state AG | 2023 | Michael D. Lansky LLC, Stacey Reeves | Litigation ongoing | TCPA; Truth in Caller ID Act; state consumer protection | 329 ITG complaints ignored; failure to terminate establishes "knowledge" |
| Global UC Inc. | FCC | 2022 | Global UC Inc. | RMD removal; reinstated after cure (DA-22-1220) | 47 CFR § 64.6305 | First use of RMD removal as enforcement tool; remediation path available |
| Mass RMD removals | FCC | 2024–2025 | 1,200+ providers | Network exclusion (blocking by all US providers) | 47 CFR § 64.6305 | Systemic network hygiene enforcement; largest mass enforcement action in programme history |
| VoIP Terminator Inc. | FTC | 2022 | VoIP Terminator Inc. | $3M+ penalty (suspended); permanent injunction | TSR § 310.3(b) | "Gatekeeper failure" — continued service after FTC warning letters |
| Hello Hello Miami | FTC | 2023 | Hello Hello Miami | Injunctive relief (Operation Stop Scam Calls) | TSR § 310.3(b) | Foreign-traffic gateway operator subject to substantial assistance liability |
| Stratics Networks | FTC | 2023 | Stratics Networks, Netlatitude | Injunctive relief sought | TSR § 310.3(b) | Wholesale SIP termination for known illegal callers; FCC C&D received March 2021 |
| NetDotSolutions / TeraMESH | FTC | 2018 | James B. Christiano, NetDotSolutions | $1.35M judgment; permanent injunction | TSR § 310.3(b) | Software licensor liable for substantial assistance |
| E Sampark / VG-Tech | DOJ (Criminal) | 2020 | E Sampark Pvt. Ltd., Gaurav Gupta | Indictment; consent injunction against server farm | Wire fraud; conspiracy; CFAA | First criminal indictment of VoIP infrastructure provider; wholesale VoIP for criminal call centres |
| India-Based Call Centre Network | DOJ (Criminal) | 2022 | Six call centres and directors | Criminal charges | Wire fraud; conspiracy; money laundering | Coordinated with civil FTC/FCC actions against US gateway carriers |
| Tismi (investigation open) | Ofcom | 2024 | Tismi B.V. | Investigation open; no final decision (March 2026) | GC B1, GC C6 | Netherlands-based carrier investigated for UK CLI number use compliance |
| Primo Dialler (investigation open) | Ofcom | 2024 | Primo Dialler | Investigation open; no final decision (March 2026) | GC B1, GC C6 | VoIP/outbound dialling compliance |
| NetSIP | ACMA (Australia) | 2024 | NetSIP | Directed compliance | Reducing Scam Calls Code | Failed to share information about ~547,000 scam calls with other telcos and ACMA |
| Tabcorp Holdings | ACMA | 2022 | Tabcorp Holdings | AU$4M+ | Spam Act 2003 | Marketing SMS without consent; no unsubscribe; no sender ID |
| Commonwealth Bank | ACMA | 2023 | Commonwealth Bank of Australia | AU$3.55M | Spam Act 2003 | Required account login to unsubscribe |
| V Marketing Australia | ACMA | Recent | V Marketing Australia | AU$1.5M + AU$60K (director) | Do Not Call Register Act 2006 | 1M+ telemarketing calls to DNC numbers |
| Royal Tiger (C-CIST) | FCC | 2024 | Illum Telecom, PZ Telecom, One Eye LLC (Prince Anand, Kaushal Bhavsar) | First C-CIST threat actor designation; industry-wide blocking | TRACED Act threat designation authority | First use of Consumer Communications Information Services Threat classification; multi-jurisdiction (India, UK, UAE, US) |

---

## APPENDIX C: TERMINOLOGY GLOSSARY

**10DLC (10-Digit Long Code):** US A2P SMS framework using standard 10-digit phone numbers for business-to-consumer messaging. Requires brand and campaign registration in The Campaign Registry.

**A2P (Application-to-Person):** Messaging or calling originating from an automated application or software platform, not an individual human caller. Distinguished from P2P (Person-to-Person) traffic.

**Attestation (STIR/SHAKEN):** The claim made by an originating carrier in a STIR/SHAKEN cryptographic token about the level of verification performed on the calling party. Levels: A (Full — KYC and RTU verified), B (Partial — KYC verified, RTU not confirmed), C (Gateway — neither verified).

**BEREC (Body of European Regulators for Electronic Communications):** EU advisory body comprising national telecom regulators. Issues reports and guidelines on common regulatory approaches but has no binding enforcement power.

**Brand (10DLC context):** The registered legal business entity in The Campaign Registry. Each brand must have a verified EIN and associated business identity.

**CLI (Calling Line Identity) / Caller ID:** The telephone number presented as the originating number when a call is made. May be a "Network Number" (the technical originating number) or a "Presentation Number" (the number displayed to the recipient).

**CSTGA (Canadian Secure Token Governance Authority):** Canada's governance authority for STIR/SHAKEN certificate issuance, analogous to the US STI-GA.

**DNO (Do Not Originate):** A registry of telephone numbers that no legitimate caller should originate calls from. In the UK, Ofcom maintains a DNO list; GC C6 requires providers to block calls presenting DNO-listed numbers.

**DLT (Distributed Ledger Technology):** Blockchain-based platform used in India's TCCCPR to record PE, TM, header, template, and consent registrations. Shared across all licensed telecom operators.

**EIN (Employer Identification Number):** US IRS-issued tax identification number for business entities. The primary identity anchor in CTIA 10DLC brand registration.

**EECC (European Electronic Communications Code):** EU Directive 2018/1972 establishing the regulatory framework for electronic communications in the EU. Implemented by member states through national law.

**eIDAS 2.0 (Regulation EU 2024/1183):** EU regulation establishing the European Digital Identity Wallet (EUDI) for digital identity across EU member states. Not yet directly applicable to telecoms originator vetting.

**Gateway Provider (FCC context):** A US-based voice service provider that receives calls directly from a foreign originating network and introduces them into the US telecommunications network. Subject to specific gateway KYC and STIR/SHAKEN obligations under FCC 23-18.

**GC (General Conditions of Entitlement):** Ofcom's standard regulatory conditions that apply to all communications providers in the UK. GC B1 (number management) and GC C6 (CLI and network protection) are the primary KYC-relevant conditions.

**Header (India TCCCPR context):** The Sender ID — the alphanumeric or numeric identifier displayed to the recipient as the source of an SMS. Must be registered by the Principal Entity on the DLT platform.

**ITG (Industry Traceback Group):** USTelecom's Industry Traceback Group — the industry body that coordinates traceback requests for the US telecommunications network. Providers must respond to ITG requests within 24 hours.

**KYC (Know Your Customer):** In telecommunications: the obligation to verify the identity of a business originator and confirm its right to use claimed communications identifiers. Distinct from financial AML KYC.

**KYT (Know Your Traffic):** The obligation to monitor, analyse, and act on traffic patterns on an ongoing basis, distinct from identity verification at onboarding.

**MAN (Mécanisme d'Authentification des Numéros):** France's national CLI authentication mechanism, based on STIR/SHAKEN principles. Mandatory for VoIP using national fixed numbers from October 2024.

**NANP (North American Numbering Plan):** The telephone numbering system shared by the US, Canada, and many Caribbean nations. All NANP numbers are in the +1 country code.

**NRA (National Regulatory Authority):** A national telecommunications regulator — e.g., Ofcom (UK), FCC (US), ARCEP (France), BNetzA (Germany), ComReg (Ireland), ACMA (Australia), IMDA (Singapore), TRAI (India), CRTC (Canada).

**PASSporT (Personal Assertion Token):** The cryptographic token format used in STIR/SHAKEN to carry caller identity assertions. Defined in IETF RFC 8225.

**PE (Principal Entity — India TCCCPR context):** A business originator of commercial SMS content registered on the DLT platform.

**PSR (Payment Systems Regulator):** UK financial regulator for payment systems. Has no jurisdiction over telecoms but its APP fraud reimbursement regime creates commercial KYC pressure on telecoms aggregators.

**RCS (Rich Communication Services):** The successor messaging standard to SMS/MMS, supporting rich media and interactive features. RCS Business Messaging (RBM) is the version for enterprise-to-consumer communications.

**RMD (Robocall Mitigation Database):** FCC public database where all US voice service providers and gateway providers must file certifications of their STIR/SHAKEN implementation status and robocall mitigation programmes.

**RMP (Robocall Mitigation Program):** A provider's documented programme for preventing, identifying, and responding to illegal robocall traffic. Filed with the FCC in the RMD.

**RTU (Right to Use):** The entitlement of an entity to use a specific communications identifier (telephone number, Sender ID, brand name) as the originating identifier for communications. The RTU obligation requires providers to verify this entitlement before assigning or enabling use of an identifier.

**SAID (Self-Addressing Identifier):** In KERI/ACDC contexts, a cryptographic identifier derived from the hash of the content it identifies. Used in verifiable credential and KERI identity systems. Not currently used in mainstream telecoms KYC frameworks but relevant to the OVC technical architecture.

**SRF (Shared Responsibility Framework — Singapore):** Singapore's mandatory scam loss reimbursement waterfall covering financial institutions and telecommunications providers, effective 16 December 2024. The first jurisdiction to impose direct telco financial liability for scam losses.

**SSIR (SMS Sender ID Registry):** Singapore's mandatory registry for business SMS Sender IDs, administered by IMDA/SGNIC. Mandatory since 31 January 2023.

**STIR/SHAKEN:** Secure Telephone Identity Revisited / Signature-based Handling of Asserted information using toKENs. A cryptographic caller ID authentication framework using PASSporT tokens. Mandated in the US and Canada; implemented voluntarily in France (MAN); not mandated in UK or EU.

**STI-GA (SHAKEN Token Issuer Governance Authority):** The governance body for STIR/SHAKEN certificate issuance in the US, operating under ATIS. Iconectiv operates as the STI-PA (Policy Administrator).

**TCR (The Campaign Registry):** The private company operating the central registry for CTIA 10DLC brand and campaign registrations in the US.

**TCCCPR (Telecom Commercial Communications Customer Preference Regulations):** India's regulatory framework for commercial communications, issued by TRAI. The basis for India's DLT-based originator vetting regime.

**TM (Telemarketer / Registered Telemarketer — India TCCCPR context):** An intermediary (SMS aggregator, CPaaS platform) registered on the DLT platform and bound to Principal Entities and access service providers.

**TRACED Act:** Telephone Robocall Abuse Criminal Enforcement and Deterrence Act (Pub. L. 116-105, 2019). US federal law creating the primary regulatory framework for robocall mitigation, KYC obligations, and STIR/SHAKEN mandates.

**TSR (Telemarketing Sales Rule):** FTC regulation (16 CFR Part 310) governing telemarketing practices. § 310.3(b) creates "knowing facilitation" liability for entities providing substantial assistance to illegal telemarketers.

**UEN (Unique Entity Number):** Singapore's business registration identifier issued by ACRA. The primary identity anchor for SSIR Sender ID registration.

**UTR (Unsolicited Telecommunications Rules — Canada):** CRTC rules governing telemarketing practices, CLI spoofing prohibition, and National Do Not Call List compliance.

---

*This report was prepared for the Open Verifiable Communications (OVC) community as a regulatory reference baseline. All facts are drawn from primary regulatory instruments, enforcement records, and documented industry frameworks. Uncertain facts are marked [UNCERTAIN]. Items flagged [OVC NOTE] have direct relevance to OVC framework design decisions. The report reflects the state of the regulatory landscape as of March 2026.*
