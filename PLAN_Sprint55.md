# Sprint 55: README Update & User Manual Requirements

## Problem Statement

The project README.md has not been updated since early development. It references a flat `app/` directory structure, mentions `requirements.txt` (which doesn't exist), and omits the Issuer service, SIP services, PBX infrastructure, monitoring, CLI tools, operational scripts, and deployed environment.

There is also no consolidated "User Manual" for system operators. Documentation is fragmented across 30+ files (DEPLOYMENT.md, SIP_SIGNER.md, SIP_VERIFIER.md, CLI_USAGE.md, E2E_TEST.md, etc.). A new operator would not know where to start or how the pieces fit together.

## Goals

1. **Update README.md** — Rewrite to accurately describe the current monorepo, all services, quickstart, and link to documentation.
2. **Define User Manual requirements** — Specify the scope, audience, structure, and content requirements for a comprehensive system operator manual (`Documentation/USER_MANUAL.md`).

## Deliverables

### Deliverable 1: Updated README.md (implementation in this sprint)

Complete rewrite of README.md to reflect the current system:

- Title updated to "VVP — Verifiable Voice Protocol"
- Architecture diagram showing all 6 services and their connections
- Services table with source directories and production URLs
- Monorepo installation instructions (pip install -e for each package)
- Docker Compose local stack instructions
- CLI tools section with example commands
- Operational scripts section (health check, SIP test, bootstrap)
- Testing instructions (per-service test scripts)
- Deployment overview linking to DEPLOYMENT.md and CICD.md
- Updated project structure tree
- Complete documentation index with categorized links

### Deliverable 2: User Manual Requirements Specification

The remainder of this document defines what the User Manual must contain, its intended audience, and acceptance criteria.

---

## User Manual Requirements

### Purpose

Create `Documentation/USER_MANUAL.md` — a single comprehensive document that enables a system operator to understand, use, and troubleshoot the entire deployed VVP system without needing to discover and cross-reference dozens of separate documents.

### Audience

| Audience | Needs |
|----------|-------|
| **System Operators** | Day-to-day management of VVP infrastructure, health monitoring, troubleshooting |
| **Integration Engineers** | Connecting PBX/SBC equipment to VVP signing and verification services |
| **Test Engineers** | Validating VVP call flows end-to-end |
| **Administrators** | Managing organizations, credentials, users, and API keys |

### Relationship to Existing Documentation

The User Manual should **consolidate and reference** existing docs, not duplicate them. It serves as:
- The **entry point** for new operators
- A **workflow guide** that walks through common tasks in sequence
- A **table of contents** pointing to detailed technical docs for deep dives

Cross-referencing strategy:
- For procedural content (step-by-step tasks): include directly in the manual
- For reference content (config variables, API endpoints, deployment details): summarize key points and link to authoritative source

### Required Sections

#### 1. Introduction
- What VVP is and what problem it solves (2-3 paragraphs)
- High-level call flow: sign → attest → verify → display
- Who this manual is for

#### 2. System Architecture
- Component diagram showing all services and connections
- Component roles table (what each service does)
- Call signing flow (step-by-step)
- Call verification flow (step-by-step)
- Reference: `knowledge/architecture.md`, `Documentation/DEPLOYMENT.md`

#### 3. Deployed Infrastructure
- Service URLs table (production)
- Health endpoints table
- DNS records table
- PBX service ports
- Reference: `Documentation/DEPLOYMENT.md` (authoritative source for all infrastructure details)

#### 4. Getting Started
- How to access the Issuer UI (login methods: M365 SSO, API key, email/password)
- Dashboard overview (what it shows, where to find it)
- Verifier UI overview (no auth required)

#### 5. Organization Management
- Creating an organization (what happens automatically: AID, pseudo-LEI, LE credential, registry)
- Creating API keys (roles, permissions, copy-once warning)
- User management (creating users, assigning to orgs)
- Reference: `services/issuer/CLAUDE.md` for implementation details

#### 6. Credential Management
- Credential chain diagram (GLEIF → QVI → LE → TN Allocation → Dossier)
- Issuing a TN Allocation credential (step-by-step with E.164 format)
- Building a dossier (selecting root credential, expected credential count)
- Creating TN mappings (phone number → dossier → signing identity)
- Testing TN mappings (pre-flight check)
- Reference: `Documentation/CREATING_DOSSIERS.md`

#### 7. Call Signing (SIP Redirect)
- How signing works (flow diagram)
- PBX/SBC configuration examples (FreeSWITCH, Kamailio, Asterisk)
- Required header: `X-VVP-API-Key`
- VVP response headers explained (P-VVP-Identity, P-VVP-Passport, X-VVP-Brand-Name, etc.)
- Error responses and causes (401, 403, 404, 500)
- Rate limiting details
- Reference: `Documentation/SIP_SIGNER.md` (authoritative admin guide)

#### 8. Call Verification (SIP Verify)
- How verification works (flow diagram)
- Expected inbound headers (Identity, P-VVP-Identity)
- Result headers (X-VVP-Status, X-VVP-Brand-Name, etc.)
- Verification status meanings (VALID, INVALID, INDETERMINATE)
- Error codes table
- Reference: `Documentation/SIP_VERIFIER.md` (authoritative admin guide)

#### 9. Monitoring and Diagnostics
- Central service dashboard (URL, what it shows, auto-refresh)
- Issuer admin dashboard (stats, health, audit log)
- Audit log viewer (event types, filtering, what to look for)
- System health check script (all flags: --e2e, --timing, --local, --json, --verbose, --restart)
- SIP call test script (--test sign/verify/chain/all, --timing, --json)
- Verifier UI diagnostics (parse JWT, fetch dossier, run verification)
- SIP Redirect status endpoint (admin-authenticated /status)

#### 10. CLI Tools
- Installation instructions
- Command summary table (all `vvp` subcommands)
- Example: full verification chain via piped commands
- Reference: `Documentation/CLI_USAGE.md` (authoritative reference)

#### 11. Operational Scripts
- `scripts/system-health-check.sh` — purpose, flags, components checked, exit codes
- `scripts/sip-call-test.py` — purpose, test modes, environment variables
- `scripts/bootstrap-issuer.py` — purpose, steps performed, arguments
- `scripts/run-integration-tests.sh` — when and how to use
- `scripts/monitor-azure-deploy.sh` — deployment monitoring
- `scripts/restart-issuer.sh` — service restart

#### 12. End-to-End Testing
- Quick test procedure (2 browser tabs, register, dial 71006)
- Test phone numbers and extensions table
- VVP routing prefix explanation
- What to expect (brand display, verified badge)
- Reference: `E2E_TEST.md` (full step-by-step walkthrough)

#### 13. Troubleshooting
- Organized by category:
  - **Signing issues**: 401, 403, 404, 500, empty headers
  - **Verification issues**: SIGNATURE_INVALID, CREDENTIAL_REVOKED, TN_NOT_AUTHORIZED, etc.
  - **Infrastructure issues**: service unhealthy, witnesses down, PBX unreachable, WebRTC failures
- Debugging tools section with specific commands:
  - System health check
  - SIP trace on PBX
  - SIP Redirect log inspection
  - Audit log filtering

#### 14. Configuration Reference
- Environment variables per service (Issuer, Verifier, SIP Signer, SIP Verifier)
- Witness configuration JSON format
- PBX dialplan key files
- Reference: `Documentation/DEPLOYMENT.md` (authoritative config source)

#### 15. Quick Reference (final section)
- All service URLs in one table
- Test phone numbers
- VVP dial prefix
- Common operations table (task → where to do it)
- Key PBX files
- Related documentation links table

### Content Guidelines

1. **Procedural sections** (4-6, parts of 7-8) should use numbered step-by-step instructions
2. **Reference sections** (14-15) should use tables
3. **Diagnostic sections** (9, 13) should use symptom → cause → solution tables
4. **Architecture sections** (2) should use ASCII diagrams consistent with DEPLOYMENT.md
5. All service URLs must match `Documentation/DEPLOYMENT.md` as the single source of truth
6. All configuration variables must match the service-specific documentation
7. Use relative links (e.g., `[DEPLOYMENT.md](DEPLOYMENT.md)`) for cross-references

### Acceptance Criteria

1. A new operator can follow the manual from section 4 through section 6 and successfully:
   - Log into the Issuer UI
   - Create an organization
   - Create an API key
   - Issue a TN Allocation credential
   - Build a dossier
   - Create and test a TN mapping
2. An integration engineer can follow section 7 and configure a FreeSWITCH PBX for VVP signing
3. All service URLs and ports match the deployed infrastructure
4. All cross-references to existing docs resolve to actual files
5. The troubleshooting section covers the top 15 most common failure modes
6. The quick reference section provides all information needed for day-to-day operations on a single page
7. No content is duplicated from existing docs — only summarized and linked

### Out of Scope

- API endpoint reference (covered by `knowledge/api-reference.md` and Swagger UI)
- Developer setup and code contribution (covered by `Documentation/DEVELOPMENT.md`)
- CI/CD pipeline details (covered by `Documentation/CICD.md`)
- Protocol specification details (covered by `Documentation/VVP_Verifier_Specification_v1.5.md`)
- KERI/ACDC internals (covered by `knowledge/keri-primer.md`)

---

## Files Changed in This Sprint

| File | Action | Purpose |
|------|--------|---------|
| `README.md` | Rewrite | Updated project landing page reflecting all services |
| `PLAN_Sprint55.md` | Create | This requirements document |
| `SPRINTS.md` | Modify | Add Sprint 55 entry |

## Exit Criteria

1. README.md accurately reflects the current monorepo structure, all services, and links to all documentation
2. User Manual requirements are specified with sufficient detail for implementation
3. All links in README resolve to existing files
