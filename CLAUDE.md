# VVP Monorepo - Claude Code Instructions

## Repository Structure

This is a monorepo with shared code and separate services:

```
VVP/
├── common/                     # Shared code (installed as package)
│   └── vvp/
│       ├── core/               # config, exceptions, logging
│       ├── models/             # ACDC, dossier data models
│       ├── canonical/          # KERI/CESR serialization
│       ├── schema/             # Schema registry, validation
│       └── utils/              # Shared utilities
├── services/
│   ├── verifier/               # VVP Verifier service
│   │   ├── app/                # FastAPI application
│   │   ├── tests/              # Test suite
│   │   ├── scripts/            # Service scripts
│   │   ├── web/                # Static assets
│   │   ├── pyproject.toml      # Service dependencies
│   │   └── Dockerfile          # Container definition
│   └── issuer/                 # VVP Issuer service (Sprint 28+)
│       ├── app/                # FastAPI application
│       │   ├── api/            # API routers (health, identity)
│       │   └── keri/           # KERI integration (identity, witness)
│       ├── tests/              # Test suite
│       ├── web/                # Static assets (/create UI)
│       ├── config/             # witnesses.json
│       ├── pyproject.toml      # Service dependencies
│       └── Dockerfile          # Container definition
├── Documentation/              # Specs, checklists, archived plans
├── keripy/                     # Vendored KERI library
├── scripts/                    # Root convenience wrappers
├── pyproject.toml              # Workspace definition
└── CLAUDE.md                   # This file
```

## Permissions

The following commands are pre-authorized and do not require user confirmation:

- `git` - All git operations (add, commit, push, status, log, diff, etc.)
- `gh` - All GitHub CLI operations (run watch, pr create, issue, etc.)
- `./scripts/*` - All scripts (root wrappers and service scripts)
- `./services/verifier/scripts/*` - Verifier service scripts
- `./services/issuer/scripts/*` - Issuer service scripts
- `pytest` - Run tests directly
- `python3` / `pip3` - Python execution and package management
- `curl` - HTTP requests for deployment verification
- `uvicorn` - Running the development server
- `docker` / `docker-compose` - Container operations (build, up, down, logs)

All test-related commands are pre-authorized.

### Web Search

Web searches (WebSearch tool) are pre-authorized without confirmation, especially during plan mode research phases.

### MCP Services

The following MCP (Model Context Protocol) services are pre-authorized for use without permission:

- `vlei_KERI_knowledge_base` - All tools for KERI/vLEI documentation:
  - `keri_search` - Search KERI documents
  - `keri_explain` - Explain KERI concepts
  - `keri_get_document` - Get full document content
  - `keri_find_related` - Find related documents
  - `keri_concepts_graph` - Get concept relationships
  - `keri_gleif_context` - Extract GLEIF vLEI training context

These MCP tools provide authoritative KERI/ACDC/vLEI documentation and should be used when researching protocol details, schema definitions, or credential chain structures.

## Docker Environment

Docker Desktop is installed at `/Applications/Docker.app`. When running Docker commands from Claude Code, use the full path or set PATH:

```bash
# Option 1: Use full path
/Applications/Docker.app/Contents/Resources/bin/docker compose --profile full up -d

# Option 2: Export PATH first
export PATH="/Applications/Docker.app/Contents/Resources/bin:$PATH"
docker compose --profile full up -d
```

### Starting the Local Stack

```bash
# Start witnesses only (default)
docker compose up -d

# Start full stack (witnesses + verifier + issuer)
docker compose --profile full up -d

# View logs
docker compose logs -f

# Stop all
docker compose down
```

### Service URLs (when running)

| Service | URL | Description |
|---------|-----|-------------|
| Issuer | http://localhost:8001 | VVP Issuer API |
| Issuer UI | http://localhost:8001/create | Identity creation web UI |
| Issuer UI | http://localhost:8001/registry/ui | Registry management web UI |
| Issuer UI | http://localhost:8001/schemas/ui | Schema browser web UI |
| Verifier | http://localhost:8000 | VVP Verifier API |
| Witness (wan) | http://localhost:5642 | KERI witness HTTP |
| Witness (wil) | http://localhost:5643 | KERI witness HTTP |
| Witness (wes) | http://localhost:5644 | KERI witness HTTP |

## PBX VM Management

The VVP PBX runs on an Azure VM. **Use Azure CLI (`az`) for all PBX management** - SSH keys are not configured for the Claude Code environment.

### VM Details

| Property | Value |
|----------|-------|
| Name | `vvp-pbx` |
| Resource Group | `VVP` |
| DNS | `pbx.rcnx.io` |
| Platform | FusionPBX (FreeSWITCH) on Debian |

### Running Commands on PBX

Use `az vm run-command invoke` to execute commands remotely:

```bash
# Basic command execution
az vm run-command invoke --resource-group VVP --name vvp-pbx --command-id RunShellScript --scripts "your command here"

# Example: Check service status
az vm run-command invoke --resource-group VVP --name vvp-pbx --command-id RunShellScript --scripts "systemctl status vvp-mock-sip --no-pager"

# Example: Reload FreeSWITCH dialplan
az vm run-command invoke --resource-group VVP --name vvp-pbx --command-id RunShellScript --scripts "fs_cli -x 'reloadxml'"

# Example: View logs
az vm run-command invoke --resource-group VVP --name vvp-pbx --command-id RunShellScript --scripts "journalctl -u vvp-mock-sip -n 50 --no-pager"
```

### Deploying Files to PBX

**Important:** Stdin piping doesn't work with `az vm run-command`. Use base64 encoding:

```bash
# Deploy a file using base64 encoding
FILE_CONTENT=$(cat path/to/local/file | base64)
az vm run-command invoke --resource-group VVP --name vvp-pbx --command-id RunShellScript --scripts "echo '$FILE_CONTENT' | base64 -d > /remote/path/file"
```

### Key PBX Paths

| Path | Description |
|------|-------------|
| `/etc/freeswitch/dialplan/public.xml` | Main dialplan (VVP routes) |
| `/opt/vvp/mock/mock_sip_redirect.py` | Mock SIP signing/verification service |
| `/etc/systemd/system/vvp-mock-sip.service` | Mock service systemd unit |

### PBX Services and Ports

| Service | Port | Description |
|---------|------|-------------|
| FreeSWITCH Internal | 5060 (UDP/TCP) | SIP for registered extensions |
| FreeSWITCH External | 5080 (UDP/TCP) | External SIP (PSTN, trunks) |
| FreeSWITCH WSS | 7443 | WebRTC SIP over WebSocket |
| VVP Mock Signing | 5070 (UDP) | Mock signing service |
| VVP Mock Verification | 5071 (UDP) | Mock verification service |

### VVP Test Flow

To test VVP loopback flow (extension 1001 → signing → extension 1006):
1. Register extension 1001 via SIP.js client at `wss://pbx.rcnx.io:7443`
2. Register extension 1006 via SIP.js client
3. From 1001, dial `71006` (7 prefix triggers VVP signing flow)
4. Extension 1006 should ring with VVP brand headers

### Common Management Commands

```bash
# Restart mock SIP service
az vm run-command invoke --resource-group VVP --name vvp-pbx --command-id RunShellScript --scripts "systemctl restart vvp-mock-sip"

# Check registered extensions
az vm run-command invoke --resource-group VVP --name vvp-pbx --command-id RunShellScript --scripts "fs_cli -x 'sofia status profile internal reg'"

# View active calls
az vm run-command invoke --resource-group VVP --name vvp-pbx --command-id RunShellScript --scripts "fs_cli -x 'show calls'"

# Restart FreeSWITCH
az vm run-command invoke --resource-group VVP --name vvp-pbx --command-id RunShellScript --scripts "systemctl restart freeswitch"
```

### Local Files (services/pbx/)

| File | Purpose |
|------|---------|
| `config/public-sip.xml` | Dialplan with VVP loopback routes |
| `config/vvp-mock-sip.service` | Systemd service for mock SIP |
| `config/SETUP_SIP_WEBRTC.md` | SIP.js WebRTC setup guide |
| `test/mock_sip_redirect.py` | Mock signing/verification Python service |
| `scripts/deploy-mock-services.sh` | Deployment script (uses SSH, prefer az CLI) |

## User Commands

### "Complete"

When the user says "Complete", immediately perform all of the following without asking for permission:

1. **Update sprint status** - Update `SPRINTS.md` to reflect any work completed in the current sprint before committing.
2. **Archive sprint plan** - If this sprint had a `PLAN.md`, run the archival script:
   - `./scripts/archive-plan.sh <sprint-number> "<title>"`
   - This appends to `Documentation/PLAN_history.md`, archives to `Documentation/archive/`, and clears `REVIEW.md`
3. **Commit all changes** - Stage all modified/new files and create a descriptive commit
4. **Push to main** - Push the commit to the main branch
5. **Monitor Azure deployment** - Use `gh run watch` to monitor the GitHub Actions workflow for successful deployment

Do not ask for confirmation - execute all steps automatically.

### "Sprint N"

When the user says "Sprint N" (e.g., "Sprint 27"), begin pair programming on that sprint by following these steps:

1. **Read sprint details** - Read `SPRINTS.md` to get the sprint's:
   - Goal and deliverables
   - Key files to create/modify
   - Technical notes and dependencies
   - Exit criteria

2. **Read architectural context** - If the sprint involves the issuer service, read the plan file which contains:
   - Architectural decisions (hybrid infrastructure, separate services, monorepo structure)
   - Phase breakdown with detailed designs
   - Risk assessment and mitigations

3. **Draft the plan** - Write `PLAN.md` in the repo root with:
   - Detailed implementation plan based on sprint deliverables
   - Specific file paths, code structure, and test strategy
   - Dependencies from previous sprints

4. **Follow pair programming workflow** - As defined in the "Pair Programming Workflow" section:
   - Draft plan in `PLAN.md` with sufficient detail for review
   - Request plan review from user (they may copy to a Reviewer agent)
   - Iterate until APPROVED
   - Implement according to plan
   - Request code review
   - Archive completed plan using `scripts/archive-plan.sh`

**Sprint Definitions:** See `SPRINTS.md` for the full sprint roadmap (Sprints 1-25 were verifier implementation, Sprints 26+ are issuer implementation).

**Example workflow:**
```
User: Sprint 27
Agent: [Reads SPRINTS.md for Sprint 27 details]
Agent: [Writes PLAN.md with implementation plan for Local Witness Infrastructure]
Agent: [Requests plan review]
... pair programming cycle continues ...
```

## Running Tests

**Always use the test runner script** - it handles libsodium library paths automatically:

```bash
# From repo root (uses wrapper scripts):
./scripts/run-tests.sh                          # Run all tests
./scripts/run-tests.sh -v                       # Verbose output
./scripts/run-tests.sh tests/test_signature.py  # Run specific file
./scripts/run-tests.sh -k "test_format"         # Run tests matching pattern
./scripts/run-tests.sh --cov=app --cov-report=term-missing  # With coverage

# Or from service directory:
cd services/verifier
./scripts/run-tests.sh -v
```

### Troubleshooting libsodium

If tests fail with libsodium errors, verify the library is installed:
```bash
brew --prefix libsodium  # Should show: /opt/homebrew/opt/libsodium
```

The test script sets `DYLD_LIBRARY_PATH="/opt/homebrew/lib"` automatically. If libsodium is installed elsewhere, update the path in `services/verifier/scripts/run-tests.sh`.

## Pair Programming Workflow

This project uses a formal two-agent workflow with an **Editor** (implementing agent) and **Reviewer** (reviewing agent). The user facilitates by copying prompts between sessions.

### Guiding Principles

1. **No implementation without approved plan** - The Editor MUST NOT write code until the Reviewer has issued formal `APPROVED` verdict
2. **Sufficient detail for understanding** - Plans must explain not only WHAT is proposed but WHY
3. **Formal acceptance gates** - Each phase has explicit approval checkpoints
4. **Documented for posterity** - Accepted plans are archived in `/Documentation`
5. **Reviewer reads prior context** - The Reviewer MUST read `CHANGES.md` and `Documentation/PLAN_history.md` before reviewing, so decisions are evaluated against the full project history, not in isolation

### Working Files

| File | Purpose | Owner |
|------|---------|-------|
| `PLAN.md` | Current phase design with rationale | Editor |
| `REVIEW.md` | Reviewer feedback on plans and code | Reviewer |
| `Documentation/PLAN_PhaseN.md` | Archive of accepted plans | Both |
| `CHANGES.md` | Change log with commit SHAs | Both |

**Note:** Plans are written to `PLAN.md` in the repository root. This file is the single source of truth for the current plan — both the Editor and Reviewer read/write from it. After approval and implementation, the plan content is archived to `Documentation/` (see Phase 3).

---

### Phase 1: Planning

#### Step 1.1: Draft the Plan

The Editor writes `PLAN.md` with sufficient detail for the Reviewer to understand:

```markdown
# Phase N: [Title]

## Problem Statement
What problem are we solving? Why does it matter?

## Spec References
- §X.Y: [Quote or paraphrase the normative requirement]
- §X.Z: [Additional relevant sections]

## Current State
What exists today? What are its limitations?

## Proposed Solution

### Approach
High-level description of the solution approach and WHY this approach was chosen over alternatives.

### Alternatives Considered
| Alternative | Pros | Cons | Why Rejected |
|-------------|------|------|--------------|
| Option A | ... | ... | ... |
| Option B | ... | ... | ... |

### Detailed Design

#### Component 1: [Name]
- **Purpose**: Why this component exists
- **Location**: `path/to/file.py`
- **Interface**: Function signatures, class definitions
- **Behavior**: What it does, edge cases handled

#### Component 2: [Name]
...

### Data Flow
Describe how data moves through the system.

### Error Handling
How errors are classified, propagated, and reported.

### Test Strategy
What tests will be written and what they verify.

## Files to Create/Modify
| File | Action | Purpose |
|------|--------|---------|
| `path/to/file.py` | Create | Description |
| `path/to/other.py` | Modify | What changes |

## Open Questions
1. [Question requiring Reviewer input]
2. [Another question]

## Risks and Mitigations
| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| ... | ... | ... | ... |
```

#### Step 1.2: Request Plan Review

The Editor provides a **copyable prompt** for the Reviewer **directly in the conversation** (not just in PLAN.md). The prompt should be in a fenced code block so the user can easily copy it to the Reviewer agent:

```text
## Plan Review Request: Phase N - [Title]

You are the Reviewer in a pair programming workflow. Please review the plan in PLAN.md and provide your assessment in REVIEW.md.

PRE-CONTEXT (read before reviewing):
1. Read CHANGES.md — understand what has been built so far and recent decisions
2. Read Documentation/PLAN_history.md — understand prior architectural choices
3. These files establish the baseline the plan builds upon

PRIOR DECISIONS RELEVANT TO THIS REVIEW:
- [Decision 1 from earlier sprint and its rationale]
- [Decision 2 that constrains this plan]
- [Any relevant context the Reviewer needs]

YOUR TASK:
1. Read the pre-context files above for project history
2. Read PLAN.md thoroughly
3. Evaluate against the spec references cited
4. Assess the rationale for design decisions
5. Check consistency with prior architectural decisions
6. Answer any open questions
7. Provide verdict and feedback in REVIEW.md

EVALUATION CRITERIA:
- Does the plan correctly interpret the spec requirements?
- Is the proposed approach sound and well-justified?
- Is the plan consistent with prior decisions (or does it justify departures)?
- Are there gaps, ambiguities, or risks not addressed?
- Is the test strategy adequate?

RESPONSE FORMAT - Write to REVIEW.md with this structure:

    ## Plan Review: Phase N - [Title]

    **Verdict:** APPROVED | CHANGES_REQUESTED

    ### Spec Compliance
    [Assessment of how well the plan addresses spec requirements]

    ### Design Assessment
    [Evaluation of the proposed approach and alternatives]

    ### Findings
    - [High]: Critical issue that blocks approval
    - [Medium]: Important issue that should be addressed
    - [Low]: Suggestion for improvement (optional)

    ### Answers to Open Questions
    1. [Answer to question 1]
    2. [Answer to question 2]

    ### Required Changes (if CHANGES_REQUESTED)
    1. [Specific change required]
    2. [Another required change]

    ### Recommendations
    - [Optional improvements or future considerations]
```

#### Step 1.3: Iterate Until Approved

If Reviewer returns `CHANGES_REQUESTED`:
1. Editor revises `PLAN.md` addressing all required changes
2. Editor provides new review prompt
3. Repeat until `APPROVED`

---

### Phase 2: Implementation

#### Step 2.1: Implement According to Plan

After receiving `APPROVED` verdict:
1. Editor implements exactly as specified in the approved plan
2. Editor writes comprehensive in-line documentation:
   - Module docstrings explaining purpose and usage
   - Function docstrings with parameters, returns, and exceptions
   - Comments for non-obvious logic explaining WHY, not WHAT
3. Editor runs tests and verifies all pass
4. Editor commits the code

#### Step 2.2: Document Implementation

The Editor updates `PLAN.md` with an implementation appendix:

```text
---

## Implementation Notes

### Deviations from Plan
[Any necessary deviations and why they were required]

### Implementation Details
[Additional context discovered during implementation]

### Test Results
[pytest output showing all tests pass]

### Files Changed
| File | Lines | Summary |
|------|-------|---------|
| path/to/file.py | +150 | Created new module for X |
| tests/test_file.py | +80 | Tests for X |
```

#### Step 2.3: Request Code Review

The Editor provides a **copyable prompt** for code review:

```text
## Code Review Request: Phase N - [Title]

You are the Reviewer in a pair programming workflow. Please review the implementation and provide your assessment in REVIEW.md.

PRE-CONTEXT (read before reviewing):
1. Read CHANGES.md — understand what has been built so far
2. Read PLAN.md — the approved plan this code implements

CONTEXT: [Brief description of what was implemented]

SPEC REFERENCES:
- §X.Y: [Section name]

FILES TO REVIEW:
- path/to/file.py (created) - [purpose]
- tests/test_file.py (created) - [what it tests]

VERIFICATION: Run python3 -m pytest tests/test_xxx.py -v

KEY DESIGN DECISIONS:
1. [Decision and rationale]
2. [Another decision and rationale]

TEST RESULTS: [N passed in X.XXs]

YOUR TASK:
1. Read CHANGES.md and PLAN.md for context
2. Review all listed files for correctness and style
3. Verify implementation matches approved plan
4. Check test coverage and edge cases
5. Provide verdict and feedback in REVIEW.md

RESPONSE FORMAT - Write to REVIEW.md with this structure:

    ## Code Review: Phase N - [Title]

    **Verdict:** APPROVED | CHANGES_REQUESTED | PLAN_REVISION_REQUIRED

    ### Implementation Assessment
    [Does the code correctly implement the approved plan?]

    ### Code Quality
    [Assessment of code clarity, documentation, error handling]

    ### Test Coverage
    [Assessment of test adequacy]

    ### Findings
    - [High]: Critical issue that blocks approval
    - [Medium]: Important issue that should be fixed
    - [Low]: Minor suggestion (optional)

    ### Required Changes (if not APPROVED)
    1. [Specific change required]
    2. [Another required change]

    ### Plan Revisions (if PLAN_REVISION_REQUIRED)
    [What needs to change in the plan before re-implementation]
```

#### Step 2.4: Iterate Until Approved

- If `CHANGES_REQUESTED`: Fix issues, provide new review prompt
- If `PLAN_REVISION_REQUIRED`: Return to Phase 1 with revised plan
- If `APPROVED`: Proceed to Phase 3

---

### Phase 3: Completion and Archival

#### Step 3.1: Archive the Plan

Run the archival script to automate the mechanical steps:

```bash
./scripts/archive-plan.sh <sprint-number> "<title>"
# Example: ./scripts/archive-plan.sh 35 "Credential Issuance"
```

This script automatically:
1. Appends `PLAN.md` content to `Documentation/PLAN_history.md` under a sprint header
2. Moves `PLAN.md` to `Documentation/archive/PLAN_SprintN.md`
3. Clears `REVIEW.md` for the next phase

#### Step 3.2: Update CHANGES.md and Commit

After running the script, manually:
1. Update `CHANGES.md` with the sprint summary, files changed, and commit SHA
2. Commit all documentation updates

---

### Quick Reference: Verdicts

| Verdict | Meaning | Next Action |
|---------|---------|-------------|
| `APPROVED` | Proceed to next phase | Move forward |
| `CHANGES_REQUESTED` | Minor issues to fix | Address and re-submit |
| `PLAN_REVISION_REQUIRED` | Fundamental issues | Revise plan, restart cycle |

## Phase Completion Requirement

At the end of every major phase of work:

1. **Produce a summary** listing:
   - All files created or modified
   - Key changes made
   - Spec sections implemented

2. **Discuss and revise** the summary with the user

3. **Update CHANGES.md** with:
   - Phase number and title
   - Date completed
   - Files changed (with brief description)
   - Commit SHA

4. **Commit CHANGES.md** and record the commit ID in the entry

## Specification Reference

- Authoritative spec: `Documentation/VVP_Verifier_Specification_v1.5.md` (also v1.4_FINAL.md for reference)
- Implementation checklist: `Documentation/VVP_Implementation_Checklist.md`

## Sprint Planning

- **Sprint roadmap:** `SPRINTS.md` - Defines all sprints with goals, deliverables, exit criteria
- **Archived verifier sprints:** `Documentation/archive/PLAN_Sprint*.md` (Sprints 1-25)
- **Issuer sprints:** 26-33 (defined in `SPRINTS.md`)

## CI/CD

- Push to `main` triggers deployment to Azure Container Apps
- Verify deployment: `curl https://vvp-verifier.wittytree-2a937ccd.uksouth.azurecontainerapps.io/healthz`

## Key Design Decisions

### Normative (fixed by spec)

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Signature Algorithm | EdDSA (Ed25519) only | §5.0, §5.1 - VVP mandates |
| Max iat Drift | 5 seconds | §5.2A - "MUST be ≤ 5 seconds" |
| SAID Algorithm | Blake3-256 | KERI ecosystem standard |

### Configurable Defaults

| Decision | Default | Rationale |
|----------|---------|-----------|
| Max PASSporT Validity | 300 seconds | §5.2B - "unless explicitly configured otherwise" |
| Clock Skew | ±300 seconds | §4.1A - "default policy" |
| Max Token Age | 300 seconds | §5.2B - configurable |

## Vendored Dependencies

- **keripy/** - KERI Python library (vendored, not yet integrated)
  - Excluded from pytest discovery via `pytest.ini`
  - TODO: Record upstream commit/version for reproducibility

## Project Structure

```
VVP/
├── common/                          # Shared code (pip install -e common/)
│   └── vvp/
│       ├── core/                    # logging, exceptions
│       ├── models/                  # ACDC, Dossier data models
│       ├── canonical/               # keri_canonical, cesr, parser, said
│       ├── schema/                  # registry, store, validator
│       └── utils/                   # tn_utils
├── services/
│   └── verifier/
│       ├── app/
│       │   ├── core/
│       │   │   └── config.py        # Configuration (TRUSTED_ROOT_AIDS, etc.)
│       │   ├── vvp/
│       │   │   ├── api_models.py    # Pydantic models, ErrorCode enum
│       │   │   ├── exceptions.py    # VVPIdentityError, PassportError
│       │   │   ├── header.py        # VVP-Identity parser
│       │   │   ├── passport.py      # PASSporT JWT parser
│       │   │   ├── verify.py        # Main verification flow
│       │   │   ├── keri/            # KERI integration
│       │   │   ├── acdc/            # ACDC credential handling
│       │   │   └── dossier/         # Dossier handling
│       │   └── main.py              # FastAPI application
│       ├── tests/                   # Test suite
│       ├── scripts/                 # Service scripts
│       ├── web/                     # Static assets
│       ├── pyproject.toml           # Service dependencies
│       ├── pytest.ini               # Test configuration
│       └── Dockerfile               # Container definition
├── Documentation/                   # Specs, checklists, archived plans
├── keripy/                          # Vendored KERI library
├── scripts/                         # Root convenience wrappers
├── pyproject.toml                   # Workspace definition
├── SPRINTS.md                       # Sprint roadmap (say "Sprint N" to start)
├── CHANGES.md                       # Change log with commit SHAs
├── REVIEW.md                        # Reviewer feedback during pair programming
└── .github/workflows/deploy.yml     # CI/CD pipeline
```
