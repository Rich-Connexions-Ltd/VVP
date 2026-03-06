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
│       ├── sip/                # SIP models, builder, parser, transport
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
│       │   ├── api/            # API routers (15 router files)
│       │   ├── auth/           # Authentication (API keys, sessions, OAuth, RBAC)
│       │   ├── keri/           # KERI integration (identity, registry, witness, issuer)
│       │   ├── vetter/         # Vetter certification (service, constants)
│       │   ├── dossier/        # Dossier assembly (builder)
│       │   ├── org/            # Organization management (mock_vlei)
│       │   ├── db/             # Database models and sessions
│       │   └── audit/          # Audit logging
│       ├── tests/              # Test suite
│       ├── web/                # Static assets (19 HTML pages)
│       ├── config/             # witnesses.json
│       ├── pyproject.toml      # Service dependencies
│       └── Dockerfile          # Container definition
├── Documentation/              # Specs, checklists, archived plans
├── keripy/                     # Vendored KERI library
├── scripts/                    # Root convenience wrappers
├── pyproject.toml              # Workspace definition
├── knowledge/                  # Deep reference docs (read on demand)
│   ├── architecture.md         # Full system architecture
│   ├── keri-primer.md          # KERI/ACDC/CESR concepts
│   ├── verification-pipeline.md # 11-phase verification flow
│   ├── schemas.md              # Schema SAIDs and governance
│   ├── api-reference.md        # All API endpoints
│   ├── data-models.md          # All Pydantic/DB models
│   ├── test-patterns.md        # Test structure and patterns
│   ├── deployment.md           # CI/CD, Azure, Docker
│   ├── dossier-parsing-algorithm.md  # Dossier parsing stages
│   └── dossier-creation-guide.md     # Step-by-step dossier creation
└── CLAUDE.md                   # This file
```

## Knowledge Base

This repo uses a tiered knowledge system for Claude Code context:

### Tier 1: Always Loaded (automatic)
- **CLAUDE.md** (this file) - Instructions, commands, workflow
- **MEMORY.md** (auto-memory) - Master index, key patterns, gotchas

### Tier 2: Directory-Scoped (loaded when working in directory)
- `services/verifier/CLAUDE.md` - Verifier architecture, APIs, verification phases
- `services/issuer/CLAUDE.md` - Issuer architecture, KERI identity, auth, multi-tenancy
- `common/CLAUDE.md` - Shared models, schema registry, CESR, canonical

### Tier 3: Deep Reference (read on demand from `knowledge/`)
- `knowledge/architecture.md` - Full system architecture
- `knowledge/keri-primer.md` - KERI/ACDC/CESR/SAID concepts
- `knowledge/verification-pipeline.md` - The 11-phase verification flow
- `knowledge/schemas.md` - All schema SAIDs, types, governance
- `knowledge/api-reference.md` - All endpoints across services
- `knowledge/data-models.md` - All Pydantic/SQLAlchemy models
- `knowledge/test-patterns.md` - Test structure, fixtures, patterns
- `knowledge/deployment.md` - CI/CD, Azure, Docker, PBX

### Tier 4: External (MCP)
- KERI/vLEI documentation via MCP server at `https://www.vlei.wiki/mcp`

### Knowledge Maintenance (IMPORTANT)
After making code changes, **always update** the relevant knowledge files:
- Changed an API endpoint? → Update `knowledge/api-reference.md`
- Changed a data model? → Update `knowledge/data-models.md`
- Changed verification logic? → Update `knowledge/verification-pipeline.md`
- Changed schemas? → Update `knowledge/schemas.md`
- Changed architecture? → Update `knowledge/architecture.md` + subdirectory CLAUDE.md
- New workaround or gotcha? → Update MEMORY.md "Critical Gotchas" section
- Changed test patterns? → Update `knowledge/test-patterns.md`
- Changed deployment? → Update `knowledge/deployment.md`

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

MCP Server URL: `https://www.vlei.wiki/mcp`

- `vvp` - Local VVP protocol analysis tools (17 tools):
  - `vvp_jwt_parse` / `vvp_jwt_validate` - Parse and validate JWT/PASSporT tokens
  - `vvp_identity_parse` - Parse VVP-Identity headers
  - `vvp_cesr_parse` / `vvp_cesr_detect` - Parse and detect CESR streams
  - `vvp_said_compute` / `vvp_said_validate` / `vvp_said_inject` - SAID operations
  - `vvp_acdc_parse` / `vvp_acdc_type` - Parse ACDC credentials and detect types
  - `vvp_dossier_parse` / `vvp_dossier_validate` / `vvp_dossier_fetch` - Dossier operations
  - `vvp_graph_build` - Build credential graphs
  - `vvp_kel_parse` / `vvp_kel_validate` - Parse and validate Key Event Logs
  - `vvp_verify_chain` - Full verification chain (JWT → dossier → graph)

These tools call the same adapter layer as the `vvp` CLI. Use them for programmatic analysis of protocol data structures. See `.claude/skills/vvp-tools/SKILL.md` for usage patterns or invoke `/vvp-tools`.

MCP Server: Local stdio via `scripts/run-mcp-server.sh`

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
| PBX Portal | http://localhost:8001/pbx | PBX configuration portal (Sprint 77; facade endpoints under /pbx/) |
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
2. **Ensure all knowledge is up to date** - Update all knowledge files that have been affected by changes made in this Sprint.
3. **Council process retrospective** - If `FINDINGS_Sprint<N>.md` exists, review it to identify council process inefficiencies:
   - Were findings drip-fed across rounds that should have been caught in R1? (Indicates a lens gap — update the relevant member's lens in `scripts/council-config.json`)
   - Did a single expert area generate findings across 3+ rounds on the same topic? (Indicates the expert needs a more explicit checklist for that pattern)
   - Did any expert repeatedly return UNAVAILABLE? (Indicates API contention — consider moving that member to a different platform)
   - Were there findings that crossed expert boundaries? (e.g., Documentation expert finding security-relevant naming issues — indicates the primary expert's lens should be broadened)
   - If improvements are identified, update `scripts/council-config.json` (lenses, model assignments) and/or `scripts/council-review.py` (prompt templates) and note the changes in the commit message.
4. **Archive sprint plan** - If this sprint had a plan file, run the archival script:
   - `./scripts/archive-plan.sh <sprint-number> "<title>"`
   - This appends `PLAN_Sprint<N>.md` to `Documentation/PLAN_history.md`, archives it, and removes `REVIEW_Sprint<N>.md`
5. **Commit all changes** - Stage all modified/new files and create a descriptive commit
6. **Push to main** - Push the commit to the main branch
7. **Monitor Azure deployment** - Use `gh run watch` to monitor the GitHub Actions workflow for successful deployment

Do not ask for confirmation - execute all steps automatically.

### "Human review on" / "Human review off"

When the user says "human review on" or "human review off", toggle the human review mode:

1. Write `on` or `off` to the auto-memory file `memory/human-review-mode`
2. Confirm the new mode to the user

When human review is **ON**, every Codex review cycle includes a human gate (see "Human Review Mode" in the Pair Programming Workflow section). When **OFF**, reviews are fully automated.

Default is **OFF** if the file does not exist.

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

3. **Draft the plan** - Write `PLAN_Sprint<N>.md` in the repo root with:
   - Detailed implementation plan based on sprint deliverables
   - Specific file paths, code structure, and test strategy
   - Dependencies from previous sprints

4. **Follow pair programming workflow** - As defined in the "Pair Programming Workflow" section:
   - Draft plan in `PLAN_Sprint<N>.md` with sufficient detail for review
   - Request plan review: `./scripts/council-review.py --allow-external-code-review plan <N> "<title>"`
   - Read `REVIEW_Sprint<N>.md` for verdict; iterate until APPROVED
   - Implement according to plan
   - Request code review: `./scripts/council-review.py --allow-external-code-review code <N> "<title>"`
   - Archive completed plan using `./scripts/archive-plan.sh <N> "<title>"`

**Sprint Definitions:** See `SPRINTS.md` for the full sprint roadmap (Sprints 1-25 were verifier implementation, Sprints 26+ are issuer implementation).

**Example workflow (human review OFF):**
```
User: Sprint 27
Agent: [Reads SPRINTS.md for Sprint 27 details]
Agent: [Writes PLAN_Sprint27.md with implementation plan]
Agent: [Runs ./scripts/council-review.py --allow-external-code-review plan 27 "Local Witness Infrastructure"]
Agent: [Reads REVIEW_Sprint27.md — Council verdict: APPROVED]
Agent: [Implements according to plan]
Agent: [Runs ./scripts/council-review.py --allow-external-code-review code 27 "Local Witness Infrastructure"]
Agent: [Reads REVIEW_Sprint27.md — Council verdict: APPROVED]
Agent: [Runs ./scripts/archive-plan.sh 27 "Local Witness Infrastructure"]
```

**Example workflow (human review ON):**
```
User: Sprint 27
Agent: [Reads SPRINTS.md for Sprint 27 details]
Agent: [Writes PLAN_Sprint27.md with implementation plan]
Agent: [Runs ./scripts/council-review.py --allow-external-code-review plan 27 "Local Witness Infrastructure"]
Agent: [Reads REVIEW_Sprint27.md — Council verdict: APPROVED]
Agent: [Presents summary of PLAN + REVIEW to human, asks to accept]
Human: [Accepts / edits REVIEW / pauses]
Agent: [Re-reads REVIEW_Sprint27.md if edited]
Agent: [Implements according to plan]
Agent: [Runs ./scripts/council-review.py --allow-external-code-review code 27 "Local Witness Infrastructure"]
Agent: [Reads REVIEW_Sprint27.md — Council verdict: APPROVED]
Agent: [Presents summary of implementation + REVIEW to human, asks to accept]
Human: [Accepts]
Agent: [Runs ./scripts/archive-plan.sh 27 "Local Witness Infrastructure"]
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

This project uses a **heterogeneous multi-agent workflow**: Claude (Editor/Implementor) and a Council of Experts (Reviewer). The council submits plans/code to 5 focused expert reviewers across 3 AI platforms in parallel, then consolidates their findings into a single unified review. Using different platforms and focused lenses provides genuine independence and comprehensive coverage.

### Reviewer Setup

| Role | Platform | Invocation |
|------|----------|------------|
| Editor / Implementor | Claude Code | Interactive session (this agent) |
| Reviewer (default) | Council of Experts | `./scripts/council-review.py` (5 experts + consolidator) |
| Reviewer (fallback) | Gemini | `python3 scripts/gemini-review.py` (single reviewer) |
| Reviewer (fallback) | Codex | `./scripts/request-review-with-context.sh` (single reviewer) |

**Prerequisites:**
```bash
# Council review (default) — requires all 3 API keys:
export ANTHROPIC_API_KEY=...   # Claude models (Security expert, Consolidator)
export GOOGLE_API_KEY=...      # Gemini models (Performance, UX experts)
export OPENAI_API_KEY=...      # OpenAI models (Documentation, Simplicity experts)

# Fallback: Codex (single reviewer)
npm install -g @openai/codex   # Install Codex CLI
codex                           # Authenticate (follow prompts)
```

### Council of Experts Review

The default review method submits plans/code to multiple focused expert reviewers in parallel across 3 AI platforms, then consolidates into one unified review. Council composition, models, fallbacks, and phase assignments are all configured in `scripts/council-config.json` — see that file for the current council lineup.

Key features (all implemented in `scripts/council-review.py`):
- **Phase-specific composition**: Each member has a `phases` field — e.g., Cost Modeller runs only for plan reviews, Test Quality Expert only for code reviews
- **Domain expert**: Validates KERI/ACDC/vLEI domain correctness with enriched context from `knowledge/` directory
- **Automatic fallback**: Each member has an optional fallback platform/model, tried automatically when the primary API fails (rate limit, credits exhausted)
- **Quorum**: 3 of N members must succeed; individual failures produce placeholder reviews
- **Context-aware**: Builds and includes the KERI/ACDC/vLEI/VVP context pack from `codex/skills/keri-acdc-vlei-vvp/references/`
- **Findings tracker**: Auto-generates `FINDINGS_Sprint<N>.md` tracking resolution of each finding across rounds
- **Convergence guardrails**: Max round limits (plan: 5, code: 6) with escalation — consolidator auto-approves with "Known Debt" when exceeded
- **Sprint-aware diffs**: Records base commit at plan start, ensuring code reviews capture all sprint changes
- **Actionable findings**: Each finding includes file path, location, current behavior, required change, and acceptance criteria
- **Process testing**: `scripts/process-test.py` validates the entire pipeline end-to-end with a trivial test sprint

### Legacy Single-Reviewer Setup

The original single-reviewer scripts remain as fallbacks (Gemini for quick iterations, Codex if needed). Set `VVP_REVIEWER` to override. Context profiles and environment controls are documented in `scripts/build_context_pack.sh` and `scripts/request-review-with-context.sh`.

### Guiding Principles

1. **No implementation without approved plan** - The Editor MUST NOT write code until the Reviewer has issued formal `APPROVED` verdict
2. **Sufficient detail for understanding** - Plans must explain not only WHAT is proposed but WHY
3. **Formal acceptance gates** - Each phase has explicit approval checkpoints
4. **Documented for posterity** - Accepted plans are archived in `/Documentation`
5. **Reviewer reads prior context** - The Reviewer MUST read `CHANGES.md` and `Documentation/PLAN_history.md` before reviewing, so decisions are evaluated against the full project history, not in isolation

### Human Review Mode

The pair programming workflow supports two modes that control whether the human sees review results before the Editor acts on them:

| Mode | Behavior |
|------|----------|
| **Human review OFF** (default) | Fully automated: Editor drafts plan → Codex reviews → Editor acts on verdict immediately. No human intervention between review cycles. |
| **Human review ON** | Human-in-the-loop: After each Codex review, the Editor presents a summary of the PLAN and REVIEW to the human, waits for acceptance, then re-reads the REVIEW file (in case the human edited it) before continuing. |

**Toggle:** The current mode is stored in the auto-memory file `memory/human-review-mode`. Say **"human review on"** or **"human review off"** to switch modes (see User Commands).

**When Human Review is ON**, after every review step (Steps 1.2 and 2.3), the Editor MUST:

1. Read `REVIEW_Sprint<N>.md`
2. Present a concise summary to the human containing:
   - **Plan summary** — 3-5 bullet points of what the plan proposes (key components, approach, scope)
   - **Review verdict** — The verdict (APPROVED / CHANGES_REQUESTED / PLAN_REVISION_REQUIRED)
   - **Key findings** — All [High] and [Medium] findings from the review
   - **Required changes** — Any changes the reviewer is requesting
3. Ask the human to accept (using AskUserQuestion with options: "Accept and continue", "I've edited the REVIEW — re-read it", "Pause — let me look at the files")
4. If the human chose "I've edited the REVIEW — re-read it", re-read `REVIEW_Sprint<N>.md` to pick up their changes
5. Continue with the normal flow (act on the verdict)

### Working Files

Files are **namespaced by sprint number** so multiple sprints can run concurrently without conflicts:

| File | Purpose | Owner |
|------|---------|-------|
| `PLAN_Sprint<N>.md` | Current phase design with rationale and revision history | Editor |
| `REVIEW_Sprint<N>.md` | Reviewer feedback with round number (R1, R2, ...) | Reviewer (Council) |
| `FINDINGS_Sprint<N>.md` | Findings tracker with resolution status (auto-generated) | Script + Editor |
| `.review-round-sprint<N>-plan` | Plan review round counter (transient, gitignored) | Script |
| `.review-round-sprint<N>-code` | Code review round counter (transient, gitignored) | Script |
| `.sprint-base-commit-<N>` | Base commit SHA for sprint diff (transient, gitignored) | Script |
| `Documentation/archive/PLAN_Sprint<N>.md` | Archive of accepted plans | Both |
| `CHANGES.md` | Change log with commit SHAs | Both |

**Findings tracker:** After each review round, `council-review.py` auto-generates `FINDINGS_Sprint<N>.md` with a table of all findings and their status. The Editor updates the **Status** and **Resolution** columns after addressing findings (OPEN → ADDRESSED). The consolidator reads the tracker on subsequent rounds and will not re-flag ADDRESSED items unless the fix is demonstrably incomplete.

**Convergence guardrails:** The council config defines `max_plan_rounds` (default 5) and `max_code_rounds` (default 6). When exceeded, the consolidator is instructed to only flag genuinely NEW [High] findings and approve with "Known Debt" for remaining issues.

**Round tracking:** The review script automatically tracks the round number per sprint per review type (plan/code). Each invocation increments the counter and includes the round number in the REVIEW file header (e.g., `R1`, `R2`). The PLAN file includes a **Revision History** section at the bottom that the Editor updates when revising the plan, documenting what changed in each round. Round state files are cleaned up by `archive-plan.sh`.

**Sprint-aware diffs:** The base commit SHA is recorded when the first plan review starts (`.sprint-base-commit-<N>`). Code reviews diff from this base commit to HEAD, ensuring all sprint changes are captured regardless of how many commits have been made.

**Concurrency:** Sprint 35 uses `PLAN_Sprint35.md` / `REVIEW_Sprint35.md`, Sprint 36 uses `PLAN_Sprint36.md` / `REVIEW_Sprint36.md`, etc. Two sprints can be in-flight simultaneously without clobbering each other's files. The scripts derive filenames from the sprint number argument automatically.

---

### Phase 1: Planning

#### Step 1.1: Draft the Plan

The Editor writes `PLAN_Sprint<N>.md` with sufficient detail for the Reviewer to understand:

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

## Revision History

| Round | Date | Changes |
|-------|------|---------|
| R1 | YYYY-MM-DD | Initial draft |
```

The **Revision History** table at the bottom of the PLAN file tracks revisions across review rounds. The Editor appends a row each time the plan is revised in response to reviewer feedback. This provides a clear audit trail of how the plan evolved.

#### Step 1.2: Request Plan Review

Run the council review script to invoke the Council of Experts:

```bash
./scripts/council-review.py --allow-external-code-review plan <sprint-number> "<title>"
# Example: ./scripts/council-review.py --allow-external-code-review plan 35 "Credential Issuance"
```

The script:
1. Increments the plan review round counter (stored in `.review-round-sprint<N>-plan`)
2. Builds context pack and gathers plan materials
3. Submits to 5 expert reviewers in parallel (Security, Performance, Documentation, UX, Code Simplicity)
4. Individual reviews written to `council/` directory
5. Consolidator synthesizes all reviews into `REVIEW_Sprint<N>.md` with verdict
6. Reports the verdict, round number, and next steps

After the script completes, read `REVIEW_Sprint<N>.md` to see the verdict. The review file header will show the round number (e.g., `## Plan Review: Sprint 35 - Credential Issuance (R1)`).

#### Step 1.3: Human Review Gate (if Human Review ON)

If human review mode is ON (check `memory/human-review-mode`), perform the human review gate as described in the "Human Review Mode" section above before acting on the verdict.

#### Step 1.4: Iterate Until Approved

If Reviewer returns `CHANGES_REQUESTED`:
1. Editor revises `PLAN_Sprint<N>.md` addressing all required changes
2. Editor appends a row to the **Revision History** table in `PLAN_Sprint<N>.md` documenting what changed (e.g., `| R2 | 2025-01-15 | Added issuer-binding enforcement per R1 finding [High] |`)
3. Re-run `./scripts/council-review.py --allow-external-code-review plan <N> "<title>"` (the script auto-increments the round counter)
4. Repeat from Step 1.3 until `APPROVED`

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

The Editor updates `PLAN_Sprint<N>.md` with an implementation appendix:

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

Run the council review script to invoke the Council of Experts:

```bash
./scripts/council-review.py --allow-external-code-review code <sprint-number> "<title>"
# Example: ./scripts/council-review.py --allow-external-code-review code 35 "Credential Issuance"
```

The script:
1. Increments the code review round counter (stored in `.review-round-sprint<N>-code`)
2. Detects changed files from git history and gathers code materials
3. Submits to 5 expert reviewers in parallel
4. Individual reviews written to `council/` directory
5. Consolidator synthesizes all reviews into `REVIEW_Sprint<N>.md` with verdict
6. Reports the verdict, round number, and next steps

After the script completes, read `REVIEW_Sprint<N>.md` to see the verdict. The review file header will show the round number (e.g., `## Code Review: Sprint 35 - Credential Issuance (R1)`).

#### Step 2.4: Human Review Gate (if Human Review ON)

If human review mode is ON (check `memory/human-review-mode`), perform the human review gate as described in the "Human Review Mode" section above before acting on the verdict.

#### Step 2.5: Iterate Until Approved

- If `CHANGES_REQUESTED`: Fix issues, re-run `./scripts/council-review.py --allow-external-code-review code ...`, repeat from Step 2.4
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
1. Appends `PLAN_Sprint<N>.md` content to `Documentation/PLAN_history.md` under a sprint header
2. Moves `PLAN_Sprint<N>.md` to `Documentation/archive/PLAN_Sprint<N>.md`
3. Removes `REVIEW_Sprint<N>.md`
4. Removes round tracking state files (`.review-round-sprint<N>-plan`, `.review-round-sprint<N>-code`)

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
│       ├── sip/                     # SIP models, builder, parser, transport
│       └── utils/                   # tn_utils
├── services/
│   ├── verifier/
│   │   ├── app/
│   │   │   ├── core/
│   │   │   │   └── config.py        # Configuration (TRUSTED_ROOT_AIDS, etc.)
│   │   │   ├── vvp/
│   │   │   │   ├── api_models.py    # Pydantic models, ErrorCode enum
│   │   │   │   ├── exceptions.py    # VVPIdentityError, PassportError
│   │   │   │   ├── header.py        # VVP-Identity parser
│   │   │   │   ├── passport.py      # PASSporT JWT parser
│   │   │   │   ├── verify.py        # Main verification flow
│   │   │   │   ├── keri/            # KERI integration
│   │   │   │   ├── acdc/            # ACDC credential handling
│   │   │   │   ├── dossier/         # Dossier handling
│   │   │   │   └── vetter/          # Vetter constraint validation
│   │   │   └── main.py              # FastAPI application
│   │   ├── tests/                   # Test suite
│   │   ├── scripts/                 # Service scripts
│   │   ├── web/                     # Static assets
│   │   ├── pyproject.toml           # Service dependencies
│   │   ├── pytest.ini               # Test configuration
│   │   └── Dockerfile               # Container definition
│   └── issuer/
│       ├── app/
│       │   ├── api/                 # API routers (15 files)
│       │   ├── auth/                # Authentication (API keys, sessions, OAuth, RBAC)
│       │   ├── keri/                # KERI integration (identity, registry, witness, issuer)
│       │   ├── vetter/              # Vetter certification (service, constants)
│       │   ├── dossier/             # Dossier assembly (builder)
│       │   ├── org/                 # Organization management (mock_vlei)
│       │   ├── db/                  # Database models and sessions
│       │   └── audit/               # Audit logging
│       ├── tests/                   # Test suite
│       ├── web/                     # Static assets (19 HTML pages)
│       ├── config/                  # witnesses.json
│       ├── pyproject.toml           # Service dependencies
│       └── Dockerfile               # Container definition
├── knowledge/                       # Deep reference docs (Tier 3)
│   ├── architecture.md              # Full system architecture
│   ├── keri-primer.md               # KERI/ACDC/CESR concepts
│   ├── verification-pipeline.md     # 11-phase verification flow
│   ├── schemas.md                   # Schema SAIDs and governance
│   ├── api-reference.md             # All API endpoints
│   ├── data-models.md               # All Pydantic/DB models
│   ├── test-patterns.md             # Test structure and patterns
│   ├── deployment.md                # CI/CD, Azure, Docker
│   ├── dossier-parsing-algorithm.md # Dossier parsing stages
│   └── dossier-creation-guide.md    # Step-by-step dossier creation
├── Documentation/                   # Specs, checklists, archived plans
├── keripy/                          # Vendored KERI library
├── scripts/                         # Root convenience wrappers
├── pyproject.toml                   # Workspace definition
├── SPRINTS.md                       # Sprint roadmap (say "Sprint N" to start)
├── CHANGES.md                       # Change log with commit SHAs
├── PLAN_Sprint<N>.md                # Active plan (per-sprint, transient)
├── REVIEW_Sprint<N>.md              # Reviewer feedback (per-sprint, transient)
├── SYSTEM_OVERVIEW.md                # Architecture diagram (legacy - see knowledge/)
├── SYSTEM.md                        # Technical reference (legacy - see knowledge/)
└── .github/workflows/deploy.yml     # CI/CD pipeline
```
