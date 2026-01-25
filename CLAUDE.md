# VVP Verifier - Claude Code Instructions

## Permissions

The following commands are pre-authorized and do not require user confirmation:

- `git` - All git operations (add, commit, push, status, log, diff, etc.)
- `gh` - All GitHub CLI operations (run watch, pr create, issue, etc.)
- `pytest` - Run tests (including with DYLD_LIBRARY_PATH prefix)
- `python3` / `pip3` - Python execution and package management
- `curl` - HTTP requests for deployment verification
- `uvicorn` - Running the development server
- `DYLD_LIBRARY_PATH=* python3 -m pytest` - Test commands with library path

All test-related commands using pytest are pre-authorized, including those that set environment variables like `DYLD_LIBRARY_PATH`.

## Running Tests

Tests require libsodium for cryptographic operations. On macOS with Homebrew:

```bash
# Run all tests with libsodium path
DYLD_LIBRARY_PATH="/opt/homebrew/lib" python3 -m pytest tests/ -v

# Run specific test file
DYLD_LIBRARY_PATH="/opt/homebrew/lib" python3 -m pytest tests/test_signature.py -v

# Run with coverage
DYLD_LIBRARY_PATH="/opt/homebrew/lib" python3 -m pytest tests/ --cov=app --cov-report=term-missing
```

If libsodium is installed elsewhere, find it with:
```bash
brew --prefix libsodium  # Shows: /opt/homebrew/opt/libsodium
find /opt/homebrew -name "libsodium*.dylib" 2>/dev/null
```

## Pair Programming Workflow

This project uses a formal two-agent workflow with an **Editor** (implementing agent) and **Reviewer** (reviewing agent). The user facilitates by copying prompts between sessions.

### Guiding Principles

1. **No implementation without approved plan** - The Editor MUST NOT write code until the Reviewer has issued formal `APPROVED` verdict
2. **Sufficient detail for understanding** - Plans must explain not only WHAT is proposed but WHY
3. **Formal acceptance gates** - Each phase has explicit approval checkpoints
4. **Documented for posterity** - Accepted plans are archived in `/Documentation`

### Working Files

| File | Purpose | Owner |
|------|---------|-------|
| Claude plan mode file | Current phase design with rationale | Editor |
| `REVIEW.md` | Reviewer feedback on plans and code | Reviewer |
| `app/Documentation/PLAN_PhaseN.md` | Archive of accepted plans | Both |
| `CHANGES.md` | Change log with commit SHAs | Both |

**Note:** Plans are now written using Claude Code's built-in plan mode rather than a separate `PLAN.md` file. The plan content is stored at `~/.claude/plans/` and archived to `app/Documentation/` after approval.

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

~~~
```
## Plan Review Request: Phase N - [Title]

You are the Reviewer in a pair programming workflow. Please review the plan in `PLAN.md` and provide your assessment in `REVIEW.md`.

### Your Task
1. Read `PLAN.md` thoroughly
2. Evaluate against the spec references cited
3. Assess the rationale for design decisions
4. Answer any open questions
5. Provide verdict and feedback in `REVIEW.md`

### Evaluation Criteria
- Does the plan correctly interpret the spec requirements?
- Is the proposed approach sound and well-justified?
- Are there gaps, ambiguities, or risks not addressed?
- Is the test strategy adequate?

### Response Format
Write your response to `REVIEW.md` using this structure:

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
~~~

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

```markdown
---

## Implementation Notes

### Deviations from Plan
[Any necessary deviations and why they were required]

### Implementation Details
[Additional context discovered during implementation]

### Test Results
```
[pytest output showing all tests pass]
```

### Files Changed
| File | Lines | Summary |
|------|-------|---------|
| `path/to/file.py` | +150 | Created new module for X |
| `tests/test_file.py` | +80 | Tests for X |
```

#### Step 2.3: Request Code Review

The Editor provides a **copyable prompt** for code review:

~~~
```
## Code Review Request: Phase N - [Title]

You are the Reviewer in a pair programming workflow. Please review the implementation and provide your assessment in `REVIEW.md`.

### Context
[Brief description of what was implemented]

### Spec References
- §X.Y: [Section name]

### Files to Review
- `path/to/file.py` (created) - [purpose]
- `tests/test_file.py` (created) - [what it tests]

### Verification Commands
```bash
python3 -m pytest tests/test_xxx.py -v
```

### Key Design Decisions
1. [Decision and rationale]
2. [Another decision and rationale]

### Test Results
[N passed in X.XXs]

### Your Task
1. Review all listed files for correctness and style
2. Verify implementation matches approved plan
3. Check test coverage and edge cases
4. Provide verdict and feedback in `REVIEW.md`

### Response Format
Write your response to `REVIEW.md` using this structure:

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
~~~

#### Step 2.4: Iterate Until Approved

- If `CHANGES_REQUESTED`: Fix issues, provide new review prompt
- If `PLAN_REVISION_REQUIRED`: Return to Phase 1 with revised plan
- If `APPROVED`: Proceed to Phase 3

---

### Phase 3: Completion and Archival

#### Step 3.1: Archive the Plan

Move accepted plan to documentation:
1. Copy `PLAN.md` to `app/Documentation/PLAN_PhaseN.md`
2. Include implementation notes and review history
3. Update `CHANGES.md` with phase summary

#### Step 3.2: Clean Up

1. Clear `PLAN.md` for next phase (or leave as reference)
2. Clear `REVIEW.md` for next phase
3. Commit all documentation updates

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

- Authoritative spec: `app/Documentation/VVP_Verifier_Specification_v1.5.md` (also v1.4_FINAL.md for reference)
- Implementation checklist: `app/Documentation/VVP_Implementation_Checklist.md`

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
app/
├── core/
│   ├── __init__.py
│   └── config.py            # Configuration (TRUSTED_ROOT_AIDS, etc.)
├── vvp/
│   ├── __init__.py
│   ├── api_models.py        # Pydantic models, ErrorCode enum
│   ├── exceptions.py        # VVPIdentityError, PassportError
│   ├── header.py            # VVP-Identity parser
│   ├── passport.py          # PASSporT JWT parser
│   ├── verify.py            # Main verification flow (Tier 1 & 2)
│   ├── keri/                # KERI integration
│   │   ├── __init__.py
│   │   ├── cache.py         # Key state caching
│   │   ├── cesr.py          # CESR encoding/decoding (PSS signatures)
│   │   ├── exceptions.py    # KeriError, SignatureInvalidError
│   │   ├── kel_parser.py    # KEL event parsing, witness validation
│   │   ├── kel_resolver.py  # Key state resolution via OOBI
│   │   ├── keri_canonical.py # Canonical KERI serialization
│   │   ├── key_parser.py    # parse_kid_to_verkey
│   │   ├── oobi.py          # OOBI dereferencing
│   │   ├── signature.py     # Signature verification
│   │   └── tel_client.py    # TEL (revocation) client
│   ├── acdc/                # ACDC credential handling (Phase 10)
│   │   ├── __init__.py
│   │   ├── exceptions.py    # ACDCChainInvalid, ACDCSignatureInvalid
│   │   ├── graph.py         # Credential graph traversal
│   │   ├── models.py        # ACDC data model
│   │   ├── parser.py        # ACDC parsing, SAID validation
│   │   └── verifier.py      # Chain validation, credential type rules
│   └── dossier/             # Dossier handling
│       ├── __init__.py
│       ├── exceptions.py    # DossierError
│       ├── fetch.py         # Dossier fetching
│       ├── models.py        # DossierDAG, DossierNode
│       ├── parser.py        # Dossier parsing, CESR extraction
│       └── validator.py     # DAG validation
├── main.py                  # FastAPI application
└── Documentation/
    ├── VVP_Verifier_Specification_v1.5.md
    ├── VVP_Implementation_Checklist.md
    └── PLAN_PhaseN.md       # Archived plans
tests/
├── __init__.py
├── test_acdc.py             # ACDC chain validation tests
├── test_cesr_pss.py         # PSS CESR decoding tests
├── test_dossier.py          # Dossier parsing tests
├── test_kel_*.py            # KEL parsing/chain/cache tests
├── test_passport.py         # PASSporT parsing tests
├── test_signature.py        # Signature verification tests
├── test_verify.py           # Integration tests
├── test_witness_validation.py # Witness signature tests
└── vectors/                 # Test vector framework
```
