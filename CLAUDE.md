# VVP Verifier - Claude Code Instructions

## Permissions

The following commands are pre-authorized and do not require user confirmation:

- `git` - All git operations (add, commit, push, status, log, diff, etc.)
- `gh` - All GitHub CLI operations (run watch, pr create, issue, etc.)
- `pytest` - Run tests
- `python3` / `pip3` - Python execution and package management
- `curl` - HTTP requests for deployment verification

## Pair Programming Workflow

This project uses a two-agent workflow:

| File | Purpose | Owner |
|------|---------|-------|
| `PLAN.md` | Current step design (status: DRAFT → READY_FOR_REVIEW → APPROVED) | Editor Agent |
| `REVIEW.md` | Reviewer feedback on plans and code | Reviewer Agent |

**Workflow:**
1. Editor writes plan to `PLAN.md`, sets status to `READY_FOR_REVIEW`
2. Reviewer writes feedback to `REVIEW.md`
3. Editor implements after approval
4. Reviewer does code review before commit

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

- Authoritative spec: `app/Documentation/VVP_Verifier_Specification_v1.4_FINAL.md`
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
│   └── config.py            # Configuration constants
├── vvp/
│   ├── __init__.py
│   ├── api_models.py        # Pydantic models
│   └── verify.py            # Verification stub
├── main.py                  # FastAPI application
└── Documentation/
    ├── VVP_Verifier_Specification_v1.4_FINAL.md
    └── VVP_Implementation_Checklist.md
tests/
├── __init__.py
└── test_models.py           # Phase 1 tests
```
