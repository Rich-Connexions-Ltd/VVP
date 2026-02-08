#!/usr/bin/env bash
# request-review.sh — Invoke the Reviewer agent (OpenAI Codex) to review a plan or implementation.
#
# Usage:
#   ./scripts/request-review.sh plan <sprint-number> "<title>"
#   ./scripts/request-review.sh code <sprint-number> "<title>"
#
# Examples:
#   ./scripts/request-review.sh plan 35 "Credential Issuance"
#   ./scripts/request-review.sh code 35 "Credential Issuance"
#
# Files:
#   Plan file:   PLAN_Sprint<N>.md   (read by reviewer)
#   Review file:  REVIEW_Sprint<N>.md (written by reviewer)
#   Namespaced by sprint number so multiple sprints can run concurrently.
#
# Environment:
#   VVP_REVIEWER       - Reviewer command (default: "codex exec --auto-edit")
#   VVP_REVIEWER_MODEL - Model flag if supported (default: unset)
#
# Prerequisites:
#   npm install -g @openai/codex   (or: brew install --cask codex)
#   Authenticated via: codex  (follow prompts)

set -euo pipefail

# ---------- arguments ----------

if [ $# -lt 3 ]; then
    echo "Usage: $0 <plan|code> <sprint-number> <title>"
    echo ""
    echo "  plan  — Review the implementation plan in PLAN_Sprint<N>.md"
    echo "  code  — Review the implementation (changed files since plan approval)"
    echo ""
    echo "Examples:"
    echo "  $0 plan 35 \"Credential Issuance\""
    echo "  $0 code 35 \"Credential Issuance\""
    exit 1
fi

REVIEW_TYPE="$1"
SPRINT_NUM="$2"
shift 2
TITLE="$*"

if [[ "$REVIEW_TYPE" != "plan" && "$REVIEW_TYPE" != "code" ]]; then
    echo "Error: first argument must be 'plan' or 'code', got '$REVIEW_TYPE'"
    exit 1
fi

REPO_ROOT="$(git rev-parse --show-toplevel)"
PLAN_FILE="$REPO_ROOT/PLAN_Sprint${SPRINT_NUM}.md"
REVIEW_FILE="$REPO_ROOT/REVIEW_Sprint${SPRINT_NUM}.md"
CHANGES_FILE="$REPO_ROOT/CHANGES.md"
HISTORY_FILE="$REPO_ROOT/Documentation/PLAN_history.md"

PLAN_BASENAME="PLAN_Sprint${SPRINT_NUM}.md"
REVIEW_BASENAME="REVIEW_Sprint${SPRINT_NUM}.md"

# ---------- validate ----------

if ! command -v codex &>/dev/null && [ -z "${VVP_REVIEWER:-}" ]; then
    echo "Error: 'codex' CLI not found and VVP_REVIEWER is not set."
    echo ""
    echo "Install Codex:  npm install -g @openai/codex"
    echo "  or set VVP_REVIEWER to a custom reviewer command."
    echo "  e.g.: VVP_REVIEWER='claude -p' $0 $REVIEW_TYPE $SPRINT_NUM $TITLE"
    exit 1
fi

if [[ "$REVIEW_TYPE" == "plan" && ! -f "$PLAN_FILE" ]]; then
    echo "Error: $PLAN_BASENAME not found at $PLAN_FILE"
    exit 1
fi

# ---------- reviewer command ----------

REVIEWER="${VVP_REVIEWER:-codex exec --auto-edit}"

# ---------- build prompt ----------

build_plan_review_prompt() {
    cat <<PROMPT
You are a senior code architect acting as Reviewer in a pair programming workflow.
You are reviewing Sprint ${SPRINT_NUM}: ${TITLE}.

INSTRUCTIONS:
1. Read these files for project context (in order):
   - CHANGES.md — what has been built, recent decisions
   - Documentation/PLAN_history.md — prior architectural choices
2. Read ${PLAN_BASENAME} — the plan under review
3. Evaluate the plan against these criteria:
   - Does it correctly interpret the spec requirements cited?
   - Is the proposed approach sound and well-justified?
   - Is it consistent with prior decisions, or does it justify departures?
   - Are there gaps, ambiguities, or risks not addressed?
   - Is the test strategy adequate?
4. Write your review to ${REVIEW_BASENAME} using the format below.

IMPORTANT: You MUST write your output to the file ${REVIEW_BASENAME} (overwrite it).
Do NOT modify any other files. Do NOT run tests or execute code.

OUTPUT FORMAT (write exactly this structure to ${REVIEW_BASENAME}):

## Plan Review: Sprint ${SPRINT_NUM} - ${TITLE}

**Verdict:** APPROVED | CHANGES_REQUESTED

### Spec Compliance
[Assessment of how well the plan addresses spec requirements]

### Design Assessment
[Evaluation of the proposed approach and alternatives]

### Findings
- [High]: Critical issues that block approval
- [Medium]: Important issues that should be addressed
- [Low]: Suggestions for improvement (optional)

### Answers to Open Questions
[Answer each open question from the plan]

### Required Changes (if CHANGES_REQUESTED)
1. [Specific change required]

### Recommendations
[Optional improvements or future considerations]
PROMPT
}

build_code_review_prompt() {
    # Get changed files since plan was last modified (approximation)
    local changed_files
    changed_files=$(git diff --name-only HEAD~1 2>/dev/null || git diff --name-only HEAD 2>/dev/null || echo "(unable to detect)")

    cat <<PROMPT
You are a senior code architect acting as Reviewer in a pair programming workflow.
You are reviewing the implementation for Sprint ${SPRINT_NUM}: ${TITLE}.

INSTRUCTIONS:
1. Read these files for context:
   - CHANGES.md — what has been built, recent decisions
   - ${PLAN_BASENAME} — the approved plan this code implements
2. Review the implementation in these changed files:

${changed_files}

3. For each file, check:
   - Does the code correctly implement the approved plan?
   - Code quality: clarity, documentation, error handling
   - Test coverage: are edge cases handled?
   - Are there security concerns?
4. Run any test commands mentioned in ${PLAN_BASENAME} to verify they pass.
5. Write your review to ${REVIEW_BASENAME} using the format below.

IMPORTANT: You MUST write your output to the file ${REVIEW_BASENAME} (overwrite it).
Do NOT modify any source files.

OUTPUT FORMAT (write exactly this structure to ${REVIEW_BASENAME}):

## Code Review: Sprint ${SPRINT_NUM} - ${TITLE}

**Verdict:** APPROVED | CHANGES_REQUESTED | PLAN_REVISION_REQUIRED

### Implementation Assessment
[Does the code correctly implement the approved plan?]

### Code Quality
[Assessment of clarity, documentation, error handling]

### Test Coverage
[Assessment of test adequacy]

### Findings
- [High]: Critical issues that block approval
- [Medium]: Important issues that should be fixed
- [Low]: Minor suggestions (optional)

### Required Changes (if not APPROVED)
1. [Specific change required]

### Plan Revisions (if PLAN_REVISION_REQUIRED)
[What needs to change in the plan before re-implementation]
PROMPT
}

# ---------- assemble and invoke ----------

if [[ "$REVIEW_TYPE" == "plan" ]]; then
    PROMPT=$(build_plan_review_prompt)
else
    PROMPT=$(build_code_review_prompt)
fi

echo "==> Requesting ${REVIEW_TYPE} review for Sprint ${SPRINT_NUM}: ${TITLE}"
echo "    Reviewer: ${REVIEWER}"
echo "    Plan:     ${PLAN_BASENAME}"
echo "    Review:   ${REVIEW_BASENAME}"
echo ""

# Capture the review file's timestamp before invocation
BEFORE_MTIME=""
if [ -f "$REVIEW_FILE" ]; then
    BEFORE_MTIME=$(stat -c %Y "$REVIEW_FILE" 2>/dev/null || stat -f %m "$REVIEW_FILE" 2>/dev/null || echo "")
fi

# Invoke the reviewer
# shellcheck disable=SC2086
$REVIEWER "$PROMPT"
REVIEW_EXIT=$?

if [ $REVIEW_EXIT -ne 0 ]; then
    echo ""
    echo "Error: Reviewer exited with code $REVIEW_EXIT"
    exit $REVIEW_EXIT
fi

# Check if review file was updated
AFTER_MTIME=""
if [ -f "$REVIEW_FILE" ]; then
    AFTER_MTIME=$(stat -c %Y "$REVIEW_FILE" 2>/dev/null || stat -f %m "$REVIEW_FILE" 2>/dev/null || echo "")
fi

echo ""
if [[ "$BEFORE_MTIME" != "$AFTER_MTIME" && -s "$REVIEW_FILE" ]]; then
    echo "==> Review complete. ${REVIEW_BASENAME} has been updated."
    echo ""
    # Extract and display the verdict
    VERDICT=$(grep -m1 '^\*\*Verdict:\*\*' "$REVIEW_FILE" 2>/dev/null || echo "")
    if [ -n "$VERDICT" ]; then
        echo "    $VERDICT"
    fi
    echo ""
    echo "Next steps:"
    if echo "$VERDICT" | grep -q "APPROVED"; then
        if [[ "$REVIEW_TYPE" == "plan" ]]; then
            echo "  - Proceed to implementation (Phase 2)"
        else
            echo "  - Proceed to archival: ./scripts/archive-plan.sh $SPRINT_NUM \"$TITLE\""
        fi
    else
        echo "  - Address the reviewer's findings in ${REVIEW_BASENAME}"
        echo "  - Re-request review: $0 $REVIEW_TYPE $SPRINT_NUM \"$TITLE\""
    fi
else
    echo "Warning: ${REVIEW_BASENAME} was not updated. The reviewer may not have written output."
    echo "Check the reviewer output above for errors."
fi
