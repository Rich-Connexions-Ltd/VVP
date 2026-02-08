#!/usr/bin/env bash
# archive-plan.sh — Automates Phase 3 (Completion and Archival) of the pair programming workflow.
#
# Usage:
#   ./scripts/archive-plan.sh <sprint-number> <title>
#
# Example:
#   ./scripts/archive-plan.sh 35 "Credential Issuance"
#
# Files (namespaced by sprint number for concurrent safety):
#   Plan file:    PLAN_Sprint<N>.md    → Documentation/archive/PLAN_Sprint<N>.md
#   Review file:  REVIEW_Sprint<N>.md  (deleted after archival)
#
# What it does:
#   1. Appends PLAN_Sprint<N>.md content to Documentation/PLAN_history.md under a sprint header
#   2. Moves PLAN_Sprint<N>.md to Documentation/archive/PLAN_Sprint<N>.md
#   3. Removes REVIEW_Sprint<N>.md
#   4. Prints a reminder to update CHANGES.md (left manual since it needs human-written summary)

set -euo pipefail

if [ $# -lt 2 ]; then
    echo "Usage: $0 <sprint-number> <title>"
    echo "Example: $0 35 \"Credential Issuance\""
    exit 1
fi

SPRINT_NUM="$1"
shift
TITLE="$*"

REPO_ROOT="$(git rev-parse --show-toplevel)"
PLAN_FILE="$REPO_ROOT/PLAN_Sprint${SPRINT_NUM}.md"
HISTORY_FILE="$REPO_ROOT/Documentation/PLAN_history.md"
ARCHIVE_DIR="$REPO_ROOT/Documentation/archive"
ARCHIVE_FILE="$ARCHIVE_DIR/PLAN_Sprint${SPRINT_NUM}.md"
REVIEW_FILE="$REPO_ROOT/REVIEW_Sprint${SPRINT_NUM}.md"

PLAN_BASENAME="PLAN_Sprint${SPRINT_NUM}.md"
REVIEW_BASENAME="REVIEW_Sprint${SPRINT_NUM}.md"

# --- Validate ---

if [ ! -f "$PLAN_FILE" ]; then
    echo "Error: $PLAN_BASENAME not found at $PLAN_FILE"
    echo "Nothing to archive."
    exit 1
fi

if [ -f "$ARCHIVE_FILE" ]; then
    echo "Error: $ARCHIVE_FILE already exists."
    echo "Sprint $SPRINT_NUM appears to have been archived already."
    exit 1
fi

# --- Ensure directories exist ---

mkdir -p "$ARCHIVE_DIR"

# --- Step 1: Append to PLAN_history.md ---

echo ""
echo "==> Appending to PLAN_history.md..."

{
    echo ""
    echo "---"
    echo ""
    echo "# Sprint ${SPRINT_NUM}: ${TITLE}"
    echo ""
    echo "_Archived: $(date +%Y-%m-%d)_"
    echo ""
    cat "$PLAN_FILE"
    echo ""
} >> "$HISTORY_FILE"

echo "    Done. Plan appended under 'Sprint ${SPRINT_NUM}: ${TITLE}'"

# --- Step 2: Move plan to archive ---

echo ""
echo "==> Moving $PLAN_BASENAME to archive..."
cp "$PLAN_FILE" "$ARCHIVE_FILE"
rm "$PLAN_FILE"
echo "    Done. Archived as $(basename "$ARCHIVE_FILE")"

# --- Step 3: Remove review file ---

echo ""
if [ -f "$REVIEW_FILE" ]; then
    echo "==> Removing $REVIEW_BASENAME..."
    rm "$REVIEW_FILE"
    echo "    Done."
else
    echo "==> No $REVIEW_BASENAME to remove (already clean)."
fi

# --- Step 4: Remind about CHANGES.md ---

echo ""
echo "==> Archival complete for Sprint ${SPRINT_NUM}: ${TITLE}"
echo ""
echo "Remaining manual step:"
echo "  - Update CHANGES.md with the sprint summary, files changed, and commit SHA"
echo "  - Then commit all documentation changes"
echo ""
echo "Files modified:"
echo "  - Documentation/PLAN_history.md  (appended)"
echo "  - Documentation/archive/PLAN_Sprint${SPRINT_NUM}.md  (created)"
echo "  - $PLAN_BASENAME  (removed)"
[ -f "$REVIEW_FILE" ] || echo "  - $REVIEW_BASENAME  (removed)"
