#!/usr/bin/env python3
"""Gemini-based reviewer for VVP pair programming workflow.

Supports both plan and code reviews. For plan reviews, focuses on the PLAN file
and project context. For code reviews, includes git diff changed files.

Usage:
    python3 scripts/gemini-review.py plan 69 "Ephemeral LMDB"
    python3 scripts/gemini-review.py code 69 "Ephemeral LMDB"

Requires: GOOGLE_API_KEY environment variable.
"""

import os
import subprocess
import sys
from pathlib import Path


def get_changed_files() -> list[str]:
    """Get list of changed files (uncommitted or recent commits)."""
    result = subprocess.run(
        ["git", "diff", "--name-only"], capture_output=True, text=True
    )
    files = result.stdout.strip().split("\n") if result.stdout.strip() else []
    if not files or files == [""]:
        result = subprocess.run(
            ["git", "diff", "--name-only", "HEAD~5..HEAD"],
            capture_output=True, text=True,
        )
        files = result.stdout.strip().split("\n") if result.stdout.strip() else []
    return [f for f in files if f]


def read_file_safe(path: str, max_lines: int = 500) -> str:
    """Read a file, truncating if too long."""
    try:
        p = Path(path)
        if not p.exists():
            return f"[File not found: {path}]"
        lines = p.read_text().splitlines()
        if len(lines) > max_lines:
            return "\n".join(lines[:max_lines]) + f"\n\n[... truncated, {len(lines)} total lines]"
        return "\n".join(lines)
    except Exception as e:
        return f"[Error reading {path}: {e}]"


def build_plan_prompt(sprint: str, title: str, round_num: int) -> str:
    """Build a plan review prompt focused on the PLAN file and project context."""
    repo_root = Path(subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        capture_output=True, text=True,
    ).stdout.strip())

    plan_file = repo_root / f"PLAN_Sprint{sprint}.md"
    changes_file = repo_root / "CHANGES.md"
    plan_history = repo_root / "Documentation" / "PLAN_history.md"

    file_sections = []

    # Plan file is the PRIMARY review target
    if plan_file.exists():
        content = read_file_safe(str(plan_file), max_lines=1000)
        file_sections.append(f"### {plan_file.name} (PRIMARY — this is what you are reviewing)\n```\n{content}\n```")
    else:
        return f"ERROR: Plan file not found: {plan_file}"

    # CHANGES.md for project history context
    if changes_file.exists():
        content = read_file_safe(str(changes_file), max_lines=200)
        file_sections.append(f"### CHANGES.md (project history)\n```\n{content}\n```")

    # PLAN_history.md for prior architectural decisions (truncated)
    if plan_history.exists():
        content = read_file_safe(str(plan_history), max_lines=300)
        file_sections.append(f"### Documentation/PLAN_history.md (prior decisions, truncated)\n```\n{content}\n```")

    files_content = "\n\n".join(file_sections)

    round_context = (
        "This is the first review of this plan."
        if round_num == 1
        else f"This is round {round_num}. The plan has been revised to address findings from previous rounds. Check that prior issues are resolved and look for any new issues introduced."
    )

    prompt = f"""You are a senior code architect acting as Reviewer in a pair programming workflow.
You are reviewing the PLAN for Sprint {sprint}: {title} — plan review round {round_num}.
{round_context}

IMPORTANT: This is a PLAN review, not a code review. You are evaluating the proposed design
BEFORE implementation. There is no code to review yet — focus on the plan document.

## Files

{files_content}

## Plan Review Instructions

1. Read CHANGES.md and PLAN_history.md for project context and prior decisions
2. Read PLAN_Sprint{sprint}.md — the plan under review
3. Evaluate the plan against these criteria:
   - Does it correctly interpret the spec requirements cited?
   - Is the proposed approach sound and well-justified?
   - Is it consistent with prior decisions, or does it justify departures?
   - Are there gaps, ambiguities, or risks not addressed?
   - Is the test strategy adequate?
4. Answer any Open Questions listed in the plan

Write your review in EXACTLY this format:

## Plan Review: Sprint {sprint} - {title} (R{round_num})

**Round:** {round_num}
**Verdict:** APPROVED | CHANGES_REQUESTED | PLAN_REVISION_REQUIRED

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

### Plan Revisions (if PLAN_REVISION_REQUIRED)
[What needs to change in the plan]

### Recommendations
[Optional improvements or future considerations]
"""
    return prompt


def build_code_prompt(sprint: str, title: str, round_num: int) -> str:
    """Build a code review prompt with changed files inline."""
    repo_root = Path(subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        capture_output=True, text=True,
    ).stdout.strip())

    plan_file = repo_root / f"PLAN_Sprint{sprint}.md"
    changes_file = repo_root / "CHANGES.md"

    # Get changed files
    changed_files = get_changed_files()

    # Build file contents section
    file_sections = []

    # Always include plan
    if plan_file.exists():
        content = read_file_safe(str(plan_file), max_lines=700)
        file_sections.append(f"### {plan_file.name}\n```\n{content}\n```")

    # Include CHANGES.md (truncated)
    if changes_file.exists():
        content = read_file_safe(str(changes_file), max_lines=200)
        file_sections.append(f"### CHANGES.md\n```\n{content}\n```")

    # Include changed source files (not docs/plans)
    source_files = [
        f for f in changed_files
        if f.endswith((".py", ".yml", ".yaml", ".toml"))
        and not f.startswith("Documentation/")
        and "PLAN_" not in f
        and "REVIEW_" not in f
    ]

    for f in source_files[:25]:  # Limit to 25 files
        full_path = repo_root / f
        content = read_file_safe(str(full_path), max_lines=300)
        file_sections.append(f"### {f}\n```python\n{content}\n```")

    files_content = "\n\n".join(file_sections)
    changed_list = "\n".join(f"- {f}" for f in changed_files)

    round_context = (
        "This is the first review of this implementation."
        if round_num == 1
        else f"This is round {round_num}. The code has been revised to address findings from previous rounds. Check that prior issues are resolved and look for any new issues introduced."
    )

    prompt = f"""You are a senior code architect acting as Reviewer in a pair programming workflow.
You are reviewing the implementation for Sprint {sprint}: {title} — code review round {round_num}.
{round_context}

## Changed Files
{changed_list}

## File Contents

{files_content}

## Review Instructions

1. Evaluate whether the code correctly implements the approved plan
2. Check code quality: clarity, documentation, error handling
3. Check test coverage: are edge cases handled?
4. Check for security concerns
5. Look for consistency across services (e.g., same SAID algorithm everywhere)

Write your review in EXACTLY this format:

## Code Review: Sprint {sprint} - {title} (R{round_num})

**Round:** {round_num}
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
"""
    return prompt


def build_prompt(review_type: str, sprint: str, title: str, round_num: int) -> str:
    """Build the review prompt based on review type (plan or code)."""
    if review_type == "plan":
        return build_plan_prompt(sprint, title, round_num)
    else:
        return build_code_prompt(sprint, title, round_num)


def main():
    if len(sys.argv) < 4:
        print("Usage: python3 scripts/gemini-review.py <plan|code> <sprint> <title>")
        sys.exit(1)

    review_type = sys.argv[1]
    sprint = sys.argv[2]
    title = " ".join(sys.argv[3:])

    if review_type not in ("plan", "code"):
        print(f"ERROR: review_type must be 'plan' or 'code', got '{review_type}'", file=sys.stderr)
        sys.exit(1)

    api_key = os.environ.get("GOOGLE_API_KEY") or os.environ.get("GOOGLE_GENAI_API_KEY")
    if not api_key:
        print("ERROR: Set GOOGLE_API_KEY environment variable", file=sys.stderr)
        sys.exit(1)

    # Round tracking
    repo_root = Path(subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        capture_output=True, text=True,
    ).stdout.strip())

    round_file = repo_root / f".review-round-sprint{sprint}-{review_type}"
    round_num = int(round_file.read_text().strip()) if round_file.exists() else 0
    round_num += 1
    round_file.write_text(str(round_num))

    review_file = repo_root / f"REVIEW_Sprint{sprint}.md"

    print(f"==> Requesting {review_type} review for Sprint {sprint}: {title} (Round {round_num})")
    print(f"    Reviewer: Gemini 2.5 Pro")
    print(f"    Review:   REVIEW_Sprint{sprint}.md")
    print(f"    Round:    {round_num}")
    print()

    # Build prompt
    prompt = build_prompt(review_type, sprint, title, round_num)
    print(f"    Prompt size: {len(prompt):,} chars")

    # Call Gemini
    from google import genai

    client = genai.Client(api_key=api_key)

    print("    Calling Gemini 2.5 Pro...")
    response = client.models.generate_content(
        model="gemini-2.5-pro",
        contents=prompt,
        config={
            "max_output_tokens": 8192,
            "temperature": 0.2,
        },
    )

    review_text = response.text

    # Write review file
    review_file.write_text(review_text)
    print(f"\n==> Review written to {review_file.name}")

    # Extract verdict
    for line in review_text.splitlines():
        if "**Verdict:**" in line:
            print(f"    {line.strip()}")
            break

    print()
    if "APPROVED" in review_text.split("Verdict")[1][:50] if "Verdict" in review_text else "":
        print(f"  Next: ./scripts/archive-plan.sh {sprint} \"{title}\"")
    else:
        print(f"  Next: Address findings, then re-run review")


if __name__ == "__main__":
    main()
