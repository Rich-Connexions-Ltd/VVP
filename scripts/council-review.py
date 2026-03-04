#!/usr/bin/env python3
"""Council of Experts review system for VVP pair programming workflow.

Submits plans/code to 5 focused expert reviewers in parallel (Security,
Performance, Documentation, UX, Code Simplicity) across 4 platforms
(Anthropic, Google, OpenAI, Codex CLI), then consolidates their findings into a
single unified REVIEW file.

Usage:
    ./scripts/council-review.py plan <sprint> "<title>"
    ./scripts/council-review.py code <sprint> "<title>"

Requires environment variables:
    ANTHROPIC_API_KEY  — Claude models (Security, Consolidator)
    GOOGLE_API_KEY     — Gemini models (Performance, UX)
    OPENAI_API_KEY     — OpenAI models (if used by any member)
    (Codex platform members authenticate via 'codex' CLI automatically) (optional, if used by any member)
    (Codex CLI members authenticate via 'codex' CLI — no env var required)
"""

import json
import os
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

QUORUM_THRESHOLD = 3  # Minimum successful council reviews needed

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


def load_config(config_path: Path) -> dict:
    """Load council configuration from JSON file."""
    if not config_path.exists():
        print(f"ERROR: Config not found: {config_path}", file=sys.stderr)
        sys.exit(1)
    with open(config_path) as f:
        return json.load(f)


def get_active_members(config: dict, review_type: str) -> list[dict]:
    """Return only council members whose phases include the review type."""
    return [
        m for m in config["council"]["members"]
        if review_type in m.get("phases", ["plan", "code"])
    ]


def validate_api_keys(config: dict, active_members: list[dict]) -> dict[str, str]:
    """Validate API keys required by active members + consolidator. Returns {env_var: key}.

    Primary keys are required (script exits if missing). Fallback keys are
    optional — collected if available so they can be used when a primary fails.
    """
    required = set()
    optional = set()
    for member in active_members:
        env = member.get("api_key_env")
        if env:  # codex platform members have no api_key_env
            required.add(env)
        fallback = member.get("fallback")
        if fallback and fallback.get("api_key_env"):
            optional.add(fallback["api_key_env"])
    required.add(config["council"]["consolidator"]["api_key_env"])
    consolidator_fb = config["council"]["consolidator"].get("fallback")
    if consolidator_fb:
        optional.add(consolidator_fb["api_key_env"])

    keys = {}
    missing = []
    for env_var in sorted(required):
        val = os.environ.get(env_var)
        if val:
            keys[env_var] = val
        else:
            missing.append(env_var)

    if missing:
        print(f"ERROR: Missing required API key(s): {', '.join(missing)}", file=sys.stderr)
        print("Set them in your environment before running council review.", file=sys.stderr)
        sys.exit(1)

    # Collect optional fallback keys (don't fail if missing)
    for env_var in sorted(optional - required):
        val = os.environ.get(env_var)
        if val:
            keys[env_var] = val

    return keys


# ---------------------------------------------------------------------------
# API Clients (raw HTTP via httpx for Anthropic/OpenAI, SDK for Google)
# ---------------------------------------------------------------------------


def call_anthropic(
    model: str, system: str, user_content: str,
    max_tokens: int, temperature: float, api_key: str, timeout: float,
) -> str:
    """Call Anthropic Messages API via httpx."""
    import httpx

    resp = httpx.post(
        "https://api.anthropic.com/v1/messages",
        headers={
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
        json={
            "model": model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "system": system,
            "messages": [{"role": "user", "content": user_content}],
        },
        timeout=timeout,
    )
    try:
        resp.raise_for_status()
    except Exception as e:
        # Re-raise without the original request object to avoid leaking the API key
        # that was present in the x-api-key request header.
        raise RuntimeError(f"Anthropic API error: {e.response.status_code} {e.response.reason_phrase}") from None
    data = resp.json()
    return data["content"][0]["text"]


def call_openai(
    model: str, system: str, user_content: str,
    max_tokens: int, temperature: float, api_key: str, timeout: float,
) -> str:
    """Call OpenAI Chat Completions API via httpx."""
    import httpx

    resp = httpx.post(
        "https://api.openai.com/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json={
            "model": model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user_content},
            ],
        },
        timeout=timeout,
    )
    try:
        resp.raise_for_status()
    except Exception as e:
        # Re-raise without the original request object to avoid leaking the Bearer token
        # that was present in the Authorization request header.
        raise RuntimeError(f"OpenAI API error: {e.response.status_code} {e.response.reason_phrase}") from None
    data = resp.json()
    return data["choices"][0]["message"]["content"]


def call_google(
    model: str, contents: str,
    max_tokens: int, temperature: float, api_key: str, timeout: float,
) -> str:
    """Call Google GenAI API via the installed SDK."""
    from google import genai

    client = genai.Client(api_key=api_key)
    response = client.models.generate_content(
        model=model,
        contents=contents,
        config={"max_output_tokens": max_tokens, "temperature": temperature},
    )
    text = response.text
    if text is None:
        raise RuntimeError("Google API returned empty/blocked response (safety filter or quota exceeded)")
    return text


def call_codex(
    system: str, user_content: str, timeout: float,
) -> str:
    """Call Codex CLI via subprocess (codex exec --full-auto).

    Codex authenticates via its own stored credentials (run 'codex' once to
    authenticate). No API key required in the environment.
    """
    combined_prompt = f"{system}\n\n---\n\n{user_content}"
    try:
        # Pass prompt via stdin, not as a CLI argument. Command-line arguments
        # are visible to other processes via `ps aux`, which would expose the
        # full review context (potentially including API keys in the materials).
        result = subprocess.run(
            ["codex", "exec", "--full-auto"],
            input=combined_prompt,
            capture_output=True, text=True, timeout=timeout,
        )
    except FileNotFoundError:
        raise RuntimeError("Codex CLI not found. Install: npm install -g @openai/codex")
    if result.returncode != 0:
        raise RuntimeError(
            f"Codex exited {result.returncode}: {(result.stderr or result.stdout)[:500]}"
        )
    output = result.stdout.strip()
    if not output:
        raise RuntimeError("Codex produced no output")
    return output


def call_model(
    platform: str, model: str, system: str, user_content: str,
    max_tokens: int, temperature: float, api_key: str, timeout: float,
) -> str:
    """Dispatch to the appropriate platform API."""
    if platform == "anthropic":
        return call_anthropic(model, system, user_content, max_tokens, temperature, api_key, timeout)
    elif platform == "openai":
        return call_openai(model, system, user_content, max_tokens, temperature, api_key, timeout)
    elif platform == "google":
        # Google SDK doesn't separate system/user — concatenate
        combined = f"{system}\n\n---\n\n{user_content}"
        return call_google(model, combined, max_tokens, temperature, api_key, timeout)
    elif platform == "codex":
        # Codex CLI — uses its own auth, ignores model/api_key params
        return call_codex(system, user_content, timeout)
    else:
        raise ValueError(f"Unknown platform: {platform}")


# ---------------------------------------------------------------------------
# Material Gathering (reuses patterns from gemini-review.py)
# ---------------------------------------------------------------------------


def read_file_safe(path: Path, max_lines: int = 500) -> str:
    """Read a file, truncating if too long."""
    if not path.exists():
        return f"[File not found: {path}]"
    try:
        lines = path.read_text().splitlines()
        if len(lines) > max_lines:
            return "\n".join(lines[:max_lines]) + f"\n\n[... truncated, {len(lines)} total lines]"
        return "\n".join(lines)
    except Exception as e:
        return f"[Error reading {path}: {e}]"


def get_changed_files(sprint: str | None = None, repo_root: Path | None = None) -> list[str]:
    """Get list of changed files for code review.

    Strategy (priority order):
    1. Sprint base commit exists → diff from that commit to HEAD
    2. Uncommitted changes (staged + unstaged vs HEAD)
    3. Recent commits (HEAD~10..HEAD, increased from 5)
    4. Parse PLAN file "Files to Create/Modify" table as last resort
    """
    # Strategy 1: Sprint-aware diff from recorded base commit
    if sprint and repo_root:
        base_file = repo_root / f".sprint-base-commit-{sprint}"
        if base_file.exists():
            base_sha = base_file.read_text().strip()
            result = subprocess.run(
                ["git", "diff", "--name-only", f"{base_sha}..HEAD"],
                capture_output=True, text=True,
            )
            if result.returncode == 0 and result.stdout.strip():
                files = [f for f in result.stdout.strip().split("\n") if f]
                if files:
                    return files

    # Strategy 2: Uncommitted changes (staged + unstaged)
    result = subprocess.run(
        ["git", "diff", "--name-only", "HEAD"],
        capture_output=True, text=True,
    )
    if result.stdout.strip():
        files = [f for f in result.stdout.strip().split("\n") if f]
        if files:
            return files

    # Strategy 3: Recent commits (increased window)
    result = subprocess.run(
        ["git", "diff", "--name-only", "HEAD~10..HEAD"],
        capture_output=True, text=True,
    )
    if result.stdout.strip():
        files = [f for f in result.stdout.strip().split("\n") if f]
        if files:
            return files

    # Strategy 4: Parse plan file for expected files
    if sprint and repo_root:
        plan_file = repo_root / f"PLAN_Sprint{sprint}.md"
        if plan_file.exists():
            files = _parse_plan_file_list(plan_file)
            if files:
                return files

    return []


def _parse_plan_file_list(plan_file: Path) -> list[str]:
    """Extract file paths from the 'Files to Create/Modify' table in a PLAN file."""
    in_table = False
    files = []
    for line in plan_file.read_text().splitlines():
        if "Files to Create/Modify" in line or "Files Changed" in line:
            in_table = True
            continue
        if in_table:
            if line.startswith("|") and "`" in line:
                # Extract backtick-quoted path
                parts = line.split("`")
                if len(parts) >= 2:
                    path = parts[1].strip()
                    if path and not path.startswith("--"):
                        files.append(path)
            elif line.strip() == "" or line.startswith("#"):
                in_table = False
    return files


def gather_plan_materials(sprint: str, repo_root: Path) -> str:
    """Gather materials for a plan review."""
    sections = []

    plan_file = repo_root / f"PLAN_Sprint{sprint}.md"
    if plan_file.exists():
        content = read_file_safe(plan_file, max_lines=1000)
        sections.append(f"### {plan_file.name} (PRIMARY — this is what you are reviewing)\n```\n{content}\n```")
    else:
        print(f"ERROR: Plan file not found: {plan_file}", file=sys.stderr)
        sys.exit(1)

    changes_file = repo_root / "CHANGES.md"
    if changes_file.exists():
        content = read_file_safe(changes_file, max_lines=200)
        sections.append(f"### CHANGES.md (project history)\n```\n{content}\n```")

    history_file = repo_root / "Documentation" / "PLAN_history.md"
    if history_file.exists():
        content = read_file_safe(history_file, max_lines=300)
        sections.append(f"### Documentation/PLAN_history.md (prior decisions, truncated)\n```\n{content}\n```")

    return "\n\n".join(sections)


def gather_code_materials(sprint: str, repo_root: Path) -> str:
    """Gather materials for a code review."""
    sections = []

    plan_file = repo_root / f"PLAN_Sprint{sprint}.md"
    if plan_file.exists():
        content = read_file_safe(plan_file, max_lines=700)
        sections.append(f"### {plan_file.name} (approved plan)\n```\n{content}\n```")

    changes_file = repo_root / "CHANGES.md"
    if changes_file.exists():
        content = read_file_safe(changes_file, max_lines=200)
        sections.append(f"### CHANGES.md\n```\n{content}\n```")

    changed_files = get_changed_files(sprint=sprint, repo_root=repo_root)
    source_files = [
        f for f in changed_files
        if f.endswith((".py", ".yml", ".yaml", ".toml", ".json", ".html"))
        and not f.startswith("Documentation/")
        and "PLAN_" not in f
        and "REVIEW_" not in f
    ]

    for f in source_files[:25]:
        full_path = repo_root / f
        content = read_file_safe(full_path, max_lines=300)
        ext = Path(f).suffix.lstrip(".")
        sections.append(f"### {f}\n```{ext}\n{content}\n```")

    if changed_files:
        file_list = "\n".join(f"- {f}" for f in changed_files)
        sections.insert(0, f"### Changed Files\n{file_list}")

    return "\n\n".join(sections)


# ---------------------------------------------------------------------------
# Context Pack
# ---------------------------------------------------------------------------


def build_context_pack(review_type: str, repo_root: Path) -> str:
    """Build context pack using existing shell script, return content."""
    profile = "review-plan" if review_type == "plan" else "review-code"
    script = repo_root / "scripts" / "build_context_pack.sh"

    if script.exists():
        result = subprocess.run(
            [str(script), profile],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            print(f"  Warning: Context pack build failed: {result.stderr.strip()}", file=sys.stderr)
            return ""

    pack_file = repo_root / "codex" / "context" / "CONTEXT_PACK.md"
    if pack_file.exists():
        return pack_file.read_text()
    return ""


# ---------------------------------------------------------------------------
# Prompt Construction
# ---------------------------------------------------------------------------


def build_council_prompt(
    member: dict, materials: str, context_pack: str,
    sprint: str, title: str, round_num: int, review_type: str,
    knowledge_context: str | None = None,
) -> tuple[str, str]:
    """Build system + user prompts for a council member. Returns (system, user)."""
    role = member["role"]
    label = member["label"]
    lens = member["lens"]

    round_context = (
        "This is the first review of this plan."
        if round_num == 1
        else f"This is round {round_num}. The plan has been revised to address findings from previous rounds. Check that prior issues are resolved and look for new issues introduced by revisions."
    )

    review_type_label = "plan" if review_type == "plan" else "code implementation"

    system_prompt = f"""You are {label} on a review council for a pair programming workflow.

## Your Review Lens
{lens}"""

    # Domain expert gets enriched context from knowledge/ directory
    domain_section = ""
    if role == "domain" and knowledge_context:
        domain_section = f"""

## Deep Domain Reference
The following are authoritative reference documents for KERI/ACDC/vLEI/VVP.
Use these to validate correctness of designs and implementations.

{knowledge_context}
"""

    user_prompt = f"""## Review Type
This is a {review_type_label} review for Sprint {sprint}: {title} (Round {round_num}).
{round_context}

## Domain Context
{context_pack if context_pack else "[No domain context available]"}
{domain_section}
## Materials Under Review
{materials}

## Output Format

Write your review in EXACTLY this structure:

### {role} Review: Sprint {sprint} (R{round_num})

**Scope:** {label}

#### Findings
List findings ONLY within your area of focus. For each finding, include the file path and location:
- **[High]** description (File: `path/to/file.py`, Location: function_name or line range)
  - Current: what exists now
  - Fix: specific action to take
- **[Medium]** description (File: `path/to/file.py`, Location: function_name or line range)
  - Current: what exists now
  - Fix: specific action to take
- **[Low]** description (File: `path/to/file.py` if applicable)

If you find NO issues in your area, write: "No findings in this area."

#### Assessment
A 2-3 sentence overall assessment of the {review_type_label} from your expert perspective.

IMPORTANT:
- Stay strictly within your area of expertise
- Do NOT comment on areas outside your lens
- Be specific: cite file paths, line numbers (for code), or section names (for plans)
- For each finding, explain WHAT is wrong AND HOW to fix it
- Distinguish between genuine issues and stylistic preferences
- If uncertain, note the uncertainty rather than asserting"""

    return system_prompt, user_prompt


def build_consolidator_prompt(
    council_reviews: dict[str, str],
    sprint: str, title: str, round_num: int, review_type: str,
    member_labels: dict[str, str],
    tracker_content: str | None = None,
    escalation_note: str | None = None,
) -> tuple[str, str]:
    """Build system + user prompts for the consolidator. Returns (system, user)."""
    review_type_cap = "Plan" if review_type == "plan" else "Code"

    # Assemble council reviews
    review_sections = []
    for role, review_text in council_reviews.items():
        label = member_labels.get(role, role.title())
        review_sections.append(f"### {label}\n{review_text}")
    all_reviews = "\n\n---\n\n".join(review_sections)

    successful_count = sum(
        1 for r in council_reviews.values() if "UNAVAILABLE" not in r
    )

    system_prompt = """You are the Consolidation Lead for a review council. Multiple domain experts have independently reviewed a plan or implementation. Your job is to synthesize their findings into a single, coherent review with one verdict."""

    # Build plan-specific or code-specific output sections
    if review_type == "plan":
        assessment_sections = """### Spec Compliance
[Synthesized assessment of how well the plan addresses spec requirements]

### Design Assessment
[Synthesized evaluation of the proposed approach]"""
    else:
        assessment_sections = """### Implementation Assessment
[Does the code correctly implement the approved plan?]

### Code Quality
[Synthesized assessment of clarity, documentation, error handling]

### Test Coverage
[Synthesized assessment of test adequacy]"""

    # Build optional tracker section
    tracker_section = ""
    if tracker_content and round_num > 1:
        tracker_section = f"""

## Prior Findings Tracker
The editor has been tracking resolution of prior findings. Items marked ADDRESSED
have been fixed by the editor. Do NOT re-flag items marked ADDRESSED unless you have
specific evidence the fix is incomplete or incorrect. Focus on OPEN items and genuinely
NEW issues not covered by the tracker.

{tracker_content}
"""

    # Build optional escalation note
    escalation_section = ""
    if escalation_note:
        escalation_section = f"\n{escalation_note}\n"

    user_prompt = f"""## Council Reviews

{all_reviews}
{tracker_section}{escalation_section}
## Consolidation Instructions

1. **Identify overlapping concerns**: If multiple experts flagged the same underlying issue from different angles, merge them into one finding and cite all relevant perspectives.

2. **Resolve conflicts**: If experts disagree (e.g., Security wants more abstraction but Simplicity wants less), use your judgment to determine which concern dominates. Explain the trade-off briefly.

3. **Filter false positives**: If a finding is speculative, based on misunderstanding the domain, or clearly outside the expert's stated lens, exclude it. Note any excluded findings with brief rationale.

4. **Assign final severity**: Re-assess severity using this rubric:
   - [High]: Would cause a bug, security vulnerability, data loss, or spec violation if shipped. Blocks approval.
   - [Medium]: Would cause maintainability, performance, or usability problems. Should be fixed but does not block.
   - [Low]: Improvement suggestion. Optional.

   **Severity calibrations:**
   - A finding that was ADDRESSED in the tracker and re-appears MUST only be flagged if you can demonstrate the fix was incomplete — otherwise exclude it
   - Style preferences (naming, comment wording) are ALWAYS [Low], never higher
   - "Should extract/refactor" is [Low] unless it causes a concrete bug, security issue, or test failure
   - Test coverage gaps are [Medium] unless the untested path is a critical security/data-loss path

5. **Determine verdict**:
   - APPROVED: Zero [High] findings AND the overall design/implementation is sound
   - CHANGES_REQUESTED: One or more [High] findings, OR three or more [Medium] findings in the same area
   - PLAN_REVISION_REQUIRED (code reviews only): Fundamental design flaw discovered during implementation

6. **Produce the unified review** in the EXACT format below.

## Output Format

## {review_type_cap} Review: Sprint {sprint} - {title} (R{round_num})

**Round:** {round_num}
**Verdict:** APPROVED | CHANGES_REQUESTED{" | PLAN_REVISION_REQUIRED" if review_type == "code" else ""}
**Review Method:** Council of Experts ({successful_count} reviewers + consolidator)

{assessment_sections}

### Findings
- **[High]** description (File: `path/to/file`, Location: function_name) (Source: expert_name)
- **[Medium]** description (File: `path/to/file`, Location: function_name) (Source: expert_name)
- **[Low]** description (Source: expert_name)

### Excluded Findings
- description — Reason: why excluded (Source: expert_name)
[If none, write "No findings excluded."]

### Answers to Open Questions
[Synthesized from experts who addressed them. If none, write "No open questions."]

### Required Changes (if CHANGES_REQUESTED)
For each required change, provide ALL of the following:
1. **File**: exact file path
   **Location**: function/class name or line range
   **Current behavior**: what the code does now (or what the plan says now)
   **Required change**: exactly what must change
   **Acceptance criteria**: how to verify the fix is correct

{"### Plan Revisions (if PLAN_REVISION_REQUIRED)" + chr(10) + "[What needs to change in the plan]" + chr(10) if review_type == "code" else ""}
### Recommendations
[Consolidated optional improvements]

### Expert Concordance
| Area | Experts Agreeing | Key Theme |
|------|-----------------|-----------|
| ... | ... | ... |"""

    return system_prompt, user_prompt


# ---------------------------------------------------------------------------
# Council Execution
# ---------------------------------------------------------------------------


def _call_member(
    platform: str, model: str, api_key_env: str,
    system_prompt: str, user_prompt: str,
    max_tokens: int, temperature: float,
    api_keys: dict, timeout: float,
) -> str:
    """Make a single API call for a council member."""
    # codex platform: no api_key needed; other platforms: look up from api_keys dict
    api_key = None if platform == "codex" else api_keys.get(api_key_env, "")
    return call_model(
        platform=platform,
        model=model,
        system=system_prompt,
        user_content=user_prompt,
        max_tokens=max_tokens,
        temperature=temperature,
        api_key=api_key,
        timeout=timeout,
    )


def run_council_member(
    member: dict, materials: str, context_pack: str, api_keys: dict,
    sprint: str, title: str, round_num: int, review_type: str,
    timeout: float,
    knowledge_context: str | None = None,
) -> tuple[str, str, float]:
    """Run a single council member with automatic fallback. Returns (role, review_text, elapsed_seconds)."""
    role = member["role"]
    start = time.monotonic()

    system_prompt, user_prompt = build_council_prompt(
        member, materials, context_pack, sprint, title, round_num, review_type,
        knowledge_context=knowledge_context,
    )

    # Try primary model
    try:
        review = _call_member(
            member["platform"], member["model"], member["api_key_env"],
            system_prompt, user_prompt,
            member["max_tokens"], member["temperature"],
            api_keys, timeout,
        )
        elapsed = time.monotonic() - start
        return role, review, elapsed

    except Exception as primary_err:
        primary_msg = f"{type(primary_err).__name__}: {primary_err}"
        fallback = member.get("fallback")

        # Try fallback model if configured and its API key is available
        fb_key_env = fallback.get("api_key_env") if fallback else None
        fb_available = fallback and (fallback.get("platform") == "codex" or fb_key_env in api_keys)
        if fb_available:
            fb_platform = fallback["platform"]
            fb_model = fallback["model"]
            print(
                f"  WARNING: {member['label']} primary failed ({member['platform']}/{member['model']}), "
                f"trying fallback ({fb_platform}/{fb_model})...",
                file=sys.stderr,
            )
            try:
                review = _call_member(
                    fb_platform, fb_model, fallback.get("api_key_env"),
                    system_prompt, user_prompt,
                    member["max_tokens"], member["temperature"],
                    api_keys, timeout,
                )
                elapsed = time.monotonic() - start
                return role, review, elapsed
            except Exception as fb_err:
                fb_msg = f"{type(fb_err).__name__}: {fb_err}"
                error_msg = f"Primary: {primary_msg} | Fallback: {fb_msg}"
        else:
            error_msg = primary_msg

        elapsed = time.monotonic() - start
        print(f"  WARNING: {member['label']} failed ({elapsed:.1f}s): {error_msg}", file=sys.stderr)
        placeholder = (
            f"### {role} Review: Sprint {sprint} (R{round_num})\n\n"
            f"**Status:** UNAVAILABLE\n"
            f"**Error:** {error_msg}\n\n"
            f"This expert was unable to complete their review."
        )
        return role, placeholder, elapsed


def run_consolidator(
    config: dict, council_reviews: dict[str, str],
    member_labels: dict[str, str],
    sprint: str, title: str, round_num: int, review_type: str,
    api_keys: dict,
    tracker_content: str | None = None,
    escalation_note: str | None = None,
) -> str:
    """Run the consolidator with automatic fallback to produce the final unified review."""
    consolidator = config["council"]["consolidator"]
    timeout = config["council"].get("consolidator_timeout_seconds", 90)

    system_prompt, user_prompt = build_consolidator_prompt(
        council_reviews, sprint, title, round_num, review_type, member_labels,
        tracker_content=tracker_content,
        escalation_note=escalation_note,
    )

    # Try primary
    try:
        return call_model(
            platform=consolidator["platform"],
            model=consolidator["model"],
            system=system_prompt,
            user_content=user_prompt,
            max_tokens=consolidator["max_tokens"],
            temperature=consolidator["temperature"],
            api_key=api_keys[consolidator["api_key_env"]],
            timeout=timeout,
        )
    except Exception as primary_err:
        fallback = consolidator.get("fallback")
        fb_key_env = fallback.get("api_key_env") if fallback else None
        fb_available = fallback and (fallback.get("platform") == "codex" or fb_key_env in api_keys)
        if fb_available:
            fb_platform = fallback["platform"]
            fb_model = fallback["model"]
            print(
                f"  WARNING: Consolidator primary failed ({consolidator['platform']}/{consolidator['model']}), "
                f"trying fallback ({fb_platform}/{fb_model})...",
                file=sys.stderr,
            )
            try:
                return call_model(
                    platform=fb_platform,
                    model=fb_model,
                    system=system_prompt,
                    user_content=user_prompt,
                    max_tokens=consolidator["max_tokens"],
                    temperature=consolidator["temperature"],
                    api_key=api_keys[fallback["api_key_env"]],
                    timeout=timeout,
                )
            except Exception as fb_err:
                print(f"  WARNING: Consolidator fallback also failed: {fb_err}", file=sys.stderr)

        print(f"  WARNING: Consolidator failed: {primary_err}", file=sys.stderr)
        return fallback_consolidation(council_reviews, sprint, title, round_num, review_type)


def fallback_consolidation(
    council_reviews: dict[str, str],
    sprint: str, title: str, round_num: int, review_type: str,
) -> str:
    """Produce a synthetic review from raw council outputs when consolidator fails."""
    review_type_cap = "Plan" if review_type == "plan" else "Code"

    # Scan for High findings to determine verdict
    has_high = any("[High]" in r for r in council_reviews.values())
    verdict = "CHANGES_REQUESTED" if has_high else "APPROVED"

    successful_count = sum(
        1 for r in council_reviews.values() if "UNAVAILABLE" not in r
    )

    all_reviews = "\n\n---\n\n".join(
        f"### {role.title()}\n{text}" for role, text in council_reviews.items()
    )

    return f"""## {review_type_cap} Review: Sprint {sprint} - {title} (R{round_num})

**Round:** {round_num}
**Verdict:** {verdict}
**Review Method:** Council of Experts ({successful_count} reviewers, consolidator FAILED — raw reviews below)

> **Note:** The consolidator was unable to synthesize these reviews. The verdict above
> is a mechanical determination: CHANGES_REQUESTED if any [High] finding exists, else APPROVED.
> Please review the individual expert assessments below.

{all_reviews}
"""


# ---------------------------------------------------------------------------
# Round Tracking (compatible with existing .review-round-sprint<N>-<type>)
# ---------------------------------------------------------------------------


def increment_round(sprint: str, review_type: str, repo_root: Path) -> int:
    """Increment and return the review round number."""
    round_file = repo_root / f".review-round-sprint{sprint}-{review_type}"
    round_num = int(round_file.read_text().strip()) if round_file.exists() else 0
    round_num += 1
    round_file.write_text(str(round_num))

    # Record base commit on first plan review (used for code review diffs)
    if review_type == "plan" and round_num == 1:
        base_file = repo_root / f".sprint-base-commit-{sprint}"
        if not base_file.exists():
            result = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                capture_output=True, text=True,
            )
            if result.returncode == 0:
                base_file.write_text(result.stdout.strip())

    return round_num


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------


def extract_verdict(review_text: str) -> str:
    """Extract the verdict line from review text."""
    for line in review_text.splitlines():
        if "**Verdict:**" in line:
            return line.strip()
    return ""


# ---------------------------------------------------------------------------
# Findings Tracker
# ---------------------------------------------------------------------------


def _parse_findings(review_text: str, round_num: int) -> list[dict]:
    """Extract findings from consolidated review markdown."""
    findings = []
    finding_id = 0
    for line in review_text.splitlines():
        line_stripped = line.strip()
        # Match lines like: - **[High]** description or -   **[High]** description
        if not (line_stripped.startswith("-") and "**[" in line_stripped):
            continue
        severity = None
        for sev in ("High", "Medium", "Low"):
            if f"[{sev}]" in line_stripped:
                severity = sev
                break
        if not severity:
            continue
        finding_id += 1
        # Extract description after severity marker
        desc = line_stripped
        marker = f"**[{severity}]**"
        idx = desc.find(marker)
        if idx >= 0:
            desc = desc[idx + len(marker):].strip().lstrip("-").strip()
        # Truncate for table width
        if len(desc) > 120:
            desc = desc[:117] + "..."
        findings.append({
            "id": finding_id,
            "round": round_num,
            "severity": severity,
            "description": desc,
            "status": "OPEN",
            "resolution": "",
        })
    return findings


def _read_tracker(tracker_file: Path) -> list[dict]:
    """Parse existing tracker file into findings list."""
    findings = []
    in_table = False
    for line in tracker_file.read_text().splitlines():
        if line.startswith("| #"):
            in_table = True
            continue
        if in_table and line.startswith("|---"):
            continue
        if in_table and line.startswith("|"):
            parts = [p.strip() for p in line.split("|")[1:-1]]
            if len(parts) >= 6:
                fid = parts[0]
                findings.append({
                    "id": int(fid) if fid.isdigit() else 0,
                    "round": int(parts[1].lstrip("R")) if parts[1].lstrip("R").isdigit() else 0,
                    "severity": parts[2],
                    "description": parts[3],
                    "status": parts[4],
                    "resolution": parts[5],
                })
        elif in_table and not line.startswith("|"):
            in_table = False
    return findings


def _text_similarity(a: str, b: str) -> float:
    """Simple word-overlap similarity (Jaccard)."""
    words_a = set(a.lower().split())
    words_b = set(b.lower().split())
    if not words_a or not words_b:
        return 0.0
    return len(words_a & words_b) / len(words_a | words_b)


def _merge_findings(
    existing: list[dict], new_findings: list[dict], round_num: int,
) -> list[dict]:
    """Merge new findings with existing tracker, avoiding re-flagging of resolved items."""
    merged = list(existing)
    next_id = max((f["id"] for f in merged), default=0) + 1

    for nf in new_findings:
        matched = False
        for ef in merged:
            # Fuzzy match: same severity + substantial text overlap
            if (ef["severity"] == nf["severity"]
                    and _text_similarity(ef["description"], nf["description"]) > 0.4):
                matched = True
                if ef["status"] == "ADDRESSED":
                    ef["status"] = "REOPENED"
                    ef["resolution"] += f" [Reopened R{round_num}]"
                break
        if not matched:
            nf["id"] = next_id
            nf["round"] = round_num
            next_id += 1
            merged.append(nf)

    # Warn about circular findings
    for ef in merged:
        reopens = ef.get("resolution", "").count("[Reopened")
        if reopens >= 2:
            print(
                f"  WARNING: Finding #{ef['id']} reopened {reopens} times — "
                f"consider accepting as known debt or escalating.",
                file=sys.stderr,
            )

    return merged


def _write_tracker(
    tracker_file: Path, sprint: str, findings: list[dict], review_type: str,
) -> None:
    """Write findings tracker as markdown table."""
    lines = [
        f"# Findings Tracker: Sprint {sprint} ({review_type})",
        "",
        "Editor: Update the **Status** and **Resolution** columns after addressing each finding.",
        "Status values: `OPEN` | `ADDRESSED` | `VERIFIED` | `WONTFIX` | `REOPENED`",
        "",
        "| # | Round | Severity | Finding | Status | Resolution |",
        "|---|-------|----------|---------|--------|------------|",
    ]
    for f in findings:
        lines.append(
            f"| {f['id']} | R{f['round']} | {f['severity']} "
            f"| {f['description']} | {f['status']} | {f['resolution']} |"
        )
    lines.append("")
    tracker_file.write_text("\n".join(lines))


def update_findings_tracker(
    sprint: str, round_num: int, review_text: str,
    review_type: str, repo_root: Path,
) -> Path:
    """Parse findings from consolidated review and update the tracker file.

    On first round: creates tracker with all findings as OPEN.
    On subsequent rounds: adds new findings, preserves editor resolution notes.
    Returns the tracker file path.
    """
    tracker_file = repo_root / f"FINDINGS_Sprint{sprint}.md"
    new_findings = _parse_findings(review_text, round_num)

    if not tracker_file.exists():
        _write_tracker(tracker_file, sprint, new_findings, review_type)
    else:
        existing = _read_tracker(tracker_file)
        merged = _merge_findings(existing, new_findings, round_num)
        _write_tracker(tracker_file, sprint, merged, review_type)

    return tracker_file


def compute_convergence_score(tracker_file: Path) -> tuple[float, str]:
    """Compute convergence score from tracker: ratio of resolved to total findings.

    Returns (score 0.0-1.0, description).
    """
    if not tracker_file.exists():
        return 0.0, "No tracker"

    findings = _read_tracker(tracker_file)
    if not findings:
        return 1.0, "No findings"

    total = len(findings)
    resolved = sum(1 for f in findings if f["status"] in ("ADDRESSED", "VERIFIED", "WONTFIX"))
    open_count = sum(1 for f in findings if f["status"] == "OPEN")
    reopened = sum(1 for f in findings if f["status"] == "REOPENED")

    score = resolved / total if total > 0 else 1.0
    desc = f"{resolved}/{total} resolved, {open_count} open, {reopened} reopened"

    return score, desc


def print_header(
    sprint: str, title: str, round_num: int, review_type: str,
    active_members: list[dict], config: dict,
) -> None:
    """Print the review header."""
    all_members = config["council"]["members"]
    consolidator = config["council"]["consolidator"]

    print(f"==> Council review for Sprint {sprint}: {title} (Round {round_num})")
    print(f"    Review type:      {review_type}")
    print(f"    Active members:   {len(active_members)} of {len(all_members)}")
    for m in active_members:
        print(f"      - {m['label']:25s} ({m['platform']}/{m['model']})")
    skipped = [m for m in all_members if m not in active_members]
    if skipped:
        print(f"    Skipped ({review_type} phase):")
        for m in skipped:
            print(f"      - {m['label']:25s} (phases: {', '.join(m.get('phases', ['plan', 'code']))})")
    print(f"    Consolidator:     {consolidator['platform']}/{consolidator['model']}")
    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    if len(sys.argv) < 4:
        print("Usage: ./scripts/council-review.py <plan|code> <sprint> <title>")
        print()
        print("  plan  — Review the implementation plan in PLAN_Sprint<N>.md")
        print("  code  — Review the implementation (changed files since plan approval)")
        print()
        print("Examples:")
        print('  ./scripts/council-review.py plan 77 "Credential Revocation"')
        print('  ./scripts/council-review.py code 77 "Credential Revocation"')
        print()
        print("Required environment variables:")
        print("  ANTHROPIC_API_KEY  — Claude models")
        print("  GOOGLE_API_KEY     — Gemini models")
        print("  OPENAI_API_KEY     — OpenAI models (if used by any member)")
        print("  (Codex platform members authenticate via 'codex' CLI automatically)")
        sys.exit(1)

    review_type = sys.argv[1]
    sprint = sys.argv[2]
    title = " ".join(sys.argv[3:])

    if review_type not in ("plan", "code"):
        print(f"ERROR: review_type must be 'plan' or 'code', got '{review_type}'", file=sys.stderr)
        sys.exit(1)

    repo_root = Path(subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        capture_output=True, text=True,
    ).stdout.strip())

    # Load config
    config_path = repo_root / "scripts" / "council-config.json"
    config = load_config(config_path)

    # Filter members by phase
    active_members = get_active_members(config, review_type)
    if not active_members:
        print(f"ERROR: No council members configured for '{review_type}' phase", file=sys.stderr)
        sys.exit(1)

    # Validate API keys (only for active members + consolidator)
    api_keys = validate_api_keys(config, active_members)

    # Round tracking
    round_num = increment_round(sprint, review_type, repo_root)

    # Print header
    print_header(sprint, title, round_num, review_type, active_members, config)

    # Build context pack
    print("  Building context pack...")
    context_pack = build_context_pack(review_type, repo_root)
    if context_pack:
        print(f"  Context pack: {len(context_pack):,} chars")
    else:
        print("  Context pack: (none)")

    # Gather materials
    print("  Gathering materials...")
    if review_type == "plan":
        materials = gather_plan_materials(sprint, repo_root)
    else:
        materials = gather_code_materials(sprint, repo_root)
    print(f"  Materials: {len(materials):,} chars")
    print()

    # Prepare council output directory
    council_dir = repo_root / config["council"].get("output_dir", "council")
    if council_dir.exists():
        shutil.rmtree(council_dir)
    council_dir.mkdir(parents=True)

    # Build member label lookup (active members only)
    member_labels = {m["role"]: m["label"] for m in active_members}

    # Load knowledge files for domain expert (if active)
    knowledge_context = None
    has_domain_expert = any(m["role"] == "domain" for m in active_members)
    if has_domain_expert:
        knowledge_dir = repo_root / "knowledge"
        if knowledge_dir.exists():
            domain_files = ["keri-primer.md", "schemas.md", "verification-pipeline.md"]
            sections = []
            for fname in domain_files:
                fpath = knowledge_dir / fname
                if fpath.exists():
                    content = read_file_safe(fpath, max_lines=200)
                    sections.append(f"### {fname}\n{content}")
            if sections:
                knowledge_context = "\n\n".join(sections)
                print(f"  Domain knowledge: {len(knowledge_context):,} chars ({len(sections)} files)")

    # Run council in parallel
    parallel_timeout = config["council"].get("parallel_timeout_seconds", 60)

    print(f"  Running {len(active_members)} council members in parallel...")
    council_reviews: dict[str, str] = {}

    with ThreadPoolExecutor(max_workers=len(active_members)) as executor:
        futures = {
            executor.submit(
                run_council_member,
                member, materials, context_pack, api_keys,
                sprint, title, round_num, review_type,
                parallel_timeout,
                knowledge_context=knowledge_context,
            ): member
            for member in active_members
        }

        for future in as_completed(futures):
            member = futures[future]
            try:
                role, review_text, elapsed = future.result(timeout=parallel_timeout + 10)
                council_reviews[role] = review_text

                # Write individual review file
                review_file = council_dir / f"{role}.md"
                review_file.write_text(review_text)

                status = "UNAVAILABLE" if "UNAVAILABLE" in review_text else "done"
                print(f"    {member['label']:25s} {status:12s} ({elapsed:.1f}s)")
            except Exception as e:
                role = member["role"]
                council_reviews[role] = (
                    f"### {role} Review: Sprint {sprint} (R{round_num})\n\n"
                    f"**Status:** UNAVAILABLE\n"
                    f"**Error:** Timeout or execution error: {e}\n\n"
                    f"This expert was unable to complete their review."
                )
                print(f"    {member['label']:25s} FAILED       ({e})")

    # Check quorum
    successful = sum(1 for r in council_reviews.values() if "UNAVAILABLE" not in r)
    print()
    print(f"  Council complete: {successful}/{len(active_members)} experts succeeded")

    if successful < QUORUM_THRESHOLD:
        print(f"  ERROR: Quorum not met ({successful} < {QUORUM_THRESHOLD}). Aborting.", file=sys.stderr)
        sys.exit(1)

    # Read existing findings tracker for consolidator context
    tracker_file = repo_root / f"FINDINGS_Sprint{sprint}.md"
    tracker_content = tracker_file.read_text() if tracker_file.exists() else None

    # Convergence guardrails
    max_rounds_key = "max_plan_rounds" if review_type == "plan" else "max_code_rounds"
    max_rounds = config["council"].get(max_rounds_key, 8)
    warning_at = config["council"].get("convergence_warning_at", 3)

    escalation_note = None
    if round_num > max_rounds:
        print(f"\n  WARNING: Round {round_num} exceeds max ({max_rounds}) for {review_type} reviews.")
        print(f"  ESCALATION: Consider accepting remaining issues as known debt.")
        escalation_note = (
            f"\nESCALATION: This is round {round_num}, exceeding the configured maximum "
            f"of {max_rounds}. The process has not converged. You MUST:\n"
            f"1. Only flag genuinely NEW [High] findings not present in prior rounds\n"
            f"2. Downgrade previously-flagged issues that are partially addressed to [Low]\n"
            f"3. If no new [High] findings exist, verdict MUST be APPROVED\n"
            f"4. List all unresolved items in a 'Known Debt' section instead of blocking\n"
        )

    # Run consolidator
    print(f"  Running consolidator ({config['council']['consolidator']['model']})...")
    start = time.monotonic()
    consolidated = run_consolidator(
        config, council_reviews, member_labels,
        sprint, title, round_num, review_type, api_keys,
        tracker_content=tracker_content,
        escalation_note=escalation_note,
    )
    elapsed = time.monotonic() - start
    print(f"  Consolidator complete ({elapsed:.1f}s)")

    # Write REVIEW file
    review_file = repo_root / f"REVIEW_Sprint{sprint}.md"
    review_file.write_text(consolidated)
    print()
    print(f"==> Review written to {review_file.name}")

    # Update findings tracker
    tracker_file = update_findings_tracker(sprint, round_num, consolidated, review_type, repo_root)
    print(f"    Findings tracker: {tracker_file.name}")

    # Extract and display verdict
    verdict = extract_verdict(consolidated)
    if verdict:
        print(f"    {verdict}")
    else:
        print("    WARNING: No verdict found in consolidated review")

    # Display convergence score (round 2+)
    if round_num > 1:
        score, desc = compute_convergence_score(tracker_file)
        print(f"    Convergence: {score:.0%} ({desc})")
        if score < 0.5 and round_num >= warning_at:
            print(f"    WARNING: Low convergence ({score:.0%}) at round {round_num}.")
            print(f"    Consider addressing [High] items only and deferring [Medium]/[Low].")

    # Next steps
    print()
    if verdict and "APPROVED" in verdict and "CHANGES_REQUESTED" not in verdict:
        if review_type == "plan":
            print("  Next: Proceed to implementation (Phase 2)")
        else:
            print(f'  Next: ./scripts/archive-plan.sh {sprint} "{title}"')
    else:
        print("  Next: Address findings in FINDINGS_Sprint{sprint}.md, then re-run:")
        print(f'        ./scripts/council-review.py {review_type} {sprint} "{title}"')


if __name__ == "__main__":
    main()
