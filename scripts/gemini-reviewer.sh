#!/usr/bin/env bash
# Gemini-based code reviewer for VVP pair programming workflow.
# Usage: VVP_REVIEWER=./scripts/gemini-reviewer.sh ./scripts/request-review-with-context.sh ...
#
# Reads the review prompt from stdin, sends it to Gemini, writes output to REVIEW file.
# Requires GOOGLE_API_KEY or GOOGLE_GENAI_API_KEY environment variable.

set -euo pipefail

# Read prompt from stdin (piped by request-review.sh)
PROMPT=$(cat)

# Use Python to call Gemini API
python3 - "$PROMPT" "$@" <<'PYEOF'
import sys
import os

# Get the prompt
prompt = sys.argv[1]

# Remaining args may include file paths to read
# The reviewer script receives: <prompt> as stdin, and the working dir is the repo root

from google import genai

# Initialize client
api_key = os.environ.get("GOOGLE_API_KEY") or os.environ.get("GOOGLE_GENAI_API_KEY")
if not api_key:
    print("ERROR: Set GOOGLE_API_KEY or GOOGLE_GENAI_API_KEY", file=sys.stderr)
    sys.exit(1)

client = genai.Client(api_key=api_key)

# Send to Gemini
response = client.models.generate_content(
    model="gemini-2.5-pro",
    contents=prompt,
    config={
        "max_output_tokens": 8192,
        "temperature": 0.2,
    },
)

# Output the response (request-review.sh captures stdout)
print(response.text)
PYEOF
