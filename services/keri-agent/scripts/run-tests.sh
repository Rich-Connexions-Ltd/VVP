#!/bin/bash
# Run KERI Agent tests with libsodium path configured.
# Usage: ./scripts/run-tests.sh [pytest-args...]
#
# Sprint 68: KERI Agent Service Extraction.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$SERVICE_DIR/../.." && pwd)"

# Set libsodium library path (macOS via Homebrew)
export DYLD_LIBRARY_PATH="/opt/homebrew/lib${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}"

# Ensure common package is available
if ! python3 -c "import common.vvp" 2>/dev/null; then
    pip install -e "$REPO_ROOT/common" --quiet 2>/dev/null || true
fi

# Run pytest from the service directory
cd "$SERVICE_DIR"
python3 -m pytest "$@"
