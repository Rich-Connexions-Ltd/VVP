#!/bin/bash
# Run pytest with libsodium library path for macOS
# Usage: ./scripts/run-tests.sh [pytest args...]
# Examples:
#   ./scripts/run-tests.sh                          # Run all tests
#   ./scripts/run-tests.sh -v                       # Verbose output
#   ./scripts/run-tests.sh tests/test_signature.py  # Run specific file
#   ./scripts/run-tests.sh -k "test_format"         # Run tests matching pattern

# Use .venv if present, otherwise system python3
if [ -d ".venv" ]; then
    source .venv/bin/activate
fi

DYLD_LIBRARY_PATH="/opt/homebrew/lib" python3 -m pytest tests/ "$@"
