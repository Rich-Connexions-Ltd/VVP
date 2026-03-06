#!/usr/bin/env bash
# Run VVP MCP server with correct library paths.
#
# This wrapper ensures libsodium is available (same approach as run-tests.sh)
# and launches the MCP server in stdio mode for Claude Code integration.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

# libsodium (required by KERI/Ed25519 operations)
export DYLD_LIBRARY_PATH="/opt/homebrew/lib:${DYLD_LIBRARY_PATH:-}"

cd "$REPO_ROOT"
exec python3 -m common.vvp.mcp.server
