#!/bin/bash
# Watch FreeSWITCH channels for VVP variables
# Usage: ./watch-channels.sh [refresh_interval]

INTERVAL=${1:-1}  # Default: refresh every 1 second

echo "============================================"
echo "VVP Channel Variable Monitor"
echo "============================================"
echo "Refresh interval: ${INTERVAL}s"
echo "Press Ctrl+C to stop"
echo ""

# Check if fs_cli is available
if ! command -v fs_cli &> /dev/null; then
    echo "ERROR: fs_cli not found. Is FreeSWITCH installed?"
    exit 1
fi

# Watch loop
watch -n "$INTERVAL" '
echo "=== Active Channels with VVP Variables ==="
echo ""
fs_cli -x "show channels" 2>/dev/null | head -5
echo ""
echo "--- VVP Variables ---"
fs_cli -x "show channels" 2>/dev/null | grep -E "(uuid|vvp_)" || echo "(no VVP variables found)"
echo ""
echo "--- Channel Count ---"
fs_cli -x "show channels count" 2>/dev/null
'
