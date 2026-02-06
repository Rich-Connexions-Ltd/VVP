#!/bin/bash
# Tail FreeSWITCH logs filtered for VVP messages
# Usage: ./tail-vvp-logs.sh [num_lines]

NUM_LINES=${1:-100}  # Default: show last 100 lines first
LOG_FILE="/var/log/freeswitch/freeswitch.log"

echo "============================================"
echo "VVP Log Viewer"
echo "============================================"
echo "Log file: ${LOG_FILE}"
echo "Filter: VVP, Identity, X-VVP headers"
echo "Press Ctrl+C to stop"
echo ""

# Check if log file exists
if [ ! -f "$LOG_FILE" ]; then
    echo "ERROR: Log file not found: ${LOG_FILE}"
    echo "Trying alternate location..."
    LOG_FILE="/usr/local/freeswitch/log/freeswitch.log"
    if [ ! -f "$LOG_FILE" ]; then
        echo "ERROR: Log file not found at alternate location either."
        echo "Check FreeSWITCH installation and log configuration."
        exit 1
    fi
fi

# Show recent matching lines first
echo "--- Recent VVP Log Entries (last ${NUM_LINES} lines) ---"
grep -E "(VVP|Identity|X-VVP|P-VVP|sip_h_)" "$LOG_FILE" | tail -n "$NUM_LINES"
echo ""

# Then follow new entries
echo "--- Following new entries (Ctrl+C to stop) ---"
tail -f "$LOG_FILE" | grep --line-buffered -E "(VVP|Identity|X-VVP|P-VVP|sip_h_)"
