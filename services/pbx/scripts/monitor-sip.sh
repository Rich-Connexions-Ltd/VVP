#!/bin/bash
# Real-time SIP monitoring with VVP header filtering
# Usage: ./monitor-sip.sh [duration_seconds]

DURATION=${1:-0}  # 0 = run until Ctrl+C
OUTPUT_DIR="/tmp"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
PCAP_FILE="${OUTPUT_DIR}/vvp_sip_${TIMESTAMP}.pcap"

echo "============================================"
echo "VVP SIP Monitor"
echo "============================================"
echo "Output file: ${PCAP_FILE}"
echo "Press Ctrl+C to stop"
echo ""

# Check if sngrep is available
if command -v sngrep &> /dev/null; then
    echo "Using sngrep for SIP capture..."
    if [ "$DURATION" -gt 0 ]; then
        timeout "$DURATION" sngrep -c -d any -O "$PCAP_FILE"
    else
        sngrep -c -d any -O "$PCAP_FILE"
    fi
else
    echo "sngrep not found, using tcpdump..."
    if command -v tcpdump &> /dev/null; then
        if [ "$DURATION" -gt 0 ]; then
            timeout "$DURATION" tcpdump -i any -w "$PCAP_FILE" 'port 5060 or port 5070'
        else
            tcpdump -i any -w "$PCAP_FILE" 'port 5060 or port 5070'
        fi
    else
        echo "ERROR: Neither sngrep nor tcpdump found. Install one:"
        echo "  apt install sngrep"
        echo "  apt install tcpdump"
        exit 1
    fi
fi

echo ""
echo "Capture saved to: ${PCAP_FILE}"
echo "To analyze: sngrep -I ${PCAP_FILE}"
