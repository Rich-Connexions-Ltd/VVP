#!/usr/bin/env bash
# =============================================================================
# VVP Service Warmup — Wait for Cold-Start Services
# =============================================================================
#
# Polls all VVP services until they report healthy, printing one line per
# service as it comes up. Shows (x/y, Ts) progress counter.
#
# Usage:
#   ./scripts/wait-for-services.sh                # Wait for production
#   ./scripts/wait-for-services.sh --local         # Wait for local dev stack
#   ./scripts/wait-for-services.sh --timeout 300   # Custom timeout (seconds)
#   ./scripts/wait-for-services.sh --json          # Output JSON summary
#
# Exit codes:
#   0  All services ready
#   1  Timeout — one or more services did not become ready
#   2  Script error
#
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    BOLD='\033[1m'
    DIM='\033[2m'
    NC='\033[0m'
else
    RED='' GREEN='' BOLD='' DIM='' NC=''
fi

MODE="azure"
TIMEOUT=180
POLL_INTERVAL=5
JSON_OUTPUT=false

# Azure production URLs
VERIFIER_URL="https://vvp-verifier.rcnx.io"
ISSUER_URL="https://vvp-issuer.rcnx.io"
KERI_AGENT_URL=""
WITNESS1_URL="https://vvp-witness1.rcnx.io"
WITNESS2_URL="https://vvp-witness2.rcnx.io"
WITNESS3_URL="https://vvp-witness3.rcnx.io"

WAN_AID="BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha"
WIL_AID="BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM"
WES_AID="BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX"

# Short timeouts — we poll repeatedly so fast failure is better than waiting
CONNECT_TIMEOUT=2
MAX_TIME=3

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------

while [[ $# -gt 0 ]]; do
    case "$1" in
        --local)
            MODE="local"
            VERIFIER_URL="http://localhost:8000"
            ISSUER_URL="http://localhost:8001"
            KERI_AGENT_URL="http://localhost:8002"
            WITNESS1_URL="http://localhost:5642"
            WITNESS2_URL="http://localhost:5643"
            WITNESS3_URL="http://localhost:5644"
            shift
            ;;
        --timeout)
            TIMEOUT="$2"
            shift 2
            ;;
        --json)
            JSON_OUTPUT=true
            shift
            ;;
        --help|-h)
            head -20 "$0" | tail -16
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 2
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Service definitions (parallel arrays — bash 3 compatible)
# ---------------------------------------------------------------------------

SVC_NAMES=()
SVC_URLS=()
SVC_TYPES=()    # health | oobi
SVC_EXTRAS=()   # health path or AID
SVC_STATUS=()   # pending | ready | failed

add_service() {
    SVC_NAMES+=("$1")
    SVC_URLS+=("$2")
    SVC_TYPES+=("$3")
    SVC_EXTRAS+=("$4")
    SVC_STATUS+=("pending")
}

# Witnesses (no deps, come up first)
add_service "Witness-wan" "$WITNESS1_URL" "oobi" "$WAN_AID"
add_service "Witness-wil" "$WITNESS2_URL" "oobi" "$WIL_AID"
add_service "Witness-wes" "$WITNESS3_URL" "oobi" "$WES_AID"

# Verifier
add_service "Verifier" "$VERIFIER_URL" "health" "/healthz"

# KERI Agent (local only — internal in production, checked via Issuer /readyz)
if [ -n "$KERI_AGENT_URL" ]; then
    add_service "KERI-Agent" "$KERI_AGENT_URL" "health" "/healthz"
fi

# Issuer /healthz (DB reachable — comes up fast)
add_service "Issuer" "$ISSUER_URL" "health" "/healthz"

# Issuer /readyz (DB AND KERI Agent — slowest, waits for agent bootstrap)
add_service "Issuer-ready" "$ISSUER_URL" "health" "/readyz"

SVC_COUNT=${#SVC_NAMES[@]}
READY_COUNT=0

# Use SECONDS builtin for elapsed time (works in bash 3+, integer precision)
SECONDS=0

# ---------------------------------------------------------------------------
# Check function
# ---------------------------------------------------------------------------

check_service() {
    local idx="$1"
    local url="${SVC_URLS[$idx]}"
    local check_type="${SVC_TYPES[$idx]}"
    local extra="${SVC_EXTRAS[$idx]}"
    local target_url http_code

    case "$check_type" in
        health) target_url="${url}${extra}" ;;
        oobi)   target_url="${url}/oobi/${extra}/controller" ;;
    esac

    http_code=$(curl -s -o /dev/null -w "%{http_code}" \
        --connect-timeout "$CONNECT_TIMEOUT" \
        --max-time "$MAX_TIME" \
        "$target_url" 2>/dev/null) || http_code="000"

    if [[ "$http_code" =~ ^2[0-9][0-9]$ ]]; then
        return 0
    else
        return 1
    fi
}

# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

if [ "$JSON_OUTPUT" = false ]; then
    echo ""
    echo -e "${BOLD}Waiting for VVP services${NC} ${DIM}(${MODE}, timeout ${TIMEOUT}s)${NC}"
    echo ""
fi

ALL_READY=false

while [ "$SECONDS" -lt "$TIMEOUT" ]; do

    for (( i=0; i<SVC_COUNT; i++ )); do
        if [ "${SVC_STATUS[$i]}" = "ready" ]; then
            continue
        fi

        # Re-check deadline before each curl (each can take up to MAX_TIME)
        if [ "$SECONDS" -ge "$TIMEOUT" ]; then
            break
        fi

        # Show which service is being probed (overwritten by OK/FAIL line)
        if [ "$JSON_OUTPUT" = false ] && [ -t 1 ]; then
            printf "\r  ${DIM}checking ${SVC_NAMES[$i]}... (${SECONDS}s)${NC}%s" "          "
        fi

        if check_service "$i"; then
            SVC_STATUS[$i]="ready"
            READY_COUNT=$((READY_COUNT + 1))

            if [ "$JSON_OUTPUT" = false ]; then
                # Clear the "checking..." line, then print the OK line
                [ -t 1 ] && printf "\r\033[2K"
                echo -e "  ${GREEN}OK${NC}  ${SVC_NAMES[$i]}  ${DIM}(${READY_COUNT}/${SVC_COUNT}, ${SECONDS}s)${NC}"
            fi
        fi
    done

    if [ "$READY_COUNT" -eq "$SVC_COUNT" ]; then
        ALL_READY=true
        break
    fi

    sleep "$POLL_INTERVAL"
done

# Clear any lingering "checking..." line
[ "$JSON_OUTPUT" = false ] && [ -t 1 ] && printf "\r\033[2K"

# Mark remaining as failed and report
if [ "$READY_COUNT" -lt "$SVC_COUNT" ]; then
    for (( i=0; i<SVC_COUNT; i++ )); do
        if [ "${SVC_STATUS[$i]}" = "pending" ]; then
            SVC_STATUS[$i]="failed"
            if [ "$JSON_OUTPUT" = false ]; then
                echo -e "  ${RED}FAIL${NC}  ${SVC_NAMES[$i]}  ${DIM}(timed out)${NC}"
            fi
        fi
    done
fi

# Summary
if [ "$JSON_OUTPUT" = false ]; then
    echo ""
    if [ "$ALL_READY" = true ]; then
        echo -e "${GREEN}${BOLD}All ${SVC_COUNT} services ready${NC} in ${SECONDS}s"
    else
        echo -e "${RED}${BOLD}Timeout after ${SECONDS}s${NC} — ${READY_COUNT}/${SVC_COUNT} ready"
    fi
    echo ""
fi

# JSON output
if [ "$JSON_OUTPUT" = true ]; then
    local_names=""
    local_statuses=""
    for (( i=0; i<SVC_COUNT; i++ )); do
        if [ $i -gt 0 ]; then
            local_names+=","
            local_statuses+=","
        fi
        local_names+="${SVC_NAMES[$i]}"
        local_statuses+="${SVC_STATUS[$i]}"
    done

    python3 -c "
import json, sys
names = sys.argv[1].split(',')
statuses = sys.argv[2].split(',')
elapsed = int(sys.argv[3])
services = dict(zip(names, statuses))
json.dump({
    'all_ready': all(s == 'ready' for s in statuses),
    'elapsed_seconds': elapsed,
    'services': services
}, sys.stdout, indent=2)
print()
" "$local_names" "$local_statuses" "$SECONDS"
fi

if [ "$ALL_READY" = true ]; then
    exit 0
else
    exit 1
fi
