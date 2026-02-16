#!/bin/bash
# =============================================================================
# VVP System Health Check
# =============================================================================
#
# Comprehensive health check for all VVP system components.
# Checks each service for liveness, correct version, and connectivity.
# Optionally runs an end-to-end verification test.
#
# Components checked:
#   Azure Container Apps:  Verifier, Issuer, Witness x3
#   PBX VM services:       FreeSWITCH, SIP Redirect, SIP Verify
#
# Usage:
#   ./scripts/system-health-check.sh                  # Check production
#   ./scripts/system-health-check.sh --local          # Check local dev stack
#   ./scripts/system-health-check.sh --e2e            # Include E2E issuer→verifier test
#   ./scripts/system-health-check.sh --e2e --timing   # E2E + cache timing measurement
#   ./scripts/system-health-check.sh --restart        # Restart all services, then check
#   ./scripts/system-health-check.sh --json           # Output JSON summary
#   ./scripts/system-health-check.sh --verbose        # Show full response bodies
#
# Environment variables:
#   VVP_VERIFIER_URL      Override verifier URL
#   VVP_ISSUER_URL        Override issuer URL
#   VVP_EXPECTED_SHA      Expected git SHA (skip if not set)
#   VVP_TEST_API_KEY      API key for E2E test
#   VVP_SKIP_PBX          Set to "true" to skip PBX VM checks
#
# Exit codes:
#   0  All checks passed
#   1  One or more checks failed
#   2  Script error (missing dependencies, etc.)
#
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Colors (disabled if not a terminal)
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    BLUE='\033[0;34m'
    CYAN='\033[0;36m'
    BOLD='\033[1m'
    DIM='\033[2m'
    NC='\033[0m'
else
    RED='' GREEN='' YELLOW='' BLUE='' CYAN='' BOLD='' DIM='' NC=''
fi

# Defaults — overridden by --local or environment
MODE="azure"
DO_RESTART=false
DO_E2E=false
DO_TIMING=false
JSON_OUTPUT=false
VERBOSE=false

# Azure production URLs
VERIFIER_URL="https://vvp-verifier.rcnx.io"
ISSUER_URL="https://vvp-issuer.rcnx.io"
WITNESS1_URL="https://vvp-witness1.rcnx.io"
WITNESS2_URL="https://vvp-witness2.rcnx.io"
WITNESS3_URL="https://vvp-witness3.rcnx.io"
PBX_HOST="pbx.rcnx.io"
SIP_REDIRECT_STATUS_PORT=8085  # VVP_STATUS_HTTP_PORT on PBX (not externally accessible)

# Witness AIDs (deterministic from salts)
WAN_AID="BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha"
WIL_AID="BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM"
WES_AID="BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX"

# Timeouts
HTTP_TIMEOUT=10
WITNESS_TIMEOUT=30

# Portable millisecond timer (macOS lacks date +%s%N)
if date +%s%N 2>/dev/null | grep -q N; then
    # macOS: %N not supported, use python3 fallback
    now_ms() { python3 -c "import time; print(int(time.time()*1000))"; }
else
    now_ms() { echo $(( $(date +%s%N) / 1000000 )); }
fi

# Tracking
TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0
WARNINGS=0
RESULTS_JSON="[]"

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------

while [[ $# -gt 0 ]]; do
    case "$1" in
        --local)
            MODE="local"
            VERIFIER_URL="http://localhost:8000"
            ISSUER_URL="http://localhost:8001"
            WITNESS1_URL="http://localhost:5642"
            WITNESS2_URL="http://localhost:5643"
            WITNESS3_URL="http://localhost:5644"
            SIP_REDIRECT_STATUS_PORT=8080  # local dev uses default port
            shift
            ;;
        --restart)
            DO_RESTART=true
            shift
            ;;
        --e2e)
            DO_E2E=true
            shift
            ;;
        --timing)
            DO_TIMING=true
            shift
            ;;
        --json)
            JSON_OUTPUT=true
            shift
            ;;
        --verbose|-v)
            VERBOSE=true
            shift
            ;;
        --help|-h)
            head -35 "$0" | tail -30
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 2
            ;;
    esac
done

# Load E2E test config if it exists (provides API keys and test fixtures)
E2E_CONFIG="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/.e2e-config"
if [ -f "$E2E_CONFIG" ]; then
    # Source config, but don't override existing environment variables
    while IFS='=' read -r key value; do
        # Skip comments and empty lines
        [[ "$key" =~ ^[[:space:]]*# ]] && continue
        [[ -z "$key" ]] && continue
        key=$(echo "$key" | xargs)  # trim whitespace
        value=$(echo "$value" | xargs)
        # Only set if not already in environment
        if [ -z "${!key:-}" ]; then
            export "$key=$value"
        fi
    done < "$E2E_CONFIG"
fi

# Apply environment overrides
VERIFIER_URL="${VVP_VERIFIER_URL:-$VERIFIER_URL}"
ISSUER_URL="${VVP_ISSUER_URL:-$ISSUER_URL}"
EXPECTED_SHA="${VVP_EXPECTED_SHA:-}"
API_KEY="${VVP_TEST_API_KEY:-}"
SKIP_PBX="${VVP_SKIP_PBX:-false}"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

log_header() {
    if [ "$JSON_OUTPUT" = false ]; then
        echo ""
        echo -e "${BOLD}${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${BOLD}${BLUE}  $1${NC}"
        echo -e "${BOLD}${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    fi
}

log_check() {
    if [ "$JSON_OUTPUT" = false ]; then
        echo -e "  ${DIM}Checking${NC} $1..."
    fi
}

log_pass() {
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
    if [ "$JSON_OUTPUT" = false ]; then
        echo -e "  ${GREEN}PASS${NC}  $1"
    fi
}

log_fail() {
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
    if [ "$JSON_OUTPUT" = false ]; then
        echo -e "  ${RED}FAIL${NC}  $1"
    fi
}

log_warn() {
    WARNINGS=$((WARNINGS + 1))
    if [ "$JSON_OUTPUT" = false ]; then
        echo -e "  ${YELLOW}WARN${NC}  $1"
    fi
}

log_info() {
    if [ "$JSON_OUTPUT" = false ]; then
        echo -e "  ${DIM}$1${NC}"
    fi
}

# Record a result for JSON output
record_result() {
    local component="$1"
    local check="$2"
    local status="$3"  # pass, fail, warn
    local detail="${4:-}"
    local version="${5:-}"
    local response_ms="${6:-}"

    RESULTS_JSON=$(_RR_COMPONENT="$component" \
    _RR_CHECK="$check" \
    _RR_STATUS="$status" \
    _RR_DETAIL="$detail" \
    _RR_VERSION="$version" \
    _RR_RESPONSE_MS="$response_ms" \
    python3 -c "
import json, sys, os
results = json.loads(sys.stdin.read())
results.append({
    'component': os.environ['_RR_COMPONENT'],
    'check': os.environ['_RR_CHECK'],
    'status': os.environ['_RR_STATUS'],
    'detail': os.environ.get('_RR_DETAIL') or None,
    'version': os.environ.get('_RR_VERSION') or None,
    'response_ms': int(os.environ['_RR_RESPONSE_MS']) if os.environ.get('_RR_RESPONSE_MS') else None,
})
json.dump(results, sys.stdout)
" <<< "$RESULTS_JSON" 2>/dev/null || echo "$RESULTS_JSON")
}

# Check an HTTP health endpoint
# Usage: check_http_health <component_name> <url> <health_path> [expected_status]
check_http_health() {
    local name="$1"
    local url="$2"
    local health_path="$3"
    local expected_status="${4:-200}"
    local full_url="${url}${health_path}"

    log_check "$name health at $full_url"

    local start_ms end_ms
    start_ms=$(now_ms)

    local http_code body response
    response=$(curl -sf --max-time "$HTTP_TIMEOUT" -w '\n%{http_code}' "$full_url" 2>/dev/null) || response="000"
    http_code=$(echo "$response" | tail -1)
    body=$(echo "$response" | sed '$d')

    end_ms=$(now_ms)
    local elapsed_ms=$(( end_ms - start_ms ))

    if [ "$VERBOSE" = true ] && [ -n "$body" ] && [ "$JSON_OUTPUT" = false ]; then
        log_info "  Response: $body"
    fi

    if [[ "$http_code" =~ ^2[0-9][0-9]$ ]]; then
        log_pass "$name is healthy (HTTP $http_code, ${elapsed_ms}ms)"
        record_result "$name" "health" "pass" "HTTP $http_code" "" "$elapsed_ms"
        return 0
    else
        log_fail "$name is unhealthy (HTTP $http_code)"
        record_result "$name" "health" "fail" "HTTP $http_code" "" "$elapsed_ms"
        return 1
    fi
}

# Check an HTTP version endpoint and optionally validate SHA
# Usage: check_http_version <component_name> <url>
check_http_version() {
    local name="$1"
    local url="$2"
    local version_url="${url}/version"

    log_check "$name version at $version_url"

    local body
    body=$(curl -sf --max-time "$HTTP_TIMEOUT" "$version_url" 2>/dev/null) || body="{}"

    local git_sha
    git_sha=$(echo "$body" | python3 -c "import json,sys; print(json.load(sys.stdin).get('git_sha','unknown'))" 2>/dev/null) || git_sha="unknown"

    local short_sha="${git_sha:0:7}"

    if [ "$git_sha" = "unknown" ] || [ -z "$git_sha" ]; then
        log_warn "$name version unknown (could not parse response)"
        record_result "$name" "version" "warn" "Could not determine version"
        return 1
    fi

    # Check against expected SHA if provided
    if [ -n "$EXPECTED_SHA" ]; then
        if [ "$git_sha" = "$EXPECTED_SHA" ]; then
            log_pass "$name version $short_sha (matches expected)"
            record_result "$name" "version" "pass" "$short_sha" "$git_sha"
        else
            log_fail "$name version $short_sha (expected ${EXPECTED_SHA:0:7})"
            record_result "$name" "version" "fail" "Expected ${EXPECTED_SHA:0:7}, got $short_sha" "$git_sha"
            return 1
        fi
    else
        log_pass "$name version $short_sha"
        record_result "$name" "version" "pass" "$short_sha" "$git_sha"
    fi

    # Store version for cross-service comparison (declare -g not available in bash 3)
    local var_name="VERSION_${name//[^a-zA-Z0-9]/_}"
    printf -v "$var_name" '%s' "$git_sha"
    return 0
}

# Check a witness OOBI endpoint
# Usage: check_witness_oobi <name> <url> <aid>
check_witness_oobi() {
    local name="$1"
    local url="$2"
    local aid="$3"
    local oobi_url="${url}/oobi/${aid}/controller"

    log_check "$name OOBI at $oobi_url"

    local start_ms end_ms
    start_ms=$(now_ms)

    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time "$WITNESS_TIMEOUT" "$oobi_url" 2>/dev/null) || http_code="000"

    end_ms=$(now_ms)
    local elapsed_ms=$(( end_ms - start_ms ))

    if [ "$http_code" = "200" ] || [ "$http_code" = "202" ]; then
        log_pass "$name OOBI responding (HTTP $http_code, ${elapsed_ms}ms)"
        record_result "$name" "oobi" "pass" "HTTP $http_code" "" "$elapsed_ms"
        return 0
    else
        log_fail "$name OOBI not responding (HTTP $http_code)"
        record_result "$name" "oobi" "fail" "HTTP $http_code" "" "$elapsed_ms"
        return 1
    fi
}

# Run a command on the PBX VM via Azure CLI
# Usage: pbx_run <command>
pbx_run() {
    local cmd="$1"
    # Azure allows only one run-command per VM at a time. Retry on Conflict.
    local attempt
    for attempt in 1 2 3; do
        local result
        result=$(az vm run-command invoke \
            --resource-group VVP \
            --name vvp-pbx \
            --command-id RunShellScript \
            --scripts "$cmd" \
            --query "value[0].message" -o tsv 2>&1)
        local rc=$?
        if [ $rc -eq 0 ]; then
            echo "$result"
            return 0
        fi
        if echo "$result" | grep -q "Conflict"; then
            sleep 15
            continue
        fi
        # Non-conflict error — fail immediately
        return $rc
    done
    return 1
}

# ---------------------------------------------------------------------------
# Phase 0: Restart (if requested)
# ---------------------------------------------------------------------------

do_restart() {
    log_header "Phase 0: System Restart"

    if [ "$MODE" = "local" ]; then
        echo -e "  ${YELLOW}Local mode: use docker compose to restart services${NC}"
        echo "    docker compose down && docker compose --profile full up -d"
        return 0
    fi

    # --- Witnesses ---
    echo -e "  ${CYAN}Restarting witnesses...${NC}"
    for name in vvp-witness1 vvp-witness2 vvp-witness3; do
        log_info "Restarting $name..."
        az containerapp revision restart \
            --name "$name" \
            --resource-group VVP 2>/dev/null || log_warn "Could not restart $name"
    done

    echo -e "  ${DIM}Waiting for witnesses to initialize (30s)...${NC}"
    sleep 30

    # --- Verifier ---
    echo -e "  ${CYAN}Restarting verifier...${NC}"
    az containerapp revision restart \
        --name vvp-verifier \
        --resource-group VVP 2>/dev/null || log_warn "Could not restart verifier"
    sleep 10

    # --- Issuer ---
    echo -e "  ${CYAN}Restarting issuer...${NC}"
    # Issuer needs stop-then-start due to LMDB locks on shared volume
    CURRENT_REV=$(az containerapp revision list \
        --name vvp-issuer \
        --resource-group VVP \
        --query "[?properties.trafficWeight > \`0\`].name" -o tsv 2>/dev/null)
    if [ -n "$CURRENT_REV" ]; then
        az containerapp revision deactivate \
            --name vvp-issuer \
            --resource-group VVP \
            --revision "$CURRENT_REV" 2>/dev/null
        echo -e "  ${DIM}Waiting for LMDB lock release (30s)...${NC}"
        sleep 30
    fi
    az containerapp revision restart \
        --name vvp-issuer \
        --resource-group VVP 2>/dev/null || log_warn "Could not restart issuer"
    sleep 15

    # --- PBX services ---
    if [ "$SKIP_PBX" != "true" ]; then
        echo -e "  ${CYAN}Restarting PBX services...${NC}"
        pbx_run "
            systemctl restart freeswitch
            sleep 3
            systemctl restart vvp-sip-redirect
            sleep 2
            systemctl restart vvp-sip-verify
            sleep 2
            echo 'All PBX services restarted'
        " || log_warn "Could not restart PBX services"
        sleep 10
    fi

    echo -e "  ${GREEN}Restart sequence complete. Running health checks...${NC}"
}

# ---------------------------------------------------------------------------
# Phase 1: Azure Container Apps Health
# ---------------------------------------------------------------------------

check_container_apps() {
    log_header "Phase 1: Azure Container Apps"

    local failed=0

    # --- Verifier ---
    check_http_health "Verifier" "$VERIFIER_URL" "/healthz" || failed=1
    check_http_version "Verifier" "$VERIFIER_URL" || true

    # --- Issuer ---
    check_http_health "Issuer" "$ISSUER_URL" "/healthz" || failed=1
    check_http_version "Issuer" "$ISSUER_URL" || true

    # --- Witnesses ---
    check_witness_oobi "Witness-wan" "$WITNESS1_URL" "$WAN_AID" || failed=1
    check_witness_oobi "Witness-wil" "$WITNESS2_URL" "$WIL_AID" || failed=1
    check_witness_oobi "Witness-wes" "$WITNESS3_URL" "$WES_AID" || failed=1

    # --- Version consistency ---
    local verifier_sha="${VERSION_Verifier:-}"
    local issuer_sha="${VERSION_Issuer:-}"

    if [ -n "$verifier_sha" ] && [ -n "$issuer_sha" ]; then
        if [ "$verifier_sha" != "$issuer_sha" ]; then
            log_warn "Version mismatch: Verifier=${verifier_sha:0:7} Issuer=${issuer_sha:0:7}"
            record_result "System" "version_consistency" "warn" "Verifier and Issuer on different commits"
        else
            log_pass "Verifier and Issuer on same commit (${verifier_sha:0:7})"
            record_result "System" "version_consistency" "pass" "All on ${verifier_sha:0:7}"
        fi
    fi

    return $failed
}

# ---------------------------------------------------------------------------
# Phase 2: PBX VM Services
# ---------------------------------------------------------------------------

check_pbx_services() {
    log_header "Phase 2: PBX VM Services"

    if [ "$SKIP_PBX" = "true" ]; then
        log_info "PBX checks skipped (VVP_SKIP_PBX=true)"
        return 0
    fi

    if [ "$MODE" = "local" ]; then
        log_info "PBX checks skipped in local mode (no Azure VM)"
        return 0
    fi

    local failed=0

    # --- All PBX checks in a single az vm run-command (Azure allows only one at a time) ---
    log_check "PBX VM services via Azure CLI"

    local pbx_output
    pbx_output=$(pbx_run "
        echo '=== SIP Redirect Health ==='
        curl -sf --max-time 5 http://localhost:$SIP_REDIRECT_STATUS_PORT/health 2>/dev/null || echo 'HEALTH_FAIL'
        echo ''
        echo '=== SIP Redirect Version ==='
        curl -sf --max-time 5 http://localhost:$SIP_REDIRECT_STATUS_PORT/version 2>/dev/null || echo '{}'
        echo ''
        echo '=== Service Status ==='
        echo \"freeswitch:\$(systemctl is-active freeswitch 2>/dev/null || echo 'not-found')\"
        echo \"sip-redirect:\$(systemctl is-active vvp-sip-redirect 2>/dev/null || echo 'not-found')\"
        echo \"sip-verify:\$(systemctl is-active vvp-sip-verify 2>/dev/null || echo 'not-found')\"
        echo ''
        echo '=== Listening Ports ==='
        ss -tulnp 2>/dev/null | grep -E ':(5060|5070|5071|5080|7443|8085) ' || echo 'No VVP ports found'
        echo ''
        echo '=== SIP Profiles ==='
        fs_cli -x 'sofia status' 2>/dev/null | head -20 || echo 'Could not query FreeSWITCH'
    " 2>/dev/null) || {
        log_fail "Could not reach PBX VM via Azure CLI"
        record_result "PBX" "vm_access" "fail" "az vm run-command failed"
        return 1
    }

    # --- Parse SIP Redirect health ---
    log_check "SIP-Redirect health at localhost:$SIP_REDIRECT_STATUS_PORT"
    if echo "$pbx_output" | grep -q '"status".*"healthy"'; then
        log_pass "SIP-Redirect is healthy"
        record_result "SIP-Redirect" "health" "pass" "Healthy"
    else
        log_fail "SIP-Redirect health check failed"
        record_result "SIP-Redirect" "health" "fail" "Unhealthy"
        failed=1
    fi

    # --- Parse SIP Redirect version ---
    log_check "SIP-Redirect version at localhost:$SIP_REDIRECT_STATUS_PORT"
    local sip_version
    sip_version=$(echo "$pbx_output" | grep -o '"short_sha": *"[^"]*"' | head -1 | sed 's/.*"short_sha": *"//;s/"//' || echo "")
    if [ -n "$sip_version" ] && [ "$sip_version" != "unknown" ]; then
        log_pass "SIP-Redirect version $sip_version"
        record_result "SIP-Redirect" "version" "pass" "$sip_version"
    else
        log_warn "SIP-Redirect version unknown"
        record_result "SIP-Redirect" "version" "warn" "unknown"
    fi

    if [ "$VERBOSE" = true ] && [ "$JSON_OUTPUT" = false ]; then
        echo "$pbx_output" | while IFS= read -r line; do
            log_info "  $line"
        done
    fi

    # Parse service statuses
    local fs_status sip_redirect_status sip_verify_status
    fs_status=$(echo "$pbx_output" | grep "^freeswitch:" | cut -d: -f2)
    sip_redirect_status=$(echo "$pbx_output" | grep "^sip-redirect:" | cut -d: -f2)
    sip_verify_status=$(echo "$pbx_output" | grep "^sip-verify:" | cut -d: -f2)

    # FreeSWITCH
    if [ "$fs_status" = "active" ]; then
        log_pass "FreeSWITCH is active"
        record_result "FreeSWITCH" "systemd" "pass" "active"
    else
        log_fail "FreeSWITCH is $fs_status"
        record_result "FreeSWITCH" "systemd" "fail" "$fs_status"
        failed=1
    fi

    # SIP Redirect (systemd)
    if [ "$sip_redirect_status" = "active" ]; then
        log_pass "SIP Redirect systemd unit is active"
        record_result "SIP-Redirect" "systemd" "pass" "active"
    else
        log_fail "SIP Redirect systemd unit is $sip_redirect_status"
        record_result "SIP-Redirect" "systemd" "fail" "$sip_redirect_status"
        failed=1
    fi

    # SIP Verify (systemd)
    if [ "$sip_verify_status" = "active" ]; then
        log_pass "SIP Verify systemd unit is active"
        record_result "SIP-Verify" "systemd" "pass" "active"
    else
        log_fail "SIP Verify systemd unit is $sip_verify_status"
        record_result "SIP-Verify" "systemd" "fail" "$sip_verify_status"
        failed=1
    fi

    # Check critical ports
    for port_name in "5060:FreeSWITCH-Internal" "5070:SIP-Redirect-SIP" "5071:SIP-Verify-SIP" "5080:FreeSWITCH-External" "7443:FreeSWITCH-WSS"; do
        local port="${port_name%%:*}"
        local label="${port_name##*:}"
        if echo "$pbx_output" | grep -q ":${port} "; then
            log_pass "$label listening on port $port"
            record_result "$label" "port" "pass" "Listening on $port"
        else
            log_fail "$label NOT listening on port $port"
            record_result "$label" "port" "fail" "Not listening on $port"
            failed=1
        fi
    done

    return $failed
}

# ---------------------------------------------------------------------------
# Phase 3: Cross-Service Connectivity
# ---------------------------------------------------------------------------

check_connectivity() {
    log_header "Phase 3: Cross-Service Connectivity"

    local failed=0

    # Use the issuer's dashboard endpoint to get aggregate health
    log_check "Issuer dashboard aggregate health"
    local dashboard_body
    dashboard_body=$(curl -sf --max-time "$HTTP_TIMEOUT" "${ISSUER_URL}/api/dashboard/status" 2>/dev/null) || dashboard_body="{}"

    local overall_status
    overall_status=$(echo "$dashboard_body" | python3 -c "import json,sys; print(json.load(sys.stdin).get('overall_status','unknown'))" 2>/dev/null) || overall_status="unknown"

    if [ "$VERBOSE" = true ] && [ "$JSON_OUTPUT" = false ]; then
        echo "$dashboard_body" | python3 -m json.tool 2>/dev/null | while IFS= read -r line; do
            log_info "  $line"
        done
    fi

    if [ "$overall_status" = "healthy" ]; then
        log_pass "Dashboard reports all services healthy"
        record_result "Dashboard" "aggregate" "pass" "Overall: healthy"
    elif [ "$overall_status" = "degraded" ]; then
        log_warn "Dashboard reports degraded status"
        record_result "Dashboard" "aggregate" "warn" "Overall: degraded"

        # Show which services are unhealthy
        echo "$dashboard_body" | python3 -c "
import json, sys
data = json.load(sys.stdin)
for svc in data.get('services', []):
    if svc.get('status') != 'healthy':
        print(f\"    {svc['name']}: {svc.get('error', 'unhealthy')}\")
" 2>/dev/null | while IFS= read -r line; do
            log_info "$line"
        done
    else
        log_fail "Dashboard reports unhealthy or unreachable (status: $overall_status)"
        record_result "Dashboard" "aggregate" "fail" "Overall: $overall_status"
        failed=1
    fi

    # PBX-to-service connectivity (single az vm run-command to avoid serialization)
    if [ "$MODE" = "azure" ] && [ "$SKIP_PBX" != "true" ]; then
        local pbx_conn
        pbx_conn=$(pbx_run "
            echo \"issuer:\$(curl -sf --max-time 10 https://vvp-issuer.rcnx.io/healthz 2>/dev/null && echo 'OK' || echo 'FAIL')\"
            echo \"verifier:\$(curl -sf --max-time 10 https://vvp-verifier.rcnx.io/healthz 2>/dev/null && echo 'OK' || echo 'FAIL')\"
        " 2>/dev/null) || pbx_conn="ERROR"

        log_check "PBX → Issuer API connectivity"
        if echo "$pbx_conn" | grep "^issuer:" | grep -q "OK"; then
            log_pass "PBX can reach Issuer API"
            record_result "PBX" "issuer_connectivity" "pass" "Reachable"
        else
            log_fail "PBX cannot reach Issuer API"
            record_result "PBX" "issuer_connectivity" "fail" "Unreachable"
            failed=1
        fi

        log_check "PBX → Verifier API connectivity"
        if echo "$pbx_conn" | grep "^verifier:" | grep -q "OK"; then
            log_pass "PBX can reach Verifier API"
            record_result "PBX" "verifier_connectivity" "pass" "Reachable"
        else
            log_fail "PBX cannot reach Verifier API"
            record_result "PBX" "verifier_connectivity" "fail" "Unreachable"
            failed=1
        fi
    fi

    return $failed
}

# ---------------------------------------------------------------------------
# Phase 4: End-to-End Call Test
# ---------------------------------------------------------------------------
# Sends real SIP INVITEs through the signing and verification services
# to prove the full call chain is functioning:
#
#   Signing:  SIP INVITE → SIP Redirect (5070) → Issuer API → 302 + VVP headers
#   Verify:   SIP INVITE → SIP Verify (5071) → Verifier API → SIP response
#   Dialplan: fs_cli originate → FreeSWITCH VVP loopback → signing → log check
#
# ---------------------------------------------------------------------------

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SIP_TEST_SCRIPT="$REPO_ROOT/scripts/sip-call-test.py"

check_e2e() {
    log_header "Phase 4: End-to-End Call Test"

    if [ "$DO_E2E" = false ]; then
        log_info "E2E call test skipped (use --e2e to enable)"
        return 0
    fi

    local failed=0

    if [ "$MODE" = "local" ]; then
        # Local mode: run SIP test script directly against local services
        _run_sip_tests_local || failed=1
    else
        # Azure mode: run SIP tests on PBX VM + FreeSWITCH originate test
        _run_sip_tests_pbx || failed=1
        _run_freeswitch_call_test || failed=1
    fi

    # Cache timing sub-phase
    if [ "$DO_TIMING" = true ]; then
        _run_timing_tests || failed=1
    fi

    return $failed
}

# Run SIP call tests against local services (direct invocation)
_run_sip_tests_local() {
    local failed=0

    if [ ! -f "$SIP_TEST_SCRIPT" ]; then
        log_fail "SIP test script not found at $SIP_TEST_SCRIPT"
        return 1
    fi

    # --- Signing test ---
    log_check "SIP Redirect signing (INVITE → port 5070 → Issuer API → 302)"

    if [ -z "$API_KEY" ]; then
        log_fail "VVP_TEST_API_KEY not set — signing test cannot run"
        record_result "E2E" "sip_signing" "fail" "No API key provided"
        failed=1
    else
        local sign_output
        sign_output=$(VVP_TEST_API_KEY="$API_KEY" python3 "$SIP_TEST_SCRIPT" \
            --test sign --host 127.0.0.1 --json --timeout 10 2>&1) || true

        _parse_sip_test_result "$sign_output" "sip_signing" "Signing" || failed=1
    fi

    # --- Verification test ---
    log_check "SIP Verify verification (INVITE → port 5071 → Verifier API)"

    local verify_output
    verify_output=$(python3 "$SIP_TEST_SCRIPT" \
        --test verify --host 127.0.0.1 --json --timeout 10 2>&1) || true

    _parse_sip_test_result "$verify_output" "sip_verify" "Verification" || failed=1

    return $failed
}

# Run SIP call tests on the PBX VM via Azure CLI
_run_sip_tests_pbx() {
    local failed=0

    if [ "$SKIP_PBX" = "true" ]; then
        log_info "PBX SIP tests skipped (VVP_SKIP_PBX=true)"
        return 0
    fi

    log_check "SIP call tests on PBX VM (signing + verification)"

    # Inline the SIP test as a Python one-liner run on the PBX.
    # We send the full test script via base64 to avoid shell escaping issues.
    local script_b64
    # macOS base64 uses -i for file input; Linux uses positional arg + -w0
    script_b64=$(base64 -w0 "$SIP_TEST_SCRIPT" 2>/dev/null || base64 -i "$SIP_TEST_SCRIPT" | tr -d '\n')

    if [ -z "$script_b64" ]; then
        log_fail "Could not encode SIP test script"
        return 1
    fi

    # Determine which tests to run
    local test_mode="all"
    local api_key_env=""
    if [ -n "$API_KEY" ]; then
        api_key_env="VVP_TEST_API_KEY='$API_KEY'"
    else
        test_mode="verify"  # Skip signing if no API key
        log_fail "VVP_TEST_API_KEY not set — signing test cannot run (set env var or pass via VVP_TEST_API_KEY=...)"
        record_result "E2E" "sip_signing_pbx" "fail" "No API key provided"
        failed=1
    fi

    local pbx_output
    pbx_output=$(pbx_run "
        # Decode and run the SIP test script
        echo '$script_b64' | base64 -d > /tmp/vvp-sip-test.py

        # Run with appropriate environment
        $api_key_env \
        VVP_SIP_REDIRECT_HOST=127.0.0.1 \
        VVP_SIP_REDIRECT_PORT=5070 \
        VVP_SIP_VERIFY_HOST=127.0.0.1 \
        VVP_SIP_VERIFY_PORT=5071 \
        python3 /tmp/vvp-sip-test.py --test $test_mode --json --timeout 10 2>&1

        # Cleanup
        rm -f /tmp/vvp-sip-test.py
    " 2>/dev/null) || {
        log_fail "Could not run SIP tests on PBX VM"
        record_result "E2E" "sip_tests_pbx" "fail" "az vm run-command failed"
        return 1
    }

    # The pbx_output from az vm run-command includes [stdout]/[stderr] markers
    # and the JSON may be pretty-printed across multiple lines.
    # Use Python to robustly extract the first valid JSON object containing "results".
    local json_output
    json_output=$(echo "$pbx_output" | python3 -c "
import sys, json
text = sys.stdin.read()
# Find each '{' and try to parse a JSON object containing 'results'
for i, c in enumerate(text):
    if c == '{':
        depth = 0
        for j in range(i, len(text)):
            if text[j] == '{': depth += 1
            elif text[j] == '}': depth -= 1
            if depth == 0:
                try:
                    obj = json.loads(text[i:j+1])
                    if 'results' in obj:
                        print(json.dumps(obj))
                        sys.exit(0)
                except (json.JSONDecodeError, ValueError):
                    pass
                break
" 2>/dev/null) || json_output=""

    if [ "$VERBOSE" = true ] && [ "$JSON_OUTPUT" = false ]; then
        log_info "PBX SIP test raw output:"
        echo "$pbx_output" | while IFS= read -r line; do
            log_info "  $line"
        done
    fi

    if [ -n "$json_output" ]; then
        # Parse each test result from the JSON
        local num_results
        num_results=$(echo "$json_output" | python3 -c "import json,sys; print(len(json.load(sys.stdin).get('results',[])))" 2>/dev/null) || num_results=0

        local i=0
        while [ "$i" -lt "$num_results" ]; do
            local test_name test_status test_detail
            read -r test_name test_status test_detail <<< $(echo "$json_output" | python3 -c "
import json, sys
data = json.load(sys.stdin)
r = data['results'][$i]
print(r.get('test','?'), r.get('status','fail'), r.get('detail',''))
" 2>/dev/null)

            local check_name="sip_${test_name}_pbx"
            if [ "$test_status" = "pass" ]; then
                log_pass "PBX $test_name: $test_detail"
                record_result "E2E" "$check_name" "pass" "$test_detail"
            elif [ "$test_status" = "warn" ]; then
                log_warn "PBX $test_name: $test_detail"
                record_result "E2E" "$check_name" "warn" "$test_detail"
            elif [ "$test_status" = "skip" ]; then
                log_info "PBX $test_name: $test_detail"
                record_result "E2E" "$check_name" "warn" "$test_detail"
            else
                log_fail "PBX $test_name: $test_detail"
                record_result "E2E" "$check_name" "fail" "$test_detail"
                failed=1
            fi

            i=$((i + 1))
        done
    else
        log_fail "Could not parse SIP test results from PBX"
        record_result "E2E" "sip_tests_pbx" "fail" "No parseable output"
        failed=1
    fi

    return $failed
}

# Test a full FreeSWITCH VVP loopback call via fs_cli originate
_run_freeswitch_call_test() {
    local failed=0

    if [ "$SKIP_PBX" = "true" ]; then
        return 0
    fi

    log_check "FreeSWITCH VVP E2E call (originate → signing → verification → delivery)"

    local call_output
    call_output=$(pbx_run "
        # Record the invite.completed count before originating
        BEFORE_COUNT=\$(journalctl -u vvp-sip-redirect --no-pager 2>/dev/null | grep -c 'invite.completed' || echo '0')
        VERIFY_BEFORE=\$(journalctl -u vvp-sip-verify --no-pager 2>/dev/null | grep -c 'Verification complete' || echo '0')

        # Originate through the loopback/public dialplan context for full 3-stage flow:
        # FreeSWITCH → sip-redirect:5070 (signing) → redirected → sip-verify:5071 (verification) → verified → delivery
        # The public context's vvp-loopback-outbound extension adds the API key and sets sip_redirect_context.
        ORIGINATE_RESULT=\$(fs_cli -x \"bgapi originate {origination_caller_id_number=+441923311000,origination_caller_id_name=VVP-HealthCheck}loopback/71006/public &park()\" 2>/dev/null) || ORIGINATE_RESULT='ORIGINATE_FAILED'

        # Wait for full signing (~3s) + verification (~1s) chain
        sleep 12

        # Count completed invites after the call — delta proves signing happened
        AFTER_COUNT=\$(journalctl -u vvp-sip-redirect --no-pager 2>/dev/null | grep -c 'invite.completed' || echo '0')
        DELTA=\$(( AFTER_COUNT - BEFORE_COUNT ))

        # Count verification completions — delta proves verification happened
        VERIFY_AFTER=\$(journalctl -u vvp-sip-verify --no-pager 2>/dev/null | grep -c 'Verification complete' || echo '0')
        VERIFY_DELTA=\$(( VERIFY_AFTER - VERIFY_BEFORE ))

        # Get recent signing logs as evidence
        SIP_LOGS=\$(journalctl -u vvp-sip-redirect -n 50 --no-pager 2>/dev/null | grep -E 'invite\.(received|completed)|Monitor event' | tail -10 || echo 'NO_LOGS')

        # Get recent verification logs as evidence
        VERIFY_LOGS=\$(journalctl -u vvp-sip-verify -n 50 --no-pager 2>/dev/null | grep -E 'Verification complete|Verifier response|Monitor event' | tail -10 || echo 'NO_LOGS')

        # Also check FreeSWITCH log file for VVP dialplan evidence
        FS_LOGS=\$(tail -50 /var/log/freeswitch/freeswitch.log 2>/dev/null | grep -i 'VVP\|loopback\|signing\|verification\|verified' | tail -5 || echo '')

        # Hang up any test channels to clean up
        fs_cli -x 'hupall NORMAL_CLEARING' 2>/dev/null || true

        # Output structured results — IMPORTANT: structured block goes LAST
        # because Azure run-command truncates output from the beginning when
        # it exceeds ~4096 chars. Logs go first (informational, truncation OK),
        # structured results go last (parsed by grep, must survive).
        echo '=== VVP_LOGS ==='
        echo \"\$SIP_LOGS\"
        echo '=== VERIFY_LOGS ==='
        echo \"\$VERIFY_LOGS\"
        echo \"\$FS_LOGS\"
        echo '=== CALL_TEST_RESULTS ==='
        echo \"originate:\$ORIGINATE_RESULT\"
        echo \"signing_delta:\$DELTA\"
        echo \"verify_delta:\$VERIFY_DELTA\"
        echo '=== END ==='
    " 2>/dev/null) || {
        log_fail "Could not run FreeSWITCH call test"
        record_result "E2E" "freeswitch_call" "fail" "az vm run-command failed"
        return 1
    }

    if [ "$VERBOSE" = true ] && [ "$JSON_OUTPUT" = false ]; then
        log_info "FreeSWITCH call test output:"
        echo "$call_output" | while IFS= read -r line; do
            log_info "  $line"
        done
    fi

    # Parse results
    local originate_result signing_delta verify_delta
    originate_result=$(echo "$call_output" | grep "^originate:" | cut -d: -f2-)
    signing_delta=$(echo "$call_output" | grep "^signing_delta:" | cut -d: -f2)
    verify_delta=$(echo "$call_output" | grep "^verify_delta:" | cut -d: -f2)

    # Check if originate succeeded (should contain a UUID or +OK)
    if echo "$originate_result" | grep -qi "OK\|Job-UUID\|[0-9a-f]\{8\}"; then
        log_pass "FreeSWITCH originated VVP loopback call"
        record_result "E2E" "fs_originate" "pass" "Call originated"
    elif echo "$originate_result" | grep -qi "ORIGINATE_FAILED"; then
        log_fail "FreeSWITCH could not originate call"
        record_result "E2E" "fs_originate" "fail" "Originate failed"
        failed=1
    else
        log_fail "FreeSWITCH originate result unclear: $originate_result"
        record_result "E2E" "fs_originate" "fail" "$originate_result"
        failed=1
    fi

    # Check if VVP signing flow was triggered (delta > 0 means new invite.completed entries)
    if [ -n "$signing_delta" ] && [ "$signing_delta" -gt 0 ] 2>/dev/null; then
        log_pass "VVP signing flow triggered ($signing_delta new invite.completed entries)"
        record_result "E2E" "vvp_signing_flow" "pass" "$signing_delta signing events"

        # Show relevant signing log lines
        if [ "$JSON_OUTPUT" = false ]; then
            echo "$call_output" | sed -n '/=== VVP_LOGS ===/,/=== VERIFY_LOGS ===/p' | grep -v "===" | while IFS= read -r line; do
                if [ -n "$line" ]; then
                    log_info "  $line"
                fi
            done
        fi
    else
        log_fail "No VVP signing evidence — signing_delta=${signing_delta:-empty}"
        record_result "E2E" "vvp_signing_flow" "fail" "No new invite.completed entries"
        failed=1
    fi

    # Check if VVP verification flow completed
    if [ -n "$verify_delta" ] && [ "$verify_delta" -gt 0 ] 2>/dev/null; then
        log_pass "VVP verification flow completed ($verify_delta new Verification complete entries)"
        record_result "E2E" "vvp_verify_flow" "pass" "$verify_delta verification events"

        # Show relevant verification log lines
        if [ "$JSON_OUTPUT" = false ]; then
            echo "$call_output" | sed -n '/=== VERIFY_LOGS ===/,/=== CALL_TEST_RESULTS ===/p' | grep -v "===" | while IFS= read -r line; do
                if [ -n "$line" ]; then
                    log_info "  $line"
                fi
            done
        fi
    else
        log_warn "No VVP verification evidence — verify_delta=${verify_delta:-empty} (verification service may be down)"
        record_result "E2E" "vvp_verify_flow" "warn" "No Verification complete entries"
    fi

    return $failed
}

# Run cache timing tests via sip-call-test.py --timing on PBX
# Called when --e2e --timing is passed. Timing failures produce warn, not fail.
_run_timing_tests() {
    log_check "Cache timing measurement (chained sign→verify, count=3)"

    if [ "$SKIP_PBX" = "true" ]; then
        log_info "Timing tests skipped (VVP_SKIP_PBX=true)"
        return 0
    fi

    if [ -z "$API_KEY" ]; then
        log_fail "VVP_TEST_API_KEY not set — timing tests cannot run"
        record_result "E2E" "cache_timing" "fail" "No API key provided"
        return 1
    fi

    # Deploy sip-call-test.py to PBX and run chained timing
    local script_b64
    # macOS base64 uses -i for file input; Linux uses positional arg + -w0
    script_b64=$(base64 -w0 "$SIP_TEST_SCRIPT" 2>/dev/null || base64 -i "$SIP_TEST_SCRIPT" | tr -d '\n')

    if [ -z "$script_b64" ]; then
        log_fail "Could not encode SIP test script for timing"
        return 1
    fi

    local timing_output
    timing_output=$(pbx_run "
        echo '$script_b64' | base64 -d > /tmp/vvp-sip-test.py

        VVP_TEST_API_KEY='$API_KEY' \
        VVP_SIP_REDIRECT_HOST=127.0.0.1 \
        VVP_SIP_REDIRECT_PORT=5070 \
        VVP_SIP_VERIFY_HOST=127.0.0.1 \
        VVP_SIP_VERIFY_PORT=5071 \
        python3 /tmp/vvp-sip-test.py \
            --test chain --timing --timing-count 3 \
            --verifier-url $VERIFIER_URL \
            --json --timeout 15 2>&1

        rm -f /tmp/vvp-sip-test.py
    " 2>/dev/null) || {
        log_warn "Could not run timing tests on PBX VM"
        record_result "E2E" "cache_timing" "warn" "az vm run-command failed"
        return 0  # warn, not fail
    }

    # Extract JSON from az vm run-command output (may be pretty-printed)
    local json_output
    json_output=$(echo "$timing_output" | python3 -c "
import sys, json
text = sys.stdin.read()
for i, c in enumerate(text):
    if c == '{':
        depth = 0
        for j in range(i, len(text)):
            if text[j] == '{': depth += 1
            elif text[j] == '}': depth -= 1
            if depth == 0:
                try:
                    obj = json.loads(text[i:j+1])
                    if 'results' in obj:
                        print(json.dumps(obj))
                        sys.exit(0)
                except (json.JSONDecodeError, ValueError):
                    pass
                break
" 2>/dev/null) || json_output=""

    if [ "$VERBOSE" = true ] && [ "$JSON_OUTPUT" = false ]; then
        log_info "Timing test raw output:"
        echo "$timing_output" | while IFS= read -r line; do
            log_info "  $line"
        done
    fi

    if [ -z "$json_output" ]; then
        log_warn "Could not parse timing test results"
        record_result "E2E" "cache_timing" "warn" "No parseable output"
        return 0
    fi

    # Parse timing results
    local timing_data
    timing_data=$(echo "$json_output" | python3 -c "
import json, sys
data = json.load(sys.stdin)
results = data.get('results', [])
for r in results:
    if r.get('test') == 'chain_timing':
        status = r.get('status', 'fail')
        speedup = r.get('speedup_ratio', 0)
        first = r.get('first_call_ms', 0)
        second = r.get('second_call_ms', 0)
        cold_uncertain = r.get('cold_uncertain', False)
        cache_metrics = r.get('cache_metrics') or {}
        cache_confirmed = cache_metrics.get('cache_confirmed', False)
        v_delta = cache_metrics.get('verification_hits_delta', '?')
        detail = r.get('detail', '')
        print(f'{status}|{speedup}|{first}|{second}|{cold_uncertain}|{cache_confirmed}|{v_delta}|{detail}')
        break
else:
    print('fail|0|0|0|False|False|?|No chain_timing result found')
" 2>/dev/null) || timing_data=""

    if [ -z "$timing_data" ]; then
        log_warn "Could not parse chain_timing result"
        record_result "E2E" "cache_timing" "warn" "Parse error"
        return 0
    fi

    local t_status t_speedup t_first t_second t_cold t_confirmed t_vdelta t_detail
    IFS='|' read -r t_status t_speedup t_first t_second t_cold t_confirmed t_vdelta t_detail <<< "$timing_data"

    local summary="Speedup ${t_speedup}x — cold=${t_first}ms, cached=${t_second}ms"
    if [ "$t_confirmed" = "True" ]; then
        summary="$summary [cache confirmed, v_hits_delta=$t_vdelta]"
    elif [ "$t_vdelta" != "?" ]; then
        summary="$summary [cache unconfirmed, v_hits_delta=$t_vdelta]"
    else
        summary="$summary [no metrics]"
    fi
    if [ "$t_cold" = "True" ]; then
        summary="$summary [cold uncertain]"
    fi

    # Timing results are always warn-not-fail
    if [ "$t_status" = "pass" ]; then
        log_pass "Cache timing: $summary"
        record_result "E2E" "cache_timing" "pass" "$summary"
    elif [ "$t_status" = "warn" ]; then
        log_warn "Cache timing: $summary"
        record_result "E2E" "cache_timing" "warn" "$summary"
    else
        # Even timing failures are only warnings
        log_warn "Cache timing: $t_detail"
        record_result "E2E" "cache_timing" "warn" "$t_detail"
    fi

    return 0
}

# Parse JSON output from sip-call-test.py and record results
# Usage: _parse_sip_test_result <json_output> <check_name> <display_name>
_parse_sip_test_result() {
    local json_output="$1"
    local check_name="$2"
    local display_name="$3"

    if [ -z "$json_output" ]; then
        log_fail "$display_name test produced no output"
        record_result "E2E" "$check_name" "fail" "No output"
        return 1
    fi

    local test_status test_detail
    test_status=$(echo "$json_output" | python3 -c "
import json, sys
data = json.load(sys.stdin)
results = data.get('results', [])
if results:
    print(results[0].get('status', 'fail'))
else:
    print('fail')
" 2>/dev/null) || test_status="fail"

    test_detail=$(echo "$json_output" | python3 -c "
import json, sys
data = json.load(sys.stdin)
results = data.get('results', [])
if results:
    print(results[0].get('detail', 'unknown'))
else:
    print('No results')
" 2>/dev/null) || test_detail="parse error"

    local result_code=0

    if [ "$test_status" = "pass" ]; then
        log_pass "$display_name: $test_detail"
        record_result "E2E" "$check_name" "pass" "$test_detail"
    elif [ "$test_status" = "warn" ]; then
        log_warn "$display_name: $test_detail"
        record_result "E2E" "$check_name" "warn" "$test_detail"
    elif [ "$test_status" = "skip" ]; then
        log_info "$display_name: $test_detail"
        record_result "E2E" "$check_name" "warn" "$test_detail"
    else
        log_fail "$display_name: $test_detail"
        record_result "E2E" "$check_name" "fail" "$test_detail"
        result_code=1
    fi

    # Show detailed checks in verbose mode
    if [ "$VERBOSE" = true ] && [ "$JSON_OUTPUT" = false ]; then
        echo "$json_output" | python3 -c "
import json, sys
data = json.load(sys.stdin)
for r in data.get('results', []):
    for check, passed in r.get('checks', {}).items():
        mark = '+' if passed else '-'
        print(f'        [{mark}] {check}')
" 2>/dev/null
    fi

    return $result_code
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

print_summary() {
    if [ "$JSON_OUTPUT" = true ]; then
        local overall="healthy"
        if [ "$FAILED_CHECKS" -gt 0 ]; then
            overall="unhealthy"
        elif [ "$WARNINGS" -gt 0 ]; then
            overall="degraded"
        fi

        _SUM_OVERALL="$overall" \
        _SUM_MODE="$MODE" \
        _SUM_TOTAL="$TOTAL_CHECKS" \
        _SUM_PASSED="$PASSED_CHECKS" \
        _SUM_FAILED="$FAILED_CHECKS" \
        _SUM_WARNINGS="$WARNINGS" \
        _SUM_CHECKED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        python3 -c "
import json, sys, os
results = json.loads(sys.stdin.read())
summary = {
    'overall_status': os.environ['_SUM_OVERALL'],
    'mode': os.environ['_SUM_MODE'],
    'total_checks': int(os.environ['_SUM_TOTAL']),
    'passed': int(os.environ['_SUM_PASSED']),
    'failed': int(os.environ['_SUM_FAILED']),
    'warnings': int(os.environ['_SUM_WARNINGS']),
    'checked_at': os.environ['_SUM_CHECKED_AT'],
    'results': results,
}
print(json.dumps(summary, indent=2))
" <<< "$RESULTS_JSON"
        return
    fi

    log_header "Summary"

    echo ""
    echo -e "  Mode:      ${BOLD}$MODE${NC}"
    echo -e "  Checks:    ${BOLD}$TOTAL_CHECKS${NC}"
    echo -e "  Passed:    ${GREEN}$PASSED_CHECKS${NC}"
    if [ "$FAILED_CHECKS" -gt 0 ]; then
        echo -e "  Failed:    ${RED}$FAILED_CHECKS${NC}"
    else
        echo -e "  Failed:    ${DIM}0${NC}"
    fi
    if [ "$WARNINGS" -gt 0 ]; then
        echo -e "  Warnings:  ${YELLOW}$WARNINGS${NC}"
    fi
    echo ""

    if [ "$FAILED_CHECKS" -eq 0 ] && [ "$WARNINGS" -eq 0 ]; then
        echo -e "  ${GREEN}${BOLD}ALL CHECKS PASSED${NC}"
    elif [ "$FAILED_CHECKS" -eq 0 ]; then
        echo -e "  ${YELLOW}${BOLD}PASSED WITH WARNINGS${NC}"
    else
        echo -e "  ${RED}${BOLD}$FAILED_CHECKS CHECK(S) FAILED${NC}"
    fi
    echo ""
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
    if [ "$JSON_OUTPUT" = false ]; then
        echo ""
        echo -e "${BOLD}VVP System Health Check${NC}"
        echo -e "${DIM}$(date -u +%Y-%m-%dT%H:%M:%SZ) | Mode: $MODE${NC}"
    fi

    # Phase 0: Restart if requested
    if [ "$DO_RESTART" = true ]; then
        do_restart
    fi

    # Phase 1: Container Apps
    check_container_apps || true

    # Phase 2: PBX
    check_pbx_services || true

    # Phase 3: Connectivity
    check_connectivity || true

    # Phase 4: E2E
    check_e2e || true

    # Summary
    print_summary

    # Exit code
    if [ "$FAILED_CHECKS" -gt 0 ]; then
        exit 1
    fi
    exit 0
}

main
