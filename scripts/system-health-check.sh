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
JSON_OUTPUT=false
VERBOSE=false

# Azure production URLs
VERIFIER_URL="https://vvp-verifier.rcnx.io"
ISSUER_URL="https://vvp-issuer.rcnx.io"
WITNESS1_URL="https://vvp-witness1.rcnx.io"
WITNESS2_URL="https://vvp-witness2.rcnx.io"
WITNESS3_URL="https://vvp-witness3.rcnx.io"
PBX_HOST="pbx.rcnx.io"
SIP_REDIRECT_STATUS_URL="http://pbx.rcnx.io:8080"

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
            SIP_REDIRECT_STATUS_URL="http://localhost:8080"
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
    az vm run-command invoke \
        --resource-group VVP \
        --name vvp-pbx \
        --command-id RunShellScript \
        --scripts "$cmd" \
        --query "value[0].message" -o tsv 2>/dev/null
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

    # --- SIP Redirect HTTP health (accessible externally) ---
    check_http_health "SIP-Redirect" "$SIP_REDIRECT_STATUS_URL" "/health" || failed=1
    check_http_version "SIP-Redirect" "$SIP_REDIRECT_STATUS_URL" || true

    # --- PBX VM process checks via Azure CLI ---
    log_check "PBX VM services via Azure CLI"

    local pbx_output
    pbx_output=$(pbx_run "
        echo '=== Service Status ==='
        echo \"freeswitch:\$(systemctl is-active freeswitch 2>/dev/null || echo 'not-found')\"
        echo \"sip-redirect:\$(systemctl is-active vvp-sip-redirect 2>/dev/null || echo 'not-found')\"
        echo \"sip-verify:\$(systemctl is-active vvp-sip-verify 2>/dev/null || echo 'not-found')\"
        echo ''
        echo '=== Listening Ports ==='
        ss -tulnp 2>/dev/null | grep -E ':(5060|5070|5071|5080|7443|8080) ' || echo 'No VVP ports found'
        echo ''
        echo '=== SIP Profiles ==='
        fs_cli -x 'sofia status' 2>/dev/null | head -20 || echo 'Could not query FreeSWITCH'
    " 2>/dev/null) || {
        log_fail "Could not reach PBX VM via Azure CLI"
        record_result "PBX" "vm_access" "fail" "az vm run-command failed"
        return 1
    }

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

    # PBX-to-service connectivity (via Azure CLI)
    if [ "$MODE" = "azure" ] && [ "$SKIP_PBX" != "true" ]; then
        log_check "PBX → Issuer API connectivity"
        local pbx_conn
        pbx_conn=$(pbx_run "
            curl -sf --max-time 10 https://vvp-issuer.rcnx.io/healthz 2>/dev/null && echo 'OK' || echo 'FAIL'
        " 2>/dev/null) || pbx_conn="ERROR"

        if echo "$pbx_conn" | grep -q "OK"; then
            log_pass "PBX can reach Issuer API"
            record_result "PBX" "issuer_connectivity" "pass" "Reachable"
        else
            log_fail "PBX cannot reach Issuer API"
            record_result "PBX" "issuer_connectivity" "fail" "Unreachable"
            failed=1
        fi

        log_check "PBX → Verifier API connectivity"
        pbx_conn=$(pbx_run "
            curl -sf --max-time 10 https://vvp-verifier.rcnx.io/healthz 2>/dev/null && echo 'OK' || echo 'FAIL'
        " 2>/dev/null) || pbx_conn="ERROR"

        if echo "$pbx_conn" | grep -q "OK"; then
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
        log_warn "Signing test requires VVP_TEST_API_KEY — skipping"
        record_result "E2E" "sip_signing" "warn" "No API key"
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
    script_b64=$(base64 -w0 "$SIP_TEST_SCRIPT" 2>/dev/null || base64 "$SIP_TEST_SCRIPT" 2>/dev/null)

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
        log_warn "No VVP_TEST_API_KEY — signing test will be skipped on PBX"
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

    # The pbx_output from az vm run-command includes stdout and stderr markers.
    # Extract the JSON portion.
    local json_output
    json_output=$(echo "$pbx_output" | grep -A9999 '{"results"' | sed '$d') || json_output=""

    if [ -z "$json_output" ]; then
        # Try to find JSON anywhere in the output
        json_output=$(echo "$pbx_output" | python3 -c "
import sys, json
text = sys.stdin.read()
# Find JSON object in the text
start = text.find('{\"results\"')
if start >= 0:
    # Find matching closing brace
    depth = 0
    for i in range(start, len(text)):
        if text[i] == '{': depth += 1
        elif text[i] == '}': depth -= 1
        if depth == 0:
            print(text[start:i+1])
            break
" 2>/dev/null) || json_output=""
    fi

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

    log_check "FreeSWITCH VVP loopback call (originate → signing → log verification)"

    local call_output
    call_output=$(pbx_run "
        set -e

        # Record timestamp for log filtering
        BEFORE=\$(date -u +%Y-%m-%dT%H:%M:%S 2>/dev/null || date +%s)

        # Originate a test call through the VVP signing flow.
        # The call routes: 71006 → vvp-loopback-outbound → SIP Redirect (5070)
        #   → Issuer API → 302 → loopback-inbound → bridge to user/1006
        # The final bridge will fail (1006 likely not registered), but the
        # signing flow is what we're testing.
        ORIGINATE_RESULT=\$(fs_cli -x \"bgapi originate {origination_caller_id_number=+441923311001,origination_caller_id_name=VVP-HealthCheck,sip_h_X-VVP-API-Key=$API_KEY}sofia/internal/71006@127.0.0.1 &park()\" 2>/dev/null || echo 'ORIGINATE_FAILED')

        # Wait for the call to process through signing flow
        sleep 5

        # Check FreeSWITCH logs for VVP activity since the test started
        VVP_LOGS=\$(journalctl -u freeswitch --since \"\$BEFORE\" --no-pager 2>/dev/null | grep -i 'VVP' | tail -20 || echo '')

        # Check if signing service was contacted (look for loopback routing)
        SIGNING_EVIDENCE=\$(echo \"\$VVP_LOGS\" | grep -c 'Loopback call\\|Routing to signing\\|VVP.*brand' || echo '0')

        # Hang up any test channels to clean up
        fs_cli -x 'hupall NORMAL_CLEARING' 2>/dev/null || true

        # Output structured results
        echo '=== CALL_TEST_RESULTS ==='
        echo \"originate:\$ORIGINATE_RESULT\"
        echo \"signing_evidence:\$SIGNING_EVIDENCE\"
        echo '=== VVP_LOGS ==='
        echo \"\$VVP_LOGS\"
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
    local originate_result signing_evidence
    originate_result=$(echo "$call_output" | grep "^originate:" | cut -d: -f2-)
    signing_evidence=$(echo "$call_output" | grep "^signing_evidence:" | cut -d: -f2)

    # Check if originate succeeded (should contain a UUID or +OK)
    if echo "$originate_result" | grep -qi "OK\|Job-UUID\|[0-9a-f]\{8\}"; then
        log_pass "FreeSWITCH originated VVP loopback call"
        record_result "E2E" "fs_originate" "pass" "Call originated"
    elif echo "$originate_result" | grep -qi "ORIGINATE_FAILED"; then
        log_fail "FreeSWITCH could not originate call"
        record_result "E2E" "fs_originate" "fail" "Originate failed"
        failed=1
    else
        log_warn "FreeSWITCH originate result unclear: $originate_result"
        record_result "E2E" "fs_originate" "warn" "$originate_result"
    fi

    # Check if VVP signing flow was triggered (evidence in logs)
    if [ -n "$signing_evidence" ] && [ "$signing_evidence" -gt 0 ] 2>/dev/null; then
        log_pass "VVP signing flow triggered ($signing_evidence log entries)"
        record_result "E2E" "vvp_signing_flow" "pass" "$signing_evidence VVP log entries"

        # Show relevant log lines
        if [ "$JSON_OUTPUT" = false ]; then
            echo "$call_output" | sed -n '/=== VVP_LOGS ===/,/=== END ===/p' | grep -v "===" | while IFS= read -r line; do
                if [ -n "$line" ]; then
                    log_info "  $line"
                fi
            done
        fi
    else
        log_warn "No VVP signing evidence in FreeSWITCH logs (signing service may not have responded)"
        record_result "E2E" "vvp_signing_flow" "warn" "No VVP log entries found"
    fi

    return $failed
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
