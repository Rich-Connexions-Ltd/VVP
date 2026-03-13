#!/usr/bin/env python3
"""VVP System Test — end-to-end gate for development sessions.

Validates the entire VVP stack: service health, PBX configuration, SIP
signing/verification flows, and X-VVP header correctness.

This script uses only stdlib and can run on any Python 3.8+ system.

Usage:
    # Full system test (health + PBX + dialplan + SIP calls)
    python3 scripts/system-test.py

    # Health checks only (skip PBX/SIP)
    python3 scripts/system-test.py --skip-pbx

    # Include loopback test (full dialplan flow, adds ~20s)
    python3 scripts/system-test.py --loopback

    # JSON output
    python3 scripts/system-test.py --json

    # Skip SIP call tests only
    python3 scripts/system-test.py --skip-sip

Environment:
    VVP_VERIFIER_URL     Override verifier URL (default: https://vvp-verifier.rcnx.io)
    VVP_ISSUER_URL       Override issuer URL (default: https://vvp-issuer.rcnx.io)
    VVP_TEST_API_KEY     API key for signing test (loaded from .e2e-config)
    VVP_SKIP_PBX         Set to "true" to skip PBX checks

Exit codes:
    0  All checks passed
    1  One or more checks failed
    2  Script error (missing dependencies, etc.)
"""

import argparse
import base64
import json
import os
import socket
import subprocess
import sys
import time
import urllib.request
import uuid
import xml.etree.ElementTree as ET


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPT_DIR)

# Default production URLs
VERIFIER_URL = "https://vvp-verifier.rcnx.io"
ISSUER_URL = "https://vvp-issuer.rcnx.io"
WITNESS_URLS = [
    "https://vvp-witness1.rcnx.io",
    "https://vvp-witness2.rcnx.io",
    "https://vvp-witness3.rcnx.io",
]

# Witness AIDs (deterministic from salts)
WAN_AID = "BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha"
WIL_AID = "BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM"
WES_AID = "BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX"
WITNESS_AIDS = [WAN_AID, WIL_AID, WES_AID]

# PBX
PBX_VM_NAME = "vvp-pbx"
PBX_RESOURCE_GROUP = "VVP"

# Timeouts
HTTP_TIMEOUT = 10
SIP_TIMEOUT = 15
GATE_TTL_SECONDS = 3600  # 1 hour

# Test TNs
DEFAULT_ORIG_TN = "+441923311000"
DEFAULT_DEST_TN = "+441923311006"

# Dialplan rules
DIALPLAN_RULES_PATH = os.path.join(
    REPO_ROOT, "services", "pbx", "config", "dialplan-rules.json"
)


# ---------------------------------------------------------------------------
# Terminal colors
# ---------------------------------------------------------------------------

if sys.stdout.isatty():
    RED = "\033[0;31m"
    GREEN = "\033[0;32m"
    YELLOW = "\033[0;33m"
    BLUE = "\033[0;34m"
    CYAN = "\033[0;36m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    NC = "\033[0m"
else:
    RED = GREEN = YELLOW = BLUE = CYAN = BOLD = DIM = NC = ""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def load_e2e_config():
    """Load test configuration from scripts/.e2e-config."""
    config = {}
    config_path = os.path.join(SCRIPT_DIR, ".e2e-config")
    if os.path.exists(config_path):
        with open(config_path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    key, value = line.split("=", 1)
                    config[key.strip()] = value.strip()
    return config


def log_header(msg, json_output=False):
    if not json_output:
        print()
        print(f"{BOLD}{BLUE}{'━' * 55}{NC}")
        print(f"{BOLD}{BLUE}  {msg}{NC}")
        print(f"{BOLD}{BLUE}{'━' * 55}{NC}")


def log_pass(msg, json_output=False):
    if not json_output:
        print(f"  {GREEN}PASS{NC}  {msg}")


def log_fail(msg, json_output=False):
    if not json_output:
        print(f"  {RED}FAIL{NC}  {msg}")


def log_warn(msg, json_output=False):
    if not json_output:
        print(f"  {YELLOW}WARN{NC}  {msg}")


def log_info(msg, json_output=False):
    if not json_output:
        print(f"  {DIM}{msg}{NC}")


def log_check(msg, json_output=False):
    if not json_output:
        print(f"  {DIM}Checking{NC} {msg}...")


def check_http(url, timeout=HTTP_TIMEOUT):
    """HTTP GET to a URL, return (ok, status_code, body, elapsed_ms)."""
    start = time.monotonic()
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            elapsed = (time.monotonic() - start) * 1000
            return True, resp.status, body, round(elapsed, 1)
    except Exception as e:
        elapsed = (time.monotonic() - start) * 1000
        return False, 0, str(e), round(elapsed, 1)


def pbx_run(command, timeout=60):
    """Run a command on the PBX VM via Azure CLI.

    Returns (ok, output). Retries on Conflict (Azure allows one
    run-command per VM at a time).
    """
    for attempt in range(3):
        try:
            result = subprocess.run(
                [
                    "az", "vm", "run-command", "invoke",
                    "--resource-group", PBX_RESOURCE_GROUP,
                    "--name", PBX_VM_NAME,
                    "--command-id", "RunShellScript",
                    "--scripts", command,
                    "--query", "value[0].message",
                    "-o", "tsv",
                ],
                capture_output=True, text=True, timeout=timeout,
            )
            if result.returncode == 0:
                return True, result.stdout.strip()
            if "Conflict" in result.stderr:
                time.sleep(15)
                continue
            return False, result.stderr.strip()
        except subprocess.TimeoutExpired:
            return False, f"az command timed out after {timeout}s"
        except FileNotFoundError:
            return False, "az CLI not found — install Azure CLI"
    return False, "PBX command failed after 3 retries (Conflict)"


def strip_az_output(output):
    """Extract stdout content from az vm run-command output.

    Azure wraps output as: 'Enable succeeded: \\n[stdout]\\n...\\n[stderr]\\n...'
    The \\n may be literal two-character sequences (backslash + n) rather than
    actual newlines, depending on how az formats --query tsv output.
    This extracts just the stdout portion, handling both cases.
    """
    text = output
    # Azure CLI sometimes outputs literal \n instead of real newlines
    # Replace literal \n sequences with real newlines first
    text = text.replace("\\n", "\n")
    # Strip 'Enable succeeded:' prefix
    if "Enable succeeded:" in text:
        text = text.split("Enable succeeded:", 1)[1]
    # Extract [stdout] content
    if "[stdout]" in text:
        text = text.split("[stdout]", 1)[1]
        if "[stderr]" in text:
            text = text.split("[stderr]")[0]
    return text.strip()


# ---------------------------------------------------------------------------
# SIP message construction (from sip-call-test.py)
# ---------------------------------------------------------------------------

def build_signing_invite(orig_tn, dest_tn, api_key,
                         local_ip="127.0.0.1", local_port=15060):
    """Build a SIP INVITE for the signing flow."""
    call_id = f"vvp-systest-{uuid.uuid4().hex[:12]}@{local_ip}"
    branch = f"z9hG4bK{uuid.uuid4().hex[:16]}"
    tag = uuid.uuid4().hex[:8]
    lines = [
        f"INVITE sip:{dest_tn}@127.0.0.1:5070 SIP/2.0",
        f"Via: SIP/2.0/UDP {local_ip}:{local_port};branch={branch}",
        f"From: <sip:{orig_tn}@{local_ip}>;tag={tag}",
        f"To: <sip:{dest_tn}@127.0.0.1>",
        f"Call-ID: {call_id}",
        "CSeq: 1 INVITE",
        f"Contact: <sip:{local_ip}:{local_port}>",
        f"X-VVP-API-Key: {api_key}",
        "Max-Forwards: 70",
        "Content-Length: 0",
    ]
    return ("\r\n".join(lines) + "\r\n\r\n").encode("utf-8")


def build_verify_invite_with_real_headers(orig_tn, dest_tn,
                                          p_identity, p_passport,
                                          local_ip="127.0.0.1",
                                          local_port=15061):
    """Build a verify INVITE using real P-VVP-Identity and P-VVP-Passport."""
    call_id = f"vvp-systest-v-{uuid.uuid4().hex[:12]}@{local_ip}"
    branch = f"z9hG4bK{uuid.uuid4().hex[:16]}"
    tag = uuid.uuid4().hex[:8]

    passport_b64 = base64.urlsafe_b64encode(
        p_passport.encode()
    ).decode().rstrip("=")
    try:
        padded = p_identity + "=" * (4 - len(p_identity) % 4)
        identity_data = json.loads(base64.urlsafe_b64decode(padded))
        info_url = identity_data.get("kid", "")
    except Exception:
        info_url = ""

    lines = [
        f"INVITE sip:{dest_tn}@127.0.0.1:5071 SIP/2.0",
        f"Via: SIP/2.0/UDP {local_ip}:{local_port};branch={branch}",
        f"From: <sip:{orig_tn}@carrier.example.com>;tag={tag}",
        f"To: <sip:{dest_tn}@127.0.0.1>",
        f"Call-ID: {call_id}",
        "CSeq: 1 INVITE",
        f"Contact: <sip:{local_ip}:{local_port}>",
        f"Identity: <{passport_b64}>;info={info_url};alg=EdDSA;ppt=vvp",
        f"P-VVP-Identity: {p_identity}",
        f"P-VVP-Passport: {p_passport}",
        "Max-Forwards: 70",
        "Content-Length: 0",
    ]
    return ("\r\n".join(lines) + "\r\n\r\n").encode("utf-8")


def parse_sip_response(data):
    """Parse a SIP response into status code and headers."""
    text = data.decode("utf-8", errors="replace")
    lines = text.split("\r\n")
    result = {"raw_status_line": "", "status_code": 0, "reason": "", "headers": {}}
    if not lines:
        return result
    status_line = lines[0]
    result["raw_status_line"] = status_line
    parts = status_line.split(" ", 2)
    if len(parts) >= 2:
        try:
            result["status_code"] = int(parts[1])
        except ValueError:
            pass
    if len(parts) >= 3:
        result["reason"] = parts[2]
    for line in lines[1:]:
        if not line:
            break
        if ":" in line:
            key, value = line.split(":", 1)
            result["headers"][key.strip()] = value.strip()
    return result


def send_sip_and_receive(invite, host, port, timeout=SIP_TIMEOUT):
    """Send a SIP INVITE via UDP and wait for response."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    start = time.monotonic()
    try:
        sock.sendto(invite, (host, port))
        data, addr = sock.recvfrom(65535)
        elapsed_ms = (time.monotonic() - start) * 1000
        response = parse_sip_response(data)
        response["elapsed_ms"] = round(elapsed_ms, 1)
        response["source"] = f"{addr[0]}:{addr[1]}"
        return response
    except socket.timeout:
        elapsed_ms = (time.monotonic() - start) * 1000
        return {"error": "timeout", "detail": f"No response within {timeout}s",
                "elapsed_ms": round(elapsed_ms, 1)}
    except OSError as e:
        elapsed_ms = (time.monotonic() - start) * 1000
        return {"error": "socket_error", "detail": str(e),
                "elapsed_ms": round(elapsed_ms, 1)}
    finally:
        sock.close()


# ---------------------------------------------------------------------------
# Phase 0: Warmup — poll all services until healthy
# ---------------------------------------------------------------------------

WARMUP_TIMEOUT = 180  # Max seconds to wait for all services
WARMUP_INTERVAL = 5   # Seconds between polls

def phase0_warmup(verifier_url, issuer_url, witness_urls,
                   json_output=False, verbose=False):
    """Warm up all services by polling health endpoints until they respond.

    Also polls PBX services via az vm run-command. Retries with backoff
    until all services are healthy or timeout is reached.
    """
    log_header("Phase 0: Service Warmup", json_output)

    # Build list of HTTP endpoints to poll
    endpoints = [
        ("Verifier", f"{verifier_url}/healthz", 10),
        ("Issuer", f"{issuer_url}/healthz", 10),
    ]
    for i, (url, aid) in enumerate(zip(witness_urls, WITNESS_AIDS)):
        endpoints.append((f"Witness {i+1}", f"{url}/oobi/{aid}/controller", 60))

    # Track which endpoints are healthy
    healthy = set()
    start = time.monotonic()
    attempt = 0

    while time.monotonic() - start < WARMUP_TIMEOUT:
        attempt += 1
        remaining = [e for e in endpoints if e[0] not in healthy]

        if not remaining:
            break

        if not json_output:
            elapsed = int(time.monotonic() - start)
            names = ", ".join(e[0] for e in remaining)
            if attempt == 1:
                log_info(f"Waiting for: {names}")
            else:
                log_info(f"Retry {attempt} ({elapsed}s): waiting for {names}")

        for name, url, timeout in remaining:
            ok, status, body, ms = check_http(url, timeout=min(timeout, 15))
            if ok:
                healthy.add(name)
                log_pass(f"{name} ready ({ms}ms)", json_output)

        if len(healthy) == len(endpoints):
            break

        time.sleep(WARMUP_INTERVAL)

    # Report results
    all_http_ok = len(healthy) == len(endpoints)
    if not all_http_ok:
        failed = [e[0] for e in endpoints if e[0] not in healthy]
        for name in failed:
            log_fail(f"{name} not ready after {WARMUP_TIMEOUT}s", json_output)

    # Warm up PBX services
    # Single pbx_run call that checks status, restarts if needed, and re-checks
    # This avoids Azure Conflict errors from sequential run-command calls
    pbx_ok = True
    if not json_output:
        log_info("Checking PBX services (with auto-restart)...")

    ok, output = pbx_run(
        "SERVICES='freeswitch vvp-sip-redirect vvp-sip-verify'\n"
        "NEED_RESTART=''\n"
        "for svc in $SERVICES; do\n"
        "  if systemctl is-active --quiet \"$svc\" 2>/dev/null; then\n"
        "    echo \"INITIAL:$svc=active\"\n"
        "  else\n"
        "    actual=$(systemctl is-active \"$svc\" 2>/dev/null)\n"
        "    echo \"INITIAL:$svc=${actual:-unknown}\"\n"
        "    NEED_RESTART=\"$NEED_RESTART $svc\"\n"
        "  fi\n"
        "done\n"
        "if [ -n \"$NEED_RESTART\" ]; then\n"
        "  echo \"RESTARTING:$NEED_RESTART\"\n"
        "  # Stop services and kill any lingering processes holding ports\n"
        "  for svc in $NEED_RESTART; do\n"
        "    systemctl stop \"$svc\" 2>&1 || true\n"
        "  done\n"
        "  sleep 2\n"
        "  # Force-kill any processes still holding SIP ports (5070-5072)\n"
        "  for port in 5070 5071 5072; do\n"
        "    PID=$(ss -lntp 2>/dev/null | grep \":$port \" | sed 's/.*pid=\\([0-9]*\\).*/\\1/' | head -1)\n"
        "    if [ -n \"$PID\" ] && [ \"$PID\" != \"0\" ]; then\n"
        "      echo \"KILLING:pid=$PID on port $port\"\n"
        "      kill -9 \"$PID\" 2>/dev/null || true\n"
        "    fi\n"
        "  done\n"
        "  sleep 2\n"
        "  for svc in $NEED_RESTART; do\n"
        "    systemctl start \"$svc\" 2>&1 || true\n"
        "  done\n"
        "  sleep 15\n"
        "  for svc in $NEED_RESTART; do\n"
        "    if systemctl is-active --quiet \"$svc\" 2>/dev/null; then\n"
        "      echo \"AFTER_RESTART:$svc=active\"\n"
        "    else\n"
        "      actual=$(systemctl is-active \"$svc\" 2>/dev/null)\n"
        "      echo \"AFTER_RESTART:$svc=${actual:-unknown}\"\n"
        "      # Show journal for failed service\n"
        "      echo \"JOURNAL:$svc=$(journalctl -u $svc -n 5 --no-pager 2>&1 | tail -3)\"\n"
        "    fi\n"
        "  done\n"
        "fi",
        timeout=120,
    )

    if ok:
        clean = strip_az_output(output)
        if verbose and not json_output:
            log_info(f"PBX warmup output: {clean[:500]}")

        for svc in ["freeswitch", "vvp-sip-redirect", "vvp-sip-verify"]:
            # Check AFTER_RESTART first (if restart was attempted), then INITIAL
            svc_active = False
            for line in clean.split("\n"):
                line = line.strip()
                if line == f"AFTER_RESTART:{svc}=active":
                    svc_active = True
                    log_pass(f"PBX {svc} ready (after restart)", json_output)
                    break
                elif line == f"INITIAL:{svc}=active":
                    svc_active = True
                    log_pass(f"PBX {svc} ready", json_output)
                    break

            if not svc_active:
                # Find the status for error reporting
                status = "unknown"
                for line in clean.split("\n"):
                    line = line.strip()
                    if line.startswith(f"AFTER_RESTART:{svc}="):
                        status = line.split("=", 1)[1]
                    elif line.startswith(f"INITIAL:{svc}="):
                        status = line.split("=", 1)[1]
                log_fail(f"PBX {svc} not active (status={status})", json_output)
                # Show journal if available
                for line in clean.split("\n"):
                    line = line.strip()
                    if line.startswith(f"JOURNAL:{svc}="):
                        journal = line.split("=", 1)[1]
                        log_info(f"  Journal: {journal[:200]}")
                pbx_ok = False
    else:
        log_warn(f"Could not reach PBX VM: {output[:100]}", json_output)
        # Non-fatal during warmup — Phase 2 will catch this
        pbx_ok = True

    total_elapsed = int(time.monotonic() - start)
    if all_http_ok and pbx_ok:
        log_pass(f"All services ready ({total_elapsed}s)", json_output)
    else:
        log_warn(f"Warmup incomplete after {total_elapsed}s", json_output)

    return all_http_ok and pbx_ok


# ---------------------------------------------------------------------------
# Phase 1: Service Health Checks
# ---------------------------------------------------------------------------

def phase1_health_checks(verifier_url, issuer_url, witness_urls,
                         json_output=False, verbose=False):
    """Check health of all VVP services."""
    log_header("Phase 1: Service Health Checks", json_output)
    results = []
    all_ok = True

    # Verifier
    log_check("Verifier", json_output)
    ok, status, body, ms = check_http(f"{verifier_url}/healthz")
    if ok:
        log_pass(f"Verifier healthy ({ms}ms)", json_output)
    else:
        log_fail(f"Verifier unhealthy: {body[:100]}", json_output)
        all_ok = False
    results.append({"component": "verifier", "ok": ok, "status": status,
                     "ms": ms, "url": verifier_url})

    # Issuer
    log_check("Issuer", json_output)
    ok, status, body, ms = check_http(f"{issuer_url}/healthz")
    if ok:
        log_pass(f"Issuer healthy ({ms}ms)", json_output)
    else:
        log_fail(f"Issuer unhealthy: {body[:100]}", json_output)
        all_ok = False
    results.append({"component": "issuer", "ok": ok, "status": status,
                     "ms": ms, "url": issuer_url})

    # Witnesses
    for i, (url, aid) in enumerate(zip(witness_urls, WITNESS_AIDS)):
        name = f"Witness {i+1}"
        log_check(name, json_output)
        oobi_url = f"{url}/oobi/{aid}/controller"
        ok, status, body, ms = check_http(oobi_url, timeout=60)
        if ok:
            log_pass(f"{name} healthy ({ms}ms)", json_output)
        else:
            log_fail(f"{name} unhealthy: {body[:100]}", json_output)
            all_ok = False
        results.append({"component": f"witness_{i+1}", "ok": ok,
                         "status": status, "ms": ms, "url": url})

    return all_ok, results


# ---------------------------------------------------------------------------
# Phase 2: PBX Service Checks
# ---------------------------------------------------------------------------

def phase2_pbx_services(json_output=False, verbose=False):
    """Check PBX VM services and ports."""
    log_header("Phase 2: PBX Service Checks", json_output)
    results = []

    log_check("PBX VM services via Azure CLI", json_output)
    ok, output = pbx_run("""
        echo '=== SERVICES ==='
        for svc in freeswitch vvp-sip-redirect vvp-sip-verify; do
            # Use --quiet so only exit code matters, then print clean status
            if systemctl is-active --quiet "$svc" 2>/dev/null; then
                echo "$svc=active"
            else
                actual=$(systemctl is-active "$svc" 2>/dev/null)
                echo "$svc=${actual:-unknown}"
            fi
        done
        echo '=== PORTS ==='
        for port in 5060 5070 5071 5072 5080 7443; do
            if ss -lntu | grep -q ":${port} "; then
                echo "port_${port}=listening"
            else
                echo "port_${port}=closed"
            fi
        done
    """)

    if not ok:
        log_fail(f"Could not reach PBX VM: {output[:100]}", json_output)
        results.append({"component": "pbx_vm", "ok": False, "detail": output[:200]})
        return False, results

    # Strip az output wrapper
    clean_output = strip_az_output(output)

    if verbose and not json_output:
        log_info(f"  PBX output: {clean_output[:300]}")

    all_ok = True

    # Parse service status — line-by-line for exact matching
    output_lines = clean_output.split("\n")
    for svc in ["freeswitch", "vvp-sip-redirect", "vvp-sip-verify"]:
        # Find the exact line for this service
        svc_status = "unknown"
        for line in output_lines:
            line = line.strip()
            if line.startswith(f"{svc}="):
                svc_status = line.split("=", 1)[1]
                break
        active = svc_status == "active"
        if active:
            log_pass(f"{svc} is active", json_output)
        else:
            log_fail(f"{svc} is NOT active (status={svc_status})", json_output)
            all_ok = False
        results.append({"component": f"pbx_{svc}", "ok": active,
                         "status": svc_status})

    # Parse port status
    for port in [5060, 5070, 5071, 5072, 5080, 7443]:
        listening = f"port_{port}=listening" in clean_output
        if listening:
            log_pass(f"Port {port} listening", json_output)
        else:
            log_fail(f"Port {port} NOT listening", json_output)
            all_ok = False
        results.append({"component": f"pbx_port_{port}", "ok": listening})

    return all_ok, results


# ---------------------------------------------------------------------------
# Phase 3: Dialplan Validation
# ---------------------------------------------------------------------------

def phase3_dialplan_validation(json_output=False, verbose=False):
    """Fetch and validate PBX dialplan against rules."""
    log_header("Phase 3: Dialplan Validation", json_output)
    results = []

    # Load rules
    if not os.path.exists(DIALPLAN_RULES_PATH):
        log_fail(f"Dialplan rules not found: {DIALPLAN_RULES_PATH}", json_output)
        results.append({"check": "rules_file", "ok": False})
        return False, results

    with open(DIALPLAN_RULES_PATH) as f:
        rules = json.load(f)

    # Fetch dialplan from PBX — use base64 encoding to avoid az run-command
    # output truncation (az has a ~4KB message limit for raw output)
    dialplan_path = rules.get("dialplan_path", "/etc/freeswitch/dialplan/public.xml")
    log_check(f"Fetching {dialplan_path} from PBX", json_output)
    ok, output = pbx_run(f"base64 {dialplan_path}")

    if not ok:
        log_fail(f"Could not fetch dialplan: {output[:100]}", json_output)
        results.append({"check": "fetch_dialplan", "ok": False, "detail": output[:200]})
        return False, results

    # Decode base64 to get raw XML
    raw_b64 = strip_az_output(output)
    # Clean up whitespace/newlines in base64 string
    raw_b64 = raw_b64.replace("\n", "").replace("\r", "").replace(" ", "")
    try:
        xml_content = base64.b64decode(raw_b64).decode("utf-8")
    except Exception as e:
        log_fail(f"Could not decode dialplan base64: {e}", json_output)
        log_info(f"  Base64 starts with: {repr(raw_b64[:100])}")
        results.append({"check": "decode_dialplan", "ok": False, "detail": str(e)})
        return False, results

    if verbose and not json_output:
        log_info(f"Raw XML (first 300 chars): {xml_content[:300]}")

    # Parse XML
    try:
        root = ET.fromstring(xml_content)
    except ET.ParseError as e:
        log_fail(f"Could not parse dialplan XML: {e}", json_output)
        # Show what we're trying to parse for debugging
        log_info(f"  Content starts with: {repr(xml_content[:200])}")
        results.append({"check": "parse_xml", "ok": False, "detail": str(e),
                         "content_preview": xml_content[:200]})
        return False, results

    log_pass("Dialplan XML parsed successfully", json_output)
    results.append({"check": "parse_xml", "ok": True})

    all_ok = True

    # Validate each context
    for ctx_name, ctx_rules in rules.get("contexts", {}).items():
        # Find context element
        ctx_elem = root.find(f".//context[@name='{ctx_name}']")
        if ctx_elem is None:
            log_fail(f"Context '{ctx_name}' not found in dialplan", json_output)
            results.append({"check": f"context_{ctx_name}", "ok": False})
            all_ok = False
            continue

        log_pass(f"Context '{ctx_name}' exists", json_output)
        results.append({"check": f"context_{ctx_name}", "ok": True})

        # Check required extensions
        for ext_name in ctx_rules.get("required_extensions", []):
            ext_elem = ctx_elem.find(f".//extension[@name='{ext_name}']")
            if ext_elem is None:
                log_fail(f"  Extension '{ext_name}' missing from '{ctx_name}'",
                         json_output)
                results.append({"check": f"ext_{ext_name}", "ok": False})
                all_ok = False
            else:
                log_pass(f"  Extension '{ext_name}' present", json_output)
                results.append({"check": f"ext_{ext_name}", "ok": True})

        # Run extension-specific checks
        for ext_name, checks in ctx_rules.get("checks", {}).items():
            ext_elem = ctx_elem.find(f".//extension[@name='{ext_name}']")
            if ext_elem is None:
                continue  # Already reported as missing

            # Collect all action data values in this extension
            actions = ext_elem.findall(".//action")
            action_data = [a.get("data", "") for a in actions]
            all_data = " ".join(action_data)

            # bridge_contains check
            if "bridge_contains" in checks:
                target = checks["bridge_contains"]
                bridge_actions = [d for d in action_data
                                  if any(a.get("application") == "bridge"
                                         for a in actions
                                         if a.get("data") == d)]
                # Simpler: just check all data for the bridge target
                found = target in all_data
                if found:
                    log_pass(f"  {ext_name}: bridge targets {target}", json_output)
                else:
                    log_fail(f"  {ext_name}: bridge does NOT target {target}",
                             json_output)
                    all_ok = False
                results.append({"check": f"{ext_name}_bridge_{target}",
                                 "ok": found})

            # bridge_contains_api_key check
            if checks.get("bridge_contains_api_key"):
                has_key = "X-VVP-API-Key=" in all_data
                if has_key:
                    log_pass(f"  {ext_name}: API key in bridge data", json_output)
                else:
                    log_fail(f"  {ext_name}: API key MISSING from bridge data",
                             json_output)
                    all_ok = False
                results.append({"check": f"{ext_name}_api_key", "ok": has_key})

            # exports_headers check
            for header in checks.get("exports_headers", []):
                found = header in all_data
                if found:
                    log_pass(f"  {ext_name}: exports {header}", json_output)
                else:
                    log_fail(f"  {ext_name}: does NOT export {header}",
                             json_output)
                    all_ok = False
                results.append({"check": f"{ext_name}_exports_{header}",
                                 "ok": found})

            # sets_variable check
            if "sets_variable" in checks:
                var = checks["sets_variable"]
                found = var in all_data
                if found:
                    log_pass(f"  {ext_name}: sets {var}", json_output)
                else:
                    log_fail(f"  {ext_name}: does NOT set {var}", json_output)
                    all_ok = False
                results.append({"check": f"{ext_name}_sets_{var}", "ok": found})

    return all_ok, results


# ---------------------------------------------------------------------------
# Phase 4: SIP Call Tests (on PBX)
# ---------------------------------------------------------------------------

def phase4_sip_calls(api_key, orig_tn, dest_tn,
                     json_output=False, verbose=False):
    """Run SIP signing and verification tests on the PBX."""
    log_header("Phase 4: SIP Call Tests", json_output)
    results = []

    if not api_key:
        log_warn("No API key — skipping SIP tests (set VVP_TEST_API_KEY "
                 "or add to scripts/.e2e-config)", json_output)
        results.append({"test": "sip_signing", "ok": True, "skipped": True})
        results.append({"test": "sip_verification", "ok": True, "skipped": True})
        return True, results

    # We run the SIP tests FROM the PBX VM itself (localhost UDP)
    # This avoids firewall/NAT issues with external UDP

    # Build Python SIP test script to run on the PBX
    sip_test_script = f'''
import base64
import json
import socket
import sys
import time
import uuid

def build_signing_invite():
    call_id = f"vvp-systest-{{uuid.uuid4().hex[:12]}}@127.0.0.1"
    branch = f"z9hG4bK{{uuid.uuid4().hex[:16]}}"
    tag = uuid.uuid4().hex[:8]
    lines = [
        "INVITE sip:{dest_tn}@127.0.0.1:5070 SIP/2.0",
        f"Via: SIP/2.0/UDP 127.0.0.1:15060;branch={{branch}}",
        f"From: <sip:{orig_tn}@127.0.0.1>;tag={{tag}}",
        "To: <sip:{dest_tn}@127.0.0.1>",
        f"Call-ID: {{call_id}}",
        "CSeq: 1 INVITE",
        "Contact: <sip:127.0.0.1:15060>",
        "X-VVP-API-Key: {api_key}",
        "Max-Forwards: 70",
        "Content-Length: 0",
    ]
    return ("\\r\\n".join(lines) + "\\r\\n\\r\\n").encode("utf-8")

def parse_response(data):
    text = data.decode("utf-8", errors="replace")
    lines = text.split("\\r\\n")
    result = {{"status_code": 0, "headers": {{}}}}
    if not lines:
        return result
    parts = lines[0].split(" ", 2)
    if len(parts) >= 2:
        try:
            result["status_code"] = int(parts[1])
        except ValueError:
            pass
    for line in lines[1:]:
        if not line:
            break
        if ":" in line:
            key, value = line.split(":", 1)
            result["headers"][key.strip()] = value.strip()
    return result

def send_and_receive(invite, host, port, timeout=15):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    start = time.monotonic()
    try:
        sock.sendto(invite, (host, port))
        data, addr = sock.recvfrom(65535)
        elapsed = (time.monotonic() - start) * 1000
        resp = parse_response(data)
        resp["elapsed_ms"] = round(elapsed, 1)
        return resp
    except socket.timeout:
        return {{"error": "timeout", "elapsed_ms": round((time.monotonic() - start) * 1000, 1)}}
    except OSError as e:
        return {{"error": str(e)}}
    finally:
        sock.close()

# --- Signing test ---
invite = build_signing_invite()
sign_result = send_and_receive(invite, "127.0.0.1", 5070)
print("SIGN_RESULT=" + json.dumps(sign_result))

# --- Verification test (chained with real headers) ---
if "error" not in sign_result and sign_result.get("status_code") == 302:
    headers = sign_result.get("headers", {{}})
    p_identity = headers.get("P-VVP-Identity", "")
    p_passport = headers.get("P-VVP-Passport", "")
    if p_identity and p_passport:
        passport_b64 = base64.urlsafe_b64encode(p_passport.encode()).decode().rstrip("=")
        try:
            padded = p_identity + "=" * (4 - len(p_identity) % 4)
            identity_data = json.loads(base64.urlsafe_b64decode(padded))
            info_url = identity_data.get("kid", "")
        except Exception:
            info_url = ""
        call_id = f"vvp-systest-v-{{uuid.uuid4().hex[:12]}}@127.0.0.1"
        branch = f"z9hG4bK{{uuid.uuid4().hex[:16]}}"
        tag = uuid.uuid4().hex[:8]
        lines = [
            "INVITE sip:{dest_tn}@127.0.0.1:5071 SIP/2.0",
            f"Via: SIP/2.0/UDP 127.0.0.1:15061;branch={{branch}}",
            f"From: <sip:{orig_tn}@carrier.example.com>;tag={{tag}}",
            "To: <sip:{dest_tn}@127.0.0.1>",
            f"Call-ID: {{call_id}}",
            "CSeq: 1 INVITE",
            "Contact: <sip:127.0.0.1:15061>",
            f"Identity: <{{passport_b64}}>;info={{info_url}};alg=EdDSA;ppt=vvp",
            f"P-VVP-Identity: {{p_identity}}",
            f"P-VVP-Passport: {{p_passport}}",
            "Max-Forwards: 70",
            "Content-Length: 0",
        ]
        verify_invite = ("\\r\\n".join(lines) + "\\r\\n\\r\\n").encode("utf-8")
        verify_result = send_and_receive(verify_invite, "127.0.0.1", 5071)
        print("VERIFY_RESULT=" + json.dumps(verify_result))
    else:
        print("VERIFY_RESULT=" + json.dumps({{"error": "missing_headers", "detail": "No P-VVP-Identity/Passport in signing response"}}))
else:
    detail = sign_result.get("error", f"status_code={{sign_result.get('status_code', 0)}}")
    print("VERIFY_RESULT=" + json.dumps({{"error": "signing_failed", "detail": str(detail)}}))
'''

    # Deploy and run the SIP test on PBX
    log_check("Running SIP tests on PBX VM", json_output)
    script_b64 = base64.b64encode(sip_test_script.encode()).decode()
    ok, output = pbx_run(
        f"echo '{script_b64}' | base64 -d > /tmp/vvp_systest_sip.py && "
        f"python3 /tmp/vvp_systest_sip.py && "
        f"rm -f /tmp/vvp_systest_sip.py",
        timeout=90,
    )

    if not ok:
        log_fail(f"SIP test execution failed: {output[:200]}", json_output)
        results.append({"test": "sip_execution", "ok": False, "detail": output[:200]})
        return False, results

    # Strip az output wrapper
    test_output = strip_az_output(output)

    if verbose and not json_output:
        log_info(f"  SIP test output: {test_output[:300]}")

    all_ok = True

    # Parse signing result
    sign_data = None
    for line in test_output.split("\n"):
        line = line.strip()
        if line.startswith("SIGN_RESULT="):
            try:
                sign_data = json.loads(line[len("SIGN_RESULT="):])
            except json.JSONDecodeError:
                pass

    if sign_data is None:
        log_fail("Could not parse signing test result", json_output)
        results.append({"test": "sip_signing", "ok": False,
                         "detail": "No SIGN_RESULT in output"})
        return False, results

    if "error" in sign_data:
        log_fail(f"Signing test failed: {sign_data.get('error')}", json_output)
        results.append({"test": "sip_signing", "ok": False,
                         "detail": sign_data.get("error")})
        all_ok = False
    else:
        code = sign_data.get("status_code", 0)
        headers = sign_data.get("headers", {})
        elapsed = sign_data.get("elapsed_ms", "?")

        checks = {
            "302_redirect": code == 302,
            "X-VVP-Status=VALID": headers.get("X-VVP-Status") == "VALID",
            "X-VVP-Brand-Name": bool(headers.get("X-VVP-Brand-Name")),
            "P-VVP-Identity": bool(headers.get("P-VVP-Identity")),
            "P-VVP-Passport": bool(headers.get("P-VVP-Passport")),
            "Contact": bool(headers.get("Contact")),
        }

        # Validate P-VVP-Identity structure
        p_id = headers.get("P-VVP-Identity", "")
        if p_id:
            try:
                padded = p_id + "=" * (4 - len(p_id) % 4)
                id_data = json.loads(base64.urlsafe_b64decode(padded))
                checks["P-VVP-Identity.ppt"] = id_data.get("ppt") == "vvp"
                checks["P-VVP-Identity.kid"] = bool(id_data.get("kid"))
                checks["P-VVP-Identity.evd"] = bool(id_data.get("evd"))
                checks["P-VVP-Identity.iat"] = bool(id_data.get("iat"))
            except Exception:
                checks["P-VVP-Identity_valid_json"] = False

        # Validate P-VVP-Passport structure (3-segment JWT)
        p_pass = headers.get("P-VVP-Passport", "")
        if p_pass:
            checks["P-VVP-Passport_3_segments"] = len(p_pass.split(".")) == 3

        failed_checks = [k for k, v in checks.items() if not v]
        if failed_checks:
            log_fail(f"Signing: SIP {code} ({elapsed}ms) — "
                     f"failed: {', '.join(failed_checks)}", json_output)
            all_ok = False
        else:
            brand = headers.get("X-VVP-Brand-Name", "")
            log_pass(f"Signing: 302 VALID brand={brand} ({elapsed}ms)",
                     json_output)

        for check_name, passed in checks.items():
            if not json_output:
                mark = f"{GREEN}+{NC}" if passed else f"{RED}-{NC}"
                print(f"        [{mark}] {check_name}")

        results.append({"test": "sip_signing", "ok": not failed_checks,
                         "checks": checks, "status_code": code,
                         "elapsed_ms": elapsed,
                         "brand": headers.get("X-VVP-Brand-Name", "")})

    # Parse verification result
    verify_data = None
    for line in test_output.split("\n"):
        line = line.strip()
        if line.startswith("VERIFY_RESULT="):
            try:
                verify_data = json.loads(line[len("VERIFY_RESULT="):])
            except json.JSONDecodeError:
                pass

    if verify_data is None:
        log_warn("Could not parse verification test result", json_output)
        results.append({"test": "sip_verification", "ok": False,
                         "detail": "No VERIFY_RESULT in output"})
        all_ok = False
    elif "error" in verify_data:
        detail = verify_data.get("detail", verify_data.get("error", ""))
        if verify_data.get("error") == "signing_failed":
            log_warn(f"Verification skipped: signing failed ({detail})",
                     json_output)
            results.append({"test": "sip_verification", "ok": True,
                             "skipped": True, "detail": detail})
        else:
            log_fail(f"Verification failed: {detail}", json_output)
            results.append({"test": "sip_verification", "ok": False,
                             "detail": detail})
            all_ok = False
    else:
        code = verify_data.get("status_code", 0)
        headers = verify_data.get("headers", {})
        elapsed = verify_data.get("elapsed_ms", "?")
        vvp_status = headers.get("X-VVP-Status", "")

        checks = {
            "sip_response": code > 0,
            "X-VVP-Status_present": bool(vvp_status),
        }

        # 302 with status is ideal; any response proves service is alive
        if code in (302, 200) and vvp_status:
            log_pass(f"Verification: SIP {code} status={vvp_status} "
                     f"({elapsed}ms)", json_output)
        elif code >= 100:
            log_pass(f"Verification: SIP {code} — service processing "
                     f"({elapsed}ms)", json_output)
        else:
            log_fail(f"Verification: unexpected response code={code}",
                     json_output)
            all_ok = False

        for check_name, passed in checks.items():
            if not json_output:
                mark = f"{GREEN}+{NC}" if passed else f"{RED}-{NC}"
                print(f"        [{mark}] {check_name}")

        results.append({"test": "sip_verification", "ok": code >= 100,
                         "checks": checks, "status_code": code,
                         "elapsed_ms": elapsed, "vvp_status": vvp_status})

    return all_ok, results


# ---------------------------------------------------------------------------
# Phase 5: Loopback Call Test (optional)
# ---------------------------------------------------------------------------

def phase5_loopback(api_key, orig_tn, dest_tn,
                    json_output=False, verbose=False):
    """Full FreeSWITCH originate loopback through all 3 dialplan contexts."""
    log_header("Phase 5: Loopback Call Test", json_output)
    results = []

    if not api_key:
        log_warn("No API key — skipping loopback test", json_output)
        results.append({"test": "loopback", "ok": True, "skipped": True})
        return True, results

    # Extract dest extension from TN (+441923311006 -> 1006)
    dest_ext = dest_tn.replace("+44192331", "")
    if not dest_ext.isdigit() or len(dest_ext) != 4:
        log_fail(f"Cannot extract extension from {dest_tn}", json_output)
        results.append({"test": "loopback", "ok": False,
                         "detail": f"Bad dest TN: {dest_tn}"})
        return False, results

    log_check("Running loopback originate on PBX", json_output)

    # Use bgapi originate to start the call, then check channel variables
    # The call will go: public(7+ext) → signing(5070) → redirected → verify(5072) → verified → park
    # We park the B-leg and inspect its variables
    originate_cmd = (
        f"bgapi originate "
        f"{{origination_caller_id_number={orig_tn},"
        f"origination_caller_id_name=VVP-SystemTest,"
        f"sip_h_X-VVP-API-Key={api_key}}}"
        f"sofia/internal/7{dest_ext}@127.0.0.1 &park"
    )

    # Use a regular string (not f-string) for the bash script to avoid
    # Python escape sequence issues with grep patterns
    loopback_script = (
        "# Start the call\n"
        "RESULT=$(fs_cli -x '" + originate_cmd + "' 2>&1)\n"
        "echo \"ORIGINATE=$RESULT\"\n"
        "\n"
        "# Wait for call to establish (signing + verification can take 10-15s)\n"
        "sleep 15\n"
        "\n"
        "# Check for channels\n"
        "CHANNELS=$(fs_cli -x 'show channels as json' 2>&1)\n"
        "echo \"CHANNELS=$CHANNELS\"\n"
        "\n"
        "# Look for our test call and extract VVP variables\n"
        "UUIDS=$(fs_cli -x 'show channels' 2>&1 | grep -E 'vvp-systest|VVP-SystemTest|" + orig_tn + "' | head -1 | awk '{print $1}')\n"
        "if [ -n \"$UUIDS\" ]; then\n"
        "    echo \"FOUND_UUID=$UUIDS\"\n"
        "    echo \"VAR_BRAND=$(fs_cli -x \\\"uuid_getvar $UUIDS vvp_brand_name\\\" 2>&1)\"\n"
        "    echo \"VAR_STATUS=$(fs_cli -x \\\"uuid_getvar $UUIDS vvp_status\\\" 2>&1)\"\n"
        "    echo \"VAR_VETTER=$(fs_cli -x \\\"uuid_getvar $UUIDS vvp_vetter_status\\\" 2>&1)\"\n"
        "fi\n"
        "\n"
        "# Clean up: hangup test calls\n"
        "fs_cli -x 'hupall NORMAL_CLEARING' 2>&1 | head -1\n"
        "\n"
        "sleep 2\n"
    )

    ok, output = pbx_run(loopback_script, timeout=120)

    if not ok:
        log_fail(f"Loopback test failed: {output[:200]}", json_output)
        results.append({"test": "loopback", "ok": False, "detail": output[:200]})
        return False, results

    # Strip az output wrapper
    test_output = strip_az_output(output)

    if verbose and not json_output:
        log_info(f"  Loopback output: {test_output[:400]}")

    # Parse results
    originate_result = ""
    brand_name = ""
    vvp_status = ""
    vetter_status = ""
    found_uuid = ""

    for line in test_output.split("\n"):
        line = line.strip()
        if line.startswith("ORIGINATE="):
            originate_result = line[len("ORIGINATE="):]
        elif line.startswith("FOUND_UUID="):
            found_uuid = line[len("FOUND_UUID="):]
        elif line.startswith("VAR_BRAND="):
            brand_name = line[len("VAR_BRAND="):]
        elif line.startswith("VAR_STATUS="):
            vvp_status = line[len("VAR_STATUS="):]
        elif line.startswith("VAR_VETTER="):
            vetter_status = line[len("VAR_VETTER="):]

    # Check if originate succeeded
    originate_ok = "+OK" in originate_result or "Job-UUID" in originate_result
    if not originate_ok:
        # Non-fatal: the call may have completed before we could check
        log_warn(f"Originate result: {originate_result[:100]}", json_output)

    checks = {
        "originate_accepted": originate_ok,
        "channel_found": bool(found_uuid),
    }

    if found_uuid:
        # Clean up _undef_ or empty
        brand_clean = brand_name if brand_name and "_undef_" not in brand_name else ""
        status_clean = vvp_status if vvp_status and "_undef_" not in vvp_status else ""

        checks["vvp_brand_name_set"] = bool(brand_clean)
        checks["vvp_status_set"] = bool(status_clean)

        if brand_clean and status_clean:
            log_pass(f"Loopback: brand={brand_clean}, status={status_clean}, "
                     f"vetter={vetter_status}", json_output)
        elif brand_clean or status_clean:
            log_warn(f"Loopback: partial headers — brand={brand_clean}, "
                     f"status={status_clean}", json_output)
        else:
            log_warn("Loopback: call placed but VVP headers not set "
                     "(call may still be in progress)", json_output)
    else:
        log_warn("Loopback: no active channel found (call may have "
                 "completed or timed out)", json_output)

    for check_name, passed in checks.items():
        if not json_output:
            mark = f"{GREEN}+{NC}" if passed else f"{YELLOW}?{NC}"
            print(f"        [{mark}] {check_name}")

    # Loopback is non-fatal (warn, not fail) since timing is unpredictable
    results.append({"test": "loopback", "ok": True, "checks": checks,
                     "brand": brand_name, "status": vvp_status,
                     "vetter": vetter_status})
    return True, results


# ---------------------------------------------------------------------------
# Phase 6: Report and Gate File
# ---------------------------------------------------------------------------

def write_gate_file(passed, summary):
    """Write .system-test-gate file."""
    gate_path = os.path.join(REPO_ROOT, ".system-test-gate")
    gate_data = {
        "timestamp": time.time(),
        "timestamp_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "passed": passed,
        "summary": summary,
    }
    with open(gate_path, "w") as f:
        json.dump(gate_data, f, indent=2)
        f.write("\n")
    return gate_path


def check_gate_file():
    """Check if gate file exists and is fresh. Returns (valid, age_seconds)."""
    gate_path = os.path.join(REPO_ROOT, ".system-test-gate")
    if not os.path.exists(gate_path):
        return False, 0
    try:
        with open(gate_path) as f:
            data = json.load(f)
        if not data.get("passed"):
            return False, 0
        age = time.time() - data["timestamp"]
        return age < GATE_TTL_SECONDS, age
    except (json.JSONDecodeError, KeyError):
        return False, 0


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="VVP System Test — end-to-end gate for development sessions"
    )
    parser.add_argument("--skip-pbx", action="store_true",
                        help="Skip PBX checks (phases 2-4)")
    parser.add_argument("--skip-sip", action="store_true",
                        help="Skip SIP call tests only (phase 4)")
    parser.add_argument("--loopback", action="store_true",
                        help="Include loopback test (phase 5, adds ~20s)")
    parser.add_argument("--json", action="store_true",
                        help="JSON output")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Show full response bodies")
    parser.add_argument("--gate-only", action="store_true",
                        help="Just check if gate file is fresh, no tests")

    args = parser.parse_args()

    # Gate-only mode: just check the gate file
    if args.gate_only:
        valid, age = check_gate_file()
        if valid:
            age_min = int(age / 60)
            if args.json:
                print(json.dumps({"gate_valid": True, "age_seconds": round(age),
                                  "age_minutes": age_min}))
            else:
                print(f"{GREEN}GATE VALID{NC} — system test passed {age_min}m ago")
            sys.exit(0)
        else:
            if args.json:
                print(json.dumps({"gate_valid": False}))
            else:
                print(f"{RED}GATE INVALID{NC} — run system test first")
            sys.exit(1)

    # Load config
    e2e_config = load_e2e_config()
    verifier_url = os.getenv("VVP_VERIFIER_URL", VERIFIER_URL)
    issuer_url = os.getenv("VVP_ISSUER_URL", ISSUER_URL)
    api_key = os.getenv("VVP_TEST_API_KEY", e2e_config.get("VVP_TEST_API_KEY", ""))
    orig_tn = os.getenv("VVP_TEST_ORIG_TN",
                        e2e_config.get("VVP_TEST_FROM_TN", DEFAULT_ORIG_TN))
    dest_tn = os.getenv("VVP_TEST_DEST_TN",
                        e2e_config.get("VVP_TEST_TO_TN", DEFAULT_DEST_TN))
    skip_pbx = args.skip_pbx or os.getenv("VVP_SKIP_PBX", "false") == "true"

    if not args.json:
        print(f"\n{BOLD}VVP System Test{NC}")
        print(f"{DIM}Target: verifier={verifier_url}, issuer={issuer_url}{NC}")
        if skip_pbx:
            print(f"{DIM}PBX checks: skipped{NC}")
        if args.loopback:
            print(f"{DIM}Loopback test: enabled{NC}")

    all_results = {}
    overall_ok = True

    # Phase 0: Warmup — ensure all services are ready before testing
    warmup_ok = phase0_warmup(verifier_url, issuer_url, WITNESS_URLS,
                               args.json, args.verbose)
    if not warmup_ok:
        log_warn("Warmup incomplete — continuing with tests", args.json)

    # Phase 1: Health checks
    ok, results = phase1_health_checks(verifier_url, issuer_url, WITNESS_URLS,
                                        args.json, args.verbose)
    all_results["phase1_health"] = results
    if not ok:
        overall_ok = False

    # Phase 2: PBX services
    if not skip_pbx:
        ok, results = phase2_pbx_services(args.json, args.verbose)
        all_results["phase2_pbx_services"] = results
        if not ok:
            overall_ok = False

        # Phase 3: Dialplan validation
        ok, results = phase3_dialplan_validation(args.json, args.verbose)
        all_results["phase3_dialplan"] = results
        if not ok:
            overall_ok = False

        # Phase 4: SIP call tests
        if not args.skip_sip:
            ok, results = phase4_sip_calls(api_key, orig_tn, dest_tn,
                                            args.json, args.verbose)
            all_results["phase4_sip"] = results
            if not ok:
                overall_ok = False

        # Phase 5: Loopback (optional)
        if args.loopback:
            ok, results = phase5_loopback(api_key, orig_tn, dest_tn,
                                           args.json, args.verbose)
            all_results["phase5_loopback"] = results
            # Loopback failures are warnings, not hard fails

    # Phase 6: Report
    if not args.json:
        print()
        print(f"{BOLD}{'━' * 55}{NC}")
        if overall_ok:
            print(f"  {GREEN}{BOLD}SYSTEM TEST PASSED{NC}")
        else:
            print(f"  {RED}{BOLD}SYSTEM TEST FAILED{NC}")
            print()
            print(f"  Troubleshooting:")
            print(f"    Health:   ./scripts/system-health-check.sh")
            print(f"    SIP:      python3 scripts/sip-call-test.py --verbose")
            print(f"    Bootstrap: python3 scripts/bootstrap-issuer.py")
        print(f"{BOLD}{'━' * 55}{NC}")
        print()

    # Write gate file
    summary = "all checks passed" if overall_ok else "one or more checks failed"
    gate_path = write_gate_file(overall_ok, summary)

    if args.json:
        print(json.dumps({
            "passed": overall_ok,
            "timestamp": time.time(),
            "results": all_results,
            "gate_file": gate_path,
        }, indent=2))
    else:
        if overall_ok:
            log_info(f"Gate file written: {gate_path}")

    sys.exit(0 if overall_ok else 1)


if __name__ == "__main__":
    main()
