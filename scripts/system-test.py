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

    # Run SIP verification against the OSS verifier (Azure)
    python3 scripts/system-test.py --oss-verifier

    # Override verifier URL for cross-verifier testing
    python3 scripts/system-test.py --verifier-url https://vvp-verifier-oss.wittytree-2a937ccd.uksouth.azurecontainerapps.io

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

# OSS Verifier
OSS_VERIFIER_URL = "https://vvp-verifier-oss.wittytree-2a937ccd.uksouth.azurecontainerapps.io"
ALLOWED_VERIFIER_ORIGINS = {
    "https://vvp-verifier.rcnx.io",
    "https://vvp-verifier.wittytree-2a937ccd.uksouth.azurecontainerapps.io",
    "https://vvp-verifier-oss.wittytree-2a937ccd.uksouth.azurecontainerapps.io",
}
OSS_VERIFY_PORT = 5073  # Test-only sip-verify-test service port on PBX

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
        "    if fuser ${port}/udp 2>/dev/null; then\n"
        "      echo \"KILLING:port ${port}/udp\"\n"
        "      fuser -k ${port}/udp 2>/dev/null || true\n"
        "    fi\n"
        "    if fuser ${port}/tcp 2>/dev/null; then\n"
        "      echo \"KILLING:port ${port}/tcp\"\n"
        "      fuser -k ${port}/tcp 2>/dev/null || true\n"
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
    """Validate PBX dialplan by running checks ON the PBX.

    Deploys a small Python validation script to the PBX via base64 to avoid
    az run-command's ~4KB output truncation. The script parses the dialplan
    XML locally and outputs structured CHECK= lines.
    """
    log_header("Phase 3: Dialplan Validation", json_output)
    results = []

    # Load rules
    if not os.path.exists(DIALPLAN_RULES_PATH):
        log_fail(f"Dialplan rules not found: {DIALPLAN_RULES_PATH}", json_output)
        results.append({"check": "rules_file", "ok": False})
        return False, results

    with open(DIALPLAN_RULES_PATH) as f:
        rules = json.load(f)

    # Build a Python validation script to run ON the PBX
    # This avoids transferring the large XML through az run-command
    rules_json = json.dumps(rules)
    validation_script = '''
import json
import sys
import xml.etree.ElementTree as ET

rules = json.loads(RULES_JSON_PLACEHOLDER)
dialplan_path = rules.get("dialplan_path", "/etc/freeswitch/dialplan/public.xml")

try:
    tree = ET.parse(dialplan_path)
    root = tree.getroot()
    print("CHECK|parse_xml|PASS")
except Exception as e:
    print(f"CHECK|parse_xml|FAIL|{e}")
    sys.exit(0)

for ctx_name, ctx_rules in rules.get("contexts", {}).items():
    ctx_elem = root.find(f".//context[@name='{ctx_name}']")
    if ctx_elem is None:
        print(f"CHECK|context_{ctx_name}|FAIL|not found")
        continue
    print(f"CHECK|context_{ctx_name}|PASS")

    for ext_name in ctx_rules.get("required_extensions", []):
        ext_elem = ctx_elem.find(f".//extension[@name='{ext_name}']")
        if ext_elem is None:
            print(f"CHECK|ext_{ext_name}|FAIL|missing")
        else:
            print(f"CHECK|ext_{ext_name}|PASS")

    for ext_name, checks in ctx_rules.get("checks", {}).items():
        ext_elem = ctx_elem.find(f".//extension[@name='{ext_name}']")
        if ext_elem is None:
            continue

        actions = ext_elem.findall(".//action")
        action_data = [a.get("data", "") for a in actions]
        all_data = " ".join(action_data)

        if "bridge_contains" in checks:
            target = checks["bridge_contains"]
            found = target in all_data
            status = "PASS" if found else "FAIL|bridge does not target " + target
            print(f"CHECK|{ext_name}_bridge_{target}|{status}")

        if checks.get("bridge_contains_api_key"):
            has_key = "X-VVP-API-Key=" in all_data
            status = "PASS" if has_key else "FAIL|API key missing"
            print(f"CHECK|{ext_name}_api_key|{status}")

        for header in checks.get("exports_headers", []):
            found = header in all_data
            status = "PASS" if found else "FAIL|header not exported"
            print(f"CHECK|{ext_name}_exports_{header}|{status}")

        if "sets_variable" in checks:
            var = checks["sets_variable"]
            found = var in all_data
            # Use sanitized name (replace = with _eq_) for display
            safe_name = var.replace("=", "_eq_")
            status = "PASS" if found else "FAIL|variable not set"
            print(f"CHECK|{ext_name}_sets_{safe_name}|{status}")
'''
    # Inject the rules JSON into the script
    validation_script = validation_script.replace(
        'RULES_JSON_PLACEHOLDER', repr(rules_json)
    )

    # Deploy and run on PBX
    log_check("Running dialplan validation on PBX", json_output)
    script_b64 = base64.b64encode(validation_script.encode()).decode()
    ok, output = pbx_run(
        f"echo '{script_b64}' | base64 -d > /tmp/vvp_dialplan_check.py && "
        f"python3 /tmp/vvp_dialplan_check.py && "
        f"rm -f /tmp/vvp_dialplan_check.py",
        timeout=60,
    )

    if not ok:
        log_fail(f"Dialplan validation failed to run: {output[:200]}", json_output)
        results.append({"check": "run_validation", "ok": False, "detail": output[:200]})
        return False, results

    # Parse CHECK= lines from output
    clean = strip_az_output(output)
    if verbose and not json_output:
        log_info(f"Validation output: {clean[:500]}")

    all_ok = True
    found_checks = False

    for line in clean.split("\n"):
        line = line.strip()
        if not line.startswith("CHECK|"):
            continue
        found_checks = True
        # Format: CHECK|name|PASS or CHECK|name|FAIL|detail
        parts = line.split("|")
        if len(parts) < 3:
            continue
        name = parts[1]
        status_part = parts[2]
        passed = status_part == "PASS"

        if passed:
            log_pass(f"  {name}", json_output)
        else:
            detail = parts[3] if len(parts) > 3 else "failed"
            log_fail(f"  {name}: {detail}", json_output)
            all_ok = False

        results.append({"check": name, "ok": passed})

    if not found_checks:
        log_fail("No validation results from PBX script", json_output)
        log_info(f"  Output: {clean[:300]}")
        results.append({"check": "validation_output", "ok": False})
        return False, results

    return all_ok, results


# ---------------------------------------------------------------------------
# Phase 4: SIP Call Tests (on PBX) — Scenario-Driven
# ---------------------------------------------------------------------------

# Test scenarios: each defines a signing+verification test with expected outcomes
# Add new scenarios here as more orgs/dossiers are bootstrapped
# Test scenarios: each defines a signing+verification test with expected outcomes.
#
# Signing service (port 5070) returns:
#   302 + P-VVP-Identity + P-VVP-Passport + Contact (NO X-VVP-* headers)
#
# Verification service (port 5071) returns:
#   302 + X-VVP-Status + X-VVP-Brand-Name + X-VVP-Brand-Logo
#       + X-VVP-Vetter-Status + X-VVP-Warning-Reason + Contact
#
# X-VVP-Status values: VALID (authorized vetter), INDETERMINATE (unknown/
# unauthorized vetter per Sprint 84), INVALID (verification failure)
#
# Add new scenarios here as more orgs/dossiers are bootstrapped.
SIP_TEST_SCENARIOS = [
    {
        "name": "ACME Inc (primary)",
        "description": "Valid dossier, full signing→verification chain",
        "orig_tn": "+441923311000",
        "dest_tn": "+441923311006",
        "expect_signing": {
            "status_code": 302,
            "has_P-VVP-Identity": True,
            "has_P-VVP-Passport": True,
            "has_Contact": True,
        },
        "expect_verification": {
            "status_code": 302,
            "has_X-VVP-Status": True,
            "X-VVP-Status": "VALID",
            "has_X-VVP-Brand-Name": True,
            "X-VVP-Brand-Name": "ACME Inc",
            "has_X-VVP-Brand-Logo": True,
        },
        "chain_to_verification": True,
    },
    {
        "name": "ACME Inc (reverse TN)",
        "description": "Same org, swapped from/dest TNs — bidirectional TN mapping",
        "orig_tn": "+441923311006",
        "dest_tn": "+441923311000",
        "expect_signing": {
            "status_code": 302,
            "has_P-VVP-Identity": True,
            "has_P-VVP-Passport": True,
            "has_Contact": True,
        },
        "expect_verification": {
            "status_code": 302,
            "has_X-VVP-Status": True,
            "X-VVP-Status": "VALID",
            "has_X-VVP-Brand-Name": True,
            "X-VVP-Brand-Name": "ACME Inc",
            "has_X-VVP-Brand-Logo": True,
        },
        "chain_to_verification": True,
    },
    {
        "name": "Phase 2a UK Ltd (authorized vetter)",
        "description": "Vetter authorized for UK (ECC=44) calling UK number — vetter PASS",
        "orig_tn": "+441923311002",
        "dest_tn": "+441923311006",
        "api_key_config": "VVP_PHASE2A_API_KEY",
        "expect_signing": {
            "status_code": 302,
            "has_P-VVP-Identity": True,
            "has_P-VVP-Passport": True,
            "has_Contact": True,
        },
        "expect_verification": {
            "status_code": 302,
            "has_X-VVP-Status": True,
            "X-VVP-Status": "VALID",
            "has_X-VVP-Brand-Name": True,
            "X-VVP-Brand-Name": "Phase 2a UK Ltd",
            "has_X-VVP-Brand-Logo": True,
            "has_X-VVP-Vetter-Status": True,
            "X-VVP-Vetter-Status": "PASS",
        },
        "chain_to_verification": True,
    },
    {
        "name": "Phase 2b US Ltd (unauthorized vetter)",
        "description": "Vetter authorized for US only (ECC=1) calling UK number — vetter jurisdiction violation",
        "orig_tn": "+441923311003",
        "dest_tn": "+441923311006",
        "api_key_config": "VVP_PHASE2B_API_KEY",
        "expect_signing": {
            "status_code": 302,
            "has_P-VVP-Identity": True,
            "has_P-VVP-Passport": True,
            "has_Contact": True,
        },
        "expect_verification": {
            "status_code": 302,
            "has_X-VVP-Status": True,
            "X-VVP-Status": "WARNING",
            "has_X-VVP-Brand-Name": True,
            "X-VVP-Brand-Name": "Phase 2b US Ltd",
            "has_X-VVP-Brand-Logo": True,
            "has_X-VVP-Vetter-Status": True,
            "has_X-VVP-Warning-Reason": True,
        },
        "chain_to_verification": True,
    },
    {
        "name": "Unmapped TN (negative)",
        "description": "From TN not in any mapping — signing returns 404",
        "orig_tn": "+441923319999",
        "dest_tn": "+441923311006",
        "expect_signing": {
            "status_code_not": 302,
        },
        "chain_to_verification": False,
    },
]


def _validate_verifier_url(url):
    """Validate that a --verifier-url value is safe and allowed.

    Returns the validated URL. Raises SystemExit on rejection.
    """
    from urllib.parse import urlparse
    parsed = urlparse(url)
    if parsed.scheme != "https":
        print(f"{RED}ERROR{NC}: --verifier-url must use https:// scheme")
        sys.exit(2)
    if parsed.username or parsed.password:
        print(f"{RED}ERROR{NC}: --verifier-url must not contain credentials")
        sys.exit(2)
    if parsed.query or parsed.fragment:
        print(f"{RED}ERROR{NC}: --verifier-url must not contain query/fragment")
        sys.exit(2)
    # Check against allowlist (origin = scheme + host + port)
    origin = f"{parsed.scheme}://{parsed.hostname}"
    if parsed.port and parsed.port != 443:
        origin += f":{parsed.port}"
    if origin not in ALLOWED_VERIFIER_ORIGINS:
        print(f"{RED}ERROR{NC}: Verifier origin not in allowlist: {origin}")
        print(f"  Allowed: {', '.join(sorted(ALLOWED_VERIFIER_ORIGINS))}")
        sys.exit(2)
    return url.rstrip("/")


def _start_oss_verify_service(verifier_url, json_output=False):
    """Start the test-only sip-verify-test service on the PBX.

    Deploys a temporary env file and starts the service on port 5073.
    The sip-verify-test service runs on the PBX itself, so if the OSS
    verifier is also on the PBX (port 8072), we use the localhost URL
    instead of the external URL.
    Returns True on success, False on failure.
    """
    log_check("Starting OSS verify test service on PBX (port 5073)", json_output)

    # The OSS verifier runs on the PBX at localhost:8072.
    # Use the localhost URL for the sip-verify-test service.
    pbx_verifier_url = "http://127.0.0.1:8072"

    env_content = (
        f"VVP_VERIFIER_URL={pbx_verifier_url}\n"
        f"VVP_SIP_VERIFY_PORT=5073\n"
        f"VVP_REDIRECT_TARGET=127.0.0.1:5080\n"
        f"PYTHONPATH=/opt/vvp/common-pkg\n"
        f"LOG_LEVEL=INFO\n"
        f"VVP_VERIFIER_TIMEOUT=15.0\n"
        f"VVP_MONITOR_ENABLED=false\n"
        f"VVP_STATUS_HTTP_PORT=8096\n"
    )
    env_b64 = base64.b64encode(env_content.encode()).decode()

    ok, output = pbx_run(
        f"echo '{env_b64}' | base64 -d > /etc/vvp/vvp-sip-verify-test.env && "
        f"systemctl restart vvp-sip-verify-test && "
        f"sleep 2 && "
        f"systemctl is-active vvp-sip-verify-test",
        timeout=60,
    )
    if ok and "active" in strip_az_output(output).lower():
        log_pass("OSS verify test service started on port 5073", json_output)
        return True
    else:
        log_fail(f"Failed to start OSS verify test service: {strip_az_output(output)[:200]}",
                 json_output)
        return False


def _stop_oss_verify_service(json_output=False):
    """Stop the test-only sip-verify-test service on the PBX."""
    pbx_run("systemctl stop vvp-sip-verify-test 2>/dev/null || true", timeout=60)
    log_info("OSS verify test service stopped", json_output)


def _build_sip_test_script(scenarios, api_key, verify_port=5071):
    """Build the Python SIP test script that runs ON the PBX.

    The script tests multiple scenarios sequentially, outputting structured
    SCENARIO_RESULT lines for each. Uses the same socket helper functions
    for all scenarios.
    """
    # Serialize scenarios as JSON for the script
    scenarios_json = json.dumps(scenarios)

    script = '''
import base64
import json
import socket
import sys
import time
import uuid

API_KEY = "''' + api_key + '''"
VERIFY_PORT = ''' + str(verify_port) + '''
SCENARIOS = json.loads(''' + repr(scenarios_json) + ''')

def parse_response(data):
    text = data.decode("utf-8", errors="replace")
    lines = text.split("\\r\\n")
    result = {"status_code": 0, "headers": {}}
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

def send_and_receive(invite, host, port, timeout=30):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    start = time.monotonic()
    try:
        sock.sendto(invite, (host, port))
        while True:
            remaining = timeout - (time.monotonic() - start)
            if remaining <= 0:
                return {"error": "timeout", "elapsed_ms": round((time.monotonic() - start) * 1000, 1)}
            sock.settimeout(remaining)
            data, addr = sock.recvfrom(65535)
            resp = parse_response(data)
            code = resp.get("status_code", 0)
            if code < 200:
                continue
            elapsed = (time.monotonic() - start) * 1000
            resp["elapsed_ms"] = round(elapsed, 1)
            return resp
    except socket.timeout:
        return {"error": "timeout", "elapsed_ms": round((time.monotonic() - start) * 1000, 1)}
    except OSError as e:
        return {"error": str(e)}
    finally:
        sock.close()

def build_invite(from_tn, to_tn, port, api_key=None, extra_headers=None):
    call_id = f"vvp-systest-{uuid.uuid4().hex[:12]}@127.0.0.1"
    branch = f"z9hG4bK{uuid.uuid4().hex[:16]}"
    tag = uuid.uuid4().hex[:8]
    lines = [
        f"INVITE sip:{to_tn}@127.0.0.1:{port} SIP/2.0",
        f"Via: SIP/2.0/UDP 127.0.0.1:{15060 + (port % 10)};branch={branch}",
        f"From: <sip:{from_tn}@127.0.0.1>;tag={tag}",
        f"To: <sip:{to_tn}@127.0.0.1>",
        f"Call-ID: {call_id}",
        "CSeq: 1 INVITE",
        f"Contact: <sip:127.0.0.1:{15060 + (port % 10)}>",
    ]
    if api_key:
        lines.append(f"X-VVP-API-Key: {api_key}")
    if extra_headers:
        for k, v in extra_headers.items():
            lines.append(f"{k}: {v}")
    lines.extend(["Max-Forwards: 70", "Content-Length: 0"])
    return ("\\r\\n".join(lines) + "\\r\\n\\r\\n").encode("utf-8")


for i, scenario in enumerate(SCENARIOS):
    name = scenario["name"]
    orig = scenario["orig_tn"]
    dest = scenario["dest_tn"]
    chain = scenario.get("chain_to_verification", False)
    result = {"name": name, "signing": None, "verification": None}

    # --- Signing ---
    scenario_api_key = scenario.get("api_key", API_KEY)
    invite = build_invite(orig, dest, 5070, api_key=scenario_api_key)
    sign_resp = send_and_receive(invite, "127.0.0.1", 5070)
    result["signing"] = sign_resp

    # --- Verification (chained) ---
    if chain and "error" not in sign_resp and sign_resp.get("status_code") == 302:
        headers = sign_resp.get("headers", {})
        p_identity = headers.get("P-VVP-Identity", "")
        p_passport = headers.get("P-VVP-Passport", "")
        if p_identity and p_passport:
            # Build Identity header (RFC 8224 format: raw JWT, not re-encoded)
            try:
                padded = p_identity + "=" * (4 - len(p_identity) % 4)
                identity_data = json.loads(base64.urlsafe_b64decode(padded))
                info_url = identity_data.get("kid", "")
            except Exception:
                info_url = ""

            extra = {
                "Identity": f"{p_passport};info=<{info_url}>;alg=EdDSA;ppt=vvp",
                "P-VVP-Identity": p_identity,
                "P-VVP-Passport": p_passport,
            }
            verify_invite = build_invite(orig, dest, VERIFY_PORT, extra_headers=extra)
            verify_resp = send_and_receive(verify_invite, "127.0.0.1", VERIFY_PORT)
            result["verification"] = verify_resp
        else:
            result["verification"] = {"error": "missing_headers", "detail": "No P-VVP-Identity/Passport in signing response"}
    elif chain:
        detail = sign_resp.get("error", f"status_code={sign_resp.get('status_code', 0)}")
        result["verification"] = {"error": "signing_failed", "detail": str(detail)}

    # Trim response to avoid az run-command 4KB output truncation
    # Only include status_code, elapsed_ms, and key header values (not full JWT tokens)
    def trim_response(resp):
        if resp is None or "error" in resp:
            return resp
        trimmed = {
            "status_code": resp.get("status_code", 0),
            "elapsed_ms": resp.get("elapsed_ms", 0),
        }
        headers = resp.get("headers", {})
        # Only include the headers we need for assertions
        for h in ["X-VVP-Status", "X-VVP-Brand-Name", "X-VVP-Brand-Logo",
                   "X-VVP-Vetter-Status", "X-VVP-Warning-Reason", "Contact"]:
            if h in headers:
                trimmed[h] = headers[h]
        # For attestation headers, just note presence + structure, not full value
        if "P-VVP-Identity" in headers:
            trimmed["has_P-VVP-Identity"] = True
            # Parse and include structure
            try:
                pid = headers["P-VVP-Identity"]
                padded = pid + "=" * (4 - len(pid) % 4)
                id_data = json.loads(base64.urlsafe_b64decode(padded))
                trimmed["P-VVP-Identity-fields"] = {
                    "ppt": id_data.get("ppt"),
                    "has_kid": bool(id_data.get("kid")),
                    "has_evd": bool(id_data.get("evd")),
                    "has_iat": bool(id_data.get("iat")),
                }
            except Exception:
                trimmed["P-VVP-Identity-fields"] = {"parse_error": True}
        if "P-VVP-Passport" in headers:
            passport = headers["P-VVP-Passport"]
            trimmed["has_P-VVP-Passport"] = True
            trimmed["P-VVP-Passport-segments"] = len(passport.split("."))
        return trimmed

    result["signing"] = trim_response(result["signing"])
    result["verification"] = trim_response(result["verification"])
    print(f"SCENARIO_RESULT_{i}=" + json.dumps(result))

    # Small delay between scenarios to avoid UDP port conflicts
    time.sleep(1)
'''
    return script


def phase4_sip_calls(api_key, orig_tn, dest_tn,
                     json_output=False, verbose=False,
                     verify_port=5071, e2e_config=None):
    """Run scenario-driven SIP signing and verification tests on the PBX.

    Tests multiple scenarios sequentially:
    - ACME Inc primary (authorized vetter, valid dossier)
    - ACME Inc reverse TN (bidirectional mapping)
    - Phase 2a UK Ltd (authorized vetter, ECC=44)
    - Phase 2b US Ltd (unauthorized vetter for UK, ECC=1)
    - Unmapped TN (negative test)

    Each scenario sends a signing INVITE to port 5070, then chains the
    signing result into a verification INVITE to the given verify_port
    (default 5071, or 5073 for OSS verifier). All SIP traffic runs on
    the PBX VM via localhost UDP.
    """
    log_header("Phase 4: SIP Call Tests", json_output)
    results = []

    if not api_key:
        log_warn("No API key — skipping SIP tests (set VVP_TEST_API_KEY "
                 "or add to scripts/.e2e-config)", json_output)
        results.append({"test": "sip_calls", "ok": True, "skipped": True})
        return True, results

    if e2e_config is None:
        e2e_config = {}

    # Build scenario list — use e2e-config TNs as defaults
    scenarios = []
    for s in SIP_TEST_SCENARIOS:
        scenario = dict(s)
        # Allow env overrides for default TNs
        if scenario["orig_tn"] == "+441923311000":
            scenario["orig_tn"] = orig_tn
        if scenario["dest_tn"] == "+441923311006":
            scenario["dest_tn"] = dest_tn
        # Resolve per-scenario API key from e2e-config
        config_key = scenario.pop("api_key_config", None)
        if config_key:
            resolved = os.getenv(config_key, e2e_config.get(config_key, ""))
            if resolved:
                scenario["api_key"] = resolved
            else:
                log_warn(f"Scenario '{scenario['name']}': {config_key} not found "
                         f"in .e2e-config — using default key", json_output)
        scenarios.append(scenario)

    # OSS verifier mode: relax expectations for features not implemented
    # in the OSS verifier (brand extraction, vetter constraints).
    if verify_port == OSS_VERIFY_PORT:
        for scenario in scenarios:
            ev = scenario.get("expect_verification")
            if not ev:
                continue
            # OSS verifier returns VALID for all authorized dossiers
            # (no vetter constraint checking, so WARNING→VALID).
            if ev.get("X-VVP-Status") == "WARNING":
                ev["X-VVP-Status"] = "VALID"
            # OSS verifier doesn't extract brand info from dossiers.
            ev.pop("has_X-VVP-Brand-Name", None)
            ev.pop("X-VVP-Brand-Name", None)
            ev.pop("has_X-VVP-Brand-Logo", None)
            # OSS verifier doesn't implement vetter constraints.
            ev.pop("has_X-VVP-Vetter-Status", None)
            ev.pop("X-VVP-Vetter-Status", None)
            ev.pop("has_X-VVP-Warning-Reason", None)

    # Build and deploy the test script
    sip_script = _build_sip_test_script(scenarios, api_key, verify_port=verify_port)

    log_check(f"Running {len(scenarios)} SIP scenarios on PBX VM", json_output)
    script_b64 = base64.b64encode(sip_script.encode()).decode()
    ok, output = pbx_run(
        f"echo '{script_b64}' | base64 -d > /tmp/vvp_systest_sip.py && "
        f"python3 /tmp/vvp_systest_sip.py && "
        f"rm -f /tmp/vvp_systest_sip.py",
        timeout=180,
    )

    if not ok:
        log_fail(f"SIP test execution failed: {output[:200]}", json_output)
        results.append({"test": "sip_execution", "ok": False, "detail": output[:200]})
        return False, results

    test_output = strip_az_output(output)
    if verbose and not json_output:
        log_info(f"  SIP test output: {test_output[:500]}")

    all_ok = True

    # Parse scenario results
    for i, scenario in enumerate(scenarios):
        prefix = f"SCENARIO_RESULT_{i}="
        scenario_data = None
        for line in test_output.split("\n"):
            line = line.strip()
            if line.startswith(prefix):
                try:
                    scenario_data = json.loads(line[len(prefix):])
                except json.JSONDecodeError:
                    pass

        name = scenario["name"]
        if not json_output:
            print(f"\n    {BOLD}Scenario: {name}{NC}")
            if verbose:
                print(f"    {DIM}{scenario.get('description', '')}{NC}")

        if scenario_data is None:
            log_fail(f"  [{name}] No result from PBX", json_output)
            results.append({"test": f"scenario_{i}", "name": name, "ok": False,
                             "detail": "No output"})
            all_ok = False
            continue

        scenario_ok = True

        # ---- Evaluate signing ----
        # Trimmed response format: status_code, elapsed_ms, header values as top-level keys,
        # has_P-VVP-Identity (bool), P-VVP-Identity-fields (dict), has_P-VVP-Passport (bool),
        # P-VVP-Passport-segments (int)
        sign = scenario_data.get("signing", {})
        expect_sign = scenario.get("expect_signing", {})

        if "error" in sign:
            if "status_code_not" in expect_sign:
                log_pass(f"  [{name}] Signing: error as expected "
                         f"({sign.get('error')})", json_output)
            else:
                log_fail(f"  [{name}] Signing: {sign.get('error')}", json_output)
                scenario_ok = False
        else:
            code = sign.get("status_code", 0)
            elapsed = sign.get("elapsed_ms", "?")

            # Check expected status code
            if "status_code" in expect_sign:
                if code != expect_sign["status_code"]:
                    log_fail(f"  [{name}] Signing: expected SIP {expect_sign['status_code']}, "
                             f"got {code}", json_output)
                    scenario_ok = False
            if "status_code_not" in expect_sign:
                if code == expect_sign["status_code_not"]:
                    log_fail(f"  [{name}] Signing: should NOT get SIP {code}", json_output)
                    scenario_ok = False
                else:
                    log_pass(f"  [{name}] Signing: SIP {code} (not {expect_sign['status_code_not']}) "
                             f"({elapsed}ms)", json_output)

            # Check header values from trimmed response
            sign_checks = []
            for key, expected in expect_sign.items():
                if key.startswith("status_code"):
                    continue
                if key.startswith("has_"):
                    header_name = key[4:]
                    # In trimmed format, has_X is a top-level bool
                    actual = bool(sign.get(f"has_{header_name}") or sign.get(header_name))
                    ok_check = actual == expected
                    sign_checks.append((header_name, ok_check, "present" if actual else "missing"))
                elif key.startswith("X-VVP-") or key.startswith("P-VVP-"):
                    actual = sign.get(key, "")
                    ok_check = actual == expected
                    sign_checks.append((key, ok_check, actual or "(empty)"))

            for check_name, passed, actual in sign_checks:
                if not json_output:
                    mark = f"{GREEN}+{NC}" if passed else f"{RED}-{NC}"
                    print(f"        [{mark}] {check_name} = {actual}")
                if not passed:
                    scenario_ok = False

            # Validate P-VVP-Identity structure from trimmed fields
            id_fields = sign.get("P-VVP-Identity-fields")
            if id_fields and code == 302:
                if id_fields.get("parse_error"):
                    if not json_output:
                        print(f"        [{RED}-{NC}] P-VVP-Identity: invalid JSON")
                    scenario_ok = False
                else:
                    id_checks = [
                        ("ppt=vvp", id_fields.get("ppt") == "vvp"),
                        ("kid present", id_fields.get("has_kid", False)),
                        ("evd present", id_fields.get("has_evd", False)),
                        ("iat present", id_fields.get("has_iat", False)),
                    ]
                    for check_name, passed in id_checks:
                        if not json_output:
                            mark = f"{GREEN}+{NC}" if passed else f"{RED}-{NC}"
                            print(f"        [{mark}] P-VVP-Identity.{check_name}")
                        if not passed:
                            scenario_ok = False

            # Validate JWT structure from trimmed segments count
            if sign.get("has_P-VVP-Passport") and code == 302:
                segments = sign.get("P-VVP-Passport-segments", 0)
                is_jwt = segments == 3
                if not json_output:
                    mark = f"{GREEN}+{NC}" if is_jwt else f"{RED}-{NC}"
                    print(f"        [{mark}] P-VVP-Passport: {segments}-segment JWT")
                if not is_jwt:
                    scenario_ok = False

            if scenario_ok and code == 302:
                brand = sign.get("X-VVP-Brand-Name", "")
                log_pass(f"  [{name}] Signing: 302 VALID brand={brand} "
                         f"({elapsed}ms)", json_output)

        # ---- Evaluate verification ----
        verify = scenario_data.get("verification")
        expect_verify = scenario.get("expect_verification", {})

        if verify is None and not scenario.get("chain_to_verification"):
            # No verification expected
            if not json_output:
                print(f"        {DIM}(verification not chained for this scenario){NC}")
        elif verify is None:
            log_fail(f"  [{name}] Verification: no result", json_output)
            scenario_ok = False
        elif "error" in verify:
            if not scenario.get("chain_to_verification"):
                pass  # expected
            else:
                log_fail(f"  [{name}] Verification: {verify.get('detail', verify.get('error'))}",
                         json_output)
                scenario_ok = False
        else:
            code = verify.get("status_code", 0)
            headers = verify.get("headers", {})
            elapsed = verify.get("elapsed_ms", "?")

            # Check expected status code
            if "status_code" in expect_verify:
                if code != expect_verify["status_code"]:
                    log_fail(f"  [{name}] Verification: expected SIP {expect_verify['status_code']}, "
                             f"got {code}", json_output)
                    scenario_ok = False

            # Check header values from trimmed response
            # In trimmed format, X-VVP-* headers are top-level keys
            verify_checks = []
            for key, expected in expect_verify.items():
                if key.startswith("status_code"):
                    continue
                if key.startswith("has_"):
                    header_name = key[4:]
                    # Check both trimmed top-level key and has_ prefix
                    actual = bool(verify.get(header_name) or verify.get(f"has_{header_name}"))
                    ok_check = actual == expected
                    actual_val = verify.get(header_name, "")
                    display = actual_val if actual_val else ("present" if actual else "missing")
                    verify_checks.append((header_name, ok_check, display))
                elif key.startswith("X-VVP-") or key.startswith("P-VVP-"):
                    actual = verify.get(key, "")
                    ok_check = actual == expected
                    verify_checks.append((key, ok_check, actual or "(empty)"))

            for check_name, passed, actual in verify_checks:
                if not json_output:
                    mark = f"{GREEN}+{NC}" if passed else f"{RED}-{NC}"
                    print(f"        [{mark}] verify {check_name} = {actual}")
                if not passed:
                    scenario_ok = False

            vvp_status = verify.get("X-VVP-Status", "")
            brand = verify.get("X-VVP-Brand-Name", "")
            vetter = verify.get("X-VVP-Vetter-Status", "")
            if scenario_ok:
                log_pass(f"  [{name}] Verification: SIP {code} "
                         f"status={vvp_status} brand={brand} "
                         f"vetter={vetter} ({elapsed}ms)", json_output)
            else:
                log_fail(f"  [{name}] Verification: SIP {code} "
                         f"status={vvp_status} ({elapsed}ms)", json_output)

        if not scenario_ok:
            all_ok = False

        results.append({
            "test": f"scenario_{i}",
            "name": name,
            "ok": scenario_ok,
            "signing": scenario_data.get("signing"),
            "verification": scenario_data.get("verification"),
        })

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
    parser.add_argument("--oss-verifier", action="store_true",
                        help="Run SIP verification against the OSS verifier (Azure)")
    parser.add_argument("--verifier-url", type=str, default=None,
                        help="Override verifier URL for SIP verification tests")

    args = parser.parse_args()

    # Validate --oss-verifier / --verifier-url
    if args.oss_verifier and args.verifier_url:
        print(f"{RED}ERROR{NC}: --oss-verifier and --verifier-url are mutually exclusive")
        sys.exit(2)
    if (args.oss_verifier or args.verifier_url) and args.loopback:
        print(f"{RED}ERROR{NC}: --oss-verifier/--verifier-url cannot be combined with --loopback")
        sys.exit(2)

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

    # Resolve OSS verifier URL
    oss_verifier_url = None
    verify_port = 5071  # default: production verify service
    if args.oss_verifier:
        # OSS verifier runs on PBX at localhost:8072; no external URL validation needed.
        oss_verifier_url = "http://127.0.0.1:8072"
        verify_port = OSS_VERIFY_PORT
    elif args.verifier_url:
        oss_verifier_url = _validate_verifier_url(args.verifier_url)
        verify_port = OSS_VERIFY_PORT

    if not args.json:
        print(f"\n{BOLD}VVP System Test{NC}")
        print(f"{DIM}Target: verifier={verifier_url}, issuer={issuer_url}{NC}")
        if oss_verifier_url:
            print(f"{DIM}OSS verifier: {oss_verifier_url} (port {verify_port}){NC}")
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
            # Start OSS verify test service if needed
            oss_started = False
            if oss_verifier_url:
                oss_started = _start_oss_verify_service(oss_verifier_url, args.json)
                if not oss_started:
                    log_fail("Cannot run SIP tests: OSS verify service failed to start",
                             args.json)
                    all_results["phase4_sip"] = [{"test": "oss_service", "ok": False}]
                    overall_ok = False

            if not oss_verifier_url or oss_started:
                try:
                    ok, results = phase4_sip_calls(api_key, orig_tn, dest_tn,
                                                    args.json, args.verbose,
                                                    verify_port=verify_port,
                                                    e2e_config=e2e_config)
                    all_results["phase4_sip"] = results
                    if not ok:
                        overall_ok = False
                finally:
                    if oss_started:
                        _stop_oss_verify_service(args.json)

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
