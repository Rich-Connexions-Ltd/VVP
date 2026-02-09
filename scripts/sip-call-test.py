#!/usr/bin/env python3
"""VVP SIP Call Test — sends real SIP INVITEs to test signing and verification.

Sends UDP SIP INVITE messages to the SIP Redirect and SIP Verify services,
parses responses, and reports whether the full call chain is functioning.

This script uses only stdlib and can run on any Python 3.8+ system.

Usage:
    # Test signing flow (SIP Redirect → Issuer API)
    python3 scripts/sip-call-test.py --test sign --host 127.0.0.1 --port 5070

    # Test verification flow (SIP Verify → Verifier API)
    python3 scripts/sip-call-test.py --test verify --host 127.0.0.1 --port 5071

    # Test both (default)
    python3 scripts/sip-call-test.py --test all

    # Timing mode — measure cache effectiveness
    python3 scripts/sip-call-test.py --test sign --timing --timing-count 3
    python3 scripts/sip-call-test.py --test chain --timing --timing-count 3

    # JSON output
    python3 scripts/sip-call-test.py --json

Environment:
    VVP_SIP_REDIRECT_HOST   SIP Redirect host (default: 127.0.0.1)
    VVP_SIP_REDIRECT_PORT   SIP Redirect port (default: 5070)
    VVP_SIP_VERIFY_HOST     SIP Verify host (default: 127.0.0.1)
    VVP_SIP_VERIFY_PORT     SIP Verify port (default: 5071)
    VVP_TEST_API_KEY        API key for signing test
    VVP_TEST_ORIG_TN        Originating TN (default: +441923311001)
    VVP_TEST_DEST_TN        Destination TN (default: +441923311006)
    VVP_VERIFIER_URL        Verifier URL for cache metrics (default: https://vvp-verifier.rcnx.io)
"""

import argparse
import base64
import json
import os
import socket
import sys
import time
import urllib.request
import uuid


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

REDIRECT_HOST = os.getenv("VVP_SIP_REDIRECT_HOST", "127.0.0.1")
REDIRECT_PORT = int(os.getenv("VVP_SIP_REDIRECT_PORT", "5070"))
VERIFY_HOST = os.getenv("VVP_SIP_VERIFY_HOST", "127.0.0.1")
VERIFY_PORT = int(os.getenv("VVP_SIP_VERIFY_PORT", "5071"))
API_KEY = os.getenv("VVP_TEST_API_KEY", "")
ORIG_TN = os.getenv("VVP_TEST_ORIG_TN", "+441923311001")
DEST_TN = os.getenv("VVP_TEST_DEST_TN", "+441923311006")
RECV_TIMEOUT = float(os.getenv("VVP_SIP_TIMEOUT", "15"))
VERIFIER_URL = os.getenv("VVP_VERIFIER_URL", "https://vvp-verifier.rcnx.io")

MAX_TIMING_COUNT = 20
MIN_TIMING_DELAY = 0.1


# ---------------------------------------------------------------------------
# SIP message construction
# ---------------------------------------------------------------------------

def build_signing_invite(orig_tn: str, dest_tn: str, api_key: str,
                         local_ip: str = "127.0.0.1",
                         local_port: int = 15060) -> bytes:
    """Build a SIP INVITE for the signing flow (SIP Redirect)."""
    call_id = f"vvp-healthcheck-{uuid.uuid4().hex[:12]}@{local_ip}"
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


def build_verify_invite(orig_tn: str, dest_tn: str,
                        local_ip: str = "127.0.0.1",
                        local_port: int = 15061) -> bytes:
    """Build a SIP INVITE for the verification flow (SIP Verify).

    Includes synthetic Identity and P-VVP-Identity headers.
    The verification will likely return INVALID (the PASSporT is not
    cryptographically valid), but we're testing that the service processes
    it and reaches the Verifier API — not that the credential is genuine.
    """
    call_id = f"vvp-healthcheck-{uuid.uuid4().hex[:12]}@{local_ip}"
    branch = f"z9hG4bK{uuid.uuid4().hex[:16]}"
    tag = uuid.uuid4().hex[:8]
    now = int(time.time())

    # Build a synthetic P-VVP-Identity (base64url JSON)
    vvp_identity = {
        "ppt": "vvp",
        "kid": "https://vvp-witness1.rcnx.io/oobi/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha/witness",
        "evd": "https://vvp-issuer.rcnx.io/v1/agent/public/test/dossier.cesr",
        "iat": now,
    }
    identity_json = json.dumps(vvp_identity, separators=(",", ":"))
    identity_b64 = base64.urlsafe_b64encode(identity_json.encode()).decode().rstrip("=")

    # Build a synthetic PASSporT JWT (header.payload.signature)
    jwt_header = base64.urlsafe_b64encode(
        json.dumps({"alg": "EdDSA", "typ": "passport", "ppt": "vvp"}, separators=(",", ":")).encode()
    ).decode().rstrip("=")
    jwt_payload = base64.urlsafe_b64encode(
        json.dumps({
            "orig": {"tn": [orig_tn.lstrip("+")]},
            "dest": {"tn": [dest_tn.lstrip("+")]},
            "iat": now,
        }, separators=(",", ":")).encode()
    ).decode().rstrip("=")
    # Fake signature (will fail verification, but tests service reachability)
    jwt_sig = base64.urlsafe_b64encode(b"\x00" * 64).decode().rstrip("=")
    passport_jwt = f"{jwt_header}.{jwt_payload}.{jwt_sig}"

    # RFC 8224 Identity header format
    passport_b64 = base64.urlsafe_b64encode(passport_jwt.encode()).decode().rstrip("=")
    info_url = vvp_identity["kid"]

    lines = [
        f"INVITE sip:{dest_tn}@127.0.0.1:5071 SIP/2.0",
        f"Via: SIP/2.0/UDP {local_ip}:{local_port};branch={branch}",
        f"From: <sip:{orig_tn}@carrier.example.com>;tag={tag}",
        f"To: <sip:{dest_tn}@127.0.0.1>",
        f"Call-ID: {call_id}",
        "CSeq: 1 INVITE",
        f"Contact: <sip:{local_ip}:{local_port}>",
        f"Identity: <{passport_b64}>;info={info_url};alg=EdDSA;ppt=vvp",
        f"P-VVP-Identity: {identity_b64}",
        f"P-VVP-Passport: {passport_jwt}",
        "Max-Forwards: 70",
        "Content-Length: 0",
    ]
    return ("\r\n".join(lines) + "\r\n\r\n").encode("utf-8")


def build_verify_invite_with_real_headers(orig_tn: str, dest_tn: str,
                                          p_identity: str, p_passport: str,
                                          local_ip: str = "127.0.0.1",
                                          local_port: int = 15061) -> bytes:
    """Build a verify INVITE using real P-VVP-Identity and P-VVP-Passport.

    Used by the chained sign→verify timing test to exercise the verification
    result cache with a real, cryptographically valid PASSporT.
    """
    call_id = f"vvp-chain-{uuid.uuid4().hex[:12]}@{local_ip}"
    branch = f"z9hG4bK{uuid.uuid4().hex[:16]}"
    tag = uuid.uuid4().hex[:8]

    # Build Identity header from the real passport
    passport_b64 = base64.urlsafe_b64encode(p_passport.encode()).decode().rstrip("=")
    # Extract kid from P-VVP-Identity for the info param
    try:
        # p_identity is base64url-encoded JSON
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


# ---------------------------------------------------------------------------
# SIP response parsing
# ---------------------------------------------------------------------------

def parse_sip_response(data: bytes) -> dict:
    """Parse a SIP response into status code and headers."""
    text = data.decode("utf-8", errors="replace")
    lines = text.split("\r\n")

    result = {
        "raw_status_line": "",
        "status_code": 0,
        "reason": "",
        "headers": {},
    }

    if not lines:
        return result

    # Parse status line: SIP/2.0 302 Moved Temporarily
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

    # Parse headers
    for line in lines[1:]:
        if not line:
            break
        if ":" in line:
            key, value = line.split(":", 1)
            result["headers"][key.strip()] = value.strip()

    return result


# ---------------------------------------------------------------------------
# Verifier cache metrics
# ---------------------------------------------------------------------------

def snapshot_verifier_metrics(verifier_url: str) -> dict | None:
    """Fetch verification cache metrics from Verifier admin endpoint.

    Returns None if the endpoint is unavailable (disabled, auth-protected,
    or unreachable). The caller should continue without cache confirmation.
    """
    try:
        req = urllib.request.Request(f"{verifier_url}/admin", method="GET")
        with urllib.request.urlopen(req, timeout=5) as resp:
            if resp.status != 200:
                return None
            data = json.loads(resp.read())
            cache = data.get("cache_metrics", {})
            return {
                "verification_hits": cache.get("verification", {}).get("hits", 0),
                "verification_misses": cache.get("verification", {}).get("misses", 0),
                "dossier_hits": cache.get("dossier", {}).get("hits", 0),
                "dossier_misses": cache.get("dossier", {}).get("misses", 0),
            }
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Test execution
# ---------------------------------------------------------------------------

def send_sip_and_receive(invite: bytes, host: str, port: int,
                         timeout: float = RECV_TIMEOUT) -> dict:
    """Send a SIP INVITE via UDP and wait for the response."""
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
        return {
            "error": "timeout",
            "detail": f"No SIP response within {timeout}s",
            "elapsed_ms": round(elapsed_ms, 1),
        }
    except OSError as e:
        elapsed_ms = (time.monotonic() - start) * 1000
        return {
            "error": "socket_error",
            "detail": str(e),
            "elapsed_ms": round(elapsed_ms, 1),
        }
    finally:
        sock.close()


def test_signing(host: str, port: int, api_key: str,
                 orig_tn: str, dest_tn: str,
                 timeout: float = RECV_TIMEOUT) -> dict:
    """Test the SIP Redirect signing flow.

    Sends a SIP INVITE with X-VVP-API-Key to the SIP Redirect service.
    Expects a 302 response with VVP brand headers, proving:
      SIP Redirect → Issuer API (/tn/lookup + /vvp/create) → 302
    """
    result = {
        "test": "signing",
        "target": f"{host}:{port}",
        "status": "fail",
        "checks": {},
    }

    if not api_key:
        result["status"] = "skip"
        result["detail"] = "No API key provided (set VVP_TEST_API_KEY)"
        return result

    invite = build_signing_invite(orig_tn, dest_tn, api_key)
    response = send_sip_and_receive(invite, host, port, timeout=timeout)
    result["response"] = response

    if "error" in response:
        result["detail"] = response["detail"]
        return result

    result["elapsed_ms"] = response["elapsed_ms"]
    code = response["status_code"]
    headers = response["headers"]

    # Check 1: Got a SIP response at all
    result["checks"]["sip_response"] = code > 0
    if code == 0:
        result["detail"] = "No valid SIP response"
        return result

    # Check 2: SIP Redirect returned 302 (signing succeeded)
    result["checks"]["302_redirect"] = code == 302
    if code == 401:
        result["detail"] = "401 Unauthorized — API key rejected"
        return result
    if code == 404:
        result["detail"] = "404 Not Found — TN not mapped in Issuer"
        return result
    if code == 403:
        result["detail"] = "403 Forbidden — rate limited or TN not authorized"
        return result

    # Check 3: VVP brand headers present
    brand_name = headers.get("X-VVP-Brand-Name", "")
    brand_logo = headers.get("X-VVP-Brand-Logo", "")
    vvp_status = headers.get("X-VVP-Status", "")
    contact = headers.get("Contact", "")

    result["checks"]["vvp_status_header"] = vvp_status == "VALID"
    result["checks"]["brand_name_present"] = bool(brand_name)
    result["checks"]["contact_present"] = bool(contact)

    result["brand_name"] = brand_name
    result["brand_logo"] = brand_logo
    result["vvp_status"] = vvp_status
    result["contact"] = contact

    # Check 4: P-VVP-Identity and P-VVP-Passport headers (credential data)
    p_identity = headers.get("P-VVP-Identity", "")
    p_passport = headers.get("P-VVP-Passport", "")
    result["checks"]["p_vvp_identity_present"] = bool(p_identity)
    result["checks"]["p_vvp_passport_present"] = bool(p_passport)

    # Overall status
    if code == 302 and vvp_status == "VALID" and brand_name:
        result["status"] = "pass"
        result["detail"] = f"302 VALID — brand={brand_name}"
    elif code == 302:
        result["status"] = "warn"
        result["detail"] = f"302 received but status={vvp_status}"
    else:
        result["detail"] = f"Unexpected SIP {code}: {response.get('reason', '')}"

    return result


def test_verification(host: str, port: int,
                      orig_tn: str, dest_tn: str,
                      timeout: float = RECV_TIMEOUT) -> dict:
    """Test the SIP Verify verification flow.

    Sends a SIP INVITE with Identity/P-VVP-Identity headers to SIP Verify.
    The PASSporT is synthetic so verification will return INVALID, but we're
    testing that the service is alive and can reach the Verifier API.

    A response (any SIP status) proves:
      SIP Verify → Verifier API (/verify-callee) → response
    """
    result = {
        "test": "verification",
        "target": f"{host}:{port}",
        "status": "fail",
        "checks": {},
    }

    invite = build_verify_invite(orig_tn, dest_tn)
    response = send_sip_and_receive(invite, host, port, timeout=timeout)
    result["response"] = response

    if "error" in response:
        result["detail"] = response["detail"]
        return result

    result["elapsed_ms"] = response["elapsed_ms"]
    code = response["status_code"]
    headers = response["headers"]

    # Check 1: Got a SIP response
    result["checks"]["sip_response"] = code > 0
    if code == 0:
        result["detail"] = "No valid SIP response"
        return result

    # Check 2: SIP Verify processed the request (any 3xx/4xx/5xx is fine)
    result["checks"]["service_responded"] = code >= 100

    # Check 3: VVP status header present
    vvp_status = headers.get("X-VVP-Status", "")
    result["checks"]["vvp_status_present"] = bool(vvp_status)
    result["vvp_status"] = vvp_status

    # Check 4: Brand info (may or may not be present depending on verification result)
    brand_name = headers.get("X-VVP-Brand-Name", "")
    result["brand_name"] = brand_name

    # We expect INVALID or INDETERMINATE since the PASSporT is synthetic.
    # The key thing is the service is alive and processing.
    if code in (302, 200) and vvp_status:
        result["status"] = "pass"
        result["detail"] = f"SIP {code} — VVP status={vvp_status} (expected for synthetic PASSporT)"
    elif code == 400:
        # Service is alive but rejected our message format
        result["status"] = "warn"
        result["detail"] = f"400 Bad Request — service alive but rejected test INVITE"
    elif code >= 100:
        result["status"] = "pass"
        result["detail"] = f"SIP {code} — service is processing calls"
    else:
        result["detail"] = f"Unexpected response: {response.get('raw_status_line', '')}"

    return result


# ---------------------------------------------------------------------------
# Timing tests
# ---------------------------------------------------------------------------

def test_timing(test_fn, test_name: str, host: str, port: int,
                count: int = 2, threshold: float = 2.0, delay: float = 0.5,
                timeout: float = RECV_TIMEOUT, **kwargs) -> dict:
    """Run multiple calls of a test function and measure cache timing.

    Works with both test_signing() and test_verification().
    """
    timings = []
    call_results = []

    for i in range(count):
        result = test_fn(host, port, timeout=timeout, **kwargs)
        call_results.append(result)

        if result.get("status") == "fail":
            return {
                "test": f"{test_name}_timing",
                "status": "fail",
                "detail": f"Call {i+1}/{count} failed: {result.get('detail', '')}",
                "call_results": call_results,
            }

        elapsed = result.get("elapsed_ms", 0)
        timings.append(elapsed)

        if i < count - 1:
            time.sleep(delay)

    first_ms = timings[0]
    cached_ms = timings[1:]
    min_cached = min(cached_ms) if cached_ms else first_ms
    speedup = first_ms / min_cached if min_cached > 0 else 0

    cold_uncertain = first_ms < 500

    status = "pass"
    if speedup < threshold:
        status = "warn"

    return {
        "test": f"{test_name}_timing",
        "status": status,
        "first_call_ms": first_ms,
        "second_call_ms": timings[1] if len(timings) > 1 else None,
        "all_timings_ms": timings,
        "min_ms": min(timings),
        "max_ms": max(timings),
        "avg_ms": round(sum(timings) / len(timings), 1),
        "speedup_ratio": round(speedup, 2),
        "threshold": threshold,
        "cold_uncertain": cold_uncertain,
        "detail": (f"Speedup {speedup:.1f}x (threshold: {threshold}x) "
                   f"— cold={first_ms:.0f}ms, cached_min={min_cached:.0f}ms"
                   + (" [cold uncertain]" if cold_uncertain else "")),
    }


def test_chained_timing(sign_host: str, sign_port: int,
                        verify_host: str, verify_port: int,
                        api_key: str, orig_tn: str, dest_tn: str,
                        count: int = 2, threshold: float = 2.0,
                        delay: float = 0.5, timeout: float = RECV_TIMEOUT,
                        verifier_url: str = VERIFIER_URL) -> dict:
    """Chain sign → verify to exercise verification cache with real PASSporT."""
    # Step 1: Get a real PASSporT from signing
    sign_result = test_signing(sign_host, sign_port, api_key,
                               orig_tn, dest_tn, timeout=timeout)

    if sign_result.get("status") not in ("pass", "warn"):
        return {
            "test": "chain_timing",
            "status": "fail" if sign_result.get("status") != "skip" else "skip",
            "detail": f"Signing failed: {sign_result.get('detail', '')}",
        }

    # Extract real VVP headers from signing response
    response = sign_result.get("response", {})
    headers = response.get("headers", {})
    p_identity = headers.get("P-VVP-Identity", "")
    p_passport = headers.get("P-VVP-Passport", "")

    if not p_identity or not p_passport:
        return {
            "test": "chain_timing",
            "status": "fail",
            "detail": "Signing response missing P-VVP-Identity/Passport headers",
        }

    # Step 2: Snapshot verifier cache metrics (before)
    before_metrics = snapshot_verifier_metrics(verifier_url)

    # Step 3: Send verify INVITEs with real headers
    timings = []
    vvp_statuses = []

    for i in range(count):
        invite = build_verify_invite_with_real_headers(
            orig_tn, dest_tn, p_identity, p_passport)
        resp = send_sip_and_receive(invite, verify_host, verify_port, timeout)

        if "error" in resp:
            return {
                "test": "chain_timing",
                "status": "fail",
                "detail": f"Verify call {i+1}/{count} failed: {resp.get('detail', '')}",
            }

        timings.append(resp["elapsed_ms"])
        vvp_status = resp.get("headers", {}).get("X-VVP-Status", "")
        vvp_statuses.append(vvp_status)

        if i < count - 1:
            time.sleep(delay)

    # Step 4: Snapshot verifier cache metrics (after)
    after_metrics = snapshot_verifier_metrics(verifier_url)

    # Compute timing results
    first_ms = timings[0]
    cached_ms = timings[1:]
    min_cached = min(cached_ms) if cached_ms else first_ms
    speedup = first_ms / min_cached if min_cached > 0 else 0
    cold_uncertain = first_ms < 500

    # Compute cache metrics delta
    cache_metrics = None
    cache_confirmed = False
    if before_metrics and after_metrics:
        v_delta = after_metrics["verification_hits"] - before_metrics["verification_hits"]
        d_delta = after_metrics["dossier_hits"] - before_metrics["dossier_hits"]
        expected_hits = count - 1
        cache_confirmed = v_delta >= expected_hits
        cache_metrics = {
            "verification_hits_delta": v_delta,
            "dossier_hits_delta": d_delta,
            "cache_confirmed": cache_confirmed,
            "metrics_approximate": True,
        }

    # Determine if verification cache was exercised
    has_valid = any(s == "VALID" for s in vvp_statuses)

    status = "pass"
    if speedup < threshold:
        status = "warn"

    return {
        "test": "chain_timing",
        "status": status,
        "sign_elapsed_ms": sign_result.get("elapsed_ms"),
        "first_call_ms": first_ms,
        "second_call_ms": timings[1] if len(timings) > 1 else None,
        "all_timings_ms": timings,
        "min_ms": min(timings),
        "max_ms": max(timings),
        "avg_ms": round(sum(timings) / len(timings), 1),
        "speedup_ratio": round(speedup, 2),
        "threshold": threshold,
        "cold_uncertain": cold_uncertain,
        "vvp_statuses": vvp_statuses,
        "cache_exercised": has_valid and len(timings) > 1,
        "cache_metrics": cache_metrics,
        "detail": (f"Speedup {speedup:.1f}x (threshold: {threshold}x) "
                   f"— cold={first_ms:.0f}ms, cached_min={min_cached:.0f}ms"
                   + (f" [cache {'confirmed' if cache_confirmed else 'unconfirmed'}]"
                      if cache_metrics else " [no metrics]")
                   + (" [cold uncertain]" if cold_uncertain else "")),
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="VVP SIP Call Test")
    parser.add_argument("--test", choices=["sign", "verify", "chain", "all"],
                        default="all", help="Which test to run")
    parser.add_argument("--host", help="Override host for both services")
    parser.add_argument("--port", type=int, help="Override port (for single test)")
    parser.add_argument("--api-key", help="API key for signing test")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--timeout", type=float, default=RECV_TIMEOUT,
                        help="SIP response timeout in seconds")

    # Timing flags
    parser.add_argument("--timing", action="store_true",
                        help="Enable timing mode (multiple calls, measure speedup)")
    parser.add_argument("--timing-count", type=int, default=2,
                        help=f"Number of calls in timing mode (max {MAX_TIMING_COUNT})")
    parser.add_argument("--timing-threshold", type=float, default=2.0,
                        help="Speedup threshold for warn (default: 2.0x)")
    parser.add_argument("--timing-delay", type=float, default=0.5,
                        help=f"Delay between timing calls in seconds (min {MIN_TIMING_DELAY})")
    parser.add_argument("--verifier-url", default=VERIFIER_URL,
                        help="Verifier URL for cache metrics (default: %(default)s)")

    args = parser.parse_args()

    # Validate chain mode
    if args.test == "chain" and not args.timing:
        print("Error: --test chain requires --timing flag", file=sys.stderr)
        sys.exit(2)

    # Enforce timing guardrails
    count = min(args.timing_count, MAX_TIMING_COUNT)
    delay = max(args.timing_delay, MIN_TIMING_DELAY)
    threshold = args.timing_threshold

    redirect_host = args.host or REDIRECT_HOST
    redirect_port = (args.port or REDIRECT_PORT) if args.test == "sign" else REDIRECT_PORT
    verify_host = args.host or VERIFY_HOST
    verify_port = (args.port or VERIFY_PORT) if args.test == "verify" else VERIFY_PORT
    api_key = args.api_key or API_KEY
    timeout = args.timeout

    results = []

    if args.timing:
        # Timing mode
        if args.test in ("sign", "all"):
            results.append(test_timing(
                test_signing, "signing", redirect_host, redirect_port,
                count=count, threshold=threshold, delay=delay, timeout=timeout,
                api_key=api_key, orig_tn=ORIG_TN, dest_tn=DEST_TN,
            ))

        if args.test in ("verify", "all"):
            results.append(test_timing(
                test_verification, "verification", verify_host, verify_port,
                count=count, threshold=threshold, delay=delay, timeout=timeout,
                orig_tn=ORIG_TN, dest_tn=DEST_TN,
            ))

        if args.test in ("chain", "all"):
            results.append(test_chained_timing(
                redirect_host, redirect_port, verify_host, verify_port,
                api_key, ORIG_TN, DEST_TN,
                count=count, threshold=threshold, delay=delay, timeout=timeout,
                verifier_url=args.verifier_url,
            ))
    else:
        # Standard mode
        if args.test in ("sign", "all"):
            sign_result = test_signing(redirect_host, redirect_port, api_key,
                                       ORIG_TN, DEST_TN, timeout=timeout)
            results.append(sign_result)

        if args.test in ("verify", "all"):
            verify_result = test_verification(verify_host, verify_port,
                                              ORIG_TN, DEST_TN, timeout=timeout)
            results.append(verify_result)

    # --- Output ---
    if args.json:
        # Clean up response raw data for JSON output
        for r in results:
            if "response" in r:
                resp = r["response"]
                if "headers" in resp:
                    vvp_headers = {k: v for k, v in resp["headers"].items()
                                   if "VVP" in k.upper() or k == "Contact"}
                    resp["vvp_headers"] = vvp_headers
                    del resp["headers"]
            # Clean up call_results too
            for cr in r.get("call_results", []):
                if "response" in cr:
                    resp = cr["response"]
                    if "headers" in resp:
                        vvp_headers = {k: v for k, v in resp["headers"].items()
                                       if "VVP" in k.upper() or k == "Contact"}
                        resp["vvp_headers"] = vvp_headers
                        del resp["headers"]
        print(json.dumps({"results": results, "timestamp": time.time()}, indent=2))
    else:
        for r in results:
            test_name = r["test"].upper()
            status = r["status"].upper()
            detail = r.get("detail", "")
            elapsed = r.get("elapsed_ms", "")

            if status == "PASS":
                icon = "PASS"
            elif status == "WARN":
                icon = "WARN"
            elif status == "SKIP":
                icon = "SKIP"
            else:
                icon = "FAIL"

            timing_str = f" ({elapsed}ms)" if elapsed else ""
            print(f"  {icon}  [{test_name}] {detail}{timing_str}")

            # Print check details
            for check, passed in r.get("checks", {}).items():
                mark = "+" if passed else "-"
                print(f"        [{mark}] {check}")

            # Print timing details
            if "all_timings_ms" in r:
                print(f"        Timings: {r['all_timings_ms']}")
                if r.get("cache_metrics"):
                    cm = r["cache_metrics"]
                    print(f"        Cache: verification_hits_delta={cm['verification_hits_delta']}, "
                          f"dossier_hits_delta={cm['dossier_hits_delta']}, "
                          f"confirmed={cm['cache_confirmed']}")

    # Exit code: 0 if all non-skipped tests passed or warned
    non_skip = [r for r in results if r["status"] != "skip"]
    if all(r["status"] in ("pass", "warn") for r in non_skip) and non_skip:
        sys.exit(0)
    elif not non_skip:
        sys.exit(0)  # All skipped
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
