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
"""

import argparse
import base64
import json
import os
import socket
import sys
import time
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
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="VVP SIP Call Test")
    parser.add_argument("--test", choices=["sign", "verify", "all"], default="all",
                        help="Which test to run")
    parser.add_argument("--host", help="Override host for both services")
    parser.add_argument("--port", type=int, help="Override port (for single test)")
    parser.add_argument("--api-key", help="API key for signing test")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--timeout", type=float, default=RECV_TIMEOUT,
                        help="SIP response timeout in seconds")
    args = parser.parse_args()

    redirect_host = args.host or REDIRECT_HOST
    redirect_port = (args.port or REDIRECT_PORT) if args.test == "sign" else REDIRECT_PORT
    verify_host = args.host or VERIFY_HOST
    verify_port = (args.port or VERIFY_PORT) if args.test == "verify" else VERIFY_PORT
    api_key = args.api_key or API_KEY
    timeout = args.timeout

    results = []

    # --- Signing test ---
    if args.test in ("sign", "all"):
        sign_result = test_signing(redirect_host, redirect_port, api_key,
                                   ORIG_TN, DEST_TN, timeout=timeout)
        results.append(sign_result)

    # --- Verification test ---
    if args.test in ("verify", "all"):
        verify_result = test_verification(verify_host, verify_port,
                                          ORIG_TN, DEST_TN, timeout=timeout)
        results.append(verify_result)

    # --- Output ---
    if args.json:
        # Clean up response raw data for JSON output
        for r in results:
            if "response" in r:
                # Don't include raw SIP bytes in JSON
                resp = r["response"]
                if "headers" in resp:
                    # Keep only VVP-related headers
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

            timing = f" ({elapsed}ms)" if elapsed else ""
            print(f"  {icon}  [{test_name}] {detail}{timing}")

            # Print check details
            for check, passed in r.get("checks", {}).items():
                mark = "+" if passed else "-"
                print(f"        [{mark}] {check}")

    # Exit code: 0 if all non-skipped tests passed
    non_skip = [r for r in results if r["status"] != "skip"]
    if all(r["status"] in ("pass", "warn") for r in non_skip) and non_skip:
        sys.exit(0)
    elif not non_skip:
        sys.exit(0)  # All skipped
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
