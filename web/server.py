#!/usr/bin/env python3
"""
DEPRECATED: This standalone server is deprecated as of Phase 13.

Use the main FastAPI application instead:
    uvicorn app.main:app --reload

The main application now serves HTMX templates with all features
previously provided by this server.

This file is kept for reference only and will be removed in a future release.

---
Original description:
Lightweight server for the VVP Parser UI.
Does not require pysodium/libsodium - just serves the UI and proxies dossier fetches.
"""
import warnings
warnings.warn(
    "web/server.py is deprecated. Use 'uvicorn app.main:app --reload' instead.",
    DeprecationWarning,
    stacklevel=2
)
import json
from http.server import HTTPServer, SimpleHTTPRequestHandler
import urllib.request
import urllib.error
import ssl
import os

MOCK_DOSSIER = [
    {
        "v": "ACDC10JSON000000_",
        "d": "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao",
        "i": "EMyYnLzlJDJskqojipIMivAKHWeZofhWiYjB79uszynS",
        "s": "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao",
        "a": {
            "d": "EGZ_DdmzryjQOtOdQauTm_YxggbVM7EWelk8IBxsnC-d",
            "i": "EMyYnLzlJDJskqojipIMivAKHWeZofhWiYjB79uszynS",
            "dt": "2025-01-20T12:00:00.000000+00:00",
            "LEI": "254900OPPU84GM83MG36",
            "legalName": "Orange France Telecom SA",
            "tn": ["330123456791"],
            "country": "FR",
            "spCode": "ORANGE-FR"
        },
        "e": {
            "d": "EKE3E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4",
            "auth": {
                "n": "EAuth00000000000000000000000000000000000000",
                "s": "ESchema0000000000000000000000000000000000"
            }
        },
        "r": {
            "d": "ERules0000000000000000000000000000000000000",
            "usageRules": {
                "validityPeriod": 300,
                "oneTimeUse": False
            }
        }
    },
    {
        "v": "ACDC10JSON000000_",
        "d": "EAuth00000000000000000000000000000000000000",
        "i": "ERegulatoryAuthority000000000000000000000",
        "s": "ESchema0000000000000000000000000000000000",
        "a": {
            "d": "EAttr00000000000000000000000000000000000",
            "i": "EMyYnLzlJDJskqojipIMivAKHWeZofhWiYjB79uszynS",
            "dt": "2024-06-01T00:00:00.000000+00:00",
            "authorizedTNs": ["33*"],
            "authorizationType": "ORIGINATION",
            "jurisdiction": "FR",
            "regulatoryBody": "ARCEP"
        }
    }
]


class VVPHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        # Serve from web/ directory
        super().__init__(*args, directory=os.path.dirname(__file__), **kwargs)

    def do_GET(self):
        # Serve mock dossier
        if self.path == "/mock-dossier":
            self._send_json(MOCK_DOSSIER)
        elif self.path == "/admin":
            self._send_json({
                "server": "VVP Parser UI Server",
                "version": "1.0.0",
                "endpoints": {
                    "GET /": "Serve index.html",
                    "GET /mock-dossier": "Return mock dossier data",
                    "GET /admin": "This endpoint",
                    "POST /proxy-fetch": "Proxy fetch external URLs",
                    "POST /check-revocation": "Check credential revocation status"
                },
                "tel_resolution": {
                    "step_1": "Inline TEL from dossier stream",
                    "step_2": "Witness derived from kid URL (PREFERRED - kid is witness OOBI per Provenant spec)",
                    "step_3": "Fallback to Provenant stage witnesses (last resort)"
                },
                "note": "The kid field in PASSporT header contains the witness OOBI URL - this is the primary method for TEL resolution",
                "fallback_witnesses": [
                    "http://witness1.stage.provenant.net:5631",
                    "http://witness2.stage.provenant.net:5631",
                    "http://witness3.stage.provenant.net:5631",
                    "http://witness4.stage.provenant.net:5631",
                    "http://witness5.stage.provenant.net:5631",
                    "http://witness6.stage.provenant.net:5631"
                ]
            })
        else:
            super().do_GET()

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)

        if self.path == "/proxy-fetch":
            try:
                req_body = json.loads(post_data)
                url = req_body.get("url", "")

                if not url:
                    self._send_json({"success": False, "error": "No URL provided"})
                    return

                # Fetch the URL (with SSL verification disabled for dev)
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                req = urllib.request.Request(url, headers={"User-Agent": "VVP-Parser/1.0"})
                with urllib.request.urlopen(req, timeout=10, context=ctx) as response:
                    content_type = response.headers.get("Content-Type", "")
                    data = response.read().decode("utf-8")

                    # Try to parse as JSON
                    try:
                        parsed = json.loads(data)
                        self._send_json({
                            "success": True,
                            "data": parsed,
                            "content_type": content_type
                        })
                    except json.JSONDecodeError:
                        # Return raw text
                        self._send_json({
                            "success": True,
                            "data": data,
                            "content_type": content_type
                        })

            except urllib.error.URLError as e:
                self._send_json({"success": False, "error": f"URL error: {e.reason}"})
            except urllib.error.HTTPError as e:
                self._send_json({"success": False, "error": f"HTTP {e.code}: {e.reason}"})
            except Exception as e:
                self._send_json({"success": False, "error": str(e)})

        elif self.path == "/check-revocation":
            # Query KERI witnesses for credential revocation status
            try:
                req_body = json.loads(post_data)
                cred_said = req_body.get("credential_said", "")
                registry_said = req_body.get("registry_said")
                oobi_url = req_body.get("oobi_url")
                kid_url = req_body.get("kid_url")  # Witness OOBI from JWT kid field
                dossier_stream = req_body.get("dossier_stream")  # Raw CESR stream

                if not cred_said:
                    self._send_json({"success": False, "error": "No credential_said provided"})
                    return

                print(f"\n[TEL] === Checking revocation for credential ===")
                print(f"[TEL] Credential SAID: {cred_said[:24]}...")
                if registry_said:
                    print(f"[TEL] Registry SAID: {registry_said[:24]}...")
                if kid_url:
                    print(f"[TEL] kid URL (witness OOBI): {kid_url}")
                if oobi_url:
                    print(f"[TEL] OOBI URL: {oobi_url[:60]}...")
                if dossier_stream:
                    print(f"[TEL] Dossier stream provided: {len(dossier_stream)} chars")

                result = self._check_revocation_status(cred_said, registry_said, oobi_url, dossier_stream, kid_url)
                print(f"[TEL] Final result: {result['status']}")
                self._send_json(result)

            except Exception as e:
                self._send_json({"success": False, "status": "ERROR", "error": str(e)})

        else:
            self.send_error(404, "Not found")

    def _extract_witness_base_url(self, oobi_url):
        """
        Extract witness base URL from an OOBI URL.

        OOBI URLs follow the pattern:
            http://witness5.stage.provenant.net:5631/oobi/{AID}/witness

        This extracts: http://witness5.stage.provenant.net:5631
        """
        if not oobi_url:
            return None
        from urllib.parse import urlparse
        try:
            parsed = urlparse(oobi_url)
            return f"{parsed.scheme}://{parsed.netloc}"
        except Exception:
            return None

    def _check_revocation_status(self, cred_said, registry_said, oobi_url, dossier_stream=None, kid_url=None):
        """
        Query KERI infrastructure for credential revocation status.

        Tries multiple approaches (Phase 9.4 resolution order):
        1. Inline TEL from dossier stream (if provided)
        2. Witness derived from kid URL (witness OOBI from PASSporT header)
        3. Registry OOBI derived from issuer OOBI
        4. Known witness endpoints (fallback)
        5. Returns UNKNOWN if no TEL data found
        """
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        # Step 1: Try inline TEL from dossier stream first (Phase 9.4)
        if dossier_stream:
            print(f"[TEL] Step 1: Checking inline TEL in dossier stream...")

            # Handle JSON-wrapped dossier format (e.g., {"details": "..."})
            raw_stream = dossier_stream
            try:
                parsed = json.loads(dossier_stream)
                if isinstance(parsed, dict) and "details" in parsed:
                    # Dossier is wrapped in JSON - extract and unescape the details field
                    details = parsed["details"]
                    if isinstance(details, str):
                        raw_stream = details
                        print(f"[TEL] Unwrapped JSON-escaped dossier from 'details' field")
            except json.JSONDecodeError:
                pass  # Not JSON-wrapped, use as-is

            # Debug: show sample of dossier and key patterns
            print(f"[TEL] Dossier sample: {raw_stream[:200]}...")
            keri_count = raw_stream.count('"v":"KERI')
            iss_count = raw_stream.count('"t":"iss')
            bis_count = raw_stream.count('"t":"bis')
            print(f"[TEL] Pattern counts: KERI={keri_count}, iss={iss_count}, bis={bis_count}")
            events = self._extract_tel_events(raw_stream)
            if events:
                print(f"[TEL] Found {len(events)} inline TEL events")
                # Filter for this credential
                cred_events = [e for e in events if e.get("i") == cred_said]
                if not cred_events and registry_said:
                    cred_events = [e for e in events if e.get("ri") == registry_said]
                if cred_events:
                    print(f"[TEL] Found {len(cred_events)} events for credential")
                    result = self._parse_tel_events(cred_events, cred_said, registry_said, "inline_dossier")
                    if result["status"] != "UNKNOWN":
                        return result

        # Build list of endpoints to try
        endpoints_to_try = []

        # Step 2: Extract witness base URL from kid (Phase 9.4 - preferred method)
        # The kid field in PASSporT header is the witness OOBI URL like:
        #   http://witness5.stage.provenant.net:5631/oobi/{AID}/witness
        kid_witness_base = None
        if kid_url:
            kid_witness_base = self._extract_witness_base_url(kid_url)
            if kid_witness_base:
                print(f"[TEL] Step 2: Extracted witness base from kid: {kid_witness_base}")
                # Query this witness for TEL data
                if registry_said:
                    endpoints_to_try.append(f"{kid_witness_base}/tels/{registry_said}")
                endpoints_to_try.append(f"{kid_witness_base}/tels/{cred_said}")

        # Step 3: Try registry OOBI derived from issuer OOBI (Phase 9.4)
        if oobi_url and registry_said:
            from urllib.parse import urlparse
            parsed = urlparse(oobi_url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            registry_oobi = f"{base_url}/oobi/{registry_said}"
            print(f"[TEL] Step 3: Trying registry OOBI: {registry_oobi}")
            endpoints_to_try.append(registry_oobi)

        # If OOBI URL provided, extract base and try TEL endpoints
        if oobi_url:
            from urllib.parse import urlparse
            parsed = urlparse(oobi_url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            endpoints_to_try.extend([
                f"{base_url}/tels/{registry_said or cred_said}",
                f"{base_url}/credentials/{cred_said}",
                f"{base_url}/oobi/{cred_said}/tels",
            ])

        # Step 4: Fallback to Provenant stage witnesses (only if kid-derived witness didn't work)
        # Note: GLEIF testnet and Provenant dev witnesses have been removed as non-functional
        if not kid_witness_base:
            print(f"[TEL] Step 4: No kid URL provided, trying fallback Provenant stage witnesses")
            provenant_stage_witnesses = [
                "http://witness1.stage.provenant.net:5631",
                "http://witness2.stage.provenant.net:5631",
                "http://witness3.stage.provenant.net:5631",
                "http://witness4.stage.provenant.net:5631",
                "http://witness5.stage.provenant.net:5631",
                "http://witness6.stage.provenant.net:5631",
            ]

            for witness in provenant_stage_witnesses:
                endpoints_to_try.append(f"{witness}/tels/{registry_said or cred_said}")

        # Try each endpoint
        for url in endpoints_to_try:
            print(f"[TEL] Querying: {url}")
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "VVP-Parser/1.0"})
                with urllib.request.urlopen(req, timeout=10, context=ctx) as response:
                    status_code = response.getcode()
                    data = response.read().decode("utf-8")
                    print(f"[TEL] Response from {url}: HTTP {status_code}, {len(data)} bytes")
                    result = self._parse_tel_response(data, cred_said, registry_said, url)
                    if result["status"] != "UNKNOWN":
                        print(f"[TEL] Found status: {result['status']}")
                        return result
                    else:
                        print(f"[TEL] No TEL events found in response")
            except urllib.error.HTTPError as e:
                print(f"[TEL] HTTP Error from {url}: {e.code} {e.reason}")
            except urllib.error.URLError as e:
                print(f"[TEL] URL Error from {url}: {e.reason}")
            except Exception as e:
                print(f"[TEL] Error from {url}: {type(e).__name__}: {e}")

        # No TEL data found from any source
        return {
            "success": True,
            "status": "UNKNOWN",
            "credential_said": cred_said,
            "registry_said": registry_said,
            "source": "none",
            "error": "No TEL data found from any configured witness"
        }

    def _parse_tel_events(self, events, cred_said, registry_said, source):
        """Parse a list of TEL events and determine revocation status."""
        if not events:
            return {
                "success": True,
                "status": "UNKNOWN",
                "credential_said": cred_said,
                "registry_said": registry_said,
                "source": source
            }

        # Sort by sequence
        events.sort(key=lambda e: int(e.get("s", 0)))

        # Find issuance and revocation
        issuance = None
        revocation = None

        for event in events:
            t = event.get("t")
            if t in ("iss", "bis"):
                issuance = event
            elif t in ("rev", "brv"):
                revocation = event

        # Build response
        result = {
            "success": True,
            "credential_said": cred_said,
            "registry_said": registry_said,
            "source": source
        }

        if revocation:
            result["status"] = "REVOKED"
            result["revocation"] = {
                "datetime": revocation.get("dt"),
                "sequence": int(revocation.get("s", 0)),
                "type": revocation.get("t")
            }
        elif issuance:
            result["status"] = "ACTIVE"
        else:
            result["status"] = "UNKNOWN"

        if issuance:
            result["issuance"] = {
                "datetime": issuance.get("dt"),
                "sequence": int(issuance.get("s", 0)),
                "type": issuance.get("t")
            }

        return result

    def _parse_tel_response(self, data, cred_said, registry_said, source):
        """Parse TEL response and determine revocation status."""
        events = self._extract_tel_events(data)

        if not events:
            return {
                "success": True,
                "status": "UNKNOWN",
                "credential_said": cred_said,
                "registry_said": registry_said,
                "source": source
            }

        # Find events for this credential
        cred_events = [e for e in events if e.get("i") == cred_said]
        if not cred_events and registry_said:
            cred_events = [e for e in events if e.get("ri") == registry_said]
        if not cred_events:
            cred_events = events

        return self._parse_tel_events(cred_events, cred_said, registry_said, source)

    def _extract_tel_events(self, data):
        """Extract TEL events from response (JSON or CESR)."""
        events = []

        # Try JSON first
        try:
            parsed = json.loads(data)
            if isinstance(parsed, list):
                for item in parsed:
                    if item.get("t") in ("iss", "rev", "bis", "brv"):
                        events.append(item)
            elif isinstance(parsed, dict) and parsed.get("t") in ("iss", "rev", "bis", "brv"):
                events.append(parsed)
            return events
        except json.JSONDecodeError:
            pass

        # Parse CESR stream
        pos = 0
        while True:
            match = data.find('{"v":"KERI', pos)
            if match == -1:
                break

            try:
                depth = 0
                start = match
                end = match

                for i in range(match, len(data)):
                    if data[i] == '{':
                        depth += 1
                    elif data[i] == '}':
                        depth -= 1
                        if depth == 0:
                            end = i + 1
                            break

                obj = json.loads(data[start:end])
                if obj.get("t") in ("iss", "rev", "bis", "brv"):
                    events.append(obj)
                pos = end
            except (json.JSONDecodeError, IndexError):
                pos = match + 1

        return events

    def _send_json(self, data):
        response = json.dumps(data).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(response))
        self.end_headers()
        self.wfile.write(response)


if __name__ == "__main__":
    port = 8000
    server = HTTPServer(("127.0.0.1", port), VVPHandler)
    print(f"VVP Parser server running at http://127.0.0.1:{port}")
    print("Press Ctrl+C to stop")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped")
