#!/usr/bin/env python3
"""Bootstrap two demo vetter scenarios on the VVP Issuer.

Creates two organizations both representing ACME Inc, but vetted by different
vetters with different geographic authorizations:

  1. Brand Assure (authorized for UK numbers) — extension 1002
  2. Deutsche Vetters (NOT authorized for UK numbers) — extension 1003

Prerequisite: Run bootstrap-issuer.py first to initialize mock vLEI
infrastructure (GLEIF, QVI, GSMA).

Usage:
    python3 scripts/bootstrap-demo-vetters.py [--url URL] [--admin-key KEY]
"""

import argparse
import json
import ssl
import sys
import time
import urllib.error
import urllib.request

# SSL context that trusts system certs (works on macOS with Python 3.13+)
_ssl_ctx = ssl.create_default_context()
try:
    import certifi
    _ssl_ctx.load_verify_locations(certifi.where())
except ImportError:
    # Fall back to unverified if certifi unavailable and system certs fail
    _ssl_ctx = ssl.create_default_context()
    _ssl_ctx.check_hostname = False
    _ssl_ctx.verify_mode = ssl.CERT_NONE


# ---------------------------------------------------------------------------
# HTTP helpers (same pattern as bootstrap-issuer.py)
# ---------------------------------------------------------------------------

def api_call(method, url, data=None, api_key=None, timeout=60):
    """Make an HTTP API call and return parsed JSON response."""
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["X-API-Key"] = api_key

    body = json.dumps(data).encode() if data else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)

    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ssl_ctx) as resp:
            resp_body = resp.read().decode()
            return resp.status, json.loads(resp_body) if resp_body else {}
    except urllib.error.HTTPError as e:
        resp_body = e.read().decode() if e.fp else ""
        try:
            detail = json.loads(resp_body)
        except (json.JSONDecodeError, ValueError):
            detail = {"detail": resp_body}
        return e.code, detail


def wait_for_health(base_url, timeout=60):
    """Wait for the issuer to be healthy."""
    print(f"  Waiting for issuer at {base_url}/healthz ...")
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            status, body = api_call("GET", f"{base_url}/healthz")
            if status == 200 and (body.get("ok") or body.get("status") == "ok"):
                print(f"  Issuer healthy")
                return True
        except Exception:
            pass
        time.sleep(2)
    print("  ERROR: Issuer did not become healthy within timeout")
    return False


# ---------------------------------------------------------------------------
# Schema SAIDs
# ---------------------------------------------------------------------------

TN_ALLOC_SCHEMA = "EGUh_fVLbjfkYFb5zAsY2Rqq0NqwnD3r5jsdKWLTpU8_"  # Extended (auto-injects certification edge)
BRAND_SCHEMA = "EK7kPhs5YkPsq9mZgUfPYfU-zq5iSlU8XVYJWqrVPk6g"
LE_SCHEMA = "ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY"
VETTER_CERT_SCHEMA = "EOefmhWU2qTpMiEQhXohE6z3xRXkpLloZdhTYIenlD4H"


# ---------------------------------------------------------------------------
# Vetter scenario definition
# ---------------------------------------------------------------------------

SCENARIOS = [
    {
        "org_name": "ACME Inc (Brand Assure)",
        "vetter_name": "Brand Assure",
        "ecc_targets": ["44"],
        "jurisdiction_targets": ["GBR"],
        "tn": "+441923311002",
        "extension": 1002,
        "description": "Authorized UK vetter — should PASS vetter constraints",
    },
    {
        "org_name": "ACME Inc (Deutsche Vetters)",
        "vetter_name": "Deutsche Vetters",
        "ecc_targets": ["49"],
        "jurisdiction_targets": ["DEU"],
        "tn": "+441923311003",
        "extension": 1003,
        "description": "German-only vetter — should FAIL vetter constraints for UK numbers",
    },
]


# ---------------------------------------------------------------------------
# Bootstrap one vetter scenario
# ---------------------------------------------------------------------------

def bootstrap_scenario(base_url, admin_key, scenario, brand_name, brand_logo):
    """Create one complete vetter scenario: org, creds, TN mapping."""
    org_name = scenario["org_name"]
    tn = scenario["tn"]
    print(f"\n{'=' * 60}")
    print(f"  {scenario['vetter_name']}: {scenario['description']}")
    print(f"{'=' * 60}")

    # 1. Create organization (handle existing org gracefully)
    print(f"\n  [1/7] Creating organization '{org_name}'...")
    status, body = api_call(
        "POST", f"{base_url}/organizations",
        data={"name": org_name},
        api_key=admin_key, timeout=120,
    )
    if status == 409:
        # Org already exists — look it up by listing all orgs
        print(f"    Org already exists, looking up...")
        list_status, list_body = api_call("GET", f"{base_url}/organizations?limit=50", api_key=admin_key)
        if list_status == 200:
            orgs = list_body.get("organizations", list_body if isinstance(list_body, list) else [])
            existing = next((o for o in orgs if o.get("name") == org_name), None)
            if existing:
                body = existing
                status = 200
                print(f"    Found existing org")
            else:
                print(f"    FAILED: Could not find existing org by name")
                return None
        else:
            print(f"    FAILED: Could not list orgs ({list_status})")
            return None
    elif status != 200:
        print(f"    FAILED ({status}): {body.get('detail', body)}")
        return None
    org_id = body["id"]
    org_aid = body.get("aid", body.get("identity_aid", ""))
    le_said = body.get("le_credential_said", body.get("le_said", ""))
    identity_name = f"org-{org_id[:8]}"
    registry_name = f"{identity_name}-registry"
    print(f"    Org ID:       {org_id[:16]}...")
    print(f"    Org AID:      {org_aid[:24]}..." if org_aid else "    Org AID:      N/A")
    print(f"    LE SAID:      {le_said[:24]}..." if le_said else "    LE SAID:      N/A")

    # If no AID yet, attempt to resolve it from the KERI agent
    if not org_aid:
        keri_status, keri_body = api_call("GET", f"{base_url}/admin/identities/{identity_name}", api_key=admin_key)
        if keri_status == 200:
            org_aid = keri_body.get("aid", "")
            if org_aid:
                print(f"    Org AID:      {org_aid[:24]}... (from KERI agent)")

    # 2. Create API key
    print(f"\n  [2/7] Creating API key...")
    status, body = api_call(
        "POST", f"{base_url}/organizations/{org_id}/api-keys",
        data={"name": f"{scenario['vetter_name']} Operator Key",
              "roles": ["org:administrator", "org:dossier_manager"]},
        api_key=admin_key,
    )
    if status != 200:
        print(f"    FAILED ({status}): {body.get('detail', body)}")
        return None
    org_api_key = body["raw_key"]
    print(f"    API Key:      {org_api_key}")

    # 3. Issue VetterCertification
    print(f"\n  [3/7] Issuing VetterCert ({scenario['vetter_name']})...")
    print(f"    ECC targets:       {scenario['ecc_targets']}")
    print(f"    Jurisdictions:     {scenario['jurisdiction_targets']}")
    status, body = api_call(
        "POST", f"{base_url}/vetter-certifications",
        data={
            "organization_id": org_id,
            "ecc_targets": scenario["ecc_targets"],
            "jurisdiction_targets": scenario["jurisdiction_targets"],
            "name": f"{scenario['vetter_name']} Certification",
        },
        api_key=admin_key, timeout=120,
    )
    if status == 409:
        # Already has an active VetterCert — fetch it
        print(f"    VetterCert already exists, fetching...")
        list_status, list_body = api_call(
            "GET", f"{base_url}/vetter-certifications?organization_id={org_id}&limit=10",
            api_key=admin_key,
        )
        if list_status == 200:
            certs = list_body.get("certifications", list_body if isinstance(list_body, list) else [])
            active = next((c for c in certs if c.get("status", "active") == "active"), None)
            if not active:
                active = certs[0] if certs else None
            if active:
                body = active
                status = 200
                print(f"    Found existing VetterCert")
            else:
                print(f"    FAILED: No active VetterCert found")
                return None
        else:
            print(f"    FAILED: Cannot list VetterCerts ({list_status})")
            return None
    elif status not in (200, 201):
        print(f"    FAILED ({status}): {body.get('detail', body)}")
        return None
    vetter_cert_said = body.get("said", body.get("credential_said", ""))
    print(f"    VetterCert SAID:   {vetter_cert_said[:24]}...")

    # 4. Issue TN Allocation
    print(f"\n  [4/7] Issuing TN Allocation for {tn}...")
    status, body = api_call(
        "POST", f"{base_url}/credential/issue",
        data={
            "registry_name": registry_name,
            "schema_said": TN_ALLOC_SCHEMA,
            "attributes": {
                "i": org_aid,
                "numbers": {"start": tn, "end": tn},
            },
            "private": True,
            "publish_to_witnesses": True,
        },
        api_key=org_api_key, timeout=120,
    )
    if status != 200:
        print(f"    FAILED ({status}): {body.get('detail', body)}")
        return None
    tnalloc_said = body["credential"]["said"]
    print(f"    TNAlloc SAID:      {tnalloc_said[:24]}...")

    # 5. Issue Brand Credential
    print(f"\n  [5/7] Issuing Brand Credential (brandName: '{brand_name}')...")
    edges = {
        "le": {"n": le_said, "s": LE_SCHEMA},
        "tnAlloc0": {"n": tnalloc_said, "s": TN_ALLOC_SCHEMA},
        "vetterCert": {"n": vetter_cert_said, "s": VETTER_CERT_SCHEMA},
    }
    attributes = {
        "i": org_aid,
        "brandName": brand_name,
        "assertionCountry": "GBR",
    }
    if brand_logo:
        attributes["logoUrl"] = brand_logo
    status, body = api_call(
        "POST", f"{base_url}/credential/issue",
        data={
            "registry_name": registry_name,
            "schema_said": BRAND_SCHEMA,
            "attributes": attributes,
            "edges": edges,
            "rules": {
                "brandUsageTerms": "The brand credential holder agrees to use this brand identity only for legitimate communications."
            },
            "private": True,
            "publish_to_witnesses": True,
        },
        api_key=org_api_key, timeout=120,
    )
    if status != 200:
        print(f"    FAILED ({status}): {body.get('detail', body)}")
        return None
    brand_said = body["credential"]["said"]
    print(f"    Brand SAID:        {brand_said[:24]}...")

    # 6. Create TN mapping
    print(f"\n  [6/7] Creating TN mapping: {tn} → dossier...")
    status, body = api_call(
        "POST", f"{base_url}/tn/mappings",
        data={"tn": tn, "dossier_said": brand_said, "identity_name": identity_name},
        api_key=org_api_key,
    )
    if status == 409:
        # Update existing
        list_status, list_body = api_call("GET", f"{base_url}/tn/mappings", api_key=org_api_key)
        if list_status == 200:
            mappings = list_body.get("mappings", [])
            existing = next((m for m in mappings if m["tn"] == tn), None)
            if existing:
                api_call("PATCH", f"{base_url}/tn/mappings/{existing['id']}",
                         data={"dossier_said": brand_said}, api_key=org_api_key)
                print(f"    Updated existing mapping")
    elif status != 200:
        print(f"    WARNING: TN mapping failed ({status}): {body.get('detail', body)}")

    # Set brand info on mapping
    mapping_id = body.get("id")
    if mapping_id:
        api_call("PATCH", f"{base_url}/tn/mappings/{mapping_id}",
                 data={"brand_name": brand_name, "brand_logo_url": brand_logo or ""},
                 api_key=org_api_key)
    print(f"    TN mapping created")

    # 7. Verify dossier builds
    print(f"\n  [7/7] Verifying dossier build...")
    status, body = api_call(
        "POST", f"{base_url}/dossier/build/info",
        data={"root_said": brand_said, "format": "cesr", "include_tel": True},
        api_key=org_api_key,
    )
    if status == 200:
        dossier = body.get("dossier", {})
        print(f"    Credentials:   {dossier.get('credential_count', '?')}")
        print(f"    Size:          {dossier.get('size_bytes', '?')} bytes")
        if dossier.get("warnings"):
            for w in dossier["warnings"]:
                print(f"    WARNING: {w}")
    else:
        print(f"    WARNING: Dossier build failed ({status})")

    return {
        "org_name": org_name,
        "org_id": org_id,
        "org_aid": org_aid,
        "identity_name": identity_name,
        "api_key": org_api_key,
        "vetter_name": scenario["vetter_name"],
        "ecc_targets": scenario["ecc_targets"],
        "jurisdiction_targets": scenario["jurisdiction_targets"],
        "vetter_cert_said": vetter_cert_said,
        "tnalloc_said": tnalloc_said,
        "brand_said": brand_said,
        "tn": tn,
        "extension": scenario["extension"],
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Bootstrap demo vetter scenarios on VVP Issuer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--url", default="https://vvp-issuer.rcnx.io",
                        help="Issuer base URL")
    parser.add_argument("--admin-key", default="sQO2aE-foISGVUYcY6aj3hhCiXnaE1sRqfaW87hMoeE",
                        help="System admin API key")
    parser.add_argument("--brand-name", default="ACME Inc",
                        help="Brand name for both scenarios")
    parser.add_argument("--brand-logo", default="https://vvp-issuer.rcnx.io/static/brand-logo.png",
                        help="Brand logo URL")
    parser.add_argument("--json-file", default=None,
                        help="Write JSON summary to file")

    args = parser.parse_args()
    base_url = args.url.rstrip("/")

    print("=" * 60)
    print("VVP Demo Vetter Scenarios Bootstrap")
    print("=" * 60)
    print(f"  URL:        {base_url}")
    print(f"  Brand:      {args.brand_name}")
    print(f"  Scenarios:  {len(SCENARIOS)}")

    if not wait_for_health(base_url):
        sys.exit(1)

    # Verify mock vLEI is initialized by checking for existing organizations
    status, body = api_call("GET", f"{base_url}/organizations", api_key=args.admin_key)
    if status != 200:
        print(f"\n  ERROR: Cannot list organizations ({status}). Is mock vLEI initialized?")
        print("  Run bootstrap-issuer.py first.")
        sys.exit(1)
    orgs = body.get("organizations", [])
    print(f"  Existing orgs: {len(orgs)}")

    # Bootstrap each scenario
    results = []
    for scenario in SCENARIOS:
        result = bootstrap_scenario(base_url, args.admin_key, scenario,
                                    args.brand_name, args.brand_logo)
        if result is None:
            print(f"\n  FATAL: Failed to bootstrap {scenario['vetter_name']}")
            sys.exit(1)
        results.append(result)

    # Write JSON summary
    if args.json_file:
        with open(args.json_file, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\nJSON summary written to: {args.json_file}")

    # Print summary and dialplan snippet
    print(f"\n{'=' * 60}")
    print("BOOTSTRAP COMPLETE — SUMMARY")
    print(f"{'=' * 60}")

    for r in results:
        print(f"\n  {r['vetter_name']}:")
        print(f"    Organization:   {r['org_name']}")
        print(f"    API Key:        {r['api_key']}")
        print(f"    TN:             {r['tn']}")
        print(f"    Extension:      {r['extension']}")
        print(f"    ECC Targets:    {r['ecc_targets']}")
        print(f"    Brand SAID:     {r['brand_said'][:24]}...")

    print(f"\n{'=' * 60}")
    print("DIALPLAN SNIPPET — paste into public-sip.xml before vvp-loopback-outbound")
    print(f"{'=' * 60}")

    for r in results:
        ext = r["extension"]
        tn = r["tn"]
        key = r["api_key"]
        name = r["vetter_name"].lower().replace(" ", "-")
        print(f"""
    <!-- {r['vetter_name']} ({', '.join(r['ecc_targets'])}) — ext {ext} -->
    <extension name="vvp-loopback-{name}">
      <condition field="${{sofia_profile_name}}" expression="^(internal)?$"/>
      <condition field="destination_number" expression="^7{ext}$">
        <action application="log" data="INFO [VVP] {r['vetter_name']} loopback to ${{destination_number}}"/>
        <action application="set" data="hangup_after_bridge=true"/>
        <action application="set" data="continue_on_fail=true"/>
        <action application="set" data="bridge_timeout=60"/>
        <action application="set" data="progress_timeout=60"/>
        <action application="set" data="sip_invite_timeout=65"/>
        <action application="set" data="loopback_dest_tn={tn}"/>
        <action application="set" data="effective_caller_id_number={tn}"/>
        <action application="set" data="effective_caller_id_name=VVP {r['vetter_name']}"/>
        <action application="set" data="sip_redirect_context=redirected"/>
        <action application="log" data="INFO [VVP] Routing to signing: {tn} via {r['vetter_name']}"/>
        <action application="bridge" data="[sip_h_X-VVP-API-Key={key},origination_caller_id_number={tn}]sofia/external/${{loopback_dest_tn}}@127.0.0.1:5070"/>
      </condition>
    </extension>""")

    print()


if __name__ == "__main__":
    main()
