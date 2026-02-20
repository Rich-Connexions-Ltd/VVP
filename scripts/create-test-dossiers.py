#!/usr/bin/env python3
"""
Create three test dossiers demonstrating VVP Phase 1 and Phase 2 credential chains.

Dossier 1 - Phase 1: Full branded call, org-asserted brand, VetterCert not explicitly linked
  - New org "Phase 1 Branded Co"
  - VetterCert required by issuer (broad ecc=['44','1']), but NOT added as explicit vetterCert edge
  - Extended Brand with le + tnAlloc edges only (no explicit vetterCert edge)
  - The VetterCert is reachable only via auto-injected 'certification' edge
  - X-VVP-Vetter-Status: PASS (broad ecc covers +44) or INDETERMINATE
  - TN: +441923311001

Dossier 2 - Phase 2a: VetterCert with correct +44 ECC target, explicitly linked
  - New org "Phase 2a UK Ltd"
  - VetterCert with ecc_targets=["44"] (UK E.164 country code)
  - Extended Brand with le + tnAlloc + explicit vetterCert edges
  - X-VVP-Vetter-Status: PASS (44 in ecc_targets)
  - TN: +441923311002

Dossier 3 - Phase 2b: VetterCert with WRONG ECC target (US only, no +44), explicitly linked
  - New org "Phase 2b US Ltd"
  - VetterCert with ecc_targets=["1"] (US only — no +44)
  - Extended Brand with le + tnAlloc + explicit vetterCert edges
  - X-VVP-Vetter-Status: FAIL-ECC (44 not in ecc_targets)
  - TN: +441923311003

Header distinction:
  Phase 1:  X-VVP-Status=VALID, X-VVP-Brand-Name=<brand>, X-VVP-Vetter-Status=PASS/INDETERMINATE
  Phase 2a: X-VVP-Status=VALID, X-VVP-Brand-Name=<brand>, X-VVP-Vetter-Status=PASS
  Phase 2b: X-VVP-Status=VALID, X-VVP-Brand-Name=<brand>, X-VVP-Vetter-Status=FAIL-ECC

Note: ENFORCE_VETTER_CONSTRAINTS=false (default) means all three return VALID overall status.
  The X-VVP-Vetter-Status header shows the constraint result independently.

Usage:
    python3 scripts/create-test-dossiers.py --admin-key <key> [--base-url https://vvp-issuer.rcnx.io]
"""

import argparse
import datetime
import json
import sys
import time
import urllib.request
import urllib.error

BASE_URL = "https://vvp-issuer.rcnx.io"

BRAND_SCHEMA = "EK7kPhs5YkPsq9mZgUfPYfU-zq5iSlU8XVYJWqrVPk6g"   # Extended Brand
TN_ALLOC_SCHEMA = "EFvnoHDY7I-kaBBeKlbDbkjG4BaI0nKLGadxBdjMGgSQ"  # TNAlloc (base)
LE_SCHEMA = "ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY"         # LE
VETTER_CERT_SCHEMA = "EOefmhWU2qTpMiEQhXohE6z3xRXkpLloZdhTYIenlD4H"  # VetterCert

BRAND_LOGO_URL = "https://vvp-issuer.rcnx.io/static/brand-logo.png"


def api_call(method, url, data=None, api_key=None, timeout=60):
    """Make an API call and return (status_code, response_body)."""
    body = json.dumps(data).encode() if data else None
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if api_key:
        headers["X-API-Key"] = api_key
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        try:
            err_body = json.loads(e.read())
        except Exception:
            err_body = {"detail": str(e)}
        return e.code, err_body


def create_org(base_url, admin_key, name):
    """Create a new organization (or return existing if already created). Returns org dict."""
    print(f"\n  Creating org '{name}'...")
    status, body = api_call("POST", f"{base_url}/organizations", {"name": name}, admin_key, timeout=120)
    if status == 409:
        # Already exists — fetch existing
        print(f"  (org already exists, fetching...)")
        s2, orgs = api_call("GET", f"{base_url}/organizations", api_key=admin_key, timeout=30)
        for o in orgs.get("organizations", []):
            if o["name"] == name:
                print(f"  OK  org_id={o['id'][:8]}... aid={o['aid'][:20]}...")
                return o
        print(f"  ERROR: Could not find existing org '{name}'")
        sys.exit(1)
    if status != 200:
        print(f"  ERROR: {status} — {body.get('detail', body)}")
        sys.exit(1)
    org = body
    print(f"  OK  org_id={org['id'][:8]}... aid={org['aid'][:20]}...")
    print(f"       le_credential_said={org['le_credential_said'][:20]}...")
    print(f"       registry_key={org['registry_key'][:20]}...")
    return org


def issue_vetter_cert(base_url, admin_key, org_id, name, ecc_targets, jurisdiction_targets):
    """Issue a VetterCertification for the org. Returns SAID (reuses existing if present)."""
    print(f"\n  Issuing VetterCert for org {org_id[:8]}... ecc={ecc_targets}...")
    status, body = api_call("POST", f"{base_url}/vetter-certifications", {
        "organization_id": org_id,
        "ecc_targets": ecc_targets,
        "jurisdiction_targets": jurisdiction_targets,
        "name": name,
    }, admin_key, timeout=120)
    if status == 409:
        # Already has active VetterCert — fetch it
        print(f"  (VetterCert already exists, fetching...)")
        s2, body2 = api_call("GET", f"{base_url}/vetter-certifications?organization_id={org_id}",
                              api_key=admin_key, timeout=30)
        certs = body2.get("certifications", [])
        if certs:
            said = certs[0]["said"]
            print(f"  OK  (existing) VetterCert SAID={said[:20]}... ecc={certs[0].get('ecc_targets')}")
            return said
        print(f"  ERROR: Could not find existing VetterCert for org {org_id[:8]}")
        sys.exit(1)
    if status != 200:
        print(f"  ERROR: {status} — {body.get('detail', body)}")
        sys.exit(1)
    said = body.get("said") or body.get("certification", {}).get("said")
    print(f"  OK  VetterCert SAID={said[:20]}...")
    return said


def issue_tn_alloc(base_url, org_api_key, org_aid, registry_name, tn_numbers):
    """Issue a base TNAlloc credential. Returns SAID."""
    print(f"\n  Issuing TNAlloc for {tn_numbers}...")
    dt = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    status, body = api_call("POST", f"{base_url}/credential/issue", {
        "registry_name": registry_name,
        "schema_said": TN_ALLOC_SCHEMA,
        "recipient_aid": org_aid,
        "attributes": {
            "i": org_aid,   # Issuee AID — required for TN rights verification
            "numbers": tn_numbers,
            "dt": dt,
        },
        "publish_to_witnesses": True,
    }, org_api_key, timeout=120)
    if status != 200:
        print(f"  ERROR: {status} — {body.get('detail', body)}")
        sys.exit(1)
    said = body["credential"]["said"]
    print(f"  OK  TNAlloc SAID={said[:20]}...")
    return said


def issue_extended_brand(base_url, org_api_key, org_aid, registry_name,
                          le_said, tnalloc_said, brand_name, vetter_cert_said=None,
                          explicit_vetter_edge=True):
    """Issue an Extended Brand credential. Returns SAID."""
    print(f"\n  Issuing Extended Brand for '{brand_name}'...")
    if vetter_cert_said and explicit_vetter_edge:
        print(f"       vetterCert (explicit edge)={vetter_cert_said[:20]}...")
    elif vetter_cert_said:
        print(f"       vetterCert required (auto-inject only, no explicit edge)")
    else:
        print(f"       No vetterCert")

    edges = {
        "le": {"n": le_said, "s": LE_SCHEMA},
        "tnAlloc0": {"n": tnalloc_said, "s": TN_ALLOC_SCHEMA},
    }
    if vetter_cert_said and explicit_vetter_edge:
        edges["vetterCert"] = {"n": vetter_cert_said, "s": VETTER_CERT_SCHEMA}

    dt = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    status, body = api_call("POST", f"{base_url}/credential/issue", {
        "registry_name": registry_name,
        "schema_said": BRAND_SCHEMA,
        "issuee_aid": org_aid,
        "attributes": {
            "i": org_aid,
            "brandName": brand_name,
            "assertionCountry": "GBR",
            "logoUrl": BRAND_LOGO_URL,
            "dt": dt,
        },
        "edges": edges,
        "rules": {
            "brandUsageTerms": "Brand credential for VVP test dossier demonstration."
        },
        "publish_to_witnesses": True,
    }, org_api_key, timeout=120)
    if status != 200:
        print(f"  ERROR: {status} — {body.get('detail', body)}")
        sys.exit(1)
    said = body["credential"]["said"]
    print(f"  OK  Brand SAID={said[:20]}...")
    return said


def verify_dossier(base_url, org_api_key, root_said):
    """Verify dossier builds correctly. Returns dossier info dict."""
    print(f"\n  Verifying dossier {root_said[:20]}...")
    status, body = api_call("POST", f"{base_url}/dossier/build/info", {
        "root_said": root_said,
    }, org_api_key, timeout=60)
    if status != 200:
        print(f"  WARNING: {status} — {body.get('detail', body)}")
        return None
    dossier = body.get("dossier", {})
    print(f"  OK  credentials={dossier['credential_count']} size={dossier['size_bytes']}B format={dossier['format']}")
    if dossier.get("warnings"):
        for w in dossier["warnings"]:
            print(f"  WARN: {w}")
    return dossier


def create_api_key(base_url, admin_key, org_id, label, roles):
    """Create an org API key for issuing credentials as that org. Returns key."""
    print(f"\n  Creating API key for org {org_id[:8]}...")
    status, body = api_call("POST", f"{base_url}/organizations/{org_id}/api-keys", {
        "name": label,
        "roles": roles,
    }, admin_key, timeout=30)
    if status != 200:
        print(f"  ERROR: {status} — {body.get('detail', body)}")
        sys.exit(1)
    key = body.get("raw_key") or body.get("key")
    print(f"  OK  key={key[:12]}...")
    return key


def create_tn_mapping(base_url, org_api_key, tn, dossier_said, identity_name, brand_name):
    """Create a TN mapping, replacing any existing mapping for this TN. Returns mapping dict."""
    print(f"\n  Creating TN mapping {tn} → dossier {dossier_said[:20]}...")
    # Check for existing mapping and delete it first
    import urllib.parse
    s, existing = api_call("GET", f"{base_url}/tn/mappings?tn={urllib.parse.quote(tn)}", api_key=org_api_key, timeout=30)
    if s == 200:
        for m in existing.get("mappings", []):
            mid = m["id"]
            sd, db = api_call("DELETE", f"{base_url}/tn/mappings/{mid}", api_key=org_api_key, timeout=30)
            print(f"  Deleted existing TN mapping {mid[:8]}...")
    status, body = api_call("POST", f"{base_url}/tn/mappings", {
        "tn": tn,
        "dossier_said": dossier_said,
        "identity_name": identity_name,
    }, org_api_key, timeout=30)
    if status not in (200, 201):
        print(f"  ERROR: {status} — {body.get('detail', body)}")
        sys.exit(1)
    print(f"  OK  TN mapping created → dossier {dossier_said[:20]}...")
    return body


def create_dossier(base_url, admin_key, org_name, tn, vetter_ecc=None,
                   vetter_jurisdiction=None, explicit_vetter_edge=True):
    """
    Create a complete dossier for a new org.

    Args:
        vetter_ecc: ECC targets for VetterCert. Extended Brand always requires a VetterCert.
        explicit_vetter_edge: If True, adds explicit vetterCert edge to brand credential
                              (Phase 2 behavior). If False, omits the vetterCert edge
                              so only the auto-injected certification edge links to VetterCert
                              (Phase 1 behavior).
    """
    print(f"\n{'='*60}")
    print(f"  Setting up: {org_name}")
    print(f"  TN: {tn}")
    print(f"  VetterCert ECC: {vetter_ecc or 'none (Phase 1)'}")
    print(f"{'='*60}")

    # Step 1: Create org (auto-creates LE credential via mock-QVI)
    org = create_org(base_url, admin_key, org_name)
    org_id = org["id"]
    org_aid = org["aid"]
    le_said = org["le_credential_said"]
    registry_name = f"org-{org_id[:8]}-registry"
    identity_name = f"org-{org_id[:8]}"

    # Step 2: Create org API key for credential issuance
    org_api_key = create_api_key(base_url, admin_key, org_id, f"{org_name} API Key",
                                  ["org:administrator", "org:dossier_manager"])

    # Step 3: Issue VetterCert (always required for Extended Brand in this issuer)
    vetter_cert_said = None
    if vetter_ecc:
        vetter_cert_said = issue_vetter_cert(
            base_url, admin_key, org_id,
            f"{org_name} Vetter Certification",
            vetter_ecc,
            vetter_jurisdiction or ["GBR"],
        )
        # Wait for KERI Agent to process
        time.sleep(2)

    # Step 4: Issue TNAlloc for the test TN plus the callee TN (+441923311006).
    # The verifier's /verify-callee checks if the caller's dossier TNAlloc covers
    # the destination TN (callee TN rights §5B). Include both origin and callee TNs.
    callee_tn = "+441923311006"
    tn_numbers = [tn] if tn == callee_tn else [tn, callee_tn]
    tnalloc_said = issue_tn_alloc(base_url, org_api_key, org_aid, registry_name, tn_numbers)

    # Step 5: Issue Extended Brand (dossier root)
    brand_name = org_name
    brand_said = issue_extended_brand(
        base_url, org_api_key, org_aid, registry_name,
        le_said, tnalloc_said, brand_name, vetter_cert_said,
        explicit_vetter_edge=explicit_vetter_edge,
    )

    # Step 6: Verify dossier builds
    dossier_info = verify_dossier(base_url, org_api_key, brand_said)

    # Step 7: Create TN mapping
    create_tn_mapping(base_url, org_api_key, tn, brand_said, identity_name, brand_name)

    result = {
        "org_name": org_name,
        "org_id": org_id,
        "org_aid": org_aid,
        "le_said": le_said,
        "vetter_cert_said": vetter_cert_said,
        "vetter_ecc": vetter_ecc,
        "explicit_vetter_edge": explicit_vetter_edge,
        "tnalloc_said": tnalloc_said,
        "brand_said": brand_said,
        "dossier_root_said": brand_said,
        "identity_name": identity_name,
        "tn": tn,
        "credential_count": dossier_info.get("credential_count") if dossier_info else None,
        "dossier_size_bytes": dossier_info.get("size_bytes") if dossier_info else None,
    }

    print(f"\n  DONE: {org_name}")
    print(f"  Dossier root: {brand_said}")
    print(f"  TN:           {tn}")
    print(f"  Identity:     {identity_name}")
    return result


def main():
    parser = argparse.ArgumentParser(description="Create three VVP test dossiers")
    parser.add_argument("--admin-key", required=True, help="Issuer admin API key")
    parser.add_argument("--base-url", default=BASE_URL, help="Issuer base URL")
    args = parser.parse_args()

    base_url = args.base_url.rstrip("/")
    admin_key = args.admin_key

    results = {}

    # -------------------------------------------------------------------------
    # Dossier 1 — Phase 1: Full branded call, VetterCert required but NOT
    #   explicitly linked as vetterCert edge on brand credential.
    #   VetterCert uses broad ecc (covers +44) so constraint is trivially met.
    #   X-VVP-Vetter-Status shows the auto-injected certification edge result.
    # -------------------------------------------------------------------------
    results["phase1"] = create_dossier(
        base_url, admin_key,
        org_name="Phase 1 Branded Co",
        tn="+441923311001",
        vetter_ecc=["44", "1"],      # Broad ECC (required by Extended Brand issuer)
        vetter_jurisdiction=["GBR", "USA"],
        explicit_vetter_edge=False,  # Phase 1: no explicit vetterCert edge
    )

    # -------------------------------------------------------------------------
    # Dossier 2 — Phase 2a: VetterCert with CORRECT +44 ECC target, explicitly linked
    # -------------------------------------------------------------------------
    results["phase2a"] = create_dossier(
        base_url, admin_key,
        org_name="Phase 2a UK Ltd",
        tn="+441923311002",
        vetter_ecc=["44"],           # UK E.164 country code only
        vetter_jurisdiction=["GBR"],  # Great Britain
        explicit_vetter_edge=True,   # Phase 2: explicit vetterCert edge
    )

    # -------------------------------------------------------------------------
    # Dossier 3 — Phase 2b: VetterCert with WRONG ECC (US only, no +44), explicitly linked
    # -------------------------------------------------------------------------
    results["phase2b"] = create_dossier(
        base_url, admin_key,
        org_name="Phase 2b US Ltd",
        tn="+441923311003",
        vetter_ecc=["1"],            # US only — does NOT cover +44
        vetter_jurisdiction=["USA"],  # United States
        explicit_vetter_edge=True,   # Phase 2: explicit vetterCert edge
    )

    # -------------------------------------------------------------------------
    # Summary
    # -------------------------------------------------------------------------
    print(f"\n{'='*60}")
    print("  SUMMARY")
    print(f"{'='*60}")
    for key, r in results.items():
        print(f"\n  [{key}] {r['org_name']}")
        print(f"    TN:             {r['tn']}")
        print(f"    VetterCert ECC: {r['vetter_ecc'] or 'none'}")
        print(f"    Dossier root:   {r['dossier_root_said'][:40]}...")
        print(f"    Identity:       {r['identity_name']}")
        print(f"    Credentials:    {r['credential_count']}")

    print("\n  To test via SIP call:")
    for key, r in results.items():
        tn = r['tn']
        org_underscore = r['org_name'].replace(' ', '_')
        cmd = (f"fs_cli -x 'originate {{origination_caller_id_number={tn},"
               f"origination_caller_id_name={org_underscore},"
               f"ignore_early_media=true}}loopback/71006/default &sleep(3)'")
        print(f"\n  [{key}] {r['org_name']} — TN {tn}:")
        print(f"    {cmd}")

    # Write results to JSON
    out = "scripts/test-dossiers-result.json"
    with open(out, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n  Results saved to {out}")


if __name__ == "__main__":
    main()
