#!/usr/bin/env python3
"""Bootstrap the VVP Issuer with test data.

Re-initializes mock vLEI infrastructure and creates a complete test
environment with organization, API keys, credentials, and TN mappings.

Usage:
    python3 scripts/bootstrap-issuer.py [--url URL] [--admin-key KEY] [--org-name NAME]

    Defaults:
        --url         https://vvp-issuer.rcnx.io
        --admin-key   sQO2aE-foISGVUYcY6aj3hhCiXnaE1sRqfaW87hMoeE
        --org-name    ACME Inc
        --tn          +15551001006
        --brand-name  ACME Inc
        --brand-logo  https://vvp-issuer.rcnx.io/static/brand-logo.png
        --skip-reinit Skip mock vLEI re-initialization (add to existing state)

Steps:
    1. POST /admin/mock-vlei/reinitialize  (clear stale state, rebuild mock GLEIF/QVI)
    2. POST /organizations                 (create org with LE credential)
    3. POST /organizations/{id}/api-keys   (create org API key)
    4. POST /tn/mappings                   (create TN mapping with brand info)
    5. POST /dossier/build/info            (verify dossier builds correctly)
    6. Print summary with all credentials and keys
"""

import argparse
import json
import sys
import time
import urllib.error
import urllib.request


# ---------------------------------------------------------------------------
# HTTP helpers (stdlib only, no external deps)
# ---------------------------------------------------------------------------

def api_call(method, url, data=None, api_key=None, timeout=60):
    """Make an HTTP API call and return parsed JSON response.

    Args:
        method: HTTP method (GET, POST, etc.)
        url: Full URL to call
        data: Dict to send as JSON body (POST/PATCH)
        api_key: API key for X-API-Key header
        timeout: Request timeout in seconds

    Returns:
        Tuple of (status_code, response_dict)
    """
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["X-API-Key"] = api_key

    body = json.dumps(data).encode() if data else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            resp_body = resp.read().decode()
            return resp.status, json.loads(resp_body) if resp_body else {}
    except urllib.error.HTTPError as e:
        resp_body = e.read().decode() if e.fp else ""
        try:
            detail = json.loads(resp_body)
        except (json.JSONDecodeError, ValueError):
            detail = {"detail": resp_body}
        return e.code, detail


def wait_for_health(base_url, timeout=120):
    """Wait for the issuer to be healthy."""
    print(f"  Waiting for issuer at {base_url}/healthz ...")
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            status, body = api_call("GET", f"{base_url}/healthz")
            if status == 200 and (body.get("ok") or body.get("status") == "ok"):
                keri = body.get("keri_agent", "?")
                print(f"  Issuer healthy (database={body.get('database', '?')}, keri_agent={keri})")
                return True
        except Exception:
            pass
        time.sleep(2)
    print("  ERROR: Issuer did not become healthy within timeout")
    return False


# ---------------------------------------------------------------------------
# Bootstrap steps
# ---------------------------------------------------------------------------

def step_reinitialize(base_url, admin_key):
    """Step 1: Re-initialize mock vLEI infrastructure."""
    print("\n[1/6] Re-initializing mock vLEI infrastructure...")
    status, body = api_call(
        "POST",
        f"{base_url}/admin/mock-vlei/reinitialize",
        api_key=admin_key,
        timeout=120,  # KERI identity creation can be slow
    )
    if status != 200 or not body.get("success"):
        print(f"  FAILED ({status}): {body.get('message', body.get('detail', body))}")
        return None
    print(f"  Tables cleared: {body['tables_cleared']}")
    print(f"  Mock GLEIF AID: {body['gleif_aid']}")
    print(f"  Mock QVI AID:   {body['qvi_aid']}")
    print(f"  QVI Credential: {body['qvi_credential_said']}")
    return body


def step_find_or_create_org(base_url, admin_key, org_name):
    """Step 2: Find existing org by name or create a new one."""
    # Try to find existing org with this name
    status, body = api_call("GET", f"{base_url}/organizations", api_key=admin_key)
    if status == 200:
        orgs = body.get("organizations", [])
        for org in orgs:
            if org.get("name") == org_name and org.get("org_type", "regular") == "regular":
                print(f"\n[2/6] Found existing organization '{org_name}'")
                org["_identity_name"] = f"org-{org['id'][:8]}"
                print(f"  Org ID:         {org['id']}")
                print(f"  Org AID:        {org.get('aid', 'N/A')}")
                return org

    return step_create_org(base_url, admin_key, org_name)


def step_create_org(base_url, admin_key, org_name):
    """Step 2: Create organization with LE credential."""
    print(f"\n[2/6] Creating organization '{org_name}'...")
    status, body = api_call(
        "POST",
        f"{base_url}/organizations",
        data={"name": org_name},
        api_key=admin_key,
        timeout=120,
    )
    if status != 200:
        print(f"  FAILED ({status}): {body.get('detail', body)}")
        return None
    org_id = body["id"]
    identity_name = f"org-{org_id[:8]}"
    print(f"  Org ID:         {org_id}")
    print(f"  Pseudo-LEI:     {body['pseudo_lei']}")
    print(f"  Org AID:        {body.get('aid', 'N/A')}")
    print(f"  LE Credential:  {body.get('le_credential_said', 'N/A')}")
    print(f"  Identity Name:  {identity_name}")
    print(f"  Registry Key:   {body.get('registry_key', 'N/A')}")
    body["_identity_name"] = identity_name
    return body


def step_create_api_key(base_url, admin_key, org_id):
    """Step 3: Create organization API key."""
    print(f"\n[3/6] Creating organization API key...")
    status, body = api_call(
        "POST",
        f"{base_url}/organizations/{org_id}/api-keys",
        data={
            "name": "Bootstrap Operator Key",
            "roles": ["org:administrator", "org:dossier_manager"],
        },
        api_key=admin_key,
    )
    if status != 200:
        print(f"  FAILED ({status}): {body.get('detail', body)}")
        return None
    print(f"  Key ID:   {body['id']}")
    print(f"  Key Name: {body['name']}")
    print(f"  Roles:    {body['roles']}")
    print(f"  Raw Key:  {body['raw_key']}")
    return body


def step_issue_vetter_certification(base_url, admin_key, org_id):
    """Step 3a: Issue VetterCertification for the test org.

    Sprint 61: Issues a VetterCertification credential via the dedicated API.
    This associates the org with GSMA vetter constraints (ECC + jurisdiction).
    """
    print("\n[3a/6] Issuing VetterCertification...")

    status, body = api_call(
        "POST",
        f"{base_url}/vetter-certifications",
        data={
            "organization_id": org_id,
            "ecc_targets": ["44", "1"],
            "jurisdiction_targets": ["GBR", "USA"],
            "name": "ACME Inc Vetter Certification",
        },
        api_key=admin_key,
        timeout=120,
    )

    if status == 409:
        print("  Already has active VetterCertification (skipping)")
        return None

    if status not in (200, 201):
        print(f"  WARNING: Failed to issue VetterCertification ({status}): {body}")
        return None

    print(f"  VetterCert SAID: {body['said'][:24]}...")
    print(f"  ECC targets:     {body.get('ecc_targets', [])}")
    print(f"  Jurisdictions:   {body.get('jurisdiction_targets', [])}")
    return body


def step_issue_tn_allocation(base_url, org_api_key, org_aid, registry_name, tn_ranges):
    """Step 3b: Issue TN Allocation credentials for ownership validation.

    The TN lookup endpoint validates that TNs are covered by a TN Allocation
    credential before allowing VVP attestation.
    """
    TN_ALLOC_SCHEMA = "EFvnoHDY7I-kaBBeKlbDbkjG4BaI0nKLGadxBdjMGgSQ"
    print(f"\n[4/6] Issuing TN Allocation credentials ({len(tn_ranges)} ranges)...")

    results = []
    for tn_range in tn_ranges:
        status, body = api_call(
            "POST",
            f"{base_url}/credential/issue",
            data={
                "registry_name": registry_name,
                "schema_said": TN_ALLOC_SCHEMA,
                "attributes": {
                    "i": org_aid,
                    "numbers": tn_range,
                },
                "publish_to_witnesses": True,
            },
            api_key=org_api_key,
            timeout=120,
        )
        if status != 200:
            print(f"  WARNING: Failed to issue TN allocation ({status}): {body.get('detail', body)}")
            continue
        cred = body["credential"]
        print(f"  TN Allocation: {cred['said'][:24]}... (range: {tn_range})")
        results.append(cred)

    return results


def step_issue_brand_credential(base_url, org_api_key, org_aid, registry_name,
                                 le_said, brand_name, brand_logo_url,
                                 tnalloc_saids=None):
    """Step 3c: Issue Extended Brand Credential linked to LE + TNAlloc credentials.

    Sprint 60: The brand credential carries brand identity (name, logo, etc.)
    and becomes the dossier root. The dossier builder DFS walks edges:
    brand → LE → QVI, brand → TNAlloc0, brand → TNAlloc1, giving the verifier
    the full credential chain including brand evidence and TN rights.
    """
    BRAND_SCHEMA = "EK7kPhs5YkPsq9mZgUfPYfU-zq5iSlU8XVYJWqrVPk6g"
    LE_SCHEMA = "ENPXp1vQzRF6JwIuS-mp2U8Uf1MKAIuPchgRiMCe48Mb"
    TN_ALLOC_SCHEMA = "EFvnoHDY7I-kaBBeKlbDbkjG4BaI0nKLGadxBdjMGgSQ"

    print(f"\n[4a/6] Issuing Extended Brand Credential...")
    print(f"  Brand Name:     {brand_name}")
    print(f"  Logo URL:       {brand_logo_url}")

    attributes = {
        "i": org_aid,
        "brandName": brand_name,
        "assertionCountry": "GBR",
    }
    if brand_logo_url:
        attributes["logoUrl"] = brand_logo_url

    # Build edges: LE (required) + TNAlloc credentials (for TN rights in dossier)
    edges = {
        "le": {
            "n": le_said,
            "s": LE_SCHEMA,
        }
    }
    if tnalloc_saids:
        for i, said in enumerate(tnalloc_saids):
            edges[f"tnAlloc{i}"] = {
                "n": said,
                "s": TN_ALLOC_SCHEMA,
            }
        print(f"  TNAlloc edges:  {len(tnalloc_saids)} credentials linked")

    status, body = api_call(
        "POST",
        f"{base_url}/credential/issue",
        data={
            "registry_name": registry_name,
            "schema_said": BRAND_SCHEMA,
            "attributes": attributes,
            "edges": edges,
            "rules": {
                "brandUsageTerms": "The brand credential holder agrees to use this brand identity only for legitimate communications and in accordance with the brand owner's guidelines and applicable regulations."
            },
            "publish_to_witnesses": True,
        },
        api_key=org_api_key,
        timeout=120,
    )
    if status != 200:
        print(f"  WARNING: Failed to issue brand credential ({status}): {body.get('detail', body)}")
        return None

    cred = body["credential"]
    brand_said = cred["said"]
    print(f"  Brand Credential: {brand_said[:24]}...")
    print(f"  Schema:           {BRAND_SCHEMA[:24]}...")
    return brand_said


def step_create_tn_mapping(base_url, org_api_key, tn, dossier_said, identity_name,
                           brand_name, brand_logo_url):
    """Step 4: Create TN mapping (idempotent — updates existing if already mapped)."""
    print(f"\n[5/6] Creating TN mapping for {tn}...")
    status, body = api_call(
        "POST",
        f"{base_url}/tn/mappings",
        data={
            "tn": tn,
            "dossier_said": dossier_said,
            "identity_name": identity_name,
        },
        api_key=org_api_key,
    )

    if status == 409:
        # TN already mapped — find existing mapping and update its dossier_said
        print(f"  TN already mapped — updating existing mapping...")
        list_status, list_body = api_call(
            "GET",
            f"{base_url}/tn/mappings",
            api_key=org_api_key,
        )
        if list_status != 200:
            print(f"  FAILED to list mappings ({list_status}): {list_body}")
            return None
        mappings = list_body.get("mappings", [])
        existing = next((m for m in mappings if m["tn"] == tn), None)
        if not existing:
            print(f"  FAILED: TN {tn} not found in mapping list despite 409")
            return None
        status, body = api_call(
            "PATCH",
            f"{base_url}/tn/mappings/{existing['id']}",
            data={"dossier_said": dossier_said},
            api_key=org_api_key,
        )
        if status != 200:
            print(f"  FAILED to update existing mapping ({status}): {body}")
            return None
        print(f"  Updated existing mapping: {existing['id'][:16]}...")

    elif status != 200:
        print(f"  FAILED ({status}): {body.get('detail', body)}")
        return None

    mapping_id = body["id"]
    print(f"  Mapping ID:     {mapping_id}")
    print(f"  TN:             {body['tn']}")
    print(f"  Dossier SAID:   {body['dossier_said'][:24]}...")
    print(f"  Identity:       {body['identity_name']}")

    # Update with brand info overrides
    if brand_name or brand_logo_url:
        update_data = {}
        if brand_name:
            update_data["brand_name"] = brand_name
        if brand_logo_url:
            update_data["brand_logo_url"] = brand_logo_url

        status2, body2 = api_call(
            "PATCH",
            f"{base_url}/tn/mappings/{mapping_id}",
            data=update_data,
            api_key=org_api_key,
        )
        if status2 == 200:
            print(f"  Brand Name:     {body2.get('brand_name', 'N/A')}")
            print(f"  Brand Logo:     {body2.get('brand_logo_url', 'N/A')}")
        else:
            print(f"  WARNING: Failed to set brand info ({status2})")

    return body


def step_verify_dossier(base_url, org_api_key, dossier_said):
    """Step 5: Verify dossier builds correctly."""
    print(f"\n[6/6] Verifying dossier build...")
    status, body = api_call(
        "POST",
        f"{base_url}/dossier/build/info",
        data={
            "root_said": dossier_said,
            "format": "cesr",
            "include_tel": True,
        },
        api_key=org_api_key,
    )
    if status != 200:
        print(f"  WARNING: Dossier build failed ({status}): {body.get('detail', body)}")
        return None
    dossier = body.get("dossier", {})
    print(f"  Root SAID:       {dossier.get('root_said', 'N/A')}")
    print(f"  Credential Count:{dossier.get('credential_count', '?')}")
    print(f"  Format:          {dossier.get('format', '?')}")
    print(f"  Size:            {dossier.get('size_bytes', '?')} bytes")
    if dossier.get("warnings"):
        for w in dossier["warnings"]:
            print(f"  WARNING: {w}")
    return body


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Bootstrap VVP Issuer with test data",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--url",
        default="https://vvp-issuer.rcnx.io",
        help="Issuer base URL (default: https://vvp-issuer.rcnx.io)",
    )
    parser.add_argument(
        "--admin-key",
        default="sQO2aE-foISGVUYcY6aj3hhCiXnaE1sRqfaW87hMoeE",
        help="System admin API key (issuer:admin role)",
    )
    parser.add_argument(
        "--org-name",
        default="ACME Inc",
        help="Organization name to create (default: ACME Inc)",
    )
    parser.add_argument(
        "--tn",
        default="+15551001006",
        help="Test telephone number for TN mapping (default: +15551001006)",
    )
    parser.add_argument(
        "--brand-name",
        default="ACME Inc",
        help="Brand name for TN mapping (default: ACME Inc)",
    )
    parser.add_argument(
        "--brand-logo",
        default="https://vvp-issuer.rcnx.io/static/brand-logo.png",
        help="Brand logo URL for TN mapping",
    )
    parser.add_argument(
        "--skip-reinit",
        action="store_true",
        help="Skip mock vLEI re-initialization (use existing state)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Output final summary as JSON (to stdout, replaces human-readable output)",
    )
    parser.add_argument(
        "--json-file",
        dest="json_file",
        default=None,
        help="Write JSON summary to this file (human-readable output still shown)",
    )

    args = parser.parse_args()
    base_url = args.url.rstrip("/")

    print("=" * 60)
    print("VVP Issuer Bootstrap")
    print("=" * 60)
    print(f"  URL:       {base_url}")
    print(f"  Org Name:  {args.org_name}")
    print(f"  Test TN:   {args.tn}")

    # Health check
    if not wait_for_health(base_url):
        sys.exit(1)

    # Step 1: Re-initialize mock vLEI
    vlei_state = None
    if not args.skip_reinit:
        vlei_state = step_reinitialize(base_url, args.admin_key)
        if vlei_state is None:
            print("\nFATAL: Mock vLEI re-initialization failed")
            sys.exit(1)
    else:
        print("\n[1/6] Skipping mock vLEI re-initialization (--skip-reinit)")

    # Step 2: Create organization (find existing if --skip-reinit, else create fresh)
    if args.skip_reinit:
        org = step_find_or_create_org(base_url, args.admin_key, args.org_name)
    else:
        org = step_create_org(base_url, args.admin_key, args.org_name)
    if org is None:
        print("\nFATAL: Organization creation failed")
        sys.exit(1)

    org_id = org["id"]
    le_said = org.get("le_credential_said", "")
    identity_name = org["_identity_name"]

    # Step 3: Create org API key
    key_resp = step_create_api_key(base_url, args.admin_key, org_id)
    if key_resp is None:
        print("\nFATAL: API key creation failed")
        sys.exit(1)

    org_api_key = key_resp["raw_key"]
    org_aid = org.get("aid", "")
    registry_name = f"{identity_name}-registry"

    # Step 3a: Issue VetterCertification
    vetter_cert = step_issue_vetter_certification(base_url, args.admin_key, org_id)

    # Step 3b: Issue TN Allocation credentials (before brand, so SAIDs can be linked)
    tn_ranges = [
        {"start": "+441923311000", "end": "+441923311099"},  # UK test range
        {"start": "+15551001000", "end": "+15551001099"},    # US test range
    ]
    tnalloc_results = []
    if org_aid:
        tnalloc_results = step_issue_tn_allocation(
            base_url, org_api_key, org_aid, registry_name, tn_ranges,
        )

    # Step 3c: Issue brand credential with edges to LE + TNAlloc credentials
    brand_said = None
    tnalloc_saids = [r["said"] for r in tnalloc_results] if tnalloc_results else None
    if le_said and org_aid:
        brand_said = step_issue_brand_credential(
            base_url, org_api_key, org_aid, registry_name,
            le_said, args.brand_name, args.brand_logo,
            tnalloc_saids=tnalloc_saids,
        )

    # Sprint 60: Use brand credential as dossier root (brand → LE → QVI chain).
    # Falls back to LE credential if brand credential wasn't created.
    dossier_root_said = brand_said or le_said

    # Step 4: Create TN mappings (uses org API key for org context)
    tn_mapping = None
    if dossier_root_said:
        tn_mapping = step_create_tn_mapping(
            base_url, org_api_key, args.tn, dossier_root_said, identity_name,
            args.brand_name, args.brand_logo,
        )
        # Also create TN mappings for PBX loopback PSTN numbers
        uk_tn_mappings = ["+441923311000", "+441923311006"]
        for uk_tn in uk_tn_mappings:
            if uk_tn != args.tn:
                step_create_tn_mapping(
                    base_url, org_api_key, uk_tn, dossier_root_said, identity_name,
                    args.brand_name, args.brand_logo,
                )
    else:
        print("\n[5/6] Skipping TN mapping (no dossier root credential)")

    # Step 5: Verify dossier (from brand root)
    dossier_info = None
    if dossier_root_said:
        dossier_info = step_verify_dossier(base_url, org_api_key, dossier_root_said)
    else:
        print("\n[6/6] Skipping dossier verification (no LE credential SAID)")

    # Summary
    summary = {
        "issuer_url": base_url,
        "admin_key": args.admin_key,
        "mock_vlei": {
            "gleif_aid": vlei_state["gleif_aid"] if vlei_state else None,
            "qvi_aid": vlei_state["qvi_aid"] if vlei_state else None,
            "qvi_credential_said": vlei_state["qvi_credential_said"] if vlei_state else None,
            "gsma_aid": vlei_state.get("gsma_aid") if vlei_state else None,
            "gsma_governance_said": vlei_state.get("gsma_governance_said") if vlei_state else None,
        },
        "organization": {
            "id": org_id,
            "name": org["name"],
            "pseudo_lei": org["pseudo_lei"],
            "aid": org.get("aid"),
            "le_credential_said": le_said,
            "brand_credential_said": brand_said,
            "dossier_root_said": dossier_root_said,
            "identity_name": identity_name,
            "registry_key": org.get("registry_key"),
        },
        "org_api_key": {
            "id": key_resp["id"],
            "raw_key": org_api_key,
            "roles": key_resp["roles"],
        },
        "tn_mapping": {
            "tn": args.tn,
            "mapping_id": tn_mapping["id"] if tn_mapping else None,
            "brand_name": args.brand_name,
            "brand_logo_url": args.brand_logo,
            "dossier_said": dossier_root_said,
        },
        "dossier_verified": dossier_info is not None,
    }

    if args.json_file:
        with open(args.json_file, "w") as f:
            json.dump(summary, f, indent=2)
        print(f"\nJSON summary written to: {args.json_file}")

    if args.json_output:
        print(json.dumps(summary, indent=2))
    else:
        print("\n" + "=" * 60)
        print("BOOTSTRAP COMPLETE")
        print("=" * 60)
        print(f"\n  Organization:     {org['name']} ({org_id[:8]}...)")
        print(f"  Org AID:          {org.get('aid', 'N/A')}")
        print(f"  LE Credential:    {le_said}")
        print(f"  Brand Credential: {brand_said or 'N/A'}")
        print(f"  Dossier Root:     {dossier_root_said}")
        print(f"  Identity Name:    {identity_name}")
        print(f"  Org API Key:      {org_api_key}")
        print(f"  Test TN:          {args.tn}")
        print(f"  Dossier Verified: {'YES' if dossier_info else 'NO'}")
        # Sprint 62: Print GSMA AID for verifier trusted roots configuration
        gsma_aid = vlei_state.get("gsma_aid") if vlei_state else None
        if gsma_aid:
            print(f"\n  GSMA AID:         {gsma_aid}")
            print(f"  GSMA Governance:  {vlei_state.get('gsma_governance_said', 'N/A')}")
            print()
            print("  Verifier Trusted Roots (add GSMA AID to VVP_TRUSTED_ROOT_AIDS):")
            print(f"    VVP_TRUSTED_ROOT_AIDS=EDP1vHcw_wc4M__Fj53-cJaBnZZASd-aMTaSyWEQ-PC2,{gsma_aid}")
        print()
        print("  SIP Redirect Config (for sip-redirect service):")
        print(f"    API_KEY={org_api_key}")
        print()
        print("  To test VVP attestation:")
        print(f"    curl -X POST {base_url}/vvp/create \\")
        print(f'      -H "X-API-Key: {org_api_key}" \\')
        print(f'      -H "Content-Type: application/json" \\')
        print(f"      -d '{{\"identity_name\": \"{identity_name}\", "
              f"\"dossier_said\": \"{dossier_root_said}\", "
              f"\"orig_tn\": \"{args.tn}\", "
              f"\"dest_tn\": [\"+15559876543\"]}}'")


if __name__ == "__main__":
    main()
