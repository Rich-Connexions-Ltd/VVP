"""Issuer management tools for the VVP MCP server.

Exposes tools for creating and managing organizations, credentials,
dossiers, TN mappings, and identities via the Issuer API.

These tools make HTTP calls to a running issuer instance. Configure:
  VVP_ISSUER_URL  - Base URL (default: http://localhost:8001)
  VVP_API_KEY     - API key for authentication
"""

import json
from typing import Annotated, Any

from fastmcp import FastMCP

from common.vvp.mcp.issuer_client import issuer_request
from common.vvp.mcp.tool_helpers import error_result, parse_json_param


def register_issuer_tools(mcp: FastMCP) -> None:
    """Register all issuer management tools on the MCP server."""

    # ── Health & Status ──────────────────────────────────────────────

    @mcp.tool(annotations={"readOnlyHint": True})
    def vvp_issuer_health(
        base_url: Annotated[
            str, "Issuer base URL (default: from VVP_ISSUER_URL env var)"
        ] = "",
    ) -> dict[str, Any]:
        """Check issuer service health (livez, healthz, readyz endpoints)."""
        kw: dict[str, Any] = {}
        if base_url:
            kw["base_url"] = base_url

        results = {}
        for probe in ("livez", "healthz", "readyz"):
            resp = issuer_request("GET", f"/{probe}", **kw)
            results[probe] = {
                "status_code": resp["status_code"],
                "ok": resp["ok"],
                "data": resp["data"],
            }

        all_ok = all(r["ok"] for r in results.values())
        return {"healthy": all_ok, "probes": results}

    @mcp.tool(annotations={"readOnlyHint": True})
    def vvp_issuer_status(
        base_url: Annotated[str, "Issuer base URL override"] = "",
    ) -> dict[str, Any]:
        """Get issuer admin status (stats, version, config)."""
        kw: dict[str, Any] = {}
        if base_url:
            kw["base_url"] = base_url

        status = issuer_request("GET", "/admin/status", **kw)
        if not status["ok"]:
            return status

        version = issuer_request("GET", "/admin/version", **kw)
        stats = issuer_request("GET", "/admin/stats", **kw)

        return {
            "status": status["data"],
            "version": version["data"] if version["ok"] else None,
            "stats": stats["data"] if stats["ok"] else None,
        }

    # ── Organizations ────────────────────────────────────────────────

    @mcp.tool(annotations={"readOnlyHint": True})
    def vvp_issuer_org_list(
        base_url: Annotated[str, "Issuer base URL override"] = "",
    ) -> dict[str, Any]:
        """List all organizations on the issuer."""
        kw: dict[str, Any] = {}
        if base_url:
            kw["base_url"] = base_url
        return issuer_request("GET", "/organizations", **kw)

    @mcp.tool(annotations={"readOnlyHint": True})
    def vvp_issuer_org_get(
        org_id: Annotated[str, "Organization UUID"],
        base_url: Annotated[str, "Issuer base URL override"] = "",
    ) -> dict[str, Any]:
        """Get details of a specific organization."""
        kw: dict[str, Any] = {}
        if base_url:
            kw["base_url"] = base_url
        return issuer_request("GET", f"/organizations/{org_id}", **kw)

    @mcp.tool()
    def vvp_issuer_org_create(
        name: Annotated[str, "Organization name (1-255 chars)"],
        base_url: Annotated[str, "Issuer base URL override"] = "",
    ) -> dict[str, Any]:
        """Create a new organization. Also creates KERI identity, registry, and LE credential."""
        kw: dict[str, Any] = {}
        if base_url:
            kw["base_url"] = base_url
        return issuer_request("POST", "/organizations", json_body={"name": name}, **kw)

    @mcp.tool()
    def vvp_issuer_org_update(
        org_id: Annotated[str, "Organization UUID"],
        name: Annotated[str, "New name (optional, empty to skip)"] = "",
        enabled: Annotated[str, "Set to 'true' or 'false' (optional, empty to skip)"] = "",
        base_url: Annotated[str, "Issuer base URL override"] = "",
    ) -> dict[str, Any]:
        """Update an organization (name and/or enabled status)."""
        kw: dict[str, Any] = {}
        if base_url:
            kw["base_url"] = base_url

        body: dict[str, Any] = {}
        if name:
            body["name"] = name
        if enabled.lower() in ("true", "false"):
            body["enabled"] = enabled.lower() == "true"

        if not body:
            return error_result("NO_CHANGES", "No fields to update")

        return issuer_request("PATCH", f"/organizations/{org_id}", json_body=body, **kw)

    # ── Identities ───────────────────────────────────────────────────

    @mcp.tool(annotations={"readOnlyHint": True})
    def vvp_issuer_identity_list(
        base_url: Annotated[str, "Issuer base URL override"] = "",
    ) -> dict[str, Any]:
        """List all KERI identities on the issuer."""
        kw: dict[str, Any] = {}
        if base_url:
            kw["base_url"] = base_url
        return issuer_request("GET", "/identity", **kw)

    @mcp.tool()
    def vvp_issuer_identity_create(
        name: Annotated[str, "Identity name (human-readable alias)"],
        transferable: Annotated[str, "Allow key rotation: 'true' (default) or 'false'"] = "true",
        base_url: Annotated[str, "Issuer base URL override"] = "",
    ) -> dict[str, Any]:
        """Create a new KERI identity (AID). Also publishes to witnesses."""
        kw: dict[str, Any] = {}
        if base_url:
            kw["base_url"] = base_url
        body: dict[str, Any] = {
            "name": name,
            "transferable": transferable.lower() != "false",
        }
        return issuer_request("POST", "/identity", json_body=body, **kw)

    @mcp.tool()
    def vvp_issuer_identity_publish(
        name: Annotated[str, "Identity name to publish OOBI for"],
        base_url: Annotated[str, "Issuer base URL override"] = "",
    ) -> dict[str, Any]:
        """Force re-publish an identity's OOBI to witnesses."""
        kw: dict[str, Any] = {}
        if base_url:
            kw["base_url"] = base_url
        return issuer_request("POST", f"/admin/publish-identity/{name}", **kw)

    # ── Credentials ──────────────────────────────────────────────────

    @mcp.tool(annotations={"readOnlyHint": True})
    def vvp_issuer_credential_list(
        schema_said: Annotated[str, "Filter by schema SAID (optional)"] = "",
        org_id: Annotated[str, "Filter by organization UUID (admin only, optional)"] = "",
        limit: Annotated[int, "Max results (1-200, default 50)"] = 50,
        offset: Annotated[int, "Offset for pagination (default 0)"] = 0,
        base_url: Annotated[str, "Issuer base URL override"] = "",
    ) -> dict[str, Any]:
        """List credentials (paginated, filterable by schema and org)."""
        kw: dict[str, Any] = {}
        if base_url:
            kw["base_url"] = base_url
        params: dict[str, Any] = {"limit": limit, "offset": offset}
        if schema_said:
            params["schema_said"] = schema_said
        if org_id:
            params["org_id"] = org_id
            kw["admin"] = True
        return issuer_request("GET", "/credential", params=params, **kw)

    @mcp.tool(annotations={"readOnlyHint": True})
    def vvp_issuer_dossier_list(
        org_id: Annotated[str, "Filter by organization UUID (optional)"] = "",
        limit: Annotated[int, "Max results (1-200, default 50)"] = 50,
        offset: Annotated[int, "Offset for pagination (default 0)"] = 0,
        base_url: Annotated[str, "Issuer base URL override"] = "",
    ) -> dict[str, Any]:
        """List all dossiers (credentials with the Brand/DE schema). Optionally filter by org."""
        kw: dict[str, Any] = {}
        if base_url:
            kw["base_url"] = base_url
        # Dossiers are credentials with the Extended Brand schema
        brand_schema = "EK7kPhs5YkPsq9mZgUfPYfU-zq5iSlU8XVYJWqrVPk6g"
        params: dict[str, Any] = {
            "schema_said": brand_schema,
            "limit": limit,
            "offset": offset,
        }
        if org_id:
            params["org_id"] = org_id
            kw["admin"] = True
        return issuer_request("GET", "/credential", params=params, **kw)

    @mcp.tool(annotations={"readOnlyHint": True})
    def vvp_issuer_credential_get(
        said: Annotated[str, "Credential SAID (44 chars)"],
        base_url: Annotated[str, "Issuer base URL override"] = "",
    ) -> dict[str, Any]:
        """Get credential details including attributes, edges, and rules."""
        kw: dict[str, Any] = {}
        if base_url:
            kw["base_url"] = base_url
        return issuer_request("GET", f"/credential/{said}", **kw)

    @mcp.tool()
    def vvp_issuer_credential_issue(
        schema_said: Annotated[str, "Schema SAID (44 chars)"],
        attributes: Annotated[str, "JSON string of credential attributes"],
        recipient_aid: Annotated[str, "Recipient AID (optional, empty for self-issued)"] = "",
        edges: Annotated[str, "JSON string of edge references (optional)"] = "",
        registry_name: Annotated[str, "Registry name (optional, auto-resolved from org)"] = "",
        organization_id: Annotated[str, "Org UUID (optional, for extended schemas)"] = "",
        base_url: Annotated[str, "Issuer base URL override"] = "",
    ) -> dict[str, Any]:
        """Issue a new ACDC credential. Requires operator or dossier_manager role."""
        kw: dict[str, Any] = {}
        if base_url:
            kw["base_url"] = base_url

        try:
            attrs = json.loads(attributes)
        except json.JSONDecodeError as e:
            return error_result("INVALID_JSON", f"Bad attributes JSON: {e}")

        body: dict[str, Any] = {
            "schema_said": schema_said,
            "attributes": attrs,
        }
        if recipient_aid:
            body["recipient_aid"] = recipient_aid
        if edges:
            try:
                body["edges"] = json.loads(edges)
            except json.JSONDecodeError as e:
                return error_result("INVALID_JSON", f"Bad edges JSON: {e}")
        if registry_name:
            body["registry_name"] = registry_name
        if organization_id:
            body["organization_id"] = organization_id

        return issuer_request("POST", "/credential/issue", json_body=body, **kw)

    @mcp.tool()
    def vvp_issuer_credential_revoke(
        said: Annotated[str, "Credential SAID to revoke"],
        base_url: Annotated[str, "Issuer base URL override"] = "",
    ) -> dict[str, Any]:
        """Revoke a credential by SAID."""
        kw: dict[str, Any] = {}
        if base_url:
            kw["base_url"] = base_url
        return issuer_request("POST", f"/credential/{said}/revoke", **kw)

    # ── Dossiers ─────────────────────────────────────────────────────

    @mcp.tool(annotations={"readOnlyHint": True})
    def vvp_issuer_dossier_readiness(
        org_id: Annotated[str, "Organization UUID to check readiness for"],
        base_url: Annotated[str, "Issuer base URL override"] = "",
    ) -> dict[str, Any]:
        """Check dossier readiness for an organization. Shows which edge slots are satisfied."""
        kw: dict[str, Any] = {}
        if base_url:
            kw["base_url"] = base_url
        return issuer_request(
            "GET", "/dossier/readiness", params={"org_id": org_id}, **kw
        )

    @mcp.tool()
    def vvp_issuer_dossier_create(
        owner_org_id: Annotated[str, "Owner organization UUID"],
        edges: Annotated[str, "JSON object mapping edge names to credential SAIDs"],
        name: Annotated[str, "Dossier name (optional)"] = "",
        osp_org_id: Annotated[str, "OSP organization UUID (optional, for delegation)"] = "",
        base_url: Annotated[str, "Issuer base URL override"] = "",
    ) -> dict[str, Any]:
        """Create a new dossier (credential bundle). Requires operator or dossier_manager role."""
        kw: dict[str, Any] = {}
        if base_url:
            kw["base_url"] = base_url

        try:
            edge_map = json.loads(edges)
        except json.JSONDecodeError as e:
            return error_result("INVALID_JSON", f"Bad edges JSON: {e}")

        body: dict[str, Any] = {
            "owner_org_id": owner_org_id,
            "edges": edge_map,
        }
        if name:
            body["name"] = name
        if osp_org_id:
            body["osp_org_id"] = osp_org_id

        return issuer_request("POST", "/dossier/create", json_body=body, **kw)

    # ── TN Mappings ──────────────────────────────────────────────────

    @mcp.tool(annotations={"readOnlyHint": True})
    def vvp_issuer_tn_list(
        base_url: Annotated[str, "Issuer base URL override"] = "",
    ) -> dict[str, Any]:
        """List TN-to-dossier mappings for the authenticated organization."""
        kw: dict[str, Any] = {}
        if base_url:
            kw["base_url"] = base_url
        return issuer_request("GET", "/tn/mappings", **kw)

    @mcp.tool()
    def vvp_issuer_tn_create(
        tn: Annotated[str, "Telephone number in E.164 format (e.g., +441923311002)"],
        dossier_said: Annotated[str, "Dossier SAID (44 chars)"],
        identity_name: Annotated[str, "KERI identity name for signing"],
        brand_name: Annotated[str, "Brand display name (optional, auto-extracted if empty)"] = "",
        brand_logo_url: Annotated[str, "Brand logo URL (optional, auto-extracted if empty)"] = "",
        base_url: Annotated[str, "Issuer base URL override"] = "",
    ) -> dict[str, Any]:
        """Create a TN-to-dossier mapping. Maps a phone number to a dossier for VVP signing."""
        kw: dict[str, Any] = {}
        if base_url:
            kw["base_url"] = base_url

        body: dict[str, Any] = {
            "tn": tn,
            "dossier_said": dossier_said,
            "identity_name": identity_name,
        }
        if brand_name:
            body["brand_name"] = brand_name
        if brand_logo_url:
            body["brand_logo_url"] = brand_logo_url

        return issuer_request("POST", "/tn/mappings", json_body=body, **kw)

    @mcp.tool()
    def vvp_issuer_tn_update(
        mapping_id: Annotated[str, "TN mapping UUID"],
        dossier_said: Annotated[str, "New dossier SAID (optional)"] = "",
        enabled: Annotated[str, "Set to 'true' or 'false' (optional)"] = "",
        brand_name: Annotated[str, "Override brand name (optional)"] = "",
        base_url: Annotated[str, "Issuer base URL override"] = "",
    ) -> dict[str, Any]:
        """Update a TN mapping (dossier, enabled status, or brand name)."""
        kw: dict[str, Any] = {}
        if base_url:
            kw["base_url"] = base_url

        body: dict[str, Any] = {}
        if dossier_said:
            body["dossier_said"] = dossier_said
        if enabled.lower() in ("true", "false"):
            body["enabled"] = enabled.lower() == "true"
        if brand_name:
            body["brand_name"] = brand_name

        if not body:
            return error_result("NO_CHANGES", "No fields to update")

        return issuer_request("PATCH", f"/tn/mappings/{mapping_id}", json_body=body, **kw)

    @mcp.tool()
    def vvp_issuer_tn_delete(
        mapping_id: Annotated[str, "TN mapping UUID to delete"],
        base_url: Annotated[str, "Issuer base URL override"] = "",
    ) -> dict[str, Any]:
        """Delete a TN mapping."""
        kw: dict[str, Any] = {}
        if base_url:
            kw["base_url"] = base_url
        return issuer_request("DELETE", f"/tn/mappings/{mapping_id}", **kw)

    @mcp.tool(annotations={"readOnlyHint": True})
    def vvp_issuer_tn_lookup(
        tn: Annotated[str, "Telephone number to look up (E.164 format)"],
        base_url: Annotated[str, "Issuer base URL override"] = "",
    ) -> dict[str, Any]:
        """Look up a TN to find its mapped dossier and brand info."""
        kw: dict[str, Any] = {}
        if base_url:
            kw["base_url"] = base_url
        return issuer_request("POST", "/tn/lookup", json_body={"tn": tn}, **kw)

    # ── VVP Attestation ──────────────────────────────────────────────

    @mcp.tool()
    def vvp_issuer_vvp_create(
        orig_tn: Annotated[str, "Originating TN (E.164, e.g., +441923311002)"],
        dest_tn: Annotated[str, "Destination TN(s) (E.164, comma-separated for multiple)"],
        identity_name: Annotated[str, "KERI identity name for signing"],
        dossier_said: Annotated[str, "Dossier SAID (44 chars)"],
        call_id: Annotated[str, "SIP Call-ID (optional but recommended)"] = "",
        cseq: Annotated[int, "SIP CSeq number (optional)"] = 0,
        exp_seconds: Annotated[int, "PASSporT validity (1-300, default 300)"] = 300,
        base_url: Annotated[str, "Issuer base URL override"] = "",
    ) -> dict[str, Any]:
        """Create a VVP attestation (PASSporT + VVP-Identity header) for a call."""
        kw: dict[str, Any] = {}
        if base_url:
            kw["base_url"] = base_url

        dest_list = [t.strip() for t in dest_tn.split(",") if t.strip()]
        body: dict[str, Any] = {
            "identity_name": identity_name,
            "dossier_said": dossier_said,
            "orig_tn": orig_tn,
            "dest_tn": dest_list,
            "exp_seconds": min(max(exp_seconds, 1), 300),
        }
        if call_id:
            body["call_id"] = call_id
        if cseq:
            body["cseq"] = cseq

        return issuer_request("POST", "/vvp/create", json_body=body, **kw)

    @mcp.tool()
    def vvp_issuer_vvp_create_for_tn(
        orig_tn: Annotated[str, "Originating TN (E.164) — used for TN lookup + signing"],
        dest_tn: Annotated[str, "Destination TN(s) (E.164, comma-separated)"],
        call_id: Annotated[str, "SIP Call-ID (optional but recommended)"] = "",
        cseq: Annotated[int, "SIP CSeq number (optional)"] = 0,
        exp_seconds: Annotated[int, "PASSporT validity (1-300, default 300)"] = 300,
        base_url: Annotated[str, "Issuer base URL override"] = "",
    ) -> dict[str, Any]:
        """Create VVP attestation by TN lookup. Resolves identity and dossier from TN mapping."""
        kw: dict[str, Any] = {}
        if base_url:
            kw["base_url"] = base_url

        dest_list = [t.strip() for t in dest_tn.split(",") if t.strip()]
        body: dict[str, Any] = {
            "orig_tn": orig_tn,
            "dest_tn": dest_list,
            "exp_seconds": min(max(exp_seconds, 1), 300),
        }
        if call_id:
            body["call_id"] = call_id
        if cseq:
            body["cseq"] = cseq

        return issuer_request("POST", "/vvp/create-for-tn", json_body=body, **kw)

    # ── Schemas ──────────────────────────────────────────────────────

    @mcp.tool(annotations={"readOnlyHint": True})
    def vvp_issuer_schema_list(
        base_url: Annotated[str, "Issuer base URL override"] = "",
    ) -> dict[str, Any]:
        """List all schemas known to the issuer."""
        kw: dict[str, Any] = {}
        if base_url:
            kw["base_url"] = base_url
        return issuer_request("GET", "/schema", **kw)

    # ── Vetter Certifications ────────────────────────────────────────

    @mcp.tool(annotations={"readOnlyHint": True})
    def vvp_issuer_vetter_list(
        base_url: Annotated[str, "Issuer base URL override"] = "",
    ) -> dict[str, Any]:
        """List vetter certifications."""
        kw: dict[str, Any] = {}
        if base_url:
            kw["base_url"] = base_url
        return issuer_request("GET", "/vetter-certifications", **kw)

    @mcp.tool(annotations={"readOnlyHint": True})
    def vvp_issuer_org_constraints(
        org_id: Annotated[str, "Organization UUID"],
        base_url: Annotated[str, "Issuer base URL override"] = "",
    ) -> dict[str, Any]:
        """Get vetter constraints for an organization (ECC targets, jurisdictions)."""
        kw: dict[str, Any] = {}
        if base_url:
            kw["base_url"] = base_url
        return issuer_request("GET", f"/organizations/{org_id}/constraints", **kw)

    # ── API Keys ─────────────────────────────────────────────────────

    @mcp.tool(annotations={"readOnlyHint": True})
    def vvp_issuer_api_key_list(
        org_id: Annotated[str, "Organization UUID"],
        base_url: Annotated[str, "Issuer base URL override"] = "",
    ) -> dict[str, Any]:
        """List API keys for an organization."""
        kw: dict[str, Any] = {}
        if base_url:
            kw["base_url"] = base_url
        return issuer_request("GET", f"/organizations/{org_id}/api-keys", **kw)

    @mcp.tool()
    def vvp_issuer_api_key_create(
        org_id: Annotated[str, "Organization UUID"],
        name: Annotated[str, "Key name/description"],
        roles: Annotated[str, "Comma-separated roles (e.g., 'org:dossier_manager,org:administrator')"],
        base_url: Annotated[str, "Issuer base URL override"] = "",
    ) -> dict[str, Any]:
        """Create an API key for an organization. Returns the key value (shown only once)."""
        kw: dict[str, Any] = {}
        if base_url:
            kw["base_url"] = base_url

        role_list = [r.strip() for r in roles.split(",") if r.strip()]
        body: dict[str, Any] = {
            "name": name,
            "roles": role_list,
        }
        return issuer_request(
            "POST", f"/organizations/{org_id}/api-keys", json_body=body, **kw
        )

    # ── Admin ────────────────────────────────────────────────────────

    @mcp.tool()
    def vvp_issuer_admin_reinitialize(
        clear_regular_orgs: Annotated[
            str, "Also clear regular orgs: 'true' or 'false' (default: false)"
        ] = "false",
        base_url: Annotated[str, "Issuer base URL override"] = "",
    ) -> dict[str, Any]:
        """Re-initialize mock vLEI trust anchors. Optionally clears all regular orgs."""
        kw: dict[str, Any] = {}
        if base_url:
            kw["base_url"] = base_url

        body: dict[str, Any] = {}
        if clear_regular_orgs.lower() == "true":
            body["clear_regular_orgs"] = True

        return issuer_request(
            "POST", "/admin/mock-vlei/reinitialize", json_body=body, **kw
        )
