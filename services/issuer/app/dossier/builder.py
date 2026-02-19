"""Dossier builder for VVP Issuer.

Assembles credentials into complete dossiers by walking edge references
and collecting all dependent credentials in the chain.

Sprint 68b: Migrated from direct app.keri.* imports to KeriAgentClient.
All KERI operations are delegated to the KERI Agent service.
"""

import logging
from dataclasses import dataclass, field

from app.dossier.exceptions import DossierBuildError
from app.keri_client import get_keri_client

log = logging.getLogger(__name__)

# Maximum chain depth to prevent infinite loops
MAX_CHAIN_DEPTH = 10


@dataclass
class DossierContent:
    """Assembled dossier content.

    Contains all credentials and TEL events needed to verify the dossier.
    """

    root_said: str  # Primary root credential SAID
    root_saids: list[str] = field(default_factory=list)  # All root SAIDs (for aggregate)
    credential_saids: list[str] = field(default_factory=list)  # In topological order
    is_aggregate: bool = False  # True if multiple roots
    credentials: dict[str, bytes] = field(default_factory=dict)  # SAID -> CESR bytes
    credentials_json: dict[str, dict] = field(default_factory=dict)  # SAID -> JSON dict
    tel_events: dict[str, bytes] = field(default_factory=dict)  # SAID -> TEL iss bytes
    warnings: list[str] = field(default_factory=list)  # Non-fatal issues


class DossierBuilder:
    """Builds dossiers from credential chains.

    Walks edge references to collect all credentials in a chain,
    then serializes them in formats the verifier can consume.
    """

    async def build(
        self,
        root_said: str,
        include_tel: bool = True,
    ) -> DossierContent:
        """Build dossier from a single root credential.

        Args:
            root_said: SAID of the root credential
            include_tel: If True, include TEL issuance events

        Returns:
            DossierContent with all credentials and optionally TEL events

        Raises:
            DossierBuildError: If root not found, cycle detected, or other error
        """
        client = get_keri_client()

        # Verify root exists
        root_cred = await client.get_credential(root_said)
        if root_cred is None:
            raise DossierBuildError(f"Root credential not found", credential_said=root_said)

        # Resolve all edges (returns topological order)
        credential_saids, warnings = await self._resolve_edges(root_said)

        # Build content
        content = DossierContent(
            root_said=root_said,
            root_saids=[root_said],
            credential_saids=credential_saids,
            is_aggregate=False,
            warnings=warnings,
        )

        # Collect CESR bytes and JSON for each credential
        for said in credential_saids:
            try:
                cesr_bytes = await client.get_credential_cesr(said)
                if cesr_bytes:
                    content.credentials[said] = cesr_bytes
                else:
                    content.warnings.append(f"Could not get CESR for credential {said}")
            except Exception:
                content.warnings.append(f"Could not get CESR for credential {said}")

            # Build JSON representation from credential attributes
            cred_info = await client.get_credential(said)
            if cred_info:
                content.credentials_json[said] = self._credential_to_json(cred_info)

        # Collect TEL events if requested
        if include_tel:
            for said in credential_saids:
                tel_bytes = await self._get_tel_event(said)
                if tel_bytes:
                    content.tel_events[said] = tel_bytes

        log.info(
            f"Built dossier: root={root_said[:16]}..., "
            f"credentials={len(content.credentials)}, "
            f"tel_events={len(content.tel_events)}"
        )

        return content

    async def build_aggregate(
        self,
        root_saids: list[str],
        include_tel: bool = True,
    ) -> DossierContent:
        """Build aggregate dossier from multiple roots.

        Args:
            root_saids: List of root credential SAIDs
            include_tel: If True, include TEL issuance events

        Returns:
            DossierContent with all credentials from all chains

        Raises:
            DossierBuildError: If any root not found or cycle detected
        """
        if not root_saids:
            raise DossierBuildError("No root credentials provided")

        client = get_keri_client()

        # Verify all roots exist
        for said in root_saids:
            root_cred = await client.get_credential(said)
            if root_cred is None:
                raise DossierBuildError(f"Root credential not found", credential_said=said)

        # Resolve edges for all roots (deduplicates automatically)
        all_saids: list[str] = []
        all_warnings: list[str] = []
        seen: set[str] = set()

        for root_said in root_saids:
            saids, warnings = await self._resolve_edges(root_said)
            all_warnings.extend(warnings)

            for said in saids:
                if said not in seen:
                    seen.add(said)
                    all_saids.append(said)

        # Build content
        content = DossierContent(
            root_said=root_saids[0],  # Primary root is first
            root_saids=root_saids,
            credential_saids=all_saids,
            is_aggregate=True,
            warnings=all_warnings,
        )

        # Collect CESR bytes and JSON
        for said in all_saids:
            try:
                cesr_bytes = await client.get_credential_cesr(said)
                if cesr_bytes:
                    content.credentials[said] = cesr_bytes
                else:
                    content.warnings.append(f"Could not get CESR for credential {said}")
            except Exception:
                content.warnings.append(f"Could not get CESR for credential {said}")

            cred_info = await client.get_credential(said)
            if cred_info:
                content.credentials_json[said] = self._credential_to_json(cred_info)

        # Collect TEL events
        if include_tel:
            for said in all_saids:
                tel_bytes = await self._get_tel_event(said)
                if tel_bytes:
                    content.tel_events[said] = tel_bytes

        log.info(
            f"Built aggregate dossier: roots={len(root_saids)}, "
            f"credentials={len(content.credentials)}, "
            f"tel_events={len(content.tel_events)}"
        )

        return content

    async def _resolve_edges(self, root_said: str) -> tuple[list[str], list[str]]:
        """Resolve all credentials reachable from root via edges.

        Uses DFS with post-order traversal to get topological order
        (dependencies first, root last).

        Args:
            root_said: Starting credential SAID

        Returns:
            Tuple of (list of SAIDs in topological order, list of warnings)

        Raises:
            DossierBuildError: If cycle detected or max depth exceeded
        """
        client = get_keri_client()
        visited: set[str] = set()
        in_stack: set[str] = set()  # For cycle detection
        result: list[str] = []
        warnings: list[str] = []

        async def dfs(said: str, depth: int = 0) -> None:
            if depth > MAX_CHAIN_DEPTH:
                raise DossierBuildError(
                    f"Maximum chain depth ({MAX_CHAIN_DEPTH}) exceeded",
                    credential_said=said,
                )

            if said in visited:
                return

            if said in in_stack:
                raise DossierBuildError(
                    f"Cycle detected in credential chain",
                    credential_said=said,
                )

            in_stack.add(said)

            # Get credential info
            cred_info = await client.get_credential(said)
            if cred_info is None:
                warnings.append(f"Edge target not found: {said}")
                in_stack.discard(said)
                return

            # Process edges first (DFS into dependencies)
            if cred_info.edges:
                for target_said in self._extract_edge_targets(cred_info.edges):
                    await dfs(target_said, depth + 1)

            # Mark visited and add to result (post-order)
            visited.add(said)
            in_stack.discard(said)
            result.append(said)

        await dfs(root_said)
        return result, warnings

    def _extract_edge_targets(self, edges: dict) -> list[str]:
        """Extract SAIDs referenced in edges.

        Handles both structured edges (dict with 'n' key) and direct SAID strings.
        Matches verifier's extract_edge_targets() logic exactly.

        Args:
            edges: The 'e' section of a credential

        Returns:
            List of target SAIDs
        """
        targets: list[str] = []

        for edge_name, edge_ref in edges.items():
            if edge_name == "d":
                continue  # Skip edge block's own SAID

            if isinstance(edge_ref, dict) and "n" in edge_ref:
                # Structured edge: {"n": "...", "s": "..."}
                targets.append(edge_ref["n"])
            elif isinstance(edge_ref, str):
                # Direct SAID string
                targets.append(edge_ref)

        return targets

    async def _get_tel_event(self, credential_said: str) -> bytes | None:
        """Get TEL issuance event for a credential.

        Calls the KERI Agent's per-credential TEL endpoint to get the iss
        event (sn=0) for inline inclusion in dossiers. The verifier uses
        inline TEL events to check revocation status without needing to
        resolve the issuer's TEL registry separately.

        Only the issuing KERI Agent's own credentials will have TEL events.
        Externally-issued edge credentials (e.g. LE from mock-QVI) return None.

        Args:
            credential_said: SAID of the credential

        Returns:
            CESR-encoded TEL iss event, or None if not available
        """
        try:
            client = get_keri_client()
            return await client.get_credential_tel(credential_said)
        except Exception as e:
            log.debug(f"TEL not available for {credential_said[:16]}...: {e}")
            return None

    def _credential_to_json(self, cred_info) -> dict:
        """Build credential JSON dict from a CredentialResponse.

        Reconstructs the ACDC-like JSON structure from the agent DTO fields.

        Args:
            cred_info: CredentialResponse from the KERI Agent

        Returns:
            Credential as dictionary with 'd', 'i', 's', 'a' and optional 'e', 'r' keys
        """
        result = {
            "d": cred_info.said,
            "i": cred_info.issuer_aid,
            "s": cred_info.schema_said,
            "a": cred_info.attributes,
        }
        if cred_info.edges:
            result["e"] = cred_info.edges
        if cred_info.rules:
            result["r"] = cred_info.rules
        return result


# Module-level singleton
_dossier_builder: DossierBuilder | None = None


async def get_dossier_builder() -> DossierBuilder:
    """Get or create the dossier builder singleton."""
    global _dossier_builder
    if _dossier_builder is None:
        _dossier_builder = DossierBuilder()
    return _dossier_builder


def reset_dossier_builder() -> None:
    """Reset the singleton (for testing)."""
    global _dossier_builder
    _dossier_builder = None
