"""Dossier builder for VVP KERI Agent.

Assembles credentials into complete dossiers by walking edge references
and collecting all dependent credentials in the chain.
"""

import logging
from dataclasses import dataclass, field

from keri.core import serdering
from keri.db import dbing

from app.dossier.exceptions import DossierBuildError
from app.keri.issuer import CredentialInfo, get_credential_issuer
from app.keri.registry import get_registry_manager

log = logging.getLogger(__name__)

# Maximum chain depth to prevent infinite loops
MAX_CHAIN_DEPTH = 10


@dataclass
class DossierContent:
    """Assembled dossier content."""

    root_said: str
    root_saids: list[str] = field(default_factory=list)
    credential_saids: list[str] = field(default_factory=list)
    is_aggregate: bool = False
    credentials: dict[str, bytes] = field(default_factory=dict)
    credentials_json: dict[str, dict] = field(default_factory=dict)
    tel_events: dict[str, bytes] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


class DossierBuilder:
    """Builds dossiers from credential chains."""

    async def build(
        self,
        root_said: str,
        include_tel: bool = True,
    ) -> DossierContent:
        """Build dossier from a single root credential."""
        issuer = await get_credential_issuer()

        root_cred = await issuer.get_credential(root_said)
        if root_cred is None:
            raise DossierBuildError(f"Root credential not found", credential_said=root_said)

        credential_saids, warnings = await self._resolve_edges(root_said)

        content = DossierContent(
            root_said=root_said,
            root_saids=[root_said],
            credential_saids=credential_saids,
            is_aggregate=False,
            warnings=warnings,
        )

        for said in credential_saids:
            cesr_bytes = await issuer.get_credential_bytes(said)
            if cesr_bytes is None:
                content.warnings.append(f"Could not get CESR for credential {said}")
                continue
            content.credentials[said] = cesr_bytes

            cred_info = await issuer.get_credential(said)
            if cred_info:
                content.credentials_json[said] = await self._credential_to_json(said)

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
        """Build aggregate dossier from multiple roots."""
        if not root_saids:
            raise DossierBuildError("No root credentials provided")

        issuer = await get_credential_issuer()

        for said in root_saids:
            root_cred = await issuer.get_credential(said)
            if root_cred is None:
                raise DossierBuildError(f"Root credential not found", credential_said=said)

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

        content = DossierContent(
            root_said=root_saids[0],
            root_saids=root_saids,
            credential_saids=all_saids,
            is_aggregate=True,
            warnings=all_warnings,
        )

        for said in all_saids:
            cesr_bytes = await issuer.get_credential_bytes(said)
            if cesr_bytes is None:
                content.warnings.append(f"Could not get CESR for credential {said}")
                continue
            content.credentials[said] = cesr_bytes

            cred_info = await issuer.get_credential(said)
            if cred_info:
                content.credentials_json[said] = await self._credential_to_json(said)

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
        """Resolve all credentials reachable from root via edges (DFS, topological order)."""
        issuer = await get_credential_issuer()
        visited: set[str] = set()
        in_stack: set[str] = set()
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

            cred_info = await issuer.get_credential(said)
            if cred_info is None:
                warnings.append(f"Edge target not found: {said}")
                in_stack.discard(said)
                return

            if cred_info.edges:
                for target_said in self._extract_edge_targets(cred_info.edges):
                    await dfs(target_said, depth + 1)

            visited.add(said)
            in_stack.discard(said)
            result.append(said)

        await dfs(root_said)
        return result, warnings

    def _extract_edge_targets(self, edges: dict) -> list[str]:
        """Extract SAIDs referenced in edges."""
        targets: list[str] = []

        for edge_name, edge_ref in edges.items():
            if edge_name == "d":
                continue

            if isinstance(edge_ref, dict) and "n" in edge_ref:
                targets.append(edge_ref["n"])
            elif isinstance(edge_ref, str):
                targets.append(edge_ref)

        return targets

    async def _get_tel_event(self, credential_said: str) -> bytes | None:
        """Get TEL issuance event for a credential."""
        try:
            registry_mgr = await get_registry_manager()
            reger = registry_mgr.regery.reger

            tel_bytes = reger.cloneTvtAt(credential_said, sn=0)
            return bytes(tel_bytes) if tel_bytes else None
        except Exception as e:
            log.warning(f"Could not get TEL for {credential_said}: {e}")
            return None

    async def _credential_to_json(self, credential_said: str) -> dict:
        """Get credential as JSON dict."""
        try:
            registry_mgr = await get_registry_manager()
            reger = registry_mgr.regery.reger

            creder = reger.creds.get(keys=(credential_said,))
            if creder is None:
                return {}

            return dict(creder.sad)
        except Exception as e:
            log.warning(f"Could not get JSON for {credential_said}: {e}")
            return {}


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
