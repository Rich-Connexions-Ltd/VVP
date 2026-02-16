"""KERI credential registry management for VVP KERI Agent.

Wraps keripy's Regery to provide TEL (Transaction Event Log) registry
lifecycle management for ACDC credential issuance tracking.
"""
import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from keri.core import coring, eventing, serdering
from keri.db.dbing import dgKey, snKey
from keri.vdr.credentialing import Regery
from keri.vdr.viring import Reger

from app.keri.identity import get_identity_manager

log = logging.getLogger(__name__)


@dataclass
class RegistryInfo:
    """Information about a credential registry."""

    registry_key: str  # Registry prefix (regk)
    name: str  # Human-readable name
    issuer_aid: str  # Issuer identity AID
    created_at: str  # ISO8601 timestamp
    sequence_number: int  # Current TEL sequence
    no_backers: bool  # Whether using TEL-specific backers


class CredentialRegistryManager:
    """Manages KERI credential registries for the agent service.

    Wraps keripy's Regery to provide:
    - Registry creation with configurable backers
    - TEL event serialization for witness publishing
    - Registry lookup by key or name
    - Persistence across restarts

    The manager shares the Habery instance from IssuerIdentityManager,
    as Regery requires a Habery for identity context.
    """

    def __init__(self, temp: bool = False):
        """Initialize registry manager."""
        self._regery: Optional[Regery] = None
        self._lock = asyncio.Lock()
        self._initialized = False
        self._temp = temp

    async def initialize(self) -> None:
        """Initialize the Regery with shared Habery."""
        async with self._lock:
            if self._initialized:
                return

            identity_mgr = await get_identity_manager()
            hby = identity_mgr.habery

            temp_mode = self._temp or identity_mgr.temp

            # IMPORTANT: db=hby.db enables the read-through tever cache (rbdict).
            reger = Reger(
                name=hby.name,
                headDirPath=hby.db.headDirPath,
                db=hby.db,
                temp=temp_mode,
                reopen=True,
            )

            self._regery = Regery(
                hby=hby,
                name=hby.name,
                reger=reger,
                temp=temp_mode,
            )

            log.info(f"Regery initialized with {len(self._regery.regs)} existing registries")
            self._ensure_tevers_loaded()
            self._initialized = True

    def _ensure_tevers_loaded(self) -> None:
        """Ensure Tever objects exist for all loaded registries."""
        reger = self._regery.reger
        tvy = self._regery.tvy
        cached = 0
        bootstrapped = 0
        failed = 0

        for regk, registry in list(self._regery.regs.items()):
            if regk in reger.tevers:
                cached += 1
                continue

            try:
                pre = regk.encode("utf-8") if isinstance(regk, str) else regk

                dig = reger.getTel(snKey(pre, 0))
                if dig is None:
                    log.warning(f"Registry {registry.name} ({regk[:16]}...): "
                                "no TEL entry at sn=0, skipping")
                    failed += 1
                    continue

                vcp_raw = reger.getTvt(dgKey(pre, bytes(dig)))
                if vcp_raw is None:
                    log.warning(f"Registry {registry.name} ({regk[:16]}...): "
                                "no TVT entry for VCP, skipping")
                    failed += 1
                    continue

                anc = reger.getAnc(dgKey(pre, bytes(dig)))
                if anc is None:
                    log.warning(f"Registry {registry.name} ({regk[:16]}...): "
                                "no anchor entry, skipping")
                    failed += 1
                    continue

                vcp_serder = serdering.SerderKERI(raw=bytes(vcp_raw))
                ancb = bytearray(anc)
                seqner = coring.Seqner(qb64b=ancb, strip=True)
                saider = coring.Saider(qb64b=ancb, strip=True)

                tvy.processEvent(
                    serder=vcp_serder,
                    seqner=seqner,
                    saider=saider,
                )
                bootstrapped += 1
                log.info(f"Bootstrapped tever for {registry.name} ({regk[:16]}...)")

            except Exception as e:
                failed += 1
                log.warning(f"Failed to bootstrap tever for {registry.name} "
                            f"({regk[:16]}...): {e}")

        parts = []
        if cached:
            parts.append(f"{cached} from state cache")
        if bootstrapped:
            parts.append(f"{bootstrapped} bootstrapped from TEL")
        if failed:
            parts.append(f"{failed} failed")
        if parts:
            log.info(f"Tever loading: {', '.join(parts)}")

    async def close(self) -> None:
        """Close the Regery and release resources."""
        async with self._lock:
            if self._regery is not None:
                self._regery.close()
                self._regery = None
                self._initialized = False
                log.info("Regery closed")

    @property
    def regery(self) -> Regery:
        """Get the Regery instance (raises if not initialized)."""
        if self._regery is None:
            raise RuntimeError("CredentialRegistryManager not initialized")
        return self._regery

    async def create_registry(
        self,
        name: str,
        issuer_aid: str,
        no_backers: bool = True,
    ) -> RegistryInfo:
        """Create a new credential registry."""
        async with self._lock:
            if self.regery.registryByName(name) is not None:
                raise ValueError(f"Registry '{name}' already exists")

            identity_mgr = await get_identity_manager()
            issuer_info = await identity_mgr.get_identity(issuer_aid)
            if issuer_info is None:
                raise ValueError(f"Issuer identity not found: {issuer_aid}")

            registry = self.regery.makeRegistry(
                name=name,
                prefix=issuer_aid,
                noBackers=no_backers,
            )

            hab = registry.hab
            rseal = eventing.SealEvent(registry.vcp.pre, registry.vcp.snh, registry.vcp.said)
            anc = hab.interact(data=[dict(i=rseal.i, s=rseal.s, d=rseal.d)])

            seqner = coring.Seqner(sn=hab.kever.sn)
            saider = coring.Saider(qb64=hab.kever.serder.said)

            registry.anchorMsg(
                pre=registry.regk,
                regd=registry.regd,
                seqner=seqner,
                saider=saider,
            )

            self.regery.tvy.processEvent(
                serder=registry.vcp,
                seqner=seqner,
                saider=saider,
            )

            log.info(f"Created registry: {name} ({registry.regk[:16]}...) for issuer {issuer_aid[:16]}...")

            # Sprint 69: Capture and persist registry nonce for deterministic rebuild
            nonce = registry.vcp.ked.get("n", "")
            from app.keri.seed_store import get_seed_store
            seed_store = get_seed_store()
            seed_store.save_registry_seed(
                name=name,
                identity_name=issuer_info.name,
                expected_registry_key=registry.regk,
                no_backers=no_backers,
                nonce=nonce if nonce else None,
            )

            try:
                seq_num = registry.regi
            except (KeyError, AttributeError):
                seq_num = 0

            return RegistryInfo(
                registry_key=registry.regk,
                name=name,
                issuer_aid=issuer_aid,
                created_at=datetime.now(timezone.utc).isoformat(),
                sequence_number=seq_num,
                no_backers=no_backers,
            )

    async def get_registry(self, registry_key: str) -> Optional[RegistryInfo]:
        """Get registry info by registry key."""
        async with self._lock:
            registry = self.regery.regs.get(registry_key)
            if registry is None:
                return None

            try:
                issuer_aid = registry.hab.pre if registry.hab else ""
            except (KeyError, AttributeError):
                issuer_aid = ""

            try:
                seq_num = registry.regi
            except (KeyError, AttributeError):
                seq_num = 0

            try:
                no_backers = registry.noBackers
            except (KeyError, AttributeError):
                no_backers = True

            return RegistryInfo(
                registry_key=registry.regk,
                name=registry.name,
                issuer_aid=issuer_aid,
                created_at="",
                sequence_number=seq_num,
                no_backers=no_backers,
            )

    async def get_registry_by_name(self, name: str) -> Optional[RegistryInfo]:
        """Get registry info by name."""
        async with self._lock:
            registry = self.regery.registryByName(name)
            if registry is None:
                return None

            try:
                issuer_aid = registry.hab.pre if registry.hab else ""
            except (KeyError, AttributeError):
                issuer_aid = ""

            try:
                seq_num = registry.regi
            except (KeyError, AttributeError):
                seq_num = 0

            try:
                no_backers = registry.noBackers
            except (KeyError, AttributeError):
                no_backers = True

            return RegistryInfo(
                registry_key=registry.regk,
                name=registry.name,
                issuer_aid=issuer_aid,
                created_at="",
                sequence_number=seq_num,
                no_backers=no_backers,
            )

    async def list_registries(self) -> list[RegistryInfo]:
        """List all managed registries."""
        async with self._lock:
            registries = []
            for regk, registry in self.regery.regs.items():
                try:
                    issuer_aid = registry.hab.pre if registry.hab else ""
                except (KeyError, AttributeError):
                    issuer_aid = ""

                try:
                    seq_num = registry.regi
                except (KeyError, AttributeError):
                    seq_num = 0

                try:
                    no_backers = registry.noBackers
                except (KeyError, AttributeError):
                    no_backers = True

                info = RegistryInfo(
                    registry_key=registry.regk,
                    name=registry.name,
                    issuer_aid=issuer_aid,
                    created_at="",
                    sequence_number=seq_num,
                    no_backers=no_backers,
                )
                registries.append(info)
            return registries

    async def delete_registry(self, registry_key: str) -> bool:
        """Delete a registry from local storage."""
        async with self._lock:
            registry = self.regery.regs.get(registry_key)
            if registry is None:
                raise ValueError(f"Registry not found: {registry_key}")

            name = registry.name

            if registry_key in self.regery.regs:
                del self.regery.regs[registry_key]

            log.info(f"Deleted registry from local storage: {name} ({registry_key[:16]}...)")
            return True

    async def get_tel_bytes(self, registry_key: str) -> bytes:
        """Get serialized TEL inception event for witness publishing."""
        async with self._lock:
            registry = self.regery.regs.get(registry_key)
            if registry is None:
                raise ValueError(f"Registry not found: {registry_key}")

            pre = registry_key.encode() if isinstance(registry_key, str) else registry_key
            msg = self.regery.reger.cloneTvt(pre=pre, dig=registry.vcp.saidb)
            return bytes(msg)

    async def get_anchor_ixn_bytes(self, registry_key: str) -> bytes:
        """Get the KEL interaction event that anchors the TEL registry."""
        async with self._lock:
            registry = self.regery.regs.get(registry_key)
            if registry is None:
                raise ValueError(f"Registry not found: {registry_key}")

            hab = registry.hab
            if hab is None:
                raise ValueError(f"Registry {registry_key} has no associated hab")

            identity_mgr = await get_identity_manager()
            hby = identity_mgr.habery

            sn = hab.kever.sn
            dgkey = hby.db.getKeLast(hab.pre.encode())
            if dgkey is None:
                raise ValueError(f"No KEL events found for issuer {hab.pre}")

            msg = hby.db.cloneEvtMsg(pre=hab.pre.encode(), fn=sn, dig=dgkey)
            if msg is None:
                raise ValueError(f"Failed to clone anchor ixn for registry {registry_key}")

            return bytes(msg)


# Module-level singleton
_registry_manager: Optional[CredentialRegistryManager] = None


async def get_registry_manager() -> CredentialRegistryManager:
    """Get or create the registry manager singleton."""
    global _registry_manager
    if _registry_manager is None:
        _registry_manager = CredentialRegistryManager()
        await _registry_manager.initialize()
    return _registry_manager


async def close_registry_manager() -> None:
    """Close the registry manager singleton."""
    global _registry_manager
    if _registry_manager is not None:
        await _registry_manager.close()
        _registry_manager = None


def reset_registry_manager() -> None:
    """Reset the singleton without closing (for testing)."""
    global _registry_manager
    _registry_manager = None
