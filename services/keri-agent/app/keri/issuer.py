"""KERI credential issuance for VVP KERI Agent.

Wraps keripy's proving.credential() and Registry.issue()/revoke() to provide
ACDC credential lifecycle management including issuance, revocation, and retrieval.
"""
import asyncio
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from keri import core
from keri.app import signing
from keri.core import coring, eventing, serdering
from keri.db import dbing
from keri.help import helping
from keri.vc import proving

from app.keri.identity import get_identity_manager
from app.keri.registry import get_registry_manager
from app.schema.store import has_embedded_schema

log = logging.getLogger(__name__)


@dataclass
class CredentialInfo:
    """Information about an issued credential."""

    said: str  # Credential SAID
    issuer_aid: str  # Issuing identity AID
    recipient_aid: Optional[str]  # Recipient AID (issuee)
    registry_key: str  # Registry key tracking this credential
    schema_said: str  # Schema SAID
    issuance_dt: str  # ISO8601 timestamp
    status: str  # "issued" | "revoked"
    revocation_dt: Optional[str]  # If revoked
    attributes: dict  # The 'a' section data
    edges: Optional[dict]  # Edge references
    rules: Optional[dict]  # Rules section


class CredentialIssuer:
    """Manages ACDC credential issuance and revocation."""

    def __init__(self, temp: bool = False):
        """Initialize credential issuer."""
        self._lock = asyncio.Lock()
        self._initialized = False
        self._temp = temp

    async def initialize(self) -> None:
        """Initialize with access to registry and identity managers."""
        async with self._lock:
            if self._initialized:
                return

            await get_identity_manager()
            await get_registry_manager()

            log.info("CredentialIssuer initialized")
            self._initialized = True

    async def close(self) -> None:
        """Release resources."""
        async with self._lock:
            if self._initialized:
                log.info("CredentialIssuer closed")
                self._initialized = False

    async def issue_credential(
        self,
        registry_name: str,
        schema_said: str,
        attributes: dict,
        recipient_aid: Optional[str] = None,
        edges: Optional[dict] = None,
        rules: Optional[dict] = None,
        private: bool = False,
    ) -> tuple[CredentialInfo, bytes]:
        """Issue a new ACDC credential."""
        t_start = time.perf_counter()
        t_lock_wait = t_start

        async with self._lock:
            t_lock_acquired = time.perf_counter()

            # 1. Validate schema exists
            if not has_embedded_schema(schema_said):
                raise ValueError(f"Schema not found: {schema_said}")

            # 2. Get registry and issuer hab
            registry_mgr = await get_registry_manager()
            registry = registry_mgr.regery.registryByName(registry_name)
            if registry is None:
                raise ValueError(f"Registry not found: {registry_name}")

            hab = registry.hab
            if hab is None:
                raise ValueError(f"Registry {registry_name} has no associated identity")

            t_setup = time.perf_counter()

            # Sprint 69: Pre-compute topological rebuild order
            from app.keri.seed_store import get_seed_store, extract_edge_saids
            seed_store = get_seed_store()
            edge_saids = extract_edge_saids(edges)
            rebuild_order = seed_store.compute_rebuild_order(edge_saids)

            t_rebuild_order = time.perf_counter()

            # 3. Create ACDC
            if "dt" not in attributes:
                attributes["dt"] = helping.nowIso8601()

            creder = proving.credential(
                schema=schema_said,
                issuer=hab.pre,
                data=attributes,
                recipient=recipient_aid,
                private=private,
                status=registry.regk,
                source=edges,
                rules=rules,
            )

            t_acdc = time.perf_counter()

            log.info(f"Created credential: {creder.said[:16]}... schema={schema_said[:16]}...")

            # 4. Create TEL issuance event
            dt = attributes.get("dt", helping.nowIso8601())
            iserder = registry.issue(said=creder.said, dt=dt)

            t_tel = time.perf_counter()

            # 5. Create KEL anchor
            rseal = eventing.SealEvent(iserder.pre, iserder.snh, iserder.said)
            anc = hab.interact(data=[dict(i=rseal.i, s=rseal.s, d=rseal.d)])

            t_kel = time.perf_counter()

            # 6. Anchor the TEL iss event
            reger = registry_mgr.regery.reger
            anc_seqner = coring.Seqner(sn=hab.kever.sn)
            anc_saider = coring.Saider(qb64=hab.kever.serder.said)

            registry.anchorMsg(
                pre=iserder.pre,
                regd=iserder.said,
                seqner=anc_seqner,
                saider=anc_saider,
            )

            registry_mgr.regery.tvy.processEvent(
                serder=iserder,
                seqner=anc_seqner,
                saider=anc_saider,
            )

            t_anchor = time.perf_counter()

            log.info(f"Created TEL iss event and KEL anchor for {creder.said[:16]}...")

            # 7. Store credential
            prefixer = coring.Prefixer(qb64=iserder.pre)
            seqner = core.Number(num=iserder.sn, code=core.NumDex.Huge)
            saider = coring.Saider(qb64=iserder.said)

            reger.creds.put(keys=(creder.said,), val=creder)
            reger.cancs.pin(keys=(creder.said,), val=[prefixer, seqner, saider])

            t_store = time.perf_counter()

            log.info(f"Stored credential {creder.said[:16]}... in reger")

            # Sprint 69: Persist credential seed to PostgreSQL (LMDB-first, then PG).
            # If PG write fails, the ephemeral LMDB credential is lost on restart —
            # no orphan state accumulates. Caller should retry on next boot.
            seed_store.save_credential_seed(
                expected_said=creder.said,
                registry_name=registry_name,
                schema_said=schema_said,
                issuer_identity_name=hab.name,
                recipient_aid=recipient_aid,
                attributes=attributes,
                edges=edges,
                rules=rules,
                private=private,
                rebuild_order=rebuild_order,
                edge_saids=edge_saids,
            )

            t_pg = time.perf_counter()

            # 8. Serialize credential with SealSourceTriples
            acdc_bytes = signing.serialize(creder, prefixer, seqner, saider)

            t_serialize = time.perf_counter()

            cred_info = CredentialInfo(
                said=creder.said,
                issuer_aid=hab.pre,
                recipient_aid=recipient_aid,
                registry_key=registry.regk,
                schema_said=schema_said,
                issuance_dt=dt,
                status="issued",
                revocation_dt=None,
                attributes=dict(creder.attrib) if creder.attrib else attributes,
                edges=edges,
                rules=rules,
            )

            t_end = time.perf_counter()

            # Performance instrumentation
            log.info(
                f"PERF issue_credential {creder.said[:12]}... "
                f"total={t_end - t_start:.3f}s "
                f"lock_wait={t_lock_acquired - t_lock_wait:.3f}s "
                f"setup={t_setup - t_lock_acquired:.3f}s "
                f"rebuild_order={t_rebuild_order - t_setup:.3f}s "
                f"acdc_create={t_acdc - t_rebuild_order:.3f}s "
                f"tel_issue={t_tel - t_acdc:.3f}s "
                f"kel_anchor={t_kel - t_tel:.3f}s "
                f"tel_anchor={t_anchor - t_kel:.3f}s "
                f"lmdb_store={t_store - t_anchor:.3f}s "
                f"pg_seed={t_pg - t_store:.3f}s "
                f"serialize={t_serialize - t_pg:.3f}s"
            )

            return cred_info, acdc_bytes

    async def get_anchor_ixn_bytes(self, credential_said: str) -> bytes:
        """Get the KEL interaction event that anchors the credential TEL."""
        async with self._lock:
            registry_mgr = await get_registry_manager()
            reger = registry_mgr.regery.reger

            creder = reger.creds.get(keys=(credential_said,))
            if creder is None:
                raise ValueError(f"Credential not found: {credential_said}")

            regk = creder.sad.get("ri")
            if regk is None:
                raise ValueError(f"Credential {credential_said} has no registry")

            registry = registry_mgr.regery.regs.get(regk)
            if registry is None:
                raise ValueError(f"Registry not found: {regk}")

            hab = registry.hab
            if hab is None:
                raise ValueError(f"Registry {regk} has no associated hab")

            tel_sn = 0
            try:
                rev_dig = reger.getTel(key=dbing.snKey(credential_said, 1))
                if rev_dig is not None:
                    tel_sn = 1
            except Exception:
                pass

            try:
                tel_raw = reger.cloneTvtAt(credential_said, sn=tel_sn)
                tel_serder = serdering.SerderKERI(raw=tel_raw)
            except Exception as e:
                raise ValueError(f"Failed to get TEL event for credential {credential_said}: {e}")

            dgkey = dbing.dgKey(credential_said, tel_serder.said)
            couple = reger.getAnc(dgkey)
            if couple is None:
                raise ValueError(f"No KEL anchor found for credential {credential_said}")

            ancb = bytearray(couple)
            anc_seqner = coring.Seqner(qb64b=ancb, strip=True)
            anc_saider = coring.Saider(qb64b=ancb, strip=True)

            identity_mgr = await get_identity_manager()
            hby = identity_mgr.habery

            msg = hby.db.cloneEvtMsg(pre=hab.pre.encode(), fn=anc_seqner.sn, dig=anc_saider.qb64b)
            if msg is None:
                raise ValueError(f"Failed to clone anchor ixn for credential {credential_said}")

            return bytes(msg)

    async def revoke_credential(self, credential_said: str) -> CredentialInfo:
        """Revoke an issued credential."""
        async with self._lock:
            registry_mgr = await get_registry_manager()
            reger = registry_mgr.regery.reger

            creder = reger.creds.get(keys=(credential_said,))
            if creder is None:
                raise ValueError(f"Credential not found: {credential_said}")

            regk = creder.sad.get("ri")
            if regk is None:
                raise ValueError(f"Credential {credential_said} has no registry")

            registry = registry_mgr.regery.regs.get(regk)
            if registry is None:
                raise ValueError(f"Registry not found: {regk}")

            try:
                tever = reger.tevers.get(credential_said)
                if tever is not None:
                    tel_dig = reger.getTel(key=dbing.snKey(credential_said, 1))
                    if tel_dig is not None:
                        raise ValueError(f"Credential already revoked: {credential_said}")
            except KeyError:
                pass

            hab = registry.hab
            if hab is None:
                raise ValueError(f"Registry {regk} has no associated hab")

            dt = helping.nowIso8601()
            rserder = registry.revoke(said=credential_said, dt=dt)

            rseal = eventing.SealEvent(rserder.pre, rserder.snh, rserder.said)
            anc = hab.interact(data=[dict(i=rseal.i, s=rseal.s, d=rseal.d)])

            anc_seqner = coring.Seqner(sn=hab.kever.sn)
            anc_saider = coring.Saider(qb64=hab.kever.serder.said)

            registry.anchorMsg(
                pre=rserder.pre,
                regd=rserder.said,
                seqner=anc_seqner,
                saider=anc_saider,
            )

            registry_mgr.regery.tvy.processEvent(
                serder=rserder,
                seqner=anc_seqner,
                saider=anc_saider,
            )

            log.info(f"Created TEL rev event for {credential_said[:16]}...")

            schema_said = creder.sad.get("s", "")
            recipient_aid = creder.attrib.get("i") if creder.attrib else None

            try:
                iss_raw = reger.cloneTvtAt(credential_said, sn=0)
                iss_serder = serdering.SerderKERI(raw=iss_raw)
                issuance_dt = iss_serder.ked.get("dt", "")
            except Exception:
                issuance_dt = ""

            return CredentialInfo(
                said=credential_said,
                issuer_aid=hab.pre,
                recipient_aid=recipient_aid,
                registry_key=regk,
                schema_said=schema_said,
                issuance_dt=issuance_dt,
                status="revoked",
                revocation_dt=dt,
                attributes=dict(creder.attrib) if creder.attrib else {},
                edges=creder.sad.get("e"),
                rules=creder.sad.get("r"),
            )

    async def get_credential(self, credential_said: str) -> Optional[CredentialInfo]:
        """Get credential info by SAID."""
        async with self._lock:
            registry_mgr = await get_registry_manager()
            reger = registry_mgr.regery.reger

            creder = reger.creds.get(keys=(credential_said,))
            if creder is None:
                return None

            regk = creder.sad.get("ri", "")
            registry = registry_mgr.regery.regs.get(regk) if regk else None
            issuer_aid = registry.hab.pre if registry and registry.hab else ""

            status = "issued"
            revocation_dt = None
            try:
                tel_dig = reger.getTel(key=dbing.snKey(credential_said, 1))
                if tel_dig is not None:
                    status = "revoked"
                    rev_raw = reger.cloneTvtAt(credential_said, sn=1)
                    rev_serder = serdering.SerderKERI(raw=rev_raw)
                    revocation_dt = rev_serder.ked.get("dt")
            except Exception:
                pass

            issuance_dt = ""
            try:
                iss_raw = reger.cloneTvtAt(credential_said, sn=0)
                iss_serder = serdering.SerderKERI(raw=iss_raw)
                issuance_dt = iss_serder.ked.get("dt", "")
            except Exception:
                pass

            schema_said = creder.sad.get("s", "")
            recipient_aid = creder.attrib.get("i") if creder.attrib else None

            return CredentialInfo(
                said=credential_said,
                issuer_aid=issuer_aid,
                recipient_aid=recipient_aid,
                registry_key=regk,
                schema_said=schema_said,
                issuance_dt=issuance_dt,
                status=status,
                revocation_dt=revocation_dt,
                attributes=dict(creder.attrib) if creder.attrib else {},
                edges=creder.sad.get("e"),
                rules=creder.sad.get("r"),
            )

    async def get_credential_bytes(self, credential_said: str) -> Optional[bytes]:
        """Get CESR-encoded credential with SealSourceTriples attachment."""
        async with self._lock:
            registry_mgr = await get_registry_manager()
            reger = registry_mgr.regery.reger

            try:
                creder, prefixer, seqner, saider = reger.cloneCred(said=credential_said)
                return signing.serialize(creder, prefixer, seqner, saider)
            except Exception:
                return None

    async def delete_credential(self, credential_said: str) -> bool:
        """Delete a credential from local storage and seed store.

        Sprint 73: Also removes the credential seed from PostgreSQL so the
        credential won't be rebuilt by StateBuilder on container restart.
        """
        async with self._lock:
            registry_mgr = await get_registry_manager()
            reger = registry_mgr.regery.reger

            creder = reger.creds.get(keys=(credential_said,))
            if creder is None:
                raise ValueError(f"Credential not found: {credential_said}")

            reger.creds.rem(keys=(credential_said,))

            try:
                reger.cancs.rem(keys=(credential_said,))
            except Exception:
                pass

            # Sprint 73: Cascade delete to seed store
            try:
                from app.keri.seed_store import get_seed_store
                seed_store = get_seed_store()
                seed_store.delete_credential_seed(credential_said)
            except Exception as e:
                log.warning(f"Failed to delete credential seed {credential_said[:16]}...: {e}")

            log.info(f"Deleted credential from local storage: {credential_said[:16]}...")
            return True

    async def list_credentials(
        self,
        registry_key: Optional[str] = None,
        status: Optional[str] = None,
    ) -> list[CredentialInfo]:
        """List credentials with optional filtering."""
        async with self._lock:
            registry_mgr = await get_registry_manager()
            reger = registry_mgr.regery.reger

            credentials = []

            for keys, creder in reger.creds.getItemIter():
                cred_said = keys[0] if keys else creder.said

                regk = creder.sad.get("ri", "")

                if registry_key is not None and regk != registry_key:
                    continue

                registry = registry_mgr.regery.regs.get(regk) if regk else None
                issuer_aid = registry.hab.pre if registry and registry.hab else ""

                cred_status = "issued"
                revocation_dt = None
                try:
                    tel_dig = reger.getTel(key=dbing.snKey(cred_said, 1))
                    if tel_dig is not None:
                        cred_status = "revoked"
                        rev_raw = reger.cloneTvtAt(cred_said, sn=1)
                        rev_serder = serdering.SerderKERI(raw=rev_raw)
                        revocation_dt = rev_serder.ked.get("dt")
                except Exception:
                    pass

                if status is not None and cred_status != status:
                    continue

                issuance_dt = ""
                try:
                    iss_raw = reger.cloneTvtAt(cred_said, sn=0)
                    iss_serder = serdering.SerderKERI(raw=iss_raw)
                    issuance_dt = iss_serder.ked.get("dt", "")
                except Exception:
                    pass

                schema_said = creder.sad.get("s", "")
                recipient_aid = creder.attrib.get("i") if creder.attrib else None

                cred_info = CredentialInfo(
                    said=cred_said,
                    issuer_aid=issuer_aid,
                    recipient_aid=recipient_aid,
                    registry_key=regk,
                    schema_said=schema_said,
                    issuance_dt=issuance_dt,
                    status=cred_status,
                    revocation_dt=revocation_dt,
                    attributes=dict(creder.attrib) if creder.attrib else {},
                    edges=creder.sad.get("e"),
                    rules=creder.sad.get("r"),
                )
                credentials.append(cred_info)

            return credentials


# Module-level singleton
_credential_issuer: Optional[CredentialIssuer] = None


async def get_credential_issuer() -> CredentialIssuer:
    """Get or create the credential issuer singleton."""
    global _credential_issuer
    if _credential_issuer is None:
        _credential_issuer = CredentialIssuer()
        await _credential_issuer.initialize()
    return _credential_issuer


async def close_credential_issuer() -> None:
    """Close the credential issuer singleton."""
    global _credential_issuer
    if _credential_issuer is not None:
        await _credential_issuer.close()
        _credential_issuer = None


def reset_credential_issuer() -> None:
    """Reset the singleton without closing (for testing)."""
    global _credential_issuer
    _credential_issuer = None
