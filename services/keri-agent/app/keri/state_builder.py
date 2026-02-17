"""Deterministic KERI state rebuild from PostgreSQL seeds.

Rebuilds all KERI identities, registries, and credentials from seed
data stored in PostgreSQL. Each container starts with fresh local LMDB
and replays all operations to recreate identical cryptographic state.

Sprint 69: Ephemeral LMDB & Zero-Downtime KERI Deploys.
Sprint 70: Automatic witness re-publishing on startup.
"""
import asyncio
import json
import logging
import time
from dataclasses import dataclass, field

from app.keri.seed_store import get_seed_store

log = logging.getLogger(__name__)


@dataclass
class RebuildReport:
    """Summary of a state rebuild operation."""

    total_seconds: float = 0.0
    identities_rebuilt: int = 0
    rotations_replayed: int = 0
    registries_rebuilt: int = 0
    credentials_rebuilt: int = 0
    witnesses_published: int = 0
    witness_publish_seconds: float = 0.0
    errors: list[str] = field(default_factory=list)

    def __str__(self) -> str:
        parts = [
            f"{self.total_seconds:.1f}s total",
            f"{self.identities_rebuilt} identities",
            f"{self.rotations_replayed} rotations",
            f"{self.registries_rebuilt} registries",
            f"{self.credentials_rebuilt} credentials",
            f"{self.witnesses_published} witness publications ({self.witness_publish_seconds:.1f}s)",
        ]
        if self.errors:
            parts.append(f"{len(self.errors)} errors")
        return ", ".join(parts)


class KeriStateBuilder:
    """Deterministically rebuilds all KERI state from PostgreSQL seeds."""

    async def rebuild(self) -> RebuildReport:
        """Full rebuild sequence. Returns timing and count report."""
        report = RebuildReport()
        start = time.monotonic()

        try:
            report.identities_rebuilt = await self._rebuild_identities(report)
            report.rotations_replayed = await self._replay_rotations(report)
            report.registries_rebuilt = await self._rebuild_registries(report)
            report.credentials_rebuilt = await self._rebuild_credentials(report)
            await self._verify_state(report)
            report.witnesses_published = await self._publish_to_witnesses(report)
        except Exception as e:
            report.errors.append(f"Rebuild failed: {e}")
            log.error(f"State rebuild failed: {e}")

        report.total_seconds = time.monotonic() - start
        return report

    async def _rebuild_identities(self, report: RebuildReport) -> int:
        """Replay all makeHab() calls from identity seeds."""
        from app.keri.identity import get_identity_manager

        seed_store = get_seed_store()
        identity_seeds = seed_store.get_all_identity_seeds()

        if not identity_seeds:
            log.info("No identity seeds to rebuild")
            return 0

        identity_mgr = await get_identity_manager()
        count = 0

        for seed in identity_seeds:
            try:
                # Check if identity already exists (idempotent)
                existing = identity_mgr.hby.habByName(seed.name)
                if existing is not None:
                    log.debug(f"Identity already exists: {seed.name}")
                    count += 1
                    continue

                witness_aids = json.loads(seed.witness_aids)

                hab = identity_mgr.hby.makeHab(
                    name=seed.name,
                    transferable=seed.transferable,
                    icount=seed.icount,
                    isith=seed.isith,
                    ncount=seed.ncount,
                    nsith=seed.nsith,
                    wits=witness_aids,
                    toad=seed.toad,
                )

                if hab.pre != seed.expected_aid:
                    report.errors.append(
                        f"AID mismatch for {seed.name}: "
                        f"expected={seed.expected_aid[:16]}... got={hab.pre[:16]}..."
                    )
                    log.error(
                        f"AID mismatch for {seed.name}: "
                        f"expected={seed.expected_aid} got={hab.pre}"
                    )
                else:
                    log.info(f"Rebuilt identity: {seed.name} ({hab.pre[:16]}...)")

                count += 1

            except Exception as e:
                report.errors.append(f"Failed to rebuild identity {seed.name}: {e}")
                log.error(f"Failed to rebuild identity {seed.name}: {e}")

        return count

    async def _replay_rotations(self, report: RebuildReport) -> int:
        """Replay all rotation events per identity in sequence_number order."""
        from app.keri.identity import get_identity_manager

        seed_store = get_seed_store()
        identity_seeds = seed_store.get_all_identity_seeds()
        identity_mgr = await get_identity_manager()
        count = 0

        for id_seed in identity_seeds:
            rotations = seed_store.get_rotations_for_identity(id_seed.name)
            if not rotations:
                continue

            hab = identity_mgr.hby.habByName(id_seed.name)
            if hab is None:
                log.warning(f"Cannot replay rotations for {id_seed.name}: identity not found")
                continue

            for rot_seed in rotations:
                try:
                    # Skip if already at or past this sequence number
                    if hab.kever.sn >= rot_seed.sequence_number:
                        count += 1
                        continue

                    hab.rotate(
                        ncount=rot_seed.ncount,
                        nsith=rot_seed.nsith,
                    )
                    count += 1
                    log.debug(
                        f"Replayed rotation: {id_seed.name} sn={rot_seed.sequence_number}"
                    )

                except Exception as e:
                    report.errors.append(
                        f"Failed to replay rotation {id_seed.name} "
                        f"sn={rot_seed.sequence_number}: {e}"
                    )
                    log.error(
                        f"Failed to replay rotation {id_seed.name} "
                        f"sn={rot_seed.sequence_number}: {e}"
                    )

        return count

    async def _rebuild_registries(self, report: RebuildReport) -> int:
        """Replay all makeRegistry() calls from registry seeds."""
        from keri.core import coring, eventing
        from app.keri.identity import get_identity_manager
        from app.keri.registry import get_registry_manager

        seed_store = get_seed_store()
        registry_seeds = seed_store.get_all_registry_seeds()

        if not registry_seeds:
            log.info("No registry seeds to rebuild")
            return 0

        identity_mgr = await get_identity_manager()
        registry_mgr = await get_registry_manager()
        count = 0

        for seed in registry_seeds:
            try:
                # Check if registry already exists (idempotent)
                existing = registry_mgr.regery.registryByName(seed.name)
                if existing is not None:
                    log.debug(f"Registry already exists: {seed.name}")
                    count += 1
                    continue

                # Find the issuer identity
                identity_seed = None
                for id_seed in seed_store.get_all_identity_seeds():
                    if id_seed.name == seed.identity_name:
                        identity_seed = id_seed
                        break

                if identity_seed is None:
                    report.errors.append(f"Identity {seed.identity_name} not found for registry {seed.name}")
                    continue

                issuer_aid = identity_seed.expected_aid

                # Create registry with stored nonce
                kwargs = dict(
                    name=seed.name,
                    prefix=issuer_aid,
                    noBackers=seed.no_backers,
                )
                if seed.nonce:
                    kwargs["nonce"] = seed.nonce

                registry = registry_mgr.regery.makeRegistry(**kwargs)

                # Anchor TEL inception in KEL (same as create_registry)
                hab = registry.hab
                rseal = eventing.SealEvent(registry.vcp.pre, registry.vcp.snh, registry.vcp.said)
                hab.interact(data=[dict(i=rseal.i, s=rseal.s, d=rseal.d)])

                seqner = coring.Seqner(sn=hab.kever.sn)
                saider = coring.Saider(qb64=hab.kever.serder.said)

                registry.anchorMsg(
                    pre=registry.regk,
                    regd=registry.regd,
                    seqner=seqner,
                    saider=saider,
                )

                registry_mgr.regery.tvy.processEvent(
                    serder=registry.vcp,
                    seqner=seqner,
                    saider=saider,
                )

                if registry.regk != seed.expected_registry_key:
                    report.errors.append(
                        f"Registry key mismatch for {seed.name}: "
                        f"expected={seed.expected_registry_key[:16]}... "
                        f"got={registry.regk[:16]}..."
                    )
                    log.error(
                        f"Registry key mismatch for {seed.name}: "
                        f"expected={seed.expected_registry_key} got={registry.regk}"
                    )
                else:
                    log.info(f"Rebuilt registry: {seed.name} ({registry.regk[:16]}...)")

                count += 1

            except Exception as e:
                report.errors.append(f"Failed to rebuild registry {seed.name}: {e}")
                log.error(f"Failed to rebuild registry {seed.name}: {e}")

        return count

    async def _rebuild_credentials(self, report: RebuildReport) -> int:
        """Replay all issue_credential() calls in topological order."""
        from keri import core
        from keri.app import signing
        from keri.core import coring, eventing
        from keri.help import helping
        from keri.vc import proving
        from app.keri.registry import get_registry_manager
        from app.schema.store import has_embedded_schema

        seed_store = get_seed_store()
        credential_seeds = seed_store.get_all_credential_seeds()

        if not credential_seeds:
            log.info("No credential seeds to rebuild")
            return 0

        registry_mgr = await get_registry_manager()
        count = 0

        for seed in credential_seeds:
            try:
                # Check if credential already exists (idempotent)
                reger = registry_mgr.regery.reger
                existing = reger.creds.get(keys=(seed.expected_said,))
                if existing is not None:
                    log.debug(f"Credential already exists: {seed.expected_said[:16]}...")
                    count += 1
                    continue

                # Find registry
                registry = registry_mgr.regery.registryByName(seed.registry_name)
                if registry is None:
                    report.errors.append(f"Registry {seed.registry_name} not found for credential {seed.expected_said[:16]}...")
                    continue

                hab = registry.hab
                if hab is None:
                    report.errors.append(f"No hab for registry {seed.registry_name}")
                    continue

                # Deserialize stored JSON
                attributes = json.loads(seed.attributes_json)
                edges = json.loads(seed.edges_json) if seed.edges_json else None
                rules = json.loads(seed.rules_json) if seed.rules_json else None

                # Create ACDC
                creder = proving.credential(
                    schema=seed.schema_said,
                    issuer=hab.pre,
                    data=attributes,
                    recipient=seed.recipient_aid,
                    private=seed.private,
                    status=registry.regk,
                    source=edges,
                    rules=rules,
                )

                if creder.said != seed.expected_said:
                    report.errors.append(
                        f"Credential SAID mismatch: "
                        f"expected={seed.expected_said[:16]}... "
                        f"got={creder.said[:16]}..."
                    )
                    log.error(
                        f"Credential SAID mismatch: "
                        f"expected={seed.expected_said} got={creder.said}"
                    )
                    # Still process it — the credential was created, just verify failed
                    # This allows the system to come up even with mismatches

                # Create TEL issuance event
                dt = attributes.get("dt", helping.nowIso8601())
                iserder = registry.issue(said=creder.said, dt=dt)

                # Create KEL anchor
                rseal = eventing.SealEvent(iserder.pre, iserder.snh, iserder.said)
                hab.interact(data=[dict(i=rseal.i, s=rseal.s, d=rseal.d)])

                # Anchor the TEL iss event
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

                # Store credential in reger
                prefixer = coring.Prefixer(qb64=iserder.pre)
                seqner = core.Number(num=iserder.sn, code=core.NumDex.Huge)
                saider = coring.Saider(qb64=iserder.said)

                reger.creds.put(keys=(creder.said,), val=creder)
                reger.cancs.pin(keys=(creder.said,), val=[prefixer, seqner, saider])

                log.info(
                    f"Rebuilt credential: {creder.said[:16]}... "
                    f"order={seed.rebuild_order}"
                )
                count += 1

            except Exception as e:
                report.errors.append(
                    f"Failed to rebuild credential {seed.expected_said[:16]}...: {e}"
                )
                log.error(
                    f"Failed to rebuild credential {seed.expected_said[:16]}...: {e}"
                )

        return count

    async def _verify_state(self, report: RebuildReport) -> None:
        """Verify all AIDs, registry keys, and credential SAIDs match expected."""
        seed_store = get_seed_store()

        # Verify identity count
        from app.keri.identity import get_identity_manager
        identity_mgr = await get_identity_manager()
        identity_seeds = seed_store.get_all_identity_seeds()
        actual_identities = len(list(identity_mgr.hby.prefixes))
        expected_identities = len(identity_seeds)

        if actual_identities < expected_identities:
            msg = (
                f"Identity count mismatch: expected={expected_identities} "
                f"actual={actual_identities}"
            )
            report.errors.append(msg)
            log.warning(msg)

        log.info(
            f"State verification: {actual_identities}/{expected_identities} identities, "
            f"{report.registries_rebuilt} registries, "
            f"{report.credentials_rebuilt} credentials, "
            f"{len(report.errors)} errors"
        )

    async def _publish_to_witnesses(self, report: RebuildReport) -> int:
        """Publish all rebuilt identity KELs to witnesses.

        Iterates in-memory hby.habs, filters to identities with witnesses,
        and publishes their KELs concurrently via asyncio.gather. Failures
        are logged but do not prevent startup.
        """
        from app.keri.identity import get_identity_manager
        from app.keri.witness import get_witness_publisher

        start = time.monotonic()
        identity_mgr = await get_identity_manager()
        publisher = get_witness_publisher()

        # Only publish identities created from seeds (skip keripy internals
        # like the Habery signator which also has witnesses configured)
        seed_store = get_seed_store()
        seeded_aids = {s.expected_aid for s in seed_store.get_all_identity_seeds()}

        habs_with_witnesses = []
        for pre, hab in identity_mgr.hby.habs.items():
            if pre not in seeded_aids:
                continue
            if hab.kever and hab.kever.wits:
                habs_with_witnesses.append(hab)

        if not habs_with_witnesses:
            log.info("No identities with witnesses to publish")
            report.witness_publish_seconds = time.monotonic() - start
            return 0

        log.info(
            f"Publishing {len(habs_with_witnesses)} identities to witnesses..."
        )

        async def _publish_one(hab):
            """Publish a single identity's inception event to witnesses."""
            aid = hab.pre
            try:
                # Send only the inception event (not full KEL) to avoid
                # confusing the witness's framed parser with subsequent
                # interaction/rotation events after the controller signature.
                inception_msg = await identity_mgr.get_inception_msg(aid)
                result = await publisher.publish_oobi(aid, inception_msg)
                if result.threshold_met:
                    log.info(
                        f"Published {hab.name} ({aid[:16]}...) to "
                        f"{result.success_count}/{result.total_count} witnesses"
                    )
                    return True
                else:
                    log.warning(
                        f"Witness publish below threshold for {hab.name} "
                        f"({aid[:16]}...): {result.success_count}/{result.total_count}"
                    )
                    for wr in result.witnesses:
                        if not wr.success:
                            log.warning(
                                f"  Witness {wr.url} failed: {wr.error}"
                            )
                    return result.success_count > 0
            except Exception as e:
                log.warning(
                    f"Failed to publish {hab.name} ({aid[:16]}...) "
                    f"to witnesses: {e}"
                )
                report.errors.append(
                    f"Witness publish failed for {hab.name}: {e}"
                )
                return False

        results = await asyncio.gather(
            *[_publish_one(hab) for hab in habs_with_witnesses],
            return_exceptions=True,
        )

        count = 0
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                hab = habs_with_witnesses[i]
                log.warning(
                    f"Witness publish exception for {hab.name}: {result}"
                )
                report.errors.append(
                    f"Witness publish exception for {hab.name}: {result}"
                )
            elif result:
                count += 1

        report.witness_publish_seconds = time.monotonic() - start
        log.info(
            f"Witness publishing complete: {count}/{len(habs_with_witnesses)} "
            f"identities in {report.witness_publish_seconds:.1f}s"
        )
        return count
