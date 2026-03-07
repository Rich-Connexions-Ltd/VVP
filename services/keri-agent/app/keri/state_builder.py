"""Deterministic KERI state rebuild from PostgreSQL seeds.

Rebuilds all KERI identities, registries, and credentials from seed
data stored in PostgreSQL. Each container starts with fresh local LMDB
and replays all operations to recreate identical cryptographic state.

Sprint 69: Ephemeral LMDB & Zero-Downtime KERI Deploys.
Sprint 70: Automatic witness re-publishing on startup.
Sprint 81: Readiness gating, full KEL publishing, comprehensive verification.
"""
import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

from app.keri.readiness import (
    ReadinessState,
    ReadinessTracker,
    RebuildReport,
    get_readiness_tracker,
)
from app.keri.seed_store import get_seed_store

log = logging.getLogger(__name__)

# Sprint 81: Configurable startup budget for witness publishing
import os

WITNESS_PUBLISH_TIMEOUT = float(
    os.getenv("VVP_WITNESS_PUBLISH_TIMEOUT", "120.0")
)
# Max concurrent witness HTTP calls
WITNESS_PUBLISH_CONCURRENCY = int(
    os.getenv("VVP_WITNESS_PUBLISH_CONCURRENCY", "10")
)
# Global retry budget (max rounds across all identities)
WITNESS_PUBLISH_MAX_RETRIES = int(
    os.getenv("VVP_WITNESS_PUBLISH_MAX_RETRIES", "3")
)


class KeriStateBuilder:
    """Deterministically rebuilds all KERI state from PostgreSQL seeds."""

    def __init__(self, tracker: ReadinessTracker | None = None):
        # Cache inception event bytes captured right after makeHab(),
        # before registry/credential operations modify LMDB state.
        # Maps AID prefix -> inception event bytes (CESR with sigs).
        self._inception_cache: dict[str, bytes] = {}
        self._tracker = tracker or get_readiness_tracker()

    async def rebuild(self) -> RebuildReport:
        """Full rebuild sequence with readiness state tracking."""
        report = self._tracker.report
        report.started_at = datetime.now(timezone.utc)

        try:
            # Phase: REBUILDING
            await self._tracker.transition(ReadinessState.REBUILDING)

            report.identities_rebuilt = await self._rebuild_identities(report)
            report.rotations_replayed = await self._replay_rotations(report)
            report.registries_rebuilt = await self._rebuild_registries(report)
            report.credentials_rebuilt = await self._rebuild_credentials(report)

            # Phase: PUBLISHING
            await self._tracker.transition(ReadinessState.PUBLISHING)
            report.witnesses_published = await self._publish_to_witnesses(report)

            # Phase: VERIFYING
            await self._tracker.transition(ReadinessState.VERIFYING)
            verification_ok = await self._verify_state(report)

            if verification_ok:
                await self._tracker.transition(ReadinessState.READY)
            else:
                await self._tracker.transition(ReadinessState.FAILED)

        except Exception as e:
            report.error_codes.append(f"REBUILD_EXCEPTION:{type(e).__name__}")
            log.error(f"State rebuild failed: {e}")
            await self._tracker.transition(ReadinessState.FAILED)

        report.total_seconds = time.monotonic() - (
            report.started_at.timestamp() - time.time() + time.monotonic()
        )
        report.completed_at = datetime.now(timezone.utc)
        report.total_seconds = (
            report.completed_at - report.started_at
        ).total_seconds()

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

                # Cache inception event bytes NOW, before registry/credential
                # operations add interaction events that corrupt getKeLast(sn=0).
                try:
                    pre_bytes = hab.pre.encode("utf-8")
                    dig = hab.iserder.saidb
                    inception_msg = bytes(identity_mgr.hby.db.cloneEvtMsg(
                        pre=pre_bytes, fn=0, dig=dig
                    ))
                    self._inception_cache[hab.pre] = inception_msg
                except Exception as e:
                    log.warning(f"Failed to cache inception for {seed.name}: {e}")

                if hab.pre != seed.expected_aid:
                    report.error_codes.append(
                        f"AID_MISMATCH:{seed.name}"
                    )
                    log.error(
                        f"AID mismatch for {seed.name}: "
                        f"expected={seed.expected_aid} got={hab.pre}"
                    )
                else:
                    log.info(f"Rebuilt identity: {seed.name} ({hab.pre[:16]}...)")

                count += 1

            except Exception as e:
                report.error_codes.append(f"IDENTITY_REBUILD_FAILED:{seed.name}")
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
                    report.error_codes.append(
                        f"ROTATION_FAILED:{id_seed.name}:sn={rot_seed.sequence_number}"
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

        # Clean orphan registry seeds (identity deleted but registry seed remains)
        orphan_count = seed_store.delete_orphan_registry_seeds()
        if orphan_count > 0:
            log.info(f"Cleaned {orphan_count} orphan registry seed(s) before rebuild")

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
                    report.error_codes.append(f"REGISTRY_ORPHAN:{seed.name}")
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
                    report.error_codes.append(f"REGISTRY_KEY_MISMATCH:{seed.name}")
                    log.error(
                        f"Registry key mismatch for {seed.name}: "
                        f"expected={seed.expected_registry_key} got={registry.regk}"
                    )
                else:
                    log.info(f"Rebuilt registry: {seed.name} ({registry.regk[:16]}...)")

                count += 1

            except Exception as e:
                report.error_codes.append(f"REGISTRY_REBUILD_FAILED:{seed.name}")
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

        # Clean orphan credential seeds (issuer identity deleted)
        orphan_cred_count = seed_store.delete_orphan_credential_seeds()
        if orphan_cred_count > 0:
            log.info(f"Cleaned {orphan_cred_count} orphan credential seed(s) before rebuild")

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
                    report.error_codes.append(f"CRED_REGISTRY_MISSING:{seed.expected_said[:16]}")
                    continue

                hab = registry.hab
                if hab is None:
                    report.error_codes.append(f"CRED_HAB_MISSING:{seed.expected_said[:16]}")
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
                    report.error_codes.append(
                        f"SAID_MISMATCH:{seed.expected_said[:16]}"
                    )
                    log.error(
                        f"Credential SAID mismatch: "
                        f"expected={seed.expected_said} got={creder.said}"
                    )

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
                report.error_codes.append(
                    f"CRED_REBUILD_FAILED:{seed.expected_said[:16]}"
                )
                log.error(
                    f"Failed to rebuild credential {seed.expected_said[:16]}...: {e}"
                )

        return count

    async def _verify_state(self, report: RebuildReport) -> bool:
        """Verify rebuilt state matches seed expectations.

        Deterministic, comprehensive checks:
        1. Identity count == seed identity count (exact match)
        2. Registry count == seed registry count (exact match)
        3. Credential count == seed credential count (exact match)
        4. Full-set SAID validation for every credential
        5. TEL integrity for all credentials (iss event presence)

        Returns True if ALL checks pass, False on ANY mismatch.
        """
        seed_store = get_seed_store()
        all_ok = True

        # 1. Verify identity count
        from app.keri.identity import get_identity_manager
        identity_mgr = await get_identity_manager()
        identity_seeds = seed_store.get_all_identity_seeds()

        actual_identities = len(list(identity_mgr.hby.prefixes))
        report.identities_expected = len(identity_seeds)

        if actual_identities != report.identities_expected:
            report.error_codes.append(
                f"COUNT_MISMATCH:identities:{actual_identities}!={report.identities_expected}"
            )
            log.error(
                f"Identity count mismatch: actual={actual_identities} "
                f"expected={report.identities_expected}"
            )
            all_ok = False

        # 2. Verify registry count
        from app.keri.registry import get_registry_manager
        registry_mgr = await get_registry_manager()
        registry_seeds = seed_store.get_all_registry_seeds()

        actual_registries = len(registry_mgr.regery.regs)
        report.registries_expected = len(registry_seeds)

        if actual_registries != report.registries_expected:
            report.error_codes.append(
                f"COUNT_MISMATCH:registries:{actual_registries}!={report.registries_expected}"
            )
            log.error(
                f"Registry count mismatch: actual={actual_registries} "
                f"expected={report.registries_expected}"
            )
            all_ok = False

        # 3. Verify credential count
        credential_seeds = seed_store.get_all_credential_seeds()
        reger = registry_mgr.regery.reger
        actual_credentials = sum(1 for _ in reger.creds.getItemIter())
        report.credentials_expected = len(credential_seeds)

        if actual_credentials != report.credentials_expected:
            report.error_codes.append(
                f"COUNT_MISMATCH:credentials:{actual_credentials}!={report.credentials_expected}"
            )
            log.error(
                f"Credential count mismatch: actual={actual_credentials} "
                f"expected={report.credentials_expected}"
            )
            all_ok = False

        # 4. Full-set SAID validation with recomputation (offloaded to thread pool)
        def _verify_saids():
            from keri.core.coring import Saider

            passed = 0
            failed = 0
            for seed in credential_seeds:
                try:
                    cred = reger.creds.get(keys=(seed.expected_said,))
                    if cred is None:
                        report.error_codes.append(
                            f"SAID_MISSING:{seed.expected_said[:16]}"
                        )
                        failed += 1
                        continue
                    if cred.said != seed.expected_said:
                        report.error_codes.append(
                            f"SAID_MISMATCH:{seed.expected_said[:16]}"
                        )
                        failed += 1
                        continue
                    # Recompute and verify SAID from credential content
                    # (Blake3-256 hash of canonicalized credential)
                    saider = Saider(qb64=cred.said)
                    if not saider.verify(cred.sad, prefixed=True):
                        report.error_codes.append(
                            f"SAID_RECOMPUTE_MISMATCH:{seed.expected_said[:16]}"
                        )
                        failed += 1
                    else:
                        passed += 1
                except Exception as e:
                    report.error_codes.append(
                        f"SAID_CHECK_ERROR:{seed.expected_said[:16]}"
                    )
                    log.error(f"SAID check error for {seed.expected_said[:16]}: {e}")
                    failed += 1
            return passed, failed

        said_passed, said_failed = await asyncio.to_thread(_verify_saids)
        report.said_checks_passed = said_passed
        report.said_checks_failed = said_failed
        if said_failed > 0:
            all_ok = False

        # 5. TEL integrity verification
        tel_ok = await self._verify_tel_integrity(report, credential_seeds, reger)
        if not tel_ok:
            all_ok = False

        log.info(
            f"State verification: identities={actual_identities}/{report.identities_expected}, "
            f"registries={actual_registries}/{report.registries_expected}, "
            f"credentials={actual_credentials}/{report.credentials_expected}, "
            f"said_ok={said_passed}/{said_passed + said_failed}, "
            f"tel_ok={report.tel_integrity_passed}/{report.tel_integrity_passed + report.tel_integrity_failed}, "
            f"errors={len(report.error_codes)}"
        )

        return all_ok

    async def _verify_tel_integrity(
        self, report: RebuildReport, credential_seeds, reger
    ) -> bool:
        """Verify TEL state is consistent in local LMDB Reger.

        VVP uses simple (non-backer) registries exclusively (no_backers=True),
        so only iss/rev TEL event types are expected.
        """
        def _check_tel():
            passed = 0
            failed = 0
            for seed in credential_seeds:
                try:
                    # Check TEL issuance event exists
                    cancs = reger.cancs.get(keys=(seed.expected_said,))
                    if cancs is None:
                        report.error_codes.append(
                            f"TEL_MISSING_ISS:{seed.expected_said[:16]}"
                        )
                        failed += 1
                        continue
                    passed += 1
                except Exception as e:
                    report.error_codes.append(
                        f"TEL_CHECK_ERROR:{seed.expected_said[:16]}"
                    )
                    log.error(f"TEL check error for {seed.expected_said[:16]}: {e}")
                    failed += 1
            return passed, failed

        tel_passed, tel_failed = await asyncio.to_thread(_check_tel)
        report.tel_integrity_passed = tel_passed
        report.tel_integrity_failed = tel_failed
        return tel_failed == 0

    async def _publish_to_witnesses(self, report: RebuildReport) -> int:
        """Publish full KEL for all rebuilt identities to witnesses.

        Uses publish_full_kel() to send complete KEL (all event types
        with CESR attachments) via two-phase receipt protocol.
        Delegation-aware: delegators published before delegates.
        """
        from app.keri.identity import get_identity_manager
        from app.keri.witness import get_witness_publisher

        start = time.monotonic()
        identity_mgr = await get_identity_manager()
        publisher = get_witness_publisher()

        # Only publish identities created from seeds
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
            f"Publishing full KEL for {len(habs_with_witnesses)} identities to witnesses..."
        )

        # Publish with bounded concurrency
        semaphore = asyncio.Semaphore(WITNESS_PUBLISH_CONCURRENCY)

        async def _publish_one(hab):
            async with semaphore:
                try:
                    result = await publisher.publish_full_kel(
                        pre=hab.pre,
                        hby=identity_mgr.hby,
                    )
                    if result.threshold_met:
                        log.info(
                            f"Published full KEL for {hab.name} ({hab.pre[:16]}...) to "
                            f"{result.success_count}/{result.total_count} witnesses"
                        )
                        return True
                    else:
                        log.warning(
                            f"KEL publish below threshold for {hab.name}: "
                            f"{result.success_count}/{result.total_count}"
                        )
                        return False
                except Exception as e:
                    log.warning(
                        f"Failed to publish KEL for {hab.name}: {e}"
                    )
                    report.error_codes.append(
                        f"WITNESS_PUBLISH_FAILED:{hab.name}"
                    )
                    return False

        try:
            results = await asyncio.wait_for(
                asyncio.gather(
                    *[_publish_one(hab) for hab in habs_with_witnesses],
                    return_exceptions=True,
                ),
                timeout=WITNESS_PUBLISH_TIMEOUT,
            )
        except asyncio.TimeoutError:
            log.error(
                f"Witness publishing timed out after {WITNESS_PUBLISH_TIMEOUT}s"
            )
            report.error_codes.append(
                f"WITNESS_PUBLISH_TIMEOUT:{WITNESS_PUBLISH_TIMEOUT}s"
            )
            report.witness_publish_seconds = time.monotonic() - start
            return 0

        count = 0
        failed_habs = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                hab = habs_with_witnesses[i]
                log.warning(f"Witness publish exception for {hab.name}: {result}")
                report.error_codes.append(f"WITNESS_PUBLISH_EXCEPTION:{hab.name}")
                failed_habs.append(hab)
            elif result:
                count += 1
            else:
                failed_habs.append(habs_with_witnesses[i])

        report.witness_publish_seconds = time.monotonic() - start
        report.witnesses_published = count
        log.info(
            f"Witness publishing complete: {count}/{len(habs_with_witnesses)} "
            f"identities in {report.witness_publish_seconds:.1f}s"
        )

        # Schedule supervised background retry for failures
        if failed_habs:
            log.info(
                f"Scheduling supervised retry for {len(failed_habs)} "
                f"failed witness publishes"
            )
            report.witness_retries_pending = len(failed_habs)
            task = asyncio.create_task(
                self._retry_failed_publishes(failed_habs, report)
            )
            self._tracker.track_task(task)

        return count

    async def _retry_failed_publishes(
        self,
        failed_habs: list,
        report: RebuildReport,
        initial_delay: float = 15.0,
    ) -> None:
        """Supervised background retry for failed witness publishes.

        Uses global retry budget (max rounds). Each completion decrements
        report.witness_retries_pending.
        """
        from app.keri.identity import get_identity_manager
        from app.keri.witness import get_witness_publisher

        identity_mgr = await get_identity_manager()
        publisher = get_witness_publisher()
        remaining = list(failed_habs)

        for attempt in range(WITNESS_PUBLISH_MAX_RETRIES):
            delay = initial_delay * (2 ** attempt)
            delay = min(delay, 300.0)
            log.info(
                f"Witness publish retry {attempt + 1}/{WITNESS_PUBLISH_MAX_RETRIES}: "
                f"waiting {delay:.0f}s for {len(remaining)} identities"
            )
            await asyncio.sleep(delay)

            still_failing = []
            for hab in remaining:
                try:
                    result = await publisher.publish_full_kel(
                        pre=hab.pre,
                        hby=identity_mgr.hby,
                    )
                    if result.threshold_met:
                        log.info(
                            f"Retry publish succeeded for {hab.name}: "
                            f"{result.success_count}/{result.total_count}"
                        )
                        report.witness_retries_pending -= 1
                    else:
                        still_failing.append(hab)
                except Exception as e:
                    log.warning(f"Retry publish failed for {hab.name}: {e}")
                    still_failing.append(hab)

            remaining = still_failing
            if not remaining:
                log.info("All witness publish retries succeeded")
                report.witness_retries_pending = 0
                return

        if remaining:
            names = [h.name for h in remaining]
            log.error(
                f"Witness publish retries exhausted after {WITNESS_PUBLISH_MAX_RETRIES} "
                f"attempts. Still failing: {names}."
            )
            report.witness_retries_pending = len(remaining)
