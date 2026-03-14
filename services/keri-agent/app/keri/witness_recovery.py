"""Centralized witness state validation and recovery.

All callers (startup, monitor, admin) use WitnessRecoveryService.
Owns the republish lock to prevent concurrent operations.

Recovery proceeds in three phases per degraded witness:
  Phase A — Full KEL replay via publish_full_kel()
  Phase B — Event-digest-aware receipt redistribution (establishment events only)
  Phase C — Full verification of ALL seeded identities

Sprint 86: Witness State Resilience.
"""
import asyncio
import logging
import os
import time
from dataclasses import dataclass, field
from urllib.parse import urlparse

import httpx
from keri.core import eventing, serdering
from keri.core.indexing import Siger
from keri.core import coring

from app.config import WITNESS_IURLS, WITNESS_TIMEOUT_SECONDS
from app.keri.witness import WitnessPublisher, get_witness_publisher

log = logging.getLogger(__name__)

# Environment configuration
VVP_ENV = os.getenv("VVP_ENV", "local")
WITNESS_MONITOR_INTERVAL = float(os.getenv("VVP_WITNESS_MONITOR_INTERVAL", "300"))
OOBI_MAX_RESPONSE_BYTES = 1_048_576  # 1 MB


class WitnessConfigurationError(Exception):
    """Raised when a witness URL fails validation."""


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------

@dataclass
class WitnessStateCheck:
    """Result of checking one witness's key state for one identity."""

    witness_url: str
    aid: str
    expected_sn: int
    expected_said: str
    witness_sn: int | None = None
    witness_said: str | None = None
    healthy: bool = False
    status: str = "unknown"  # healthy, stale, corrupted, divergent, unreachable


@dataclass
class WitnessRecoveryResult:
    """Typed result for one witness's recovery outcome."""

    witness_url: str
    was_degraded: bool = False
    identities_published: int = 0
    identities_verified: int = 0
    identities_failed: int = 0
    receipt_redistribution_ok: bool = False
    fully_recovered: bool = False
    error_codes: list[str] = field(default_factory=list)


@dataclass
class RecoveryReport:
    """Structured result for all witness recovery operations."""

    action: str = "admin_republish"
    witnesses_checked: int = 0
    witnesses_degraded: int = 0
    identities_published: int = 0
    identities_total: int = 0
    identities_verified: int = 0
    identities_failed: int = 0
    fully_recovered: bool = False
    elapsed_seconds: float = 0.0
    per_witness: list[WitnessRecoveryResult] = field(default_factory=list)
    error_codes: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------

class WitnessRecoveryService:
    """Centralized witness state validation and recovery.

    All callers (startup, monitor, admin) use this service.
    Owns the republish lock to prevent concurrent operations.
    """

    def __init__(
        self,
        publisher: WitnessPublisher | None = None,
        cooldown_seconds: float = 120.0,
        max_recoveries_per_hour: int = 3,
    ):
        self._publisher = publisher or get_witness_publisher()
        self._cooldown_seconds = cooldown_seconds
        self._max_per_hour = max_recoveries_per_hour

        self._lock = asyncio.Lock()
        # Per-witness tracking: url -> list of recovery timestamps
        self._recovery_history: dict[str, list[float]] = {}
        self._last_recovery_time: dict[str, float] = {}
        self._circuit_open: set[str] = set()

        # Rotating probe index for monitoring mode
        self._probe_index = 0

        # Extract configured witness URLs from IURLS
        self._witness_urls = self._extract_witness_urls()

    def _extract_witness_urls(self) -> list[str]:
        """Extract base witness URLs from configured OOBI introduction URLs.

        Parses WITNESS_IURLS (e.g. 'http://host:port/oobi/AID/controller')
        and returns the base URL portion before '/oobi/'.
        """
        urls = []
        for iurl in WITNESS_IURLS:
            parts = iurl.split("/oobi/")
            if parts:
                urls.append(parts[0].rstrip("/"))
        return urls

    def _validate_witness_url(self, url: str) -> str:
        """Validate a witness URL against the configured allowlist.

        Raises WitnessConfigurationError if invalid.
        """
        normalized = url.rstrip("/")
        parsed = urlparse(normalized)

        # Allowlist enforcement
        if normalized not in self._witness_urls:
            raise WitnessConfigurationError(
                f"Witness URL not in configured pool: {normalized}"
            )

        # HTTPS enforcement in non-local environments
        if VVP_ENV not in ("local", "test") and parsed.scheme != "https":
            raise WitnessConfigurationError(
                f"HTTPS required in {VVP_ENV} environment: {normalized}"
            )

        return normalized

    def _check_cooldown(self, witness_url: str) -> bool:
        """Return True if witness is within cooldown window."""
        last = self._last_recovery_time.get(witness_url, 0)
        return (time.monotonic() - last) < self._cooldown_seconds

    def _check_budget(self, witness_url: str) -> bool:
        """Return True if witness has exhausted hourly budget."""
        now = time.monotonic()
        history = self._recovery_history.get(witness_url, [])
        # Keep only last hour
        recent = [t for t in history if now - t < 3600]
        self._recovery_history[witness_url] = recent
        return len(recent) >= self._max_per_hour

    def _record_recovery(self, witness_url: str) -> None:
        """Record a recovery attempt for budget tracking."""
        now = time.monotonic()
        self._last_recovery_time[witness_url] = now
        if witness_url not in self._recovery_history:
            self._recovery_history[witness_url] = []
        self._recovery_history[witness_url].append(now)

    async def check_witness_state(
        self,
        probe_all: bool = False,
    ) -> list[WitnessStateCheck]:
        """Key-state-aware health check for all witnesses.

        Args:
            probe_all: If True, check ALL seeded identities.
                       If False, use rotating bounded probe set (up to 3).
        """
        from app.keri.identity import get_identity_manager
        from app.keri.seed_store import get_seed_store

        identity_mgr = await get_identity_manager()
        seed_store = get_seed_store()
        seeds = seed_store.get_all_identity_seeds()

        if not seeds:
            return []

        # Select probe set
        if probe_all:
            probe_seeds = seeds
        else:
            # Rotating window of up to 3
            n = min(3, len(seeds))
            start = self._probe_index % len(seeds)
            probe_seeds = []
            for i in range(n):
                probe_seeds.append(seeds[(start + i) % len(seeds)])
            self._probe_index += n

        results: list[WitnessStateCheck] = []

        for seed in probe_seeds:
            hab = identity_mgr.hby.habByName(seed.name)
            if hab is None or hab.kever is None:
                continue

            expected_sn = hab.kever.sn
            expected_said = hab.kever.serder.said

            for witness_url in self._witness_urls:
                try:
                    self._validate_witness_url(witness_url)
                except WitnessConfigurationError as e:
                    results.append(WitnessStateCheck(
                        witness_url=witness_url,
                        aid=seed.expected_aid,
                        expected_sn=expected_sn,
                        expected_said=expected_said,
                        healthy=False,
                        status="config_error",
                    ))
                    continue

                check = await self._probe_witness(
                    witness_url, seed.expected_aid, expected_sn, expected_said
                )
                results.append(check)

        return results

    async def _probe_witness(
        self,
        witness_url: str,
        aid: str,
        expected_sn: int,
        expected_said: str,
    ) -> WitnessStateCheck:
        """Probe a single witness for a single identity's key state."""
        oobi_url = f"{witness_url}/oobi/{aid}/controller"
        check = WitnessStateCheck(
            witness_url=witness_url,
            aid=aid,
            expected_sn=expected_sn,
            expected_said=expected_said,
        )

        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(WITNESS_TIMEOUT_SECONDS, connect=5.0),
                follow_redirects=False,
            ) as client:
                resp = await client.get(oobi_url)

                if resp.status_code == 404:
                    check.status = "stale"
                    return check

                if resp.status_code != 200:
                    check.status = "unreachable"
                    return check

                # Size guard
                if len(resp.content) > OOBI_MAX_RESPONSE_BYTES:
                    check.status = "stale"  # fail-closed
                    return check

                # Parse CESR response to extract sn/said
                witness_sn, witness_said = self._parse_oobi_state(
                    resp.content, aid
                )
                check.witness_sn = witness_sn
                check.witness_said = witness_said

                if witness_sn is None or witness_said is None:
                    check.status = "stale"  # fail-closed: unparseable
                    return check

                # Exact-match health predicate
                if witness_sn == expected_sn and witness_said == expected_said:
                    check.healthy = True
                    check.status = "healthy"
                elif witness_sn > expected_sn:
                    check.status = "divergent"
                elif witness_sn == expected_sn and witness_said != expected_said:
                    check.status = "corrupted"
                else:
                    check.status = "stale"

        except (httpx.TimeoutException, httpx.ConnectError):
            check.status = "unreachable"
        except Exception as e:
            log.warning(f"Witness probe failed for {aid[:16]}... on {witness_url}: {e}")
            check.status = "stale"  # fail-closed

        return check

    def _parse_oobi_state(
        self, content: bytes, aid: str
    ) -> tuple[int | None, str | None]:
        """Parse OOBI CESR response to extract latest sn and SAID.

        Iterates through the CESR stream to find the last event
        matching the target AID prefix.
        """
        try:
            msg = bytearray(content)
            latest_sn = None
            latest_said = None

            while msg:
                try:
                    serder = serdering.SerderKERI(raw=msg)
                except Exception:
                    break

                if serder.pre == aid:
                    latest_sn = serder.sn
                    latest_said = serder.said

                # Advance past this event + its attachments
                msg = msg[serder.size:]
                # Skip CESR attachments (start with -)
                while msg and msg[0:1] == b"-":
                    try:
                        from keri.core.counting import Counter
                        ctr = Counter(qb64b=msg, strip=True)
                        # Skip the counted group
                        for _ in range(ctr.count):
                            # Skip verfer/siger/cigar entries
                            coring.Verfer(qb64b=msg, strip=True)
                    except Exception:
                        # Can't parse further attachments — break
                        break

            return latest_sn, latest_said

        except Exception as e:
            log.debug(f"Failed to parse OOBI state for {aid[:16]}...: {e}")
            return None, None

    async def recover_degraded_witnesses(
        self,
        degraded_urls: list[str] | None = None,
        action: str = "admin_republish",
        force: bool = False,
    ) -> RecoveryReport:
        """Republish identities to specific degraded witnesses only.

        Processes ALL seeded identities for each degraded witness.
        """
        start = time.monotonic()
        report = RecoveryReport(action=action)

        from app.keri.identity import get_identity_manager
        from app.keri.seed_store import get_seed_store

        identity_mgr = await get_identity_manager()
        seed_store = get_seed_store()
        seeds = seed_store.get_all_identity_seeds()
        report.identities_total = len(seeds)

        if not seeds:
            report.fully_recovered = True
            report.elapsed_seconds = time.monotonic() - start
            return report

        # If no specific URLs given, check all and find degraded ones
        if degraded_urls is None:
            checks = await self.check_witness_state(probe_all=True)
            # Group by witness URL
            degraded_set: set[str] = set()
            all_urls: set[str] = set()
            for c in checks:
                all_urls.add(c.witness_url)
                if not c.healthy:
                    degraded_set.add(c.witness_url)
            report.witnesses_checked = len(all_urls)
            report.witnesses_degraded = len(degraded_set)
            target_urls = list(degraded_set)
        else:
            report.witnesses_checked = len(degraded_urls)
            report.witnesses_degraded = len(degraded_urls)
            target_urls = degraded_urls

        if not target_urls:
            report.fully_recovered = True
            report.elapsed_seconds = time.monotonic() - start
            return report

        async with self._lock:
            all_recovered = True

            for witness_url in target_urls:
                # Validate URL
                try:
                    witness_url = self._validate_witness_url(witness_url)
                except WitnessConfigurationError as e:
                    log.error(f"Invalid witness URL: {e}")
                    wr = WitnessRecoveryResult(
                        witness_url=witness_url,
                        was_degraded=True,
                        error_codes=[f"CONFIG_ERROR:{witness_url}"],
                    )
                    report.per_witness.append(wr)
                    report.error_codes.append(f"CONFIG_ERROR:{witness_url}")
                    all_recovered = False
                    continue

                # Check circuit breaker (unless force)
                if not force and witness_url in self._circuit_open:
                    log.warning(f"Circuit open for {witness_url}, skipping")
                    wr = WitnessRecoveryResult(
                        witness_url=witness_url,
                        was_degraded=True,
                        error_codes=[f"CIRCUIT_OPEN:{witness_url}"],
                    )
                    report.per_witness.append(wr)
                    report.error_codes.append(f"CIRCUIT_OPEN:{witness_url}")
                    all_recovered = False
                    continue

                # Check cooldown (unless force)
                if not force and self._check_cooldown(witness_url):
                    log.info(f"Cooldown active for {witness_url}, skipping")
                    wr = WitnessRecoveryResult(
                        witness_url=witness_url,
                        was_degraded=True,
                        error_codes=[f"COOLDOWN_ACTIVE:{witness_url}"],
                    )
                    report.per_witness.append(wr)
                    report.error_codes.append(f"COOLDOWN_ACTIVE:{witness_url}")
                    all_recovered = False
                    continue

                # Check hourly budget (unless force)
                if not force and self._check_budget(witness_url):
                    self._circuit_open.add(witness_url)
                    log.warning(
                        f"witness_circuit_open: {witness_url}, "
                        f"failed_attempts: {self._max_per_hour}"
                    )
                    wr = WitnessRecoveryResult(
                        witness_url=witness_url,
                        was_degraded=True,
                        error_codes=[f"BUDGET_EXHAUSTED:{witness_url}"],
                    )
                    report.per_witness.append(wr)
                    report.error_codes.append(f"BUDGET_EXHAUSTED:{witness_url}")
                    all_recovered = False
                    continue

                # Record attempt
                self._record_recovery(witness_url)

                # Perform recovery
                wr = await self._recover_one_witness(
                    witness_url, seeds, identity_mgr, action
                )
                report.per_witness.append(wr)
                report.identities_published += wr.identities_published
                report.identities_verified += wr.identities_verified
                report.identities_failed += wr.identities_failed
                report.error_codes.extend(wr.error_codes)

                if not wr.fully_recovered:
                    all_recovered = False

                    # Check if budget is now exhausted
                    if self._check_budget(witness_url):
                        self._circuit_open.add(witness_url)
                        log.warning(
                            f"witness_circuit_open: {witness_url}, "
                            f"failed_attempts: {self._max_per_hour}"
                        )

            report.fully_recovered = all_recovered

        report.elapsed_seconds = time.monotonic() - start

        # Cost telemetry
        log.info(
            f"recovery_complete "
            f"action={action} "
            f"recovery_identities_count={report.identities_total} "
            f"recovery_elapsed_seconds={report.elapsed_seconds:.2f} "
            f"fully_recovered={report.fully_recovered} "
            f"witnesses_degraded={report.witnesses_degraded}"
        )

        return report

    async def _recover_one_witness(
        self,
        witness_url: str,
        seeds,
        identity_mgr,
        action: str,
    ) -> WitnessRecoveryResult:
        """Run Phase A + B + C recovery for a single witness."""
        wr = WitnessRecoveryResult(
            witness_url=witness_url,
            was_degraded=True,
        )

        hby = identity_mgr.hby

        # Phase A: Full KEL replay for ALL seeded identities
        published = 0
        for seed in seeds:
            hab = hby.habByName(seed.name)
            if hab is None or hab.kever is None:
                continue
            if not hab.kever.wits:
                continue

            try:
                result = await self._publisher.publish_full_kel(
                    pre=hab.pre,
                    hby=hby,
                    witnesses=[witness_url],
                )
                if result.success_count > 0:
                    published += 1
                else:
                    wr.error_codes.append(
                        f"PUBLISH_FAILED:{seed.expected_aid[:16]}"
                    )
            except Exception as e:
                log.warning(
                    f"Phase A failed for {seed.name} on {witness_url}: {e}"
                )
                wr.error_codes.append(
                    f"PUBLISH_EXCEPTION:{seed.expected_aid[:16]}"
                )

        wr.identities_published = published

        # Phase B: Event-digest-aware receipt redistribution
        receipt_ok = await self._redistribute_receipts(
            witness_url, seeds, identity_mgr
        )
        wr.receipt_redistribution_ok = receipt_ok

        # Phase C: Full verification
        verified, failed = await self.verify_full_recovery(witness_url)
        wr.identities_verified = verified
        wr.identities_failed = failed
        wr.fully_recovered = (failed == 0 and verified > 0)

        if wr.fully_recovered:
            log.info(
                f"Witness {witness_url} recovered: "
                f"{published} published, {verified} verified"
            )
        else:
            log.warning(
                f"Witness {witness_url} partial recovery: "
                f"{published} published, {verified} verified, "
                f"{failed} failed"
            )

        return wr

    async def _redistribute_receipts(
        self,
        witness_url: str,
        seeds,
        identity_mgr,
    ) -> bool:
        """Phase B: Redistribute witness receipts for establishment events.

        Only establishment events (icp, rot, dip, drt) need witness
        receipts. Non-establishment events (ixn) do not participate
        in the witness receipt protocol.
        """
        hby = identity_mgr.hby
        all_ok = True
        semaphore = asyncio.Semaphore(10)

        async def _redistribute_one(seed):
            nonlocal all_ok
            async with semaphore:
                hab = hby.habByName(seed.name)
                if hab is None or hab.kever is None:
                    return
                if not hab.kever.wits:
                    return

                try:
                    await self._redistribute_identity_receipts(
                        witness_url, hab, hby
                    )
                except Exception as e:
                    log.warning(
                        f"Receipt redistribution failed for {seed.name} "
                        f"on {witness_url}: {e}"
                    )
                    all_ok = False

        await asyncio.gather(
            *[_redistribute_one(seed) for seed in seeds],
            return_exceptions=True,
        )

        return all_ok

    async def _redistribute_identity_receipts(
        self,
        witness_url: str,
        hab,
        hby,
    ) -> None:
        """Redistribute receipts for all establishment events of one identity.

        Iterates through the KEL to find establishment events (icp, rot,
        dip, drt) and redistributes their witness receipts.
        """
        pre_bytes = hab.pre.encode("utf-8")
        establishment_ilks = {"icp", "rot", "dip", "drt"}

        # Get all events from the KEL
        events_to_receipt: list[tuple[int, str, bytes]] = []

        def _gather_establishment_events():
            """Synchronous LMDB read — run in thread."""
            result = []
            for msg in hby.db.clonePreIter(pre=pre_bytes, fn=0):
                try:
                    serder = serdering.SerderKERI(raw=bytearray(msg))
                    ilk = serder.ked.get("t", "")
                    if ilk in establishment_ilks:
                        result.append((serder.sn, serder.said, serder.saidb))
                except Exception:
                    continue
            return result

        events_to_receipt = await asyncio.to_thread(_gather_establishment_events)

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(WITNESS_TIMEOUT_SECONDS, connect=5.0),
            follow_redirects=False,
        ) as client:
            for sn, said, dig in events_to_receipt:
                try:
                    # Get witness indexed signatures for this event
                    def _get_wigs(sn=sn, dig=dig):
                        return list(hab.db.getWigs(
                            pre_bytes, sn=sn, dig=dig
                        ))

                    wigers_raw = await asyncio.to_thread(_get_wigs)

                    if not wigers_raw:
                        log.debug(
                            f"No wigs for {hab.pre[:16]}... sn={sn}, "
                            f"skipping receipt redistribution"
                        )
                        continue

                    # Build receipt event
                    rserder = eventing.receipt(
                        pre=hab.pre,
                        sn=sn,
                        said=said,
                    )

                    # Convert raw wigers to Siger objects with correct indices
                    wits = hab.kever.wits
                    sigers = []
                    for wiger in wigers_raw:
                        if hasattr(wiger, "index") and hasattr(wiger, "raw"):
                            sigers.append(wiger)
                        elif hasattr(wiger, "qb64b"):
                            # Try to reconstruct as Siger
                            try:
                                siger = Siger(qb64b=wiger.qb64b)
                                sigers.append(siger)
                            except Exception:
                                continue

                    if not sigers:
                        continue

                    rct_msg = eventing.messagize(
                        serder=rserder, wigers=sigers
                    )

                    # Distribute to the repaired witness
                    await self._publisher._distribute_receipt(
                        client, witness_url, bytes(rct_msg)
                    )

                except Exception as e:
                    log.debug(
                        f"Receipt redistribution for {hab.pre[:16]}... "
                        f"sn={sn} failed: {e}"
                    )

    async def verify_full_recovery(
        self,
        witness_url: str,
    ) -> tuple[int, int]:
        """Post-republish verification for ALL seeded identities.

        Probes the repaired witness's OOBI for every seeded identity
        and confirms sn/SAID matches local authoritative state.

        OOBI 200 with correct sn/SAID proves fullyWitnessed() —
        keripy witnesses only serve OOBIs when receipt threshold met.

        Returns (verified_count, failed_count).
        """
        from app.keri.identity import get_identity_manager
        from app.keri.seed_store import get_seed_store

        identity_mgr = await get_identity_manager()
        seed_store = get_seed_store()
        seeds = seed_store.get_all_identity_seeds()

        verified = 0
        failed = 0

        for seed in seeds:
            hab = identity_mgr.hby.habByName(seed.name)
            if hab is None or hab.kever is None:
                continue
            if not hab.kever.wits:
                verified += 1  # No witnesses — trivially verified
                continue

            expected_sn = hab.kever.sn
            expected_said = hab.kever.serder.said

            check = await self._probe_witness(
                witness_url, seed.expected_aid, expected_sn, expected_said
            )

            if check.healthy:
                verified += 1
            elif check.status == "divergent":
                log.error(
                    f"WITNESS_DIVERGENT: {witness_url} has sn={check.witness_sn} "
                    f"for {seed.expected_aid[:16]}... (expected sn={expected_sn}). "
                    f"Manual intervention required."
                )
                failed += 1
            else:
                log.warning(
                    f"Verification failed for {seed.expected_aid[:16]}... "
                    f"on {witness_url}: status={check.status}"
                )
                failed += 1

        return verified, failed


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_recovery_service: WitnessRecoveryService | None = None


def get_recovery_service() -> WitnessRecoveryService:
    """Get or create the singleton WitnessRecoveryService."""
    global _recovery_service
    if _recovery_service is None:
        _recovery_service = WitnessRecoveryService()
    return _recovery_service


def reset_recovery_service() -> None:
    """Reset the singleton (for testing)."""
    global _recovery_service
    _recovery_service = None
