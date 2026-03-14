"""Periodic witness state monitor — thin wrapper around WitnessRecoveryService.

Runs a background task that periodically checks witness health via
sampling (probe_all=False) and triggers targeted recovery when
degradation is detected.

Sprint 86: Witness State Resilience.
"""
import asyncio
import logging
import os

from app.keri.witness_recovery import WitnessRecoveryService

log = logging.getLogger(__name__)

MONITOR_INTERVAL = float(os.getenv("VVP_WITNESS_MONITOR_INTERVAL", "300"))
MONITOR_ENABLED = os.getenv("VVP_WITNESS_MONITOR_ENABLED", "true").lower() == "true"


class WitnessHealthMonitor:
    """Periodic witness state monitor.

    Starts after KERI Agent reaches READY. Uses sampling mode
    for lightweight detection, then triggers full recovery when
    degradation is found.
    """

    def __init__(
        self,
        recovery_service: WitnessRecoveryService,
        check_interval: float = MONITOR_INTERVAL,
    ):
        self._recovery_service = recovery_service
        self._check_interval = check_interval
        self._task: asyncio.Task | None = None
        self._running = False

    async def start(self) -> asyncio.Task:
        """Start the background health check loop.

        Returns the task so callers can track it with ReadinessTracker.
        """
        if not MONITOR_ENABLED:
            log.info("Witness health monitor disabled (VVP_WITNESS_MONITOR_ENABLED=false)")
            return None

        if self._running:
            log.warning("Witness health monitor already running")
            return self._task

        self._running = True
        self._task = asyncio.create_task(self._monitor_loop())
        log.info(
            f"Witness health monitor started "
            f"(interval={self._check_interval}s)"
        )
        return self._task

    async def stop(self) -> None:
        """Stop the monitor and cancel the loop task."""
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        self._task = None
        log.info("Witness health monitor stopped")

    async def _monitor_loop(self) -> None:
        """Background loop: check witnesses, recover if degraded."""
        while self._running:
            try:
                await asyncio.sleep(self._check_interval)

                if not self._running:
                    break

                # Sampling mode — lightweight detection
                checks = await self._recovery_service.check_witness_state(
                    probe_all=False
                )

                # Find degraded witnesses
                degraded_urls: set[str] = set()
                for check in checks:
                    if not check.healthy:
                        degraded_urls.add(check.witness_url)

                if not degraded_urls:
                    log.debug("All witnesses healthy (sampling check)")
                    continue

                log.info(
                    f"Witness degradation detected: "
                    f"{len(degraded_urls)} witness(es) degraded"
                )

                # Trigger targeted recovery
                report = await self._recovery_service.recover_degraded_witnesses(
                    degraded_urls=list(degraded_urls),
                    action="monitor_check",
                )

                if report.fully_recovered:
                    log.info(
                        f"Monitor recovery complete: {report.identities_verified} "
                        f"identities verified in {report.elapsed_seconds:.1f}s"
                    )
                else:
                    log.warning(
                        f"Monitor recovery incomplete: "
                        f"{report.identities_verified} verified, "
                        f"{report.identities_failed} failed in "
                        f"{report.elapsed_seconds:.1f}s"
                    )

            except asyncio.CancelledError:
                break
            except Exception as e:
                log.error(f"Witness monitor error: {e}", exc_info=True)
                # Never crash — wait for next interval
