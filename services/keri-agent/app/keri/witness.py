"""Witness interaction for VVP KERI Agent.

Handles OOBI publishing to KERI witnesses for identity discovery.

Phase 2 (receipt distribution) sends a receipt event (rct) with all
collected witness indexed signatures (-B WitnessIdxSigs attachment) to
each witness's root HTTP endpoint. This matches the keripy-proven
approach (test_witness.py) which uses processReceiptWitness to verify
and store wigers in db.wigs via addWig, satisfying the fullyWitnessed()
check required for OOBI resolution.
"""
import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

import httpx
from keri import kering
from keri.core import coring, eventing, serdering
from keri.core.counting import Counter, Codens
from keri.core.indexing import Siger

from app.config import (
    WITNESS_IURLS,
    WITNESS_TIMEOUT_SECONDS,
    WITNESS_RECEIPT_THRESHOLD,
    WITNESS_RETRY_MAX_ATTEMPTS,
    WITNESS_RETRY_BACKOFF_BASE,
)

# CESR HTTP format constants (from keripy httping)
CESR_CONTENT_TYPE = "application/cesr+json"
CESR_ATTACHMENT_HEADER = "CESR-ATTACHMENT"

log = logging.getLogger(__name__)


@dataclass
class WitnessResult:
    """Result of publishing to a single witness."""

    url: str
    success: bool
    error: Optional[str] = None
    response_time_ms: Optional[int] = None


@dataclass
class PublishResult:
    """Result of publishing to all witnesses."""

    aid: str
    success_count: int
    total_count: int
    threshold_met: bool
    witnesses: list[WitnessResult]


class WitnessPublisher:
    """Publishes identity events to KERI witnesses."""

    def __init__(
        self,
        witness_urls: Optional[list[str]] = None,
        timeout: float = WITNESS_TIMEOUT_SECONDS,
        threshold: int = WITNESS_RECEIPT_THRESHOLD,
        max_attempts: int = WITNESS_RETRY_MAX_ATTEMPTS,
        backoff_base: float = WITNESS_RETRY_BACKOFF_BASE,
    ):
        self._witness_urls = witness_urls or self._extract_urls_from_iurls()
        self._timeout = timeout
        self._threshold = threshold
        self._max_attempts = max_attempts
        self._backoff_base = backoff_base

    def _extract_urls_from_iurls(self) -> list[str]:
        """Extract base URLs from OOBI iurls."""
        urls = []
        for iurl in WITNESS_IURLS:
            parts = iurl.split("/oobi/")
            if parts:
                urls.append(parts[0])
        return urls

    async def publish_oobi(
        self,
        aid: str,
        kel_bytes: bytes,
    ) -> PublishResult:
        """Publish identity KEL to witnesses."""
        if not self._witness_urls:
            log.warning("No witness URLs configured for publishing")
            return PublishResult(
                aid=aid,
                success_count=0,
                total_count=0,
                threshold_met=False,
                witnesses=[],
            )

        results: list[WitnessResult] = []
        receipts: dict[str, bytes] = {}

        async with httpx.AsyncClient(timeout=self._timeout) as client:
            # Phase 1: Send event to each witness and collect receipts
            tasks = [
                self._publish_to_witness(client, url, aid, kel_bytes)
                for url in self._witness_urls
            ]
            phase1_results = await asyncio.gather(*tasks, return_exceptions=True)

            for i, result in enumerate(phase1_results):
                url = self._witness_urls[i]
                if isinstance(result, tuple):
                    wr, receipt = result
                    results.append(wr)
                    if wr.success and receipt:
                        receipts[url] = receipt
                elif isinstance(result, Exception):
                    results.append(
                        WitnessResult(url=url, success=False, error=str(result))
                    )
                else:
                    results.append(result)

            # Phase 2: Distribute all witness indexed signatures to each
            # witness via a receipt (rct) event with -B WitnessIdxSigs.
            # This uses the keripy-proven processReceiptWitness path
            # (eventing.py:3905) which stores wigers in db.wigs via addWig.
            if len(receipts) > 1:
                try:
                    rct_msg = self._build_witness_receipt(
                        kel_bytes, receipts
                    )
                    if rct_msg:
                        log.info(
                            f"Distributing receipt with {len(receipts)} witness "
                            f"sigs to {len(self._witness_urls)} witnesses"
                        )
                        dist_tasks = [
                            self._distribute_receipt(client, url, rct_msg)
                            for url in self._witness_urls
                        ]
                        await asyncio.gather(
                            *dist_tasks, return_exceptions=True
                        )
                except Exception as e:
                    log.warning(f"Failed to build/send witness receipt: {e}")

        success_count = sum(1 for r in results if r.success)

        return PublishResult(
            aid=aid,
            success_count=success_count,
            total_count=len(results),
            threshold_met=success_count >= self._threshold,
            witnesses=results,
        )

    async def publish_event(
        self,
        pre: str,
        event_bytes: bytes,
    ) -> PublishResult:
        """Publish a KERI/ACDC event to witnesses."""
        return await self.publish_oobi(aid=pre, kel_bytes=event_bytes)

    @staticmethod
    def _is_retryable_error(error: Optional[str]) -> bool:
        """Check if an error string indicates a retryable failure."""
        if not error:
            return False
        # HTTP 5xx errors
        if error.startswith("HTTP 5"):
            return True
        # Network errors
        if error in ("Timeout", "ConnectError"):
            return True
        return False

    async def _publish_to_witness(
        self,
        client: httpx.AsyncClient,
        url: str,
        aid: str,
        kel_bytes: bytes,
    ) -> tuple[WitnessResult, Optional[bytes]]:
        """Publish to a single witness with retry on transient failures.

        Retries on: HTTP 202 (escrowed), HTTP 5xx, timeout, connect error.
        Does not retry on: HTTP 200 (success), HTTP 4xx (client error).
        """
        last_result: Optional[tuple[WitnessResult, Optional[bytes]]] = None

        for attempt in range(self._max_attempts):
            result, receipt = await self._try_publish(
                client, url, aid, kel_bytes
            )

            # 200 with receipt — full success, no retry needed
            if result.success and receipt is not None:
                return result, receipt

            # 202 escrowed — witness is up but not ready to receipt.
            # Retry: witness may still be initializing after restart.
            if result.success and receipt is None:
                if attempt < self._max_attempts - 1:
                    backoff = self._backoff_base * (2 ** attempt)
                    log.info(
                        f"Witness {url} escrowed {aid[:16]}..., "
                        f"retry {attempt + 1}/{self._max_attempts} in {backoff:.1f}s"
                    )
                    await asyncio.sleep(backoff)
                    continue
                # Accept escrowed on final attempt
                return result, receipt

            # Failure — check if retryable
            if (
                self._is_retryable_error(result.error)
                and attempt < self._max_attempts - 1
            ):
                backoff = self._backoff_base * (2 ** attempt)
                log.warning(
                    f"Witness {url} failed ({result.error}), "
                    f"retry {attempt + 1}/{self._max_attempts} in {backoff:.1f}s"
                )
                await asyncio.sleep(backoff)
                continue

            # Non-retryable error or final attempt
            return result, receipt

        # Should not reach here, but return last result as safety net
        return result, receipt  # type: ignore[return-value]

    async def _try_publish(
        self,
        client: httpx.AsyncClient,
        url: str,
        aid: str,
        kel_bytes: bytes,
    ) -> tuple[WitnessResult, Optional[bytes]]:
        """Single attempt to publish to a witness. Returns (result, receipt)."""
        start = datetime.now(timezone.utc)

        try:
            msg = bytearray(kel_bytes)
            serder = serdering.SerderKERI(raw=msg)
            event_json = bytes(serder.raw)
            attachments = bytes(msg[serder.size:])

            receipts_url = f"{url.rstrip('/')}/receipts"
            headers = {
                "Content-Type": CESR_CONTENT_TYPE,
                CESR_ATTACHMENT_HEADER: attachments.decode("utf-8"),
            }

            response = await client.post(
                receipts_url,
                content=event_json,
                headers=headers,
            )

            elapsed_ms = int((datetime.now(timezone.utc) - start).total_seconds() * 1000)

            if response.status_code == 200:
                receipt_bytes = response.content
                log.info(f"Published {aid[:16]}... to {receipts_url} ({elapsed_ms}ms), got receipt")
                return (
                    WitnessResult(url=url, success=True, response_time_ms=elapsed_ms),
                    receipt_bytes,
                )
            elif response.status_code == 202:
                log.info(f"Published {aid[:16]}... to {receipts_url} ({elapsed_ms}ms), escrowed")
                return (
                    WitnessResult(url=url, success=True, response_time_ms=elapsed_ms),
                    None,
                )
            else:
                error_detail = ""
                try:
                    error_data = response.json()
                    error_detail = f": {error_data.get('description', '')}"
                except Exception:
                    pass
                log.warning(f"Witness {receipts_url} returned {response.status_code}{error_detail}")
                return (
                    WitnessResult(
                        url=url,
                        success=False,
                        error=f"HTTP {response.status_code}{error_detail}",
                        response_time_ms=elapsed_ms,
                    ),
                    None,
                )

        except httpx.TimeoutException:
            log.warning(f"Timeout publishing to {url}")
            return (WitnessResult(url=url, success=False, error="Timeout"), None)
        except httpx.ConnectError:
            log.warning(f"Connection refused publishing to {url}")
            return (WitnessResult(url=url, success=False, error="ConnectError"), None)
        except Exception as e:
            log.error(f"Failed to publish to {url}: {e}")
            return (WitnessResult(url=url, success=False, error=str(e)), None)

    def _build_witness_receipt(
        self,
        inception_msg: bytes,
        receipts: dict[str, bytes],
    ) -> Optional[bytes]:
        """Build receipt event with witness indexed signatures from receipts.

        Parses each witness receipt (couple signature format) to extract the
        witness prefix and raw signature, converts to indexed witness
        signatures (Sigers), and creates an rct event with -B (WitnessIdxSigs)
        attachment — the keripy-proven approach from test_witness.py.

        The witness's processReceiptWitness handler verifies each wiger
        and stores them in db.wigs via addWig.
        """
        # Extract witness list and event metadata from inception event
        msg = bytearray(inception_msg)
        serder = serdering.SerderKERI(raw=msg)
        wits = serder.ked.get("b", [])
        if not wits:
            log.warning(
                f"Inception event has no witnesses (b field), "
                f"ilk={serder.ked.get('t')}"
            )
            return None

        # Parse each receipt to extract witness prefix and signature
        wigers = []
        for url, receipt_bytes in receipts.items():
            try:
                rct_msg = bytearray(receipt_bytes)
                rct_serder = serdering.SerderKERI(raw=rct_msg)
                rct_atc = bytearray(rct_msg[rct_serder.size:])

                # Parse CESR: Counter(-C, N) + [Verfer + Cigar] * N
                ctr = Counter(qb64b=rct_atc, strip=True)

                for _i in range(ctr.count):
                    verfer = coring.Verfer(qb64b=rct_atc, strip=True)
                    cigar = coring.Cigar(qb64b=rct_atc, strip=True)
                    cigar.verfer = verfer

                    wit_pre = verfer.qb64
                    if wit_pre in wits:
                        index = wits.index(wit_pre)
                        wiger = Siger(
                            raw=cigar.raw, index=index, verfer=verfer
                        )
                        wigers.append(wiger)
                        log.debug(
                            f"Extracted witness sig: {wit_pre[:16]}... "
                            f"index={index}"
                        )
                    else:
                        log.warning(
                            f"Receipt signer {wit_pre[:16]}... not in "
                            f"witness list"
                        )
            except Exception as e:
                log.warning(f"Failed to parse receipt from {url}: {e}")

        if not wigers:
            log.warning("No witness signatures extracted from receipts")
            return None

        # Build receipt event (rct) with -B WitnessIdxSigs attachment.
        # This matches keripy test_witness.py:124-128 approach:
        #   rserder = eventing.receipt(pre, sn, said)
        #   msg = eventing.messagize(serder=rserder, wigers=wigers)
        rserder = eventing.receipt(
            pre=serder.pre,
            sn=serder.sn,
            said=serder.said,
        )
        rct_wit_msg = eventing.messagize(serder=rserder, wigers=wigers)

        log.info(
            f"Built witness receipt: {len(wigers)} witness sigs, "
            f"{len(rct_wit_msg)} total bytes"
        )
        return bytes(rct_wit_msg)

    async def _distribute_receipt(
        self,
        client: httpx.AsyncClient,
        url: str,
        rct_msg: bytes,
    ) -> None:
        """Distribute witness receipt event to a witness's root endpoint.

        Posts the rct event (with -B WitnessIdxSigs) to the root /
        endpoint which queues it for background processing via the
        witness's Parsator. The processReceiptWitness handler verifies
        each wiger and stores them in db.wigs via addWig.

        The root / endpoint is used instead of /receipts because
        ReceiptEnd.on_post only accepts key events (icp/rot/ixn/dip/drt),
        not receipt events (rct).

        Retries on transient failures (5xx, timeout, connect error).
        """
        msg = bytearray(rct_msg)
        serder = serdering.SerderKERI(raw=msg)
        event_json = bytes(serder.raw)
        attachments = bytes(msg[serder.size:])

        root_url = url.rstrip('/')  # root / endpoint
        headers = {
            "Content-Type": CESR_CONTENT_TYPE,
            CESR_ATTACHMENT_HEADER: attachments.decode("utf-8"),
        }

        for attempt in range(self._max_attempts):
            try:
                response = await client.post(
                    root_url, content=event_json, headers=headers
                )
                if response.status_code in (200, 204):
                    log.info(f"Distributed witness receipt to {root_url}: OK")
                    return
                elif response.status_code >= 500:
                    if attempt < self._max_attempts - 1:
                        backoff = self._backoff_base * (2 ** attempt)
                        log.warning(
                            f"Witness receipt to {root_url} returned {response.status_code}, "
                            f"retry {attempt + 1}/{self._max_attempts} in {backoff:.1f}s"
                        )
                        await asyncio.sleep(backoff)
                        continue
                    log.warning(
                        f"Distributed witness receipt to {root_url}: "
                        f"HTTP {response.status_code} (after {self._max_attempts} attempts)"
                    )
                    return
                else:
                    log.warning(
                        f"Distributed witness receipt to {root_url}: "
                        f"HTTP {response.status_code}"
                    )
                    return
            except (httpx.TimeoutException, httpx.ConnectError) as e:
                if attempt < self._max_attempts - 1:
                    backoff = self._backoff_base * (2 ** attempt)
                    log.warning(
                        f"Witness receipt to {root_url} failed ({type(e).__name__}), "
                        f"retry {attempt + 1}/{self._max_attempts} in {backoff:.1f}s"
                    )
                    await asyncio.sleep(backoff)
                    continue
                log.warning(
                    f"Distributed witness receipt to {root_url}: "
                    f"{type(e).__name__} (after {self._max_attempts} attempts)"
                )
                return
            except Exception as e:
                log.warning(f"Failed to distribute receipt to {root_url}: {e}")
                return


# Module-level singleton
_witness_publisher: Optional[WitnessPublisher] = None


def get_witness_publisher() -> WitnessPublisher:
    """Get or create the witness publisher singleton."""
    global _witness_publisher
    if _witness_publisher is None:
        _witness_publisher = WitnessPublisher()
    return _witness_publisher


def reset_witness_publisher() -> None:
    """Reset the singleton (for testing)."""
    global _witness_publisher
    _witness_publisher = None
