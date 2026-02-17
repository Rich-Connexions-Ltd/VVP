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
    ):
        self._witness_urls = witness_urls or self._extract_urls_from_iurls()
        self._timeout = timeout
        self._threshold = threshold

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

    async def _publish_to_witness(
        self,
        client: httpx.AsyncClient,
        url: str,
        aid: str,
        kel_bytes: bytes,
    ) -> tuple[WitnessResult, Optional[bytes]]:
        """Publish to a single witness and collect receipt."""
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

        response = await client.post(
            root_url, content=event_json, headers=headers
        )
        if response.status_code in (200, 204):
            log.info(f"Distributed witness receipt to {root_url}: OK")
        else:
            log.warning(
                f"Distributed witness receipt to {root_url}: "
                f"HTTP {response.status_code}"
            )


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
