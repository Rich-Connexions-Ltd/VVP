"""Witness interaction for VVP KERI Agent.

Handles OOBI publishing to KERI witnesses for identity discovery.

Phase 2 (receipt distribution) uses keripy's duplicate inception handler
(eventing.py:3801-3819) which is explicitly designed for "late arriving
witness receipts". We extract witness couple signatures from Phase 1
receipts, convert them to indexed witness signatures (wigers), and
re-POST the inception event to /receipts. The Kevery's duplicate handler
verifies the wigers and stores them in db.wigs via logEvent/putWigs,
satisfying the fullyWitnessed() check required for OOBI resolution.
"""
import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

import httpx
from keri import kering
from keri.core import coring, serdering
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

            # Phase 2: Re-POST inception event with collected witness indexed
            # signatures so each witness stores them in db.wigs via the
            # duplicate inception handler (eventing.py:3801-3819).
            if len(receipts) > 1:
                try:
                    enhanced_msg = self._build_enhanced_inception(
                        kel_bytes, receipts
                    )
                    if enhanced_msg:
                        log.info(
                            f"Re-posting inception with {len(receipts)} witness "
                            f"sigs to {len(self._witness_urls)} witnesses"
                        )
                        repost_tasks = [
                            self._repost_enhanced(client, url, enhanced_msg)
                            for url in self._witness_urls
                        ]
                        await asyncio.gather(
                            *repost_tasks, return_exceptions=True
                        )
                except Exception as e:
                    log.warning(f"Failed to build/send enhanced inception: {e}")

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

    def _build_enhanced_inception(
        self,
        inception_msg: bytes,
        receipts: dict[str, bytes],
    ) -> Optional[bytes]:
        """Build inception message with witness indexed signatures from receipts.

        Parses each witness receipt (couple signature format) to extract the
        witness prefix and raw signature, converts to indexed witness
        signatures (Sigers), and appends a -B (WitnessIdxSigs) CESR
        attachment to the original inception message.

        The duplicate inception handler in keripy's Kevery verifies these
        against eserder.berfers and stores them via kever.logEvent/putWigs.
        """
        # Extract witness list from inception event to determine indices
        msg = bytearray(inception_msg)
        serder = serdering.SerderKERI(raw=msg)
        wits = serder.ked.get("b", [])
        if not wits:
            log.warning(
                f"Inception event has no witnesses (b field), "
                f"ilk={serder.ked.get('t')}"
            )
            return None

        # Original controller signature attachment
        ctrl_attachment = bytes(msg[serder.size:])

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

        # Build witness indexed signature CESR attachment (-B count code)
        wit_atc = bytearray()
        wit_atc.extend(
            Counter(
                Codens.WitnessIdxSigs,
                count=len(wigers),
                gvrsn=kering.Vrsn_1_0,
            ).qb64b
        )
        for wiger in wigers:
            wit_atc.extend(wiger.qb64b)

        # Combine: inception_json + controller_sigs + witness_indexed_sigs
        enhanced = bytearray(serder.raw)
        enhanced.extend(ctrl_attachment)
        enhanced.extend(wit_atc)

        log.info(
            f"Built enhanced inception: {len(wigers)} witness sigs, "
            f"{len(enhanced)} total bytes"
        )
        return bytes(enhanced)

    async def _repost_enhanced(
        self,
        client: httpx.AsyncClient,
        url: str,
        enhanced_msg: bytes,
    ) -> None:
        """Re-POST enhanced inception event with witness sigs to /receipts.

        The witness's ReceiptEnd.on_post calls parseOne(local=True) which
        triggers the Kevery's duplicate inception handler. This handler
        verifies the new witness indexed signatures and stores them in
        db.wigs via logEvent/putWigs.
        """
        msg = bytearray(enhanced_msg)
        serder = serdering.SerderKERI(raw=msg)
        event_json = bytes(serder.raw)
        attachments = bytes(msg[serder.size:])

        receipts_url = f"{url.rstrip('/')}/receipts"
        headers = {
            "Content-Type": CESR_CONTENT_TYPE,
            CESR_ATTACHMENT_HEADER: attachments.decode("utf-8"),
        }

        response = await client.post(
            receipts_url, content=event_json, headers=headers
        )
        if response.status_code == 200:
            log.info(f"Re-posted enhanced inception to {receipts_url}: OK")
        elif response.status_code == 202:
            log.warning(
                f"Re-posted enhanced inception to {receipts_url}: "
                f"202 (escrowed — unexpected)"
            )
        else:
            log.warning(
                f"Re-posted enhanced inception to {receipts_url}: "
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
