"""Witness interaction for VVP KERI Agent.

Handles OOBI publishing to KERI witnesses for identity discovery.
"""
import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

import httpx
from keri.core import serdering

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

            # Phase 2: Distribute all receipts to all witnesses
            if len(receipts) > 1:
                log.info(f"Distributing {len(receipts)} receipts ({sum(len(r) for r in receipts.values())} bytes) to witnesses")
                all_receipts = bytearray()
                for rct in receipts.values():
                    all_receipts.extend(rct)

                for url in receipts:
                    try:
                        await self._send_receipts(client, url, bytes(all_receipts))
                        log.info(f"Distributed receipts to {url}")
                    except Exception as e:
                        log.warning(f"Failed to distribute receipts to {url}: {e}")

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

    async def _send_receipts(
        self,
        client: httpx.AsyncClient,
        url: str,
        receipt_bytes: bytes,
    ) -> None:
        """Send receipts to a witness."""
        root_url = f"{url.rstrip('/')}"
        headers = {"Content-Type": "application/cesr"}

        response = await client.put(root_url, content=receipt_bytes, headers=headers)
        if response.status_code not in (200, 202, 204):
            log.warning(f"Failed to distribute receipts to {url}: HTTP {response.status_code}")


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
