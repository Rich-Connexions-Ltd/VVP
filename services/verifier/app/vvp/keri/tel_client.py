"""
Lightweight TEL (Transaction Event Log) client for querying KERI witnesses/watchers.
Does not require full keripy installation - uses direct HTTP queries.

Per KERI spec, TEL events track credential lifecycle:
- iss: issuance (simple)
- rev: revocation (simple)
- bis: backer-backed issuance
- brv: backer-backed revocation
"""

import asyncio
import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, List, Dict, Any, Tuple
from urllib.parse import urljoin, urlparse

import httpx

from app.core.config import TEL_CLIENT_TIMEOUT_SECONDS

log = logging.getLogger(__name__)


class CredentialStatus(str, Enum):
    """Credential revocation status."""
    ACTIVE = "ACTIVE"         # Issued, not revoked
    REVOKED = "REVOKED"       # Explicitly revoked
    UNKNOWN = "UNKNOWN"       # No TEL data found
    ERROR = "ERROR"           # Error querying status


@dataclass
class TELEvent:
    """Parsed TEL event."""
    event_type: str           # iss, rev, bis, brv
    credential_said: str      # Credential identifier
    registry_said: str        # Registry identifier
    sequence: int             # Event sequence number
    datetime: Optional[str]   # ISO8601 timestamp
    digest: str               # Event digest
    raw: Dict[str, Any]       # Full event data


@dataclass
class RevocationResult:
    """Result of revocation status check."""
    status: CredentialStatus
    credential_said: str
    registry_said: Optional[str]
    issuance_event: Optional[TELEvent]
    revocation_event: Optional[TELEvent]
    error: Optional[str]
    source: str  # 'witness', 'watcher', 'cache', 'dossier'


@dataclass
class ChainExtractionResult:
    """Result of chain SAID extraction from a credential graph.

    Used to pass chain information to check_chain_revocation().

    Attributes:
        chain_saids: Ordered list of credential SAIDs from leaf to root.
        registry_saids: Mapping of credential SAID to registry SAID (ri field).
        missing_links: SAIDs referenced by edges but not found in graph.
        complete: True if all edge targets are in graph (no missing links).
    """
    chain_saids: List[str] = field(default_factory=list)
    registry_saids: Dict[str, str] = field(default_factory=dict)
    missing_links: List[str] = field(default_factory=list)
    complete: bool = False


@dataclass
class ChainRevocationResult:
    """Result of chain-wide revocation check.

    Chain Status Semantics:
    - REVOKED: At least one credential in chain is revoked → chain invalid
    - ACTIVE: ALL credentials checked AND all are active → chain valid
    - UNKNOWN: Missing chain links OR some checks failed → indeterminate

    A chain is only ACTIVE if:
    1. All required chain credentials were resolved (chain_complete=True)
    2. All credentials were successfully checked (no errors)
    3. All credentials returned ACTIVE status

    Attributes:
        chain_status: Overall chain status (ACTIVE/REVOKED/UNKNOWN).
        credential_results: Individual revocation results keyed by SAID.
        revoked_credentials: List of SAIDs that are revoked.
        chain_saids: Ordered chain SAIDs (leaf → root) that were checked.
        missing_chain_links: SAIDs that couldn't be resolved.
        check_complete: True only if ALL chain links resolved AND checked.
        errors: Error messages encountered during checking.
        checked_at: ISO8601 timestamp of when check completed.
    """
    chain_status: CredentialStatus
    credential_results: Dict[str, RevocationResult] = field(default_factory=dict)
    revoked_credentials: List[str] = field(default_factory=list)
    chain_saids: List[str] = field(default_factory=list)
    missing_chain_links: List[str] = field(default_factory=list)
    check_complete: bool = False
    errors: List[str] = field(default_factory=list)
    checked_at: str = ""


class TELClient:
    """
    Client for querying KERI witnesses/watchers for TEL events.

    KERI OOBI patterns for TEL queries:
    - /oobi/{aid}/witness/{wit-aid}  - Witness key state
    - /.well-known/keri/oobi/{aid}   - Well-known OOBI
    - /tels/{registry-aid}           - TEL events for registry
    - /credentials/{cred-said}       - Credential + TEL state
    """

    # Legacy fallback witnesses - kept for backwards compatibility
    # New code should use the WitnessPool instead (use_witness_pool=True)
    DEFAULT_WITNESSES = [
        # Provenant OVC stage witnesses (last resort fallback)
        "http://witness1.stage.provenant.net:5631",
        "http://witness2.stage.provenant.net:5631",
        "http://witness3.stage.provenant.net:5631",
        "http://witness4.stage.provenant.net:5631",
        "http://witness5.stage.provenant.net:5631",
        "http://witness6.stage.provenant.net:5631",
    ]

    @staticmethod
    def extract_witness_base_url(oobi_url: str) -> Optional[str]:
        """
        Extract witness base URL from an OOBI URL.

        OOBI URLs follow the pattern:
            http://witness5.stage.provenant.net:5631/oobi/{AID}/witness

        Returns: http://witness5.stage.provenant.net:5631

        This allows deriving the witness endpoint from the PASSporT kid field,
        which should contain a witness OOBI URL per KERI/Provenant specs.

        NOTE: Prefer using witness_pool.extract_witness_base_url() which
        includes URL validation.
        """
        if not oobi_url:
            return None
        try:
            parsed = urlparse(oobi_url)
            return f"{parsed.scheme}://{parsed.netloc}"
        except Exception:
            return None

    def __init__(
        self,
        timeout: float = 10.0,
        witness_urls: Optional[List[str]] = None,
        use_witness_pool: bool = True,
    ):
        """Initialize TEL client.

        Args:
            timeout: HTTP request timeout.
            witness_urls: Explicit list of witness URLs (overrides pool).
            use_witness_pool: If True and witness_urls is None, use WitnessPool.
        """
        self.timeout = timeout
        self._use_witness_pool = use_witness_pool and witness_urls is None
        self._explicit_witness_urls = witness_urls
        self._cache: Dict[str, RevocationResult] = {}
        # Cache metrics
        self._cache_hits: int = 0
        self._cache_misses: int = 0

    @property
    def witness_urls(self) -> List[str]:
        """Get witness URLs synchronously (no GLEIF discovery).

        For async contexts that need GLEIF discovery, use _get_witness_urls_async().
        """
        if self._explicit_witness_urls:
            return self._explicit_witness_urls
        if self._use_witness_pool:
            from .witness_pool import get_witness_pool
            return get_witness_pool().get_witness_urls()
        return self.DEFAULT_WITNESSES

    async def _get_witness_urls_async(self) -> List[str]:
        """Get witness URLs with GLEIF discovery (async).

        Triggers lazy GLEIF discovery if enabled, ensuring all available
        witnesses are queried.
        """
        if self._explicit_witness_urls:
            return self._explicit_witness_urls
        if self._use_witness_pool:
            from .witness_pool import get_witness_pool
            pool = get_witness_pool()
            witnesses = await pool.get_all_witnesses()
            return [w.url for w in witnesses]
        return self.DEFAULT_WITNESSES

    async def check_revocation(
        self,
        credential_said: str,
        registry_said: Optional[str] = None,
        oobi_url: Optional[str] = None,
    ) -> RevocationResult:
        """
        Check revocation status for a credential.

        Args:
            credential_said: SAID of the credential (ACDC 'd' field)
            registry_said: SAID of the credential registry (ACDC 'ri' field)
            oobi_url: OOBI URL to resolve witness/watcher

        Returns:
            RevocationResult with status and event details
        """
        log.info(f"check_revocation: cred={credential_said[:20]}... reg={registry_said[:20] if registry_said else 'None'}...")
        cache_key = f"{credential_said}:{registry_said}"

        # Check cache first
        if cache_key in self._cache:
            cached = self._cache[cache_key]
            self._cache_hits += 1
            log.info(f"  cache_hit: status={cached.status.value}")
            return cached

        self._cache_misses += 1

        # Try OOBI resolution if URL provided
        if oobi_url:
            log.info(f"  trying_oobi: {oobi_url[:50]}...")
            result = await self._query_via_oobi(credential_said, registry_said, oobi_url)
            log.info(f"  oobi_result: status={result.status.value} error={result.error}")
            if result.status != CredentialStatus.ERROR:
                self._cache[cache_key] = result
                return result

        # Try known witnesses (with GLEIF discovery) — parallel first-success
        witness_urls = await self._get_witness_urls_async()
        log.info(f"  trying_witnesses: count={len(witness_urls)} (parallel)")

        # Launch parallel queries, return first non-ERROR result
        tasks = [
            asyncio.create_task(self._query_witness(credential_said, registry_said, url))
            for url in witness_urls
        ]
        try:
            for coro in asyncio.as_completed(tasks):
                result = await coro
                if result.status != CredentialStatus.ERROR:
                    # Cancel remaining tasks
                    for t in tasks:
                        t.cancel()
                    self._cache[cache_key] = result
                    return result
        finally:
            # Ensure all tasks are cancelled on exit
            for t in tasks:
                t.cancel()
            # Suppress CancelledError from cancelled tasks
            await asyncio.gather(*tasks, return_exceptions=True)

        # No TEL data found
        log.info(f"  no_tel_data_found: returning UNKNOWN")
        return RevocationResult(
            status=CredentialStatus.UNKNOWN,
            credential_said=credential_said,
            registry_said=registry_said,
            issuance_event=None,
            revocation_event=None,
            error="No TEL data found from any source",
            source="none"
        )

    async def _query_via_oobi(
        self,
        credential_said: str,
        registry_said: Optional[str],
        oobi_url: str
    ) -> RevocationResult:
        """Query TEL via OOBI URL."""
        try:
            # Parse OOBI to extract witness endpoint
            parsed = urlparse(oobi_url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"

            # Try endpoints in order of preference:
            # 1. Provenant query endpoint (most likely to work)
            # 2. Standard KERI TEL endpoints
            endpoints = [
                f"/query?typ=tel&vcid={credential_said}",  # Provenant format
                f"/tels/{registry_said or credential_said}",
                f"/credentials/{credential_said}",
                f"/oobi/{credential_said}/tels",
            ]

            from app.vvp.http_client import get_shared_client
            client = get_shared_client()
            for endpoint in endpoints:
                url = urljoin(base_url, endpoint)
                log.info(f"    oobi_query: {url}")

                try:
                    resp = await client.get(url, timeout=self.timeout)
                    log.info(f"    oobi_response: status={resp.status_code} len={len(resp.text)}")
                    if resp.status_code == 200:
                        result = self._parse_tel_response(
                            credential_said, registry_said, resp.text, "oobi"
                        )
                        log.info(f"    oobi_parsed: status={result.status.value}")
                        return result
                except httpx.RequestError as e:
                    log.info(f"    oobi_error: {type(e).__name__}: {e}")
                    continue

            return RevocationResult(
                status=CredentialStatus.ERROR,
                credential_said=credential_said,
                registry_said=registry_said,
                issuance_event=None,
                revocation_event=None,
                error=f"OOBI resolution failed for {oobi_url}",
                source="oobi"
            )

        except Exception as e:
            log.error(f"OOBI query error: {e}")
            return RevocationResult(
                status=CredentialStatus.ERROR,
                credential_said=credential_said,
                registry_said=registry_said,
                issuance_event=None,
                revocation_event=None,
                error=str(e),
                source="oobi"
            )

    async def _query_witness(
        self,
        credential_said: str,
        registry_said: Optional[str],
        witness_url: str
    ) -> RevocationResult:
        """Query a specific witness for TEL events.

        Tries multiple endpoint patterns:
        1. Provenant query endpoint: /query?typ=tel&vcid=<credential_said>
        2. Standard KERI TEL endpoint: /tels/<registry_said or credential_said>
        """
        try:
            from app.vvp.http_client import get_shared_client
            client = get_shared_client()
            # Try Provenant-specific query endpoint first
            # Format: /query?typ=tel&vcid=<credential_said>
            provenant_url = f"{witness_url}/query?typ=tel&vcid={credential_said}"
            log.info(f"    witness_query (provenant): {provenant_url}")
            try:
                resp = await client.get(provenant_url, timeout=self.timeout)
                log.info(f"    witness_response: status={resp.status_code} len={len(resp.text)}")
                if resp.status_code == 200 and resp.text.strip():
                    result = self._parse_tel_response(
                        credential_said, registry_said, resp.text, "witness"
                    )
                    log.info(f"    witness_parsed: status={result.status.value}")
                    if result.status != CredentialStatus.UNKNOWN:
                        return result
            except httpx.RequestError as e:
                log.info(f"    provenant_endpoint_error: {type(e).__name__}: {e}")

            # Fall back to standard KERI TEL endpoint
            standard_url = f"{witness_url}/tels/{registry_said or credential_said}"
            log.info(f"    witness_query (standard): {standard_url}")
            resp = await client.get(standard_url, timeout=self.timeout)
            log.info(f"    witness_response: status={resp.status_code} len={len(resp.text)}")

            if resp.status_code == 200:
                result = self._parse_tel_response(
                    credential_said, registry_said, resp.text, "witness"
                )
                log.info(f"    witness_parsed: status={result.status.value}")
                return result

        except Exception as e:
            log.info(f"    witness_error: {type(e).__name__}: {e}")

        return RevocationResult(
            status=CredentialStatus.ERROR,
            credential_said=credential_said,
            registry_said=registry_said,
            issuance_event=None,
            revocation_event=None,
            error=f"Witness query failed: {witness_url}",
            source="witness"
        )

    def _parse_tel_response(
        self,
        credential_said: str,
        registry_said: Optional[str],
        response_text: str,
        source: str
    ) -> RevocationResult:
        """Parse TEL response and determine revocation status."""
        events = self._extract_tel_events(response_text)

        if not events:
            return RevocationResult(
                status=CredentialStatus.UNKNOWN,
                credential_said=credential_said,
                registry_said=registry_said,
                issuance_event=None,
                revocation_event=None,
                error=None,
                source=source
            )

        # Find events for this credential
        cred_events = [e for e in events if e.credential_said == credential_said]
        if not cred_events and registry_said:
            # Try matching by registry
            cred_events = [e for e in events if e.registry_said == registry_said]

        if not cred_events:
            cred_events = events  # Use all events if no specific match

        # Sort by sequence number
        cred_events.sort(key=lambda e: e.sequence)

        # Find issuance and revocation events
        issuance = None
        revocation = None

        for event in cred_events:
            if event.event_type in ('iss', 'bis'):
                issuance = event
            elif event.event_type in ('rev', 'brv'):
                revocation = event

        # Determine status
        if revocation:
            status = CredentialStatus.REVOKED
        elif issuance:
            status = CredentialStatus.ACTIVE
        else:
            status = CredentialStatus.UNKNOWN

        return RevocationResult(
            status=status,
            credential_said=credential_said,
            registry_said=registry_said,
            issuance_event=issuance,
            revocation_event=revocation,
            error=None,
            source=source
        )

    def _extract_tel_events(self, data: str) -> List[TELEvent]:
        """Extract TEL events from CESR stream or JSON response."""
        events = []

        # Try JSON first
        try:
            parsed = json.loads(data)

            # Handle Provenant wrapper format: {"details": "...CESR content..."}
            if isinstance(parsed, dict) and "details" in parsed:
                details = parsed["details"]
                if isinstance(details, str):
                    # Recursively extract from the details string
                    return self._extract_tel_events(details)

            if isinstance(parsed, list):
                for item in parsed:
                    event = self._parse_tel_event(item)
                    if event:
                        events.append(event)
            elif isinstance(parsed, dict):
                event = self._parse_tel_event(parsed)
                if event:
                    events.append(event)
            return events
        except json.JSONDecodeError:
            pass

        # Parse CESR stream - find KERI JSON objects
        pos = 0
        while True:
            # Find next KERI JSON object
            match = data.find('{"v":"KERI', pos)
            if match == -1:
                break

            try:
                # Extract complete JSON object
                depth = 0
                start = match
                end = match

                for i in range(match, len(data)):
                    if data[i] == '{':
                        depth += 1
                    elif data[i] == '}':
                        depth -= 1
                        if depth == 0:
                            end = i + 1
                            break

                json_str = data[start:end]
                obj = json.loads(json_str)

                # Check if it's a TEL event
                event = self._parse_tel_event(obj)
                if event:
                    events.append(event)

                pos = end
            except (json.JSONDecodeError, IndexError):
                pos = match + 1

        return events

    def _parse_tel_event(self, obj: Dict[str, Any]) -> Optional[TELEvent]:
        """Parse a single TEL event from JSON."""
        if not isinstance(obj, dict):
            return None

        # TEL events have 't' field with iss/rev/bis/brv
        event_type = obj.get('t')
        if event_type not in ('iss', 'rev', 'bis', 'brv'):
            return None

        return TELEvent(
            event_type=event_type,
            credential_said=obj.get('i', ''),  # Credential/registry identifier
            registry_said=obj.get('ri', ''),   # Registry identifier (if present)
            sequence=int(obj.get('s', 0)),     # Sequence number
            datetime=obj.get('dt'),            # ISO8601 datetime
            digest=obj.get('d', ''),           # Event digest
            raw=obj
        )

    def parse_dossier_tel(
        self,
        dossier_data: str,
        credential_said: str,
        registry_said: Optional[str] = None
    ) -> RevocationResult:
        """
        Parse TEL events from a dossier CESR stream (no network request).
        Use this when TEL events are included in the dossier response.
        """
        log.info(
            f"parse_dossier_tel: cred={credential_said[:20]}... "
            f"reg={registry_said[:20] if registry_said else 'None'}... "
            f"data_len={len(dossier_data)}"
        )

        # Extract events to log what we found
        events = self._extract_tel_events(dossier_data)
        log.info(f"  inline_tel_events_found: {len(events)}")
        for i, evt in enumerate(events):
            log.info(
                f"  event[{i}]: type={evt.event_type} seq={evt.sequence} "
                f"cred={evt.credential_said[:20]}..."
            )

        result = self._parse_tel_response(
            credential_said, registry_said, dossier_data, "dossier"
        )
        log.info(
            f"  inline_tel_result: status={result.status.value} "
            f"has_iss={result.issuance_event is not None} "
            f"has_rev={result.revocation_event is not None}"
        )
        return result

    async def check_revocation_with_fallback(
        self,
        credential_said: str,
        registry_said: Optional[str] = None,
        dossier_data: Optional[str] = None,
        oobi_url: Optional[str] = None,
    ) -> RevocationResult:
        """Check revocation status with live witness query, dossier as optimization.

        This method provides live revocation checking:
        1. If dossier shows REVOKED, return immediately (revocation is permanent)
        2. Otherwise, query witnesses for live TEL status
        3. Dossier TEL only used to short-circuit for already-revoked credentials

        Note: Dossier TEL data is a snapshot at creation time. A credential that
        was ACTIVE when the dossier was created may have been revoked since then.
        Therefore we always query the witness for live status unless the dossier
        already shows revocation.

        Args:
            credential_said: SAID of the credential to check.
            registry_said: Registry SAID (ri field from ACDC).
            dossier_data: Raw dossier CESR content (for inline TEL parsing).
            oobi_url: OOBI URL for witness discovery.

        Returns:
            RevocationResult with status and event details.
        """
        log.info(
            f"check_revocation_with_fallback: cred={credential_said[:20]}... "
            f"reg={registry_said[:20] if registry_said else 'None'}..."
        )

        # Step 1: Check dossier for REVOKED status only (optimization)
        # If dossier shows REVOKED, we can return immediately - revocation is permanent
        if dossier_data:
            dossier_result = self.parse_dossier_tel(
                dossier_data=dossier_data,
                credential_said=credential_said,
                registry_said=registry_said,
            )
            if dossier_result.status == CredentialStatus.REVOKED:
                log.info(f"  dossier_shows_revoked: returning immediately")
                return dossier_result
            log.info(f"  dossier_status={dossier_result.status.value}: querying witness for live status")

        # Step 2: Query witnesses for live TEL status
        # This is necessary because dossier ACTIVE status may be stale
        result = await self.check_revocation(
            credential_said=credential_said,
            registry_said=registry_said,
            oobi_url=oobi_url,
        )
        log.info(f"  live_query_result: status={result.status.value}")
        return result

    async def check_chain_revocation(
        self,
        chain_info: ChainExtractionResult,
        dossier_data: Optional[str] = None,
        oobi_url: Optional[str] = None,
        timeout: float = 30.0,
    ) -> ChainRevocationResult:
        """Check revocation status for entire credential chain.

        Checks ALL credentials in parallel. If ANY is REVOKED, chain is invalid.
        Per vLEI spec: "Anyone in the chain-of-authority can revoke the credential
        issued-by them. This breaks the chain."

        Chain Status Rules:
        - If chain_info.complete is False → chain_status = UNKNOWN
        - If ANY credential REVOKED → chain_status = REVOKED
        - If ALL credentials ACTIVE and chain complete → chain_status = ACTIVE
        - Otherwise → chain_status = UNKNOWN

        Args:
            chain_info: ChainExtractionResult with chain SAIDs and completeness info.
            dossier_data: Raw dossier CESR content (for inline TEL parsing).
            oobi_url: OOBI URL for witness discovery.
            timeout: Overall timeout for all checks.

        Returns:
            ChainRevocationResult with aggregate chain status.
        """
        log.info(
            f"check_chain_revocation: chain_len={len(chain_info.chain_saids)} "
            f"complete={chain_info.complete}"
        )

        results: Dict[str, RevocationResult] = {}
        errors: List[str] = []

        # Pre-check: incomplete chain → status will be UNKNOWN
        if not chain_info.complete:
            errors.append(f"Chain incomplete: missing {chain_info.missing_links}")

        # Check all credentials in parallel
        async def check_one(said: str) -> Tuple[str, RevocationResult]:
            registry_said = chain_info.registry_saids.get(said)
            result = await self.check_revocation_with_fallback(
                credential_said=said,
                registry_said=registry_said,
                dossier_data=dossier_data,
                oobi_url=oobi_url,
            )
            return (said, result)

        try:
            async with asyncio.timeout(timeout):
                tasks = [check_one(said) for said in chain_info.chain_saids]
                check_results = await asyncio.gather(*tasks, return_exceptions=True)
        except TimeoutError:
            errors.append(f"Chain revocation check timed out after {timeout}s")
            check_results = []

        # Process results
        revoked: List[str] = []
        for item in check_results:
            if isinstance(item, Exception):
                errors.append(str(item))
                continue
            said, result = item
            results[said] = result
            if result.status == CredentialStatus.REVOKED:
                revoked.append(said)
                log.info(f"  chain_credential_revoked: {said[:20]}...")

        # Determine chain status
        # Guard: empty chain_saids means nothing was checked - status is UNKNOWN
        if not chain_info.chain_saids:
            chain_status = CredentialStatus.UNKNOWN
            errors.append("No credentials in chain to check")
        elif revoked:
            chain_status = CredentialStatus.REVOKED
        elif not chain_info.complete:
            chain_status = CredentialStatus.UNKNOWN
        elif errors:
            chain_status = CredentialStatus.UNKNOWN
        elif not results:
            # No results despite having chain SAIDs - something went wrong
            chain_status = CredentialStatus.UNKNOWN
        elif all(r.status == CredentialStatus.ACTIVE for r in results.values()):
            chain_status = CredentialStatus.ACTIVE
        else:
            chain_status = CredentialStatus.UNKNOWN

        log.info(
            f"  chain_revocation_result: status={chain_status.value} "
            f"checked={len(results)} revoked={len(revoked)} errors={len(errors)}"
        )

        return ChainRevocationResult(
            chain_status=chain_status,
            credential_results=results,
            revoked_credentials=revoked,
            chain_saids=chain_info.chain_saids,
            missing_chain_links=chain_info.missing_links,
            check_complete=chain_info.complete and len(errors) == 0,
            errors=errors,
            checked_at=datetime.now(timezone.utc).isoformat(),
        )

    def clear_cache(self):
        """Clear the revocation status cache."""
        self._cache.clear()

    def cache_metrics(self) -> Dict[str, Any]:
        """Get cache metrics for monitoring.

        Returns:
            Dictionary with cache statistics.
        """
        total = self._cache_hits + self._cache_misses
        hit_rate = self._cache_hits / total if total > 0 else 0.0
        return {
            "hits": self._cache_hits,
            "misses": self._cache_misses,
            "size": len(self._cache),
            "hit_rate": round(hit_rate, 4),
        }


# Singleton instance
_tel_client: Optional[TELClient] = None


def get_tel_client() -> TELClient:
    """Get or create the TEL client singleton."""
    global _tel_client
    if _tel_client is None:
        _tel_client = TELClient(timeout=TEL_CLIENT_TIMEOUT_SECONDS)
    return _tel_client
