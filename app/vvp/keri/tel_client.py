"""
Lightweight TEL (Transaction Event Log) client for querying KERI witnesses/watchers.
Does not require full keripy installation - uses direct HTTP queries.

Per KERI spec, TEL events track credential lifecycle:
- iss: issuance (simple)
- rev: revocation (simple)
- bis: backer-backed issuance
- brv: backer-backed revocation
"""

import json
import logging
import re
from dataclasses import dataclass
from enum import Enum
from typing import Optional, List, Dict, Any
from urllib.parse import urljoin, urlparse

import httpx

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


class TELClient:
    """
    Client for querying KERI witnesses/watchers for TEL events.

    KERI OOBI patterns for TEL queries:
    - /oobi/{aid}/witness/{wit-aid}  - Witness key state
    - /.well-known/keri/oobi/{aid}   - Well-known OOBI
    - /tels/{registry-aid}           - TEL events for registry
    - /credentials/{cred-said}       - Credential + TEL state
    """

    # Fallback witnesses - used ONLY when kid doesn't provide witness URL
    # PRIMARY method: Derive witness from PASSporT kid field (witness OOBI URL)
    # GLEIF testnet witnesses removed - not functional for OVC project
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
        witness_urls: Optional[List[str]] = None
    ):
        self.timeout = timeout
        self.witness_urls = witness_urls or self.DEFAULT_WITNESSES
        self._cache: Dict[str, RevocationResult] = {}
        # Cache metrics
        self._cache_hits: int = 0
        self._cache_misses: int = 0

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

        # Try known witnesses
        log.info(f"  trying_witnesses: count={len(self.witness_urls)}")
        for i, witness_url in enumerate(self.witness_urls):
            result = await self._query_witness(credential_said, registry_said, witness_url)
            log.info(f"  witness[{i}] {witness_url}: status={result.status.value}")
            if result.status != CredentialStatus.ERROR:
                self._cache[cache_key] = result
                return result

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

            # Try standard KERI API endpoints
            endpoints = [
                f"/tels/{registry_said or credential_said}",
                f"/credentials/{credential_said}",
                f"/oobi/{credential_said}/tels",
            ]

            async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
                for endpoint in endpoints:
                    url = urljoin(base_url, endpoint)
                    log.info(f"    oobi_query: {url}")

                    try:
                        resp = await client.get(url)
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
        """Query a specific witness for TEL events."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
                # Standard witness TEL endpoint
                url = f"{witness_url}/tels/{registry_said or credential_said}"
                log.info(f"    witness_query: {url}")
                resp = await client.get(url)
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
        _tel_client = TELClient()
    return _tel_client
