"""KERI Key State Resolver.

Resolves the key state for an AID at a specific reference time T.
This is the core component for Tier 2 verification, enabling
historical key state validation per VVP spec §5.

Per spec §5A Step 4: "Resolve issuer key state at reference time T"
Per spec §5D: "VVP passports can verify at arbitrary past moments using historical data"
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import List, Optional

from .cache import CacheConfig, KeyStateCache
from .delegation import DelegationChain
from .exceptions import (
    KELChainInvalidError,
    KeyNotYetValidError,
    ResolutionFailedError,
)
from .kel_parser import (
    ESTABLISHMENT_TYPES,
    EventType,
    KELEvent,
    WitnessReceipt,
    parse_kel_stream,
    validate_kel_chain,
)
from .oobi import OOBIResult, dereference_oobi, validate_oobi_is_kel


@dataclass
class KeyState:
    """Resolved key state at a specific point in time.

    Represents the signing keys that were valid for an AID at a given
    reference time T.

    Attributes:
        aid: The AID (Autonomic Identifier).
        signing_keys: List of Ed25519 public keys (32 bytes each).
        sequence: Establishment event sequence number.
        establishment_digest: SAID of the establishment event.
        valid_from: Earliest witness timestamp for this state.
        witnesses: List of witness AIDs.
        toad: Witness threshold (threshold of accountable duplicity).
        is_delegated: True if this is a delegated identifier (dip/drt).
        delegator_aid: For delegated identifiers, the delegator's AID.
        inception_event: The inception event (icp/dip) for multi-level resolution.
        delegation_chain: Full delegation chain if resolved.
    """
    aid: str
    signing_keys: List[bytes]
    sequence: int
    establishment_digest: str
    valid_from: Optional[datetime]
    witnesses: List[str]
    toad: int
    is_delegated: bool = False
    delegator_aid: Optional[str] = None
    inception_event: Optional[KELEvent] = None
    delegation_chain: Optional["DelegationChain"] = None


# Global cache instance (singleton pattern)
_cache: Optional[KeyStateCache] = None


def get_cache(config: Optional[CacheConfig] = None) -> KeyStateCache:
    """Get or create the global key state cache.

    Args:
        config: Optional configuration for the cache.

    Returns:
        The KeyStateCache instance.
    """
    global _cache
    if _cache is None:
        _cache = KeyStateCache(config)
    return _cache


def reset_cache() -> None:
    """Reset the global cache (for testing)."""
    global _cache
    _cache = None


async def resolve_key_state(
    kid: str,
    reference_time: datetime,
    oobi_url: Optional[str] = None,
    min_witnesses: Optional[int] = None,
    use_cache: bool = True,
    _allow_test_mode: bool = False
) -> KeyState:
    """Resolve the key state for an AID at reference time T.

    This is the main entry point for Tier 2 key state resolution.
    It fetches the KEL, validates the chain, and determines which
    keys were valid at time T.

    Features:
    - CESR binary format (application/cesr, application/json+cesr)
    - KERI-compliant canonicalization with proper field ordering
    - SAID validation using Blake3-256
    - Witness receipt signature validation

    Behavior:
    - Rotation before T is normal: returns the rotated key
    - Only errors if no establishment event exists at/before T

    Args:
        kid: The AID (Autonomic Identifier) to resolve.
        reference_time: The reference time T (typically PASSporT iat).
        oobi_url: Optional OOBI URL for fetching KEL.
        min_witnesses: Minimum witness receipts required (uses event's toad if None).
        use_cache: Whether to use/update the cache.
        _allow_test_mode: Internal flag to bypass feature gate in tests.

    Returns:
        KeyState representing the keys valid at time T.

    Raises:
        ResolutionFailedError: If TIER2_KEL_RESOLUTION_ENABLED is False.
        ResolutionFailedError: If resolution fails (recoverable → INDETERMINATE).
        KELChainInvalidError: If chain validation fails (non-recoverable → INVALID).
        KeyNotYetValidError: If no establishment event at/before T (→ INVALID).
    """
    from app.core.config import TIER2_KEL_RESOLUTION_ENABLED

    # Feature gate check
    if not TIER2_KEL_RESOLUTION_ENABLED and not _allow_test_mode:
        raise ResolutionFailedError(
            "Tier 2 KEL resolution is disabled. "
            "Set TIER2_KEL_RESOLUTION_ENABLED=true to enable KERI-based "
            "key state resolution."
        )

    # Extract AID from kid (may be a full OOBI URL or just the AID)
    aid = _extract_aid(kid)

    cache = get_cache() if use_cache else None

    # Check cache first
    if cache:
        cached = await cache.get_for_time(aid, reference_time)
        if cached:
            return cached

    # Determine OOBI URL
    if not oobi_url:
        oobi_url = _construct_oobi_url(kid)

    # Fetch and validate KEL via OOBI per §4.2
    # Use strict validation in production mode, lenient in test mode
    oobi_result, events = await _fetch_and_validate_oobi(
        oobi_url,
        aid,
        strict_validation=not _allow_test_mode
    )

    # Find key state at reference time T
    key_state = _find_key_state_at_time(
        aid=aid,
        events=events,
        reference_time=reference_time,
        min_witnesses=min_witnesses,
        strict_validation=not _allow_test_mode  # Strict mode validates witness sigs (§7.3)
    )

    # Cache the result with the query reference_time for future lookups
    if cache:
        await cache.put(key_state, reference_time=reference_time)

    return key_state


async def resolve_key_state_with_kel(
    kid: str,
    reference_time: datetime,
    oobi_url: Optional[str] = None,
    min_witnesses: Optional[int] = None,
    _allow_test_mode: bool = False
) -> tuple[KeyState, List[KELEvent]]:
    """Resolve key state AND return the full KEL for delegation authorization.

    This is an extended version of resolve_key_state() that also returns
    the parsed KEL events. Used for delegation authorization validation
    which requires access to the delegator's full KEL to find anchor events.

    Args:
        kid: The AID (Autonomic Identifier) to resolve.
        reference_time: The reference time T.
        oobi_url: Optional OOBI URL for fetching KEL.
        min_witnesses: Minimum witness receipts required.
        _allow_test_mode: Internal flag to bypass feature gate in tests.

    Returns:
        Tuple of (KeyState, List[KELEvent]).

    Raises:
        Same as resolve_key_state().
    """
    from app.core.config import TIER2_KEL_RESOLUTION_ENABLED

    if not TIER2_KEL_RESOLUTION_ENABLED and not _allow_test_mode:
        raise ResolutionFailedError(
            "Tier 2 KEL resolution is disabled."
        )

    aid = _extract_aid(kid)

    if not oobi_url:
        oobi_url = _construct_oobi_url(kid)

    # Fetch and validate KEL via OOBI
    oobi_result, events = await _fetch_and_validate_oobi(
        oobi_url,
        aid,
        strict_validation=not _allow_test_mode
    )

    # Find key state at reference time T
    key_state = _find_key_state_at_time(
        aid=aid,
        events=events,
        reference_time=reference_time,
        min_witnesses=min_witnesses,
        strict_validation=not _allow_test_mode
    )

    return key_state, events


async def _fetch_and_validate_oobi(
    oobi_url: str,
    aid: str,
    timeout: float = 5.0,
    strict_validation: bool = True
) -> tuple[OOBIResult, List[KELEvent]]:
    """Fetch OOBI and validate it contains a valid KEL.

    Per VVP §4.2, the kid OOBI must resolve to a valid Key Event Log.
    This function integrates validation from validate_oobi_is_kel() but
    returns the events for time-based key state lookup.

    Args:
        oobi_url: OOBI URL to fetch.
        aid: Expected AID.
        timeout: Request timeout in seconds.
        strict_validation: If True, use canonical KERI validation (production).
            If False, allow lenient validation (test fixtures).

    Returns:
        Tuple of (OOBIResult, parsed events).

    Raises:
        ResolutionFailedError: If fetch fails or KEL is invalid.
        KELChainInvalidError: If chain validation fails.
        OOBIContentInvalidError: If content structure is invalid.
    """
    from .exceptions import OOBIContentInvalidError

    # Fetch OOBI content
    oobi_result = await dereference_oobi(oobi_url, timeout=timeout)

    if not oobi_result.kel_data:
        raise OOBIContentInvalidError(f"OOBI response contains no KEL data for {aid}")

    # Parse KEL events
    events = parse_kel_stream(
        oobi_result.kel_data,
        content_type=oobi_result.content_type,
        allow_json_only=True  # Allow JSON for testing
    )

    if not events:
        raise OOBIContentInvalidError(f"Empty KEL for AID {aid}")

    # Validate first event is inception (per §4.2)
    from .kel_parser import EventType
    first_event = events[0]
    if first_event.event_type not in {EventType.ICP, EventType.DIP}:
        raise OOBIContentInvalidError(
            f"OOBI KEL must start with inception event, found: {first_event.event_type.value}"
        )

    # Validate KEL chain (signatures and continuity)
    # Per §4.2: OOBI MUST resolve to valid KEL
    # In strict mode (production), use canonical KERI validation
    # In lenient mode (test), allow placeholder SAIDs and non-canonical serialization
    validate_kel_chain(
        events,
        validate_saids=strict_validation,  # Strict mode validates SAIDs
        use_canonical=strict_validation,   # Strict mode uses canonical serialization
        validate_witnesses=strict_validation  # Strict mode validates witness signatures (§7.3)
    )

    return oobi_result, events


def _extract_aid(kid: str) -> str:
    """Extract the AID from a kid value.

    The kid may be:
    - A bare AID (e.g., "BIKKvIT9...")
    - An OOBI URL containing the AID

    Args:
        kid: The kid value from PASSporT header.

    Returns:
        The extracted AID string.
    """
    # Check if it's a URL
    if kid.startswith(("http://", "https://")):
        from .oobi import _extract_aid_from_url
        aid = _extract_aid_from_url(kid)
        if aid:
            return aid
        raise ResolutionFailedError(f"Could not extract AID from OOBI URL: {kid}")

    # Check for did:web: format (e.g., did:web:domain#AID)
    if kid.startswith("did:web:"):
        if "#" in kid:
            aid = kid.split("#", 1)[1]
            if aid and aid[0] in "BDEFGHJKLMNOPQRSTUVWXYZ":
                return aid
        raise ResolutionFailedError(f"Could not extract AID from did:web URL: {kid[:30]}...")

    # Otherwise, treat as bare AID
    # KERI AIDs start with derivation codes (B, D, E, etc.)
    if kid and kid[0] in "BDEFGHJKLMNOPQRSTUVWXYZ":
        return kid

    raise ResolutionFailedError(f"Invalid kid format: {kid[:20]}...")


def _construct_oobi_url(kid: str) -> str:
    """Construct an OOBI URL from a kid value.

    If the kid is already an OOBI URL, return it.
    Otherwise, we cannot construct a URL without additional configuration.

    Args:
        kid: The kid value.

    Returns:
        OOBI URL string.

    Raises:
        ResolutionFailedError: If URL cannot be constructed.
    """
    if kid.startswith(("http://", "https://")):
        return kid

    # Cannot construct OOBI URL from bare AID without witness configuration
    raise ResolutionFailedError(
        f"Cannot resolve bare AID {kid[:20]}...: OOBI URL required. "
        f"Tier 2 resolution requires either an OOBI URL in the kid field "
        f"or configured witness endpoints."
    )


def _find_key_state_at_time(
    aid: str,
    events: List[KELEvent],
    reference_time: datetime,
    min_witnesses: Optional[int],
    strict_validation: bool = False
) -> KeyState:
    """Find the key state that was valid at reference time T.

    Walks the KEL chronologically and finds the last establishment event
    at or before T.

    Args:
        aid: The AID being resolved.
        events: Parsed and validated KEL events.
        reference_time: The reference time T.
        min_witnesses: Minimum witness receipts required.
        strict_validation: If True, validates witness signatures (production).

    Returns:
        KeyState representing keys valid at T.

    Raises:
        KeyNotYetValidError: If T is before the first establishment event.
        ResolutionFailedError: If insufficient witness receipts.
        StateInvalidError: If witness signature validation fails (strict mode).
    """
    # Find all establishment events
    establishment_events = [e for e in events if e.is_establishment]

    if not establishment_events:
        raise ResolutionFailedError(f"No establishment events in KEL for {aid}")

    # Find the last establishment event at or before reference_time
    valid_event: Optional[KELEvent] = None
    rotation_without_timestamp = False

    for event in establishment_events:
        # Determine event's effective time
        event_time = _get_event_time(event)

        if event_time is None:
            # No timestamp available
            if event.is_inception:
                # Inception without timestamp: accept it (required to establish identity)
                valid_event = event
            else:
                # Rotation without timestamp: we cannot determine if it was
                # before or after reference_time T. Flag this for later.
                rotation_without_timestamp = True
                # Don't update valid_event - stay with the last timestamped state
        elif _compare_datetimes(event_time, reference_time) <= 0:
            valid_event = event
            rotation_without_timestamp = False  # Found a timestamped event at/before T

    # If we found rotations without timestamps after our valid_event,
    # we cannot be certain about the key state at reference_time
    if rotation_without_timestamp and valid_event is not None:
        raise ResolutionFailedError(
            f"Cannot determine key state at {reference_time.isoformat()}: "
            f"KEL contains rotation events without timestamps. "
            f"Witness receipts with timestamps are required for historical key state resolution."
        )

    if valid_event is None:
        # Reference time is before any establishment event
        first_event_time = _get_event_time(establishment_events[0])
        if first_event_time:
            raise KeyNotYetValidError(
                f"Reference time {reference_time.isoformat()} is before "
                f"inception at {first_event_time.isoformat()}"
            )
        else:
            raise KeyNotYetValidError(
                f"Reference time {reference_time.isoformat()} is before inception"
            )

    # Validate witness receipts (§7.3)
    _validate_witness_receipts(valid_event, min_witnesses, strict_validation)

    # Determine if this is a delegated identifier
    # Check the inception event for delegation status
    inception_event = establishment_events[0]
    is_delegated = inception_event.event_type in {EventType.DIP, EventType.DRT}
    delegator_aid = inception_event.delegator_aid if is_delegated else None

    # Build KeyState
    return KeyState(
        aid=aid,
        signing_keys=valid_event.signing_keys,
        sequence=valid_event.sequence,
        establishment_digest=valid_event.digest,
        valid_from=_get_event_time(valid_event),
        witnesses=valid_event.witnesses,
        toad=valid_event.toad,
        is_delegated=is_delegated,
        delegator_aid=delegator_aid,
        inception_event=inception_event,
        delegation_chain=None  # Populated by caller if needed
    )


def _normalize_datetime(dt: datetime) -> datetime:
    """Normalize datetime to UTC for comparison.

    Handles both timezone-aware and naive datetimes.
    """
    if dt.tzinfo is None:
        # Naive datetime - assume UTC
        return dt.replace(tzinfo=timezone.utc)
    else:
        # Already timezone-aware
        return dt


def _compare_datetimes(dt1: datetime, dt2: datetime) -> int:
    """Compare two datetimes, handling timezone-aware vs naive.

    Returns:
        -1 if dt1 < dt2
        0 if dt1 == dt2
        1 if dt1 > dt2
    """
    norm1 = _normalize_datetime(dt1)
    norm2 = _normalize_datetime(dt2)

    if norm1 < norm2:
        return -1
    elif norm1 > norm2:
        return 1
    else:
        return 0


def _get_event_time(event: KELEvent) -> Optional[datetime]:
    """Get the effective time for an event.

    Uses the event's timestamp if available, or the earliest witness
    receipt timestamp.

    Args:
        event: The KEL event.

    Returns:
        The event's effective timestamp, or None if unavailable.
    """
    # Try event timestamp first
    if event.timestamp:
        return event.timestamp

    # Fall back to earliest witness receipt timestamp
    receipt_times = [
        r.timestamp for r in event.witness_receipts
        if r.timestamp is not None
    ]
    if receipt_times:
        return min(receipt_times)

    return None


def _validate_witness_receipts(
    event: KELEvent,
    min_witnesses: Optional[int],
    strict_validation: bool = False
) -> None:
    """Validate that an event has sufficient witness receipts.

    Per VVP §7.3, witness receipts MUST be validated in production.

    Args:
        event: The event to validate.
        min_witnesses: Minimum receipts required (uses event's toad if None).
        strict_validation: If True, validates signatures (production).
            If False, only checks count (test mode).

    Raises:
        ResolutionFailedError: If no receipts in strict mode.
        StateInvalidError: If insufficient valid receipts in strict mode.
    """
    from .exceptions import StateInvalidError

    # Determine threshold
    if min_witnesses is not None:
        threshold = min_witnesses
    else:
        # Use event's toad (threshold of accountable duplicity)
        threshold = event.toad

    # For testing/dev, allow 0 threshold
    if threshold <= 0:
        return

    # Check receipt count first
    receipt_count = len(event.witness_receipts)

    if receipt_count == 0:
        if strict_validation:
            # In strict mode, no receipts is a resolution failure (may be recoverable)
            raise ResolutionFailedError(
                f"No witness receipts for event (need {threshold} per toad)"
            )
        return  # In non-strict mode, allow missing receipts

    if receipt_count < threshold:
        if strict_validation:
            # In strict mode, insufficient receipts is a state validity error
            raise StateInvalidError(
                f"Insufficient witness receipts: got {receipt_count}, "
                f"need {threshold} (toad={event.toad})"
            )
        else:
            # In non-strict mode, log warning but allow
            raise ResolutionFailedError(
                f"Insufficient witness receipts: got {receipt_count}, "
                f"need {threshold} (toad={event.toad})"
            )

    # In strict mode, validate signatures using kel_parser
    if strict_validation:
        from .kel_parser import validate_witness_receipts as validate_witness_sigs
        from .keri_canonical import canonical_serialize

        # Compute signing input for signature verification
        # Per KERI spec, witnesses sign the canonical serialization of the event
        signing_input = canonical_serialize(event.raw)

        # Validate signatures - this raises if validation fails
        try:
            validate_witness_sigs(event, signing_input, threshold)
        except Exception as e:
            raise StateInvalidError(f"Witness signature validation failed: {e}")


async def resolve_key_state_tier1_fallback(kid: str) -> KeyState:
    """Tier 1 fallback: Extract key directly from AID without KEL validation.

    This provides backwards compatibility with the Tier 1 implementation
    that extracts keys directly from the AID prefix.

    WARNING: This does NOT validate key state at time T. It returns the
    key embedded in the AID, which may have been rotated.

    Args:
        kid: The AID (must be a bare AID, not OOBI URL).

    Returns:
        KeyState with the embedded key (sequence 0, no temporal validity).

    Raises:
        ResolutionFailedError: If kid format is invalid.
    """
    from .key_parser import parse_kid_to_verkey

    verkey = parse_kid_to_verkey(kid)

    return KeyState(
        aid=kid,
        signing_keys=[verkey.raw],
        sequence=0,
        establishment_digest="",  # Unknown without KEL
        valid_from=None,  # Unknown without witnesses
        witnesses=[],
        toad=0
    )
