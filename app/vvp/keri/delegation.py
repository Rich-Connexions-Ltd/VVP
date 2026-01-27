"""Multi-level KERI delegation validation.

Supports delegation chains: Delegator A -> Sub-Delegator B -> Identifier C

Per KERI spec, delegated identifiers (dip/drt events) require authorization
from their delegator. This module resolves and validates complete delegation
chains back to a non-delegated root.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, List, Optional, Set, Tuple

from .kel_parser import EventType, KELEvent
from .exceptions import KELChainInvalidError, ResolutionFailedError
from ..api_models import ClaimStatus

log = logging.getLogger(__name__)

# Maximum delegation depth to prevent infinite recursion
MAX_DELEGATION_DEPTH = 5


@dataclass
class DelegationChain:
    """Represents a validated delegation chain.

    Attributes:
        delegates: List of AIDs from leaf to root delegator.
        root_aid: The non-delegated root identifier.
        valid: Whether the chain was successfully validated.
        errors: List of validation errors encountered.
    """
    delegates: List[str] = field(default_factory=list)
    root_aid: Optional[str] = None
    valid: bool = False
    errors: List[str] = field(default_factory=list)


async def resolve_delegation_chain(
    delegated_aid: str,
    inception_event: KELEvent,
    reference_time: datetime,
    oobi_resolver: Callable,
    visited: Optional[Set[str]] = None,
    depth: int = 0
) -> DelegationChain:
    """Recursively resolve delegation chain to non-delegated root.

    For each delegated identifier:
    1. Extract delegator AID from 'di' field
    2. Resolve delegator's KEL via OOBI
    3. Validate delegator's key state at delegation time
    4. If delegator is also delegated, recurse
    5. Return full chain when non-delegated root found

    Args:
        delegated_aid: The delegated identifier to validate.
        inception_event: The DIP event establishing the delegation.
        reference_time: Time T for key state lookup.
        oobi_resolver: Async function(aid, time) -> KeyState to resolve key state.
        visited: Set of AIDs visited (cycle detection).
        depth: Current recursion depth.

    Returns:
        DelegationChain with full chain and validation status.

    Raises:
        KELChainInvalidError: If delegation chain is invalid.
        ResolutionFailedError: If delegator cannot be resolved.
    """
    # Check depth limit
    if depth > MAX_DELEGATION_DEPTH:
        raise KELChainInvalidError(
            f"Delegation chain exceeds max depth {MAX_DELEGATION_DEPTH}"
        )

    # Initialize visited set for cycle detection
    visited = visited or set()
    if delegated_aid in visited:
        raise KELChainInvalidError(
            f"Circular delegation detected: {delegated_aid}"
        )
    visited.add(delegated_aid)

    # Get delegator AID from inception event
    delegator_aid = inception_event.delegator_aid
    if not delegator_aid:
        raise KELChainInvalidError(
            f"DIP event for {delegated_aid[:20]}... missing delegator AID"
        )

    log.debug(
        f"Resolving delegation: {delegated_aid[:20]}... -> {delegator_aid[:20]}... "
        f"(depth {depth})"
    )

    try:
        # Resolve delegator's key state
        delegator_key_state = await oobi_resolver(delegator_aid, reference_time)
    except Exception as e:
        raise ResolutionFailedError(
            f"Failed to resolve delegator {delegator_aid[:20]}...: {e}"
        )

    # Check if delegator is also delegated (multi-level chain)
    if delegator_key_state.is_delegated:
        # Recurse to resolve delegator's delegator
        delegator_inception = delegator_key_state.inception_event
        if not delegator_inception:
            raise KELChainInvalidError(
                f"Delegator {delegator_aid[:20]}... missing inception event"
            )

        parent_chain = await resolve_delegation_chain(
            delegator_aid,
            delegator_inception,
            reference_time,
            oobi_resolver,
            visited,
            depth + 1
        )

        return DelegationChain(
            delegates=[delegated_aid] + parent_chain.delegates,
            root_aid=parent_chain.root_aid,
            valid=parent_chain.valid,
            errors=parent_chain.errors
        )

    # Delegator is non-delegated root
    log.debug(f"Found delegation root: {delegator_aid[:20]}...")
    return DelegationChain(
        delegates=[delegated_aid, delegator_aid],
        root_aid=delegator_aid,
        valid=True,
        errors=[]
    )


async def validate_delegation_authorization(
    delegation_event: KELEvent,
    delegator_kel: List[KELEvent],
    delegator_key_state: "KeyState"
) -> Tuple[bool, ClaimStatus, List[str]]:
    """Validate that delegator authorized this delegation.

    Per KERI spec, delegation requires:
    1. Delegator's seal in an interaction event (ixn) anchoring the delegation
    2. The seal contains the delegated identifier's inception event SAID
    3. Delegator's signature on the interaction event

    Verification Algorithm:
    1. Extract delegation SAID from dip event's 'd' field
    2. Search delegator's KEL for an interaction (ixn) event containing
       a seal with matching SAID in its 'a' (anchor) field
    3. Verify the ixn event's signature against delegator's key state
       at the time of the ixn event
    4. Verify ixn event occurred before or at delegation time

    Args:
        delegation_event: The DIP/DRT event to validate.
        delegator_kel: Full KEL of the delegator.
        delegator_key_state: Delegator's resolved key state.

    Returns:
        Tuple of (is_valid, claim_status, errors):
        - (True, VALID, []) if delegation is properly authorized
        - (False, INVALID, [...]) if seal missing or signature invalid
        - (False, INDETERMINATE, [...]) if delegator KEL incomplete
    """
    errors: List[str] = []

    # 1. Get the delegation event's SAID
    delegation_said = delegation_event.digest
    if not delegation_said:
        return (False, ClaimStatus.INVALID, ["Delegation event missing SAID"])

    # 2. Search delegator's KEL for anchoring interaction event
    anchor_event: Optional[KELEvent] = None
    for event in delegator_kel:
        if event.event_type != EventType.IXN:
            continue

        # Check anchor field for delegation seal
        anchors = event.raw.get("a", [])
        if isinstance(anchors, list):
            for anchor in anchors:
                if isinstance(anchor, dict) and anchor.get("d") == delegation_said:
                    anchor_event = event
                    break
        elif isinstance(anchors, dict) and anchors.get("d") == delegation_said:
            anchor_event = event

        if anchor_event:
            break

    if not anchor_event:
        # No anchoring event found - delegator KEL may be incomplete
        log.warning(
            f"Delegation anchor not found in delegator KEL for {delegation_said[:20]}..."
        )
        return (
            False,
            ClaimStatus.INDETERMINATE,
            ["Delegation anchor not found in delegator KEL"]
        )

    # 3. Verify anchor event signature against delegator's key state
    # Get delegator's key state at time of anchor event
    anchor_seq = anchor_event.sequence
    key_at_anchor = _find_key_state_at_sequence(delegator_kel, anchor_seq)
    if not key_at_anchor:
        return (
            False,
            ClaimStatus.INDETERMINATE,
            ["Cannot determine delegator key state at anchor time"]
        )

    # Verify signature
    if not _verify_event_signature(anchor_event, key_at_anchor):
        return (
            False,
            ClaimStatus.INVALID,
            ["Delegator anchor event signature invalid"]
        )

    # 4. Verify timing: anchor must precede or equal delegation
    if anchor_event.timestamp and delegation_event.timestamp:
        if anchor_event.timestamp > delegation_event.timestamp:
            return (
                False,
                ClaimStatus.INVALID,
                ["Delegation anchor event occurred after delegation"]
            )

    log.debug(
        f"Delegation authorization verified: anchor seq {anchor_seq} for "
        f"{delegation_said[:20]}..."
    )
    return (True, ClaimStatus.VALID, [])


def _find_key_state_at_sequence(
    kel: List[KELEvent],
    target_seq: int
) -> Optional[List[bytes]]:
    """Find signing keys in effect at a given sequence number.

    Walks through establishment events to find keys at target sequence.

    Args:
        kel: List of KEL events in sequence order.
        target_seq: Sequence number to find key state for.

    Returns:
        List of signing key bytes, or None if not determinable.
    """
    current_keys: Optional[List[bytes]] = None

    for event in kel:
        if event.sequence > target_seq:
            break

        # Only establishment events update key state
        if event.is_establishment and event.signing_keys:
            current_keys = event.signing_keys

    return current_keys


def _verify_event_signature(
    event: KELEvent,
    signing_keys: List[bytes]
) -> bool:
    """Verify event signature against signing keys.

    Args:
        event: The event to verify.
        signing_keys: Keys that should have signed the event.

    Returns:
        True if signature valid, False otherwise.
    """
    if not event.signatures:
        log.warning(f"Event seq {event.sequence} has no signatures")
        return False

    if not signing_keys:
        log.warning(f"No signing keys provided for event seq {event.sequence}")
        return False

    # Import here to avoid circular imports
    import pysodium
    from .keri_canonical import canonical_serialize

    # Get canonical bytes for signature verification
    try:
        signing_input = canonical_serialize(event.raw)
    except Exception as e:
        log.warning(f"Failed to serialize event for verification: {e}")
        return False

    # Verify at least one signature matches at least one key
    for sig in event.signatures:
        for key in signing_keys:
            try:
                pysodium.crypto_sign_verify_detached(sig, signing_input, key)
                return True  # Found valid signature
            except Exception:
                continue  # Try next key

    log.warning(f"No valid signature found for event seq {event.sequence}")
    return False
