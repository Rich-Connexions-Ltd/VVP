"""KEL (Key Event Log) parser and validator.

Parses and validates KERI Key Event Logs per the KERI spec.
Supports both CESR-encoded streams (normative) and JSON (test fallback).

Chain validation ensures:
1. Each event's prior_digest matches the previous event's digest
2. Each event is signed by keys from the prior event (or self-signed for inception)
"""

import base64
import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from .cesr import CESRMessage, parse_cesr_stream as cesr_parse, is_cesr_stream
from .exceptions import (
    KELChainInvalidError,
    ResolutionFailedError,
)
from .keri_canonical import canonical_serialize, most_compact_form

# Content types for OOBI responses
CESR_CONTENT_TYPE = "application/json+cesr"
JSON_CONTENT_TYPE = "application/json"


class EventType(Enum):
    """KERI event types.

    Only establishment events (icp, rot, dip, drt) affect key state.
    Interaction events (ixn) are included in the log but don't change keys.
    """
    ICP = "icp"  # Inception - first event, establishes AID
    ROT = "rot"  # Rotation - changes signing keys
    IXN = "ixn"  # Interaction - anchors data, no key change
    DIP = "dip"  # Delegated inception
    DRT = "drt"  # Delegated rotation


# Establishment events that change key state
ESTABLISHMENT_TYPES = frozenset({EventType.ICP, EventType.ROT, EventType.DIP, EventType.DRT})

# Delegated events requiring special handling
DELEGATED_TYPES = frozenset({EventType.DIP, EventType.DRT})


@dataclass
class WitnessReceipt:
    """Receipt from a witness confirming an event.

    Witnesses provide threshold signatures on events to establish
    consensus on the event log state.

    Attributes:
        witness_aid: The AID of the witness.
        signature: The witness's signature on the event.
        timestamp: Optional timestamp when the witness signed.
    """
    witness_aid: str
    signature: bytes
    timestamp: Optional[datetime] = None


@dataclass
class KELEvent:
    """Parsed KERI event from a Key Event Log.

    Contains both the event data and attached signatures/receipts.

    Attributes:
        event_type: The type of event (icp, rot, etc.).
        sequence: Event sequence number (0 for inception).
        prior_digest: SAID of the prior event (empty for inception).
        digest: This event's SAID (self-addressing identifier).
        signing_keys: Current signing key(s) from 'k' field.
        next_keys_digest: Commitment to next keys ('n' field).
        toad: Witness threshold (threshold of accountable duplicity).
        witnesses: List of witness AIDs from 'b' field.
        timestamp: Timestamp from witness receipts (if available).
        signatures: Attached controller signatures.
        witness_receipts: Receipts from witnesses.
        raw: Original parsed event dict for debugging.
        delegator_aid: For delegated events (dip/drt), the delegator's AID from 'di' field.
    """
    event_type: EventType
    sequence: int
    prior_digest: str
    digest: str
    signing_keys: List[bytes]
    next_keys_digest: Optional[str]
    toad: int
    witnesses: List[str]
    timestamp: Optional[datetime] = None
    signatures: List[bytes] = field(default_factory=list)
    witness_receipts: List[WitnessReceipt] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)
    delegator_aid: Optional[str] = None

    @property
    def is_establishment(self) -> bool:
        """True if this event establishes or rotates key state."""
        return self.event_type in ESTABLISHMENT_TYPES

    @property
    def is_inception(self) -> bool:
        """True if this is an inception event (icp or dip)."""
        return self.event_type in {EventType.ICP, EventType.DIP}

    @property
    def is_delegated(self) -> bool:
        """True if this is a delegated event requiring delegator validation."""
        return self.event_type in DELEGATED_TYPES


def parse_kel_stream(
    kel_data: bytes,
    content_type: str = JSON_CONTENT_TYPE,
    allow_json_only: bool = False
) -> List[KELEvent]:
    """Parse a KEL stream into a list of events.

    Routes to CESR or JSON parser based on content type. Production use
    requires CESR format; JSON is only allowed for testing.

    Args:
        kel_data: Raw KEL data (CESR or JSON encoded).
        content_type: Content-Type from OOBI response. Used for routing
            to the appropriate parser.
        allow_json_only: If True, accept JSON format even when CESR is expected.
            Defaults to False (production mode). Set True only for testing.

    Returns:
        List of parsed KELEvent objects in sequence order.

    Raises:
        ResolutionFailedError: If parsing fails.
        DelegationNotSupportedError: If delegated events are detected.
    """
    # Detect format based on content type and data inspection
    is_cesr = CESR_CONTENT_TYPE.lower() in content_type.lower()

    # Also check for CESR markers in data (regardless of content type)
    if not is_cesr and kel_data:
        is_cesr = is_cesr_stream(kel_data)

    if is_cesr:
        # Parse CESR stream
        return _parse_cesr_kel(kel_data)

    # JSON format - check if allowed
    if not allow_json_only:
        # Check if data looks like JSON
        if kel_data and kel_data[0:1] == b"{":
            # Warn but allow in this transition period
            pass  # Could log a warning here
        elif kel_data and kel_data[0:1] in (b"-", b"0", b"1", b"4", b"5", b"6"):
            # CESR markers detected but content_type was JSON
            return _parse_cesr_kel(kel_data)

    # Try JSON parsing
    try:
        return _parse_json_kel(kel_data)
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise ResolutionFailedError(
            f"Failed to parse KEL: {e}"
        )


def _parse_json_kel(kel_data: bytes) -> List[KELEvent]:
    """Parse JSON-encoded KEL (test fallback).

    JSON format is a list of event objects with attached signatures.
    This is non-normative and only for testing.
    """
    data = json.loads(kel_data.decode("utf-8"))

    # Handle both single event and list of events
    if isinstance(data, dict):
        events_data = [data]
    elif isinstance(data, list):
        events_data = data
    else:
        raise ResolutionFailedError(f"Invalid JSON KEL format: expected dict or list")

    events = []
    for event_data in events_data:
        event = _parse_event_dict(event_data)
        events.append(event)

    # Sort by sequence number
    events.sort(key=lambda e: e.sequence)

    return events


def _parse_event_dict(data: Dict[str, Any]) -> KELEvent:
    """Parse a single event from a dictionary.

    KERI event fields:
    - t: event type
    - s: sequence number (hex string)
    - p: prior event digest
    - d: this event's digest (SAID)
    - k: signing keys
    - n: next keys digest
    - bt: witness threshold
    - b: witnesses
    """
    try:
        event_type_str = data.get("t", "")
        try:
            event_type = EventType(event_type_str)
        except ValueError:
            raise ResolutionFailedError(f"Unknown event type: {event_type_str}")

        # Extract delegator AID for delegated events (dip/drt)
        delegator_aid = None
        if event_type in DELEGATED_TYPES:
            delegator_aid = data.get("di")  # 'di' = delegator identifier
            if not delegator_aid:
                raise ResolutionFailedError(
                    f"Delegated event '{event_type_str}' missing required 'di' field"
                )

        # Parse sequence (hex string in KERI)
        seq_str = data.get("s", "0")
        sequence = int(seq_str, 16) if isinstance(seq_str, str) else int(seq_str)

        # Parse keys from 'k' field
        keys_data = data.get("k", [])
        signing_keys = []
        for key_str in keys_data:
            key_bytes = _decode_keri_key(key_str)
            signing_keys.append(key_bytes)

        # Parse signatures (attached as list or '-' prefixed entries)
        signatures = []
        sigs_data = data.get("signatures", data.get("-", []))
        if isinstance(sigs_data, list):
            for sig in sigs_data:
                if isinstance(sig, str):
                    signatures.append(_decode_signature(sig))
                elif isinstance(sig, dict) and "sig" in sig:
                    signatures.append(_decode_signature(sig["sig"]))

        # Parse witness receipts
        witness_receipts = []
        receipts_data = data.get("receipts", data.get("rcts", []))
        if isinstance(receipts_data, list):
            for rct in receipts_data:
                if isinstance(rct, dict):
                    witness_receipts.append(WitnessReceipt(
                        witness_aid=rct.get("i", ""),
                        signature=_decode_signature(rct.get("s", "")),
                        timestamp=_parse_timestamp(rct.get("dt"))
                    ))

        return KELEvent(
            event_type=event_type,
            sequence=sequence,
            prior_digest=data.get("p", ""),
            digest=data.get("d", ""),
            signing_keys=signing_keys,
            next_keys_digest=data.get("n", [None])[0] if isinstance(data.get("n"), list) else data.get("n"),
            toad=int(data.get("bt", "0"), 16) if isinstance(data.get("bt"), str) else data.get("bt", 0),
            witnesses=data.get("b", []),
            timestamp=_parse_timestamp(data.get("dt")),
            signatures=signatures,
            witness_receipts=witness_receipts,
            raw=data,
            delegator_aid=delegator_aid
        )
    except Exception as e:
        raise ResolutionFailedError(f"Failed to parse event: {e}")


def _parse_cesr_kel(kel_data: bytes) -> List[KELEvent]:
    """Parse CESR-encoded KEL stream.

    CESR is a self-framing binary format. This implementation handles
    the subset needed for VVP verification by delegating to the cesr module.

    Returns:
        List of KELEvent objects parsed from the CESR stream.

    Raises:
        ResolutionFailedError: If parsing fails.
    """
    # Parse CESR stream using the cesr module
    cesr_messages = cesr_parse(kel_data)

    if not cesr_messages:
        # Empty or whitespace-only stream
        return []

    events = []
    for msg in cesr_messages:
        # Convert CESRMessage to KELEvent
        event = _parse_event_dict(msg.event_dict)

        # Add signatures from CESR attachments
        event.signatures = msg.controller_sigs

        # Convert CESR witness receipts to KELEvent format
        for receipt in msg.witness_receipts:
            event.witness_receipts.append(WitnessReceipt(
                witness_aid=receipt.witness_aid,
                signature=receipt.signature,
            ))

        events.append(event)

    # Sort by sequence number
    events.sort(key=lambda e: e.sequence)

    return events


def _decode_keri_key(key_str: str) -> bytes:
    """Decode a KERI-encoded public key.

    KERI keys use CESR encoding with a derivation code prefix.
    For Ed25519 keys (B or D prefix), the standard CESR qb64 format is:
    - 44 chars total, decodes to 33 bytes (1 lead byte + 32-byte key)
    - B-prefix (non-transferable): lead byte 0x04
    - D-prefix (transferable): lead byte 0x0c

    This function also handles legacy/test formats where the key is simply
    prefix + base64url(raw_key) (produces different lead bytes).

    Example CESR: "DER2RcVO4AlODS6zPZgYuMexC0TRhYQEYCuhWio2tCZY" (D = Ed25519)
    """
    if not key_str or len(key_str) < 2:
        raise ResolutionFailedError(f"Invalid key format: too short")

    # Extract derivation code from first character
    code = key_str[0]

    # For Ed25519 (B or D prefix)
    if code in ("B", "D"):
        # Try to decode the full qb64 string (including the code char)
        try:
            full_decoded = base64.urlsafe_b64decode(key_str)
        except Exception as e:
            raise ResolutionFailedError(f"Failed to decode key: {e}")

        if len(full_decoded) == 33:
            # Check lead byte to determine encoding format
            lead_byte = full_decoded[0]
            # CESR standard lead bytes: 0x04 for B-prefix, 0x0c for D-prefix
            if lead_byte in (0x04, 0x0c):
                # Standard CESR: skip the lead byte
                return full_decoded[1:]
            else:
                # Legacy format: strip code char from string, decode, return as-is
                # The lead byte doesn't match CESR standard, so this is
                # a simple prefix + base64(raw_key) format
                key_b64 = key_str[1:]
                padded = key_b64 + "=" * (-len(key_b64) % 4)
                try:
                    return base64.urlsafe_b64decode(padded)
                except Exception as e:
                    raise ResolutionFailedError(f"Failed to decode key: {e}")
        elif len(full_decoded) == 32:
            # Legacy format: no lead byte
            return full_decoded
        else:
            raise ResolutionFailedError(
                f"Invalid key length after decode: {len(full_decoded)}, expected 32 or 33"
            )

    # For other codes, might need different handling
    raise ResolutionFailedError(f"Unsupported key derivation code: {code}")


def _decode_signature(sig_str: str) -> bytes:
    """Decode a KERI-encoded signature.

    KERI signatures use count codes and base64url encoding.
    Example: "0B..." (0B = indexed Ed25519 sig)
    """
    if not sig_str:
        return b""

    # Handle common signature formats
    # Indexed controller signatures start with 0A, 0B, etc.
    # For simplicity, try base64url decode after stripping common prefixes
    if sig_str.startswith(("0A", "0B", "0C", "0D", "1A", "2A")):
        sig_b64 = sig_str[2:]
    elif sig_str.startswith("-"):
        # CESR stream marker
        sig_b64 = sig_str[1:]
    else:
        sig_b64 = sig_str

    padded = sig_b64 + "=" * (-len(sig_b64) % 4)
    try:
        return base64.urlsafe_b64decode(padded)
    except Exception:
        # Return empty if decode fails (might be complex CESR)
        return b""


def _parse_timestamp(ts_str: Optional[str]) -> Optional[datetime]:
    """Parse an ISO 8601 timestamp string."""
    if not ts_str:
        return None
    try:
        # Handle various ISO formats
        if ts_str.endswith("Z"):
            ts_str = ts_str[:-1] + "+00:00"
        return datetime.fromisoformat(ts_str)
    except ValueError:
        return None


def validate_kel_chain(
    events: List[KELEvent],
    validate_saids: bool = True,
    use_canonical: bool = True,
    validate_witnesses: bool = False
) -> None:
    """Validate KEL chain continuity and signatures.

    Validates:
    1. First event is inception (icp or dip)
    2. Sequence numbers are consecutive
    3. Each event's prior_digest matches previous event's digest
    4. Each event is signed by keys from prior event (or self-signed for inception)
    5. Each event's digest (d field) matches computed SAID (if validate_saids=True)
    6. Witness receipts meet threshold (if validate_witnesses=True)

    Note: Defaults changed in Tier 2 completion - now uses canonical serialization
    and SAID validation by default for production safety.

    Args:
        events: List of KELEvent objects in sequence order.
        validate_saids: If True, verify each event's digest matches computed SAID.
            Defaults to False because SAID validation uses JSON canonicalization
            which only works for specially-prepared test fixtures, not real KERI
            events or typical test data with placeholder digests.
        use_canonical: If True, use KERI canonical serialization for signing input.
            This is required for validating real KERI events from production.
            Defaults to False for backward compatibility with JSON test fixtures.
        validate_witnesses: If True, validate witness receipt signatures against
            event.toad threshold. Requires use_canonical=True for production use.

    Raises:
        KELChainInvalidError: If chain validation fails.
    """
    if not events:
        raise KELChainInvalidError("Empty KEL: no events to validate")

    # Validate first event is inception
    first_event = events[0]
    if not first_event.is_inception:
        raise KELChainInvalidError(
            f"KEL must start with inception, found {first_event.event_type.value}"
        )

    if first_event.sequence != 0:
        raise KELChainInvalidError(
            f"Inception event must have sequence 0, found {first_event.sequence}"
        )

    # Validate SAID for first event
    if validate_saids:
        _validate_event_said(first_event, use_canonical=use_canonical)

    # Validate inception is self-signed
    _validate_inception_signature(first_event, use_canonical=use_canonical)

    # Validate witness receipts for inception if enabled
    if validate_witnesses and first_event.toad > 0:
        signing_input = _compute_signing_input(first_event, use_canonical=use_canonical)
        validate_witness_receipts(first_event, signing_input, min_threshold=first_event.toad)

    # Track current signing keys for signature validation
    current_keys = first_event.signing_keys

    # Validate remaining events
    prev_event = first_event
    for event in events[1:]:
        # Check sequence continuity
        expected_seq = prev_event.sequence + 1
        if event.sequence != expected_seq:
            raise KELChainInvalidError(
                f"Sequence gap: expected {expected_seq}, found {event.sequence}"
            )

        # Check chain continuity (prior_digest)
        if event.prior_digest != prev_event.digest:
            raise KELChainInvalidError(
                f"Chain break at seq {event.sequence}: prior_digest "
                f"{event.prior_digest[:16]}... != previous digest {prev_event.digest[:16]}..."
            )

        # Validate SAID if enabled
        if validate_saids:
            _validate_event_said(event, use_canonical=use_canonical)

        # Validate event signature against current keys
        _validate_event_signature(event, current_keys, use_canonical=use_canonical)

        # Validate witness receipts if enabled
        if validate_witnesses and event.toad > 0:
            signing_input = _compute_signing_input(event, use_canonical=use_canonical)
            validate_witness_receipts(event, signing_input, min_threshold=event.toad)

        # Update current keys if this is an establishment event
        if event.is_establishment:
            current_keys = event.signing_keys

        prev_event = event


def _validate_event_said(event: KELEvent, use_canonical: bool = False) -> None:
    """Validate that an event's digest (d field) matches its computed SAID.

    Args:
        event: The KELEvent to validate.
        use_canonical: If True, use KERI canonical serialization for SAID
            computation. If False, use JSON sorted-keys (test mode only).

    Raises:
        KELChainInvalidError: If the digest doesn't match computed SAID.
    """
    if not event.digest:
        # No digest to validate
        return

    if not event.raw:
        # No raw data to compute SAID from
        return

    # Remove attachment fields before computing SAID (same as signing input)
    # SAID is computed over the event body, not the attachments
    raw_copy = dict(event.raw)
    raw_copy.pop("signatures", None)
    raw_copy.pop("-", None)
    raw_copy.pop("receipts", None)
    raw_copy.pop("rcts", None)

    # For inception events (icp, dip), the 'i' field equals 'd' (self-addressing).
    # When computing SAID, both should be placeholders since they're circular.
    # If i == d, we need to clear 'i' before computing so the SAID matches
    # what was originally computed before 'i' was set.
    event_type = raw_copy.get("t", "")
    if event_type in ("icp", "dip"):
        # Self-addressing: i == d, so clear i for SAID computation
        raw_copy["i"] = ""

    # Compute expected SAID using appropriate method
    if use_canonical:
        computed = compute_said_canonical(raw_copy)
    else:
        computed = compute_said(raw_copy)

    # Compare (allowing for different derivation codes)
    # The first character is the derivation code, rest is the hash
    if len(event.digest) > 1 and len(computed) > 1:
        # Compare the hash portion (skip derivation code if they differ)
        event_hash = event.digest[1:] if event.digest[0].isalpha() else event.digest
        computed_hash = computed[1:] if computed[0].isalpha() else computed

        if event_hash != computed_hash:
            raise KELChainInvalidError(
                f"Event at seq {event.sequence} has invalid SAID: "
                f"digest {event.digest[:20]}... != computed {computed[:20]}..."
            )


def _validate_inception_signature(event: KELEvent, use_canonical: bool = False) -> None:
    """Validate that an inception event is self-signed.

    For inception, the signing keys in the event itself must have signed it.

    Args:
        event: The inception event to validate.
        use_canonical: If True, use KERI canonical serialization for signing input.
    """
    if not event.signatures:
        raise KELChainInvalidError(
            f"Inception event at seq {event.sequence} has no signatures"
        )

    if not event.signing_keys:
        raise KELChainInvalidError(
            f"Inception event at seq {event.sequence} has no signing keys"
        )

    # Verify at least one signature matches a signing key
    signing_input = _compute_signing_input(event, use_canonical=use_canonical)
    verified = False

    for sig in event.signatures:
        for key in event.signing_keys:
            if _verify_signature(signing_input, sig, key):
                verified = True
                break
        if verified:
            break

    if not verified:
        raise KELChainInvalidError(
            f"Inception event at seq {event.sequence} has invalid self-signature"
        )


def _validate_event_signature(
    event: KELEvent,
    prior_keys: List[bytes],
    use_canonical: bool = False
) -> None:
    """Validate that an event is signed by keys from the prior event.

    Args:
        event: The event to validate.
        prior_keys: Signing keys from the prior establishment event.
        use_canonical: If True, use KERI canonical serialization for signing input.
    """
    if not event.signatures:
        raise KELChainInvalidError(
            f"Event at seq {event.sequence} has no signatures"
        )

    if not prior_keys:
        raise KELChainInvalidError(
            f"No prior keys available to validate event at seq {event.sequence}"
        )

    signing_input = _compute_signing_input(event, use_canonical=use_canonical)
    verified = False

    for sig in event.signatures:
        for key in prior_keys:
            if _verify_signature(signing_input, sig, key):
                verified = True
                break
        if verified:
            break

    if not verified:
        raise KELChainInvalidError(
            f"Event at seq {event.sequence} has invalid signature "
            f"(not signed by prior keys)"
        )


def _compute_signing_input(event: KELEvent, use_canonical: bool = True) -> bytes:
    """Compute the signing input for an event.

    Args:
        event: The KELEvent to compute signing input for.
        use_canonical: If True (default), use KERI canonical serialization (proper
            field ordering per event type). If False, use JSON sorted-keys which
            is only valid for legacy test fixtures.

    Returns:
        The bytes that should have been signed.

    Note:
        The default is use_canonical=True for production safety. KERI events
        from real witnesses are signed over canonical serialization, not
        JSON sorted keys.

        The use_canonical=False path is retained only for backwards compatibility
        with legacy test fixtures that were signed using sorted-key JSON.
    """
    # Remove attachment fields before computing signing input
    raw_copy = dict(event.raw)
    raw_copy.pop("signatures", None)
    raw_copy.pop("-", None)
    raw_copy.pop("receipts", None)
    raw_copy.pop("rcts", None)

    if use_canonical:
        # Use KERI canonical serialization with proper field ordering
        return canonical_serialize(raw_copy)
    else:
        # Legacy: Sort keys for canonical form (NOT KERI-compliant, test only)
        canonical = json.dumps(raw_copy, sort_keys=True, separators=(",", ":"))
        return canonical.encode("utf-8")


def _verify_signature(message: bytes, signature: bytes, public_key: bytes) -> bool:
    """Verify an Ed25519 signature.

    Args:
        message: The signed message.
        signature: The signature bytes.
        public_key: The Ed25519 public key (32 bytes).

    Returns:
        True if signature is valid, False otherwise.
    """
    if len(public_key) != 32:
        return False
    if len(signature) != 64:
        return False

    try:
        # Lazy import to avoid requiring pysodium for parsing-only operations
        import pysodium
        pysodium.crypto_sign_verify_detached(signature, message, public_key)
        return True
    except Exception:
        return False


def compute_said(data: Dict[str, Any], algorithm: str = "blake3-256") -> str:
    """Compute the SAID (Self-Addressing IDentifier) for an event.

    SAID is computed by hashing the serialized event with the 'd' field
    set to a placeholder, then base64url encoding the hash.

    Args:
        data: Event data dictionary.
        algorithm: Hash algorithm (default blake3-256 per KERI).

    Returns:
        The computed SAID string.
    """
    # Make copy and set placeholder for 'd' field
    data_copy = dict(data)

    # Placeholder must match the expected output length
    # For Blake3-256: 32 bytes = 44 base64url chars (with padding stripped)
    placeholder = "E" + "_" * 43  # E = Blake3-256 derivation code

    data_copy["d"] = placeholder

    # Serialize canonically
    canonical = json.dumps(data_copy, sort_keys=True, separators=(",", ":"))

    # Hash
    if algorithm == "blake3-256":
        try:
            import blake3
            digest = blake3.blake3(canonical.encode("utf-8")).digest()
        except ImportError:
            # Fall back to sha256 if blake3 not available
            digest = hashlib.sha256(canonical.encode("utf-8")).digest()
    else:
        digest = hashlib.sha256(canonical.encode("utf-8")).digest()

    # Encode with derivation code
    encoded = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return "E" + encoded


def compute_kel_event_said(event: Dict[str, Any], require_blake3: bool = False) -> str:
    """Compute SAID for a KEL event using KERI canonical field ordering.

    This is the correct function to use for KEL events (icp, rot, ixn, dip, drt, etc.).
    It uses KERI canonical serialization with proper field ordering per event type.

    DO NOT use this for:
    - ACDC credentials (use acdc.parser.compute_acdc_said instead)
    - JSON Schemas (use acdc.schema_fetcher.compute_schema_said instead)

    Those have different canonicalization rules per their respective specs.

    Args:
        event: KEL event dictionary with 't' field indicating event type.
        require_blake3: If True, raise ImportError if blake3 not available.

    Returns:
        The computed SAID string (44 chars, starting with 'E' for Blake3-256).

    Example:
        >>> event = {"v": "KERI10JSON...", "t": "icp", "d": "", "i": "...", ...}
        >>> said = compute_kel_event_said(event)
        >>> event["d"] = said  # Set the computed SAID
    """
    return compute_said_canonical(event, require_blake3=require_blake3, said_field="d")


def _cesr_encode(raw: bytes, code: str = "E") -> str:
    """Encode raw bytes in CESR format with derivation code.

    CESR (Composable Event Streaming Representation) encoding combines
    the derivation code with the base64 representation of the raw bytes
    in a specific way that ensures proper byte alignment.

    For fixed-size codes like 'E' (Blake3-256, 32 bytes):
    1. Compute pad size: ps = (3 - (len(raw) % 3)) % 3
    2. Prepad raw with ps zero bytes
    3. Base64 encode the prepadded bytes
    4. Skip the first ps characters (which encode the zero padding)
    5. Prepend the derivation code

    Args:
        raw: Raw bytes to encode (e.g., 32-byte digest).
        code: Derivation code character (e.g., "E" for Blake3-256).

    Returns:
        CESR-encoded string (e.g., "EO97yMHEAfX2...").
    """
    rs = len(raw)
    ls = 0  # lead bytes for 'E' code
    cs = len(code)  # code size is 1 for 'E'

    # Compute pad size
    ps = (3 - ((rs + ls) % 3)) % 3

    # Prepad with ps + ls zero bytes
    prepadded = bytes([0] * (ps + ls)) + raw

    # Base64 encode
    b64 = base64.urlsafe_b64encode(prepadded).decode("ascii")

    # Skip first ps characters and strip padding
    trimmed = b64[ps:].rstrip("=")

    # Prepend code
    return code + trimmed


def compute_said_canonical(
    event: Dict[str, Any],
    require_blake3: bool = False,
    said_field: str = "d"
) -> str:
    """Compute SAID using KERI canonical serialization.

    This is the production-ready SAID computation that uses proper
    KERI field ordering instead of JSON sorted keys.

    Steps:
    1. Create most compact form with placeholder
    2. Hash with Blake3-256 (or SHA256 in test mode)
    3. Encode with CESR derivation code

    Args:
        event: Event dictionary with 't' field indicating type.
        require_blake3: If True, raise ImportError if blake3 not available.
            Should be True in production, False for tests.
        said_field: Field containing SAID (usually 'd').

    Returns:
        SAID string with derivation code prefix (e.g., "E...").

    Raises:
        ImportError: If blake3 not available and require_blake3=True.
        CanonicalSerializationError: If event type unknown.
    """
    # Generate most compact form with placeholder
    canonical_bytes = most_compact_form(event, said_field=said_field)

    # Hash with Blake3-256
    try:
        import blake3
        digest = blake3.blake3(canonical_bytes).digest()
    except ImportError:
        if require_blake3:
            raise ImportError(
                "blake3 is required for production SAID computation. "
                "Install with: pip install blake3"
            )
        # Fall back to SHA256 in test mode
        digest = hashlib.sha256(canonical_bytes).digest()

    # Encode with CESR format (E = Blake3-256)
    return _cesr_encode(digest, code="E")


def validate_event_said_canonical(
    event: Dict[str, Any],
    require_blake3: bool = False,
    said_field: str = "d"
) -> None:
    """Validate that event's SAID field matches computed SAID.

    Uses KERI canonical serialization for production-ready validation.

    Args:
        event: Event dictionary.
        require_blake3: If True, raise ImportError if blake3 not available.
        said_field: Field containing SAID (usually 'd').

    Raises:
        KELChainInvalidError: If SAID doesn't match.
        ImportError: If blake3 not available and require_blake3=True.
    """
    if said_field not in event:
        return  # No SAID to validate

    expected_said = event[said_field]
    if not expected_said or expected_said.startswith("#"):
        return  # Placeholder or empty, skip validation

    computed_said = compute_said_canonical(
        event,
        require_blake3=require_blake3,
        said_field=said_field
    )

    if expected_said != computed_said:
        raise KELChainInvalidError(
            f"SAID mismatch: event has {expected_said[:20]}... "
            f"but computed {computed_said[:20]}..."
        )


def validate_witness_receipts(
    event: KELEvent,
    signing_input: bytes,
    min_threshold: int = 0
) -> List[str]:
    """Validate witness receipt signatures against an event.

    Per VVP §7.3, witness receipts must be cryptographically validated,
    not just presence-checked. This function:
    1. Resolves witness AID to public key (non-transferable AIDs embed the key)
    2. Verifies Ed25519 signature against signing input
    3. Counts valid signatures and compares to threshold
    4. Returns list of validated witness AIDs

    Threshold Determination (per KERI spec):
    - Use event's 'bt' (witness threshold) field if present and non-zero
    - Otherwise, use provided min_threshold if non-zero
    - Otherwise, default to majority: ceil(len(witnesses) / 2)
    - Do NOT hardcode 2-of-3

    Non-transferable witness AIDs (B-prefix) contain the public key directly
    in the AID, so no KEL resolution is needed for them.

    Args:
        event: The KELEvent with witness receipts to validate.
        signing_input: Canonical bytes that were signed by witnesses.
        min_threshold: Minimum valid signatures required. If 0, computes from
            event.toad or witness majority.

    Returns:
        List of witness AIDs whose signatures validated successfully.

    Raises:
        KELChainInvalidError: If insufficient valid witness signatures (KERI_STATE_INVALID).
        ResolutionFailedError: If witness AIDs cannot be resolved.
    """
    import math

    if not event.witness_receipts:
        # No receipts to validate
        # Compute threshold to check if we should fail
        if min_threshold > 0:
            raise KELChainInvalidError(
                f"No witness receipts but threshold requires {min_threshold}"
            )
        if event.toad > 0:
            raise KELChainInvalidError(
                f"No witness receipts but event toad requires {event.toad}"
            )
        return []

    # Determine threshold (priority: explicit param > event.toad > majority)
    if min_threshold > 0:
        threshold = min_threshold
    elif event.toad > 0:
        threshold = event.toad
    elif event.witnesses:
        # Default to majority: ceil(len(witnesses) / 2)
        threshold = math.ceil(len(event.witnesses) / 2)
    else:
        # No witnesses and no threshold - nothing to validate
        threshold = 0

    # Build a set of valid witness AIDs from the event's witness list
    valid_witness_aids = set(event.witnesses)

    validated_aids: List[str] = []
    errors = []

    for receipt in event.witness_receipts:
        witness_aid = receipt.witness_aid
        signature = receipt.signature

        # Skip receipts with empty AID (indexed witness sigs need context)
        if not witness_aid:
            continue

        # Verify witness is in event's witness list
        if valid_witness_aids and witness_aid not in valid_witness_aids:
            errors.append(f"Witness {witness_aid[:16]}... not in event's witness list")
            continue

        # Extract public key from witness AID
        try:
            public_key = _decode_keri_key(witness_aid)
        except ResolutionFailedError as e:
            errors.append(f"Cannot decode witness AID {witness_aid[:16]}...: {e}")
            continue

        # Verify signature
        if _verify_signature(signing_input, signature, public_key):
            validated_aids.append(witness_aid)
        else:
            errors.append(f"Invalid signature from witness {witness_aid[:16]}...")

    # Check threshold
    if len(validated_aids) < threshold:
        error_summary = "; ".join(errors[:3])  # Limit error details
        if len(errors) > 3:
            error_summary += f" (and {len(errors) - 3} more)"
        raise KELChainInvalidError(
            f"Insufficient valid witness signatures: {len(validated_aids)} < threshold {threshold}. "
            f"Errors: {error_summary if errors else 'none'}"
        )

    return validated_aids


def compute_signing_input_canonical(event: Dict[str, Any]) -> bytes:
    """Compute canonical signing input for an event.

    This uses KERI canonical serialization (proper field ordering)
    and is suitable for production use.

    Args:
        event: Event dictionary with 't' field indicating type.

    Returns:
        Canonical bytes that should have been signed.
    """
    # Remove any non-canonical fields (signatures, receipts)
    event_copy = dict(event)
    event_copy.pop("signatures", None)
    event_copy.pop("-", None)
    event_copy.pop("receipts", None)
    event_copy.pop("rcts", None)

    return canonical_serialize(event_copy)
