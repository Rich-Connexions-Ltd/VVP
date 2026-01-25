"""Tests for KERI key state resolver.

Tests key state resolution at reference time T per PLAN.md:
- Find key at time T (no rotations)
- Find key at time T (with rotation before T - returns rotated key)
- Find key at time T (with rotation after T - returns pre-rotation key)
- Handle reference time before inception (error)
"""

import base64
import json
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, patch
import pytest
import pysodium

from app.vvp.keri.kel_resolver import (
    KeyState,
    resolve_key_state,
    resolve_key_state_tier1_fallback,
    _extract_aid,
    _find_key_state_at_time,
    reset_cache,
)
from app.vvp.keri.kel_parser import EventType, KELEvent, WitnessReceipt
from app.vvp.keri.oobi import OOBIResult
from app.vvp.keri.exceptions import (
    KeyNotYetValidError,
    ResolutionFailedError,
)


def generate_keypair():
    """Generate a test Ed25519 keypair."""
    pk, sk = pysodium.crypto_sign_keypair()
    return pk, sk


def encode_keri_key(pk: bytes) -> str:
    """Encode a public key in KERI format."""
    return "B" + base64.urlsafe_b64encode(pk).decode().rstrip("=")


def make_kel_event(
    event_type: EventType,
    seq: int,
    signing_key: bytes,
    digest: str = None,
    prior_digest: str = "",
    timestamp: datetime = None,
    witnesses: list = None,
    toad: int = 0,
) -> KELEvent:
    """Create a test KELEvent."""
    if digest is None:
        digest = f"ESAID_{seq}"

    return KELEvent(
        event_type=event_type,
        sequence=seq,
        prior_digest=prior_digest,
        digest=digest,
        signing_keys=[signing_key],
        next_keys_digest="NEXT",
        toad=toad,
        witnesses=witnesses or [],
        timestamp=timestamp,
        signatures=[b"sig" * 21],
        witness_receipts=[],
        raw={},
    )


@pytest.fixture(autouse=True)
def clear_cache():
    """Reset the global cache before each test."""
    reset_cache()
    yield
    reset_cache()


class TestExtractAID:
    """Test AID extraction from kid values."""

    def test_extract_bare_aid(self):
        """Extract AID from bare AID string."""
        aid = "BIKKvIT9N5Qg5N8H9A9V5T5DWDQ"
        assert _extract_aid(aid) == aid

    def test_extract_aid_from_oobi_url(self):
        """Extract AID from OOBI URL."""
        url = "http://witness.example.com/oobi/BIKKvIT9N5Qg5N8H9A9V5T5DWDQ/witness/BXYZ"
        assert _extract_aid(url) == "BIKKvIT9N5Qg5N8H9A9V5T5DWDQ"

    def test_extract_aid_invalid_format(self):
        """Reject invalid kid format."""
        with pytest.raises(ResolutionFailedError, match="Invalid kid format"):
            _extract_aid("invalid")

    def test_extract_aid_empty(self):
        """Reject empty kid."""
        with pytest.raises(ResolutionFailedError, match="Invalid kid format"):
            _extract_aid("")


class TestFindKeyStateAtTime:
    """Test finding key state at reference time T."""

    def test_find_key_no_rotations(self):
        """Find key at T with no rotations."""
        pk, _ = generate_keypair()
        inception_time = datetime(2024, 1, 1, 12, 0, 0)
        reference_time = datetime(2024, 1, 15, 12, 0, 0)

        events = [
            make_kel_event(EventType.ICP, 0, pk, timestamp=inception_time),
        ]

        key_state = _find_key_state_at_time(
            aid="BAID",
            events=events,
            reference_time=reference_time,
            min_witnesses=0
        )

        assert key_state.signing_keys == [pk]
        assert key_state.sequence == 0

    def test_find_key_rotation_before_t(self):
        """Find key at T with rotation BEFORE T - returns rotated key."""
        pk1, _ = generate_keypair()
        pk2, _ = generate_keypair()

        inception_time = datetime(2024, 1, 1)
        rotation_time = datetime(2024, 1, 10)  # Before reference
        reference_time = datetime(2024, 1, 15)

        events = [
            make_kel_event(EventType.ICP, 0, pk1, digest="D0", timestamp=inception_time),
            make_kel_event(EventType.ROT, 1, pk2, digest="D1", prior_digest="D0",
                          timestamp=rotation_time),
        ]

        key_state = _find_key_state_at_time(
            aid="BAID",
            events=events,
            reference_time=reference_time,
            min_witnesses=0
        )

        # Should return the ROTATED key (pk2)
        assert key_state.signing_keys == [pk2]
        assert key_state.sequence == 1

    def test_find_key_rotation_after_t(self):
        """Find key at T with rotation AFTER T - returns pre-rotation key."""
        pk1, _ = generate_keypair()
        pk2, _ = generate_keypair()

        inception_time = datetime(2024, 1, 1)
        reference_time = datetime(2024, 1, 15)
        rotation_time = datetime(2024, 1, 20)  # After reference

        events = [
            make_kel_event(EventType.ICP, 0, pk1, digest="D0", timestamp=inception_time),
            make_kel_event(EventType.ROT, 1, pk2, digest="D1", prior_digest="D0",
                          timestamp=rotation_time),
        ]

        key_state = _find_key_state_at_time(
            aid="BAID",
            events=events,
            reference_time=reference_time,
            min_witnesses=0
        )

        # Should return the PRE-ROTATION key (pk1)
        assert key_state.signing_keys == [pk1]
        assert key_state.sequence == 0

    def test_find_key_multiple_rotations(self):
        """Find key at T with multiple rotations."""
        pk1, _ = generate_keypair()
        pk2, _ = generate_keypair()
        pk3, _ = generate_keypair()

        inception_time = datetime(2024, 1, 1)
        rot1_time = datetime(2024, 1, 10)
        rot2_time = datetime(2024, 1, 20)
        reference_time = datetime(2024, 1, 15)  # Between rot1 and rot2

        events = [
            make_kel_event(EventType.ICP, 0, pk1, digest="D0", timestamp=inception_time),
            make_kel_event(EventType.ROT, 1, pk2, digest="D1", prior_digest="D0",
                          timestamp=rot1_time),
            make_kel_event(EventType.ROT, 2, pk3, digest="D2", prior_digest="D1",
                          timestamp=rot2_time),
        ]

        key_state = _find_key_state_at_time(
            aid="BAID",
            events=events,
            reference_time=reference_time,
            min_witnesses=0
        )

        # Should return pk2 (after rot1, before rot2)
        assert key_state.signing_keys == [pk2]
        assert key_state.sequence == 1

    def test_reference_time_before_inception_raises(self):
        """Reference time before inception raises KeyNotYetValidError."""
        pk, _ = generate_keypair()
        inception_time = datetime(2024, 1, 10)
        reference_time = datetime(2024, 1, 1)  # Before inception

        events = [
            make_kel_event(EventType.ICP, 0, pk, timestamp=inception_time),
        ]

        with pytest.raises(KeyNotYetValidError, match="before inception"):
            _find_key_state_at_time(
                aid="BAID",
                events=events,
                reference_time=reference_time,
                min_witnesses=0
            )

    def test_events_without_timestamps_raises_indeterminate(self):
        """Rotations without timestamps raise ResolutionFailedError."""
        pk1, _ = generate_keypair()
        pk2, _ = generate_keypair()

        events = [
            make_kel_event(EventType.ICP, 0, pk1, digest="D0", timestamp=None),
            make_kel_event(EventType.ROT, 1, pk2, digest="D1", prior_digest="D0",
                          timestamp=None),
        ]

        # With no timestamps on rotations, we cannot determine if the rotation
        # was before or after reference_time. This should raise INDETERMINATE.
        with pytest.raises(ResolutionFailedError, match="without timestamps"):
            _find_key_state_at_time(
                aid="BAID",
                events=events,
                reference_time=datetime(2024, 1, 15),
                min_witnesses=0
            )

    def test_inception_only_without_timestamp_succeeds(self):
        """Inception-only KEL without timestamps still works."""
        pk1, _ = generate_keypair()

        events = [
            make_kel_event(EventType.ICP, 0, pk1, digest="D0", timestamp=None),
        ]

        # Inception without timestamp is allowed (no rotations to be uncertain about)
        key_state = _find_key_state_at_time(
            aid="BAID",
            events=events,
            reference_time=datetime(2024, 1, 15),
            min_witnesses=0
        )

        assert key_state.signing_keys == [pk1]

    def test_witness_receipt_timestamp_used(self):
        """Event time can come from witness receipts."""
        pk1, _ = generate_keypair()
        pk2, _ = generate_keypair()

        inception_time = datetime(2024, 1, 1)
        rotation_time = datetime(2024, 1, 20)  # After reference
        reference_time = datetime(2024, 1, 15)

        icp_event = make_kel_event(EventType.ICP, 0, pk1, digest="D0", timestamp=None)
        icp_event.witness_receipts = [
            WitnessReceipt(witness_aid="W1", signature=b"sig", timestamp=inception_time)
        ]

        rot_event = make_kel_event(EventType.ROT, 1, pk2, digest="D1",
                                   prior_digest="D0", timestamp=None)
        rot_event.witness_receipts = [
            WitnessReceipt(witness_aid="W1", signature=b"sig", timestamp=rotation_time)
        ]

        events = [icp_event, rot_event]

        key_state = _find_key_state_at_time(
            aid="BAID",
            events=events,
            reference_time=reference_time,
            min_witnesses=0
        )

        # Rotation is after reference time, should return inception key
        assert key_state.signing_keys == [pk1]


class TestWitnessValidation:
    """Test witness receipt validation."""

    def test_insufficient_witnesses_raises(self):
        """Insufficient witness receipts raises error in strict mode."""
        pk, _ = generate_keypair()

        events = [
            make_kel_event(EventType.ICP, 0, pk, toad=2),  # Requires 2 witnesses
        ]

        # In strict_validation mode, missing receipts raises ResolutionFailedError
        with pytest.raises(ResolutionFailedError, match="No witness receipts"):
            _find_key_state_at_time(
                aid="BAID",
                events=events,
                reference_time=datetime(2024, 1, 15),
                min_witnesses=None,  # Will use toad=2
                strict_validation=True  # Strict mode validates witness receipts
            )

    def test_sufficient_witnesses_passes(self):
        """Sufficient witness receipts passes validation."""
        pk, _ = generate_keypair()

        event = make_kel_event(EventType.ICP, 0, pk, toad=1)
        event.witness_receipts = [
            WitnessReceipt(witness_aid="W1", signature=b"sig", timestamp=None)
        ]

        events = [event]

        # Should not raise
        key_state = _find_key_state_at_time(
            aid="BAID",
            events=events,
            reference_time=datetime(2024, 1, 15),
            min_witnesses=None
        )

        assert key_state is not None

    def test_min_witnesses_override(self):
        """min_witnesses parameter overrides toad."""
        pk, _ = generate_keypair()

        event = make_kel_event(EventType.ICP, 0, pk, toad=5)  # High toad
        event.witness_receipts = [
            WitnessReceipt(witness_aid="W1", signature=b"sig", timestamp=None)
        ]

        events = [event]

        # Override with min_witnesses=1
        key_state = _find_key_state_at_time(
            aid="BAID",
            events=events,
            reference_time=datetime(2024, 1, 15),
            min_witnesses=1
        )

        assert key_state is not None


class TestResolveKeyState:
    """Test the main resolve_key_state function."""

    @pytest.mark.asyncio
    async def test_resolve_with_mock_oobi(self):
        """Resolve key state with mocked OOBI fetch."""
        pk, _ = generate_keypair()
        key_str = encode_keri_key(pk)

        # Create mock KEL response
        kel_json = json.dumps([{
            "t": "icp",
            "s": "0",
            "d": "ESAID_0",
            "p": "",
            "k": [key_str],
            "n": ["NEXT"],
            "bt": "0",
            "b": [],
            "signatures": ["0B" + "A" * 86],
        }])

        mock_oobi_result = OOBIResult(
            aid="BAID",
            kel_data=kel_json.encode(),
            witnesses=[]
        )

        with patch(
            "app.vvp.keri.kel_resolver.dereference_oobi",
            new_callable=AsyncMock,
            return_value=mock_oobi_result
        ):
            with patch(
                "app.vvp.keri.kel_resolver.validate_kel_chain"
            ):  # Skip chain validation for this test
                key_state = await resolve_key_state(
                    kid="http://example.com/oobi/BAID",
                    reference_time=datetime(2024, 1, 15),
                    min_witnesses=0,
                    _allow_test_mode=True
                )

        assert key_state.aid == "BAID"
        assert len(key_state.signing_keys) == 1

    @pytest.mark.asyncio
    async def test_resolve_bare_aid_without_oobi_raises(self):
        """Resolving bare AID without OOBI URL raises error."""
        with pytest.raises(ResolutionFailedError, match="OOBI URL required"):
            await resolve_key_state(
                kid="BAID_WITHOUT_OOBI",
                reference_time=datetime(2024, 1, 15),
                _allow_test_mode=True
            )


class TestTier1Fallback:
    """Test Tier 1 fallback resolution."""

    @pytest.mark.asyncio
    async def test_tier1_fallback_extracts_key(self):
        """Tier 1 fallback extracts key from AID."""
        pk, _ = generate_keypair()
        kid = encode_keri_key(pk)

        key_state = await resolve_key_state_tier1_fallback(kid)

        assert key_state.aid == kid
        assert key_state.signing_keys == [pk]
        assert key_state.sequence == 0
        assert key_state.establishment_digest == ""  # Unknown without KEL

    @pytest.mark.asyncio
    async def test_tier1_fallback_invalid_kid(self):
        """Tier 1 fallback rejects invalid kid."""
        with pytest.raises(ResolutionFailedError):
            await resolve_key_state_tier1_fallback("invalid")


class TestKeyStateDataclass:
    """Test KeyState dataclass."""

    def test_key_state_creation(self):
        """Create KeyState with all fields."""
        pk, _ = generate_keypair()
        ts = datetime(2024, 1, 1)

        ks = KeyState(
            aid="BAID",
            signing_keys=[pk],
            sequence=0,
            establishment_digest="ESAID",
            valid_from=ts,
            witnesses=["W1", "W2"],
            toad=1,
        )

        assert ks.aid == "BAID"
        assert ks.signing_keys == [pk]
        assert ks.sequence == 0
        assert ks.establishment_digest == "ESAID"
        assert ks.valid_from == ts
        assert len(ks.witnesses) == 2
        assert ks.toad == 1
