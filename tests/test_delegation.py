"""Tests for multi-level KERI delegation validation.

Tests for VVP §7.15: Delegation validation (dip, drt events).
"""

import base64
import json
import pytest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pysodium

from app.vvp.keri.delegation import (
    MAX_DELEGATION_DEPTH,
    DelegationChain,
    resolve_delegation_chain,
    validate_delegation_authorization,
    _find_key_state_at_sequence,
    _verify_event_signature,
)
from app.vvp.keri.kel_parser import EventType, KELEvent, WitnessReceipt
from app.vvp.keri.exceptions import KELChainInvalidError, ResolutionFailedError
from app.vvp.api_models import ClaimStatus


def generate_keypair():
    """Generate a test Ed25519 keypair."""
    pk, sk = pysodium.crypto_sign_keypair()
    return pk, sk


def encode_keri_key(pk: bytes) -> str:
    """Encode Ed25519 public key in KERI format."""
    return "B" + base64.urlsafe_b64encode(pk).decode().rstrip("=")


def create_kel_event(
    event_type: EventType,
    sequence: int,
    signing_keys: list,
    delegator_aid: str = None,
    prior_digest: str = "",
    digest: str = None,
    signatures: list = None,
    raw: dict = None,
) -> KELEvent:
    """Create a KELEvent for testing."""
    if digest is None:
        digest = f"ESAID_{sequence}"
    if raw is None:
        raw = {"t": event_type.value, "s": str(sequence), "d": digest}
        if delegator_aid:
            raw["di"] = delegator_aid
    return KELEvent(
        event_type=event_type,
        sequence=sequence,
        prior_digest=prior_digest,
        digest=digest,
        signing_keys=signing_keys,
        next_keys_digest=None,
        toad=0,
        witnesses=[],
        timestamp=datetime.now(timezone.utc),
        signatures=signatures or [],
        witness_receipts=[],
        raw=raw,
        delegator_aid=delegator_aid,
    )


class TestDelegationChainDataclass:
    """Tests for DelegationChain dataclass."""

    def test_empty_chain(self):
        """Empty delegation chain has correct defaults."""
        chain = DelegationChain()
        assert chain.delegates == []
        assert chain.root_aid is None
        assert chain.valid is False
        assert chain.errors == []

    def test_populated_chain(self):
        """Populated delegation chain stores values correctly."""
        chain = DelegationChain(
            delegates=["AID_C", "AID_B", "AID_A"],
            root_aid="AID_A",
            valid=True,
            errors=[],
        )
        assert len(chain.delegates) == 3
        assert chain.root_aid == "AID_A"
        assert chain.valid is True


class TestResolveDelegationChain:
    """Tests for resolve_delegation_chain."""

    @pytest.mark.asyncio
    async def test_single_level_delegation(self):
        """Single-level delegation resolves to non-delegated root."""
        pk, sk = generate_keypair()
        delegated_aid = encode_keri_key(pk)
        delegator_aid = "ERoot00000000000000000000000000000000000"

        inception_event = create_kel_event(
            event_type=EventType.DIP,
            sequence=0,
            signing_keys=[pk],
            delegator_aid=delegator_aid,
        )

        # Mock the OOBI resolver to return non-delegated key state
        mock_key_state = MagicMock()
        mock_key_state.is_delegated = False
        mock_oobi_resolver = AsyncMock(return_value=mock_key_state)

        chain = await resolve_delegation_chain(
            delegated_aid=delegated_aid,
            inception_event=inception_event,
            reference_time=datetime.now(timezone.utc),
            oobi_resolver=mock_oobi_resolver,
        )

        assert chain.valid is True
        assert chain.root_aid == delegator_aid
        assert len(chain.delegates) == 2
        assert chain.delegates[0] == delegated_aid
        assert chain.delegates[1] == delegator_aid

    @pytest.mark.asyncio
    async def test_multi_level_delegation(self):
        """Multi-level delegation (A -> B -> C) resolves correctly."""
        pk_c, _ = generate_keypair()
        pk_b, _ = generate_keypair()

        delegated_c = encode_keri_key(pk_c)
        delegator_b = encode_keri_key(pk_b)
        root_a = "ERoot00000000000000000000000000000000000"

        # C's inception event (delegated by B)
        inception_c = create_kel_event(
            event_type=EventType.DIP,
            sequence=0,
            signing_keys=[pk_c],
            delegator_aid=delegator_b,
        )

        # B's inception event (delegated by A)
        inception_b = create_kel_event(
            event_type=EventType.DIP,
            sequence=0,
            signing_keys=[pk_b],
            delegator_aid=root_a,
        )

        # Mock key states
        key_state_b = MagicMock()
        key_state_b.is_delegated = True
        key_state_b.inception_event = inception_b

        key_state_a = MagicMock()
        key_state_a.is_delegated = False

        call_count = 0
        async def mock_resolver(aid, time):
            nonlocal call_count
            call_count += 1
            if aid == delegator_b:
                return key_state_b
            elif aid == root_a:
                return key_state_a
            raise ResolutionFailedError(f"Unknown AID: {aid}")

        chain = await resolve_delegation_chain(
            delegated_aid=delegated_c,
            inception_event=inception_c,
            reference_time=datetime.now(timezone.utc),
            oobi_resolver=mock_resolver,
        )

        assert chain.valid is True
        assert chain.root_aid == root_a
        assert len(chain.delegates) == 3
        assert chain.delegates == [delegated_c, delegator_b, root_a]

    @pytest.mark.asyncio
    async def test_delegation_depth_limit(self):
        """Chain exceeding max depth raises KELChainInvalidError."""
        pk, _ = generate_keypair()
        delegated_aid = encode_keri_key(pk)

        # Create an inception event
        initial_inception = create_kel_event(
            event_type=EventType.DIP,
            sequence=0,
            signing_keys=[pk],
            delegator_aid="EDelegator_0_0000000000000000000000000",
        )

        call_count = 0

        # Mock resolver that creates a new unique delegator at each level
        async def deep_delegation_resolver(aid, time):
            nonlocal call_count
            call_count += 1
            # Create a new key state with a unique delegator at each level
            mock_key_state = MagicMock()
            mock_key_state.is_delegated = True
            # Each delegator delegates to the next level
            next_delegator = f"EDelegator_{call_count}_000000000000000000000"
            mock_key_state.inception_event = create_kel_event(
                event_type=EventType.DIP,
                sequence=0,
                signing_keys=[pk],
                delegator_aid=next_delegator,
            )
            return mock_key_state

        with pytest.raises(KELChainInvalidError) as exc_info:
            await resolve_delegation_chain(
                delegated_aid=delegated_aid,
                inception_event=initial_inception,
                reference_time=datetime.now(timezone.utc),
                oobi_resolver=deep_delegation_resolver,
            )
        assert "max depth" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_circular_delegation_detected(self):
        """Circular delegation (A -> B -> A) raises KELChainInvalidError."""
        pk_a, _ = generate_keypair()
        pk_b, _ = generate_keypair()

        aid_a = encode_keri_key(pk_a)
        aid_b = encode_keri_key(pk_b)

        # A's inception (delegated by B)
        inception_a = create_kel_event(
            event_type=EventType.DIP,
            sequence=0,
            signing_keys=[pk_a],
            delegator_aid=aid_b,
        )

        # B's inception (delegated by A - creates cycle)
        inception_b = create_kel_event(
            event_type=EventType.DIP,
            sequence=0,
            signing_keys=[pk_b],
            delegator_aid=aid_a,
        )

        key_state_a = MagicMock()
        key_state_a.is_delegated = True
        key_state_a.inception_event = inception_a

        key_state_b = MagicMock()
        key_state_b.is_delegated = True
        key_state_b.inception_event = inception_b

        async def mock_resolver(aid, time):
            if aid == aid_a:
                return key_state_a
            if aid == aid_b:
                return key_state_b
            raise ResolutionFailedError(f"Unknown AID: {aid}")

        with pytest.raises(KELChainInvalidError) as exc_info:
            await resolve_delegation_chain(
                delegated_aid=aid_a,
                inception_event=inception_a,
                reference_time=datetime.now(timezone.utc),
                oobi_resolver=mock_resolver,
            )
        assert "Circular delegation" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_missing_delegator_aid_raises(self):
        """DIP event missing delegator_aid raises KELChainInvalidError."""
        pk, _ = generate_keypair()
        delegated_aid = encode_keri_key(pk)

        # Create inception event without delegator_aid
        inception_event = create_kel_event(
            event_type=EventType.DIP,
            sequence=0,
            signing_keys=[pk],
            delegator_aid=None,  # Missing!
        )

        mock_resolver = AsyncMock()

        with pytest.raises(KELChainInvalidError) as exc_info:
            await resolve_delegation_chain(
                delegated_aid=delegated_aid,
                inception_event=inception_event,
                reference_time=datetime.now(timezone.utc),
                oobi_resolver=mock_resolver,
            )
        assert "missing delegator AID" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_delegator_resolution_failure(self):
        """Failed delegator resolution raises ResolutionFailedError."""
        pk, _ = generate_keypair()
        delegated_aid = encode_keri_key(pk)
        delegator_aid = "EDelegator00000000000000000000000000000"

        inception_event = create_kel_event(
            event_type=EventType.DIP,
            sequence=0,
            signing_keys=[pk],
            delegator_aid=delegator_aid,
        )

        async def failing_resolver(aid, time):
            raise Exception("Network timeout")

        with pytest.raises(ResolutionFailedError) as exc_info:
            await resolve_delegation_chain(
                delegated_aid=delegated_aid,
                inception_event=inception_event,
                reference_time=datetime.now(timezone.utc),
                oobi_resolver=failing_resolver,
            )
        assert "Failed to resolve delegator" in str(exc_info.value)


class TestValidateDelegationAuthorization:
    """Tests for validate_delegation_authorization."""

    @pytest.mark.asyncio
    async def test_anchor_found_returns_valid(self):
        """Delegation with anchor event found returns VALID (signature validation simplified)."""
        from datetime import timedelta
        from app.vvp.keri.keri_canonical import canonical_serialize

        pk, sk = generate_keypair()
        delegation_said = "EDelegationSAID000000000000000000000000"

        # Set timestamps: anchor must be before or equal to delegation
        delegation_time = datetime.now(timezone.utc)
        anchor_time = delegation_time - timedelta(seconds=10)  # Anchor is earlier

        # Create delegation event with specific timestamp
        delegation_event = create_kel_event(
            event_type=EventType.DIP,
            sequence=0,
            signing_keys=[pk],
            delegator_aid="EDelegator",
            digest=delegation_said,
        )
        delegation_event.timestamp = delegation_time

        # Create anchor event (ixn) with seal referencing the delegation
        anchor_raw = {
            "v": "KERI10JSON000000_",
            "t": "ixn",
            "d": "EAnchorSAID",
            "i": "EDelegator",
            "s": "5",
            "p": "EPriorSAID",
            "a": [{"d": delegation_said}],
        }

        # Sign the anchor event using canonical serialization
        anchor_bytes = canonical_serialize(anchor_raw)
        sig = pysodium.crypto_sign_detached(anchor_bytes, sk)

        # Create inception event to establish keys with proper ICP structure
        inception_raw = {
            "v": "KERI10JSON000000_",
            "t": "icp",
            "d": "EInceptionSAID",
            "i": "EDelegator",
            "s": "0",
            "kt": "1",
            "k": [encode_keri_key(pk)],
            "nt": "1",
            "n": [],
            "bt": "0",
            "b": [],
            "c": [],
            "a": [],
        }
        inception_bytes = canonical_serialize(inception_raw)
        inception_sig = pysodium.crypto_sign_detached(inception_bytes, sk)

        inception_event = KELEvent(
            event_type=EventType.ICP,
            sequence=0,
            prior_digest="",
            digest="EInceptionSAID",
            signing_keys=[pk],
            next_keys_digest=None,
            toad=0,
            witnesses=[],
            timestamp=datetime.now(timezone.utc),
            signatures=[inception_sig],
            witness_receipts=[],
            raw=inception_raw,
            delegator_aid=None,
        )

        anchor_event = KELEvent(
            event_type=EventType.IXN,
            sequence=5,
            prior_digest="",
            digest="EAnchorSAID",
            signing_keys=[pk],
            next_keys_digest=None,
            toad=0,
            witnesses=[],
            timestamp=anchor_time,  # Anchor is before delegation
            signatures=[sig],
            witness_receipts=[],
            raw=anchor_raw,
            delegator_aid=None,
        )

        delegator_kel = [inception_event, anchor_event]
        delegator_key_state = MagicMock()
        delegator_key_state.signing_keys = [pk]

        is_valid, status, errors = await validate_delegation_authorization(
            delegation_event=delegation_event,
            delegator_kel=delegator_kel,
            delegator_key_state=delegator_key_state,
        )

        # Debug: print result if not valid
        if not is_valid:
            print(f"DEBUG: status={status}, errors={errors}")

        assert is_valid is True, f"Expected VALID but got status={status}, errors={errors}"
        assert status == ClaimStatus.VALID
        assert errors == []

    @pytest.mark.asyncio
    async def test_anchor_not_found_indeterminate(self):
        """Missing anchor event returns INDETERMINATE."""
        pk, _ = generate_keypair()
        delegation_said = "EDelegationSAID000000000000000000000000"

        delegation_event = create_kel_event(
            event_type=EventType.DIP,
            sequence=0,
            signing_keys=[pk],
            delegator_aid="EDelegator",
            digest=delegation_said,
        )

        # Delegator KEL with no anchor for this delegation
        inception = create_kel_event(
            event_type=EventType.ICP,
            sequence=0,
            signing_keys=[pk],
        )
        unrelated_ixn = create_kel_event(
            event_type=EventType.IXN,
            sequence=1,
            signing_keys=[pk],
        )
        unrelated_ixn.raw["a"] = [{"d": "EDifferentSAID"}]  # Different seal

        delegator_kel = [inception, unrelated_ixn]
        delegator_key_state = MagicMock()

        is_valid, status, errors = await validate_delegation_authorization(
            delegation_event=delegation_event,
            delegator_kel=delegator_kel,
            delegator_key_state=delegator_key_state,
        )

        assert is_valid is False
        assert status == ClaimStatus.INDETERMINATE
        assert any("not found" in e for e in errors)

    @pytest.mark.asyncio
    async def test_missing_delegation_said_invalid(self):
        """Delegation event without SAID returns INVALID."""
        pk, _ = generate_keypair()

        delegation_event = create_kel_event(
            event_type=EventType.DIP,
            sequence=0,
            signing_keys=[pk],
            delegator_aid="EDelegator",
            digest="",  # Empty SAID
        )

        is_valid, status, errors = await validate_delegation_authorization(
            delegation_event=delegation_event,
            delegator_kel=[],
            delegator_key_state=MagicMock(),
        )

        assert is_valid is False
        assert status == ClaimStatus.INVALID
        assert any("missing SAID" in e for e in errors)


class TestFindKeyStateAtSequence:
    """Tests for _find_key_state_at_sequence helper."""

    def test_finds_keys_at_target_sequence(self):
        """Returns keys in effect at target sequence."""
        pk1, _ = generate_keypair()
        pk2, _ = generate_keypair()

        inception = create_kel_event(EventType.ICP, 0, [pk1])
        rotation = create_kel_event(EventType.ROT, 5, [pk2])

        kel = [inception, rotation]

        # At seq 3, should return inception keys
        keys = _find_key_state_at_sequence(kel, 3)
        assert keys == [pk1]

        # At seq 5, should return rotation keys
        keys = _find_key_state_at_sequence(kel, 5)
        assert keys == [pk2]

        # At seq 10, should return rotation keys
        keys = _find_key_state_at_sequence(kel, 10)
        assert keys == [pk2]

    def test_returns_none_before_inception(self):
        """Returns None if no establishment events found."""
        kel = []  # Empty KEL
        keys = _find_key_state_at_sequence(kel, 0)
        assert keys is None

    def test_ignores_non_establishment_events(self):
        """Only establishment events update key state."""
        pk, _ = generate_keypair()

        inception = create_kel_event(EventType.ICP, 0, [pk])
        ixn = create_kel_event(EventType.IXN, 1, [])  # Non-establishment

        kel = [inception, ixn]

        keys = _find_key_state_at_sequence(kel, 5)
        assert keys == [pk]


class TestVerifyEventSignature:
    """Tests for _verify_event_signature helper."""

    def test_valid_signature_passes(self):
        """Valid Ed25519 signature returns True."""
        from app.vvp.keri.keri_canonical import canonical_serialize

        pk, sk = generate_keypair()

        raw = {"t": "icp", "s": "0", "d": "ESAID"}
        event_bytes = canonical_serialize(raw)
        sig = pysodium.crypto_sign_detached(event_bytes, sk)

        event = KELEvent(
            event_type=EventType.ICP,
            sequence=0,
            prior_digest="",
            digest="ESAID",
            signing_keys=[pk],
            next_keys_digest=None,
            toad=0,
            witnesses=[],
            timestamp=None,
            signatures=[sig],
            witness_receipts=[],
            raw=raw,
            delegator_aid=None,
        )

        assert _verify_event_signature(event, [pk]) is True

    def test_invalid_signature_fails(self):
        """Invalid signature returns False."""
        from app.vvp.keri.keri_canonical import canonical_serialize

        pk, sk = generate_keypair()
        wrong_pk, _ = generate_keypair()

        raw = {"t": "icp", "s": "0", "d": "ESAID"}
        event_bytes = canonical_serialize(raw)
        sig = pysodium.crypto_sign_detached(event_bytes, sk)

        event = KELEvent(
            event_type=EventType.ICP,
            sequence=0,
            prior_digest="",
            digest="ESAID",
            signing_keys=[wrong_pk],  # Different key
            next_keys_digest=None,
            toad=0,
            witnesses=[],
            timestamp=None,
            signatures=[sig],
            witness_receipts=[],
            raw=raw,
            delegator_aid=None,
        )

        assert _verify_event_signature(event, [wrong_pk]) is False

    def test_no_signatures_fails(self):
        """Event without signatures returns False."""
        pk, _ = generate_keypair()

        event = KELEvent(
            event_type=EventType.ICP,
            sequence=0,
            prior_digest="",
            digest="ESAID",
            signing_keys=[pk],
            next_keys_digest=None,
            toad=0,
            witnesses=[],
            timestamp=None,
            signatures=[],  # No signatures
            witness_receipts=[],
            raw={"t": "icp"},
            delegator_aid=None,
        )

        assert _verify_event_signature(event, [pk]) is False

    def test_no_keys_fails(self):
        """No signing keys returns False."""
        from app.vvp.keri.keri_canonical import canonical_serialize

        pk, sk = generate_keypair()

        raw = {"t": "icp", "s": "0", "d": "ESAID"}
        event_bytes = canonical_serialize(raw)
        sig = pysodium.crypto_sign_detached(event_bytes, sk)

        event = KELEvent(
            event_type=EventType.ICP,
            sequence=0,
            prior_digest="",
            digest="ESAID",
            signing_keys=[],
            next_keys_digest=None,
            toad=0,
            witnesses=[],
            timestamp=None,
            signatures=[sig],
            witness_receipts=[],
            raw=raw,
            delegator_aid=None,
        )

        assert _verify_event_signature(event, []) is False


# =============================================================================
# Integration Tests: Delegation Validation in Runtime Path
# =============================================================================


class TestDelegationRuntimeIntegration:
    """Tests verifying delegation validation is invoked in the runtime path.

    These tests ensure that resolve_delegation_chain() is called when
    KeyState.is_delegated is True during verify_passport_signature_tier2().
    """

    @pytest.mark.asyncio
    async def test_delegated_key_state_triggers_delegation_validation(self):
        """When KeyState.is_delegated=True, delegation chain is resolved."""
        from unittest.mock import AsyncMock, patch, MagicMock
        from datetime import datetime, timezone
        from app.vvp.keri.signature import verify_passport_signature_tier2
        from app.vvp.keri.kel_resolver import KeyState
        from app.vvp.keri.kel_parser import EventType, KELEvent

        pk, sk = generate_keypair()
        aid = encode_keri_key(pk)
        delegator_aid = "EDelegator000000000000000000000000000000000"

        # Create a delegated key state
        inception_event = create_kel_event(
            event_type=EventType.DIP,
            sequence=0,
            signing_keys=[pk],
            delegator_aid=delegator_aid,
        )

        delegated_key_state = KeyState(
            aid=aid,
            signing_keys=[pk],
            sequence=0,
            establishment_digest="ESAID",
            valid_from=datetime.now(timezone.utc),
            witnesses=[],
            toad=0,
            is_delegated=True,
            delegator_aid=delegator_aid,
            inception_event=inception_event,
            delegation_chain=None,
        )

        # Create delegator key state for authorization check
        delegator_pk, _ = generate_keypair()
        delegator_key_state = KeyState(
            aid=delegator_aid,
            signing_keys=[delegator_pk],
            sequence=0,
            establishment_digest="EDelegatorSAID",
            valid_from=datetime.now(timezone.utc),
            witnesses=[],
            toad=0,
            is_delegated=False,
            delegator_aid=None,
            inception_event=None,
            delegation_chain=None,
        )

        # Create a mock passport
        mock_passport = MagicMock()
        mock_passport.header.kid = f"https://example.com/oobi/{aid}"
        mock_passport.payload.iat = int(datetime.now(timezone.utc).timestamp())
        mock_passport.raw_header = "eyJhbGciOiJFZERTQSJ9"
        mock_passport.raw_payload = "eyJpYXQiOjE3MDAwMDAwMDB9"
        # Create valid signature
        signing_input = f"{mock_passport.raw_header}.{mock_passport.raw_payload}".encode("ascii")
        mock_passport.signature = pysodium.crypto_sign_detached(signing_input, sk)

        # Patch at the kel_resolver module where resolve_key_state is defined
        with patch("app.vvp.keri.kel_resolver.resolve_key_state", new_callable=AsyncMock) as mock_resolve:
            mock_resolve.return_value = delegated_key_state

            # Patch delegation at the delegation module where it's defined
            with patch("app.vvp.keri.delegation.resolve_delegation_chain", new_callable=AsyncMock) as mock_delegation:
                mock_delegation.return_value = DelegationChain(
                    delegates=[aid, delegator_aid],
                    root_aid=delegator_aid,
                    valid=True,
                    errors=[],
                )

                # Mock resolve_key_state_with_kel for authorization check
                with patch("app.vvp.keri.kel_resolver.resolve_key_state_with_kel", new_callable=AsyncMock) as mock_with_kel:
                    mock_with_kel.return_value = (delegator_key_state, [])

                    # Mock validate_delegation_authorization to succeed
                    with patch("app.vvp.keri.delegation.validate_delegation_authorization", new_callable=AsyncMock) as mock_auth:
                        mock_auth.return_value = (True, ClaimStatus.VALID, [])

                        # Run verification
                        await verify_passport_signature_tier2(
                            mock_passport,
                            _allow_test_mode=True,
                        )

                        # Assert delegation chain resolution was called
                        assert mock_delegation.called, "resolve_delegation_chain should be called for delegated identifiers"
                        call_args = mock_delegation.call_args
                        assert call_args.kwargs["delegated_aid"] == aid

                        # Assert authorization was validated
                        assert mock_auth.called, "validate_delegation_authorization should be called"

    @pytest.mark.asyncio
    async def test_non_delegated_key_state_skips_delegation_validation(self):
        """When KeyState.is_delegated=False, delegation validation is skipped."""
        from unittest.mock import AsyncMock, patch, MagicMock
        from datetime import datetime, timezone
        from app.vvp.keri.signature import verify_passport_signature_tier2
        from app.vvp.keri.kel_resolver import KeyState

        pk, sk = generate_keypair()
        aid = encode_keri_key(pk)

        # Create a non-delegated key state
        non_delegated_key_state = KeyState(
            aid=aid,
            signing_keys=[pk],
            sequence=0,
            establishment_digest="ESAID",
            valid_from=datetime.now(timezone.utc),
            witnesses=[],
            toad=0,
            is_delegated=False,  # Not delegated
            delegator_aid=None,
            inception_event=None,
            delegation_chain=None,
        )

        # Create a mock passport
        mock_passport = MagicMock()
        mock_passport.header.kid = f"https://example.com/oobi/{aid}"
        mock_passport.payload.iat = int(datetime.now(timezone.utc).timestamp())
        mock_passport.raw_header = "eyJhbGciOiJFZERTQSJ9"
        mock_passport.raw_payload = "eyJpYXQiOjE3MDAwMDAwMDB9"
        signing_input = f"{mock_passport.raw_header}.{mock_passport.raw_payload}".encode("ascii")
        mock_passport.signature = pysodium.crypto_sign_detached(signing_input, sk)

        with patch("app.vvp.keri.kel_resolver.resolve_key_state", new_callable=AsyncMock) as mock_resolve:
            mock_resolve.return_value = non_delegated_key_state

            with patch("app.vvp.keri.delegation.resolve_delegation_chain", new_callable=AsyncMock) as mock_delegation:
                await verify_passport_signature_tier2(
                    mock_passport,
                    _allow_test_mode=True,
                )

                # Assert delegation chain resolution was NOT called
                assert not mock_delegation.called, "resolve_delegation_chain should NOT be called for non-delegated identifiers"

    @pytest.mark.asyncio
    async def test_delegation_chain_invalid_raises_kel_chain_error(self):
        """Invalid delegation chain raises KELChainInvalidError."""
        from unittest.mock import AsyncMock, patch, MagicMock
        from datetime import datetime, timezone
        from app.vvp.keri.signature import verify_passport_signature_tier2
        from app.vvp.keri.kel_resolver import KeyState
        from app.vvp.keri.exceptions import KELChainInvalidError

        pk, sk = generate_keypair()
        aid = encode_keri_key(pk)

        inception_event = create_kel_event(
            event_type=EventType.DIP,
            sequence=0,
            signing_keys=[pk],
            delegator_aid="EDelegator000000000000000000000000000000000",
        )

        delegated_key_state = KeyState(
            aid=aid,
            signing_keys=[pk],
            sequence=0,
            establishment_digest="ESAID",
            valid_from=datetime.now(timezone.utc),
            witnesses=[],
            toad=0,
            is_delegated=True,
            delegator_aid="EDelegator000000000000000000000000000000000",
            inception_event=inception_event,
            delegation_chain=None,
        )

        mock_passport = MagicMock()
        mock_passport.header.kid = f"https://example.com/oobi/{aid}"
        mock_passport.payload.iat = int(datetime.now(timezone.utc).timestamp())
        mock_passport.raw_header = "eyJhbGciOiJFZERTQSJ9"
        mock_passport.raw_payload = "eyJpYXQiOjE3MDAwMDAwMDB9"
        signing_input = f"{mock_passport.raw_header}.{mock_passport.raw_payload}".encode("ascii")
        mock_passport.signature = pysodium.crypto_sign_detached(signing_input, sk)

        with patch("app.vvp.keri.kel_resolver.resolve_key_state", new_callable=AsyncMock) as mock_resolve:
            mock_resolve.return_value = delegated_key_state

            with patch("app.vvp.keri.delegation.resolve_delegation_chain", new_callable=AsyncMock) as mock_delegation:
                # Simulate invalid delegation chain
                mock_delegation.return_value = DelegationChain(
                    delegates=[aid],
                    root_aid=None,
                    valid=False,
                    errors=["Circular delegation detected"],
                )

                with pytest.raises(KELChainInvalidError) as exc_info:
                    await verify_passport_signature_tier2(
                        mock_passport,
                        _allow_test_mode=True,
                    )

                assert "Circular delegation detected" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_delegation_resolution_failure_raises_resolution_error(self):
        """Delegation resolution failure raises ResolutionFailedError."""
        from unittest.mock import AsyncMock, patch, MagicMock
        from datetime import datetime, timezone
        from app.vvp.keri.signature import verify_passport_signature_tier2
        from app.vvp.keri.kel_resolver import KeyState
        from app.vvp.keri.exceptions import ResolutionFailedError

        pk, sk = generate_keypair()
        aid = encode_keri_key(pk)

        inception_event = create_kel_event(
            event_type=EventType.DIP,
            sequence=0,
            signing_keys=[pk],
            delegator_aid="EDelegator000000000000000000000000000000000",
        )

        delegated_key_state = KeyState(
            aid=aid,
            signing_keys=[pk],
            sequence=0,
            establishment_digest="ESAID",
            valid_from=datetime.now(timezone.utc),
            witnesses=[],
            toad=0,
            is_delegated=True,
            delegator_aid="EDelegator000000000000000000000000000000000",
            inception_event=inception_event,
            delegation_chain=None,
        )

        mock_passport = MagicMock()
        mock_passport.header.kid = f"https://example.com/oobi/{aid}"
        mock_passport.payload.iat = int(datetime.now(timezone.utc).timestamp())
        mock_passport.raw_header = "eyJhbGciOiJFZERTQSJ9"
        mock_passport.raw_payload = "eyJpYXQiOjE3MDAwMDAwMDB9"
        signing_input = f"{mock_passport.raw_header}.{mock_passport.raw_payload}".encode("ascii")
        mock_passport.signature = pysodium.crypto_sign_detached(signing_input, sk)

        with patch("app.vvp.keri.kel_resolver.resolve_key_state", new_callable=AsyncMock) as mock_resolve:
            mock_resolve.return_value = delegated_key_state

            with patch("app.vvp.keri.delegation.resolve_delegation_chain", new_callable=AsyncMock) as mock_delegation:
                # Simulate delegator resolution failure
                mock_delegation.side_effect = ResolutionFailedError(
                    "Failed to resolve delegator OOBI"
                )

                with pytest.raises(ResolutionFailedError) as exc_info:
                    await verify_passport_signature_tier2(
                        mock_passport,
                        _allow_test_mode=True,
                    )

                assert "Failed to resolve delegator" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_delegation_authorization_failure_raises_error(self):
        """Failing anchor authorization raises appropriate error."""
        from unittest.mock import AsyncMock, patch, MagicMock
        from datetime import datetime, timezone
        from app.vvp.keri.signature import verify_passport_signature_tier2
        from app.vvp.keri.kel_resolver import KeyState
        from app.vvp.keri.exceptions import KELChainInvalidError

        pk, sk = generate_keypair()
        aid = encode_keri_key(pk)
        delegator_aid = "EDelegator000000000000000000000000000000000"

        inception_event = create_kel_event(
            event_type=EventType.DIP,
            sequence=0,
            signing_keys=[pk],
            delegator_aid=delegator_aid,
        )

        delegated_key_state = KeyState(
            aid=aid,
            signing_keys=[pk],
            sequence=0,
            establishment_digest="ESAID",
            valid_from=datetime.now(timezone.utc),
            witnesses=[],
            toad=0,
            is_delegated=True,
            delegator_aid=delegator_aid,
            inception_event=inception_event,
            delegation_chain=None,
        )

        # Create delegator key state for authorization check
        delegator_pk, _ = generate_keypair()
        delegator_key_state = KeyState(
            aid=delegator_aid,
            signing_keys=[delegator_pk],
            sequence=0,
            establishment_digest="EDelegatorSAID",
            valid_from=datetime.now(timezone.utc),
            witnesses=[],
            toad=0,
            is_delegated=False,
            delegator_aid=None,
            inception_event=None,
            delegation_chain=None,
        )

        # Create empty KEL (no anchor events) for delegator
        delegator_kel = []

        mock_passport = MagicMock()
        mock_passport.header.kid = f"https://example.com/oobi/{aid}"
        mock_passport.payload.iat = int(datetime.now(timezone.utc).timestamp())
        mock_passport.raw_header = "eyJhbGciOiJFZERTQSJ9"
        mock_passport.raw_payload = "eyJpYXQiOjE3MDAwMDAwMDB9"
        signing_input = f"{mock_passport.raw_header}.{mock_passport.raw_payload}".encode("ascii")
        mock_passport.signature = pysodium.crypto_sign_detached(signing_input, sk)

        with patch("app.vvp.keri.kel_resolver.resolve_key_state", new_callable=AsyncMock) as mock_resolve:
            mock_resolve.return_value = delegated_key_state

            with patch("app.vvp.keri.delegation.resolve_delegation_chain", new_callable=AsyncMock) as mock_chain:
                # Chain resolution succeeds
                mock_chain.return_value = DelegationChain(
                    delegates=[aid, delegator_aid],
                    root_aid=delegator_aid,
                    valid=True,
                    errors=[],
                )

                with patch("app.vvp.keri.kel_resolver.resolve_key_state_with_kel", new_callable=AsyncMock) as mock_with_kel:
                    # Return delegator key state and empty KEL (no anchor)
                    mock_with_kel.return_value = (delegator_key_state, delegator_kel)

                    with patch("app.vvp.keri.delegation.validate_delegation_authorization", new_callable=AsyncMock) as mock_auth:
                        # Simulate authorization failure - no anchor found
                        mock_auth.return_value = (
                            False,
                            ClaimStatus.INDETERMINATE,
                            ["Delegation anchor not found in delegator KEL"]
                        )

                        with pytest.raises(ResolutionFailedError) as exc_info:
                            await verify_passport_signature_tier2(
                                mock_passport,
                                _allow_test_mode=True,
                            )

                        assert "Cannot verify delegation authorization" in str(exc_info.value)
                        assert "anchor not found" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_delegation_authorization_invalid_raises_chain_error(self):
        """Invalid anchor authorization (bad signature) raises KELChainInvalidError."""
        from unittest.mock import AsyncMock, patch, MagicMock
        from datetime import datetime, timezone
        from app.vvp.keri.signature import verify_passport_signature_tier2
        from app.vvp.keri.kel_resolver import KeyState
        from app.vvp.keri.exceptions import KELChainInvalidError

        pk, sk = generate_keypair()
        aid = encode_keri_key(pk)
        delegator_aid = "EDelegator000000000000000000000000000000000"

        inception_event = create_kel_event(
            event_type=EventType.DIP,
            sequence=0,
            signing_keys=[pk],
            delegator_aid=delegator_aid,
        )

        delegated_key_state = KeyState(
            aid=aid,
            signing_keys=[pk],
            sequence=0,
            establishment_digest="ESAID",
            valid_from=datetime.now(timezone.utc),
            witnesses=[],
            toad=0,
            is_delegated=True,
            delegator_aid=delegator_aid,
            inception_event=inception_event,
            delegation_chain=None,
        )

        delegator_pk, _ = generate_keypair()
        delegator_key_state = KeyState(
            aid=delegator_aid,
            signing_keys=[delegator_pk],
            sequence=0,
            establishment_digest="EDelegatorSAID",
            valid_from=datetime.now(timezone.utc),
            witnesses=[],
            toad=0,
            is_delegated=False,
            delegator_aid=None,
            inception_event=None,
            delegation_chain=None,
        )

        mock_passport = MagicMock()
        mock_passport.header.kid = f"https://example.com/oobi/{aid}"
        mock_passport.payload.iat = int(datetime.now(timezone.utc).timestamp())
        mock_passport.raw_header = "eyJhbGciOiJFZERTQSJ9"
        mock_passport.raw_payload = "eyJpYXQiOjE3MDAwMDAwMDB9"
        signing_input = f"{mock_passport.raw_header}.{mock_passport.raw_payload}".encode("ascii")
        mock_passport.signature = pysodium.crypto_sign_detached(signing_input, sk)

        with patch("app.vvp.keri.kel_resolver.resolve_key_state", new_callable=AsyncMock) as mock_resolve:
            mock_resolve.return_value = delegated_key_state

            with patch("app.vvp.keri.delegation.resolve_delegation_chain", new_callable=AsyncMock) as mock_chain:
                mock_chain.return_value = DelegationChain(
                    delegates=[aid, delegator_aid],
                    root_aid=delegator_aid,
                    valid=True,
                    errors=[],
                )

                with patch("app.vvp.keri.kel_resolver.resolve_key_state_with_kel", new_callable=AsyncMock) as mock_with_kel:
                    mock_with_kel.return_value = (delegator_key_state, [])

                    with patch("app.vvp.keri.delegation.validate_delegation_authorization", new_callable=AsyncMock) as mock_auth:
                        # Simulate INVALID authorization - bad signature
                        mock_auth.return_value = (
                            False,
                            ClaimStatus.INVALID,
                            ["Delegator anchor event signature invalid"]
                        )

                        with pytest.raises(KELChainInvalidError) as exc_info:
                            await verify_passport_signature_tier2(
                                mock_passport,
                                _allow_test_mode=True,
                            )

                        assert "Delegation not authorized" in str(exc_info.value)
                        assert "signature invalid" in str(exc_info.value)
