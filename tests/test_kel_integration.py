"""Integration tests for KERI key state resolution.

Tests end-to-end key state resolution with mocked OOBI server.
"""

import base64
import json
from datetime import datetime
from unittest.mock import AsyncMock, patch
import pytest
import pysodium

from app.vvp.keri import (
    resolve_key_state,
    verify_passport_signature_tier2,
    KELChainInvalidError,
    KeyNotYetValidError,
    ResolutionFailedError,
)
from app.vvp.keri.kel_resolver import reset_cache
from app.vvp.keri.oobi import OOBIResult


def generate_keypair():
    """Generate a test Ed25519 keypair."""
    pk, sk = pysodium.crypto_sign_keypair()
    return pk, sk


def encode_keri_key(pk: bytes) -> str:
    """Encode a public key in KERI format using proper CESR encoding.

    CESR B-prefix (Ed25519N) encoding prepends a lead byte (0x04) to the
    32-byte public key, then base64url encodes the 33-byte result.
    """
    # Prepend CESR lead byte for B-prefix (Ed25519N non-transferable)
    cesr_lead_byte = bytes([0x04])
    full_bytes = cesr_lead_byte + pk
    return base64.urlsafe_b64encode(full_bytes).decode().rstrip("=")


def sign_event(event_dict: dict, private_key: bytes) -> str:
    """Sign an event and return KERI-encoded signature."""
    raw_copy = dict(event_dict)
    raw_copy.pop("signatures", None)
    canonical = json.dumps(raw_copy, sort_keys=True, separators=(",", ":"))
    message = canonical.encode("utf-8")
    signature = pysodium.crypto_sign_detached(message, private_key)
    return "0B" + base64.urlsafe_b64encode(signature).decode().rstrip("=")


def create_signed_kel(
    keypairs: list,
    timestamps: list = None,
    aid: str = None
) -> bytes:
    """Create a valid signed KEL with given keypairs.

    Args:
        keypairs: List of (pk, sk) tuples. First is inception, rest are rotations.
        timestamps: Optional list of ISO timestamps for each event.
        aid: Optional AID (derived from first key if not provided).

    Returns:
        JSON-encoded KEL as bytes.
    """
    if not keypairs:
        raise ValueError("At least one keypair required")

    events = []
    prev_digest = ""

    for i, (pk, sk) in enumerate(keypairs):
        is_inception = (i == 0)
        event_type = "icp" if is_inception else "rot"
        digest = f"ESAID_{i}"

        event = {
            "t": event_type,
            "s": hex(i)[2:],  # KERI uses hex sequence
            "p": prev_digest,
            "d": digest,
            "k": [encode_keri_key(pk)],
            "n": ["NEXT_KEY_DIGEST"],
            "bt": "0",
            "b": [],
        }

        if timestamps and i < len(timestamps):
            event["dt"] = timestamps[i]

        # Sign with appropriate key
        if is_inception:
            # Inception self-signed
            event["signatures"] = [sign_event(event, sk)]
        else:
            # Rotation signed by PRIOR key
            prior_sk = keypairs[i - 1][1]
            event["signatures"] = [sign_event(event, prior_sk)]

        events.append(event)
        prev_digest = digest

    return json.dumps(events).encode()


@pytest.fixture(autouse=True)
def clear_cache():
    """Reset the global cache before each test."""
    reset_cache()
    yield
    reset_cache()


class TestEndToEndKeyResolution:
    """End-to-end key state resolution tests."""

    @pytest.mark.asyncio
    async def test_resolve_inception_only(self):
        """Resolve key state from KEL with only inception."""
        pk, sk = generate_keypair()
        kid = encode_keri_key(pk)

        kel_data = create_signed_kel(
            keypairs=[(pk, sk)],
            timestamps=["2024-01-01T00:00:00Z"]
        )

        mock_result = OOBIResult(
            aid=kid,
            kel_data=kel_data,
            witnesses=[]
        )

        with patch(
            "app.vvp.keri.kel_resolver.dereference_oobi",
            new_callable=AsyncMock,
            return_value=mock_result
        ):
            key_state = await resolve_key_state(
                kid=f"http://example.com/oobi/{kid}",
                reference_time=datetime(2024, 6, 15),
                min_witnesses=0,
                _allow_test_mode=True
            )

        assert key_state.signing_keys == [pk]
        assert key_state.sequence == 0

    @pytest.mark.asyncio
    async def test_resolve_with_rotation(self):
        """Resolve key state from KEL with rotation."""
        pk1, sk1 = generate_keypair()
        pk2, sk2 = generate_keypair()
        kid = encode_keri_key(pk1)

        kel_data = create_signed_kel(
            keypairs=[(pk1, sk1), (pk2, sk2)],
            timestamps=["2024-01-01T00:00:00Z", "2024-06-01T00:00:00Z"]
        )

        mock_result = OOBIResult(
            aid=kid,
            kel_data=kel_data,
            witnesses=[]
        )

        with patch(
            "app.vvp.keri.kel_resolver.dereference_oobi",
            new_callable=AsyncMock,
            return_value=mock_result
        ):
            # Query for time AFTER rotation
            key_state = await resolve_key_state(
                kid=f"http://example.com/oobi/{kid}",
                reference_time=datetime(2024, 7, 15),
                min_witnesses=0,
                _allow_test_mode=True
            )

        # Should get rotated key
        assert key_state.signing_keys == [pk2]
        assert key_state.sequence == 1

    @pytest.mark.asyncio
    async def test_resolve_pre_rotation_key(self):
        """Resolve key state from before a rotation."""
        pk1, sk1 = generate_keypair()
        pk2, sk2 = generate_keypair()
        kid = encode_keri_key(pk1)

        kel_data = create_signed_kel(
            keypairs=[(pk1, sk1), (pk2, sk2)],
            timestamps=["2024-01-01T00:00:00Z", "2024-06-01T00:00:00Z"]
        )

        mock_result = OOBIResult(
            aid=kid,
            kel_data=kel_data,
            witnesses=[]
        )

        with patch(
            "app.vvp.keri.kel_resolver.dereference_oobi",
            new_callable=AsyncMock,
            return_value=mock_result
        ):
            # Query for time BEFORE rotation
            key_state = await resolve_key_state(
                kid=f"http://example.com/oobi/{kid}",
                reference_time=datetime(2024, 3, 15),
                min_witnesses=0,
                _allow_test_mode=True
            )

        # Should get pre-rotation key
        assert key_state.signing_keys == [pk1]
        assert key_state.sequence == 0

    @pytest.mark.asyncio
    async def test_reference_before_inception_fails(self):
        """Reference time before inception raises error."""
        pk, sk = generate_keypair()
        kid = encode_keri_key(pk)

        kel_data = create_signed_kel(
            keypairs=[(pk, sk)],
            timestamps=["2024-06-01T00:00:00Z"]  # Inception in June
        )

        mock_result = OOBIResult(
            aid=kid,
            kel_data=kel_data,
            witnesses=[]
        )

        with patch(
            "app.vvp.keri.kel_resolver.dereference_oobi",
            new_callable=AsyncMock,
            return_value=mock_result
        ):
            with pytest.raises(KeyNotYetValidError):
                await resolve_key_state(
                    kid=f"http://example.com/oobi/{kid}",
                    reference_time=datetime(2024, 1, 15),  # Before inception
                    min_witnesses=0,
                    _allow_test_mode=True
                )


class TestDelegatedEventDetection:
    """Test detection and parsing of delegated events."""

    @pytest.mark.asyncio
    async def test_delegated_inception_parsed_successfully(self):
        """Delegated inception with di field parses and resolves successfully."""
        pk, sk = generate_keypair()
        kid = encode_keri_key(pk)

        # Create a delegated inception event with proper delegator
        delegator_aid = "EDelegatorAID00000000000000000000000000000"
        dip_event = {
            "t": "dip",  # Delegated inception
            "s": "0",
            "d": "ESAID_0",
            "p": "",
            "k": [kid],
            "di": delegator_aid,  # Delegator AID (required)
            "bt": "0",
            "b": [],
        }

        # Sign the event for chain validation
        event_bytes = json.dumps(dip_event, separators=(",", ":"), sort_keys=True).encode()
        sig = pysodium.crypto_sign_detached(event_bytes, sk)
        sig_b64 = "0B" + base64.urlsafe_b64encode(sig).decode().rstrip("=")
        dip_event["signatures"] = [sig_b64]

        kel_data = json.dumps([dip_event]).encode()

        mock_result = OOBIResult(
            aid=kid,
            kel_data=kel_data,
            witnesses=[]
        )

        with patch(
            "app.vvp.keri.kel_resolver.dereference_oobi",
            new_callable=AsyncMock,
            return_value=mock_result
        ):
            key_state = await resolve_key_state(
                kid=f"http://example.com/oobi/{kid}",
                reference_time=datetime(2024, 6, 15),
                min_witnesses=0,
                _allow_test_mode=True
            )
            # Verify delegation info is populated
            assert key_state.is_delegated is True
            assert key_state.delegator_aid == delegator_aid
            assert key_state.inception_event is not None
            assert key_state.inception_event.delegator_aid == delegator_aid

    @pytest.mark.asyncio
    async def test_delegated_inception_missing_di_raises(self):
        """Delegated inception missing di field raises ResolutionFailedError."""
        pk, sk = generate_keypair()
        kid = encode_keri_key(pk)

        # Create a delegated inception event WITHOUT di field
        dip_event = {
            "t": "dip",  # Delegated inception
            "s": "0",
            "d": "ESAID_0",
            "p": "",
            "k": [kid],
            # Missing "di" field - should cause error
        }

        kel_data = json.dumps([dip_event]).encode()

        mock_result = OOBIResult(
            aid=kid,
            kel_data=kel_data,
            witnesses=[]
        )

        with patch(
            "app.vvp.keri.kel_resolver.dereference_oobi",
            new_callable=AsyncMock,
            return_value=mock_result
        ):
            with pytest.raises(ResolutionFailedError) as exc_info:
                await resolve_key_state(
                    kid=f"http://example.com/oobi/{kid}",
                    reference_time=datetime(2024, 6, 15),
                    min_witnesses=0,
                    _allow_test_mode=True
                )
            assert "missing required 'di' field" in str(exc_info.value)


class TestChainValidationIntegration:
    """Test chain validation in resolution flow."""

    @pytest.mark.asyncio
    async def test_broken_chain_detected(self):
        """Broken chain continuity is detected."""
        pk1, sk1 = generate_keypair()
        pk2, sk2 = generate_keypair()
        kid = encode_keri_key(pk1)

        # Create valid inception
        icp_event = {
            "t": "icp",
            "s": "0",
            "p": "",
            "d": "ESAID_0",
            "k": [encode_keri_key(pk1)],
            "n": ["NEXT"],
            "bt": "0",
            "b": [],
        }
        icp_event["signatures"] = [sign_event(icp_event, sk1)]

        # Create rotation with WRONG prior_digest
        rot_event = {
            "t": "rot",
            "s": "1",
            "p": "WRONG_DIGEST",  # Should be ESAID_0
            "d": "ESAID_1",
            "k": [encode_keri_key(pk2)],
            "n": ["NEXT"],
            "bt": "0",
            "b": [],
        }
        rot_event["signatures"] = [sign_event(rot_event, sk1)]

        kel_data = json.dumps([icp_event, rot_event]).encode()

        mock_result = OOBIResult(
            aid=kid,
            kel_data=kel_data,
            witnesses=[]
        )

        with patch(
            "app.vvp.keri.kel_resolver.dereference_oobi",
            new_callable=AsyncMock,
            return_value=mock_result
        ):
            with pytest.raises(KELChainInvalidError, match="Chain break"):
                await resolve_key_state(
                    kid=f"http://example.com/oobi/{kid}",
                    reference_time=datetime(2024, 6, 15),
                    min_witnesses=0,
                    _allow_test_mode=True
                )


class TestCachingBehavior:
    """Test caching in resolution flow."""

    @pytest.mark.asyncio
    async def test_cache_hit_avoids_oobi_fetch(self):
        """Cached result avoids OOBI fetch."""
        pk, sk = generate_keypair()
        kid = encode_keri_key(pk)

        kel_data = create_signed_kel(
            keypairs=[(pk, sk)],
            timestamps=["2024-01-01T00:00:00Z"]
        )

        mock_oobi = AsyncMock(return_value=OOBIResult(
            aid=kid,
            kel_data=kel_data,
            witnesses=[]
        ))

        with patch(
            "app.vvp.keri.kel_resolver.dereference_oobi",
            mock_oobi
        ):
            # First call - should fetch
            await resolve_key_state(
                kid=f"http://example.com/oobi/{kid}",
                reference_time=datetime(2024, 6, 15),
                min_witnesses=0,
                _allow_test_mode=True
            )

            # Second call - should use cache
            await resolve_key_state(
                kid=f"http://example.com/oobi/{kid}",
                reference_time=datetime(2024, 6, 15),
                min_witnesses=0,
                _allow_test_mode=True
            )

        # OOBI should only be called once
        assert mock_oobi.call_count == 1

    @pytest.mark.asyncio
    async def test_disable_cache(self):
        """Cache can be disabled."""
        pk, sk = generate_keypair()
        kid = encode_keri_key(pk)

        kel_data = create_signed_kel(
            keypairs=[(pk, sk)],
            timestamps=["2024-01-01T00:00:00Z"]
        )

        mock_oobi = AsyncMock(return_value=OOBIResult(
            aid=kid,
            kel_data=kel_data,
            witnesses=[]
        ))

        with patch(
            "app.vvp.keri.kel_resolver.dereference_oobi",
            mock_oobi
        ):
            # First call
            await resolve_key_state(
                kid=f"http://example.com/oobi/{kid}",
                reference_time=datetime(2024, 6, 15),
                min_witnesses=0,
                use_cache=False,
                _allow_test_mode=True
            )

            # Second call with cache disabled
            await resolve_key_state(
                kid=f"http://example.com/oobi/{kid}",
                reference_time=datetime(2024, 6, 15),
                min_witnesses=0,
                use_cache=False,
                _allow_test_mode=True
            )

        # OOBI should be called twice
        assert mock_oobi.call_count == 2


class TestFeatureFlag:
    """Test Tier 2 feature flag gating."""

    @pytest.mark.asyncio
    async def test_tier2_disabled_when_flag_false(self):
        """Tier 2 resolution is blocked when feature flag is explicitly disabled."""
        # When TIER2_KEL_RESOLUTION_ENABLED=False and _allow_test_mode=False,
        # resolution should fail with a clear error message
        with patch(
            "app.core.config.TIER2_KEL_RESOLUTION_ENABLED",
            False
        ):
            with pytest.raises(ResolutionFailedError, match="disabled"):
                await resolve_key_state(
                    kid="http://example.com/oobi/BAID",
                    reference_time=datetime(2024, 6, 15),
                    min_witnesses=0,
                    _allow_test_mode=False  # Explicitly disable test mode
                )

    @pytest.mark.asyncio
    async def test_tier2_allowed_with_test_mode(self):
        """Tier 2 resolution works when _allow_test_mode is True."""
        pk, sk = generate_keypair()
        kid = encode_keri_key(pk)

        kel_data = create_signed_kel(
            keypairs=[(pk, sk)],
            timestamps=["2024-01-01T00:00:00Z"]
        )

        mock_result = OOBIResult(
            aid=kid,
            kel_data=kel_data,
            witnesses=[]
        )

        # Even with flag disabled, _allow_test_mode=True bypasses the gate
        with patch(
            "app.core.config.TIER2_KEL_RESOLUTION_ENABLED",
            False
        ):
            with patch(
                "app.vvp.keri.kel_resolver.dereference_oobi",
                new_callable=AsyncMock,
                return_value=mock_result
            ):
                key_state = await resolve_key_state(
                    kid=f"http://example.com/oobi/{kid}",
                    reference_time=datetime(2024, 6, 15),
                    min_witnesses=0,
                    _allow_test_mode=True  # Bypass the gate for testing
                )

        assert key_state.signing_keys == [pk]
