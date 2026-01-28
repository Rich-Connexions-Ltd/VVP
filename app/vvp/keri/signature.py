"""Ed25519 signature verification for VVP PASSporTs.

Tier 1 implementation: Direct verification using public key embedded in KERI AID.
Tier 2 implementation: Resolve key state at reference time T via KEL lookup.

Note: pysodium is imported lazily inside functions to:
1. Avoid import errors when libsodium is not available at module load time
2. Enable testing of code paths that don't require signature verification
"""

from datetime import datetime, timezone
from typing import Optional

from app.vvp.passport import Passport
from .key_parser import parse_kid_to_verkey
from .exceptions import SignatureInvalidError


def verify_passport_signature(passport: Passport) -> None:
    """Verify PASSporT signature using Ed25519 (Tier 1).

    The signing input for JWT is: base64url(header).base64url(payload)
    The signature is verified against this input using the public key
    extracted from the kid field.

    Args:
        passport: Parsed Passport with raw_header, raw_payload, signature.

    Raises:
        SignatureInvalidError: Signature cryptographically invalid (→ INVALID).
        ResolutionFailedError: Could not resolve/parse kid to key (→ INDETERMINATE).

    Note:
        Tier 1 does not validate key state at time T (iat).
        It assumes the key embedded in the AID is currently valid.
    """
    # Step 1: Parse kid to get verification key
    # This may raise ResolutionFailedError (recoverable → INDETERMINATE)
    verkey = parse_kid_to_verkey(passport.header.kid)

    # Step 2: Reconstruct JWT signing input: header.payload (ASCII bytes)
    # Per JWT spec, the signature covers the exact base64url-encoded strings
    signing_input = f"{passport.raw_header}.{passport.raw_payload}".encode("ascii")

    # Step 3: Verify signature using pysodium (libsodium)
    import pysodium
    try:
        # pysodium.crypto_sign_verify_detached raises ValueError if invalid
        pysodium.crypto_sign_verify_detached(
            passport.signature,
            signing_input,
            verkey.raw
        )
    except Exception:
        # Any verification failure is a cryptographic failure → INVALID
        raise SignatureInvalidError(
            f"Ed25519 signature verification failed for kid={passport.header.kid[:20]}..."
        )


async def _verify_passport_signature_tier2_impl(
    passport: Passport,
    reference_time: Optional[datetime] = None,
    oobi_url: Optional[str] = None,
    min_witnesses: Optional[int] = None,
    _allow_test_mode: bool = False
) -> tuple:
    """Internal Tier 2 implementation returning (KeyState, authorization_status).

    Refactored as shared implementation per Sprint 25 plan to avoid duplication.
    Both verify_passport_signature_tier2() and verify_passport_signature_tier2_with_key_state()
    use this internal function.

    Args:
        passport: Parsed Passport with raw_header, raw_payload, signature.
        reference_time: Reference time T (defaults to passport.payload.iat).
        oobi_url: Optional OOBI URL for fetching KEL.
        min_witnesses: Minimum witness receipts required.
        _allow_test_mode: Internal flag to bypass feature gate in tests.

    Returns:
        Tuple of (KeyState, authorization_status) where:
        - KeyState: Resolved key state with delegation_chain populated if delegated
        - authorization_status: "VALID", "INVALID", or "INDETERMINATE"

    Raises:
        ResolutionFailedError: If TIER2_KEL_RESOLUTION_ENABLED is False.
        SignatureInvalidError: Signature cryptographically invalid (→ INVALID).
        KELChainInvalidError: KEL chain validation failed (→ INVALID).
        KeyNotYetValidError: No valid key state at reference time (→ INVALID).
        ResolutionFailedError: Could not resolve key state (→ INDETERMINATE).
    """
    from app.core.config import TIER2_KEL_RESOLUTION_ENABLED
    from .kel_resolver import resolve_key_state, resolve_key_state_with_kel, KeyState
    from .exceptions import ResolutionFailedError, KELChainInvalidError
    from .delegation import resolve_delegation_chain, validate_delegation_authorization
    from ..api_models import ClaimStatus

    # Feature gate check
    if not TIER2_KEL_RESOLUTION_ENABLED and not _allow_test_mode:
        raise ResolutionFailedError(
            "Tier 2 KEL resolution is disabled. "
            "Set TIER2_KEL_RESOLUTION_ENABLED=true to enable KERI-based "
            "key state resolution."
        )

    # Use iat as reference time if not specified
    # Use UTC to ensure consistent timezone handling
    if reference_time is None:
        reference_time = datetime.fromtimestamp(passport.payload.iat, tz=timezone.utc)

    # Resolve key state at reference time T
    # This may raise various exceptions that map to claim statuses
    key_state = await resolve_key_state(
        kid=passport.header.kid,
        reference_time=reference_time,
        oobi_url=oobi_url,
        min_witnesses=min_witnesses,
        _allow_test_mode=_allow_test_mode
    )

    # Track authorization status for delegation (VALID if non-delegated)
    authorization_status = "VALID"

    # Validate delegation chain if this is a delegated identifier
    # Per KERI spec, delegated identifiers (dip/drt) must have their
    # delegation chain resolved and authorized
    if key_state.is_delegated and key_state.inception_event:
        # Create OOBI resolver for delegation chain resolution
        async def oobi_resolver(aid: str, ref_time: datetime) -> KeyState:
            """Resolve delegator's key state via OOBI."""
            # Construct OOBI URL from base URL pattern
            delegator_oobi = None
            if oobi_url:
                # Replace AID in OOBI path with delegator AID
                from urllib.parse import urlparse
                parsed = urlparse(oobi_url)
                delegator_oobi = f"{parsed.scheme}://{parsed.netloc}/oobi/{aid}"

            return await resolve_key_state(
                kid=aid,
                reference_time=ref_time,
                oobi_url=delegator_oobi,
                min_witnesses=min_witnesses,
                _allow_test_mode=_allow_test_mode
            )

        try:
            # Resolve delegation chain to non-delegated root
            # This validates: no cycles, max depth, delegator resolvable
            delegation_chain = await resolve_delegation_chain(
                delegated_aid=key_state.aid,
                inception_event=key_state.inception_event,
                reference_time=reference_time,
                oobi_resolver=oobi_resolver
            )

            # Store delegation chain in key state for downstream use
            key_state.delegation_chain = delegation_chain

            if not delegation_chain.valid:
                raise KELChainInvalidError(
                    f"Delegation chain invalid: {', '.join(delegation_chain.errors)}"
                )

            # Validate delegation authorization (anchor seal + signature)
            # Per KERI spec, the delegator must authorize the delegation via
            # an interaction event (ixn) containing a seal with the delegation SAID
            delegator_aid = key_state.delegator_aid
            if delegator_aid:
                # Construct delegator OOBI URL
                delegator_oobi = None
                if oobi_url:
                    from urllib.parse import urlparse
                    parsed = urlparse(oobi_url)
                    delegator_oobi = f"{parsed.scheme}://{parsed.netloc}/oobi/{delegator_aid}"

                # Fetch delegator's key state AND full KEL for authorization check
                delegator_key_state, delegator_kel = await resolve_key_state_with_kel(
                    kid=delegator_aid,
                    reference_time=reference_time,
                    oobi_url=delegator_oobi,
                    min_witnesses=min_witnesses,
                    _allow_test_mode=_allow_test_mode
                )

                # Validate that delegator authorized this delegation
                is_authorized, auth_status, auth_errors = await validate_delegation_authorization(
                    delegation_event=key_state.inception_event,
                    delegator_kel=delegator_kel,
                    delegator_key_state=delegator_key_state
                )

                if not is_authorized:
                    if auth_status == ClaimStatus.INVALID:
                        authorization_status = "INVALID"
                        raise KELChainInvalidError(
                            f"Delegation not authorized: {'; '.join(auth_errors)}"
                        )
                    else:
                        # INDETERMINATE - delegator KEL may be incomplete
                        authorization_status = "INDETERMINATE"
                        raise ResolutionFailedError(
                            f"Cannot verify delegation authorization: {'; '.join(auth_errors)}"
                        )

        except KELChainInvalidError:
            # Re-raise KEL chain errors as-is (maps to INVALID)
            authorization_status = "INVALID"
            raise
        except ResolutionFailedError:
            # Re-raise resolution errors as-is (maps to INDETERMINATE)
            authorization_status = "INDETERMINATE"
            raise
        except Exception as e:
            # Unexpected delegation error - wrap in ResolutionFailedError
            authorization_status = "INDETERMINATE"
            raise ResolutionFailedError(
                f"Delegation validation failed: {e}"
            )

    # Reconstruct JWT signing input
    signing_input = f"{passport.raw_header}.{passport.raw_payload}".encode("ascii")

    # Verify signature against all signing keys from the resolved state
    # At least one key must validate the signature
    import pysodium
    signature_valid = False

    for signing_key in key_state.signing_keys:
        try:
            pysodium.crypto_sign_verify_detached(
                passport.signature,
                signing_input,
                signing_key
            )
            signature_valid = True
            break
        except Exception:
            continue

    if not signature_valid:
        raise SignatureInvalidError(
            f"Ed25519 signature verification failed for kid={passport.header.kid[:20]}... "
            f"at reference time {reference_time.isoformat()} "
            f"(key state seq={key_state.sequence})"
        )

    return key_state, authorization_status


async def verify_passport_signature_tier2(
    passport: Passport,
    reference_time: Optional[datetime] = None,
    oobi_url: Optional[str] = None,
    min_witnesses: Optional[int] = None,
    _allow_test_mode: bool = False
) -> None:
    """Verify PASSporT signature using historical key state (Tier 2).

    Resolves the key state at reference time T (default: passport iat),
    validates the KEL chain, and verifies the signature against the
    historical key state.

    Per spec §5A Step 4: "Resolve issuer key state at reference time T"

    Features:
    - CESR binary format (application/cesr, application/json+cesr)
    - KERI-compliant canonicalization with proper field ordering
    - SAID validation using Blake3-256
    - Witness receipt signature validation

    For delegated identifiers (dip/drt events), this function also:
    - Resolves the full delegation chain to the non-delegated root
    - Validates each delegation is properly authorized by anchor events
    Per KERI spec, delegated identifiers require authorization from their
    delegator via an interaction event containing a seal.

    Args:
        passport: Parsed Passport with raw_header, raw_payload, signature.
        reference_time: Reference time T (defaults to passport.payload.iat).
        oobi_url: Optional OOBI URL for fetching KEL.
        min_witnesses: Minimum witness receipts required.
        _allow_test_mode: Internal flag to bypass feature gate in tests.

    Raises:
        ResolutionFailedError: If TIER2_KEL_RESOLUTION_ENABLED is False.
        SignatureInvalidError: Signature cryptographically invalid (→ INVALID).
        KELChainInvalidError: KEL chain validation failed (→ INVALID).
        KeyNotYetValidError: No valid key state at reference time (→ INVALID).
        ResolutionFailedError: Could not resolve key state (→ INDETERMINATE).
    """
    # Delegate to shared implementation
    await _verify_passport_signature_tier2_impl(
        passport=passport,
        reference_time=reference_time,
        oobi_url=oobi_url,
        min_witnesses=min_witnesses,
        _allow_test_mode=_allow_test_mode
    )


async def verify_passport_signature_tier2_with_key_state(
    passport: Passport,
    reference_time: Optional[datetime] = None,
    oobi_url: Optional[str] = None,
    min_witnesses: Optional[int] = None,
    _allow_test_mode: bool = False
) -> tuple:
    """Verify PASSporT signature and return KeyState with authorization status.

    Sprint 25: Enables caller to access KeyState.delegation_chain and the
    authorization outcome without catching exceptions. Used by UI endpoints
    to surface delegation chain visualization.

    Args:
        passport: Parsed Passport with raw_header, raw_payload, signature.
        reference_time: Reference time T (defaults to passport.payload.iat).
        oobi_url: Optional OOBI URL for fetching KEL.
        min_witnesses: Minimum witness receipts required.
        _allow_test_mode: Internal flag to bypass feature gate in tests.

    Returns:
        Tuple of (KeyState, authorization_status) where:
        - KeyState: Resolved key state with delegation_chain populated if delegated
        - authorization_status: "VALID", "INVALID", or "INDETERMINATE"

    Raises:
        ResolutionFailedError: If TIER2_KEL_RESOLUTION_ENABLED is False.
        SignatureInvalidError: Signature cryptographically invalid (→ INVALID).
        KELChainInvalidError: KEL chain validation failed (→ INVALID).
        KeyNotYetValidError: No valid key state at reference time (→ INVALID).
        ResolutionFailedError: Could not resolve key state (→ INDETERMINATE).
    """
    return await _verify_passport_signature_tier2_impl(
        passport=passport,
        reference_time=reference_time,
        oobi_url=oobi_url,
        min_witnesses=min_witnesses,
        _allow_test_mode=_allow_test_mode
    )
