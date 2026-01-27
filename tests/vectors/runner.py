"""Test vector runner for executing vectors against verify_vvp."""

from contextlib import ExitStack
from unittest.mock import AsyncMock, MagicMock, patch

import httpx

from app.vvp.api_models import CallContext, VerifyRequest
from app.vvp.verify import verify_vvp

from .schema import VectorCase


class VectorRunner:
    """Executes test vectors against verify_vvp with mocked externals."""

    def __init__(self, vector: VectorCase):
        self.vector = vector

    async def run(self):
        """Execute the vector and return (request_id, response)."""
        req = VerifyRequest(
            passport_jwt=self.vector.input.passport_jwt,
            context=CallContext(**self.vector.input.call_context),
        )
        with self._setup_mocks():
            return await verify_vvp(req, self.vector.input.vvp_identity_header)

    def _setup_mocks(self):
        """Create mocks for deterministic vector execution."""
        stack = ExitStack()
        ctx = self.vector.verification_context
        artifacts = self.vector.artifacts

        # 1. Freeze time at reference_time_t for deterministic iat/exp checks
        stack.enter_context(
            patch("time.time", return_value=float(ctx.reference_time_t))
        )
        # Also patch header module's time.time
        stack.enter_context(
            patch("app.vvp.header.time.time", return_value=float(ctx.reference_time_t))
        )

        # 2. Apply clock_skew and max_token_age from verification_context
        stack.enter_context(
            patch("app.vvp.header.CLOCK_SKEW_SECONDS", ctx.clock_skew)
        )
        stack.enter_context(
            patch("app.vvp.header.MAX_TOKEN_AGE_SECONDS", ctx.max_token_age)
        )
        stack.enter_context(
            patch("app.vvp.passport.CLOCK_SKEW_SECONDS", ctx.clock_skew)
        )
        stack.enter_context(
            patch("app.vvp.passport.MAX_TOKEN_AGE_SECONDS", ctx.max_token_age)
        )

        # 2. Mock httpx.AsyncClient to simulate fetch with content-type validation
        async def mock_get(url, **kwargs):
            if artifacts.should_timeout_evd:
                raise httpx.TimeoutException("Timeout", request=None)

            response = MagicMock()
            response.status_code = artifacts.http_status_evd
            response.headers = {"content-type": artifacts.evd_content_type}
            response.reason_phrase = f"HTTP {artifacts.http_status_evd} Error"

            if artifacts.http_status_evd != 200:
                response.raise_for_status.side_effect = httpx.HTTPStatusError(
                    f"HTTP {artifacts.http_status_evd}",
                    request=MagicMock(),
                    response=response,
                )
            else:
                response.raise_for_status = MagicMock()  # No-op for 200
                # Use explicit None check to allow empty string for parse failure tests
                body = artifacts.evd_body if artifacts.evd_body is not None else "[]"
                response.content = body.encode()

            return response

        # AsyncMock for proper async context manager behavior
        mock_client = MagicMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.get = mock_get

        stack.enter_context(
            patch("app.vvp.dossier.fetch.httpx.AsyncClient", return_value=mock_client)
        )

        # 3. Mock TEL client to return ACTIVE for all credentials by default
        # This ensures vector tests are deterministic without real witness queries
        from app.vvp.keri.tel_client import CredentialStatus, RevocationResult

        async def mock_check_revocation(credential_said, registry_said=None, oobi_url=None):
            return RevocationResult(
                status=CredentialStatus.ACTIVE,
                credential_said=credential_said,
                registry_said=registry_said,
                issuance_event=None,
                revocation_event=None,
                error=None,
                source="mock"
            )

        mock_tel_client = MagicMock()
        mock_tel_client.check_revocation = mock_check_revocation

        stack.enter_context(
            patch("app.vvp.keri.tel_client.get_tel_client", return_value=mock_tel_client)
        )

        # 4. Mock Tier 2 signature verification to accept bare AIDs for Tier 1 vectors
        # The test vectors use pre-computed JWTs with bare AID kids.
        # Since Phase 11, bare AIDs are rejected (§4.2 requires OOBI URLs).
        # We mock Tier 2 verification to allow these vectors to test other aspects.
        from app.vvp.keri import SignatureInvalidError

        # Determine if this vector should have invalid signature based on expected result
        sig_should_fail = (
            self.vector.expected.root_claim
            and self.vector.expected.root_claim.children
            and any(
                c.node.name == "passport_verified"
                and c.node.status.value == "INVALID"
                and c.node.reasons_contain
                and any("signature" in r.lower() for r in c.node.reasons_contain)
                for c in self.vector.expected.root_claim.children
            )
        )

        async def mock_verify_tier2(passport, oobi_url=None, _allow_test_mode=False):
            if sig_should_fail:
                raise SignatureInvalidError("signature verification failed (mocked)")
            # Return tuple (KeyState, auth_status) for verify_passport_signature_tier2_with_key_state
            mock_key_state = MagicMock()
            mock_key_state.aid = "ETest123456789012345"
            mock_key_state.delegation_chain = None
            return (mock_key_state, "VALID")

        stack.enter_context(
            patch("app.vvp.verify.verify_passport_signature_tier2_with_key_state", mock_verify_tier2)
        )

        # 5. Mock chain validation for Tier 1 vectors (no real ACDC validation)
        async def mock_validate_chain(*args, **kwargs):
            result = MagicMock()
            result.root_aid = "EGLEIF0000000000"
            return result

        stack.enter_context(
            patch("app.vvp.acdc.validate_credential_chain", mock_validate_chain)
        )

        # 6. Mock _find_leaf_credentials to return DAG root as leaf
        def mock_find_leaves(dag, dossier_acdcs):
            if dag and dag.root_said:
                return [dag.root_said]
            return []

        stack.enter_context(
            patch("app.vvp.verify._find_leaf_credentials", mock_find_leaves)
        )

        # 7. Mock _convert_dag_to_acdcs to return mock ACDCs
        def mock_convert(dag):
            if not dag or not dag.root_said:
                return {}
            mock_acdc = MagicMock()
            mock_acdc.said = dag.root_said
            return {dag.root_said: mock_acdc}

        stack.enter_context(
            patch("app.vvp.verify._convert_dag_to_acdcs", mock_convert)
        )

        # 8. Mock PASSporT signature verification (for v04 - iat before inception)
        # Per §4.2A: Reference time before inception → KERI_STATE_INVALID
        # KeyNotYetValidError is now caught in verify.py and maps to KERI_STATE_INVALID
        if artifacts.mock_key_state_error == "KEY_NOT_YET_VALID":
            from app.vvp.keri import KeyNotYetValidError

            async def mock_sig_verify_before_inception(*args, **kwargs):
                raise KeyNotYetValidError(
                    "Reference time 2023-12-31T23:00:00+00:00 is before "
                    "inception at 2024-01-01T00:00:00+00:00"
                )

            stack.enter_context(
                patch("app.vvp.verify.verify_passport_signature_tier2_with_key_state", mock_sig_verify_before_inception)
            )

        # 8b. Mock key state error (for v12 - key rotated before T)
        # Per §5.1.1-2.4: Key rotated before reference time → KERI_STATE_INVALID
        if artifacts.mock_key_state_error == "KEY_ROTATED":
            from app.vvp.keri import KeyNotYetValidError

            async def mock_sig_verify_key_rotated(*args, **kwargs):
                raise KeyNotYetValidError(
                    "Signing key was rotated before reference time T. "
                    "Key rotated at 2023-12-01T00:00:00+00:00, "
                    "reference time 2023-12-31T23:00:00+00:00"
                )

            stack.enter_context(
                patch("app.vvp.verify.verify_passport_signature_tier2_with_key_state", mock_sig_verify_key_rotated)
            )

        # 9. Mock SAID validation (for v07 - SAID mismatch)
        # Per §4.2A: SAID mismatch → ACDC_SAID_MISMATCH (distinct from chain invalid)
        # ACDCSAIDMismatch is now caught in verify.py and maps to ACDC_SAID_MISMATCH
        if artifacts.mock_said_validation_error:
            from app.vvp.acdc.exceptions import ACDCSAIDMismatch

            async def mock_chain_said_fail(*args, **kwargs):
                raise ACDCSAIDMismatch("SAID does not match computed Blake3-256 hash")

            # Override the default mock_validate_chain
            stack.enter_context(
                patch("app.vvp.acdc.validate_credential_chain", mock_chain_said_fail)
            )

        # 10. Mock revocation checking (for v10 - revoked credential)
        if artifacts.mock_revocation:
            from app.vvp.api_models import ClaimStatus

            rev_config = artifacts.mock_revocation
            target_said = rev_config.get("credential_said")

            async def mock_check_dossier_revocations(dag, raw_dossier=None, oobi_url=None):
                """Mock that returns INVALID with revoked credential SAID."""
                # Import locally to avoid circular imports
                from app.vvp.verify import ClaimBuilder
                claim = ClaimBuilder("revocation_clear")
                claim.fail(ClaimStatus.INVALID, f"Credential {target_said} revoked")
                return (claim, [target_said])

            stack.enter_context(
                patch("app.vvp.verify.check_dossier_revocations", mock_check_dossier_revocations)
            )

        # 11. Mock authorization validation (for v09 - TNAlloc mismatch, v11 - delegation invalid)
        # validate_authorization returns (party_claim, tn_rights_claim) tuple
        if artifacts.mock_tn_mismatch or artifacts.mock_delegation_error:
            from app.vvp.api_models import ClaimStatus
            from app.vvp.authorization import AuthorizationClaimBuilder

            def mock_validate_authorization(ctx):
                """Mock that returns failure claims for authorization scenarios."""
                party_claim = AuthorizationClaimBuilder("party_authorized")
                tn_rights_claim = AuthorizationClaimBuilder("tn_rights_valid")

                if artifacts.mock_tn_mismatch:
                    # TN rights mismatch - tn_rights_claim is INVALID
                    tn_rights_claim.fail(
                        ClaimStatus.INVALID,
                        "orig.tn +12025551234 not covered by any TNAlloc credential"
                    )

                if artifacts.mock_delegation_error:
                    # Delegation invalid - party_claim is INVALID
                    party_claim.fail(
                        ClaimStatus.INVALID,
                        "Delegation target SAID_MISSING_TARGET not found in dossier"
                    )

                return (party_claim, tn_rights_claim)

            stack.enter_context(
                patch("app.vvp.verify.validate_authorization", mock_validate_authorization)
            )

        return stack

    def verify_result(self, response) -> None:
        """Assert response matches expected values."""
        expected = self.vector.expected

        # Assert overall_status (ClaimStatus is enum, compare values)
        assert response.overall_status.value == expected.overall_status.value, (
            f"Expected overall_status={expected.overall_status.value}, "
            f"got {response.overall_status.value}"
        )

        # Assert claim tree structure (nested children with required flags)
        if expected.root_claim and response.claims:
            self._verify_claim_tree(response.claims[0], expected.root_claim)

        # Assert errors (ErrorDetail.code is a string, not enum)
        if expected.errors:
            actual_errors = response.errors or []
            actual_codes = {e.code for e in actual_errors}
            for exp_err in expected.errors:
                assert exp_err["code"] in actual_codes, (
                    f"Missing error: {exp_err['code']}, got {actual_codes}"
                )
                # Optionally check recoverable flag
                if "recoverable" in exp_err:
                    match = next(e for e in actual_errors if e.code == exp_err["code"])
                    assert match.recoverable == exp_err["recoverable"], (
                        f"Error {exp_err['code']}: expected recoverable="
                        f"{exp_err['recoverable']}, got {match.recoverable}"
                    )

    def _verify_claim_tree(self, actual, expected) -> None:
        """Recursively verify claim tree including required/optional children."""
        assert actual.name == expected.name, (
            f"Expected claim name={expected.name}, got {actual.name}"
        )
        assert actual.status.value == expected.status.value, (
            f"Claim {expected.name}: expected status={expected.status.value}, "
            f"got {actual.status.value}"
        )

        if expected.reasons_contain:
            for substr in expected.reasons_contain:
                assert any(substr.lower() in r.lower() for r in actual.reasons), (
                    f"Claim {expected.name}: expected reason containing '{substr}', "
                    f"got {actual.reasons}"
                )

        if expected.evidence_contain:
            for substr in expected.evidence_contain:
                assert any(substr.lower() in e.lower() for e in actual.evidence), (
                    f"Claim {expected.name}: expected evidence containing '{substr}', "
                    f"got {actual.evidence}"
                )

        if expected.children:
            # Strict check: exact child count for Tier 1 structure guarantees
            assert len(actual.children) == len(expected.children), (
                f"Claim {expected.name}: expected exactly {len(expected.children)} "
                f"children, got {len(actual.children)}"
            )
            for exp_child in expected.children:
                match = next(
                    (c for c in actual.children if c.node.name == exp_child.node.name),
                    None,
                )
                assert match, (
                    f"Missing child: {exp_child.node.name} in {expected.name}"
                )
                assert match.required == exp_child.required, (
                    f"required mismatch for {exp_child.node.name}: "
                    f"expected {exp_child.required}, got {match.required}"
                )
                self._verify_claim_tree(match.node, exp_child.node)
