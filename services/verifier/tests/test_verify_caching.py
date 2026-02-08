"""Integration tests for Sprint 51: Verification Result Cache with verify_vvp().

Tests cache hit/miss flows, revocation staleness, feature flag, TTL,
config fingerprint, and deep-copy isolation through the full verify_vvp() pipeline.
"""

import asyncio
import copy
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.vvp.api_models import (
    CallContext,
    ClaimStatus,
    VerifyRequest,
)
from app.vvp.verify import verify_vvp


# =============================================================================
# Shared fixtures
# =============================================================================

EVD_URL = "http://cache-integration.example.com/dossier.cesr"
SIGNER_AID = "EAbcCacheTest12345"
PASSPORT_KID = f"http://witness.example.com/oobi/{SIGNER_AID}/witness/EXyz"


@pytest.fixture
def valid_context():
    return CallContext(call_id="cache-test-123", received_at="2024-01-01T00:00:00Z")


def _patch_full_pipeline():
    """Return a context manager that patches all 12 verify_vvp dependencies.

    Returns a dict-like object (patch dict) after __enter__.
    """
    return _PatchedPipeline()


class _PatchedPipeline:
    """Context manager wrapping all the patches needed for a full VALID pipeline."""

    def __init__(self):
        self.mocks = {}
        self._patches = []

    def __enter__(self):
        sync_targets = {
            "vvp": "app.vvp.verify.parse_vvp_identity",
            "passport": "app.vvp.verify.parse_passport",
            "binding": "app.vvp.verify.validate_passport_binding",
            "fetch": "app.vvp.verify.fetch_dossier",
            "parse": "app.vvp.verify.parse_dossier",
            "build": "app.vvp.verify.build_dag",
            "validate": "app.vvp.verify.validate_dag",
            "find_leaves": "app.vvp.verify._find_leaf_credentials",
            "convert": "app.vvp.verify._convert_dag_to_acdcs",
            "auth": "app.vvp.verify.validate_authorization",
        }
        async_targets = {
            "sig": "app.vvp.verify.verify_passport_signature_tier2_with_key_state",
            "chain": "app.vvp.acdc.validate_credential_chain",
            "revocation": "app.vvp.verify.check_dossier_revocations",
        }
        for name, target in sync_targets.items():
            p = patch(target)
            self.mocks[name] = p.start()
            self._patches.append(p)
        for name, target in async_targets.items():
            p = patch(target, new_callable=AsyncMock)
            self.mocks[name] = p.start()
            self._patches.append(p)

        self._configure_valid_defaults()
        return self

    def __exit__(self, *args):
        for p in self._patches:
            p.stop()

    def _configure_valid_defaults(self):
        m = self.mocks
        m["vvp"].return_value = MagicMock(evd=EVD_URL)

        m["passport"].return_value = MagicMock(
            header=MagicMock(kid=PASSPORT_KID),
            payload=MagicMock(orig={"tn": ["+15551234567"]}, card=None, goal=None),
        )
        m["binding"].return_value = None
        m["sig"].return_value = (
            MagicMock(aid=SIGNER_AID, delegation_chain=None),
            "VALID",
        )

        m["fetch"].return_value = b"[]"
        m["parse"].return_value = ([], {})
        dag = MagicMock()
        dag.root_said = "SAID_ROOT_CACHE"
        dag.is_aggregate = False
        dag.nodes = {"SAID_ROOT_CACHE": MagicMock()}
        dag.warnings = []
        m["build"].return_value = dag
        m["validate"].return_value = None

        m["find_leaves"].return_value = ["SAID_ROOT_CACHE"]
        acdc = MagicMock()
        acdc.said = "SAID_ROOT_CACHE"
        m["convert"].return_value = {"SAID_ROOT_CACHE": acdc}

        chain_result = MagicMock()
        chain_result.root_aid = "EGLEIF0000000000"
        chain_result.validated = True
        chain_result.has_variant_limitations = False
        chain_result.status = "VALID"
        m["chain"].return_value = chain_result

        from app.vvp.authorization import AuthorizationClaimBuilder

        party = AuthorizationClaimBuilder("party_authorized")
        tn = AuthorizationClaimBuilder("tn_rights_valid")
        m["auth"].return_value = (party, tn)

        # Phase 9: Mock check_dossier_revocations to return VALID (no revocations)
        from app.vvp.verify import ClaimBuilder

        revocation_claim = ClaimBuilder("revocation_clear")
        revocation_claim.add_evidence("all_credentials_unrevoked")
        m["revocation"].return_value = (revocation_claim, [])


# =============================================================================
# Tests
# =============================================================================


class TestVerifyCachingIntegration:
    """Integration tests for the verification result cache through verify_vvp()."""

    @pytest.mark.asyncio
    async def test_first_call_stores_in_cache(self, valid_context):
        """First VALID verification stores result in cache."""
        with _PatchedPipeline() as pp:
            req = VerifyRequest(passport_jwt="jwt1", context=valid_context)
            _, resp = await verify_vvp(req, "header1")

            assert resp.overall_status == ClaimStatus.VALID

            # Cache should have one entry
            from app.vvp.verification_cache import get_verification_cache

            cache = get_verification_cache()
            entry = await cache.get(EVD_URL, PASSPORT_KID)
            assert entry is not None
            assert entry.dossier_url == EVD_URL
            assert entry.passport_kid == PASSPORT_KID

    @pytest.mark.asyncio
    async def test_second_call_hits_cache(self, valid_context):
        """Second call with same inputs skips expensive phases."""
        with _PatchedPipeline() as pp:
            req = VerifyRequest(passport_jwt="jwt1", context=valid_context)

            # First call — full pipeline
            _, resp1 = await verify_vvp(req, "header1")
            assert resp1.overall_status == ClaimStatus.VALID

            # Record call counts
            fetch_calls_after_first = pp.mocks["fetch"].call_count
            chain_calls_after_first = pp.mocks["chain"].call_count

            # Second call — should hit cache
            _, resp2 = await verify_vvp(req, "header1")
            assert resp2.overall_status == ClaimStatus.VALID

            # fetch_dossier and chain validation should NOT be called again
            assert pp.mocks["fetch"].call_count == fetch_calls_after_first
            assert pp.mocks["chain"].call_count == chain_calls_after_first

            # Response should contain cache_hit evidence
            dossier_claim = resp2.claims[0].children[1].node
            evidence_str = " ".join(dossier_claim.evidence)
            assert "cache_hit:dossier_verification" in evidence_str

    @pytest.mark.asyncio
    async def test_different_kid_is_cache_miss(self, valid_context):
        """Different passport kid → separate cache entry (verification cache miss)."""
        with _PatchedPipeline() as pp:
            req = VerifyRequest(passport_jwt="jwt1", context=valid_context)

            # First call
            _, resp1 = await verify_vvp(req, "header1")
            assert resp1.overall_status == ClaimStatus.VALID
            chain_calls_1 = pp.mocks["chain"].call_count

            # Change passport kid
            other_kid = "http://other-witness.example.com/oobi/EDifferent123/witness/EXyz"
            pp.mocks["passport"].return_value = MagicMock(
                header=MagicMock(kid=other_kid),
                payload=MagicMock(
                    orig={"tn": ["+15551234567"]}, card=None, goal=None
                ),
            )

            # Second call — different kid should miss verification cache
            _, resp2 = await verify_vvp(req, "header1")

            # Chain validation SHOULD be called again (verification cache miss)
            # Note: dossier-level cache may still hit (same URL), but chain is re-run
            assert pp.mocks["chain"].call_count > chain_calls_1

    @pytest.mark.asyncio
    async def test_invalid_chain_not_cached(self, valid_context):
        """INVALID chain result is NOT cached (VALID-only policy)."""
        with _PatchedPipeline() as pp:
            from app.vvp.acdc import ACDCChainInvalid

            pp.mocks["chain"].side_effect = ACDCChainInvalid("No trusted root")

            req = VerifyRequest(passport_jwt="jwt1", context=valid_context)
            _, resp = await verify_vvp(req, "header1")

            # Should be INVALID
            assert resp.overall_status == ClaimStatus.INVALID

            # Cache should be empty (INVALID not stored)
            from app.vvp.verification_cache import get_verification_cache

            cache = get_verification_cache()
            entry = await cache.get(EVD_URL, PASSPORT_KID)
            assert entry is None

    @pytest.mark.asyncio
    async def test_passport_failure_skips_cache_check(self, valid_context):
        """Fatal passport error skips cache check entirely."""
        with _PatchedPipeline() as pp:
            from app.vvp.exceptions import PassportError

            pp.mocks["passport"].side_effect = PassportError.parse_failed("bad jwt")

            req = VerifyRequest(passport_jwt="bad", context=valid_context)
            _, resp = await verify_vvp(req, "header1")

            assert resp.overall_status == ClaimStatus.INVALID

            # Cache should be empty
            from app.vvp.verification_cache import get_verification_cache

            cache = get_verification_cache()
            assert cache.metrics().hits == 0
            assert cache.metrics().misses == 0  # Never checked

    @pytest.mark.asyncio
    async def test_cache_disabled_via_feature_flag(self, valid_context):
        """Cache disabled → chain validation runs on every call."""
        with _PatchedPipeline() as pp:
            with patch(
                "app.core.config.VVP_VERIFICATION_CACHE_ENABLED", False
            ):
                req = VerifyRequest(passport_jwt="jwt1", context=valid_context)

                # First call
                _, resp1 = await verify_vvp(req, "header1")
                assert resp1.overall_status == ClaimStatus.VALID
                chain_count = pp.mocks["chain"].call_count

                # Second call — chain validation re-runs (no verification cache)
                _, resp2 = await verify_vvp(req, "header1")
                assert pp.mocks["chain"].call_count > chain_count

    @pytest.mark.asyncio
    async def test_cache_hit_with_fresh_unrevoked(self, valid_context):
        """Cache hit with fresh UNREVOKED revocation → VALID, no pending."""
        with _PatchedPipeline() as pp:
            req = VerifyRequest(passport_jwt="jwt1", context=valid_context)

            # First call — populates cache with UNREVOKED
            _, resp1 = await verify_vvp(req, "header1")
            assert resp1.overall_status == ClaimStatus.VALID

            # Second call — cache hit, fresh revocation
            _, resp2 = await verify_vvp(req, "header1")
            assert resp2.overall_status == ClaimStatus.VALID
            assert resp2.revocation_pending is False

    @pytest.mark.asyncio
    async def test_cache_hit_stale_revocation_is_indeterminate(self, valid_context):
        """Cache hit with stale revocation data → INDETERMINATE."""
        with _PatchedPipeline() as pp:
            req = VerifyRequest(passport_jwt="jwt1", context=valid_context)

            # First call
            _, resp1 = await verify_vvp(req, "header1")
            assert resp1.overall_status == ClaimStatus.VALID

            # Manually make revocation timestamp stale
            from app.vvp.verification_cache import get_verification_cache

            cache = get_verification_cache()
            async with cache._lock:
                for key, entry in cache._cache.items():
                    if key[0] == EVD_URL:
                        entry.revocation_last_checked = time.time() - 600.0

            # Second call — stale revocation → INDETERMINATE
            _, resp2 = await verify_vvp(req, "header1")

            # The revocation claim should be INDETERMINATE
            dossier_claim = resp2.claims[0].children[1].node
            revocation_claim = dossier_claim.children[1].node  # chain_verified, revocation_clear
            assert revocation_claim.status == ClaimStatus.INDETERMINATE

    @pytest.mark.asyncio
    async def test_cache_hit_with_revoked_credential(self, valid_context):
        """Cache hit with REVOKED credential → INVALID + error."""
        with _PatchedPipeline() as pp:
            req = VerifyRequest(passport_jwt="jwt1", context=valid_context)

            # First call — populates cache
            _, resp1 = await verify_vvp(req, "header1")
            assert resp1.overall_status == ClaimStatus.VALID

            # Manually mark credential as REVOKED in cache
            from app.vvp.verification_cache import (
                RevocationStatus,
                get_verification_cache,
            )

            cache = get_verification_cache()
            async with cache._lock:
                for key, entry in cache._cache.items():
                    if key[0] == EVD_URL:
                        for said in entry.contained_saids:
                            entry.credential_revocation_status[said] = (
                                RevocationStatus.REVOKED
                            )

            # Second call — cached revocation is REVOKED
            _, resp2 = await verify_vvp(req, "header1")

            assert resp2.overall_status == ClaimStatus.INVALID
            # Should have CREDENTIAL_REVOKED error
            assert any(
                e.code == "CREDENTIAL_REVOKED" for e in (resp2.errors or [])
            )

    @pytest.mark.asyncio
    async def test_cache_hit_undefined_revocation_sets_pending(self, valid_context):
        """Cache hit with UNDEFINED revocation → INDETERMINATE + revocation_pending."""
        with _PatchedPipeline() as pp:
            req = VerifyRequest(passport_jwt="jwt1", context=valid_context)

            # First call
            _, resp1 = await verify_vvp(req, "header1")

            # Manually set credential to UNDEFINED
            from app.vvp.verification_cache import (
                RevocationStatus,
                get_verification_cache,
            )

            cache = get_verification_cache()
            async with cache._lock:
                for key, entry in cache._cache.items():
                    if key[0] == EVD_URL:
                        for said in entry.contained_saids:
                            entry.credential_revocation_status[said] = (
                                RevocationStatus.UNDEFINED
                            )

            # Second call — UNDEFINED → pending
            _, resp2 = await verify_vvp(req, "header1")

            assert resp2.revocation_pending is True

    @pytest.mark.asyncio
    async def test_cache_metrics_increment(self, valid_context):
        """Cache metrics track hits and misses correctly."""
        with _PatchedPipeline() as pp:
            req = VerifyRequest(passport_jwt="jwt1", context=valid_context)

            from app.vvp.verification_cache import get_verification_cache

            cache = get_verification_cache()

            # First call → miss (nothing in cache yet) + put
            _, _ = await verify_vvp(req, "header1")
            assert cache.metrics().misses == 1
            assert cache.metrics().hits == 0

            # Second call → hit
            _, _ = await verify_vvp(req, "header1")
            assert cache.metrics().hits == 1

    @pytest.mark.asyncio
    async def test_deep_copy_isolation(self, valid_context):
        """Mutating cache-hit response doesn't affect next cache read."""
        with _PatchedPipeline() as pp:
            req = VerifyRequest(passport_jwt="jwt1", context=valid_context)

            # Populate cache
            _, resp1 = await verify_vvp(req, "header1")

            # Mutate the response's chain claim
            chain_claim = resp1.claims[0].children[1].node.children[0].node
            chain_claim.reasons.append("MUTATED")

            # Next call should get a clean copy
            _, resp2 = await verify_vvp(req, "header1")
            chain_claim2 = resp2.claims[0].children[1].node.children[0].node
            assert "MUTATED" not in chain_claim2.reasons

    @pytest.mark.asyncio
    async def test_cache_ttl_eviction(self, valid_context):
        """Expired TTL → verification cache miss, chain re-runs."""
        with _PatchedPipeline() as pp:
            req = VerifyRequest(passport_jwt="jwt1", context=valid_context)

            # First call
            _, _ = await verify_vvp(req, "header1")
            chain_count = pp.mocks["chain"].call_count

            # Manually set created_at to past (beyond 3600s TTL)
            from app.vvp.verification_cache import get_verification_cache

            cache = get_verification_cache()
            async with cache._lock:
                for key, entry in cache._cache.items():
                    entry.created_at = time.time() - 7200.0  # 2 hours ago

            # Second call — should miss due to TTL
            _, _ = await verify_vvp(req, "header1")

            # Chain validation should be called again (verification cache miss)
            assert pp.mocks["chain"].call_count > chain_count

    @pytest.mark.asyncio
    async def test_config_fingerprint_mismatch(self, valid_context):
        """Config fingerprint change → verification cache miss, chain re-runs."""
        with _PatchedPipeline() as pp:
            req = VerifyRequest(passport_jwt="jwt1", context=valid_context)

            # First call
            _, _ = await verify_vvp(req, "header1")
            chain_count = pp.mocks["chain"].call_count

            # Manually change config fingerprint in cached entry
            from app.vvp.verification_cache import get_verification_cache

            cache = get_verification_cache()
            async with cache._lock:
                for key, entry in cache._cache.items():
                    entry.config_fingerprint = "deadbeef12345678"

            # Second call — fingerprint mismatch → miss
            _, _ = await verify_vvp(req, "header1")

            assert pp.mocks["chain"].call_count > chain_count

    @pytest.mark.asyncio
    async def test_authorization_always_recomputed(self, valid_context):
        """Authorization phases run on every call, even on cache hit."""
        with _PatchedPipeline() as pp:
            req = VerifyRequest(passport_jwt="jwt1", context=valid_context)

            # First call
            _, _ = await verify_vvp(req, "header1")
            auth_calls_1 = pp.mocks["auth"].call_count

            # Second call (cache hit)
            _, _ = await verify_vvp(req, "header1")

            # Authorization should be called again
            assert pp.mocks["auth"].call_count > auth_calls_1

    @pytest.mark.asyncio
    async def test_revocation_pending_false_on_first_call(self, valid_context):
        """First call (cache miss) should not set revocation_pending."""
        with _PatchedPipeline() as pp:
            req = VerifyRequest(passport_jwt="jwt1", context=valid_context)
            _, resp = await verify_vvp(req, "header1")

            assert resp.revocation_pending is False
