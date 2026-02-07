"""Dossier caching and revocation checking for VVP signing.

Before signing a PASSporT, checks whether any credential in the
dossier chain has been revoked. Policy: unknown status = TRUSTED
(allow call to proceed); REVOKED = UNTRUSTED (reject signing).

The issuer is simpler than the verifier:
- It doesn't need to *fetch* dossiers over HTTP (it created them)
- On cache miss it uses its own DossierBuilder to resolve the chain
- Background revocation checks use the common TELClient
"""

import logging
import time
from typing import Optional, Tuple

from common.vvp.dossier.cache import CachedDossier, DossierCache
from common.vvp.dossier.config import DOSSIER_CACHE_MAX_ENTRIES, DOSSIER_CACHE_TTL_SECONDS
from common.vvp.dossier.trust import TrustDecision, revocation_to_trust
from common.vvp.keri.tel_client import ChainExtractionResult
from common.vvp.models.dossier import ACDCNode, DossierDAG

log = logging.getLogger(__name__)

# Module-level cache singleton
_cache: Optional[DossierCache] = None


def get_issuer_dossier_cache() -> DossierCache:
    """Get or create the issuer's dossier cache singleton.

    The issuer does not have its own WitnessPool, so we don't inject
    a tel_client_factory — the common DossierCache will use its own
    fallback (common.vvp.keri.tel_client.get_tel_client).
    """
    global _cache
    if _cache is None:
        _cache = DossierCache(
            ttl_seconds=DOSSIER_CACHE_TTL_SECONDS,
            max_entries=DOSSIER_CACHE_MAX_ENTRIES,
        )
    return _cache


def reset_issuer_dossier_cache() -> None:
    """Reset the dossier cache singleton (for testing)."""
    global _cache
    _cache = None


async def check_dossier_revocation(
    dossier_url: str,
    dossier_said: str,
) -> Tuple[TrustDecision, Optional[str]]:
    """Check dossier revocation status with caching.

    Flow:
    1. Check cache for existing entry by URL
    2. If hit with revocation result: return trust decision
    3. If hit without revocation result: TRUSTED (still pending)
    4. If miss: build chain from local credentials, populate cache,
       start background revocation check, return TRUSTED

    Args:
        dossier_url: Dossier URL (evd field value).
        dossier_said: Root credential SAID (used to resolve chain on miss).

    Returns:
        Tuple of (TrustDecision, Optional[warning_message])
        - TRUSTED: Safe to sign (active or unknown/pending status)
        - UNTRUSTED: Revoked credentials detected, reject signing
    """
    cache = get_issuer_dossier_cache()

    # Check cache for existing entry
    cached = await cache.get(dossier_url)
    if cached is not None:
        trust = revocation_to_trust(cached.chain_revocation)
        if trust == TrustDecision.UNTRUSTED:
            log.warning(f"Revoked credential detected: {dossier_url[:50]}...")
            return trust, "Credential chain contains revoked credentials"
        if cached.chain_revocation is None:
            return TrustDecision.TRUSTED, "Revocation status still pending"
        return TrustDecision.TRUSTED, None

    # Cache miss — resolve chain from local credentials and populate cache
    log.info(f"Dossier cache miss, resolving chain: {dossier_said[:16]}...")
    try:
        cached_dossier, chain_info = await _build_cache_entry(dossier_said)
    except Exception as e:
        log.warning(f"Failed to resolve dossier chain for revocation: {e}")
        return TrustDecision.TRUSTED, f"Chain resolution failed: {e}"

    # Store in cache with auto-start background revocation check
    await cache.put(
        url=dossier_url,
        dossier=cached_dossier,
        chain_info=chain_info,
    )

    log.info(
        f"Dossier cached with {len(cached_dossier.contained_saids)} SAIDs, "
        f"background revocation started: {dossier_url[:50]}..."
    )
    return TrustDecision.TRUSTED, "First request - revocation check started in background"


async def _build_cache_entry(
    dossier_said: str,
) -> Tuple[CachedDossier, ChainExtractionResult]:
    """Build a CachedDossier and ChainExtractionResult from local credentials.

    Uses the issuer's DossierBuilder to resolve the credential chain,
    then constructs the structures needed by DossierCache.

    Args:
        dossier_said: Root credential SAID.

    Returns:
        Tuple of (CachedDossier, ChainExtractionResult).
    """
    from app.dossier.builder import get_dossier_builder
    from app.keri.issuer import get_credential_issuer

    builder = await get_dossier_builder()
    issuer = await get_credential_issuer()

    # Build dossier content (resolves edge chain via DFS)
    content = await builder.build(dossier_said, include_tel=False)

    # Build DossierDAG from credential chain
    dag = DossierDAG(
        root_said=dossier_said,
        root_saids=[dossier_said],
    )
    for said in content.credential_saids:
        cred_info = await issuer.get_credential(said)
        if cred_info:
            dag.nodes[said] = ACDCNode(
                said=said,
                issuer=cred_info.issuer_aid,
                schema=cred_info.schema_said,
                attributes=cred_info.attributes or {},
                edges=cred_info.edges,
                rules=cred_info.rules,
            )

    # Build ChainExtractionResult (maps SAIDs to registry SAIDs)
    registry_saids = {}
    for said in content.credential_saids:
        cred_info = await issuer.get_credential(said)
        if cred_info:
            registry_saids[said] = cred_info.registry_key

    chain_info = ChainExtractionResult(
        chain_saids=content.credential_saids,
        registry_saids=registry_saids,
        missing_links=[],  # Issuer has all credentials locally
        complete=True,
    )

    # Build CachedDossier
    cached_dossier = CachedDossier(
        dag=dag,
        raw_content=b"",  # Issuer doesn't need raw bytes
        fetch_timestamp=time.time(),
        content_type="application/cesr",
        contained_saids=set(content.credential_saids),
    )

    return cached_dossier, chain_info
