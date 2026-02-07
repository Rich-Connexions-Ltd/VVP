## Code Review: Shared Dossier Caching with Background Revocation

**Verdict:** APPROVED

### Implementation Assessment
Cache miss now resolves the chain with the issuer’s `DossierBuilder`, builds a `CachedDossier` + `ChainExtractionResult`, and stores via `cache.put(chain_info=...)`, which triggers the background revocation task as intended. Cache hits correctly map revocation outcomes to trust decisions, and chain resolution failures degrade to TRUSTED per the stated policy.

### Architecture Assessment
The issuer-side cache population closes the previous gap without breaking the DI/shim approach in the verifier. The cache-only revocation check is now sufficient because the issuer populates the cache on demand from local credentials.

### Code Quality
Implementation is clear and localized. The DAG node construction uses `ACDCNode` with `issuer` and `schema` fields mapped from `CredentialInfo.issuer_aid` and `CredentialInfo.schema_said`, which is the correct field mapping for the common model.

### Test Coverage
New issuer tests cover cache miss population, cache hit decisions (ACTIVE/REVOKED/pending), chain resolution failure, and DAG/registry mapping in `_build_cache_entry`. This addresses the prior gap.

### API Compatibility
`check_dossier_revocation()` now requires `dossier_said`, and `vvp.py` passes it. The external API response shape remains backward compatible with `revocation_status` defaulting to "TRUSTED" and 403 only on revoked credentials.

### Findings
- None.

### Required Changes (if not APPROVED)
N/A

### Plan Revisions (if PLAN_REVISION_REQUIRED)
N/A
