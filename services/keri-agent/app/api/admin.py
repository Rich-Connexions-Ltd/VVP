"""Admin API endpoints for KERI Agent bulk operations.

Sprint 73: Credential & Identity Cleanup — bulk delete endpoints
with filter support, dry-run mode, and safety guards.
"""
import fnmatch
import json
import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.keri.identity import get_identity_manager, IdentityNotFoundError
from app.keri.issuer import get_credential_issuer
from app.keri.seed_store import get_seed_store

log = logging.getLogger(__name__)

router = APIRouter(prefix="/admin", tags=["admin"])

# Trust-anchor metadata types that require force=true to delete
PROTECTED_METADATA_TYPES = {"mock_gleif", "mock_qvi", "mock_gsma"}


# -- Request/Response Models --

class BulkCredentialCleanupRequest(BaseModel):
    saids: Optional[list[str]] = None
    issuer_identity_name: Optional[str] = None
    schema_said: Optional[str] = None
    before: Optional[datetime] = None
    force: bool = False
    dry_run: bool = False


class BulkCredentialCleanupResponse(BaseModel):
    deleted_count: int
    deleted_saids: list[str]
    failed: list[dict]
    blocked_saids: list[str]
    dry_run: bool


class BulkIdentityCleanupRequest(BaseModel):
    names: Optional[list[str]] = None
    name_pattern: Optional[str] = None
    metadata_type: Optional[str] = None
    before: Optional[datetime] = None
    cascade_credentials: bool = False
    force: bool = False
    dry_run: bool = False


class BulkIdentityCleanupResponse(BaseModel):
    deleted_count: int
    deleted_names: list[str]
    failed: list[dict]
    blocked_names: list[dict]
    cascaded_credential_count: int
    dry_run: bool


# -- Credential Cleanup --

@router.post("/cleanup/credentials", response_model=BulkCredentialCleanupResponse)
async def bulk_cleanup_credentials(request: BulkCredentialCleanupRequest):
    """Bulk delete credentials by filter criteria.

    Filters (all optional, combined with AND):
    - saids: explicit list of credential SAIDs to delete
    - issuer_identity_name: delete credentials issued by this identity
    - schema_said: delete credentials with this schema
    - before: delete credentials created before this timestamp

    Safety:
    - force=false (default): blocks deletion of credentials that other credentials depend on
    - dry_run=true: returns what would be deleted without deleting
    """
    seed_store = get_seed_store()

    # Build target SAID list from filters
    target_saids = set()

    if request.saids:
        target_saids.update(request.saids)
    else:
        # Query seeds matching filters
        all_seeds = seed_store.get_all_credential_seeds()

        for seed in all_seeds:
            match = True
            if request.issuer_identity_name and seed.issuer_identity_name != request.issuer_identity_name:
                match = False
            if request.schema_said and seed.schema_said != request.schema_said:
                match = False
            if request.before and seed.created_at >= request.before:
                match = False
            if match:
                target_saids.add(seed.expected_said)

    if not target_saids:
        return BulkCredentialCleanupResponse(
            deleted_count=0, deleted_saids=[], failed=[],
            blocked_saids=[], dry_run=request.dry_run,
        )

    # Check for dependents (unless force=true)
    blocked_saids = []
    if not request.force:
        all_seeds = seed_store.get_all_credential_seeds()
        for seed in all_seeds:
            if seed.expected_said in target_saids:
                continue
            if seed.edge_saids:
                edge_list = json.loads(seed.edge_saids)
                for dep_said in edge_list:
                    if dep_said in target_saids:
                        blocked_saids.append(dep_said)

        blocked_saids = list(set(blocked_saids))
        target_saids -= set(blocked_saids)

    if request.dry_run:
        return BulkCredentialCleanupResponse(
            deleted_count=len(target_saids),
            deleted_saids=sorted(target_saids),
            failed=[],
            blocked_saids=blocked_saids,
            dry_run=True,
        )

    # Delete from LMDB + seeds
    deleted_saids = []
    failed = []
    issuer = await get_credential_issuer()

    for said in sorted(target_saids):
        try:
            await issuer.delete_credential(said)
            deleted_saids.append(said)
        except ValueError:
            # Not in LMDB — still try to clean up the seed
            try:
                seed_store.delete_credential_seed(said)
                deleted_saids.append(said)
            except Exception as e:
                failed.append({"said": said, "error": str(e)})
        except Exception as e:
            failed.append({"said": said, "error": str(e)})

    log.info(f"Bulk credential cleanup: {len(deleted_saids)} deleted, {len(failed)} failed, {len(blocked_saids)} blocked")

    return BulkCredentialCleanupResponse(
        deleted_count=len(deleted_saids),
        deleted_saids=deleted_saids,
        failed=failed,
        blocked_saids=blocked_saids,
        dry_run=False,
    )


# -- Identity Cleanup --

@router.post("/cleanup/identities", response_model=BulkIdentityCleanupResponse)
async def bulk_cleanup_identities(request: BulkIdentityCleanupRequest):
    """Bulk delete identities by filter criteria.

    Filters (all optional, combined with AND):
    - names: explicit list of identity names to delete
    - name_pattern: glob pattern for identity names (e.g., "test-*")
    - metadata_type: delete identities with this metadata type
    - before: delete identities created before this timestamp

    Safety:
    - force=false (default): blocks deletion of trust-anchor identities (GLEIF, QVI, GSMA)
    - cascade_credentials=false (default): blocks deletion of identities that have issued credentials
    - dry_run=true: returns what would be deleted without deleting
    """
    seed_store = get_seed_store()

    # Build target names list from filters
    target_names = set()
    all_identity_seeds = seed_store.get_all_identity_seeds()

    if request.names:
        target_names.update(request.names)
    else:
        for seed in all_identity_seeds:
            match = True
            if request.name_pattern and not fnmatch.fnmatch(seed.name, request.name_pattern):
                match = False
            if request.metadata_type:
                meta = json.loads(seed.metadata_json) if seed.metadata_json else {}
                if meta.get("type") != request.metadata_type:
                    match = False
            if request.before and seed.created_at >= request.before:
                match = False
            if match:
                target_names.add(seed.name)

    if not target_names:
        return BulkIdentityCleanupResponse(
            deleted_count=0, deleted_names=[], failed=[],
            blocked_names=[], cascaded_credential_count=0,
            dry_run=request.dry_run,
        )

    # Check for protected identities (unless force=true)
    blocked_names = []
    if not request.force:
        for seed in all_identity_seeds:
            if seed.name not in target_names:
                continue
            meta = json.loads(seed.metadata_json) if seed.metadata_json else {}
            if meta.get("type") in PROTECTED_METADATA_TYPES:
                blocked_names.append({
                    "name": seed.name,
                    "reason": f"Trust-anchor identity (type={meta['type']}). Use force=true to override.",
                })
                target_names.discard(seed.name)

    # Check for identities with issued credentials
    cascaded_credential_count = 0
    credentials_to_cascade = []  # (identity_name, [saids])

    for name in list(target_names):
        cred_seeds = seed_store.get_credential_seeds_by_issuer(name)
        if cred_seeds:
            if not request.cascade_credentials:
                blocked_names.append({
                    "name": name,
                    "reason": f"Has {len(cred_seeds)} issued credential(s). Use cascade_credentials=true to also delete them.",
                })
                target_names.discard(name)
            else:
                credentials_to_cascade.append(
                    (name, [s.expected_said for s in cred_seeds])
                )

    if request.dry_run:
        dry_cascade_count = sum(len(saids) for _, saids in credentials_to_cascade)
        return BulkIdentityCleanupResponse(
            deleted_count=len(target_names),
            deleted_names=sorted(target_names),
            failed=[],
            blocked_names=blocked_names,
            cascaded_credential_count=dry_cascade_count,
            dry_run=True,
        )

    # Delete cascaded credentials first
    issuer = await get_credential_issuer()
    for identity_name, cred_saids in credentials_to_cascade:
        for said in cred_saids:
            try:
                await issuer.delete_credential(said)
                cascaded_credential_count += 1
            except ValueError:
                # Not in LMDB — clean up seed only
                try:
                    seed_store.delete_credential_seed(said)
                    cascaded_credential_count += 1
                except Exception:
                    pass
            except Exception:
                pass

    # Delete identities from LMDB + seeds
    deleted_names = []
    failed = []
    mgr = await get_identity_manager()

    for name in sorted(target_names):
        # Find AID for this name
        seed = None
        for s in all_identity_seeds:
            if s.name == name:
                seed = s
                break

        if seed is None:
            failed.append({"name": name, "error": "Identity seed not found"})
            continue

        try:
            await mgr.delete_identity(seed.expected_aid)
            deleted_names.append(name)
        except IdentityNotFoundError:
            # Not in LMDB — still try to clean up seed
            try:
                seed_store.delete_identity_seed(name)
                deleted_names.append(name)
            except Exception as e:
                failed.append({"name": name, "error": str(e)})
        except Exception as e:
            failed.append({"name": name, "error": str(e)})

    log.info(
        f"Bulk identity cleanup: {len(deleted_names)} deleted, {len(failed)} failed, "
        f"{len(blocked_names)} blocked, {cascaded_credential_count} credentials cascaded"
    )

    return BulkIdentityCleanupResponse(
        deleted_count=len(deleted_names),
        deleted_names=deleted_names,
        failed=failed,
        blocked_names=blocked_names,
        cascaded_credential_count=cascaded_credential_count,
        dry_run=False,
    )
