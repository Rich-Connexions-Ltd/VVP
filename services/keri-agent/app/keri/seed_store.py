"""KERI seed persistence store.

Persists KERI seed data (salts, identity params, registry nonces,
credential metadata) to PostgreSQL for deterministic state rebuild.
All save operations are idempotent (upsert on unique key).

Design note: Uses synchronous SQLAlchemy sessions intentionally.
All keripy operations (makeHab, makeRegistry, proving.credential) are
synchronous and CPU-bound. The seed persist calls run inline with these
sync keripy calls during creation events (rare). The state rebuild runs
at startup before the server accepts any requests. For this single-replica,
low-concurrency service, async DB would add complexity without benefit.

Sprint 69: Ephemeral LMDB & Zero-Downtime KERI Deploys.
"""
import json
import logging
from typing import Optional

from app.db.models import (
    KeriCredentialSeed,
    KeriHaberySalt,
    KeriIdentitySeed,
    KeriRegistrySeed,
    KeriRotationSeed,
)

log = logging.getLogger(__name__)


def _get_db_session():
    """Late-binding accessor for DB session context manager.

    Imported at call time (not module level) so that test fixtures can
    reload app.db.session with a new engine/DB URL and the seed store
    automatically picks up the new session factory.
    """
    from app.db.session import get_db_session
    return get_db_session()


def _insertion_order_json(data: dict | list | None) -> str | None:
    """Serialize to insertion-order JSON for SAID-stable storage.

    Uses compact separators and preserves dict key ordering.
    Matches the insertion-order convention used throughout the codebase
    for SAID computation (established in Sprint 68c).
    """
    if data is None:
        return None
    return json.dumps(data, separators=(",", ":"))


def extract_edge_saids(edges: dict | None) -> list[str] | None:
    """Extract credential SAIDs referenced in edge dict.

    Edge dicts have the structure: {"edgeName": {"n": "<SAID>", "s": "<schema>"}, ...}
    We extract the "n" (node) values which are the referenced credential SAIDs.
    """
    if not edges:
        return None
    saids = []
    for key, val in edges.items():
        if key == "d":
            continue  # Skip the edge block's own SAID
        if isinstance(val, dict) and "n" in val:
            saids.append(val["n"])
    return saids if saids else None


class SeedStore:
    """Persists KERI seed data to PostgreSQL for deterministic rebuild."""

    # -- Habery Salt --

    def save_habery_salt(self, salt: str, habery_name: str) -> None:
        """Save the master Habery salt. Idempotent (upsert on id=1)."""
        with _get_db_session() as db:
            existing = db.query(KeriHaberySalt).filter_by(id=1).first()
            if existing is not None:
                if existing.salt != salt:
                    log.warning(
                        f"Habery salt mismatch for {habery_name}: "
                        f"stored={existing.salt[:8]}... vs new={salt[:8]}..."
                    )
                return  # Already stored, don't overwrite

            record = KeriHaberySalt(id=1, salt=salt, habery_name=habery_name)
            db.add(record)
            log.info(f"Stored Habery salt for {habery_name}")

    def get_habery_salt(self, habery_name: str) -> Optional[str]:
        """Get the stored Habery salt, or None if not yet stored."""
        with _get_db_session() as db:
            record = db.query(KeriHaberySalt).filter_by(id=1).first()
            if record is None:
                return None
            return record.salt

    # -- Identity Seeds --

    def save_identity_seed(
        self,
        name: str,
        expected_aid: str,
        transferable: bool,
        icount: int,
        isith: str,
        ncount: int,
        nsith: str,
        witness_aids: list[str],
        toad: int,
        metadata: Optional[dict] = None,
    ) -> None:
        """Save identity seed. Idempotent (upsert on name)."""
        with _get_db_session() as db:
            existing = db.query(KeriIdentitySeed).filter_by(name=name).first()
            if existing is not None:
                return  # Already stored

            record = KeriIdentitySeed(
                name=name,
                expected_aid=expected_aid,
                transferable=transferable,
                icount=icount,
                isith=str(isith),
                ncount=ncount,
                nsith=str(nsith),
                witness_aids=json.dumps(witness_aids),
                toad=toad,
                metadata_json=_insertion_order_json(metadata),
            )
            db.add(record)
            log.info(f"Stored identity seed: {name} ({expected_aid[:16]}...)")

    def get_all_identity_seeds(self) -> list[KeriIdentitySeed]:
        """Get all identity seeds ordered by creation time."""
        with _get_db_session() as db:
            seeds = (
                db.query(KeriIdentitySeed)
                .order_by(KeriIdentitySeed.created_at)
                .all()
            )
            # Detach from session so they can be used after session closes
            db.expunge_all()
            return seeds

    # -- Registry Seeds --

    def save_registry_seed(
        self,
        name: str,
        identity_name: str,
        expected_registry_key: str,
        no_backers: bool,
        nonce: Optional[str] = None,
    ) -> None:
        """Save registry seed. Idempotent (upsert on name)."""
        with _get_db_session() as db:
            existing = db.query(KeriRegistrySeed).filter_by(name=name).first()
            if existing is not None:
                return  # Already stored

            record = KeriRegistrySeed(
                name=name,
                identity_name=identity_name,
                expected_registry_key=expected_registry_key,
                no_backers=no_backers,
                nonce=nonce,
            )
            db.add(record)
            log.info(f"Stored registry seed: {name} ({expected_registry_key[:16]}...)")

    def get_all_registry_seeds(self) -> list[KeriRegistrySeed]:
        """Get all registry seeds ordered by creation time."""
        with _get_db_session() as db:
            seeds = (
                db.query(KeriRegistrySeed)
                .order_by(KeriRegistrySeed.created_at)
                .all()
            )
            db.expunge_all()
            return seeds

    # -- Rotation Seeds --

    def save_rotation_seed(
        self,
        identity_name: str,
        sequence_number: int,
        ncount: Optional[int] = None,
        nsith: Optional[str] = None,
    ) -> None:
        """Save rotation seed. Idempotent (upsert on identity_name + sequence_number)."""
        with _get_db_session() as db:
            existing = (
                db.query(KeriRotationSeed)
                .filter_by(identity_name=identity_name, sequence_number=sequence_number)
                .first()
            )
            if existing is not None:
                return  # Already stored

            record = KeriRotationSeed(
                identity_name=identity_name,
                sequence_number=sequence_number,
                ncount=ncount,
                nsith=str(nsith) if nsith is not None else None,
            )
            db.add(record)
            log.info(f"Stored rotation seed: {identity_name} sn={sequence_number}")

    def get_rotations_for_identity(self, identity_name: str) -> list[KeriRotationSeed]:
        """Get all rotation seeds for an identity ordered by sequence number."""
        with _get_db_session() as db:
            seeds = (
                db.query(KeriRotationSeed)
                .filter_by(identity_name=identity_name)
                .order_by(KeriRotationSeed.sequence_number)
                .all()
            )
            db.expunge_all()
            return seeds

    # -- Credential Seeds --

    def save_credential_seed(
        self,
        expected_said: str,
        registry_name: str,
        schema_said: str,
        issuer_identity_name: str,
        recipient_aid: Optional[str],
        attributes: dict,
        edges: Optional[dict],
        rules: Optional[dict],
        private: bool,
        rebuild_order: int,
        edge_saids: Optional[list[str]] = None,
    ) -> None:
        """Save credential seed. Idempotent (upsert on expected_said)."""
        with _get_db_session() as db:
            existing = (
                db.query(KeriCredentialSeed)
                .filter_by(expected_said=expected_said)
                .first()
            )
            if existing is not None:
                return  # Already stored

            record = KeriCredentialSeed(
                expected_said=expected_said,
                registry_name=registry_name,
                schema_said=schema_said,
                issuer_identity_name=issuer_identity_name,
                recipient_aid=recipient_aid,
                attributes_json=_insertion_order_json(attributes),
                edges_json=_insertion_order_json(edges),
                rules_json=_insertion_order_json(rules),
                private=private,
                rebuild_order=rebuild_order,
                edge_saids=json.dumps(edge_saids) if edge_saids else None,
            )
            db.add(record)
            log.info(f"Stored credential seed: {expected_said[:16]}... order={rebuild_order}")

    def get_all_credential_seeds(self) -> list[KeriCredentialSeed]:
        """Get all credential seeds ordered by rebuild_order (topological)."""
        with _get_db_session() as db:
            seeds = (
                db.query(KeriCredentialSeed)
                .order_by(KeriCredentialSeed.rebuild_order, KeriCredentialSeed.created_at)
                .all()
            )
            db.expunge_all()
            return seeds

    def compute_rebuild_order(self, edge_saids: Optional[list[str]]) -> int:
        """Compute topological rebuild order from credential edge dependencies.

        Algorithm: for each edge SAID, look up its rebuild_order. This credential's
        rebuild_order = max(dependency rebuild_orders) + 1. Credentials with no edges
        get rebuild_order = 0.
        """
        if not edge_saids:
            return 0

        with _get_db_session() as db:
            max_dep_order = 0
            for said in edge_saids:
                dep = (
                    db.query(KeriCredentialSeed)
                    .filter_by(expected_said=said)
                    .first()
                )
                if dep is not None and dep.rebuild_order >= max_dep_order:
                    max_dep_order = dep.rebuild_order + 1
            return max_dep_order

    # -- Delete Methods (Sprint 73: Cascade Delete) --

    def delete_credential_seed(self, expected_said: str) -> bool:
        """Delete a credential seed by SAID. Returns True if deleted, False if not found."""
        with _get_db_session() as db:
            count = (
                db.query(KeriCredentialSeed)
                .filter(KeriCredentialSeed.expected_said == expected_said)
                .delete()
            )
            if count > 0:
                log.info(f"Deleted credential seed: {expected_said[:16]}...")
            return count > 0

    def delete_identity_seed(self, name: str) -> bool:
        """Delete an identity seed by name and its associated rotation seeds.

        Returns True if the identity seed was found and deleted.
        """
        with _get_db_session() as db:
            # Delete rotation seeds first (FK by identity_name)
            rot_count = (
                db.query(KeriRotationSeed)
                .filter(KeriRotationSeed.identity_name == name)
                .delete()
            )
            if rot_count > 0:
                log.info(f"Deleted {rot_count} rotation seed(s) for identity: {name}")

            count = (
                db.query(KeriIdentitySeed)
                .filter(KeriIdentitySeed.name == name)
                .delete()
            )
            if count > 0:
                log.info(f"Deleted identity seed: {name}")
            return count > 0

    def delete_identity_seed_by_aid(self, aid: str) -> bool:
        """Delete an identity seed by AID (expected_aid) and its rotation seeds.

        Looks up the identity name from the seed record, then deletes
        both the identity seed and associated rotation seeds.
        Returns True if the identity seed was found and deleted.
        """
        with _get_db_session() as db:
            seed = (
                db.query(KeriIdentitySeed)
                .filter(KeriIdentitySeed.expected_aid == aid)
                .first()
            )
            if seed is None:
                return False

            name = seed.name

            # Delete rotation seeds first
            rot_count = (
                db.query(KeriRotationSeed)
                .filter(KeriRotationSeed.identity_name == name)
                .delete()
            )
            if rot_count > 0:
                log.info(f"Deleted {rot_count} rotation seed(s) for identity: {name}")

            db.delete(seed)
            log.info(f"Deleted identity seed by AID: {name} ({aid[:16]}...)")
            return True

    def delete_credential_seeds_bulk(self, saids: list[str]) -> int:
        """Delete multiple credential seeds by SAID list. Returns count deleted."""
        if not saids:
            return 0
        with _get_db_session() as db:
            count = (
                db.query(KeriCredentialSeed)
                .filter(KeriCredentialSeed.expected_said.in_(saids))
                .delete(synchronize_session="fetch")
            )
            if count > 0:
                log.info(f"Bulk deleted {count} credential seed(s)")
            return count

    def delete_identity_seeds_bulk(self, names: list[str]) -> int:
        """Delete multiple identity seeds and their rotation seeds. Returns identity count deleted."""
        if not names:
            return 0
        with _get_db_session() as db:
            # Delete rotation seeds first
            rot_count = (
                db.query(KeriRotationSeed)
                .filter(KeriRotationSeed.identity_name.in_(names))
                .delete(synchronize_session="fetch")
            )
            if rot_count > 0:
                log.info(f"Bulk deleted {rot_count} rotation seed(s)")

            count = (
                db.query(KeriIdentitySeed)
                .filter(KeriIdentitySeed.name.in_(names))
                .delete(synchronize_session="fetch")
            )
            if count > 0:
                log.info(f"Bulk deleted {count} identity seed(s)")
            return count

    # -- Query Helpers --

    def get_credential_seeds_by_issuer(self, identity_name: str) -> list[KeriCredentialSeed]:
        """Get all credential seeds issued by a specific identity."""
        with _get_db_session() as db:
            seeds = (
                db.query(KeriCredentialSeed)
                .filter(KeriCredentialSeed.issuer_identity_name == identity_name)
                .order_by(KeriCredentialSeed.rebuild_order)
                .all()
            )
            db.expunge_all()
            return seeds

    def get_credential_seeds_by_schema(self, schema_said: str) -> list[KeriCredentialSeed]:
        """Get all credential seeds for a specific schema."""
        with _get_db_session() as db:
            seeds = (
                db.query(KeriCredentialSeed)
                .filter(KeriCredentialSeed.schema_said == schema_said)
                .order_by(KeriCredentialSeed.rebuild_order)
                .all()
            )
            db.expunge_all()
            return seeds

    def get_identity_seed_by_aid(self, aid: str) -> Optional[KeriIdentitySeed]:
        """Get an identity seed by AID."""
        with _get_db_session() as db:
            seed = (
                db.query(KeriIdentitySeed)
                .filter(KeriIdentitySeed.expected_aid == aid)
                .first()
            )
            if seed:
                db.expunge(seed)
            return seed

    def has_seeds(self) -> bool:
        """Check if any seeds exist (to distinguish first boot from rebuild)."""
        with _get_db_session() as db:
            return db.query(KeriIdentitySeed).first() is not None


# Module-level singleton
_seed_store: Optional[SeedStore] = None


def get_seed_store() -> SeedStore:
    """Get or create the seed store singleton."""
    global _seed_store
    if _seed_store is None:
        _seed_store = SeedStore()
    return _seed_store


def reset_seed_store() -> None:
    """Reset the singleton (for testing)."""
    global _seed_store
    _seed_store = None
