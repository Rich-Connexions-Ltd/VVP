"""Seed export endpoint for disaster recovery.

Sprint 69: Ephemeral LMDB & Zero-Downtime KERI Deploys.
"""
import base64
import json
import logging
import os
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Query

from app.keri.seed_store import get_seed_store

router = APIRouter(prefix="/admin", tags=["admin"])
log = logging.getLogger(__name__)


def _encrypt_payload(plaintext: bytes, passphrase: str) -> dict:
    """Encrypt plaintext with AES-256-GCM using PBKDF2-derived key.

    Returns a dict with algorithm metadata and ciphertext components.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes

    iterations = 600_000
    kdf_salt = os.urandom(16)
    iv = os.urandom(12)

    # Derive 256-bit key from passphrase
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=kdf_salt,
        iterations=iterations,
    )
    key = kdf.derive(passphrase.encode("utf-8"))

    # Encrypt
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(iv, plaintext, None)

    # AES-GCM appends the 16-byte tag to ciphertext
    ct_bytes = ciphertext[:-16]
    tag_bytes = ciphertext[-16:]

    return {
        "v": 1,
        "alg": "AES-256-GCM",
        "kdf": "PBKDF2-SHA256",
        "iterations": iterations,
        "salt": base64.b64encode(kdf_salt).decode(),
        "iv": base64.b64encode(iv).decode(),
        "ciphertext": base64.b64encode(ct_bytes).decode(),
        "tag": base64.b64encode(tag_bytes).decode(),
    }


def _seed_to_dict(seed, fields: list[str]) -> dict:
    """Convert a SQLAlchemy seed object to a dict with the specified fields."""
    result = {}
    for f in fields:
        val = getattr(seed, f, None)
        if isinstance(val, datetime):
            val = val.isoformat()
        result[f] = val
    return result


@router.get("/seeds/export")
async def export_seeds(passphrase: str = Query(..., min_length=8)):
    """Export all seed data as AES-256-GCM encrypted JSON for disaster recovery.

    The passphrase is used to derive the encryption key via PBKDF2-SHA256
    (600,000 iterations). The passphrase is NOT stored — the operator must
    remember it for future import.
    """
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: F401
    except ImportError:
        raise HTTPException(
            status_code=501,
            detail="cryptography package not installed — seed export unavailable",
        )

    seed_store = get_seed_store()

    # Collect all seed data
    habery_salt_record = None
    from app.db.session import get_db_session
    from app.db.models import KeriHaberySalt
    with get_db_session() as db:
        habery_salt_record = db.query(KeriHaberySalt).filter_by(id=1).first()
        if habery_salt_record:
            db.expunge(habery_salt_record)

    identity_seeds = seed_store.get_all_identity_seeds()
    registry_seeds = seed_store.get_all_registry_seeds()
    rotation_seeds_by_identity = {}
    for iseed in identity_seeds:
        rotations = seed_store.get_rotations_for_identity(iseed.name)
        if rotations:
            rotation_seeds_by_identity[iseed.name] = [
                _seed_to_dict(r, ["identity_name", "sequence_number", "ncount", "nsith", "created_at"])
                for r in rotations
            ]
    credential_seeds = seed_store.get_all_credential_seeds()

    # Build plaintext payload
    payload = {
        "version": 1,
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "habery_salt": {
            "salt": habery_salt_record.salt if habery_salt_record else None,
            "habery_name": habery_salt_record.habery_name if habery_salt_record else None,
        } if habery_salt_record else None,
        "identity_seeds": [
            _seed_to_dict(s, [
                "name", "expected_aid", "transferable", "icount", "isith",
                "ncount", "nsith", "witness_aids", "toad", "metadata_json", "created_at",
            ]) for s in identity_seeds
        ],
        "registry_seeds": [
            _seed_to_dict(s, [
                "name", "identity_name", "expected_registry_key",
                "no_backers", "nonce", "created_at",
            ]) for s in registry_seeds
        ],
        "rotation_seeds": rotation_seeds_by_identity,
        "credential_seeds": [
            _seed_to_dict(s, [
                "expected_said", "registry_name", "schema_said",
                "issuer_identity_name", "recipient_aid",
                "attributes_json", "edges_json", "rules_json",
                "private", "rebuild_order", "edge_saids", "created_at",
            ]) for s in credential_seeds
        ],
        "counts": {
            "identities": len(identity_seeds),
            "registries": len(registry_seeds),
            "credentials": len(credential_seeds),
            "rotations": sum(len(v) for v in rotation_seeds_by_identity.values()),
        },
    }

    plaintext = json.dumps(payload, indent=2).encode("utf-8")
    encrypted = _encrypt_payload(plaintext, passphrase)

    log.info(
        f"Seed export: {len(identity_seeds)} identities, "
        f"{len(registry_seeds)} registries, "
        f"{len(credential_seeds)} credentials"
    )

    return encrypted
