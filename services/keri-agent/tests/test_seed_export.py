"""Tests for seed export endpoint.

Sprint 69: Ephemeral LMDB & Zero-Downtime KERI Deploys.
"""
import base64
import json

import pytest

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


def _decrypt_export(export_data: dict, passphrase: str) -> dict:
    """Decrypt a seed export response and return the plaintext JSON."""
    kdf_salt = base64.b64decode(export_data["salt"])
    iv = base64.b64decode(export_data["iv"])
    ct = base64.b64decode(export_data["ciphertext"])
    tag = base64.b64decode(export_data["tag"])

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=kdf_salt,
        iterations=export_data["iterations"],
    )
    key = kdf.derive(passphrase.encode("utf-8"))

    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(iv, ct + tag, None)
    return json.loads(plaintext)


class TestSeedExportEndpoint:
    """Tests for GET /admin/seeds/export."""

    @pytest.mark.asyncio
    async def test_export_empty_db(self, client):
        """Export with no seeds returns encrypted empty payload."""
        response = await client.get("/admin/seeds/export?passphrase=test-passphrase-12345")
        assert response.status_code == 200

        data = response.json()
        assert data["v"] == 1
        assert data["alg"] == "AES-256-GCM"
        assert data["kdf"] == "PBKDF2-SHA256"
        assert data["iterations"] == 600_000
        assert "salt" in data
        assert "iv" in data
        assert "ciphertext" in data
        assert "tag" in data

        # Decrypt and verify contents
        payload = _decrypt_export(data, "test-passphrase-12345")
        assert payload["version"] == 1
        assert payload["habery_salt"] is None
        assert payload["identity_seeds"] == []
        assert payload["registry_seeds"] == []
        assert payload["credential_seeds"] == []
        assert payload["counts"]["identities"] == 0

    @pytest.mark.asyncio
    async def test_export_with_seeds(self, client):
        """Export with populated seeds returns all seed data."""
        from app.keri.seed_store import get_seed_store

        seed_store = get_seed_store()
        seed_store.save_habery_salt("0AHabSaltForTest1234567890abcdefghijk", "test-issuer")
        seed_store.save_identity_seed(
            name="test-id",
            expected_aid="EExampleAID1234567890abcdefghijklmn",
            transferable=True,
            icount=1,
            isith="1",
            ncount=1,
            nsith="1",
            witness_aids=[],
            toad=0,
        )
        seed_store.save_registry_seed(
            name="test-registry",
            identity_name="test-id",
            expected_registry_key="EExampleRegKey1234567890abcdefghij",
            no_backers=True,
            nonce="AAAAAAAAAAAAAAAA",
        )

        response = await client.get("/admin/seeds/export?passphrase=strong-passphrase-here")
        assert response.status_code == 200

        payload = _decrypt_export(response.json(), "strong-passphrase-here")
        assert payload["habery_salt"]["salt"] == "0AHabSaltForTest1234567890abcdefghijk"
        assert payload["habery_salt"]["habery_name"] == "test-issuer"
        assert len(payload["identity_seeds"]) == 1
        assert payload["identity_seeds"][0]["name"] == "test-id"
        assert payload["identity_seeds"][0]["expected_aid"] == "EExampleAID1234567890abcdefghijklmn"
        assert len(payload["registry_seeds"]) == 1
        assert payload["registry_seeds"][0]["nonce"] == "AAAAAAAAAAAAAAAA"
        assert payload["counts"]["identities"] == 1
        assert payload["counts"]["registries"] == 1

    @pytest.mark.asyncio
    async def test_export_requires_passphrase(self, client):
        """Export without passphrase returns 422."""
        response = await client.get("/admin/seeds/export")
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_export_short_passphrase_rejected(self, client):
        """Export with passphrase shorter than 8 chars returns 422."""
        response = await client.get("/admin/seeds/export?passphrase=short")
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_export_wrong_passphrase_fails_decrypt(self, client):
        """Decryption with wrong passphrase raises an error."""
        response = await client.get("/admin/seeds/export?passphrase=correct-passphrase")
        assert response.status_code == 200

        with pytest.raises(Exception):
            _decrypt_export(response.json(), "wrong-passphrase!!")

    @pytest.mark.asyncio
    async def test_export_auth_required(self, client_with_auth):
        """Export endpoint requires authentication when auth is enabled."""
        response = await client_with_auth.get("/admin/seeds/export?passphrase=test-passphrase-12345")
        assert response.status_code == 401


class TestEncryptPayload:
    """Tests for _encrypt_payload helper."""

    def test_round_trip(self):
        """Encrypt then decrypt returns original plaintext."""
        from app.api.seeds import _encrypt_payload

        plaintext = b'{"test": "data", "nested": {"key": "value"}}'
        passphrase = "my-strong-passphrase"

        encrypted = _encrypt_payload(plaintext, passphrase)
        decrypted = _decrypt_export(encrypted, passphrase)

        assert decrypted == {"test": "data", "nested": {"key": "value"}}

    def test_different_passphrases_produce_different_output(self):
        """Different passphrases produce different ciphertexts."""
        from app.api.seeds import _encrypt_payload

        plaintext = b'{"test": "data"}'
        enc1 = _encrypt_payload(plaintext, "passphrase-one!!")
        enc2 = _encrypt_payload(plaintext, "passphrase-two!!")

        assert enc1["ciphertext"] != enc2["ciphertext"]

    def test_same_passphrase_different_iv(self):
        """Same passphrase produces different output due to random IV/salt."""
        from app.api.seeds import _encrypt_payload

        plaintext = b'{"test": "data"}'
        enc1 = _encrypt_payload(plaintext, "same-passphrase!")
        enc2 = _encrypt_payload(plaintext, "same-passphrase!")

        # Random salt and IV should differ
        assert enc1["salt"] != enc2["salt"] or enc1["iv"] != enc2["iv"]
