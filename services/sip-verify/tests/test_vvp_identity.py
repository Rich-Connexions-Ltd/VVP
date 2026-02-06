"""Tests for VVP-Identity header decoder.

Sprint 44: Tests for decoding P-VVP-Identity header.
"""

import base64
import json
import pytest

from app.verify.vvp_identity import (
    VVPIdentityData,
    decode_vvp_identity,
    VVPIdentityDecodeError,
)


def _encode_identity(data: dict) -> str:
    """Helper to encode identity data as base64url JSON."""
    json_str = json.dumps(data)
    encoded = base64.urlsafe_b64encode(json_str.encode()).decode()
    return encoded.rstrip("=")


class TestDecodeVVPIdentity:
    """Tests for decode_vvp_identity function."""

    def test_decode_valid_identity(self):
        """Decode valid VVP-Identity header."""
        data = {
            "ppt": "vvp",
            "kid": "https://witness.example.com/oobi/EAbc/witness",
            "evd": "https://dossier.example.com/dossiers/SAbc",
            "iat": 1704067200,
            "exp": 1704153600,
        }
        header = _encode_identity(data)

        result = decode_vvp_identity(header)

        assert result.ppt == "vvp"
        assert result.kid == "https://witness.example.com/oobi/EAbc/witness"
        assert result.evd == "https://dossier.example.com/dossiers/SAbc"
        assert result.iat == 1704067200
        assert result.exp == 1704153600

    def test_decode_minimal_identity(self):
        """Decode identity with only required fields."""
        data = {
            "ppt": "vvp",
            "kid": "https://witness.example.com/oobi/EAbc/witness",
            "evd": "https://dossier.example.com/dossiers/SAbc",
        }
        header = _encode_identity(data)

        result = decode_vvp_identity(header)

        assert result.ppt == "vvp"
        assert result.kid == "https://witness.example.com/oobi/EAbc/witness"
        assert result.evd == "https://dossier.example.com/dossiers/SAbc"
        assert result.iat is None
        assert result.exp is None

    def test_decode_http_urls(self):
        """Decode identity with HTTP URLs (not just HTTPS)."""
        data = {
            "ppt": "vvp",
            "kid": "http://localhost:5631/oobi/EAbc/witness",
            "evd": "http://localhost:8000/dossiers/SAbc",
        }
        header = _encode_identity(data)

        result = decode_vvp_identity(header)

        assert "http://" in result.kid
        assert "http://" in result.evd

    def test_decode_empty_header_raises(self):
        """Empty header should raise error."""
        with pytest.raises(VVPIdentityDecodeError, match="Empty"):
            decode_vvp_identity("")

    def test_decode_invalid_base64_raises(self):
        """Invalid base64 should raise error."""
        with pytest.raises(VVPIdentityDecodeError, match="base64|UTF-8"):
            decode_vvp_identity("!!!invalid!!!")

    def test_decode_invalid_json_raises(self):
        """Invalid JSON should raise error."""
        invalid = base64.urlsafe_b64encode(b"not json").decode().rstrip("=")
        with pytest.raises(VVPIdentityDecodeError, match="JSON"):
            decode_vvp_identity(invalid)

    def test_decode_non_object_raises(self):
        """Non-object JSON should raise error."""
        header = _encode_identity(["list", "not", "object"])
        with pytest.raises(VVPIdentityDecodeError, match="object"):
            decode_vvp_identity(header)

    def test_decode_missing_ppt_raises(self):
        """Missing ppt field should raise error."""
        data = {
            "kid": "https://example.com/oobi/EAbc/witness",
            "evd": "https://example.com/dossiers/SAbc",
        }
        header = _encode_identity(data)

        with pytest.raises(VVPIdentityDecodeError, match="ppt"):
            decode_vvp_identity(header)

    def test_decode_wrong_ppt_raises(self):
        """Non-vvp ppt should raise error."""
        data = {
            "ppt": "shaken",
            "kid": "https://example.com/oobi/EAbc/witness",
            "evd": "https://example.com/dossiers/SAbc",
        }
        header = _encode_identity(data)

        with pytest.raises(VVPIdentityDecodeError, match="vvp"):
            decode_vvp_identity(header)

    def test_decode_missing_kid_raises(self):
        """Missing kid field should raise error."""
        data = {
            "ppt": "vvp",
            "evd": "https://example.com/dossiers/SAbc",
        }
        header = _encode_identity(data)

        with pytest.raises(VVPIdentityDecodeError, match="kid"):
            decode_vvp_identity(header)

    def test_decode_missing_evd_raises(self):
        """Missing evd field should raise error."""
        data = {
            "ppt": "vvp",
            "kid": "https://example.com/oobi/EAbc/witness",
        }
        header = _encode_identity(data)

        with pytest.raises(VVPIdentityDecodeError, match="evd"):
            decode_vvp_identity(header)

    def test_decode_non_url_kid_raises(self):
        """Non-URL kid should raise error."""
        data = {
            "ppt": "vvp",
            "kid": "not-a-url",
            "evd": "https://example.com/dossiers/SAbc",
        }
        header = _encode_identity(data)

        with pytest.raises(VVPIdentityDecodeError, match="OOBI URL"):
            decode_vvp_identity(header)

    def test_decode_non_url_evd_raises(self):
        """Non-URL evd should raise error."""
        data = {
            "ppt": "vvp",
            "kid": "https://example.com/oobi/EAbc/witness",
            "evd": "not-a-url",
        }
        header = _encode_identity(data)

        with pytest.raises(VVPIdentityDecodeError, match="dossier URL"):
            decode_vvp_identity(header)


class TestVVPIdentityData:
    """Tests for VVPIdentityData dataclass."""

    def test_dataclass_fields(self):
        """Verify dataclass has expected fields."""
        data = VVPIdentityData(
            ppt="vvp",
            kid="https://example.com/oobi/EAbc",
            evd="https://example.com/dossiers/SAbc",
            iat=1704067200,
            exp=1704153600,
        )

        assert data.ppt == "vvp"
        assert data.kid == "https://example.com/oobi/EAbc"
        assert data.evd == "https://example.com/dossiers/SAbc"
        assert data.iat == 1704067200
        assert data.exp == 1704153600

    def test_optional_fields_default_none(self):
        """Optional fields should default to None."""
        data = VVPIdentityData(
            ppt="vvp",
            kid="https://example.com/oobi/EAbc",
            evd="https://example.com/dossiers/SAbc",
        )

        assert data.iat is None
        assert data.exp is None
