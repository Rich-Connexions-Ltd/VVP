# Copyright (c) Rich Connexions Ltd. All rights reserved.
# Licensed under the MIT License. See LICENSE for details.
"""Tests for the VVP-Identity header parser (app.vvp.header).

Covers valid parsing, missing/empty input, invalid base64, missing
fields, type validation, future iat rejection, and default exp
derivation.

References:
    - VVP Verifier Specification §4.1A — VVP-Identity header format
    - app.vvp.header.parse_vvp_identity
"""

from __future__ import annotations

import base64
import json
import time

import pytest

from app.vvp.header import parse_vvp_identity
from app.vvp.exceptions import VVPIdentityError


class TestValidParse:
    """Test successful parsing of well-formed VVP-Identity headers."""

    def test_valid_parse(self, make_vvp_identity):
        """A fully populated VVP-Identity header should parse correctly."""
        now = int(time.time())
        raw = make_vvp_identity(ppt="vvp", kid="Btest_kid_000000000000000000000000000000000", evd="https://example.com/dossier.cesr", iat=now)

        result = parse_vvp_identity(raw)

        assert result.ppt == "vvp"
        assert result.kid == "Btest_kid_000000000000000000000000000000000"
        assert result.evd == "https://example.com/dossier.cesr"
        assert result.iat == now

    def test_exp_default(self, make_vvp_identity):
        """When exp is omitted, it should default to iat + 300."""
        now = int(time.time())
        raw = make_vvp_identity(iat=now)

        result = parse_vvp_identity(raw)

        assert result.exp == now + 300
        assert result.exp_provided is False

    def test_exp_explicit(self, make_vvp_identity):
        """When exp is provided, it should be used directly."""
        now = int(time.time())
        raw = make_vvp_identity(iat=now, exp=now + 600)

        result = parse_vvp_identity(raw)

        assert result.exp == now + 600
        assert result.exp_provided is True


class TestMissingHeader:
    """Test handling of missing or empty headers."""

    def test_missing_header(self):
        """None input should raise VVP_IDENTITY_MISSING."""
        with pytest.raises(VVPIdentityError) as exc_info:
            parse_vvp_identity(None)
        assert exc_info.value.code == "VVP_IDENTITY_MISSING"

    def test_empty_header(self):
        """Empty string should raise VVP_IDENTITY_MISSING."""
        with pytest.raises(VVPIdentityError) as exc_info:
            parse_vvp_identity("")
        assert exc_info.value.code == "VVP_IDENTITY_MISSING"

    def test_whitespace_only(self):
        """Whitespace-only input should raise VVP_IDENTITY_MISSING."""
        with pytest.raises(VVPIdentityError) as exc_info:
            parse_vvp_identity("   ")
        assert exc_info.value.code == "VVP_IDENTITY_MISSING"


class TestInvalidInput:
    """Test handling of structurally invalid input."""

    def test_invalid_base64(self):
        """Non-base64 characters should raise VVP_IDENTITY_INVALID."""
        with pytest.raises(VVPIdentityError) as exc_info:
            parse_vvp_identity("!!!")
        assert exc_info.value.code == "VVP_IDENTITY_INVALID"

    def test_not_json_object(self):
        """Base64url-encoded non-object JSON should raise VVP_IDENTITY_INVALID."""
        encoded = base64.urlsafe_b64encode(b'"just a string"').decode().rstrip("=")
        with pytest.raises(VVPIdentityError) as exc_info:
            parse_vvp_identity(encoded)
        assert exc_info.value.code == "VVP_IDENTITY_INVALID"


class TestMissingFields:
    """Test validation of required fields."""

    def test_missing_kid(self):
        """Omitting 'kid' should raise VVP_IDENTITY_INVALID."""
        data = {"ppt": "vvp", "evd": "https://example.com/d.cesr", "iat": int(time.time())}
        raw = base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")
        with pytest.raises(VVPIdentityError) as exc_info:
            parse_vvp_identity(raw)
        assert exc_info.value.code == "VVP_IDENTITY_INVALID"

    def test_missing_ppt(self):
        """Omitting 'ppt' should raise VVP_IDENTITY_INVALID."""
        data = {"kid": "Btest_kid_000000000000000000000000000000000", "evd": "https://example.com/d.cesr", "iat": int(time.time())}
        raw = base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")
        with pytest.raises(VVPIdentityError) as exc_info:
            parse_vvp_identity(raw)
        assert exc_info.value.code == "VVP_IDENTITY_INVALID"

    def test_missing_evd(self):
        """Omitting 'evd' should raise VVP_IDENTITY_INVALID."""
        data = {"ppt": "vvp", "kid": "Btest_kid_000000000000000000000000000000000", "iat": int(time.time())}
        raw = base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")
        with pytest.raises(VVPIdentityError) as exc_info:
            parse_vvp_identity(raw)
        assert exc_info.value.code == "VVP_IDENTITY_INVALID"


class TestTypeValidation:
    """Test type-checking of field values."""

    def test_non_integer_iat(self):
        """Non-integer iat should raise VVP_IDENTITY_INVALID."""
        data = {"ppt": "vvp", "kid": "Btest_kid_000000000000000000000000000000000", "evd": "https://example.com/d.cesr", "iat": "abc"}
        raw = base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")
        with pytest.raises(VVPIdentityError) as exc_info:
            parse_vvp_identity(raw)
        assert exc_info.value.code == "VVP_IDENTITY_INVALID"

    def test_boolean_iat_rejected(self):
        """Boolean iat (which is technically int in Python) should be rejected."""
        data = {"ppt": "vvp", "kid": "Btest_kid_000000000000000000000000000000000", "evd": "https://example.com/d.cesr", "iat": True}
        raw = base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")
        with pytest.raises(VVPIdentityError) as exc_info:
            parse_vvp_identity(raw)
        assert exc_info.value.code == "VVP_IDENTITY_INVALID"


class TestIatValidation:
    """Test issued-at timestamp validation."""

    def test_future_iat(self):
        """iat far in the future should raise VVP_IDENTITY_INVALID."""
        future_iat = int(time.time()) + 100000  # far beyond clock skew
        data = {"ppt": "vvp", "kid": "Btest_kid_000000000000000000000000000000000", "evd": "https://example.com/d.cesr", "iat": future_iat}
        raw = base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")
        with pytest.raises(VVPIdentityError) as exc_info:
            parse_vvp_identity(raw)
        assert exc_info.value.code == "VVP_IDENTITY_INVALID"
