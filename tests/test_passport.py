# Copyright (c) Rich Connexions Ltd. All rights reserved.
# Licensed under the MIT License. See LICENSE for details.
"""Tests for the PASSporT JWT parser (app.vvp.passport).

Covers valid parsing, missing/empty input, structural errors, algorithm
validation, ppt validation, required field checks, and binding validation
between PASSporT and VVP-Identity headers.

References:
    - VVP Verifier Specification §5.0-§5.4 — PASSporT format and binding
    - app.vvp.passport.parse_passport
    - app.vvp.passport.validate_passport_binding
"""

from __future__ import annotations

import base64
import json
import time

import pytest

from app.vvp.passport import parse_passport, validate_passport_binding
from app.vvp.header import parse_vvp_identity, VVPIdentity
from app.vvp.exceptions import PassportError


class TestValidParse:
    """Test successful parsing of well-formed PASSporT JWTs."""

    def test_valid_parse(self, make_passport_jwt):
        """A correctly structured JWT should parse into all expected fields."""
        jwt_str, aid = make_passport_jwt()
        passport = parse_passport(jwt_str)

        assert passport.header.alg == "EdDSA"
        assert passport.header.ppt == "vvp"
        assert passport.header.kid == aid
        assert passport.payload.iat is not None
        assert passport.payload.orig == {"tn": ["+15551234567"]}
        assert passport.payload.dest == {"tn": ["+15559876543"]}
        assert passport.payload.evd == "https://example.com/dossier.cesr"
        assert len(passport.signature) > 0

    def test_raw_segments_preserved(self, make_passport_jwt):
        """Raw header and payload segments should be preserved for signature verification."""
        jwt_str, _ = make_passport_jwt()
        passport = parse_passport(jwt_str)

        parts = jwt_str.split(".")
        assert passport.raw_header == parts[0]
        assert passport.raw_payload == parts[1]


class TestMissingInput:
    """Test handling of missing or empty JWT input."""

    def test_missing_jwt(self):
        """None input should raise PASSPORT_MISSING."""
        with pytest.raises(PassportError) as exc_info:
            parse_passport(None)
        assert exc_info.value.code == "PASSPORT_MISSING"

    def test_empty_jwt(self):
        """Empty string should raise PASSPORT_MISSING."""
        with pytest.raises(PassportError) as exc_info:
            parse_passport("")
        assert exc_info.value.code == "PASSPORT_MISSING"


class TestStructuralErrors:
    """Test handling of structurally malformed JWTs."""

    def test_wrong_parts(self):
        """A JWT with only 2 parts should raise PASSPORT_PARSE_FAILED."""
        with pytest.raises(PassportError) as exc_info:
            parse_passport("a.b")
        assert exc_info.value.code == "PASSPORT_PARSE_FAILED"

    def test_four_parts(self):
        """A JWT with 4 parts should raise PASSPORT_PARSE_FAILED."""
        with pytest.raises(PassportError) as exc_info:
            parse_passport("a.b.c.d")
        assert exc_info.value.code == "PASSPORT_PARSE_FAILED"


class TestAlgorithmValidation:
    """Test algorithm enforcement per §5.0-§5.1."""

    def test_wrong_algorithm(self, make_passport_jwt):
        """A forbidden algorithm (RS256) should raise PASSPORT_FORBIDDEN_ALG."""
        jwt_str, _ = make_passport_jwt(extra_header={"alg": "RS256"})
        with pytest.raises(PassportError) as exc_info:
            parse_passport(jwt_str)
        assert exc_info.value.code == "PASSPORT_FORBIDDEN_ALG"

    def test_none_algorithm(self, make_passport_jwt):
        """The 'none' algorithm should raise PASSPORT_FORBIDDEN_ALG."""
        jwt_str, _ = make_passport_jwt(extra_header={"alg": "none"})
        with pytest.raises(PassportError) as exc_info:
            parse_passport(jwt_str)
        assert exc_info.value.code == "PASSPORT_FORBIDDEN_ALG"


class TestPptValidation:
    """Test PASSporT type (ppt) enforcement."""

    def test_wrong_ppt(self, make_passport_jwt):
        """A non-'vvp' ppt should raise PASSPORT_PARSE_FAILED."""
        jwt_str, _ = make_passport_jwt(extra_header={"ppt": "shaken"})
        with pytest.raises(PassportError) as exc_info:
            parse_passport(jwt_str)
        assert exc_info.value.code == "PASSPORT_PARSE_FAILED"


class TestRequiredFields:
    """Test validation of required payload fields."""

    def test_missing_orig(self, make_passport_jwt):
        """Omitting orig should raise PASSPORT_PARSE_FAILED."""
        now = int(time.time())
        header = {"alg": "EdDSA", "ppt": "vvp", "kid": "Btest_kid_000000000000000000000000000000000", "typ": "passport"}
        payload = {"iat": now, "dest": {"tn": ["+15559876543"]}, "evd": "https://example.com/d.cesr"}
        h = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        p = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        s = base64.urlsafe_b64encode(b"\x00" * 64).decode().rstrip("=")
        jwt_str = f"{h}.{p}.{s}"

        with pytest.raises(PassportError) as exc_info:
            parse_passport(jwt_str)
        assert exc_info.value.code == "PASSPORT_PARSE_FAILED"

    def test_missing_dest(self, make_passport_jwt):
        """Omitting dest should raise PASSPORT_PARSE_FAILED."""
        now = int(time.time())
        header = {"alg": "EdDSA", "ppt": "vvp", "kid": "Btest_kid_000000000000000000000000000000000", "typ": "passport"}
        payload = {"iat": now, "orig": {"tn": ["+15551234567"]}, "evd": "https://example.com/d.cesr"}
        h = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        p = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        s = base64.urlsafe_b64encode(b"\x00" * 64).decode().rstrip("=")
        jwt_str = f"{h}.{p}.{s}"

        with pytest.raises(PassportError) as exc_info:
            parse_passport(jwt_str)
        assert exc_info.value.code == "PASSPORT_PARSE_FAILED"


class TestBindingValidation:
    """Test PASSporT-to-VVP-Identity binding checks per §5.2-§5.4."""

    def test_binding_ppt_mismatch(self, make_passport_jwt, make_vvp_identity):
        """Different ppt values between passport and identity should fail."""
        jwt_str, aid = make_passport_jwt()
        passport = parse_passport(jwt_str)
        # Create a VVP-Identity with a different ppt
        identity = VVPIdentity(ppt="shaken", kid=aid, evd="https://example.com/d.cesr", iat=passport.payload.iat, exp=passport.payload.iat + 300, exp_provided=False)

        with pytest.raises(PassportError) as exc_info:
            validate_passport_binding(passport, identity)
        assert exc_info.value.code == "PASSPORT_PARSE_FAILED"
        assert "ppt" in exc_info.value.message

    def test_binding_kid_mismatch(self, make_passport_jwt, make_vvp_identity):
        """Different kid values between passport and identity should fail."""
        jwt_str, aid = make_passport_jwt()
        passport = parse_passport(jwt_str)
        identity = VVPIdentity(ppt="vvp", kid="Bdifferent_kid_0000000000000000000000000", evd="https://example.com/d.cesr", iat=passport.payload.iat, exp=passport.payload.iat + 300, exp_provided=False)

        with pytest.raises(PassportError) as exc_info:
            validate_passport_binding(passport, identity)
        assert exc_info.value.code == "PASSPORT_PARSE_FAILED"
        assert "kid" in exc_info.value.message

    def test_binding_iat_drift(self, make_passport_jwt, make_vvp_identity):
        """iat drift exceeding MAX_IAT_DRIFT_SECONDS (5s) should fail."""
        now = int(time.time())
        jwt_str, aid = make_passport_jwt(iat=now)
        passport = parse_passport(jwt_str)
        # Create identity with iat 10 seconds different (drift > 5)
        identity = VVPIdentity(ppt="vvp", kid=aid, evd="https://example.com/d.cesr", iat=now + 10, exp=now + 310, exp_provided=False)

        with pytest.raises(PassportError) as exc_info:
            validate_passport_binding(passport, identity, now=now)
        assert exc_info.value.code == "PASSPORT_PARSE_FAILED"
        assert "drift" in exc_info.value.message.lower()
