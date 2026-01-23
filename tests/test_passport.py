"""
Unit tests for PASSporT JWT parsing and validation per Phase 3.

Covers:
- Parsing (missing JWT, malformed, invalid base64/JSON)
- Algorithm validation (§5.0, §5.1)
- Header fields (alg, ppt, kid, typ)
- Payload fields (iat, orig, dest, evd, optional fields)
- Binding validation (§5.2)
- Temporal binding (§5.2A)
- Expiry policy (§5.2B)
"""

import base64
import json
import time

import pytest

from app.vvp.api_models import ErrorCode
from app.vvp.exceptions import PassportError
from app.vvp.header import VVPIdentity
from app.vvp.passport import (
    Passport,
    PassportHeader,
    PassportPayload,
    parse_passport,
    validate_passport_binding,
)


# =============================================================================
# Test Helpers
# =============================================================================

def b64url_encode(data: dict) -> str:
    """Base64url encode a dictionary as JSON."""
    json_bytes = json.dumps(data).encode("utf-8")
    return base64.urlsafe_b64encode(json_bytes).rstrip(b"=").decode("ascii")


def make_jwt(header: dict, payload: dict, signature: str = "c2lnbmF0dXJl") -> str:
    """Create a JWT string from header and payload dicts."""
    return f"{b64url_encode(header)}.{b64url_encode(payload)}.{signature}"


def valid_header() -> dict:
    """Return a valid PASSporT header."""
    return {
        "alg": "EdDSA",
        "ppt": "vvp",
        "kid": "did:keri:EExampleAID123",
    }


def valid_payload(iat: int = None) -> dict:
    """Return a valid PASSporT payload."""
    if iat is None:
        iat = int(time.time())
    return {
        "iat": iat,
        "orig": {"tn": "+12025551234"},
        "dest": {"tn": ["+12025555678"]},
        "evd": "oobi:http://example.com/oobi/EExampleAID123",
    }


def valid_vvp_identity(iat: int = None, exp: int = None, exp_provided: bool = False) -> VVPIdentity:
    """Return a valid VVPIdentity for binding tests.

    Args:
        iat: Issued-at timestamp (defaults to current time)
        exp: Expiry timestamp (defaults to iat + 300)
        exp_provided: Whether exp was explicitly provided in the header.
                      Defaults to False to simulate computed default per §4.1A.
    """
    if iat is None:
        iat = int(time.time())
    if exp is None:
        exp = iat + 300
    return VVPIdentity(
        ppt="vvp",
        kid="did:keri:EExampleAID123",
        evd="oobi:http://example.com/oobi/EExampleAID123",
        iat=iat,
        exp=exp,
        exp_provided=exp_provided,
    )


# =============================================================================
# Parsing Tests
# =============================================================================

class TestParsing:
    """Tests for JWT structure parsing."""

    def test_missing_jwt_none(self):
        """Missing JWT (None) → PASSPORT_MISSING."""
        with pytest.raises(PassportError) as exc:
            parse_passport(None)
        assert exc.value.code == ErrorCode.PASSPORT_MISSING

    def test_missing_jwt_empty(self):
        """Empty JWT ("") → PASSPORT_MISSING."""
        with pytest.raises(PassportError) as exc:
            parse_passport("")
        assert exc.value.code == ErrorCode.PASSPORT_MISSING

    def test_missing_jwt_whitespace(self):
        """Whitespace-only JWT → PASSPORT_MISSING."""
        with pytest.raises(PassportError) as exc:
            parse_passport("   ")
        assert exc.value.code == ErrorCode.PASSPORT_MISSING

    def test_malformed_jwt_one_part(self):
        """Malformed JWT (1 part) → PASSPORT_PARSE_FAILED."""
        with pytest.raises(PassportError) as exc:
            parse_passport("onlyonepart")
        assert exc.value.code == ErrorCode.PASSPORT_PARSE_FAILED
        assert "3 parts" in exc.value.message

    def test_malformed_jwt_two_parts(self):
        """Malformed JWT (2 parts) → PASSPORT_PARSE_FAILED."""
        with pytest.raises(PassportError) as exc:
            parse_passport("part1.part2")
        assert exc.value.code == ErrorCode.PASSPORT_PARSE_FAILED
        assert "3 parts" in exc.value.message

    def test_malformed_jwt_four_parts(self):
        """Malformed JWT (4 parts) → PASSPORT_PARSE_FAILED."""
        with pytest.raises(PassportError) as exc:
            parse_passport("a.b.c.d")
        assert exc.value.code == ErrorCode.PASSPORT_PARSE_FAILED
        assert "3 parts" in exc.value.message

    def test_invalid_base64_header(self):
        """Invalid base64 in header → PASSPORT_PARSE_FAILED."""
        with pytest.raises(PassportError) as exc:
            parse_passport("!!!invalid!!!.eyJpYXQiOjF9.sig")
        assert exc.value.code == ErrorCode.PASSPORT_PARSE_FAILED
        assert "header" in exc.value.message.lower()

    def test_invalid_base64_payload(self):
        """Invalid base64 in payload → PASSPORT_PARSE_FAILED."""
        header = b64url_encode(valid_header())
        with pytest.raises(PassportError) as exc:
            parse_passport(f"{header}.!!!invalid!!!.sig")
        assert exc.value.code == ErrorCode.PASSPORT_PARSE_FAILED
        assert "payload" in exc.value.message.lower()

    def test_invalid_json_header(self):
        """Invalid JSON in header → PASSPORT_PARSE_FAILED."""
        # Base64-encode something that's not valid JSON
        bad_header = base64.urlsafe_b64encode(b"not json").rstrip(b"=").decode()
        with pytest.raises(PassportError) as exc:
            parse_passport(f"{bad_header}.eyJpYXQiOjF9.sig")
        assert exc.value.code == ErrorCode.PASSPORT_PARSE_FAILED
        assert "header" in exc.value.message.lower()

    def test_invalid_json_payload(self):
        """Invalid JSON in payload → PASSPORT_PARSE_FAILED."""
        header = b64url_encode(valid_header())
        bad_payload = base64.urlsafe_b64encode(b"not json").rstrip(b"=").decode()
        with pytest.raises(PassportError) as exc:
            parse_passport(f"{header}.{bad_payload}.sig")
        assert exc.value.code == ErrorCode.PASSPORT_PARSE_FAILED
        assert "payload" in exc.value.message.lower()

    def test_header_not_object(self):
        """Header is array, not object → PASSPORT_PARSE_FAILED."""
        bad_header = base64.urlsafe_b64encode(b'["array"]').rstrip(b"=").decode()
        with pytest.raises(PassportError) as exc:
            parse_passport(f"{bad_header}.eyJpYXQiOjF9.sig")
        assert exc.value.code == ErrorCode.PASSPORT_PARSE_FAILED
        assert "object" in exc.value.message.lower()

    def test_payload_not_object(self):
        """Payload is array, not object → PASSPORT_PARSE_FAILED."""
        header = b64url_encode(valid_header())
        bad_payload = base64.urlsafe_b64encode(b'["array"]').rstrip(b"=").decode()
        with pytest.raises(PassportError) as exc:
            parse_passport(f"{header}.{bad_payload}.sig")
        assert exc.value.code == ErrorCode.PASSPORT_PARSE_FAILED
        assert "object" in exc.value.message.lower()

    def test_valid_jwt_parses(self):
        """Valid JWT parses successfully."""
        jwt = make_jwt(valid_header(), valid_payload())
        passport = parse_passport(jwt)
        assert isinstance(passport, Passport)
        assert passport.header.alg == "EdDSA"
        assert passport.header.ppt == "vvp"


# =============================================================================
# Algorithm Validation Tests (§5.0, §5.1)
# =============================================================================

class TestAlgorithmValidation:
    """Tests for algorithm validation per §5.0, §5.1."""

    def test_alg_none_rejected(self):
        """alg: "none" → PASSPORT_FORBIDDEN_ALG."""
        header = valid_header()
        header["alg"] = "none"
        jwt = make_jwt(header, valid_payload())
        with pytest.raises(PassportError) as exc:
            parse_passport(jwt)
        assert exc.value.code == ErrorCode.PASSPORT_FORBIDDEN_ALG
        assert "none" in exc.value.message

    def test_alg_es256_rejected(self):
        """alg: "ES256" → PASSPORT_FORBIDDEN_ALG."""
        header = valid_header()
        header["alg"] = "ES256"
        jwt = make_jwt(header, valid_payload())
        with pytest.raises(PassportError) as exc:
            parse_passport(jwt)
        assert exc.value.code == ErrorCode.PASSPORT_FORBIDDEN_ALG
        assert "ES256" in exc.value.message

    def test_alg_hs256_rejected(self):
        """alg: "HS256" → PASSPORT_FORBIDDEN_ALG."""
        header = valid_header()
        header["alg"] = "HS256"
        jwt = make_jwt(header, valid_payload())
        with pytest.raises(PassportError) as exc:
            parse_passport(jwt)
        assert exc.value.code == ErrorCode.PASSPORT_FORBIDDEN_ALG
        assert "HS256" in exc.value.message

    def test_alg_hs384_rejected(self):
        """alg: "HS384" → PASSPORT_FORBIDDEN_ALG."""
        header = valid_header()
        header["alg"] = "HS384"
        jwt = make_jwt(header, valid_payload())
        with pytest.raises(PassportError) as exc:
            parse_passport(jwt)
        assert exc.value.code == ErrorCode.PASSPORT_FORBIDDEN_ALG

    def test_alg_hs512_rejected(self):
        """alg: "HS512" → PASSPORT_FORBIDDEN_ALG."""
        header = valid_header()
        header["alg"] = "HS512"
        jwt = make_jwt(header, valid_payload())
        with pytest.raises(PassportError) as exc:
            parse_passport(jwt)
        assert exc.value.code == ErrorCode.PASSPORT_FORBIDDEN_ALG

    def test_alg_rs256_rejected(self):
        """alg: "RS256" → PASSPORT_FORBIDDEN_ALG."""
        header = valid_header()
        header["alg"] = "RS256"
        jwt = make_jwt(header, valid_payload())
        with pytest.raises(PassportError) as exc:
            parse_passport(jwt)
        assert exc.value.code == ErrorCode.PASSPORT_FORBIDDEN_ALG
        assert "RS256" in exc.value.message

    def test_alg_rs384_rejected(self):
        """alg: "RS384" → PASSPORT_FORBIDDEN_ALG."""
        header = valid_header()
        header["alg"] = "RS384"
        jwt = make_jwt(header, valid_payload())
        with pytest.raises(PassportError) as exc:
            parse_passport(jwt)
        assert exc.value.code == ErrorCode.PASSPORT_FORBIDDEN_ALG

    def test_alg_rs512_rejected(self):
        """alg: "RS512" → PASSPORT_FORBIDDEN_ALG."""
        header = valid_header()
        header["alg"] = "RS512"
        jwt = make_jwt(header, valid_payload())
        with pytest.raises(PassportError) as exc:
            parse_passport(jwt)
        assert exc.value.code == ErrorCode.PASSPORT_FORBIDDEN_ALG

    def test_alg_unknown_rejected(self):
        """Unknown algorithm → PASSPORT_FORBIDDEN_ALG."""
        header = valid_header()
        header["alg"] = "PS256"
        jwt = make_jwt(header, valid_payload())
        with pytest.raises(PassportError) as exc:
            parse_passport(jwt)
        assert exc.value.code == ErrorCode.PASSPORT_FORBIDDEN_ALG

    def test_alg_eddsa_accepted(self):
        """alg: "EdDSA" → Valid."""
        header = valid_header()
        header["alg"] = "EdDSA"
        jwt = make_jwt(header, valid_payload())
        passport = parse_passport(jwt)
        assert passport.header.alg == "EdDSA"


# =============================================================================
# Header Field Tests
# =============================================================================

class TestHeaderFields:
    """Tests for header field validation."""

    def test_missing_alg(self):
        """Missing alg → PASSPORT_PARSE_FAILED."""
        header = valid_header()
        del header["alg"]
        jwt = make_jwt(header, valid_payload())
        with pytest.raises(PassportError) as exc:
            parse_passport(jwt)
        assert exc.value.code == ErrorCode.PASSPORT_PARSE_FAILED
        assert "alg" in exc.value.message

    def test_missing_ppt(self):
        """Missing ppt → PASSPORT_PARSE_FAILED."""
        header = valid_header()
        del header["ppt"]
        jwt = make_jwt(header, valid_payload())
        with pytest.raises(PassportError) as exc:
            parse_passport(jwt)
        assert exc.value.code == ErrorCode.PASSPORT_PARSE_FAILED
        assert "ppt" in exc.value.message

    def test_missing_kid(self):
        """Missing kid → PASSPORT_PARSE_FAILED."""
        header = valid_header()
        del header["kid"]
        jwt = make_jwt(header, valid_payload())
        with pytest.raises(PassportError) as exc:
            parse_passport(jwt)
        assert exc.value.code == ErrorCode.PASSPORT_PARSE_FAILED
        assert "kid" in exc.value.message

    def test_ppt_vvp_valid(self):
        """ppt = "vvp" → Valid."""
        header = valid_header()
        header["ppt"] = "vvp"
        jwt = make_jwt(header, valid_payload())
        passport = parse_passport(jwt)
        assert passport.header.ppt == "vvp"

    def test_ppt_not_vvp_rejected(self):
        """ppt != "vvp" (e.g., "shaken") → PASSPORT_PARSE_FAILED."""
        header = valid_header()
        header["ppt"] = "shaken"
        jwt = make_jwt(header, valid_payload())
        with pytest.raises(PassportError) as exc:
            parse_passport(jwt)
        assert exc.value.code == ErrorCode.PASSPORT_PARSE_FAILED
        assert "vvp" in exc.value.message.lower()

    def test_missing_typ_valid(self):
        """Missing typ → Valid (not required)."""
        header = valid_header()
        assert "typ" not in header
        jwt = make_jwt(header, valid_payload())
        passport = parse_passport(jwt)
        assert passport.header.typ is None

    def test_typ_present_ignored(self):
        """typ present → Ignored (not validated)."""
        header = valid_header()
        header["typ"] = "passport"
        jwt = make_jwt(header, valid_payload())
        passport = parse_passport(jwt)
        assert passport.header.typ == "passport"

    def test_typ_wrong_value_ignored(self):
        """typ with wrong value → Ignored (not validated)."""
        header = valid_header()
        header["typ"] = "wrong-type"
        jwt = make_jwt(header, valid_payload())
        passport = parse_passport(jwt)
        # Should not raise - typ is ignored
        assert passport.header.typ == "wrong-type"

    def test_alg_empty_string_rejected(self):
        """alg empty string → PASSPORT_PARSE_FAILED."""
        header = valid_header()
        header["alg"] = ""
        jwt = make_jwt(header, valid_payload())
        with pytest.raises(PassportError) as exc:
            parse_passport(jwt)
        assert exc.value.code == ErrorCode.PASSPORT_PARSE_FAILED
        assert "empty" in exc.value.message.lower()

    def test_kid_empty_string_rejected(self):
        """kid empty string → PASSPORT_PARSE_FAILED."""
        header = valid_header()
        header["kid"] = ""
        jwt = make_jwt(header, valid_payload())
        with pytest.raises(PassportError) as exc:
            parse_passport(jwt)
        assert exc.value.code == ErrorCode.PASSPORT_PARSE_FAILED
        assert "empty" in exc.value.message.lower()


# =============================================================================
# Payload Field Tests
# =============================================================================

class TestPayloadFields:
    """Tests for payload field validation."""

    def test_missing_iat(self):
        """Missing iat → PASSPORT_PARSE_FAILED."""
        payload = valid_payload()
        del payload["iat"]
        jwt = make_jwt(valid_header(), payload)
        with pytest.raises(PassportError) as exc:
            parse_passport(jwt)
        assert exc.value.code == ErrorCode.PASSPORT_PARSE_FAILED
        assert "iat" in exc.value.message

    def test_missing_orig(self):
        """Missing orig → PASSPORT_PARSE_FAILED (local policy)."""
        payload = valid_payload()
        del payload["orig"]
        jwt = make_jwt(valid_header(), payload)
        with pytest.raises(PassportError) as exc:
            parse_passport(jwt)
        assert exc.value.code == ErrorCode.PASSPORT_PARSE_FAILED
        assert "orig" in exc.value.message

    def test_missing_dest(self):
        """Missing dest → PASSPORT_PARSE_FAILED (local policy)."""
        payload = valid_payload()
        del payload["dest"]
        jwt = make_jwt(valid_header(), payload)
        with pytest.raises(PassportError) as exc:
            parse_passport(jwt)
        assert exc.value.code == ErrorCode.PASSPORT_PARSE_FAILED
        assert "dest" in exc.value.message

    def test_missing_evd(self):
        """Missing evd → PASSPORT_PARSE_FAILED (local policy)."""
        payload = valid_payload()
        del payload["evd"]
        jwt = make_jwt(valid_header(), payload)
        with pytest.raises(PassportError) as exc:
            parse_passport(jwt)
        assert exc.value.code == ErrorCode.PASSPORT_PARSE_FAILED
        assert "evd" in exc.value.message

    def test_missing_iss_valid(self):
        """Missing iss → Valid (optional)."""
        payload = valid_payload()
        assert "iss" not in payload
        jwt = make_jwt(valid_header(), payload)
        passport = parse_passport(jwt)
        assert passport.payload.iss is None

    def test_iss_present(self):
        """iss present → Preserved."""
        payload = valid_payload()
        payload["iss"] = "did:keri:issuer123"
        jwt = make_jwt(valid_header(), payload)
        passport = parse_passport(jwt)
        assert passport.payload.iss == "did:keri:issuer123"

    def test_optional_fields_preserved(self):
        """All optional fields → Preserved when present."""
        payload = valid_payload()
        payload["iss"] = "issuer"
        payload["exp"] = payload["iat"] + 300
        payload["card"] = {"name": "Test Card"}
        payload["goal"] = "verification"
        payload["call-reason"] = "business"
        payload["origid"] = "call-123"
        jwt = make_jwt(valid_header(), payload)
        passport = parse_passport(jwt)
        assert passport.payload.iss == "issuer"
        assert passport.payload.exp == payload["iat"] + 300
        assert passport.payload.card == {"name": "Test Card"}
        assert passport.payload.goal == "verification"
        assert passport.payload.call_reason == "business"
        assert passport.payload.origid == "call-123"

    def test_iat_non_integer_rejected(self):
        """iat as string → PASSPORT_PARSE_FAILED."""
        payload = valid_payload()
        payload["iat"] = "not-an-integer"
        jwt = make_jwt(valid_header(), payload)
        with pytest.raises(PassportError) as exc:
            parse_passport(jwt)
        assert exc.value.code == ErrorCode.PASSPORT_PARSE_FAILED
        assert "iat" in exc.value.message

    def test_iat_boolean_rejected(self):
        """iat as boolean → PASSPORT_PARSE_FAILED."""
        payload = valid_payload()
        payload["iat"] = True
        jwt = make_jwt(valid_header(), payload)
        with pytest.raises(PassportError) as exc:
            parse_passport(jwt)
        assert exc.value.code == ErrorCode.PASSPORT_PARSE_FAILED
        assert "integer" in exc.value.message.lower()

    def test_iat_float_accepted(self):
        """iat as float with integer value → Accepted (coerced)."""
        payload = valid_payload()
        payload["iat"] = 1700000000.0  # Float but integer value
        jwt = make_jwt(valid_header(), payload)
        passport = parse_passport(jwt)
        assert passport.payload.iat == 1700000000

    def test_orig_not_object_rejected(self):
        """orig as string → PASSPORT_PARSE_FAILED."""
        payload = valid_payload()
        payload["orig"] = "not-an-object"
        jwt = make_jwt(valid_header(), payload)
        with pytest.raises(PassportError) as exc:
            parse_passport(jwt)
        assert exc.value.code == ErrorCode.PASSPORT_PARSE_FAILED
        assert "object" in exc.value.message.lower()


# =============================================================================
# Binding Validation Tests (§5.2)
# =============================================================================

class TestBindingValidation:
    """Tests for binding validation per §5.2."""

    def test_ppt_mismatch(self):
        """ppt mismatch with VVP-Identity → PASSPORT_PARSE_FAILED."""
        now = int(time.time())
        passport = parse_passport(make_jwt(valid_header(), valid_payload(now)))
        identity = VVPIdentity(
            ppt="shaken",  # Mismatch
            kid="did:keri:EExampleAID123",
            evd="oobi:http://example.com/oobi/EExampleAID123",
            iat=now,
            exp=now + 300,
            exp_provided=False,
        )
        with pytest.raises(PassportError) as exc:
            validate_passport_binding(passport, identity, now)
        assert exc.value.code == ErrorCode.PASSPORT_PARSE_FAILED
        assert "ppt mismatch" in exc.value.message.lower()

    def test_kid_mismatch(self):
        """kid mismatch with VVP-Identity → PASSPORT_PARSE_FAILED."""
        now = int(time.time())
        passport = parse_passport(make_jwt(valid_header(), valid_payload(now)))
        identity = VVPIdentity(
            ppt="vvp",
            kid="did:keri:EDifferentAID456",  # Mismatch
            evd="oobi:http://example.com/oobi/EExampleAID123",
            iat=now,
            exp=now + 300,
            exp_provided=False,
        )
        with pytest.raises(PassportError) as exc:
            validate_passport_binding(passport, identity, now)
        assert exc.value.code == ErrorCode.PASSPORT_PARSE_FAILED
        assert "kid mismatch" in exc.value.message.lower()

    def test_binding_valid(self):
        """ppt = "vvp" and matches VVP-Identity → Valid."""
        now = int(time.time())
        passport = parse_passport(make_jwt(valid_header(), valid_payload(now)))
        identity = valid_vvp_identity(now)
        # Should not raise
        validate_passport_binding(passport, identity, now)


# =============================================================================
# Temporal Binding Tests (§5.2A)
# =============================================================================

class TestTemporalBinding:
    """Tests for temporal binding per §5.2A."""

    def test_iat_drift_exceeds_5_seconds(self):
        """iat drift > 5 seconds → PASSPORT_PARSE_FAILED."""
        now = int(time.time())
        passport_iat = now
        identity_iat = now + 10  # 10 second drift
        passport = parse_passport(make_jwt(valid_header(), valid_payload(passport_iat)))
        identity = valid_vvp_identity(identity_iat)
        with pytest.raises(PassportError) as exc:
            validate_passport_binding(passport, identity, now)
        assert exc.value.code == ErrorCode.PASSPORT_PARSE_FAILED
        assert "drift" in exc.value.message.lower()

    def test_iat_drift_exactly_5_seconds_valid(self):
        """iat drift = 5 seconds → Valid."""
        now = int(time.time())
        passport_iat = now
        identity_iat = now + 5  # Exactly 5 second drift (at boundary)
        passport = parse_passport(make_jwt(valid_header(), valid_payload(passport_iat)))
        identity = valid_vvp_identity(identity_iat)
        # Should not raise
        validate_passport_binding(passport, identity, now)

    def test_iat_drift_within_5_seconds_valid(self):
        """iat drift ≤ 5 seconds → Valid."""
        now = int(time.time())
        passport_iat = now
        identity_iat = now + 3  # 3 second drift
        passport = parse_passport(make_jwt(valid_header(), valid_payload(passport_iat)))
        identity = valid_vvp_identity(identity_iat)
        # Should not raise
        validate_passport_binding(passport, identity, now)

    def test_exp_less_than_iat(self):
        """exp < iat → PASSPORT_PARSE_FAILED."""
        now = int(time.time())
        payload = valid_payload(now)
        payload["exp"] = now - 100  # exp before iat
        passport = parse_passport(make_jwt(valid_header(), payload))
        identity = valid_vvp_identity(now)
        with pytest.raises(PassportError) as exc:
            validate_passport_binding(passport, identity, now)
        assert exc.value.code == ErrorCode.PASSPORT_PARSE_FAILED
        assert "exp" in exc.value.message and "iat" in exc.value.message

    def test_exp_equals_iat(self):
        """exp = iat → PASSPORT_PARSE_FAILED."""
        now = int(time.time())
        payload = valid_payload(now)
        payload["exp"] = now  # exp equals iat
        passport = parse_passport(make_jwt(valid_header(), payload))
        identity = valid_vvp_identity(now)
        with pytest.raises(PassportError) as exc:
            validate_passport_binding(passport, identity, now)
        assert exc.value.code == ErrorCode.PASSPORT_PARSE_FAILED
        assert "greater than iat" in exc.value.message

    def test_exp_drift_exceeds_5_seconds(self):
        """exp drift > 5 seconds (both present) → PASSPORT_PARSE_FAILED."""
        now = int(time.time())
        passport_exp = now + 300
        identity_exp = now + 310  # 10 second drift
        payload = valid_payload(now)
        payload["exp"] = passport_exp
        passport = parse_passport(make_jwt(valid_header(), payload))
        identity = VVPIdentity(
            ppt="vvp",
            kid="did:keri:EExampleAID123",
            evd="oobi:http://example.com/oobi/EExampleAID123",
            iat=now,
            exp=identity_exp,
            exp_provided=True,  # Explicit exp for drift check
        )
        with pytest.raises(PassportError) as exc:
            validate_passport_binding(passport, identity, now)
        assert exc.value.code == ErrorCode.PASSPORT_PARSE_FAILED
        assert "exp drift" in exc.value.message.lower()

    def test_exp_drift_within_5_seconds_valid(self):
        """exp drift ≤ 5 seconds → Valid."""
        now = int(time.time())
        passport_exp = now + 300
        identity_exp = now + 303  # 3 second drift
        payload = valid_payload(now)
        payload["exp"] = passport_exp
        passport = parse_passport(make_jwt(valid_header(), payload))
        identity = VVPIdentity(
            ppt="vvp",
            kid="did:keri:EExampleAID123",
            evd="oobi:http://example.com/oobi/EExampleAID123",
            iat=now,
            exp=identity_exp,
            exp_provided=True,  # Explicit exp for drift check
        )
        # Should not raise
        validate_passport_binding(passport, identity, now)


# =============================================================================
# Expiry Policy Tests (§5.2B)
# =============================================================================

class TestExpiryPolicy:
    """Tests for expiry policy per §5.2B."""

    def test_validity_window_exceeds_300_seconds(self):
        """exp - iat > 300 seconds → PASSPORT_EXPIRED."""
        now = int(time.time())
        payload = valid_payload(now)
        payload["exp"] = now + 400  # 400 second validity window
        passport = parse_passport(make_jwt(valid_header(), payload))
        # Use an identity with matching exp to avoid drift check
        identity = VVPIdentity(
            ppt="vvp",
            kid="did:keri:EExampleAID123",
            evd="oobi:http://example.com/oobi/EExampleAID123",
            iat=now,
            exp=now + 400,
            exp_provided=True,  # Explicit exp for drift check
        )
        with pytest.raises(PassportError) as exc:
            validate_passport_binding(passport, identity, now)
        assert exc.value.code == ErrorCode.PASSPORT_EXPIRED
        assert "validity window" in exc.value.message.lower()

    def test_validity_window_exactly_300_seconds_valid(self):
        """exp - iat = 300 seconds → Valid."""
        now = int(time.time())
        payload = valid_payload(now)
        payload["exp"] = now + 300  # Exactly 300 second validity window
        passport = parse_passport(make_jwt(valid_header(), payload))
        identity = valid_vvp_identity(now, now + 300)
        # Should not raise
        validate_passport_binding(passport, identity, now)

    def test_token_expired(self):
        """PASSporT expired (now > exp + skew) → PASSPORT_EXPIRED."""
        now = int(time.time())
        past = now - 1000
        payload = valid_payload(past)
        payload["exp"] = past + 100  # Expired long ago
        passport = parse_passport(make_jwt(valid_header(), payload))
        identity = VVPIdentity(
            ppt="vvp",
            kid="did:keri:EExampleAID123",
            evd="oobi:http://example.com/oobi/EExampleAID123",
            iat=past,
            exp=past + 100,
            exp_provided=True,  # Explicit exp
        )
        with pytest.raises(PassportError) as exc:
            validate_passport_binding(passport, identity, now)
        assert exc.value.code == ErrorCode.PASSPORT_EXPIRED
        assert "expired" in exc.value.message.lower()

    def test_token_not_expired_within_skew(self):
        """Token within clock skew → Valid."""
        now = int(time.time())
        # Token "expired" 100 seconds ago, but within 300s clock skew
        exp_time = now - 100
        iat_time = exp_time - 200
        payload = valid_payload(iat_time)
        payload["exp"] = exp_time
        passport = parse_passport(make_jwt(valid_header(), payload))
        identity = VVPIdentity(
            ppt="vvp",
            kid="did:keri:EExampleAID123",
            evd="oobi:http://example.com/oobi/EExampleAID123",
            iat=iat_time,
            exp=exp_time,
            exp_provided=True,  # Explicit exp
        )
        # Should not raise (within 300s clock skew)
        validate_passport_binding(passport, identity, now)

    def test_max_age_exceeded_no_exp(self):
        """exp absent (both), max-age exceeded → PASSPORT_EXPIRED."""
        now = int(time.time())
        old_iat = now - 1000  # Very old
        payload = valid_payload(old_iat)
        # No exp field in PASSporT
        passport = parse_passport(make_jwt(valid_header(), payload))
        # VVP-Identity exp computed (not explicit) - tests §5.2B max-age policy
        identity = VVPIdentity(
            ppt="vvp",
            kid="did:keri:EExampleAID123",
            evd="oobi:http://example.com/oobi/EExampleAID123",
            iat=old_iat,
            exp=old_iat + 300,
            exp_provided=False,  # Computed default - follow max-age policy
        )
        with pytest.raises(PassportError) as exc:
            validate_passport_binding(passport, identity, now)
        assert exc.value.code == ErrorCode.PASSPORT_EXPIRED
        assert "max-age" in exc.value.message.lower()

    def test_max_age_within_limit_no_exp(self):
        """exp absent (both computed), within max-age → Valid per §5.2B."""
        now = int(time.time())
        recent_iat = now - 100  # Recent (within 300s + 300s skew)
        payload = valid_payload(recent_iat)
        # No exp field in PASSporT
        passport = parse_passport(make_jwt(valid_header(), payload))
        # VVP-Identity exp computed (not explicit) - tests §5.2B max-age policy
        identity = VVPIdentity(
            ppt="vvp",
            kid="did:keri:EExampleAID123",
            evd="oobi:http://example.com/oobi/EExampleAID123",
            iat=recent_iat,
            exp=recent_iat + 300,
            exp_provided=False,  # Computed default - follow max-age policy
        )
        # Should not raise - both exp absent, within max-age per §5.2B
        validate_passport_binding(passport, identity, now)

    def test_exp_omission_rejected_when_identity_exp_explicit(self):
        """PASSporT exp absent, VVP-Identity exp explicit → PASSPORT_EXPIRED per §5.2A.

        §5.2A: "If VVP-Identity exp is present but PASSporT exp is absent,
        the verifier MUST treat the PASSporT as expired unless explicitly
        configured to allow exp omission (default: reject)."
        """
        now = int(time.time())
        payload = valid_payload(now)
        # No exp field in PASSporT
        passport = parse_passport(make_jwt(valid_header(), payload))
        # VVP-Identity has explicit exp
        identity = VVPIdentity(
            ppt="vvp",
            kid="did:keri:EExampleAID123",
            evd="oobi:http://example.com/oobi/EExampleAID123",
            iat=now,
            exp=now + 300,
            exp_provided=True,  # Explicit exp - triggers §5.2A rejection
        )
        with pytest.raises(PassportError) as exc:
            validate_passport_binding(passport, identity, now)
        assert exc.value.code == ErrorCode.PASSPORT_EXPIRED
        assert "exp absent" in exc.value.message.lower() or "omission" in exc.value.message.lower()

    def test_exp_omission_allowed_when_configured(self):
        """PASSporT exp absent, VVP-Identity exp explicit, but ALLOW_PASSPORT_EXP_OMISSION=True → Valid.

        Tests the §5.2A configuration override: when ALLOW_PASSPORT_EXP_OMISSION is True,
        PASSporT exp omission is permitted even when VVP-Identity has explicit exp.
        """
        import app.vvp.passport as passport_module

        now = int(time.time())
        payload = valid_payload(now)
        # No exp field in PASSporT
        passport = parse_passport(make_jwt(valid_header(), payload))
        # VVP-Identity has explicit exp
        identity = VVPIdentity(
            ppt="vvp",
            kid="did:keri:EExampleAID123",
            evd="oobi:http://example.com/oobi/EExampleAID123",
            iat=now,
            exp=now + 300,
            exp_provided=True,  # Explicit exp - would normally trigger rejection
        )
        # Patch the config to allow exp omission
        original_value = passport_module.ALLOW_PASSPORT_EXP_OMISSION
        try:
            passport_module.ALLOW_PASSPORT_EXP_OMISSION = True
            # Should not raise when config allows omission
            validate_passport_binding(passport, identity, now)
        finally:
            passport_module.ALLOW_PASSPORT_EXP_OMISSION = original_value


# =============================================================================
# Signature Decoding Tests
# =============================================================================

class TestSignatureDecoding:
    """Tests for signature decoding (Phase 4 prep)."""

    def test_signature_preserved(self):
        """Signature bytes preserved for Phase 4 verification."""
        jwt = make_jwt(valid_header(), valid_payload())
        passport = parse_passport(jwt)
        assert isinstance(passport.signature, bytes)
        assert len(passport.signature) > 0

    def test_raw_header_preserved(self):
        """Raw header preserved for signature verification."""
        jwt = make_jwt(valid_header(), valid_payload())
        passport = parse_passport(jwt)
        assert passport.raw_header == jwt.split(".")[0]

    def test_raw_payload_preserved(self):
        """Raw payload preserved for signature verification."""
        jwt = make_jwt(valid_header(), valid_payload())
        passport = parse_passport(jwt)
        assert passport.raw_payload == jwt.split(".")[1]

    def test_invalid_signature_base64(self):
        """Invalid base64 in signature → PASSPORT_PARSE_FAILED."""
        header = b64url_encode(valid_header())
        payload = b64url_encode(valid_payload())
        # Python base64 is lenient, but a single character causes padding error:
        # 1 data char can't be 1 more than multiple of 4
        with pytest.raises(PassportError) as exc:
            parse_passport(f"{header}.{payload}.A")
        assert exc.value.code == ErrorCode.PASSPORT_PARSE_FAILED
        assert "signature" in exc.value.message.lower()


# =============================================================================
# Edge Cases
# =============================================================================

class TestEdgeCases:
    """Edge case tests."""

    def test_whitespace_trimmed(self):
        """Leading/trailing whitespace trimmed from JWT."""
        jwt = make_jwt(valid_header(), valid_payload())
        passport = parse_passport(f"  {jwt}  ")
        assert passport.header.alg == "EdDSA"

    def test_extra_header_fields_ignored(self):
        """Extra header fields ignored."""
        header = valid_header()
        header["extra"] = "ignored"
        jwt = make_jwt(header, valid_payload())
        passport = parse_passport(jwt)
        assert passport.header.alg == "EdDSA"

    def test_extra_payload_fields_ignored(self):
        """Extra payload fields ignored."""
        payload = valid_payload()
        payload["extra"] = "ignored"
        jwt = make_jwt(valid_header(), payload)
        passport = parse_passport(jwt)
        assert passport.payload.iat is not None

    def test_call_reason_mapped(self):
        """call-reason maps to call_reason."""
        payload = valid_payload()
        payload["call-reason"] = "business-inquiry"
        jwt = make_jwt(valid_header(), payload)
        passport = parse_passport(jwt)
        assert passport.payload.call_reason == "business-inquiry"
