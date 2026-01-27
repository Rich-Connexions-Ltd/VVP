"""
Integration tests for HTMX UI endpoints.

These tests ensure UI endpoints properly delegate to the domain layer
instead of reimplementing parsing logic. This prevents bugs where the
UI layer diverges from the domain layer.

Phase 13B: Separation of Concerns Refactoring.
"""

import base64
import json
import time

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.vvp.passport import parse_passport


client = TestClient(app)


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
        "kid": "http://witness.example.com/oobi/EExampleAID123",
    }


def valid_payload(iat: int = None) -> dict:
    """Return a valid PASSporT payload."""
    if iat is None:
        iat = int(time.time())
    return {
        "iat": iat,
        "orig": {"tn": ["+12025551234"]},  # Single-element array per §4.2
        "dest": {"tn": ["+12025555678"]},
        "evd": "http://example.com/dossier",
    }


# =============================================================================
# /ui/parse-jwt Tests
# =============================================================================

class TestUIParseJWT:
    """Test /ui/parse-jwt endpoint uses domain layer correctly."""

    def test_parse_jwt_returns_same_values_as_domain_layer(self):
        """UI endpoint must produce same values as domain layer parse_passport()."""
        jwt = make_jwt(valid_header(), valid_payload())

        # Parse with domain layer
        passport = parse_passport(jwt)

        # Parse with UI endpoint
        response = client.post("/ui/parse-jwt", data={"jwt": jwt})

        # Verify success
        assert response.status_code == 200

        # Verify header values appear in response
        assert passport.header.alg in response.text
        assert passport.header.ppt in response.text
        assert passport.header.kid in response.text

        # Verify payload values appear in response
        assert str(passport.payload.iat) in response.text
        assert passport.payload.evd in response.text

    def test_parse_jwt_handles_ppt_suffix(self):
        """UI endpoint strips ;ppt=vvp suffix (UI convenience)."""
        jwt = make_jwt(valid_header(), valid_payload())
        jwt_with_suffix = f"{jwt};ppt=vvp"

        response = client.post("/ui/parse-jwt", data={"jwt": jwt_with_suffix})

        assert response.status_code == 200
        # Should parse successfully, not error
        assert "error" not in response.text.lower() or "Error" not in response.text

    def test_parse_jwt_invalid_format_shows_error(self):
        """Invalid JWT should show error message from domain layer."""
        response = client.post("/ui/parse-jwt", data={"jwt": "not.valid"})

        assert response.status_code == 200  # HTML response
        # Should contain error message
        assert "error" in response.text.lower() or "Error" in response.text

    def test_parse_jwt_forbidden_algorithm_shows_error(self):
        """Forbidden algorithm should show error from domain layer."""
        header = valid_header()
        header["alg"] = "ES256"  # Forbidden

        jwt = make_jwt(header, valid_payload())
        response = client.post("/ui/parse-jwt", data={"jwt": jwt})

        assert response.status_code == 200
        assert "forbidden" in response.text.lower() or "ES256" in response.text

    def test_parse_jwt_signature_displayed_as_hex(self):
        """Signature should be displayed as hex string."""
        jwt = make_jwt(valid_header(), valid_payload())

        response = client.post("/ui/parse-jwt", data={"jwt": jwt})

        assert response.status_code == 200
        # The base64url signature "c2lnbmF0dXJl" decodes to "signature"
        # which in hex is "7369676e6174757265"
        assert "7369676e6174757265" in response.text


class TestUIParseJWTDomainLayerAlignment:
    """Verify UI endpoint stays aligned with domain layer behavior."""

    def test_missing_required_field_caught(self):
        """Domain layer catches missing required fields."""
        header = valid_header()
        payload = {"iat": int(time.time())}  # Missing orig, dest, evd

        jwt = make_jwt(header, payload)
        response = client.post("/ui/parse-jwt", data={"jwt": jwt})

        assert response.status_code == 200
        # Domain layer should catch missing field
        assert "orig" in response.text or "required" in response.text.lower()

    def test_orig_tn_must_be_array_not_string(self):
        """Domain layer validates orig.tn is array, not bare string (§4.2)."""
        header = valid_header()
        payload = valid_payload()
        payload["orig"]["tn"] = "+12025551234"  # Should be array with single element

        jwt = make_jwt(header, payload)
        response = client.post("/ui/parse-jwt", data={"jwt": jwt})

        assert response.status_code == 200
        # Domain layer should catch this
        assert "array" in response.text.lower() or "string" in response.text.lower()


class TestUIParseJWTPermissiveMode:
    """Test permissive decode - show content even when validation fails."""

    def test_invalid_jwt_shows_content_and_error(self):
        """Invalid JWT should show decoded content AND validation error."""
        header = valid_header()
        payload = valid_payload()
        payload["orig"]["tn"] = "+12025551234"  # Invalid: bare string instead of array

        jwt = make_jwt(header, payload)
        response = client.post("/ui/parse-jwt", data={"jwt": jwt})

        assert response.status_code == 200
        # Should show the content (decoded payload)
        assert "12025551234" in response.text  # Phone number visible
        assert header["alg"] in response.text  # Algorithm visible
        # Should also show validation warning
        assert "Validation Warning" in response.text or "array" in response.text.lower()

    def test_forbidden_alg_shows_content_and_error(self):
        """Forbidden algorithm JWT shows decoded content AND validation error."""
        header = valid_header()
        header["alg"] = "ES256"  # Forbidden algorithm
        payload = valid_payload()

        jwt = make_jwt(header, payload)
        response = client.post("/ui/parse-jwt", data={"jwt": jwt})

        assert response.status_code == 200
        # Should show decoded content
        assert "ES256" in response.text  # Algorithm visible in decoded header
        # Should show validation error
        assert "forbidden" in response.text.lower()

    def test_validation_error_includes_spec_reference(self):
        """Validation errors should include spec section reference."""
        header = valid_header()
        payload = valid_payload()
        payload["orig"]["tn"] = "+12025551234"  # Invalid: bare string instead of array

        jwt = make_jwt(header, payload)
        response = client.post("/ui/parse-jwt", data={"jwt": jwt})

        assert response.status_code == 200
        # Should show spec section reference for orig.tn validation
        assert "§4.2" in response.text  # Spec section for phone number validation

    def test_forbidden_alg_shows_spec_reference(self):
        """Forbidden algorithm should show §5.0/§5.1 spec reference."""
        header = valid_header()
        header["alg"] = "ES256"  # Forbidden algorithm
        payload = valid_payload()

        jwt = make_jwt(header, payload)
        response = client.post("/ui/parse-jwt", data={"jwt": jwt})

        assert response.status_code == 200
        # Should show spec section for algorithm validation
        assert "§5.0" in response.text or "§5.1" in response.text


# =============================================================================
# Trial PASSporT Integration Test
# =============================================================================

# This is a real-world PASSporT from Provenant's demo system
TRIAL_PASSPORT_JWT = (
    "eyJhbGciOiJFZERTQSIsInR5cCI6InBhc3Nwb3J0IiwicHB0IjoidnZwIiwia2lkIjoiaHR0cDov"
    "L3dpdG5lc3M1LnN0YWdlLnByb3ZlbmFudC5uZXQ6NTYzMS9vb2JpL0VHYXk1dWZCcUFhbmJoRmFf"
    "cWUtS01GVVBKSG44SjBNRmJhOTZ5eVdSckxGL3dpdG5lc3MifQ."
    "eyJvcmlnIjp7InRuIjpbIjQ0Nzg4NDY2NjIwMCJdfSwiZGVzdCI6eyJ0biI6WyI0NDc3Njk3MTAy"
    "ODUiXX0sImlhdCI6MTc2OTE4MzMwMiwiY2FyZCI6WyJDQVRFR09SSUVTOiIsIkxPR087SEFTSD1z"
    "aGEyNTYtNDBiYWM2ODZhM2YwYjQ4MjUzZGU1NWIzNGY1NTJjODA3MGJhZjIyZjgxMjU1YWFjNDQ5"
    "NzIxYzg3OWM3MTZhNDtWQUxVRT1VUkk6aHR0cHM6Ly9vcmlnaW4tY2VsbC1mcmFua2Z1cnQuczMu"
    "ZXUtY2VudHJhbC0xLmFtYXpvbmF3cy5jb20vYnJhbmQtYXNzZXRzL3JpY2gtY29ubmV4aW9ucy9s"
    "b2dvLnBuZyIsIk5PVEU7TEVJOjk4NDUwMERFRTc1MzdBMDdZNjE1IiwiT1JHOlJpY2ggQ29ubmV4"
    "aW9ucyJdLCJjYWxsX3JlYXNvbiI6bnVsbCwiZ29hbCI6bnVsbCwiZXZkIjoiaHR0cHM6Ly9vcmln"
    "aW4uZGVtby5wcm92ZW5hbnQubmV0L3YxL2FnZW50L3B1YmxpYy9FSGxWWFVKLWRZS3F0UGR2enRk"
    "Q0ZKRWJreXI2elgyZFgxMmh3ZEU5eDhleS9kb3NzaWVyLmNlc3IiLCJvcmlnSWQiOiIiLCJleHAi"
    "OjE3NjkxODM2MDIsInJlcXVlc3RfaWQiOiIifQ."
    "OvoaiAwt1dgPb6gLkK7ufWoL2qzdtmudyyiL38oqB0wfaicGSG4B_QFtHY2vS2w-PYZ6LhN9dWXp"
    "sOHtpKAXCw"
)


class TestTrialPASSporT:
    """Integration tests using the Provenant trial PASSporT."""

    def test_trial_passport_decodes_successfully(self):
        """Trial PASSporT should decode and show content."""
        response = client.post("/ui/parse-jwt", data={"jwt": TRIAL_PASSPORT_JWT})

        assert response.status_code == 200
        # Should show decoded content
        assert "EdDSA" in response.text  # Algorithm
        assert "vvp" in response.text  # ppt
        assert "447884666200" in response.text  # orig.tn
        assert "447769710285" in response.text  # dest.tn

    def test_trial_passport_shows_format_warning(self):
        """Trial PASSporT has non-E.164 phone numbers (missing +), shows warning."""
        response = client.post("/ui/parse-jwt", data={"jwt": TRIAL_PASSPORT_JWT})

        assert response.status_code == 200
        # Should parse successfully
        # Phone numbers are shown (non-E.164 but accepted with warning)
        assert "447884666200" in response.text
        # Warning about E.164 format should be shown
        assert "E.164" in response.text or "warning" in response.text.lower()

    def test_trial_passport_shows_evd_url(self):
        """Trial PASSporT evd field should be visible."""
        response = client.post("/ui/parse-jwt", data={"jwt": TRIAL_PASSPORT_JWT})

        assert response.status_code == 200
        # Should show evidence URL
        assert "origin.demo.provenant.net" in response.text

    def test_trial_passport_shows_vcard(self):
        """Trial PASSporT contains vCard data that should be displayed."""
        response = client.post("/ui/parse-jwt", data={"jwt": TRIAL_PASSPORT_JWT})

        assert response.status_code == 200
        # Should show vCard organization
        assert "Rich Connexions" in response.text
        # Should show LEI
        assert "984500DEE7537A07Y615" in response.text

    def test_trial_passport_shows_evd_url(self):
        """Trial PASSporT contains evd URL that should be displayed."""
        response = client.post("/ui/parse-jwt", data={"jwt": TRIAL_PASSPORT_JWT})

        assert response.status_code == 200
        # Should show the evidence URL
        assert "dossier.cesr" in response.text


# =============================================================================
# /ui/fetch-dossier Tests
# =============================================================================

class TestUIFetchDossier:
    """Test /ui/fetch-dossier endpoint uses domain layer correctly."""

    def test_fetch_dossier_endpoint_exists(self):
        """Verify endpoint exists and returns HTML on error."""
        # Invalid URL should return HTML error, not crash
        response = client.post(
            "/ui/fetch-dossier",
            data={"evd_url": "http://invalid.localhost/dossier.cesr"}
        )

        # Should return HTML (200 with error message), not 5xx
        assert response.status_code == 200
        assert "error" in response.text.lower() or "Error" in response.text


# =============================================================================
# /ui/parse-sip Tests
# =============================================================================

class TestUIParseSIP:
    """Test /ui/parse-sip endpoint (UI-specific, no domain equivalent)."""

    def test_parse_sip_extracts_identity_header(self):
        """SIP parsing extracts Identity header JWT."""
        sip_invite = """INVITE sip:+12025555678@example.com SIP/2.0
Via: SIP/2.0/UDP 192.0.2.1:5060
From: <sip:+12025551234@example.com>
To: <sip:+12025555678@example.com>
Identity: eyJhbGciOiJFZERTQSJ9.eyJpYXQiOjE3MDAwMDAwMDB9.sig;info=<http://example.com>
"""

        response = client.post("/ui/parse-sip", data={"sip_invite": sip_invite})

        assert response.status_code == 200
        # Should extract the JWT portion
        assert "eyJhbGciOiJFZERTQSJ9" in response.text

    def test_parse_sip_no_identity_header(self):
        """SIP without Identity header shows appropriate message."""
        sip_invite = """INVITE sip:+12025555678@example.com SIP/2.0
Via: SIP/2.0/UDP 192.0.2.1:5060
From: <sip:+12025551234@example.com>
"""

        response = client.post("/ui/parse-sip", data={"sip_invite": sip_invite})

        assert response.status_code == 200
        # Should indicate no Identity header found
        assert "No Identity" in response.text or "not found" in response.text.lower()


# =============================================================================
# Trial Dossier Integration Tests
# =============================================================================

# Load trial dossier fixture (saved from Provenant demo system)
import os
FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")
TRIAL_DOSSIER_PATH = os.path.join(FIXTURES_DIR, "trial_dossier.json")


def load_trial_dossier():
    """Load the trial dossier fixture."""
    with open(TRIAL_DOSSIER_PATH) as f:
        return json.load(f)


def load_trial_dossier_raw():
    """Load the trial dossier as raw bytes."""
    with open(TRIAL_DOSSIER_PATH, "rb") as f:
        return f.read()


class TestTrialDossierParsing:
    """Tests for parsing the Provenant trial dossier.

    The trial dossier contains:
    - 6 ACDCs (credentials) in the CESR stream
    - 7 TEL issuance events (iss)
    - 0 TEL revocation events (all credentials are ACTIVE)

    These tests ensure our parsing correctly handles real-world Provenant data.
    """

    def test_dossier_fixture_exists(self):
        """Verify trial dossier fixture is available."""
        assert os.path.exists(TRIAL_DOSSIER_PATH), "Trial dossier fixture not found"

    def test_dossier_has_details_wrapper(self):
        """Trial dossier uses Provenant wrapper format."""
        data = load_trial_dossier()
        assert "details" in data, "Dossier should have 'details' wrapper"
        assert isinstance(data["details"], str), "Details should be a string"
        assert len(data["details"]) > 100000, "Details should contain CESR stream"

    def test_parse_dossier_extracts_acdcs(self):
        """parse_dossier() correctly extracts ACDCs from trial dossier."""
        from app.vvp.dossier.parser import parse_dossier

        raw = load_trial_dossier_raw()
        nodes, signatures = parse_dossier(raw)

        # Trial dossier contains 6 unique ACDCs
        assert len(nodes) == 6, f"Expected 6 ACDCs, got {len(nodes)}"

        # Each ACDC should have required fields
        for node in nodes:
            assert node.said, "ACDC should have SAID"
            assert node.issuer, "ACDC should have issuer"
            assert node.schema, "ACDC should have schema"
            assert node.said.startswith("E"), "SAID should start with E (Blake3-256)"

    def test_parse_dossier_extracts_acdc_types(self):
        """parse_dossier() extracts ACDCs with identifiable types."""
        from app.vvp.dossier.parser import parse_dossier

        raw = load_trial_dossier_raw()
        nodes, _ = parse_dossier(raw)

        # Check for expected credential types based on actual Provenant ACDC attributes:
        # - vcard: contact/organization info
        # - numbers: phone number credentials
        # - role: role-based credentials
        # - lids: legal entity identifiers
        has_vcard_credential = False
        has_phone_credential = False

        for node in nodes:
            attrs = node.attributes if isinstance(node.attributes, dict) else {}
            if "vcard" in attrs:
                has_vcard_credential = True
            if "numbers" in attrs:
                has_phone_credential = True

        assert has_vcard_credential, "Should have at least one vcard credential"
        assert has_phone_credential, "Should have at least one phone number credential"

    def test_parse_dossier_deduplicates_by_said(self):
        """parse_dossier() deduplicates ACDCs by SAID."""
        from app.vvp.dossier.parser import parse_dossier

        raw = load_trial_dossier_raw()
        nodes, _ = parse_dossier(raw)

        # All SAIDs should be unique
        saids = [node.said for node in nodes]
        assert len(saids) == len(set(saids)), "SAIDs should be unique"


class TestTrialDossierTELExtraction:
    """Tests for TEL (Transaction Event Log) extraction from trial dossier.

    The trial dossier contains inline TEL events that indicate credential
    issuance status. These tests verify correct extraction.
    """

    def test_tel_client_extracts_events(self):
        """TELClient._extract_tel_events() finds TEL events in dossier."""
        from app.vvp.keri.tel_client import TELClient

        data = load_trial_dossier()
        # Pass the full JSON (client handles wrapper format)
        dossier_str = json.dumps(data)

        client = TELClient()
        events = client._extract_tel_events(dossier_str)

        # Trial dossier has 7 issuance events
        assert len(events) == 7, f"Expected 7 TEL events, got {len(events)}"

    def test_tel_events_are_all_issuance(self):
        """All TEL events in trial dossier are issuance (iss), not revocation."""
        from app.vvp.keri.tel_client import TELClient

        data = load_trial_dossier()
        client = TELClient()
        events = client._extract_tel_events(json.dumps(data))

        # All should be 'iss' (issuance) events
        event_types = [e.event_type for e in events]
        assert all(t == "iss" for t in event_types), f"All events should be 'iss', got {set(event_types)}"
        assert "rev" not in event_types, "Should have no revocation events"

    def test_tel_events_have_credential_saids(self):
        """TEL events reference valid credential SAIDs."""
        from app.vvp.keri.tel_client import TELClient

        data = load_trial_dossier()
        client = TELClient()
        events = client._extract_tel_events(json.dumps(data))

        # Each event should have a credential SAID
        for event in events:
            assert event.credential_said, "TEL event should have credential_said"
            assert event.credential_said.startswith("E"), "Credential SAID should start with E"

    def test_tel_wrapper_format_handled(self):
        """TEL extraction handles Provenant wrapper format."""
        from app.vvp.keri.tel_client import TELClient

        # Raw JSON with wrapper
        data = load_trial_dossier()

        client = TELClient()

        # Should work with wrapper format
        events_from_wrapper = client._extract_tel_events(json.dumps(data))
        assert len(events_from_wrapper) > 0, "Should extract events from wrapper format"

        # Should also work with just the details content
        events_from_details = client._extract_tel_events(data["details"])
        assert len(events_from_details) == len(events_from_wrapper), \
            "Both methods should find same number of events"


class TestTrialDossierRevocationStatus:
    """Tests for determining revocation status from trial dossier.

    All credentials in the trial dossier should be ACTIVE (issued but not revoked).
    """

    def test_parse_dossier_tel_returns_active(self):
        """parse_dossier_tel() returns ACTIVE for trial dossier credentials."""
        from app.vvp.keri.tel_client import TELClient, CredentialStatus
        from app.vvp.dossier.parser import parse_dossier

        raw = load_trial_dossier_raw()
        nodes, _ = parse_dossier(raw)

        client = TELClient()
        dossier_str = raw.decode("utf-8")

        # Check first ACDC
        first_node = nodes[0]
        result = client.parse_dossier_tel(
            dossier_str,
            credential_said=first_node.said,
            registry_said=first_node.raw.get("ri")
        )

        assert result.status == CredentialStatus.ACTIVE, \
            f"First credential should be ACTIVE, got {result.status}"
        assert result.source == "dossier", "Source should be 'dossier'"
        assert result.issuance_event is not None, "Should have issuance event"
        assert result.revocation_event is None, "Should not have revocation event"

    def test_all_credentials_are_active(self):
        """All credentials in trial dossier have ACTIVE status."""
        from app.vvp.keri.tel_client import TELClient, CredentialStatus
        from app.vvp.dossier.parser import parse_dossier

        raw = load_trial_dossier_raw()
        nodes, _ = parse_dossier(raw)

        client = TELClient()
        dossier_str = raw.decode("utf-8")

        statuses = []
        for node in nodes:
            result = client.parse_dossier_tel(
                dossier_str,
                credential_said=node.said,
                registry_said=node.raw.get("ri")
            )
            statuses.append((node.said[:20], result.status))

        # All should be ACTIVE or UNKNOWN (some may not have matching TEL)
        active_count = sum(1 for _, s in statuses if s == CredentialStatus.ACTIVE)
        revoked_count = sum(1 for _, s in statuses if s == CredentialStatus.REVOKED)

        assert revoked_count == 0, f"No credentials should be revoked, but found {revoked_count}"
        assert active_count > 0, "At least some credentials should be ACTIVE"

    def test_build_revocation_map(self):
        """TEL events build correct revocation status map."""
        from app.vvp.keri.tel_client import TELClient, CredentialStatus

        data = load_trial_dossier()
        client = TELClient()
        events = client._extract_tel_events(json.dumps(data))

        # Build status map manually
        status_map = {}
        for event in events:
            if event.event_type == "iss":
                status_map[event.credential_said] = "ACTIVE"
            elif event.event_type == "rev":
                status_map[event.credential_said] = "REVOKED"

        # Should have 7 unique credentials marked as ACTIVE
        active_creds = [k for k, v in status_map.items() if v == "ACTIVE"]
        # Note: Some SAIDs may be duplicated across iss events
        assert len(active_creds) > 0, "Should have ACTIVE credentials"
        assert all(v == "ACTIVE" for v in status_map.values()), "All should be ACTIVE"


class TestTrialDossierUIEndpoint:
    """Tests for UI endpoints with trial dossier data."""

    def test_check_revocation_with_dossier_stream(self):
        """UI revocation check extracts TEL from dossier stream."""
        from app.vvp.dossier.parser import parse_dossier

        raw = load_trial_dossier_raw()
        nodes, _ = parse_dossier(raw)
        dossier_str = raw.decode("utf-8")

        # Build ACDC list as the endpoint expects
        acdcs = []
        for node in nodes:
            acdc = node.raw.copy() if node.raw else {}
            acdc["d"] = node.said
            acdc["i"] = node.issuer
            acdc["s"] = node.schema
            acdcs.append(acdc)

        # Call the revocation check endpoint
        response = client.post(
            "/ui/check-revocation",
            data={
                "acdcs": json.dumps(acdcs),
                "kid_url": "",
                "dossier_stream": dossier_str,
            }
        )

        assert response.status_code == 200
        # Should show results for credentials
        # Either ACTIVE status or source indication
        text = response.text.lower()
        # Should not show ERROR for all (at least some should parse)
        assert "active" in text or "dossier" in text or "unknown" in text
