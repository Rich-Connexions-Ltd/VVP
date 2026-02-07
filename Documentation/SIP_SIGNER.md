# VVP SIP Signing Service - Administrator Guide

## Overview

The VVP SIP Signing Service is a SIP redirect server that adds cryptographic attestation to outbound calls. When your PBX or SBC sends a SIP INVITE to this service, it:

1. Authenticates your organization via the `X-VVP-API-Key` header
2. Looks up the originating telephone number (TN) in your configured mappings
3. Validates that your organization owns the TN (via TN Allocation credentials)
4. Creates VVP-Identity and PASSporT headers proving your identity
5. Returns a SIP 302 redirect with the attestation headers attached

Your SBC then forwards the call to the carrier with the VVP headers, providing cryptographic proof of caller identity.

## Architecture

```
                                    ┌─────────────────────┐
                                    │   VVP Issuer API    │
                                    │  (TN Mappings, VVP  │
                                    │   Header Creation)  │
                                    └──────────▲──────────┘
                                               │ HTTPS
                                               │
┌─────────────┐    SIP INVITE     ┌────────────┴────────────┐
│             │   + X-VVP-API-Key │                         │
│  Your PBX   │ ────────────────> │   VVP SIP Signer       │
│    / SBC    │                   │   (UDP 5070 live, or   │
│             │ <──────────────── │    5060/5061 prod)     │
└─────────────┘    302 Redirect   └─────────────────────────┘
       │           + VVP Headers
       │
       │    INVITE + VVP Headers
       ▼
┌─────────────┐
│   Carrier   │
│   Network   │
└─────────────┘
```

## Prerequisites

Before using the SIP signing service, you must:

1. **Have an Organization in VVP Issuer** - Your organization must be registered
2. **Have an API Key** - Create an org API key with `dossier_manager` role
3. **Have TN Mappings Configured** - Map your phone numbers to dossiers
4. **Have TN Allocation Credentials** - Credentials proving you own the TNs

### Creating TN Mappings

In the VVP Issuer UI (`/ui/tn-mappings`), create mappings for each TN you want to attest:

| Field | Description |
|-------|-------------|
| **Telephone Number** | E.164 format (e.g., `+15551234567`) |
| **Dossier** | The credential chain for attestation |
| **Signing Identity** | KERI identity used to sign VVP headers |

---

## PBX/SBC Configuration

### Required SIP Header

Your PBX/SBC must add the following header to INVITE requests sent to the signing service:

```
X-VVP-API-Key: <your-api-key>
```

This header authenticates your organization and determines which TN mappings are available.

### Routing Configuration

Configure your PBX/SBC to route outbound calls through the signing service:

| Setting | Value |
|---------|-------|
| **Destination Host** | `<sip-signer-host>` |
| **Port** | `5060` (UDP/TCP) or `5061` (TLS/SIPS) |
| **Protocol** | UDP, TCP, or TLS |

#### Example: FreeSWITCH Dialplan

```xml
<extension name="vvp-outbound">
  <condition field="destination_number" expression="^(\d{10,15})$">
    <!-- Add API key header -->
    <action application="set" data="sip_h_X-VVP-API-Key=vvp_org_abc123..."/>

    <!-- Route through VVP signer -->
    <action application="bridge" data="sofia/external/$1@sip-signer.example.com:5060"/>
  </condition>
</extension>
```

#### Example: Kamailio Configuration

```
# Add API key header
append_hf("X-VVP-API-Key: vvp_org_abc123...\r\n");

# Route to VVP signer
$du = "sip:sip-signer.example.com:5060";
route(RELAY);
```

#### Example: Asterisk Dialplan

```
[outbound-vvp]
exten => _X.,1,Set(PJSIP_HEADER(add,X-VVP-API-Key)=vvp_org_abc123...)
same => n,Dial(PJSIP/${EXTEN}@vvp-signer)
```

---

## Response Handling

### Successful Attestation (302 Moved Temporarily)

When the TN is mapped and validated, you receive a **302** response with VVP headers:

```
SIP/2.0 302 Moved Temporarily
Via: SIP/2.0/UDP your-pbx.example.com:5060;branch=z9hG4bK...
From: <sip:+15551234567@your-pbx.example.com>;tag=abc123
To: <sip:+14445678901@carrier.com>;tag=def456
Call-ID: unique-call-id@your-pbx.example.com
CSeq: 1 INVITE
Contact: <sip:+14445678901@carrier.com>
P-VVP-Identity: eyJhbGciOiJFZERTQSIsInR5cCI6InZkcCJ9...
P-VVP-Passport: eyJhbGciOiJFZERTQSIsInR5cCI6InBhc3Nwb3J0In0...
X-VVP-Brand-Name: Your Company Inc
X-VVP-Brand-Logo: https://example.com/logo.png
X-VVP-Status: VALID
Content-Length: 0
```

**Your SBC should:**
1. Extract the VVP headers (`P-VVP-Identity`, `P-VVP-Passport`, `X-VVP-Brand-Name`, etc.)
2. Add these headers to the outbound INVITE to the carrier
3. Follow the redirect to complete the call

### Error Responses

#### 401 Unauthorized - Missing or Invalid API Key

```
SIP/2.0 401 Unauthorized
...
X-VVP-Status: INVALID
Content-Length: 0
```

**Causes:**
- `X-VVP-API-Key` header missing from request
- API key is invalid or revoked
- API key belongs to a disabled organization

**Resolution:**
- Verify the API key is correctly configured in your PBX/SBC
- Check that the API key is active in the VVP Issuer UI

#### 403 Forbidden - Rate Limited or Unauthorized TN

```
SIP/2.0 403 Forbidden
...
X-VVP-Status: INVALID
Content-Length: 0
```

**Causes:**
- Rate limit exceeded (too many requests per second)
- TN is not covered by your organization's TN Allocation credentials

**Resolution:**
- If rate limited, reduce call volume or contact administrator
- Verify you have valid TN Allocation credentials for the calling number

#### 404 Not Found - TN Not Mapped

```
SIP/2.0 404 Not Found
...
X-VVP-Status: INVALID
Content-Length: 0
```

**Causes:**
- No TN mapping exists for the originating phone number
- TN mapping exists but is disabled

**Resolution:**
- Create a TN mapping in the VVP Issuer UI (`/ui/tn-mappings`)
- Ensure the mapping is enabled

#### 500 Server Internal Error

```
SIP/2.0 500 Server Internal Error
...
X-VVP-Status: INDETERMINATE
Content-Length: 0
```

**Causes:**
- Internal service error (database, API connectivity, etc.)

**Resolution:**
- Retry the call
- Contact administrator if persistent

---

## X-VVP-Status Values

Every response includes the `X-VVP-Status` header indicating the attestation result:

| Status | Meaning | Response Code |
|--------|---------|---------------|
| `VALID` | TN successfully attested | 302 |
| `INVALID` | Authentication or authorization failed | 401, 403, 404 |
| `INDETERMINATE` | Unable to determine (internal error) | 500 |

---

## Rate Limiting

The service enforces per-API-key rate limiting to prevent abuse:

| Parameter | Default | Description |
|-----------|---------|-------------|
| Requests per second | 10 | Sustained request rate |
| Burst size | 50 | Maximum burst before throttling |

If you exceed the rate limit, you'll receive a **403 Forbidden** response. The rate limit resets over time using a token bucket algorithm.

---

## Deployed Service Location

The VVP SIP Signing Service is deployed at:

| Service | Host | Port | Protocol | Status |
|---------|------|------|----------|--------|
| **SIP Signer (Live)** | `pbx.rcnx.io` | 5070 | UDP | **Deployed** |
| **SIP Signer (Production)** | `pbx.rcnx.io` | 5060 | UDP/TCP | Future |
| **SIP Signer (TLS)** | `pbx.rcnx.io` | 5061 | TLS/SIPS | Future |
| **Status Endpoint** | `pbx.rcnx.io` | 8080 | HTTP | Deployed |
| **VVP Issuer API** | `vvp-issuer.rcnx.io` | 443 | HTTPS | Deployed |
| **VVP Verifier API** | `vvp-verifier.rcnx.io` | 443 | HTTPS | Deployed |

> **Note:** The current live deployment uses port **5070** for testing and development.
> Production deployments will use standard SIP ports 5060/5061 once enterprise TLS
> configuration is complete. See [DEPLOYMENT.md](DEPLOYMENT.md#port-reference) for
> the authoritative port mapping.

### DNS Records

```
pbx.rcnx.io          → VVP PBX VM (SIP Signer)
vvp-issuer.rcnx.io   → Azure Container App (Issuer)
vvp-verifier.rcnx.io → Azure Container App (Verifier)
```

---

## Service Endpoints

### Current Live Deployment (Testing)

| Protocol | Port | Description |
|----------|------|-------------|
| UDP | 5070 | SIP signer (current live) |
| HTTP | 8080 | Status endpoint (admin auth required) |

### Production Deployment (Future)

| Protocol | Port | Description |
|----------|------|-------------|
| UDP | 5060 | Standard SIP (default) |
| TCP | 5060 | SIP over TCP |
| TLS | 5061 | SIPS - encrypted SIP |

**Recommendation:** Use TLS (port 5061) in production to protect the API key in transit.

---

## Monitoring and Troubleshooting

### Status Endpoint

If enabled, the service provides an HTTP status endpoint:

```bash
curl -H "X-Admin-Key: <admin-key>" http://sip-signer:8080/status
```

Returns:
```json
{
  "status": "healthy",
  "uptime_seconds": 3600,
  "call_summary": {
    "total_calls": 1523,
    "success_count": 1498,
    "error_count": 25,
    "by_status": {
      "302": 1498,
      "404": 20,
      "401": 5
    }
  },
  "rate_limiter": {
    "active_keys": 12
  }
}
```

### Common Issues

| Symptom | Likely Cause | Solution |
|---------|--------------|----------|
| All calls get 401 | API key not being sent | Check PBX header configuration |
| Specific TN gets 404 | TN not mapped | Create mapping in UI |
| Calls work then fail | Rate limiting | Reduce call volume |
| 500 errors | Issuer API down | Check issuer service health |

### Audit Logs

All INVITE requests are logged with:
- Timestamp
- Call-ID
- Originating/Destination TN
- API key prefix (first 8 chars)
- Response status code
- VVP status

Logs are written to `/var/log/vvp-sip/audit-YYYY-MM-DD.jsonl` in JSON Lines format.

---

## Configuration Reference

The SIP signing service is configured via environment variables:

| Variable | Default | Live Value | Description |
|----------|---------|------------|-------------|
| `VVP_SIP_LISTEN_HOST` | `0.0.0.0` | `0.0.0.0` | Listen address |
| `VVP_SIP_LISTEN_PORT` | `5060` | `5070` | SIP port (live uses 5070) |
| `VVP_SIP_TRANSPORT` | `udp` | `udp` | Transport: `udp`, `tcp`, `both`, `all` |
| `VVP_SIPS_ENABLED` | `false` | `false` | Enable TLS on 5061 |
| `VVP_SIPS_LISTEN_PORT` | `5061` | - | SIPS/TLS port (future) |
| `VVP_SIPS_CERT_FILE` | - | TLS certificate path |
| `VVP_SIPS_KEY_FILE` | - | TLS private key path |
| `VVP_ISSUER_URL` | `http://localhost:8001` | VVP Issuer API URL |
| `VVP_RATE_LIMIT_RPS` | `10.0` | Requests per second per API key |
| `VVP_RATE_LIMIT_BURST` | `50` | Burst size |
| `LOG_LEVEL` | `INFO` | Logging level |

---

## Quick Start Checklist

- [ ] Organization created in VVP Issuer
- [ ] API key created with `dossier_manager` role
- [ ] TN Allocation credential issued for your phone numbers
- [ ] Dossier created with your identity credentials
- [ ] TN mappings created linking phone numbers to dossiers
- [ ] PBX/SBC configured to add `X-VVP-API-Key` header
- [ ] PBX/SBC configured to route through signing service
- [ ] PBX/SBC configured to extract and forward VVP headers from 302 response
- [ ] Test call placed and VVP headers verified at carrier

---

## Test Assets for Development

A comprehensive set of test fixtures is provided for testing VVP signing and verification during development and integration testing.

### Location

Test assets are located at:
```
services/sip-redirect/tests/fixtures/
├── credentials.py      # AIDs, keys, credential builders
├── sip_messages.py     # Pre-built SIP INVITE messages
├── test_data.json      # All test data in JSON format
├── acme_logo.svg       # Test organization logo
└── README.md           # Fixture documentation
```

### Test Organization: Acme Corp

The fixtures include a complete test organization:

| Field | Value |
|-------|-------|
| **Name** | Acme Corp |
| **LEI** | 549300EXAMPLE000001 |
| **Pseudo-LEI** | 5493001234567890AB12 |
| **Test TN** | +441923311000 |
| **Test API Key** | `vvp_test_acme_corp_api_key_12345678901234567890` |

### Credential Chain

A complete vLEI credential chain is provided:

```
GLEIF (Root of Trust)
│   AID: EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4
│
└── QVI Credential
    │   Issuer: GLEIF → Issuee: Test QVI
    │
    └── LE Credential (Acme Corp)
        │   Issuer: Test QVI → Issuee: Acme Corp
        │
        └── TN Allocation
            Numbers: +441923311000
            Channel: voice
```

### Using Python Test Fixtures

```python
from tests.fixtures import (
    ACME_CORP,
    TEST_TN,
    TEST_API_KEY,
    get_test_dossier,
    get_test_keys,
    create_test_vvp_identity,
    create_test_passport,
)

# Get test organization info
print(ACME_CORP["name"])  # "Acme Corp"

# Get the test telephone number
print(TEST_TN)  # "+441923311000"

# Get complete dossier with credentials
dossier = get_test_dossier()

# Get test keys for any identity
keys = get_test_keys("acme_signer")  # or "gleif", "qvi", "acme_corp"
print(keys["public"])   # Base64-encoded public key
print(keys["private"])  # Base64-encoded private key

# Create test VVP headers
vvp_identity = create_test_vvp_identity(orig_tn=TEST_TN)
passport = create_test_passport(orig_tn=TEST_TN, dest_tn="+442071234567")
```

### Pre-built SIP Messages

Ready-to-use SIP INVITE messages for various test scenarios:

```python
from tests.fixtures.sip_messages import (
    VALID_INVITE_EXT_1001,      # Valid INVITE with API key
    INVITE_NO_API_KEY,          # Missing X-VVP-API-Key (expect 401)
    INVITE_INVALID_API_KEY,     # Wrong API key (expect 401)
    INVITE_UNMAPPED_TN,         # TN not in mappings (expect 404)
    build_invite,               # Custom INVITE builder
    build_many_invites,         # Rate limit testing
)

# Test successful attestation
response = await handle_invite(parse_sip_request(VALID_INVITE_EXT_1001))
assert response.status_code == 302
assert b"X-VVP-Status: VALID" in response.to_bytes()

# Test missing API key
response = await handle_invite(parse_sip_request(INVITE_NO_API_KEY))
assert response.status_code == 401

# Build custom INVITE
custom_invite = build_invite(
    from_tn="+441234567890",
    to_tn="+442071234567",
    api_key="your_api_key_here",
)

# Generate many INVITEs for rate limit testing
invites = build_many_invites(100)
```

### JSON Data for External Tools

The `test_data.json` file can be loaded by external tools:

```bash
# Extract test TN
jq '.telephone_numbers.extension_1001.tn' test_data.json
# Output: "+441923311000"

# Get Acme Corp AID
jq '.aids.acme_corp.aid' test_data.json
# Output: "EHMnCf8_nIemuPx-cUHb_92fFXt9yjsn7NJJGKfgCkC0"

# Get expected 302 response headers
jq '.expected_responses.successful_302.headers' test_data.json

# List all schema SAIDs
jq '.schemas' test_data.json
```

### Test Scenarios

| Scenario | INVITE to Use | Expected Response |
|----------|---------------|-------------------|
| Successful attestation | `VALID_INVITE_EXT_1001` | 302 + VVP headers |
| Missing API key | `INVITE_NO_API_KEY` | 401 Unauthorized |
| Invalid API key | `INVITE_INVALID_API_KEY` | 401 Unauthorized |
| Unmapped TN | `INVITE_UNMAPPED_TN` | 404 Not Found |
| Rate limiting | `build_many_invites(100)` | 403 after threshold |

### Running Fixture Validation Tests

Verify the test fixtures are correctly structured:

```bash
cd services/sip-redirect
./scripts/run-tests.sh tests/test_fixtures.py -v
```

This validates:
- JSON data loads correctly
- Credential chain structure is valid
- VVP headers have correct format
- SIP messages contain required headers
- All test keys exist and are valid

**Warning:** These test fixtures contain deterministic keys and credentials that are **NOT CRYPTOGRAPHICALLY SECURE**. They are intended only for testing purposes and must **NEVER** be used in production.

### Configuring the PBX for Trial Testing

To test with the Acme Corp trial dossier, configure your PBX with these exact values:

| Setting | Value |
|---------|-------|
| **API Key** | `vvp_test_acme_corp_api_key_12345678901234567890` |
| **Test TN** | `+441923311000` |
| **SIP Signer Host** | `pbx.rcnx.io:5060` |

> **API Key Requirements:**
>
> The API key must be registered in the VVP Issuer database with either:
> - **System role:** `issuer:operator` (or higher: `issuer:admin`)
> - **Organization role:** `org:dossier_manager` (or higher: `org:administrator`)
>
> For the test fixtures to work, the test API key must be provisioned with
> `org:dossier_manager` role and associated with an organization that has:
> 1. The Acme Corp TN Allocation credential (covering `+441923311000`)
> 2. A TN mapping from `+441923311000` to the test dossier
> 3. A signing identity with the test keys

#### FreeSWITCH Configuration

Add to `/etc/freeswitch/dialplan/default.xml`:

```xml
<!-- VVP Trial Test Extension -->
<extension name="vvp-trial-test">
  <condition field="caller_id_number" expression="^1001$">
    <condition field="destination_number" expression="^71006$">
      <!-- Set the test API key -->
      <action application="set" data="sip_h_X-VVP-API-Key=vvp_test_acme_corp_api_key_12345678901234567890"/>

      <!-- Set caller ID to test TN -->
      <action application="set" data="effective_caller_id_number=+441923311000"/>

      <!-- Route through VVP signer on localhost (same PBX) -->
      <action application="bridge" data="sofia/external/${destination_number}@127.0.0.1:5070"/>
    </condition>
  </condition>
</extension>
```

#### Kamailio Configuration

```
# VVP Trial Test Route
if ($fU == "1001" && $rU == "71006") {
    # Add test API key
    append_hf("X-VVP-API-Key: vvp_test_acme_corp_api_key_12345678901234567890\r\n");

    # Route to VVP signer
    $du = "sip:127.0.0.1:5070";
    route(RELAY);
}
```

#### Asterisk Configuration

```
[vvp-trial-test]
exten => 71006,1,NoOp(VVP Trial Test)
same => n,Set(CALLERID(num)=+441923311000)
same => n,Set(PJSIP_HEADER(add,X-VVP-API-Key)=vvp_test_acme_corp_api_key_12345678901234567890)
same => n,Dial(PJSIP/71006@vvp-signer-local)
```

#### Testing the Configuration

1. **Register extension 1001** on your softphone
2. **Dial 71006** (the VVP loopback test extension)
3. **Expected flow:**
   - Call goes to SIP signer with API key header
   - Signer looks up TN `+441923311000` → finds Acme Corp mapping
   - Returns 302 with VVP headers
   - Call completes with attestation

#### Verifying the Test Dossier is Working

Check the SIP signer logs for:
```
[INFO] INVITE from +441923311000 with API key vvp_test...
[INFO] TN lookup: +441923311000 → Acme Corp (ETnAllocationSAID...)
[INFO] 302 Moved Temporarily with X-VVP-Status: VALID
```

---

### End-to-End Testing

To run a complete end-to-end test of signing and verification:

#### 1. Serve the Test Dossier

The verifier needs to fetch the dossier from the `evd` URL. For local testing, serve the dossier file:

```bash
# Option A: Use Python's built-in HTTP server
cd services/sip-redirect/tests/fixtures
python3 -m http.server 8888

# Dossier URL: http://localhost:8888/acme_dossier.json
```

#### 2. Create VVP-Identity Header

```python
from tests.fixtures.credentials import create_vvp_identity_header

# For local testing (dossier served on localhost)
vvp_identity = create_vvp_identity_header(
    evd_url="http://localhost:8888/acme_dossier.json"
)
print(f"VVP-Identity: {vvp_identity}")
```

#### 3. Test Against Verifier

```bash
# Verify the VVP-Identity header using the verifier API
curl -X POST https://vvp-verifier.rcnx.io/verify \
  -H "Content-Type: application/json" \
  -d '{
    "vvp_identity": "<base64url VVP-Identity header>",
    "orig_tn": "+441923311000",
    "dest_tn": "+442071234567"
  }'
```

#### 4. Test SIP Flow (Using SIPp or netcat)

```bash
# Build a test INVITE
python3 -c "
from tests.fixtures.sip_messages import build_invite
from tests.fixtures.credentials import TEST_API_KEY, TEST_TN

invite = build_invite(from_tn=TEST_TN, api_key=TEST_API_KEY)
print(invite.decode())
"

# Send to SIP signer (UDP)
echo -e "INVITE sip:+442071234567@carrier.example.com SIP/2.0\r\n..." | \
  nc -u pbx.rcnx.io 5060
```

#### 5. FreeSWITCH Loopback Test

If using the VVP PBX with FreeSWITCH:

```bash
# Dial the VVP loopback extension from extension 1001
# This triggers: 1001 → SIP Signer → 302 → Verifier → Answer
fs_cli -x "originate user/1001 &bridge(loopback/71006)"
```

### Test Assets Summary

| Asset | Location | Purpose |
|-------|----------|---------|
| Dossier JSON | `tests/fixtures/acme_dossier.json` | Serve at evd URL |
| Credentials | `tests/fixtures/credentials.py` | AIDs, keys, builders |
| SIP Messages | `tests/fixtures/sip_messages.py` | Pre-built INVITEs |
| Logo | `tests/fixtures/acme_logo.svg` | Brand logo |
| JSON Data | `tests/fixtures/test_data.json` | All data in JSON |

### VVP-Identity Header Format

The verifier expects this structure in the VVP-Identity header:

```json
{
  "ppt": "shaken",
  "kid": "EJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1",
  "evd": "https://vvp-issuer.rcnx.io/dossiers/ETnAllocationSAIDforAcmeCorpExtension1001",
  "iat": 1770374855,
  "exp": 1770375155
}
```

| Field | Description |
|-------|-------------|
| `ppt` | PASSporT profile type (`shaken`) |
| `kid` | Key identifier - the signer's AID |
| `evd` | Evidence URL - where to fetch the dossier |
| `iat` | Issued-at timestamp (Unix epoch) |
| `exp` | Expiry timestamp (optional, default: iat + 300) |

---

## Support

For issues with the SIP signing service, contact your VVP administrator with:

1. The Call-ID of the affected call
2. The originating TN
3. The timestamp of the issue
4. The SIP response received (if any)
