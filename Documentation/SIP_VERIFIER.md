# VVP SIP Verification Service

## Overview

The VVP SIP Verification Service (`sip-verify`) receives inbound SIP INVITE requests containing VVP verification headers, validates the caller's identity through the VVP Verifier API, and returns verification results as custom headers in the SIP 302 redirect response.

This allows a PBX or WebRTC client to display verified caller identity (brand name, logo) before the user answers.

## Architecture

```
Carrier/Originating PBX
         │
         │ SIP INVITE + Identity header
         │ + P-VVP-Identity + P-VVP-Passport
         ▼
┌─────────────────────────┐
│  VVP SIP Verify Service │ UDP/TCP port 5061
│  (sip-verify)           │
└───────────┬─────────────┘
            │ HTTPS POST /verify-callee
            ▼
┌─────────────────────────┐
│    VVP Verifier API     │
│  (vvp-verifier.rcnx.io) │
└───────────┬─────────────┘
            │ VerifyResponse
            ▼
┌─────────────────────────┐
│  SIP 302 Redirect       │
│  + X-VVP-* headers      │
└───────────┬─────────────┘
            │
            ▼
    Destination PBX/WebRTC
```

## Network Configuration

### Listening Ports

| Protocol | Default Port | Environment Variable |
|----------|--------------|---------------------|
| UDP | 5061 | `VVP_SIP_VERIFY_PORT` |
| TCP | 5061 | `VVP_SIP_VERIFY_PORT` |
| TLS (SIPS) | 5062 | `VVP_SIPS_PORT` (if enabled) |

### Firewall Rules

Allow inbound traffic from your carrier/SBC source IPs:

```bash
# Example UFW rules
ufw allow from <carrier_ip>/32 to any port 5061 proto udp
ufw allow from <carrier_ip>/32 to any port 5061 proto tcp
```

### Outbound Connectivity

The service requires HTTPS (443) connectivity to the VVP Verifier API:
- Default: `https://vvp-verifier.rcnx.io`
- Configurable via: `VVP_VERIFIER_URL`

---

## Deployed Service Location

The VVP SIP Verification Service is deployed at:

| Service | Host | Port | Protocol |
|---------|------|------|----------|
| **SIP Verify (Dev/Mock)** | `pbx.rcnx.io` | 5071 | UDP/TCP |
| **VVP Verifier API** | `vvp-verifier.rcnx.io` | 443 | HTTPS |
| **VVP Issuer API** | `vvp-issuer.rcnx.io` | 443 | HTTPS |

### DNS Records

```
pbx.rcnx.io          → VVP PBX VM (SIP Services)
vvp-verifier.rcnx.io → Azure Container App (Verifier)
vvp-issuer.rcnx.io   → Azure Container App (Issuer)
```

**Note:** The mock verification service on port 5071 is for development and testing. Production deployments should use a dedicated SIP verification service instance.

---

## Environment Variables

### Required

| Variable | Description | Example |
|----------|-------------|---------|
| `VVP_VERIFIER_URL` | VVP Verifier API base URL | `https://vvp-verifier.rcnx.io` |
| `VVP_REDIRECT_TARGET` | SIP URI to redirect verified calls to | `sip:pbx.rcnx.io:5060` |

### Optional

| Variable | Default | Description |
|----------|---------|-------------|
| `VVP_SIP_VERIFY_HOST` | `0.0.0.0` | Listen address |
| `VVP_SIP_VERIFY_PORT` | `5061` | Listen port (UDP/TCP) |
| `VVP_VERIFIER_TIMEOUT` | `5.0` | Verifier API timeout in seconds |
| `VVP_VERIFIER_API_KEY` | (none) | API key for Verifier authentication |
| `VVP_FALLBACK_STATUS` | `INDETERMINATE` | Status when Verifier unreachable |
| `VVP_LOG_LEVEL` | `INFO` | Logging level (DEBUG, INFO, WARNING, ERROR) |
| `VVP_SIP_TRANSPORT` | `udp` | Transport: `udp`, `tcp`, `both`, `all` |
| `VVP_SIPS_ENABLED` | `false` | Enable TLS transport |
| `VVP_SIPS_PORT` | `5062` | TLS listen port |
| `VVP_SIPS_CERT_FILE` | (none) | Path to TLS certificate |
| `VVP_SIPS_KEY_FILE` | (none) | Path to TLS private key |

---

## Input: Expected SIP Headers

The service expects these headers on incoming SIP INVITE requests:

### Required Headers (at least one must be present)

| Header | Format | Description |
|--------|--------|-------------|
| `Identity` | RFC 8224 format | PASSporT JWT with signature |
| `P-VVP-Identity` | Base64url JSON | VVP-specific identity claims |

### Optional Headers

| Header | Format | Description |
|--------|--------|-------------|
| `P-VVP-Passport` | JWT string | Fallback PASSporT if not in Identity |

### Identity Header Format (RFC 8224)

```
Identity: <base64url-encoded-passport>;info=<oobi-url>;alg=EdDSA;ppt=vvp
```

Example:
```
Identity: <eyJhbGciOiJFZERTQSJ9...>;info=https://witness.example.com/oobi/EAbc.../witness;alg=EdDSA;ppt=vvp
```

### P-VVP-Identity Header Format

Base64url-encoded JSON with these fields:

```json
{
  "ppt": "vvp",
  "kid": "https://witness.example.com/oobi/{AID}/witness",
  "evd": "https://dossier.example.com/dossiers/{SAID}",
  "iat": 1704067200,
  "exp": 1704153600
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `ppt` | Yes | Must be "vvp" |
| `kid` | Yes | OOBI URL for key resolution |
| `evd` | Yes | Dossier evidence URL |
| `iat` | Yes* | Issued-at timestamp (Unix epoch) |
| `exp` | No | Expiration timestamp (Unix epoch) |

*Required by the VVP Verifier API

---

## Output: SIP Response Headers

### Success Response (302 Moved Temporarily)

The service always returns SIP 302 to forward the call, with verification results in custom headers.

| Header | Values | Description |
|--------|--------|-------------|
| `X-VVP-Status` | `VALID`, `INVALID`, `INDETERMINATE` | Overall verification result |
| `X-VVP-Brand-Name` | String | Verified organization name |
| `X-VVP-Brand-Logo` | URL | Logo image URL |
| `X-VVP-Caller-ID` | E.164 | Verified caller telephone number |
| `X-VVP-Error` | Error code | Error code if status is INVALID |
| `Contact` | SIP URI | Redirect target from `VVP_REDIRECT_TARGET` |
| `P-VVP-Identity` | (pass-through) | Original identity header |
| `P-VVP-Passport` | (pass-through) | Original passport header |

Example successful verification:
```
SIP/2.0 302 Moved Temporarily
Via: SIP/2.0/UDP carrier.com:5060;branch=z9hG4bK123
From: <sip:+15551234567@carrier.com>;tag=abc123
To: <sip:+14155551234@pbx.example.com>
Call-ID: xyz789@carrier.com
CSeq: 1 INVITE
Contact: <sip:+14155551234@pbx.example.com:5060>
X-VVP-Status: VALID
X-VVP-Brand-Name: ACME Corporation
X-VVP-Brand-Logo: https://cdn.acme.com/logo.png
X-VVP-Caller-ID: +15551234567
Content-Length: 0
```

### Error Response (400 Bad Request)

Returned when required headers are missing or malformed.

| Condition | Response |
|-----------|----------|
| No verification headers | 400 Bad Request |
| Malformed Identity header | 400 Bad Request |
| Malformed P-VVP-Identity | 400 Bad Request |
| Missing OOBI URL (kid) | 400 Bad Request |
| Missing dossier URL (evd) | 400 Bad Request |

Example:
```
SIP/2.0 400 Bad Request
Via: SIP/2.0/UDP carrier.com:5060;branch=z9hG4bK123
From: <sip:+15551234567@carrier.com>;tag=abc123
To: <sip:+14155551234@pbx.example.com>
Call-ID: xyz789@carrier.com
CSeq: 1 INVITE
X-VVP-Error: Missing VVP verification headers
Content-Length: 0
```

---

## Verification Status Meanings

| Status | Meaning | Action |
|--------|---------|--------|
| `VALID` | Caller identity verified | Display brand name and logo to callee |
| `INVALID` | Verification failed | Show warning or block call based on policy |
| `INDETERMINATE` | Cannot determine | Allow call but don't display verification |

### Error Codes (X-VVP-Error)

When `X-VVP-Status` is `INVALID`, the `X-VVP-Error` header contains one of:

| Error Code | Description |
|------------|-------------|
| `SIGNATURE_INVALID` | PASSporT signature verification failed |
| `CREDENTIAL_REVOKED` | One or more credentials in the chain are revoked |
| `TN_NOT_AUTHORIZED` | Caller TN not authorized by credential chain |
| `DOSSIER_INVALID` | Dossier structure or content invalid |
| `IAT_DRIFT` | PASSporT issued-at timestamp too far from current time |
| `TOKEN_EXPIRED` | PASSporT or credential has expired |

When `X-VVP-Status` is `INDETERMINATE`, these informational codes may appear:

| Error Code | Description |
|------------|-------------|
| `VERIFIER_TIMEOUT` | Verifier API request timed out |
| `VERIFIER_UNREACHABLE` | Could not connect to Verifier API |
| `VERIFIER_ERROR` | Verifier returned non-200 response |

---

## PBX Gateway Configuration

### FreeSWITCH / FusionPBX

Create a gateway profile pointing to the sip-verify service:

```xml
<!-- /etc/freeswitch/sip_profiles/external/vvp-verify.xml -->
<gateway name="vvp-verify">
  <param name="realm" value="pbx.rcnx.io"/>
  <param name="proxy" value="pbx.rcnx.io:5061"/>
  <param name="register" value="false"/>
  <param name="caller-id-in-from" value="true"/>
</gateway>
```

Route inbound calls through verification:

```xml
<!-- dialplan/public.xml -->
<extension name="vvp_inbound_verify">
  <condition field="destination_number" expression="^(\+1\d{10})$">
    <!-- Send to VVP verification first -->
    <action application="bridge" data="sofia/gateway/vvp-verify/$1"/>
  </condition>
</extension>
```

### Kamailio

Configure the sip-verify service as an outbound proxy for inbound calls:

```
# Route inbound PSTN calls through VVP verification
route[VVP_VERIFY] {
    $du = "sip:pbx.rcnx.io:5061";
    route(RELAY);
}
```

---

## Docker Deployment

### Using Docker Compose

```yaml
services:
  sip-verify:
    build:
      context: .
      dockerfile: services/sip-verify/Dockerfile
    ports:
      - "5061:5061/udp"
      - "5061:5061/tcp"
    environment:
      - VVP_VERIFIER_URL=https://vvp-verifier.rcnx.io
      - VVP_REDIRECT_TARGET=sip:pbx.internal:5060
      - VVP_LOG_LEVEL=INFO
    restart: unless-stopped
```

### Standalone Docker

```bash
docker build -f services/sip-verify/Dockerfile -t vvp-sip-verify .

docker run -d \
  --name vvp-sip-verify \
  -p 5061:5061/udp \
  -p 5061:5061/tcp \
  -e VVP_VERIFIER_URL=https://vvp-verifier.rcnx.io \
  -e VVP_REDIRECT_TARGET=sip:pbx.internal:5060 \
  vvp-sip-verify
```

---

## Monitoring and Logging

### Log Format

Logs use structured format with call tracing:

```
2024-01-01 12:00:00 INFO [vvp-sip] Starting VVP SIP Verify Service...
2024-01-01 12:00:01 INFO [vvp-sip] UDP server ready on 0.0.0.0:5061
2024-01-01 12:00:05 INFO [verify.handler] Verification complete: call_id=xyz789@carrier.com, status=VALID, brand=ACME Corporation, time_ms=125.3
```

### Audit Events

Each verification is logged with:
- Call-ID
- From/To telephone numbers
- Verification status
- Brand name (if VALID)
- Error code (if INVALID/INDETERMINATE)
- Processing time in milliseconds

### Health Check

The service exposes an optional HTTP health endpoint:

```
GET http://localhost:8080/health
```

Response:
```json
{
  "status": "healthy",
  "verifier_url": "https://vvp-verifier.rcnx.io",
  "uptime_seconds": 3600
}
```

---

## Troubleshooting

### Common Issues

| Symptom | Possible Cause | Solution |
|---------|----------------|----------|
| 400 for all calls | Missing Identity headers | Verify carrier is sending RFC 8224 Identity header |
| INDETERMINATE status | Verifier unreachable | Check network connectivity to VVP Verifier API |
| INVALID status | Credential revoked or expired | Check credential status in dossier |
| Connection refused | Service not running | Check Docker container status and port bindings |
| TLS handshake failure | Certificate issues | Verify SIPS cert/key configuration |

### Debug Mode

Enable verbose logging:

```bash
VVP_LOG_LEVEL=DEBUG docker compose up sip-verify
```

### Testing with netcat

Send a test SIP INVITE:

```bash
echo -e "INVITE sip:+14155551234@pbx.example.com SIP/2.0\r
Via: SIP/2.0/UDP test:5060;branch=z9hG4bK123\r
From: <sip:+15551234567@test>;tag=abc\r
To: <sip:+14155551234@pbx.example.com>\r
Call-ID: test123\r
CSeq: 1 INVITE\r
Identity: <$(echo 'test.payload.sig' | base64)>;info=https://example.com;alg=EdDSA;ppt=vvp\r
P-VVP-Identity: $(echo '{"ppt":"vvp","kid":"https://example.com/oobi","evd":"https://example.com/dossier","iat":1704067200}' | base64 -w0)\r
Content-Length: 0\r
\r
" | nc -u pbx.rcnx.io 5061
```

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-02-06 | Initial release (Sprint 44) |
