# VVP End-to-End Test Walkthrough

This document provides a detailed step-by-step guide for validating the complete VVP (Verified Voice Protocol) system from infrastructure setup through to verified calls.

## System Configuration

### Configured Extensions and Phone Numbers

| Extension | Phone Number (E.164) | Description |
|-----------|---------------------|-------------|
| 1001 | +441923311000 | Test extension 1 |
| 1006 | +441923311006 | Test extension 2 |

### VVP Routing Prefix

The PBX uses prefix **`7`** to route calls through the VVP SIP loopback:

| Dial | From | To | Route |
|------|------|-----|-------|
| `71006` | 1001 | 1006 | Via VVP (signing → verifier → destination) |
| `71001` | 1006 | 1001 | Via VVP (signing → verifier → destination) |
| `1006` | 1001 | 1006 | Direct (no VVP) |

**Call flow with prefix 7:**
1. Extension 1001 dials `71006`
2. PBX routes to SIP Redirect (signing service)
3. SIP Redirect looks up TN mapping for caller (+441923311000)
4. SIP Redirect returns 302 with VVP headers (Identity, VVP-Identity)
5. PBX follows redirect through loopback
6. Inbound leg delivers call to extension 1006 with VVP headers
7. Extension 1006 sees verified caller display

These phone numbers should be used when:
- Creating TN Allocation credentials
- Creating TN mappings
- Setting caller ID for outbound calls
- Testing call flows between extensions

---

## Prerequisites

Before starting, ensure you have:
- SSH access to the PBX server (`pbx.rcnx.io`)
- Admin credentials for the Issuer UI (`https://vvp-issuer.rcnx.io`)
- Access to the Verifier UI (`https://vvp-verifier.rcnx.io`)
- A WebRTC-capable browser for the soft phone

---

## Part 1: Infrastructure Validation

### 1.1 Verify SIP Redirect Service is Running

SSH to the PBX server and check the SIP redirect service:

```bash
ssh root@pbx.rcnx.io

# Check service status
systemctl status vvp-sip-redirect

# View recent logs
journalctl -u vvp-sip-redirect -n 50

# Verify listening on port 5060
ss -ulnp | grep 5060
```

**Expected output:**
- Service is `active (running)`
- Logs show "VVP SIP Redirect Service started"
- UDP listener on `0.0.0.0:5060`

### 1.2 Verify Status Endpoint (if configured)

If `VVP_STATUS_ADMIN_KEY` is set, test the status endpoint:

```bash
# From the PBX server
curl -H "X-Admin-Key: <your-admin-key>" http://localhost:8080/status | jq .

# Health check (no auth required)
curl http://localhost:8080/health
```

**Expected output:**
```json
{
  "healthy": true,
  "uptime_seconds": 1234.5,
  "rate_limits": [],
  "recent_calls": {
    "total_calls": 0,
    "success_count": 0,
    "error_count": 0,
    "by_status": {}
  },
  "config": {
    "rate_limit_rps": 10.0,
    "rate_limit_burst": 50
  }
}
```

### 1.3 Verify PBX Gateway Configuration

Check FreeSWITCH has the VVP gateway configured:

```bash
# List gateways
fs_cli -x "sofia status gateway vvp-redirect"

# Check dialplan is loaded
fs_cli -x "show dialplan" | grep -i vvp
```

**Expected output:**
- Gateway `vvp-redirect` shows `REGED` or `NOREG` (depending on config)
- Dialplan includes VVP routing rules

### 1.4 Verify Issuer Service Connectivity

From the PBX, verify it can reach the Issuer API:

```bash
# Test issuer health endpoint
curl -s https://vvp-issuer.rcnx.io/healthz | jq .

# Test issuer is configured in SIP redirect
grep ISSUER_URL /etc/vvp-sip/config.env
```

**Expected output:**
- Issuer returns `{"status": "healthy", ...}`
- `VVP_ISSUER_URL` points to the correct issuer endpoint

---

## Part 2: Organization and Identity Setup

### 2.1 Login to Issuer UI

1. Navigate to `https://vvp-issuer.rcnx.io/login`
2. Login using one of:
   - Microsoft 365 SSO (if configured)
   - System admin API key
   - Email/password credentials

### 2.2 Create Organization

1. Navigate to **Organizations** page (`/ui/organizations`)
2. Click **"Create Organization"**
3. Enter organization details:
   - **Name**: e.g., "Acme Corporation Test"
   - Other fields auto-populate
4. Click **"Create"**

**Verify success:**
- Organization card appears with:
  - Name and "Active" status badge
  - Pseudo-LEI (starts with `984500...`)
  - AID (KERI identifier, starts with `E...`)
  - LE Credential SAID (auto-issued)

**Record these values:**
```
Organization Name: _______________________
Organization ID:   _______________________
AID:              _______________________
LE Credential SAID: _______________________
```

### 2.3 Create API Key for SIP Gateway

1. On the organization card, find **"API Keys"** section
2. Click **"+ Add"**
3. Configure the key:
   - **Name**: "SIP Gateway Key"
   - **Roles**: Select **Dossier Manager** (minimum required for TN lookup/VVP creation)
4. Click **"Create API Key"**

**CRITICAL**: Copy the displayed API key immediately. It will NOT be shown again.

**Record the API key:**
```
API Key Name:  SIP Gateway Key
API Key Value: _______________________
               (Keep this secure!)
```

---

## Part 3: Credential and Dossier Setup

### 3.1 Issue TN Allocation Credential

1. Navigate to **Credentials** > **Issue Credential** (`/ui/credentials`)
2. Fill in the form:
   - **Schema**: Select "TN Allocation"
   - **Registry**: Select the organization's registry
   - **Attributes**:
     - `i`: Organization's AID (should auto-populate)
     - `numbers`: Enter the phone numbers in JSON format:
       ```json
       {"tn": ["+441923311000", "+441923311006"]}
       ```
       (Use E.164 format with country code)

       **Current system phone numbers:**
       - Extension 1001: `+441923311000`
       - Extension 1006: `+441923311006`
   - **Edges**: Add edge to the LE credential (links TN to Legal Entity)
3. Click **"Issue Credential"**

**Verify success:**
- New credential card appears
- Status shows "issued"
- SAID is displayed

**Record:**
```
TN Credential SAID: _______________________
Phone Number(s):    _______________________
```

### 3.2 Build Dossier

1. Navigate to **Dossiers** > **Build Dossier** (`/ui/dossiers`)
2. Configure:
   - **Root Credential**: Select the TN Allocation credential just issued
   - **Format**: CESR (production) or JSON (debugging)
3. Click **"Build Dossier"**

**Verify success:**
- Dossier info displays:
  - Root SAID
  - Credential count (should be 4: TN → LE → QVI → GLEIF root)
  - Download links

**Record:**
```
Dossier Root SAID:  _______________________
Credential Count:   _______________________
```

### 3.3 Create TN Mapping

1. Navigate to **TN Mappings** (`/ui/tn-mappings`)
2. Click **"Create TN Mapping"**
3. Fill in:
   - **Telephone Number**: E.164 format (e.g., `+441923311000`)
   - **Dossier**: Select from dropdown (shows by root SAID)
   - **Signing Identity**: Select organization's KERI identity
4. Click **"Create Mapping"**

**Verify success:**
- TN appears in table with:
  - Phone number (monospace)
  - Brand name and logo (extracted from dossier)
  - Identity name
  - Dossier SAID (truncated)
  - Status: Enabled

### 3.4 Test TN Mapping (Pre-flight Check)

Before configuring the PBX, verify the TN mapping works:

1. On the TN Mappings page, find the mapping row
2. Click **"Test"** button
3. Review the modal result

**Expected success result:**
```
TN Lookup Successful
-------------------
TN:           +441923311000
Organization: Acme Corporation Test
Dossier SAID: EHlVXUJ-dYKqtPdvztdCFJEbkyr6zX2dX12hwdE9x8ey
Identity:     acme-signer
Brand:        Acme Corp
```

**If test fails**, check:
- Mapping is enabled (not disabled)
- Dossier exists and is accessible
- Signing identity exists

---

## Part 4: PBX Configuration

### 4.1 Configure API Key in FreeSWITCH

SSH to the PBX and update the dialplan to include the API key:

```bash
ssh root@pbx.rcnx.io

# Edit the VVP dialplan
nano /etc/freeswitch/dialplan/public/vvp-outbound.xml
```

Add or update the gateway configuration to include the API key header:

```xml
<extension name="vvp-outbound">
  <condition field="destination_number" expression="^(\+\d+)$">
    <!-- Set the VVP API key header -->
    <action application="set" data="sip_h_X-VVP-API-Key=YOUR_API_KEY_HERE"/>

    <!-- Set originating caller ID to a mapped TN -->
    <action application="set" data="effective_caller_id_number=+441923311000"/>

    <!-- Route through VVP redirect gateway -->
    <action application="bridge" data="sofia/gateway/vvp-redirect/$1"/>
  </condition>
</extension>
```

Replace `YOUR_API_KEY_HERE` with the actual API key from step 2.3.

### 4.2 Reload FreeSWITCH Configuration

```bash
# Reload dialplan
fs_cli -x "reloadxml"

# Verify dialplan loaded
fs_cli -x "show dialplan" | grep vvp-outbound
```

### 4.3 Configure Inbound VVP Processing

Ensure the inbound dialplan processes VVP headers:

```xml
<extension name="vvp-inbound">
  <condition field="destination_number" expression="^(\d+)$">
    <!-- Extract VVP headers if present -->
    <action application="set" data="vvp_identity=${sip_h_VVP-Identity}"/>
    <action application="set" data="vvp_passport=${sip_h_Identity}"/>

    <!-- Route to internal extension -->
    <action application="bridge" data="user/$1@${domain_name}"/>
  </condition>
</extension>
```

---

## Part 5: Test Call Execution

### Quick Test (TL;DR)

If all setup is complete, the fastest way to test:

1. Open two browser tabs with `https://pbx.rcnx.io/app/vvp-phone/sip-phone.html`
2. Register as **1001** in one tab, **1006** in the other
3. From extension 1001, dial **`71006`**
4. Extension 1006 should ring with verified caller display showing brand name

If this works, VVP is functioning end-to-end. If not, follow the detailed steps below.

---

### 5.1 Register WebRTC Client

1. Open `https://pbx.rcnx.io/app/vvp-phone/sip-phone.html`
2. Enter credentials:
   - **Extension**: `1001` (phone: +441923311000) or `1006` (phone: +441923311006)
   - **Password**: (configured password)
   - **Server**: `pbx.rcnx.io`
3. Click **Register**

**Verify:**
- Status shows "Registered"
- Phone is ready to receive calls

**Test scenario:** Register as extension 1006 to receive calls from 1001.

### 5.2 Make Test Call from WebRTC Phone

The simplest way to test VVP is to dial using the **7 prefix** from a registered phone:

1. Register WebRTC client as extension 1001
2. Dial **`71006`** (the 7 prefix routes through VVP)
3. Extension 1006 receives call with VVP verification display

**What happens:**
- `7` prefix triggers VVP routing through SIP Redirect
- SIP Redirect looks up TN mapping for +441923311000 (1001's number)
- VVP headers are attached and call loops back to 1006

### 5.3 Make Test Call via CLI

For debugging, you can originate calls directly via FreeSWITCH CLI:

```bash
# Call from extension 1001 (+441923311000) to extension 1006 via VVP
# The 7 prefix routes through the VVP loopback
fs_cli -x "originate user/1001 71006"

# Or directly through the VVP gateway with explicit headers:
fs_cli -x "originate {sip_h_X-VVP-API-Key=YOUR_API_KEY,origination_caller_id_number=+441923311000}sofia/gateway/vvp-redirect/+441923311006 &park()"
```

**Parameters explained:**
- `71006`: Dial string with 7 prefix to route through VVP loopback
- `sip_h_X-VVP-API-Key`: API key for authentication (when using direct gateway)
- `origination_caller_id_number`: **MUST match** a TN in your TN mappings (+441923311000 or +441923311006)

**Test scenarios:**
1. Register WebRTC client as extension 1006
2. From another phone (or CLI), dial `71006` as extension 1001
3. Call routes through VVP redirect and arrives at extension 1006 with VVP attestation

### 5.4 Verify SIP Redirect Response

Check the SIP trace for the 302 redirect:

```bash
# Watch SIP messages in real-time
fs_cli -x "sofia global siptrace on"

# Make the test call (1001 calling 1006 via VVP prefix)
fs_cli -x "originate user/1001 71006"

# Or with explicit gateway:
fs_cli -x "originate {sip_h_X-VVP-API-Key=YOUR_API_KEY,origination_caller_id_number=+441923311000}sofia/gateway/vvp-redirect/+441923311006 &park()"

# Stop tracing
fs_cli -x "sofia global siptrace off"
```

**Expected in trace:**
1. INVITE sent to SIP redirect with `X-VVP-API-Key` header
2. 302 Moved Temporarily response with:
   - `VVP-Identity` header (base64url-encoded JSON)
   - `Identity` header (PASSporT JWT)
   - `VVP-Status: VALID`
3. Follow-up INVITE to loopback with VVP headers attached

### 5.5 Verify VVP Display on Phone

On the WebRTC client:

**Expected display:**
- Incoming call notification
- Brand name (e.g., "Acme Corp")
- Brand logo (if configured)
- Green "Verified" badge
- Caller ID showing the mapped TN

---

## Part 6: Monitoring and Diagnostics

### 6.1 Issuer Admin Dashboard

Navigate to `https://vvp-issuer.rcnx.io/ui/admin`

**Check:**
- [ ] Service health: "Healthy" indicator
- [ ] Service version and git commit displayed
- [ ] Statistics show:
  - Identity count
  - Registry count
  - Credential count
  - Schema count
- [ ] Authentication status shows enabled with API key count

### 6.2 Audit Log Viewer

On the Admin page, scroll to **Audit Log** section:

**Check:**
- [ ] Recent events load automatically
- [ ] Filter by action type works (auth., tn_mapping., credential.)
- [ ] Filter by status works (success, denied, error)
- [ ] Events show timestamp, action, principal, status

**Look for:**
- `tn_mapping.lookup` events for your test TN
- `vvp.create` events for attestation creation
- Any `denied` or `error` status events

### 6.3 SIP Redirect Status (if configured)

```bash
curl -H "X-Admin-Key: YOUR_ADMIN_KEY" http://localhost:8080/status | jq .
```

**Check:**
- [ ] `healthy: true`
- [ ] `recent_calls.total_calls` incremented
- [ ] `recent_calls.success_count` shows 302 redirects
- [ ] `rate_limits` shows your API key prefix (if rate limited)

### 6.4 Verifier UI Diagnostics

Navigate to `https://vvp-verifier.rcnx.io/`

**Test JWT Parsing:**
1. Capture the `Identity` header from a SIP trace
2. Paste into the JWT textarea
3. Click **"Parse JWT"**
4. Verify header and payload decode correctly

**Test Dossier Fetch:**
1. After parsing JWT, the `evd` URL should appear
2. Click **"Fetch Dossier"**
3. Verify credential chain loads (should show 4 ACDCs)

**Test Full Verification:**
1. After fetching dossier, **"Full Verification"** section appears
2. Click **"Run Full Verification"**
3. Verify result shows:
   - Status: VALID (green banner)
   - No errors
   - Brand information extracted

---

## Part 7: Troubleshooting Guide

### 7.1 SIP Redirect Returns 401 Unauthorized

**Symptom:** Call fails immediately with 401 response

**Check:**
1. API key is included in INVITE: `sip_h_X-VVP-API-Key`
2. API key is valid (not revoked)
3. API key has correct roles (Dossier Manager minimum)

**Debug:**
```bash
# Check audit log for auth failures
journalctl -u vvp-sip-redirect | grep "auth.failure"
```

### 7.2 SIP Redirect Returns 404 Not Found

**Symptom:** Call fails with "No mapping for +441923311000"

**Check:**
1. Caller ID (`origination_caller_id_number`) matches a TN mapping
2. TN format is correct (E.164 with `+` and country code)
3. TN mapping is enabled (not disabled)

**Debug:**
1. Go to TN Mappings UI
2. Click "Test" on the mapping
3. Verify it succeeds

### 7.3 SIP Redirect Returns 500 Error

**Symptom:** Call fails with "Internal server error"

**Check:**
1. Issuer service is reachable from PBX
2. Dossier exists and is accessible
3. Signing identity exists

**Debug:**
```bash
# Check SIP redirect logs
journalctl -u vvp-sip-redirect -n 100 | grep -i error

# Check issuer connectivity
curl -s https://vvp-issuer.rcnx.io/healthz
```

### 7.4 VVP Headers Not Appearing on Inbound

**Symptom:** Call connects but no VVP display

**Check:**
1. 302 redirect included VVP headers (check SIP trace)
2. Inbound dialplan extracts headers
3. Phone/endpoint processes VVP headers

**Debug:**
```bash
# Check inbound call details
fs_cli -x "show channels"
fs_cli -x "uuid_dump <channel-uuid>" | grep -i vvp
```

### 7.5 Verification Fails in Verifier UI

**Symptom:** "Run Full Verification" shows INVALID

**Check the errors displayed:**
- **SIGNATURE_INVALID**: PASSporT signature verification failed
- **CREDENTIAL_REVOKED**: One of the ACDCs has been revoked
- **CHAIN_INCOMPLETE**: Missing credentials in dossier
- **ISSUER_UNTRUSTED**: Root issuer not in trusted list

---

## Part 8: Quick Reference

### Key URLs

| Service | URL | Purpose |
|---------|-----|---------|
| Issuer UI | https://vvp-issuer.rcnx.io | Organization/credential management |
| Issuer Admin | https://vvp-issuer.rcnx.io/ui/admin | Dashboard and audit logs |
| TN Mappings | https://vvp-issuer.rcnx.io/ui/tn-mappings | Phone number to dossier mapping |
| Verifier UI | https://vvp-verifier.rcnx.io | JWT parsing and verification |
| WebRTC Phone | https://pbx.rcnx.io/app/vvp-phone/sip-phone.html | Test phone client |

### Key Files on PBX

| File | Purpose |
|------|---------|
| `/etc/freeswitch/dialplan/public/vvp-outbound.xml` | Outbound VVP routing |
| `/etc/freeswitch/dialplan/public/vvp-inbound.xml` | Inbound VVP processing |
| `/etc/vvp-sip/config.env` | SIP redirect configuration |
| `/var/log/vvp-sip/audit-*.jsonl` | SIP redirect audit logs |

### Environment Variables (SIP Redirect)

| Variable | Default | Purpose |
|----------|---------|---------|
| `VVP_ISSUER_URL` | http://localhost:8001 | Issuer API endpoint |
| `VVP_SIP_LISTEN_PORT` | 5060 | SIP UDP listen port |
| `VVP_RATE_LIMIT_RPS` | 10.0 | Requests per second per API key |
| `VVP_RATE_LIMIT_BURST` | 50 | Burst size for rate limiting |
| `VVP_STATUS_ADMIN_KEY` | (none) | Admin key for /status endpoint |
| `VVP_STATUS_HTTP_PORT` | 8080 | HTTP port for status endpoint |

---

## Appendix: Test Checklist

### Pre-Test Setup
- [ ] SIP Redirect service running
- [ ] Issuer service accessible
- [ ] Verifier service accessible
- [ ] PBX gateway configured

### Credential Setup
- [ ] Organization created
- [ ] API key created and recorded
- [ ] TN credential issued
- [ ] Dossier built (4 credentials)
- [ ] TN mapping created and enabled
- [ ] TN mapping test passes

### PBX Configuration
- [ ] API key added to dialplan
- [ ] Caller ID set to mapped TN
- [ ] Dialplan reloaded

### Call Test
- [ ] WebRTC client registered
- [ ] Test call originated
- [ ] 302 redirect received with VVP headers
- [ ] Call connects with VVP display
- [ ] Brand name shown correctly
- [ ] Verification badge displayed

### Diagnostics
- [ ] Admin dashboard healthy
- [ ] Audit log shows events
- [ ] Verifier parses JWT correctly
- [ ] Full verification passes
