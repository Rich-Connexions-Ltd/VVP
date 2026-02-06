# VVP Phone SIP.js Setup Guide

This guide explains how to configure FusionPBX/FreeSWITCH for bidirectional calling (inbound PSTN and outbound dialing) with a SIP.js WebRTC client.

## Why SIP.js Instead of Verto?

FreeSWITCH has two WebRTC approaches:

| Feature | Verto (JSON-RPC) | SIP.js (SIP over WSS) |
|---------|------------------|----------------------|
| Protocol | JSON-RPC over WebSocket | Standard SIP over WebSocket |
| Port | 8081 (WS) / 8082 (WSS) | 7443 (WSS) |
| Endpoint | `verto.rtc` | `user/extension` |
| **Incoming calls** | **NOT SUPPORTED** | **SUPPORTED** |
| Registration | Custom JSON-RPC | Standard SIP REGISTER |

**Key finding:** The `verto.rtc` endpoint returns `CHAN_NOT_IMPLEMENTED` when FreeSWITCH tries to originate an outbound call to it. This is a fundamental limitation - Verto was designed for browser-to-PBX calls, not PBX-to-browser.

SIP.js clients register as standard SIP users via WebSocket, so the `user/` endpoint works for incoming calls.

## Prerequisites

1. FusionPBX installed on Azure VM (pbx.rcnx.io)
2. Port 7443 open in Azure NSG (for WSS SIP)
3. Valid SSL certificate (Let's Encrypt)
4. Extension 1001 configured with password

## Step 1: Verify WSS SIP is Enabled

Check that the internal profile has WSS enabled on port 7443:

```bash
fs_cli -x "sofia status"
```

Look for:
```
WSS-BIND-URL     sips:mod_sofia@10.0.0.4:7443;transport=wss
```

If not present, add to internal profile settings in FusionPBX:
- Navigate to: Advanced > SIP Profiles > internal > Settings
- Add: `wss-binding` = `:7443`

## Step 2: Verify Extension 1001

Ensure extension 1001 exists and has a password:

```sql
SELECT * FROM v_extensions WHERE extension = '1001';
```

The extension should be in the default domain (usually matches hostname).

## Step 3: Update Public Dialplan

Replace `/etc/freeswitch/dialplan/public.xml` with the VVP dialplan:

```bash
sudo cp /path/to/services/pbx/config/public-sip.xml /etc/freeswitch/dialplan/public.xml
```

Or manually update to include:

```xml
<?xml version="1.0" encoding="utf-8"?>
<include>
  <context name="public">
    <extension name="vvp-inbound-sip">
      <condition field="destination_number" expression=".*">
        <!-- Log -->
        <action application="log" data="INFO [VVP] Inbound PSTN call from ${caller_id_number}"/>

        <!-- Set VVP headers for SIP.js client -->
        <action application="set" data="sip_h_X-VVP-Brand-Name=Test Corporation Ltd"/>
        <action application="set" data="sip_h_X-VVP-Brand-Logo=https://example.com/logo.png"/>
        <action application="set" data="sip_h_X-VVP-Status=VALID"/>

        <!-- Export to B-leg -->
        <action application="export" data="nolocal:sip_h_X-VVP-Brand-Name=Test Corporation Ltd"/>
        <action application="export" data="nolocal:sip_h_X-VVP-Brand-Logo=https://example.com/logo.png"/>
        <action application="export" data="nolocal:sip_h_X-VVP-Status=VALID"/>

        <!-- Ring and bridge -->
        <action application="ring_ready"/>
        <action application="set" data="hangup_after_bridge=true"/>

        <!-- Bridge to SIP user (SIP.js client) -->
        <action application="bridge" data="user/1001@pbx.rcnx.io"/>

        <!-- Fallback -->
        <action application="answer"/>
        <action application="playback" data="ivr/ivr-call_cannot_be_completed_as_dialed.wav"/>
        <action application="hangup"/>
      </condition>
    </extension>
  </context>
</include>
```

## Step 4: Reload FreeSWITCH Configuration

```bash
fs_cli -x "reloadxml"
```

## Step 5: Test SIP.js Registration

1. Open `sip-phone.html` in browser
2. Enter:
   - Server: `wss://pbx.rcnx.io:7443`
   - Extension: `1001`
   - Password: (extension password)
3. Click "Connect & Register"
4. Should see "Registered - Ready for calls"

## Step 6: Verify Registration in FreeSWITCH

```bash
fs_cli -x "sofia status profile internal reg"
```

Should show extension 1001 registered.

## Step 7: Test Inbound Call

1. Call +44 1923 311000 from a phone
2. SIP.js client should show incoming call
3. VVP headers should be extracted and displayed

## Step 8: Test Outbound Call

The dialplan supports outbound dialing via Twilio:

| Dial Pattern | Destination | Example |
|--------------|-------------|---------|
| `90xxxxxxxxxx` | UK number (+44...) | `907785463210` → `+447785463210` |
| `900xxxxxxxxxxx` | International (+...) | `9001234567890` → `+1234567890` |

**Note:** The dialplan sets `effective_caller_id_number=+441923311000` for outbound calls. This number must be verified in your Twilio account.

1. Enter a UK number with 9-prefix: `907785463210`
2. Click "Call"
3. Call should connect via Twilio

## Troubleshooting

### Registration fails

1. Check password is correct
2. Verify port 7443 is open: `nc -zv pbx.rcnx.io 7443`
3. Check SSL certificate is valid

### Incoming call not received

1. Verify PSTN call reaches FreeSWITCH: `sngrep -d any`
2. Check dialplan is loaded: `fs_cli -x "show dialplan"`
3. Verify user is registered: `fs_cli -x "sofia status profile internal reg"`

### Headers not received

1. Enable header debugging in SIP.js
2. Check FreeSWITCH logs for header set actions
3. Verify `sip_h_` prefix is used (passes headers to B-leg INVITE)

### Outbound call fails with "Invalid Caller ID"

Twilio requires a verified caller ID for outbound calls:

1. Verify the caller ID number in Twilio Console → Phone Numbers → Verified Caller IDs
2. Or use a Twilio-purchased number as the caller ID
3. Update `effective_caller_id_number` in the dialplan

### Outbound call rejected by ACL

If calls fail with "Rejected by acl", disable the inbound ACL for the internal profile:

```sql
UPDATE v_sip_profile_settings
SET sip_profile_setting_enabled = 'false'
WHERE sip_profile_setting_name = 'apply-inbound-acl'
AND sip_profile_uuid = (SELECT sip_profile_uuid FROM v_sip_profiles WHERE sip_profile_name = 'internal');
```

Then restart the profile: `fs_cli -x "sofia profile internal restart"`

## Architecture

### Inbound PSTN Call Flow
```
Twilio ─UDP:5080─> FreeSWITCH (external profile)
                        │
                   [public.xml dialplan]
                   - Sets VVP headers
                   - bridge user/1001
                        │
                        ▼
                   FreeSWITCH (internal profile)
                        │
                   WSS:7443
                        │
                        ▼
                   SIP.js Client (browser)
                   - Receives X-VVP-* headers
                   - Displays VVP verification info
```

### Outbound Call Flow
```
SIP.js Client (browser)
        │
   WSS:7443 INVITE
        │
        ▼
FreeSWITCH (internal profile)
        │
   [public.xml dialplan]
   - Matches 90... pattern
   - Sets caller ID
   - bridge sofia/gateway/twilio
        │
        ▼
FreeSWITCH (external profile)
        │
   UDP:5080
        │
        ▼
      Twilio ─────> PSTN
```
