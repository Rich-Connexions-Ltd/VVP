# PLAN_PBX: Test Infrastructure for VVP SIP Redirect Signer

**Status:** APPROVED (v2)

## Problem Statement

We need to test the VVP SIP redirect signer end-to-end. This requires:

1. A **PBX with integrated SBC** that can:
   - Send SIP INVITE to the redirect server
   - Follow 3xx redirect responses
   - Extract and forward X-headers from the verification service

2. A **WebRTC client** that can:
   - Display caller name and logo derived from SIP headers (X-VVP-Brand-Name, X-VVP-Brand-Logo)
   - Provide a visual indication of VVP verification status

3. **Azure hosting** for the PBX infrastructure

## Current VVP Architecture Context

From the existing codebase:

- **VVP-Identity Header**: Base64url JSON containing `ppt`, `kid` (OOBI URL), `evd` (dossier URL), `iat`, `exp`
- **PASSporT JWT**: Contains `card` field in vCard format with brand info (`fn`, `org`, `logo`, `url`, `photo`)
- **SIP Redirect Service** (Sprint 42): Will run on Azure VM (UDP required), returns 302 with:
  - `P-VVP-Identity`: Base64url VVP-Identity
  - `P-VVP-Passport`: JWT
  - `X-VVP-Brand-Name`: Extracted from card
  - `X-VVP-Brand-Logo`: URL from card
  - `X-VVP-Status`: VALID/INVALID/INDETERMINATE

## Options Analysis

### PBX Platform Options

| Platform | SBC | 3xx Redirect | WebRTC | Azure | Docker | Complexity |
|----------|-----|--------------|--------|-------|--------|------------|
| **FreeSWITCH + FusionPBX** | Built-in | Yes | mod_verto | Marketplace | Yes | Medium |
| **Asterisk + FreePBX** | Via config | PJSIP issues | Native | Marketplace | Yes | Medium |
| **Kamailio** | Full SBC | Native | Via RTPengine | Manual | Yes | High |
| **3CX** | Built-in | Yes | Yes | Yes | No | Low |

**Recommendation: FreeSWITCH + FusionPBX**

Rationale:
- Native SBC functionality handles 3xx redirects properly
- mod_verto provides WebSocket/WebRTC support with flexible data passing
- Available as turnkey Azure Marketplace image
- Docker deployment option for local development
- Open source with active community
- JSON-RPC interface allows custom header/data passing to WebRTC clients

### WebRTC Client Options

| Client | Custom Headers | UI Customization | Integration |
|--------|---------------|------------------|-------------|
| **SIP.js** | extraHeaders | Full control | Any SIP proxy |
| **FreeSWITCH Verto.js** | JSON-RPC params | Full control | FreeSWITCH only |
| **SaraPhone** | Via Verto | Fork required | FusionPBX native |
| **Custom React/Vue** | Via SIP.js | Full control | Any |

**Recommendation: SaraPhone (FusionPBX built-in) with VVP extensions**

Rationale:
- SaraPhone is already integrated with FusionPBX and uses Verto.js
- Reduces initial build effort - fork and extend rather than build from scratch
- Can migrate to fully custom client if SaraPhone proves limiting
- Verto.js provides channel variable access via JSON-RPC params

### Azure Hosting Options

| Option | Cost | Setup | Maintenance | Best For |
|--------|------|-------|-------------|----------|
| **Azure VM (Marketplace)** | ~$50-100/mo | Minutes | Managed updates | Production |
| **Azure VM (Manual)** | ~$30-50/mo | Hours | Self-managed | Dev/Test |
| **Docker on Azure VM** | ~$30-50/mo | Medium | Self-managed | Flexibility |
| **Azure Container Instances** | Variable | Medium | Low | Not viable (no UDP) |

**Recommendation: FusionPBX Azure Marketplace image for initial testing**

Rationale:
- Turnkey deployment in minutes
- Pre-configured FreeSWITCH with WebRTC support
- SSL/TLS certificates manageable via UI
- Can migrate to Docker for more control later

## Recommended Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Azure UK South                               │
│                                                                      │
│  ┌──────────────────┐     ┌──────────────────┐    ┌──────────────┐ │
│  │ FusionPBX VM     │     │ SIP Redirect VM  │    │ VVP Verifier │ │
│  │ (FreeSWITCH)     │     │ (Sprint 42)      │    │ Container App│ │
│  │                  │     │                  │    │              │ │
│  │ - SBC functions  │ SIP │ - Receives INVITE│HTTP│ - /verify    │ │
│  │ - mod_verto      │────>│ - Calls issuer   │───>│ - /verify-   │ │
│  │ - WebRTC gateway │<────│ - Returns 302    │    │   callee     │ │
│  │                  │ 302 │   + X-VVP-*      │    │              │ │
│  └────────┬─────────┘     └──────────────────┘    └──────────────┘ │
│           │                                                         │
│           │ WSS (WebSocket Secure)                                  │
│           │                                                         │
└───────────┼─────────────────────────────────────────────────────────┘
            │
            ▼
    ┌──────────────────┐
    │ WebRTC Client    │
    │ (Browser)        │
    │                  │
    │ - Verto.js       │
    │ - Display name   │
    │ - Display logo   │
    │ - Show VVP status│
    └──────────────────┘
```

## Data Flow for VVP Headers to WebRTC

### Critical Assumption: 302 Header Preservation

**Risk:** The entire approach depends on FreeSWITCH preserving X-VVP-* headers from the 302 response into the redirected call leg (B-leg). This must be validated before proceeding to client development.

**Call Leg Context:**
- **A-leg**: Original INVITE from caller → VVP Redirect Server
- **302 Response**: Contains X-VVP-* headers
- **B-leg**: Redirected INVITE to final destination (contains headers)
- **C-leg**: FreeSWITCH → WebRTC client via Verto

The headers must propagate from B-leg channel variables to C-leg for Verto.js access.

### Primary Approach: FreeSWITCH Channel Variables

1. FreeSWITCH receives redirected INVITE (B-leg) with X-VVP-* headers
2. Dialplan extracts headers to channel variables on B-leg:
   ```xml
   <!-- Location: /etc/freeswitch/dialplan/public/00_vvp_headers.xml -->
   <extension name="vvp-header-extraction">
     <condition field="destination_number" expression="^(.*)$">
       <action application="set" data="vvp_brand_name=${sip_h_X-VVP-Brand-Name}"/>
       <action application="set" data="vvp_brand_logo=${sip_h_X-VVP-Brand-Logo}"/>
       <action application="set" data="vvp_status=${sip_h_X-VVP-Status}"/>
       <action application="export" data="nolocal:vvp_brand_name=${vvp_brand_name}"/>
       <action application="export" data="nolocal:vvp_brand_logo=${vvp_brand_logo}"/>
       <action application="export" data="nolocal:vvp_status=${vvp_status}"/>
       <action application="log" data="INFO VVP Headers: name=${vvp_brand_name}, logo=${vvp_brand_logo}, status=${vvp_status}"/>
     </condition>
   </extension>
   ```
3. `export nolocal:` propagates variables to C-leg (Verto/WebRTC)
4. mod_verto passes channel variables to WebRTC client via JSON-RPC
5. Verto.js client receives variables in call event:
   ```javascript
   vertoSession.on('newCall', (call) => {
     const brandName = call.params.vvp_brand_name;
     const brandLogo = call.params.vvp_brand_logo;
     const vvpStatus = call.params.vvp_status;
     updateCallerDisplay(brandName, brandLogo, vvpStatus);
   });
   ```

### Fallback Approach: Kamailio Header Injection

If FreeSWITCH does not preserve 302 headers on the redirected leg, use Kamailio as a SIP proxy in front of FreeSWITCH:

1. Kamailio receives 302 from VVP Redirect Server
2. Kamailio extracts X-VVP-* headers and stores in AVP (attribute-value pair)
3. Kamailio sends new INVITE to FreeSWITCH with headers explicitly added
4. FreeSWITCH receives headers on initial INVITE (not redirect)

```
# Kamailio script snippet
if (is_method("INVITE")) {
    $avp(vvp_name) = $hdr(X-VVP-Brand-Name);
    $avp(vvp_logo) = $hdr(X-VVP-Brand-Logo);
    $avp(vvp_status) = $hdr(X-VVP-Status);
}

# On redirect response
onreply_route[REDIRECT] {
    if (t_check_status("302")) {
        # Re-inject headers into new INVITE
        append_hf("X-VVP-Brand-Name: $avp(vvp_name)\r\n");
        append_hf("X-VVP-Brand-Logo: $avp(vvp_logo)\r\n");
        append_hf("X-VVP-Status: $avp(vvp_status)\r\n");
    }
}
```

## Implementation Phases

### Phase 1: Azure Infrastructure Setup

**Goal:** Deploy FusionPBX on Azure with basic SIP trunk

**Tasks:**
1. Deploy FusionPBX from Azure Marketplace (UK South)
1. Deploy FusionPBX from Azure Marketplace (UK South preferred; fallback to North Europe if capacity constrained)
2. Configure SSL certificate (Let's Encrypt via FusionPBX)
3. Configure basic SIP trunk to test connectivity
4. Verify WebRTC works with built-in SaraPhone client
5. Document access URLs and credentials

**Exit Criteria:**
- FusionPBX accessible at https://pbx.rcnx.io
- SIP registration working on port 5060
- WebRTC calls working between two browser clients

### Phase 2: SIP 3xx Redirect Handling & Header Validation

**Goal:** Validate that FreeSWITCH preserves 302 response headers into channel variables, or implement fallback

**Critical Validation Task (MUST PASS before Phase 3):**

Deploy a mock SIP redirect server that returns 302 with test X-VVP-* headers, then verify headers appear as channel variables on the redirected call leg.

**Tasks:**

1. **Deploy mock redirect server** (Python script or sipp scenario):
   ```python
   # services/pbx/test/mock_redirect.py
   # Returns 302 with X-VVP-* headers for any INVITE
   ```

2. **Configure FreeSWITCH gateway**:
   ```xml
   <!-- Location: /etc/freeswitch/sip_profiles/external/vvp_redirect.xml -->
   <gateway name="vvp-redirect-test">
     <param name="realm" value="redirect-server-ip"/>
     <param name="proxy" value="redirect-server-ip:5060"/>
     <param name="register" value="false"/>
   </gateway>
   ```

3. **Configure FreeSWITCH redirect handling**:
   ```xml
   <!-- Location: /etc/freeswitch/sip_profiles/external.xml -->
   <!-- Add to gateway or profile settings -->
   <param name="manage-presence" value="false"/>
   <!-- FreeSWITCH follows 3xx by default; verify behavior -->
   ```

4. **Add VVP header extraction dialplan** (as defined in Data Flow section)

5. **Run validation test with sipp or test call**:
   ```bash
   # Capture SIP trace
   sngrep -O /tmp/sip_trace.pcap

   # Make test call through redirect
   fs_cli -x "originate sofia/gateway/vvp-redirect-test/+15551234567 &park()"

   # Verify channel variables
   fs_cli -x "show channels" | grep vvp_
   ```

6. **Acceptance Test Criteria** (validate on B-leg channel):
   - [ ] SIP trace shows 302 response with X-VVP-* headers
   - [ ] SIP trace shows new INVITE to redirect target
   - [ ] `fs_cli show channels` displays vvp_brand_name, vvp_brand_logo, vvp_status on B-leg
   - [ ] FreeSWITCH logs show "VVP Headers:" line with values
   - [ ] After bridge to C-leg (Verto), verify variables propagated via `export nolocal:`

7. **If validation FAILS**: Implement Kamailio fallback (see Fallback Approach above)

**Exit Criteria:**
- Validation test PASSES: X-VVP-* headers available as channel variables
- OR fallback implemented: Kamailio proxy injecting headers
- SIP trace documentation saved for reference
- Decision recorded: primary approach or fallback

### Phase 3: WebRTC Client Development

**Goal:** Extend SaraPhone to display VVP brand info from channel variables

**Primary Client:** SaraPhone (FusionPBX built-in)
- Already integrated with FreeSWITCH via Verto.js
- Reduces build time; fork and extend rather than build from scratch
- Migrate to fully custom client only if SaraPhone proves limiting

**Tasks:**

1. **Fork SaraPhone repository**:
   ```bash
   git clone https://github.com/gmaruzz/saraphone.git services/pbx/webrtc/saraphone-vvp
   ```

2. **Locate Verto.js call event handler** in SaraPhone source

3. **Add VVP channel variable extraction**:
   ```javascript
   // In call event handler
   function handleIncomingCall(call) {
     const vvpData = {
       brandName: call.params.vvp_brand_name || call.params.caller_id_name,
       brandLogo: call.params.vvp_brand_logo,
       status: call.params.vvp_status || 'UNKNOWN'
     };
     updateVVPDisplay(vvpData);
   }
   ```

4. **Add VVP display UI components**:
   - Brand name: Large, prominent display replacing/augmenting caller ID
   - Logo: Image element with fallback placeholder
   - Status indicator: Color-coded badge (VALID=green, INVALID=red, INDETERMINATE=amber, UNKNOWN=gray)

5. **Style to match VVP branding** (colors, fonts from issuer UI)

6. **Test with mock channel variables**:
   ```bash
   # Set test variables on a call
   fs_cli -x "uuid_setvar <uuid> vvp_brand_name 'Test Corp'"
   fs_cli -x "uuid_setvar <uuid> vvp_brand_logo 'https://example.com/logo.png'"
   fs_cli -x "uuid_setvar <uuid> vvp_status 'VALID'"
   ```

**Exit Criteria:**
- SaraPhone fork displays vvp_brand_name prominently
- Logo loads from vvp_brand_logo URL (with fallback for missing)
- VVP status badge shows correct color for each status
- Works in Chrome, Firefox, Safari
- No regressions in basic SaraPhone functionality

### Phase 4: End-to-End Integration

**Goal:** Complete test flow from INVITE to branded call display

**Tasks:**
1. Connect FusionPBX to VVP SIP Redirect service (Sprint 42)
2. Configure test TN mappings in issuer
3. Make test call through full chain
4. Verify brand name and logo appear on WebRTC client
5. Test all VVP status outcomes (VALID/INVALID/INDETERMINATE)

**Exit Criteria:**
- End-to-end call flow working
- Real brand data displayed from VVP dossier
- All verification statuses handled correctly

## Files to Create/Modify

| Location | File | Purpose |
|----------|------|---------|
| Documentation/ | PLAN_PBX.md | This plan |
| services/pbx/ | README.md | PBX setup documentation |
| services/pbx/config/ | dialplan.xml | FreeSWITCH dialplan for header extraction |
| services/pbx/config/ | verto.conf.xml | Verto configuration |
| services/pbx/webrtc/ | index.html | WebRTC client |
| services/pbx/webrtc/ | vvp-phone.js | Custom Verto.js client |
| services/pbx/webrtc/ | styles.css | VVP-branded styling |
| SPRINTS.md | (update) | Add PBX test infrastructure sprint |

## Decisions Made

| Decision | Choice | Notes |
|----------|--------|-------|
| Domain | pbx.rcnx.io | Use existing rcnx.io domain |
| Azure Subscription | Existing VVP | Deploy in UK South with verifier/issuer |
| Azure Subscription | Existing VVP | Deploy in UK South (or North Europe fallback) |
| SSL Certificate | Let's Encrypt | Via FusionPBX built-in support |

## Open Questions

1. **Test TNs**: Which telephone numbers should be configured for testing?

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| **302 headers not preserved** | Medium | High | Phase 2 validation task with explicit fallback (Kamailio) |
| FreeSWITCH redirect behavior undocumented | Medium | High | Test with mock server + sipp before committing |
| Channel variables not propagating to Verto | Medium | High | Use `export nolocal:` and verify with fs_cli |
| WebRTC browser compatibility | Medium | Medium | Test all browsers; use adapter.js shim |
| Azure VM costs | Low | Low | Use B2s size; shut down when not testing; costs vary by region |
| Azure Region Capacity | Medium | High | Fallback to North Europe (low latency to UK South) |
| SSL/TLS complexity | Medium | Medium | FusionPBX has built-in Let's Encrypt support |
| Header size limits in SIP | Low | Medium | Truncate logo URLs if needed |

## Cost Estimate

| Resource | Monthly Cost |
|----------|-------------|
| Azure VM (Standard_B2s) | ~$30-50 |
| Public IP (static) | ~$3-5 |
| Storage (OS disk) | ~$5 |
| Bandwidth (UDP/SIP) | Variable |
| **Total** | **~$40-65/month** |

*Note: Costs may vary by Azure region. UK South pricing used as baseline. Shut down VM when not testing to reduce costs.*

## Revision History

### v2 - Addressing Reviewer Feedback

**Changes made based on REVIEW.md feedback:**

1. **[High] 302 Header Preservation Validation**
   - Added "Critical Assumption" section explaining the risk
   - Clarified call leg context (A-leg, B-leg, C-leg)
   - Added explicit Kamailio fallback approach with script snippets
   - Phase 2 now includes mandatory validation task with acceptance criteria

2. **[Medium] Concrete FreeSWITCH Configuration**
   - Added specific file paths (`/etc/freeswitch/dialplan/public/00_vvp_headers.xml`)
   - Added `export nolocal:` to propagate variables across legs
   - Added sipp/sngrep test commands
   - Added acceptance test checklist with specific criteria

3. **[Low] Primary WebRTC Client Decision**
   - Changed recommendation from "Verto.js or SIP.js" to "SaraPhone with VVP extensions"
   - Updated Phase 3 to fork SaraPhone rather than build from scratch
   - Added specific code integration points

4. **Cost Estimate Clarification**
   - Added note about regional cost variability
   - Added bandwidth line item

## References

- [FusionPBX Azure Marketplace](https://marketplace.microsoft.com/en-us/product/virtual-machines/solvedevops1643693563360.fusionpbx_debian12)
- [FusionPBX WebRTC Documentation](https://docs.fusionpbx.com/en/latest/applications_optional/webrtc.html)
- [FreeSWITCH mod_verto](https://developer.signalwire.com/freeswitch/FreeSWITCH-Explained/Modules/mod_verto_3964934/)
- [SIP.js Library](https://sipjs.com/)
- [SaraPhone GitHub](https://github.com/gmaruzz/saraphone)
- [FusionPBX Docker](https://github.com/rgon/FusionPBX-docker)
- Existing VVP SIP Router Plan: `Documentation/SIP_Router/PLAN.md`
