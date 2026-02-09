# VVP System Health Check — Live Validation Task

## Context

Branch `claude/system-health-check-eJzUX` contains two new scripts that implement
a comprehensive system health check with real SIP call testing:

- `scripts/system-health-check.sh` — 4-phase health check orchestrator
- `scripts/sip-call-test.py` — Standalone SIP INVITE test tool (stdlib only)

These scripts have been **syntactically validated** but have NOT been run against
live services. The task is to execute them against production, fix any issues, and
confirm a successful end-to-end call check.

## What needs to happen

### 1. Run the full health check against production

```bash
# First, check out the branch
git fetch origin claude/system-health-check-eJzUX
git checkout claude/system-health-check-eJzUX

# Run phases 1-3 (no --e2e yet, just validate basic health)
./scripts/system-health-check.sh --verbose

# If phases 1-3 pass, run with E2E call tests
VVP_TEST_API_KEY=Xt1uEFpqkp4egcPIYQl6PLOwoHHcIFxENOBVH5DyMSY \
  ./scripts/system-health-check.sh --e2e --verbose
```

### 2. What the E2E call tests do

Phase 4 runs three tests on the PBX VM via `az vm run-command invoke`:

**Test A — SIP Redirect signing test:**
- Deploys `scripts/sip-call-test.py` to PBX via base64 encoding
- Sends a UDP SIP INVITE to port 5070 with `X-VVP-API-Key` header
- SIP Redirect calls Issuer API (`/tn/lookup` + `/vvp/create`)
- Expects: `SIP/2.0 302 Moved Temporarily` with headers:
  - `X-VVP-Status: VALID`
  - `X-VVP-Brand-Name: <org name>`
  - `P-VVP-Identity: <base64>`
  - `P-VVP-Passport: <jwt>`
- Uses TN +441923311001 → +441923311006, API key from dialplan

**Test B — SIP Verify verification test:**
- Sends UDP SIP INVITE to port 5071 with synthetic `Identity` + `P-VVP-Identity` headers
- SIP Verify calls Verifier API (`/verify-callee`)
- Expects: Any SIP response proving the service is alive
- The synthetic PASSporT will fail validation (expected), but a response proves the chain works

**Test C — FreeSWITCH loopback call:**
- Uses `fs_cli bgapi originate` to place a call to 71006 through the VVP dialplan
- The call goes: FreeSWITCH → SIP Redirect (5070) → Issuer API → 302
- Checks FreeSWITCH logs for VVP-related entries as evidence
- Final bridge to user/1006 will fail (no client registered) — that's expected

### 3. If tests fail, here's what to investigate

| Failure | Likely cause | Fix |
|---------|-------------|-----|
| SIP Redirect timeout | Service not listening on 5070 | `systemctl status vvp-sip-redirect` |
| SIP Redirect 401 | API key not recognized | Check Issuer API key config |
| SIP Redirect 404 | TN not mapped in Issuer | Check TN mappings via Issuer admin |
| SIP Verify timeout | Service not listening on 5071 | `systemctl status vvp-sip-verify` |
| FreeSWITCH originate fails | FS not running or dialplan issue | `fs_cli -x 'sofia status'` |
| az vm run-command fails | Azure CLI not authenticated | `az login` |
| Base64 decode fails on PBX | Different base64 flags (GNU vs BSD) | Check `-w0` flag |

### 4. Quick manual test on PBX (if scripts have issues)

Run this directly via `az vm run-command invoke` to test the signing flow:

```bash
az vm run-command invoke --resource-group VVP --name vvp-pbx \
  --command-id RunShellScript --scripts "
python3 -c '
import socket, uuid, time

call_id = f\"vvp-test-{uuid.uuid4().hex[:8]}@127.0.0.1\"
branch = f\"z9hG4bK{uuid.uuid4().hex[:12]}\"
tag = uuid.uuid4().hex[:8]

invite = (
    f\"INVITE sip:+441923311006@127.0.0.1:5070 SIP/2.0\r\n\"
    f\"Via: SIP/2.0/UDP 127.0.0.1:15060;branch={branch}\r\n\"
    f\"From: <sip:+441923311001@127.0.0.1>;tag={tag}\r\n\"
    f\"To: <sip:+441923311006@127.0.0.1>\r\n\"
    f\"Call-ID: {call_id}\r\n\"
    f\"CSeq: 1 INVITE\r\n\"
    f\"Contact: <sip:127.0.0.1:15060>\r\n\"
    f\"X-VVP-API-Key: Xt1uEFpqkp4egcPIYQl6PLOwoHHcIFxENOBVH5DyMSY\r\n\"
    f\"Max-Forwards: 70\r\n\"
    f\"Content-Length: 0\r\n\"
    f\"\r\n\"
).encode()

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(10)
sock.sendto(invite, (\"127.0.0.1\", 5070))
try:
    data, addr = sock.recvfrom(65535)
    resp = data.decode(errors=\"replace\")
    lines = resp.split(\"\r\n\")
    print(f\"Status: {lines[0]}\")
    for l in lines[1:]:
        if \"VVP\" in l.upper() or \"Contact\" in l:
            print(l)
    if \"302\" in lines[0]:
        print(\"\\nSIGNING TEST: PASS\")
    else:
        print(f\"\\nSIGNING TEST: UNEXPECTED ({lines[0]})\")
except socket.timeout:
    print(\"SIGNING TEST: FAIL (no response in 10s)\")
sock.close()
'
"
```

### 5. Success criteria

All of these must be true for the health check to be considered validated:

- [ ] Phase 1: Verifier, Issuer, and all 3 Witnesses report healthy
- [ ] Phase 2: FreeSWITCH, SIP Redirect, SIP Verify all active; ports 5060/5070/5071/5080/7443 listening
- [ ] Phase 3: Dashboard aggregate healthy; PBX can reach Issuer and Verifier APIs
- [ ] Phase 4A: SIP Redirect returns `302` with `X-VVP-Status: VALID` and brand headers
- [ ] Phase 4B: SIP Verify responds to INVITE (any SIP response = service alive)
- [ ] Phase 4C: FreeSWITCH originates loopback call, VVP log entries appear

### 6. After validation

Once all checks pass, commit any fixes and push:

```bash
git add -A
git commit -m "Fix issues found during live E2E call validation"
git push -u origin claude/system-health-check-eJzUX
```
