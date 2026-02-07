# VVP PBX Test Infrastructure

Test infrastructure for validating VVP SIP redirect signing. Provides a FusionPBX (FreeSWITCH) deployment with WebRTC client for end-to-end testing.

## Architecture

```
WebRTC Client ──INVITE──> FusionPBX ──INVITE──> VVP SIP Redirect
     │                        │                      │
     │                        │ <── 302 + X-VVP-* ───┘
     │                        │
     │                        │──INVITE + Identity──> Destination
     │                        │   (with STIR header)
     └────────────────────────┘
```

## Components

| Component | Purpose |
|-----------|---------|
| FusionPBX VM | PBX with FreeSWITCH, handles SIP redirects |
| SaraPhone-VVP | WebRTC client fork with VVP brand display |
| Diagnostic Tools | SIP monitoring and debugging scripts |

## Azure VM Deployment

### Prerequisites

- Azure CLI installed and logged in (`az login`)
- DNS access to rcnx.io domain

### Step 1: Create Azure VM

```bash
# Variables
RESOURCE_GROUP="vvp-rg"
LOCATION="uksouth"
VM_NAME="vvp-pbx"
VM_SIZE="Standard_B2s"

# Create VM from FusionPBX Marketplace image
az vm create \
  --resource-group $RESOURCE_GROUP \
  --name $VM_NAME \
  --location $LOCATION \
  --image "solvedevops1643693563360:fusionpbx_debian12:fusionpbx_debian12:latest" \
  --size $VM_SIZE \
  --admin-username vvpadmin \
  --generate-ssh-keys \
  --public-ip-address-allocation static \
  --nsg-rule SSH

# Get public IP
az vm show -d -g $RESOURCE_GROUP -n $VM_NAME --query publicIps -o tsv
```

### Step 2: Configure Network Security Group

```bash
NSG_NAME="${VM_NAME}NSG"

# SIP UDP/TCP
az network nsg rule create -g $RESOURCE_GROUP --nsg-name $NSG_NAME \
  -n AllowSIP --priority 100 --destination-port-ranges 5060 \
  --protocol '*' --access Allow

# SIPS (TLS)
az network nsg rule create -g $RESOURCE_GROUP --nsg-name $NSG_NAME \
  -n AllowSIPS --priority 101 --destination-port-ranges 5061 \
  --protocol Tcp --access Allow

# HTTPS
az network nsg rule create -g $RESOURCE_GROUP --nsg-name $NSG_NAME \
  -n AllowHTTPS --priority 102 --destination-port-ranges 443 \
  --protocol Tcp --access Allow

# HTTP (for Let's Encrypt)
az network nsg rule create -g $RESOURCE_GROUP --nsg-name $NSG_NAME \
  -n AllowHTTP --priority 103 --destination-port-ranges 80 \
  --protocol Tcp --access Allow

# RTP Media
az network nsg rule create -g $RESOURCE_GROUP --nsg-name $NSG_NAME \
  -n AllowRTP --priority 104 --destination-port-ranges 16384-32768 \
  --protocol Udp --access Allow

# WebSocket Secure (Verto)
az network nsg rule create -g $RESOURCE_GROUP --nsg-name $NSG_NAME \
  -n AllowWSS --priority 105 --destination-port-ranges 8082 \
  --protocol Tcp --access Allow
```

### Step 3: Configure DNS

Add A record for `pbx.rcnx.io` pointing to the VM's public IP:

```bash
# Get public IP
PUBLIC_IP=$(az vm show -d -g $RESOURCE_GROUP -n $VM_NAME --query publicIps -o tsv)
echo "Add DNS A record: pbx.rcnx.io -> $PUBLIC_IP"
```

### Step 4: Initial FusionPBX Setup

1. SSH to VM: `ssh vvpadmin@pbx.rcnx.io`
2. Access setup wizard: `https://<public-ip>/`
3. Complete setup:
   - Set domain: `pbx.rcnx.io`
   - Set admin password (store securely)
   - Configure database

### Step 5: Configure SSL Certificate

FusionPBX has built-in Let's Encrypt support:

```bash
# On the VM
sudo /usr/src/fusionpbx-install.sh/debian/resources/letsencrypt.sh
```

Or manually:

```bash
sudo apt install certbot
sudo certbot certonly --webroot -w /var/www/fusionpbx -d pbx.rcnx.io
```

### Step 6: Deploy VVP Configuration

```bash
# Copy dialplan configs
scp config/*.xml vvpadmin@pbx.rcnx.io:/tmp/

# On VM: Move to FreeSWITCH config
ssh vvpadmin@pbx.rcnx.io
sudo cp /tmp/00_vvp_*.xml /etc/freeswitch/dialplan/public/
sudo cp /tmp/01_vvp_*.xml /etc/freeswitch/dialplan/default/
sudo cp /tmp/02_vvp_*.xml /etc/freeswitch/dialplan/default/
sudo fs_cli -x "reloadxml"
```

### Step 7: Deploy Diagnostic Scripts

```bash
# Copy scripts
scp scripts/*.sh vvpadmin@pbx.rcnx.io:/tmp/

# On VM: Install scripts
ssh vvpadmin@pbx.rcnx.io
sudo cp /tmp/*.sh /usr/local/bin/
sudo chmod +x /usr/local/bin/monitor-sip.sh
sudo chmod +x /usr/local/bin/watch-channels.sh
sudo chmod +x /usr/local/bin/tail-vvp-logs.sh
```

### Step 8: Deploy SaraPhone-VVP

```bash
# Copy WebRTC client
scp -r webrtc/saraphone-vvp vvpadmin@pbx.rcnx.io:/tmp/

# On VM: Install to FusionPBX
ssh vvpadmin@pbx.rcnx.io
sudo cp -r /tmp/saraphone-vvp /var/www/fusionpbx/app/
sudo chown -R www-data:www-data /var/www/fusionpbx/app/saraphone-vvp
```

Access at: `https://pbx.rcnx.io/app/saraphone-vvp/`

## Diagnostic Tools

### Real-time SIP Monitoring

```bash
# On VM
monitor-sip.sh
# Creates pcap files in /tmp/vvp_sip_*.pcap
```

### Watch Channel Variables

```bash
# On VM
watch-channels.sh
# Shows vvp_* variables on active calls
```

### Tail VVP Logs

```bash
# On VM
tail-vvp-logs.sh
# Filters FreeSWITCH logs for VVP messages
```

### FreeSWITCH CLI

```bash
# Check channels
fs_cli -x "show channels"

# Check registrations
fs_cli -x "show registrations"

# Reload dialplan
fs_cli -x "reloadxml"

# Originate test call
fs_cli -x "originate sofia/gateway/vvp-redirect/+15551234567 &park()"
```

## Test Extensions

| Extension | Purpose |
|-----------|---------|
| 7777 | Dump all VVP headers to log |
| 7778 | Inject test VVP headers and bridge to 1001 |
| 8888 | C-leg validation (bridge to Verto with test vars) |
| 9999 | Loopback target for B-leg validation |

## Directory Structure

```
services/pbx/
├── README.md                     # This file
├── config/
│   ├── 00_vvp_diagnostics.xml   # Diagnostic extensions (7777, 7778)
│   ├── 00_vvp_headers.xml       # VVP header extraction dialplan
│   ├── 01_vvp_loopback.xml      # Loopback target (9999)
│   ├── 02_vvp_verto_test.xml    # C-leg validation (8888)
│   ├── vvp_redirect.xml         # Gateway to VVP SIP Redirect
│   ├── vvp-sip-redirect.service # Systemd unit for sip-redirect
│   └── nginx-sip-monitor.conf  # nginx reverse proxy for dashboard
├── scripts/
│   ├── deploy-sip-monitor.sh    # Deploy sip-redirect + monitor to PBX
│   ├── provision-monitor-user.sh # Create dashboard admin user
│   ├── monitor-sip.sh           # SIP packet capture
│   ├── watch-channels.sh        # Channel variable monitoring
│   └── tail-vvp-logs.sh         # VVP log filtering
├── test/
│   └── mock_redirect.py         # Mock SIP 302 server for testing
├── webrtc/
│   └── saraphone-vvp/           # Forked SaraPhone with VVP display
│       ├── index.html
│       ├── js/
│       │   ├── vvp-handler.js   # VVP data extraction
│       │   └── vvp-diagnostics.js
│       └── css/
│           └── vvp-styles.css   # VVP branding
└── VALIDATION_RESULTS.md        # Phase 2 validation documentation
```

## X-Header Reference

Headers returned by VVP SIP Redirect service on 302 responses:

| Header | Required | Description |
|--------|----------|-------------|
| `Identity` | Yes | RFC 8224 STIR PASSporT |
| `P-VVP-Identity` | Yes | Base64url VVP-Identity JSON |
| `P-VVP-Passport` | Yes | Complete PASSporT JWT |
| `X-VVP-Brand-Name` | Yes | Organization name from dossier |
| `X-VVP-Brand-Logo` | No | Logo URL from dossier vCard |
| `X-VVP-Status` | Yes | VALID, INVALID, or INDETERMINATE |

## SIP Monitoring Dashboard

Real-time SIP event visualization dashboard for debugging VVP call flows.

**URL:** `https://pbx.rcnx.io/sip-monitor/`

### Features

- Real-time WebSocket streaming of SIP INVITE events
- JWT/PASSporT decoding with VVP field highlighting
- Session-based authentication with rate limiting
- Tabbed detail view: Summary, All Headers, VVP Headers, PASSporT, Raw SIP

### Initial Setup

The deployment script handles everything:

```bash
# From repo root
./services/pbx/scripts/deploy-sip-monitor.sh
```

This stops the old mock service, deploys the sip-redirect code, installs dependencies, configures nginx, provisions an admin user, and starts the service. The admin password is displayed once during provisioning.

### Management Commands

```bash
# Check service status
az vm run-command invoke --resource-group VVP --name vvp-pbx --command-id RunShellScript --scripts "systemctl status vvp-sip-redirect --no-pager"

# View service logs
az vm run-command invoke --resource-group VVP --name vvp-pbx --command-id RunShellScript --scripts "journalctl -u vvp-sip-redirect -n 50 --no-pager"

# Restart service
az vm run-command invoke --resource-group VVP --name vvp-pbx --command-id RunShellScript --scripts "systemctl restart vvp-sip-redirect"
```

### Architecture

```
Browser ──HTTPS──> nginx (pbx.rcnx.io:443)
                     │
                     ├── /sip-monitor/ ──proxy──> aiohttp (127.0.0.1:8090)
                     │                              ├── /login    (login page)
                     │                              ├── /         (dashboard)
                     │                              ├── /api/*    (REST API)
                     │                              └── /ws       (WebSocket)
                     │
                     └── /* ──> FusionPBX (default)
```

## Cost

| Resource | Monthly |
|----------|---------|
| Azure VM (B2s) | ~$35 |
| Public IP | ~$4 |
| Storage | ~$5 |
| **Total** | **~$45/month** |

*Tip: Shut down VM when not actively testing to reduce costs.*

## Related Documentation

- [PLAN_PBX.md](../../Documentation/PLAN_PBX.md) - Approved architecture
- [Sprint 42](../../SPRINTS.md) - SIP Redirect Signing Service
- [Sprint 43](../../SPRINTS.md) - PBX Test Infrastructure
- [Sprint 47-49](../../SPRINTS.md) - SIP Monitor Dashboard
