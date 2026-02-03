# VVP Azure Deployment Guide

This document describes how to deploy the VVP services (Issuer, Verifier, and Witnesses) to Azure Container Apps.

## Prerequisites

- Azure CLI installed and authenticated (`az login`)
- Access to the VVP resource group in Azure
- GitHub repository secrets configured for CI/CD
- DNS access to rcnx.io domain

## Architecture Overview

```
                    ┌─────────────────────────────────────────────┐
                    │              rcnx.io DNS                     │
                    │  vvp-verifier.rcnx.io → Azure Container App  │
                    │  vvp-issuer.rcnx.io   → Azure Container App  │
                    │  vvp-witness1.rcnx.io → Azure Container App  │
                    │  vvp-witness2.rcnx.io → Azure Container App  │
                    │  vvp-witness3.rcnx.io → Azure Container App  │
                    └─────────────────────────────────────────────┘
                                         │
                    ┌────────────────────┼────────────────────┐
                    │                    │                    │
              ┌─────▼─────┐       ┌──────▼──────┐      ┌─────▼─────┐
              │ vvp-issuer │       │ vvp-verifier│      │ witnesses │
              │  (public)  │       │   (public)  │      │  (public) │
              │  API auth  │       │             │      │   x3      │
              └────────────┘       └─────────────┘      └───────────┘
                    │                                         │
              ┌─────▼─────┐                           ┌──────▼──────┐
              │Azure Files│                           │ Azure Files │
              │  Premium  │                           │   Premium   │
              └───────────┘                           └─────────────┘
```

## Resource Summary

| Component | Azure Service | Storage | Custom Domain |
|-----------|---------------|---------|---------------|
| Verifier | Container App | - | vvp-verifier.rcnx.io |
| Issuer | Container App | Azure Files (issuerstorage) | vvp-issuer.rcnx.io |
| Witness 1 (wan) | Container App | Azure Files (witness1storage) | vvp-witness1.rcnx.io |
| Witness 2 (wil) | Container App | Azure Files (witness2storage) | vvp-witness2.rcnx.io |
| Witness 3 (wes) | Container App | Azure Files (witness3storage) | vvp-witness3.rcnx.io |
| API Keys | Key Vault (vvp-issuer-kv) | - | - |

---

## Part 1: Issuer Deployment

### 1.1 Create Storage Account

```bash
# Create storage account (Premium for LMDB performance)
az storage account create \
  --name vvpissuerdata \
  --resource-group VVP \
  --location uksouth \
  --sku Premium_LRS \
  --kind FileStorage

# Get storage key
STORAGE_KEY=$(az storage account keys list \
  --account-name vvpissuerdata \
  --resource-group VVP \
  --query "[0].value" -o tsv)

# Create file share
az storage share create \
  --name vvp-issuer-data \
  --account-name vvpissuerdata \
  --account-key "$STORAGE_KEY" \
  --quota 100
```

### 1.2 Create Key Vault

```bash
# Create Key Vault
az keyvault create \
  --name vvp-issuer-kv \
  --resource-group VVP \
  --location uksouth \
  --enable-rbac-authorization true

# Grant yourself access
USER_ID=$(az ad signed-in-user show --query id -o tsv)
az role assignment create \
  --role "Key Vault Secrets Officer" \
  --assignee "$USER_ID" \
  --scope "/subscriptions/$(az account show --query id -o tsv)/resourceGroups/VVP/providers/Microsoft.KeyVault/vaults/vvp-issuer-kv"

# Generate and store API key
python3 services/issuer/scripts/generate-api-key.py
# Copy the JSON output and store in Key Vault:
az keyvault secret set \
  --vault-name vvp-issuer-kv \
  --name issuer-api-keys \
  --value '<JSON_FROM_SCRIPT>'
```

### 1.3 Create Container App

```bash
# Create issuer Container App
az containerapp create \
  --name vvp-issuer \
  --resource-group VVP \
  --environment vvp-env \
  --image mcr.microsoft.com/hello-world \
  --target-port 8001 \
  --ingress external \
  --min-replicas 1 \
  --max-replicas 1 \
  --cpu 0.5 \
  --memory 1Gi

# Enable managed identity
az containerapp identity assign \
  --name vvp-issuer \
  --resource-group VVP \
  --system-assigned

# Grant Key Vault access
IDENTITY_ID=$(az containerapp show --name vvp-issuer --resource-group VVP \
  --query 'identity.principalId' -o tsv)

az role assignment create \
  --role "Key Vault Secrets User" \
  --assignee "$IDENTITY_ID" \
  --scope "/subscriptions/$(az account show --query id -o tsv)/resourceGroups/VVP/providers/Microsoft.KeyVault/vaults/vvp-issuer-kv"
```

### 1.4 Configure Storage Mount

```bash
# Add storage to environment
az containerapp env storage set \
  --name vvp-env \
  --resource-group VVP \
  --storage-name issuerstorage \
  --azure-file-account-name vvpissuerdata \
  --azure-file-account-key "$STORAGE_KEY" \
  --azure-file-share-name vvp-issuer-data \
  --access-mode ReadWrite
```

Then export, modify, and re-apply the Container App YAML to add volume mounts.

---

## Part 2: Witness Deployment

### 2.1 Create Witness Storage

```bash
# Create storage account for witnesses
az storage account create \
  --name vvpwitnessdata \
  --resource-group VVP \
  --location uksouth \
  --sku Premium_LRS \
  --kind FileStorage

STORAGE_KEY=$(az storage account keys list \
  --account-name vvpwitnessdata \
  --resource-group VVP \
  --query "[0].value" -o tsv)

# Create file shares
az storage share create --name witness1-data --account-name vvpwitnessdata --account-key "$STORAGE_KEY" --quota 100
az storage share create --name witness2-data --account-name vvpwitnessdata --account-key "$STORAGE_KEY" --quota 100
az storage share create --name witness3-data --account-name vvpwitnessdata --account-key "$STORAGE_KEY" --quota 100

# Add to Container Apps environment
az containerapp env storage set --name vvp-env --resource-group VVP \
  --storage-name witness1storage --azure-file-account-name vvpwitnessdata \
  --azure-file-account-key "$STORAGE_KEY" --azure-file-share-name witness1-data --access-mode ReadWrite

az containerapp env storage set --name vvp-env --resource-group VVP \
  --storage-name witness2storage --azure-file-account-name vvpwitnessdata \
  --azure-file-account-key "$STORAGE_KEY" --azure-file-share-name witness2-data --access-mode ReadWrite

az containerapp env storage set --name vvp-env --resource-group VVP \
  --storage-name witness3storage --azure-file-account-name vvpwitnessdata \
  --azure-file-account-key "$STORAGE_KEY" --azure-file-share-name witness3-data --access-mode ReadWrite
```

### 2.2 Deploy Witness Container Apps

```bash
# Create witness Container Apps
az containerapp create --name vvp-witness1 --resource-group VVP --environment vvp-env \
  --image gleif/keri:1.2.10 --target-port 5642 --ingress external \
  --min-replicas 1 --max-replicas 1 --cpu 0.5 --memory 1Gi

az containerapp create --name vvp-witness2 --resource-group VVP --environment vvp-env \
  --image gleif/keri:1.2.10 --target-port 5643 --ingress external \
  --min-replicas 1 --max-replicas 1 --cpu 0.5 --memory 1Gi

az containerapp create --name vvp-witness3 --resource-group VVP --environment vvp-env \
  --image gleif/keri:1.2.10 --target-port 5644 --ingress external \
  --min-replicas 1 --max-replicas 1 --cpu 0.5 --memory 1Gi
```

Then configure each via YAML with:
- Command: `kli witness demo --name <wan|wil|wes> --tcp <port> --http <port>`
- Environment: `KERI_DB_PATH=/data/witness`
- Volume mount: `/data/witness` → witnessNstorage

**Deterministic Witness AIDs:**
- wan: `BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha`
- wil: `BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM`
- wes: `BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX`

---

## Part 3: Custom Domain Configuration

### 3.1 DNS Records

Add these records to your DNS provider (rcnx.io):

**CNAME Records:**
```
vvp-verifier.rcnx.io  CNAME  vvp-verifier.wittytree-2a937ccd.uksouth.azurecontainerapps.io
vvp-issuer.rcnx.io    CNAME  vvp-issuer.wittytree-2a937ccd.uksouth.azurecontainerapps.io
vvp-witness1.rcnx.io  CNAME  vvp-witness1.wittytree-2a937ccd.uksouth.azurecontainerapps.io
vvp-witness2.rcnx.io  CNAME  vvp-witness2.wittytree-2a937ccd.uksouth.azurecontainerapps.io
vvp-witness3.rcnx.io  CNAME  vvp-witness3.wittytree-2a937ccd.uksouth.azurecontainerapps.io
```

**TXT Records (for domain validation):**
```
asuid.vvp-verifier.rcnx.io  TXT  F9F237347CA164438429A037DAA1CBB6BE40E8F497D03ED173AA6E4C02EB345F
asuid.vvp-issuer.rcnx.io    TXT  F9F237347CA164438429A037DAA1CBB6BE40E8F497D03ED173AA6E4C02EB345F
asuid.vvp-witness1.rcnx.io  TXT  F9F237347CA164438429A037DAA1CBB6BE40E8F497D03ED173AA6E4C02EB345F
asuid.vvp-witness2.rcnx.io  TXT  F9F237347CA164438429A037DAA1CBB6BE40E8F497D03ED173AA6E4C02EB345F
asuid.vvp-witness3.rcnx.io  TXT  F9F237347CA164438429A037DAA1CBB6BE40E8F497D03ED173AA6E4C02EB345F
```

### 3.2 Bind Custom Domains

```bash
# Add hostnames
az containerapp hostname add --name vvp-verifier --resource-group VVP --hostname vvp-verifier.rcnx.io
az containerapp hostname add --name vvp-issuer --resource-group VVP --hostname vvp-issuer.rcnx.io
az containerapp hostname add --name vvp-witness1 --resource-group VVP --hostname vvp-witness1.rcnx.io
az containerapp hostname add --name vvp-witness2 --resource-group VVP --hostname vvp-witness2.rcnx.io
az containerapp hostname add --name vvp-witness3 --resource-group VVP --hostname vvp-witness3.rcnx.io

# Bind with managed certificates
az containerapp hostname bind --name vvp-verifier --resource-group VVP \
  --hostname vvp-verifier.rcnx.io --environment vvp-env --validation-method CNAME

az containerapp hostname bind --name vvp-issuer --resource-group VVP \
  --hostname vvp-issuer.rcnx.io --environment vvp-env --validation-method CNAME

az containerapp hostname bind --name vvp-witness1 --resource-group VVP \
  --hostname vvp-witness1.rcnx.io --environment vvp-env --validation-method CNAME

az containerapp hostname bind --name vvp-witness2 --resource-group VVP \
  --hostname vvp-witness2.rcnx.io --environment vvp-env --validation-method CNAME

az containerapp hostname bind --name vvp-witness3 --resource-group VVP \
  --hostname vvp-witness3.rcnx.io --environment vvp-env --validation-method CNAME
```

---

## Part 4: Scaling Configuration

### Setting Minimum Replicas

By default, services scale to 0 when idle to save costs. For always-on availability:

```bash
# Set minimum replicas to 1 (always running)
az containerapp update --name vvp-issuer --resource-group VVP --min-replicas 1 --max-replicas 1
az containerapp update --name vvp-verifier --resource-group VVP --min-replicas 1

# Set to 0 for scale-to-zero (cost savings, cold start delay)
az containerapp update --name vvp-issuer --resource-group VVP --min-replicas 0 --max-replicas 1
az containerapp update --name vvp-verifier --resource-group VVP --min-replicas 0
```

**Note**: Witnesses and issuer must use `maxReplicas=1` due to LMDB single-writer requirement on SMB storage.

### Admin API for Scaling

The issuer service provides an admin API for managing Container App scaling without Azure CLI access.

**Prerequisites:**
- Set `AZURE_SUBSCRIPTION_ID` environment variable on the issuer Container App
- Ensure the issuer's managed identity has `Contributor` role on the VVP resource group

```bash
# Grant scaling permissions to issuer's managed identity
IDENTITY_ID=$(az containerapp show --name vvp-issuer --resource-group VVP \
  --query 'identity.principalId' -o tsv)

az role assignment create \
  --role "Contributor" \
  --assignee "$IDENTITY_ID" \
  --scope "/subscriptions/$(az account show --query id -o tsv)/resourceGroups/VVP"

# Set subscription ID on the container app
az containerapp update --name vvp-issuer --resource-group VVP \
  --set-env-vars "AZURE_SUBSCRIPTION_ID=$(az account show --query id -o tsv)"
```

**API Endpoints:**

```bash
# Get current scaling status for all apps
curl -H "X-API-Key: <admin-key>" https://vvp-issuer.rcnx.io/admin/scaling

# Set minimum replicas to 1 (warm instances)
curl -X POST -H "X-API-Key: <admin-key>" -H "Content-Type: application/json" \
  -d '{"min_replicas": 1}' \
  https://vvp-issuer.rcnx.io/admin/scaling

# Set minimum replicas to 0 (scale to zero when idle)
curl -X POST -H "X-API-Key: <admin-key>" -H "Content-Type: application/json" \
  -d '{"min_replicas": 0}' \
  https://vvp-issuer.rcnx.io/admin/scaling

# Update specific apps only
curl -X POST -H "X-API-Key: <admin-key>" -H "Content-Type: application/json" \
  -d '{"min_replicas": 1, "apps": ["vvp-issuer", "vvp-verifier"]}' \
  https://vvp-issuer.rcnx.io/admin/scaling
```

**Notes:**
- Witnesses enforce `maxReplicas=1` regardless of setting (LMDB safety)
- Requires `issuer:admin` role in API key
- Changes take effect immediately but may take a few seconds to complete

---

## Verification

### Health Checks

```bash
# Verifier
curl https://vvp-verifier.rcnx.io/healthz

# Issuer (requires API key)
curl -H "X-API-Key: <key>" https://vvp-issuer.rcnx.io/healthz

# Witnesses
curl https://vvp-witness1.rcnx.io/oobi/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha/controller
curl https://vvp-witness2.rcnx.io/oobi/BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM/controller
curl https://vvp-witness3.rcnx.io/oobi/BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX/controller
```

### View Logs

```bash
az containerapp logs show --name vvp-issuer --resource-group VVP --follow
az containerapp logs show --name vvp-verifier --resource-group VVP --follow
az containerapp logs show --name vvp-witness1 --resource-group VVP --follow
```

---

## LMDB on SMB - Risk Acceptance

The vvp-env Container Apps environment lacks VNet integration, which is required for Azure Files NFS. SMB is used instead with these mitigations:

1. **Single-writer constraint**: `maxReplicas=1` prevents concurrent LMDB writers
2. **Premium storage**: Low-latency access for LMDB workloads
3. **Backup**: Azure Files backup enabled for all shares

**Migration Plan:**
- Trigger: LMDB errors detected, scale-out required, or Q2 2026 review
- Action: Create VNet-integrated environment with NFS storage

**Monitoring Query (Log Analytics):**
```kql
ContainerAppConsoleLogs_CL
| where ContainerAppName_s in ("vvp-issuer", "vvp-witness1", "vvp-witness2", "vvp-witness3")
| where Log_s contains "MDB_" or Log_s contains "lmdb" or Log_s contains "lock"
| project TimeGenerated, ContainerAppName_s, Log_s
```

**Setup monitoring alerts:**
```bash
# Run the setup script (see scripts/setup-lmdb-alerts.sh)
LOG_ANALYTICS_WORKSPACE=vvp-logs ./scripts/setup-lmdb-alerts.sh
```

---

## CI/CD

The GitHub Actions workflow (`.github/workflows/deploy.yml`) handles:

1. **Testing**: Runs tests for verifier (79% coverage) and issuer (60% coverage)
2. **Building**: Creates Docker images and pushes to ACR
3. **Deploying**: Updates Container Apps with new images

Witnesses use the `gleif/keri:1.2.10` image directly (no custom build).

---

## API Key Management

Retrieve the production API key:

```bash
az keyvault secret show --vault-name vvp-issuer-kv --name issuer-api-keys --query value -o tsv
```

**Do not embed raw keys in documentation or code.**
