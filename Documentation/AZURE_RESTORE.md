# VVP Issuer Backup and Restore Procedures

This document describes backup configuration and restore procedures for the VVP Issuer service in Azure.

## Backup Configuration

### Set Up Azure Backup for File Share

```bash
# Create Recovery Services vault
/opt/homebrew/bin/az backup vault create \
  --name vvp-backup-vault \
  --resource-group VVP \
  --location uksouth

# Enable backup for file share (daily, 30-day retention)
/opt/homebrew/bin/az backup protection enable-for-azurefileshare \
  --vault-name vvp-backup-vault \
  --resource-group VVP \
  --storage-account vvpissuerdata \
  --azure-file-share vvp-issuer-data \
  --policy-name DefaultPolicy
```

### Manual Snapshot (Ad-hoc Backup)

```bash
# Create snapshot before major changes
/opt/homebrew/bin/az storage share snapshot create \
  --name vvp-issuer-data \
  --account-name vvpissuerdata
```

## Restore Procedure

### Pre-Restore: Stop the Issuer

**IMPORTANT**: LMDB databases must not be written to during restore. Scale the issuer to zero replicas first.

```bash
# Scale to 0 replicas
/opt/homebrew/bin/az containerapp update \
  --name vvp-issuer \
  --resource-group VVP \
  --min-replicas 0 \
  --max-replicas 0

# Verify no replicas running
/opt/homebrew/bin/az containerapp revision list \
  --name vvp-issuer \
  --resource-group VVP \
  --query "[?properties.runningState=='Running']" -o table
```

Wait until no replicas are running before proceeding.

### Option A: Restore from Azure Backup

1. Navigate to Azure Portal > Recovery Services vault > `vvp-backup-vault`
2. Select "Backup items" > "Azure Storage (Azure Files)"
3. Select `vvp-issuer-data`
4. Click "Restore share" or "Restore files"
5. Choose recovery point and restore to original location

Or via CLI:

```bash
# List recovery points
/opt/homebrew/bin/az backup recoverypoint list \
  --vault-name vvp-backup-vault \
  --resource-group VVP \
  --container-name "StorageContainer;Storage;VVP;vvpissuerdata" \
  --item-name "AzureFileShare;vvp-issuer-data" \
  --query "[].{Name:name, Time:properties.recoveryPointTime}" -o table

# Restore from recovery point (replace <recovery-point-name>)
/opt/homebrew/bin/az backup restore restore-azurefileshare \
  --vault-name vvp-backup-vault \
  --resource-group VVP \
  --container-name "StorageContainer;Storage;VVP;vvpissuerdata" \
  --item-name "AzureFileShare;vvp-issuer-data" \
  --rp-name <recovery-point-name> \
  --resolve-conflict Overwrite \
  --restore-mode OriginalLocation
```

### Option B: Restore from Snapshot

```bash
# List available snapshots
/opt/homebrew/bin/az storage share list-snapshots \
  --name vvp-issuer-data \
  --account-name vvpissuerdata \
  --query "[].snapshot" -o tsv

# Restore specific directory from snapshot
/opt/homebrew/bin/az storage file copy start \
  --source-account-name vvpissuerdata \
  --source-share vvp-issuer-data \
  --source-path "databases" \
  --destination-share vvp-issuer-data \
  --destination-path "databases" \
  --source-snapshot <snapshot-timestamp>
```

### Post-Restore: Verify and Restart

#### 1. Scale Issuer Back Up

```bash
/opt/homebrew/bin/az containerapp update \
  --name vvp-issuer \
  --resource-group VVP \
  --min-replicas 1
```

#### 2. Verify LMDB Integrity

```bash
# Check LMDB can open in read-only mode
/opt/homebrew/bin/az containerapp exec \
  --name vvp-issuer \
  --resource-group VVP \
  --command "python3 -c \"import lmdb; env=lmdb.open('/data/vvp-issuer/databases', readonly=True); print('LMDB OK:', env.stat())\""
```

Expected output shows database statistics. If this fails, the database may be corrupted.

#### 3. Test Health Endpoint

```bash
/opt/homebrew/bin/az containerapp exec \
  --name vvp-issuer \
  --resource-group VVP \
  --command "curl -s http://localhost:8001/healthz"
```

Expected: `{"ok": true}`

#### 4. Verify Credential Access

```bash
# List credentials (confirms KEL/TEL integrity)
/opt/homebrew/bin/az containerapp exec \
  --name vvp-issuer \
  --resource-group VVP \
  --command "curl -s -H 'X-API-Key: <YOUR_API_KEY>' http://localhost:8001/credential | head -c 500"
```

Expected: JSON array of credentials (may be empty if no credentials exist).

#### 5. Check Logs for Errors

```bash
/opt/homebrew/bin/az containerapp logs show \
  --name vvp-issuer \
  --resource-group VVP \
  --tail 50
```

Look for LMDB errors or startup failures.

## Rollback Procedure

If the issuer fails after a deployment, roll back to the previous revision:

```bash
# List revisions
/opt/homebrew/bin/az containerapp revision list \
  --name vvp-issuer \
  --resource-group VVP \
  --query "[].{Name:name, Active:properties.active, Running:properties.runningState}" -o table

# Activate previous revision
/opt/homebrew/bin/az containerapp revision activate \
  --name vvp-issuer \
  --resource-group VVP \
  --revision <previous-revision-name>

# Route all traffic to previous revision
/opt/homebrew/bin/az containerapp ingress traffic set \
  --name vvp-issuer \
  --resource-group VVP \
  --revision-weight <previous-revision-name>=100
```

## SMB Storage Considerations

Since vvp-env does not have VNet integration, we use Azure Files SMB instead of NFS.

**Known Risks**:
- LMDB uses mmap which may have issues with SMB
- Concurrent writes could cause corruption

**Mitigations in Place**:
- `maxReplicas=1` enforced to prevent concurrent access
- Daily backups via Azure Backup
- This restore procedure includes integrity checks

**Monitoring**:
- Watch logs for LMDB errors: `MDB_CORRUPTED`, `MDB_PAGE_NOTFOUND`
- If corruption is detected, restore from the most recent backup

## Emergency Contacts

- Azure Support: https://portal.azure.com/#blade/Microsoft_Azure_Support
- VVP Repository: https://github.com/anthropics/vvp
