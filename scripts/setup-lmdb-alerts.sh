#!/bin/bash
# Setup LMDB monitoring alerts in Azure Log Analytics
# Run this script after deploying to Azure

set -e

RESOURCE_GROUP="${AZURE_RESOURCE_GROUP:-VVP}"
LOG_ANALYTICS_WORKSPACE="${LOG_ANALYTICS_WORKSPACE:-}"

echo "Setting up LMDB monitoring alerts..."

# Check if Log Analytics workspace is configured
if [ -z "$LOG_ANALYTICS_WORKSPACE" ]; then
    echo "Note: LOG_ANALYTICS_WORKSPACE not set."
    echo "To enable LMDB monitoring, create a Log Analytics workspace and set the variable."
    echo ""
    echo "Example commands:"
    echo ""
    cat << 'EOF'
# Create Log Analytics workspace (one-time setup)
az monitor log-analytics workspace create \
  --resource-group VVP \
  --workspace-name vvp-logs \
  --location uksouth

# Get workspace ID
WORKSPACE_ID=$(az monitor log-analytics workspace show \
  --resource-group VVP \
  --workspace-name vvp-logs \
  --query id -o tsv)

# Link Container Apps environment to Log Analytics
az containerapp env update \
  --name vvp-env \
  --resource-group VVP \
  --logs-workspace-id "$WORKSPACE_ID"
EOF
    echo ""
    echo "After setup, run this script with LOG_ANALYTICS_WORKSPACE=vvp-logs"
    exit 0
fi

# LMDB monitoring query
LMDB_QUERY='ContainerAppConsoleLogs_CL
| where ContainerAppName_s in ("vvp-issuer", "vvp-witness1", "vvp-witness2", "vvp-witness3")
| where Log_s contains "MDB_" or Log_s contains "lmdb" or Log_s contains "lock contention" or Log_s contains "database error"
| project TimeGenerated, ContainerAppName_s, Log_s
| order by TimeGenerated desc'

echo "LMDB Monitoring Query:"
echo "----------------------"
echo "$LMDB_QUERY"
echo ""

# Get workspace resource ID
WORKSPACE_ID=$(az monitor log-analytics workspace show \
  --resource-group "$RESOURCE_GROUP" \
  --workspace-name "$LOG_ANALYTICS_WORKSPACE" \
  --query id -o tsv 2>/dev/null || echo "")

if [ -z "$WORKSPACE_ID" ]; then
    echo "Error: Could not find Log Analytics workspace '$LOG_ANALYTICS_WORKSPACE'"
    exit 1
fi

echo "Creating scheduled query rule for LMDB errors..."

# Create alert rule for LMDB errors
az monitor scheduled-query create \
  --name "vvp-lmdb-errors" \
  --resource-group "$RESOURCE_GROUP" \
  --scopes "$WORKSPACE_ID" \
  --condition "count > 0" \
  --condition-query "$LMDB_QUERY" \
  --evaluation-frequency "5m" \
  --window-size "5m" \
  --severity 2 \
  --description "Alert when LMDB errors are detected in VVP services" \
  --action-groups "" \
  --auto-mitigate true \
  2>/dev/null || echo "Alert rule may already exist or require action group"

echo ""
echo "Done. To view logs manually, run:"
echo ""
echo "az monitor log-analytics query \\"
echo "  --workspace \"$WORKSPACE_ID\" \\"
echo "  --analytics-query '$LMDB_QUERY' \\"
echo "  --timespan P1D"
