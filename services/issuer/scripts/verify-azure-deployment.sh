#!/bin/bash
# Verify Azure deployment of VVP Issuer service
# Usage: ./verify-azure-deployment.sh

set -e

AZ_CMD="${AZ_CMD:-/opt/homebrew/bin/az}"
RESOURCE_GROUP="${RESOURCE_GROUP:-VVP}"
APP_NAME="${APP_NAME:-vvp-issuer}"

echo "=== VVP Issuer Azure Deployment Verification ==="
echo ""

# Check if logged in to Azure
echo "1. Checking Azure CLI authentication..."
if ! $AZ_CMD account show &>/dev/null; then
    echo "   ERROR: Not logged in to Azure. Run: az login"
    exit 1
fi
echo "   OK: Authenticated to Azure"
echo ""

# Check Container App exists
echo "2. Checking Container App exists..."
APP_STATUS=$($AZ_CMD containerapp show --name $APP_NAME --resource-group $RESOURCE_GROUP --query "properties.provisioningState" -o tsv 2>/dev/null || echo "NotFound")
if [ "$APP_STATUS" = "NotFound" ]; then
    echo "   ERROR: Container App '$APP_NAME' not found in resource group '$RESOURCE_GROUP'"
    exit 1
fi
echo "   OK: Container App found (status: $APP_STATUS)"
echo ""

# Check replicas running
echo "3. Checking running replicas..."
REPLICAS=$($AZ_CMD containerapp show --name $APP_NAME --resource-group $RESOURCE_GROUP --query "properties.template.scale.minReplicas" -o tsv)
echo "   Min replicas configured: $REPLICAS"
echo ""

# Check health via exec
echo "4. Checking health endpoint..."
HEALTH_RESULT=$($AZ_CMD containerapp exec --name $APP_NAME --resource-group $RESOURCE_GROUP --command "curl -s http://localhost:8001/healthz" 2>&1 || echo "FAILED")
if [[ "$HEALTH_RESULT" == *'"ok"'* ]] || [[ "$HEALTH_RESULT" == *'true'* ]]; then
    echo "   OK: Health check passed"
    echo "   Response: $HEALTH_RESULT"
else
    echo "   WARNING: Health check may have failed"
    echo "   Response: $HEALTH_RESULT"
fi
echo ""

# Check storage mount
echo "5. Checking storage mount..."
STORAGE_RESULT=$($AZ_CMD containerapp exec --name $APP_NAME --resource-group $RESOURCE_GROUP --command "ls -la /data/vvp-issuer/ 2>&1 || echo 'Mount not found'" 2>&1)
if [[ "$STORAGE_RESULT" == *"No such file"* ]] || [[ "$STORAGE_RESULT" == *"Mount not found"* ]]; then
    echo "   WARNING: Storage mount may not be configured"
else
    echo "   OK: Storage mount accessible"
fi
echo "   Contents:"
echo "$STORAGE_RESULT" | head -10 | sed 's/^/   /'
echo ""

# Check recent logs
echo "6. Recent logs (last 10 lines)..."
$AZ_CMD containerapp logs show --name $APP_NAME --resource-group $RESOURCE_GROUP --tail 10 2>&1 | sed 's/^/   /' || echo "   Could not retrieve logs"
echo ""

# Check ingress configuration
echo "7. Checking ingress configuration..."
INGRESS=$($AZ_CMD containerapp show --name $APP_NAME --resource-group $RESOURCE_GROUP --query "properties.configuration.ingress" -o json)
echo "   $INGRESS" | head -5
echo ""

echo "=== Verification Complete ==="
