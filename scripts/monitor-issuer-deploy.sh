#!/bin/bash
# Monitor VVP Issuer deployment to Azure
# Usage: ./scripts/monitor-issuer-deploy.sh
#
# Polls the issuer health endpoint until it responds successfully
# or until max attempts is reached.

set -e

AZ_CMD="${AZ_CMD:-/opt/homebrew/bin/az}"
RESOURCE_GROUP="${RESOURCE_GROUP:-VVP}"
APP_NAME="${APP_NAME:-vvp-issuer}"
MAX_ATTEMPTS="${MAX_ATTEMPTS:-10}"
SLEEP_SECONDS="${SLEEP_SECONDS:-30}"

echo "Monitoring VVP Issuer deployment..."
echo "Container App: $APP_NAME"
echo "Resource Group: $RESOURCE_GROUP"
echo "Max attempts: $MAX_ATTEMPTS (${SLEEP_SECONDS}s interval)"
echo ""

for i in $(seq 1 $MAX_ATTEMPTS); do
    echo "Attempt $i/$MAX_ATTEMPTS: Checking issuer health..."

    # Try to get health via exec
    RESULT=$($AZ_CMD containerapp exec \
        --name $APP_NAME \
        --resource-group $RESOURCE_GROUP \
        --command "curl -s http://localhost:8001/healthz" 2>&1 || echo "EXEC_FAILED")

    if [[ "$RESULT" == *'"ok"'* ]] || [[ "$RESULT" == *'true'* ]]; then
        echo ""
        echo "SUCCESS: Issuer is healthy!"
        echo "Response: $RESULT"
        exit 0
    fi

    echo "  Not ready yet: $RESULT"

    if [ $i -lt $MAX_ATTEMPTS ]; then
        echo "  Waiting ${SLEEP_SECONDS}s before next attempt..."
        sleep $SLEEP_SECONDS
    fi
done

echo ""
echo "FAILED: Issuer did not become healthy after $MAX_ATTEMPTS attempts"
echo "Check logs with: az containerapp logs show --name $APP_NAME --resource-group $RESOURCE_GROUP --follow"
exit 1
