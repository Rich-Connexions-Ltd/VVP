#!/bin/bash
# Explore Provenant API endpoints for credential resolution
# Usage: ./scripts/explore-provenant-api.sh [SAID]
#
# This script probes various Provenant API endpoints to discover
# how to resolve credentials for ACDC chain validation.

set -e

# Default credential SAID from test JWT
CRED_SAID="${1:-EFraNIE0qvXSojKskl9m7Y1BM3iPj005qMClVl7a--Ki}"

# AIDs from the test JWT
SIGNER_AID="EGay5ufBqAanbhFa_qe-KMFUPJHn8J0MFba96yyWRrLF"
ISSUER_AID="EPI6riUghhZcrzeRrf4qxOSgMvqL97LKxMSaxcDUciub"
AGENT_AID="EHlVXUJ-dYKqtPdvztdCFJEbkyr6zX2dX12hwdE9x8ey"

# Endpoints
ORIGIN="https://origin.demo.provenant.net"
WITNESS_BASE="http://witness5.stage.provenant.net:5631"

echo "=== Exploring Provenant API for Credential Resolution ==="
echo "Target SAID: $CRED_SAID"
echo ""

# Function to probe an endpoint
probe() {
    local name="$1"
    local url="$2"
    echo "[$name]"
    echo "  URL: $url"
    local http_code
    http_code=$(curl -s -o /tmp/probe_response.txt -w "%{http_code}" --connect-timeout 5 "$url" 2>/dev/null || echo "000")
    echo "  HTTP: $http_code"
    if [ "$http_code" = "200" ]; then
        local size
        size=$(wc -c < /tmp/probe_response.txt | tr -d ' ')
        echo "  Size: $size bytes"
        echo "  Preview:"
        head -c 200 /tmp/probe_response.txt
        echo ""
    elif [ "$http_code" != "000" ]; then
        echo "  Response: $(head -c 100 /tmp/probe_response.txt)"
    fi
    echo ""
}

echo "=== 1. Origin Server Endpoints ==="
probe "API Root" "$ORIGIN/"
probe "V1 Root" "$ORIGIN/v1/"
probe "Credentials Root" "$ORIGIN/v1/credentials/"
probe "Credential by SAID" "$ORIGIN/v1/credentials/$CRED_SAID"
probe "Agent Public Credentials" "$ORIGIN/v1/agent/public/$AGENT_AID/credentials"
probe "Agent Public Credentials List" "$ORIGIN/v1/agent/public/$AGENT_AID/credentials/"
probe "Issuer Public Credentials" "$ORIGIN/v1/agent/public/$ISSUER_AID/credentials"
probe "Well-Known KERI" "$ORIGIN/.well-known/keri/"

echo "=== 2. Witness Endpoints ==="
probe "Witness Credentials by SAID" "$WITNESS_BASE/credentials/$CRED_SAID"
probe "Witness Credentials by Issuer" "$WITNESS_BASE/credentials?issuer=$ISSUER_AID"
probe "Witness OOBI Credentials" "$WITNESS_BASE/oobi/$ISSUER_AID/credentials"
probe "Witness Issuer OOBI" "$WITNESS_BASE/oobi/$ISSUER_AID/witness"

echo "=== 3. Alternative Witness Ports ==="
for port in 5632 5633 5634 5635; do
    probe "Witness port $port" "http://witness5.stage.provenant.net:$port/credentials/$CRED_SAID"
done

echo "=== Summary ==="
echo "Endpoints that returned 200 may have credential data."
echo "Check /tmp/probe_response.txt for last response."
