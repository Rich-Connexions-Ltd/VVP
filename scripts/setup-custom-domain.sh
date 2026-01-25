#!/bin/bash
#
# Setup custom domain for Azure Container Apps
# Usage: ./scripts/setup-custom-domain.sh
#

set -euo pipefail

# Configuration - update these values
RESOURCE_GROUP="${AZURE_RG:-}"
CONTAINER_APP_NAME="${AZURE_CONTAINERAPP_NAME:-}"
CUSTOM_DOMAIN="vvp.rcnx.io"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# Check required variables
if [[ -z "$RESOURCE_GROUP" ]]; then
    read -p "Enter Azure Resource Group name: " RESOURCE_GROUP
fi

if [[ -z "$CONTAINER_APP_NAME" ]]; then
    read -p "Enter Container App name: " CONTAINER_APP_NAME
fi

# Verify Azure CLI is logged in
info "Checking Azure CLI login status..."
if ! az account show &>/dev/null; then
    error "Not logged in to Azure CLI. Run 'az login' first."
fi

SUBSCRIPTION=$(az account show --query "name" -o tsv)
info "Using subscription: $SUBSCRIPTION"

# Get the Container App Environment
info "Getting Container App Environment..."
ENVIRONMENT=$(az containerapp show \
    --name "$CONTAINER_APP_NAME" \
    --resource-group "$RESOURCE_GROUP" \
    --query "properties.environmentId" -o tsv)

ENVIRONMENT_NAME=$(basename "$ENVIRONMENT")
info "Environment: $ENVIRONMENT_NAME"

# Get the custom domain verification ID
info "Getting custom domain verification ID..."
VERIFICATION_ID=$(az containerapp show \
    --name "$CONTAINER_APP_NAME" \
    --resource-group "$RESOURCE_GROUP" \
    --query "properties.customDomainVerificationId" -o tsv)

# Get the default FQDN
DEFAULT_FQDN=$(az containerapp show \
    --name "$CONTAINER_APP_NAME" \
    --resource-group "$RESOURCE_GROUP" \
    --query "properties.configuration.ingress.fqdn" -o tsv)

echo ""
echo "=============================================="
echo "  DNS CONFIGURATION REQUIRED"
echo "=============================================="
echo ""
echo "Add these DNS records at your DNS provider for rcnx.io:"
echo ""
echo "  1. CNAME Record:"
echo "     Name:  vvp"
echo "     Value: $DEFAULT_FQDN"
echo ""
echo "  2. TXT Record (for domain verification):"
echo "     Name:  asuid.vvp"
echo "     Value: $VERIFICATION_ID"
echo ""
echo "=============================================="
echo ""

read -p "Have you configured the DNS records? (y/N): " DNS_CONFIGURED

if [[ "${DNS_CONFIGURED,,}" != "y" ]]; then
    warn "Please configure DNS records first, then run this script again."
    exit 0
fi

# Check DNS propagation
info "Checking DNS propagation..."
if ! host "$CUSTOM_DOMAIN" &>/dev/null; then
    warn "DNS for $CUSTOM_DOMAIN not yet resolvable. It may take a few minutes to propagate."
    read -p "Continue anyway? (y/N): " CONTINUE
    if [[ "${CONTINUE,,}" != "y" ]]; then
        exit 0
    fi
fi

# Add the custom domain
info "Adding custom domain to Container App..."
az containerapp hostname add \
    --hostname "$CUSTOM_DOMAIN" \
    --name "$CONTAINER_APP_NAME" \
    --resource-group "$RESOURCE_GROUP"

# Bind managed certificate
info "Binding managed SSL certificate (this may take a few minutes)..."
az containerapp hostname bind \
    --hostname "$CUSTOM_DOMAIN" \
    --name "$CONTAINER_APP_NAME" \
    --resource-group "$RESOURCE_GROUP" \
    --environment "$ENVIRONMENT_NAME" \
    --validation-method CNAME

echo ""
info "Custom domain setup complete!"
echo ""
echo "Your service is now available at:"
echo "  https://$CUSTOM_DOMAIN"
echo ""
echo "Verify with:"
echo "  curl https://$CUSTOM_DOMAIN/healthz"
echo ""
