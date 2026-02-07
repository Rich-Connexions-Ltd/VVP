#!/bin/bash
# Deploy VVP SIP Redirect + Monitor to PBX VM.
# Sprint 49: Uses az vm run-command for all remote operations.
#
# Prerequisites:
#   - Azure CLI installed and logged in (az login)
#   - Run from the VVP repository root
#
# Usage:
#   ./services/pbx/scripts/deploy-sip-monitor.sh

set -euo pipefail

RG="VVP"
VM="vvp-pbx"
INSTALL_DIR="/opt/vvp/sip-redirect"
SIP_REDIRECT_DIR="services/sip-redirect"

az_run() {
    local desc="$1"
    shift
    echo "==> ${desc}"
    az vm run-command invoke \
        --resource-group "${RG}" --name "${VM}" \
        --command-id RunShellScript \
        --scripts "$@"
    echo ""
}

echo "========================================"
echo "VVP SIP Monitor Deployment"
echo "========================================"
echo ""

# Step 1: Stop old mock service (if running)
echo "--- Step 1: Stop mock service ---"
az_run "Stopping vvp-mock-sip" \
    "systemctl stop vvp-mock-sip 2>/dev/null || true; systemctl disable vvp-mock-sip 2>/dev/null || true; echo 'Mock service stopped/disabled'"

# Step 2: Create directory structure
echo "--- Step 2: Create directories ---"
az_run "Creating install directories" \
    "mkdir -p ${INSTALL_DIR}/app/monitor ${INSTALL_DIR}/app/monitor_web ${INSTALL_DIR}/app/redirect ${INSTALL_DIR}/app/sip"

# Step 3: Deploy pyproject.toml
echo "--- Step 3: Deploy pyproject.toml ---"
FILE_B64=$(base64 < "${SIP_REDIRECT_DIR}/pyproject.toml")
az_run "Deploying pyproject.toml" \
    "echo '${FILE_B64}' | base64 -d > ${INSTALL_DIR}/pyproject.toml"

# Step 4: Deploy app/ Python files (batch by directory)
echo "--- Step 4: Deploy app code ---"

deploy_file() {
    local local_path="$1"
    local remote_path="$2"
    local b64
    b64=$(base64 < "${local_path}")
    az_run "Deploying $(basename "${local_path}")" \
        "echo '${b64}' | base64 -d > ${remote_path}"
}

# Top-level app files
for f in __init__.py main.py config.py status.py audit.py; do
    if [ -f "${SIP_REDIRECT_DIR}/app/${f}" ]; then
        deploy_file "${SIP_REDIRECT_DIR}/app/${f}" "${INSTALL_DIR}/app/${f}"
    fi
done

# redirect/ module
for f in $(find "${SIP_REDIRECT_DIR}/app/redirect" -name '*.py' -maxdepth 1 2>/dev/null); do
    fname=$(basename "${f}")
    deploy_file "${f}" "${INSTALL_DIR}/app/redirect/${fname}"
done

# sip/ module
for f in $(find "${SIP_REDIRECT_DIR}/app/sip" -name '*.py' -maxdepth 1 2>/dev/null); do
    fname=$(basename "${f}")
    deploy_file "${f}" "${INSTALL_DIR}/app/sip/${fname}"
done

# monitor/ module
for f in $(find "${SIP_REDIRECT_DIR}/app/monitor" -name '*.py' -maxdepth 1 2>/dev/null); do
    fname=$(basename "${f}")
    deploy_file "${f}" "${INSTALL_DIR}/app/monitor/${fname}"
done

# monitor_web/ static files
for f in "${SIP_REDIRECT_DIR}"/app/monitor_web/*; do
    fname=$(basename "${f}")
    deploy_file "${f}" "${INSTALL_DIR}/app/monitor_web/${fname}"
done

# Step 5: Create venv and install dependencies
echo "--- Step 5: Install dependencies ---"
az_run "Creating venv and installing deps" \
    "cd ${INSTALL_DIR} && python3 -m venv venv && ${INSTALL_DIR}/venv/bin/pip install --upgrade pip && ${INSTALL_DIR}/venv/bin/pip install -e '.[monitor]'"

# Step 6: Deploy systemd service
echo "--- Step 6: Deploy systemd service ---"
SERVICE_B64=$(base64 < "services/pbx/config/vvp-sip-redirect.service")
az_run "Installing systemd service" \
    "echo '${SERVICE_B64}' | base64 -d > /etc/systemd/system/vvp-sip-redirect.service && systemctl daemon-reload && systemctl enable vvp-sip-redirect"

# Step 7: Configure nginx reverse proxy
echo "--- Step 7: Configure nginx ---"
NGINX_B64=$(base64 < "services/pbx/config/nginx-sip-monitor.conf")
az_run "Injecting nginx location block" \
    "echo '${NGINX_B64}' | base64 -d > /etc/nginx/snippets/sip-monitor.conf && \
     if ! grep -q 'sip-monitor.conf' /etc/nginx/sites-enabled/fusionpbx 2>/dev/null; then \
         sed -i '/^server {/,/^}/ { /^}/i\\    include /etc/nginx/snippets/sip-monitor.conf;' /etc/nginx/sites-enabled/fusionpbx; \
     fi && \
     nginx -t && echo 'nginx config OK'"

# Step 8: Provision admin user
echo "--- Step 8: Provision admin user ---"
az_run "Creating admin user" \
    "cd ${INSTALL_DIR} && VVP_MONITOR_USERS_FILE=${INSTALL_DIR}/users.json ${INSTALL_DIR}/venv/bin/python -m app.monitor.auth --username admin"

# Step 9: Start services
echo "--- Step 9: Start services ---"
az_run "Starting sip-redirect service" \
    "systemctl restart vvp-sip-redirect && systemctl reload nginx && echo 'Services started'"

# Step 10: Verify
echo "--- Step 10: Verify ---"
az_run "Checking service status" \
    "systemctl status vvp-sip-redirect --no-pager && echo '' && curl -s -o /dev/null -w 'Dashboard HTTP status: %{http_code}\n' http://127.0.0.1:8090/login"

echo ""
echo "========================================"
echo "Deployment complete!"
echo "Dashboard: https://pbx.rcnx.io/sip-monitor/"
echo "========================================"
