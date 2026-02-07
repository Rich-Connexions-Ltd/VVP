#!/bin/bash
# Provision initial admin user for VVP SIP Monitor dashboard.
# Run on the PBX VM. Generates a random password and displays it once.
# The user will be required to change the password on first login.
#
# Usage:
#   ./provision-monitor-user.sh [username]
#
# Default username: admin

set -euo pipefail

USERNAME="${1:-admin}"
INSTALL_DIR="/opt/vvp/sip-redirect"

echo "Creating SIP Monitor admin user: ${USERNAME}"
cd "${INSTALL_DIR}"
"${INSTALL_DIR}/venv/bin/python" -m app.monitor.auth --username "${USERNAME}"
