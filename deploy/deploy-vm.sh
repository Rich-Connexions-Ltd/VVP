#!/usr/bin/env bash
set -euo pipefail
TARBALL="${1:?Usage: deploy-vm.sh <tarball-path> [version-label]}"
VERSION="${2:-$(date +%Y%m%d-%H%M%S)}"
DEPLOY_DIR="/opt/vvp/vvp-verifier-oss"
VENV_DIR="/opt/vvp/venv"
SERVICE_NAME="vvp-verifier-oss"
ENV_FILE="/etc/vvp/${SERVICE_NAME}.env"
echo "==> Deploying version: ${VERSION}"
[ ! -d "${VENV_DIR}" ] && python3 -m venv "${VENV_DIR}"
"${VENV_DIR}/bin/pip" install -q --upgrade pip
RELEASE_DIR="${DEPLOY_DIR}/releases/${VERSION}"
mkdir -p "${RELEASE_DIR}"
tar -xzf "${TARBALL}" -C "${RELEASE_DIR}"
[ -f "${RELEASE_DIR}/pyproject.toml" ] && "${VENV_DIR}/bin/pip" install -q "${RELEASE_DIR}"
ln -sfn "${RELEASE_DIR}" "${DEPLOY_DIR}/current.new"
mv -Tf "${DEPLOY_DIR}/current.new" "${DEPLOY_DIR}/current"
cd "${DEPLOY_DIR}/releases" && ls -t | tail -n +4 | xargs -r rm -rf
mkdir -p /etc/vvp
if [ ! -f "${ENV_FILE}" ]; then
cat > "${ENV_FILE}" <<'ENVEOF'
VVP_SIP_HOST=127.0.0.1
VVP_SIP_PORT=5072
VVP_HTTP_HOST=127.0.0.1
VVP_HTTP_PORT=8072
VVP_WITNESS_URLS=https://vvp-witness1.rcnx.io,https://vvp-witness2.rcnx.io,https://vvp-witness3.rcnx.io
VVP_TRUSTED_ROOT_AIDS=EDP1vHcw_wc4M__Fj53-cJaBnZZASd-aMTaSyWEQ-PC2
VVP_LOG_LEVEL=INFO
ENVEOF
fi
[ -f "${RELEASE_DIR}/deploy/vvp-verifier.service" ] && cp "${RELEASE_DIR}/deploy/vvp-verifier.service" "/etc/systemd/system/${SERVICE_NAME}.service"
systemctl daemon-reload
systemctl enable "${SERVICE_NAME}" 2>/dev/null || true
systemctl restart "${SERVICE_NAME}"
sleep 3
systemctl is-active --quiet "${SERVICE_NAME}" && echo "==> Running" || exit 1
