#!/usr/bin/env bash
# huginn-lvx VPS installer - Ubuntu 22.04/24.04, Debian 12.
#   sudo bash deploy/install.sh
# Idempotent: safe to re-run. Does NOT overwrite an existing .env or state.
set -euo pipefail

APP_DIR=/opt/huginn
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "==> huginn-lvx installer (source: ${SRC_DIR})"

[ "$(id -u)" -eq 0 ] || { echo "run with sudo"; exit 1; }

echo "==> system deps"
apt-get update -qq
apt-get install -y -qq python3 python3-venv python3-pip >/dev/null

echo "==> app dir ${APP_DIR}"
mkdir -p "${APP_DIR}/state"
id -u huginn >/dev/null 2>&1 || useradd --system --home "${APP_DIR}" --shell /usr/sbin/nologin huginn

echo "==> venv + package (stdlib only - no third-party deps to install)"
python3 -m venv "${APP_DIR}/venv"
"${APP_DIR}/venv/bin/pip" install --quiet --upgrade pip
"${APP_DIR}/venv/bin/pip" install --quiet "${SRC_DIR}"

echo "==> config files (existing files are NEVER overwritten)"
[ -f "${APP_DIR}/.env" ] || { cp "${SRC_DIR}/deploy/env.example" "${APP_DIR}/.env"; chmod 600 "${APP_DIR}/.env"; }
cp "${SRC_DIR}/deploy/pilot.sh" "${APP_DIR}/pilot.sh"
chmod 755 "${APP_DIR}/pilot.sh"
chown -R huginn:huginn "${APP_DIR}"

echo "==> systemd units"
cp "${SRC_DIR}/deploy/huginn-pilot.service" /etc/systemd/system/
cp "${SRC_DIR}/deploy/huginn-pilot.timer"   /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now huginn-pilot.timer

echo
echo "installed. next:"
echo "  1. edit ${APP_DIR}/.env   (HUG_GH_USER first - fetch/draft need ZERO X keys)"
echo "  2. sudo -u huginn ${APP_DIR}/venv/bin/huginn fetch"
echo "  3. sudo -u huginn ${APP_DIR}/venv/bin/huginn draft"
echo "  4. sudo -u huginn ${APP_DIR}/venv/bin/huginn status"
echo "  5. sudo systemctl start huginn-pilot      # dry-run preview"
echo "     journalctl -u huginn-pilot -n 30"
echo "  6. portal -> generate OAuth 1.0a Access Token + Secret -> fill the 4 HUG_X_* lines"
echo "  7. watch a few dry runs, then HUG_AUTOPILOT=1 in .env - the timer takes it from there"
