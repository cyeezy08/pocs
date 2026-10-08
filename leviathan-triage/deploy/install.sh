#!/usr/bin/env bash
# leviathan-feed VPS installer - Ubuntu 22.04/24.04, Debian 12.
#   sudo bash deploy/install.sh
# Idempotent: safe to re-run. Does NOT overwrite an existing .env or assets.json.
set -euo pipefail

APP_DIR=/opt/leviathan-feed
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "==> leviathan-feed installer (source: ${SRC_DIR})"

[ "$(id -u)" -eq 0 ] || { echo "run with sudo"; exit 1; }

echo "==> system deps"
apt-get update -qq
apt-get install -y -qq python3 python3-venv python3-pip >/dev/null

echo "==> app dir ${APP_DIR}"
mkdir -p "${APP_DIR}"
id -u leviathan >/dev/null 2>&1 || useradd --system --home "${APP_DIR}" --shell /usr/sbin/nologin leviathan

echo "==> venv + package"
python3 -m venv "${APP_DIR}/venv"
"${APP_DIR}/venv/bin/pip" install --quiet --upgrade pip
"${APP_DIR}/venv/bin/pip" install --quiet "${SRC_DIR}"

echo "==> config files (existing files are NEVER overwritten)"
[ -f "${APP_DIR}/.env" ]          || { cp "${SRC_DIR}/deploy/env.example" "${APP_DIR}/.env"; chmod 600 "${APP_DIR}/.env"; }
[ -f "${APP_DIR}/assets.json" ]   || "${APP_DIR}/venv/bin/leviathan-triage" init-assets "${APP_DIR}/assets.json"
chown -R leviathan:leviathan "${APP_DIR}"

echo "==> systemd units"
cp "${SRC_DIR}/deploy/leviathan-feed-gateway.service" /etc/systemd/system/
cp "${SRC_DIR}/deploy/leviathan-feed-alerts.service"  /etc/systemd/system/
cp "${SRC_DIR}/deploy/leviathan-feed-alerts.timer"    /etc/systemd/system/
cp "${SRC_DIR}/deploy/leviathan-feed-digest.service"  /etc/systemd/system/
cp "${SRC_DIR}/deploy/leviathan-feed-digest.timer"    /etc/systemd/system/
cp "${SRC_DIR}/deploy/leviathan-feed-tweet.service"   /etc/systemd/system/
cp "${SRC_DIR}/deploy/leviathan-feed-tweet.timer"     /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now leviathan-feed-alerts.timer leviathan-feed-digest.timer

echo
echo "installed. next:"
echo "  1. edit ${APP_DIR}/.env   (bot token, webhooks, gumroad, guild/role)"
echo "  2. edit ${APP_DIR}/assets.json   (the stack you triage against)"
echo "  3. ${APP_DIR}/venv/bin/leviathan-triage register-commands"
echo "  4. sudo systemctl restart leviathan-feed-gateway"
echo "  5. follow deploy/GO-LIVE.md for Discord + Gumroad + the first post"
