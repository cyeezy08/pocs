#!/usr/bin/env bash
# Leviathan Intel -- Contabo day-0 bootstrap (fresh Ubuntu 24.04, run as root)
#
# One paste over SSH (repo is PRIVATE -> fetch via the token-authenticated
# Contents API, not raw.githubusercontent which 404s for private repos):
#
#   export GITHUB_TOKEN=ghp_xxx
#   curl -fsSL -H "Authorization: Bearer $GITHUB_TOKEN" \
#     -H "Accept: application/vnd.github.raw" \
#     https://api.github.com/repos/cyeezy08/leviathan-intel/contents/scripts/bootstrap_server.sh \
#     -o bs.sh && bash bs.sh
#
# What it does:
#   1. installs docker + compose plugin, git, ufw, openssl
#   2. firewall: default deny in, allow 22/80/443
#   3. clones the private repo to /opt/leviathan (uses GITHUB_TOKEN)
#   4. writes /opt/leviathan/.env -- ADMIN_TOKEN auto-generated,
#      pay addresses prompted (enter = skip, edit later with nano)
#   5. docker compose up -d --build  (api + postgres + settle-watch)
#   6. health check + prints the keys you must save NOW
#
# Rerunnable: safe to run again, it resumes where it left off.

set -euo pipefail

REPO_URL="https://github.com/cyeezy08/leviathan-intel.git"
DIR="/opt/leviathan"
BRANCH="${BRANCH:-main}"

if [[ $EUID -ne 0 ]]; then echo "run as root (you're on a fresh box, be root)"; exit 1; fi
if [[ -z "${GITHUB_TOKEN:-}" ]]; then
  echo "GITHUB_TOKEN missing. Run: GITHUB_TOKEN=ghp_xxx bash bs.sh"
  echo "(a fine-grained PAT with repo 'leviathan-intel' Contents:Read only)"
  exit 1
fi

echo "== [1/6] packages =="
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq ca-certificates curl git openssl ufw >/dev/null
if ! command -v docker >/dev/null; then
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -qq
  apt-get install -y -qq docker-ce docker-ce-cli containerd.io \
    docker-buildx-plugin docker-compose-plugin >/dev/null
fi
systemctl enable --now docker >/dev/null 2>&1 || true

echo "== [2/6] firewall (22/80/443) =="
ufw default deny incoming >/dev/null
ufw default allow outgoing >/dev/null
ufw allow 22/tcp >/dev/null   # ssh -- keep open or you lock yourself out
ufw allow 80/tcp >/dev/null   # http  (ACME + redirect)
ufw allow 443/tcp >/dev/null  # https
ufw --force enable >/dev/null

echo "== [3/6] clone repo =="
if [[ ! -d "$DIR/.git" ]]; then
  git clone --depth 1 --branch "$BRANCH" \
    "https://x-access-token:${GITHUB_TOKEN}@${REPO_URL#https://}" "$DIR"
else
  git -C "$DIR" fetch --depth 1 origin "$BRANCH"
  git -C "$DIR" reset --hard "origin/$BRANCH"
fi
cd "$DIR"

echo "== [4/6] .env =="
ADMIN_TOKEN="$(openssl rand -hex 24)"
if [[ ! -f .env ]]; then
  {
    echo "ADMIN_TOKEN=$ADMIN_TOKEN"
    echo "SHODAN_API_KEY=${SHODAN_API_KEY:-}"
    echo "NVD_API_KEY="
    echo "WALLET_PAY_TOKEN="
    echo "DATABASE_URL=postgresql://postgres:postgres@db:5432/leviathan"
    echo ""
    echo "# receive addresses (public info; seed phrases NEVER go here)"
  } > .env
fi
# only prompt for keys that are still empty
for key in PAY_ADDRESS_TON PAY_ADDRESS_TRON PAY_ADDRESS_SOL PAY_ADDRESS_BTC SHODAN_API_KEY; do
  if ! grep -q "^${key}=.\+" .env; then
    read -r -p "  ${key} (enter to skip): " val || val=""
    if [[ -n "$val" ]]; then
      grep -q "^${key}=" .env && sed -i "s|^${key}=.*|${key}=${val}|" .env || echo "${key}=${val}" >> .env
    fi
  fi
done
grep -q "^PAY_ADDRESS_TON=" .env || echo "PAY_ADDRESS_TON=" >> .env
grep -q "^PAY_ADDRESS_TRON=" .env || echo "PAY_ADDRESS_TRON=" >> .env
grep -q "^PAY_ADDRESS_SOL=" .env || echo "PAY_ADDRESS_SOL=" >> .env
grep -q "^PAY_ADDRESS_BTC=" .env || echo "PAY_ADDRESS_BTC=" >> .env
chmod 600 .env

echo "== [5/6] docker compose up (api + db + settle-watch) =="
docker compose up -d --build --quiet-pull

echo "== [6/6] health check =="
for i in $(seq 1 30); do
  if curl -fsS http://localhost:8000/health >/dev/null 2>&1; then HEALTH=ok; break; fi
  sleep 2
done
[[ "${HEALTH:-}" == ok ]] || { echo "health check FAILED -- run: docker compose logs api | tail -30"; exit 1; }

IP=$(curl -fsS --max-time 5 https://api.ipify.org || echo "<your-ip>")
echo ""
echo "============================================================================"
echo " LEVIATHAN INTEL IS LIVE"
echo "   api:        http://${IP}:8000  (/health = ok)"
echo "   admin token: $(grep '^ADMIN_TOKEN=' .env | cut -d= -f2)"
echo "============================================"
echo " SAVE the token above (password manager, not chat)."
echo " Add pay addresses later:  nano ${DIR}/.env && docker compose up -d"
echo " Watcher probe on the box: docker compose exec api python -m billing.settle_watch --probe"
echo " Next step: DNS A record -> ${IP} , then TLS (talk to your agent)."
