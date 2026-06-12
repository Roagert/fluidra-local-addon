#!/usr/bin/env bash
set -euo pipefail
REPO_URL="${REPO_URL:-https://github.com/Roagert/fluidra-local-addon.git}"
INSTALL_DIR="${INSTALL_DIR:-/opt/fluidra-local}"
CONFIG_DIR="${CONFIG_DIR:-/etc/fluidra-local}"
SERVICE_USER="${SERVICE_USER:-fluidra-local}"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root inside the Proxmox LXC/VM." >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends git curl ca-certificates python3 python3-venv

if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
  useradd --system --home-dir "$INSTALL_DIR" --shell /usr/sbin/nologin "$SERVICE_USER"
fi

if [[ -d "$INSTALL_DIR/.git" ]]; then
  git -C "$INSTALL_DIR" fetch --all --tags
  git -C "$INSTALL_DIR" checkout main
  git -C "$INSTALL_DIR" pull --ff-only origin main
else
  rm -rf "$INSTALL_DIR"
  git clone "$REPO_URL" "$INSTALL_DIR"
fi

python3 -m venv "$INSTALL_DIR/.venv"
"$INSTALL_DIR/.venv/bin/pip" install --upgrade pip
if [[ -s "$INSTALL_DIR/requirements.txt" ]]; then
  "$INSTALL_DIR/.venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt"
fi
chmod +x "$INSTALL_DIR/proxmox/start-fluidra-local.sh"

install -d -m 700 "$CONFIG_DIR"
if [[ ! -f "$CONFIG_DIR/fluidra-local.env" ]]; then
  install -m 600 "$INSTALL_DIR/proxmox/fluidra-local.env.example" "$CONFIG_DIR/fluidra-local.env"
  TOKEN="$(python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(32))
PY
)"
  sed -i "s/^FLUIDRA_LOCAL_AUTH_TOKEN=.*/FLUIDRA_LOCAL_AUTH_TOKEN=${TOKEN}/" "$CONFIG_DIR/fluidra-local.env"
  echo "Created $CONFIG_DIR/fluidra-local.env with a generated local auth token."
fi
chmod 600 "$CONFIG_DIR/fluidra-local.env"
chown root:root "$CONFIG_DIR/fluidra-local.env"

install -m 644 "$INSTALL_DIR/proxmox/fluidra-local.service" /etc/systemd/system/fluidra-local.service
chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
systemctl daemon-reload
systemctl enable fluidra-local.service

echo
echo "Edit $CONFIG_DIR/fluidra-local.env and add Fluidra credentials/refresh token, then run:"
echo "  systemctl restart fluidra-local"
echo "  systemctl status fluidra-local --no-pager"
echo "  curl -H 'Authorization: Bearer <token>' http://127.0.0.1:8765/discover"
