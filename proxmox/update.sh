#!/usr/bin/env bash
set -euo pipefail
INSTALL_DIR="${INSTALL_DIR:-/opt/fluidra-local}"
if [[ "${EUID}" -ne 0 ]]; then echo "Run as root" >&2; exit 1; fi
git -C "$INSTALL_DIR" fetch --all --tags
git -C "$INSTALL_DIR" checkout main
git -C "$INSTALL_DIR" pull --ff-only origin main
"$INSTALL_DIR/.venv/bin/pip" install --upgrade pip
if [[ -s "$INSTALL_DIR/requirements.txt" ]]; then "$INSTALL_DIR/.venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt"; fi
install -m 644 "$INSTALL_DIR/proxmox/fluidra-local.service" /etc/systemd/system/fluidra-local.service
chmod +x "$INSTALL_DIR/proxmox/start-fluidra-local.sh"
systemctl daemon-reload
systemctl restart fluidra-local
systemctl status fluidra-local --no-pager
