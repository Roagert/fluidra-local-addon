#!/usr/bin/env bash
set -euo pipefail
INSTALL_DIR="${INSTALL_DIR:-/opt/fluidra-local}"
CONFIG_DIR="${CONFIG_DIR:-/etc/fluidra-local}"
if [[ "${EUID}" -ne 0 ]]; then echo "Run as root" >&2; exit 1; fi
systemctl disable --now fluidra-local.service 2>/dev/null || true
rm -f /etc/systemd/system/fluidra-local.service
systemctl daemon-reload
rm -rf "$INSTALL_DIR"
echo "Left $CONFIG_DIR in place so secrets are not destroyed. Remove it manually if desired."
