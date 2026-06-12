#!/usr/bin/env bash
set -euo pipefail

REPO_URL="${REPO_URL:-https://github.com/Roagert/fluidra-local-addon.git}"
CTID="${CTID:-}"
HOSTNAME="${HOSTNAME:-fluidra-local}"
STORAGE="${STORAGE:-local-lvm}"
TEMPLATE_STORAGE="${TEMPLATE_STORAGE:-local}"
TEMPLATE="${TEMPLATE:-debian-12-standard_12.7-1_amd64.tar.zst}"
MEMORY="${MEMORY:-512}"
CORES="${CORES:-1}"
DISK="${DISK:-4}"
BRIDGE="${BRIDGE:-vmbr0}"
NET="${NET:-dhcp}"
PASSWORD="${PASSWORD:-}"
START="${START:-1}"
UNPRIVILEGED="${UNPRIVILEGED:-1}"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run this on the Proxmox VE host as root." >&2
  exit 1
fi
if ! command -v pct >/dev/null 2>&1; then
  echo "pct not found; this must run on a Proxmox VE host." >&2
  exit 1
fi
if [[ -z "$CTID" ]]; then
  CTID="$(pvesh get /cluster/nextid)"
fi
if [[ -z "$PASSWORD" ]]; then
  PASSWORD="$(openssl rand -base64 18)"
  echo "Generated root password for CT $CTID. Save it now: $PASSWORD"
fi

TEMPLATE_PATH="${TEMPLATE_STORAGE}:vztmpl/${TEMPLATE}"
if ! pveam list "$TEMPLATE_STORAGE" | grep -q "$TEMPLATE"; then
  echo "Downloading template $TEMPLATE to $TEMPLATE_STORAGE..."
  pveam update
  pveam download "$TEMPLATE_STORAGE" "$TEMPLATE"
fi

if pct status "$CTID" >/dev/null 2>&1; then
  echo "CT $CTID already exists; refusing to overwrite." >&2
  exit 1
fi

pct create "$CTID" "$TEMPLATE_PATH" \
  --hostname "$HOSTNAME" \
  --cores "$CORES" \
  --memory "$MEMORY" \
  --rootfs "${STORAGE}:${DISK}" \
  --net0 "name=eth0,bridge=${BRIDGE},ip=${NET}" \
  --unprivileged "$UNPRIVILEGED" \
  --features nesting=1 \
  --password "$PASSWORD" \
  --start "$START" \
  --onboot 1

if [[ "$START" == "1" ]]; then
  echo "Waiting for network..."
  sleep 10
  pct exec "$CTID" -- bash -lc "apt-get update && apt-get install -y curl ca-certificates"
  pct exec "$CTID" -- bash -lc "REPO_URL='$REPO_URL' bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Roagert/fluidra-local-addon/main/proxmox/install.sh)\""
fi

echo
pct status "$CTID"
echo "Created Fluidra Local LXC CTID=$CTID hostname=$HOSTNAME"
echo "Edit credentials inside the CT: pct exec $CTID -- nano /etc/fluidra-local/fluidra-local.env"
echo "Restart bridge: pct exec $CTID -- systemctl restart fluidra-local"
