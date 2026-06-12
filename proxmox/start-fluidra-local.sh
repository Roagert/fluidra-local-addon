#!/usr/bin/env bash
set -euo pipefail
: "${FLUIDRA_LOCAL_HOST:=0.0.0.0}"
: "${FLUIDRA_LOCAL_PORT:=8765}"
: "${FLUIDRA_LOCAL_BACKEND:=cloud}"
: "${FLUIDRA_LOCAL_DEVICE_ID:=LG24440781}"
export FLUIDRA_LOCAL_DEVICE_IP="${FLUIDRA_LOCAL_DEVICE_IP:-}"
args=(/opt/fluidra-local/.venv/bin/python /opt/fluidra-local/fluidra_local.py serve --host "$FLUIDRA_LOCAL_HOST" --port "$FLUIDRA_LOCAL_PORT" --backend "$FLUIDRA_LOCAL_BACKEND" --device-id "$FLUIDRA_LOCAL_DEVICE_ID")
if [[ -n "${FLUIDRA_LOCAL_AUTH_TOKEN:-}" ]]; then
  args+=(--auth-token "$FLUIDRA_LOCAL_AUTH_TOKEN")
fi
exec "${args[@]}"
