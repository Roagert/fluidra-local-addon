#!/usr/bin/env bash
set -euo pipefail

OPTIONS="${FLUIDRA_OPTIONS_PATH:-/data/options.json}"
if [[ ! -f "$OPTIONS" && -f /config/options.json ]]; then
  OPTIONS=/config/options.json
fi
if [[ ! -f "$OPTIONS" ]]; then
  echo "Missing $OPTIONS" >&2
  exit 1
fi

json_get() {
  local key="$1" default="${2:-}"
  jq -r --arg key "$key" --arg default "$default" '.[$key] // $default' "$OPTIONS"
}

HOST="$(json_get host '0.0.0.0')"
PORT="$(json_get port '8765')"
BACKEND="$(json_get backend 'cloud')"
DEVICE_ID="$(json_get device_id 'LG24440781')"
KNOWN_DEVICE_IP="$(json_get known_device_ip '')"
AUTH_TOKEN="$(json_get auth_token '')"
LOG_LEVEL="$(json_get log_level 'info')"

export FLUIDRA_USERNAME="$(json_get fluidra_username '')"
export FLUIDRA_PASSWORD="$(json_get fluidra_password '')"
export FLUIDRA_REFRESH_TOKEN="$(json_get fluidra_refresh_token '')"
export FLUIDRA_LOCAL_DEVICE_IP="$KNOWN_DEVICE_IP"
export FLUIDRA_LOCAL_AUTH_TOKEN="$AUTH_TOKEN"
export PYTHONUNBUFFERED=1

args=(python3 /app/fluidra_local.py serve --host "$HOST" --port "$PORT" --backend "$BACKEND" --device-id "$DEVICE_ID")

echo "Starting Fluidra Local Bridge backend=$BACKEND host=$HOST port=$PORT device_id=$DEVICE_ID auth=$([[ -n "$AUTH_TOKEN" ]] && echo enabled || echo disabled) log_level=$LOG_LEVEL"
exec "${args[@]}"
