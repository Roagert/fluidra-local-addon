#!/usr/bin/env bash
set -euo pipefail
python3 -m compileall -q fluidra_local.py emulator_flows.py
python3 -m pytest -q tests/test_fluidra_local.py
bash -n fluidra-local/run.sh proxmox/install.sh proxmox/update.sh proxmox/uninstall.sh proxmox/start-fluidra-local.sh proxmox/create-lxc.sh
python3 - <<'PY'
import json, pathlib
json.loads(pathlib.Path('repository.json').read_text())
try:
 import yaml
except Exception:
 print('pyyaml unavailable; skipped yaml parse')
else:
 yaml.safe_load(pathlib.Path('fluidra-local/config.yaml').read_text())
 print('metadata parse ok')
PY
