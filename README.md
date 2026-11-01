> [!WARNING]
> **Deprecated — superseded by [Roagert/ha-fluidra-pool](https://github.com/Roagert/ha-fluidra-pool) 2.0.0.**
> 2.0.0 is still in progress ([ha-fluidra-pool#11](https://github.com/Roagert/ha-fluidra-pool/pull/11));
> this notice applies once it is released. This bridge was only a second hop to the same
> Fluidra cloud; Fluidra Pool talks to that cloud directly from Home Assistant (REST +
> WebSocket push), so neither this bridge nor `ha-fluidra-local` is needed.
>
> To migrate:
>
> 1. Stop the bridge. Add-on: Settings → Add-ons → **Fluidra Local Bridge** → **Uninstall**,
>    then remove this add-on repository. Proxmox/Debian: run
>    `sudo bash /opt/fluidra-local/proxmox/uninstall.sh`, then delete `/etc/fluidra-local`
>    (the script keeps it; it holds your Fluidra credentials/token).
> 2. Remove the **Fluidra Local Server** integration: delete its entry under Settings →
>    Devices & services, remove it and its custom repository in HACS, restart Home Assistant.
> 3. HACS → ⋮ → **Custom repositories** → add `https://github.com/Roagert/ha-fluidra-pool`,
>    type **Integration**; download **Fluidra Pool** and restart Home Assistant.
> 4. Settings → Devices & services → **Add integration** → **Fluidra Pool**, then sign in with
>    your Fluidra account e-mail and password (two-step verification / MFA codes are supported).
> 5. Entity ids will differ, because Fluidra Pool is a different integration domain
>    (`fluidra_pool`, not `fluidra_local`): update your automations and dashboards.

# Fluidra Local Add-on

Home Assistant add-on and Proxmox helper packaging for the Fluidra Local Bridge.

This repo packages the proven `fluidra_local.py` bridge as:

1. A Home Assistant OS/Supervised add-on.
2. A Proxmox/Debian/Ubuntu helper install for an LXC or VM using systemd.

The bridge gives Home Assistant a local HTTP API for Fluidra heat-pump control. The current backend is still Fluidra cloud REST; Home Assistant talks locally to this bridge, but stock-firmware direct LAN control is **not** claimed.

## Architecture

```text
Home Assistant entities
  ↓ HACS integration Roagert/ha-fluidra-local v0.3.0+
Fluidra Local Bridge add-on / Proxmox service
  ↓ cloud REST backend today
Fluidra cloud / physical heat pump
```

## Features

- Local HTTP bridge exposing `/state`, `/capabilities`, `/discover`, `/component/<id>`.
- Full control endpoints for safe known controls: `/power`, `/temperature`, `/mode`.
- Optional bearer-token auth with `Authorization: Bearer <token>`.
- Discovery endpoint identifies configured/local candidates without claiming direct LAN control.
- Home Assistant add-on packaging.
- Proxmox helper scripts for LXC/VM systemd deployment.

## Home Assistant add-on install

Add this repository in Home Assistant:

```text
https://github.com/Roagert/fluidra-local-addon
```

Then install **Fluidra Local Bridge**.

Configure options:

```yaml
backend: cloud
host: 0.0.0.0
port: 8765
device_id: LG24440781
known_device_ip: 192.168.1.29
auth_token: your-local-bridge-token
fluidra_refresh_token: your-fluidra-refresh-token
```

Then configure the HACS integration `Roagert/ha-fluidra-local` v0.3.0+ with:

```text
Bridge URL: http://<home-assistant-ip>:8765
auth_token: same token as add-on
```

## Proxmox helper install

On a Debian/Ubuntu LXC/VM:

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/Roagert/fluidra-local-addon/main/proxmox/install.sh)"
```

Edit `/etc/fluidra-local/fluidra-local.env`, then:

```bash
systemctl restart fluidra-local
systemctl status fluidra-local --no-pager
curl -H "Authorization: Bearer $FLUIDRA_LOCAL_AUTH_TOKEN" http://127.0.0.1:8765/discover
```

## API quick check

```bash
curl http://HOST:8765/
curl -H "Authorization: Bearer TOKEN" http://HOST:8765/discover
curl -H "Authorization: Bearer TOKEN" http://HOST:8765/capabilities
```

## Security

Do not expose the bridge to the public internet. Use a strong `auth_token` for LAN deployments. Secrets belong in Home Assistant add-on options or `/etc/fluidra-local/fluidra-local.env`, not in git.
