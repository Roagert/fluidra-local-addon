# Proxmox / Debian helper

Install inside a Debian/Ubuntu LXC or VM:

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/Roagert/fluidra-local-addon/main/proxmox/install.sh)"
```

Then edit `/etc/fluidra-local/fluidra-local.env`, restart the service, and configure the HA integration to point at this host.

## Proxmox VE host helper

From the Proxmox host shell, create a dedicated LXC and install the bridge:

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/Roagert/fluidra-local-addon/main/proxmox/create-lxc.sh)"
```

Optional environment variables:

```bash
CTID=123 HOSTNAME=fluidra-local STORAGE=local-lvm BRIDGE=vmbr0 NET=dhcp bash -c "$(curl -fsSL https://raw.githubusercontent.com/Roagert/fluidra-local-addon/main/proxmox/create-lxc.sh)"
```
