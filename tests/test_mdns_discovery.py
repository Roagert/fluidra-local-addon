from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SERVER = ROOT / "fluidra-local" / "fluidra_local.py"


def test_server_declares_fluidra_mdns_service_type():
    text = SERVER.read_text()
    assert 'MDNS_SERVICE_TYPE = "_fluidra-local._tcp.local."' in text
    assert "ServiceInfo" in text
    assert "Zeroconf" in text


def test_server_advertises_home_assistant_discovery_properties():
    text = SERVER.read_text()
    assert '"base_url"' in text
    assert '"device_id"' in text
    assert '"auth_required"' in text
    assert '"api_version"' in text


def test_packaged_server_installs_zeroconf_dependency():
    requirements = (ROOT / "fluidra-local" / "requirements.txt").read_text()
    assert "zeroconf" in requirements


def test_home_assistant_addon_uses_host_network_for_mdns():
    config = (ROOT / "fluidra-local" / "config.yaml").read_text()
    assert "host_network: true" in config


def test_server_can_disable_mdns_advertisement_once_already_connected():
    text = SERVER.read_text()
    assert "--no-mdns" in text
    assert "FLUIDRA_LOCAL_MDNS" in text
    assert "fluidra local mDNS disabled by configuration" in text


def test_addon_json_get_preserves_false_boolean_for_mdns_option():
    run_sh = (ROOT / "fluidra-local" / "run.sh").read_text()
    assert "if has($key) and .[$key] != null then .[$key] else $default end" in run_sh
    assert "ADVERTISE_MDNS=\"$(json_get advertise_mdns 'false')\"" in run_sh


def test_proxmox_path_documents_persistent_mdns_disable():
    start_sh = (ROOT / "proxmox" / "start-fluidra-local.sh").read_text()
    env_example = (ROOT / "proxmox" / "fluidra-local.env.example").read_text()
    assert "FLUIDRA_LOCAL_MDNS:=0" in start_sh
    assert "--no-mdns" in start_sh
    assert "FLUIDRA_LOCAL_MDNS=0" in env_example
