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
