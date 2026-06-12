from __future__ import annotations

import json
import socket
import urllib.error
import urllib.request
from pathlib import Path

import emulator_flows
import fluidra_local


def _synthetic_pcap_with_ws_toggle() -> bytes:
    guest = "10.0.2.15"
    t = 1000.0
    packets = [
        (t - 0.5, emulator_flows._tcp(guest, "54.170.189.168", 40000, 443, 0x18, b"cmd")),
        (t - 0.4, emulator_flows._tcp("54.170.189.168", guest, 443, 40000, 0x18, b"ack")),
        (t + 0.2, emulator_flows._tcp(guest, "45.60.80.124", 40001, 443, 0x18, b"rest")),
    ]
    return emulator_flows._w(packets)


def test_capture_evidence_reports_no_lan_or_mqtt_and_classifies_cloud_burst(tmp_path: Path):
    pcap = tmp_path / "toggle.cap"
    pcap.write_bytes(_synthetic_pcap_with_ws_toggle())

    evidence = fluidra_local.capture_evidence(pcap, around=1000.0, window=1.0)

    assert evidence["device_ip"] == "192.168.1.29"
    assert evidence["lan_device_packets"] == 0
    assert evidence["mqtt_tls_packets"] == 0
    assert evidence["cloud_tls_packets"] == 3
    assert evidence["conclusion"] == "cloud_websocket_or_https_only"
    assert evidence["endpoints"]["54.170.189.168:443"]["packets"] == 2
    assert evidence["endpoints"]["45.60.80.124:443"]["packets"] == 1


def test_capture_evidence_flags_lan_device_control(tmp_path: Path):
    guest = "10.0.2.15"
    pcap = tmp_path / "local.cap"
    pcap.write_bytes(emulator_flows._w([
        (1000.0, emulator_flows._udp(guest, "192.168.1.29", 51000, 9003, b"hello")),
    ]))

    evidence = fluidra_local.capture_evidence(pcap, around=1000.0, window=1.0)

    assert evidence["lan_device_packets"] == 1
    assert evidence["conclusion"] == "local_device_traffic_detected"


def test_dry_run_controller_validates_and_records_component_writes():
    controller = fluidra_local.DryRunController(device_id="LG24440781")

    result = controller.set_component(13, 1)

    assert result == {
        "backend": "dry-run",
        "device_id": "LG24440781",
        "component_id": 13,
        "desired_value": 1,
        "would_send": {"desiredValue": 1},
    }
    assert controller.history[-1]["component_id"] == 13


def test_dry_run_controller_rejects_unknown_component():
    controller = fluidra_local.DryRunController(device_id="LG24440781")

    try:
        controller.set_component(999, 1)
    except ValueError as exc:
        assert "unsupported component" in str(exc)
    else:
        raise AssertionError("expected ValueError")


def test_local_http_server_exposes_state_and_control(tmp_path: Path, socket_enabled):
    controller = fluidra_local.DryRunController(device_id="LG24440781")
    server = fluidra_local.start_local_server(controller, host="127.0.0.1", port=0)
    port = server.server_address[1]
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/state", timeout=2) as resp:
            state = json.loads(resp.read().decode())
        assert state["device_id"] == "LG24440781"
        assert state["backend"] == "dry-run"

        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/component/13",
            data=json.dumps({"desiredValue": 0}).encode(),
            headers={"Content-Type": "application/json"},
            method="PUT",
        )
        with urllib.request.urlopen(req, timeout=2) as resp:
            result = json.loads(resp.read().decode())
        assert result["component_id"] == 13
        assert result["desired_value"] == 0
    finally:
        server.shutdown()
        server.server_close()


class FakeHTTP:
    def __init__(self):
        self.requests = []
        self.responses = []

    def queue_json(self, payload, status=200):
        self.responses.append((status, payload))

    def request_json(self, method, url, *, headers=None, payload=None, timeout=15):
        self.requests.append({
            "method": method,
            "url": url,
            "headers": headers or {},
            "payload": payload,
            "timeout": timeout,
        })
        status, body = self.responses.pop(0)
        if status >= 400:
            raise fluidra_local.HTTPStatusError(status, body)
        return body


def test_cloud_rest_controller_refreshes_token_and_gets_state():
    http = FakeHTTP()
    http.queue_json({"AuthenticationResult": {"AccessToken": "ACCESS", "ExpiresIn": 300}})
    http.queue_json({"id": "LG24440781", "name": "Heat Pump"})
    controller = fluidra_local.CloudRestController(
        device_id="LG24440781",
        client_id="CLIENT",
        refresh_token="REFRESH",
        http=http,
    )

    state = controller.state()

    assert state["backend"] == "cloud-rest"
    assert state["device_id"] == "LG24440781"
    assert state["device"]["id"] == "LG24440781"
    auth_req = http.requests[0]
    assert auth_req["method"] == "POST"
    assert auth_req["url"] == "https://cognito-idp.eu-west-1.amazonaws.com/"
    assert auth_req["payload"]["AuthFlow"] == "REFRESH_TOKEN_AUTH"
    api_req = http.requests[1]
    assert api_req["method"] == "GET"
    assert api_req["url"] == "https://api.fluidra-emea.com/generic/devices/LG24440781?deviceType=connected"
    assert api_req["headers"]["Authorization"] == "Bearer ACCESS"


def test_cloud_rest_controller_writes_component_and_polls_component():
    http = FakeHTTP()
    http.queue_json({"AuthenticationResult": {"AccessToken": "ACCESS", "ExpiresIn": 300}})
    http.queue_json({"id": 13, "desiredValue": 1})
    http.queue_json({"id": 13, "desiredValue": 1, "reportedValue": 1})
    controller = fluidra_local.CloudRestController(
        device_id="LG24440781",
        client_id="CLIENT",
        refresh_token="REFRESH",
        http=http,
    )

    result = controller.set_component(13, 1)

    assert result["backend"] == "cloud-rest"
    assert result["component_id"] == 13
    assert result["desired_value"] == 1
    assert result["write_response"] == {"id": 13, "desiredValue": 1}
    assert result["readback"] == {"id": 13, "desiredValue": 1, "reportedValue": 1}
    put_req = http.requests[1]
    assert put_req["method"] == "PUT"
    assert put_req["url"] == "https://api.fluidra-emea.com/generic/devices/LG24440781/components/13?deviceType=connected"
    assert put_req["payload"] == {"desiredValue": 1}


def test_cloud_rest_controller_redacted_state_does_not_expose_tokens():
    http = FakeHTTP()
    http.queue_json({"AuthenticationResult": {"AccessToken": "SECRET_ACCESS", "ExpiresIn": 300}})
    http.queue_json({"id": "LG24440781"})
    controller = fluidra_local.CloudRestController(
        device_id="LG24440781",
        client_id="CLIENT",
        refresh_token="SECRET_REFRESH",
        http=http,
    )

    state_text = json.dumps(controller.state())

    assert "SECRET_ACCESS" not in state_text
    assert "SECRET_REFRESH" not in state_text


def test_local_http_server_exposes_components_and_component_get(socket_enabled):
    class ReadController(fluidra_local.DryRunController):
        def get_components(self):
            return [{"id": 13, "desiredValue": 0}]
        def get_component(self, component_id):
            return {"id": component_id, "desiredValue": 0}
    server = fluidra_local.start_local_server(ReadController(device_id="LG24440781"), host="127.0.0.1", port=0)
    port = server.server_address[1]
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/components", timeout=2) as resp:
            components = json.loads(resp.read().decode())
        assert components == [{"id": 13, "desiredValue": 0}]
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/component/13", timeout=2) as resp:
            component = json.loads(resp.read().decode())
        assert component == {"id": 13, "desiredValue": 0}
    finally:
        server.shutdown(); server.server_close()


def test_local_http_server_power_temperature_and_mode_helpers(socket_enabled):
    controller = fluidra_local.DryRunController(device_id="LG24440781")
    server = fluidra_local.start_local_server(controller, host="127.0.0.1", port=0)
    port = server.server_address[1]
    def put(path, payload):
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}{path}",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="PUT",
        )
        with urllib.request.urlopen(req, timeout=2) as resp:
            return json.loads(resp.read().decode())
    try:
        assert put("/power", {"on": True})["component_id"] == 13
        assert controller.history[-1]["desired_value"] == 1
        assert put("/temperature", {"celsius": 26.5})["component_id"] == 15
        assert controller.history[-1]["desired_value"] == 265
        assert put("/mode", {"desiredValue": 2})["component_id"] == 14
        assert controller.history[-1]["desired_value"] == 2
    finally:
        server.shutdown(); server.server_close()



def test_capabilities_endpoint_exposes_mode_map(socket_enabled):
    controller = fluidra_local.DryRunController(device_id="LG24440781")
    server = fluidra_local.start_local_server(controller, host="127.0.0.1", port=0)
    try:
        import json
        import urllib.request
        base = f"http://127.0.0.1:{server.server_address[1]}"
        with urllib.request.urlopen(base + "/capabilities", timeout=5) as resp:
            data = json.loads(resp.read().decode())
        assert data["device_id"] == "LG24440781"
        assert data["components"]["13"]["name"] == "power"
        assert data["components"]["15"]["scale"] == 10
        assert data["components"]["19"]["name"] == "pool_temperature"
        assert data["components"]["67"]["name"] == "air_temperature"
        assert data["components"]["28"]["name"] == "flow_status"
        assert data["modes"]["Boost Heating"] == 3
        assert data["modes_by_value"]["3"] == "Boost Heating"
    finally:
        server.shutdown(); server.server_close()


def test_mode_endpoint_accepts_named_mode(socket_enabled):
    controller = fluidra_local.DryRunController(device_id="LG24440781")
    server = fluidra_local.start_local_server(controller, host="127.0.0.1", port=0)
    try:
        import json
        import urllib.request
        base = f"http://127.0.0.1:{server.server_address[1]}"
        req = urllib.request.Request(
            base + "/mode",
            data=json.dumps({"mode": "Boost Heating"}).encode(),
            headers={"Content-Type": "application/json"},
            method="PUT",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
        assert data["component_id"] == 14
        assert data["desired_value"] == 3
        assert data["mode"] == "Boost Heating"
    finally:
        server.shutdown(); server.server_close()


def test_local_server_root_endpoint(socket_enabled):
    import json
    import urllib.request
    controller = fluidra_local.DryRunController(device_id="dev1")
    server = fluidra_local.start_local_server(controller, "127.0.0.1", 0)
    try:
        port = server.server_address[1]
        with urllib.request.urlopen("http://127.0.0.1:%d/" % port, timeout=5) as response:
            data = json.loads(response.read().decode())
        assert data["name"] == "Fluidra Local Bridge"
        assert "GET /capabilities" in data["endpoints"]
    finally:
        server.shutdown()
        server.server_close()



def test_parse_ip_neigh_discovers_candidate_device():
    text = "192.168.1.29 dev wlan0 lladdr aa:bb:cc:dd:ee:ff REACHABLE\n192.168.1.1 dev wlan0 lladdr 11:22:33:44:55:66 STALE\n"
    devices = fluidra_local.parse_ip_neigh(text, known_device_ip="192.168.1.29", known_device_id="LG24440781")
    assert devices[0]["ip"] == "192.168.1.29"
    assert devices[0]["device_id"] == "LG24440781"
    assert devices[0]["confidence"] == "known_ip_match"
    assert devices[0]["mac"] == "aa:bb:cc:dd:ee:ff"


def test_dry_run_discovery_and_endpoint(socket_enabled):
    controller = fluidra_local.DryRunController(device_id="LG24440781")
    server = fluidra_local.start_local_server(controller, host="127.0.0.1", port=0)
    try:
        base = f"http://127.0.0.1:{server.server_address[1]}"
        with urllib.request.urlopen(base + "/discover", timeout=5) as resp:
            data = json.loads(resp.read().decode())
        assert data["device_id"] == "LG24440781"
        assert data["local_control_proven"] is False
        assert data["devices"][0]["ip"] == "192.168.1.29"
        assert data["devices"][0]["source"] == "configured"
    finally:
        server.shutdown(); server.server_close()


def test_server_rejects_unsafe_control_values_and_parses_false_string(socket_enabled):
    controller = fluidra_local.DryRunController(device_id="LG24440781")
    server = fluidra_local.start_local_server(controller, host="127.0.0.1", port=0)
    base = f"http://127.0.0.1:{server.server_address[1]}"
    def put(path, payload):
        req = urllib.request.Request(base + path, data=json.dumps(payload).encode(), headers={"Content-Type":"application/json"}, method="PUT")
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read().decode())
    def put_error(path, payload):
        req = urllib.request.Request(base + path, data=json.dumps(payload).encode(), headers={"Content-Type":"application/json"}, method="PUT")
        try:
            urllib.request.urlopen(req, timeout=5)
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode())
        raise AssertionError("expected HTTPError")
    try:
        assert put("/power", {"on": "false"})["desired_value"] == 0
        assert put_error("/power", {"desiredValue": 9})[0] == 400
        assert put_error("/temperature", {"celsius": 99})[0] == 400
        assert put_error("/mode", {"desiredValue": 99})[0] == 400
    finally:
        server.shutdown(); server.server_close()


def test_server_limits_body_and_requires_optional_auth_for_writes(socket_enabled):
    controller = fluidra_local.DryRunController(device_id="LG24440781")
    server = fluidra_local.start_local_server(controller, host="127.0.0.1", port=0, auth_token="TOKEN")
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        with urllib.request.urlopen(base + "/capabilities", timeout=5) as resp:
            assert resp.status == 200
        req = urllib.request.Request(base + "/power", data=json.dumps({"on": True}).encode(), headers={"Content-Type":"application/json"}, method="PUT")
        try:
            urllib.request.urlopen(req, timeout=5)
        except urllib.error.HTTPError as exc:
            assert exc.code == 401
        else:
            raise AssertionError("expected unauthorized")
        req = urllib.request.Request(base + "/power", data=json.dumps({"on": True}).encode(), headers={"Content-Type":"application/json", "Authorization":"Bearer TOKEN"}, method="PUT")
        with urllib.request.urlopen(req, timeout=5) as resp:
            assert json.loads(resp.read().decode())["desired_value"] == 1
        huge = b"{" + b"x" * 20000 + b"}"
        req = urllib.request.Request(base + "/power", data=huge, headers={"Content-Type":"application/json", "Authorization":"Bearer TOKEN"}, method="PUT")
        try:
            urllib.request.urlopen(req, timeout=5)
        except urllib.error.HTTPError as exc:
            assert exc.code == 413
        else:
            raise AssertionError("expected payload too large")
    finally:
        server.shutdown(); server.server_close()


def test_wait_parameters_are_clamped(socket_enabled):
    class Recorder(fluidra_local.DryRunController):
        def wait_for_component(self, component_id, reported_value, *, timeout=120.0, interval=10.0):
            return {"matched": True, "timeout": timeout, "interval": interval}
    server = fluidra_local.start_local_server(Recorder(), host="127.0.0.1", port=0)
    try:
        base = f"http://127.0.0.1:{server.server_address[1]}"
        req = urllib.request.Request(base + "/power?wait=1&timeout=9999&interval=0.01", data=json.dumps({"on": True}).encode(), headers={"Content-Type":"application/json"}, method="PUT")
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
        assert data["verification"]["timeout"] == 180.0
        assert data["verification"]["interval"] == 0.5
    finally:
        server.shutdown(); server.server_close()



def test_server_returns_400_for_non_object_json_and_bad_wait(socket_enabled):
    server = fluidra_local.start_local_server(fluidra_local.DryRunController(), host="127.0.0.1", port=0)
    base = f"http://127.0.0.1:{server.server_address[1]}"
    def expect_400(path, body):
        req = urllib.request.Request(base + path, data=body, headers={"Content-Type":"application/json"}, method="PUT")
        try:
            urllib.request.urlopen(req, timeout=5)
        except urllib.error.HTTPError as exc:
            assert exc.code == 400
            return json.loads(exc.read().decode())
        raise AssertionError("expected HTTP 400")
    try:
        assert "JSON object" in expect_400("/power", b"[]")["error"]
        assert "invalid wait" in expect_400("/power?wait=1&timeout=abc", json.dumps({"on": True}).encode())["error"]
    finally:
        server.shutdown(); server.server_close()


def test_server_rejects_float_desired_value(socket_enabled):
    server = fluidra_local.start_local_server(fluidra_local.DryRunController(), host="127.0.0.1", port=0)
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        req = urllib.request.Request(base + "/power", data=json.dumps({"desiredValue": 1.9}).encode(), headers={"Content-Type":"application/json"}, method="PUT")
        try:
            urllib.request.urlopen(req, timeout=5)
        except urllib.error.HTTPError as exc:
            assert exc.code == 400
            assert "integer" in json.loads(exc.read().decode())["error"]
        else:
            raise AssertionError("expected HTTP 400")
    finally:
        server.shutdown(); server.server_close()
