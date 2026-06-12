#!/usr/bin/env python3
"""Deterministic local Fluidra bridge/capture tool.

This module deliberately avoids ESPHome/hardware assumptions. It provides two
software-only building blocks:

1. Capture evidence: parse emulator/server pcaps and classify whether a control
   burst touched the LAN device, MQTT/TLS, or only cloud TLS endpoints.
2. Local server facade: expose a stable local HTTP API backed by a controller.
   The first backend is dry-run, so control semantics can be tested without
   sending live commands. A cloud backend can later be plugged in under the same
   local API.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import time
import threading
import urllib.error
import urllib.request
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import emulator_flows

DEFAULT_DEVICE_IP = "192.168.1.29"
DEFAULT_DEVICE_ID = "LG24440781"
SUPPORTED_COMPONENTS = {
    13: "power",
    14: "mode",
    15: "set_temperature_celsius_x10",
}

HEAT_PUMP_MODES = {
    "Smart Heating": 0,
    "Smart Cooling": 1,
    "Smart Auto": 2,
    "Boost Heating": 3,
    "Silence Heating": 4,
    "Boost Cooling": 5,
    "Silence Cooling": 6,
}
MODES_BY_VALUE = {value: name for name, value in HEAT_PUMP_MODES.items()}
COMPONENT_CAPABILITIES = {
    "13": {"name": "power", "type": "switch", "values": {"0": "off", "1": "on"}},
    "14": {"name": "mode", "type": "select", "modes": HEAT_PUMP_MODES},
    "15": {"name": "target_temperature", "type": "number", "unit": "°C", "scale": 10, "min": 8.1, "max": 40.0, "step": 0.1},
    "19": {"name": "pool_temperature", "type": "sensor", "unit": "°C", "scale": 10},
    "67": {"name": "air_temperature", "type": "sensor", "unit": "°C", "scale": 10},
    "28": {"name": "flow_status", "type": "binary_sensor", "values": {"0": "ok", "1": "no_flow"}},
    "81": {"name": "min_setpoint", "type": "sensor", "unit": "°C"},
    "82": {"name": "max_setpoint", "type": "sensor", "unit": "°C"},
}

MAX_JSON_BODY_BYTES = 16 * 1024
MAX_WAIT_TIMEOUT = 180.0
MIN_WAIT_INTERVAL = 0.5
MAX_WAIT_INTERVAL = 30.0


def parse_bool_value(value: Any) -> bool:
    """Parse strict booleans from JSON values used by the local API."""
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in (0, 1):
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "on", "yes"}:
            return True
        if normalized in {"0", "false", "off", "no"}:
            return False
    raise ValueError(f"invalid boolean value {value!r}")




def parse_int_value(value: Any, *, name: str = "value") -> int:
    """Parse strict integers without truncating floats or accepting booleans."""
    if isinstance(value, bool):
        raise ValueError(f"{name} must be an integer")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        if text and (text.isdigit() or (text[0] == "-" and text[1:].isdigit())):
            return int(text)
    raise ValueError(f"{name} must be an integer")

def validate_component_value(component_id: int, desired_value: int) -> int:
    """Validate safe writable component ranges before sending any live command."""
    if component_id == 13 and desired_value not in (0, 1):
        raise ValueError("power component 13 only accepts 0/off or 1/on")
    if component_id == 14 and desired_value not in MODES_BY_VALUE:
        raise ValueError(f"mode component 14 only accepts {sorted(MODES_BY_VALUE)}")
    if component_id == 15 and not (81 <= desired_value <= 400):
        raise ValueError("target temperature component 15 must be between 8.1°C and 40.0°C")
    return desired_value


def parse_ip_neigh(text: str, *, known_device_ip: str = DEFAULT_DEVICE_IP, known_device_id: str = DEFAULT_DEVICE_ID) -> list[dict[str, Any]]:
    """Parse `ip neigh` output into deterministic discovery candidates."""
    devices: list[dict[str, Any]] = []
    for line in text.splitlines():
        parts = line.split()
        if not parts:
            continue
        ip = parts[0]
        mac = None
        state = parts[-1] if len(parts) > 1 else "UNKNOWN"
        if "lladdr" in parts:
            idx = parts.index("lladdr")
            if idx + 1 < len(parts):
                mac = parts[idx + 1]
        confidence = "known_ip_match" if ip == known_device_ip else "neighbor"
        item: dict[str, Any] = {
            "ip": ip,
            "mac": mac,
            "state": state,
            "source": "ip_neigh",
            "confidence": confidence,
            "local_control_proven": False,
        }
        if ip == known_device_ip:
            item["device_id"] = known_device_id
        devices.append(item)
    devices.sort(key=lambda item: (0 if item["ip"] == known_device_ip else 1, item["ip"]))
    return devices


def discover_local_devices(*, known_device_ip: str = DEFAULT_DEVICE_IP, known_device_id: str = DEFAULT_DEVICE_ID, run_probe: bool = True) -> dict[str, Any]:
    """Discover local candidates without claiming stock-firmware LAN control.

    This is intentionally conservative: ARP/neighbor table evidence identifies a
    host at the configured IP, but `local_control_proven` remains false until a
    real local protocol is proven.
    """
    devices: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    if run_probe:
        try:
            completed = subprocess.run(["ip", "neigh"], check=False, capture_output=True, text=True, timeout=3)
            if completed.returncode == 0:
                devices.extend(parse_ip_neigh(completed.stdout, known_device_ip=known_device_ip, known_device_id=known_device_id))
            else:
                errors.append({"source": "ip_neigh", "error": completed.stderr.strip() or f"exit {completed.returncode}"})
        except Exception as exc:
            errors.append({"source": "ip_neigh", "error": f"{type(exc).__name__}: {exc}"})
    if not any(item.get("ip") == known_device_ip for item in devices):
        devices.insert(0, {
            "ip": known_device_ip,
            "device_id": known_device_id,
            "mac": None,
            "state": "configured",
            "source": "configured",
            "confidence": "configured_known_ip",
            "local_control_proven": False,
        })
    return {
        "device_id": known_device_id,
        "known_device_ip": known_device_ip,
        "local_control_proven": False,
        "methods": ["configured_known_ip", "ip_neigh"],
        "devices": devices,
        "errors": errors,
        "note": "Discovery identifies local network candidates only; stock-firmware local control is not proven.",
    }



def _remote_endpoint(src: str, sport: int, dst: str, dport: int) -> tuple[str, int]:
    if emulator_flows._emu_side(src):
        return dst, dport
    return src, sport


def capture_evidence(
    pcap: str | Path,
    *,
    around: float | None = None,
    window: float = 3.0,
    device_ip: str = DEFAULT_DEVICE_IP,
) -> dict[str, Any]:
    """Return deterministic network evidence for a capture/window.

    The result is intentionally decryption-free. It only classifies endpoints by
    IP/port/protocol and counts payload-bearing packets.
    """
    raw = Path(pcap).read_bytes()
    packets = list(emulator_flows.parse(raw))
    if around is not None:
        lo, hi = around - window, around + window
        packets = [p for p in packets if lo <= p[0] <= hi]

    endpoints: dict[str, dict[str, Any]] = defaultdict(lambda: {"packets": 0, "bytes": 0, "protocols": set()})
    lan_device_packets = 0
    mqtt_tls_packets = 0
    cloud_tls_packets = 0

    for _ts, proto, src, sport, dst, dport, _flags, plen in packets:
        rip, rport = _remote_endpoint(src, sport, dst, dport)
        key = f"{rip}:{rport}"
        endpoints[key]["packets"] += 1
        endpoints[key]["bytes"] += plen
        endpoints[key]["protocols"].add(proto)
        if rip == device_ip:
            lan_device_packets += 1
        if rport == 8883:
            mqtt_tls_packets += 1
        if proto == "TCP" and rport == 443 and rip != device_ip:
            cloud_tls_packets += 1

    if lan_device_packets:
        conclusion = "local_device_traffic_detected"
    elif mqtt_tls_packets:
        conclusion = "mqtt_tls_cloud_control_possible"
    elif cloud_tls_packets:
        conclusion = "cloud_websocket_or_https_only"
    else:
        conclusion = "no_control_network_burst_detected"

    normalized_endpoints = {
        key: {
            "packets": value["packets"],
            "bytes": value["bytes"],
            "protocols": sorted(value["protocols"]),
        }
        for key, value in sorted(endpoints.items())
    }
    return {
        "pcap": str(pcap),
        "around": around,
        "window": window,
        "device_ip": device_ip,
        "packets": len(packets),
        "lan_device_packets": lan_device_packets,
        "mqtt_tls_packets": mqtt_tls_packets,
        "cloud_tls_packets": cloud_tls_packets,
        "conclusion": conclusion,
        "endpoints": normalized_endpoints,
    }




class HTTPStatusError(RuntimeError):
    """Raised when a JSON HTTP request returns an error status."""

    def __init__(self, status: int, payload: Any):
        super().__init__(f"HTTP {status}: {payload}")
        self.status = status
        self.payload = payload


class UrllibJSONHTTP:
    """Tiny JSON HTTP client using only the Python standard library."""

    def request_json(self, method: str, url: str, *, headers: dict[str, str] | None = None,
                     payload: Any | None = None, timeout: int = 15) -> Any:
        body = None if payload is None else json.dumps(payload).encode()
        req_headers = {"Accept": "application/json", **(headers or {})}
        if body is not None:
            req_headers.setdefault("Content-Type", "application/json")
        req = urllib.request.Request(url, data=body, headers=req_headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                text = resp.read().decode()
                return json.loads(text) if text else {}
        except urllib.error.HTTPError as exc:
            text = exc.read().decode(errors="replace")
            try:
                payload_obj = json.loads(text) if text else {"error": exc.reason}
            except json.JSONDecodeError:
                payload_obj = {"error": text or exc.reason}
            raise HTTPStatusError(exc.code, payload_obj) from exc


class CloudRestController:
    """Live Fluidra cloud REST backend behind the local deterministic API."""

    backend = "cloud-rest"
    cognito_url = "https://cognito-idp.eu-west-1.amazonaws.com/"
    api_base = "https://api.fluidra-emea.com"

    def __init__(
        self,
        *,
        device_id: str = DEFAULT_DEVICE_ID,
        client_id: str | None = None,
        refresh_token: str | None = None,
        access_token: str | None = None,
        device_type: str = "connected",
        http: Any | None = None,
    ):
        self.device_id = device_id
        self.client_id = client_id
        self.refresh_token = refresh_token
        self.access_token = access_token
        self.device_type = device_type
        self.http = http or UrllibJSONHTTP()
        self.expires_at = 0.0 if access_token is None else time.time() + 240
        self.history: list[dict[str, Any]] = []

    @classmethod
    def from_env(cls, *, device_id: str | None = None, http: Any | None = None) -> "CloudRestController":
        return cls(
            device_id=device_id or os.environ.get("FLUIDRA_DEVICE_ID", DEFAULT_DEVICE_ID),
            client_id=os.environ.get("FLUIDRA_CLIENT_ID") or os.environ.get("COGNITO_CLIENT_ID"),
            refresh_token=os.environ.get("FLUIDRA_REFRESH_TOKEN") or os.environ.get("COGNITO_REFRESH_TOKEN"),
            access_token=os.environ.get("FLUIDRA_ACCESS_TOKEN") or os.environ.get("COGNITO_ACCESS_TOKEN"),
            device_type=os.environ.get("FLUIDRA_DEVICE_TYPE", "connected"),
            http=http,
        )

    def _ensure_token(self) -> str:
        if self.access_token and time.time() < self.expires_at - 30:
            return self.access_token
        if self.access_token and not self.refresh_token:
            return self.access_token
        if not self.client_id or not self.refresh_token:
            raise RuntimeError("cloud backend requires FLUIDRA_CLIENT_ID and FLUIDRA_REFRESH_TOKEN, or FLUIDRA_ACCESS_TOKEN")
        payload = {
            "AuthFlow": "REFRESH_TOKEN_AUTH",
            "ClientId": self.client_id,
            "AuthParameters": {"REFRESH_TOKEN": self.refresh_token},
        }
        headers = {
            "Content-Type": "application/x-amz-json-1.1",
            "X-Amz-Target": "AWSCognitoIdentityProviderService.InitiateAuth",
        }
        result = self.http.request_json("POST", self.cognito_url, headers=headers, payload=payload)
        auth = result.get("AuthenticationResult", result)
        token = auth.get("AccessToken")
        if not token:
            raise RuntimeError("Cognito refresh did not return AccessToken")
        self.access_token = token
        self.expires_at = time.time() + int(auth.get("ExpiresIn", 300))
        return token

    def _api(self, method: str, path: str, *, payload: Any | None = None) -> Any:
        token = self._ensure_token()
        sep = "&" if "?" in path else "?"
        url = f"{self.api_base}{path}{sep}deviceType={self.device_type}"
        return self.http.request_json(
            method,
            url,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            payload=payload,
        )

    def get_device(self) -> Any:
        return self._api("GET", f"/generic/devices/{self.device_id}")

    def get_components(self) -> Any:
        return self._api("GET", f"/generic/devices/{self.device_id}/components")

    def get_component(self, component_id: int) -> Any:
        try:
            return self._api("GET", f"/generic/devices/{self.device_id}/components/{component_id}")
        except HTTPStatusError:
            comps = self.get_components()
            items = comps.get("items") if isinstance(comps, dict) else comps
            if isinstance(items, list):
                for item in items:
                    if isinstance(item, dict) and item.get("id") == component_id:
                        return item
            raise

    def wait_for_component(self, component_id: int, reported_value: int, *, timeout: float = 120.0, interval: float = 10.0) -> dict[str, Any]:
        deadline = time.time() + timeout
        polls: list[dict[str, Any]] = []
        while True:
            component = self.get_component(component_id)
            polls.append({"elapsed": round(timeout - max(0.0, deadline - time.time()), 3), "component": component})
            if isinstance(component, dict) and component.get("reportedValue") == reported_value:
                return {"matched": True, "reported_value": reported_value, "component": component, "polls": polls}
            if time.time() >= deadline:
                return {"matched": False, "reported_value": reported_value, "component": component, "polls": polls}
            time.sleep(interval)

    def capabilities(self) -> dict[str, Any]:
        return {
            "backend": self.backend,
            "device_id": self.device_id,
            "components": COMPONENT_CAPABILITIES,
            "modes": HEAT_PUMP_MODES,
            "modes_by_value": {str(k): v for k, v in MODES_BY_VALUE.items()},
            "diagnostics": {"local_control_proven": False, "transport": self.backend},
        }

    def discover_devices(self) -> dict[str, Any]:
        return discover_local_devices(known_device_id=self.device_id, run_probe=True)

    def state(self) -> dict[str, Any]:
        return {
            "backend": self.backend,
            "device_id": self.device_id,
            "device_type": self.device_type,
            "device": self.get_device(),
            "history": self.history,
            "auth": {
                "has_access_token": bool(self.access_token),
                "has_refresh_token": bool(self.refresh_token),
                "expires_at": int(self.expires_at) if self.expires_at else None,
            },
        }

    def set_component(self, component_id: int, desired_value: int) -> dict[str, Any]:
        if component_id not in SUPPORTED_COMPONENTS:
            raise ValueError(f"unsupported component {component_id}; supported: {sorted(SUPPORTED_COMPONENTS)}")
        desired_value = validate_component_value(component_id, desired_value)
        write_response = self._api(
            "PUT",
            f"/generic/devices/{self.device_id}/components/{component_id}",
            payload={"desiredValue": desired_value},
        )
        try:
            readback = self.get_component(component_id)
        except Exception as exc:
            readback = {"error": type(exc).__name__, "message": str(exc)}
        result = {
            "backend": self.backend,
            "device_id": self.device_id,
            "component_id": component_id,
            "desired_value": desired_value,
            "write_response": write_response,
            "readback": readback,
        }
        self.history.append(result)
        return result


class DryRunController:
    """Deterministic controller that validates and records component writes."""

    backend = "dry-run"

    def __init__(self, device_id: str = DEFAULT_DEVICE_ID):
        self.device_id = device_id
        self.history: list[dict[str, Any]] = []

    def capabilities(self) -> dict[str, Any]:
        return {
            "backend": self.backend,
            "device_id": self.device_id,
            "components": COMPONENT_CAPABILITIES,
            "modes": HEAT_PUMP_MODES,
            "modes_by_value": {str(k): v for k, v in MODES_BY_VALUE.items()},
            "diagnostics": {"local_control_proven": False, "transport": self.backend},
        }

    def discover_devices(self) -> dict[str, Any]:
        return discover_local_devices(known_device_id=self.device_id, run_probe=True)

    def state(self) -> dict[str, Any]:
        return {
            "backend": self.backend,
            "device_id": self.device_id,
            "supported_components": SUPPORTED_COMPONENTS,
            "history": self.history,
        }

    def set_component(self, component_id: int, desired_value: int) -> dict[str, Any]:
        if component_id not in SUPPORTED_COMPONENTS:
            raise ValueError(f"unsupported component {component_id}; supported: {sorted(SUPPORTED_COMPONENTS)}")
        desired_value = validate_component_value(component_id, desired_value)
        result = {
            "backend": self.backend,
            "device_id": self.device_id,
            "component_id": component_id,
            "desired_value": desired_value,
            "would_send": {"desiredValue": desired_value},
        }
        self.history.append(result)
        return result

    def wait_for_component(self, component_id: int, reported_value: int, *, timeout: float = 120.0, interval: float = 10.0) -> dict[str, Any]:
        component = {"id": component_id, "reportedValue": reported_value}
        return {"matched": True, "reported_value": reported_value, "component": component, "polls": [{"elapsed": 0, "component": component}]}


class _LocalHandler(BaseHTTPRequestHandler):
    server: "LocalFluidraHTTPServer"

    def log_message(self, format: str, *args: Any) -> None:  # keep CLI deterministic/quiet under tests
        return

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, sort_keys=True).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        parts = path.strip("/").split("/")
        try:
            if path == "/":
                c = self.server.controller
                self._send_json(200, {
                    "name": "Fluidra Local Bridge",
                    "status": "ok",
                    "backend": c.backend,
                    "device_id": c.device_id,
                    "endpoints": [
                        "GET /",
                        "GET /state",
                        "GET /capabilities",
                        "GET /components",
                        "GET /component/<id>",
                        "GET /discover",
                        "PUT /component/<id>",
                        "PUT /power",
                        "PUT /temperature",
                        "PUT /mode",
                    ],
                })
                return
            if path == "/state":
                self._send_json(200, self.server.controller.state())
                return
            if path == "/components" and hasattr(self.server.controller, "get_components"):
                self._send_json(200, self.server.controller.get_components())
                return
            if path == "/capabilities" and hasattr(self.server.controller, "capabilities"):
                self._send_json(200, self.server.controller.capabilities())
                return
            if path == "/discover" and hasattr(self.server.controller, "discover_devices"):
                self._send_json(200, self.server.controller.discover_devices())
                return
            if len(parts) == 2 and parts[0] == "component" and parts[1].isdigit() and hasattr(self.server.controller, "get_component"):
                self._send_json(200, self.server.controller.get_component(int(parts[1])))
                return
        except PermissionError as exc:
            self._send_json(401, {"error": str(exc)})
            return
        except OverflowError as exc:
            self._send_json(413, {"error": str(exc)})
            return
        except ValueError as exc:
            self._send_json(400, {"error": str(exc)})
            return
        except Exception as exc:
            self._send_json(502, {"error": type(exc).__name__, "message": str(exc)})
            return
        self._send_json(404, {"error": "not found", "path": path})

    def _check_write_auth(self) -> None:
        token = getattr(self.server, "auth_token", None)
        if not token:
            return
        if self.headers.get("Authorization") != f"Bearer {token}":
            raise PermissionError("missing or invalid bearer token")

    def _read_json_body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if length < 0:
            raise ValueError("Content-Length must be non-negative")
        if length > MAX_JSON_BODY_BYTES:
            raise OverflowError(f"JSON body too large; max={MAX_JSON_BODY_BYTES} bytes")
        payload = json.loads(self.rfile.read(length).decode() or "{}")
        if not isinstance(payload, dict):
            raise ValueError("request body must be a JSON object")
        return payload

    def do_PUT(self) -> None:
        path = urlparse(self.path).path
        parts = path.strip("/").split("/")
        try:
            self._check_write_auth()
            payload = self._read_json_body()
            if len(parts) == 2 and parts[0] == "component" and parts[1].isdigit():
                if "desiredValue" not in payload:
                    raise ValueError("missing desiredValue")
                result = self.server.controller.set_component(int(parts[1]), parse_int_value(payload["desiredValue"], name="desiredValue"))
            elif path == "/power":
                if "desiredValue" in payload:
                    value = parse_int_value(payload["desiredValue"], name="desiredValue")
                elif "on" in payload:
                    value = 1 if parse_bool_value(payload["on"]) else 0
                elif "state" in payload:
                    value = 1 if parse_bool_value(payload["state"]) else 0
                else:
                    raise ValueError("missing desiredValue/on/state")
                result = self.server.controller.set_component(13, value)
            elif path == "/temperature":
                if "desiredValue" in payload:
                    value = parse_int_value(payload["desiredValue"], name="desiredValue")
                elif "celsius" in payload:
                    value = int(round(float(payload["celsius"]) * 10))
                else:
                    raise ValueError("missing desiredValue/celsius")
                result = self.server.controller.set_component(15, value)
            elif path == "/mode":
                mode_name = None
                if "desiredValue" in payload:
                    value = parse_int_value(payload["desiredValue"], name="desiredValue")
                    mode_name = MODES_BY_VALUE.get(value)
                elif "mode" in payload:
                    mode_name = str(payload["mode"])
                    if mode_name not in HEAT_PUMP_MODES:
                        raise ValueError(f"unsupported mode {mode_name!r}; supported={sorted(HEAT_PUMP_MODES)}")
                    value = HEAT_PUMP_MODES[mode_name]
                else:
                    raise ValueError("missing desiredValue/mode")
                result = self.server.controller.set_component(14, value)
                if mode_name:
                    result = dict(result)
                    result["mode"] = mode_name
            else:
                self._send_json(404, {"error": "not found", "path": path})
                return
        except PermissionError as exc:
            self._send_json(401, {"error": str(exc)})
            return
        except OverflowError as exc:
            self._send_json(413, {"error": str(exc)})
            return
        except ValueError as exc:
            self._send_json(400, {"error": str(exc)})
            return
        except json.JSONDecodeError as exc:
            self._send_json(400, {"error": f"invalid JSON: {exc}"})
            return
        except Exception as exc:
            self._send_json(502, {"error": type(exc).__name__, "message": str(exc)})
            return
        try:
            query = parse_qs(urlparse(self.path).query)
            if query.get("wait", ["0"])[0].lower() in {"1", "true", "yes"}:
                try:
                    timeout = min(MAX_WAIT_TIMEOUT, max(0.0, float(query.get("timeout", ["120"])[0])))
                    interval = min(MAX_WAIT_INTERVAL, max(MIN_WAIT_INTERVAL, float(query.get("interval", ["10"])[0])))
                except ValueError as exc:
                    raise ValueError(f"invalid wait parameter: {exc}") from exc
                result = dict(result)
                result["verification"] = self.server.controller.wait_for_component(
                    int(result["component_id"]), int(result["desired_value"]), timeout=timeout, interval=interval
                )
        except ValueError as exc:
            self._send_json(400, {"error": str(exc)})
            return
        except Exception as exc:
            self._send_json(502, {"error": type(exc).__name__, "message": str(exc)})
            return
        self._send_json(200, result)


class LocalFluidraHTTPServer(ThreadingHTTPServer):
    def __init__(self, server_address: tuple[str, int], controller: Any, *, auth_token: str | None = None):
        super().__init__(server_address, _LocalHandler)
        self.controller = controller
        self.auth_token = auth_token
        self.thread: threading.Thread | None = None


def start_local_server(controller: Any, host: str = "127.0.0.1", port: int = 8765, *, auth_token: str | None = None) -> LocalFluidraHTTPServer:
    server = LocalFluidraHTTPServer((host, port), controller, auth_token=auth_token)
    thread = threading.Thread(target=server.serve_forever, name="fluidra-local-http", daemon=True)
    server.thread = thread
    thread.start()
    return server


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Deterministic local Fluidra bridge/capture tool")
    sub = parser.add_subparsers(dest="cmd", required=True)

    cap = sub.add_parser("capture", help="classify pcap traffic around an optional timestamp")
    cap.add_argument("pcap")
    cap.add_argument("--around", type=float)
    cap.add_argument("--window", type=float, default=3.0)
    cap.add_argument("--device-ip", default=DEFAULT_DEVICE_IP)

    srv = sub.add_parser("serve", help="run local HTTP control facade")
    srv.add_argument("--host", default="127.0.0.1")
    srv.add_argument("--port", type=int, default=8765)
    srv.add_argument("--device-id", default=DEFAULT_DEVICE_ID)
    srv.add_argument("--backend", choices=["dry-run", "cloud"], default="dry-run")
    srv.add_argument("--auth-token", default=os.environ.get("FLUIDRA_LOCAL_AUTH_TOKEN"), help="optional bearer token required for write endpoints")

    disc = sub.add_parser("discover", help="discover local network candidates for the configured Fluidra device")
    disc.add_argument("--device-ip", default=DEFAULT_DEVICE_IP)
    disc.add_argument("--device-id", default=DEFAULT_DEVICE_ID)
    disc.add_argument("--no-probe", action="store_true", help="only return configured known device candidate")

    setp = sub.add_parser("set-component", help="set a component and optionally wait for reportedValue")
    setp.add_argument("--backend", choices=["dry-run", "cloud"], default="dry-run")
    setp.add_argument("--device-id", default=DEFAULT_DEVICE_ID)
    setp.add_argument("--component-id", type=int, required=True)
    setp.add_argument("--desired-value", type=int, required=True)
    setp.add_argument("--wait", action="store_true")
    setp.add_argument("--timeout", type=float, default=120.0)
    setp.add_argument("--interval", type=float, default=10.0)

    args = parser.parse_args(argv)
    if args.cmd == "capture":
        print(json.dumps(capture_evidence(args.pcap, around=args.around, window=args.window, device_ip=args.device_ip), indent=2, sort_keys=True))
        return 0
    if args.cmd == "serve":
        controller = (CloudRestController.from_env(device_id=args.device_id) if args.backend == "cloud" else DryRunController(device_id=args.device_id))
        server = start_local_server(controller, host=args.host, port=args.port, auth_token=args.auth_token)
        print(f"fluidra local server listening on http://{args.host}:{server.server_address[1]}", flush=True)
        try:
            server.thread.join()
        except KeyboardInterrupt:
            server.shutdown()
            server.server_close()
        return 0
    if args.cmd == "discover":
        print(json.dumps(discover_local_devices(known_device_ip=args.device_ip, known_device_id=args.device_id, run_probe=not args.no_probe), indent=2, sort_keys=True))
        return 0
    if args.cmd == "set-component":
        controller = (CloudRestController.from_env(device_id=args.device_id) if args.backend == "cloud" else DryRunController(device_id=args.device_id))
        result = controller.set_component(args.component_id, args.desired_value)
        if args.wait:
            result = dict(result)
            result["verification"] = controller.wait_for_component(args.component_id, args.desired_value, timeout=args.timeout, interval=args.interval)
        print(json.dumps(result, sort_keys=True))
        return 0 if not args.wait or result["verification"].get("matched") else 1
    raise AssertionError(args.cmd)


if __name__ == "__main__":
    raise SystemExit(main())
