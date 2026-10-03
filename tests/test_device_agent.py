"""Tests for the device-agent transport layer (Branch 2).

Tests the transport config, client, runtime dispatch, deploy lifecycle,
and agent-threaded module functions.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from threading import Thread

import pytest

from droid_recon import shell
from droid_recon.cli import build_parser
from droid_recon.device_agent.client import DeviceAgentClient
from droid_recon.device_agent.runtime import exec_on_device, exec_script
from droid_recon.transport import DeviceAgentConfig, TransportConfig

# ---- DeviceAgentConfig ----

def test_agent_config_defaults():
    c = DeviceAgentConfig()
    assert c.host == "127.0.0.1"
    assert c.port == 18080
    assert c.enabled is True
    assert len(c.secret) == 32  # 16 bytes hex


def test_agent_config_base_url():
    c = DeviceAgentConfig(host="10.0.0.1", port=9999)
    assert c.base_url == "http://10.0.0.1:9999"


def test_agent_config_unique_secrets():
    a = DeviceAgentConfig()
    b = DeviceAgentConfig()
    assert a.secret != b.secret


# ---- TransportConfig with agent ----

def test_transport_config_has_agent():
    tc = TransportConfig()
    assert tc.agent.enabled is True
    assert tc.agent.port == 18080


def test_transport_from_cli_no_agent():
    args = build_parser().parse_args(["dynamic", "--no-agent", "test.apk"])
    tc = TransportConfig.from_cli(args)
    assert tc.agent.enabled is False


def test_transport_from_cli_default_agent():
    args = build_parser().parse_args(["dynamic", "test.apk"])
    tc = TransportConfig.from_cli(args)
    assert tc.agent.enabled is True


# ---- DeviceAgentClient ----

class _FakeAgentHandler(BaseHTTPRequestHandler):
    """Minimal HTTP handler that mimics the on-device agent."""

    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        if self.path == "/health":
            body = json.dumps({"ok": True, "version": "0.1.0", "uid": 0, "pid": 1234,
                               "whoami": "root"}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b""
        req = json.loads(raw) if raw else {}

        if self.path == "/exec":
            resp = {"rc": 0, "stdout": f"ran: {req.get('argv', [])}", "stderr": "",
                    "timed_out": False}
        elif self.path == "/exec/script":
            resp = {"rc": 0, "stdout": f"script: {req.get('script', '')[:20]}",
                    "stderr": "", "timed_out": False}
        elif self.path == "/fs/read":
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            data = b"fake file content"
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        elif self.path == "/fs/stat":
            resp = {"exists": True, "size": 42, "is_dir": False, "mode": "0o100644"}
        else:
            resp = {"error": "not found"}
            self.send_response(404)
            body = json.dumps(resp).encode()
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        body = json.dumps(resp).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture()
def fake_agent():
    """Start a fake agent HTTP server on a random port."""
    server = HTTPServer(("127.0.0.1", 0), _FakeAgentHandler)
    port = server.server_address[1]
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    config = DeviceAgentConfig(port=port, secret="", enabled=True)
    client = DeviceAgentClient(config)
    yield client
    server.shutdown()


def test_client_health(fake_agent):
    h = fake_agent.health()
    assert h["ok"] is True
    assert h["version"] == "0.1.0"


def test_client_is_alive(fake_agent):
    assert fake_agent.is_alive()


def test_client_is_alive_no_server():
    cfg = DeviceAgentConfig(port=19999, secret="", enabled=True)
    client = DeviceAgentClient(cfg)
    assert not client.is_alive()


def test_client_exec(fake_agent):
    proc = fake_agent.exec(["ls", "-la"], timeout=10)
    assert isinstance(proc, shell.Proc)
    assert proc.rc == 0
    assert "ls" in proc.stdout


def test_client_exec_script(fake_agent):
    proc = fake_agent.exec_script("echo hello", timeout=10)
    assert proc.rc == 0
    assert "echo hello" in proc.stdout


def test_client_read_file(fake_agent):
    data = fake_agent.read_file("/tmp/test.txt", timeout=10)
    assert data == b"fake file content"


def test_client_stat(fake_agent):
    result = fake_agent.stat("/tmp/test.txt")
    assert result["exists"] is True
    assert result["size"] == 42


def test_client_exec_returns_proc_on_error():
    cfg = DeviceAgentConfig(port=19999, secret="", enabled=True)
    client = DeviceAgentClient(cfg)
    proc = client.exec(["ls"], timeout=2)
    assert proc.rc == 1
    assert "agent error" in proc.stderr


# ---- HMAC auth ----

def test_client_auth_headers():
    cfg = DeviceAgentConfig(secret="testsecret123")
    client = DeviceAgentClient(cfg)
    headers = client._auth_headers("POST", "/exec", '{"argv": ["ls"]}')
    assert "X-Auth-Token" in headers
    assert "X-Timestamp" in headers
    ts = headers["X-Timestamp"]
    msg = f'{ts}:POST:/exec:{{"argv": ["ls"]}}'
    expected = hmac.new(b"testsecret123", msg.encode(), hashlib.sha256).hexdigest()
    assert headers["X-Auth-Token"] == expected


def test_client_no_auth_when_no_secret():
    cfg = DeviceAgentConfig(secret="")
    client = DeviceAgentClient(cfg)
    headers = client._auth_headers("GET", "/health")
    assert headers == {}


# ---- runtime dispatch ----

def test_exec_on_device_uses_agent(fake_agent):
    proc = exec_on_device(["whoami"], agent=fake_agent, timeout=10)
    assert proc.rc == 0
    assert "whoami" in proc.stdout


def test_exec_on_device_fallback_to_adb(monkeypatch):
    called = []
    monkeypatch.setattr(shell, "adb_shell",
                        lambda cmd, serial=None, timeout=60: (
                            called.append(cmd) or
                            shell.Proc(cmd, 0, "root", "")))
    proc = exec_on_device(["whoami"], agent=None, serial="emu-5554", timeout=10)
    assert proc.rc == 0
    assert called == [["whoami"]]


def test_exec_script_uses_agent(fake_agent):
    proc = exec_script("echo hello", agent=fake_agent, timeout=10)
    assert proc.rc == 0


def test_exec_script_fallback_to_adb(monkeypatch):
    called = []
    monkeypatch.setattr(shell, "adb_script",
                        lambda s, serial=None, timeout=60: (
                            called.append(s) or
                            shell.Proc(["sh", "-c", s], 0, "hello", "")))
    proc = exec_script("echo hello", agent=None, serial="emu-5554", timeout=10)
    assert proc.rc == 0
    assert called == ["echo hello"]


# ---- deploy ----

def test_has_python_checks_which(monkeypatch):
    from droid_recon.device_agent import deploy
    calls = []

    def fake_adb_shell(cmd, serial=None, timeout=60):
        calls.append(cmd)
        if cmd == ["which", "python3"]:
            return shell.Proc(cmd, 0, "/usr/bin/python3", "")
        if cmd == ["/usr/bin/python3", "--version"]:
            return shell.Proc(cmd, 0, "Python 3.11.2", "")
        return shell.Proc(cmd, 1, "", "not found")

    monkeypatch.setattr(shell, "adb_shell", fake_adb_shell)
    result = deploy._has_python("emu-5554")
    assert result == "/usr/bin/python3"


def test_has_python_returns_none(monkeypatch):
    from droid_recon.device_agent import deploy
    monkeypatch.setattr(shell, "adb_shell",
                        lambda cmd, serial=None, timeout=60:
                        shell.Proc(cmd, 1, "", "not found"))
    assert deploy._has_python("emu-5554") is None


# ---- probes with agent ----

def test_probe_context_has_agent():
    from droid_recon.device.probes import ProbeContext
    ctx = ProbeContext(package="com.test", agent="mock_agent")
    assert ctx.agent == "mock_agent"


def test_probe_context_agent_defaults_none():
    from droid_recon.device.probes import ProbeContext
    ctx = ProbeContext(package="com.test")
    assert ctx.agent is None


# ---- logcat with agent ----

def test_logcat_clear_uses_agent(fake_agent):
    from droid_recon.device import logcat
    logcat.clear(agent=fake_agent)


def test_logcat_dump_uses_agent(fake_agent):
    from droid_recon.device import logcat
    result = logcat.dump(agent=fake_agent)
    assert isinstance(result, str)


# ---- screen with agent ----

def test_screen_current_focus_uses_agent(fake_agent):
    from droid_recon.device import screen
    result = screen.current_focus(agent=fake_agent)
    assert isinstance(result, str)


# ---- oracle with agent ----

def test_oracle_snapshot_uses_agent(fake_agent, monkeypatch):
    from droid_recon.device import oracle, screen
    monkeypatch.setattr(screen, "ui_tree_xml",
                        lambda serial=None, agent=None: None)
    snap = oracle.snapshot("com.test", agent=fake_agent, with_ui=False)
    assert isinstance(snap, oracle.Snapshot)


# ---- server.py exists as pushable artifact ----

def test_server_script_exists():
    server_py = Path(__file__).parent.parent / "src" / "droid_recon" / "device_agent" / "server.py"
    assert server_py.exists()
    text = server_py.read_text()
    assert "HTTPServer" in text
    assert "droid-recon-agent" in text
    assert "/exec" in text
    assert "/health" in text


# ---- Branch 3: bootstrap module ----

def test_bootstrap_launch_app_uses_agent(fake_agent):
    from droid_recon.device import bootstrap
    bootstrap.launch_app("com.test", agent=fake_agent)


def test_bootstrap_launch_app_fallback_adb(monkeypatch):
    from droid_recon.device import bootstrap
    called = []
    monkeypatch.setattr(shell, "adb_shell",
                        lambda cmd, serial=None, timeout=60: (
                            called.append(cmd) or
                            shell.Proc(cmd, 0, "", "")))
    bootstrap.launch_app("com.test", serial="emu-5554")
    assert len(called) == 1
    assert "monkey" in called[0]


def test_bootstrap_notify_proxy_uses_agent(fake_agent):
    from droid_recon.device import bootstrap
    bootstrap.notify_proxy_change(agent=fake_agent)


def test_bootstrap_notify_proxy_fallback_adb(monkeypatch):
    from droid_recon.device import bootstrap
    called = []
    monkeypatch.setattr(shell, "adb_shell",
                        lambda cmd, serial=None, timeout=60: (
                            called.append(cmd) or
                            shell.Proc(cmd, 0, "", "")))
    bootstrap.notify_proxy_change(serial="emu-5554")
    assert len(called) == 1
    assert "PROXY_CHANGE" in " ".join(called[0])


def test_bootstrap_force_stop(monkeypatch):
    from droid_recon.device import bootstrap
    called = []
    monkeypatch.setattr(shell, "adb_shell",
                        lambda cmd, serial=None, timeout=60: (
                            called.append(cmd) or
                            shell.Proc(cmd, 0, "", "")))
    bootstrap.force_stop("com.test", serial="emu-5554")
    assert called == [["am", "force-stop", "com.test"]]


def test_bootstrap_module_docstring():
    from droid_recon.device import bootstrap
    assert "Bootstrap" in bootstrap.__doc__
    assert "RUNTIME" in bootstrap.__doc__
