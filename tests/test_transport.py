"""Tests for the three-tier transport abstraction.

Branch 1 (transport/frida-tcp): Frida TCP vs USB device connection.
"""

from __future__ import annotations

import pytest

from droid_recon import shell
from droid_recon.cli import build_parser
from droid_recon.frida import server
from droid_recon.transport import FridaTransportConfig, TransportConfig


# ---- FridaTransportConfig ----

def test_config_defaults():
    c = FridaTransportConfig()
    assert c.mode == "auto"
    assert c.host == "127.0.0.1"
    assert c.port == 27042


def test_config_rejects_invalid_mode():
    with pytest.raises(ValueError, match="tcp|usb|auto"):
        FridaTransportConfig(mode="bluetooth")


def test_config_accepts_all_valid_modes():
    for mode in ("tcp", "usb", "auto"):
        c = FridaTransportConfig(mode=mode)
        assert c.mode == mode


# ---- TransportConfig.from_cli ----

def test_transport_from_cli_default():
    args = build_parser().parse_args(["frida", "setup"])
    tc = TransportConfig.from_cli(args)
    assert tc.frida.mode == "auto"


def test_transport_from_cli_explicit_tcp():
    args = build_parser().parse_args(["frida", "--frida-transport", "tcp", "setup"])
    tc = TransportConfig.from_cli(args)
    assert tc.frida.mode == "tcp"


def test_transport_from_cli_explicit_usb():
    args = build_parser().parse_args(["frida", "--frida-transport", "usb", "setup"])
    tc = TransportConfig.from_cli(args)
    assert tc.frida.mode == "usb"


def test_native_parser_accepts_frida_transport():
    args = build_parser().parse_args(
        ["native", "--frida-transport", "tcp", "trace", "com.example.app"]
    )
    tc = TransportConfig.from_cli(args)
    assert tc.frida.mode == "tcp"


# ---- _device_args ----

def test_device_args_tcp():
    cfg = FridaTransportConfig(mode="tcp", host="10.0.0.1", port=9999)
    result = server._device_args("emulator-5554", cfg)
    assert result == ["-H", "10.0.0.1:9999"]


def test_device_args_usb_with_serial():
    cfg = FridaTransportConfig(mode="usb")
    result = server._device_args("emulator-5554", cfg)
    assert result == ["-D", "emulator-5554"]


def test_device_args_usb_no_serial():
    cfg = FridaTransportConfig(mode="usb")
    result = server._device_args(None, cfg)
    assert result == ["-U"]


def test_device_args_auto_uses_tcp():
    cfg = FridaTransportConfig(mode="auto")
    result = server._device_args("emulator-5554", cfg)
    assert result == ["-H", "127.0.0.1:27042"]


# ---- _has_connect_error ----

def test_connect_error_detected():
    assert server._has_connect_error("Failed to connect to the device")
    assert server._has_connect_error("unable to connect to remote frida")
    assert server._has_connect_error("Connection refused")
    assert server._has_connect_error("timed out while waiting for device")


def test_no_false_connect_error():
    assert not server._has_connect_error("[ssl_unpin] Interceptor.attach(...)")
    assert not server._has_connect_error("console.log('hello')")
    assert not server._has_connect_error("")


# ---- ensure_server with transport ----

def test_ensure_server_forwards_port_on_tcp(monkeypatch):
    forwarded = []

    monkeypatch.setattr(server, "host_version", lambda: "16.5.0")
    monkeypatch.setattr(server, "is_running", lambda serial=None: True)
    monkeypatch.setattr(server.shell, "adb",
                        lambda *a, serial=None, timeout=60: _capture_forward(a, forwarded))

    cfg = FridaTransportConfig(mode="tcp", port=27042)
    ok, msg = server.ensure_server("emu-5554", transport=cfg)
    assert ok
    assert any("27042" in str(f) for f in forwarded)


def test_ensure_server_skips_forward_on_usb(monkeypatch):
    forwarded = []

    monkeypatch.setattr(server, "host_version", lambda: "16.5.0")
    monkeypatch.setattr(server, "is_running", lambda serial=None: True)
    monkeypatch.setattr(server.shell, "adb",
                        lambda *a, serial=None, timeout=60: _capture_forward(a, forwarded))

    cfg = FridaTransportConfig(mode="usb")
    ok, msg = server.ensure_server("emu-5554", transport=cfg)
    assert ok
    assert not forwarded


def _capture_forward(args, collector):
    if args and "forward" in str(args):
        collector.append(args)
    return shell.Proc(list(args), 0, "", "")


# ---- ensure_server starts with TCP listen ----

def test_ensure_server_starts_with_tcp_listen(monkeypatch):
    started_cmds = []

    monkeypatch.setattr(server, "host_version", lambda: "16.5.0")

    call_count = {"n": 0}

    def fake_is_running(serial=None):
        call_count["n"] += 1
        return call_count["n"] > 1

    monkeypatch.setattr(server, "is_running", fake_is_running)
    monkeypatch.setattr(server, "fetch_server", lambda v, a: __import__("pathlib").Path("/fake"))
    monkeypatch.setattr(server.shell, "adb_shell",
                        lambda cmd, serial=None, timeout=60: shell.Proc(cmd, 0, "root", ""))
    monkeypatch.setattr(server.shell, "adb",
                        lambda *a, serial=None, timeout=60: shell.Proc(list(a), 0, "", ""))

    def capture_script(script, serial=None, timeout=20):
        started_cmds.append(script)
        return shell.Proc(["adb", "shell", script], 0, "", "")

    monkeypatch.setattr(server.shell, "adb_script", capture_script)

    import time
    monkeypatch.setattr(time, "sleep", lambda s: None)

    cfg = FridaTransportConfig(mode="tcp", port=27042)
    ok, msg = server.ensure_server("emu-5554", transport=cfg)
    assert ok
    assert any("-l 0.0.0.0:27042" in cmd for cmd in started_cmds)


# ---- run_script TCP vs USB argv ----

def test_run_script_tcp_uses_H_flag(monkeypatch):
    captured = []
    monkeypatch.setattr(server.shell, "which", lambda name: "/usr/bin/frida")
    monkeypatch.setattr(server.shell, "run",
                        lambda argv, timeout: _capture_argv(argv, captured))

    script = __import__("pathlib").Path(__file__).parent / "fixtures.py"
    cfg = FridaTransportConfig(mode="tcp", host="10.0.0.1", port=9999)
    server.run_script("com.example", script, "emu-5554", transport=cfg)

    assert captured
    argv = captured[0]
    assert "-H" in argv
    assert "10.0.0.1:9999" in argv
    assert "-U" not in argv
    assert "-D" not in argv


def test_run_script_usb_uses_D_flag(monkeypatch):
    captured = []
    monkeypatch.setattr(server.shell, "which", lambda name: "/usr/bin/frida")
    monkeypatch.setattr(server.shell, "run",
                        lambda argv, timeout: _capture_argv(argv, captured))

    script = __import__("pathlib").Path(__file__).parent / "fixtures.py"
    cfg = FridaTransportConfig(mode="usb")
    server.run_script("com.example", script, "emu-5554", transport=cfg)

    assert captured
    argv = captured[0]
    assert "-D" in argv
    assert "emu-5554" in argv
    assert "-H" not in argv


def test_run_script_auto_fallback_to_usb(monkeypatch):
    captured = []
    call_count = {"n": 0}

    def fake_run(argv, timeout):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return shell.Proc(argv, 1, "", "Failed to connect to remote frida-server")
        return shell.Proc(argv, 0, "hook installed", "")

    monkeypatch.setattr(server.shell, "which", lambda name: "/usr/bin/frida")
    monkeypatch.setattr(server.shell, "run", lambda argv, timeout: (
        captured.append(list(argv)) or fake_run(argv, timeout)
    ))

    script = __import__("pathlib").Path(__file__).parent / "fixtures.py"
    cfg = FridaTransportConfig(mode="auto")
    ok, output = server.run_script("com.example", script, "emu-5554", transport=cfg)

    assert ok
    assert len(captured) == 2
    assert "-H" in captured[0]
    assert "-D" in captured[1]


def _capture_argv(argv, collector):
    collector.append(list(argv))
    return shell.Proc(argv, 0, "hook installed", "")
