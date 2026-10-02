"""MCP tool policy is enforced by the server, before any handler runs."""

from __future__ import annotations

import io
import json
from pathlib import Path

from droid_recon import mcp_server
from droid_recon.device import ordinary
from droid_recon.models import AttackSurface, Component
from droid_recon.session import Session


def _call(name: str, args: dict | None = None) -> dict:
    return {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": name, "arguments": args or {}}}


def test_default_gate_hides_and_blocks_mutating_tools(monkeypatch):
    called = []
    monkeypatch.setitem(mcp_server._HANDLERS, "tap", lambda args: called.append(args) or {"ok": True})
    listing = mcp_server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    visible = {tool["name"] for tool in listing["result"]["tools"]}
    assert "tap" not in visible
    assert "verify_caller" not in visible
    assert "read_app_storage" not in visible
    assert "static_analyze" in visible
    denied = mcp_server.handle(_call("tap", {"x": 1, "y": 2}))
    assert denied["result"]["isError"] is True
    assert "permission_denied" in denied["result"]["content"][0]["text"]
    assert called == []
    forged = _call("tap", {"x": 1, "y": 2})
    forged["params"]["allow_mutating"] = True
    forged["params"]["arguments"]["allow_mutating"] = True
    assert mcp_server.handle(forged)["result"]["isError"] is True
    assert called == []


def test_explicit_opt_in_allows_mutating_handler(monkeypatch):
    called = []
    monkeypatch.setitem(mcp_server._HANDLERS, "tap", lambda args: called.append(args) or {"ok": True})
    listing = mcp_server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                                allow_mutating=True)
    assert "tap" in {tool["name"] for tool in listing["result"]["tools"]}
    reply = mcp_server.handle(_call("tap", {"x": 1, "y": 2}), allow_mutating=True)
    assert called == [{"x": 1, "y": 2}]
    assert json.loads(reply["result"]["content"][0]["text"]) == {"ok": True}


def test_environment_opt_in_applies_to_serve_but_explicit_false_overrides(monkeypatch):
    monkeypatch.setenv(mcp_server.MCP_MUTATION_ENV, "1")
    assert mcp_server._mutations_enabled(None) is True
    assert mcp_server._mutations_enabled(False) is False
    called = []
    monkeypatch.setitem(mcp_server._HANDLERS, "tap", lambda args: called.append(args) or {"ok": True})
    monkeypatch.setattr(mcp_server.sys, "stdin", io.StringIO(json.dumps(_call("tap")) + "\n"))
    out = io.StringIO()
    monkeypatch.setattr(mcp_server.sys, "stdout", out)
    from droid_recon import log
    monkeypatch.setattr(log, "set_quiet", lambda value: None)
    assert mcp_server.serve(allow_mutating=None) == 0
    assert called == [{}]
    assert json.loads(out.getvalue())["result"]["content"]


def test_verify_caller_tool_records_ordinary_uid_result_without_device(monkeypatch, tmp_path):
    component = Component(name="com.example.app.OpenActivity", type="activity",
                          exported=True, reachable_from="third_party_app")
    surface = AttackSurface(package="com.example.app", apk_sha256="sha",
                            components=[component])
    session = Session.open(surface.package, tmp_path / "sessions")
    monkeypatch.setattr(mcp_server, "_surface_for", lambda target: (surface, []))
    monkeypatch.setattr(mcp_server, "_session", lambda package: session)
    monkeypatch.setattr(mcp_server.emulator, "running_serial", lambda: "emulator-test")
    monkeypatch.setattr(mcp_server.ordinary, "build_companion",
                        lambda: ordinary.CompanionBuild("built", Path("companion.apk")))
    monkeypatch.setattr(mcp_server.ordinary, "install_companion",
                        lambda apk, serial: ordinary.CompanionInstall(
                            "installed", serial=serial, verified_build=True))

    def fake_run_probe(request, *, serial, trusted_source):
        assert serial == "emulator-test"
        assert trusted_source is True
        return ordinary.OrdinaryResult(
            request.id, request.operation, request.target_package, "accepted_by_os",
            caller_package=ordinary.COMPANION_PACKAGE, caller_uid=12345,
            verified_ordinary_uid=True,
        )

    monkeypatch.setattr(mcp_server.ordinary, "run_probe", fake_run_probe)
    evidence_calls = []
    monkeypatch.setattr(mcp_server.evidence, "record",
                        lambda *args, **kwargs: evidence_calls.append((args, kwargs)))
    reply = mcp_server.handle(_call("verify_caller", {
        "target": "fixture", "component": component.name,
    }), allow_mutating=True)
    payload = json.loads(reply["result"]["content"][0]["text"])
    assert payload["result"]["accessible"] is True
    assert payload["result"]["evidence_status"] == "OBSERVED_ORDINARY_UID"
    lines = (session.dir / "ordinary_results.jsonl").read_text().splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["component"] == component.name
    assert evidence_calls[0][1]["execution_context"] == "ordinary_app_uid"
    assert evidence_calls[0][1]["serial"] == "emulator-test"


def test_verify_caller_is_blocked_by_default_even_with_valid_arguments(monkeypatch):
    monkeypatch.setattr(mcp_server, "_surface_for",
                        lambda target: (_ for _ in ()).throw(AssertionError("handler ran")))
    reply = mcp_server.handle(_call("verify_caller", {
        "target": "fixture", "component": "com.example.app.OpenActivity",
    }))
    assert reply["result"]["isError"] is True


def test_verify_caller_rejects_invalid_request_before_device_setup(monkeypatch):
    component = Component(name="com.example.app.OpenActivity", type="activity",
                          exported=True, reachable_from="third_party_app")
    surface = AttackSurface(package="com.example.app", components=[component])
    monkeypatch.setattr(mcp_server, "_surface_for", lambda target: (surface, []))
    monkeypatch.setattr(mcp_server.ordinary, "build_companion",
                        lambda: (_ for _ in ()).throw(AssertionError("build started")))
    reply = mcp_server.handle(_call("verify_caller", {
        "target": "fixture", "component": component.name, "operation": "delete_all",
    }), allow_mutating=True)
    assert reply["result"]["isError"] is True
    assert "unsupported ordinary probe" in reply["result"]["content"][0]["text"]


def test_verify_caller_forwards_only_explicit_provider_call_method(monkeypatch, tmp_path):
    component = Component(
        name="com.example.app.DataProvider", type="provider",
        exported=True, reachable_from="third_party_app",
        authorities=["com.example.app.data"],
    )
    surface = AttackSurface(package="com.example.app", components=[component])
    session = Session.open(surface.package, tmp_path / "sessions")
    monkeypatch.setattr(mcp_server, "_surface_for", lambda target: (surface, []))
    monkeypatch.setattr(mcp_server, "_session", lambda package: session)
    monkeypatch.setattr(mcp_server.emulator, "running_serial", lambda: "emulator-test")
    monkeypatch.setattr(mcp_server.evidence, "record", lambda *args, **kwargs: {})
    monkeypatch.setattr(mcp_server.ordinary, "build_companion",
                        lambda: ordinary.CompanionBuild("built", Path("companion.apk")))
    monkeypatch.setattr(mcp_server.ordinary, "install_companion",
                            lambda apk, serial: ordinary.CompanionInstall(
                                "installed", serial=serial, verified_build=True))
    received = []

    def fake_run_probe(request, *, serial, trusted_source):
        assert trusted_source is True
        received.append(request)
        return ordinary.OrdinaryResult(
            request.id, request.operation, request.target_package,
            "dispatched_unconfirmed",
            caller_package=ordinary.COMPANION_PACKAGE, caller_uid=12345,
            verified_ordinary_uid=True,
        )

    monkeypatch.setattr(mcp_server.ordinary, "run_probe", fake_run_probe)
    reply = mcp_server.handle(_call("verify_caller", {
        "target": "fixture", "component": component.name,
        "operation": "provider_call", "method": "getStatus",
    }), allow_mutating=True)
    assert not reply["result"].get("isError", False)
    assert received[0].operation == "provider_call"
    assert received[0].method == "getStatus"
    assert received[0].uri == "content://com.example.app.data"
