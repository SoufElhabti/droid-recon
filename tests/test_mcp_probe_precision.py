"""MCP dynamic actions use current APK evidence and record each probe's scope."""

from __future__ import annotations

import json
from types import SimpleNamespace

from droid_recon import mcp_server
from droid_recon.models import AttackSurface, Component, Observation
from droid_recon.session import Session


def _observation(component: Component, kind: str, identifier: str) -> Observation:
    return Observation(
        id=identifier, kind=kind, package="com.example.app",
        component=component.name, reachable_from=component.reachable_from,
        signal="ok", interesting=True,
    )


def _ipc_coverage(session: Session) -> list[dict]:
    return [
        json.loads(line) for line in session.coverage_path.read_text(
            encoding="utf-8").splitlines()
        if json.loads(line).get("stage") == "ipc"
    ]


def test_probe_replaces_stale_surface_and_records_tested_and_skipped(
        monkeypatch, tmp_path):
    first = Component(name="com.example.app.First", type="activity",
                      exported=True, reachable_from="third_party_app")
    limited = Component(name="com.example.app.Limited", type="activity",
                        exported=True, reachable_from="third_party_app")
    guarded = Component(name="com.example.app.Guarded", type="activity",
                        exported=False, reachable_from="none")
    current = AttackSurface(package="com.example.app", apk_sha256="new",
                            components=[first, limited, guarded])
    stale = AttackSurface(
        package=current.package, apk_sha256="old",
        components=[Component(name="com.example.app.Old", type="activity",
                              exported=True, reachable_from="third_party_app")])
    session = Session.open(current.package, tmp_path / "sessions")
    session.write_surface(stale)
    monkeypatch.setattr(mcp_server, "_surface_for", lambda target: (current, []))
    monkeypatch.setattr(mcp_server, "_session", lambda package: session)
    monkeypatch.setattr(mcp_server.emulator, "running_serial", lambda: "emulator-test")
    monkeypatch.setattr(mcp_server, "_agent", lambda: None)
    called = []
    monkeypatch.setattr(mcp_server.probes, "launch_activity",
                        lambda ctx, comp: called.append(comp.name) or
                        _observation(comp, "launch_activity", "O0001"))
    recorded = []
    monkeypatch.setattr(mcp_server.evidence, "record",
                        lambda *args, **kwargs: recorded.append((args, kwargs)))

    result = mcp_server._probe_ipc({"target": "fixture", "limit": 1})
    assert result["components_probed"] == 1
    assert called == [first.name]
    assert session.read_surface().apk_sha256 == "new"
    assert recorded[0][1] == {
        "serial": "emulator-test", "execution_context": "adb_shell"}
    assert recorded[0][0][1].apk_sha256 == "new"
    coverage = {entry["component"]: entry for entry in _ipc_coverage(session)}
    assert coverage[first.name]["status"] == "tested"
    assert coverage[first.name]["evidence_ids"] == ["O0001"]
    assert coverage[limited.name]["status"] == "skipped"
    assert coverage[guarded.name]["status"] == "skipped"
    assert stale.components[0].name not in coverage


def test_probe_does_not_use_code_paths_from_another_apk(monkeypatch, tmp_path):
    provider = Component(
        name="com.example.app.Provider", type="provider", exported=True,
        reachable_from="shell", read_reachable_from="shell",
        write_reachable_from="third_party_app", call_reachable_from="third_party_app",
        authorities=["com.example.app.data"],
    )
    surface = AttackSurface(package="com.example.app", apk_sha256="new",
                            components=[provider])
    session = Session.open(surface.package, tmp_path / "sessions")
    session.write_code_report({
        "apk_sha256": "old",
        "provider_paths": {"paths": {"com.example.app.data": ["stale-path"]},
                           "call_methods": ["staleMethod"]},
    })
    monkeypatch.setattr(mcp_server, "_surface_for", lambda target: (surface, []))
    monkeypatch.setattr(mcp_server, "_session", lambda package: session)
    monkeypatch.setattr(mcp_server.emulator, "running_serial", lambda: "emulator-test")
    monkeypatch.setattr(mcp_server, "_agent", lambda: None)
    monkeypatch.setattr(mcp_server.evidence, "record", lambda *args, **kwargs: {})
    seen = []

    def fake_query(ctx, comp, authority, path):
        seen.append(path)
        return _observation(comp, "query_provider", f"O{len(seen):04d}")

    monkeypatch.setattr(mcp_server.probes, "query_provider", fake_query)
    monkeypatch.setattr(
        mcp_server.probes, "call_provider",
        lambda *args: (_ for _ in ()).throw(AssertionError("stale call method used")))
    result = mcp_server._probe_ipc({"target": "fixture", "types": ["provider"]})
    assert result["components_probed"] == 1
    assert seen and "stale-path" not in seen


def test_triage_replaces_findings_on_repeat_and_uses_utf8(monkeypatch, tmp_path):
    surface = AttackSurface(package="com.example.app", apk_sha256="sha")
    session = Session.open(surface.package, tmp_path / "sessions")
    session.write_surface(surface)
    monkeypatch.setattr(mcp_server, "_session", lambda package: session)
    finding = SimpleNamespace(to_dict=lambda: {"id": "F0001", "title": "Café"})
    result = SimpleNamespace(
        findings=[finding], candidates=[], rejected=[],
        summary=lambda: {"finding_count": 1},
    )
    monkeypatch.setattr(mcp_server.triage_mod, "triage",
                        lambda surface, observations: result)
    mcp_server._triage({"package": surface.package})
    mcp_server._triage({"package": surface.package})
    lines = session.findings_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["title"] == "Café"


def test_get_report_reads_unicode_markdown(monkeypatch, tmp_path):
    surface = AttackSurface(package="com.example.app")
    session = Session.open(surface.package, tmp_path / "sessions")
    markdown = session.dir / "get_report.md"
    markdown.write_text("Café — tested", encoding="utf-8")
    monkeypatch.setattr(mcp_server, "_session", lambda package: session)
    monkeypatch.setattr(
        mcp_server.report_mod, "write",
        lambda sess: (markdown, sess.dir / "get_report.json", {"ok": True}),
    )
    assert mcp_server._get_report({"package": surface.package})["markdown"] == (
        "Café — tested")
