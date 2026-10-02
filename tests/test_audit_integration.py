"""CLI audit run boundaries and phase orchestration without an Android device."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from zipfile import ZipFile

import pytest

from droid_recon import cli, runs
from droid_recon.device import ordinary
from droid_recon.models import AttackSurface, Component, IntentFilter, Observation, SessionState
from droid_recon.session import Session
from droid_recon.static import manifest, sweep


def _apk(tmp_path: Path) -> Path:
    apk = tmp_path / "target.apk"
    with ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", "test fixture")
    return apk


def _surface(apks) -> AttackSurface:
    apk = Path(apks[0])
    digest = hashlib.sha256(apk.read_bytes()).hexdigest()
    return AttackSurface(
        package="com.example.target", apk_paths=[str(apk)], apk_sha256=digest,
        apk_sha256s={str(apk): digest},
        components=[Component(name="com.example.target.PublicActivity",
                              type="activity", exported=True,
                              reachable_from="third_party_app")],
    )


def _args(tmp_path: Path, apk: Path, *extra: str):
    return cli.build_parser().parse_args(
        ["--sessions", str(tmp_path / "sessions"), "audit", str(apk),
         "--no-resources", "--no-storage", "--no-install", *extra]
    )


def _fake_phases(monkeypatch, calls: list[str]):
    monkeypatch.setattr(cli.manifest, "analyze", _surface)

    def session_for(args):
        return Session.open("com.example.target", Path(args.sessions))

    def static(args):
        calls.append("static")
        print('{"intermediate": "static"}')
        session = session_for(args)
        session.begin_coverage_run()
        session.write_surface(_surface([args.target]))
        state = session.load_state() or SessionState("fixture", "com.example.target")
        session.mark_step(state, "static")
        return 0

    def code(args):
        calls.append("code")
        session = session_for(args)
        session.write_code_report({"files_scanned": 1})
        state = session.load_state()
        session.mark_step(state, "code")
        return 0

    def dynamic(args):
        calls.append("dynamic")
        session = session_for(args)
        state = session.load_state()
        session.mark_step(state, "probes")
        return 0

    monkeypatch.setattr(cli, "cmd_static", static)
    monkeypatch.setattr(cli, "cmd_code", code)
    monkeypatch.setattr(cli, "cmd_dynamic", dynamic)
    monkeypatch.setattr(cli, "cmd_triage", lambda args: calls.append("triage") or 0)
    monkeypatch.setattr(cli, "cmd_report", lambda args: calls.append("report") or 0)


def test_new_run_without_device_records_gap_and_resume_reuses_run(tmp_path, monkeypatch,
                                                                 capsys):
    apk = _apk(tmp_path)
    calls: list[str] = []
    _fake_phases(monkeypatch, calls)
    monkeypatch.setattr(cli.emulator, "running_serial", lambda: None)
    monkeypatch.setattr(cli.emulator, "boot", lambda *a, **kw: None)

    first = _args(tmp_path, apk, "--skip-code")
    assert cli.cmd_audit(first) == 0
    assert capsys.readouterr().out == "", "mocked final report is the only stdout producer"
    assert calls == ["static", "report"]
    session = Session.open("com.example.target", Path(first.sessions))
    run_before = json.loads((session.dir / "run_manifest.json").read_text())
    matrix = session.coverage_summary()
    assert any(e["stage"] == "ipc" and e["status"] == "failed" and
               e["result_state"] == "BLOCKED" for e in matrix["entries"])
    assert not (session.dir / "runs").exists(), "first run must not archive itself"

    resumed = _args(tmp_path, apk, "--skip-code", "--resume")
    assert cli.cmd_audit(resumed) == 0
    assert calls == ["static", "report", "report"], "completed static phase must not repeat"
    run_after = json.loads((session.dir / "run_manifest.json").read_text())
    assert run_after["run_id"] == run_before["run_id"]
    assert not (session.dir / "runs").exists(), "resume must not archive active artifacts"


def test_new_run_archives_previous_artifacts_and_changed_apk_blocks_resume(
    tmp_path, monkeypatch,
):
    apk = _apk(tmp_path)
    calls: list[str] = []
    _fake_phases(monkeypatch, calls)
    monkeypatch.setattr(cli.emulator, "running_serial", lambda: None)
    monkeypatch.setattr(cli.emulator, "boot", lambda *a, **kw: None)
    args = _args(tmp_path, apk, "--skip-code")
    assert cli.cmd_audit(args) == 0
    session = Session.open("com.example.target", Path(args.sessions))
    first = json.loads((session.dir / "run_manifest.json").read_text())
    assert cli.cmd_audit(_args(tmp_path, apk, "--skip-code")) == 0
    second = json.loads((session.dir / "run_manifest.json").read_text())
    assert second["run_id"] != first["run_id"]
    archives = list((session.dir / "runs").iterdir())
    assert len(archives) == 1
    assert json.loads((archives[0] / "run_manifest.json").read_text())["run_id"] == first["run_id"]

    with ZipFile(apk, "a") as archive:
        archive.writestr("classes.dex", b"changed")
    with pytest.raises(SystemExit) as error:
        cli.cmd_audit(_args(tmp_path, apk, "--skip-code", "--resume"))
    assert error.value.code == 6
    assert json.loads((session.dir / "run_manifest.json").read_text())["run_id"] == second["run_id"]


def test_deep_audit_runs_extra_stages_and_resume_skips_completed_phases(
    tmp_path, monkeypatch,
):
    apk = _apk(tmp_path)
    calls: list[str] = []
    _fake_phases(monkeypatch, calls)
    monkeypatch.setattr(cli.emulator, "running_serial", lambda: "emulator-5554")
    monkeypatch.setattr(cli.emulator, "become_root", lambda serial: calls.append("root") or True)
    monkeypatch.setattr(cli.bootstrap, "launch_app", lambda pkg, serial: calls.append("launch"))
    monkeypatch.setattr(cli.explorer.Credentials, "load", lambda path: type("Creds", (), {"present": False})())
    monkeypatch.setattr(cli.explorer, "explore", lambda *a, **kw: {"screens": []})
    monkeypatch.setattr(cli, "cmd_exploit", lambda args: calls.append("exploit") or 0)
    monkeypatch.setattr(cli, "cmd_verify_caller", lambda args: calls.append("ordinary") or 0)
    monkeypatch.setattr(cli, "cmd_chains", lambda args: calls.append("chains") or 0)

    first = _args(tmp_path, apk, "--deep")
    assert cli.cmd_audit(first) == 0
    assert calls == ["static", "code", "root", "dynamic", "exploit", "ordinary",
                     "launch", "chains", "triage", "report"]
    session = Session.open("com.example.target", Path(first.sessions))
    assert (session.dir / "screen_graph.json").is_file()
    assert first.serial == "emulator-5554"

    calls.clear()
    assert cli.cmd_audit(_args(tmp_path, apk, "--deep", "--resume")) == 0
    assert "static" not in calls and "code" not in calls and "dynamic" not in calls
    assert "exploit" not in calls and "ordinary" not in calls and "chains" not in calls


def test_completed_resume_replays_report_without_duplicate_artifacts(
    tmp_path, monkeypatch, capsys,
):
    apk = _apk(tmp_path)
    calls: list[str] = []
    real_triage, real_report = cli.cmd_triage, cli.cmd_report
    _fake_phases(monkeypatch, calls)

    def dynamic(args):
        calls.append("dynamic")
        session = Session.open("com.example.target", Path(args.sessions))
        session.evidence_path.write_text(json.dumps({
            "package": "com.example.target", "apks": [],
            "execution_contexts": ["adb_shell"], "sdk": {"device": 35},
        }), encoding="utf-8")
        session.add_observation(Observation(
            id="O0001", kind="launch_activity", package="com.example.target",
            component="com.example.target.PublicActivity",
            reachable_from="third_party_app", signal="crash", interesting=True,
            command=["am", "start"], logcat_excerpt=(
                "FATAL EXCEPTION: main\n"
                "at com.example.target.PublicActivity.onCreate(PublicActivity.java:42)"),
        ))
        session.record_coverage("ipc", "tested",
                                component="com.example.target.PublicActivity",
                                result_state="OBSERVED", evidence_ids=["O0001"])
        session.mark_step(session.load_state(), "probes")
        return 0

    monkeypatch.setattr(cli, "cmd_dynamic", dynamic)
    monkeypatch.setattr(cli, "cmd_triage", real_triage)
    monkeypatch.setattr(cli, "cmd_report", real_report)
    monkeypatch.setattr(cli.emulator, "running_serial", lambda: "emulator-5554")
    monkeypatch.setattr(cli.emulator, "become_root", lambda serial: calls.append("root") or True)

    first = _args(tmp_path, apk, "--skip-code")
    assert cli.cmd_audit(first) == 0
    capsys.readouterr()
    session = Session.open("com.example.target", Path(first.sessions))
    assert session.count_findings() == 1
    assert "audit" in session.load_state().steps_done
    names = ("observations.jsonl", "findings.jsonl", "coverage.jsonl",
             "evidence_manifest.json", "triage_candidates.json", "report.json",
             "report.md", "state.json")
    before = {name: (session.dir / name).read_bytes() for name in names}

    calls.clear()
    resumed = _args(tmp_path, apk, "--skip-code", "--resume", "--format", "json")
    assert cli.cmd_audit(resumed) == 0
    replayed = json.loads(capsys.readouterr().out)
    assert replayed == json.loads(before["report.json"])
    assert calls == [], "a completed resume must not touch the device or rerun phases"
    assert {name: (session.dir / name).read_bytes() for name in names} == before


def test_dynamic_passes_complete_provider_path_report_to_prober(tmp_path, monkeypatch):
    apk = _apk(tmp_path)
    surface = _surface([apk])
    surface.components = [Component(
        name="com.example.target.OpenProvider", type="provider", exported=True,
        reachable_from="third_party_app", authorities=["com.example.target.provider"],
    )]
    provider_paths = {
        "paths": {"com.example.target.provider": ["items/#"]},
        "floating_paths": ["unresolved/path"],
        "call_methods": ["readStatus"],
    }
    session = Session.open(surface.package, tmp_path / "sessions")
    session.write_surface(surface)
    session.write_code_report({"provider_paths": provider_paths})
    seen = []

    monkeypatch.setattr(cli.manifest, "analyze", lambda apks: surface)
    monkeypatch.setattr(cli.evidence, "record", lambda *a, **kw: {})
    monkeypatch.setattr(cli, "ensure_agent", lambda *a, **kw: None)
    monkeypatch.setattr(cli.install, "stop", lambda *a, **kw: None)
    monkeypatch.setattr(cli, "_probe_provider",
                        lambda ctx, sess, comp, paths, args: seen.append(paths))
    args = cli.build_parser().parse_args([
        "--sessions", str(tmp_path / "sessions"), "dynamic", str(apk),
        "--serial", "emulator-5554", "--no-install", "--no-storage", "--no-logcat",
    ])
    assert cli.cmd_dynamic(args) == 0
    assert seen == [provider_paths]


@pytest.mark.parametrize("signal,detail,reason_fragment", [
    ("crash", {"crash_origin": "app_initialization"}, "app initialization crashed"),
    ("error", {"command_rejected": "Error: app is in background uid"},
     "OS rejected the probe command"),
])
def test_dynamic_marks_component_logic_blocked_before_dispatch(
    tmp_path, monkeypatch, signal, detail, reason_fragment,
):
    apk = _apk(tmp_path)
    surface = _surface([apk])
    session = Session.open(surface.package, tmp_path / "sessions")
    session.write_surface(surface)
    monkeypatch.setattr(cli.manifest, "analyze", lambda apks: surface)
    monkeypatch.setattr(cli.evidence, "record", lambda *a, **kw: {})
    monkeypatch.setattr(cli, "ensure_agent", lambda *a, **kw: None)
    monkeypatch.setattr(cli.install, "stop", lambda *a, **kw: None)

    def blocked_probe(ctx, sess, comp, args):
        sess.add_observation(Observation(
            id="O0001", kind="launch_activity", package=surface.package,
            component=comp.name, reachable_from="third_party_app", signal=signal,
            interesting=False, detail=detail,
            logcat_excerpt="Unable to get provider com.google.firebase.provider.FirebaseInitProvider",
        ))

    monkeypatch.setattr(cli, "_probe_activity", blocked_probe)
    args = cli.build_parser().parse_args([
        "--sessions", str(tmp_path / "sessions"), "dynamic", str(apk),
        "--serial", "emulator-5554", "--no-install", "--no-storage", "--no-logcat",
    ])
    assert cli.cmd_dynamic(args) == 0
    rows = [r for r in session.coverage_summary()["entries"] if r["stage"] == "ipc"]
    assert len(rows) == 1
    assert rows[0]["status"] == "failed" and rows[0]["result_state"] == "BLOCKED"
    assert rows[0]["evidence_ids"] == ["O0001"]
    assert reason_fragment in rows[0]["reason"]
    assert "before component code" in rows[0]["reason"]
    assert session.count_observations() == 1


def test_verify_caller_provider_call_runs_only_for_explicit_method(tmp_path, monkeypatch):
    apk = _apk(tmp_path)
    surface = _surface([apk])
    surface.components = [Component(
        name="com.example.target.OpenProvider", type="provider", exported=True,
        reachable_from="third_party_app", authorities=["com.example.target.provider"],
    )]
    seen = []
    monkeypatch.setattr(cli.manifest, "analyze", lambda apks: surface)
    monkeypatch.setattr(cli, "_pick_serial", lambda args: "emulator-5554")
    monkeypatch.setattr(cli.ordinary, "build_companion",
                        lambda: ordinary.CompanionBuild("built", apk))
    monkeypatch.setattr(cli.ordinary, "install_companion",
                        lambda apk, serial: ordinary.CompanionInstall("installed", serial=serial))
    monkeypatch.setattr(cli.ordinary, "run_probe", lambda request, **kwargs: (
        seen.append(request) or ordinary.OrdinaryResult(
            request.id, request.operation, request.target_package, "denied",
            caller_package=ordinary.COMPANION_PACKAGE, caller_uid=10123,
            verified_ordinary_uid=True)))
    monkeypatch.setattr(cli.evidence, "record", lambda *a, **kw: {})
    base = ["--sessions", str(tmp_path / "sessions"), "verify-caller", str(apk),
            "--type", "provider"]

    assert cli.cmd_verify_caller(cli.build_parser().parse_args(base)) == 0
    assert [(request.operation, request.method) for request in seen] == [
        ("provider_query", None)]

    seen.clear()
    assert cli.cmd_verify_caller(cli.build_parser().parse_args(
        [*base, "--provider-method", "getStatus"])) == 0
    assert [(request.operation, request.method) for request in seen] == [
        ("provider_query", None), ("provider_call", "getStatus")]
    assert seen[1].payload()["uri"] == "content://com.example.target.provider"

    audit = _args(tmp_path, apk, "--deep", "--provider-method", "getStatus")
    assert audit.provider_method == ["getStatus"]


def test_verify_caller_deeplink_result_is_package_scoped(tmp_path, monkeypatch):
    apk = _apk(tmp_path)
    surface = _surface([apk])
    surface.components[0].intent_filters = [IntentFilter(
        actions=["android.intent.action.VIEW"],
        categories=["android.intent.category.BROWSABLE"],
        data=[{"scheme": "https", "host": "example.com", "path": "/open"}],
    )]
    monkeypatch.setattr(cli.manifest, "analyze", lambda apks: surface)
    monkeypatch.setattr(cli, "_pick_serial", lambda args: "emulator-5554")
    monkeypatch.setattr(cli.ordinary, "build_companion",
                        lambda: ordinary.CompanionBuild("built", apk))
    monkeypatch.setattr(cli.ordinary, "install_companion",
                        lambda apk, serial: ordinary.CompanionInstall(
                            "installed", serial=serial, verified_build=True))
    monkeypatch.setattr(cli.ordinary, "run_probe", lambda request, **kwargs:
                        ordinary.OrdinaryResult(
                            request.id, request.operation, request.target_package,
                            "accepted_by_os", caller_package=ordinary.COMPANION_PACKAGE,
                            caller_uid=10123, verified_ordinary_uid=True))
    monkeypatch.setattr(cli.evidence, "record", lambda *a, **kw: {})
    args = cli.build_parser().parse_args([
        "--sessions", str(tmp_path / "sessions"), "verify-caller", str(apk),
        "--type", "activity",
    ])
    assert cli.cmd_verify_caller(args) == 0
    artifact = Session.open(surface.package, tmp_path / "sessions").dir / "ordinary_results.jsonl"
    results = [json.loads(line) for line in artifact.read_text(encoding="utf-8").splitlines()]
    link = next(result for result in results if result["operation"] == "deeplink")
    assert link["component"] is None
    assert link["declared_component"] == surface.components[0].name
    assert link["resolution_scope"] == "package"


def test_verify_caller_resume_retries_only_failed_component(tmp_path, monkeypatch):
    apk = _apk(tmp_path)
    surface = _surface([apk])
    surface.components.append(Component(
        name="com.example.target.OtherActivity", type="activity", exported=True,
        reachable_from="third_party_app",
    ))
    monkeypatch.setattr(cli.manifest, "analyze", lambda apks: surface)
    monkeypatch.setattr(cli, "_pick_serial", lambda args: "emulator-5554")
    monkeypatch.setattr(cli.ordinary, "build_companion",
                        lambda: ordinary.CompanionBuild("built", apk))
    monkeypatch.setattr(cli.ordinary, "install_companion",
                        lambda apk, serial: ordinary.CompanionInstall(
                            "installed", serial=serial, verified_build=True))
    monkeypatch.setattr(cli.evidence, "record", lambda *a, **kw: {})
    calls = []

    def probe(request, **kwargs):
        calls.append(request.component)
        if request.component.endswith("PublicActivity") and calls.count(request.component) == 1:
            raise OSError("temporary logcat failure")
        return ordinary.OrdinaryResult(
            request.id, request.operation, request.target_package, "denied",
            caller_package=ordinary.COMPANION_PACKAGE, caller_uid=10123,
            verified_ordinary_uid=True,
        )

    monkeypatch.setattr(cli.ordinary, "run_probe", probe)
    args = cli.build_parser().parse_args([
        "--sessions", str(tmp_path / "sessions"), "verify-caller", str(apk),
    ])
    assert cli.cmd_verify_caller(args) == 6
    assert calls == ["com.example.target.PublicActivity", "com.example.target.OtherActivity"]
    args.resume = True  # audit --resume uses the same command object
    assert cli.cmd_verify_caller(args) == 0
    assert calls == ["com.example.target.PublicActivity", "com.example.target.OtherActivity",
                     "com.example.target.PublicActivity"]


_WRITE_OPEN_PROVIDER = '''
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
          package="com.example.target">
  <uses-sdk android:targetSdkVersion="34" />
  <permission android:name="com.example.target.READ" android:protectionLevel="signature" />
  <application>
    <provider android:name=".OpenWrites" android:exported="true"
              android:authorities="com.example.target.open"
              android:readPermission="com.example.target.READ" />
  </application>
</manifest>
'''


def test_write_open_provider_is_not_dismissed_as_unreachable():
    surface = manifest.parse_manifest(_WRITE_OPEN_PROVIDER)
    provider = surface.components[0]
    assert provider.provider_reach("read") == "none"
    assert provider.provider_reach("write") == "third_party_app"
    assert provider.provider_reach("call") == "third_party_app"
    assert sweep.verdict(surface).startswith("INVESTIGATE")


def test_dynamic_targets_provider_with_guarded_read_but_open_call(
    tmp_path, monkeypatch,
):
    apk = _apk(tmp_path)
    surface = manifest.parse_manifest(_WRITE_OPEN_PROVIDER)
    digest = hashlib.sha256(apk.read_bytes()).hexdigest()
    surface.apk_paths = [str(apk)]
    surface.apk_sha256 = digest
    surface.apk_sha256s = {str(apk): digest}
    session = Session.open(surface.package, tmp_path / "sessions")
    session.write_surface(surface)
    session.write_code_report({"provider_paths": {
        "paths": {}, "floating_paths": [], "call_methods": ["getStatus"],
    }})
    seen = []
    monkeypatch.setattr(cli.manifest, "analyze", lambda apks: surface)
    monkeypatch.setattr(cli.evidence, "record", lambda *a, **kw: {})
    monkeypatch.setattr(cli, "ensure_agent", lambda *a, **kw: None)
    monkeypatch.setattr(cli.install, "stop", lambda *a, **kw: None)
    monkeypatch.setattr(cli, "_probe_provider",
                        lambda ctx, sess, comp, paths, args: seen.append(comp.name))
    args = cli.build_parser().parse_args([
        "--sessions", str(tmp_path / "sessions"), "dynamic", str(apk),
        "--serial", "emulator-5554", "--no-install", "--no-storage", "--no-logcat",
    ])
    assert cli.cmd_dynamic(args) == 0
    assert seen == ["com.example.target.OpenWrites"]


@pytest.mark.parametrize("changed", [
    {"no_resources": False},
    {"max_screens": 100},
    {"max_depth": 8},
    {"serial": "emulator-5556"},
])
def test_resume_rejects_changed_audit_coverage_options(tmp_path, changed):
    apk = _apk(tmp_path)
    surface = _surface([apk])
    session = Session.open(surface.package, tmp_path / "sessions")
    original = _args(tmp_path, apk, "--deep", "--serial", "emulator-5554")
    runs.prepare(session, surface, original, resume=False)
    resumed = _args(tmp_path, apk, "--deep", "--serial", "emulator-5554", "--resume")
    for key, value in changed.items():
        setattr(resumed, key, value)
    with pytest.raises(ValueError, match="differ"):
        runs.prepare(session, surface, resumed, resume=True)


def test_resume_rejects_changed_companion_apk_at_same_path(tmp_path):
    apk = _apk(tmp_path)
    surface = _surface([apk])
    session = Session.open(surface.package, tmp_path / "sessions")
    companion = tmp_path / "companion.apk"
    companion.write_bytes(b"first build")
    original = _args(tmp_path, apk, "--deep", "--companion-apk", str(companion))
    runs.prepare(session, surface, original, resume=False)
    companion.write_bytes(b"changed build")
    resumed = _args(tmp_path, apk, "--deep", "--companion-apk", str(companion), "--resume")
    with pytest.raises(ValueError, match="differ"):
        runs.prepare(session, surface, resumed, resume=True)
