"""Pure protocol tests for the ordinary-UID companion (no Android SDK/device)."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from zipfile import ZipFile

import pytest

from droid_recon import shell
from droid_recon.device import ordinary
from droid_recon.models import Component, IntentFilter
from droid_recon.static import manifest


def _request(**overrides):
    fields = {"operation": "activity", "target_package": "com.example.target",
              "component": "com.example.target.PublicActivity",
              "id": "a" * 32}
    fields.update(overrides)
    return ordinary.ProbeRequest(**fields)


def _log(request, *, status="accepted_by_os", uid=10123, package=None):
    payload = {"id": request.id, "operation": request.operation, "status": status,
               "caller_uid": uid,
               "caller_package": package or ordinary.COMPANION_PACKAGE}
    return f"I/{ordinary.LOG_TAG}( 4321): {ordinary.RESULT_PREFIX}{json.dumps(payload)}\n"


def test_request_validation_rejects_malformed_class_and_bad_provider_uri():
    with pytest.raises(ValueError, match="fully qualified component"):
        _request(component="not-a-class").payload()
    with pytest.raises(ValueError, match="content://"):
        _request(operation="provider_query", component=None, uri="https://example.com").payload()
    with pytest.raises(ValueError, match="scheme"):
        _request(operation="deeplink", component=None, uri="/relative").payload()
    with pytest.raises(ValueError, match="32 lower-case hex"):
        _request(id="predictable").payload()


def test_request_for_manifest_component_uses_declared_action_and_uri():
    receiver = Component(name="com.example.target.R", type="receiver", exported=True,
                         intent_filters=[IntentFilter(actions=["com.example.ACTION"])])
    broadcast = ordinary.request_for_component("com.example.target", receiver)
    assert broadcast.operation == "broadcast"
    assert broadcast.action == "com.example.ACTION"

    provider = Component(name="com.example.target.P", type="provider", exported=True,
                         authorities=["com.example.provider"])
    query = ordinary.request_for_component("com.example.target", provider)
    assert query.uri == "content://com.example.provider"

    call = ordinary.request_for_component(
        "com.example.target", provider, operation="provider_call", method="getStatus")
    assert call.payload() == {
        "id": call.id, "operation": "provider_call",
        "target_package": "com.example.target",
        "component": "com.example.target.P",
        "uri": "content://com.example.provider", "method": "getStatus",
    }


def test_library_namespaced_activity_retains_explicit_target_package():
    component = Component(
        name="androidx.test.core.app.InstrumentationActivityInvoker$BootstrapActivity",
        type="activity", exported=True,
    )
    request = ordinary.request_for_component("com.watchguard.authpoint", component)
    payload = request.payload()
    assert payload["target_package"] == "com.watchguard.authpoint"
    assert payload["component"] == component.name

    # The companion fixes the ComponentName package separately from the class.
    source = (ordinary.DEFAULT_PROJECT / "app" / "src" / "main" / "java" /
              "org" / "droidrecon" / "companion" / "ProbeActivity.java").read_text()
    assert "new ComponentName(target, component)" in source
    assert "component.startsWith(target" not in source


def test_provider_call_requires_an_explicit_bounded_method():
    provider = Component(name="com.example.target.P", type="provider", exported=True,
                         authorities=["com.example.provider"])
    default = ordinary.request_for_component("com.example.target", provider)
    assert default.operation == "provider_query"
    assert "method" not in default.payload()
    with pytest.raises(ValueError, match="bounded method"):
        ordinary.request_for_component("com.example.target", provider,
                                       operation="provider_call").payload()
    with pytest.raises(ValueError, match="bounded method"):
        ordinary.request_for_component("com.example.target", provider,
                                       operation="provider_call", method="x" * 257).payload()
    with pytest.raises(ValueError, match="bounded method"):
        ordinary.request_for_component("com.example.target", provider,
                                       operation="provider_call", method="x\n").payload()
    with pytest.raises(ValueError, match="only valid"):
        ordinary.request_for_component("com.example.target", provider,
                                       method="getStatus").payload()
    with pytest.raises(ValueError, match="provider component"):
        ordinary.request_for_component(
            "com.example.target",
            Component(name="com.example.target.A", type="activity", exported=True),
            operation="provider_call", method="getStatus")


def test_provider_call_result_records_only_presence_of_returned_bundle():
    request = _request(operation="provider_call", component=None,
                       uri="content://com.example.provider", method="getStatus")
    payload = {"id": request.id, "operation": request.operation,
               "status": "accepted_by_os", "caller_uid": 10123,
               "caller_package": ordinary.COMPANION_PACKAGE,
               "has_result": True, "secret": "must not be copied"}
    result = ordinary._parse_result(
        f"I/{ordinary.LOG_TAG}: {ordinary.RESULT_PREFIX}{json.dumps(payload)}", request,
        trusted_source=True)
    assert result is not None
    assert result.accessible is True
    assert result.detail == {"has_result": True}


def test_result_requires_matching_nonce_operation_package_and_application_uid():
    request = _request()
    stale = _log(_request(id="b" * 32))
    result = ordinary._parse_result(stale + _log(request), request, trusted_source=True)
    assert result is not None
    assert result.verified_ordinary_uid is True
    assert result.accessible is True
    assert result.to_dict()["evidence_status"] == "OBSERVED_ORDINARY_UID"

    spoofed = ordinary._parse_result(_log(request, uid=2000), request,
                                     trusted_source=True)
    assert spoofed is not None
    assert spoofed.verified_ordinary_uid is False
    assert spoofed.accessible is None

    wrong_package = ordinary._parse_result(_log(request, package="com.other"), request,
                                           trusted_source=True)
    assert wrong_package is not None and wrong_package.verified_ordinary_uid is False

    untrusted = ordinary._parse_result(_log(request), request)
    assert untrusted is not None
    assert untrusted.verified_ordinary_uid is False
    assert untrusted.accessible is None
    assert untrusted.detail["reason"] == "unverified_companion_build"


@pytest.mark.parametrize("status,expected", [
    ("queried", True), ("denied", False), ("not_found", False),
    ("dispatched_unconfirmed", None), ("null_cursor_unconfirmed", None),
    ("timeout", None), ("blocked_by_platform", None),
])
def test_accessible_result_states_are_bounded(status, expected):
    request = _request()
    result = ordinary._parse_result(_log(request, status=status), request,
                                    trusted_source=True)
    assert result is not None
    assert result.accessible is expected


def test_run_probe_launches_only_companion_and_reads_nonce_matched_result(monkeypatch):
    request = _request()
    calls = []

    def fake_shell(argv, *, serial, timeout):
        calls.append(("shell", argv, serial))
        if argv[:2] == ["getprop", "ro.kernel.qemu"]:
            return shell.Proc(argv, 0, "1\n", "")
        if argv[:2] == ["pm", "path"]:
            return shell.Proc(argv, 0, "package:/data/app/org.droidrecon.companion/base.apk\n", "")
        return shell.Proc(argv, 0, "Starting: Intent {...}\nStatus: ok\n", "")

    def fake_adb(*args, serial, timeout):
        calls.append(("adb", args, serial))
        return shell.Proc(list(args), 0, _log(request), "")

    monkeypatch.setattr(ordinary.shell, "adb_shell", fake_shell)
    monkeypatch.setattr(ordinary.shell, "adb", fake_adb)
    result = ordinary.run_probe(request, serial="emulator-5554", trusted_source=True)
    assert result.accessible is True
    launch = next(argv for kind, argv, _ in calls if kind == "shell" and argv[:2] == ["am", "start"])
    assert launch[4] == ordinary.COMPANION_ACTIVITY
    decoded = json.loads(base64.urlsafe_b64decode(launch[-1]))
    assert decoded == request.payload()
    assert all(ordinary.COMPANION_PACKAGE in " ".join(map(str, argv))
               for kind, argv, _ in calls if kind == "shell" and argv[0] == "am")
    assert any(kind == "adb" and argv[0] == "logcat" for kind, argv, _ in calls)


def test_physical_device_is_rejected_before_install_or_probe(monkeypatch, tmp_path):
    def getprop(argv, *, serial, timeout):
        return shell.Proc(argv, 0, "0\n", "")

    monkeypatch.setattr(ordinary.shell, "adb_shell", getprop)
    with pytest.raises(ValueError, match="not an Android emulator"):
        ordinary.run_probe(_request(), serial="physical-serial")
    with pytest.raises(ValueError, match="not an Android emulator"):
        ordinary.install_companion(tmp_path / "app.apk", serial="physical-serial")


def test_install_does_not_autogrant_permissions(monkeypatch, tmp_path):
    apk = tmp_path / "app.apk"
    with ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"fixture")
    monkeypatch.setattr(manifest, "dump_manifest_xml", lambda apk, timeout: (
        '<manifest package="org.droidrecon.companion" />'))
    calls = []

    def fake_shell(argv, *, serial, timeout):
        if argv[0] == "getprop":
            return shell.Proc(argv, 0, "1\n", "")
        return shell.Proc(argv, 0, "package:/data/app/base.apk\n", "")

    def fake_adb(*args, serial, timeout):
        calls.append(args)
        return shell.Proc(list(args), 0, "Success\n", "")

    monkeypatch.setattr(ordinary.shell, "adb_shell", fake_shell)
    monkeypatch.setattr(ordinary.shell, "adb", fake_adb)
    installed = ordinary.install_companion(apk, serial="emulator-5554")
    assert installed.status == "installed"
    assert installed.verified_build is False
    assert calls == [("install", "-r", str(apk))]


@pytest.mark.parametrize("unsafe_manifest,reason", [
    ('<manifest package="com.other" />', "must declare package"),
    ('<manifest package="org.droidrecon.companion"><uses-permission '
     'android:name="android.permission.INTERNET" /></manifest>', "no Android permissions"),
    ('<manifest package="org.droidrecon.companion" '
     'android:sharedUserId="android.uid.system" />', "shared user ID"),
])
def test_install_rejects_wrong_package_permissions_and_shared_uid(
    monkeypatch, tmp_path, unsafe_manifest, reason,
):
    apk = tmp_path / "unsafe.apk"
    with ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"fixture")
    xml = ('<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
           + unsafe_manifest.split("<manifest ", 1)[1])
    monkeypatch.setattr(manifest, "dump_manifest_xml", lambda apk, timeout: xml)
    monkeypatch.setattr(ordinary, "_emulator_serial", lambda serial: "emulator-5554")
    monkeypatch.setattr(ordinary.shell, "adb", lambda *a, **kw: pytest.fail(
        "unsafe APK must not be installed"))
    installed = ordinary.install_companion(apk, serial="emulator-5554")
    assert installed.status == "failed"
    assert reason in installed.message


def test_known_source_build_hash_is_trusted_only_for_default_project(tmp_path):
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"source build")
    digest = ordinary._apk_sha256(apk)
    ordinary._TRUSTED_SOURCE_BUILD_SHA256S.discard(digest)
    ordinary._remember_source_build(apk, tmp_path)
    assert digest not in ordinary._TRUSTED_SOURCE_BUILD_SHA256S
    ordinary._remember_source_build(apk, ordinary.DEFAULT_PROJECT)
    assert digest in ordinary._TRUSTED_SOURCE_BUILD_SHA256S
    ordinary._TRUSTED_SOURCE_BUILD_SHA256S.discard(digest)


def test_exact_allowlisted_release_hash_can_verify_prebuilt(monkeypatch, tmp_path):
    apk = tmp_path / "release.apk"
    with ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"fixture")
    digest = ordinary._apk_sha256(apk)
    monkeypatch.setattr(ordinary, "TRUSTED_RELEASE_APK_SHA256S", frozenset({digest}))
    monkeypatch.setattr(manifest, "dump_manifest_xml", lambda apk, timeout: pytest.fail(
        "exact release hash should not require SDK manifest decoding"))
    monkeypatch.setattr(ordinary, "_emulator_serial", lambda serial: "emulator-5554")
    monkeypatch.setattr(ordinary.shell, "adb", lambda *a, **kw: shell.Proc(
        list(a), 0, "Success\n", ""))
    monkeypatch.setattr(ordinary.shell, "adb_shell", lambda *a, **kw: shell.Proc(
        list(a), 0, "package:/data/app/org.droidrecon.companion/base.apk\n", ""))
    installed = ordinary.install_companion(apk, serial="emulator-5554")
    assert installed.status == "installed"
    assert installed.verified_build is True


def test_release_allowlist_retains_prior_and_rebuilt_companion():
    assert {
        "3650e010fcbd6f9d20dce74cfcd1ad0ec8660b63fe34f18f70c08fae15e5fc39",
        "0f180ca373830769fd9a50a240e00da575148ca2aefc6248e6dfdbd4057823bf",
    } <= ordinary.TRUSTED_RELEASE_APK_SHA256S


def test_companion_source_declares_no_permissions_or_network_calls():
    root = ordinary.DEFAULT_PROJECT
    manifest = (root / "app" / "src" / "main" / "AndroidManifest.xml").read_text()
    source = (root / "app" / "src" / "main" / "java" / "org" / "droidrecon"
              / "companion" / "ProbeActivity.java").read_text()
    assert "uses-permission" not in manifest
    assert "ContentResolver().insert" not in source
    assert "getContentResolver().update" not in source
    assert "getContentResolver().delete" not in source
    assert "getContentResolver().call(" in source
    assert "uri.getAuthority(), method, null, null" in source
    assert "java.net." not in source
