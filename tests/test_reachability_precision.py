"""Manifest reachability must match the operation that an observation exercises."""

from __future__ import annotations

from types import SimpleNamespace

from droid_recon.device import probes
from droid_recon.models import AttackSurface, classify_reach
from droid_recon.static.manifest import parse_manifest


NS = 'xmlns:android="http://schemas.android.com/apk/res/android"'


def manifest(body: str, *, app_attrs: str = "") -> str:
    return (f'<manifest {NS} package="com.example.precision">'
            '<permission android:name="com.example.precision.STRONG" '
            'android:protectionLevel="signature"/>'
            f'<application {app_attrs}>{body}</application></manifest>')


def component(surface, tail: str):
    return next(c for c in surface.components if c.name.endswith(tail))


def test_disabled_component_and_application_never_count_as_reachable():
    xml = manifest(
        '<activity android:name=".Off" android:exported="true" '
        'android:enabled="false"/>'
        '<activity android:name=".On" android:exported="true"/>')
    surface = parse_manifest(xml)
    assert component(surface, ".Off").reachable_from == "none"
    assert component(surface, ".Off").issues == []
    assert component(surface, ".On").reachable_from == "third_party_app"
    assert surface.summary()["reachable_third_party"] == 1

    disabled_app = parse_manifest(manifest(
        '<activity android:name=".ExplicitOn" android:exported="true" '
        'android:enabled="true"/>', app_attrs='android:enabled="false"'))
    assert component(disabled_app, ".ExplicitOn").enabled is False
    assert component(disabled_app, ".ExplicitOn").reachable_from == "none"
    assert classify_reach(exported=False, enabled=False, permission=None,
                          permission_protection=None) == "none"


def test_browser_reach_requires_view_browsable_scheme_and_activity():
    xml = manifest(
        '<activity android:name=".Valid" android:exported="true">'
        '<intent-filter><action android:name="android.intent.action.VIEW"/>'
        '<category android:name="android.intent.category.BROWSABLE"/>'
        '<data android:scheme="https" android:host="example.test"/></intent-filter>'
        '</activity>'
        '<activity android:name=".NoView" android:exported="true">'
        '<intent-filter><action android:name="android.intent.action.SEND"/>'
        '<category android:name="android.intent.category.BROWSABLE"/>'
        '<data android:scheme="https"/></intent-filter></activity>'
        '<activity android:name=".NoBrowse" android:exported="true">'
        '<intent-filter><action android:name="android.intent.action.VIEW"/>'
        '<data android:scheme="https"/></intent-filter></activity>'
        '<activity android:name=".NoScheme" android:exported="true">'
        '<intent-filter><action android:name="android.intent.action.VIEW"/>'
        '<category android:name="android.intent.category.BROWSABLE"/>'
        '<data android:host="example.test"/></intent-filter></activity>'
        '<receiver android:name=".Receiver" android:exported="true">'
        '<intent-filter><action android:name="android.intent.action.VIEW"/>'
        '<category android:name="android.intent.category.BROWSABLE"/>'
        '<data android:scheme="https"/></intent-filter></receiver>')
    surface = parse_manifest(xml)
    valid = component(surface, ".Valid")
    assert valid.reachable_from == "browser"
    assert valid.deeplinks() == ["https://example.test"]
    for tail in (".NoView", ".NoBrowse", ".NoScheme", ".Receiver"):
        c = component(surface, tail)
        assert c.reachable_from == "third_party_app"
        assert c.browsable is False
    assert component(surface, ".NoView").deeplinks() == []
    assert component(surface, ".NoBrowse").deeplinks() == []
    assert component(surface, ".NoScheme").deeplinks() == []


def test_provider_read_write_and_call_reach_are_distinct_and_serialized():
    xml = manifest(
        '<provider android:name=".ReadLocked" android:exported="true" '
        'android:authorities="com.example.precision.read" '
        'android:readPermission="com.example.precision.STRONG"/>'
        '<provider android:name=".WriteLocked" android:exported="true" '
        'android:authorities="com.example.precision.write" '
        'android:writePermission="com.example.precision.STRONG"/>')
    surface = parse_manifest(xml)
    read_locked = component(surface, ".ReadLocked")
    write_locked = component(surface, ".WriteLocked")
    assert read_locked.reachable_from == "none"  # legacy field stays read reach
    assert read_locked.provider_reach("read") == "none"
    assert read_locked.provider_reach("write") == "third_party_app"
    assert read_locked.provider_reach("call") == "third_party_app"
    assert write_locked.provider_reach("read") == "third_party_app"
    assert write_locked.provider_reach("write") == "none"
    assert surface.summary()["providers_read_reachable"] == 1
    assert surface.summary()["providers_write_reachable"] == 1

    restored = AttackSurface.from_dict(surface.to_dict())
    assert component(restored, ".ReadLocked").provider_reach("write") == "third_party_app"
    old = read_locked.to_dict()
    old.pop("read_reachable_from")
    old.pop("write_reachable_from")
    old.pop("call_reachable_from")
    assert type(read_locked).from_dict(old).provider_reach("write") == "none"


def test_provider_observations_use_operation_specific_reach(monkeypatch):
    surface = parse_manifest(manifest(
        '<provider android:name=".ReadLocked" android:exported="true" '
        'android:authorities="com.example.precision.read" '
        'android:readPermission="com.example.precision.STRONG"/>'))
    provider = component(surface, ".ReadLocked")

    def fake_exec(argv, **kwargs):
        stdout = "Row: 0 col=value" if argv[:2] == ["content", "query"] else "ok"
        return SimpleNamespace(rc=0, stdout=stdout, stderr="")

    from droid_recon.device_agent import runtime
    monkeypatch.setattr(runtime, "exec_on_device", fake_exec)
    ctx = probes.ProbeContext(package=surface.package, capture_logcat=False)
    query = probes.query_provider(ctx, provider, "com.example.precision.read", "items")
    read_file = probes.read_provider_file(ctx, provider, "com.example.precision.read", "file")
    call = probes.call_provider(ctx, provider, "com.example.precision.read", "action")
    write = probes._run_probe(ctx, "insert_provider", ["content", "insert"], provider)
    assert query.reachable_from == "none" and not query.interesting
    assert read_file.reachable_from == "none" and not read_file.interesting
    assert call.reachable_from == "third_party_app"
    assert write.reachable_from == "third_party_app"
    assert write.detail["reach_basis"] == "manifest provider write reach"
    assert "path permissions" in write.detail["reach_limit"]
