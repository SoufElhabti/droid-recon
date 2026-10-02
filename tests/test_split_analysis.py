"""Split APK coverage: manifest identity, provenance, and code cache invalidation."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from types import SimpleNamespace
from zipfile import ZipFile

import pytest

from droid_recon.static import decompile, manifest


ANDROID_NS = 'xmlns:android="http://schemas.android.com/apk/res/android"'


def _apk(directory, name: str, xml: str):
    path = directory / name
    with ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", xml)
    return path


def _decoded_manifest(apk, timeout=120):
    with ZipFile(apk) as archive:
        return archive.read("AndroidManifest.xml").decode()


@pytest.fixture
def split_set(tmp_path, monkeypatch):
    monkeypatch.setattr(manifest, "dump_manifest_xml", _decoded_manifest)
    base = _apk(tmp_path, "base.apk", f'''
        <manifest {ANDROID_NS} package="com.example.app"
                  android:versionCode="5" split="">
          <uses-sdk android:targetSdkVersion="34" />
          <application android:allowBackup="false">
            <activity android:name=".Main" android:exported="true" />
          </application>
        </manifest>''')
    feature = _apk(tmp_path, "feature.payments.apk", f'''
        <manifest {ANDROID_NS} package="com.example.app" split="payments"
                  android:versionCode="5">
          <permission android:name="com.example.app.PRIVATE"
                      android:protectionLevel="signature" />
          <uses-permission android:name="android.permission.CAMERA" />
          <application>
            <activity android:name=".Pay" android:exported="true"
                      android:permission="com.example.app.PRIVATE" />
            <receiver android:name=".PaymentReceiver" android:exported="true" />
          </application>
        </manifest>''')
    config = _apk(tmp_path, "config.en.apk", f'''
        <manifest {ANDROID_NS} package="com.example.app" split="config.en"
                  android:versionCode="5" />''')
    return base, feature, config


def test_feature_manifest_is_merged_with_base_and_provenance(split_set):
    base, feature, config = split_set
    surface = manifest.analyze(base.parent)

    assert surface.apk_paths[0] == str(base)
    assert set(surface.apk_paths) == {str(base), str(feature), str(config)}
    assert len(surface.apk_sha256s) == 3
    assert surface.apk_sha256 == surface.apk_sha256s[str(base)]
    assert {component.name for component in surface.components} == {
        "com.example.app.Main", "com.example.app.Pay", "com.example.app.PaymentReceiver"
    }
    pay = next(c for c in surface.components if c.name.endswith(".Pay"))
    assert pay.source_apk == str(feature)
    assert pay.source_split == "payments"
    assert pay.reachable_from == "none", "feature permission must be resolved across manifests"
    main = next(c for c in surface.components if c.name.endswith(".Main"))
    assert main.source_apk == str(base)
    assert main.source_split is None
    assert "android.permission.CAMERA" in surface.uses_permissions
    assert surface.allow_backup is False, "a split without app flags must not override base defaults"

    restored = type(surface).from_dict(surface.to_dict())
    assert restored.apk_sha256s == surface.apk_sha256s
    assert restored.components[1].source_split == surface.components[1].source_split


def test_explicit_apk_list_works_across_directories(split_set, tmp_path):
    base, feature, _ = split_set
    other_dir = tmp_path / "other_dir"
    other_dir.mkdir()
    moved_feature = other_dir / feature.name
    feature.replace(moved_feature)
    surface = manifest.analyze([moved_feature, base])
    assert surface.apk_paths == [str(base), str(moved_feature)]
    assert len(surface.components) == 3


def test_mixed_packages_are_rejected(split_set, tmp_path):
    base, _, _ = split_set
    other = _apk(tmp_path, "other.apk", f'''
        <manifest {ANDROID_NS} package="com.other" split="other" />''')
    with pytest.raises(ValueError, match="package mismatch"):
        manifest.analyze([base, other])


def test_duplicate_component_is_rejected(split_set, tmp_path):
    base, _, _ = split_set
    duplicate = _apk(tmp_path, "duplicate.apk", f'''
        <manifest {ANDROID_NS} package="com.example.app" split="duplicate">
          <application><activity android:name=".Main" android:exported="false" />
          </application>
        </manifest>''')
    with pytest.raises(ValueError, match="duplicate activity"):
        manifest.analyze([base, duplicate])


def test_missing_base_is_rejected(split_set):
    _, feature, config = split_set
    with pytest.raises(ValueError, match="exactly one base"):
        manifest.analyze([feature, config])


def test_mismatched_version_is_rejected(split_set, tmp_path):
    base, _, _ = split_set
    bad = _apk(tmp_path, "version.apk", f'''
        <manifest {ANDROID_NS} package="com.example.app" split="new"
                  android:versionCode="6" />''')
    with pytest.raises(ValueError, match="versionCode mismatch"):
        manifest.analyze([base, bad])


def test_aapt2_fallback_keeps_manifest_package_and_split_unqualified():
    xml = manifest._xmltree_to_xml('''
E: manifest
  A: package="com.example.app"
  A: split="payments"
  E: application
    E: activity
      A: android:name=".Pay"
      A: android:exported="true"
''')
    root = ET.fromstring(xml)
    assert root.attrib["package"] == "com.example.app"
    assert root.attrib["split"] == "payments"


def test_decompile_passes_all_apks_and_invalidates_cache_when_split_changes(
    split_set, tmp_path, monkeypatch,
):
    base, feature, config = split_set
    commands = []

    def fake_run(argv, timeout):
        commands.append(argv)
        from pathlib import Path
        out = Path(argv[argv.index("-d") + 1])
        source = out / "sources" / "com" / "example" / "app" / "Pay.java"
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text("class Pay {}")
        return SimpleNamespace(ok=True, rc=0, timed_out=False)

    monkeypatch.setattr(decompile.shell, "which", lambda *_: "jadx")
    monkeypatch.setattr(decompile.shell, "run", fake_run)
    apks = [base, feature, config]
    kwargs = {"cache_root": tmp_path / "cache"}
    first = decompile.decompile(apks, manifest.sha256_of(base), **kwargs)
    assert first is not None
    assert commands[0][-3:] == [str(base), str(feature), str(config)]
    assert decompile.decompile(apks, manifest.sha256_of(base), **kwargs) == first
    assert len(commands) == 1, "identical split set should hit cache"

    with ZipFile(feature, "a") as archive:
        archive.writestr("new.dex", b"changed split code")
    second = decompile.decompile(apks, manifest.sha256_of(base), **kwargs)
    assert second is not None and second != first
    assert len(commands) == 2, "changing a feature APK must invalidate the code cache"
