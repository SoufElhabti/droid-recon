"""Build and inspect the ordinary-caller APK without an emulator or device."""

from __future__ import annotations

import re
from zipfile import ZipFile

import pytest

from droid_recon import shell
from droid_recon.device import ordinary


def _sdk_ready() -> bool:
    sdk = shell.android_home()
    return bool(sdk and shell.aapt2_path() and shell.which("javac") and
                list((sdk / "platforms").glob("android-*/android.jar")))


@pytest.mark.skipif(not _sdk_ready(), reason="Android SDK and JDK not installed")
def test_offline_companion_apk_has_dex_no_permissions_and_valid_signature(
    tmp_path, monkeypatch,
):
    # Exercise the SDK-only build path, even on a workstation that also has Gradle.
    original_which = shell.which
    monkeypatch.setattr(ordinary.shell, "which",
                        lambda name, *paths: None if name == "gradle"
                        else original_which(name, *paths))

    built = ordinary.build_companion(build_root=tmp_path)
    assert built.status == "built", built.message
    assert built.apk is not None and built.apk.is_file()
    assert built.apk.parent == tmp_path
    with ZipFile(built.apk) as archive:
        names = set(archive.namelist())
    assert {"AndroidManifest.xml", "classes.dex", "resources.arsc"} <= names

    aapt2 = shell.aapt2_path()
    badging = shell.run([aapt2, "dump", "badging", str(built.apk)], timeout=30)
    assert badging.ok, badging.stderr
    assert "package: name='org.droidrecon.companion'" in badging.stdout
    assert "minSdkVersion:'26'" in badging.stdout
    assert "targetSdkVersion:'35'" in badging.stdout

    permissions = shell.run([aapt2, "dump", "permissions", str(built.apk)], timeout=30)
    assert permissions.ok, permissions.stderr
    assert "uses-permission" not in permissions.stdout

    manifest = shell.run(
        [aapt2, "dump", "xmltree", "--file", "AndroidManifest.xml", str(built.apk)],
        timeout=30,
    )
    assert manifest.ok, manifest.stderr
    assert 'package="org.droidrecon.companion"' in manifest.stdout
    assert 'android:name(0x01010003)=".ProbeActivity"' in manifest.stdout
    assert 'android:exported(0x01010010)=true' in manifest.stdout

    javac = shell.which("javac")
    java = str(type(built.apk)(javac).with_name("java.exe" if javac.lower().endswith(".exe")
                                                 else "java"))
    signer = str(type(built.apk)(aapt2).parent / "lib" / "apksigner.jar")
    signature = shell.run(
        [java, "-jar", signer, "verify", "--verbose", "--print-certs", str(built.apk)],
        timeout=30,
    )
    assert signature.ok, signature.stderr
    assert "Verified using v2 scheme (APK Signature Scheme v2): true" in signature.stdout
    cert = re.search(r"Signer #1 certificate SHA-256 digest: ([0-9a-f]+)",
                     signature.stdout)
    assert cert, signature.stdout

    # A rebuild must retain the signing key so adb install -r can update the app.
    rebuilt = ordinary.build_companion(build_root=tmp_path)
    assert rebuilt.status == "built", rebuilt.message
    signature_again = shell.run(
        [java, "-jar", signer, "verify", "--print-certs", str(rebuilt.apk)],
        timeout=30,
    )
    assert signature_again.ok
    assert cert.group(1) in signature_again.stdout

    # The exact APK built from bundled source is trusted after manifest inspection.
    monkeypatch.setattr(ordinary, "_emulator_serial", lambda serial: "emulator-5554")
    monkeypatch.setattr(ordinary.shell, "adb", lambda *a, **kw: shell.Proc(
        list(a), 0, "Success\n", ""))
    monkeypatch.setattr(ordinary.shell, "adb_shell", lambda *a, **kw: shell.Proc(
        list(a), 0, "package:/data/app/org.droidrecon.companion/base.apk\n", ""))
    installed = ordinary.install_companion(rebuilt.apk, serial="emulator-5554")
    assert installed.status == "installed", installed.message
    assert installed.verified_build is True
