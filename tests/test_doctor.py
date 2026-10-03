"""Host capability checks must not require an Android SDK to test."""

from droid_recon import doctor, shell


def test_doctor_reports_stage_availability_without_executing_tools():
    installed = {"adb", "apkanalyzer", "jadx"}
    result = doctor.inspect(
        find=lambda name, *paths: f"/tools/{name}" if name in installed else None,
        sdk_home=lambda: None,
    )
    assert result["capabilities"]["manifest"] is True
    assert result["capabilities"]["code"] is True
    assert result["capabilities"]["device"] is False
    assert "device" in result["missing_capabilities"]
    assert result["capabilities"]["network"] is False


def test_doctor_does_not_claim_broken_frida_is_available(monkeypatch):
    installed = {"adb": "/tools/adb", "frida": "/tools/frida"}
    monkeypatch.setattr(shell, "which", lambda name, *paths: installed.get(name))
    monkeypatch.setattr(
        shell,
        "run",
        lambda argv, **kwargs: shell.Proc(list(argv), 1, "", "ImportError: broken frida"),
    )

    result = doctor.inspect(
        sdk_home=lambda: None,
        avd_list=lambda: [],
        device_list=lambda: [],
    )

    assert result["tools"]["frida"] == "/tools/frida"
    assert result["tool_health"]["frida"]["runnable"] is False
    assert result["capabilities"]["frida"] is False


def test_doctor_distinguishes_emulator_binary_from_configured_avd(tmp_path):
    sdk = tmp_path / "sdk"
    (sdk / "platforms" / "android-35").mkdir(parents=True)
    (sdk / "platforms" / "android-35" / "android.jar").write_bytes(b"fixture")
    installed = {"adb", "emulator", "aapt2", "java", "javac"}
    def lookup(name, *paths):
        return f"/tools/{name}" if name in installed else None

    absent = doctor.inspect(find=lookup, sdk_home=lambda: sdk,
                            avd_list=lambda: [], device_list=lambda: [])
    assert absent["capabilities"]["device"] is False
    assert absent["capabilities"]["companion_build"] is True
    assert absent["android_platforms"] == ["android-35"]
    configured = doctor.inspect(find=lookup, sdk_home=lambda: sdk,
                                avd_list=lambda: ["lab"], device_list=lambda: [])
    assert configured["capabilities"]["device"] is True
    assert configured["avds"][0]["name"] == "lab"


def test_doctor_follows_absolute_avd_pointer_outside_android_home(tmp_path, monkeypatch):
    user_home = tmp_path / ".android"
    avd_home = user_home / "avd"
    avd_home.mkdir(parents=True)
    external = tmp_path / "other-drive" / "lab.avd"
    external.mkdir(parents=True)
    (external / "config.ini").write_text("abi.type=x86_64\n", encoding="utf-8")
    (avd_home / "lab.ini").write_text(f"path={external}\n", encoding="utf-8")
    monkeypatch.setenv("ANDROID_USER_HOME", str(user_home))
    monkeypatch.delenv("ANDROID_AVD_HOME", raising=False)

    result = doctor.inspect(find=lambda name, *paths: None, sdk_home=lambda: None,
                            avd_list=lambda: ["lab"], device_list=lambda: [])
    assert result["avds"][0]["abi"] == "x86_64"


def test_doctor_follows_relative_avd_pointer_and_ignores_traversal(tmp_path, monkeypatch):
    user_home = tmp_path / ".android"
    avd_home = user_home / "avd"
    avd_home.mkdir(parents=True)
    relative_avd = user_home / "relocated" / "lab.avd"
    relative_avd.mkdir(parents=True)
    (relative_avd / "config.ini").write_text("abi.type=arm64-v8a\n", encoding="utf-8")
    pointer = avd_home / "lab.ini"
    pointer.write_text("path.rel=relocated\\lab.avd\n", encoding="utf-8")
    monkeypatch.setenv("ANDROID_USER_HOME", str(user_home))
    monkeypatch.delenv("ANDROID_AVD_HOME", raising=False)

    def inspect():
        return doctor.inspect(
            find=lambda name, *paths: None,
            sdk_home=lambda: None,
            avd_list=lambda: ["lab"],
            device_list=lambda: [],
        )
    assert inspect()["avds"][0]["abi"] == "arm64-v8a"

    (relative_avd / "config.ini").unlink()
    outside = tmp_path / "outside.avd"
    outside.mkdir()
    (outside / "config.ini").write_text("abi.type=x86_64\n", encoding="utf-8")
    pointer.write_text("path.rel=..\\outside.avd\n", encoding="utf-8")
    assert inspect()["avds"][0]["abi"] is None
