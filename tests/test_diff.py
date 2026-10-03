from zipfile import ZipFile

from droid_recon.diff import compare
from droid_recon.models import AttackSurface, Component


def test_diff_highlights_new_external_entry_point_and_permission_change():
    before = AttackSurface(
        package="example.app", version_code=1,
        components=[Component(name="example.app.Private", type="activity",
                              exported=False, reachable_from="shell")],
    )
    after = AttackSurface(
        package="example.app", version_code=2,
        components=[
            Component(name="example.app.Private", type="activity",
                      exported=True, reachable_from="third_party_app"),
            Component(name="example.app.New", type="provider", exported=True,
                      authorities=["example.app.data"], reachable_from="third_party_app"),
        ],
    )
    result = compare(before, after)
    assert result["newly_reachable"] == [
        "activity:example.app.Private", "provider:example.app.New"
    ]
    assert result["changed_components"]["activity:example.app.Private"]["exported"] == {
        "before": False, "after": True
    }


def test_diff_rejects_comparison_of_different_apps():
    try:
        compare(AttackSurface(package="first"), AttackSurface(package="second"))
    except ValueError as exc:
        assert "different packages" in str(exc)
    else:
        raise AssertionError("different packages were compared")


def test_diff_identifies_changed_shipped_dex_and_native_binary(tmp_path):
    old_apk = tmp_path / "old" / "base.apk"
    new_apk = tmp_path / "new" / "base.apk"
    old_apk.parent.mkdir()
    new_apk.parent.mkdir()
    with ZipFile(old_apk, "w") as archive:
        archive.writestr("classes.dex", b"old-code")
        archive.writestr("lib/arm64-v8a/libfoo.so", b"old-library")
    with ZipFile(new_apk, "w") as archive:
        archive.writestr("classes.dex", b"new-code")
        archive.writestr("lib/arm64-v8a/libfoo.so", b"new-library")
    result = compare(
        AttackSurface(package="example.app", apk_paths=[str(old_apk)]),
        AttackSurface(package="example.app", apk_paths=[str(new_apk)]),
    )
    assert result["shipped_code_and_library_changes"]["changed"] == [
        "base.apk:classes.dex", "base.apk:lib/arm64-v8a/libfoo.so"
    ]


def test_diff_detects_new_provider_call_reach_with_read_still_guarded():
    before = AttackSurface(package="example.app", components=[Component(
        name="example.app.Data", type="provider", exported=True,
        reachable_from="none", read_reachable_from="none",
        write_reachable_from="none", call_reachable_from="none",
    )])
    after = AttackSurface(package="example.app", components=[Component(
        name="example.app.Data", type="provider", exported=True,
        reachable_from="none", read_reachable_from="none",
        write_reachable_from="none", call_reachable_from="third_party_app",
    )])
    diff = compare(before, after)
    assert diff["newly_reachable"] == ["provider:example.app.Data"]
    assert diff["newly_reachable_operations"] == ["provider:example.app.Data:call"]
    assert "provider_reach" in diff["changed_components"]["provider:example.app.Data"]
