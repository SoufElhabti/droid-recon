from pathlib import Path

from droid_recon.static import resources


def test_analyze_all_keeps_resource_provenance_across_splits(tmp_path: Path, monkeypatch):
    base = tmp_path / "base.apk"
    feature = tmp_path / "feature.apk"
    base.write_bytes(b"base")
    feature.write_bytes(b"feature")

    def decode(apk, dest, *, force=False):
        xml = dest / "res" / "xml"
        xml.mkdir(parents=True)
        if apk == feature:
            (xml / "paths.xml").write_text(
                '<paths><root-path xmlns:android="http://schemas.android.com/apk/res/android" '
                'android:name="files" android:path="/"/></paths>'
            )
        return dest

    monkeypatch.setattr(resources, "extract_resources", decode)
    result = resources.analyze_all([base, feature], tmp_path / "cache")
    assert [item["apk"] for item in result["status"]] == [str(base), str(feature)]
    assert result["fileprovider_paths"][0]["source_apk"] == str(feature)
    assert result["fileprovider_paths"][0]["dangerous"] is True
